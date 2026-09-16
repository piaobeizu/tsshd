/*
MIT License

Copyright (c) 2024-2026 The Trzsz SSH Authors.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package tsshd

// Control-input latency benchmark for Claude Code / Pi style workloads.
//
// This harness reproduces and decomposes the latency of a control input
// (Ctrl-C, 0x03) while a session floods output over `tssh --udp --kcp`,
// measuring at every boundary:
//
//	client stdin pipe (agent -> tssh)          [T_inject]
//	  -> smux stream (client -> server)        (transport; same repo on both sides)
//	  -> KCP + FEC 1+1 over a lossy link      (userspace netem relay, seeded)
//	  -> server smux stream -> PTY write      (tsshd session layer)
//	  -> kernel ISIG -> SIGINT in the child   [T_sigint, via unix socket side channel]
//	  -> child stops flooding                 [T_lastwrite]
//	  -> marker written to PTY                [T_child_marker]
//	  -> output backlog drain over the link   (relay queue + kcp + smux buffers)
//	  -> client sees the marker                [T_client_marker]
//
// Run one case per process:
//
//	TSSHD_CTRL_BENCH=bottleneck_shared go test ./tsshd -run TestControlLatencyUnderFlood -v -count=1
//
// See benchmarks/control-latency/README.md for the case matrix, methodology
// and the mapping to `tc netem` conditions. Skipped unless TSSHD_CTRL_BENCH
// is set, so `go test ./...` stays fast.
//
// Everything except the child process and two real UDP sockets runs
// in-process: the tsshd KCP server (initServer), the SshUdpClient transport
// and the netem relay are library code, so timestamps share one clock
// (CLOCK_MONOTONIC, comparable with the re-exec'd child on the same host).

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

// ---------------------------------------------------------------------------
// monotonic clock (comparable across processes on the same host)
// ---------------------------------------------------------------------------

func ctrlMonoNS() int64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return time.Now().UnixNano()
	}
	return int64(ts.Sec)*1e9 + int64(ts.Nsec)
}

// ---------------------------------------------------------------------------
// netem relay: userspace tc-netem equivalent between client and server.
//
// Semantics deliberately mirror `tc netem delay D loss P rate R limit L`:
//   - enqueue is NON-BLOCKING (like the kernel qdisc); a full queue
//     tail-drops. This matters: kcp-go's defaultTx writes packets inside the
//     session update goroutine, so a blocking write would stall all KCP
//     processing (an artifact tc netem does not have).
//   - loss is applied at enqueue (egress loss), delay + strict pacing at
//     egress, order preserved. FEC 1+1 parity packets are shaped too (the
//     rate limiter counts real datagram bytes, like the kernel would).
//   - SHARED mode models one bottleneck queue carrying both directions
//     (e.g. a single netem qdisc on a veth pair); SPLIT mode models
//     per-direction qdiscs.
// ---------------------------------------------------------------------------

type ctrlNetemConfig struct {
	Name      string  `json:"name"`
	Shared    bool    `json:"shared"`      // single shared queue for both directions
	DelayUp   float64 `json:"delay_up_ms"` // one-way delay in ms
	DelayDown float64 `json:"delay_down_ms"`
	LossUp    float64 `json:"loss_up"` // random loss probability
	LossDown  float64 `json:"loss_down"`
	RateUp    int64   `json:"rate_up_bps"` // bytes per second; 0 = unlimited
	RateDown  int64   `json:"rate_down_bps"`
	LimitUp   int     `json:"limit_up_pkts"` // queue limit in packets (netem default 1000)
	LimitDown int     `json:"limit_down_pkts"`
	Seed      int64   `json:"seed"`
}

type ctrlPkt struct {
	data    []byte
	dest    *net.UDPAddr
	readyAt int64
	ingress int64
}

type ctrlQStats struct {
	Enqueued       uint64 `json:"enqueued"`
	Egressed       uint64 `json:"egressed"`
	DroppedLoss    uint64 `json:"dropped_loss"`
	DroppedQueue   uint64 `json:"dropped_queue_full"`
	EnqueuedBytes  uint64 `json:"enqueued_bytes"`
	EgressedBytes  uint64 `json:"egressed_bytes"`
	DroppedBytes   uint64 `json:"dropped_bytes"`
	MaxQLenPackets int    `json:"max_qlen_packets"`
	MaxQLenBytes   int    `json:"max_qlen_bytes"`
}

type ctrlQLenSample struct {
	TNS     int64 `json:"t_ns"`
	Packets int   `json:"packets"`
	Bytes   int   `json:"bytes"`
}

type ctrlQ struct {
	mu      sync.Mutex
	pkts    []ctrlPkt
	limit   int
	loss    float64
	delayNS int64
	rate    float64 // bytes/sec, 0 = unlimited
	lastEgr int64
	stats   ctrlQStats
	rng     *rand.Rand
	qlenLog []ctrlQLenSample
	closeCh chan struct{}
	closed  bool
}

func (q *ctrlQ) enqueue(p ctrlPkt) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return false
	}
	if q.rng.Float64() < q.loss {
		q.stats.DroppedLoss++
		q.stats.DroppedBytes += uint64(len(p.data))
		return false
	}
	if len(q.pkts) >= q.limit {
		q.stats.DroppedQueue++
		q.stats.DroppedBytes += uint64(len(p.data))
		return false
	}
	now := ctrlMonoNS()
	p.ingress = now
	ready := now + q.delayNS
	if q.rate > 0 {
		if prev := q.lastEgr; prev > ready {
			ready = prev
		}
		ready += int64(float64(len(p.data)) * 1e9 / q.rate)
		q.lastEgr = ready
	}
	p.readyAt = ready
	q.pkts = append(q.pkts, p)
	q.stats.Enqueued++
	q.stats.EnqueuedBytes += uint64(len(p.data))
	if l := len(q.pkts); l > q.stats.MaxQLenPackets {
		q.stats.MaxQLenPackets = l
	}
	if b := q.byteLenLocked(); b > q.stats.MaxQLenBytes {
		q.stats.MaxQLenBytes = b
	}
	return true
}

func (q *ctrlQ) byteLenLocked() int {
	b := 0
	for _, p := range q.pkts {
		b += len(p.data)
	}
	return b
}

func (q *ctrlQ) pacer(send func(ctrlPkt)) {
	sampleTick := time.NewTicker(20 * time.Millisecond)
	defer sampleTick.Stop()
	for {
		select {
		case <-q.closeCh:
			return
		case <-sampleTick.C:
			q.mu.Lock()
			q.qlenLog = append(q.qlenLog, ctrlQLenSample{
				TNS: ctrlMonoNS(), Packets: len(q.pkts), Bytes: q.byteLenLocked()})
			q.mu.Unlock()
		default:
		}

		q.mu.Lock()
		if len(q.pkts) == 0 {
			q.mu.Unlock()
			time.Sleep(2 * time.Millisecond)
			continue
		}
		head := q.pkts[0]
		now := ctrlMonoNS()
		if head.readyAt > now {
			q.mu.Unlock()
			d := time.Duration(head.readyAt-now) * time.Nanosecond
			if d > 5*time.Millisecond {
				d = 5 * time.Millisecond
			}
			time.Sleep(d)
			continue
		}
		q.pkts = q.pkts[1:]
		q.stats.Egressed++
		q.stats.EgressedBytes += uint64(len(head.data))
		q.mu.Unlock()

		send(head)
	}
}

func (q *ctrlQ) close() {
	q.mu.Lock()
	if !q.closed {
		q.closed = true
		close(q.closeCh)
	}
	q.mu.Unlock()
}

type ctrlRelayStats struct {
	Up   ctrlQStats `json:"up"`
	Down ctrlQStats `json:"down"`
}

type ctrlRelay struct {
	conn       *net.UDPConn
	serverAddr *net.UDPAddr
	clientAddr atomic.Pointer[net.UDPAddr]

	shared bool
	up     *ctrlQ
	down   *ctrlQ
	wg     sync.WaitGroup
}

func newCtrlRelay(cfg ctrlNetemConfig, serverAddr *net.UDPAddr) (*ctrlRelay, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		return nil, fmt.Errorf("relay listen failed: %w", err)
	}
	mkQ := func(limit int, loss float64, delayMS float64, rate int64, seed int64) *ctrlQ {
		l := limit
		if l <= 0 {
			l = 1000
		}
		q := &ctrlQ{
			limit:   l,
			loss:    loss,
			delayNS: int64(delayMS * float64(time.Millisecond)),
			rate:    float64(rate),
			closeCh: make(chan struct{}),
		}
		q.rng = rand.New(rand.NewSource(seed))
		return q
	}
	r := &ctrlRelay{conn: conn, serverAddr: serverAddr, shared: cfg.Shared}
	r.up = mkQ(cfg.LimitUp, cfg.LossUp, cfg.DelayUp, cfg.RateUp, cfg.Seed)
	if cfg.Shared {
		r.down = r.up // one shared bottleneck queue
	} else {
		r.down = mkQ(cfg.LimitDown, cfg.LossDown, cfg.DelayDown, cfg.RateDown, cfg.Seed+1)
	}
	return r, nil
}

func (r *ctrlRelay) addr() *net.UDPAddr { return r.conn.LocalAddr().(*net.UDPAddr) }

func (r *ctrlRelay) start() {
	r.wg.Add(2)
	go func() { // classifier: non-blocking enqueue, like a kernel qdisc
		defer r.wg.Done()
		buf := make([]byte, 65536)
		for {
			n, addr, err := r.conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			var dst *net.UDPAddr
			var isDownlink bool
			if addr.IP.Equal(r.serverAddr.IP) && addr.Port == r.serverAddr.Port {
				dst = r.clientAddr.Load()
				isDownlink = true
			} else {
				r.clientAddr.CompareAndSwap(nil, addr)
				dst = r.serverAddr
			}
			if dst == nil {
				continue
			}
			data := make([]byte, n)
			copy(data, buf[:n])
			if isDownlink {
				r.down.enqueue(ctrlPkt{data: data, dest: dst})
			} else {
				r.up.enqueue(ctrlPkt{data: data, dest: dst})
			}
		}
	}()
	go func() { // pacers
		defer r.wg.Done()
		var inner sync.WaitGroup
		inner.Add(1)
		go func() {
			defer inner.Done()
			r.up.pacer(func(p ctrlPkt) { _, _ = r.conn.WriteToUDP(p.data, p.dest) })
		}()
		if r.down != r.up {
			inner.Add(1)
			go func() {
				defer inner.Done()
				r.down.pacer(func(p ctrlPkt) { _, _ = r.conn.WriteToUDP(p.data, p.dest) })
			}()
		}
		inner.Wait()
	}()
}

func (r *ctrlRelay) stats() ctrlRelayStats {
	s := ctrlRelayStats{}
	r.up.mu.Lock()
	s.Up = r.up.stats
	r.up.mu.Unlock()
	if r.down != r.up {
		r.down.mu.Lock()
		s.Down = r.down.stats
		r.down.mu.Unlock()
	} else {
		s.Down = s.Up
	}
	return s
}

func (r *ctrlRelay) qlenSnapshot() (up, down int) {
	r.up.mu.Lock()
	up = len(r.up.pkts)
	r.up.mu.Unlock()
	if r.down != r.up {
		r.down.mu.Lock()
		down = len(r.down.pkts)
		r.down.mu.Unlock()
	} else {
		down = up
	}
	return
}

func (r *ctrlRelay) close() {
	r.up.close()
	if r.down != r.up {
		r.down.close()
	}
	_ = r.conn.Close()
	r.wg.Wait()
}

// ---------------------------------------------------------------------------
// side channel: unix socket carrying child events (bypasses the transport)
// ---------------------------------------------------------------------------

type ctrlEvent struct {
	Name   string `json:"name"`
	MonoNS int64  `json:"mono_ns"`
	Extra  int64  `json:"extra,omitempty"`
}

func ctrlSideChannelListen(path string) (<-chan ctrlEvent, io.Closer, error) {
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, nil, fmt.Errorf("side channel listen failed: %w", err)
	}
	ch := make(chan ctrlEvent, 1024)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				close(ch)
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				sc := bufio.NewScanner(c)
				sc.Buffer(make([]byte, 1024), 1024)
				for sc.Scan() {
					fields := strings.Fields(sc.Text())
					if len(fields) == 0 {
						continue
					}
					ev := ctrlEvent{Name: fields[0]}
					if len(fields) > 1 {
						v, _ := strconv.ParseInt(fields[1], 10, 64)
						ev.MonoNS = v
					}
					if len(fields) > 2 {
						v, _ := strconv.ParseInt(fields[2], 10, 64)
						ev.Extra = v
					}
					ch <- ev
				}
			}(conn)
		}
	}()
	return ch, ln, nil
}

// ---------------------------------------------------------------------------
// child mode (re-exec of the test binary, runs under the server-side PTY)
// ---------------------------------------------------------------------------

const ctrlMarker = "=== AFTER-SIGINT ==="

func ctrlChildMain() int {
	// os.Args: [bin, "--ctrlbench-child", mode, sockPath, extra]
	if len(os.Args) < 4 {
		fmt.Fprintln(os.Stderr, "ctrlbench child: missing args")
		return 2
	}
	mode := os.Args[2]
	sockPath := os.Args[3]
	extra := ""
	if len(os.Args) > 4 {
		extra = os.Args[4]
	}

	var conn net.Conn
	var err error
	for i := 0; i < 200; i++ {
		conn, err = net.Dial("unix", sockPath)
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ctrlbench child: side channel connect failed:", err)
		return 2
	}
	defer conn.Close()

	var sendMu sync.Mutex
	send := func(name string, extraVal int64) {
		sendMu.Lock()
		defer sendMu.Unlock()
		_, _ = fmt.Fprintf(conn, "%s %d %d\n", name, ctrlMonoNS(), extraVal)
	}

	send("READY", 0)

	switch mode {
	case "flood":
		return ctrlChildFlood(send)
	case "floodread":
		return ctrlChildFloodRead(send)
	case "ctrlcount":
		target := int64(30)
		if v, e := strconv.ParseInt(extra, 10, 64); e == nil && v > 0 {
			target = v
		}
		return ctrlChildCtrlCount(send, target)
	default:
		fmt.Fprintln(os.Stderr, "ctrlbench child: unknown mode", mode)
		return 2
	}
}

// ctrlChildFlood writes Claude-Code-style colored output lines as fast as the
// PTY accepts them, until SIGINT arrives. Then it writes the marker (which
// travels back through the transport) and exits.
func ctrlChildFlood(send func(string, int64)) int {
	stopped := atomic.Bool{}
	sigCh := make(chan os.Signal, 4)
	signal.Notify(sigCh, syscall.SIGINT)

	go func() {
		<-sigCh
		send("SIGINT", 0)
		stopped.Store(true)
	}()

	floodDone := make(chan int64, 1)
	go func() {
		var total int64
		line := 0
		buf := make([]byte, 0, 208)
		for !stopped.Load() {
			line++
			buf = buf[:0]
			buf = append(buf, "\x1b[32mflood\x1b[0m "...)
			buf = strconv.AppendInt(buf, int64(line), 10)
			buf = append(buf, ' ')
			for len(buf) < 205 {
				buf = append(buf, 'x')
			}
			buf = append(buf, '\n')
			n, _ := os.Stdout.Write(buf)
			total += int64(n)
			if line%2000 == 0 {
				send("W", int64(line)) // progress probes: gaps expose PTY backpressure
			}
		}
		floodDone <- total
	}()

	total := <-floodDone
	send("LASTWRITE", total)

	_, _ = os.Stdout.Write([]byte("\r\n" + ctrlMarker + "\r\n"))
	send("MARKERWRITTEN", 0)
	time.Sleep(200 * time.Millisecond) // let the marker leave the process
	send("EXIT", 0)
	return 0
}

// ctrlChildFloodRead is ctrlChildFlood plus a stdin drain loop: it models
// a Claude Code / Pi style agent whose input thread keeps consuming stdin
// (and thus the PTY input buffer) while its output floods, so the PTY
// head-of-line block cannot engage and only the transport can delay Ctrl-C.
func ctrlChildFloodRead(send func(string, int64)) int {
	go func() { _, _ = io.Copy(io.Discard, os.Stdin) }()
	return ctrlChildFlood(send)
}

// ctrlChildCtrlCount counts SIGINTs (no flood, does not exit on SIGINT).
func ctrlChildCtrlCount(send func(string, int64), target int64) int {
	sigCh := make(chan os.Signal, 64)
	signal.Notify(sigCh, syscall.SIGINT)
	for i := int64(1); i <= target; i++ {
		<-sigCh
		send("SIGINT", i)
	}
	send("EXIT", 0)
	return 0
}

// TestMain re-executes this binary in child mode; otherwise runs tests.
func TestMain(m *testing.M) {
	if len(os.Args) >= 2 && os.Args[1] == "--ctrlbench-child" {
		os.Exit(ctrlChildMain())
	}
	os.Exit(m.Run())
}

// ---------------------------------------------------------------------------
// case definitions
// ---------------------------------------------------------------------------

type ctrlCase struct {
	Netem     ctrlNetemConfig
	ChildMode string // "flood" | "floodread" | "ctrlcount"
	CtrlCount int    // samples for ctrlcount

	// Expect documents the anticipated outcome so the harness can assert
	// DOCUMENTED pathologies as pass conditions instead of red tests.
	Expect ctrlExpect

	Warmup   time.Duration // let the flood reach steady state before Ctrl-C
	PasteKB  int           // write this much stdin before Ctrl-C (0 = none)
	DrainBPS int64         // cap client output drain rate (0 = unbounded)

	HeartbeatInterval time.Duration // tssh sends a bus "alive" every interval
	HeartbeatTimeout  time.Duration // tssh default heartbeat timeout
	WaitTimeout       time.Duration
}

// ctrlExpect is the anticipated outcome of a case; it turns documented
// pathologies into assertions instead of unexplained red tests.
type ctrlExpect int

const (
	ctrlExpectOK         ctrlExpect = iota
	ctrlExpectNoSigint              // control input is (pathologically) never delivered
	ctrlExpectNoMarker              // SIGINT delivered, but confirmation never reaches the client
	ctrlExpectSigintOnly            // SIGINT delivered within WaitTimeout; marker timing is data
)

func (e ctrlExpect) String() string {
	switch e {
	case ctrlExpectNoSigint:
		return "no_sigint"
	case ctrlExpectNoMarker:
		return "no_marker"
	case ctrlExpectSigintOnly:
		return "sigint_only"
	default:
		return "ok"
	}
}

func defaultCtrlCase(name string) ctrlCase {
	return ctrlCase{
		Netem: ctrlNetemConfig{
			Name:      name,
			LimitUp:   1000, // tc netem default queue limit
			LimitDown: 1000,
			Seed:      20260916,
		},
		ChildMode:         "flood",
		Warmup:            5 * time.Second,
		HeartbeatInterval: time.Second,
		HeartbeatTimeout:  3 * time.Second,
		WaitTimeout:       150 * time.Second,
	}
}

var ctrlCases = map[string]func() ctrlCase{
	// ideal link: pure machinery overhead + backlog drain at loopback speed
	"baseline": func() ctrlCase {
		c := defaultCtrlCase("baseline")
		c.Netem.DelayUp, c.Netem.DelayDown = 50, 50 // RTT ~100 ms
		return c
	},
	// 20% bidirectional loss, no flood: control-path latency distribution.
	// Reproduces the earlier "input echo p95 ~211ms" style measurement.
	"loss20": func() ctrlCase {
		c := defaultCtrlCase("loss20")
		c.Netem.DelayUp, c.Netem.DelayDown = 50, 50
		c.Netem.LossUp, c.Netem.LossDown = 0.20, 0.20
		c.ChildMode = "ctrlcount"
		c.CtrlCount = 30
		c.WaitTimeout = 60 * time.Second
		return c
	},
	// flood + 20% bidirectional loss, no rate limit
	"loss20_flood": func() ctrlCase {
		c := defaultCtrlCase("loss20_flood")
		c.Netem.DelayUp, c.Netem.DelayDown = 50, 50
		c.Netem.LossUp, c.Netem.LossDown = 0.20, 0.20
		return c
	},
	// the reported failing scenario: 2 Mbps SHARED bottleneck + 20% loss +
	// flood. Documented pathology: Ctrl-C queues behind the output flood in
	// the ONE shared bottleneck queue (queue HOL), and the confirmation
	// marker is buried in the output backlog behind it.
	"bottleneck_shared": func() ctrlCase {
		c := defaultCtrlCase("bottleneck_shared")
		c.Netem.Shared = true
		c.Netem.DelayUp, c.Netem.DelayDown = 50, 50
		c.Netem.LossUp, c.Netem.LossDown = 0.20, 0.20
		c.Netem.RateUp = 250_000 // 2 Mbps = 250_000 B/s for BOTH directions, one queue
		return c
	},
	// 2 Mbps per-direction queues: the input keeps a fast dedicated queue.
	// The downlink-only saturation does NOT delay Ctrl-C (stable, asserted);
	// the confirmation latency is data only — it swings between ~2 s and
	// >40 s across runs with the KCP retransmit luck on the collapsed
	// downlink goodput, which is too brittle to assert either way.
	"bottleneck_split": func() ctrlCase {
		c := defaultCtrlCase("bottleneck_split")
		c.Netem.DelayUp, c.Netem.DelayDown = 50, 50
		c.Netem.LossUp, c.Netem.LossDown = 0.20, 0.20
		c.Netem.RateUp = 250_000
		c.Netem.RateDown = 250_000
		c.Expect = ctrlExpectSigintOnly
		return c
	},
	// downlink bottleneck only; uplink unlimited (uplink loss still applies)
	"bottleneck_upclean": func() ctrlCase {
		c := defaultCtrlCase("bottleneck_upclean")
		c.Netem.DelayUp, c.Netem.DelayDown = 50, 50
		c.Netem.LossUp, c.Netem.LossDown = 0.20, 0.20
		c.Netem.RateDown = 250_000
		return c
	},
	// shared bottleneck + 64 KB paste before Ctrl-C with a child that NEVER
	// reads stdin: two stacked head-of-line blocks (saturated shared queue +
	// full 4 KB PTY input buffer). Documented pathology: Ctrl-C never
	// delivered while the paste is stuck ahead of it.
	"paste_block": func() ctrlCase {
		c := defaultCtrlCase("paste_block")
		c.Netem.Shared = true
		c.Netem.DelayUp, c.Netem.DelayDown = 50, 50
		c.Netem.LossUp, c.Netem.LossDown = 0.20, 0.20
		c.Netem.RateUp = 250_000
		c.PasteKB = 64
		c.Expect = ctrlExpectNoSigint
		return c
	},
	// paste + flood over a CLEAN link, child never reads stdin: isolates the
	// PTY input-buffer head-of-line block from all network effects. If Ctrl-C
	// is not delivered here, the 4 KB ldisc buffer alone is sufficient to
	// swallow control input behind a paste.
	"paste_baseline": func() ctrlCase {
		c := defaultCtrlCase("paste_baseline")
		c.Netem.DelayUp, c.Netem.DelayDown = 50, 50
		c.PasteKB = 64
		c.Expect = ctrlExpectNoSigint
		return c
	},
	// paste + flood + shared bottleneck, child READS stdin continuously
	// (models Claude Code / Pi: the agent's input thread drains stdin while
	// its output floods). The PTY never fills, so Ctrl-C is delayed only by
	// the paste's transit through the saturated shared queue.
	"paste_shared_reading": func() ctrlCase {
		c := defaultCtrlCase("paste_shared_reading")
		c.Netem.Shared = true
		c.Netem.DelayUp, c.Netem.DelayDown = 50, 50
		c.Netem.LossUp, c.Netem.LossDown = 0.20, 0.20
		c.Netem.RateUp = 250_000
		c.ChildMode = "floodread"
		c.PasteKB = 64
		c.Expect = ctrlExpectSigintOnly
		return c
	},
	// slow client (terminal rendering), no loss/rate: does client-side output
	// backpressure (smux window) block the control path?
	"slow_client": func() ctrlCase {
		c := defaultCtrlCase("slow_client")
		c.Netem.DelayUp, c.Netem.DelayDown = 50, 50
		c.DrainBPS = 200_000 // client renders output at ~200 KB/s
		return c
	},
}

// ---------------------------------------------------------------------------
// results
// ---------------------------------------------------------------------------

type ctrlSample struct {
	InjectMonoNS int64    `json:"inject_mono_ns"`
	CtrlMs       float64  `json:"ctrl_ms"` // inject -> SIGINT (side channel)
	EchoMs       *float64 `json:"echo_ms"` // inject -> "^C" visible in client output
}

type ctrlResult struct {
	Case    string          `json:"case"`
	Netem   ctrlNetemConfig `json:"netem"`
	Expect  string          `json:"expect"`
	OK      bool            `json:"ok"`
	Failure string          `json:"failure,omitempty"`

	ChildMode string `json:"child_mode"`
	PasteKB   int    `json:"paste_kb"`
	WarmupSec int    `json:"warmup_sec"`
	DrainBPS  int64  `json:"drain_bps"`

	// timestamps (CLOCK_MONOTONIC ns) and derived deltas (ms)
	TInject        int64 `json:"t_inject_ns"`
	TPipeWriteDone int64 `json:"t_pipe_write_done_ns"`
	TSigint        int64 `json:"t_sigint_ns"`
	TLastWrite     int64 `json:"t_lastwrite_ns"`
	TChildMarker   int64 `json:"t_child_marker_ns"`
	TClientMarker  int64 `json:"t_client_marker_ns"`
	TPasteInject   int64 `json:"t_paste_inject_ns,omitempty"`
	TPipePasteDone int64 `json:"t_pipe_paste_done_ns,omitempty"`

	CtrlPathMs       *float64 `json:"ctrl_path_ms"`       // T_sigint - T_inject
	PipeWriteMs      *float64 `json:"pipe_write_ms"`      // client-local stdin pipe write
	ChildReactMs     *float64 `json:"child_react_ms"`     // T_lastwrite - T_sigint
	MarkerTravelMs   *float64 `json:"marker_travel_ms"`   // T_client_marker - T_child_marker
	PerceivedMs      *float64 `json:"perceived_total_ms"` // T_client_marker - T_inject
	PastePipeWriteMs *float64 `json:"paste_pipe_write_ms,omitempty"`

	Samples   []ctrlSample `json:"samples,omitempty"`
	CtrlP50Ms *float64     `json:"ctrl_p50_ms,omitempty"`
	CtrlP95Ms *float64     `json:"ctrl_p95_ms,omitempty"`
	CtrlMaxMs *float64     `json:"ctrl_max_ms,omitempty"`
	EchoP50Ms *float64     `json:"echo_p50_ms,omitempty"`
	EchoP95Ms *float64     `json:"echo_p95_ms,omitempty"`

	ChildWroteBytes     uint64 `json:"child_wrote_bytes"`
	ClientBytesAtMarker uint64 `json:"client_bytes_at_marker"`
	ClientBytesTotal    uint64 `json:"client_bytes_total"`
	DiscardWarnings     int    `json:"discard_warnings"` // "tsshd discarded" notices seen

	Relay            ctrlRelayStats `json:"relay"`
	QLenUpAtInject   *int           `json:"qlen_up_pkts_at_inject"`
	QLenDownAtInject *int           `json:"qlen_down_pkts_at_inject"`
}

// ---------------------------------------------------------------------------
// the harness
// ---------------------------------------------------------------------------

func TestControlLatencyUnderFlood(t *testing.T) {
	caseName := os.Getenv("TSSHD_CTRL_BENCH")
	if caseName == "" {
		t.Skip("set TSSHD_CTRL_BENCH=<case> to run this benchmark (see benchmarks/control-latency/README.md)")
	}
	mk, ok := ctrlCases[caseName]
	if !ok {
		names := make([]string, 0, len(ctrlCases))
		for n := range ctrlCases {
			names = append(names, n)
		}
		sort.Strings(names)
		t.Fatalf("unknown case %q, known cases: %s", caseName, strings.Join(names, ", "))
	}
	cfg := mk()
	res := ctrlRunCase(t, cfg)

	if out := os.Getenv("TSSHD_CTRL_BENCH_OUT"); out != "" {
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err == nil {
			b, _ := json.MarshalIndent(res, "", "  ")
			if err := os.WriteFile(out, b, 0o644); err != nil {
				t.Logf("write result %s failed: %v", out, err)
			}
		}
	}

	ctrlLogResult(t, res)
	if !res.OK {
		t.Errorf("case %s failed: %s", caseName, res.Failure)
	}
}

func ctrlQuoteArg(s string) string { return strconv.Quote(s) }

// client-side drain state, shared between the drain loop and the harness.
type ctrlDrainState struct {
	mu              sync.Mutex
	bytes           uint64
	markerTNS       int64 // 0 = not seen
	markerBytes     uint64
	discardWarnings int
	echoTimes       []int64 // mono ns of each "^C" echo sighting
	capNSPerByte    float64
	capNextFree     int64
	dumpedChunks    int32

	// scan state: scanBuf keeps the tail so patterns split across reads are
	// matched exactly once (per-pattern counters are recomputed after trim).
	scanBuf        []byte
	countedEcho    int
	countedDiscard int
}

var (
	ctrlEchoPat    = []byte("^C")
	ctrlDiscardPat = []byte("tsshd discarded")
)

func (d *ctrlDrainState) record(n int, chunk []byte) {
	if os.Getenv("TSSHD_CTRL_BENCH_DEBUG") != "" && atomic.AddInt32(&d.dumpedChunks, 1) <= 6 {
		safe := chunk
		if len(safe) > 400 {
			safe = safe[:400]
		}
		fmt.Printf("[DRAIN %d] %q\n", atomic.LoadInt32(&d.dumpedChunks), safe)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	now := ctrlMonoNS()
	d.bytes += uint64(n)
	d.scanBuf = append(d.scanBuf, chunk...)

	if d.markerTNS == 0 && bytes.Contains(d.scanBuf, []byte(ctrlMarker)) {
		d.markerTNS = now
		d.markerBytes = d.bytes
	}
	if c := bytes.Count(d.scanBuf, ctrlDiscardPat); c > d.countedDiscard {
		d.discardWarnings += c - d.countedDiscard
		d.countedDiscard = c
	}
	if c := bytes.Count(d.scanBuf, ctrlEchoPat); c > d.countedEcho {
		for i := d.countedEcho; i < c; i++ {
			d.echoTimes = append(d.echoTimes, now)
		}
		d.countedEcho = c
	}

	// keep only the longest-pattern tail minus one byte
	keep := len(ctrlMarker) - 1
	if len(d.scanBuf) > keep {
		d.scanBuf = append(d.scanBuf[:0], d.scanBuf[len(d.scanBuf)-keep:]...)
		// re-credit matches now fully inside the tail so they are not
		// counted again when the next chunk arrives
		d.countedEcho = bytes.Count(d.scanBuf, ctrlEchoPat)
		d.countedDiscard = bytes.Count(d.scanBuf, ctrlDiscardPat)
	}
}

func (d *ctrlDrainState) throttle(n int) {
	if d.capNSPerByte <= 0 {
		return
	}
	d.mu.Lock()
	if d.capNextFree == 0 {
		// anchor the budget to the clock on first use; starting from the
		// zero value would compare against a huge monotonic uptime and never
		// sleep at all (the cap silently became a no-op)
		d.capNextFree = ctrlMonoNS()
	}
	d.capNextFree += int64(float64(n) * d.capNSPerByte)
	next := d.capNextFree
	d.mu.Unlock()
	if wait := next - ctrlMonoNS(); wait > 0 {
		time.Sleep(time.Duration(wait))
	}
}

func (d *ctrlDrainState) markerTime() int64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.markerTNS
}

func ctrlRunCase(t *testing.T, cfg ctrlCase) *ctrlResult {
	res := &ctrlResult{
		Case: cfg.Netem.Name, Netem: cfg.Netem, Expect: cfg.Expect.String(),
		ChildMode: cfg.ChildMode,
		PasteKB:   cfg.PasteKB, WarmupSec: int(cfg.Warmup / time.Second),
		DrainBPS: cfg.DrainBPS, OK: false,
	}

	// ---- side channel ----
	sockDir := t.TempDir()
	sockPath := filepath.Join(sockDir, "side.sock")
	events, lnCloser, err := ctrlSideChannelListen(sockPath)
	if err != nil {
		res.Failure = err.Error()
		return res
	}
	defer func() { _ = lnCloser.Close() }()

	// ---- server (in-process, real KCP listener + real PTY sessions) ----
	// SSH_CONNECTION (set when this box is reached over SSH) makes
	// getUdpAddrs bind only the SSH interface; neutralize it for the test so
	// the server also binds loopback, where the relay forwards to it.
	savedSSHConn := os.Getenv("SSH_CONNECTION")
	_ = os.Setenv("SSH_CONNECTION", "")
	serverArgs := &tsshdArgs{KCP: true, IPv4: true, ConnectTimeout: 10 * time.Second}
	info, _, err := initServer(serverArgs)
	_ = os.Setenv("SSH_CONNECTION", savedSSHConn)
	if err != nil {
		res.Failure = fmt.Sprintf("initServer failed: %v", err)
		return res
	}
	serverAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: int(info.Port)}

	// ---- netem relay between client and server ----
	relay, err := newCtrlRelay(cfg.Netem, serverAddr)
	if err != nil {
		res.Failure = err.Error()
		return res
	}
	relay.start()
	defer relay.close()
	// always capture the final relay picture, even on early failure paths
	defer func() { res.Relay = relay.stats() }()

	// ---- client (the same transport library tssh uses) ----
	client, err := NewSshUdpClient(&UdpClientOptions{
		ServerInfo:       info,
		TsshdAddr:        relay.addr().String(),
		SessionName:      "ctrlbench",
		AliveTimeout:     10 * 24 * time.Hour,
		IntervalTime:     cfg.HeartbeatInterval,
		HeartbeatTimeout: cfg.HeartbeatTimeout,
		ConnectTimeout:   10 * time.Second,
	})
	if err != nil {
		res.Failure = fmt.Sprintf("NewSshUdpClient failed: %v", err)
		return res
	}
	defer func() { _ = client.Close() }()

	session, err := client.NewSession()
	if err != nil {
		res.Failure = fmt.Sprintf("NewSession failed: %v", err)
		return res
	}
	defer func() { _ = session.Close() }()

	if err := session.RequestPty("xterm-256color", 50, 200, ssh.TerminalModes{}); err != nil {
		res.Failure = fmt.Sprintf("RequestPty failed: %v", err)
		return res
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		res.Failure = err.Error()
		return res
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		res.Failure = err.Error()
		return res
	}

	// ---- client output drain loop (models the local terminal) ----
	drain := &ctrlDrainState{}
	if cfg.DrainBPS > 0 {
		drain.capNSPerByte = 1e9 / float64(cfg.DrainBPS)
	}
	drainDone := make(chan struct{})
	go func() {
		defer close(drainDone)
		buf := make([]byte, 32*1024)
		for {
			n, err := stdout.Read(buf)
			if n > 0 {
				drain.record(n, buf[:n])
				drain.throttle(n)
			}
			if err != nil {
				return
			}
		}
	}()

	// ---- start the child under the server-side PTY ----
	bin, _ := os.Executable()
	if bin == "" {
		bin = os.Args[0]
	}
	childCmd := strings.Join([]string{
		ctrlQuoteArg(bin), "--ctrlbench-child", cfg.ChildMode,
		ctrlQuoteArg(sockPath), ctrlQuoteArg(strconv.Itoa(cfg.CtrlCount)),
	}, " ")
	if err := session.Start(childCmd); err != nil {
		res.Failure = fmt.Sprintf("session.Start failed: %v", err)
		return res
	}

	// wait for child READY (consume nothing else)
	ready := false
	deadline := time.After(20 * time.Second)
	for !ready {
		select {
		case ev, ok := <-events:
			if !ok {
				res.Failure = "side channel closed before READY"
				return res
			}
			if ev.Name == "READY" {
				ready = true
			}
		case <-deadline:
			res.Failure = "timeout waiting for child READY"
			return res
		}
	}

	if cfg.ChildMode == "ctrlcount" {
		ctrlRunCountCase(cfg, res, events, stdin, drain)
	} else {
		ctrlRunFloodCase(cfg, res, events, relay, stdin, drain)
	}

	// ---- final accounting ----
	_ = stdin.Close()
	select {
	case <-drainDone:
	case <-time.After(30 * time.Second):
		t.Logf("drain loop did not finish; continuing")
	}
	drain.mu.Lock()
	res.ClientBytesTotal = drain.bytes
	res.DiscardWarnings = drain.discardWarnings
	res.TClientMarker = drain.markerTNS
	if res.ClientBytesAtMarker == 0 {
		res.ClientBytesAtMarker = drain.markerBytes
	}
	drain.mu.Unlock()
	res.Relay = relay.stats()

	// ---- derived metrics ----
	setf := func(dst **float64, from, to int64) {
		if from > 0 && to > 0 {
			v := float64(to-from) / 1e6
			*dst = &v
		}
	}
	setf(&res.CtrlPathMs, res.TInject, res.TSigint)
	setf(&res.PipeWriteMs, res.TInject, res.TPipeWriteDone)
	setf(&res.ChildReactMs, res.TSigint, res.TLastWrite)
	setf(&res.MarkerTravelMs, res.TChildMarker, res.TClientMarker)
	setf(&res.PerceivedMs, res.TInject, res.TClientMarker)
	setf(&res.PastePipeWriteMs, res.TPasteInject, res.TPipePasteDone)

	if cfg.ChildMode == "ctrlcount" {
		ctrls := make([]float64, 0, len(res.Samples))
		for _, s := range res.Samples {
			ctrls = append(ctrls, s.CtrlMs)
		}
		if len(ctrls) > 0 {
			p50 := ctrlPercentile(ctrls, 0.50)
			p95 := ctrlPercentile(ctrls, 0.95)
			mx := ctrlPercentile(ctrls, 1.0)
			res.CtrlP50Ms, res.CtrlP95Ms, res.CtrlMaxMs = &p50, &p95, &mx
		}
		drain.mu.Lock()
		echos := drain.echoTimes
		drain.mu.Unlock()
		if len(echos) > 0 {
			es := make([]float64, 0, len(echos))
			for i := range res.Samples {
				if i < len(echos) && res.Samples[i].InjectMonoNS > 0 {
					v := float64(echos[i]-res.Samples[i].InjectMonoNS) / 1e6
					res.Samples[i].EchoMs = &v
					if v >= 0 {
						es = append(es, v)
					}
				}
			}
			if len(es) > 0 {
				p50 := ctrlPercentile(es, 0.50)
				p95 := ctrlPercentile(es, 0.95)
				res.EchoP50Ms, res.EchoP95Ms = &p50, &p95
			}
		}
	}

	res.OK = res.Failure == "" && (cfg.ChildMode == "ctrlcount" || res.TSigint > 0) &&
		(cfg.ChildMode == "ctrlcount" || res.TClientMarker > 0)
	if res.OK == false && res.Failure == "" {
		if cfg.ChildMode != "ctrlcount" && res.TSigint == 0 {
			res.Failure = "SIGINT never delivered to the child"
		} else if cfg.ChildMode != "ctrlcount" && res.TClientMarker == 0 {
			res.Failure = "client never saw the post-SIGINT marker"
		}
	}
	switch cfg.Expect {
	case ctrlExpectNoSigint:
		// documented pathology: assert the control input is swallowed
		res.OK = res.TSigint == 0
	case ctrlExpectNoMarker:
		// documented pathology: SIGINT arrives, the confirmation does not
		res.OK = res.TSigint > 0 && res.TClientMarker == 0
	case ctrlExpectSigintOnly:
		// document the paste transit delay; marker timing is informational
		res.OK = res.TSigint > 0
	}
	return res
}

// ctrlRunFloodCase: warmup -> (optional paste) -> Ctrl-C -> collect events.
func ctrlRunFloodCase(cfg ctrlCase, res *ctrlResult, events <-chan ctrlEvent,
	relay *ctrlRelay, stdin io.WriteCloser, drain *ctrlDrainState) {

	// consume events during warmup (W progress probes), then proceed
	warmupDeadline := ctrlMonoNS() + cfg.Warmup.Nanoseconds()
	for ctrlMonoNS() < warmupDeadline {
		select {
		case ev, ok := <-events:
			if !ok {
				res.Failure = "side channel closed during warmup"
				return
			}
			if ev.Name == "SIGINT" || ev.Name == "LASTWRITE" {
				res.Failure = "child stopped before Ctrl-C injection: " + ev.Name
				return
			}
		case <-time.After(time.Duration(warmupDeadline-ctrlMonoNS()) * time.Nanosecond):
		}
	}

	up, down := relay.qlenSnapshot()
	res.QLenUpAtInject, res.QLenDownAtInject = &up, &down

	if cfg.PasteKB > 0 {
		paste := bytes.Repeat([]byte{'x'}, cfg.PasteKB*1024-1)
		paste = append(paste, '\n')
		res.TPasteInject = ctrlMonoNS()
		_, err := stdin.Write(paste)
		res.TPipePasteDone = ctrlMonoNS()
		if err != nil {
			res.Failure = fmt.Sprintf("paste write failed: %v", err)
			return
		}
	}

	res.TInject = ctrlMonoNS()
	if _, err := stdin.Write([]byte{0x03}); err != nil {
		res.Failure = fmt.Sprintf("ctrl-c write failed: %v", err)
		return
	}
	res.TPipeWriteDone = ctrlMonoNS()

	deadline := time.After(cfg.WaitTimeout)
	for done := false; !done; {
		select {
		case ev, ok := <-events:
			if !ok {
				res.Failure = "side channel closed unexpectedly"
				return
			}
			switch ev.Name {
			case "SIGINT":
				res.TSigint = ev.MonoNS
			case "LASTWRITE":
				res.TLastWrite = ev.MonoNS
				res.ChildWroteBytes = uint64(ev.Extra)
			case "MARKERWRITTEN":
				res.TChildMarker = ev.MonoNS
			case "EXIT":
				done = true
			}
		case <-deadline:
			res.Failure = fmt.Sprintf("timeout after %v: sigint=%v lastwrite=%v marker=%v",
				cfg.WaitTimeout, res.TSigint != 0, res.TLastWrite != 0, res.TChildMarker != 0)
			return
		}
	}

	// allow some drain time for the marker to become client-visible
	giveUp := time.After(10 * time.Second)
	for drain.markerTime() == 0 {
		select {
		case <-giveUp:
			return // absence itself is a result (marker lost in discard machinery)
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// ctrlRunCountCase: N Ctrl-C samples, no flood. Control-path and "^C"-echo
// latency distribution under pure loss.
func ctrlRunCountCase(cfg ctrlCase, res *ctrlResult, events <-chan ctrlEvent,
	stdin io.WriteCloser, drain *ctrlDrainState) {

	target := cfg.CtrlCount
	for i := 0; i < target; i++ {
		t0 := ctrlMonoNS()
		if _, err := stdin.Write([]byte{0x03}); err != nil {
			res.Failure = fmt.Sprintf("ctrl-c write failed: %v", err)
			return
		}
		timeout := time.After(10 * time.Second)
	waitSig:
		for {
			select {
			case ev, ok := <-events:
				if !ok {
					res.Failure = "side channel closed"
					return
				}
				switch ev.Name {
				case "SIGINT":
					res.Samples = append(res.Samples, ctrlSample{
						InjectMonoNS: t0,
						CtrlMs:       float64(ev.MonoNS-t0) / 1e6,
					})
					break waitSig
				case "EXIT":
					res.Failure = "child exited before all samples"
					return
				}
			case <-timeout:
				res.Failure = fmt.Sprintf("sample %d: no SIGINT within 10s", i)
				return
			}
		}
		select {
		case <-time.After(300 * time.Millisecond):
		case ev, ok := <-events:
			if ok && ev.Name == "EXIT" {
				return
			}
		}
	}

	// drain remaining child events (EXIT expected)
	idle := time.After(2 * time.Second)
	for {
		select {
		case _, ok := <-events:
			if !ok {
				return
			}
		case <-idle:
			return
		}
	}
}

// ---------------------------------------------------------------------------
// reporting
// ---------------------------------------------------------------------------

func ctrlPercentile(xs []float64, p float64) float64 {
	if len(xs) == 0 {
		return math.NaN()
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	idx := int(math.Ceil(float64(len(s))*p)) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(s) {
		idx = len(s) - 1
	}
	return s[idx]
}

func ctrlLogResult(t *testing.T, res *ctrlResult) {
	f := func(p *float64) string {
		if p == nil {
			return "-"
		}
		return fmt.Sprintf("%.1f", *p)
	}
	t.Logf("=== control-latency case: %s (child=%s) ===", res.Case, res.ChildMode)
	if res.ChildMode == "ctrlcount" {
		t.Logf("samples=%d ctrl: p50=%s p95=%s max=%s ms | echo: p50=%s p95=%s ms",
			len(res.Samples), f(res.CtrlP50Ms), f(res.CtrlP95Ms), f(res.CtrlMaxMs),
			f(res.EchoP50Ms), f(res.EchoP95Ms))
	} else {
		t.Logf("ctrl_path (inject->SIGINT)       : %s ms", f(res.CtrlPathMs))
		t.Logf("client pipe write                : %s ms", f(res.PipeWriteMs))
		t.Logf("child react (SIGINT->lastwrite)  : %s ms", f(res.ChildReactMs))
		t.Logf("marker travel (child->client)    : %s ms", f(res.MarkerTravelMs))
		t.Logf("perceived total (inject->client) : %s ms", f(res.PerceivedMs))
		if res.PastePipeWriteMs != nil {
			t.Logf("paste pipe write (%d KB)         : %s ms", res.PasteKB, f(res.PastePipeWriteMs))
		}
		t.Logf("child wrote %d B; client got %d B at marker, %d B total; discard_warnings=%d",
			res.ChildWroteBytes, res.ClientBytesAtMarker, res.ClientBytesTotal, res.DiscardWarnings)
	}
	t.Logf("relay: up enq=%d loss=%d qfull=%d maxq=%d | down enq=%d loss=%d qfull=%d maxq=%d",
		res.Relay.Up.Enqueued, res.Relay.Up.DroppedLoss, res.Relay.Up.DroppedQueue, res.Relay.Up.MaxQLenPackets,
		res.Relay.Down.Enqueued, res.Relay.Down.DroppedLoss, res.Relay.Down.DroppedQueue, res.Relay.Down.MaxQLenPackets)
	t.Logf("qlen@inject: up=%v down=%v pkts", ctrlPtrToInt(res.QLenUpAtInject), ctrlPtrToInt(res.QLenDownAtInject))
	if res.Failure != "" {
		t.Logf("FAILURE: %s", res.Failure)
	}
}

func ctrlPtrToInt(p *int) int {
	if p == nil {
		return -1
	}
	return *p
}
