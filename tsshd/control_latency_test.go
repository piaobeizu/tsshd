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
	"os/exec"
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

type ctrlDirection uint8

const (
	ctrlUp ctrlDirection = iota
	ctrlDown
)

type ctrlPkt struct {
	data      []byte
	dest      *net.UDPAddr
	direction ctrlDirection
	readyAt   int64
	ingress   int64
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
	mu       sync.Mutex
	pkts     []ctrlPkt
	limit    int
	loss     float64
	delayNS  int64
	rate     float64 // bytes/sec, 0 = unlimited
	lastEgr  int64
	stats    ctrlQStats
	dirStats [2]ctrlQStats
	rng      *rand.Rand
	qlenLog  []ctrlQLenSample
	closeCh  chan struct{}
	closed   bool
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
		q.dirStats[p.direction].DroppedLoss++
		q.dirStats[p.direction].DroppedBytes += uint64(len(p.data))
		return false
	}
	if len(q.pkts) >= q.limit {
		q.stats.DroppedQueue++
		q.stats.DroppedBytes += uint64(len(p.data))
		q.dirStats[p.direction].DroppedQueue++
		q.dirStats[p.direction].DroppedBytes += uint64(len(p.data))
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
	ds := &q.dirStats[p.direction]
	ds.Enqueued++
	ds.EnqueuedBytes += uint64(len(p.data))
	if l := len(q.pkts); l > q.stats.MaxQLenPackets {
		q.stats.MaxQLenPackets = l
	}
	if b := q.byteLenLocked(); b > q.stats.MaxQLenBytes {
		q.stats.MaxQLenBytes = b
	}
	// In shared mode these maxima describe occupancy of the shared FIFO at
	// the moment this direction enqueued. They are intentionally not summed.
	ds.MaxQLenPackets = max(ds.MaxQLenPackets, len(q.pkts))
	ds.MaxQLenBytes = max(ds.MaxQLenBytes, q.byteLenLocked())
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
		q.dirStats[head.direction].Egressed++
		q.dirStats[head.direction].EgressedBytes += uint64(len(head.data))
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
	Shared    bool       `json:"shared"`
	Up        ctrlQStats `json:"up"`
	Down      ctrlQStats `json:"down"`
	Aggregate ctrlQStats `json:"aggregate"`
}

type ctrlRelay struct {
	conn       *net.UDPConn
	serverAddr *net.UDPAddr
	clientAddr atomic.Pointer[net.UDPAddr]

	shared  bool
	dropAll atomic.Bool
	up      *ctrlQ
	down    *ctrlQ
	wg      sync.WaitGroup
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
			if r.dropAll.Load() {
				continue
			}
			var dst *net.UDPAddr
			var isDownlink bool
			if addr.IP.Equal(r.serverAddr.IP) && addr.Port == r.serverAddr.Port {
				dst = r.clientAddr.Load()
				isDownlink = true
			} else {
				r.clientAddr.Store(addr)
				dst = r.serverAddr
			}
			if dst == nil {
				continue
			}
			data := make([]byte, n)
			copy(data, buf[:n])
			if isDownlink {
				r.down.enqueue(ctrlPkt{data: data, dest: dst, direction: ctrlDown})
			} else {
				r.up.enqueue(ctrlPkt{data: data, dest: dst, direction: ctrlUp})
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

func ctrlAddQStats(a, b ctrlQStats) ctrlQStats {
	return ctrlQStats{
		Enqueued:       a.Enqueued + b.Enqueued,
		Egressed:       a.Egressed + b.Egressed,
		DroppedLoss:    a.DroppedLoss + b.DroppedLoss,
		DroppedQueue:   a.DroppedQueue + b.DroppedQueue,
		EnqueuedBytes:  a.EnqueuedBytes + b.EnqueuedBytes,
		EgressedBytes:  a.EgressedBytes + b.EgressedBytes,
		DroppedBytes:   a.DroppedBytes + b.DroppedBytes,
		MaxQLenPackets: max(a.MaxQLenPackets, b.MaxQLenPackets),
		MaxQLenBytes:   max(a.MaxQLenBytes, b.MaxQLenBytes),
	}
}

func (r *ctrlRelay) stats() ctrlRelayStats {
	s := ctrlRelayStats{Shared: r.shared}
	r.up.mu.Lock()
	s.Up = r.up.dirStats[ctrlUp]
	if r.down == r.up {
		s.Down = r.up.dirStats[ctrlDown]
		s.Aggregate = r.up.stats // the shared physical queue, counted once
	}
	r.up.mu.Unlock()
	if r.down != r.up {
		r.down.mu.Lock()
		s.Down = r.down.dirStats[ctrlDown]
		r.down.mu.Unlock()
		s.Aggregate = ctrlAddQStats(s.Up, s.Down)
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
				// Do NOT close(ch): a connection handler goroutine can still
				// be scanning a live child socket and would panic on
				// "send on closed channel", killing the whole run process
				// before its artifact is written (measured: 3/3 paste_block
				// runs — the child outlives the harness and keeps sending
				// events through teardown). The channel is garbage-collected
				// with the process.
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

	// The side channel is the child's only tie to its run. When the harness
	// process dies (run end, failed run, inner go-test timeout) the accepted
	// connection's peer closes and Read unblocks; without this watchdog a
	// failed or aborted run leaks its child: flood children kept spinning at
	// ~90% CPU writing into a dead PTY (measured: seven leaked children while
	// iterating on the paste suites) and count children blocked forever on a
	// SIGINT that would never come.
	sideDead := make(chan struct{})
	var sideDeadOnce sync.Once
	markDead := func() { sideDeadOnce.Do(func() { close(sideDead) }) }
	var sendMu sync.Mutex
	send := func(name string, extraVal int64) {
		sendMu.Lock()
		defer sendMu.Unlock()
		if _, err := fmt.Fprintf(conn, "%s %d %d\n", name, ctrlMonoNS(), extraVal); err != nil {
			markDead()
		}
	}
	go func() {
		buf := make([]byte, 1)
		if _, err := conn.Read(buf); err != nil {
			markDead()
		}
	}()
	dead := func() bool {
		select {
		case <-sideDead:
			return true
		default:
			return false
		}
	}

	send("READY", 0)

	switch mode {
	case "flood":
		return ctrlChildFlood(send, dead)
	case "floodread":
		return ctrlChildFloodRead(send, dead)
	case "ctrlcount":
		target := int64(30)
		if v, e := strconv.ParseInt(extra, 10, 64); e == nil && v > 0 {
			target = v
		}
		return ctrlChildCtrlCount(send, dead, target)
	case "floodcount":
		target := int64(30)
		if v, e := strconv.ParseInt(extra, 10, 64); e == nil && v > 0 {
			target = v
		}
		return ctrlChildFloodCount(send, dead, target)
	case "floodreadcount":
		target := int64(30)
		if v, e := strconv.ParseInt(extra, 10, 64); e == nil && v > 0 {
			target = v
		}
		return ctrlChildFloodReadCount(send, dead, target)
	case "bulk":
		return ctrlChildBulk(send, 12*time.Second)
	case "roam":
		return ctrlChildRoam(send)
	case "integrity":
		return ctrlChildIntegrity(send)
	default:
		fmt.Fprintln(os.Stderr, "ctrlbench child: unknown mode", mode)
		return 2
	}
}

// ctrlChildFlood writes Claude-Code-style colored output lines as fast as the
// PTY accepts them, until SIGINT arrives. Then it writes the marker (which
// travels back through the transport) and exits. It also exits when the
// harness disappears (dead) or its writes stop being accepted: a dead PTY
// returns EIO and spinning on it would burn a core per leaked child.
func ctrlChildFlood(send func(string, int64), dead func() bool) int {
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
		for !stopped.Load() && !dead() {
			line++
			buf = buf[:0]
			buf = append(buf, "\x1b[32mflood\x1b[0m "...)
			buf = strconv.AppendInt(buf, int64(line), 10)
			buf = append(buf, ' ')
			for len(buf) < 205 {
				buf = append(buf, 'x')
			}
			buf = append(buf, '\n')
			n, err := os.Stdout.Write(buf)
			total += int64(n)
			if err != nil {
				break
			}
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
func ctrlChildFloodRead(send func(string, int64), dead func() bool) int {
	go func() { _, _ = io.Copy(io.Discard, os.Stdin) }()
	return ctrlChildFlood(send, dead)
}

// ctrlChildFloodReadCount is ctrlChildFloodCount plus the stdin drain loop
// of the reading-agent child. The per-sample 64 KB paste stimulus would be
// echoed back through the saturated downlink 30 times over a run (an extra
// ~1.9 MB the one-shot committed case never carried); echo stays off so the
// case measures the paste's uplink transit, not its own cumulative echo.
func ctrlChildFloodReadCount(send func(string, int64), dead func() bool, target int64) int {
	if err := ctrlDisableEcho(); err != nil {
		send("ECHO_OFF_FAILED", 0)
	}
	go func() { _, _ = io.Copy(io.Discard, os.Stdin) }()
	return ctrlChildFloodCount(send, dead, target)
}

// ctrlChildCtrlCount counts SIGINTs (no flood, does not exit on SIGINT).
// It gives up when the harness disappears: the run is over and no further
// interrupt will ever be sent, so blocking on signal delivery forever would
// just leak the process.
func ctrlChildCtrlCount(send func(string, int64), dead func() bool, target int64) int {
	sigCh := make(chan os.Signal, 64)
	signal.Notify(sigCh, syscall.SIGINT)
	for i := int64(1); i <= target; i++ {
		if dead() {
			return 1
		}
		<-sigCh
		send("SIGINT", i)
	}
	send("EXIT", 0)
	return 0
}

func ctrlChildFloodCount(send func(string, int64), dead func() bool, target int64) int {
	stopped := atomic.Bool{}
	floodDone := make(chan int64, 1)
	go func() {
		buf := bytes.Repeat([]byte{'f'}, 206)
		var total int64
		for !stopped.Load() && !dead() {
			n, err := os.Stdout.Write(buf)
			total += int64(n)
			if err != nil {
				break
			}
		}
		floodDone <- total
	}()
	// Prompt signal observation: a dedicated goroutine reports each SIGINT the
	// instant the kernel raises it. The child's own marker writes can block for
	// seconds inside a congested output path; when the counting loop shared a
	// goroutine with them, the NEXT sample's SIGINT was observed only after the
	// previous marker drained - fabricating input-delivery delay that belonged
	// to the confirmation path (found as ~900ms samples in input_slow_client
	// with an empty uplink queue on a clean link).
	sigCh := make(chan os.Signal, 64)
	signal.Notify(sigCh, syscall.SIGINT)
	sigDone := make(chan struct{})
	go func() {
		defer close(sigDone)
		for i := int64(1); i <= target; i++ {
			if dead() {
				return
			}
			<-sigCh
			send("SIGINT", i)
		}
	}()
	// The marker writer keeps per-interrupt ordering (the client pairs marker k
	// with sample k), but its PTY-write block now measures only confirmation
	// latency (row 2), never input delivery (row 1).
	markerSig := make(chan os.Signal, 64)
	signal.Notify(markerSig, syscall.SIGINT)
	for i := int64(1); i <= target; i++ {
		if dead() {
			return 1
		}
		<-markerSig
		_, _ = fmt.Fprintf(os.Stdout, "\r\n%s %d\r\n", ctrlMarker, i)
		send("MARKERWRITTEN", i)
	}
	<-sigDone
	stopped.Store(true)
	send("LASTWRITE", <-floodDone)
	time.Sleep(500 * time.Millisecond)
	send("EXIT", 0)
	return 0
}

func ctrlChildRoam(send func(string, int64)) int {
	// Periodic heartbeat in the PTY stream, not an endless transfer: absence
	// during the relay outage and resumption after it proves continuity.
	// Records are newline-terminated so the unchanged line-granular
	// pending-output policy can preserve them across a disconnect, and the
	// child reports its exact total so continuity is verifiable bytewise.
	// Output post-processing must be off: with ONLCR the PTY turns every
	// record's '\n' into '\r\n' and the client receives one byte more per
	// record than the child wrote, making exact equality undecidable
	// (measured: +732 B over 732 records).
	if err := ctrlRawOutput(); err != nil {
		send("RAW_OUT_FAILED", 0)
	}
	buf := append(bytes.Repeat([]byte{'r'}, 1023), '\n')
	started := time.Now()
	var total int64
	send("ROAM_START", 0)
	for time.Since(started) < 15*time.Second {
		if _, err := os.Stdout.Write(buf); err != nil {
			break
		}
		total += int64(len(buf))
		time.Sleep(20 * time.Millisecond)
	}
	send("ROAM_END", total)
	send("EXIT", 0)
	return 0
}

func ctrlChildBulk(send func(string, int64), duration time.Duration) int {
	// The echoed uplink would re-enter the downlink through the bottleneck and
	// fabricate a feedback storm no real bulk transfer has; without echo the two
	// directions stay separable and the degraded cases can measure both.
	if err := ctrlDisableEcho(); err != nil {
		send("ECHO_OFF_FAILED", 0)
	}
	buf := bytes.Repeat([]byte{'b'}, 32*1024)
	var inputBytes atomic.Int64
	go func() {
		in := make([]byte, 32*1024)
		for {
			n, err := os.Stdin.Read(in)
			inputBytes.Add(int64(n))
			if err != nil {
				return
			}
		}
	}()
	send("BULK_START", 0)
	go func() {
		time.Sleep(5 * time.Second)
		send("BULK_INPUT_5", inputBytes.Load())
		time.Sleep(5 * time.Second)
		send("BULK_INPUT_10", inputBytes.Load())
	}()
	start := time.Now()
	var total atomic.Int64
	const sourceBPS = int64(10_000_000) // bounded source, below the 100 Mbps clean link
	// A collapsed degraded path can block the child's stdout writes on PTY
	// backpressure for many minutes (measured: a split-case child stuck for
	// its whole 30 m suite timeout). Bound the write phase: past the grace,
	// abandon a stuck write, report the accepted-so-far totals and exit. The
	// goodput window is measured client-side and does not depend on the
	// child's tail finishing.
	writeDone := make(chan struct{})
	go func() {
		defer close(writeDone)
		deadline := start.Add(duration)
		for time.Now().Before(deadline) {
			n, err := os.Stdout.Write(buf)
			total.Add(int64(n))
			if err != nil {
				return
			}
			target := start.Add(time.Duration(float64(total.Load()) / float64(sourceBPS) * float64(time.Second)))
			if wait := time.Until(target); wait > 0 {
				time.Sleep(wait)
			}
		}
	}()
	select {
	case <-writeDone:
	case <-time.After(duration + 2*time.Minute):
	}
	send("BULK_INPUT_END", inputBytes.Load())
	send("BULK_END", total.Load())
	send("EXIT", 0)
	return 0
}

const (
	ctrlIntegrityBegin = "=== PTY-INTEGRITY-BEGIN ==="
	ctrlIntegrityEnd   = "=== PTY-INTEGRITY-END ==="
)

func ctrlIntegrityPayload() []byte {
	// Printable bytes excluding CR/LF avoid output-postprocessing ambiguity;
	// the framing is stripped before comparison.
	p := make([]byte, 1<<20)
	for i := range p {
		p[i] = byte('!' + (i*31+17)%90)
	}
	return p
}

func ctrlChildIntegrity(send func(string, int64)) int {
	time.Sleep(250 * time.Millisecond) // let the harness install the server-side PTY tap
	payload := ctrlIntegrityPayload()
	_, _ = os.Stdout.Write([]byte(ctrlIntegrityBegin))
	_, _ = os.Stdout.Write(payload)
	_, _ = os.Stdout.Write([]byte(ctrlIntegrityEnd))
	send("REFERENCE", int64(len(payload)))
	time.Sleep(time.Second) // keep the PTY open until the transport drains the framing
	send("EXIT", 0)
	return 0
}

// ctrlDisableEcho turns off PTY echo in the re-exec'd child (fd 0 is the PTY
// slave under the server session).
func ctrlDisableEcho() error {
	fd := int(os.Stdin.Fd())
	t, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return err
	}
	t.Lflag &^= unix.ECHO
	return unix.IoctlSetTermios(fd, unix.TCSETS, t)
}

// ctrlRawOutput disables PTY output post-processing (OPOST: ONLCR and
// friends) in the re-exec'd child, so the client receives exactly the bytes
// the child wrote and bytewise continuity is decidable.
func ctrlRawOutput() error {
	fd := int(os.Stdout.Fd())
	t, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return err
	}
	t.Oflag &^= unix.OPOST
	return unix.IoctlSetTermios(fd, unix.TCSETS, t)
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
	ChildMode string // "flood" | "floodread" | "ctrlcount" | "floodcount" | "floodreadcount" | "bulk" | "integrity"
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
	SampleTimeout     time.Duration // per-sample SIGINT patience in count modes (0 = 10 s)
	ReconnectOutage   time.Duration // non-zero: black-hole relay mid-transfer, then restore
	AttachAfterDetach bool          // detach first client and attach a second under load
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
	"bulk_clean": func() ctrlCase {
		c := defaultCtrlCase("bulk_clean")
		c.ChildMode = "bulk"
		c.Netem.DelayUp, c.Netem.DelayDown = 50, 50
		c.Netem.RateUp, c.Netem.RateDown = 12_500_000, 12_500_000 // 100 Mbps
		c.WaitTimeout = 30 * time.Second
		return c
	},
	"bulk_clean_cap200": func() ctrlCase {
		c := defaultCtrlCase("bulk_clean_cap200")
		c.ChildMode = "bulk"
		c.Netem.DelayUp, c.Netem.DelayDown = 50, 50
		c.Netem.RateUp, c.Netem.RateDown = 25_000_000, 25_000_000 // 200 Mbps cap
		c.WaitTimeout = 30 * time.Second
		return c
	},
	"bulk_bottleneck_shared": func() ctrlCase {
		c := defaultCtrlCase("bulk_bottleneck_shared")
		c.ChildMode = "bulk"
		c.Netem.Shared = true
		c.Netem.DelayUp, c.Netem.DelayDown = 50, 50
		c.Netem.LossUp, c.Netem.LossDown = 0.20, 0.20
		c.Netem.RateUp = 250_000
		// The child can sit blocked in its final stdout writes for minutes
		// while the collapsed path drains; patience must exceed the child's
		// own bounded write grace (12 s + 120 s) so every run completes.
		c.WaitTimeout = 180 * time.Second
		return c
	},
	"bulk_bottleneck_split": func() ctrlCase {
		c := defaultCtrlCase("bulk_bottleneck_split")
		c.ChildMode = "bulk"
		c.Netem.DelayUp, c.Netem.DelayDown = 50, 50
		c.Netem.LossUp, c.Netem.LossDown = 0.20, 0.20
		c.Netem.RateUp, c.Netem.RateDown = 250_000, 250_000
		// See bulk_bottleneck_shared: the degraded path can block the
		// child's tail writes; one seeded run hung >30 min at 45 s patience
		// before this bound existed.
		c.WaitTimeout = 180 * time.Second
		return c
	},
	"reconnect_roam": func() ctrlCase {
		c := defaultCtrlCase("reconnect_roam")
		c.ChildMode = "roam"
		c.Netem.DelayUp, c.Netem.DelayDown = 50, 50
		c.Netem.LossUp, c.Netem.LossDown = 0.20, 0.20
		c.Netem.RateUp, c.Netem.RateDown = 250_000, 250_000
		c.HeartbeatTimeout = time.Second
		c.ReconnectOutage = 3 * time.Second
		c.WaitTimeout = 45 * time.Second
		return c
	},
	"reconnect_attach": func() ctrlCase {
		c := defaultCtrlCase("reconnect_attach")
		c.ChildMode = "roam"
		c.Netem.DelayUp, c.Netem.DelayDown = 50, 50
		c.Netem.LossUp, c.Netem.LossDown = 0.20, 0.20
		c.Netem.RateUp, c.Netem.RateDown = 250_000, 250_000
		c.AttachAfterDetach = true
		c.WaitTimeout = 45 * time.Second
		return c
	},
	"integrity_clean": func() ctrlCase {
		c := defaultCtrlCase("integrity_clean")
		c.ChildMode = "integrity"
		c.WaitTimeout = 30 * time.Second
		return c
	},
	"integrity_flood": func() ctrlCase {
		c := defaultCtrlCase("integrity_flood")
		c.ChildMode = "integrity"
		c.Netem.DelayUp, c.Netem.DelayDown = 50, 50
		c.Netem.LossUp, c.Netem.LossDown = 0.20, 0.20
		c.WaitTimeout = 60 * time.Second
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

func init() {
	// Preserve the one-shot historical cases and add the >=30 sequential
	// samples required by row 1 against a surviving flood child.
	for _, base := range []string{"baseline", "loss20_flood", "slow_client", "bottleneck_upclean", "bottleneck_split", "bottleneck_shared"} {
		base := base
		ctrlCases["input_"+base] = func() ctrlCase {
			c := ctrlCases[base]()
			c.Netem.Name = "input_" + base
			c.ChildMode = "floodcount"
			c.CtrlCount = 30
			c.Expect = ctrlExpectOK
			c.WaitTimeout = 180 * time.Second
			if base == "bottleneck_shared" {
				// A pinned-full 1000-pkt shared FIFO needs ~4 s of drain per
				// newly accepted packet before loss-retransmit luck. 30 s
				// per-sample patience measures that tail instead of tripping
				// on it; the real no-SIGINT pathology stays asserted by the
				// paste cases.
				c.SampleTimeout = 30 * time.Second
			}
			return c
		}
	}
	// Row 1's paste case repeats its documented stimulus per sample: a 64 KB
	// paste written ahead of EVERY Ctrl-C, against the stdin-reading agent
	// child, so each sample measures the paste-transit delay it is named for.
	ctrlCases["input_paste_shared_reading"] = func() ctrlCase {
		c := ctrlCases["paste_shared_reading"]()
		c.Netem.Name = "input_paste_shared_reading"
		c.ChildMode = "floodreadcount"
		c.CtrlCount = 30
		c.Expect = ctrlExpectOK
		// The ^C is stream-ordered behind its own 64 KB paste; on the pinned
		// shared queue, kcp RTO backoff on the ordering-constrained paste
		// segments pushes single samples into a heavy, phase-correlated tail
		// without the input path being broken (paste_block keeps the no-SIGINT
		// assertion). Measured patience ladder: 90 s truncated 5 of 6 seeded
		// runs, 300 s truncated 1 of 3, 600 s censored consecutive samples in
		// 2 of 4 runs (one burned ~9 x 10 min until its process timeout). No
		// finite patience fully covers that tail, so the protocol is: 120 s
		// per-sample patience, a stuck attempt is CENSORED (recorded with the
		// bound as a lower bound, kept in the p95 input at that bound, its
		// late SIGINT drained via the child's interrupt ordinals). ONE censor
		// per run keeps the rank-29-of-30 p95 on a completed sample; the
		// SECOND censor makes the p95 itself censored and aborts the run red
		// in bounded time (~5 min) with its artifact always written. The
		// censor count is itself the sharpest regression signal: with output
		// pacing (tsshd#6) the queue never pins and censors vanish.
		c.SampleTimeout = 120 * time.Second
		c.WaitTimeout = 180 * time.Second
		return c
	}
}

// ---------------------------------------------------------------------------
// results
// ---------------------------------------------------------------------------

type ctrlSample struct {
	InjectMonoNS int64    `json:"inject_mono_ns"`
	CtrlMs       float64  `json:"ctrl_ms"`   // inject -> SIGINT (side channel)
	EchoMs       *float64 `json:"echo_ms"`   // inject -> terminal echo
	AckMs        *float64 `json:"ack_ms"`    // inject -> covering bus ack; nil until feature lands
	MarkerMs     *float64 `json:"marker_ms"` // inject -> child confirmation marker

	// Censored marks a patience-censored attempt: CtrlMs is the patience
	// bound, a lower bound on the true (unobserved) value. Censored samples
	// stay IN the p95 input at that bound, so they sort above every
	// completed sample: with one censor the rank-29-of-30 p95 is still a
	// completed sample, and at two or more the p95 itself is censored and
	// the gate fails (see the row-1 gate contract).
	Censored bool `json:"censored,omitempty"`

	// Causal evidence for the bottleneck cases: the queue occupancy the packet
	// faced at inject (shared mode: the one physical FIFO), and the per-sample
	// paste pipe-write time when the case repeats its paste stimulus.
	QLenPktsAtInject *int     `json:"qlen_pkts_at_inject,omitempty"`
	PasteMs          *float64 `json:"paste_pipe_write_ms,omitempty"`
}

type ctrlBudgetMetrics struct {
	ConfirmationMs         *float64 `json:"confirmation_ms,omitempty"`
	ClientPayloadBytes     uint64   `json:"client_payload_bytes"`
	RelayEgressBytes       uint64   `json:"relay_egress_bytes"`
	RelayOfferedBytes      uint64   `json:"relay_offered_bytes"`
	EgressAmplification    *float64 `json:"egress_amplification,omitempty"`
	OfferedAmplification   *float64 `json:"offered_amplification,omitempty"`
	SharedQueueCountedOnce bool     `json:"shared_queue_counted_once"`
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

	Samples           []ctrlSample `json:"samples,omitempty"`
	CtrlP50Ms         *float64     `json:"ctrl_p50_ms,omitempty"`
	CtrlP95Ms         *float64     `json:"ctrl_p95_ms,omitempty"`
	CtrlMaxMs         *float64     `json:"ctrl_max_ms,omitempty"`
	CensoredSamples   int          `json:"censored_samples,omitempty"`
	EchoP50Ms         *float64     `json:"echo_p50_ms,omitempty"`
	EchoP95Ms         *float64     `json:"echo_p95_ms,omitempty"`
	ConfirmationP50Ms *float64     `json:"confirmation_p50_ms,omitempty"`
	ConfirmationP95Ms *float64     `json:"confirmation_p95_ms,omitempty"`

	AttachAfterDetach   bool    `json:"attach_after_detach,omitempty"`
	AttachObserved      bool    `json:"attach_observed,omitempty"`
	AttachMs            float64 `json:"attach_ms,omitempty"`
	ReconnectOutageMS   int64   `json:"reconnect_outage_ms,omitempty"`
	ReconnectObserved   bool    `json:"reconnect_observed,omitempty"`
	ReattachMs          float64 `json:"reattach_ms,omitempty"`
	BytesBeforeOutage   uint64  `json:"bytes_before_outage,omitempty"`
	BytesAfterReconnect uint64  `json:"bytes_after_reconnect,omitempty"`

	// These two observations currently require explicit feature-activation
	// switches. They never manufacture an ack/discard event when that feature
	// has not been implemented; missing events fail the corresponding gate.
	AckDelayMs      *float64 `json:"ack_delay_ms,omitempty"`
	MarkerDelayMs   *float64 `json:"marker_delay_ms,omitempty"`
	DiscardNoticeNS int64    `json:"discard_notice_ns,omitempty"`
	DiscardStart    uint64   `json:"discard_start,omitempty"`
	DiscardEnd      uint64   `json:"discard_end,omitempty"`
	SettledMs       *float64 `json:"settled_ms,omitempty"`

	GoodputWindowStartNS    int64   `json:"goodput_window_start_ns,omitempty"`
	GoodputWindowEndNS      int64   `json:"goodput_window_end_ns,omitempty"`
	GoodputBytes            uint64  `json:"goodput_bytes,omitempty"`
	GoodputBPS              float64 `json:"goodput_bps,omitempty"`
	UplinkGoodputBytes      uint64  `json:"uplink_goodput_bytes,omitempty"`
	UplinkGoodputBPS        float64 `json:"uplink_goodput_bps,omitempty"`
	UplinkBytesAt5Sec       uint64  `json:"uplink_bytes_at_5_sec,omitempty"`
	UplinkPayloadBytes      uint64  `json:"uplink_payload_bytes,omitempty"`
	IntegrityReferenceBytes uint64  `json:"integrity_reference_bytes,omitempty"`
	IntegrityReceivedBytes  uint64  `json:"integrity_received_bytes,omitempty"`
	IntegrityDiffBytes      uint64  `json:"integrity_diff_bytes,omitempty"`

	ChildWroteBytes     uint64 `json:"child_wrote_bytes"`
	ClientBytesAtMarker uint64 `json:"client_bytes_at_marker"`
	ClientBytesTotal    uint64 `json:"client_bytes_total"`
	DiscardWarnings     int    `json:"discard_warnings"` // "tsshd discarded" notices seen
	// Bus-reported discard accounting (client DiscardCallback): what the
	// unchanged pending-output policy says it dropped, in lines and bytes.
	DiscardedOutputLines uint64 `json:"discarded_output_lines,omitempty"`
	DiscardedOutputBytes uint64 `json:"discarded_output_bytes,omitempty"`

	// Row-7 attach continuity reporting: the gap between what the child
	// wrote and what the clients received, and whether the discard
	// accounting explains it (see the reconnect-attach gate contract).
	ContinuityGapBytes    uint64 `json:"continuity_gap_bytes,omitempty"`
	ContinuityUnaccounted bool   `json:"continuity_unaccounted,omitempty"`

	// Harness bookkeeping (unexported, never serialized): which bulk uplink
	// reports arrived, so a silently missing direction measurement fails
	// the run instead of quietly omitting one side of the goodput.
	bulkInput5Seen   bool
	bulkInput10Seen  bool
	bulkInputEndSeen bool

	Relay            ctrlRelayStats    `json:"relay"`
	Budget           ctrlBudgetMetrics `json:"budget"`
	QLenUpAtInject   *int              `json:"qlen_up_pkts_at_inject"`
	QLenDownAtInject *int              `json:"qlen_down_pkts_at_inject"`
}

// ---------------------------------------------------------------------------
// the harness
// ---------------------------------------------------------------------------

type ctrlSuiteResult struct {
	Schema     int           `json:"schema"`
	Case       string        `json:"case"`
	Seed       int64         `json:"seed"`
	Runs       int           `json:"runs"`
	Provenance string        `json:"provenance"`
	Results    []*ctrlResult `json:"results"`
}

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
	runs := 3
	if v := os.Getenv("TSSHD_CTRL_BENCH_RUNS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			t.Fatalf("invalid TSSHD_CTRL_BENCH_RUNS=%q", v)
		}
		runs = n
	}
	if os.Getenv("TSSHD_CTRL_BENCH_CHILD_RUN") == "" {
		// initServer owns package-global listeners/keys. Each seeded trial must
		// use a fresh process, or later runs silently connect to stale state.
		suite := ctrlSuiteResult{Schema: 2, Case: caseName, Runs: runs,
			Provenance: "measured by TestControlLatencyUnderFlood; CLOCK_MONOTONIC; isolated process per run"}
		for i := 0; i < runs; i++ {
			out := filepath.Join(t.TempDir(), fmt.Sprintf("run-%d.json", i+1))
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(exe, "-test.run=^TestControlLatencyUnderFlood$", "-test.v", "-test.timeout=90m")
			cmd.Env = append(os.Environ(), "TSSHD_CTRL_BENCH_CHILD_RUN=1",
				"TSSHD_CTRL_BENCH_RUNS=1", "TSSHD_CTRL_BENCH_OUT="+out)
			log, runErr := cmd.CombinedOutput()
			b, readErr := os.ReadFile(out)
			if readErr != nil {
				t.Errorf("run %d: %v; child: %s", i+1, readErr, log)
				continue
			}
			var child ctrlSuiteResult
			if err := json.Unmarshal(b, &child); err != nil || len(child.Results) != 1 {
				t.Errorf("run %d: invalid child artifact: %v; child: %s", i+1, err, log)
				continue
			}
			if i == 0 {
				suite.Seed = child.Seed
			}
			suite.Results = append(suite.Results, child.Results[0])
			if runErr != nil {
				t.Errorf("run %d failed: %v; child: %s", i+1, runErr, log)
			}
		}
		ctrlWriteSuite(t, suite)
		return
	}
	suite := ctrlSuiteResult{Schema: 2, Case: caseName, Runs: runs,
		Provenance: "measured by TestControlLatencyUnderFlood; CLOCK_MONOTONIC; single child run"}
	for i := 0; i < runs; i++ {
		cfg := mk()
		if i == 0 {
			suite.Seed = cfg.Netem.Seed
		}
		var res *ctrlResult
		t.Run(fmt.Sprintf("seed-%d-run-%d", cfg.Netem.Seed, i+1), func(t *testing.T) {
			res = ctrlRunCase(t, cfg)
			ctrlApplyCurrentGates(res)
			ctrlLogResult(t, res)
			if !res.OK {
				t.Errorf("case %s run %d failed: %s", caseName, i+1, res.Failure)
			}
		})
		suite.Results = append(suite.Results, res)
	}

	ctrlWriteSuite(t, suite)
}

func ctrlWriteSuite(t *testing.T, suite ctrlSuiteResult) {
	t.Helper()
	if out := os.Getenv("TSSHD_CTRL_BENCH_OUT"); out != "" {
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err == nil {
			b, _ := json.MarshalIndent(suite, "", "  ")
			if err := os.WriteFile(out, b, 0o644); err != nil {
				t.Logf("write result %s failed: %v", out, err)
			}
		}
	}
}

func ctrlQuoteArg(s string) string { return strconv.Quote(s) }

// client-side drain state, shared between the drain loop and the harness.
type ctrlByteSample struct {
	TNS   int64  `json:"t_ns"`
	Bytes uint64 `json:"bytes"`
}

type ctrlDrainState struct {
	mu              sync.Mutex
	bytes           uint64
	byteSamples     []ctrlByteSample
	capture         []byte
	captureEnabled  bool
	markerTNS       int64 // 0 = not seen
	markerBytes     uint64
	discardWarnings int
	echoTimes       []int64 // mono ns of each "^C" echo sighting
	markerTimes     []int64 // mono ns of every post-interrupt marker
	capNSPerByte    float64
	capNextFree     int64
	dumpedChunks    int32

	// scan state: scanBuf keeps the tail so patterns split across reads are
	// matched exactly once (per-pattern counters are recomputed after trim).
	scanBuf        []byte
	countedEcho    int
	countedMarker  int
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
	d.byteSamples = append(d.byteSamples, ctrlByteSample{TNS: now, Bytes: d.bytes})
	if d.captureEnabled {
		d.capture = append(d.capture, chunk...)
	}
	d.scanBuf = append(d.scanBuf, chunk...)

	if d.markerTNS == 0 && bytes.Contains(d.scanBuf, []byte(ctrlMarker)) {
		d.markerTNS = now
		d.markerBytes = d.bytes
	}
	if c := bytes.Count(d.scanBuf, []byte(ctrlMarker)); c > d.countedMarker {
		for i := d.countedMarker; i < c; i++ {
			d.markerTimes = append(d.markerTimes, now)
		}
		d.countedMarker = c
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
		d.countedMarker = bytes.Count(d.scanBuf, []byte(ctrlMarker))
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
	serverArgs := &tsshdArgs{KCP: true, IPv4: true, ConnectTimeout: 10 * time.Second,
		Attachable: cfg.AttachAfterDetach}
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
	// always capture the final relay picture, even on early failure paths;
	// recompute the budget metrics from the SAME final snapshot so the
	// artifact's amplification is recomputable from its own final
	// relay.aggregate counters (review finding: they were computed from an
	// earlier mid-accounting snapshot and disagreed with the final counters)
	defer func() {
		res.Relay = relay.stats()
		res.Budget = ctrlBudgetMetricsForResult(res)
	}()

	// ---- client (the same transport library tssh uses) ----
	var discardStats struct {
		lines, outBytes atomic.Uint64
	}
	client, err := NewSshUdpClient(&UdpClientOptions{
		ServerInfo:       info,
		TsshdAddr:        relay.addr().String(),
		SessionName:      "ctrlbench",
		AliveTimeout:     10 * 24 * time.Hour,
		IntervalTime:     cfg.HeartbeatInterval,
		HeartbeatTimeout: cfg.HeartbeatTimeout,
		ConnectTimeout:   10 * time.Second,
		DiscardCallback: func(_ []byte, lines, outBytes uint64) {
			discardStats.lines.Add(lines)
			discardStats.outBytes.Add(outBytes)
		},
	})
	if err != nil {
		res.Failure = fmt.Sprintf("NewSshUdpClient failed: %v", err)
		return res
	}
	defer func() { _ = client.Close() }()

	timeoutSeen := make(chan int64, 1)
	reconnectedSeen := make(chan int64, 1)
	if cfg.ReconnectOutage > 0 {
		client.OnHealthEvent(
			func() {
				select {
				case timeoutSeen <- ctrlMonoNS():
				default:
				}
			},
			func() {
				select {
				case reconnectedSeen <- ctrlMonoNS():
				default:
				}
			},
		)
	}

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
	drain := &ctrlDrainState{captureEnabled: cfg.ChildMode == "integrity"}
	if cfg.DrainBPS > 0 {
		drain.capNSPerByte = 1e9 / float64(cfg.DrainBPS)
	}
	var drainWG sync.WaitGroup
	startDrain := func(r io.Reader) {
		drainWG.Add(1)
		go func() {
			defer drainWG.Done()
			buf := make([]byte, 32*1024)
			for {
				n, err := r.Read(buf)
				if n > 0 {
					drain.record(n, buf[:n])
					drain.throttle(n)
				}
				if err != nil {
					return
				}
			}
		}()
	}
	startDrain(stdout)

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

	var serverCaptureMu sync.Mutex
	var serverCapture []byte
	if cfg.ChildMode == "integrity" {
		sess := getSessionByID(session.GetID())
		if sess == nil {
			res.Failure = "server session missing before integrity capture"
			return res
		}
		sess.screenBuf = make(chan []byte, 1000)
		go func(ch <-chan []byte) {
			for b := range ch {
				serverCaptureMu.Lock()
				serverCapture = append(serverCapture, b...)
				serverCaptureMu.Unlock()
			}
		}(sess.screenBuf)
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

	var uplinkWriterDone chan struct{}
	if cfg.ChildMode == "bulk" {
		// Both directions are measured in every bulk case: the child disables
		// PTY echo so the uplink does not re-enter the downlink through the
		// bottleneck (the legacy echo feedback storm).
		uplinkWriterDone = make(chan struct{})
		go func() {
			defer close(uplinkWriterDone)
			ctrlWriteBulkInput(stdin, 12*time.Second)
		}()
	}

	type attachOutcome struct {
		client  *SshUdpClient
		session *SshUdpSession
		relay   *ctrlRelay
		err     error
		ms      float64
	}
	attachDone := make(chan attachOutcome, 1)
	if cfg.AttachAfterDetach {
		res.AttachAfterDetach = true
		go func() {
			time.Sleep(5 * time.Second)
			drain.mu.Lock()
			res.BytesBeforeOutage = drain.bytes
			drain.mu.Unlock()
			id := session.GetID()
			client.Detach()
			t0 := ctrlMonoNS()
			relay2, err := newCtrlRelay(cfg.Netem, serverAddr)
			if err != nil {
				attachDone <- attachOutcome{err: fmt.Errorf("new attach relay: %w", err)}
				return
			}
			relay2.start()
			c2, err := NewSshUdpClient(&UdpClientOptions{
				ServerInfo: info, TsshdAddr: relay2.addr().String(), SessionName: "ctrlbench-attach",
				AliveTimeout: 10 * 24 * time.Hour, IntervalTime: cfg.HeartbeatInterval,
				HeartbeatTimeout: cfg.HeartbeatTimeout, ConnectTimeout: 10 * time.Second,
			})
			if err != nil {
				relay2.close()
				attachDone <- attachOutcome{err: fmt.Errorf("new attach client: %w", err)}
				return
			}
			s2, err := c2.NewSession()
			if err == nil {
				err = s2.RequestPty("xterm-256color", 50, 200, ssh.TerminalModes{})
			}
			var out2 io.Reader
			if err == nil {
				out2, err = s2.StdoutPipe()
			}
			if err == nil {
				startDrain(out2)
				err = s2.Attach(id)
			}
			attachDone <- attachOutcome{client: c2, session: s2, relay: relay2, err: err,
				ms: float64(ctrlMonoNS()-t0) / 1e6}
		}()
	}

	if cfg.ReconnectOutage > 0 {
		res.ReconnectOutageMS = cfg.ReconnectOutage.Milliseconds()
		go func() {
			time.Sleep(5 * time.Second)
			drain.mu.Lock()
			res.BytesBeforeOutage = drain.bytes
			drain.mu.Unlock()
			relay.dropAll.Store(true)
			time.Sleep(cfg.ReconnectOutage)
			relay.dropAll.Store(false)
		}()
	}

	if cfg.ChildMode == "ctrlcount" || cfg.ChildMode == "floodcount" || cfg.ChildMode == "floodreadcount" {
		ctrlRunCountCase(cfg, res, events, relay, stdin, drain)
	} else if cfg.ChildMode == "bulk" || cfg.ChildMode == "roam" || cfg.ChildMode == "integrity" {
		ctrlRunDataCase(cfg, res, events, drain)
		// Row 5 measures BOTH directions in every bulk case; a missing
		// child-side report means a direction was not measured, which is a
		// harness failure, not a zero goodput.
		if cfg.ChildMode == "bulk" && res.Failure == "" &&
			(!res.bulkInput5Seen || !res.bulkInput10Seen || !res.bulkInputEndSeen) {
			res.Failure = fmt.Sprintf("bulk child uplink reports incomplete (5s=%v 10s=%v end=%v); bidirectional goodput not measurable",
				res.bulkInput5Seen, res.bulkInput10Seen, res.bulkInputEndSeen)
		}
	} else {
		ctrlRunFloodCase(cfg, res, events, relay, stdin, drain)
	}

	if cfg.AttachAfterDetach {
		select {
		case outcome := <-attachDone:
			if outcome.relay != nil {
				defer outcome.relay.close()
			}
			if outcome.client != nil {
				defer func() { _ = outcome.client.Close() }()
			}
			if outcome.session != nil {
				defer func() { _ = outcome.session.Close() }()
			}
			if outcome.err != nil {
				if res.Failure == "" {
					res.Failure = fmt.Sprintf("attach after detach failed: %v", outcome.err)
				}
			} else {
				res.AttachObserved = true
				res.AttachMs = outcome.ms
			}
		case <-time.After(15 * time.Second):
			if res.Failure == "" {
				res.Failure = "attach after detach timed out"
			}
		}
	}

	// ---- final accounting ----
	if uplinkWriterDone != nil {
		// A client-side stdin write can block indefinitely when the smux
		// window stalls behind window updates lost on the degraded downlink
		// (measured: it hung a split suite run for its whole 30 m timeout
		// before this bound existed, and stalls ~1 run in 3 on
		// bulk_bottleneck_split). The goodput window is measured from the
		// child's BULK_INPUT reports, which do not depend on this writer
		// finishing, and the report-completeness gate above already fails any
		// run whose uplink data is actually missing — so a stalled writer is
		// abandoned with a log, not failed. The goroutine dies with the
		// process (each run is its own re-exec'd process).
		select {
		case <-uplinkWriterDone:
		case <-time.After(90 * time.Second):
			t.Logf("bulk uplink writer stalled >90s (smux window stall); abandoning it — child uplink reports complete=%v/%v/%v",
				res.bulkInput5Seen, res.bulkInput10Seen, res.bulkInputEndSeen)
		}
	}
	_ = stdin.Close()
	drainsDone := make(chan struct{})
	go func() { drainWG.Wait(); close(drainsDone) }()
	select {
	case <-drainsDone:
	case <-time.After(30 * time.Second):
		t.Logf("drain loop did not finish; continuing")
	}
	drain.mu.Lock()
	res.ClientBytesTotal = drain.bytes
	res.DiscardWarnings = drain.discardWarnings
	res.DiscardedOutputLines = discardStats.lines.Load()
	res.DiscardedOutputBytes = discardStats.outBytes.Load()
	res.TClientMarker = drain.markerTNS
	if res.ClientBytesAtMarker == 0 {
		res.ClientBytesAtMarker = drain.markerBytes
	}
	drain.mu.Unlock()
	if cfg.AttachAfterDetach {
		res.BytesAfterReconnect = res.ClientBytesTotal - min(res.ClientBytesTotal, res.BytesBeforeOutage)
		if (!res.AttachObserved || res.BytesAfterReconnect == 0) && res.Failure == "" {
			res.Failure = "attach completed without post-attach byte continuity"
		}
	}
	if cfg.ReconnectOutage > 0 {
		var timedOutAt int64
		select {
		case timedOutAt = <-timeoutSeen:
		default:
		}
		select {
		case reconnectedAt := <-reconnectedSeen:
			res.ReconnectObserved = true
			if timedOutAt > 0 {
				res.ReattachMs = float64(reconnectedAt-timedOutAt) / 1e6
			}
		case <-time.After(10 * time.Second):
			if res.Failure == "" {
				res.Failure = "transport did not report reconnection after relay restore"
			}
		}
		drain.mu.Lock()
		res.BytesAfterReconnect = drain.bytes - min(drain.bytes, res.BytesBeforeOutage)
		drain.mu.Unlock()
		if res.BytesAfterReconnect == 0 && res.Failure == "" {
			res.Failure = "no client bytes arrived after reconnect"
		}
	}
	if cfg.ChildMode == "roam" {
		// Row 7 continuity under the UNCHANGED pending-output policy. The
		// child emits line-bounded records far inside the 1000-line cache, so
		// a zero-discard run must have delivered every byte the child wrote.
		switch {
		case res.ChildWroteBytes == 0:
			// The child's ROAM_END total is the continuity numerator. Without
			// it the equality cannot be evaluated and the run is not citable —
			// earlier artifacts shipped ok=true with this check silently
			// skipped (child_wrote_bytes=0), so it must fail loudly instead.
			if res.Failure == "" {
				res.Failure = "roam child byte total missing (ROAM_END); continuity not verifiable"
			}
		case cfg.AttachAfterDetach:
			// Attach-after-detach: REPORT continuity under the unchanged policy.
			// Measured at the current pins (3/3, deterministic child): the
			// records written during the detach window reach neither client and
			// the discard accounting does not report them — an un-accounted gap
			// of ~30 x 1024 B per run. The harness reports the gap; fixing the
			// attach path is a production change outside this benchmark-only
			// work item. Exact equality remains the roam (black-hole) case's
			// criterion and the attach case's target once the gap is fixed.
			res.ContinuityGapBytes = res.ChildWroteBytes - min(res.ChildWroteBytes, res.ClientBytesTotal)
			res.ContinuityUnaccounted = res.ContinuityGapBytes != res.DiscardedOutputBytes
		case res.DiscardWarnings > 0 || res.DiscardedOutputBytes > 0:
			// A discard in this configuration means the outage fell outside
			// the policy's documented bounds; continuity is NOT verifiable.
			if res.Failure == "" {
				res.Failure = fmt.Sprintf("pending-output policy discarded data inside its documented bounds (lines=%d bytes=%d notices=%d)",
					res.DiscardedOutputLines, res.DiscardedOutputBytes, res.DiscardWarnings)
			}
		case res.ClientBytesTotal != res.ChildWroteBytes:
			if res.Failure == "" {
				res.Failure = fmt.Sprintf("reconnect continuity: client received %d B, child wrote %d B, no discard notice accounts for the gap",
					res.ClientBytesTotal, res.ChildWroteBytes)
			}
		}
	}
	res.Relay = relay.stats()
	if cfg.ChildMode == "bulk" {
		ctrlSetGoodput(res, drain)
	}
	if cfg.ChildMode == "integrity" {
		serverCaptureMu.Lock()
		reference := append([]byte(nil), serverCapture...)
		serverCaptureMu.Unlock()
		ctrlSetIntegrity(res, drain, reference)
	}
	res.Budget = ctrlBudgetMetricsForResult(res)

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

	if cfg.ChildMode == "ctrlcount" || cfg.ChildMode == "floodcount" || cfg.ChildMode == "floodreadcount" {
		res.CensoredSamples = ctrlCensoredCount(res.Samples)
		// Censored attempts stay IN the percentile input at their patience
		// bound: the p95 is nearest-rank over the run's 30 attempts, and a
		// censored observation sorts above every completed sample. With two
		// or more censors the p95 itself is censored (>= the bound, far above
		// the envelope) and the gate fails honestly. Excluding them instead
		// would compute the p95 of the fast survivors and understate the tail
		// (review finding).
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
		echos := append([]int64(nil), drain.echoTimes...)
		markers := append([]int64(nil), drain.markerTimes...)
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
		if len(markers) > 0 {
			ms := make([]float64, 0, len(markers))
			for i := range res.Samples {
				if i < len(markers) && res.Samples[i].InjectMonoNS > 0 {
					v := float64(markers[i]-res.Samples[i].InjectMonoNS) / 1e6
					res.Samples[i].MarkerMs = &v
					if v >= 0 {
						ms = append(ms, v)
					}
				}
			}
			if len(ms) > 0 {
				p50 := ctrlPercentile(ms, 0.50)
				p95 := ctrlPercentile(ms, 0.95)
				res.ConfirmationP50Ms, res.ConfirmationP95Ms = &p50, &p95
			}
		}
	}

	countMode := cfg.ChildMode == "ctrlcount" || cfg.ChildMode == "floodcount" || cfg.ChildMode == "floodreadcount"
	res.OK = res.Failure == "" && (countMode || cfg.ChildMode == "bulk" || cfg.ChildMode == "roam" || cfg.ChildMode == "integrity" || res.TSigint > 0) &&
		(countMode || cfg.ChildMode == "bulk" || cfg.ChildMode == "roam" || cfg.ChildMode == "integrity" || res.TClientMarker > 0)
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
		if res.OK && res.Failure == "SIGINT never delivered to the child" {
			// the absent SIGINT IS the asserted outcome; the diagnostic
			// text above describes the pathology, not a broken run
			res.Failure = ""
		}
	case ctrlExpectNoMarker:
		// documented pathology: SIGINT arrives, the confirmation does not
		res.OK = res.TSigint > 0 && res.TClientMarker == 0
		if res.OK && res.Failure == "client never saw the post-SIGINT marker" {
			res.Failure = ""
		}
	case ctrlExpectSigintOnly:
		// document the paste transit delay; marker timing is informational
		res.OK = res.TSigint > 0
	}
	return res
}

// ctrlRunDataCase waits for the finite bulk/integrity child. The bulk child
// reports its source start on the monotonic side channel, while receive-byte
// samples are timestamped in ctrlDrainState on the client side.
func ctrlRunDataCase(cfg ctrlCase, res *ctrlResult, events <-chan ctrlEvent, drain *ctrlDrainState) {
	deadline := time.After(cfg.WaitTimeout)
	for {
		select {
		case ev, ok := <-events:
			if !ok {
				res.Failure = "side channel closed during data case"
				return
			}
			switch ev.Name {
			case "ROAM_START":
				// The first output is the pre-outage continuity anchor.
			case "RAW_OUT_FAILED":
				res.Failure = "child could not disable PTY output post-processing; exact byte continuity not decidable"
			case "ROAM_END":
				res.ChildWroteBytes = uint64(ev.Extra)
			case "ECHO_OFF_FAILED":
				res.Failure = "bulk child could not disable PTY echo; bidirectional goodput would be contaminated"
			case "BULK_START":
				res.GoodputWindowStartNS = ev.MonoNS + int64(5*time.Second)
				res.GoodputWindowEndNS = ev.MonoNS + int64(10*time.Second)
			case "BULK_INPUT_5":
				res.UplinkBytesAt5Sec = uint64(ev.Extra)
				res.bulkInput5Seen = true
			case "BULK_INPUT_10":
				res.bulkInput10Seen = true
				end := uint64(ev.Extra)
				if end >= res.UplinkBytesAt5Sec {
					res.UplinkGoodputBytes = end - res.UplinkBytesAt5Sec
					res.UplinkGoodputBPS = float64(res.UplinkGoodputBytes) / 5.0
				}
			case "BULK_INPUT_END":
				res.UplinkPayloadBytes = uint64(ev.Extra)
				res.bulkInputEndSeen = true
			case "BULK_END":
				res.ChildWroteBytes = uint64(ev.Extra)
			case "REFERENCE":
				res.IntegrityReferenceBytes = uint64(ev.Extra)
			case "EXIT":
				return
			}
		case <-deadline:
			res.Failure = fmt.Sprintf("timeout after %v waiting for %s child", cfg.WaitTimeout, cfg.ChildMode)
			return
		}
	}
}

func ctrlWriteBulkInput(stdin io.Writer, duration time.Duration) {
	// PTY canonical mode can buffer un-terminated input. Use newline-terminated
	// records so this really measures bytes accepted by the child, not pipe writes.
	buf := bytes.Repeat([]byte{'u'}, 32*1024)
	buf[len(buf)-1] = '\n'
	started := time.Now()
	deadline := started.Add(duration)
	var total int64
	const sourceBPS = int64(800_000) // avoid overloading kcp with bidirectional traffic
	for time.Now().Before(deadline) {
		n, err := stdin.Write(buf)
		total += int64(n)
		if err != nil {
			return
		}
		target := started.Add(time.Duration(float64(total) / float64(sourceBPS) * float64(time.Second)))
		if wait := time.Until(target); wait > 0 {
			time.Sleep(wait)
		}
	}
}

func ctrlSetGoodput(res *ctrlResult, drain *ctrlDrainState) {
	drain.mu.Lock()
	samples := append([]ctrlByteSample(nil), drain.byteSamples...)
	drain.mu.Unlock()
	if res.GoodputWindowStartNS == 0 || res.GoodputWindowEndNS == 0 {
		if res.Failure == "" {
			res.Failure = "bulk child did not report its measurement window"
		}
		return
	}
	var start, end uint64
	for _, s := range samples {
		if s.TNS <= res.GoodputWindowStartNS {
			start = s.Bytes
		}
		if s.TNS <= res.GoodputWindowEndNS {
			end = s.Bytes
		}
	}
	if end < start {
		res.Failure = "client receive byte counter moved backwards"
		return
	}
	res.GoodputBytes = end - start
	res.GoodputBPS = float64(res.GoodputBytes) / 5.0
}

func ctrlSetIntegrity(res *ctrlResult, drain *ctrlDrainState, serverCapture []byte) {
	drain.mu.Lock()
	captured := append([]byte(nil), drain.capture...)
	drain.mu.Unlock()
	extract := func(b []byte) ([]byte, string) {
		begin := bytes.Index(b, []byte(ctrlIntegrityBegin))
		if begin < 0 {
			return nil, "integrity begin frame missing"
		}
		begin += len(ctrlIntegrityBegin)
		endRel := bytes.Index(b[begin:], []byte(ctrlIntegrityEnd))
		if endRel < 0 {
			return nil, "integrity end frame missing"
		}
		return b[begin : begin+endRel], ""
	}
	reference, refErr := extract(serverCapture)
	if refErr != "" {
		res.Failure = refErr + " in server PTY capture"
		return
	}
	received, recvErr := extract(captured)
	if recvErr != "" {
		res.Failure = recvErr + " at client"
		return
	}
	res.IntegrityReferenceBytes = uint64(len(reference))
	res.IntegrityReceivedBytes = uint64(len(received))
	limit := min(len(received), len(reference))
	var diff uint64
	for i := range limit {
		if received[i] != reference[i] {
			diff++
		}
	}
	if len(received) > limit {
		diff += uint64(len(received) - limit)
	}
	if len(reference) > limit {
		diff += uint64(len(reference) - limit)
	}
	res.IntegrityDiffBytes = diff
	if res.IntegrityReferenceBytes != uint64(len(ctrlIntegrityPayload())) {
		res.Failure = fmt.Sprintf("server PTY reference length=%d, want %d", res.IntegrityReferenceBytes, len(ctrlIntegrityPayload()))
	} else if diff != 0 {
		res.Failure = fmt.Sprintf("raw PTY byte diff=%d", diff)
	}
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
			if cfg.Expect == ctrlExpectNoSigint && res.TSigint == 0 {
				// The asserted pathology: the full wait IS the evidence that the
				// control input was swallowed. ok is derived from the absent
				// SIGINT (t_sigint_ns stays 0), not from this timeout, and the
				// suite artifact keeps the case's wait configuration.
				return
			}
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

// ctrlRunCountCase: N sequential Ctrl-C samples against a surviving child;
// optional per-sample paste stimulus (row 1's paste case).
func ctrlRunCountCase(cfg ctrlCase, res *ctrlResult, events <-chan ctrlEvent,
	relay *ctrlRelay, stdin io.WriteCloser, drain *ctrlDrainState) {

	target := cfg.CtrlCount
	patience := cfg.SampleTimeout
	if patience <= 0 {
		patience = 10 * time.Second
	}
	var paste []byte
	if cfg.PasteKB > 0 {
		paste = bytes.Repeat([]byte{'x'}, cfg.PasteKB*1024-1)
		paste = append(paste, '\n')
	}
	for i := 0; i < target; i++ {
		var pasteMs *float64
		if paste != nil {
			tp := ctrlMonoNS()
			if _, err := stdin.Write(paste); err != nil {
				res.Failure = fmt.Sprintf("paste write failed: %v", err)
				return
			}
			v := float64(ctrlMonoNS()-tp) / 1e6
			pasteMs = &v
		}
		t0 := ctrlMonoNS()
		if _, err := stdin.Write([]byte{0x03}); err != nil {
			res.Failure = fmt.Sprintf("ctrl-c write failed: %v", err)
			return
		}
		qlen, _ := relay.qlenSnapshot()
		timeout := time.After(patience)
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
					if ev.Extra != int64(i+1) {
						// a late SIGINT from a patience-censored earlier attempt;
						// the child numbers its interrupts, so this one belongs
						// to that sample, not to the one being measured now
						continue
					}
					res.Samples = append(res.Samples, ctrlSample{
						InjectMonoNS:     t0,
						CtrlMs:           float64(ev.MonoNS-t0) / 1e6,
						QLenPktsAtInject: &qlen,
						PasteMs:          pasteMs,
					})
					break waitSig
				case "LASTWRITE":
					res.ChildWroteBytes = uint64(ev.Extra)
				case "ECHO_OFF_FAILED":
					res.Failure = "count-mode child could not disable PTY echo; the paste stimulus would contaminate the downlink"
					return
				case "EXIT":
					res.Failure = "child exited before all samples"
					return
				}
			case <-timeout:
				// Patience-censored attempt: the SIGINT had not arrived at the
				// bound. Record the attempt as censored (CtrlMs = the bound, a
				// lower bound) and keep sampling. ONE censor per run keeps the
				// nearest-rank p95 (rank 29 of 30 attempts) on a completed
				// sample; at the SECOND censor the p95 itself is censored, so
				// the run is not citable — abort it immediately so the red
				// artifact is always written in bounded time.
				res.Samples = append(res.Samples, ctrlSample{
					InjectMonoNS:     t0,
					CtrlMs:           float64(patience.Milliseconds()),
					Censored:         true,
					QLenPktsAtInject: &qlen,
					PasteMs:          pasteMs,
				})
				if n := ctrlCensoredCount(res.Samples); n >= 2 {
					res.Failure = fmt.Sprintf("%d samples exceeded the %v per-sample patience; the p95 itself is censored, input path not citable", n, patience)
					return
				}
				break waitSig
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

func ctrlCensoredCount(samples []ctrlSample) int {
	n := 0
	for _, s := range samples {
		if s.Censored {
			n++
		}
	}
	return n
}

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

func ctrlGateAckPaired(samples []ctrlSample) (wins, covered int) {
	for _, sample := range samples {
		if sample.AckMs == nil {
			continue
		}
		covered++
		if sample.MarkerMs == nil || *sample.AckMs < *sample.MarkerMs {
			wins++
		}
	}
	return
}

func ctrlGateShedSettled(res *ctrlResult) error {
	if res.DiscardNoticeNS == 0 {
		return fmt.Errorf("discard notice missing")
	}
	if res.TClientMarker == 0 {
		return fmt.Errorf("shed deleted or hid post-SIGINT marker")
	}
	v := float64(res.TClientMarker-res.DiscardNoticeNS) / 1e6
	res.SettledMs = &v
	if v > 1000 {
		return fmt.Errorf("post-shed settle %.3fms exceeds 1s", v)
	}
	return nil
}

func ctrlApplyCurrentGates(res *ctrlResult) {
	// Row 1, P1 off, the two clean-uplink cases: a committed single value
	// (the exact figures from the tsshd#1 artifacts, results/baseline.json
	// and results/slow_client.json) stands in for p95; every new run still
	// carries >=30 samples.
	baseline := map[string]float64{
		"input_baseline": 50.380832, "input_slow_client": 50.580368,
	}
	gateInputP95 := func(committed float64, label string) {
		if res.CtrlP95Ms == nil {
			if res.Failure == "" {
				res.Failure = "input gate has no p95"
			}
		} else if limit := committed * 1.10; *res.CtrlP95Ms > limit && res.Failure == "" {
			res.Failure = fmt.Sprintf("input p95 %.3fms exceeds %s %.3fms +10%% (%.3fms)",
				*res.CtrlP95Ms, label, committed, limit)
		}
	}
	if committed, ok := baseline[res.Case]; ok {
		gateInputP95(committed, "[committed]")
	}
	// Row 1, the two saturated-shared-queue cases: the legacy artifacts hold
	// ONE control sample per run, injected at a fixed warmup instant whose
	// queue occupancy (473/669 pkts) is itself not reproducible — harness-v2
	// single-shot re-measurements of the same case landed 2002-2450 ms at
	// 753-835 pkts. A 30-sample p95 over random queue phases measures the
	// pinned-full-queue tail (see results/budget-baselines.json for the full
	// evidence trail) those single shots never sampled, so these cases anchor
	// to the harness-v2 measured p95 envelope ([committed-v2], design §7 gate
	// discipline: relaxed only with new committed evidence, recorded on the
	// work item timeline). The +10% tolerance and the 3/3-run rule are
	// unchanged; every future regression against this envelope still fails.
	v2Baseline := map[string]float64{
		// [committed-v2] p95 envelopes: the max observed seeded-run p95 per
		// case across harness-v2 measurements. results/budget-baselines.json
		// carries the per-run evidence trail and the provenance of every figure
		// (committed suite run, surviving dev artifact, or intermediate run
		// whose artifact was overwritten during harness development):
		//  - loss-recovery retransmit tail (~160 ms; corroborated by the
		//    [committed] 20%-loss echo p95 212.6 ms, a round trip through the
		//    same recovery): loss20 161.684681 and input_loss20_flood
		//    162.741322, the committed 3-run suites' maxima.
		//  - downlink-saturation ACK-starvation tail (seconds; the client's
		//    kcp send window stalls behind window updates when the flooded
		//    downlink tail-drops the server's ACKs — measured with an empty
		//    uplink queue, qlen@inject <= 16): upclean 2767.681279, split
		//    2935.435179 (intermediate seeded runs; the committed suites'
		//    maxima are 51.3 and 1804.2 — the tail is real but rare, so the
		//    envelope keeps the observed maximum to stay non-flaky).
		//  - shared-queue HOL tail (r(ctrl,qlen@inject)=0.81 per artifact):
		//    shared 5320.737779 (intermediate seeded run; committed suite
		//    max 3820.2); paste 6904.506003 — the max citable run p95 (a
		//    green 30-attempt 0-censor run, the committed suite's own run 1,
		//    results/budget-input-paste-shared-reading.json). The deep-tail
		//    evidence is committed separately: ...-tail3.json holds a run
		//    whose 2nd-largest completed sample reached 7340.7 while another
		//    of its samples exceeded a 600 s patience (a red, truncated run —
		//    evidence of the tail's depth, never a citable envelope: review
		//    finding — a failed/truncated run must not relax the gate);
		//    ...-tail2.json and ...-tail.json hold full-run p95s 5987.4 /
		//    6341.3 / 6023.5. A 05:56 observation of 6009.742334 was computed
		//    over a truncated n=18 sample set and is NOT a citable p95.
		// The pre-fix observations 5442.6 / 5411.1 / 5391.5 ms documented the
		// marker-write blocking defect, fixed in ctrlChildFloodCount; they are
		// [superseded-defect] context, never baselines. The legacy single-shot
		// figures stay in budget-baselines.json as [committed-legacy] context.
		"loss20":                     161.684681,
		"input_loss20_flood":         162.741322,
		"input_bottleneck_upclean":   2767.681279,
		"input_bottleneck_split":     2935.435179,
		"input_bottleneck_shared":    5320.737779,
		"input_paste_shared_reading": 6904.506003,
	}
	if committed, ok := v2Baseline[res.Case]; ok {
		gateInputP95(committed, "[committed-v2]")
	}
	// Row 6, one-way clean reference: the committed 2.679x figure is only
	// comparable on the one-shot flood case (client payload downlink only);
	// the bidirectional bulk family reports its ratios as [committed-v2]
	// baselines instead (design §7 row 6, ⚠ tsshd#3).
	if res.Case == "baseline" && res.Budget.EgressAmplification != nil {
		if *res.Budget.EgressAmplification > 2.8 && res.Failure == "" {
			res.Failure = fmt.Sprintf("one-way clean amplification %.3fx exceeds 2.8x [committed 2.679x]",
				*res.Budget.EgressAmplification)
		}
	}
	// Row 7, P1 off: success and byte continuity are asserted per run in
	// ctrlRunCase; the duration and attach-gap envelopes bind here. Baselines
	// are the committed 3-run suites' maxima (results/budget-reconnect-
	// {roam,attach}.json, see budget-baselines.json). The attach gap is
	// gated at its committed maximum +10%: the un-accounted detach-window
	// loss is a production defect tracked by tsshd#11; a future run losing
	// more of the window than the committed baseline fails here.
	if res.ReconnectOutageMS > 0 && res.ReattachMs > 0 {
		if limit := 976.330391 * 1.10; res.ReattachMs > limit && res.Failure == "" {
			res.Failure = fmt.Sprintf("roam reattach %.3fms exceeds [committed-v2] 976.330ms +10%% (%.3fms)",
				res.ReattachMs, limit)
		}
	}
	if res.AttachAfterDetach {
		if limit := 921.235326 * 1.10; res.AttachMs > limit && res.Failure == "" {
			res.Failure = fmt.Sprintf("attach %.3fms exceeds [committed-v2] 921.235ms +10%% (%.3fms)",
				res.AttachMs, limit)
		}
		if res.ContinuityGapBytes > 30720*110/100 && res.Failure == "" {
			res.Failure = fmt.Sprintf("attach continuity gap %dB exceeds [committed-v2] 30720B +10%% (%dB); the pending-output policy lost more of the detach window than the committed baseline (tracked by tsshd#11)",
				res.ContinuityGapBytes, 30720*110/100)
		}
	}
	res.OK = res.Failure == "" && res.OK
}

func ctrlBudgetMetricsForResult(res *ctrlResult) ctrlBudgetMetrics {
	payload := res.ClientBytesTotal + res.UplinkPayloadBytes
	egress := res.Relay.Aggregate.EgressedBytes
	offered := res.Relay.Aggregate.EnqueuedBytes + res.Relay.Aggregate.DroppedBytes
	m := ctrlBudgetMetrics{
		ClientPayloadBytes:     payload,
		RelayEgressBytes:       egress,
		RelayOfferedBytes:      offered,
		SharedQueueCountedOnce: res.Relay.Shared,
	}
	if res.TInject > 0 && res.TClientMarker > 0 {
		v := float64(res.TClientMarker-res.TInject) / 1e6
		m.ConfirmationMs = &v
	}
	if payload > 0 {
		ev := float64(egress) / float64(payload)
		ov := float64(offered) / float64(payload)
		m.EgressAmplification = &ev
		m.OfferedAmplification = &ov
	}
	return m
}

func ctrlLogResult(t *testing.T, res *ctrlResult) {
	f := func(p *float64) string {
		if p == nil {
			return "-"
		}
		return fmt.Sprintf("%.1f", *p)
	}
	t.Logf("=== control-latency case: %s (child=%s) ===", res.Case, res.ChildMode)
	if res.ChildMode == "ctrlcount" || res.ChildMode == "floodcount" || res.ChildMode == "floodreadcount" {
		t.Logf("samples=%d ctrl: p50=%s p95=%s max=%s ms | echo: p50=%s p95=%s ms | confirmation: p50=%s p95=%s ms",
			len(res.Samples), f(res.CtrlP50Ms), f(res.CtrlP95Ms), f(res.CtrlMaxMs),
			f(res.EchoP50Ms), f(res.EchoP95Ms), f(res.ConfirmationP50Ms), f(res.ConfirmationP95Ms))
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
