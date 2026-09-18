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

import (
	"bytes"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

type clientOutputForwarder struct {
	name         string
	sess         *SshUdpSession
	client       *SshUdpClient
	reader       Stream
	writer       *io.PipeWriter
	marker       atomic.Pointer[[]byte]
	cacheBuf     []byte
	discardLines uint64
	discardBytes uint64

	// done is closed when forward returns, i.e. the output stream has ended
	// and every byte read from it has been handed to the caller through the
	// session pipe. The detach rendezvous (SshUdpClient.notifyServerDetach)
	// waits on it before closing the transport, so no already-received
	// output can be discarded unread.
	done chan struct{}
}

func (f *clientOutputForwarder) forward() {
	defer func() {
		_ = f.writer.Close()
		if !f.client.detached.Load() {
			_ = f.reader.CloseRead()
		}
		close(f.done)
	}()

	buffer := make([]byte, 32*1024)
	for {
		n, err := f.reader.Read(buffer)
		if n > 0 {
			buf := buffer[:n]

			// Check if we need to discard output until a marker is found
			if marker := f.marker.Load(); marker != nil {
				f.cacheBuf = append(f.cacheBuf, buf...)

				if pos := bytes.Index(f.cacheBuf, *marker); pos >= 0 { // Marker found!
					// Record stats for the data BEFORE the marker
					if f.client.discardCallback != nil {
						f.discardLines += uint64(bytes.Count(f.cacheBuf[:pos], []byte("\n")))
						f.discardBytes += uint64(pos)
					}
					// Keep only the data AFTER the marker
					f.cacheBuf = f.cacheBuf[pos+len(*marker):]
					// Safely clear the marker state
					if f.marker.CompareAndSwap(marker, nil) {
						// Add 1 to discardLines to account for the final line fragment before the marker
						lines, bytes := f.discardLines+1, f.discardBytes
						if enableDebugLogging {
							f.client.debug("session [%d] %s matched marker: %s", f.sess.id, f.name, string(*marker))
							if bytes > 0 {
								f.client.debug("discard output %d lines %d bytes", lines, bytes)
							}
						}
						if f.client.discardCallback != nil {
							go f.client.discardCallback(nil, lines, bytes)
						}

						buf = f.cacheBuf
						f.cacheBuf, f.discardLines, f.discardBytes = nil, 0, 0

						if err := writeAll(f.writer, buf); err != nil {
							break
						}
					}
				} else { // Marker NOT found yet.
					// Keep only the tail to handle split markers across reads.
					if keepLen := len(*marker) - 1; len(f.cacheBuf) > keepLen {
						tail := make([]byte, keepLen)
						pos := len(f.cacheBuf) - keepLen
						copy(tail, f.cacheBuf[pos:])
						if f.client.discardCallback != nil {
							f.discardLines += uint64(bytes.Count(f.cacheBuf[:pos], []byte("\n")))
							f.discardBytes += uint64(pos)
						}
						f.cacheBuf = tail
					}
				}
				// Skip normal writing, go read more data
				continue
			}

			// Normal flow: no marker, just write
			if err := writeAll(f.writer, buf); err != nil {
				break
			}
		}
		if err != nil {
			break
		}
	}
	f.client.debug("session [%d] %s completed", f.sess.id, f.name)
}

// waitDone blocks until the forwarder has completed (see done) or the
// timeout elapses. A nil forwarder - no output pipe was requested - is
// trivially done.
func (f *clientOutputForwarder) waitDone(timeout time.Duration) bool {
	if f == nil {
		return true
	}
	select {
	case <-f.done:
		return true
	case <-time.After(timeout):
		return false
	}
}

type serverOutputForwarder struct {
	name   string
	sess   *sessionContext
	reader io.Reader
	stream Stream

	handleMutex sync.Mutex
	// processing serializes cache/queue mutations while allowing the mutex to
	// be released during a blocked transport send or reconnect wait. Other
	// handlers wait for the current owner without holding handleMutex.
	processing       bool
	processDone      chan struct{}
	reconnectPending bool
	returned         bool
	writeError       atomic.Bool
	done             chan struct{}
	writeBufCh       chan []byte

	cacheLines       [][]byte
	tmuxOutputPrefix string

	// chHasNewLine ensures the client receives a complete line before further output is cached.
	chHasNewLine bool

	// noNewLineCount records consecutive reads that contain no '\n'.
	// After 3 consecutive reads without newline, output will start being cached.
	// This helps handle cases where some programs may output progress bars or status
	// lines by repeatedly using carriage return ('\r') without emitting newline characters.
	noNewLineCount int

	discardLines   uint64
	discardBytes   uint64
	voidedCapacity uint64

	discardOutput atomic.Bool
	discardMarker atomic.Pointer[[]byte]
}

func (f *serverOutputForwarder) beginProcessing() {
	f.handleMutex.Lock()
	for f.processing {
		done := f.processDone
		f.handleMutex.Unlock()
		<-done
		f.handleMutex.Lock()
	}
	f.processing = true
	f.processDone = make(chan struct{})
}

// endProcessing is called with handleMutex held by the processing owner.
func (f *serverOutputForwarder) endProcessing() {
	// A reconnect can race with a handler that cached the final output chunk.
	// Defer the replay until that handler finishes, rather than dropping the
	// notification or sending its cache ahead of the chunk it still owns.
	for f.reconnectPending && !f.returned {
		f.reconnectPending = false
		f.flushOutput()
	}
	f.processing = false
	close(f.processDone)
	f.handleMutex.Unlock()
}

// waitForQueue releases only the state mutex. The processing token remains
// held, so reconnect cannot replay cached lines ahead of the pending write.
func (f *serverOutputForwarder) waitForQueue() {
	f.handleMutex.Unlock()
	time.Sleep(10 * time.Millisecond)
	f.handleMutex.Lock()
}

// enqueueWhileDisconnected is used for the old timeout path, which can wait
// for stream capacity. A failed writer cannot consume this queue again.
func (f *serverOutputForwarder) enqueueWhileDisconnected(buf []byte) bool {
	for {
		select {
		case f.writeBufCh <- buf:
			return true
		default:
			if f.returned || f.writeError.Load() {
				return false
			}
			f.waitForQueue()
		}
	}
}

// kWireAmpEstimate is the wire-amplification estimate that converts a downlink
// WIRE budget (bytes/s on the physical link, FEC parity packets and transport
// framing included) into the payload token rate the pacer grants to PTY
// output before it enters the smux stream:
//
//	payload rate = wire budget / kWireAmpEstimate
//
// Composition: the FEC 1+1 floor of 2.0 (every datagram is doubled: one data
// shard plus one parity shard, including kcp ACK packets), times framing
// (~1.04: smux+kcp headers against ~1.4 KB packets), times the loss-recovery
// retransmission factor (~1.25 at the 20%-loss reference: each segment needs
// ~1/0.8 sends on average). 2.6 is the evidence-backed tightening of the
// design's initial 2.2: measured 2026-09-18 on the tsshd#6 harness at the
// 2 Mbps + 20% loss reference (results/p1off-* and the campaign artifacts):
// at 2.2 the recipe's 175 KB/s wire budget was itself oversubscribed - the
// downlink's retransmit overhead pushed actual wire usage to ~2.5x payload,
// the shared queue re-pinned (maxq 1000, ~5.7 MB tail-dropped) and the
// downlink goodput collapsed to ~20 KB/s; at 2.6 the offered wire stays
// inside the budget including retransmissions. The value may only be
// re-tightened (never loosened) with new measured amplification evidence,
// and any change must recompute the row-5 gate by its pinned formula
// (delivered >= 0.8 x (1.4 Mbps / amp); see docs/weak-network-agent-design.md
// section 7) and be recorded on the work item timeline.
const kWireAmpEstimate = 2.6

// kPacerTokenInterval is the pacer's token interval. The bucket's burst
// capacity is exactly one token interval's worth of payload tokens
// (rate x interval), so the pacer never lets a burst run more than one
// token interval ahead of the configured wire budget.
const kPacerTokenInterval = 100 * time.Millisecond

// kPacerMaxSleep bounds each individual wait() sleep. The deficit is paid in
// slices of at most this length, so wait() re-evaluates at least once a second
// and an erroneously long single sleep can never be scheduled; the TOTAL
// retention of a closing connection's writer goroutine (server shutdown waits
// on the writer through forward's <-done) remains the full deficit payoff,
// n_deficit / payload_rate: sub-second at the documented recipe (a 32 KiB
// chunk at 175,000 B/s wire / 2.6 ~= 0.48 s), ~21 s per 32 KiB chunk at the
// kMinKcpWireRate warning floor, and unbounded below it - which is why the
// floor produces a startup warning rather than a silent clamp.
const kPacerMaxSleep = time.Second

// wireRatePacer is a token bucket that paces one KCP connection's session
// PTY output (stdout and stderr of every session on that connection) before
// it enters the smux stream, keeping the offered wire rate under a configured
// downlink WIRE budget so a weak-link bottleneck queue stays out of
// saturation. That headroom is what lets small control packets and the
// uplink kcp ACKs regain medium time (the tsshd#1/tsshd#3 measured failure
// mode: an unpaced flood pins the bottleneck queue, and the confirmation
// marker is buried behind a multi-second in-flight backlog).
//
// Exactly ONE pacer exists per KCP connection, owned by that connection's
// sshUdpServer and shared by all of its session forwarders; independent
// per-forwarder buckets could collectively exceed the wire budget. Forwarders
// look the pacer up through their session's CURRENT server so a session that
// reattaches to a new connection follows the new connection's pacer.
//
// The budget clock is anchored to the monotonic clock on FIRST USE, not at
// construction: construction time and first-use time can be arbitrarily far
// apart (a server may accept its first session minutes later), and a
// construction-anchored bucket silently grants a huge burst of stale tokens
// (the tsshd#1 measured pitfall).
//
// A nil *wireRatePacer means pacing is disabled (--kcp-wire-rate 0, the
// default): every method is a no-op and writerLoop never touches a lock, so
// the default configuration is byte-for-byte the unpaced code path.
type wireRatePacer struct {
	mu sync.Mutex

	// rate is the payload token rate in bytes/s: wire budget / amp estimate.
	rate float64

	// burst is the bucket capacity: one token interval's worth of tokens.
	// A write may spend at most this many accrued tokens immediately; any
	// excess waits for tokens to accrue. Bounded burst <= one token interval.
	burst float64

	// tok is the currently accrued token balance. It starts at burst on
	// first use (one interval of headroom, so an interactive-sized first
	// write is not delayed behind an empty bucket) and never exceeds burst.
	tok float64

	// last is the monotonic time of the last refill; the zero value means
	// "never used" and anchors the clock on the first wait call.
	last time.Time
}

// newWireRatePacer builds a pacer for a downlink wire budget in bytes/s.
// wireRateBPS <= 0 returns nil: the knob is off and pacing is disabled.
func newWireRatePacer(wireRateBPS uint64) *wireRatePacer {
	if wireRateBPS == 0 {
		return nil
	}
	rate := float64(wireRateBPS) / kWireAmpEstimate
	return &wireRatePacer{
		rate:  rate,
		burst: rate * kPacerTokenInterval.Seconds(),
	}
}

// wait blocks until n payload bytes may be handed to the smux stream.
//
// The bucket works as bounded credit + serialized debt: accrued credit is
// capped at one token interval's worth (the burst), but a single take may
// exceed the accrued credit — it goes into debt for the difference and
// sleeps the debt off at the payload rate. Sleeping happens UNDER the pacer
// mutex, on purpose. This pacer is the shared budget for the whole
// connection: if two forwarders each slept their own deficit outside the
// lock, both would wake at the same instant and collectively overshoot the
// wire budget. Holding the lock across the sleep makes the debt itself
// serial: a second forwarder queues behind the first one's paced write.
// In any window the bytes released to the transport never exceed
// burst + rate x window, so the offered wire rate stays under the budget
// while an interactive-sized write (<= burst) is never delayed behind an
// empty bucket. Writes are chunk-granular (writeBufCh holds one buffer, at
// most the 32 KB read chunk), so at the weak-link recipe the longest single
// sleep is sub-second, and the pacing chain (writerLoop -> writeBufCh ->
// handleBuffer spin -> PTY kernel buffer -> child write) is exactly the
// intended backpressure: the flooding child blocks at the source instead of
// the server flooding the transport faster than the link can drain it.
func (p *wireRatePacer) wait(n int) {
	if p == nil || n <= 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	if p.last.IsZero() {
		// First use: anchor the clock here and grant exactly one token
		// interval of burst credit - not the whole interval since
		// construction (see the type comment).
		p.last = now
		p.tok = p.burst
	} else {
		// Accrued credit is capped at one token interval of burst; debt
		// (tok < 0) is never reached here because every wait sleeps its
		// own deficit off before returning.
		p.tok += now.Sub(p.last).Seconds() * p.rate
		if p.tok > p.burst {
			p.tok = p.burst
		}
	}
	p.last = now
	p.tok -= float64(n)
	// Anything smaller than half a byte of deficit is float rounding noise
	// (-1e-13 etc.), not debt: without this floor the residue re-enters the
	// loop with a zero-length sleep and spins forever (caught by the pacer
	// unit tests when the sliced sleep was introduced).
	for p.tok < -0.5 {
		// The deficit sleep pays the debt at the payload rate, in slices of
		// at most kPacerMaxSleep (see that constant for the retention
		// trade-off at sub-recipe rates). time.Sleep never wakes early;
		// any timer overshoot is discarded, never lent as extra credit.
		deficit := -p.tok
		sleep := time.Duration(deficit / p.rate * float64(time.Second))
		if sleep > kPacerMaxSleep {
			sleep = kPacerMaxSleep
		}
		time.Sleep(sleep)
		paid := sleep.Seconds() * p.rate
		p.tok += min(paid, deficit)
		p.last = time.Now()
	}
	if p.tok < 0 {
		p.tok = 0
	}
}

func (f *serverOutputForwarder) writerLoop() {
	defer func() { _ = f.stream.CloseWrite(); close(f.done) }()
	for buf := range f.writeBufCh {
		// Pace the offered payload BEFORE the smux write: bytes already inside
		// kcp's send queue cannot be evicted without corrupting smux framing, so
		// prevention has to happen ahead of the transport. The lookup goes
		// through the session's CURRENT server (nil while detached, QUIC servers
		// and the 0-rate default carry no pacer), so reattached sessions follow
		// the new connection's budget.
		f.sess.wirePacer().wait(len(buf))
		if err := writeAll(f.stream, buf); err != nil {
			f.writeError.Store(true)
			warning("write to [%s] failed: %v", f.name, err)
			return
		}
	}
}

func (f *serverOutputForwarder) cacheOutput(buf []byte) {
	for len(buf) > 0 {
		pos := bytes.IndexByte(buf, '\n')
		if pos < 0 {
			pos = bytes.IndexByte(buf, '\r')
		}

		var line []byte
		if pos >= 0 {
			line = buf[:pos+1]
			buf = buf[pos+1:]
		} else {
			line = buf
			buf = nil
		}

		if len(f.cacheLines) == 0 {
			f.cacheLines = append(f.cacheLines, line)
			continue
		}
		last := f.cacheLines[len(f.cacheLines)-1]
		if b := last[len(last)-1]; b != '\n' && (b != '\r' || line[0] == '\n') && len(last) < 1000 {
			f.cacheLines[len(f.cacheLines)-1] = append(last, line...)
			continue
		}
		f.cacheLines = append(f.cacheLines, line)
	}

	maxLines := max(maxPendingOutputLines, f.sess.rows*2)
	if len(f.cacheLines) > maxLines {
		if f.discardLines == 0 {
			f.tmuxOutputPrefix = extractTmuxOutputPrefix(f.cacheLines)
		}

		dropLines := len(f.cacheLines) - maxLines
		f.discardLines += uint64(dropLines)
		for i := range dropLines {
			f.discardBytes += uint64(len(f.cacheLines[i]))
		}
		f.cacheLines = f.cacheLines[dropLines:]

		f.voidedCapacity += uint64(dropLines)
		if f.voidedCapacity > uint64(maxLines) {
			newCacheLines := make([][]byte, len(f.cacheLines), maxLines*2+10)
			copy(newCacheLines, f.cacheLines)
			f.cacheLines = newCacheLines
			f.voidedCapacity = 0
		}
	}
}

func (f *serverOutputForwarder) flushOutput() {
	if len(f.cacheLines) == 0 || f.sess.clientChecker.isTimeout() {
		return
	}

	if f.discardLines > 0 {
		// Output has been discarded due to buffer limits. Attempt to force a screen redraw.
		// If successful (and the session is a PTY), clear the remaining buffered output.
		// The application will repaint the screen, ensuring the client receives a clean state.
		if f.sess.SetSize(0, 0, true, true, nil) == nil {
			f.clearOutput()
			return
		}
	}

	filteredCount := 0
	if enableDebugLogging {
		defer func() {
			if filteredCount > 0 {
				debug("filtered %d ESC[6n cursor position request(s)", filteredCount)
			}
		}()
	}

	for i := -1; i < len(f.cacheLines); i++ {
		var line []byte
		if i < 0 {
			if f.discardLines == 0 {
				continue
			}
			newline := "\r\n"
			if len(f.cacheLines) > 0 && len(f.cacheLines[0]) > 0 && f.cacheLines[0][len(f.cacheLines[0])-1] == '\r' {
				newline = "\r"
			}
			line = fmt.Appendf(nil,
				"\r\033[0;33mWarning: tsshd discarded %d lines %d bytes of output during client disconnection at this point!\033[0m\033[K%s",
				f.discardLines, f.discardBytes, newline)
			if len(f.tmuxOutputPrefix) > 0 {
				line = encodeTmuxOutput(f.tmuxOutputPrefix, line)
			}
		} else {
			line = f.cacheLines[i]
			if enableDebugLogging {
				filteredCount += bytes.Count(line, []byte("\x1b[6n"))
			}
			line = bytes.ReplaceAll(line, []byte("\x1b[6n"), []byte(""))
			if len(line) == 0 {
				continue
			}
		}
	out:
		for {
			select {
			case f.writeBufCh <- line:
				if i < 0 {
					debug("discard old output %d lines %d bytes", f.discardLines, f.discardBytes)
					f.discardLines, f.discardBytes = 0, 0
				}
				break out
			default:
				if f.sess.clientChecker.isTimeout() {
					if i > 0 {
						f.cacheLines = f.cacheLines[i:]
					}
					return
				}
				if f.returned || f.writeError.Load() {
					return
				}
				f.waitForQueue()
			}
		}
	}

	f.cacheLines, f.chHasNewLine, f.noNewLineCount = nil, false, 0
}

func (f *serverOutputForwarder) clearOutput() {
	f.discardLines += uint64(len(f.cacheLines))
	for _, line := range f.cacheLines {
		f.discardBytes += uint64(len(line))
	}
	if f.discardLines > 0 {
		debug("discard all output %d lines %d bytes", f.discardLines, f.discardBytes)
		if server := f.sess.server.Load(); server != nil {
			msg := &discardMessage{DiscardedOutputLines: f.discardLines, DiscardedOutputBytes: f.discardBytes}
			go func() {
				if err := server.sendBusMessage("discard", msg); err != nil {
					debug("send discard message failed: %v", err)
				}
			}()
		}
	}
	f.discardLines, f.discardBytes = 0, 0
	f.cacheLines, f.chHasNewLine, f.noNewLineCount = nil, false, 0
}

func (f *serverOutputForwarder) onReconnected() {
	f.handleMutex.Lock()
	// The active handler observes the updated checker itself. A second flush
	// while it is processing would duplicate or reorder its cached output.
	if f.returned {
		f.handleMutex.Unlock()
		return
	}
	if f.processing {
		f.reconnectPending = true
		f.handleMutex.Unlock()
		return
	}
	f.processing = true
	f.processDone = make(chan struct{})
	defer f.endProcessing()

	f.flushOutput()
}

func (f *serverOutputForwarder) handleBuffer(buf []byte) {
	f.beginProcessing()
	defer f.endProcessing()

	// The client requested discarding all previous output.
	// Clear any cached output on the server side and echo the marker
	// back to the client so it can discard any already-delivered data.
	if marker := f.discardMarker.Swap(nil); marker != nil {
		debug("session [%d] %s inject marker: %s", f.sess.id, f.name, string(*marker))

		// Disable server-side discard to prevent conflict,
		// the client will now handle synchronization using the injected marker.
		f.discardOutput.Store(false)

		f.clearOutput()

		buffer := make([]byte, len(*marker)+len(buf))
		copy(buffer, *marker)
		copy(buffer[len(*marker):], buf)
		buf = buffer
	}

	// Discard the cached output exactly once. The flag must be set again for future discards.
	if f.discardOutput.CompareAndSwap(true, false) {
		f.clearOutput()
	}

	if f.chHasNewLine && f.sess.clientChecker.isTimeout() && !f.sess.isKeepPendingOutput() {
		f.cacheOutput(buf)
		return
	}

	if len(f.cacheLines) > 0 {
		f.cacheOutput(buf)
		f.flushOutput()
		return
	}

	var remaining []byte
	if f.sess.clientChecker.isTimeout() && !f.sess.isKeepPendingOutput() {
		pos := bytes.IndexByte(buf, '\n')
		if pos >= 0 {
			remaining = buf[pos+1:]
			buf = buf[:pos+1]
			f.chHasNewLine = true
		} else {
			if f.noNewLineCount < 3 {
				f.noNewLineCount++
			} else {
				f.chHasNewLine = true
				f.cacheOutput(buf)
				return
			}
		}
	}

out:
	for {
		select {
		case f.writeBufCh <- buf:
			break out
		default:
			if f.sess.clientChecker.isTimeout() {
				if f.sess.isKeepPendingOutput() {
					f.handleMutex.Unlock()
					err := f.sess.clientChecker.waitUntilReconnected()
					f.handleMutex.Lock()
					if err != nil {
						return
					}
					continue
				}
				select {
				case b := <-f.writeBufCh:
					buf = append(b, buf...)
				default:
				}
				pos := bytes.IndexByte(buf, '\n')
				if pos < 0 && f.noNewLineCount < 3 {
					if !f.enqueueWhileDisconnected(buf) {
						return
					}
					f.noNewLineCount++
					break out
				}

				if pos < 0 {
					if !f.enqueueWhileDisconnected(buf) {
						return
					}
				} else {
					if !f.enqueueWhileDisconnected(buf[:pos+1]) {
						return
					}
					left := buf[pos+1:]
					if len(left) > 0 {
						f.cacheOutput(left)
					}
				}

				f.chHasNewLine = true
				break out
			}
			if f.returned || f.writeError.Load() {
				return
			}
			f.waitForQueue()
		}
	}

	if len(remaining) > 0 {
		f.cacheOutput(remaining)
	}
}

func (f *serverOutputForwarder) handleError() {
	f.beginProcessing()
	defer f.endProcessing()

	for len(f.cacheLines) > 0 && !f.writeError.Load() {
		if f.sess.clientChecker.isTimeout() {
			f.handleMutex.Unlock()
			err := f.sess.clientChecker.waitUntilReconnected()
			f.handleMutex.Lock()
			if err != nil {
				break
			}
		}
		f.flushOutput()
	}
}

func (f *serverOutputForwarder) forward() {
	defer func() {
		f.handleMutex.Lock()
		f.returned = true
		for f.processing {
			done := f.processDone
			f.handleMutex.Unlock()
			<-done
			f.handleMutex.Lock()
		}
		close(f.writeBufCh)
		f.handleMutex.Unlock()
		<-f.done
	}()

	go f.writerLoop()

	buffer := make([]byte, 32*1024)
	for {
		n, err := f.reader.Read(buffer)
		if n > 0 {
			buf := make([]byte, n)
			copy(buf, buffer[:n])
			if f.sess.screenBuf != nil {
				select {
				case f.sess.screenBuf <- buf:
				default:
					select {
					case f.sess.screenBuf <- buf:
					case <-time.After(100 * time.Millisecond):
						warning("screen update blocked for 100ms, dropping %d bytes", len(buf))
					}
				}
			}
			f.handleBuffer(buf)
		}
		if err != nil {
			f.handleError()
			break
		}
	}

	debug("session [%d] %s completed", f.sess.id, f.name)
}
