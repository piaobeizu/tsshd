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

// Input-ACCEPTED ack machinery (tsshd#7, design doc §3 rank 2 / §4 item 5 /
// §4.5). This file owns:
//
//   - orderedBusSender: the ONE per-connection goroutine that alone writes
//     the ordering-sensitive bus events (input_ack and the kind-classified
//     discard reports), consuming a FIFO of pre-serialized single-frame
//     events. Enqueue order = state-change order = wire order, because
//     every enqueue happens under the session's input-state mutex at the
//     point of state change (session.go).
//   - the writer-owned handoff accounting for inFlightBytes (R7-W1): the
//     countingWriteProxy installed by newOutputForwarder and the
//     serverOutputForwarder.inFlightBytes accessor defined here so this
//     work item does not touch output.go (held by a concurrent work item).
//
// Event atomicity: smux v2 Stream.Write splits payloads larger than one
// frame (~48 KB) into per-frame writeFrameInternal requests through the
// session-wide shaper, so two concurrent multi-frame Writes can interleave.
// Every ordered event is therefore one small pre-serialized buffer - a
// single frame - and classified reports carry COUNTS, never the discarded
// byte payload (the legacy byte-payload message stays on the legacy
// sendBusMessage path for non-negotiating clients). Non-coordinate bus
// messages (alive echo, detachAck, quit, exit, channel, error, debug) keep
// the existing direct path: their interleaving with ordered events is
// semantically inert, and the heartbeat RTT stays free of FIFO queueing
// delay.

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sync"
)

// kMaxOrderedReports caps the outstanding REPORT entries (all classified
// kinds) plus their unconsumed reservations in one connection's ordered
// sender. At the cap, marker installation is REFUSED (the session refuses
// input until a boundary can be established) - never degraded to an
// undisclosed marker (design §4.5, the round-6/7 degradation variant is
// removed as unsafe).
const kMaxOrderedReports = 256

// orderedEvent is one pre-serialized bus event in the ordered FIFO.
type orderedEvent struct {
	buf      []byte          // command + framed message, one write buffer
	session  *sessionContext // owning session (acks and input reports)
	isAck    bool            // an input_ack entry (the session's bounded slot)
	isReport bool            // counts against kMaxOrderedReports
	seq      uint64          // FIFO sequence number (barrier bookkeeping)
	epoch    uint64          // ack epoch (coalescing rule)
	idx      int             // queue index (in-place coalescing)
}

// sessionSenderState is the sender's per-session bookkeeping, guarded by
// orderedBusSender.mu.
type sessionSenderState struct {
	// pendingAck tracks the session's bounded ack slot: at most one ack
	// entry per session may sit in the FIFO (idx identifies it for
	// in-place coalescing; seq feeds the report barrier rule).
	pendingAckIdx   int
	pendingAckSeq   uint64
	pendingAckEpoch uint64
	// lastReportSeq is the FIFO sequence of the most recently enqueued
	// REPORT for this session: an ack may not be superseded once a report
	// was enqueued after it (the barrier).
	lastReportSeq uint64
	// boundaryIdx/boundarySeq track the session's enqueued-but-unsent
	// inputBoundary report: a re-install while the previous boundary is
	// still unsent REPLACES it in place (the superseded boundary never
	// existed for the client - its marker was never announced, so never
	// injected), which is what keeps a stalled connection's per-session
	// report occupancy bounded at 2 entries under repeated reconnects.
	boundaryIdx int
	boundarySeq uint64
	// reserved counts report slots reserved-but-not-yet-enqueued for this
	// session (the reserve-before-mutate admission of the marker
	// lifecycle: boundary + completion).
	reserved int
}

func (st *sessionSenderState) reset() {
	st.pendingAckIdx, st.pendingAckSeq, st.pendingAckEpoch = -1, 0, 0
	st.lastReportSeq, st.boundaryIdx, st.boundarySeq = 0, -1, 0
	st.reserved = 0
}

// orderedBusSender is the per-connection ordered event sender. ONE run()
// goroutine alone performs the bus-stream writes of ordered events; no
// enqueue ever waits on the network.
type orderedBusSender struct {
	mu     sync.Mutex
	stream Stream
	queue  []orderedEvent
	head   int // index of the next event to send; entries before it are done
	seq    uint64
	states map[*sessionContext]*sessionSenderState
	// reports is the outstanding count of enqueued report entries plus
	// unconsumed reservations, bounded by kMaxOrderedReports.
	reports int
	// broken is latched when a REPORT's bus write fails: emission stops
	// (the client can never process an ack whose prerequisite report was
	// lost); every later enqueue is dropped.
	broken  bool
	stopped bool
	wake    chan struct{}
	stopCh  chan struct{}
}

func newOrderedBusSender(stream Stream) *orderedBusSender {
	return &orderedBusSender{
		stream: stream,
		states: make(map[*sessionContext]*sessionSenderState),
		wake:   make(chan struct{}, 1),
		stopCh: make(chan struct{}),
	}
}

func (s *orderedBusSender) stateFor(sess *sessionContext) *sessionSenderState {
	st, ok := s.states[sess]
	if !ok {
		st = &sessionSenderState{}
		st.reset()
		s.states[sess] = st
	}
	return st
}

// buildOrderedEvent pre-serializes one bus event into the exact
// command+length+payload framing sendCommandAndMessage produces, so run()
// performs a single atomic write of a single smux frame.
func buildOrderedEvent(command string, msg any) ([]byte, error) {
	msgBuf, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("marshal ordered event [%s] failed: %w", command, err)
	}
	if len(command) == 0 || len(command) > 255 {
		return nil, fmt.Errorf("ordered event command invalid: %s", command)
	}
	buffer := make([]byte, 1+len(command)+4+len(msgBuf))
	buffer[0] = uint8(len(command))
	copy(buffer[1:], []byte(command))
	binary.BigEndian.PutUint32(buffer[1+len(command):], uint32(len(msgBuf)))
	copy(buffer[1+len(command)+4:], msgBuf)
	return buffer, nil
}

// signalLocked wakes the run goroutine. The wake channel is buffered (cap 1)
// and the append already happened under s.mu, so a publication racing an
// idle or sleeping sender is never lost: either the wake is delivered, or
// one was already pending (the sender re-checks the FIFO after every wake).
// This is the durable-handoff property the R7-B1 executor contract requires.
func (s *orderedBusSender) signalLocked() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// reserveReports admits n future report entries for sess before a state
// change (reserve-before-mutate). Returns false at the cap or on a
// broken/stopped sender - the caller must then NOT perform the mutation.
func (s *orderedBusSender) reserveReports(sess *sessionContext, n int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.broken || s.stopped {
		return false
	}
	if s.reports+n > kMaxOrderedReports {
		return false
	}
	s.reports += n
	s.stateFor(sess).reserved += n
	return true
}

// releaseReports returns unused reservations (an empty-prefix completion, a
// superseded or detached boundary). n may not exceed the session's reserved
// count.
func (s *orderedBusSender) releaseReports(sess *sessionContext, n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.stateFor(sess)
	if n > st.reserved {
		n = st.reserved
	}
	st.reserved -= n
	s.reports -= n
}

// enqueueReport appends one classified discard report. It consumes one of
// the session's reserved slots when present (the marker lifecycle's
// pre-admission); an unreserved enqueue (a future ad-hoc report) is
// admitted only under the cap and fails (dropped) at the cap - never
// blocking.
func (s *orderedBusSender) enqueueReport(sess *sessionContext, msg discardMessage) bool {
	buf, err := buildOrderedEvent("discard", &msg)
	if err != nil {
		warning("build discard report failed: %v", err)
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.broken || s.stopped {
		return false
	}
	st := s.stateFor(sess)
	if st.reserved > 0 {
		st.reserved--
	} else if s.reports < kMaxOrderedReports {
		s.reports++
	} else {
		// Cap: an unreserved report is dropped (advisory). Load-bearing
		// reports always arrive through reserveReports first.
		return false
	}
	ev := orderedEvent{buf: buf, session: sess, isReport: true}
	s.pushLocked(&ev)
	st.lastReportSeq = ev.seq
	return true
}

// enqueueBoundaryReport appends (or, when the previous boundary report is
// still unsent, REPLACES in place) the session's inputBoundary report -
// the load-bearing announcement the client injects its marker from.
// Consumes one reserved slot exactly like enqueueReport.
func (s *orderedBusSender) enqueueBoundaryReport(sess *sessionContext, msg discardMessage) bool {
	buf, err := buildOrderedEvent("discard", &msg)
	if err != nil {
		warning("build discard report failed: %v", err)
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.broken || s.stopped {
		return false
	}
	st := s.stateFor(sess)
	// Supersede in place when the previous boundary report is still
	// unsent: the client never learned its marker (so never injected it),
	// and the newest boundary is the only one that ever existed for it.
	// The entry keeps its FIFO position and its already-paid slot; the
	// newly reserved boundary slot is returned (no new entry is created).
	if st.boundarySeq != 0 && st.boundaryIdx >= s.head && st.boundaryIdx < len(s.queue) {
		old := &s.queue[st.boundaryIdx]
		if old.session == sess && old.seq == st.boundarySeq && old.isReport {
			if st.reserved > 0 {
				st.reserved--
				s.reports--
			}
			old.buf = buf
			st.lastReportSeq = old.seq
			return true
		}
	}
	if st.reserved > 0 {
		st.reserved--
	} else if s.reports < kMaxOrderedReports {
		s.reports++
	} else {
		// Cap: an unreserved report is dropped (advisory). Load-bearing
		// reports always arrive through reserveReports first.
		return false
	}
	ev := orderedEvent{buf: buf, session: sess, isReport: true}
	s.pushLocked(&ev)
	st.lastReportSeq = ev.seq
	st.boundaryIdx, st.boundarySeq = ev.idx, ev.seq
	return true
}

// offerAck offers one input_ack for sess (epoch and appliedBytes read
// under the session's input-state mutex at the point of state change).
// The bounded per-session slot admits at most one ack entry per session;
// a pending unsent entry may be superseded ONLY by a newer ack of the SAME
// epoch while no report was enqueued after it (never across a report
// barrier - the client's D must never be stale); any other offer is
// dropped. Acks are advisory.
func (s *orderedBusSender) offerAck(sess *sessionContext, epoch, appliedBytes uint64, writeMS int64) bool {
	buf, err := buildOrderedEvent("inputAck", &inputAckMessage{
		SessionID: sess.id, Epoch: epoch, AppliedBytes: appliedBytes, WriteMS: writeMS})
	if err != nil {
		warning("build input ack failed: %v", err)
		return false
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.broken || s.stopped {
		return false
	}
	st := s.stateFor(sess)
	if st.pendingAckSeq != 0 {
		if st.pendingAckEpoch == epoch && st.lastReportSeq < st.pendingAckSeq {
			// Same epoch, before the report barrier: coalesce in place.
			s.queue[st.pendingAckIdx].buf = buf
			return true
		}
		return false // barrier or cross-epoch: drop (advisory)
	}
	ev := orderedEvent{buf: buf, session: sess, isAck: true, epoch: epoch}
	s.pushLocked(&ev)
	st.pendingAckIdx, st.pendingAckSeq, st.pendingAckEpoch = ev.idx, ev.seq, epoch
	return true
}

// pushLocked appends an event and assigns its FIFO identity (seq for the
// barrier rule, idx for in-place coalescing). The event is passed by
// POINTER: the identity is written back into the caller's copy.
func (s *orderedBusSender) pushLocked(ev *orderedEvent) {
	s.seq++
	ev.seq = s.seq
	ev.idx = len(s.queue)
	s.queue = append(s.queue, *ev)
	s.signalLocked()
}

// popLocked returns the next event or none. The event is returned BY
// VALUE: the sender reads its buffer after releasing the mutex, so it
// must not alias the queue's storage (compaction can overwrite it).
func (s *orderedBusSender) popLocked() (orderedEvent, bool) {
	if s.head >= len(s.queue) {
		return orderedEvent{}, false
	}
	ev := s.queue[s.head]
	s.head++
	// Compact the consumed prefix so the queue's memory stays bounded by
	// the live window, not the connection's lifetime. Compaction shifts
	// live entries toward the front, so every session's pending-ack and
	// boundary indices shift with them (an index below the old head
	// belonged to an entry already sent - popLocked clears those slots at
	// send time, so this is a defensive clamp only).
	if s.head == len(s.queue) && s.head > 0 {
		s.queue, s.head = s.queue[:0], 0
		s.reindexSlotsLocked(0)
	} else if s.head > 1024 {
		shift := s.head
		n := copy(s.queue, s.queue[shift:])
		s.queue, s.head = s.queue[:n], 0
		s.reindexSlotsLocked(shift)
	}
	return ev, true
}

// reindexSlotsLocked adjusts the pending-ack and boundary queue indices
// after a compaction that shifted live entries down by `shift`.
func (s *orderedBusSender) reindexSlotsLocked(shift int) {
	for _, st := range s.states {
		if st.pendingAckSeq != 0 {
			st.pendingAckIdx -= shift
			if st.pendingAckIdx < 0 {
				st.pendingAckIdx, st.pendingAckSeq, st.pendingAckEpoch = -1, 0, 0
			}
		}
		if st.boundarySeq != 0 {
			st.boundaryIdx -= shift
			if st.boundaryIdx < 0 {
				st.boundaryIdx, st.boundarySeq = -1, 0
			}
		}
	}
}

// run is the ONE goroutine that alone writes ordered events to the bus
// stream. It exits when stopped or when a report write fails (broken
// stream: emission stops).
func (s *orderedBusSender) run() {
	for {
		s.mu.Lock()
		ev, ok := s.popLocked()
		if !ok {
			s.mu.Unlock()
			select {
			case <-s.wake:
				continue
			case <-s.stopCh:
				return
			}
		}
		st := s.stateFor(ev.session)
		if ev.isAck {
			st.pendingAckSeq, st.pendingAckIdx = 0, -1
		} else if st.boundarySeq == ev.seq {
			st.boundarySeq, st.boundaryIdx = 0, -1
		}
		if ev.isReport {
			s.reports--
		}
		s.mu.Unlock()

		if err := writeAll(s.stream, ev.buf); err != nil {
			if ev.isReport {
				// On a discard report's bus-write failure the ordered
				// stream is marked broken and emission stops (design
				// §4.5): the client must never process an ack whose
				// prerequisite report was lost.
				s.mu.Lock()
				s.broken = true
				s.queue, s.head = nil, 0
				s.mu.Unlock()
				warning("ordered bus stream broken: %v", err)
				return
			}
			// An ack write failure drops that ack (advisory); the next
			// report failure latches the break.
			continue
		}
	}
}

// stop terminates the sender (server Close); idempotent.
func (s *orderedBusSender) stop() {
	s.mu.Lock()
	if !s.stopped {
		s.stopped = true
		close(s.stopCh)
	}
	s.mu.Unlock()
}

// countingWriteProxy tracks the writer-owned bytes of the forwarder's
// in-progress transport write: bytes accepted into Write minus bytes the
// underlying stream has taken. Installed by newOutputForwarder
// (session.go) so tsshd#7 does not touch output.go. writeAll drives it
// with whole buffers; a partial write leaves the remainder counted, and an
// error leaves the never-completed remainder counted too - exactly the
// writer-owned handoff unit R7-W1 defines.
type countingWriteProxy struct {
	Stream
	mu      sync.Mutex
	inWrite uint64
}

func (p *countingWriteProxy) Write(buf []byte) (int, error) {
	p.mu.Lock()
	p.inWrite += uint64(len(buf))
	p.mu.Unlock()
	n, err := p.Stream.Write(buf)
	p.mu.Lock()
	p.inWrite -= uint64(n)
	p.mu.Unlock()
	return n, err
}

func (p *countingWriteProxy) inFlight() uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.inWrite
}

// inFlightBytes is the R7-W1 definition: the writer-owned handoff backlog
// of this forwarder at report time - the unwritten remainder of the buffer
// writerLoop is currently writing (countingWriteProxy.inWrite, installed as
// the forwarder's stream by newOutputForwarder), plus the bytes in the one
// buffer already accepted into writeBufCh. It EXCLUDES bytes still in
// cacheLines (pending cache, accounted by the discard counters), bytes
// inside kcp's send queue, and kernel/PTY buffers.
//
// The queued-channel share is not byte-measurable without instrumenting
// the push sites in output.go (concurrently locked by tsshd#13); its
// push-site accounting lands with tsshd#8's population of the field. The
// definition and the in-progress remainder are exact here.
func (f *serverOutputForwarder) inFlightBytes() uint64 {
	if p, ok := f.stream.(*countingWriteProxy); ok {
		return p.inFlight()
	}
	return 0
}
