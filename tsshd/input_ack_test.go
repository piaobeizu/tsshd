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

// Protocol gates for tsshd#7: capability-negotiated input-ACCEPTED ack on
// the bus stream. Two layers:
//
//   - Unit tests against fake streams for the orderedBusSender mechanics
//     (ack coalescing, the report barrier, the 256-entry cap, the broken
//     stream, the durable wake), the marker lifecycle (reserve-before-
//     mutate, refusal, supersede, completion at the pre-marker epoch) and
//     the R7-W1 inFlightBytes measurement.
//   - ONE full-stack in-process test (initServer + NewSshUdpClient, the
//     detach_test.go pattern: SSH_CONNECTION neutralized,
//     activeSshUdpServer reset + cleanupOnExit in teardown, Detach() not
//     Close(), exactly one initServer per process - see the in-process
//     poisoning notes in control_latency_test.go).
//
// Every wait is bounded; a hung path fails the test instead of wedging it.

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// ---------------------------------------------------------------------------
// fakes
// ---------------------------------------------------------------------------

// ackTestStream is a scriptable Stream: writes are recorded, and an
// optional stall channel or scripted failure controls them.
type ackTestStream struct {
	mu     sync.Mutex
	writes [][]byte
	stall  chan struct{} // non-nil: every write blocks until closed
	failN  int           // >0: this write and every later one fail
	n      int
}

func newAckTestStream() *ackTestStream {
	return &ackTestStream{}
}

func (s *ackTestStream) Write(buf []byte) (int, error) {
	if s.stall != nil {
		<-s.stall
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.n++
	if s.failN > 0 && s.n >= s.failN {
		return 0, fmt.Errorf("scripted write failure #%d", s.n)
	}
	s.writes = append(s.writes, append([]byte(nil), buf...))
	return len(buf), nil
}

func (s *ackTestStream) recorded() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([][]byte, len(s.writes))
	copy(out, s.writes)
	return out
}

func (s *ackTestStream) Read(buf []byte) (int, error)       { return 0, io.EOF }
func (s *ackTestStream) Close() error                       { return nil }
func (s *ackTestStream) CloseRead() error                   { return nil }
func (s *ackTestStream) CloseWrite() error                  { return nil }
func (s *ackTestStream) LocalAddr() net.Addr                { return nil }
func (s *ackTestStream) RemoteAddr() net.Addr               { return nil }
func (s *ackTestStream) SetDeadline(t time.Time) error      { return nil }
func (s *ackTestStream) SetReadDeadline(t time.Time) error  { return nil }
func (s *ackTestStream) SetWriteDeadline(t time.Time) error { return nil }

// parseAckTestEvent decodes one recorded write into (command, payload).
// The buffer mirrors buildOrderedEvent/sendCommandAndMessage framing:
// [cmdlen][command][4-byte payload length][payload].
func parseAckTestEvent(t *testing.T, buf []byte) (string, []byte) {
	t.Helper()
	if len(buf) < 1 || int(buf[0]) > len(buf)-1 {
		t.Fatalf("bad event framing: len=%d cmdlen=%d", len(buf), buf[0])
	}
	cmd := string(buf[1 : 1+buf[0]])
	rest := buf[1+buf[0]:]
	if len(rest) < 4 {
		t.Fatalf("bad event payload length prefix: %v", rest)
	}
	plen := int(binary.BigEndian.Uint32(rest[:4]))
	if len(rest)-4 != plen {
		t.Fatalf("bad event payload: want %d bytes, got %d", plen, len(rest)-4)
	}
	return cmd, rest[4:]
}

func decodeAckTestMessage(t *testing.T, payload []byte, msg any) {
	t.Helper()
	if err := json.Unmarshal(payload, msg); err != nil {
		t.Fatalf("unmarshal %s failed: %v", payload, err)
	}
}

// newAckTestSession builds a bare sessionContext with a pipe stdin, for
// marker-lifecycle tests that do not need a real PTY.
func newAckTestSession(id uint64) (*sessionContext, *io.PipeReader) {
	pipeReader, pipeWriter := io.Pipe()
	sess := &sessionContext{id: id, stdin: pipeWriter, inputApplied: inputEpochCounter{epoch: kFirstInputEpoch}}
	return sess, pipeReader
}

// newAckTestSender wires a sender to a fake stream and runs it.
func newAckTestSender(stream Stream) *orderedBusSender {
	sender := newOrderedBusSender(stream)
	go sender.run()
	return sender
}

// waitUntil polls cond with a bound.
func waitUntil(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cond()
}

func senderBroken(s *orderedBusSender) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.broken
}

func senderDrained(s *orderedBusSender) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.queue) == 0
}

// ackTestServer builds a bare sshUdpServer wired for the input-ack path.
func ackTestServer(sender *orderedBusSender, ack bool) *sshUdpServer {
	server := &sshUdpServer{orderedSender: sender}
	server.inputAck.Store(ack)
	return server
}

// ---------------------------------------------------------------------------
// orderedBusSender unit gates
// ---------------------------------------------------------------------------

// TestOrderedSenderAckCoalescing pins the epoch-aware, barrier-respecting
// coalescing rule: a pending unsent ack may be superseded only by a newer
// ack of the SAME epoch while no report was enqueued after it; anything
// else drops. Also pins wire order = state-change order (an ack never
// overtakes a preceding report).
func TestOrderedSenderAckCoalescing(t *testing.T) {
	// Same-epoch coalescing, inspected on the staged queue (the sender is
	// NOT running, so the entry is deterministically still pending): two
	// offers coalesce into one entry with the newest coordinates.
	stream := newAckTestStream()
	sender := newOrderedBusSender(stream)
	defer sender.stop()
	sess, _ := newAckTestSession(7)

	if !sender.offerAck(sess, 1, 10, 0) {
		t.Fatalf("first ack offer must be admitted")
	}
	if !sender.offerAck(sess, 1, 20, 0) {
		t.Fatalf("same-epoch pre-barrier offer must coalesce")
	}
	sender.mu.Lock()
	staged := append([]orderedEvent(nil), sender.queue[sender.head:]...)
	sender.mu.Unlock()
	if len(staged) != 1 {
		t.Fatalf("coalescing must stage exactly one ack, got %d", len(staged))
	}
	cmd, payload := parseAckTestEvent(t, staged[0].buf)
	if cmd != "inputAck" {
		t.Fatalf("want inputAck, got %s", cmd)
	}
	var ack inputAckMessage
	decodeAckTestMessage(t, payload, &ack)
	if ack.AppliedBytes != 20 || ack.Epoch != 1 || ack.SessionID != 7 {
		t.Fatalf("coalesced ack must carry the newest coordinates: %+v", ack)
	}

	// Cross-epoch offer while a different-epoch ack is pending: dropped.
	sender2 := newOrderedBusSender(newAckTestStream())
	defer sender2.stop()
	if !sender2.offerAck(sess, 1, 10, 0) {
		t.Fatalf("first ack offer must be admitted")
	}
	if sender2.offerAck(sess, 2, 30, 0) {
		t.Fatalf("cross-epoch supersede must be refused")
	}
	sender2.mu.Lock()
	staged2 := append([]orderedEvent(nil), sender2.queue[sender2.head:]...)
	sender2.mu.Unlock()
	if len(staged2) != 1 {
		t.Fatalf("a refused offer must not add an entry, got %d", len(staged2))
	}
	_, p := parseAckTestEvent(t, staged2[0].buf)
	var ack2 inputAckMessage
	decodeAckTestMessage(t, p, &ack2)
	if ack2.Epoch != 1 || ack2.AppliedBytes != 10 {
		t.Fatalf("the pending ack must keep its own coordinates: %+v", ack2)
	}

	// Barrier: stage the pair and the refused offer with the sender NOT
	// running (deterministic), then drain and check the wire order keeps
	// the frozen ack before the report, and that the post-drain offer
	// lands after it.
	stream3 := newAckTestStream()
	sender3 := newOrderedBusSender(stream3)
	if !sender3.reserveReports(sess, 1) {
		t.Fatalf("report reservation must succeed")
	}
	if !sender3.offerAck(sess, 3, 100, 0) {
		t.Fatalf("ack offer must be admitted")
	}
	if !sender3.enqueueReport(sess, discardMessage{Kind: kDiscardKindInputCompleted, SessionID: 7, Epoch: 2}) {
		t.Fatalf("report enqueue must succeed on its reservation")
	}
	if sender3.offerAck(sess, 3, 200, 0) {
		t.Fatalf("post-barrier supersede must be refused (the client's D would go stale)")
	}
	go sender3.run()
	defer sender3.stop()
	if !waitUntil(2*time.Second, func() bool { return len(stream3.recorded()) >= 2 }) {
		t.Fatalf("sender never drained the ack + report pair")
	}
	cmdA, pA := parseAckTestEvent(t, stream3.recorded()[0])
	cmdB, _ := parseAckTestEvent(t, stream3.recorded()[1])
	if cmdA != "inputAck" || cmdB != "discard" {
		t.Fatalf("wire order must keep the frozen ack before the report: %s then %s", cmdA, cmdB)
	}
	var frozen inputAckMessage
	decodeAckTestMessage(t, pA, &frozen)
	if frozen.Epoch != 3 || frozen.AppliedBytes != 100 {
		t.Fatalf("the barrier must freeze the pending ack's coordinates: %+v", frozen)
	}
	// The slot freed after the send: a fresh offer is admitted and lands
	// after the report (state-change order).
	if !sender3.offerAck(sess, 3, 200, 0) {
		t.Fatalf("post-drain ack offer must be admitted")
	}
	if !waitUntil(2*time.Second, func() bool { return len(stream3.recorded()) >= 3 }) {
		t.Fatalf("sender never drained the post-barrier ack")
	}
	cmdC, _ := parseAckTestEvent(t, stream3.recorded()[2])
	if cmdC != "inputAck" {
		t.Fatalf("the post-barrier ack must follow the report, got %s", cmdC)
	}
}

// TestOrderedSenderCapAndReservations pins the 256-entry outstanding cap
// and the reserve/release accounting: reservations count against the cap,
// and a release frees exactly its slots.
func TestOrderedSenderCapAndReservations(t *testing.T) {
	stream := newAckTestStream()
	stream.stall = make(chan struct{})
	sender := newOrderedBusSender(stream)
	go sender.run()
	defer func() { close(stream.stall); sender.stop() }()

	var dummies []*sessionContext
	for {
		s, _ := newAckTestSession(uint64(len(dummies) + 500))
		if !sender.reserveReports(s, 2) {
			break
		}
		dummies = append(dummies, s)
	}
	if len(dummies) != kMaxOrderedReports/2 {
		t.Fatalf("the cap must admit exactly %d full reservations, got %d", kMaxOrderedReports/2, len(dummies))
	}
	realSess, _ := newAckTestSession(999)
	if sender.reserveReports(realSess, 2) {
		t.Fatalf("reservation must fail at the cap")
	}

	// Releasing one dummy frees exactly its slots.
	sender.releaseReports(dummies[0], 2)
	if !sender.reserveReports(realSess, 2) {
		t.Fatalf("reservation must succeed after a release")
	}
	sender.mu.Lock()
	outstanding := sender.reports
	sender.mu.Unlock()
	if outstanding != kMaxOrderedReports {
		t.Fatalf("outstanding must be exactly the cap, got %d", outstanding)
	}
}

// TestOrderedSenderBrokenStopsEmission pins the break rule: a REPORT's
// write failure latches the ordered stream broken and emission stops -
// nothing (ack or report) is emitted after the break. An ACK write failure
// alone only drops that ack.
func TestOrderedSenderBrokenStopsEmission(t *testing.T) {
	// An ack write failure does not break the stream by itself.
	stream := newAckTestStream()
	stream.failN = 1
	sender := newAckTestSender(stream)
	defer sender.stop()
	sess, _ := newAckTestSession(1)
	if !sender.offerAck(sess, 1, 5, 0) {
		t.Fatalf("ack offer must be admitted")
	}
	if !waitUntil(2*time.Second, func() bool { return senderDrained(sender) }) {
		t.Fatalf("sender did not process the failed ack write")
	}
	if senderBroken(sender) {
		t.Fatalf("an ack write failure must not break the ordered stream")
	}

	// A report write failure latches broken and stops emission.
	stream2 := newAckTestStream()
	stream2.failN = 1
	sender2 := newAckTestSender(stream2)
	defer sender2.stop()
	sess2, _ := newAckTestSession(2)
	if !sender2.reserveReports(sess2, 2) {
		t.Fatalf("report reservation must succeed")
	}
	if !sender2.enqueueReport(sess2, discardMessage{Kind: kDiscardKindInputBoundary, SessionID: 2}) {
		t.Fatalf("report enqueue must succeed")
	}
	if !waitUntil(2*time.Second, func() bool { return senderBroken(sender2) }) {
		t.Fatalf("a report write failure must latch the ordered stream broken")
	}
	if sender2.offerAck(sess2, 1, 1, 0) {
		t.Fatalf("no ack may be offered after the break")
	}
	if sender2.reserveReports(sess2, 1) {
		t.Fatalf("no reservation may be admitted after the break")
	}
}

// TestOrderedSenderWakeWhileIdle pins the durable-handoff property (the
// input-path share of the R7-B1 executor contract): an enqueue racing an
// idle sender is never lost.
func TestOrderedSenderWakeWhileIdle(t *testing.T) {
	stream := newAckTestStream()
	sender := newOrderedBusSender(stream)
	go sender.run()
	defer sender.stop()

	// Let the sender go idle on the wake channel.
	time.Sleep(50 * time.Millisecond)

	sess, _ := newAckTestSession(3)
	if !sender.offerAck(sess, 1, 42, 0) {
		t.Fatalf("ack offer must be admitted")
	}
	if !waitUntil(time.Second, func() bool { return len(stream.recorded()) >= 1 }) {
		t.Fatalf("idle sender lost the publication - durable wake broken")
	}
	_, payload := parseAckTestEvent(t, stream.recorded()[0])
	var ack inputAckMessage
	decodeAckTestMessage(t, payload, &ack)
	if ack.AppliedBytes != 42 {
		t.Fatalf("wrong ack: %+v", ack)
	}
}

// ---------------------------------------------------------------------------
// marker lifecycle unit gates (R7-B3 / R7-B4)
// ---------------------------------------------------------------------------

// TestMarkerLifecycleReserveAndComplete drives the full lifecycle on a bare
// session: install (reserve 2, epoch bump, boundary report), discard a
// prefix (completion at the pre-marker epoch), apply the surviving suffix,
// and the empty-prefix release - all without ever blocking on queue space.
func TestMarkerLifecycleReserveAndComplete(t *testing.T) {
	stream := newAckTestStream()
	sender := newAckTestSender(stream)
	defer sender.stop()

	sess, stdinPipe := newAckTestSession(11)
	server := ackTestServer(sender, true)

	marker := []byte{0xFF, 0xC0, 0xC1, 0xFF, 1, 0, 0, 1}
	if !sess.installInputBoundary(server, marker, true) {
		t.Fatalf("install must succeed with free capacity")
	}
	sess.inputStateMu.Lock()
	epoch, refused, pendingReserved := sess.inputApplied.epoch, sess.inputRefused, sess.pendingDiscardReserved
	closedEpoch := sess.pendingDiscardEpoch
	sess.inputStateMu.Unlock()
	if epoch != kFirstInputEpoch+1 || refused || !pendingReserved {
		t.Fatalf("install must bump the epoch, clear refusal and hold the completion slot: epoch=%d refused=%v held=%v", epoch, refused, pendingReserved)
	}
	if closedEpoch != kFirstInputEpoch {
		t.Fatalf("the completion must be attributed to the pre-marker epoch %d, got %d", kFirstInputEpoch, closedEpoch)
	}

	// Stale prefix + marker + live suffix through the discard machinery.
	// The pipe reader must exist BEFORE the call, and the marker pointer is
	// the one the install STORED (as acceptInput loads it in production).
	prefix := []byte("STALEINPUT")
	suffix := []byte("LIVEINPUT")
	buf := append(append([]byte(nil), prefix...), marker...)
	buf = append(buf, suffix...)
	type pipeRead struct {
		n   int
		buf []byte
	}
	got := make(chan pipeRead, 1)
	go func() {
		b := make([]byte, 32)
		n, _ := stdinPipe.Read(b)
		got <- pipeRead{n, append([]byte(nil), b[:n]...)}
	}()
	stored := sess.discardMarker.Load()
	if stored == nil {
		t.Fatalf("the install must have stored its marker")
	}
	if err := sess.discardPendingInput(server, buf, stored); err != nil {
		t.Fatalf("discardPendingInput failed: %v", err)
	}

	// The surviving suffix reached the PTY (the pipe) verbatim.
	select {
	case r := <-got:
		if string(r.buf[:r.n]) != string(suffix) {
			t.Fatalf("surviving suffix must be applied verbatim, got %q", r.buf[:r.n])
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("surviving suffix never reached the PTY")
	}

	// Wire order: the boundary report first, then the completion report at
	// the closed epoch, then the ack covering the suffix.
	if !waitUntil(2*time.Second, func() bool { return len(stream.recorded()) >= 3 }) {
		t.Fatalf("sender never drained boundary + completion + ack")
	}
	var kinds []string
	var epochs []uint64
	ackSeen, ackApplied := false, uint64(0)
	for _, w := range stream.recorded() {
		cmd, payload := parseAckTestEvent(t, w)
		switch cmd {
		case "discard":
			var msg discardMessage
			decodeAckTestMessage(t, payload, &msg)
			kinds = append(kinds, msg.Kind)
			epochs = append(epochs, msg.Epoch)
			if msg.Kind == kDiscardKindInputCompleted && msg.DiscardedInputBytes != uint64(len(prefix)) {
				t.Fatalf("completion must report the exact prefix length, got %d", msg.DiscardedInputBytes)
			}
		case "inputAck":
			var ack inputAckMessage
			decodeAckTestMessage(t, payload, &ack)
			ackSeen, ackApplied = true, ack.AppliedBytes
			if ack.Epoch != kFirstInputEpoch+1 {
				t.Fatalf("the suffix ack must carry the new epoch, got %d", ack.Epoch)
			}
		}
	}
	if len(kinds) < 2 || kinds[0] != kDiscardKindInputBoundary || kinds[1] != kDiscardKindInputCompleted {
		t.Fatalf("wire order must be boundary then completion, got %v", kinds)
	}
	if epochs[1] != kFirstInputEpoch {
		t.Fatalf("completion must be attributed to the pre-marker epoch (R7-B4), got %d", epochs[1])
	}
	if !ackSeen || ackApplied != uint64(len(suffix)) {
		t.Fatalf("the suffix ack must count exactly the applied suffix bytes, got %d", ackApplied)
	}

	// Marker-only: a fresh boundary with an empty prefix releases the
	// completion slot without emitting a completion report. The marker is
	// loaded from the session exactly as acceptInput does in production
	// (pointer identity is the reservation's ownership token).
	before := len(stream.recorded())
	marker2 := []byte{0xFF, 0xC0, 0xC1, 0xFF, 1, 0, 0, 2}
	if !sess.installInputBoundary(server, marker2, true) {
		t.Fatalf("second install must succeed")
	}
	stored2 := sess.discardMarker.Load()
	if stored2 == nil {
		t.Fatalf("the second install must have stored its marker")
	}
	if err := sess.discardPendingInput(server, append([]byte(nil), *stored2...), stored2); err != nil {
		t.Fatalf("marker-only discard failed: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	for _, w := range stream.recorded()[before:] {
		cmd, payload := parseAckTestEvent(t, w)
		if cmd != "discard" {
			continue
		}
		var msg discardMessage
		decodeAckTestMessage(t, payload, &msg)
		if msg.Kind == kDiscardKindInputCompleted {
			t.Fatalf("marker-only discard must not emit a completion report")
		}
	}
	sess.inputStateMu.Lock()
	held := sess.pendingDiscardReserved
	sess.inputStateMu.Unlock()
	if held {
		t.Fatalf("marker-only discard must release the completion slot")
	}
}

// TestMarkerRefusalAtCap pins reserve-before-mutate: at the report cap the
// marker is NOT installed, the epoch does not bump, the session refuses
// input (dropped, never blocking), and a later successful install clears
// the refusal.
func TestMarkerRefusalAtCap(t *testing.T) {
	stream := newAckTestStream()
	sender := newOrderedBusSender(stream)
	go sender.run()
	defer sender.stop()

	var dummies []*sessionContext
	for {
		s, _ := newAckTestSession(uint64(len(dummies) + 500))
		if !sender.reserveReports(s, 2) {
			break
		}
		dummies = append(dummies, s)
	}
	if len(dummies) == 0 {
		t.Fatalf("the cap must admit at least one reservation")
	}

	sess, _ := newAckTestSession(42)
	server := ackTestServer(sender, true)
	marker := []byte{0xFF, 0xC0, 0xC1, 0xFF, 1, 0, 0, 9}

	if sess.installInputBoundary(server, marker, true) {
		t.Fatalf("install must fail at the cap")
	}
	sess.inputStateMu.Lock()
	epoch, refused := sess.inputApplied.epoch, sess.inputRefused
	sess.inputStateMu.Unlock()
	if !refused {
		t.Fatalf("the session must refuse input when no boundary can be established")
	}
	if epoch != kFirstInputEpoch {
		t.Fatalf("a refused install must not bump the epoch, got %d", epoch)
	}
	if m := sess.discardMarker.Load(); m != nil {
		t.Fatalf("a refused install must not install the marker")
	}

	// Refused input is dropped without touching the PTY (stdin is nil
	// here: a write attempt would panic inside writeAll, so returning
	// cleanly IS the no-stall assertion).
	if err := sess.acceptInput(server, []byte("must be dropped")); err != nil {
		t.Fatalf("refused input must be dropped without error: %v", err)
	}

	// Free the capacity: a later reconnect's install succeeds and clears
	// the refusal.
	sender.releaseReports(dummies[0], 2)
	if !sess.installInputBoundary(server, marker, true) {
		t.Fatalf("install must succeed once capacity frees")
	}
	sess.inputStateMu.Lock()
	refused = sess.inputRefused
	sess.inputStateMu.Unlock()
	if refused {
		t.Fatalf("a successful install must clear the refusal")
	}
}

// TestMarkerSupersedeBoundedOccupancy pins the repeated-reconnect policy
// under a STALLED (not failed) sender: a re-install releases the previous
// boundary's stale completion slot, so per-session occupancy stays bounded
// and nothing blocks; once the stream drains, everything completes.
func TestMarkerSupersedeBoundedOccupancy(t *testing.T) {
	// The sender is NOT running while the boundaries install: the staged
	// FIFO is the stalled-wire model (a backed-up ordered stream), and it
	// is what makes the in-place replacement observable - once the sender
	// pops an entry it owns it, and a re-install legitimately pushes a new
	// one.
	stream := newAckTestStream()
	sender := newOrderedBusSender(stream)
	defer sender.stop()

	sess, _ := newAckTestSession(5)
	server := ackTestServer(sender, true)

	m1 := []byte{0xFF, 0xC0, 0xC1, 0xFF, 2, 0, 0, 1}
	if !sess.installInputBoundary(server, m1, true) {
		t.Fatalf("first install must succeed")
	}
	sender.mu.Lock()
	first := sender.reports
	sender.mu.Unlock()
	if first != 2 {
		t.Fatalf("a stalled install holds boundary+completion, got %d outstanding", first)
	}

	for i := 2; i <= 5; i++ {
		m := []byte{0xFF, 0xC0, 0xC1, 0xFF, 2, 0, 0, byte(i)}
		if !sess.installInputBoundary(server, m, true) {
			t.Fatalf("re-install #%d must succeed under the stall", i)
		}
		sender.mu.Lock()
		outstanding := sender.reports
		sender.mu.Unlock()
		if outstanding > 2 {
			t.Fatalf("occupancy must stay bounded at 2, got %d", outstanding)
		}
	}

	go sender.run()
	if !waitUntil(2*time.Second, func() bool { return senderDrained(sender) }) {
		t.Fatalf("the backed-up sender never drained")
	}
	// The five installs produced exactly ONE boundary report on the wire -
	// the newest (the superseded four were replaced in place while unsent)
	// - and exactly one reservation (the unconsummated completion slot)
	// remains held.
	boundaries, lastEpoch := 0, uint64(0)
	for _, w := range stream.recorded() {
		cmd, payload := parseAckTestEvent(t, w)
		if cmd != "discard" {
			continue
		}
		var msg discardMessage
		decodeAckTestMessage(t, payload, &msg)
		if msg.Kind == kDiscardKindInputBoundary {
			boundaries++
			lastEpoch = msg.Epoch
		}
	}
	if boundaries != 1 {
		t.Fatalf("five stalled re-installs must collapse to one boundary report, got %d", boundaries)
	}
	if lastEpoch != kFirstInputEpoch+5 {
		t.Fatalf("the surviving boundary must be the newest epoch %d, got %d", kFirstInputEpoch+5, lastEpoch)
	}
	sender.mu.Lock()
	outstanding := sender.reports
	sender.mu.Unlock()
	if outstanding != 1 {
		t.Fatalf("exactly the held completion slot must remain, got %d outstanding", outstanding)
	}
}

// TestMarkerWriteAcrossBoundaryEpochAttribution pins the R7-B4 attribution
// for a PTY write in flight across an installation: the bytes land in the
// CLOSED epoch's counter and are never acked; post-install writes count in
// the new epoch and are acked.
func TestMarkerWriteAcrossBoundaryEpochAttribution(t *testing.T) {
	stream := newAckTestStream()
	sender := newAckTestSender(stream)
	defer sender.stop()

	sess, stdinPipe := newAckTestSession(9)
	server := ackTestServer(sender, true)

	// A write of the closed epoch's bytes, straddled across the install:
	// the write goroutine snapshots its epoch (as acceptInput does) and
	// signals BEFORE entering the PTY write - nobody drains the pipe yet,
	// so the write stays blocked inside writeAll while the boundary
	// installs; only after the install does the drain start, so the write
	// completes in the CLOSED epoch deterministically.
	snapDone := make(chan struct{})
	writeDone := make(chan error, 1)
	go func() {
		sess.inputStateMu.Lock()
		snap := sess.inputApplied.epoch
		sess.inputStateMu.Unlock()
		close(snapDone)
		if err := writeAll(sess.stdin, []byte("inflight")); err != nil {
			writeDone <- err
			return
		}
		sess.countAppliedInput(server, 8, snap)
		writeDone <- nil
	}()
	select {
	case <-snapDone:
	case <-time.After(2 * time.Second):
		t.Fatalf("the write goroutine never registered its snapshot")
	}
	time.Sleep(20 * time.Millisecond) // let it enter (and block in) the PTY write
	marker := []byte{0xFF, 0xC0, 0xC1, 0xFF, 3, 0, 0, 1}
	if !sess.installInputBoundary(server, marker, true) {
		t.Fatalf("install must succeed")
	}
	// Drain the pipe: the straddled write completes in the CLOSED epoch.
	go func() {
		buf := make([]byte, 64)
		for {
			if _, err := stdinPipe.Read(buf); err != nil {
				return
			}
		}
	}()
	if err := <-writeDone; err != nil {
		t.Fatalf("in-flight write failed: %v", err)
	}

	// A post-install write is counted and acked in the new epoch.
	sess.inputStateMu.Lock()
	snap2 := sess.inputApplied.epoch
	sess.inputStateMu.Unlock()
	if err := writeAll(sess.stdin, []byte("after")); err != nil {
		t.Fatalf("post-install write failed: %v", err)
	}
	sess.countAppliedInput(server, 5, snap2)

	if !waitUntil(2*time.Second, func() bool { return len(stream.recorded()) >= 2 }) {
		t.Fatalf("sender never drained boundary + post-install ack")
	}
	ackCount, lastApplied, lastEpoch := 0, uint64(0), uint64(0)
	for _, w := range stream.recorded() {
		cmd, payload := parseAckTestEvent(t, w)
		if cmd != "inputAck" {
			continue
		}
		ackCount++
		var ack inputAckMessage
		decodeAckTestMessage(t, payload, &ack)
		lastApplied, lastEpoch = ack.AppliedBytes, ack.Epoch
	}
	if ackCount != 1 {
		t.Fatalf("only the post-install write may be acked, got %d acks", ackCount)
	}
	if lastEpoch != kFirstInputEpoch+1 || lastApplied != 5 {
		t.Fatalf("the post-install ack must count only the new epoch's bytes: epoch=%d applied=%d", lastEpoch, lastApplied)
	}
}

// TestLegacyDiscardBytePayloadUnchanged pins the legacy (non-negotiating)
// path: the discarded prefix is reported as the byte payload through the
// direct sendBusMessage, with the surviving suffix applied first - exactly
// the pre-ack wire behavior.
func TestLegacyDiscardBytePayloadUnchanged(t *testing.T) {
	busStream := newAckTestStream()
	server := &sshUdpServer{}
	server.busStream = busStream

	sess, stdinPipe := newAckTestSession(13)
	marker := []byte{0xFF, 0xC0, 0xC1, 0xFF, 4, 0, 0, 1}
	sess.discardMarker.Store(&marker)

	prefix := []byte("OLD-INPUT")
	suffix := []byte("NEW-INPUT")
	buf := append(append([]byte(nil), prefix...), marker...)
	buf = append(buf, suffix...)

	// Drain the pipe concurrently.
	go func() {
		buf := make([]byte, 64)
		for {
			if _, err := stdinPipe.Read(buf); err != nil {
				return
			}
		}
	}()

	if err := sess.discardPendingInput(server, buf, &marker); err != nil {
		t.Fatalf("legacy discardPendingInput failed: %v", err)
	}
	if !waitUntil(time.Second, func() bool { return len(busStream.recorded()) >= 1 }) {
		t.Fatalf("the legacy discard message never reached the bus")
	}
	cmd, payload := parseAckTestEvent(t, busStream.recorded()[0])
	if cmd != "discard" {
		t.Fatalf("want the legacy discard message, got %s", cmd)
	}
	var msg discardMessage
	decodeAckTestMessage(t, payload, &msg)
	if string(msg.DiscardedInput) != string(prefix) {
		t.Fatalf("the legacy message must carry the discarded prefix bytes verbatim, got %q", msg.DiscardedInput)
	}
	if msg.Kind != "" || msg.Epoch != 0 {
		t.Fatalf("the legacy message must carry no classified fields, got %+v", msg)
	}
}

// ---------------------------------------------------------------------------
// R7-W1: inFlightBytes direct assertions
// ---------------------------------------------------------------------------

// holdingStream models the transport under the counting proxy with
// REAL writer semantics (what smux actually does): a Write blocks until
// released, then either completes the whole buffer or takes exactly
// `accept` bytes and FAILS - production writers never return a no-error
// partial write, and writeAll's retry loop must not be fed one.
type holdingStream struct {
	release chan struct{}
	accept  *atomic.Int64
}

func (h *holdingStream) Write(buf []byte) (int, error) {
	<-h.release
	if k := h.accept.Load(); k > 0 && k < int64(len(buf)) {
		return int(k), fmt.Errorf("scripted partial transport write")
	}
	return len(buf), nil
}
func (h *holdingStream) Read(buf []byte) (int, error)       { return 0, io.EOF }
func (h *holdingStream) Close() error                       { return nil }
func (h *holdingStream) CloseRead() error                   { return nil }
func (h *holdingStream) CloseWrite() error                  { return nil }
func (h *holdingStream) LocalAddr() net.Addr                { return nil }
func (h *holdingStream) RemoteAddr() net.Addr               { return nil }
func (h *holdingStream) SetDeadline(t time.Time) error      { return nil }
func (h *holdingStream) SetReadDeadline(t time.Time) error  { return nil }
func (h *holdingStream) SetWriteDeadline(t time.Time) error { return nil }

// TestInFlightBytesWriterOwnedHandoff asserts the R7-W1 measurement
// directly: the counting proxy tracks exactly the accepted-minus-written
// bytes of the in-progress transport write, including the never-completed
// remainder of a failed write, and
// serverOutputForwarder.inFlightBytes reads it through the stream the
// forwarder was constructed with.
func TestInFlightBytesWriterOwnedHandoff(t *testing.T) {
	// Phase 1: a write blocked inside the transport - all 10 bytes are
	// writer-owned; completing it leaves nothing in flight.
	block := make(chan struct{})
	var zero atomic.Int64
	held := &holdingStream{release: block, accept: &zero}
	proxy := &countingWriteProxy{Stream: held}

	writeDone := make(chan error, 1)
	go func() {
		_, _ = proxy.Write([]byte("0123456789"))
		writeDone <- nil
	}()
	if !waitUntil(time.Second, func() bool { return proxy.inFlight() == 10 }) {
		t.Fatalf("in-progress write must count its accepted bytes, got %d", proxy.inFlight())
	}
	close(block)
	<-writeDone
	if !waitUntil(time.Second, func() bool { return proxy.inFlight() == 0 }) {
		t.Fatalf("a completed write must leave nothing in flight, got %d", proxy.inFlight())
	}

	// Phase 2: a transport that takes 4 bytes then fails - the
	// never-completed remainder (6) stays writer-owned, exactly the
	// handoff unit a shed report must name.
	block2 := make(chan struct{})
	var partial atomic.Int64
	partial.Store(4)
	held2 := &holdingStream{release: block2, accept: &partial}
	proxy2 := &countingWriteProxy{Stream: held2}
	writeDone2 := make(chan error, 1)
	go func() {
		_, _ = proxy2.Write([]byte("0123456789"))
		writeDone2 <- nil
	}()
	if !waitUntil(time.Second, func() bool { return proxy2.inFlight() == 10 }) {
		t.Fatalf("in-progress write must count its accepted bytes, got %d", proxy2.inFlight())
	}
	close(block2)
	<-writeDone2
	if !waitUntil(time.Second, func() bool { return proxy2.inFlight() == 6 }) {
		t.Fatalf("the never-completed remainder must stay counted, got %d", proxy2.inFlight())
	}

	// The forwarder accessor reads the proxy installed by
	// newOutputForwarder; an idle forwarder reports zero.
	sess := &sessionContext{id: 1}
	forwarder := sess.newOutputForwarder("stdout", bytes.NewReader(nil), newAckTestStream())
	if forwarder.inFlightBytes() != 0 {
		t.Fatalf("an idle forwarder must report zero in flight, got %d", forwarder.inFlightBytes())
	}
}

// ---------------------------------------------------------------------------
// client state machine unit gates (R7-B4 / loss honesty)
// ---------------------------------------------------------------------------

// TestClientAckStateCoverageAndDesync pins the client-side coverage rule,
// application-level loss honesty (sent-but-never-applied bytes never
// confirm), D accounting with stale-epoch rejection, and the desync /
// matched-boundary recovery schedule.
func TestClientAckStateCoverageAndDesync(t *testing.T) {
	var st sessionAckState
	st.adoptBoundary(1) // a session-start success (matched boundary)

	if snap := st.snapshot(); !snap.Supported || snap.Epoch != 1 || snap.Offset != 0 {
		t.Fatalf("fresh epoch snapshot must be {supported, 1, 0}: %+v", snap)
	}

	st.countSent(100)
	ctrlSnap := st.snapshot()
	if ctrlSnap.Offset != 100 {
		t.Fatalf("R must count non-marker sent bytes, got %d", ctrlSnap.Offset)
	}
	if st.delivered(ctrlSnap) {
		t.Fatalf("nothing is delivered before an ack covers the offset")
	}

	st.observeAck(1, 60)
	if st.delivered(ctrlSnap) {
		t.Fatalf("60 bytes applied must not confirm a control at offset 100")
	}
	st.observeAck(1, 100)
	if !st.delivered(ctrlSnap) {
		t.Fatalf("appliedBytes == R must confirm the control")
	}

	// Application-level loss: bytes counted as sent but never applied keep
	// the next control unconfirmable (a stale-coordinates ack cannot
	// cover them).
	st.countSent(50) // dropped at the client send path: never acked
	next := st.snapshot()
	st.observeAck(1, 100)
	if st.delivered(next) {
		t.Fatalf("loss must never confirm: applied=100 < offset=150")
	}

	// D accounting: a same-epoch completion report subtracts the discarded
	// bytes from the coverage requirement; stale-epoch D is ignored.
	st.addDiscarded(1, 50)
	if !st.delivered(next) {
		t.Fatalf("applied + D must cover the offset: 100 + 50 >= 150")
	}
	st.addDiscarded(99, 1000)
	if st.discarded != 50 {
		t.Fatalf("stale-epoch D updates must be ignored, got %d", st.discarded)
	}

	// Desync: an ack from a different epoch sets desync and stops every
	// confirmation, even for offsets the coordinates would cover.
	st.observeAck(2, 1000)
	if st.delivered(st.snapshot()) {
		t.Fatalf("desync must stop all confirmations")
	}
	// A matched boundary is the only recovery; it resets R/D and ends
	// desync.
	st.adoptBoundary(3)
	fresh := st.snapshot()
	if fresh.Epoch != 3 || fresh.Offset != 0 || st.delivered(fresh) {
		t.Fatalf("recovery must reset coordinates and confirm nothing yet: %+v", fresh)
	}
	st.observeAck(3, 0)
	if !st.delivered(st.snapshot()) {
		t.Fatalf("a same-epoch ack must confirm the empty offset after recovery")
	}

	// A snapshot from a superseded epoch never confirms.
	st.countSent(10)
	old := InputAckSnapshot{Supported: true, Epoch: 1, Offset: 5}
	if st.delivered(old) {
		t.Fatalf("an offset from a superseded epoch must never confirm")
	}
}

// TestClientAckStateUnsupported pins the old-server gate: no adopted epoch
// means nothing ever confirms (zero behavioral difference for a new client
// against a server without the feature).
func TestClientAckStateUnsupported(t *testing.T) {
	var st sessionAckState
	snap := st.snapshot()
	if snap.Supported {
		t.Fatalf("a session that never learned an epoch must be unsupported")
	}
	st.observeAck(1, 100)
	if st.delivered(snap) {
		t.Fatalf("an unsupported session must never confirm")
	}
}

// ---------------------------------------------------------------------------
// full-stack end-to-end (the ONLY initServer in this file)
// ---------------------------------------------------------------------------

// ackE2E wraps an in-process client with the ack/report collectors.
type ackE2E struct {
	client  *SshUdpClient
	acks    chan InputAckInfo
	reports chan InputReportInfo
}

func newAckE2EClient(t *testing.T, info *ServerInfo, negotiated bool) *ackE2E {
	t.Helper()
	e2e := &ackE2E{
		acks:    make(chan InputAckInfo, 256),
		reports: make(chan InputReportInfo, 256),
	}
	client, err := NewSshUdpClient(&UdpClientOptions{
		ServerInfo:       info,
		TsshdAddr:        net.JoinHostPort("127.0.0.1", strconv.Itoa(info.Port)),
		SessionName:      "ack-e2e",
		AliveTimeout:     10 * 24 * time.Hour,
		IntervalTime:     time.Second,
		HeartbeatTimeout: 3 * time.Second,
		ConnectTimeout:   10 * time.Second,
		EnableDebugging:  os.Getenv("TSSHD_ACK_E2E_DEBUG") != "",
		DebugFunc: func(ts int64, msg string) {
			t.Logf("[dbg] %s", msg)
		},
		OnInputAck: func(_ *SshUdpClient, ack InputAckInfo) {
			select {
			case e2e.acks <- ack:
			default:
			}
		},
		OnInputReport: func(_ *SshUdpClient, report InputReportInfo) {
			select {
			case e2e.reports <- report:
			default:
			}
		},
	})
	if err != nil {
		t.Fatalf("NewSshUdpClient failed: %v", err)
	}
	e2e.client = client
	if negotiated {
		if err := client.SetInputAck(true); err != nil {
			t.Fatalf("SetInputAck failed: %v", err)
		}
	}
	return e2e
}

func (e *ackE2E) waitDelivered(sess *SshUdpSession, snap InputAckSnapshot, timeout time.Duration) bool {
	return waitUntil(timeout, func() bool { return sess.InputDelivered(snap) })
}

// waitSnapshot polls until the session's sent offset reaches want (the
// client counts R at transport-write completion, which races the pipe
// write's return) and returns the settled snapshot.
func waitSnapshot(sess *SshUdpSession, want uint64, timeout time.Duration) (InputAckSnapshot, bool) {
	ok := waitUntil(timeout, func() bool { return sess.InputAckSnapshot().Offset >= want })
	return sess.InputAckSnapshot(), ok
}

func (e *ackE2E) drainAcks() []InputAckInfo {
	var out []InputAckInfo
	for {
		select {
		case a := <-e.acks:
			out = append(out, a)
		default:
			return out
		}
	}
}

func (e *ackE2E) drainReports() []InputReportInfo {
	var out []InputReportInfo
	for {
		select {
		case r := <-e.reports:
			out = append(out, r)
		default:
			return out
		}
	}
}

// serverSession returns the server-side sessionContext for a client session.
func serverSession(t *testing.T, id uint64) *sessionContext {
	t.Helper()
	sess := getSessionByID(id)
	if sess == nil {
		t.Fatalf("no server-side session %d", id)
	}
	return sess
}

// TestInputAckEndToEnd is the full-stack gate: negotiation, the raw ack at
// PTY-write return (a child that never reads), ordered paste counting,
// per-session attribution, the marker lifecycle through the real bus
// (boundary adoption, prefix discard at the pre-marker epoch, marker-only
// release), and the legacy (non-negotiating) client's unchanged behavior.
func TestInputAckEndToEnd(t *testing.T) {
	t.Setenv("SSH_CONNECTION", "")
	serverArgs := &tsshdArgs{KCP: true, IPv4: true, Attachable: true,
		Port: "31000-65000", ConnectTimeout: 10 * time.Second}
	info, _, err := initServer(serverArgs)
	if err != nil {
		t.Fatalf("init server failed: %v", err)
	}
	// One initServer per process (in-process poisoning: see the notes at
	// the top of this file); reset the globals in cleanup.
	defer func() {
		activeSshUdpServer.Store(nil)
		cleanupOnExit()
	}()

	// ---- phase 1: negotiated client, raw ack at write return ----
	e2e := newAckE2EClient(t, info, true)
	defer e2e.client.Detach() // Detach, not Close: the bus "close" command latches process-global state

	sess1, err := e2e.client.NewSession()
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}
	if err := sess1.RequestPty("xterm-256color", 50, 200, ssh.TerminalModes{}); err != nil {
		t.Fatalf("RequestPty failed: %v", err)
	}
	// The stdin pipe must exist BEFORE Start: startSession launches the
	// input forwarder only when a stdin pipe was requested.
	stdin1, err := sess1.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe failed: %v", err)
	}
	// A child that never reads stdin and ignores SIGINT: the ack must
	// fire at PTY-write return regardless of the child consuming them.
	if err := sess1.Start(`sh -c "trap '' INT; sleep 30"`); err != nil {
		t.Fatalf("session start failed: %v", err)
	}

	snap0 := sess1.InputAckSnapshot()
	if !snap0.Supported || snap0.Epoch != kFirstInputEpoch {
		t.Fatalf("the session-start response must establish epoch 1: %+v", snap0)
	}

	if _, err := stdin1.Write(bytes.Repeat([]byte{'a'}, 64)); err != nil {
		t.Fatalf("stdin write failed: %v", err)
	}
	snapCtrl, ok := waitSnapshot(sess1, 64, 2*time.Second)
	if !ok || snapCtrl.Offset != 64 {
		t.Fatalf("client R must count exactly the written bytes, got %+v", snapCtrl)
	}
	if !e2e.waitDelivered(sess1, snapCtrl, 5*time.Second) {
		t.Fatalf("the ack must cover the write at PTY-write return without the child reading")
	}

	// ---- phase 2: ordered paste counting (paste-HOL honesty) ----
	paste := append(bytes.Repeat([]byte{'p'}, 2047), 0x03) // Ctrl-C last
	if _, err := stdin1.Write(paste); err != nil {
		t.Fatalf("paste write failed: %v", err)
	}
	pasteSnap, ok := waitSnapshot(sess1, 64+2048, 2*time.Second)
	if !ok || pasteSnap.Offset != 64+2048 {
		t.Fatalf("R must count the paste including the Ctrl-C byte, got %+v", pasteSnap)
	}
	if !e2e.waitDelivered(sess1, pasteSnap, 5*time.Second) {
		t.Fatalf("the trailing Ctrl-C must be confirmed only after the whole paste is accepted")
	}
	time.Sleep(100 * time.Millisecond) // let the final ack land
	acks := e2e.drainAcks()
	if len(acks) == 0 || acks[len(acks)-1].AppliedBytes != pasteSnap.Offset {
		t.Fatalf("the newest ack must carry the exact applied count, got %+v", acks)
	}

	// ---- phase 3: two simultaneous sessions, per-session attribution ----
	sess2, err := e2e.client.NewSession()
	if err != nil {
		t.Fatalf("second NewSession failed: %v", err)
	}
	if err := sess2.RequestPty("xterm-256color", 50, 200, ssh.TerminalModes{}); err != nil {
		t.Fatalf("second RequestPty failed: %v", err)
	}
	stdin2, err := sess2.StdinPipe()
	if err != nil {
		t.Fatalf("second StdinPipe failed: %v", err)
	}
	if err := sess2.Start(`sh -c "trap '' INT; sleep 30"`); err != nil {
		t.Fatalf("second session start failed: %v", err)
	}
	if _, err := stdin1.Write([]byte("one")); err != nil {
		t.Fatalf("sess1 write failed: %v", err)
	}
	if _, err := stdin2.Write([]byte("twotwo")); err != nil {
		t.Fatalf("sess2 write failed: %v", err)
	}
	s1Snap, ok := waitSnapshot(sess1, 64+2048+3, 2*time.Second)
	if !ok {
		t.Fatalf("session 1's R must settle at its writes, got %+v", s1Snap)
	}
	s2Snap, ok := waitSnapshot(sess2, 6, 2*time.Second)
	if !ok {
		t.Fatalf("session 2's R must settle at its writes, got %+v", s2Snap)
	}
	if s1Snap.Epoch != 1 || s2Snap.Epoch != 1 {
		t.Fatalf("both sessions must run their own epoch-1 coordinates")
	}
	if !e2e.waitDelivered(sess1, s1Snap, 5*time.Second) {
		t.Fatalf("session 1's write must be confirmed by its own acks")
	}
	if !e2e.waitDelivered(sess2, s2Snap, 5*time.Second) {
		t.Fatalf("session 2's write must be confirmed by its own acks")
	}
	if s1Snap.Offset != 64+2048+3 || s2Snap.Offset != 6 {
		t.Fatalf("per-session R must stay independent: s1=%d s2=%d", s1Snap.Offset, s2Snap.Offset)
	}
	for _, a := range e2e.drainAcks() {
		if a.SessionID == sess2.GetID() && a.AppliedBytes > 6 {
			t.Fatalf("session 2's applied counter must not see session 1's bytes: %+v", a)
		}
	}

	// ---- phase 4: the marker lifecycle through the real bus ----
	//
	// The stale-prefix (pos > 0) completion flow is covered
	// deterministically by the unit tests (TestMarkerLifecycleReserveAnd
	// Complete drives prefix+marker+suffix through discardPendingInput
	// directly; on a live loopback the client's marker injection races the
	// in-flight data, so pos is 0 or 5 nondeterministically). This phase
	// asserts what IS deterministic on the real stack: the boundary
	// report's arrival and epoch, the client's coordinate reset, the
	// marker-first injection of the next write (pos == 0), the surviving
	// suffix being applied + acked in the new epoch, and the empty-prefix
	// rule (no completion report when nothing was discarded).
	server := activeSshUdpServer.Load()
	if server == nil {
		t.Fatalf("no active server")
	}
	srvSess1 := serverSession(t, sess1.GetID())

	// A reconnect's pending-input discard installs a boundary on every
	// owned session (keepPendingInput is false: this client never set it).
	server.enablePendingInputDiscard()
	if !waitUntil(3*time.Second, func() bool { return srvSess1.discardMarker.Load() != nil }) {
		t.Fatalf("the server never installed the discard marker")
	}

	// The client adopts the boundary: epoch 2, R reset to 0, and the
	// marker is armed for injection at the next write.
	if !waitUntil(3*time.Second, func() bool {
		s := sess1.InputAckSnapshot()
		return s.Supported && s.Epoch == kFirstInputEpoch+1 && s.Offset == 0
	}) {
		t.Fatalf("the client must reset R/D and adopt epoch 2 at the boundary")
	}
	if !waitUntil(3*time.Second, func() bool { return sess1.inputMarker.Load() != nil }) {
		t.Fatalf("the boundary report must arm the client's marker injection")
	}
	var boundarySeen bool
	for _, r := range e2e.drainReports() {
		if r.Kind == kDiscardKindInputBoundary && r.SessionID == sess1.GetID() {
			boundarySeen = true
			if r.Epoch != kFirstInputEpoch+1 {
				t.Fatalf("the boundary report must carry the new epoch, got %d", r.Epoch)
			}
		}
	}
	if !boundarySeen {
		t.Fatalf("the client must receive session 1's inputBoundary report")
	}

	// Live input after the report goes out marker-first: the server sees an
	// empty prefix, applies the surviving suffix and acks it in epoch 2.
	if _, err := stdin1.Write([]byte("LIVE")); err != nil {
		t.Fatalf("live write failed: %v", err)
	}
	liveSnap, ok := waitSnapshot(sess1, 4, 2*time.Second)
	if !ok || liveSnap.Epoch != kFirstInputEpoch+1 || liveSnap.Offset != 4 {
		t.Fatalf("the live write must count 4 bytes in epoch 2: %+v", liveSnap)
	}
	if !e2e.waitDelivered(sess1, liveSnap, 5*time.Second) {
		t.Fatalf("the surviving suffix must be applied and acked in the new epoch")
	}
	// An old-epoch offset must never confirm through the new epoch's acks.
	if sess1.InputDelivered(InputAckSnapshot{Supported: true, Epoch: kFirstInputEpoch, Offset: 64 + 2048 + 3}) {
		t.Fatalf("an old-epoch offset must never confirm after the boundary")
	}

	// Marker-only boundary (deterministic on the live stack: the report is
	// processed before the next write): the next write goes out
	// marker-first, the prefix is empty, and NO completion report is
	// emitted for this boundary.
	time.Sleep(100 * time.Millisecond) // let any straggler reports land
	server.enablePendingInputDiscard()
	if !waitUntil(3*time.Second, func() bool {
		s := sess1.InputAckSnapshot()
		return s.Epoch == kFirstInputEpoch+2 && s.Offset == 0
	}) {
		t.Fatalf("the client must adopt epoch 3 at the second boundary")
	}
	if _, err := stdin1.Write([]byte("NEXT")); err != nil {
		t.Fatalf("next write failed: %v", err)
	}
	nextSnap, ok := waitSnapshot(sess1, 4, 2*time.Second)
	if !ok {
		t.Fatalf("the post-boundary write must count 4 bytes in epoch 3: %+v", nextSnap)
	}
	if !e2e.waitDelivered(sess1, nextSnap, 5*time.Second) {
		t.Fatalf("the post-boundary write must be applied and acked")
	}
	time.Sleep(100 * time.Millisecond)
	for _, r := range e2e.drainReports() {
		if r.Kind == kDiscardKindInputCompleted && r.SessionID == sess1.GetID() {
			t.Fatalf("a marker-only discard must not emit a completion report: %+v", r)
		}
	}

	// ---- phase 5: the legacy (non-negotiating) client is unchanged ----
	e2e.client.Detach()

	legacyAckSeen := make(chan InputAckInfo, 16)
	legacy, err := NewSshUdpClient(&UdpClientOptions{
		ServerInfo:       info,
		TsshdAddr:        net.JoinHostPort("127.0.0.1", strconv.Itoa(info.Port)),
		SessionName:      "ack-e2e-legacy",
		AliveTimeout:     10 * 24 * time.Hour,
		IntervalTime:     time.Second,
		HeartbeatTimeout: 3 * time.Second,
		ConnectTimeout:   10 * time.Second,
		OnInputAck: func(_ *SshUdpClient, ack InputAckInfo) {
			select {
			case legacyAckSeen <- ack:
			default:
			}
		},
		DiscardCallback: func(_ []byte, _, _ uint64) {},
	})
	if err != nil {
		t.Fatalf("legacy NewSshUdpClient failed: %v", err)
	}
	defer legacy.Detach()
	legacySession, err := legacy.NewSession()
	if err != nil {
		t.Fatalf("legacy NewSession failed: %v", err)
	}
	if err := legacySession.RequestPty("xterm-256color", 50, 200, ssh.TerminalModes{}); err != nil {
		t.Fatalf("legacy RequestPty failed: %v", err)
	}
	legacyStdin, err := legacySession.StdinPipe()
	if err != nil {
		t.Fatalf("legacy StdinPipe failed: %v", err)
	}
	if err := legacySession.Start(`sh -c "trap '' INT; sleep 30"`); err != nil {
		t.Fatalf("legacy session start failed: %v", err)
	}
	// The legacy session's start response carried an epoch, but this
	// client never negotiated: its state must stay unsupported.
	if snap := legacySession.InputAckSnapshot(); snap.Supported {
		t.Fatalf("a non-negotiating client must not adopt ack coordinates: %+v", snap)
	}
	if _, err := legacyStdin.Write([]byte("legacy")); err != nil {
		t.Fatalf("legacy stdin write failed: %v", err)
	}
	srvLegacy := serverSession(t, legacySession.GetID())
	if !waitUntil(3*time.Second, func() bool {
		srvLegacy.inputStateMu.Lock()
		defer srvLegacy.inputStateMu.Unlock()
		return srvLegacy.inputApplied.bytes == 6
	}) {
		t.Fatalf("legacy input must be applied exactly as before")
	}
	select {
	case a := <-legacyAckSeen:
		t.Fatalf("a non-negotiating client must never receive an ack: %+v", a)
	case <-time.After(300 * time.Millisecond):
	}
	// The legacy marker announcement still arrives and is injected.
	server2 := activeSshUdpServer.Load()
	if server2 == nil {
		t.Fatalf("no active server after the legacy client activated")
	}
	server2.enablePendingInputDiscard()
	if !waitUntil(3*time.Second, func() bool { return legacySession.inputMarker.Load() != nil }) {
		t.Fatalf("the legacy client must receive the broadcast marker announcement")
	}
	// A write after the marker is applied (post-marker path, unchanged).
	if _, err := legacyStdin.Write([]byte("post")); err != nil {
		t.Fatalf("legacy post-marker write failed: %v", err)
	}
	if !waitUntil(3*time.Second, func() bool {
		srvLegacy.inputStateMu.Lock()
		defer srvLegacy.inputStateMu.Unlock()
		return srvLegacy.inputApplied.bytes == 6+4
	}) {
		t.Fatalf("the legacy post-marker write must be applied")
	}
	select {
	case a := <-legacyAckSeen:
		t.Fatalf("a non-negotiating client must never receive an ack: %+v", a)
	case <-time.After(300 * time.Millisecond):
	}
}
