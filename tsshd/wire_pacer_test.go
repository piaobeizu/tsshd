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
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --kcp-wire-rate / sshd_config KcpWireRate precedence: flag wins, config
// applies only when the flag is unset, invalid config is off+warning, and
// the knob is KCP-only (ignored with a warning on a QUIC server).
func TestResolveKcpWireRate(t *testing.T) {
	assert.Equal(t, uint64(0), resolveKcpWireRate(0, false, "", true), "default off")
	assert.Equal(t, uint64(175_000), resolveKcpWireRate(175_000, true, "9600", true), "flag wins over config")
	assert.Equal(t, uint64(9_600), resolveKcpWireRate(0, false, "9600", true), "config applies when flag unset")
	assert.Equal(t, uint64(0), resolveKcpWireRate(0, true, "9600", true), "explicit --kcp-wire-rate 0 overrides a nonzero config (flag presence wins)")
	assert.Equal(t, uint64(0), resolveKcpWireRate(0, false, "not-a-number", true), "invalid config is off")
	assert.Equal(t, uint64(0), resolveKcpWireRate(175_000, true, "9600", false), "KCP-only: ignored on QUIC")
	assert.Equal(t, uint64(0), resolveKcpWireRate(0, false, "9600", false), "KCP-only: config also ignored on QUIC")
}

// Pacer tests use a 26,000 B/s wire budget so the payload token rate is
// exactly 10,000 B/s (kWireAmpEstimate 2.6) and the burst is exactly
// 1,000 bytes (one 100 ms token interval).

// The default configuration must be a complete no-op: a zero wire rate
// produces no pacer at all, and a nil pacer's wait returns without blocking,
// so the unpaced path never touches a lock.
func TestWireRatePacerOffByDefault(t *testing.T) {
	assert.Nil(t, newWireRatePacer(0))

	p := (*wireRatePacer)(nil)
	done := make(chan struct{})
	go func() {
		p.wait(1 << 20) // nil receiver: returns immediately
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("nil pacer wait blocked")
	}
}

// Steady-state offered rate must match the configured wire budget: pushing
// 5,000 payload bytes at rate 10,000 B/s with a 1,000-byte burst takes
// ~400 ms (the first 1,000 bytes ride the burst). The tolerance is generous
// (sleep overshoot is one-sided; undershoot would mean a leaking bucket).
func TestWireRatePacerRateAccuracy(t *testing.T) {
	p := newWireRatePacer(26_000)
	require.NotNil(t, p)

	start := time.Now()
	for i := 0; i < 5; i++ {
		p.wait(1_000)
	}
	elapsed := time.Since(start)
	assert.GreaterOrEqual(t, elapsed, 250*time.Millisecond, "pacer underslept: %v", elapsed)
	assert.Less(t, elapsed, 900*time.Millisecond, "pacer overslept: %v", elapsed)
}

// Burst is bounded to one token interval: the first interval's worth of
// tokens is granted immediately (interactive-sized writes are not delayed
// behind an empty bucket), but an immediate second take of the same size
// must wait for tokens to re-accrue.
func TestWireRatePacerBurstBound(t *testing.T) {
	p := newWireRatePacer(26_000)
	require.NotNil(t, p)

	start := time.Now()
	p.wait(1_000) // rides the first-use burst
	first := time.Since(start)
	assert.Less(t, first, 50*time.Millisecond, "first write must ride the burst, took %v", first)

	start = time.Now()
	p.wait(1_000) // bucket empty: must sleep ~one token interval
	second := time.Since(start)
	assert.GreaterOrEqual(t, second, 80*time.Millisecond, "second write must wait for tokens, took %v", second)
	assert.Less(t, second, 500*time.Millisecond, "second write overslept: %v", second)
}

// The budget clock anchors on FIRST USE, not construction. A pacer left
// idle for several token intervals must not return with more than one
// interval of burst credit: the first take rides the burst, and the second
// still has to wait, no matter how long construction preceded first use.
// (The tsshd#1 measured pitfall was this class of bug: an
// construction-anchored budget silently no-ops or bursts.)
func TestWireRatePacerFirstUseAnchor(t *testing.T) {
	p := newWireRatePacer(26_000)
	require.NotNil(t, p)

	time.Sleep(350 * time.Millisecond) // >> one token interval of idle time

	start := time.Now()
	p.wait(1_000) // first use: granted burst, NOT burst + idle accrual
	first := time.Since(start)
	assert.Less(t, first, 50*time.Millisecond, "first use must start at burst, took %v", first)

	start = time.Now()
	p.wait(1_000)
	second := time.Since(start)
	assert.GreaterOrEqual(t, second, 80*time.Millisecond,
		"idle time before first use leaked into the bucket; second take took %v", second)
}

// A take larger than the whole bucket (e.g. a full 32 KB read chunk on a
// small wire budget) must sleep exactly its deficit at the payload rate:
// (n - burst) / rate, once — the earlier capped-refill loop recomputed the
// deficit against a bucket that could never exceed the 1,000-byte burst cap
// and slept forever (caught by this class of test).
func TestWireRatePacerOversizedTake(t *testing.T) {
	p := newWireRatePacer(26_000)
	require.NotNil(t, p)

	start := time.Now()
	p.wait(10_000) // (10,000 - 1,000 burst) / 10,000 B/s = 900 ms
	elapsed := time.Since(start)
	assert.GreaterOrEqual(t, elapsed, 800*time.Millisecond,
		"oversized take underslept: %v", elapsed)
	assert.Less(t, elapsed, 1_500*time.Millisecond,
		"oversized take overslept (or looped): %v", elapsed)
}

// The per-connection bucket must aggregate concurrent forwarders: two
// goroutines pushing 5,000 bytes each through ONE pacer take about twice a
// single push (the debt serializes under the lock), not the time of one.
func TestWireRatePacerSharedAggregate(t *testing.T) {
	p := newWireRatePacer(26_000)
	require.NotNil(t, p)

	var wg sync.WaitGroup
	start := time.Now()
	for g := 0; g < 2; g++ {
		wg.Go(func() {
			for i := 0; i < 5; i++ {
				p.wait(1_000)
			}
		})
	}
	wg.Wait()
	elapsed := time.Since(start)

	// 10,000 bytes total at 10,000 B/s with 1,000 burst ≈ 900 ms.
	// Independent buckets would finish in ~400 ms.
	assert.GreaterOrEqual(t, elapsed, 700*time.Millisecond,
		"shared bucket did not aggregate concurrent forwarders: %v", elapsed)
	assert.Less(t, elapsed, 1_800*time.Millisecond, "shared bucket overslept: %v", elapsed)
}

// The deficit sleep holds the shared debt: a second writer arriving while
// the first one sleeps cannot spend tokens the first writer is already
// waiting for.
func TestWireRatePacerHoldsDebtAcrossSleep(t *testing.T) {
	p := newWireRatePacer(26_000)
	require.NotNil(t, p)

	var wg sync.WaitGroup
	wg.Go(func() {
		p.wait(10_000) // sleeps ~900 ms under the lock
	})
	time.Sleep(50 * time.Millisecond) // let the first take enter its sleep
	start := time.Now()
	wg.Go(func() {
		p.wait(100) // queued behind the first writer's debt
	})
	wg.Wait()
	queued := time.Since(start)
	assert.GreaterOrEqual(t, queued, 300*time.Millisecond,
		"second writer jumped the first writer's debt, waited only %v", queued)
}

// Wire-rate plumbing: the session looks its pacer up through its CURRENT
// server, so output pacing follows the connection the session is attached
// to and is absent while detached or on a connection without a pacer.
func TestSessionWirePacerLookup(t *testing.T) {
	sess, reset := newTestSessionContext(false, false, 10)
	defer reset()

	server := sess.server.Load()
	require.NotNil(t, server)
	assert.Nil(t, sess.wirePacer(), "no pacer configured: lookup must be nil (default off)")

	server.wirePacer = newWireRatePacer(26_000)
	require.NotNil(t, sess.wirePacer())

	old := sess.server.Swap(nil)
	assert.Nil(t, sess.wirePacer(), "detached session must not pace")

	// Reattach to a different server instance: its pacer wins (per KCP
	// connection bucket follows the CURRENT connection).
	other := &sshUdpServer{}
	other.wirePacer = newWireRatePacer(44_000)
	sess.server.Store(other)
	assert.Same(t, other.wirePacer, sess.wirePacer())
	sess.server.Store(old)
}

// timestampedStream records when each Write lands so a test can assert the
// pacing gaps between consecutive stream writes.
type timestampedStream struct {
	mu     sync.Mutex
	writes []time.Time
	buf    bytes.Buffer
}

func (s *timestampedStream) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writes = append(s.writes, time.Now())
	return s.buf.Write(p)
}
func (s *timestampedStream) Read(_ []byte) (int, error)         { return 0, nil }
func (s *timestampedStream) Close() error                       { return nil }
func (s *timestampedStream) CloseRead() error                   { return nil }
func (s *timestampedStream) CloseWrite() error                  { return nil }
func (s *timestampedStream) LocalAddr() net.Addr                { return nil }
func (s *timestampedStream) RemoteAddr() net.Addr               { return nil }
func (s *timestampedStream) SetDeadline(_ time.Time) error      { return nil }
func (s *timestampedStream) SetReadDeadline(_ time.Time) error  { return nil }
func (s *timestampedStream) SetWriteDeadline(_ time.Time) error { return nil }
func (s *timestampedStream) String() string                     { return s.buf.String() }
func (s *timestampedStream) writeTimes() []time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]time.Time{}, s.writes...)
}

// writerLoop integration: with a pacer configured on the session's server,
// consecutive output chunks reaching the transport stream are separated by
// the pacing sleep; without one they are written back-to-back (the default
// stays byte-identical to the unpaced path).
func TestForwardOutput_PacesWritesToStream(t *testing.T) {
	sess, reset := newTestSessionContext(false, false, 10)
	defer reset()

	chunks := [][]byte{bytes.Repeat([]byte("a"), 1_000), bytes.Repeat([]byte("b"), 1_000)}
	reader := func() *chunkReader { return &chunkReader{data: [][]byte{chunks[0], chunks[1]}, chunk: 1 << 20} }

	// Unpaced: both writes land nearly together.
	baselineStream := &timestampedStream{}
	baseline := sess.newOutputForwarder("stdout", reader(), baselineStream)
	baseline.forward()
	baseWrites := baselineStream.writeTimes()
	require.Len(t, baseWrites, 2)
	assert.Less(t, baseWrites[1].Sub(baseWrites[0]), 50*time.Millisecond,
		"default (no pacer) must not delay writes")

	// Paced at 10,000 B/s payload with a 1,000-byte burst: the second chunk
	// waits ~one token interval behind the first.
	sess.server.Load().wirePacer = newWireRatePacer(26_000)
	pacedStream := &timestampedStream{}
	paced := sess.newOutputForwarder("stdout", reader(), pacedStream)
	paced.forward()
	pacedWrites := pacedStream.writeTimes()
	require.Len(t, pacedWrites, 2)
	assert.Equal(t, string(chunks[0])+string(chunks[1]), pacedStream.String(),
		"pacing must not alter the byte stream")
	gap := pacedWrites[1].Sub(pacedWrites[0])
	assert.GreaterOrEqual(t, gap, 80*time.Millisecond, "second chunk not paced: gap %v", gap)
	assert.Less(t, gap, 600*time.Millisecond, "second chunk overslept: gap %v", gap)
}
