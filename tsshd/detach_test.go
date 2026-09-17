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

// Regression gate for tsshd#11: attach-after-detach output continuity.
//
// The control-latency harness (TSSHD_CTRL_BENCH=reconnect_attach) measured
// 3/3 runs losing the records the child wrote during the detach window
// (~30 x 1024 B at the seeded config) with zero discard accounting: a
// graceful client detach gave the server no signal, so the session kept
// forwarding child output into the detached client's dead kcp send path
// until the next client activated. This gate reproduces the same path on a
// clean loopback (no netem): every byte the child writes must reach EITHER
// the detaching client or the attaching client, exactly.
//
// The re-exec'd roam child (ctrlChildRoam) is the stimulus: newline-bounded
// 1024 B records every 20 ms, OPOST cleared so byte counts are decidable,
// with its exact written total reported through the side channel (ROAM_END).

import (
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// testDrain counts every byte read from r until EOF, then closes done.
func testDrain(r io.Reader) (*atomic.Uint64, chan struct{}) {
	var n atomic.Uint64
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 32*1024)
		for {
			m, err := r.Read(buf)
			if m > 0 {
				n.Add(uint64(m))
			}
			if err != nil {
				return
			}
		}
	}()
	return &n, done
}

// TestDetachAttachByteContinuity is the tsshd#11 gate: after a graceful
// detach and a later attach, the two clients together must have received
// every byte the child wrote. On the pre-fix tree the detach window's
// records are silently lost (red); the rendezvous detach preserves them.
func TestDetachAttachByteContinuity(t *testing.T) {
	// getUdpAddrs binds only the SSH interface when SSH_CONNECTION is set;
	// neutralize it so the server binds loopback, where the client dials.
	t.Setenv("SSH_CONNECTION", "")
	serverArgs := &tsshdArgs{KCP: true, IPv4: true, Attachable: true,
		Port: "31000-65000", ConnectTimeout: 10 * time.Second}
	info, _, err := initServer(serverArgs)
	if err != nil {
		t.Fatalf("init server failed: %v", err)
	}
	// initServer owns package-global state for the whole process (the
	// harness runs each seeded trial in a fresh process for this reason).
	// Later tests must not inherit this test's server instance: a leftover
	// activeSshUdpServer that still reports serving makes handleKcpConn
	// drop every new connection for non-attachable servers (TestProxy's KCP
	// cases wedge on it). Clear the global in cleanup and let the detached
	// instances be garbage-collected with the process.
	defer func() {
		activeSshUdpServer.Store(nil)
		cleanupOnExit()
	}()

	sockPath := t.TempDir() + "/detach-test.sock"
	events, _, err := ctrlSideChannelListen(sockPath)
	if err != nil {
		t.Fatalf("side channel listen failed: %v", err)
	}
	// The side channel is intentionally NOT closed: the child can still be
	// scanning it during teardown (see the harness notes in
	// control_latency_test.go) and is garbage-collected with the process.

	newClient := func(name string) *SshUdpClient {
		client, err := NewSshUdpClient(&UdpClientOptions{
			ServerInfo:       info,
			TsshdAddr:        net.JoinHostPort("127.0.0.1", strconv.Itoa(info.Port)),
			SessionName:      name,
			AliveTimeout:     10 * 24 * time.Hour,
			IntervalTime:     time.Second,
			HeartbeatTimeout: 3 * time.Second,
			ConnectTimeout:   10 * time.Second,
		})
		if err != nil {
			t.Fatalf("NewSshUdpClient failed: %v", err)
		}
		return client
	}

	clientA := newClient("detach-test-a")
	sessionA, err := clientA.NewSession()
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}
	if err := sessionA.RequestPty("xterm-256color", 50, 200, ssh.TerminalModes{}); err != nil {
		t.Fatalf("RequestPty failed: %v", err)
	}
	stdoutA, err := sessionA.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe failed: %v", err)
	}
	bytesA, drainedA := testDrain(stdoutA)
	defer func() { _ = clientA.Close() }() // already detached: skips the destructive close

	bin, _ := os.Executable()
	if bin == "" {
		bin = os.Args[0]
	}
	childCmd := fmt.Sprintf("%s --ctrlbench-child roam %s %d",
		ctrlQuoteArg(bin), ctrlQuoteArg(sockPath), 0)
	if err := sessionA.Start(childCmd); err != nil {
		t.Fatalf("session.Start failed: %v", err)
	}

	waitEvent := func(name string, timeout time.Duration) ctrlEvent {
		deadline := time.After(timeout)
		for {
			select {
			case ev, ok := <-events:
				if !ok {
					t.Fatalf("side channel closed while waiting for %s", name)
				}
				if ev.Name == name {
					return ev
				}
			case <-deadline:
				t.Fatalf("timeout waiting for child %s", name)
			}
		}
	}
	waitEvent("READY", 20*time.Second)
	waitEvent("ROAM_START", 10*time.Second)

	// Let the child stream for a while, then detach mid-stream and wait out
	// a realistic detach-to-attach gap. On the pre-fix tree the server keeps
	// forwarding into the dead client's transport for this whole window.
	time.Sleep(2 * time.Second)
	sessionID := sessionA.GetID()
	t0 := time.Now()
	clientA.Detach()
	detachMS := time.Since(t0).Milliseconds()
	select {
	case <-drainedA:
	case <-time.After(5 * time.Second):
		t.Fatalf("client A output did not drain to EOF after detach")
	}
	bytesBefore := bytesA.Load()
	t.Logf("detach completed in %dms, client A received %d bytes", detachMS, bytesBefore)

	time.Sleep(300 * time.Millisecond)

	clientB := newClient("detach-test-b")
	// Detach (never Close): a non-detached client's Close sends the bus
	// "close" command, which latches the process-global busClosing flag
	// and would poison every later in-process server. Detachment is also
	// the production teardown for an attachable client.
	defer clientB.Detach()
	sessionB, err := clientB.NewSession()
	if err != nil {
		t.Fatalf("second NewSession failed: %v", err)
	}
	if err := sessionB.RequestPty("xterm-256color", 50, 200, ssh.TerminalModes{}); err != nil {
		t.Fatalf("second RequestPty failed: %v", err)
	}
	stdoutB, err := sessionB.StdoutPipe()
	if err != nil {
		t.Fatalf("second StdoutPipe failed: %v", err)
	}
	bytesB, drainedB := testDrain(stdoutB)
	if err := sessionB.Attach(sessionID); err != nil {
		t.Fatalf("attach failed: %v", err)
	}

	// The child writes for 15s total and reports its exact byte count.
	roamEnd := waitEvent("ROAM_END", 25*time.Second)
	total := uint64(roamEnd.Extra)
	select {
	case <-drainedB:
	case <-time.After(25 * time.Second):
		t.Fatalf("client B output did not drain to EOF before timeout")
	}

	received := bytesA.Load() + bytesB.Load()
	t.Logf("child wrote %d bytes; client A received %d, client B received %d (total %d)",
		total, bytesA.Load(), bytesB.Load(), received)
	if bytesA.Load() == 0 || bytesB.Load() == 0 {
		t.Fatalf("expected both clients to receive output: A=%d B=%d", bytesA.Load(), bytesB.Load())
	}
	if received != total {
		t.Fatalf("attach-after-detach continuity: child wrote %d bytes, clients received %d (gap %d bytes, unaccounted)",
			total, received, total-received)
	}

	// ---- Phase 2: the protocol gate (same server; one per process) ----
	// A client pinned to protocol 1 - an older tssh against this newer
	// tsshd - must not stall in the rendezvous on detach: the notice is
	// never sent, the detach is immediate, and the session survives for a
	// later attach (the successor's activation detaches it, as before).
	oldInfo := *info
	oldInfo.ProtoVer = 1
	clientC, err := NewSshUdpClient(&UdpClientOptions{
		ServerInfo:       &oldInfo,
		TsshdAddr:        net.JoinHostPort("127.0.0.1", strconv.Itoa(info.Port)),
		SessionName:      "detach-test-c",
		AliveTimeout:     10 * 24 * time.Hour,
		IntervalTime:     time.Second,
		HeartbeatTimeout: 3 * time.Second,
		ConnectTimeout:   10 * time.Second,
	})
	if err != nil {
		t.Fatalf("proto-1 NewSshUdpClient failed: %v", err)
	}
	defer func() { _ = clientC.Close() }() // proto-1: already detached in the flow, skips the destructive close
	sessionC, err := clientC.NewSession()
	if err != nil {
		t.Fatalf("proto-1 NewSession failed: %v", err)
	}
	if err := sessionC.Start("sleep 30"); err != nil {
		t.Fatalf("proto-1 session.Start failed: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	sessionCID := sessionC.GetID()

	// Phase 2 pins the CLIENT's negotiated protocol to 1 (an older tssh
	// against this newer tsshd) - it exercises the client-side gate, not a
	// real old server; a true cross-version test needs a version-pinned
	// server fixture. What it does pin is the gate itself.
	t0 = time.Now()
	clientC.Detach()
	elapsed := time.Since(t0)
	// The gated path performs no waits (CAS + immediate Close, bounded
	// internally at ~1s worst case); a rendezvous that wrongly ran would
	// block at least the 3s ack bound. 2.5s leaves generous scheduling
	// margin while staying below that.
	if elapsed > 2500*time.Millisecond {
		t.Fatalf("detach against a proto-1 server stalled %dms; the rendezvous must be protocol-gated", elapsed.Milliseconds())
	}
	if !clientC.IsClosed() {
		t.Fatalf("detach must still close the old client")
	}

	clientD := newClient("detach-test-d")
	defer clientD.Detach() // Detach, not Close: see the clientB note above
	sessionD, err := clientD.NewSession()
	if err != nil {
		t.Fatalf("second-phase NewSession failed: %v", err)
	}
	if err := sessionD.Attach(sessionCID); err != nil {
		t.Fatalf("attach after proto-1 detach failed: %v", err)
	}
}

// TestClientOutputForwarderWaitDone pins the drain-wait bounds the detach
// rendezvous relies on: a completed forwarder reports done immediately, a
// nil forwarder (no output pipe) is trivially done, and a stuck forwarder
// hits the timeout instead of blocking.
func TestClientOutputForwarderWaitDone(t *testing.T) {
	if !(*clientOutputForwarder)(nil).waitDone(10 * time.Millisecond) {
		t.Fatalf("nil forwarder must be trivially done")
	}

	f := &clientOutputForwarder{done: make(chan struct{})}
	if f.waitDone(20 * time.Millisecond) {
		t.Fatalf("incomplete forwarder must not report done")
	}
	close(f.done)
	if !f.waitDone(20 * time.Millisecond) {
		t.Fatalf("completed forwarder must report done")
	}
}
