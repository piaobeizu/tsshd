# Weak-network KCP improvements for interactive coding agents (Claude Code / Pi)

Status: **design + phased implementation plan** (tsshd#2). Evidence base: tsshd#1
(merged [PR #1](https://github.com/piaobeizu/tsshd/pull/1) — `benchmarks/control-latency/`,
`tsshd/control_latency_test.go`). This document changes no runtime behavior; every
production change is filed as an independently verifiable work item
([§8 follow-up index](#8-follow-up-work-items)).

> **Revision v7 (six review rounds).** Rounds 1-3 (deep, FAIL): the
> opt-in discard contract; honest transport-aware ack claims; wire-aware
> pacing with recipe/gate coherence; corrected evidence arithmetic with
> provenance labels; executable per-row gate specs with gate ownership
> mapped to work items; one closed applied-coordinates offset domain; a
> non-vacuous paired-event ack gate. Rounds 4-5 (deep, FAIL): the ordered
> bus sender; the producer-context cut; the desync epoch rule; the request
> lifecycle. Round 6 (deep, FAIL) forced the final mechanism closures:
> **executor coverage in every state** (TryLock idle executor + checkpoints
> in ALL mutex-holding sections incl. flushOutput's retry loop — the shed
> can never depend on the blocked drain it bypasses), **ownership-partition
> accounting** (every source byte in exactly one of forwarded/queued/
> cachedPending/local; `S = handed + queued + cachedPending + local` as a
> unit-tested identity; range = the source suffix by construction;
> measured, not assumed, in-flight residue), **reserve-before-mutate report
> admission** (state changes reserve their report slot first; the
> load-bearing reconnect marker has a guaranteed slot or is not installed
> and the session refuses input — never an undisclosed marker), and
> **kind-classified, epoch-attributed discard reports** (only inputBoundary
> resets R/D; D updates carry the epoch of the discarded bytes, so
> stale-epoch double-subtraction is impossible; output ranges are
> session-lifetime). All rounds' convergence path stands: **ship
> configurable wire-aware aggregate pacing + a conservatively named
> input-accepted notification; keep all destructive output shedding
> behind explicit opt-in and boundary-safety gates.**

All line/function references verified at `tsshd@c8c2f77` / `trzsz-ssh@d5284bf`
(post-PR#1 merge). Measured numbers cite their provenance: **[committed]** = a
committed result artifact in `benchmarks/control-latency/results/`, **[reported]**
= a figure documented in the PR #1 README across runs (variance notes), not
independently re-derivable from the committed JSON set.

---

## 1. Problem and evidence

While a Claude Code / Pi style agent floods output over `tssh --udp --kcp` on a weak
network, Ctrl-C "feels dead": the confirmation that the interrupt worked is buried
for seconds to tens of seconds. tsshd#1 measured every boundary and proved:

1. **The control-input path is sound.** With any uplink headroom, a bare Ctrl-C is
   delivered in ≈ one-way transit time (51 ms measured; the link's one-way delay is
   50 ms at 100 ms RTT) in *every* tested condition — 20 % bidirectional loss,
   saturated + backpressured output path (`loss20_flood` 51.1 ms, `bottleneck_split`
   50.9 ms, `bottleneck_upclean` 50.7 ms, `slow_client` 50.6 ms, all [committed]).
   No defect exists in the tssh input path, smux, kcp-go or the tsshd session input
   forwarder. Loss alone is acceptable: `loss20` control p50 50.6 / p95 51.4 /
   max 161.4 ms, echo p95 212.6 ms [committed, single 30-sample run].
2. **The perceived failure has three owners, none in the input path:**

   | # | owner | measured | layer |
   |---|---|---|---|
   | a | shared-bottleneck queue HOL: both directions share one saturated FIFO queue; the control packet waits behind the output flood | input itself 667–1240 ms [committed]; 0.7–1.6 s over four runs incl. 1642 ms [reported]; worst case ≈ full queue ≈ 5.6 s (1000 pkt × 1400 B / 250 KB/s) | link / qdisc topology (not software) |
   | b | confirmation masking: the interrupt's on-screen confirmation is ordered behind the in-flight output backlog of the single smux data stream; kcp (no congestion control, `SetNoDelay(1,10,2,1)`, FEC 1+1) overshoots the pipe, drops cascade, retransmissions dominate | perceived confirmation 2.5–4.9 s in committed bottleneck runs; up to 8.6 s [reported]; marker travel 709.6 ms (`upclean`), 1.76 s (`split`) [committed], up to >40 s [reported] | tsshd server output layer |
   | c | PTY input-buffer HOL: a paste ordered ahead of Ctrl-C blocks the interrupt until the remote program consumes stdin; a never-reading remote makes Ctrl-C dead forever, even on a clean link | `paste_baseline`: never (≥150 s, clean link) [committed]; reading-agent model: 1.7–3.0 s for 64 KB [committed + reported] | kernel terminal semantics |

3. **What "overshoot" means in bytes** (`bottleneck_shared-r2` [committed]):
   the child wrote 574,122 B in total — the source itself was throttled by
   end-to-end backpressure — and the client eventually received 564,060 B
   (≈98 % of source output; the problem is *when*, not *whether*). To deliver
   those 564 KB of payload, the relay **attempted 5,046,977 B of wire traffic**
   (`enqueued` 1,825,076 + `dropped` 3,221,901: originals + FEC 1+1 parity +
   retransmissions, both directions) — an offered-based amplification of ≈8.9×;
   3.22 MB of that never crossed (the relay's `dropped` counter mixes the seeded
   20 % random loss with queue-full drops, so a pure tail-drop share cannot be
   derived from the current artifacts). Egress-based amplification was ≈3.2× in
   that run vs ≈2.68× on the clean baseline [committed]. **Harness accounting
   caveat:** in shared mode the relay's up/down JSON sections mirror the same
   single queue's statistics; per-direction attribution must be fixed by tsshd#3
   before its baselines are cited per-direction.

### Backlog anatomy (approximate inventory; order-of-magnitude, not a precise bound)

Server-side live buffering is *small*: `serverOutputForwarder` holds on the order
of a few 32 KB buffers at once — one slot in `writeBufCh` (capacity 1,
`newOutputForwarder`), one buffer in flight inside `writerLoop`'s `writeAll`, and
one buffer spinning in `handleBuffer`'s 10 ms retry loop. `cacheLines` is
populated while the client is disconnected (bounded by
`max(maxPendingOutputLines, rows*2)` lines, `maxPendingOutputLines = 1000`) and is
flushed during/after reconnect. The multi-second backlog is therefore mostly
**in flight**: kcp's send queue (occupancy bounded by `snd_wnd = 1024` × MTU 1400
≈ 1.4 MB — a configuration-derived upper bound; actual dynamics are kcp-go
internals) + the smux stream buffer (`MaxStreamBuffer` 512 KB) + the bottleneck
queue itself. Two consequences drive this whole design:

* **Pacing belongs in `serverOutputForwarder.writerLoop`, before the smux write.**
  Pacing there backpressures the whole chain — smux → kcp `WaitSnd` →
  `writeBufCh` → `handleBuffer` spin → the PTY kernel output buffer → the flooding
  child blocks at the source. The backlog stops being *created*.
* **Bytes already inside kcp's send queue cannot be reclaimed.** Purging the snd
  queue mid-stream would corrupt smux framing, and kcp-go exposes no such API.
  Disposal (§3 P2) can therefore only reach tsshd's **own** buffers — where
  accounting is exact and the prefix is contiguous — and only *after* the
  corresponding input has been applied. Reaching into the PTY kernel queue is a
  separate, harder mechanism with its own evidence bar (§3 P2, deferred; §9).
  **Prevention (pacing) outranks cure (disposal).**

---

## 2. Non-goals (binding for every phase)

* **No input-path changes.** trzsz-ssh/tsshd/kcp-go/smux input paths are measured
  sound (10-case matrix, 11 committed runs incl. one repeat — PR #1). Reopened only on new defect evidence — filed
  separately, never bundled into an output-layer change.
* **No Mosh-style framebuffer state sync.** The forwarded stream stays raw PTY
  bytes; scrollback, touchpad scrolling and copy semantics stay SSH-identical (the
  project's own README lists "Local Echo & Line Editing: Not Planned"). No
  reflow/rewrite/repaint-reconstruction of output.
* **No destructive output shedding by default.** Any mechanism that drops output
  the PTY produced is **opt-in** (capability-gated, config-gated) until the
  boundary-safety gates in §9 exist and pass. The only in-stream notice
  precedent — `flushOutput`'s disconnect-time yellow warning line — is
  pre-existing behavior for the disconnect case and is *not* extended to new
  mechanisms by this design.
* **Dynamic FEC is not the root-cause fix.** The failure mode is overshoot +
  retransmission storms (≈8.9× offered amplification [committed]), not
  insufficient error correction. FEC tuning may follow *only* as a later
  optimization, only with new evidence (tsshd#5's attribution is the evidence
  engine). No FEC work item is opened now.
* **This work item ships no production code.** Design + gates + phased follow-up
  work items only.

---

## 3. Ranked improvement candidates

Ranked by contribution to the perceived failure, given each candidate's *reachable*
effect and risk. Measurement gates (P0) land first. Phase ids are stable across
this document and the filed work items; ranks are the engineering order.

### Rank 1 — P1: server output pacing, wire-aware, per-connection aggregate

**tsshd#6 · tsshd repo · `output.go writerLoop` + config plumbing**

*What*: one token-bucket rate limiter **per KCP connection** (shared across that
connection's session stdout/stderr forwarders — independent per-forwarder buckets
could collectively exceed the cap), pacing the offered byte rate into the smux
stream. The knob is a **downlink wire budget** (`--kcp-wire-rate`); the server
derives the payload token rate as `wire_budget / amp_estimate`, where
`amp_estimate ≥ 2.2` by default (FEC 1+1 doubles every wire datagram — including
kcp ACK packets — plus framing; the floor is 2.0), tightened by tsshd#3's measured
amplification. Recommended recipe: wire budget = **0.7 × bottleneck wire rate**
(leaving room for amplification error, retransmits, bus/control, ACK feedback).
Burst: at most one token-interval of bytes ahead. **Recipe/gate coherence** (the
§7 row-5 degraded-goodput gate is derived FROM this recipe, never independent of
it): delivered ≥ **0.8 × (1.4 Mbps ÷ amp_estimate)**, with **amp_estimate
pinned at 2.2 for the reference gate** — at the 2 Mbps reference, 0.7 ×
250,000 B/s = 175,000 B/s wire budget → offered payload ≈ 175,000/2.2 ≈
79,500 B/s ≈ 0.64 Mbps, so the pinned gate is **≥ 0.5 Mbps delivered (≈ 80 % of
the recipe's offered payload rate) and ≥ 2× the unpaced baseline**. If
tsshd#3's measurement later tightens amp_estimate, the gate recomputes by the
formula (not by fiat) and the change is recorded as an evidence-backed gate
adjustment on this wi's timeline. Clean-link regression is measured with
pacing OFF (the default) and with a deliberately high cap (200 Mbps on the
100 Mbps clean case) — never at the weak-link recipe, so "must not throttle
strong links" and "must fill a weak link" are different, separately-configured
tests. Port-forward and datagram
streams are excluded from the bucket in v1 (documented limitation: the agent
flood problem lives in the session streams). Paced writes keep the bottleneck
queue out of saturation, so (a) the retransmission storm stops (the >40 s drains
are overshoot artifacts), (b) the shared-queue HOL shrinks because the queue is
no longer full of flood, and (c) uplink kcp ACKs are not starved — tsshd#5's
hypothesis for the [reported] ~6× split-vs-upclean asymmetry.

*Why rank 1*: the only candidate that attacks the mechanism producing
seconds-to-tens-of-seconds of masking. Everything else bounds *perception* or
*hygiene*; P1 shrinks the *reality* (§1.3: ≈8.9× attempted wire bytes to deliver
564 KB).

*Defaults*: **off** (`--kcp-wire-rate 0`). A static default cannot be right for
both 2 Mbps and 1 Gbps links; the weak-network recipe goes in the ops doc, and a
safe adaptive default is a *future* decision gated on tsshd#5 evidence —
explicitly not guessed now. Budget clock must anchor to the monotonic clock on
first use (tsshd#1 pitfall: a struct-init-anchored budget silently no-ops).

*Rejected alternative*: shrinking kcp `snd_wnd` — trades loss-recovery
parallelism for latency on *all* traffic; pacing targets the same overflow with a
scoped, configurable knob.

### Rank 2 — P3: input-*accepted* ACK on the bus stream

**tsshd#7 · tsshd repo · `session.go forwardInput` + `bus.go` + `proto.go` + `client.go`**

*What*: after the input has been **accepted by the PTY** — `writeAll` returned on
**every** server input write path (the normal `forwardInput` loop AND the
surviving-suffix write inside `discardPendingInput`) — the server emits an
`input_ack` on the existing bus stream, from a dedicated bounded coalescing
emitter (§4.5). Semantics are deliberately conservative: **"accepted by the
PTY"**, *not* "the application handled it" and *not* "an interrupt fired"
(a raw-mode agent like Claude Code handles 0x03 itself, only when it reads it —
which is exactly the paste-HOL truth the user needs to see). The full message
and coverage contract — **applied coordinates** (non-marker input bytes only,
so client offsets and server counters live in one domain), epoch boundaries at
(re)attach AND discard events, the D-offset rule over bus-ordered discard
reports — is §4.5; this section does not restate it. No server-side VINTR/ISIG
sniffing in v1: it is unsound as a *guarantee* (literal-next quoting yields
false positives; raw mode false negatives; the production PTY path applies no
client-supplied terminal modes today).

*What the ack does and does not bypass* (round-1 finding 2 + round-3 R3-B2,
adopted): the bus is a separate **smux stream**, so the ack is not blocked by
the data stream's smux receive window — the multi-second backlog that holds
the confirmation marker inside the transport's reliable delivery of that
stream. It does **not** bypass the shared KCP connection (segments already
serialized ahead of it, retransmission load) or the bottleneck queue: if the
input itself is queue-delayed (owner a), or the downlink is saturated, the ack
is delayed with it. The claim that an ack arrives before the drain completes is
therefore a **benchmark-established property, not a transport guarantee** —
§7 row 3(b) measures it as a paired event gate. Gates are conditional (§7):
fast only where the input path has headroom and the downlink is kept shallow
(P1 on); in the unmitigated shared-bottleneck config **no absolute ack-latency
bound is claimed** — the gate there is the paired beats-the-drain win with an
explicit coverage floor and missing-ack outcomes (§7 row 3(b)), and missing
acks (advisory loss) are counted and rendered as "no confirmation" rather
than vanishing from the sample set. The user still learns the truth without
waiting for the 2.5–8.6 s drain — the actual baseline failure (perceived
2.5–4.9 s [committed] / up to 8.6 s [reported], vs input delivery 0.7–1.6 s).

*Why rank 2*: smallest code, immediately removes the *perceptual* problem under
the conditions users actually have once P1 lands, and honest by construction. Emission
is non-blocking (ack dropped + debug-logged on bus-write failure; acks are
advisory).

### Rank 3 — P2: bounded, client-requested output disposal (opt-in)

**tsshd#8 · tsshd repo · `output.go` + `session.go` + `bus.go`/`proto.go`**

*What (v1 scope)*: a capability-gated, **default-off** bus command
`discard_output {sessionID, epoch, inputOffset}` by which the *client* — which
knows it sent an interrupt — asks the server to drop the **server's own pending
output buffers of that session's stdout forwarder** (`writeBufCh` slot +
`cacheLines`; the stderr forwarder is untouched in v1 — stated, not accidental),
as one contiguous prefix, *after* the server's `appliedBytes` for that epoch has
reached `inputOffset` (**both in applied coordinates**, §4.5 — the rendezvous
makes bus/data stream ordering irrelevant: the request cannot act before its
referenced input is applied). Accounting is exact there — lines and bytes of
tsshd's own buffers — and reported via the **existing** `discard` bus message,
extended with session/epoch attribution and the dropped region's output stream
byte range (schema in §4.5). No new event name, **no bytes injected into the
forwarded stream** (the client that requested the shed renders the notice
itself; old clients never request it and are never shed for).

*Documented consequences of the opt-in (stated, not hidden)*: input-before-disposal
is not old-output-only — the child may emit its new prompt between interrupt-apply
and the request, and that prompt can occupy the pending buffers and be deleted; a
dropped prefix may also open an escape-sequence or terminal-mode transition, so
byte-preservation of the tail does not guarantee interpretation-preservation. The
requesting client opts into exactly this. The `discard` report therefore carries
the dropped region's **output stream byte range** `[start, end)` (§4.5), and the
range makes the §7 row-8 integrity gate reconstructable. The §7 row-4 gate
doubles as the adversarial preservation check: a shed that deletes the benchmark
child's post-SIGINT marker fails the run.

***The cut point* (rounds 4-6, R4-B2/R5-B1-B2/R6-B1-B2 — exact accounting
with NO new lock-wait chains; the v1 shed never cuts mid-`writeAll`):
the shed is executed **by whichever goroutine first holds `handleMutex`
at a shed checkpoint after the flag is set** — and the flag can ALWAYS be
serviced, in every state:

* **Executor** = one function, `executeShedIfPending()`, callable in two
  ways: (a) from **`sync.Mutex.TryLock`** in the bus handler — the idle case
  (queue+cache empty, `forward()` blocked in `reader.Read`, mutex free)
  completes immediately with an empty or full drop set without waiting for
  anything; TryLock NEVER waits, so no new lock chain exists; (b) from
  **checkpoints at the top of EVERY mutex-holding section** —
  `handleBuffer` (top AND inside its existing 10 ms send-retry loop),
  `flushOutput` (top AND inside its channel-capacity retry loop, so
  reconnect flushing cannot strand the shed), and `handleError`. This
  covers all three producers of queued/cached bytes; a shed can never again
  depend on the blocked drain it is meant to bypass.
* **Ownership partition (the accounting foundation)**: every accepted
  source byte is in EXACTLY ONE of four disjoint states — **forwarded**
  (dequeued by `writerLoop`, including its in-flight `writeAll` buffer),
  **queued** (in `writeBufCh`), **cached** (in `cacheLines`, not yet handed
  to the channel), **producer-local** (accepted from the PTY read but not
  yet handed to the channel — including a line mid-`flushOutput` retry and
  the buffer in hand in `handleBuffer`). The forwarder maintains disjoint
  byte counters per state and the identity `S = handed + queued +
  cachedPending + local` holds as a unit-tested invariant (`S` = source
  cursor, advanced when a PTY read is accepted in `forward()`; `handed` =
  bytes given to `writeBufCh`). Double counting is impossible by
  construction: handing a cached line to the channel moves its bytes from
  `cachedPending` to `queued` atomically under `handleMutex`.
* **The cut**: under `handleMutex`, the executor (a) drops the queued set
  (non-blocking receives — the executing producer cannot wait on itself),
  (b) clears the not-yet-handed cache (`cachedPending`), (c) drops the
  producer-local bytes in hand (for a checkpoint inside `handleBuffer`/
  `flushOutput`, that is the current invocation's un-enqueued payload),
  and reports `droppedBytes = queued + cachedPending + local` as the
  half-open range `[S - droppedBytes, S)` — the dropped bytes are exactly
  the source suffix ending at S **by the ownership identity**, and the
  in-flight `writerLoop` buffer is excluded by construction (its bytes are
  in `handed`). Successive sheds are non-overlapping (each cut's suffix
  starts where the previous `handed` frontier ended). Row-8 reconstruction
  is exact.
* **In-flight residue (round-6 R6-W1, qualified honestly)**: the residue
  is the `writerLoop` in-flight hand-off unit. On the LIVE path it is one
  PTY read (32 KB) plus a possible marker prefix — asserted by a direct
  unit test. The DISCONNECTED path can combine buffers into a larger unit
  that survives reconnect, so the residue is **measured, not assumed**: the
  report carries `inFlightBytes`, and the row-4 settle gate and row-8
  reconstruction consume it. No claim is made that the residue is always
  <= 32 KB.
* **Request lifecycle** (rounds 5-6): at most ONE outstanding
  `discard_output` per session; a second request supersedes the first
  (`ShedStatus = superseded`, reports echo `requestInputOffset`); the
  executor revalidates the epoch at the cut (changed -> `expired`,
  nothing shed); a reached-offset request whose report was admitted always
  executes at a checkpoint or via TryLock — the idle executor guarantees
  it.

*What is explicitly NOT in v1 (round-1 finding 1, adopted)*: no automatic
server-side shedding, no PTY kernel-queue flush (`tcflush` returns no accounting,
races with the child's own post-SIGINT output — the very prompt the user wants —
and a line boundary is not a terminal-state boundary: dropping a line that opens
an escape sequence or enters the alt screen corrupts the interpretation of
surviving bytes), no in-flight kcp bytes (unreclaimable, §1). Any extension to
those mechanisms requires the adversarial boundary-safety gates in §9 to exist
and pass, and remains opt-in.

*Why rank 3 (down from 2)*: the reachable backlog (server-own buffers, order of
a few 32 KB buffers + the disconnected-cache) is small next to the in-flight
backlog; disposal's marginal value is conditional on P1 and manifests as bounded
hygiene plus a client-driven escape hatch. P3 above it: the ack delivers
perceptual value with no lossy operation at all.

### Rank 4 — P5: qdisc/DSCP for small control packets (deployment-bounded)

**tsshd#4 · tsshd repo docs/ (+ optional trzsz-ssh flag)**

*What*: the shared-bottleneck HOL (owner a) is a *topology* property:
per-direction queues remove it entirely (benchmark-verified: shared 667–1240 ms
[committed] / up to 1642 ms [reported] vs split 51 ms [committed]). The deliverable is an ops guide — when both
directions share one queue (half-duplex WiFi medium, single-queue shapers, some
VPN concentrators): per-direction qdiscs first-best; size-keyed `tc` filters at
the bottleneck owner second; WiFi WMM DSCP→AC mapping and DSCP-stripping /
VPN-encapsulation caveats stated. Optional cooperative lever: tssh sets
`IP_TOS`/DSCP EF on its KCP socket — the client uplink carries (almost) only
control + ACKs, so uplink-wide marking prioritizes exactly the traffic that
matters (per-packet marking is impossible: kcp uses one UDP 4-tuple). Default
off.

*Why rank 4*: real effect but deployment-bounded — needs admin control of the
bottleneck node (usually the *user's* router/AP, often unavailable), and DSCP
survives only where middleboxes honor it. A complement to P1 (pacing empties the
shared queue in the first place), never a substitute. No tsshd code can fix a
queue tsshd does not own — hence *documented boundaries*, not a "fix".

### Rank 5 — P6: split-vs-shared goodput attribution (diagnostic)

**tsshd#5 · tsshd repo benchmark-only**

*What*: downlink goodput collapsed ~6× harder when the *uplink* was also
rate-capped (`bottleneck_split` vs `bottleneck_upclean`) [reported]. Working
hypothesis: uplink capping delays kcp ACK feedback → `WaitSnd`/snd_wnd stalls and
RTO degradation → collapse; FEC 1+1 doubles uplink ACK datagrams too. Vary
uplink cap × downlink cap × loss with per-direction accounting fixed (§1 caveat);
instrument kcp internals; recommend whether P1's wire budget must explicitly
reserve uplink ACK capacity and whether loss-adaptive pacing is warranted.

*Why rank 5*: pure attribution — refines P1's recipe and is the evidence gate for
any future FEC or adaptive-default decision, but ships nothing to users by
itself.

### Evaluated and rejected

| candidate | verdict | evidence |
|---|---|---|
| input-path changes (client queue, smux priority, kcp input) | **rejected** | pipe write ≤ 0.2 ms in all 10 cases (11 committed runs); Ctrl-C ≈ one-way transit under loss + flood + backpressure whenever uplink has headroom; `slow_client` proves backpressure engages without touching input |
| Mosh framebuffer / local echo / line editing | **rejected** | violates raw-PTY/scrollback/copy non-goals; project stance "Not Planned"; the diagnosis shows the input path is not the problem a framebuffer would solve |
| dynamic FEC as the root-cause fix | **rejected for now** | the failure mode is overshoot + retransmission storm (≈8.9× offered amplification [committed]); FEC 1+1's low interactive tail latency is confirmed good; revisit only on tsshd#5 evidence |
| shrinking kcp `snd_wnd` as a backlog bound | **rejected** | global window shrink trades loss-recovery parallelism for latency on *all* traffic; pacing targets the same overflow with a scoped, configurable knob |
| automatic server-side output shedding (any form) | **rejected for v1** | no realizable boundary/accounting mechanism that preserves post-interrupt bytes and terminal state (round-1 finding 1); revisit only behind §9's gates, still opt-in |

---

## 4. Protocol compatibility and old-client fallback

The design adds **no breaking wire change**. Everything in this section is
**prospective**: the tree at the stated pins contains none of the additions
below (verified — `settingsMessage` has no `InputAck`, `discardMessage` has
none of the extension fields, `forwardInput` counts nothing, `writerLoop`
paces nothing); this document is the contract those PRs implement against,
and each child work item's own review verifies its implementation. Verified
mechanisms the compat story RELIES ON (both bus
dispatches tolerate unknown commands via `handleUnknownEvent`, which consumes the
JSON payload, warns, and keeps the loop alive — verified server-side `bus.go` and
client-side `client.go`; the bus wire is length-prefixed JSON; `settingsMessage`
already uses `omitempty` pointer fields; the bus hello already versions clients —
server gates tssh ≥ 0.1.6):

1. **Capability advertise (client→server)**: extend `settingsMessage` with
   `InputAck *bool` (`json:",omitempty"`, same pattern as
   `KeepPendingInput/KeepPendingOutput`). Old *servers* ignore the unknown JSON
   field (Go `json.Unmarshal` default) — no error path.
2. **Server emission is capability-gated**: `input_ack` events and
   `discard_output` acceptance happen only for clients that advertised
   `InputAck`. Old *clients* therefore never receive a new event; even if they
   did, both dispatch loops tolerate unknown commands (belt and braces).
3. **New client + old server**: no acks arrive (feature absent) — the client
   renders nothing; zero behavioral difference.
4. **Server-side policy is not a protocol change**: pacing is config-gated
   (default off). Disposal is client-requested and capability-gated (default off)
   — old clients cannot trigger it and are never shed for; **no output the user's
   client did not explicitly ask to drop is dropped by any v1 mechanism**.
5. **ACK & disposal coordinate contract** (round-1 finding 4 + round-2 W1 +
   round-3 R3-B1, adopted). One offset domain, called **applied coordinates**:
   the ordered count of **non-marker input bytes** of one session within one
   epoch. Protocol markers (client-injected discard markers) are excluded on
   BOTH sides — the client knows exactly which bytes it sent as markers, and
   the server knows the markers it scans for — so client offsets and server
   counters live in the same domain with no translation.
   * `inputAckMessage = {sessionID uint64, epoch uint64, appliedBytes uint64,
     writeMS int64}`. `appliedBytes` = non-marker bytes actually written to the
     PTY master through **every** server input write path in this epoch — the
     normal `forwardInput` `writeAll` AND the surviving-suffix write inside
     `discardPendingInput`. Discarded prefixes are excluded (never applied).
     There is deliberately **no** received-counter: the round-2 dual-counter
     design broke on marker accounting and is withdrawn.
   * `sessionID` because one connection carries multiple sessions
     (resize/exit messages already carry theirs).
   * **Client coverage rule**: the client tracks its Ctrl-C at its applied-
     coordinate offset R (its own non-marker sent bytes since the epoch
     began). "Delivered" renders when `appliedBytes ≥ R − D`, where D is the
     sum of this session's discarded non-marker input bytes in this epoch,
     learned from **discard reports** (below). No byte-identity mapping across
     discards is attempted — R, D and `appliedBytes` are all counts in one
     domain, so the accounting is closed.
   * **Epoch boundaries** = (re)attach AND any server-side input-discard event
     (reconnect marker installation). All boundaries are client-observable in
     order: reconnects are client-driven, client-requested discards are
     client-initiated, and server-side discards are reported on the bus. At a
     boundary the client resets R to 0 and **invalidates** every pending
     control (renders nothing — never "delivered"); controls sent after the
     boundary map into the new epoch immediately. Input in flight across a
     boundary is by definition discarded-or-unknown; no pending control is
     left unmappable. **Epoch synchronization** (round-4 R4-W1 + round-5 R5-B4):
     epoch numbers are assigned by the server. The EAGER channel is an
     additive field of the session-start success response (the `sendSuccess`
     path) — a client that begins sending before any ack still knows the
     epoch. The SELF-HEALING channel is deliberately conservative: an ack
     whose epoch differs from the client's current epoch does NOT rebase
     anything — an ack reports applied-at-generation-time and cannot map the
     client's outstanding sent bytes (round-5 counterexample: rebase to
     appliedBytes=10 renumbers 90 in-flight bytes and lets a later partial
     ack falsely confirm a control). Instead the client enters **desync**:
     it stops confirming ANY control (renders nothing) until the next
     **unambiguous boundary event** — its own reconnect, its own discard
     request, or a bus-ordered server discard report — at which in-flight
     input is by definition discarded-or-unknown and R/D legitimately reset.
     New controls sent while desynced remain unconfirmable rather than being
     assigned offsets from an unrelated ack snapshot. **Desync recovery**
     (round-6 R6-B4): only a `kind = inputBoundary` report (or the client's
     own reconnect/discard-request event) establishes the shared input
     origin that ends desync — completion, output-shed and request-status
     reports never do. A repeated boundary report for an epoch the client
     already observes is ignored (no double reset). Recovery is silent
     until that origin is established. D is per-epoch (resets
     at boundaries). Disagreement is therefore detectable and always
     resolves conservatively, never silently. The first ack of an epoch
     carries the then-current `appliedBytes` (liveness confirmation).
   * **The ordered bus sender** (round-4 R4-B1 + round-5 R5-B3 — the
     enforcement mechanism, not an implementation detail): every
     ordering-sensitive bus event of a connection — `input_ack` AND the
     extended `discard` reports — is emitted through ONE per-connection
     sender goroutine which alone performs the bus-stream write, consuming a
     FIFO of pre-serialized messages. Events are enqueued **at the point of
     state change, under the same per-session input-state mutex that updates
     `appliedBytes`/D** — enqueue order = state-change order = wire order —
     so an ack can never overtake the discard report of a discard that
     preceded it (the client's D is never stale when it evaluates `R − D`).
     **No enqueue ever waits on the network** (round-5 R5-B3): acks occupy a
     bounded per-session slot with **epoch-aware, barrier-respecting
     coalescing** — an ack may only be superseded by a newer ack of the SAME
     epoch positioned AFTER the last enqueued discard report in the FIFO
     (never across a report barrier); overflow drops the ack (advisory).
     Discard reports go into a grow-on-demand queue **capped at 256
     outstanding**; at cap, discard/shed REQUESTS are rejected with a
     visible `ShedStatus = rejected` — and the load-bearing
     reconnect-marker report follows the **reserve-before-mutate policy
     below** (a guaranteed slot, or the marker is not installed and the
     session refuses input; the earlier degradation variant is removed as
     unsafe — design review rounds 6-7) — **no producer ever blocks on
     network-dependent queue space while holding input state or inside
     `forwardInput`**.. On a bus-write failure of a discard report, the
     sender marks the connection's ordered stream broken and stops emitting
     (the session's existing error path applies; nothing follows on a dead
     stream, so the client can never process an ack whose prerequisite
     report was lost). The existing `go func()` discard sends and the
     mutex-released-before-write `sendBusMessage` pattern are REPLACED for
     these events (legacy disconnect-time cache reports keep their current
     path — no epoch, and they precede epoch-boundary processing by
     construction). Acks remain advisory (loss renders "no confirmation");
     the loss rate is a reported gate statistic (§7 row 3). **Client rule**:
     bus dispatch updates D/R state synchronously in dispatch order; UI
     callbacks are invoked asynchronously only AFTER the state update. The
     ack flow can never stall `forwardInput`.
   * The existing `discard` bus message is EXTENDED (schema addition, see
     wire list) to `{kind, sessionID, epoch, discardedInputBytes (non-marker),
     discardedOutputLines, discardedOutputBytes, outputStart, outputEnd,
     requestInputOffset, ShedStatus, inFlightBytes}` — **kind-classified**
     (round-6 R6-B4): `kind ∈ {inputBoundary (marker installed),
     inputDiscardCompleted, outputShed, requestStatus}`. Only
     **`inputBoundary`** creates an epoch boundary and resets client R/D;
     completion/status/output reports NEVER reset anything. **D
     attribution** (round-6 R6-B4): a report's `epoch` is the epoch IN
     WHICH THE DISCARDED BYTES WERE RECEIVED — pre-marker bytes discarded
     after a boundary belong to the OLD epoch, so a client already in the
     new epoch ignores stale-epoch D updates entirely (they surface in UI
     transparency only, never touching R/D): the round-6 counterexample
     (`101 >= 201 - 100` false-confirming) is impossible, because those 100
     bytes are never subtracted from the new epoch's R domain. The
     `outputStart/outputEnd` pair is the half-open `[start, end)` range in
     the session's **stdout output stream source coordinates —
     session-lifetime, never reset by input epochs** (round-6 R6-B2 wire
     fix; the range is what makes §7 row 8's shed case reconstructable).
     **Reserve-before-mutate admission** (round-6 R6-B3): every
     state-changing discard/shed operation reserves its report slot in the
     ordered sender BEFORE performing the state change. The
     reconnect-marker report — which is load-bearing: the client injects
     the marker from it, and `discardPendingInput` cannot find its
     delimiter without it — has a **guaranteed single reserved slot** (one
     per reconnect, bounded by reconnect frequency); if even that slot
     cannot be reserved (bus dead), the marker is **NOT installed** and the
     server refuses further input on that session until the bus recovers
     (explicit connection-level failure — never an undisclosed marker
     with input silently accumulating). A shed request is admitted only
     with a reservable slot; its own rejection (`ShedStatus = rejected`)
     consumes that slot; a request arriving with no reservable slot is not
     admitted (dropped + server debug log; the client's 10 s no-notice
     timeout renders "no confirmation" — conservative, never false). The
     pre-existing legacy fields and the client's `DiscardCallback`
     plumbing are reused; the callback surface gains the new fields.
   * `discard_output {sessionID, epoch, inputOffset}`: `inputOffset` is in
     applied coordinates — the client's `R − D` for the control it wants to
     shed behind. The server defers execution until `appliedBytes(epoch) ≥
     inputOffset` (same domain, no translation), then drops that session's
     pending stdout-forwarder buffers at the §3-P2 cut point and reports via
     the extended `discard` message. **Expiry** (round-4 R4-W2): if
     `inputOffset` is not reached within **10 s** of the request (or at epoch
     end, whichever comes first), the request expires with an explicit
     `discard` report whose `ShedStatus = expired` field says so (additive
     enum) — the client learns the shed did not happen instead of inferring
     it; no output is shed on expiry. The harness test injects loss at the **application level** — bytes are
     dropped at the client send path before entering the transport (kcp is
     reliable: wire loss alone is never permanent input loss) — so expiry is
     deterministic.
   * **Required tests** (tsshd#7/#8): two simultaneous sessions (D attribution),
     marker-only discard, marker+Ctrl-C surviving-suffix, discard-report/ack
     bus ordering, input in flight across an epoch boundary, `inputOffset`
     unreachable expiry.
6. **Reuse over invention**: disposal accounting reuses `discardMessage`; the
   client consumes it through the existing `UdpClientOptions.DiscardCallback`
   plumbing (whose tssh wiring precedent is `handleTmuxDiscardedInput` — a
   callback *wiring* reference, not a render implementation; P4's render is new
   work, §5).

Wire additions in total: one `settingsMessage` field; one message struct
(`inputAckMessage`); one optional request command (`discard_output`); a
**schema extension of the existing `discardMessage`** (sessionID, epoch,
discardedInputBytes, output range, request echo, ShedStatus — additive JSON
fields, old clients that receive a `discard` message ignore the new fields
exactly as they ignore the rest of the extension); and an **additive epoch
field in the existing session-start success response** (an additive field in
an existing message, not a new handshake message). No changes to the
data-stream protocol's framing or the reconnect protocol's flow.

---

## 5. Exact ownership map

"new" marks surfaces that do not exist yet; everything else was verified in the
tree at the stated pins.

| change | repo | module / file | functions / surfaces |
|---|---|---|---|
| P0 budget gates | tsshd | `tsshd/control_latency_test.go`, `benchmarks/control-latency/` | harness + result JSONs; **new**: per-direction relay accounting in shared mode, goodput/amplification/ack/reconnect/byte-integrity cases |
| P1 pacing | tsshd | `tsshd/output.go` | `serverOutputForwarder.writerLoop` (**new**: per-connection token bucket before `writeAll`; pacing state shared by the connection's forwarders) |
| P1 config plumbing | tsshd | `tsshd/main.go` (`tsshdArgs` lives here), `tsshd/service.go` (`initServer`), `tsshd/session.go` (`newOutputForwarder`/`forwardIO` wiring), `tsshd/sshd_config.go` | **new**: `--kcp-wire-rate` arg → connection-level pacing config → forwarders |
| P2 disposal | tsshd | `tsshd/output.go`, `tsshd/session.go`, `tsshd/bus.go`, `tsshd/proto.go` | **new**: `discard_output` handling + rendezvous on the P3 counter; drop of own pending buffers with exact accounting; reuse of `discardMessage`; existing: `flushOutput`/`clearOutput`/`cacheOutput` accounting |
| P3 ack | tsshd | `tsshd/session.go`, `tsshd/bus.go`, `tsshd/proto.go`, `tsshd/client.go` | `forwardInput` (**new**: epoch counter + post-write ack emission), `sendBusMessage`, **new** `inputAckMessage` + client dispatch case + ack callback surface |
| P4 client display | trzsz-ssh | `go.mod`, `tssh/udp.go`, tssh UI layer | re-pin tsshd; advertise capability via `UdpClientOptions`/settings; **new** render of ack marker + shed notice outside the forwarded stream (the `handleTmuxDiscardedInput` callback is a wiring precedent only — its body ignores output counts today) |
| P5 ops guide | tsshd (+ trzsz-ssh flag) | `docs/`, `tssh/udp.go` | per-direction qdisc / size-keyed tc recipes, WMM/DSCP caveats, **new** optional `--udp-tos` |

Platform scope: everything in v1 (pacing, ack, own-buffer disposal) is
platform-neutral Go. The *deferred* PTY-queue flush variant would be Unix-only
(`tcflush` via `utils_unix.go`) — one more reason it stays behind §9's gates.
No kcp-go or smux fork changes are required by any phase; if tsshd#5's
attribution later demands transport instrumentation, it lands in the owned forks
(`github.com/trzsz/kcp-go/v5`, `github.com/trzsz/smux`) as its own work item.

---

## 6. Terminal semantics preservation (hard constraints)

* The forwarded stream is raw PTY bytes. No reflow, no cursor math, no repaint
  synthesis. v1 adds **zero** bytes to the forwarded stream: the ack and the shed
  notice travel on the bus stream and are rendered by the requesting client's UI
  layer only. (The pre-existing disconnect-time warning line in `flushOutput` is
  unchanged legacy behavior, not extended.)
* Disposal (when explicitly requested) drops a **contiguous prefix of tsshd's own
  pending buffers**, with exact lines/bytes accounting reported; the surviving
  stream is byte-exact **at the byte level** — terminal-state interpretation of
  surviving bytes is not guaranteed if the dropped prefix opened a state
  transition (a documented consequence of the opt-in, §3 P2). Nothing drops
  PTY-produced bytes from the kernel queue or the transport in v1.
* Ack rendering (P4) happens **outside** the forwarded stream — a transient
  status indicator in tssh's UI layer. In all **no-shed** operation,
  copy/scrollback produce exactly what a plain SSH session would (§7: harness
  byte-diff gate + P4's manual UI checklist); after an explicitly requested
  shed, copy reflects the shed prefix and its notice — by design, opted into
  (§3 P2).
* Scrollback, touchpad scrolling and selection are untouched by every phase;
  the reconnect pending-output cache (existing `max(…, rows*2)` line bound)
  keeps its semantics.

---

## 7. Performance budgets and regression gates (executable contracts)

Measurement procedure, common to every row: the env-gated harness (tsshd#3
extends PR #1's: non-blocking tail-drop relay queue, FEC-aware rate shaping,
`CLOCK_MONOTONIC` everywhere, absolute artifact paths), one command per case,
seeded. **Each gate case = 3 seeded runs; latency rows take ≥ 30 control samples
per run using the `loss20` stimulus pattern (sequential interrupts against the
surviving flood child — the child does not exit after one interrupt);
nearest-rank p95 is computed PER RUN and the gate requires EVERY run's p95 (or
the row's stated statistic) to meet the threshold (3/3); every run is reported
in the artifact.** ⚠ = tsshd#3 re-measures the baseline first (harness v2,
including the shared-mode per-direction accounting fix); gates marked
"vs ⚠baseline" bind to the re-measured value. **Pacing configuration is named
per row** (P1 off = the shipped default; "recipe" = `--kcp-wire-rate` at
0.7 × bottleneck, amp_estimate pinned 2.2). **Gate ownership** — a row is
*closed* when its named owner's gate run passes it: **tsshd#3** builds and ships
every case and wraps on harness correctness plus the P1-off / no-feature
configurations of rows 1–2 and 5–8 at the current pins; **tsshd#6** closes the
P1-on variants of rows 1–2, 5–7 and the no-shed row 8 (its before/after run);
**tsshd#7** closes row 3(b), which needs no P1; **tsshd#8** — blocked by #6 AND
#7, hence guaranteed to execute after both — runs row 3(a) as its **entry gate** (it measures only #6+#7 features) and closes rows 4 and the row-8 shed case as its **completion gates** (they measure #8's own implementation); **tsshd#9** owns the manual UI checklist
(below). No row is closed by a work item that precedes the feature it measures.

| # | budget | closed by | definition (counters) | case / prerequisites | baseline | gate |
|---|---|---|---|---|---|---|
| 1 | Input delivery | #3 (P1 off) · #6 (P1 on) | `T_inject → T_sigint` (unix-socket side channel); per-run p95 over ≥ 30 samples | the 8 cases with a committed control measurement (the paste-pathology cases keep their asserted no-SIGINT expectations); P1 on @ recipe AND off | per-case [committed] (51 ms-class wherever uplink has headroom) | each run's p95 within **+10 % of the committed value** (a committed single value stands in for p95 where only one committed run exists; `loss20` uses its committed p95), 3/3 runs |
| 2 | Visible confirmation (drain) | #3 (P1 off, ⚠baseline) · #6 (P1 on) | confirmation latency = `T_client_marker − T_inject`; per-run p95 | `bottleneck_shared`, `bottleneck_split` @ 2 Mbps + 20 % loss + flood; P1 on @ recipe | ⚠ recomputed under this definition (committed anchors: split marker 1.76 s, upclean marker 709.6 ms; perceived 2.5–4.9 s [committed], 8.6 s and >40 s [reported]) | **each run's p95 ≤ 1.5 s**, 3/3 runs |
| 3 | Visible confirmation (ack) | (b) #7 · (a) #8 | (a) `T_inject → client receives an ack covering the Ctrl-C offset` (coverage rule §4.5), per-run p95; (b) **paired-event gate** against the child's post-SIGINT marker (the harness-recognized first post-interrupt output), ≥ 30 paired trials per run | (a) `bottleneck_split` + P1 on @ recipe; (b) `bottleneck_shared` unmitigated, P1 off | (a) new capability — the 150 ms target is **provisional, ⚠ re-anchored with evidence if tsshd#3's loss-recovery measurement disagrees** (20 %-loss echo p95 was 212.6 ms [committed]); (b) input delivery itself 0.67–1.24 s [committed] | (a) **each run's p95 ≤ 1.5×RTT** (150 ms @ 100 ms RTT); (b) **paired-win ≥ 90 % among delivered acks AND delivered-ack coverage ≥ 20/30 per run**: a paired win = ackDelay < markerDelay; ack absent → counted in the loss rate, never a win; marker absent within the existing observation patience → win, noted; tie → not a win; **no absolute bound claimed** |
| 4 | Post-shed settle (P2, opt-in) | #8 | settle = `T_marker(client) − T_discard_notice(client)`; start = the `discard` notice, end = the child's post-SIGINT marker | `bottleneck_shared` + P1 on @ recipe + client-requested shed mid-flood | ⚠ #3 ships the case; #8 activates it | **≤ 1 s, 3/3 runs** (a marker arriving before the notice — possible, independent bus/data streams — counts as ≤ 0 and passes, reported); **notice missing → run FAILS**; **a shed that deletes the marker fails the run** (adversarial preservation, §3 P2) |
| 5 | Bulk goodput | #3 (P1 off, ⚠baselines) · #6 (P1 on) | client-received payload bytes (client receive timestamps) in the window t ∈ [5 s, 10 s] of the steady transfer ÷ 5 s, per direction | clean 100 Mbps with P1 **off** and with a 200 Mbps cap; degraded = `bottleneck_shared` AND `bottleneck_split` @ 2 Mbps + 20 % loss + flood, P1 on @ recipe | ⚠ tsshd#3 (unpaced + paced) | clean: capped ≥ **90 %** of the P1-off value; degraded: **≥ 0.8 × (1.4 Mbps ÷ 2.2) = 0.5 Mbps** delivered (§3 P1 pinned formula) AND **≥ 2×** the ⚠unpaced degraded baseline |
| 6 | Wire amplification | #3 (P1 off, ⚠baselines) · #6 (P1 on) | **both-direction relay egress ÷ client payload bytes** (the statistic behind the committed baselines); offered-based (enqueued+dropped ÷ payload) reported alongside; shared-mode sections counted **once** | same configs as row 5 | clean ≈ 2.68× [committed `baseline.json`]; shared degraded ≈ 3.2× egress / ≈ 8.9× offered [committed r2] | clean: **≤ 2.8×**; degraded: **≤ 4.0×** egress-based while meeting row 5; 3/3 runs |
| 7 | Reconnect | #3 (P1 off, ⚠baselines) · #6 (P1 on) | roam-under-load (client reconnect mid-flood, session persists) + attach-after-detach; success, time-to-reattach, post-reattach byte continuity under the unchanged pending-output policy | mid-flood @ 2 Mbps + 20 % loss; P1 on @ recipe and off | ⚠ tsshd#3 | success 3/3; reattach ≤ ⚠baseline + 10 %; continuity per existing cache accounting, no new loss |
| 8 | Raw PTY byte integrity | #3 + #6 (no-shed) · #8 (shed) | byte-diff of server-side PTY reference capture vs client-received stream; shed case reconstructs expected = reference minus the `discard`-reported output byte range | clean; flood; flood + client-requested shed; P1 on @ recipe and off | n/a (new) | diff = **0** in all no-shed cases, 3/3 runs; shed case: received == reference minus **exactly** the reported byte range (lines+bytes consistent) |

**Library gates vs UI acceptance**: rows 1–8 are harness-verifiable. The claim
"the ack indicator is visible and copy/scrollback stay byte-faithful in a real
terminal" is **not** harness-verifiable; it is P4's explicit **manual acceptance
checklist** (tsshd#9): copy in a flood session == plain-SSH copy; scrollback
intact; ack indicator transient and outside the stream. tsshd#9 does not wrap
without that checklist recorded. (The ≈98 % client/source counter ratio in
§1.3 is a counter ratio, not a byte-integrity proof — row 8 is the proof.)

Gate discipline: every phase's PR runs its budget cases before/after and attaches
both JSON sets; a gate may only be relaxed with new committed evidence and an
explicit note on this wi's timeline.

---

## 8. Follow-up work items

Filed under tsshd#2 (parent), milestone `kcp-improvement`, dependency-ordered
(edges verified via `pf_list_dependencies` at revision time; see the wi
timeline note):

| phase | wi | scope | blocked by |
|---|---|---|---|
| P0 | tsshd#3 | budget-gate harness + baselines (§7), per-direction shared-mode accounting fix | tsshd#2 |
| P1 | tsshd#6 | wire-aware per-connection output pacing (§3 rank 1) | tsshd#3 |
| P3 | tsshd#7 | input-accepted ack + capability negotiation (§3 rank 2, §4) | tsshd#3 |
| P2 | tsshd#8 | opt-in client-requested disposal (§3 rank 3) | tsshd#6, tsshd#7 |
| P4 | tsshd#9 | client ack/shed rendering + manual UI checklist (§5, §6) | tsshd#7 |
| P5 | tsshd#4 | qdisc/DSCP ops guide + optional flag (§3 rank 4) | tsshd#2 |
| P6 | tsshd#5 | split-vs-shared goodput attribution (§3 rank 5) | tsshd#2 |

P4 (tsshd#9) delivers in two stages within one work item: **stage 1** after P3
alone (re-pin to the P3-carrying release, ack indicator — blocked only by
tsshd#7) **releases independently** — its PR may merge without waiting for P2 —
while tsshd#9 itself **remains open** until **stage 2** lands (shed notices +
the client shed-request policy; second re-pin, after tsshd#8).
P3's row-3(a) fast-ack gate requires P1's configuration; tsshd#7 wraps on
implementation + protocol tests + the row-3(b) paired-event gate (which needs
no P1), and the row-3(a) gate is formally closed as an **entry gate of
tsshd#8** — which is blocked by tsshd#6 AND tsshd#7 and therefore guaranteed to
execute after both implementations (§7 gate ownership).
P4 stage 1 may proceed in parallel with P2's disposal work once P3 lands
(different repos; the `session.go`/`bus.go` overlap between P1/P2/P3 is
serialized by file-scope locks).
P6's findings flow back into P1's recipe as a follow-up patch, not a blocker.
Child-wi contents were reconciled through revision v7 at review_fix time;
the dependency edges were verified authoritatively via `pf_list_dependencies`
(tsshd#8 is blocked by tsshd#6 AND tsshd#7).

---

## 9. Open questions (evidence-gated, deliberately unanswered here)

1. **Adaptive pacing default** — can tsshd infer a safe wire budget
   (loss/RTT-driven) without hurting strong links? Blocked on tsshd#5.
2. **FEC tuning** — only after tsshd#5 shows correction (not overshoot) matters;
   until then dynamic FEC stays closed.
3. **PTY-queue flush safety** — the boundary-safety gates any future
   default-on/auto shed must pass before it may even be proposed as default:
   immediate-post-SIGINT output preservation (prompt race), partial writes,
   no-newline output, escape-sequence/terminal-state boundaries (incl. alt
   screen), concurrent reconnect, exact accounting, per-platform behavior.
   Until those gates exist and pass, disposal stays client-requested and
   own-buffers-only.
4. **Raw-mode disposal ergonomics** — how aggressively a raw-mode agent's client
   should request sheds (heuristics live client-side where the intent is known);
   decided in tsshd#8/#9 specs against their own gates.
