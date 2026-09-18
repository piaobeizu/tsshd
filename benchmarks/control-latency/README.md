# Control-input latency under agent-style flood output

Reproduction and decomposition of the reported failure: **while a Claude
Code / Pi style agent floods output over `tssh --udp --kcp` on a weak
network, Ctrl-C (and other control input) feels dead or is never
confirmed** — measured at every boundary: client, KCP/smux transport,
server output path, and the server-side PTY.

Everything here runs from one env-gated Go test in `tsshd/tsshd/control_latency_test.go`.
`go test ./...` is unaffected: the test skips unless `TSSHD_CTRL_BENCH` is set.

## What is measured

```
client stdin pipe (harness -> SshUdpSession)     [T_inject]
  -> client smux stream (one stream, in+out)     (client accepts instantly: 512KB stream window)
  -> kcp-go UDPSession -> netem relay (up)       (loss / delay / rate / tail-drop queue)
  -> server kcp -> smux -> session forwardInput  (session.go)
  -> PTY master write -> kernel ISIG -> SIGINT   [T_sigint, unix-socket side channel]
  -> child stops flooding                        [T_lastwrite]
  -> child writes marker to PTY                  [T_child_marker]
  -> output backlog drains over the same link    (relay queue + kcp + smux buffers)
  -> client drain loop sees the marker            [T_client_marker = "user perceives it worked"]
```

All timestamps are `CLOCK_MONOTONIC` (comparable across the re-exec'd child
on the same host). The side channel is a unix socket, so child events never
traverse the transport under test.

## Harness semantics (why it is trustworthy)

* **In-process server and client**: `initServer(KCP)` and `NewSshUdpClient`
  are the production code paths (`tssh` wraps the same `SshUdpClient`;
  trzsz-ssh pins `github.com/trzsz/tsshd`).
* **Userspace netem relay** mirroring `tc netem delay D loss P rate R limit L`:
  * enqueue is **non-blocking** — a full queue tail-drops, exactly like a
    kernel qdisc. (A blocking write would stall kcp-go's update-loop
    `defaultTx` and fabricate a processing stall no real link has.)
  * loss applies at enqueue (egress loss), delay + **strict byte pacing**
    at egress, order preserved; FEC 1+1 parity packets are shaped too (the
    rate limiter counts real datagram bytes).
  * **shared** mode models one bottleneck queue carrying both directions
    (a single netem qdisc); **split** models per-direction qdiscs.
  * Seeded RNG → the loss pattern is reproducible per case.
* **Claude-Code-style child**: re-exec of the test binary under the
  server-side PTY, flooding ~206-byte colored lines as fast as the PTY
  accepts, with a SIGINT handler + side-channel timestamps. `floodread`
  additionally drains stdin, modeling an agent whose input thread keeps
  reading while its output floods.
* **Perceptual confirmation**: the child writes a marker right after
  SIGINT; `T_client_marker` is when the *user* would see the interrupt
  took effect. Marker patience is 10 s + 30 s drain — a user is long gone
  by then.

## Case matrix

| case | link | child | paste | isolates |
|---|---|---|---|---|
| `baseline` | 100 ms RTT only | flood | — | pure machinery overhead |
| `loss20` | + 20% loss both ways | ctrlcount ×30 | — | control-path distribution under pure loss |
| `loss20_flood` | + 20% loss, no rate cap | flood | — | does flood alone block control input? |
| `slow_client` | clean; client drains output at 200 KB/s | flood | — | does client-side output backpressure block control input? |
| `bottleneck_upclean` | downlink 2 Mbps only + 20% loss | flood | — | downlink saturation without uplink contention |
| `bottleneck_split` | 2 Mbps **per direction** + 20% loss | flood | — | same, uplink also capped but separate queue |
| `bottleneck_shared` | 2 Mbps **shared queue** + 20% loss | flood | — | the reported failing config |
| `paste_shared_reading` | shared bottleneck | flood **+ reads stdin** | 64 KB | agent model: paste-then-Ctrl-C |
| `paste_block` | shared bottleneck | flood, never reads stdin | 64 KB | pathological paste target |
| `paste_baseline` | clean link | flood, never reads stdin | 64 KB | PTY input-buffer HOL with no network |
| `input_*` (8) | as the base case | floodcount/ctrlcount ×30 (`floodreadcount` + echo off for the paste case) | 64 KB per sample for `input_paste_shared_reading` | row-1 gate suites: ≥30 sequential interrupts against a surviving child |
| `bulk_clean`, `bulk_clean_cap200` | 100 Mbps / 200 Mbps cap | bulk ×12 s (echo off, reads stdin) | — | row-5 goodput, both directions |
| `bulk_bottleneck_shared`, `bulk_bottleneck_split` | 2 Mbps + 20% + flood | bulk ×12 s | — | row-5 degraded goodput, both directions |
| `reconnect_roam` | 2 Mbps + 20% loss | roam ×15 s (raw output) | — | row-7 black-hole reconnect under load |
| `reconnect_attach` | 2 Mbps + 20% loss | roam ×15 s (raw output) | — | row-7 detach + attach under load |
| `integrity_clean`, `integrity_flood` | clean / +20% loss | integrity (1 MiB framed payload) | — | row-8 byte diff vs server PTY reference |

`TSSHD_CTRL_BENCH_OUT=<file>` writes a schema-2 suite containing all
seeded runs (three by default) as JSON. Set `TSSHD_CTRL_BENCH_RUNS=1` only
for harness development; a citable gate artifact always contains 3/3 runs.

```sh
# one case, three seeded runs, one reproducible suite artifact:
TSSHD_CTRL_BENCH=bottleneck_shared \
TSSHD_CTRL_BENCH_OUT="$PWD/benchmarks/control-latency/results/my-shared-suite.json" \
go test ./tsshd -run '^TestControlLatencyUnderFlood$' -v -count=1
# raise go test's own 10m default for slow suites, e.g. the paste case:
# go test ./tsshd -run '^TestControlLatencyUnderFlood$' -count=1 -timeout=2h
```

## Budget-gate harness

The gate inventory is executable and machine-readable. This command emits the
contract, activation state, threshold and baseline provenance for any case:

```sh
TSSHD_CTRL_GATE=all go test ./tsshd -run '^TestControlBudgetGateCatalog$' -v -count=1
```

Every measurement uses the same `TSSHD_CTRL_BENCH=<case>` command shown above.
The RNG seed (`20260916`), run count and every run are embedded in the suite;
timestamps use `CLOCK_MONOTONIC`. `results/budget-baselines.json` is the
baseline index. It distinguishes `[committed]`, `[README-reported]` and
`[design-target]` figures and names the source artifact for each committed
number.

| budget | active cases | statistic / behavior |
|---|---|---|
| row 1 input delivery | `input_baseline`, `loss20`, `input_loss20_flood`, `input_slow_client`, `input_bottleneck_upclean`, `input_bottleneck_split`, `input_bottleneck_shared`, `input_paste_shared_reading` | 30 sequential interrupts against a surviving child per run; nearest-rank p95; committed value +10% |
| row 2 drain confirmation | `input_bottleneck_shared`, `input_bottleneck_split` | per-sample `T_client_marker-T_inject`, nearest-rank p95; P1-off baseline only |
| row 3(b) ack confirmation (tsshd#7) | `ack_bottleneck_shared` (inactive until the row-3(b) campaign attaches artifacts) | identical stimulus/netem to `input_bottleneck_shared` (unmitigated shared bottleneck, P1 off) with the input-ACCEPTED ack negotiated: per-sample `T_client_ack-T_inject` via the §4.5 coverage rule, paired against the child's post-SIGINT marker; paired-win ≥90% among delivered acks AND delivered-ack coverage ≥20/30 per run AND ack traffic <1% of stream bytes (the artifact carries `ack_events`/`ack_wire_bytes`); ack absent → loss rate, never a win; marker absent within patience → win, noted; tie → not a win; **no absolute latency bound claimed**. A dedicated `ack_*` case keeps rows 1/2's committed stimulus byte-identical (no ack traffic on their baselines) |
| row 5 bulk goodput | `bulk_clean`, `bulk_clean_cap200`, `bulk_bottleneck_shared`, `bulk_bottleneck_split` | client receive byte samples in `[5s,10s] / 5s`, **each direction in every case**: downlink from client byte samples, uplink from child-received bytes at the same window (child disables PTY echo so the two directions stay separable; no echo feedback storm). The uplink is line-discipline-bound (~4 KB per canonical line per round trip), not transport-bound — the figure measures a canonical-PTY session uplink. Missing child uplink reports fail the run. |
| row 6 amplification | the four bulk cases + the one-way `baseline` case | `relay.aggregate.egressed_bytes/client_payload`; offered ratio alongside; shared-mode aggregate counted once. The one-way clean reference (`baseline`, ≤2.8× vs committed 2.679×) is gated; the bidirectional bulk family reports [committed-v2] baselines (echo off changes the denominator; the legacy one-way figure is context, not a directly comparable gate). |
| row 7 reconnect | `reconnect_roam`, `reconnect_attach` | mid-transfer black-hole reconnect and real detach/new-client attach; reattach time plus byte continuity under the unchanged pending-output policy. Roam: **exact equality** required (child total == client total; the child disables PTY OPOST so the count is bytewise-decidable; a missing child total or any unaccounted gap fails the run). Attach: success + attach time required, and the continuity gap is **gated at the committed maximum +10%** (30720 B) — measured 3/3: the detach-window records (~30 x 1024 B) reach neither client with zero discard notices, an un-accounted loss recorded in `continuity_gap_bytes`/`continuity_unaccounted` and in the baselines index; the production defect is tracked by tsshd#11, and exact equality is this case's target once it lands |
| row 8 integrity | `integrity_clean`, `integrity_flood` | exact framed 1 MiB PTY payload comparison against a server-side PTY reference (`screenBuf` tap, captured before stream forwarding), byte diff must be zero |

Feature-dependent contracts are present but deliberately **inactive**:
`visible-confirmation-ack-split` (row 3(a)) is tsshd#8's entry gate and waits
for its campaign (the #6+#7 features it measures have landed);
`visible-confirmation-ack-shared` (row 3(b)) has its measurement case
(`ack_bottleneck_shared`, landed with tsshd#7) and waits for the row-3(b)
campaign's committed artifacts; `post-shed-settle` and
`raw-pty-byte-integrity-shed` wait for tsshd#8. `TSSHD_CTRL_GATE` only
reports these contracts—it cannot activate them. This prevents a placeholder
or absent capability from producing a green gate.

Shared-mode artifacts no longer mirror one queue into both directions. Each
packet carries an up/down classification, while `relay.aggregate` is the one
physical shared FIFO and is counted exactly once for amplification. In split
mode the aggregate is the sum of both physical queues. A focused unit test
pins this accounting.

The suite is benchmark-only: no production code path reads either environment
variable, and without them both tests skip, so normal `go test ./...` remains
unchanged.

**Baseline re-anchor, limitations and open gates.** The legacy single-shot
artifacts were fixed-phase draws: their Ctrl-C was injected at one warmup
instant whose queue occupancy is not reproducible, so they never sampled the
pinned-full-queue tail. Harness-v2 30-sample suites measure that tail, so
rows were re-anchored to [committed-v2] p95 envelopes per design §7 gate
discipline (relaxed only with new committed evidence, recorded on the work
item's timeline); `results/budget-baselines.json` carries the per-run
evidence trail and the provenance of every figure. Committed 3/3 suites
exist for every active row-1/2/5-8 case at the current pins. Known limits:

* The clean 200-Mbps case caps the *relay*, not P1's future server output
  pacer; it cannot close the P1-on comparison (owned by tsshd#6).
* The paste case's per-sample patience is 120 s with a patience-censoring
  protocol: kcp RTO backoff on the ordering-constrained paste segments
  pushes single samples into a heavy, phase-correlated tail without the
  input path being broken (the measured ladder: 90 s truncated 5 of 6
  seeded runs, 300 s truncated 1 of 3, 600 s censored consecutive samples
  in 2 of 4 runs). A stuck attempt is recorded as `censored` in the
  artifact (CtrlMs = the bound, a lower bound) and KEPT in the p95 input
  at that bound, so censored attempts sort above every completed sample:
  one censor per run keeps the rank-29-of-30 p95 on a completed sample,
  while the second makes the p95 itself censored and aborts the run red —
  a red run always writes its artifact in bounded time (~5 min) instead of
  burning hours. The censor count is itself the sharpest regression
  signal: with output pacing (tsshd#6) the queue never pins and censors
  vanish.
* Degraded bulk runs are liveness-bounded on both sides: the child abandons
  stdout writes blocked longer than 12 s + 120 s, and the client's uplink
  writer is waited for at most 90 s. The goodput window comes from the
  child's own reports, so a writer stalled behind a collapsed downlink is
  abandoned with a log rather than failing the run — a run whose uplink
  reports are actually missing fails the suite instead of silently
  reporting one direction. The re-exec'd children also exit when their
  harness process disappears (side-channel EOF or stdout write error),
  so failed runs stop leaking spinning flood children.
* Reconnect continuity is exact-bytewise in zero-discard runs (client total
  == child total); the roam child disables PTY OPOST, otherwise ONLCR adds
  one byte per record and equality is undecidable.
* The integrity reference is captured from the server PTY's `screenBuf` tap,
  before stream forwarding, and not inferred from client bytes.

Roughly equivalent `tc netem` on a veth pair (for validating the real
binaries; the in-process harness exists because cross-process timestamping
and qdisc manipulation need root and are not CI-friendly):

```sh
# shared bottleneck (one qdisc for both directions):
tc qdisc add dev veth-client root handle 1: netem delay 50ms loss 20% rate 250kbit limit 1000
# split (per direction): same command on both veth ends
```

## P1 output pacing (tsshd#6): the p1_* variants

The server now ships a default-off, per-KCP-connection output pacer
(`--kcp-wire-rate <bytes/s>` / sshd_config `KcpWireRate`; see `tsshd/output.go`).
The `p1_*` case variants run the same cases with the pacer at the recipe:
`0.7 x bottleneck` wire budget — 175,000 B/s at the 2 Mbps reference — with
the payload token rate = wire budget / 2.6 (amp tightened 2.2 -> 2.6 with
campaign evidence; see below). The clean-link regression uses the design's
separately-configured 200 Mbps cap (25,000,000 B/s) on the 100 Mbps case,
never the weak-link recipe. Uncapped clean/loss cases run the weak-link
recipe so the pacer is the binding downlink constraint even on a clean link.

**Measured (2026-09-18, same-pin before/after campaign; `results/p1-*.json`
vs `results/p1off-*.json`, 3 seeded runs each):**

| budget | P1-off (before) | P1-on @ recipe (after) | gate |
|---|---|---|---|
| row 1 input p95 (8 cases) | committed envelopes + same-pin re-measure | 51-215 ms on the 7 non-paste cases (bottleneck envelopes were 2767-5320 ms); paste 4.7-5.0 s, inside its 6.9 s envelope | **3/3 PASS** every case |
| row 2 confirmation p95 | honest full-coverage accounting (24-30 of 30 markers): shared 10.9-13.2 s, split 8.7-9.4 s | prefix p95 shared 5.7-7.1 s, split 3.6-4.3 s; only 5-15 of 30 markers arrive within the 120 s marker drain | **FAIL 3/3**: over the 1.5 s design target AND not citable (truncated marker prefix; ~2x improvement on the comparable prefix; remainder owned by tsshd#13 — see below) |
| row 5 degraded goodput | collapsed: same-pin medians shared 10.7 KB/s, split 38.5 KB/s (committed 14.7/66.8 KB/s) | shared 551-577 kbps; split 531-537 kbps | shared **3/3 PASS** (formula floor 53846 B/s + 2x unpaced); split passes formula + committed parity 63427 B/s (2x unreachable by construction, see the row-5-p1 contract) |
| row 5 clean capped | same-pin median 1.18 MB/s (`p1off-bulk-clean-cap200.json`) | 1.19-1.27 MB/s | **3/3 PASS** (>= 90% of same-pin P1-off median) |
| row 5 matched-stimulus attribution | p1offq references (same 8 KB/s uplink, pacing off): shared 29.8-55.1 KB/s (median 53.2), split 23.2-107.7 KB/s (median 93.0; retransmit-luck spread) | shared 68.8-72.1 KB/s (1.29x the matched median); split capped at the recipe | controlled attribution: shared improves under pacing; split is deliberately capped by the weak-link recipe (its per-direction queue has no downlink/uplink contention) - the honest cost, recorded in budget-baselines.json |
| row 6 amplification | clean ~2.68x one-way; degraded 4.1-8.7x | one-way `p1_baseline` 2.29-2.31x; degraded bulk 2.34-2.60x | **3/3 PASS** (<= 2.8x one-way, <= 4.0x degraded) |
| row 7 reconnect | same-pin maxima 1140.4/1015.7 ms (committed 976.3/921.2); attach gap 30720 B committed, 0 expected now | roam reattach 736.5-941.7 ms; attach 819.8-921.8 ms; continuity gap **0** (tsshd#11 landed) | **3/3 PASS** (same-pin suite max +10%, the committed row-7 convention) |
| row 8 integrity | diff 0 | diff **0** under pacing (clean + flood) | **3/3 PASS** |
| paste censors | red truncated/censored runs on the deep tail | **zero censored samples, 3/3 green** | as the row-1 contract predicted |

**Row 2 analysis (why 1.5 s is not reached, and why the P1-on side is not
citable; honest full-marker accounting, evidence on the tsshd#6 timeline,
remainder owned by tsshd#13):** the original harness computed confirmation
p95 over a truncated marker prefix (the `markerCount()` scan-tail bug) and
understated the tail; with cumulative marker counting, a bounded 120 s
full-marker drain and a citability gate, the two pacing regimes fail
differently. UNPACED, the shared queue pins, the flooding child blocks hard,
the backlog stops growing and drains completely — 24-30 of 30 markers arrive
within the bounded drain, at p95 10.9-13.2 s (shared) and 8.7-9.4 s (split).
PACED, the queue never pins, so the child keeps flooding for the whole run:
delivery tracks ~0.8x the offered payload at 20% bidirectional loss (the
design's own 0.8 efficiency factor) and the deficit accumulates in the kcp
send queue; the stream-ordered marker sits behind it, the received-prefix
lags plateau at ~4-4.6 s, and once the paced stream thins to a sparse tail,
loss recovery degrades to kcp RTO backoff (~4 KB/s measured post-flood stall)
so only 5-15 of 30 markers arrive within the 120 s drain. The child itself
writes every marker within ~1.2 s (`marker_write_ms` in every count-mode
artifact), so the child-side fd starvation is real but is not the tail
driver. The prefix p95 already exceeds the 1.5 s target 2.4-4.7x, so the
verdict does not hinge on the missing tail; the citability gate fails the
runs independently, honestly. The deficit is proportional to the offer
(measured at amp 2.2, 2.6 and 3.4), so tightening the amp further does not
close the gap. Pacing still buys the full input-latency win (row 1), kills
the queue pinning (maxq ~30 vs 1000), drops wire amplification to
~2.0-2.8x, and roughly halves confirmation latency on the comparable prefix
(11.9 s -> 5.7 s shared, 8.7 s -> 3.8 s split). Closing the remainder needs
kcp-level loss-recovery work (hole recovery under sparse tails), explicitly
out of tsshd#6's non-goals — filed as **tsshd#13**; the 1.5 s gate stays
enforced, never relaxed.

**Amp tightening evidence (2.2 -> 2.6):** at 2.2 the recipe's 175 KB/s wire
budget was itself oversubscribed — the downlink's retransmit overhead at 20%
loss pushed actual wire usage to ~2.5x payload, the shared queue re-pinned
(maxq 1000, ~5.7 MB tail-dropped) and degraded goodput collapsed to ~20 KB/s.
At 2.6 the offered wire stays inside the budget including retransmissions.

**Bounded uplink source in the degraded bulk cases (both pacing configurations):**
the p1 and p1offq degraded bulk variants bound the client's uplink source to
8 KB/s (~3x the canonical-PTY line-discipline drain the harness itself
measured: uplink delivered 0.3-0.8 KB/s in every committed bulk run). The
historical 800 KB/s firehose exists to stress the unpaced collapse; against
a paced downlink it fabricates an uplink-side collapse (the client's kcp
send queue absorbs ~2 MB and retransmits it into the shared queue for the
whole run — 5.7-10.8 MB offered uplink for ~70 KB of payload, in both paced
and committed unpaced runs). No real agent session pushes input faster than
its PTY consumes; the row-5 pinned-formula gate tests the downlink recipe
and requires the downlink to actually receive its budgeted share. The
before/after comparison is controlled (review finding): the `p1offq_*`
reference suites run the same degraded bulk cases with the SAME 8 KB/s
uplink and pacing OFF, while the 800 KB/s firehose P1-off re-measures stay
committed separately as the alternate workload
(`results/p1off-bulk_bottleneck_*.json`). The row-5-p1 gate keeps binding
to the committed/original-stimulus references per the wi's own wording; the
p1offq artifacts carry the controlled attribution reported in the campaign
summary.

**Regenerating the campaign summary:** the `tsshd6_campaign` section of
`results/budget-baselines.json` is GENERATED from the result artifacts by
`gen_campaign_summary.py` (invoked at the end of `run_campaign.sh`, or
`./run_campaign.sh gen` alone) — summary numbers are never hand-typed
(review finding: hand-typed prose had drifted from the artifacts).

## Measured results (committed artifacts, 2026-09-16, loopback host)

| case | Ctrl-C → SIGINT | child react | marker travel | perceived total | verdict |
|---|---|---|---|---|---|
| baseline | 50.4 ms | 5.1 ms | 61.4 ms | 116.9 ms | machinery ≈ RTT |
| loss20 (30 samples) | p50 50.6 / p95 51.4 / max 161.4 ms | — | echo p50 101 / **p95 212.6 ms** | — | matches the earlier independent `tc netem` measurement (~211 ms echo p95) |
| loss20_flood | 51.1 ms | 1.2 ms | 112.4 ms | 164.8 ms | flood alone: no effect |
| slow_client | 50.6 ms | 241.8 ms | 1388.3 ms | 1680.8 ms | client backpressure engages end-to-end, control unaffected |
| bottleneck_upclean | 50.7 ms | 2470.4 ms | 709.6 ms | 3230.7 ms | input fine; confirmation 3.2 s |
| bottleneck_split | 50.9 ms | 757.8 ms | 1761.2 ms | 2570 ms | input fine; marker 1.7 s … **>40 s** across runs |
| bottleneck_shared (r1) | **1642.1 ms** | 675.0 ms | 193.9 ms | 2511.1 ms | input itself queue-delayed |
| bottleneck_shared (r2) | **1240.1 ms** | 5.0 ms | 3621.1 ms | 4866.1 ms | (two more runs: 1234 / 685 ms — see variance note) |
| paste_shared_reading | **1739.4 ms** | 2899.7 ms | 166.2 ms | 4805.3 ms | agent model: Ctrl-C behind 64 KB paste ≈ 1.7–3.0 s |
| paste_block | **never** (≥150 s) | — | — | — | expected pathology (asserted) |
| paste_baseline | **never** (≥150 s) | — | — | — | expected pathology (asserted) — on a *clean* link |

Run-to-run variance (same seeded case, wall-clock kcp dynamics differ):
shared-queue Ctrl-C 0.7–1.6 s over four runs; split-case marker 1.7 s to
>40 s; paste_shared_reading Ctrl-C 1.7–3.0 s over two runs. The *ordering*
of the cases is stable; only the bottleneck-queue cases move at all.

## Latency budget for the reported failing scenario

`bottleneck_shared` (2 Mbps shared bottleneck, 20% bidirectional loss,
agent flood), Ctrl-C typed with no pending paste:

| segment | contribution | evidence |
|---|---|---|
| client stdin pipe write | ~0.0–0.2 ms | `pipe_write_ms` in every case |
| client smux stream accept | immediate | 512 KB stream window, 1-byte payload |
| client kcp send | immediate | uplink has no outstanding data (no paste) |
| **shared bottleneck queue** | **0.7–1.6 s measured; worst case ≈ 5.6 s** (1000 pkts × 1400 B / 250 KB/s) | `qlen@inject` 473–709 pkts; ctrl 1240/1642 ms vs 51 ms in split |
| kcp loss recovery | ~+110 ms per lost attempt (20% loss) | loss20: 50 → 161 ms steps |
| server kcp → smux → forwardInput → PTY → ISIG | ~0 ms | child react after SIGINT is about *output*, not input |
| **confirmation (marker) behind in-flight output backlog** | **0.2–3.6 s measured; >40 s observed when downlink goodput collapses** | marker travel, split/upclean/shared rows |
| PTY input buffer | ∞ (only with pending paste + non-reading remote) | paste_baseline: never, on a clean link |

## Hypothesis elimination

| hypothesis | verdict | evidence |
|---|---|---|
| tssh client input path / stdio queue blocks control input | **eliminated** | pipe write ≤0.2 ms in all 11 cases; `slow_client` pushes full output backpressure through io.Pipe → smux window → kcp → PTY (child throttled 7.1 MB → 1.34 MB) yet Ctrl-C still 50.6 ms |
| smux/KCP machinery delays control input under flood | **eliminated** (without a bottleneck) | loss20_flood 51.1 ms, split 50.9 ms, upclean 50.7 ms — all ≈ RTT while the downlink is saturated |
| server output queue / backpressure blocks the input path | **eliminated** | separate `forwardInput` goroutine + independent stream window; slow_client proves the backpressure chain engages without touching input |
| 20% loss alone makes Ctrl-C feel dead | **quantified, not the cause** | p50 50.6 ms, p95 51–160 ms, echo p95 ~212 ms — matches the user's earlier tc-netem echo measurement, acceptable interactively |
| shared bottleneck queue head-of-line blocks the input packet itself | **confirmed** | shared 1240–1642 ms vs split 50.9 ms with identical loss and rates; `qlen@inject` shows the input enqueueing behind 470–710 flood packets |
| confirmation is buried behind the output backlog (input *did* arrive) | **confirmed** | perceived totals 2.5–8.6 s in bottleneck cases; split marker 1.7 s ↔ >40 s; user's "Ctrl-C 确认测试未成功完成" reproduces as this |
| PTY input buffer swallows Ctrl-C behind a paste | **confirmed** | paste_baseline: Ctrl-C **never** delivered in 150 s on a clean 100 ms RTT link — the 4 KB ldisc buffer + strict byte ordering in `forwardInput` are sufficient, no network required |
| paste into a *reading* agent (real Claude Code / Pi model) still delays Ctrl-C | **confirmed, bounded** | paste_shared_reading: 1.7–3.0 s (64 KB paste transit through the saturated shared queue), then SIGINT delivered |

## Conclusion — owning layer

1. **Bare control-input delivery is not a software defect.** With any
   uplink headroom (per-direction queues, or unlimited uplink), Ctrl-C is
   delivered at RTT + ε (≈51 ms here) in every configuration tested,
   including 20% loss and a saturated, backpressured output path. The
   client input path (trzsz-ssh `tssh` + `SshUdpClient`), smux, kcp-go and
   the tsshd session input path all stay out of the way.
2. **The delay the user feels has three owners, none of them a bug in the
   input path:**
   * **Shared-bottleneck queue HOL (link/qdisc layer):** when both
     directions share one saturated FIFO queue, the 1-byte control
     packet waits behind ~0.7–1.6 s of output flood (worst case ≈ full
     queue ≈ 5.6 s). This is a *topology* property — `tc netem` on a
     single qdisc reproduces it; per-direction qdiscs remove it entirely.
     A network-config mitigation (priority for small uplink packets) is
     possible; the software could also reserve uplink headroom by pacing
     output — that would be a `tsshd`-repo change in the server output
     path (`tsshd/output.go` / `session.go`), explicitly *not* attempted
     here (diagnosis-only scope).
   * **Confirmation masking (output path, `tsshd` repo):** the marker —
     and any on-screen evidence the interrupt worked — is ordered behind
     the entire in-flight output backlog of the single smux stream.
     Under loss + bottleneck, kcp (no congestion control, `nodelay
     1,10,2,1`, FEC 1+1) overshoots the pipe, the queue tail-drops
     heavily and downlink goodput collapses, stretching drain times to
     seconds or tens of seconds. The input arrives; the *screen* says
     otherwise. Any future fix (output pacing, backlog shedding with a
     visible notice, control-input ack echo) belongs in the `tsshd`
     repo's output/session layer; trzsz-ssh needs no change.
   * **PTY input-buffer HOL (kernel terminal semantics):** a paste
     ordered ahead of Ctrl-C blocks the interrupt until the remote
     program consumes stdin; if it never reads (flood without an input
     thread), Ctrl-C is dead *forever*, even on a clean link. This is
     inherent to PTYs (local xterm behaves the same); the practical
     mitigation is agents reading stdin — the realistic agent model
     (`floodread`) bounds the damage to the paste's transit time
     (1.7–3.0 s for 64 KB here).
3. **Repo attribution for the earlier tc-netem experiments:** the
   "Ctrl-C confirmation never completed at 2 Mbps + 20% loss + flood"
   observation is reproduced by `bottleneck_shared` / `bottleneck_split`
   and is fully explained by (1)+(2): control input delivered in ~0.7–1.6 s
   (shared) or ~51 ms (split), with the *confirmation* lost in the output
   backlog for tens of seconds. No evidence of a `kcp-go`, `smux`,
   `trzsz-ssh` or `tsshd` input-path defect was found at pins
   `tsshd@b9fa50ed` / `trzsz-ssh@d5284bf`.

### Follow-up candidates (out of scope here)

These candidates are now evaluated, ranked and filed as phased, independently
verifiable work items — see
[docs/weak-network-agent-design.md](../../docs/weak-network-agent-design.md)
(tsshd#2): output pacing (rank 1) → input-accepted bus ack (2) → opt-in
client-requested backlog disposal (3) → qdisc/DSCP boundaries (4) →
goodput attribution (5).

* server output pacing / uplink-headroom reservation (tsshd)
* a bus-stream "input ack" echo so the client can show that Ctrl-C was
  delivered while output is still draining (tsshd, one-way traffic on the
  already-separate bus stream)
* split vs shared netem asymmetry: downlink goodput collapsed ~6× harder
  when the *uplink* was also rate-capped (split vs upclean) — worth a
  dedicated investigation if weak-network throughput matters
* priority queuing for small uplink packets (network config)

## Artifacts

`results/*.json` — one JSON per committed run (full timestamps, relay
queue statistics, derived deltas). Filenames `-r2` are repeat runs of the
same case used for the variance figures above.
