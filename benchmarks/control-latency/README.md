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

`TSSHD_CTRL_BENCH_OUT=<file>` writes the full measurement as JSON
(one artifact per run is committed under `results/`).

```sh
# one case per process:
TSSHD_CTRL_BENCH=bottleneck_shared \
TSSHD_CTRL_BENCH_OUT=/tmp/shared.json \
go test ./tsshd -run TestControlLatencyUnderFlood -v -count=1
```

Roughly equivalent `tc netem` on a veth pair (for validating the real
binaries; the in-process harness exists because cross-process timestamping
and qdisc manipulation need root and are not CI-friendly):

```sh
# shared bottleneck (one qdisc for both directions):
tc qdisc add dev veth-client root handle 1: netem delay 50ms loss 20% rate 250kbit limit 1000
# split (per direction): same command on both veth ends
```

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
