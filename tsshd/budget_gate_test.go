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
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// ctrlGateContract is the machine-readable inventory of the budget gates in
// docs/weak-network-agent-design.md section 7. Keeping inactive feature cases
// in this inventory makes their eventual activation a reviewed code change;
// an environment variable cannot accidentally turn a not-yet-implemented
// feature into a passing gate.
type ctrlGateContract struct {
	Name           string   `json:"name"`
	Budget         string   `json:"budget"`
	Cases          []string `json:"cases"`
	Runs           int      `json:"runs"`
	SamplesPerRun  int      `json:"samples_per_run,omitempty"`
	Active         bool     `json:"active"`
	InactiveUntil  string   `json:"inactive_until,omitempty"`
	Statistic      string   `json:"statistic"`
	Threshold      string   `json:"threshold"`
	Baseline       string   `json:"baseline"`
	BaselineSource string   `json:"baseline_source"`
}

var ctrlGateContracts = []ctrlGateContract{
	{Name: "input-delivery", Budget: "row-1", Cases: []string{"input_baseline", "loss20", "input_loss20_flood", "input_slow_client", "input_bottleneck_upclean", "input_bottleneck_split", "input_bottleneck_shared", "input_paste_shared_reading"}, Runs: 3, SamplesPerRun: 30, Active: true, Statistic: "nearest-rank p95(T_sigint-T_inject)", Threshold: "each run <= baseline +10%; the two clean-uplink cases anchor [committed] single samples (50.38/50.58 ms), the six loss/bottleneck cases anchor [committed-v2] measured p95 envelopes (the legacy figures were single fixed-phase draws that never sampled the pinned-full tail; see the per-case envelope provenance in results/budget-baselines.json); paste pathologies retain their no-SIGINT expectation. Patience-censoring protocol for the deep paste tail: a stuck attempt is recorded as censored (CtrlMs = the patience bound, a lower bound) and KEPT in the p95 input at that bound; one censor per run keeps the rank-29-of-30 p95 on a completed sample, while the second makes the p95 itself censored and aborts the run red in bounded time (its artifact is always written); the censor count is reported per run and is the sharpest regression signal (it must vanish with output pacing)", Baseline: "51.4ms loss20 committed p95 [committed-legacy]; 50.38/50.58ms committed singles; [committed-v2] envelopes: loss20 161.7, loss20_flood 162.7, upclean 2767.7, split 2935.4, shared 5320.7, paste 6904.5 ms", BaselineSource: "[committed] results/baseline.json, results/slow_client.json; [committed-v2]/[committed-v2-tail] the budget-input-*.json suites + budget-input-paste-shared-reading-tail.json (see results/budget-baselines.json for the full re-anchor evidence trail)"},
	{Name: "visible-confirmation-drain", Budget: "row-2", Cases: []string{"input_bottleneck_shared", "input_bottleneck_split"}, Runs: 3, SamplesPerRun: 30, Active: true, Statistic: "nearest-rank p95(T_client_marker-T_inject), per sample", Threshold: "report [committed-v2] baseline (design §7 ⚠ recompute); the <=1.5s P1-on gate remains owned by tsshd#6", Baseline: "per-run confirmation p95 from the 30-sample sequential suites", BaselineSource: "[committed-v2] budget-input-bottleneck-shared.json, budget-input-bottleneck-split.json; legacy one-shot anchors (shared 2.5-4.9s perceived, split 1.76s marker) stay recorded in results/budget-baselines.json"},
	{Name: "visible-confirmation-ack-split", Budget: "row-3a", Cases: []string{"bottleneck_split"}, Runs: 3, SamplesPerRun: 30, Active: false, InactiveUntil: "input-accepted ack (tsshd#7) and pacing (tsshd#6)", Statistic: "nearest-rank p95(T_client_ack-T_inject)", Threshold: "<=1.5x RTT", Baseline: "provisional 150ms at 100ms RTT", BaselineSource: "[design-target], re-anchor from measured 20%-loss recovery"},
	{Name: "visible-confirmation-ack-shared", Budget: "row-3b", Cases: []string{"bottleneck_shared"}, Runs: 3, SamplesPerRun: 30, Active: false, InactiveUntil: "input-accepted ack (tsshd#7)", Statistic: "ackDelay < markerDelay among delivered acks", Threshold: ">=90% paired wins and >=20/30 ack coverage per run", Baseline: "none; no absolute latency bound", BaselineSource: "[design-contract]"},
	{Name: "post-shed-settle", Budget: "row-4", Cases: []string{"bottleneck_shared"}, Runs: 3, Active: false, InactiveUntil: "client-requested output shed (tsshd#8)", Statistic: "T_client_marker-T_client_discard_notice", Threshold: "<=1s, 3/3; missing notice or deleted marker fails", Baseline: "none", BaselineSource: "[design-contract]"},
	{Name: "bulk-goodput", Budget: "row-5", Cases: []string{"bulk_clean", "bulk_clean_cap200", "bulk_bottleneck_shared", "bulk_bottleneck_split"}, Runs: 3, Active: true, Statistic: "client-received payload bytes timestamped in [5s,10s]/5s, each direction (child disables PTY echo so uplink and downlink stay separable)", Threshold: "report [committed-v2] baselines while P1 is off, both directions; P1-on thresholds owned by tsshd#6", Baseline: "generated by this harness", BaselineSource: "[committed-v2] budget result artifacts"},
	{Name: "wire-amplification", Budget: "row-6", Cases: []string{"baseline", "bulk_clean", "bulk_clean_cap200", "bulk_bottleneck_shared", "bulk_bottleneck_split"}, Runs: 3, Active: true, Statistic: "aggregate relay egress/client payload; offered/client payload alongside; shared sections once", Threshold: "one-way clean reference (baseline case) <=2.8x [committed 2.679x]; bidirectional bulk family reports [committed-v2] baselines (legacy one-way figure not comparable, PTY echo disabled); P1-on <=4.0x owned by tsshd#6", Baseline: "one-way clean ~2.68x [committed]; bulk family ratios generated by this harness", BaselineSource: "[committed] results/baseline.json; [committed-v2] budget-bulk-*.json"},
	{Name: "reconnect-roam", Budget: "row-7a", Cases: []string{"reconnect_roam"}, Runs: 3, Active: true, Statistic: "success, reattach duration, exact byte continuity under unchanged pending-output policy", Threshold: "success 3/3; reattach <= [committed-v2] 976.330ms +10% (enforced per run in ctrlApplyCurrentGates); zero-discard run must deliver every byte the child wrote (exact equality, enforced per run)", Baseline: "generated by this harness", BaselineSource: "[committed-v2] budget result artifacts"},
	{Name: "reconnect-attach", Budget: "row-7b", Cases: []string{"reconnect_attach"}, Runs: 3, Active: true, Statistic: "success, attach duration, continuity gap under unchanged pending-output policy (client total vs child total, accounted by the discard callback)", Threshold: "success 3/3; attach <= [committed-v2] 921.235ms +10% AND continuity gap <= [committed-v2] 30720B +10%, both enforced per run in ctrlApplyCurrentGates. Measured at the current pins (3/3 deterministic): the detach-window records (~30 x 1024 B) reach neither client and the discard accounting does not report them — an un-accounted loss, the production defect tracked by tsshd#11; exact equality is the roam case's criterion and this case's target once tsshd#11 lands", Baseline: "generated by this harness", BaselineSource: "[committed-v2] budget result artifacts"},
	{Name: "raw-pty-byte-integrity", Budget: "row-8", Cases: []string{"integrity_clean", "integrity_flood"}, Runs: 3, Active: true, Statistic: "byte diff(server PTY reference, client receive)", Threshold: "diff=0 in every no-shed run", Baseline: "zero diff", BaselineSource: "[invariant]"},
	{Name: "raw-pty-byte-integrity-shed", Budget: "row-8-shed", Cases: []string{"integrity_shed"}, Runs: 3, Active: false, InactiveUntil: "client-requested output shed with reported byte range (tsshd#8)", Statistic: "client receive == PTY reference minus reported half-open range", Threshold: "exact equality; line and byte counts consistent", Baseline: "none", BaselineSource: "[design-contract]"},
}

func ctrlGateByCase(name string) (ctrlGateContract, bool) {
	for _, gate := range ctrlGateContracts {
		for _, c := range gate.Cases {
			if c == name {
				return gate, true
			}
		}
	}
	return ctrlGateContract{}, false
}

// TestControlBudgetGateCatalog is env-gated so normal go test remains fast.
// It emits the exact contract selected by a benchmark case. Measurement cases
// use TSSHD_CTRL_BENCH in TestControlLatencyUnderFlood; this catalog command is
// intentionally separate from feature activation and cannot enable a feature.
func TestControlBudgetGateCatalog(t *testing.T) {
	name := os.Getenv("TSSHD_CTRL_GATE")
	if name == "" {
		t.Skip("set TSSHD_CTRL_GATE=<case|all> to emit budget-gate contracts")
	}
	var selected []ctrlGateContract
	if name == "all" {
		selected = append(selected, ctrlGateContracts...)
	} else if gate, ok := ctrlGateByCase(name); ok {
		selected = append(selected, gate)
	} else {
		var names []string
		for _, gate := range ctrlGateContracts {
			names = append(names, gate.Cases...)
		}
		sort.Strings(names)
		t.Fatalf("unknown gate case %q; known cases: %s", name, strings.Join(names, ", "))
	}
	b, err := json.MarshalIndent(selected, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if out := os.Getenv("TSSHD_CTRL_BENCH_OUT"); out != "" {
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(out, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, gate := range selected {
		state := "ACTIVE"
		if !gate.Active {
			state = "INACTIVE until " + gate.InactiveUntil
		}
		t.Logf("%s %s: %s (%s)", gate.Budget, gate.Name, state, gate.Statistic)
	}
}

func TestControlGateContracts(t *testing.T) {
	seen := make(map[string]string)
	for _, gate := range ctrlGateContracts {
		if gate.Runs != 3 {
			t.Errorf("%s runs=%d, want 3", gate.Name, gate.Runs)
		}
		if gate.BaselineSource == "" || gate.Statistic == "" || gate.Threshold == "" {
			t.Errorf("%s has incomplete provenance/contract", gate.Name)
		}
		if !gate.Active && gate.InactiveUntil == "" {
			t.Errorf("%s is inactive without an activation dependency", gate.Name)
		}
		for _, c := range gate.Cases {
			key := gate.Budget + "/" + c
			if prev, ok := seen[key]; ok {
				t.Errorf("duplicate case %s in %s and %s", key, prev, gate.Name)
			}
			seen[key] = gate.Name
		}
	}
}

// TestControlGateCaseWiring pins the harness contract to the case inventory:
// every ACTIVE gate names cases that exist and meet its sample contract; the
// paste case's per-sample patience covers the measured RTO tail (2 of 3
// seeded runs truncated at 90 s before it was raised); the degraded bulk
// patience exceeds the child's bounded write grace so runs always complete.
func TestControlGateCaseWiring(t *testing.T) {
	for _, gate := range ctrlGateContracts {
		for _, name := range gate.Cases {
			mk, ok := ctrlCases[name]
			if !ok {
				if gate.Active {
					t.Errorf("active gate %s references missing case %s", gate.Name, name)
				}
				continue
			}
			cfg := mk()
			if gate.Active && gate.SamplesPerRun > 0 && cfg.CtrlCount < gate.SamplesPerRun {
				t.Errorf("%s case %s: %d samples, want >= %d", gate.Name, name, cfg.CtrlCount, gate.SamplesPerRun)
			}
		}
	}
	if c := ctrlCases["input_paste_shared_reading"](); c.SampleTimeout < 2*time.Minute {
		t.Errorf("paste per-sample patience %v, want >= 2m (the measured tail starts past 90s; stuck attempts are censored, see the row-1 contract)", c.SampleTimeout)
	}
	for _, name := range []string{"bulk_bottleneck_shared", "bulk_bottleneck_split"} {
		if c := ctrlCases[name](); c.WaitTimeout < 150*time.Second {
			t.Errorf("%s wait patience %v, want >= 150s (child write grace is 132s)", name, c.WaitTimeout)
		}
	}
}

func TestControlFeatureGateSemantics(t *testing.T) {
	ms := func(v float64) *float64 { return &v }
	wins, coverage := ctrlGateAckPaired([]ctrlSample{
		{AckMs: ms(100), MarkerMs: ms(200)}, // win
		{AckMs: ms(200), MarkerMs: ms(200)}, // tie is not a win
		{AckMs: nil, MarkerMs: ms(300)},     // missing ack is not delivered
		{AckMs: ms(300)},                    // marker missing is a win (noted)
	})
	if wins != 2 || coverage != 3 {
		t.Fatalf("ack paired semantics: wins=%d coverage=%d; want 2/3", wins, coverage)
	}
	res := &ctrlResult{TClientMarker: 1000}
	if err := ctrlGateShedSettled(res); err == nil {
		t.Fatal("missing notice must fail settle")
	}
	res.DiscardNoticeNS = 2000 // marker before notice is <=0 and passes
	if err := ctrlGateShedSettled(res); err != nil || res.SettledMs == nil || *res.SettledMs >= 0 {
		t.Fatalf("marker-before-notice must pass: settled=%v err=%v", res.SettledMs, err)
	}
	res.TClientMarker = 0
	if err := ctrlGateShedSettled(res); err == nil {
		t.Fatal("missing marker must fail settle")
	}
}

func TestControlSharedRelayAccounting(t *testing.T) {
	cfg := ctrlNetemConfig{Shared: true, LimitUp: 10, LimitDown: 10, Seed: 7}
	r, err := newCtrlRelay(cfg, &netUDPAddrForAccountingTest)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		r.up.close()
		_ = r.conn.Close()
	}()
	dst := r.addr()
	r.up.enqueue(ctrlPkt{data: []byte("up"), dest: dst, direction: ctrlUp})
	r.down.enqueue(ctrlPkt{data: []byte("down"), dest: dst, direction: ctrlDown})
	s := r.stats()
	if s.Up.Enqueued != 1 || s.Down.Enqueued != 1 {
		t.Fatalf("direction attribution mirrored: up=%d down=%d", s.Up.Enqueued, s.Down.Enqueued)
	}
	if s.Aggregate.Enqueued != 2 || s.Aggregate.EnqueuedBytes != 6 {
		t.Fatalf("shared aggregate counted incorrectly: %+v", s.Aggregate)
	}
}

var netUDPAddrForAccountingTest = net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9}

func TestControlBudgetMetricsCountsSharedQueueOnce(t *testing.T) {
	res := &ctrlResult{ClientBytesTotal: 100, Relay: ctrlRelayStats{
		Shared: true,
		Up:     ctrlQStats{EgressedBytes: 150}, Down: ctrlQStats{EgressedBytes: 150},
		Aggregate: ctrlQStats{EgressedBytes: 150, EnqueuedBytes: 200, DroppedBytes: 50},
	}}
	m := ctrlBudgetMetricsForResult(res)
	if got := fmt.Sprintf("%.2f/%.2f", *m.EgressAmplification, *m.OfferedAmplification); got != "1.50/2.50" {
		t.Fatalf("amplification double counted shared sections: got %s", got)
	}
}
