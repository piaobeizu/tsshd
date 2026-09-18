#!/bin/bash
# tsshd#6 P1-on/off budget-matrix campaign driver.
# Usage: run_campaign.sh <p1on|p1off|gen>
#   p1on  - 16 P1-on suites (pacing at the recipe)         -> results/p1-*.json
#   p1off - 16 P1-off suites (shipped default) + the 2
#           matched-stimulus reference suites (p1offq_*)   -> results/p1off-*.json, results/p1offq-*.json
#   gen   - regenerate the tsshd6_campaign section of results/budget-baselines.json
#           from the result artifacts (numbers are never hand-typed; review finding)
set -u
cd "$(dirname "$0")"
MODE="${1:-p1on}"
OUT="results"  # after cd "$(dirname "$0")" this is benchmarks/control-latency/results
LOG="/tmp/campaign-$MODE.log"

regen_summary() {
  if command -v python3 >/dev/null 2>&1; then
    if python3 gen_campaign_summary.py; then
      echo "=== campaign summary regenerated from artifacts ===" >> "$LOG"
    else
      # Missing artifacts for the not-yet-run mode is expected mid-campaign;
      # the generator itself says what is missing. Never fail the campaign on it.
      echo "!!! campaign summary NOT regenerated (see generator output above)" >> "$LOG"
    fi
  else
    echo "!!! python3 not found: campaign summary NOT regenerated" >> "$LOG"
  fi
}

if [ "$MODE" = "gen" ]; then
  exec python3 gen_campaign_summary.py
fi

: > "$LOG"

if [ "$MODE" = "p1on" ]; then
  CASES="p1_baseline p1_input_baseline p1_loss20 p1_input_loss20_flood p1_input_slow_client p1_input_bottleneck_upclean p1_input_bottleneck_split p1_input_bottleneck_shared p1_input_paste_shared_reading p1_bulk_clean_cap200 p1_bulk_bottleneck_shared p1_bulk_bottleneck_split p1_reconnect_roam p1_reconnect_attach p1_integrity_clean p1_integrity_flood"
  PREFIX="p1-"
else
  CASES="baseline input_baseline loss20 input_loss20_flood input_slow_client input_bottleneck_upclean input_bottleneck_split input_bottleneck_shared input_paste_shared_reading bulk_clean bulk_clean_cap200 bulk_bottleneck_shared bulk_bottleneck_split reconnect_roam reconnect_attach integrity_clean integrity_flood p1offq_bulk_bottleneck_shared p1offq_bulk_bottleneck_split"
  PREFIX="p1off-"
fi

for c in $CASES; do
  case "$c" in
    *paste*) TMO=150m ;;
    p1_input_*|input_*) TMO=90m ;;
    p1_bulk_*|bulk_*|p1offq_*) TMO=40m ;;
    p1_reconnect_*|reconnect_*) TMO=15m ;;
    p1_integrity_*|integrity_*) TMO=20m ;;
    *) TMO=30m ;;
  esac
  echo "=== [$(date +%H:%M:%S)] $c (timeout $TMO) ===" >> "$LOG"
  P="$PREFIX$c.json"
  case "$c" in
    p1offq_*) P="p1offq-${c#p1offq_}.json" ;;
  esac
  TSSHD_CTRL_BENCH="$c" \
  TSSHD_CTRL_BENCH_OUT="$PWD/$OUT/$P" \
  go test ./tsshd -run '^TestControlLatencyUnderFlood$' -count=1 -timeout="$TMO" >> "$LOG" 2>&1
  rc=$?
  echo "=== [$(date +%H:%M:%S)] $c rc=$rc ===" >> "$LOG"
  if [ $rc -ne 0 ]; then
    echo "!!! $c FAILED (rc=$rc) — continuing with the campaign" >> "$LOG"
  fi
done
echo "=== [$(date +%H:%M:%S)] CAMPAIGN $MODE DONE ===" >> "$LOG"

regen_summary

# The tsshd#6 before/after campaign:
#   ./run_campaign.sh p1on   # 16 P1-on suites (pacing at the recipe) -> results/p1-*.json
#   ./run_campaign.sh p1off  # 16 P1-off suites + 2 matched-stimulus refs -> results/p1off-*.json, results/p1offq-*.json
# Each suite = 3 seeded runs (TSSHD_CTRL_BENCH_RUNS default). Red suites still
# write their artifact (per the censoring protocol) and the campaign continues.
# Both campaigns regenerate results/budget-baselines.json's tsshd6_campaign
# section from the artifacts once both sides exist (gen_campaign_summary.py
# tolerates a missing side mid-campaign and regenerates on the next pass;
# ./run_campaign.sh gen regenerates alone).
