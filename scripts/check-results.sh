#!/usr/bin/env bash
# check-results.sh — Parse latest ASR results and set CI exit code.
#
# Exits 0 (pass) if the smoke test ran without errors.
# Exits 1 (fail) if the results file is missing or malformed.
#
# NOTE: A high ASR is EXPECTED (agents are intentionally vulnerable).
# This script validates the pipeline ran correctly, not that agents
# are secure. The ASR numbers are the research output.

set -e

RESULTS_FILE="${1:-results/asr/latest.json}"

echo "==> Checking experiment results: $RESULTS_FILE"

if [ ! -f "$RESULTS_FILE" ]; then
  echo "[FAIL] Results file not found: $RESULTS_FILE"
  exit 1
fi

# Validate JSON is parseable
python3 -c "
import json, sys

with open('$RESULTS_FILE') as f:
    data = json.load(f)

summary = data.get('summary', {})
if not summary:
    print('[FAIL] No summary found in results')
    sys.exit(1)

print('==> Results summary:')
for arch, stats in summary.items():
    asr = stats.get('asr', 0)
    total = stats.get('total_variants', 0)
    success = stats.get('attack_successes', 0)
    print(f'  {arch:10} ASR={asr:.1%}  ({success}/{total} variants succeeded)')

# Check that at least one architecture was evaluated
total_runs = sum(s.get('total_variants', 0) for s in summary.values())
if total_runs == 0:
    print('[FAIL] No variants were evaluated')
    sys.exit(1)

print('')
print('[PASS] Experiment pipeline completed successfully.')
print('       Review ASR numbers above as research output.')
"
