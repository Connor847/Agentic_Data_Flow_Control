#!/usr/bin/env bash
# D28: re-grade the Pro pilot. The 60 trajectories are valid; the first grading pass
# never installed the hidden tests. Docker time only, no quota.
set -u
WORKERS=2
log() { printf '\n=== %s  [%s] ===\n' "$1" "$(date +%H:%M:%S)"; }
for rid in dfc-pro-smoke dfc-pro-arm0-s20260923 dfc-pro-arm1-s20260923; do
  log "REGRADE ${rid}"
  python -m dfc.run evaluate --run-id "$rid" --max-workers $WORKERS --regrade all
  python -m dfc.run envcheck --run-id "$rid" --max-workers $WORKERS --force
  python -m dfc.run report   --run-id "$rid"
  python -m dfc.run audit    --run-id "$rid" --high-only
done
log "DONE"
echo "Check:"
echo "  - every workspace/ has dfc_test_apply.log ending in exit=0 (hidden tests installed)"
echo "  - no harness-error rows; if any say 'hidden tests not installed', read that instance's dfc_test_apply.log"
echo "  - Arm 0 resolve rate in a plausible range (Pro public leaderboard: Sonnet 4.5 ~43%); near zero = still broken (Phase 4 gate)"
