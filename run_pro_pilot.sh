#!/usr/bin/env bash
# SWE-bench Pro pilot (D27): 2 arms x n=30, one seed, Python pytest repos only.
#
# Overnight-shaped: a smoke phase that fails fast on anything structural (image pull,
# entrypoint, repo path, grader invocation) BEFORE the 60 quota-costing trajectories,
# then seed-major solve so an interrupted run leaves complete pairs, then grading.
#
# Resume is safe: re-issue the identical script; completed trajectories are skipped
# and the Pro grader skips instances whose output exists.

set -u
SEED=20260923
N=30
CAP=150
WORKERS=2          # Pro images are large and run under emulation; 4 tends to swap
REPOS="internetarchive/openlibrary,qutebrowser/qutebrowser"
log() { printf '\n=== %s  [%s] ===\n' "$1" "$(date +%H:%M:%S)"; }

# ---------------------------------------------------------------------------
# Phase 0 - smoke: one instance, arm0, end to end, before anything expensive.
# ---------------------------------------------------------------------------
log "SMOKE: 1 instance, arm0, solve+evaluate+report"
python -m dfc.run solve --bench pro --repos "$REPOS" --n 1 --arm arm0 --seed "$SEED" \
  --max-turns "$CAP" --run-id dfc-pro-smoke || { echo "smoke solve failed"; exit 1; }
python -m dfc.run evaluate --run-id dfc-pro-smoke --max-workers 1 || { echo "smoke evaluate failed"; exit 1; }
python -m dfc.run report   --run-id dfc-pro-smoke || { echo "smoke report failed"; exit 1; }
if grep -q '"error": "container' runs/dfc-pro-smoke/trajectories.json; then
  echo "smoke: container failed to start - fix before the overnight run"; exit 1
fi
if [ ! -f logs/run_evaluation/dfc-pro-smoke/pro/*/dfc-sonnet5_output.json ]; then
  echo "smoke: grader produced no output.json - check logs/run_evaluation/dfc-pro-smoke/pro/*/"; exit 1
fi
log "SMOKE PASSED"

# ---------------------------------------------------------------------------
# Phase 1 - solve, both arms, same seed (paired). Costs quota.
# ---------------------------------------------------------------------------
for arm in arm0 arm1; do
  log "SOLVE dfc-pro-${arm}-s${SEED}"
  python -m dfc.run solve --bench pro --repos "$REPOS" --n "$N" --arm "$arm" --seed "$SEED" \
    --max-turns "$CAP" --run-id "dfc-pro-${arm}-s${SEED}"
done

# ---------------------------------------------------------------------------
# Phase 2 - grade, envcheck in the same pass (D26), report, audit.
# ---------------------------------------------------------------------------
for arm in arm0 arm1; do
  rid="dfc-pro-${arm}-s${SEED}"
  log "EVALUATE ${rid}"
  python -m dfc.run evaluate --run-id "$rid" --max-workers "$WORKERS"
  python -m dfc.run envcheck --run-id "$rid" --max-workers "$WORKERS"
  python -m dfc.run report   --run-id "$rid"
  python -m dfc.run audit    --run-id "$rid" --high-only
done

log "DONE"
echo "Check before reading numbers:"
echo "  - classifier 76f60a616dbb in both reports; no 'different classifier versions' warning"
echo "  - no instance cap-bound at ${CAP}; if any, raise and re-run before drawing conclusions (D14)"
echo "  - zero high-severity audit findings (D16/D24)"
echo "  - no harness-error rows; preexisting_dirty / reserved_collisions populated where expected (D20/D21)"
echo "  - patch_successfully_applied True everywhere; Pro's git apply has no fuzzy fallback"
echo "  - escape_targets: anything the pytest repos reach for that Lite never did"
