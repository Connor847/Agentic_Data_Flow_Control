#!/usr/bin/env bash
# DFC scale run - 2 arms x 3 seeds x n=30 = 180 trajectories
#
# Ordering matters: this interleaves arms WITHIN each seed rather than running all of
# arm0 then all of arm1. If you run out of quota, hit a rate limit, or just stop early,
# you are left with complete PAIRED seeds, which are analysable. Running arm-major
# instead would leave you with 90 arm0 trajectories and 0 arm1 - a paired design with
# nothing to pair against, and no result at any spend level short of the full 180.
#
# solve costs subscription quota; evaluate costs only local Docker time. They are kept
# in separate passes so a mistake in one never forces you to pay for the other again.
#
# Resume is safe: re-issue this identical script and completed trajectories are skipped
# (D14), while empty-patch-after-success records are retried (D19).

set -u  # NOT -e: one instance failing must not abandon the rest of the run.

SEEDS=(20260811 20260812 20260813)
ARMS=(arm0 arm1)
N=30
CAP=150            # gate ran clean at 150 with max observed 65 turns
WORKERS=4

log() { printf '\n=== %s  [%s] ===\n' "$1" "$(date +%H:%M:%S)"; }

# ---------------------------------------------------------------------------
# Pass 1 - solve. Costs quota. Seed-major so partial runs stay paired.
# ---------------------------------------------------------------------------
for seed in "${SEEDS[@]}"; do
  for arm in "${ARMS[@]}"; do
    rid="dfc-${arm}-s${seed}"
    log "SOLVE ${rid}"
    python -m dfc.run solve \
      --n "$N" --arm "$arm" --seed "$seed" --max-turns "$CAP" --run-id "$rid"
  done
done

# ---------------------------------------------------------------------------
# Pass 2 - evaluate, report, audit. Free but slow (x86 images under emulation).
# ---------------------------------------------------------------------------
for seed in "${SEEDS[@]}"; do
  for arm in "${ARMS[@]}"; do
    rid="dfc-${arm}-s${seed}"
    log "EVALUATE ${rid}"
    python -m dfc.run evaluate --run-id "$rid" --max-workers "$WORKERS"
    python -m dfc.run envcheck --run-id "$rid" --max-workers "$WORKERS"
    python -m dfc.run report   --run-id "$rid"
    python -m dfc.run audit    --run-id "$rid" --high-only
  done
done

log "DONE"
echo "Check before analysing:"
echo "  - one classifier fingerprint (76f60a616dbb after D24; c0b87151304a for the 21 Aug data) across all six reports"
echo "  - no instance cap-bound at ${CAP} in any run"
echo "  - zero high-severity audit findings (D16)"
echo "  - no 'empty-patch-after-success' rows in any dfc_report.csv (D19)"
echo "  - no PatchTooLarge harness-errors; preexisting_dirty empty or disjoint from the write set (D20)"
