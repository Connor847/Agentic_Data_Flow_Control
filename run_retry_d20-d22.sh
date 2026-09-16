#!/usr/bin/env bash
# Re-run after D20-D22 (2026-09-16). Two passes with different rules.
#
# Pass 1 - RETRY (10 trajectories). The originals were not valid measurements: our
# extraction produced a patch the grader could not use (D20: requests-863 build/
# sweep; D21: flask-4992 and sphinx-8595 fixture collisions). Records are replaced
# in place in the scale-run run-ids, so the n=90 paired dataset is repaired.
#
# Pass 2 - DIAGNOSTIC (15 trajectories). Genuine failures re-solved into SEPARATE
# run-ids to see whether they reproduce. These must never replace the originals or
# be pooled with seeded runs: re-running only failures and keeping the better result
# is selection on the outcome. `report` flags these run-ids as explicit.
#
# Resume is safe for both. solve costs quota; evaluate costs Docker time only.

set -u
CAP=150
WORKERS=4
log() { printf '\n=== %s  [%s] ===\n' "$1" "$(date +%H:%M:%S)"; }

# ---------------------------------------------------------------------------
# Pass 1 - retry in place
# ---------------------------------------------------------------------------
# macOS ships bash 3.2 (no associative arrays), so a function instead of a map.
retry_ids() {
  case "$1" in
    dfc-arm0-s20260812) echo "psf__requests-863,pallets__flask-4992,sphinx-doc__sphinx-8595" ;;
    dfc-arm0-s20260813) echo "psf__requests-863,pallets__flask-4992" ;;
    dfc-arm1-s20260812) echo "psf__requests-863,pallets__flask-4992,sphinx-doc__sphinx-8595" ;;
    dfc-arm1-s20260813) echo "psf__requests-863,pallets__flask-4992" ;;
    *) echo "" ;;
  esac
}
# sphinx-8595 was drawn on seed 20260812 only.

for rid in dfc-arm0-s20260812 dfc-arm0-s20260813 dfc-arm1-s20260812 dfc-arm1-s20260813; do
  arm=${rid#dfc-}; arm=${arm%%-*}
  seed=${rid##*-s}
  ids=$(retry_ids "$rid")
  log "RETRY ${rid}: ${ids}"
  python -m dfc.run solve --n 30 --arm "$arm" --seed "$seed" --max-turns "$CAP" \
    --run-id "$rid" --retry "$ids"
done

# ---------------------------------------------------------------------------
# Pass 2 - diagnostic, separate run-ids
# ---------------------------------------------------------------------------
# Arm 0 on the seven instances that failed in BOTH arms with no resolve anywhere:
# a second failure says deterministic (look for an environment or hidden-test
# cause); a resolve says stochastic (a real model failure).
DIAG_ARM0="astropy__astropy-7746,matplotlib__matplotlib-18869,pydata__xarray-4248,pytest-dev__pytest-7220,sympy__sympy-16503,sympy__sympy-24102,mwaskom__seaborn-3407"
# Arm 1 on the four rewrite-infidelity trajectories (does the hook's rewrite
# reproduce the loss?) and the four Arm-1-only losses (does the restriction
# reproduce it, or was it noise?).
DIAG_ARM1="astropy__astropy-14182,pylint-dev__pylint-6506,sphinx-doc__sphinx-10451,pylint-dev__pylint-7114,django__django-11001,django__django-14730,pytest-dev__pytest-5413,pydata__xarray-3364"

log "DIAG arm0"
python -m dfc.run solve --arm arm0 --max-turns "$CAP" --run-id dfc-arm0-diag-20260916 --instances "$DIAG_ARM0"
log "DIAG arm1"
python -m dfc.run solve --arm arm1 --max-turns "$CAP" --run-id dfc-arm1-diag-20260916 --instances "$DIAG_ARM1"

# ---------------------------------------------------------------------------
# Evaluate + report everything touched
# ---------------------------------------------------------------------------
for rid in dfc-arm0-s20260812 dfc-arm0-s20260813 dfc-arm1-s20260812 dfc-arm1-s20260813 \
           dfc-arm0-diag-20260916 dfc-arm1-diag-20260916; do
  log "EVALUATE ${rid}"
  python -m dfc.run evaluate --run-id "$rid" --max-workers "$WORKERS"
  python -m dfc.run report   --run-id "$rid"
  python -m dfc.run audit    --run-id "$rid" --high-only
done

log "DONE"
echo "Check:"
echo "  - retried rows: no harness-error, preexisting_dirty/reserved_collisions populated where expected"
echo "  - psf__requests-863 now has a real result in all four run-ids"
echo "  - pallets__flask-4992: expect resolves (all visible tests passed before)"
echo "  - diag run-ids carry 'selection: explicit' in report; do NOT pool them"
