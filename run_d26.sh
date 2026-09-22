#!/usr/bin/env bash
# D26 follow-up: re-solve the four sphinx trajectories whose patches carried the
# image's own setup.py/tox.ini edits (harness reverse-applied them), and re-grade the
# twelve requests trajectories whose August grades reflect httpbin.org being down.
set -u
CAP=150; WORKERS=4
log() { printf '\n=== %s  [%s] ===\n' "$1" "$(date +%H:%M:%S)"; }

log "RETRY sphinx (seed 20260811, both arms)"
python -m dfc.run solve --n 30 --arm arm0 --seed 20260811 --max-turns $CAP \
  --run-id dfc-arm0-s20260811 --retry sphinx-doc__sphinx-8435,sphinx-doc__sphinx-8627
python -m dfc.run solve --n 30 --arm arm1 --seed 20260811 --max-turns $CAP \
  --run-id dfc-arm1-s20260811 --retry sphinx-doc__sphinx-8435,sphinx-doc__sphinx-8627

regrade_ids() {
  case "$1" in
    dfc-arm0-s20260811|dfc-arm1-s20260811) echo "psf__requests-1963,psf__requests-2317" ;;
    dfc-arm0-s20260812|dfc-arm1-s20260812) echo "psf__requests-1963,psf__requests-2148" ;;
    dfc-arm0-s20260813|dfc-arm1-s20260813) echo "psf__requests-1963,psf__requests-2317" ;;
  esac
}
for rid in dfc-arm0-s20260811 dfc-arm1-s20260811 dfc-arm0-s20260812 dfc-arm1-s20260812 dfc-arm0-s20260813 dfc-arm1-s20260813; do
  log "EVALUATE ${rid}"
  python -m dfc.run evaluate --run-id "$rid" --max-workers $WORKERS      # picks up the retries
  python -m dfc.run evaluate --run-id "$rid" --max-workers $WORKERS --regrade "$(regrade_ids "$rid")"
  python -m dfc.run envcheck --run-id "$rid" --max-workers $WORKERS --force --instances "$(regrade_ids "$rid")"
  python -m dfc.run report   --run-id "$rid"
  python -m dfc.run audit    --run-id "$rid" --high-only
done
log "DONE"
echo "Check: sphinx-8435/8627 no longer applied-broke-P2P; requests rows resolved or environment-suspect, not applied-broke-P2P"
