#!/usr/bin/env bash
# D28 follow-up: the first (broken) grading pass poisoned the Pro baseline - with no
# hidden tests installed, every P2P test read as failing with no patch. Drop those
# entries and re-baseline from the correct grader. Docker only.
set -u
for rid in dfc-pro-arm0-s20260923 dfc-pro-arm1-s20260923; do
  python -m dfc.run envcheck --run-id "$rid" --max-workers 2 --force --reset
  python -m dfc.run report   --run-id "$rid"
done
