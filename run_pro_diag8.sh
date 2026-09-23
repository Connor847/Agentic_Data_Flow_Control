#!/usr/bin/env bash
# Three-arm diagnostic on 8 Pro instances (D31 follow-up).
#
# The eight are chosen, not sampled: the seven instances Arm 0 solved and Arm 1 lost
# in the pilot, plus one both arms solved as a control. This is the set where the arms
# are known to differ, so it is where Arm 2 either recovers ground or does not, and
# where reading the three trajectories side by side says why. It is a diagnostic
# run-id (`selection: explicit`) and is never pooled with seeded runs.
#
# All three arms run on the current fingerprint, so Arm 0 and Arm 1 here are also a
# second observation of those instances (the pilot ran on 76f60a616dbb).

set -u
CAP=150; WORKERS=2; TAG=diag8-20260924
IDS="instance_qutebrowser__qutebrowser-ef5ba1a0360b39f9eff027fbdc57f363597c3c3b-v363c8a7e5ccdf6968fc7ab84a2053ac78036691d,instance_qutebrowser__qutebrowser-96b997802e942937e81d2b8a32d08f00d3f4bc4e-v5fc38aaf22415ab0b70567368332beee7955b367,instance_qutebrowser__qutebrowser-233cb1cc48635130e5602549856a6fa4ab4c087f-v35616345bb8052ea303186706cec663146f0f184,instance_internetarchive__openlibrary-f0341c0ba81c790241b782f5103ce5c9a6edf8e3-ve8fc82d8aae8463b752a211156c5b7b59f349237,instance_qutebrowser__qutebrowser-7f9713b20f623fc40473b7167a082d6db0f0fd40-va0fd88aac89cde702ec1ba84877234da33adce8a,instance_qutebrowser__qutebrowser-35168ade46184d7e5b91dfa04ca42fe2abd82717-v363c8a7e5ccdf6968fc7ab84a2053ac78036691d,instance_qutebrowser__qutebrowser-ed19d7f58b2664bb310c7cb6b52c5b9a06ea60b2-v059c6fdc75567943479b23ebca7c07b5e9a7f34c,instance_internetarchive__openlibrary-3f580a5f244c299d936d73d9e327ba873b6401d9-v0f5aece3601a5b4419f7ccec1dbda2071be28ee4"
log() { printf '\n=== %s  [%s] ===\n' "$1" "$(date +%H:%M:%S)"; }

for arm in arm0 arm1 arm2; do
  log "SOLVE dfc-pro-${arm}-${TAG}"
  python -m dfc.run solve --bench pro --arm "$arm" --max-turns "$CAP" \
    --run-id "dfc-pro-${arm}-${TAG}" --instances "$IDS"
done
for arm in arm0 arm1 arm2; do
  rid="dfc-pro-${arm}-${TAG}"
  log "EVALUATE ${rid}"
  python -m dfc.run evaluate --run-id "$rid" --max-workers $WORKERS
  python -m dfc.run envcheck --run-id "$rid" --max-workers $WORKERS
  python -m dfc.run report   --run-id "$rid"
  python -m dfc.run audit    --run-id "$rid" --high-only
done
log "COMPARE"
python -m dfc.run compare --run-ids dfc-pro-arm0-${TAG},dfc-pro-arm1-${TAG},dfc-pro-arm2-${TAG}
log "DONE"
echo "Then, per instance and arm:"
echo "  python -m dfc.run inspect --run-id dfc-pro-arm1-${TAG} --instance <id> --reasoning"
