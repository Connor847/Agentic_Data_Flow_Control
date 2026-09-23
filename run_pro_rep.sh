#!/usr/bin/env bash
# Within-instance replication (24 Sep). Same 8 instances as run_pro_diag8.sh, each
# arm solved 3 MORE times under distinct run-ids. With the pilot and diag8 already
# in hand that gives >=4 observations per instance per arm for Arms 0/1 and 4 for
# Arm 2 - enough to estimate a per-instance resolve probability under each arm and
# to see how much of the pilot's discordance was sampling.
#
# Diagnostic set (selection: explicit). Never pooled with seeded runs; the 8 were
# chosen where the arms disagreed, so they over-represent unstable instances.
#
# Interleaved arm-within-repeat so a stop at any point leaves complete triples.
# Resume by re-running; completed trajectories are skipped, graded instances too.

set -u
CAP=150; WORKERS=2
IDS="instance_qutebrowser__qutebrowser-ef5ba1a0360b39f9eff027fbdc57f363597c3c3b-v363c8a7e5ccdf6968fc7ab84a2053ac78036691d,instance_qutebrowser__qutebrowser-96b997802e942937e81d2b8a32d08f00d3f4bc4e-v5fc38aaf22415ab0b70567368332beee7955b367,instance_qutebrowser__qutebrowser-233cb1cc48635130e5602549856a6fa4ab4c087f-v35616345bb8052ea303186706cec663146f0f184,instance_internetarchive__openlibrary-f0341c0ba81c790241b782f5103ce5c9a6edf8e3-ve8fc82d8aae8463b752a211156c5b7b59f349237,instance_qutebrowser__qutebrowser-7f9713b20f623fc40473b7167a082d6db0f0fd40-va0fd88aac89cde702ec1ba84877234da33adce8a,instance_qutebrowser__qutebrowser-35168ade46184d7e5b91dfa04ca42fe2abd82717-v363c8a7e5ccdf6968fc7ab84a2053ac78036691d,instance_qutebrowser__qutebrowser-ed19d7f58b2664bb310c7cb6b52c5b9a06ea60b2-v059c6fdc75567943479b23ebca7c07b5e9a7f34c,instance_internetarchive__openlibrary-3f580a5f244c299d936d73d9e327ba873b6401d9-v0f5aece3601a5b4419f7ccec1dbda2071be28ee4"
log() { printf '\n=== %s  [%s] ===\n' "$1" "$(date +%H:%M:%S)"; }

for rep in 1 2 3; do
  for arm in arm0 arm1 arm2; do
    rid="dfc-pro-${arm}-rep${rep}-diag8"
    log "SOLVE ${rid}"
    python -m dfc.run solve --bench pro --arm "$arm" --max-turns "$CAP" --run-id "$rid" --instances "$IDS"
  done
done

for rep in 1 2 3; do
  for arm in arm0 arm1 arm2; do
    rid="dfc-pro-${arm}-rep${rep}-diag8"
    log "EVALUATE ${rid}"
    python -m dfc.run evaluate --run-id "$rid" --max-workers $WORKERS
    python -m dfc.run report   --run-id "$rid"
  done
done
# one envcheck is enough: the environment does not depend on the arm or the repeat
python -m dfc.run envcheck --run-id dfc-pro-arm0-rep1-diag8 --max-workers $WORKERS
for rep in 1 2 3; do for arm in arm0 arm1 arm2; do
  python -m dfc.run report --run-id "dfc-pro-${arm}-rep${rep}-diag8" >/dev/null
done; done
log "DONE"
python -m dfc.run compare --run-ids dfc-pro-arm0-rep1-diag8,dfc-pro-arm1-rep1-diag8,dfc-pro-arm2-rep1-diag8
echo "Per-instance resolve counts across all observations (pilot + diag8 + rep1-3) come from the analysis script; see the morning message."
