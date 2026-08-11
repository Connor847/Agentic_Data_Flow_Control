# Phase 2 runbook — 8 instances, Arm 0, Sonnet 5

Run these on your Mac. Everything below assumes repo root
`/Users/connorfeldman/Documents_Folder/College/DAP/DFC`.

**Configuration for this run** (chosen 2026-08-11):

| | |
|---|---|
| Executor | MCP `bash` tool → `docker exec` into the instance container; built-in `Bash` denied |
| Dataset | SWE-bench Lite, stratified across repos, seed `20260811` |
| Arm | Arm 0 only — unrestricted, observe-only hook |
| Budget | Turn cap, 40 |
| Model | `claude-sonnet-5` via Claude Code subscription |

**Acceptance criterion (§8 Phase 2).** Arm 0 resolves ≥1 instance end to end *and* the
flow log is non-empty. Both. A resolve with an empty flow log means the instrumentation
is not wired up and is exactly the failure the last run had.

---

## 1. Environment

`dfc-env` is on Python 3.14, which the setup guide itself flags as a `swebench`
compatibility risk. Rebuild on 3.11 before running anything.

```bash
cd "/Users/connorfeldman/Documents_Folder/College/DAP/DFC"

# 3.11, per §5 housekeeping
python3.11 -m venv dfc-env-311
source dfc-env-311/bin/activate

pip install -r requirements.txt
pip install swebench
```

If `python3.11` is missing: `brew install python@3.11`.

## 2. Authentication — subscription, not API key

The Agent SDK reads a subscription OAuth token from the environment. Generate one
once; it is valid for a year.

```bash
export CLAUDE_CODE_OAUTH_TOKEN=$(claude setup-token | tr -d '[:space:]')

# verify: one line, ~108-110 characters
echo -n "$CLAUDE_CODE_OAUTH_TOKEN" | wc -c
echo "$CLAUDE_CODE_OAUTH_TOKEN" | wc -l
```

**Do not paste the token by hand.** A token copied out of a wrapped terminal carries an
embedded newline, and the CLI then refuses it with `Invalid Authorization header value
... it contains a line break`. The model gets no tools, answers once with the error
text, and stops — every instance comes back with one turn, zero commands and zero cost,
which reads exactly like a harness bug. `preflight` now checks the token's shape, and
`solve` aborts after two consecutive zero-command trajectories rather than working
through the whole sample.

Set **either** `CLAUDE_CODE_OAUTH_TOKEN` **or** `ANTHROPIC_API_KEY`, never both. With
only the OAuth token set, the run draws on your Pro/Max subscription rather than
usage-billed API credit. Preflight warns if both are present.

Put it in a `.env` you do not commit — `.gitignore` already excludes `dfc-env*`, but
the token is not covered, so keep it out of tracked files.

## 3. Docker

Docker Desktop must be running. The SWE-bench images are x86-only and will run under
emulation on Apple Silicon — correct but slow. Expect the first instance of each repo
to spend several minutes pulling.

```bash
docker version
docker pull --platform linux/amd64 swebench/sweb.eval.x86_64.astropy_1776_astropy-12907:latest
```

Give Docker Desktop at least 8 GB of memory (Settings → Resources). Each container is
capped at 4 GB and 2 CPUs.

## 4. Preflight

```bash
python -m dfc.run preflight
```

Checks Python version, Docker daemon, the SDK, auth token *shape*, the classifier,
`datasets`, and `swebench`. Everything it checks is free; everything after this costs
quota or time. Do not proceed on a FAIL.

Then prove the session actually works, with one live call and no Docker:

```bash
python -m dfc.run doctor
```

This starts a real SDK session with a trivial MCP tool and checks the model calls it.
It separates the two things that both present as "zero commands": authentication, and
tool wiring. If `doctor` passes but a real run still shows zero commands, the problem is
the container layer.

## 5. Solve

```bash
python -m dfc.run solve --n 8 --arm arm0 --max-turns 40
```

Prints the sample, the gold-patch size distribution, and a line per instance. Writes to
`runs/dfc-arm0-<timestamp>/`:

| File | Contents |
|---|---|
| `sample.json` | instance ids, seed, gold-patch sizes — the reproducibility record |
| `trajectories.json` | per-instance turns, stop reason, cost, tool stats, patch |
| `predictions.json` | the harness input |
| `flow_log.jsonl` | one record per shell command |

Watch the per-instance line. `0 cmds` on every instance means the MCP tool is not
wired up. A large `denied` count under Arm 0 would mean the arm config is wrong —
Arm 0 is observe-only and must never deny.

Useful flags:

- `--n 1` for a single-instance smoke test first. **Do this before the 8.**
- `--hints` includes `hints_text`. Off by default: hints are not available in a
  realistic setting and inflate the baseline.
- `--command-timeout 600` if test suites are timing out.

## 6. Evaluate

Separate command on purpose. Solving costs subscription quota; evaluation costs only
local Docker time, so a mistake here never forces you to pay for the trajectories
again.

```bash
python -m dfc.run evaluate --run-id dfc-arm0-<timestamp> --max-workers 4
```

This shells out to the official `swebench.harness.run_evaluation`. Unchanged from the
pipeline that already worked — the harness integration was the genuinely hard
infrastructure and it is not being rewritten.

## 7. Report

```bash
python -m dfc.run report --run-id dfc-arm0-<timestamp>
```

Writes `dfc_report.csv` with the failure taxonomy and the flow-log join. Columns that
matter for the acceptance check:

- `dfc_observed` — must be non-empty in every row. It was empty in **every** row of the
  previous run; there was no detector behind the dependent variable.
- `failure_class` — one of the E2 taxonomy labels.
- `coverage` — fraction of invocations the primitive set subsumes, weighted by
  invocation rather than by command identity.

---

## What to look at first

1. **Is the flow log non-empty?** If not, nothing else matters.
2. **Did anything resolve?** Published Pro baselines put Sonnet 4.5 at 43.7%; Lite is
   easier. If Arm 0 is 0/8, the harness is broken — stop and debug rather than scaling.
   That is the Phase 4 gate applied early.
3. **What did the agent actually reach for?** `python -m dfc.run report` prints the
   verb histogram and, once you run Arm 1, `escape_targets` — the commands the model
   tried that the primitive set does not admit. That list is the empirical input to a
   v2 primitive set driven by what agents actually use rather than by enumeration.
4. **Coverage.** With `SWE-bench_Pro-os/traj/` containing only resolve booleans and no
   trajectories, this Arm 0 run is your only source for the §7 coverage denominator.

## Known limits of this run

- **No envelope.** `--network-none` exists but is off. Phase 2b turns it on and proves
  the containment property. Until then `pip install` still works inside the container,
  and egress is possible in principle.
- **`docker exec` is stateless.** Working directory is tracked and re-injected per
  call, but exported shell variables and background jobs do not survive between calls.
  If the agent seems confused about state, that is the first thing to check.
- **n=8, one arm, one seed.** Nothing here is a measurement. It is a check that the
  machinery runs end to end.
