# DFC — policed primitives for agent shell usage

Measuring what it costs to restrict a coding agent to a small set of auditable shell
commands, and how much of its behaviour becomes classifiable as a result.

Agentic systems run arbitrary shell commands, which makes information flow across an
organisation of agents effectively untrackable: you cannot tell from a trajectory what
data was read, where it came from, or where it went. The claim under test is that a
small set of **policed primitives** can subsume the overwhelming majority of real agent
shell usage, such that every action becomes an auditable data-flow edge — at an
acceptable cost to task performance.

Two numbers, equally important:

| | Metric | Question |
|---|---|---|
| **Cost** | Resolve-rate delta vs. an unrestricted baseline | How much capability is lost? |
| **Benefit** | Flow-classification coverage | How much of the trajectory becomes auditable? |

A result of the form *"resolve rate drops N points; coverage rises from X% to Y%"* is
the finding. Resolve rate alone is not.

## Where to start reading

| File | What it is |
|---|---|
| `DFC_STATUS_AND_BUILD_PLAN.md` | The research design: the flow model, the primitive set, the experimental arms |
| `DECISIONS.md` | Every design decision (D1–D17) with alternatives rejected and consequences. **Read this before changing anything** — several entries record bugs that silently corrupted a run |
| `PHASE2_RUNBOOK.md` | How to actually run it, with acceptance gates |
| `dfc/README.md` | Module-by-module map of the package |

## The arms

| Arm | Tools | Purpose |
|---|---|---|
| **0 — baseline** | Unrestricted shell. The classifier runs in observe-only mode: it parses, classifies and logs, but never blocks or rewrites | Control, and the source of the natural command distribution |
| **1 — primitives** | `ls`, `grep`, `curl`, `tee`/`>`, restricted `awk`, `head`/`tail` on a pipe, plus a fixed infrastructure allowlist | The restriction |
| **2 — scoped sed** | Arm 1 plus address-scoped `sed -i` (`s///`, `d`, `i`, `a`) | Prices the whole-file-rewrite tax |

Commands with an admissible canonical rewrite are **silently rewritten** — the agent
writes `cat f`, the container runs `grep "" f`, and it is not told. Commands with no
admissible rewrite are **denied**. Those two populations must be reported separately;
see D2.

## Setup

Requires Python 3.11 (`swebench` is not reliable on newer), Docker, and a Claude Code
subscription or Anthropic API key.

```bash
git clone <this-repo> && cd DFC
python3.11 -m venv dfc-env-311 && source dfc-env-311/bin/activate
pip install -r requirements.txt swebench

python -m dfc.run preflight   # deps, Docker, auth token shape, classifier
python -m dfc.run doctor      # one live SDK call, no Docker: proves auth + tool wiring
```

`preflight` and `doctor` exist because two different failure modes both present as
"zero commands executed", and one of them once burned a whole run. Do not skip them.

## Running an experiment

```bash
python -m dfc.run solve    --n 30 --arm arm0 --max-turns 100 --run-id my-arm0
python -m dfc.run evaluate --run-id my-arm0
python -m dfc.run report   --run-id my-arm0
python -m dfc.run audit    --run-id my-arm0     # did any rewrite change what was asked?
```

Use the **same `--seed`** across arms so the comparison is paired; McNemar's test
depends on it. `solve` resumes — re-issue the identical command with the same
`--run-id` and completed trajectories are skipped.

Other commands:

```bash
python -m dfc.run census                              # natural command distribution
python -m dfc.run inspect --run-id X --failures       # triage every failure
python -m dfc.run inspect --run-id X --instance Y --reasoning
python -m dfc.run transcript --instance Y             # recover reasoning from past runs
```

## Things that will bite you

Each of these cost real time and is recorded in `DECISIONS.md`.

- **A bad rewrite is worse than a denial.** `find -maxdepth 6 -iname X` was being
  rewritten to `ls -R /` — an unbounded listing of the whole filesystem in place of a
  bounded search. A denial is visible to the agent and to you; silent corruption is
  visible to neither. Run `dfc.run audit` after every run (D16).
- **The classifier version is fingerprinted.** Two runs on different fingerprints are
  not comparable on any flow-derived metric. `report` says so when it detects a mix (D14).
- **A binding turn cap invalidates the cost comparison.** The restricted arm needs more
  turns for the same work, so a cap that binds penalises it structurally. If any
  instance reaches the cap, raise it and re-run (D14).
- **Some SWE-bench Lite instances depend on a live third-party service.** Three
  `psf__requests` instances call `httpbin.org`; when it returns 503 the tests fail
  regardless of the patch, and the harness scores that as a model regression.
- **The agent can pass its own tests and still fail.** Several trajectories close with
  "all tests pass" after running a filtered subset that excludes the target test. Use
  `dfc.run inspect --failures`, which flags this.
- **`docker exec` is stateless.** Working directory is tracked and re-injected per call;
  exported variables and background jobs do not survive between commands.

## Tests

```bash
python -m pytest tests/ -q      # 247 tests, no Docker or API access required
```

The suite covers the adversarial cases the design depends on: `curl file://` vs `curl -o`
vs `curl -K`, `grep pat f > out` as simultaneously a read and a write, restricted-`awk`
escapes, `sed` escape hatches, heredoc writes, command substitution. Several tests exist
because a real run found the bug first; those are labelled.

## What is not published here

`runs/` and `logs/` are gitignored — they hold flow logs, trajectories and harness
output, including full model reasoning. Ask if you need them for comparison.
