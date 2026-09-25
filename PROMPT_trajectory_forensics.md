# Task: why does the same agent solve the same instance three times out of five?

You are joining a research project at `~/Documents_Folder/College/DAP/DFC` (a git repo; a
folder of the same name is connected to this session). Read `HANDOFF_2026-09-16.md` first,
then this file. Do not read `DFC_STATUS_AND_BUILD_PLAN.md` §3–§5; they are stale.

## What the project is, in three sentences

We restrict a coding agent (Claude Sonnet 5, bash-only, via the Claude Agent SDK) to a
small set of auditable shell primitives and measure what it costs on SWE-bench. Arm 0 is
the unrestricted control; Arms 1 and 2 are restricted. On SWE-bench Pro we found that
**Arm 0's outcome on a given instance is not stable**: the same instance, same image, same
prompt, same turn cap, run five times, resolves on some runs and not others.

## Your task

Two SWE-bench Pro instances were each solved by Arm 0 in 3 of 5 independent runs. For
each, read all five trajectories and determine **where the successful and failed runs
diverge, and what the divergence is**. The output is a causal account per instance, not
a summary: at which turn, on what decision, and whether that decision was recoverable.

### The instances and their runs

Instance A — `instance_qutebrowser__qutebrowser-35168ade46184d7e5b91dfa04ca42fe2abd82717-v363c8a7e5ccdf6968fc7ab84a2053ac78036691d`

| run-id | outcome | turns | patch bytes | files touched |
|---|---|---|---|---|
| `dfc-pro-arm0-s20260923` | resolved | 44 | 4893 | 2 |
| `dfc-pro-arm0-diag8-20260924` | resolved | 51 | 4492 | 3 |
| `dfc-pro-arm0-rep1-diag8` | applied-F2P-unfixed | 38 | 4725 | 2 |
| `dfc-pro-arm0-rep2-diag8` | applied-F2P-unfixed | 40 | 4107 | 2 |
| `dfc-pro-arm0-rep3-diag8` | resolved | 47 | 5748 | 3 |

Instance B — `instance_internetarchive__openlibrary-f0341c0ba81c790241b782f5103ce5c9a6edf8e3-ve8fc82d8aae8463b752a211156c5b7b59f349237`

| run-id | outcome | turns | patch bytes | files touched |
|---|---|---|---|---|
| `dfc-pro-arm0-s20260923` | resolved | 41 | 4491 | 5 |
| `dfc-pro-arm0-diag8-20260924` | applied-F2P-unfixed | 41 | 5475 | 5 |
| `dfc-pro-arm0-rep1-diag8` | applied-F2P-unfixed | 46 | 4513 | 5 |
| `dfc-pro-arm0-rep2-diag8` | resolved | 42 | 4593 | 5 |
| `dfc-pro-arm0-rep3-diag8` | resolved | 47 | 5103 | 5 |

Note the patch sizes and file counts are similar across pass and fail in both. The
divergence is not "gave up early"; it is in what the patch does.

(Optional third, already partly understood: `…233cb1cc48635130…` — the failing Arm 0
runs implement the feature as CSS in `shared.py` and never touch `configinit.py`, where
the hidden tests live. Use it as a calibration case if useful.)

### Where the evidence is

For a run-id `R` and instance `I`:

- `runs/R/trajectories.json` — one record per instance. Fields that matter:
  `model_patch` (the submitted diff), `dirty_paths` (files the agent changed),
  `reasoning` (a list of per-turn entries: the model's thinking/prose and the command it
  led to — this is the primary evidence), `final_text` (the agent's closing summary),
  `turns`, `tool_stats`.
- `runs/R/flow_log.jsonl` — one line per command, all instances; filter on
  `instance_id == I`. Fields: `command` (as the agent wrote it), `exit_code`, `outcome`
  (`observed` for Arm 0), `actions` (verb + targets).
- `logs/run_evaluation/R/pro/I/` — the grader's output: `dfc-sonnet5_output.json`
  (flat list of `{name, status}` for every test that ran), `dfc-sonnet5_stdout.log` /
  `_stderr.log` (pytest output), `dfc-sonnet5_patch.diff` (what was graded),
  `workspace/dfc_test_apply.log` (must end `exit=0`).
- `runs/R/sample.json` → `instances[]` → the row for `I`: `problem_statement` (what the
  agent was told), `patch` (the gold fix — the agent never saw it), `test_patch` (the
  hidden tests — the agent never saw them), `fail_to_pass`, `pass_to_pass`.
- `python -m dfc.run inspect --run-id R --instance I --reasoning` prints a trajectory
  with reasoning beside each command. `python -m dfc.run compare --run-ids R1,R2,...`
  prints one row per instance across run-ids. Activate the venv first:
  `source dfc-env-311/bin/activate`.

The grader's `output.json` tells you **which hidden tests failed** in each failing run;
`sample.json`'s `test_patch` tells you **what those tests check**. Start there, then work
backwards through the failing trajectory's reasoning to the decision that made the
patch miss it, then find the corresponding point in a passing trajectory.

### Method

For each instance:

1. Read the issue text and the gold patch. Write down, in one paragraph, what a correct
   fix must do and which files it must touch. Note anything the hidden tests require
   that the issue text does not state (a specific function name, exception type,
   return shape) — this category is real and has bitten seven Lite instances.
2. Diff the five submitted patches against each other and against the gold patch. Which
   hunks are common to all five? Which are only in the passing runs? Which are only in
   the failing runs?
3. For each failing run, identify the failing hidden tests from `output.json` and, from
   `test_patch`, what they assert. Map each assertion to the missing or wrong hunk.
4. Walk the failing run's `reasoning` from the start and find the **first turn** at
   which its path diverges from a passing run's: a file it did not open, a hypothesis it
   formed, a test it did not run, a test it ran and misread, a design choice. Quote the
   reasoning entry. Do the same for the passing run at the same point.
5. Classify the divergence: exploration (did not find the relevant code), diagnosis
   (found it, wrong theory of the bug), design (right theory, chose an implementation the
   hidden tests do not accept), verification (had the wrong fix and its own testing did
   not catch it — check whether it ran the relevant test file at all and whether it
   filtered the failing test out), or contract (the hidden test requires something
   unstated). More than one may apply; say which is primary.
6. State whether the failing run **could** have recovered: was the information it needed
   available in the repo, and did any of its own commands surface it?

### Pitfalls, from earlier work on this project

- A flag or feature present in a failing trajectory is not the cause of the failure
  unless it is absent from the passing ones (D15 in `DECISIONS.md`). Compare, do not
  narrate one trajectory.
- The agent's `final_text` often says "all tests pass". Check which tests it actually
  ran (`flow_log.jsonl`); several past trajectories ran a filtered subset that excluded
  the target test.
- Run-to-run variance is the phenomenon under study. Do not conclude "the model is
  unreliable" and stop; the question is *what* varies and *when*.
- `patch_successfully_applied` is true for all ten runs and the hidden tests were
  installed (`exit=0`) in all ten; the harness is not the cause here. If you find
  evidence otherwise, that is a finding — record it, do not work around it.
- `git` on the mounted folder leaves stale `.git/index.lock` files; if you use git, run
  it from a real terminal or delete the lock first.

### Deliverable

Append one section per instance to a new file `FORENSICS_2026-09-25.md` in the repo
root, each with: the correct-fix paragraph; the patch-hunk comparison as a small table;
the failing tests and what they check; the divergence turn, quoted, for each failing run
with the passing run's counterpart; the classification; the recoverability judgement.
Close with a short cross-instance section: is the divergence type the same for both,
and what does that suggest about which per-instance property (issue ambiguity, number
of files, test discoverability) predicts instability. Do not edit `DECISIONS.md`; if
you believe you found a harness defect, describe it in the forensics file and say so in
chat.

Keep the file under about 1,500 words. Quote reasoning sparingly and exactly.
