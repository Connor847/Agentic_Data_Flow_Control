# DFC — Design decisions log

Decisions that resolve ambiguities left open by `DFC_STATUS_AND_BUILD_PLAN.md`.
Each entry states the decision, the alternatives rejected, and the consequence that
has to be reported in the paper. Append, do not rewrite.

---

## D1 — Two rule tables, not one (2026-08-10)

The 56 CSV rules use the taxonomy `READ / WRITE / METADATA / INGRESS / EGRESS /
TRANSFORM / ESCAPE / NON-FLOW`. §2 of the plan uses a different model: six verbs plus
two label lattices. They do not line up — §2 splits `curl` into `fetch` vs `write-ext`,
and the CSV has no confidentiality or integrity columns at all.

**Decision.** Two tables with separate jobs.

- `dfc/policy.py` — **enforcement table**, keyed on §2 verbs and labels. Small.
  Drives the hook. This is what the restriction *is*.
- `dfc/canon.py` — **canonicalization table**, the 56 CSV rules ported intact with
  `csv_row` provenance. Drives silent rewriting and the §7 coverage-mining analysis.

Neither table distorts to fit the other. A rule in `canon` proposes a rewrite; `policy`
decides whether the rewritten form is admissible.

*Rejected:* re-expressing all 56 rows in the §2 model (loses the existing asset, and
the TRANSFORM bucket has no honest §2 verb); porting verbatim with extra columns (the
hook would then reason over a mixed vocabulary).

---

## D2 — The hook silently rewrites (2026-08-10)

**Decision.** `PreToolUse` returns `hookSpecificOutput.updatedInput` with the
canonicalized command. `cat f` is executed as `grep "" f`. The agent is not told.

Mechanism confirmed against current Claude Code hook docs: `PreToolUse` is one of the
events that can rewrite content rather than only allow or block it — `updatedInput`
sits directly under `hookSpecificOutput` and replaces the tool's arguments before it
runs.

**Consequence that must be stated in the paper.** This changes what the treatment arms
measure. Under a deny-only gate, Arm 1 measures *the cost of restricting the agent to
the primitive set*. Under silent rewrite, any command with an admissible rewrite is not
a restriction at all — it is a translation. The resolve-rate delta therefore prices
**canonicalization**, and the residual denials (commands with no admissible rewrite) are
the only true restriction. Report the two populations separately:

| Outcome | Meaning |
|---|---|
| `passthrough` | already canonical |
| `rewritten` | non-canonical but foldable — translated silently |
| `denied` | no admissible rewrite exists — this is the restriction |

"Escape attempts per trajectory" (§7) counts `denied` only. `rewritten` is a separate
and independently interesting number: it is the size of the translation layer.

---

## D3 — Restricted `awk` is admitted as a seventh primitive (2026-08-10)

Ten of the 56 rules rewrite *into* commands §2 denies: `tail`, `cut`, `tr`, `uniq`,
`wc -w` and stream `sed s///` all fold onto `awk`; `od`/`xxd`/`strings` fold onto
`python3 -c`. Under D2 the hook would be silently executing a denied command on the
agent's behalf. That is incoherent, so one of the two had to give.

**Decision.** Admit `awk` in a **restricted form** that satisfies the §2 admission
criterion. An `awk` invocation is admissible iff *all* hold:

1. no `system(` in the program text
2. no `print >`, `print >>`, `printf >`, `printf >>` (output redirection from inside
   the program)
3. no `| getline` and no `cmd |` piping inside the program
4. no `close(`
5. no `-f progfile` — the program text must be **literal in argv**, never loaded from
   a file
6. no `ENVIRON` access
7. input files, if any, are literal words

With those excluded, targets are statically extractable from the command line and the
verb is exactly one (`transform`), so it passes the same test `grep` and `ls` pass.

`python3 -c` is **not** readmitted. The `od`/`xxd`/`strings` rules therefore have no
admissible rewrite and are denied; binary reads are out of scope.

**Consequence.** §2 of the plan says awk is out. That claim is now narrower: *unrestricted*
awk is out, restricted awk is in. The paper must carry the seven-clause definition above,
because "we allow awk" without it would be a false statement about the threat model.
The residual imprecision is that awk's read set is the whole of each input stream, so a
`transform` edge over file `f` must be labelled as a full read of `f`, not a partial one.

---

## D4 — Lossy rewrites are applied but flagged (2026-08-10)

Rules marked `Partial` or `Limitation` are not output-equivalent: `cp` → `tee` drops
mode and timestamps, `du` → `ls` stops aggregating, `file` reads content bytes.

**Decision.** Apply them. Stamp every flow-log record with the rule's `status` and a
derived boolean `fidelity_risk`. Add `rewrite-infidelity` to the E2 failure taxonomy.

**Consequence.** Failure analysis can separate *restriction cost* from *our rewrite
being wrong*, but only after the fact, and only if the flag is actually used when
triaging. If a restricted arm loses, the first thing to check is whether the losing
trajectories are enriched for `fidelity_risk=true` records.

*Rejected:* Verified-only rewriting (drops roughly a third of the table and inflates the
denial rate with denials that are artifacts of our own conservatism); applying all rules
with no distinction (makes any resolve-rate loss uninterpretable).

---

## D5 — Arm 0 runs the hook in observe-only mode (2026-08-10)

§7 defines Arm 0 as "unrestricted Bash, no hook". But the §7 coverage claim — *"our N
primitives subsume X% of observed bash invocations"* — needs a denominator drawn from
unrestricted runs.

**Decision.** Arm 0 runs the same hook binary with `mode=observe`: parse, classify, log,
always return allow, never rewrite, never deny. The arms then differ in exactly one
config value rather than in whether a hook exists at all.

**Consequence.** Hook latency and any classifier crash now touch the baseline too. The
hook must fail **open** in observe mode (log the parse failure, allow the command) and
fail **closed** in enforce mode (deny on parse failure). A parser exception must never
be able to change the Arm 0 resolve rate.

---

## D6 — Primitives plus a named infrastructure allowlist (2026-08-10)

**Decision.** Beyond the primitive set, a fixed infrastructure allowlist is permitted in
every arm, logged but not counted as a policed flow edge: `cd`, `pwd`, `pytest` /
`python -m pytest`, `git status`, `git diff`, `git checkout`, `git stash`, `git apply`,
`true`, `false`, `exit`.

**Consequence.** The allowlist must be **byte-identical across arms** or it confounds
the comparison. It is defined once in `dfc/policy.py` as `INFRA_ALLOWLIST` and no arm
config may override it. `git` is allowed only in the enumerated read-only and
working-tree subcommands; `git push`, `git clone`, `git fetch`, `git pull` remain
network edges and are governed as such.

---

## D7 — `dfc/` package under git; notebooks frozen (2026-08-10)

**Decision.** New work lives in a `dfc/` Python package with pytest tests. `git init` at
the repo root. `swe_bench_dfc.ipynb` and `swe_bench_pro_dfc.ipynb` are frozen as
reference artifacts and are no longer on the execution path.

**Note on Phase 0's probe-injection item.** The plan calls for deleting probe injection
from notebook cell `e26b3e3d` and dropping `DEFAULT_INJECT`. Because the notebooks are
now off the execution path, the probe is inert by construction — the new pipeline has no
injection code and cannot fabricate the dependent variable. The notebook is left
byte-identical so the prior run remains reproducible for the record. **Do not re-run the
notebooks to generate new results.**

---

## D8 — tree-sitter-bash replaces bashlex (2026-08-10)

`bashlex` cannot parse heredocs. It raises `ParsingError: here-document at line 0
delimited by end-of-file` on `tee f <<'EOF' … EOF`, which §8 Phase 2 mandates for
*every* write ("use a quoted heredoc for all writes … `echo`/`printf` into `>` is the
likely cause of syntax-error failures and it is avoidable").

**Decision.** tree-sitter-bash. It parses heredocs natively, exposes `heredoc_body` as
data so the write payload can be captured, and reports `root_node.has_error` so
malformed input fails closed under enforcement and open under observation (D5).

---

## D9 — the bash executor is an MCP tool, not the built-in Bash tool (2026-08-11)

Claude Code's built-in `Bash` executes on the **host**. Nothing in the Agent SDK routes
it into a container. Arm 0 is unrestricted bash, so a host executor means an
unrestricted agent on the researcher's own machine.

**Decision.** `disallowed_tools=["Bash"]` removes host bash from the model's context
entirely. An in-process SDK MCP server exposes a single `bash(command)` tool that runs
`docker exec -w /testbed <cid>`. The failure mode is closed by construction: there is
no host shell to fall back to, so a bug in our wrapper cannot escalate into host
execution.

**Sub-decision: the gate moved from the hook into the tool.** §6.1 put the classifier
in a `PreToolUse` hook because the built-in Bash tool was the executor and a hook was
the only interposition point. With our own MCP tool as the only path to a shell,
gating inside it is equally non-bypassable, keeps classification and execution in one
place so they cannot disagree, and does not depend on `updatedInput` semantics holding
for MCP tools. The `PreToolUse` hook is still registered, but only to deny the built-in
file tools (§6.1 layer 3).

**Consequence.** The model sees a tool named `mcp__dfc__bash` rather than `Bash`, with
our tool description rather than Claude Code's. Commands are still free-form bash
strings, so the "we police real shells" premise survives, but this is a deviation from
a stock scaffold and belongs in the paper's threats-to-validity section. It also means
Arm 3 (Option B, named-tool MCP) is now a *smaller* step than planned rather than a
different architecture.

**Consequence 2.** `docker exec` is stateless. Working directory is tracked and
re-injected on every call; exported variables and background jobs do not survive
between calls, unlike the built-in Bash tool's persistent shell.

---

## D10 — run parameters for the first Phase 2 run (2026-08-11)

Dataset SWE-bench Lite, stratified across repos, seed `20260811`, n=8. Arm 0 only.
Turn cap of 40; §9 decision 4 (turns vs tokens for budget parity) stays open and is
answered only for this run.

**Consequence.** A turn cap structurally disadvantages the restricted arms later:
whole-file rewrites cost more turns than targeted edits, so Arm 1 may lose to turn
exhaustion rather than to the restriction — the confound §7 explicitly warns about.
Before the paired arms run, either switch to a token cap or run at least one arm with a
raised turn budget to see whether the gap closes.
