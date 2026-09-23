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

---

## D11 — `head` / `tail` admitted on stdin only (2026-08-11)

Replaying the first Arm 0 run showed pipeline `head`/`tail` accounting for 11 of 38
Arm 1 denials — 29% of the denial rate — with no data-flow consequence whatsoever.

`head -20 f.py` names a file: it opens it, so it is a READ of an extractable target and
folds onto `grep -m 20 "" f.py`. `cmd | head -20` names nothing. It reads the pipe,
never opens a file, and cannot reach any data the upstream command did not already read
and log. Its target set is empty, so "all targets statically extractable" holds
vacuously and the verb is unambiguously one.

**Decision.** Admit `head` and `tail` as `transform` primitives **iff there is no file
operand**. With a file operand they remain denied so the canon table folds them onto
`grep -m N ""`.

Unlike `awk` (D3), no clause list is needed: `head` and `tail` have no escape surface.
They cannot call out, redirect, or open anything. The single condition — no file operand
— is the whole restriction.

**Consequence.** The primitive set now has more members than §2 enumerates. The paper
must state the set as `ls, grep, curl, tee/>, restricted awk, head/tail on stdin`, plus
scoped `sed -i` in Arm 2, with the stdin-only condition explicit. Coverage rose from
44.1% to 65.0% on the same 177 real commands.

---

## D12 — Restricted arms are told the allowed command set (2026-08-11)

The first Arm 0 run edited files **exclusively** with `python - <<'EOF'` — 14 times in
70 commands — and used `tee` exactly **zero** times. This is §6.4's composition problem
appearing as the agent's main path, precisely as the plan predicted: "on SWE-bench this
is not an edge case: write-a-file-then-run-it is the literal task."

Under Arm 1 that strategy is denied. Without being told the allowed set, the agent must
rediscover the write idiom from denial messages, and the measurement then prices
*unfamiliarity* alongside *restriction*. §7 already warns that a restricted arm can lose
to turn exhaustion rather than to the restriction itself, and at a 40-turn cap that is a
live risk rather than a theoretical one.

**Decision.** Enforcing arms get a block appended to the system prompt naming every
allowed command and showing the `tee path <<'EOF'` write idiom. Arm 2 additionally gets
the scoped `sed -i` form. Arm 0's prompt is untouched.

**Consequence, and it is a real cost.** The arms now differ in **two** deliberate ways:
the gate and the prompt. §7's "the only difference vs. treatment is the restriction
itself" no longer holds literally, and the paper must say so. The defence is that an
undocumented toolset is not what a deployed system would look like, and that measuring
an agent's confusion is not measuring the restriction. The clean alternative — an
informed/naive sub-arm pair — remains available and would price the difference directly.

Related: the Arm 1 vs Arm 2 delta, which the plan calls the headline number, was
**identically zero** on the observed traffic, because the agent used `sed -i` once in
177 commands and `python` instead. Without D12's Arm 2 prompt block, that delta would
measure nothing.

---

## D13 — Three canon rules widened against observed traffic (2026-08-11)

Several denials turned out to be narrow regexes rather than policy: `find -iname` did
not match a rule requiring `-type f`; `cat a.py b.py` did not match a rule requiring
exactly one operand; `head -50` did not match a rule requiring `-n`.

**Decision.** Widen rows 1, 2 and 10 to cover the forms their CSV descriptions plainly
intend. Each widening carries an inline `WIDENED 2026-08-11` note so the diff against
the original sheet stays visible.

**Consequence.** Two of the three become lossy and are now flagged under D4:
`cat` over multiple files rewrites to a `grep ""` that prefixes each line with the
filename (content preserved, framing not), and `find` with a name filter rewrites to
`ls -R`, which returns a **superset** of the matching paths. The count of
fidelity-flagged rules went from 14 to 16. These widenings buy coverage at a price, and
the price is recorded per-record rather than hidden.

---

## D14 — Turn cap raised to 100; four pilot defects fixed (2026-08-11)

The n=8 pilot (Arm 0 5/8, Arm 1 4/8) surfaced four defects that would have corrupted a
larger run. None affected the pilot's resolve rates; all affected what could be
concluded from them.

**1. The turn cap was a live confound.** At 40 it bound on 2/8 Arm 0 trajectories and
4/8 Arm 1 trajectories — three Arm 1 instances stopped at exactly 37 commands. A cap
that binds harder on the treatment arm than the control means the resolve-rate delta
cannot distinguish restriction cost from turn exhaustion, which is precisely the
confound §7 warns about. **Decision: raise to 100** and record `cap_bound` and
`max_turns` per trajectory so the confound is visible in the data rather than inferred
from a `stop_reason` string. §9 decision 4 (turns vs tokens) remains open in principle;
this answers it for the scaled run only. *Acceptance: if any instance reaches 100, the
cap is still binding and the number must go up again before the result is reportable.*

**2. `turns` counted the wrong thing.** It incremented on every assistant message,
including text-only ones, so it reported 72 turns against a cap of 40 — a cost metric
not comparable to the cap it was measured against. Now counts tool-use round trips,
the unit `max_turns` uses; assistant messages are kept separately as
`assistant_messages`.

**3. Denial attribution was wrong.** `escape_targets` credited every command in a
denied record, so `cd /repo && python - <<EOF` counted against `cd`. This metric is
meant to produce an empirically grounded v2 primitive set — "what agents actually reach
for" — so a wrong ranking defeats its purpose. `Decision.denied_by` now names the
single command that caused the denial. On the Arm 1 pilot traffic the correction moves
`python` from 29 to 10, `cat` from 12 to 3, `which` from 4 to 1, and promotes `sed`
(10) to second place — which is itself evidence for Arm 2, since the agent was reaching
for an in-place editor it did not have.

**4. Classifier version was unrecorded.** Arm 0 and Arm 1 ran days apart on different
classifier versions and nothing captured that. Resolve rates survived it — observe mode
never alters a command — but every flow-derived number was silently incomparable: Arm
0's log recorded **zero** `read` verbs because of a bug fixed before Arm 1 ran, and its
selectivity is unrecoverable without a re-run. A content hash of `classifier.py`,
`policy.py` and `canon.py` is now stamped into run metadata and every flow record, and
`report` refuses to compare flow metrics across differing fingerprints.

**Also added: resume.** `solve` skips instances already present in `trajectories.json`
that ran at least one command, so an interrupted run continues rather than restarting.
Harness-error records are retried rather than cemented.

**Consequence.** The pilot's Arm 0 flow log is retired for comparison purposes. Both
arms must be re-run at n=8 under the raised cap and a single classifier fingerprint
before scaling, and Arm 2 — which has never been executed once — needs a smoke test
before it enters any design.

---

## D15 — Findings from the raised-cap re-run (2026-08-11)

Both gates passed: no instance reached the 100-turn cap (max 35 in Arm 0, 57 in Arm 1)
and both runs carry one classifier fingerprint, `466769bd16f7`.

**1. The cap was hiding the cost.** Under the binding 40-turn cap the restricted arm
looked 22% more expensive in turns. Uncapped it is **+79% turns, +91% commands, +141%
estimated cost**. Truncation was suppressing the very quantity being measured. Any cost
number taken from a run where the cap binds is a lower bound, not an estimate.

**2. Run-to-run variance is larger than the treatment effect.** Arm 0 was run twice on
the same seed and the same eight instances, resolving 5/8 both times — but only **three
of the five overlap**. `flask` and `pylint` gained, which the cap explains (both were
cap-bound at 40). `requests` and `seaborn` were lost, and neither was cap-bound in
either run, so that is model stochasticity alone.

This is decisive for the design. The arm-to-arm difference is one instance; the
same-arm run-to-run difference is two. **At n=8 the noise exceeds the signal**, and no
amount of care in a single pair of runs fixes it. §7's k≥3 seeds is not a robustness
nicety, it is the minimum for the question to be answerable — and note the variance
observed here is *within* a seed, so seeds must be replicated, not merely varied.

**3. `sed` is the second most-denied command** (11 denials, behind `python` at 12).
The agent repeatedly reaches for an in-place editor Arm 1 does not grant. Arm 2 exists
precisely to price that, and this is the first direct evidence the delta is real rather
than notional.

**4. `diff` (6) and `mkdir` (3) are newly visible** now that attribution is correct.
Neither is on the infrastructure allowlist and neither carries a canonicalization rule.
They are candidates for D6's allowlist rather than the primitive set, on the same
argument as `git log` and `timeout`.

**5. Two Arm 1 failures are labelled `rewrite-infidelity`.** Treat this as a triage
hint, not a conclusion: only 7 of 263 records carried `fidelity_risk`, so the label
means "a lossy rewrite was present in a failing trajectory", not "the lossy rewrite
caused the failure". Confirming or dismissing it requires reading those seven records.
This is exactly the check D4 was designed to make possible.

**Consequence for the scaled run.** n=30 with k=3 seeds is the floor, and the seeds
must be genuinely replicated rather than one run each. Reporting a resolve-rate delta
from anything smaller would be reporting noise.

---

## D16 — `find` rewriting withdrawn; a bad rewrite is worse than a denial (2026-08-11)

The n=30 run gave Arm 0 20/30 and Arm 1 15/30, but the delta was contaminated.

**What went wrong.** D13 widened `find_enumerate` to match `-iname`, `-name` and
`-maxdepth`. The rewrite kept only the directory operand and dropped every predicate,
so

    find / -maxdepth 6 -iname "regex" -type d      became      ls -R /

a bounded, filtered search replaced by an unbounded recursive listing of the entire
container filesystem. D13 described this as "returns a superset", which understated it
to the point of being wrong: the agent received an enormous listing that answered a
question it had not asked. This fired on 27 of 30 `find` rewrites, touched 13 of 30
instances, and 5 of the 7 instances Arm 1 lost were among them.

**Decision.** `find` proposes no rewrite. The rule remains for labelling and coverage
mining; `find` is denied. It was never in the §2 primitive set, and `ls` cannot express
find's predicates — dropping them silently returns the wrong path set.

**The general principle, which is the real lesson.** Before D13, `find -iname` was
denied: the agent saw an error and adapted, and the denial was counted honestly as an
escape attempt. After D13, the agent silently received a wrong answer. **A rewrite that
loses information is strictly worse than a denial**, because a denial is visible to the
agent *and* to us, while silent corruption is visible to neither. Under D2's
silent-rewrite design this is the principal risk, and every future rule must be judged
against it: if a faithful rewrite does not exist, deny.

**Instrumentation added.** `dfc/audit.py` and `python -m dfc.run audit` compare each
command against what was executed and flag structural divergence — dropped scope flags,
dropped operands, scope escalation, changed redirect shape, multi-file `grep` framing.
On the n=30 Arm 1 log it reports 72 high-severity findings, every one traceable to
`find`. Replaying the same 1,366 commands through the fixed classifier gives **zero**.
Coverage moves 85.9% → 83.7%, which is the honest number: the missing 2.2 points were
commands we were mistranslating rather than handling.

**Two instrumentation defects fixed alongside.**

*Fidelity was flagged per rule, not per match.* `cat f` (faithful) and `cat a b`
(lossy — `grep` prefixes each line with its filename) were flagged identically, so
`fidelity_risk` appeared in 53% of resolved and 67% of failed trajectories and
discriminated almost nothing. `Rule.lossy_when` now decides per match.

*Rule attribution was fictional.* `_try_rewrite` stamped the first matched rule onto
every unlabelled action, so per-rule counts drawn from `action.rule` bore no relation to
the commands they sat on. Applied rules are now recorded on the `Decision` as
`rules_applied`; per-action attribution happens only when a single rule fired.

**Consequence.** The n=30 Arm 1 resolve rate is retired. Cost figures (+63% turns, +91%
dollars) stand — they are unaffected by output corruption. Arm 1 must be re-run before
its resolve rate means anything.

**Also worth recording:** the audit's first run reported 47 false `redirect-shape-changed`
findings because the check used a regex and read `>=` and `<=` inside
`awk 'NR>=25&&NR<=60'` as redirections — the same mistake §10 warns about for the
classifier, repeated in the tool built to catch it. It now goes through the parser.

---

## D17 — Arm 2 first run: sed `a`/`i`/`c` text blocks were parsed as commands (2026-08-13)

Arm 2 (n=8, cap 100) resolved **5/8** — matching Arm 0 and one ahead of Arm 1 — with a
clean audit: zero high-severity findings, confirming the D16 fix held. But the scoped
`sed` parser had a defect that suppressed the arm's whole reason for existing.

**The defect.** `a`, `i` and `c` take a *text block*, and in the one-liner form that
block runs to the end of the script, newlines included. The validator kept parsing it as
sed syntax, so an appended

    def foo(self):
        return 1

was read as command `d` (unaddressed delete → denied) and command `r` (read an unlisted
file → denied). Reported denial reasons included `\`, `X`, `"`, `-` and `I` — all first
characters of *inserted source code*. This denied **19 of 91** `sed -i` calls, and
multi-line insertion is precisely the capability Arm 2 exists to provide.

**Fix.** On reaching an `a`/`i`/`c` command, validate the command and its address, then
stop: everything after is text. This matches GNU sed, which treats `sed '1a foo; 2d'` as
appending the literal text `foo; 2d`. The escape hatches are unaffected because sed
itself would not execute them there either — a `w /tmp/x` inside appended text is text.

**Effect, replaying the same 324 commands:** coverage 81.5% → 86.1%, denials 60 → 45,
`sed -i` denials 19 → 4. The four survivors are one genuine `c`, one stream `sed`, and
two malformed scripts.

**Open sub-decision: admit `c`?** `c` (change) is `d` followed by `i`, address-scoped,
with no escape surface the other three lack. The plan's subset is `s, d, i, a`, so it is
currently denied by name. It is the strongest remaining candidate for admission and the
decision belongs in the paper either way.

**Comparison caveat, caught by the fingerprint stamp.** Arm 2 ran on classifier
`793103d05d84`; the Arm 0 and Arm 1 n=8 runs used `466769bd16f7`. Arm 2 therefore
carries the D16 `find` fix and the earlier arms do not, so **Arm 1 vs Arm 2 is not a
clean comparison** — Arm 2 is advantaged. Arm 0's resolve rate remains comparable
(observe mode never alters a command), but Arm 1 and Arm 2 must be re-run on one
fingerprint before their delta means anything.

**Also worth noting:** Arm 2 used *more* turns than Arm 1 (347 vs 284), not fewer. The
hypothesis was that an in-place editor removes the whole-file-rewrite tax. With 19 false
denials forcing retries, this run cannot test that; the re-run can.

---

## D18 — Scoped `sed -i` moves into Arm 1; Arm 2 retired (2026-08-17)

Arm 1 was `ls`, `grep`, `curl`, `tee`/`>`, restricted `awk` (D3) and stdin-only
`head`/`tail` (D11). Address-scoped `sed -i` sat in a separate Arm 2, on the plan's
§2 argument that the Arm 1 → Arm 2 delta prices the whole-file-rewrite tax.

**Decision.** Scoped `sed -i` (`s///`, `d`, `i`, `a`, address-required for `d`) is a
member of the Arm 1 primitive set. Arm 2 was Arm 1 plus exactly that, so it is now
byte-identical to Arm 1 and is **retired**: removed from `ARMS`, `ARM2` deleted from
`policy.py` and the package exports. The experiment runs two arms.

**Two reasons, and they are independent.**

1. *It passes the admission criterion on §2's own terms.* Address-scoped `sed -i` maps
   to exactly one verb (`write-int`) and its targets are statically extractable from the
   command line — the same test `grep`, `ls` and `tee` pass. `sed_admissible()` already
   rejects every escape hatch that would break this (`r`/`R`/`w`/`W`/`e`, `s///e`,
   `s///w`, `-f progfile`, unaddressed `d`). It was split into its own arm for
   experimental convenience, not because it failed admission. An Arm 1 without any
   in-place editor is a restriction we would never propose deploying, and measuring its
   cost measures a strawman.
2. *The denial data says so.* `sed` is the second most-denied command in Arm 1 — 22
   denials at n=30, 11 at n=8, behind only `python` (D15.3). §7 says the v2 primitive
   set should be driven by what agents actually reach for rather than by enumeration.
   This is that principle applied to its clearest case.

**Note: canon was already correct.** `canon.py` has carried `sed_inplace` (CSV row 21,
base `tee`, WRITE, status `Native`) since the table was ported. The canonicalization
layer always treated `sed -i` as a native write primitive; only the Arm 1 policy gate
excluded it. This change is policy-only — no canon rule was added or altered.

**Consequence, and it is the real cost of this decision.** The whole-file-rewrite tax is
**no longer measured**. §2 calls the Arm 1 → Arm 2 delta "the headline number"; there is
now no arm pair that isolates it, and Arm 2 never produced a clean measurement of it
before being retired — its one run (5/8, D17) carried 19 false `sed -i` denials and ran
on a fingerprint no other arm shared. The paper must either drop that claim or reinstate
the no-editor configuration as an ablation arm. The `Arm` dataclass still supports it:
`allow_sed_inplace=False` with `sed` absent from `primitives` reconstructs the old Arm 1
in two lines, and `sed_admissible()` is untouched.

**Mechanical effects.**

- Classifier fingerprint moves to `c0b87151304a`. Every run in `runs/` was already on a
  stale fingerprint, so nothing comparable is lost.
- Three tests asserting Arm 1 has no in-place editor are removed
  (`test_sed_inplace_denied_in_arm1`, `test_arm1_is_not_told_about_sed`,
  `test_arm1_still_refuses_sed_inplace`); the scoped-`sed` suite now runs against Arm 1.
  244 tests pass.
- Arm 1's D12 prompt block now carries the scoped `sed -i` form, since
  `system_prompt_for` keys off `allow_sed_inplace`.
- The §9.3 scale run drops from 270 trajectories to 180 (2 arms × 3 seeds × n=30),
  roughly $160–200 at the observed per-instance rates rather than $230–280.

**Still open from D17:** whether to admit `c` (change). It is `d` followed by `i`,
address-scoped, with no escape surface the admitted three lack, and it is currently
denied by name because the plan's subset is `s, d, i, a`. That question now applies to
Arm 1 rather than Arm 2.

---

## D19 — Patch extraction ran in the agent's cwd, not the repo (2026-08-20)

The n=8 gate re-run of Arm 0 at a 150-turn cap returned `pylint-dev__pylint-7228` with
`stop_reason: success`, `cap_bound: False`, `turns: 53`, **`model_patch_bytes: 0`** and
`dirty_paths: []`, while the agent's own closing summary named four files it had
changed. The same instance at a 100-turn cap produced a 10,286-byte patch. The work was
done and then lost.

**Cause.** `container.exec()` tracks the working directory across calls, because
`docker exec` is stateless and without tracking the agent's second command silently runs
in the wrong place (D9, consequence 2). The tracked cwd is read back from `$PWD` after
every command. This trajectory's final command was

    cd /testbed && python -m pytest ... && cd /tmp/rxgtest && python -m pylint t.py t2.py

leaving `self.workdir = /tmp/rxgtest`. `model_patch()` then called
`self.exec("git add -A")`, which is wrapped as `cd '/tmp/rxgtest' ... ; git add -A`.
The directory existed, so the `cd` succeeded, `git add -A` ran outside any repository
and exited non-zero, and `model_patch()` returned `""` by its own guard.
`dirty_paths()` failed the same way, which is why the write set was empty too.

**This is our harness, not SWE-bench's.** The official harness received an empty
`model_patch` in `predictions.json` and correctly reported an empty patch. Everything
downstream behaved. The defect is an interaction between two independently sound
decisions: D9's cwd tracking (necessary) and §8 R5's "the patch is produced by
`git diff` at end of trajectory" (necessary). Neither is wrong; nothing connected them.

**Decision.** `exec()` gains `workdir=` (pin this call, ignore the tracked cwd) and
`track_cwd=False` (do not write the tracked cwd back). `model_patch()`, `dirty_paths()`
and `reset()` go through a new `_repo_exec()` helper that sets both, so housekeeping
always runs in `/testbed` regardless of where the agent wandered, and pinning never
disturbs where the agent thinks it is.

**Second layer, because the first failure mode was silence.** A trajectory that ends
cleanly, issues commands and yields no diff is now classified
`empty-patch-after-success` rather than `empty-patch`. The distinction matters: the
former is a patch-extraction failure until proven otherwise, the latter is a model that
declined to edit. Scoring the first as the second is what let this run for a full
instance without anyone noticing, and at 180 trajectories it would have silently
depressed whichever arm happened to wander.

**Consequence for the gate runs.** The classifier fingerprint is **unchanged** at
`c0b87151304a` — `container.py` and `run.py` are deliberately outside `FINGERPRINTED`,
which covers only the three modules that decide what a command *means*. So
`dfc-arm1-gate-c0b8` and `dfc--gate-c0b8` remain valid and comparable. Only the
`dfc-arm0-gate-c0b8` result for `pylint-7228` is affected, and it is a false negative:
Arm 0's honest n=8 score is **5/8**, tied with Arm 1, not 4/8.

**Also worth recording.** `git stash` was the first suspect — the trajectory contains
`git stash && pytest ... ; git stash pop` — and it was wrong. The compound command
exited 0, meaning the pop succeeded. It is on `INFRA_ALLOWLIST` and remains there. The
lesson is the same one D16 recorded from the other direction: check the exit code before
building a theory on the command text.

251 tests pass, including four that drift the tracked cwd to `/tmp/rxgtest` and assert
both git calls still land in `/testbed`.

**Follow-on: resume cemented the bad record.** Re-running the identical `solve` command
reported `8 trajectory(ies) already complete, 0 to go`. D14's resume predicate is
`tool_stats.calls > 0`, and the lost-patch trajectory made 51 calls, so it counted as
finished. D14's own rationale — "a harness-error record is retried rather than
cemented" — applies verbatim here; the record simply was not recognised as a harness
error. `_retryable_harness_failure()` now re-runs any trajectory that made calls, ended
with `stop_reason: success`, was not cap-bound, and produced no patch. A cap-bound empty
patch is left alone: that is a real result about the turn budget, not our bug.

Retrying also has to prune the flow log, which is append-only. Without
`_prune_flow_log()` a retried instance contributes two sets of records to the same file
and silently inflates the coverage denominator those records feed.

256 tests pass.

---

## D20 — `git add -A` swept pre-existing image state into the patch (2026-09-16)

`psf__requests-863` harness-errored in all four trajectories that ran it (both arms,
seeds 20260812 and 20260813): `dirty_paths: ['requests/models.py', 'build/']`, a
**873,799-byte patch with 69 diff headers**, no report from the harness. The agent ran
nine commands, none of which build or install, and one of them was
`find ... | grep -v build` — it was filtering `build/` *out* of its own searches, so the
directory was there before it started. The image's own package install created it, and
that 2013-era snapshot's `.gitignore` does not list it.

**Cause.** `model_patch()` runs `git add -A` before `git diff --cached`. The `-A` is
necessary — plain `git diff` misses files the agent creates — but it carries the
assumption that *everything untracked is the agent's work*, which is false when the
image ships a dirty tree. Same shape as D19: two sound decisions (§8 R5's "the patch
comes from git" and the need to capture new files) with nothing connecting them to the
state of the image.

For calibration, across the other 176 scale-run trajectories the patch median is
1,903 B, p90 4,119 B, max 41,590 B (`mwaskom__seaborn-3190`). The only four above
that are this instance.

**Decision.** Three parts, all in `container.py` and `solver.py`, so the classifier
fingerprint is unchanged at `c0b87151304a` and every existing run stays comparable.

1. **Snapshot at start.** `start()` now calls `snapshot_start_state()`, which records
   `git status --porcelain` before the agent's first command into
   `preexisting_dirty`. Pinned to `/testbed` via `_repo_exec()` per D19.
2. **Subtract at extraction.** `model_patch()` still runs `git add -A`, then
   `git reset -q -- <snapshot paths>` before `git diff --cached`. A clean image issues
   exactly the old two commands. The trajectory's `dirty_paths` becomes
   `agent_dirty_paths()` — the write set minus the snapshot — and the snapshot itself
   is stored as `preexisting_dirty` so the exclusion is auditable per trajectory.
3. **Size guard.** A diff over `MAX_PATCH_BYTES` (250 KB: six times the largest real
   patch, a quarter of the sweep) raises `PatchTooLarge`. The solver's existing
   `except` around extraction turns that into `error`, and `classify_failure` scores
   `error` as `harness-error` before anything else. Raising was chosen over returning
   `""` because D19 already established that an empty patch after a clean finish must
   not masquerade as a model result; an oversized one is the same failure from the
   other side.

**Known limit, stated rather than hidden.** If the agent edits a file that was already
*modified* (not merely untracked) at start, `git reset -- path` unstages the whole file
and the agent's change to it is lost from the patch. The alternative — committing the
start state so the diff is taken against it — would change what the agent sees in
`git log`/`git status` and so alter the condition relative to the 21 Aug runs. Since
`preexisting_dirty` is recorded, the case is detectable after the fact: any path in
both `preexisting_dirty` and the flow log's write set needs a manual look.

**Consequence for the scale-run numbers.** None to the comparison: `requests-863`
failed in both arms on both seeds, so it is concordant and the discordant counts
(7 / 3) do not move. It costs two usable pairs. The honest Arm 0 baseline excluding it
and the five environment-dependent instances the handoff identifies is 68.8% (n=80)
rather than 61.1% (n=90); the CI on the paired difference widens slightly to
[−2.7, +12.7].

**Not done here, deliberately.** The handoff's second proposal — an
`environment-suspect` failure class for instances whose PASS_TO_PASS failure set is
identical across independent trajectories with different patches (`sphinx-8435`,
`sphinx-8627`, the three `httpbin.org` `requests` instances) — is a separate change to
`classify_failure` in `run.py` and gets its own entry when built.

265 tests pass, nine new: the snapshot, the unstage sequence, the clean-image
no-op, path quoting, the write-set subtraction, D19 pinning of the snapshot, the
size refusal, a calibration guard on the limit, and the end-to-end classification.

---

## D21 — Agent-created files collided with the hidden test patch (2026-09-16)

`pallets__flask-4992` failed all four times it was drawn (both arms, seeds 20260812
and 20260813) as `applied-broke-P2P` / `applied-F2P-unfixed`; `sphinx-doc__sphinx-8595`
failed both times (seed 20260812) the same way. Every one of the six evaluation logs
contains the same line, which nothing downstream reads:

    error: tests/static/config.toml: already exists in working directory

**Cause.** The harness grades a trajectory by applying the agent's patch, running
`git checkout <base> -- <existing test files>`, then `git apply` of the instance's
hidden test patch, then pytest. The `flask-4992` test patch *creates*
`tests/static/config.toml` as a fixture. The agent, writing a test for its own change,
had created a fixture at exactly that path, and it went into the model patch as a new
file. `git apply` refuses to create a file that exists, and it is all-or-nothing, so the
edit to `tests/test_config.py` was dropped along with it. Pytest ran the *old* test
file: 18 passed, none of them the tests the report was looking for, so every hidden test
was scored as failed. The agent's fix was never exercised. `sphinx-8595` is the same
mechanism at `tests/roots/test-ext-autodoc/target/empty_all.py`.

The `git checkout` step does not help: it restores only files that exist at the base
commit, and a fixture the PR introduced does not.

This is a harness defect scored as a model failure, the third in the D19–D21 series.
The agent's behaviour was correct engineering; there was no way for it to know the path
was reserved.

**Decision.** The instance's `test_patch` is known at solve time (it is a column on the
dataset row), so `run.py` now passes `paths_in_patch(inst["test_patch"])` — every
`diff --git a/X b/X` header, both sides — into `InstanceContainer.reserved_paths`.
`model_patch()` records which of those the agent actually staged
(`reserved_collisions`, via `git diff --cached --name-only`, taken *before* anything is
unstaged so it reflects behaviour), then unstages them in the same `git reset --` call
D20 uses for the pre-existing set. The trajectory stores `reserved_collisions`;
`dirty_paths` keeps the colliding paths because the agent did write them.

Existing test files are excluded as well as new ones. The harness discards agent edits
to those anyway via the checkout step, so nothing the evaluation sees changes; the
submitted patch is simply the part of the agent's work that can be graded.

**Why not tell the agent instead.** Adding "do not write to these paths" to the prompt
would leak the test patch's file list, which for many instances names the test that
will be run. It would also change the condition relative to the 21 Aug runs. The
extraction-side fix changes nothing the agent sees.

**Consequence for the scale-run numbers.** None to the comparison — all six
trajectories are concordant. Two instances, six trajectories, are recoverable by
re-running extraction... except that the containers are gone, so recovery means
re-solving. In `flask-4992` all 18 visible tests passed in every trajectory and the
source change is a two-line `text=True` branch; those four are likely resolves. The
handoff's n=80 "environment-excluded" baseline did not know about this class, so its
Arm 0 figure of 68.8% is itself slightly low.

**Pro.** Test patches on SWE-bench Pro are larger and add more fixture files, so the
chance an agent chooses a reserved path rises. This is the one D19–D21 fix that gets
*more* important with the migration.

Classifier fingerprint unchanged at `c0b87151304a`. 274 tests pass, nine new: the
header parser (plain, rename, empty), the unstage sequence, collision recording (real
ones only, none), D20+D21 composing into one reset, the no-reserved no-op, and the
write set retaining what the agent wrote.

---

## D22 — New files pytest would collect are dropped from the patch (2026-09-16)

D21 removes what the grader will overwrite. This entry removes the one further class
of agent output that can *change a grade* without being part of the fix: a new file
that the grader's own pytest session will load on its own.

**The hazard.** The grader runs `pytest -rA <named test files>` in a fresh container
after applying the model patch. Pytest loads every `conftest.py` on the path from the
rootdir to those files, and a bare invocation collects any `test_*.py` / `*_test.py` at
the root. An agent that left a `conftest.py` behind — a fixture it wrote to reproduce
the issue, say — therefore runs code inside the grading session that the real test
suite never asked for. Nothing in the 180 scale-run trajectories happened to do this:
27 submitted new files, of which three were root-level scratch modules
(`_tmp_conftest_check.py`, `_issue_test_module_{1,2}.py`) whose names pytest would
not collect. That is luck, not a property.

**Decision.** After `git add -A`, `git diff --cached --name-only --diff-filter=A` lists
the *additions* only. Any addition for which `is_collectible_scratch()` holds — a
`conftest.py` at any depth, or a `test_*.py` / `*_test.py` at the repo root — is
unstaged with the D20/D21 set and recorded as `scratch_excluded` on the trajectory.

**What the rule deliberately does not do.**

- It never touches a modified file. `--diff-filter=A` is the guarantee: a fix to an
  existing `conftest.py` or test module stays in the patch. This is the property that
  keeps the rule from ever dropping a real fix to existing code.
- It does not classify directories. `tests/test_repro.py` is left in. The grader names
  its test files explicitly, so a test module in a subdirectory is not collected, and
  "is this directory a test directory" is exactly the layout heuristic D16 warns
  against — `src/pkg/test_utils.py` can be a source module.
- It does not remove non-collectible scratch (`repro.py`, changelog fragments). They
  are inert to the grader and removing them buys nothing the paper measures.

Options 3 and 4 from the discussion — exclude all new files under test-like paths, or
exclude all new files — were rejected for the same reason: each adds a judgment that
can silently drop a legitimate new module on Pro, and none of them changes a grade
that this rule does not already protect.

**Ordering.** Exclusion groups are unioned in order D20, D21, D22 with no duplicates,
one `git reset --` call. A reserved path is a D21 collision, never D22 scratch.

Classifier fingerprint unchanged. 289 tests pass, fifteen new: eleven parametrised
cases for `is_collectible_scratch`, the unstage-and-record path, modifications never
qualifying, a new source module surviving, and D21/D22 not double-counting. The D19
cwd-pinning test now asserts that *every* housekeeping call is pinned rather than
counting them, since D20–D22 each added a probe.

---

## D23 — `--retry` and `--instances` on `solve` (2026-09-16)

D20–D22 invalidated ten scale-run trajectories: the grader never saw a usable patch,
so the recorded failures are not measurements. `solve` could not re-run them. Resume
skips any instance with a record, and D19's automatic retry covers only the
empty-patch case; these had patches, just wrong ones.

**`--retry ID,ID`** discards the named instances' records in an existing run-id,
prunes their flow-log entries (D19's `_prune_flow_log`), and — new — removes their
`logs/run_evaluation/<run-id>/<model>/<id>/` directory, because the official harness
skips an instance whose `report.json` exists and the retry would otherwise be graded
by the stale report. The re-solve then proceeds under the identical seed, arm and cap.

**`--instances ID,ID`** replaces the seeded sample with a hand-picked set.
`sample.json` records `selection: explicit` and `report` prints a warning line.

**The rule that goes with them.** Replacing a record is legitimate only when the
original was not a valid measurement. Re-running a *genuine* failure and keeping the
better result is selection on the outcome — nobody re-runs successes — and it inflates
the resolve rate by exactly the regression-to-the-mean it invites. So: harness-defect
trajectories are retried in place; everything else that needs a second look goes
through `--instances` into a separate run-id, which is diagnostic and is never pooled
with the seeded runs. `run_retry_d20-d22.sh` is the first use and follows this split.

291 tests pass, two new (id parsing; the evaluation-log removal touches only the named
instances).

---

## D24 — `cat -A` was rewritten to a malformed `grep`; fingerprint moves (2026-09-18)

The D23 diagnostic run's audit listed `cat -A /dev/null` → `grep "" -A /dev/null` and
`... | cat -A | head` → `... | grep "" -A | head` as *low-severity* `multifile-grep-prefix`
findings. They are neither low nor about prefixes. `cat -A` shows non-printing
characters; grep's `-A` is a context count and requires a number, so both rewritten
forms fail with an argument error. The agent asked to read a file and received an
error — or, with `2>/dev/null` (`flask-5063`), silently received nothing.

**Cause.** `cat_read`'s regex `^cat\s+(?P<f>[^|<>]+?)\s*$` captures everything after
`cat` as the file list, flags included, and pastes it after `grep ""`. The rule was
widened on 2026-08-11 to accept multiple operands and globs; nothing excluded flags.

**Extent.** 15 occurrences across the Arm 1 flow logs (scale run, pilots, diag), all
`-A`, in ~10 trajectories. Exit codes on the compound lines were 0 because a later
segment succeeded, which is why nothing tripped. No trajectory outcome is attributable
to it — the agent typically saw the error and read the file another way — but the
`2>/dev/null` shape is the D16 failure mode exactly: a silent wrong answer.

**Decision, two parts.**

1. `canon.py`: `cat_read` no longer matches when any operand begins with `-` (a lone
   `--` excepted; grep accepts it identically). No `cat` flag has a grep equivalent
   (`-A/-v/-e/-t/-E/-T` change rendering, `-s` squeezes blanks, `-b` numbers non-blank
   lines), so a flagged `cat` falls through to a denial the agent can see. `cat -n` is
   unaffected; it has its own rule. Edge: `cat -- -oddname` is now denied rather than
   rewritten; acceptable and conservative.
2. `audit.py`: new check `malformed-rewrite`, high severity — an executed `grep` whose
   `-A/-B/-C/-m` is followed by nothing, a separator, or a non-number (a `2>/dev/null`
   redirect after the flag counts as nothing). Re-run against the three scale-run Arm 1
   logs it finds **3 + 5 + 3 = 11 high-severity findings** that the 21 Aug audit
   reported as zero. The readout's "zero high-severity audit findings" gate was true
   under the audit of the day and is false under this one; that sentence must change.

**Consequence: the classifier fingerprint moves, `c0b87151304a` → `76f60a616dbb`.**
`canon.py` is fingerprinted, so by D14 every run from here is not comparable to the
180 scale-run trajectories on flow-derived metrics — coverage, denial rate,
selectivity, escape targets. Resolve rate and cost remain comparable: the change turns
15 malformed rewrites into 15 visible denials, which can only shift the
rewritten/denied split, not what the harness grades. This was chosen over deferring
the fix to a batch (with the open D17 `sed c` question) because the diagnostic run
existed to find bugs and a known-malformed rewrite left in place contradicts D16.
Any further canon change before the next scale run should be batched with this one so
the fingerprint moves once more at most.

**For the writeup.** The 21 Aug flow metrics stand as measured under `c0b87151304a`,
with the caveat that ~15 of the 3,558 Arm 1 invocations (0.4%) were rewritten into
commands that could not run and are counted as `rewritten` rather than `denied`.
Coverage is overstated by at most that much.

318 tests pass, 27 new: eight flagged-`cat` forms that must not match, five unflagged
forms that still must, `cat -n` untouched, denial (not mangling) at the classifier for
the single and pipeline shapes, four malformed rewrites the audit must rate high, and
six well-formed greps it must not.

---

## D25 — `environment-suspect`: score the environment, not the model, when the environment is broken (2026-09-18)

Sixteen scale-run trajectories are labelled `applied-broke-P2P` — the patch applied
and previously-passing tests now fail — on five instances where the patch is not what
broke them: `psf__requests-1963/2148/2317` (tests call `httpbin.org` live; 23–34
failures, identical 25-test core across six different patches, one run with zero when
the service was up) and `sphinx-doc__sphinx-8435/8627` (16 and 17 `typing`-internals
failures, identical in every run). The report scored all sixteen against the model.

**Why not the handoff's "identical across trajectories" rule.** The obvious detector —
same P2P failure set across ≥2 trajectories with different patches — has a false
positive that this run exposed: `sphinx-10451` fails the same three P2P tests in three
trajectories with three different patches, because the model makes the same
over-broad fix every time. Identical failure is consistent with a broken environment
*and* with a consistently wrong model. The two cannot be told apart from patched runs.

**Decision: measure the environment directly.** `dfc.run envcheck --run-id X`
evaluates every P2P-broken instance in X with **no model patch** (a one-file inert
diff, since the harness skips an empty one) under the harness run-id `dfc-envcheck`,
and records the tests that fail anyway in `runs/envcheck/baseline.json`. Successive
envchecks *union* into the baseline, because a live-service test that fails on
Tuesday and passes on Wednesday is still an environment failure. Docker time only;
no agent, no quota.

`classify_failure` then applies one rule, before the regression branch: **if every
P2P failure in the report also fails with no patch, the label is
`environment-suspect`.** Subset, not overlap — one failing test the baseline has never
seen means the patch did break something, and the row stays `applied-broke-P2P`.
`sphinx-10451`'s three tests pass on the pristine container, so it is correctly not
caught. F2P results on an environment-suspect row are not scored either: the same
broken service sits under them.

`report` prints how many rows are environment-suspect and, when any
`applied-broke-P2P` row has never been baselined, says so and names the command.
`dfc_report.csv` gains `env_checked`.

**What this is and is not.** It is the cheap, automatic version of the human
annotation OpenAI paid for to build SWE-bench Verified: "does this instance's test
suite pass in its own container before anyone touches it." It is not a claim that the
instance is unsolvable; a patch that also repaired the environment would resolve it.
It moves those rows out of the model's record into a category the paper reports
separately, with the baseline file as the evidence.

**Expected effect on the 21 Aug data.** After `envcheck` on the six scale-run run-ids,
sixteen rows move from `applied-broke-P2P` to `environment-suspect`. The paired
comparison does not change — all sixteen are concordant — and the resolve rate over
the remaining 74 pairs is what the paper should report, alongside the 90-pair figure.

Outside the fingerprint. 326 tests pass, eight new: the httpbin case, a real
regression on top of environment failures staying a regression, environment beating
`rewrite-infidelity`, no-baseline and empty-baseline leaving the old label, F2P-only
having no environment signal, baseline union across runs, and the no-op patch being
a single inert new file.

---

## D26 — The environment hypothesis was wrong for sphinx, and right for requests in a way the baseline cannot see (2026-09-22)

`envcheck` ran on all six scale-run run-ids. With no model patch, the pristine
containers pass **every** PASS_TO_PASS test on `sphinx-8435`, `sphinx-8627`,
`requests-2148` and `requests-2317`, and all but one on `requests-1963`. The handoff's
§4b claim — "six instances fail for reasons the patch cannot affect" — is false as
stated. Two different things were going on.

### sphinx-8435 / 8627: a harness defect, D20's sibling

Every sphinx patch carried edits to `setup.py` and `tox.ini` the agent never made.
SWE-bench builds its sphinx images by editing those files in place (dependency pins,
`pytest -rA`), leaving them as **modified tracked files** in the working tree. D20's
`build/` was untracked; this is the same defect one column over in `git status`, and
`git add -A` swept it up identically.

The consequence in the eval container is worse than D20's. The same edits are already
present there, so `git apply` fails on those hunks, `git apply --reject` fails, and the
official harness falls back to `patch --batch --fuzz=5`. GNU patch in batch mode, on
seeing hunks that are already applied, prints `Reversed (or previously applied) patch
detected! Assuming -R.` and applies the **whole patch in reverse** — five files,
including `sphinx/util/typing.py`. `run_instance.log` records it, then `Git diff
before:` is empty: the agent's fix was never in the tree, and the image's `-rA` pin
was removed from `tox.ini`, so pytest emitted no per-test PASSED lines and the log
parser scored all 16–17 P2P tests as failures. That is why the failure set was
"identical in every run": it was the parser's, not the model's.

`patch_successfully_applied: True` throughout. The harness had no idea.

**Fix.** D20 already covers it: `snapshot_start_state()` records `git status
--porcelain` in full, modified entries included, and unstages them at extraction.
No code change to the mechanism; three tests added pinning the modified-tracked
shape explicitly, since D20's tests only exercised `?? build/`. The four scale-run
trajectories are re-solved with `--retry` under D23's rule.

### requests-1963 / 2148 / 2317: environmental, but time-dependent

These patches are clean (`requests/sessions.py`, `requests/models.py` only). The
August grades showed 23–34 P2P failures; the September no-patch baseline shows 0–1.
`httpbin.org` was degraded on 21 Aug and is healthy now. The union-baseline design
(D25) cannot represent "the service was down on the day the patch was graded"; a
baseline taken on a good day exonerates nothing.

**Fix.** `evaluate --regrade ID,ID` discards those instances' harness reports and
grades the **same patches** again. This is not a re-solve and not selection on the
outcome: the patch is unchanged, only the day is. Twelve trajectories. If httpbin is
up, they get real grades; if it is down again, `envcheck` run in the same pass
records it and `report` labels them `environment-suspect`. The runbook now says to run
`envcheck` in the same pass as `evaluate`, for exactly this reason.

`merge_baseline` was also double-counting: `envcheck` merged every requested report on
every call, including ones the harness skipped as already complete, so `runs` read 12
after two passes. It now merges only reports the harness produced during that call.

### What this does to the handoff's arithmetic

The "n=80 excluding six environment instances" baseline in §4b should not be
reported. After the retries and regrades the honest figure is whatever the harness
returns; the exclusion set is empty until `report` says otherwise.

329 tests pass.

---

## D27 — SWE-bench Pro adapter; the pilot is the two pytest repos (2026-09-23)

The Lite triage is done: every concordant failure has a named cause, and the remaining
failures are the model's. Pro is where the experiment was always headed (§7, Phase 4).

**What differs, and where it lives.** Nothing that decides what a command *means*
changes: `classifier.py`, `policy.py`, `canon.py` are untouched and the fingerprint
stays `76f60a616dbb`. Everything benchmark-specific is now in `dfc/bench.py` as a
profile — dataset, checkout path, image naming, `docker run` shape, grader — and
`sample.py`, `container.py`, `solver.py`, `run.py` read it instead of hard-coding
Lite. `--bench pro` on `solve` selects it; `sample.json` records it so `evaluate`,
`envcheck`, `report` and `inspect` follow without being told again. Lite is
byte-identical (tested: same image names, same prompts, same `docker run`).

| | Lite | Pro |
|---|---|---|
| Dataset | `princeton-nlp/SWE-bench_Lite` | `ScaleAI/SWE-bench_Pro` (731 public) |
| Checkout | `/testbed` | `/app` |
| Image | `swebench/sweb.eval.x86_64.<id>` | `jefzda/sweap-images:<repo>.<name>-<id>` (128-char cap; mirrors `helper_code/image_uri.py`) |
| Entrypoint | none | `ENTRYPOINT ["/bin/bash"]` → `--entrypoint sleep` + `infinity` |
| Hidden tests | `git apply` of a test patch | `git checkout <sha> -- <files>` from a commit already in the image |
| Model patch | `git apply`, fuzzy `patch` fallback (D26) | `git apply -v`, no fallback; entryscript has no `set -e` |
| Grader | `swebench.harness.run_evaluation` → `report.json` | `swe_bench_pro_eval.py --use_local_docker` → `<prefix>_output.json`, flat test list |

`bench.pro_report()` turns the flat list into the `tests_status` shape
`classify_failure` already reads, and infers `patch_successfully_applied` from the
entryscript's `git apply -v` stderr — necessary because a failed apply still runs the
tests on the base commit and would otherwise read as "applied, unfixed".

**D20–D22 carry over unchanged**, and D21 matters less: `git checkout -- <paths>`
overwrites an agent-created file where `git apply` refused. D20 matters as much: the
Pro entryscript's `git reset --hard` clears modified tracked files but not untracked
ones, and the images are built by third-party Dockerfiles.

**The pilot is `internetarchive/openlibrary` and `qutebrowser/qutebrowser` only.**
Pro's public split has eleven repos in four languages. Arm 1's execute rule admits
`pytest` and `python -m pytest`; a repo whose native runner is `go test`, `npm test`
or `python bin/ansible-test` cannot run its own tests under the restriction. Including
those repos in a paired run would measure a tooling gap in the primitive set, not the
restriction, and the two would be inseparable in the result. Of the three Python
repos, ansible is excluded for that reason (`ansible-test`). Widening the execute rule
to other runners is a real design decision — it moves the fingerprint and needs its
own entry — and is the obvious next one once the pilot shows Pro works at all.
`--repos` overrides the default; `PRO_PYTHON_REPOS` adds ansible back.

**Design: 2 arms × n=30, one seed (`20260923`), stratified round-robin across the two
repos (15 each), cap 150.** A smoke phase — one instance, arm0, solve + grade — runs
first and aborts the script on a container or grader failure, so an overnight run
cannot burn sixty trajectories on a structural mistake. Grading uses two workers:
Pro images are multi-gigabyte and the Mac runs them under emulation.

**Known unknowns going in.** Pro instances are larger (median gold patch ~6 KB vs
~1 KB on Lite); the cap may bind (D14) and the whole-file-rewrite cost may bite harder
(§2). The HF dataset's column casing differs between exports; `normalize()` accepts
both. Image pull size for 30 instances is unmeasured; the smoke phase pulls one.

351 tests pass, 22 new in `tests/test_bench.py`.

---

## D28 — The Pro pilot graded the base commit's tests; the hidden tests were never installed (2026-09-23)

The pilot ran clean — 60 trajectories, no cap-bound, no harness-error, zero
high-severity audit findings, D20/D21 firing as designed (7 dirty images, 22–25
collisions) — and scored **0/30 in both arms with 11–12 `environment-suspect` rows
each**. That combination is the Phase 4 gate exactly: a near-zero baseline means the
harness is broken, not the model. It was.

**Cause.** The Scale entryscript installs the hidden tests by running the *last line*
of the dataset row's `before_repo_set_cmd`. In the public HuggingFace rows that line
is `git apply --verbose /tests/test_patch.patch`. The file exists in Scale's internal
ECR images and not in the `jefzda/sweap-images` DockerHub images the local-docker path
pulls. The apply failed, the entryscript has no `set -e`, the tests ran on the base
commit, and — because git's output goes to the container's stdout, which the grader
does not keep — nothing recorded it. The visible symptom was `collected 0 items` for
a test file that "does not exist", and P2P failures reproducing with no patch, which
D25 dutifully labelled environmental. The repo's own `helper_code/sweap_eval_full_v2.jsonl`
(a July export) uses `git checkout <sha> -- <files>` instead, a commit that *is* in
the images; but its FAIL/PASS lists differ from HF on all 30 sampled instances (HF
removed outdated tests in February), so grading with it would score against the
wrong test lists.

**Decision.** The grader is handed a `before_repo_set_cmd` whose last line we write
(`bench.pro_setup_line`). It carries the HF `test_patch` itself, base64 on one line,
and applies it — so the tests graded are the tests the HF lists name. The same line
first records `git status --porcelain` into `/workspace` (the only evidence of whether
the *model* patch applied, since git's stdout is lost) and captures our own
`git apply --verbose` output and exit code. `/workspace` is a bind mount, so both
survive the container. `pro_report` reads them: model patch applied iff every file it
touches is dirty in that status; hidden tests installed iff `exit=0`; anything else
is `error`, which `classify_failure` now maps to `harness-error` ahead of every other
label, so this class of failure can never again present as 0/30.

**Nothing about the trajectories changes.** They were solved in the correct image at
the correct commit with the correct prompt; only the grade was wrong. `evaluate
--regrade all` (new) re-grades every instance; `run_pro_regrade.sh` does the three
run-ids. Docker time only.

**Why this was not caught by the smoke phase.** The smoke checked that a container
starts, the grader runs and writes `output.json`. It did not check that the grade
*could have been* anything but a failure. The runbook's Phase 4 gate ("Arm 0 near zero
⇒ stop") is the check that caught it, one run later than a smarter smoke would have.
The smoke now fails if `dfc_test_apply.log` is missing or non-zero.

356 tests pass, five new.

---

## D29 — `sed c` admitted; fingerprint moves to `10c5e789bf69` (2026-09-24)

Open since D17. `c` (change) replaces the addressed lines with a literal text block. It
is `d` followed by `i` at the same address: same file, same range, same verb
(write-int), and the same D17 text-block handling — everything after `c\` is
replacement text, not commands, so a `w` or `r` inside it is not an escape. Nothing
but the plan's original four-command table kept it out, and admitting `s`, `d`, `i`,
`a` while denying their composition had no principled defence.

**Decision.** `c` joins `_SED_ALLOWED_COMMANDS`. An address is required, as for `i`
and `a` and as for `d` under `sed_require_address_for_delete`: an unaddressed `c`
replaces every line of the file. The Arm 1 prompt block shows the form. The no-editor
ablation (`allow_sed_inplace=False`) still denies it.

**What it is not.** It is not a lever on the Pro gap. Of the 44 `sed` denials in the
Pro Arm 1 log, **6** were `c` forms. **31** were the agent reading line ranges through
a pipeline — `grep -n "" f | sed -n '1193,1240p'` — which is a *read*, not an edit,
and which the canon already rewrites to `awk 'NR>=A&&NR<=B'` when `sed -n` has a file
operand but not when it reads stdin. That is the actual source of `sed` denials on
Pro, it is a canonicalisation gap rather than a policy question, and it gets its own
entry when fixed (the rewrite is exact: `sed -n 'A,Bp'` on a stream is `awk
'NR>=A&&NR<=B'` on the same stream). The remaining 7 are `q`, `o`, `t` and mixed
forms, correctly outside the subset.

**Fingerprint** `76f60a616dbb` → `10c5e789bf69`. The Pro pilot (one seed) and every
Lite run stay on their own fingerprints; nothing is re-run for this. This is the first
entry in the pre-experiment batch; the stream-`sed` rewrite and whatever the Pro
failure triage adds should land before the fingerprint is frozen, so it moves once
more at most.

361 tests pass, six new; one D17 case moved from "denied" to "passthrough".
