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
