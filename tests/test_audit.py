"""Rewrite audit (D16).

The `find` defect reached a 30-instance run before anyone noticed, despite being
plainly visible in the flow log. These tests pin the checks that would have caught it
on the first trajectory, and pin the false positive that nearly buried it.
"""

from __future__ import annotations

import pytest

from dfc import audit, classify
from dfc.model import Outcome
from dfc.policy import ARM1


def kinds(findings):
    return {f.kind for f in findings}


# --------------------------------------------------------------------------
# The defect this module exists for
# --------------------------------------------------------------------------

def test_dropped_scope_flag_detected():
    f = audit.inspect('find / -maxdepth 6 -iname "regex" -type d', "ls -R /")
    assert "dropped-scope-flag" in kinds(f)
    assert any(x.severity == "high" for x in f)


def test_scope_escalation_detected():
    """A bounded request became a recursive listing of the whole filesystem."""
    f = audit.inspect("find /usr/lib -maxdepth 2 -name 'x*'", "ls -R /")
    assert "scope-escalation" in kinds(f)


def test_dropped_operand_detected():
    f = audit.inspect("cat a.py b.py", 'grep "" a.py')
    assert "dropped-operand" in kinds(f)


def test_faithful_rewrite_produces_no_high_findings():
    f = audit.inspect("cat setup.py", 'grep "" setup.py')
    assert not [x for x in f if x.severity == "high"]


def test_identical_command_produces_nothing():
    assert audit.inspect("ls -la", "ls -la") == []


def test_multifile_grep_is_low_not_high():
    """Content is preserved, framing is not. Worth knowing, not a wrong answer."""
    f = audit.inspect("cat a.py b.py", 'grep "" a.py b.py')
    assert "multifile-grep-prefix" in kinds(f)
    assert not [x for x in f if x.severity == "high"]


# --------------------------------------------------------------------------
# The false positive that nearly buried the real finding
# --------------------------------------------------------------------------

def test_awk_comparisons_are_not_redirects():
    """`awk 'NR>=25&&NR<=60'` contains >= and <=. A regex read them as redirections and
    produced 47 false findings - the largest group in the first audit run. The shape
    comparison goes through the parser for exactly this reason (§10)."""
    f = audit.inspect("sed -n '25,60p' pyproject.toml",
                      "awk 'NR>=25&&NR<=60' pyproject.toml")
    assert "redirect-shape-changed" not in kinds(f)
    assert f == [] or all(x.severity == "low" for x in f)


def test_real_redirect_change_is_still_caught():
    f = audit.inspect("cp a.txt b.txt", "tee b.txt < a.txt >/dev/null")
    assert "redirect-shape-changed" in kinds(f)


def test_unparseable_input_does_not_crash():
    assert isinstance(audit.inspect("if [ ; then", "ls"), list)


# --------------------------------------------------------------------------
# End to end over records
# --------------------------------------------------------------------------

def test_audit_records_ignores_non_rewrites():
    recs = [
        {"outcome": "passthrough", "command": "ls", "updated_command": ""},
        {"outcome": "denied", "command": "find . -name x", "updated_command": ""},
    ]
    findings, counts = audit.audit_records(recs)
    assert findings == [] and counts == {}


def test_audit_records_flags_a_bad_rewrite():
    recs = [{"outcome": "rewritten", "instance_id": "i1",
             "command": 'find / -maxdepth 6 -iname "regex"',
             "updated_command": "ls -R /"}]
    findings, counts = audit.audit_records(recs)
    assert counts["scope-escalation"] == 1
    assert findings[0].instance_id == "i1"


def test_grouping_collapses_a_systemic_defect():
    recs = [{"outcome": "rewritten", "command": f'find /{i} -maxdepth 2 -name "x"',
             "updated_command": "ls -R /"} for i in range(5)]
    findings, _ = audit.audit_records(recs)
    groups = audit.group_by_shape(findings)
    assert any(len(v) == 5 for v in groups.values())


def test_cd_prefix_does_not_hide_the_culprit():
    """`cd /testbed && find . -type f` should group under find, not cd."""
    recs = [{"outcome": "rewritten", "command": "cd /testbed && find . -type f",
             "updated_command": "cd /testbed && ls -R ."}]
    findings, _ = audit.audit_records(recs)
    assert any("find" in k for k in audit.group_by_shape(findings))


# --------------------------------------------------------------------------
# D16: the fix holds
# --------------------------------------------------------------------------

@pytest.mark.parametrize("cmd", [
    'find / -maxdepth 6 -iname "regex" -type d',
    "cd /testbed && find . -maxdepth 1 -iname '*change*'",
    "find tests/data -type f",
])
def test_find_now_denied_so_it_cannot_be_mistranslated(cmd):
    d = classify(cmd, ARM1)
    assert d.outcome is Outcome.DENIED
    assert d.updated_command is None


def test_no_high_severity_findings_from_current_classifier():
    """Replay the shapes that produced 72 high-severity findings in the n=30 run."""
    cmds = [
        'find / -maxdepth 6 -iname "regex" -type d 2>/dev/null',
        "cd /testbed && find . -path ./astroid -prune -o -iname '*.rst' -print",
        "cd /testbed && find tests/data -type f",
        "cat setup.py",
        "head -n 20 setup.py",
        "wc -l setup.py",
        "sed -n '25,60p' pyproject.toml",
    ]
    recs = []
    for c in cmds:
        d = classify(c, ARM1)
        recs.append({"outcome": d.outcome.value, "command": c,
                     "updated_command": d.updated_command or ""})
    findings, _ = audit.audit_records(recs)
    assert [f for f in findings if f.severity == "high"] == []


# --------------------------------------------------------------------------
# Command census (§7)
# --------------------------------------------------------------------------

def test_census_counts_every_command_node_not_the_first_word(tmp_path):
    """`cd /repo && grep x f | head -20` is three invocations. Counting the first
    token would report only `cd`, which is the most frequent token in every arm."""
    from dfc import census
    run = tmp_path / "runs" / "r1"
    run.mkdir(parents=True)
    (run / "sample.json").write_text('{"arm": "arm0-baseline"}')
    (run / "flow_log.jsonl").write_text(
        '{"command": "cd /repo && grep x f | head -20", "outcome": "observed"}\n')
    c = census.collect(tmp_path / "runs")["arm0"]
    assert c.invocations == 3
    assert set(c.counts) == {"cd", "grep", "head"}


def test_census_counts_what_the_agent_wrote_not_what_ran(tmp_path):
    """Counting `executed` would measure our canonicalization table instead of the
    agent's behaviour."""
    from dfc import census
    run = tmp_path / "runs" / "r1"
    run.mkdir(parents=True)
    (run / "sample.json").write_text('{"arm": "arm1-primitives"}')
    (run / "flow_log.jsonl").write_text(
        '{"command": "cat f.py", "executed": "grep \\"\\" f.py", '
        '"updated_command": "grep \\"\\" f.py", "outcome": "rewritten"}\n')
    c = census.collect(tmp_path / "runs")["arm1"]
    assert c.counts["cat"] == 1
    assert "grep" not in c.counts


def test_census_separates_arms(tmp_path):
    from dfc import census
    for name, arm, cmd in (("r0", "arm0-baseline", "python3 -c x"),
                           ("r1", "arm1-primitives", "grep y f")):
        run = tmp_path / "runs" / name
        run.mkdir(parents=True)
        (run / "sample.json").write_text(f'{{"arm": "{arm}"}}')
        (run / "flow_log.jsonl").write_text(
            '{"command": "%s", "outcome": "observed"}\n' % cmd)
    cs = census.collect(tmp_path / "runs")
    assert set(cs) == {"arm0", "arm1"}
    assert cs["arm0"].counts["python3"] == 1
    assert cs["arm1"].counts["grep"] == 1


def test_coverage_reports_invocation_and_name_shares(tmp_path):
    """The gap between the two *is* the Zipfian argument."""
    from dfc import census
    c = census.ArmCensus(arm="arm0", invocations=10)
    c.counts.update({"grep": 8, "python": 1, "xargs": 1})
    cov = census.coverage_of(c, {"grep"})
    assert cov["by_invocation"] == 0.8
    assert round(cov["by_distinct_name"], 3) == 0.333
    assert cov["uncovered_invocations"] == 2


def test_unparseable_lines_counted_not_silently_dropped(tmp_path):
    from dfc import census
    run = tmp_path / "runs" / "r1"
    run.mkdir(parents=True)
    (run / "sample.json").write_text('{"arm": "arm0-baseline"}')
    (run / "flow_log.jsonl").write_text('{"command": "if [ ; then", "outcome": "observed"}\n')
    c = census.collect(tmp_path / "runs")["arm0"]
    assert c.unparseable == 1 and c.invocations == 0
