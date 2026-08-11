"""Phase 2 unit tests - everything that can be checked without Docker or the SDK."""

from __future__ import annotations

import pytest

from dfc import bashtool, container, run, sample
from dfc.model import Decision, Outcome, Verb


# --------------------------------------------------------------------------
# Container plumbing
# --------------------------------------------------------------------------

def test_image_key_matches_harness_convention():
    assert container.image_key("astropy__astropy-12907") == "astropy_1776_astropy-12907"
    assert container.image_for("django__django-11099").endswith(
        "django_1776_django-11099:latest")


def test_sentinel_split_strips_private_line_and_recovers_cwd():
    from dfc.container import _split_sentinel
    text, cwd = _split_sentinel("hello\nworld\n__DFC_CWD__/testbed/sub\n", "__DFC_CWD__")
    assert text.rstrip("\n") == "hello\nworld"
    assert cwd == "/testbed/sub"
    assert "__DFC_CWD__" not in text


def test_sentinel_absent_leaves_output_alone():
    from dfc.container import _split_sentinel
    text, cwd = _split_sentinel("just output", "__DFC_CWD__")
    assert text == "just output"
    assert cwd == ""


# --------------------------------------------------------------------------
# Return channel (§6.4)
# --------------------------------------------------------------------------

def test_l0_emits_nothing():
    out, n = bashtool.filter_output("lots of test output", "L0")
    assert out == "" and n == 0


def test_l2_truncates():
    out, n = bashtool.filter_output("x" * 5000, "L2")
    assert n == 2000


def test_l4_is_lossless():
    """§9 decision 1: the main arms run at L4. Restricting test output would handicap
    the capability measurement, and the containment claim is deferred."""
    text = "x" * 50000
    out, n = bashtool.filter_output(text, "L4")
    assert out == text and n == len(text)


def test_default_level_is_l4():
    assert bashtool.RETURN_CHANNEL_LEVEL == "L4"


# --------------------------------------------------------------------------
# The bash tool: gate, rewrite, log
# --------------------------------------------------------------------------

class FakeContainer:
    """Stands in for a running instance container."""

    def __init__(self, stdout="ok", exit_code=0):
        self.calls: list[str] = []
        self.stdout = stdout
        self.exit_code = exit_code
        self.workdir = "/testbed"

    def exec(self, command, timeout=300):
        self.calls.append(command)
        return {"exit_code": self.exit_code, "stdout": self.stdout, "stderr": "",
                "timed_out": False, "cwd": self.workdir}


@pytest.fixture
def tool(tmp_path, monkeypatch):
    monkeypatch.setenv("DFC_FLOW_LOG", str(tmp_path / "flow.jsonl"))
    from dfc.policy import ARM1
    return bashtool.BashTool(container=FakeContainer(), arm=ARM1,
                             instance_id="test-1", measure_selectivity=False)


def test_denied_command_never_reaches_the_container(tool):
    result = tool.run("python3 -c 'import os'")
    assert result["is_error"] is True
    assert tool.container.calls == []
    assert tool.denials == 1


def test_denial_reason_is_returned_to_the_model(tool):
    result = tool.run("awk '{system(\"id\")}' f")
    text = result["content"][0]["text"]
    assert "Blocked" in text and "system()" in text


def test_rewrite_executes_the_canonical_form(tool):
    """D2: the agent wrote `cat`, the container ran `grep`."""
    tool.run("cat setup.py")
    assert tool.container.calls == ['grep "" setup.py']
    assert tool.rewrites == 1


def test_rewrite_is_not_disclosed_to_the_model(tool):
    result = tool.run("cat setup.py")
    assert "grep" not in result["content"][0]["text"]
    assert "is_error" not in result


def test_passthrough_runs_verbatim(tool):
    tool.run("ls -la")
    assert tool.container.calls == ["ls -la"]


def test_arm0_runs_everything(tmp_path, monkeypatch):
    monkeypatch.setenv("DFC_FLOW_LOG", str(tmp_path / "flow.jsonl"))
    from dfc.policy import ARM0
    t = bashtool.BashTool(container=FakeContainer(), arm=ARM0,
                          measure_selectivity=False)
    t.run("python3 -c 'import os'")
    t.run("cat setup.py")
    assert t.container.calls == ["python3 -c 'import os'", "cat setup.py"]
    assert t.denials == 0 and t.rewrites == 0


def test_stats_track_the_three_populations(tool):
    tool.run("ls")
    tool.run("cat setup.py")
    tool.run("eval x")
    s = tool.stats()
    assert (s["calls"], s["passthrough"], s["rewrites"], s["denials"]) == (3, 1, 1, 1)


def test_nonzero_exit_is_surfaced(tmp_path, monkeypatch):
    monkeypatch.setenv("DFC_FLOW_LOG", str(tmp_path / "flow.jsonl"))
    from dfc.policy import ARM1
    t = bashtool.BashTool(container=FakeContainer(stdout="boom", exit_code=1),
                          arm=ARM1, measure_selectivity=False)
    assert "[exit code 1]" in t.run("ls")["content"][0]["text"]


def test_flow_log_written_per_call(tool, tmp_path):
    import json
    tool.run("ls")
    tool.run("eval x")
    lines = [json.loads(x) for x in
             (tmp_path / "flow.jsonl").read_text().splitlines() if x.strip()]
    assert [r["outcome"] for r in lines] == ["passthrough", "denied"]
    assert lines[0]["executed"] == "ls"
    assert lines[0]["return_channel"]["level"] == "L4"


# --------------------------------------------------------------------------
# Solver configuration - the §10 gotchas
# --------------------------------------------------------------------------

def test_every_shell_bypassing_tool_is_denied():
    """§10: if Read/Edit/Grep/Glob are not denied, the experiment silently measures
    nothing."""
    from dfc.solver import DISALLOWED
    for t in ("Read", "Edit", "Write", "Glob", "Grep", "WebFetch", "NotebookEdit"):
        assert t in DISALLOWED, t


def test_builtin_bash_is_denied():
    """The executor is the MCP tool. A host shell would put an unrestricted Arm 0 agent
    on the researcher's own machine."""
    from dfc.solver import DISALLOWED
    assert "Bash" in DISALLOWED


def test_task_denied_in_v1():
    """§6.5: a subagent call is simultaneously an external write and an untrusted read.
    It is the v2 marquee experiment, not part of v1."""
    from dfc.solver import DISALLOWED
    assert "Task" in DISALLOWED


def test_system_prompt_pushes_heredoc_writes():
    """§8 Phase 2: echo/printf into `>` is the likely cause of syntax-error failures and
    it is avoidable."""
    assert "<<'EOF'" in solver_prompt()


def solver_prompt() -> str:
    from dfc.solver import SYSTEM_PROMPT
    return SYSTEM_PROMPT


# --------------------------------------------------------------------------
# Sampling (§4.5, E3)
# --------------------------------------------------------------------------

def _fake_instances():
    out = []
    for repo, k in (("astropy", 20), ("django", 30), ("sympy", 15), ("flask", 3)):
        for i in range(k):
            out.append({
                "instance_id": f"{repo}__{repo}-{1000 + i}",
                "patch": "diff --git a/x b/x\n@@ -1 +1 @@\n-a\n+b\n",
            })
    return out


def test_sampling_spreads_across_repos():
    """`list(ds)[:5]` gave five instances from one repo. That is not a sample (§4.5)."""
    picked = sample.stratified(_fake_instances(), 8)
    repos = {sample.repo_of(i["instance_id"]) for i in picked}
    assert len(picked) == 8
    assert len(repos) == 4


def test_sampling_is_deterministic():
    a = sample.stratified(_fake_instances(), 8, seed=1)
    b = sample.stratified(_fake_instances(), 8, seed=1)
    assert [i["instance_id"] for i in a] == [i["instance_id"] for i in b]


def test_seed_changes_the_sample():
    a = sample.stratified(_fake_instances(), 8, seed=1)
    b = sample.stratified(_fake_instances(), 8, seed=2)
    assert [i["instance_id"] for i in a] != [i["instance_id"] for i in b]


def test_sampling_handles_small_repos():
    picked = sample.stratified(_fake_instances(), 60)
    assert len(picked) == 60


def test_patch_size_report():
    rep = sample.size_report(_fake_instances()[:4])
    assert rep["n"] == 4
    assert rep["median_lines_touched"] == 2
    assert rep["degeneracy_risk"] is False


def test_degeneracy_risk_trips_on_large_patches():
    """§7: measure the gold-patch size distribution before committing compute."""
    big = "\n".join(
        ["diff --git a/f%d b/f%d" % (i, i) for i in range(4)]
        + ["+line"] * 30 + ["-line"] * 30
    )
    rep = sample.size_report([{"instance_id": "x__x-1", "patch": big}])
    assert rep["degeneracy_risk"] is True


# --------------------------------------------------------------------------
# Failure taxonomy (E2)
# --------------------------------------------------------------------------

def test_harness_error_beats_everything():
    assert run.classify_failure({"error": "boom"}, None, 0.0, False) == "harness-error"


def test_empty_patch():
    assert run.classify_failure({"model_patch": ""}, None, 0.0, False) == "empty-patch"


def test_turn_limit():
    traj = {"model_patch": "", "stop_reason": "turn-limit"}
    assert run.classify_failure(traj, None, 0.0, False) == "turn-limit"


def test_resolved():
    traj = {"model_patch": "diff"}
    assert run.classify_failure(traj, {"resolved": True}, 0.0, False) == "resolved"


def test_malformed_patch():
    traj = {"model_patch": "diff"}
    rep = {"resolved": False, "patch_successfully_applied": False}
    assert run.classify_failure(traj, rep, 0.0, False) == "patch-malformed"


def test_p2p_regression_detected():
    """§10: `patch --fuzz=5` applies a wrong patch in the wrong place and reports
    success. Always check PASS_TO_PASS."""
    traj = {"model_patch": "diff"}
    rep = {"resolved": False, "patch_successfully_applied": True,
           "tests_status": {"PASS_TO_PASS": {"failure": ["t1"]},
                            "FAIL_TO_PASS": {"failure": ["t2"]}}}
    assert run.classify_failure(traj, rep, 0.0, False) == "applied-broke-P2P"


def test_fidelity_risk_reclassifies_a_regression():
    """D4: separate restriction cost from our rewrite being wrong."""
    traj = {"model_patch": "diff"}
    rep = {"resolved": False, "patch_successfully_applied": True,
           "tests_status": {"PASS_TO_PASS": {"failure": ["t1"]}}}
    assert run.classify_failure(traj, rep, 0.0, True) == "rewrite-infidelity"


def test_deadlock_when_denials_dominate():
    traj = {"model_patch": "diff"}
    rep = {"resolved": False, "patch_successfully_applied": True,
           "tests_status": {"PASS_TO_PASS": {"failure": []},
                            "FAIL_TO_PASS": {"failure": ["t2"]}}}
    assert run.classify_failure(traj, rep, 0.5, False) == "blocked-tool-deadlock"


def test_taxonomy_covers_every_returned_label():
    labels = {
        run.classify_failure({"error": "x"}, None, 0, False),
        run.classify_failure({"model_patch": ""}, None, 0, False),
        run.classify_failure({"model_patch": "d"}, {"resolved": True}, 0, False),
    }
    assert labels <= set(run.TAXONOMY)
