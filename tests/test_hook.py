"""Hook protocol tests - the JSON contract with Claude Code."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from dfc import hook

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch, tmp_path):
    monkeypatch.setenv("DFC_ARM", "arm1")
    monkeypatch.setenv("DFC_FLOW_LOG", str(tmp_path / "flow.jsonl"))
    monkeypatch.delenv("DFC_INSTANCE_ID", raising=False)


def call(command: str, tool: str = "Bash") -> dict:
    return hook.handle({"tool_name": tool, "tool_input": {"command": command}})


def hso(out: dict) -> dict:
    return out["hookSpecificOutput"]


def test_passthrough_allows():
    out = call("ls -la")
    assert hso(out)["permissionDecision"] == "allow"
    assert "updatedInput" not in hso(out)


def test_rewrite_returns_updated_input():
    """D2: the mechanism that makes silent rewriting possible."""
    out = call("cat setup.py")
    h = hso(out)
    assert h["permissionDecision"] == "allow"
    assert h["updatedInput"]["command"] == 'grep "" setup.py'


def test_rewrite_is_silent():
    """No reason string on a rewrite - the agent is not told (D2)."""
    assert "permissionDecisionReason" not in hso(call("cat setup.py"))


def test_rewrite_preserves_other_tool_input_fields():
    out = hook.handle({
        "tool_name": "Bash",
        "tool_input": {"command": "cat setup.py", "timeout": 120000,
                       "description": "read setup"},
    })
    updated = hso(out)["updatedInput"]
    assert updated["timeout"] == 120000
    assert updated["description"] == "read setup"


def test_deny_carries_an_actionable_reason():
    out = call("awk '{system(\"id\")}' f")
    h = hso(out)
    assert h["permissionDecision"] == "deny"
    assert "system()" in h["permissionDecisionReason"]


def test_builtin_file_tools_denied():
    """§10: if Read/Edit/Grep/Glob are not denied, the experiment silently measures
    nothing, because the model never touches bash."""
    for tool in ("Read", "Edit", "Write", "Glob", "Grep", "WebFetch", "Task"):
        out = hook.handle({"tool_name": tool, "tool_input": {}})
        assert hso(out)["permissionDecision"] == "deny", tool


def test_unknown_tool_allowed():
    out = hook.handle({"tool_name": "TodoWrite", "tool_input": {}})
    assert hso(out)["permissionDecision"] == "allow"


def test_arm0_never_denies(monkeypatch):
    monkeypatch.setenv("DFC_ARM", "arm0")
    for cmd in ("python3 -c 'x'", "cat $(ls)", "eval x"):
        assert hso(call(cmd))["permissionDecision"] == "allow"


def test_arm0_never_rewrites(monkeypatch):
    monkeypatch.setenv("DFC_ARM", "arm0")
    assert "updatedInput" not in hso(call("cat setup.py"))


def test_flow_log_written_for_every_outcome(tmp_path, monkeypatch):
    log = tmp_path / "fl.jsonl"
    monkeypatch.setenv("DFC_FLOW_LOG", str(log))
    call("ls")                       # passthrough
    call("cat setup.py")             # rewritten
    call("python3 -c 'x'")           # denied
    lines = [json.loads(x) for x in log.read_text().splitlines() if x.strip()]
    assert [r["outcome"] for r in lines] == ["passthrough", "rewritten", "denied"]


def test_summary_counts_escapes(tmp_path, monkeypatch):
    from dfc import flowlog
    log = tmp_path / "fl.jsonl"
    monkeypatch.setenv("DFC_FLOW_LOG", str(log))
    call("ls")
    call("cat setup.py")
    call("python3 -c 'x'")
    s = flowlog.summarize(flowlog.read(log))
    assert s["invocations"] == 3
    assert s["escape_attempts"] == 1
    assert s["coverage_by_invocation"] == pytest.approx(2 / 3)


def test_subprocess_contract():
    """The hook must work as a plain executable reading stdin, printing JSON, exit 0."""
    env = dict(os.environ, DFC_ARM="arm1", PYTHONPATH=str(ROOT))
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": "cat x.py"}})
    proc = subprocess.run(
        [sys.executable, "-m", "dfc.hook"],
        input=payload, capture_output=True, text=True, env=env, cwd=str(ROOT),
    )
    assert proc.returncode == 0
    out = json.loads(proc.stdout)
    assert out["hookSpecificOutput"]["updatedInput"]["command"] == 'grep "" x.py'


def test_malformed_hook_input_does_not_gate():
    """Bad hook input is our bug, not the agent's."""
    env = dict(os.environ, DFC_ARM="arm1", PYTHONPATH=str(ROOT))
    proc = subprocess.run(
        [sys.executable, "-m", "dfc.hook"],
        input="{not json", capture_output=True, text=True, env=env, cwd=str(ROOT),
    )
    assert proc.returncode == 0
    assert json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"] == "allow"


def test_empty_command_allowed():
    assert hso(call("   "))["permissionDecision"] == "allow"
