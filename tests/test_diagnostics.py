"""Regression tests for the failure that burned a whole run.

A token with an embedded line break made the CLI refuse to authenticate. The model got
no tools, answered once with the error text, and stopped. Every trajectory reported
`stop_reason: success`, `error: ''`, one turn, zero commands, zero cost - which reads as
a clean model failure and is nothing of the kind. Preflight had passed, because it only
checked that the variable was set.
"""

from __future__ import annotations

import pytest

from dfc import run


REAL_ERROR = (
    "Invalid auth token · Fix external auth token · Invalid Authorization "
    "header value from CLAUDE_CODE_OAUTH_TOKEN: it contains a line break at character "
    "85 (110 characters on 2 lines)."
)


# --------------------------------------------------------------------------
# Token shape validation
# --------------------------------------------------------------------------

def test_newline_in_token_fails_preflight(monkeypatch, capsys):
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "sk-ant-oat01-" + "a" * 60 + "\n" + "b" * 30)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert run._check_auth() is False
    out = capsys.readouterr().out
    assert "whitespace" in out
    assert "tr -d" in out          # the fix is printed, not just the diagnosis


def test_trailing_newline_fails(monkeypatch):
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "sk-ant-oat01-abc\n")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert run._check_auth() is False


def test_embedded_space_fails(monkeypatch):
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "sk-ant-oat01-abc def")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert run._check_auth() is False


def test_clean_token_passes(monkeypatch, capsys):
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "sk-ant-oat01-" + "a" * 90)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert run._check_auth() is True
    assert "single line" in capsys.readouterr().out


def test_missing_token_is_not_a_failure(monkeypatch, capsys):
    """No env token just means the CLI's own stored login will be used. Hard-failing
    here would push people toward pasting a token, which is the thing that breaks."""
    monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert run._check_auth() is True
    assert "doctor" in capsys.readouterr().out


def test_malformed_token_still_hard_fails(monkeypatch):
    """A present-but-broken token is worse than no token: it overrides the CLI login."""
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "sk-ant-oat01-abc\ndef")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert run._check_auth() is False


def test_api_key_is_accepted_but_flagged_as_not_subscription(monkeypatch, capsys):
    monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-api03-abc")
    assert run._check_auth() is True
    assert "NOT your subscription" in capsys.readouterr().out


def test_wrong_prefix_warns_but_passes(monkeypatch, capsys):
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "oat01-" + "a" * 90)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert run._check_auth() is True
    assert "does not start with" in capsys.readouterr().out


# --------------------------------------------------------------------------
# Zero-call diagnosis
# --------------------------------------------------------------------------

def test_line_break_error_is_diagnosed_from_model_text():
    reason = run._zero_call_reason({"final_text": REAL_ERROR})
    assert "line break" in reason
    assert "tr -d" in reason


def test_generic_auth_text_is_diagnosed():
    reason = run._zero_call_reason({"final_text": "Your credit balance is too low"})
    assert "auth or quota" in reason


def test_unknown_zero_call_still_reports_model_text():
    reason = run._zero_call_reason({"final_text": "I have finished the task."})
    assert "no tool calls" in reason
    assert "finished the task" in reason


def test_empty_text_does_not_crash():
    assert run._zero_call_reason({}) != ""


# --------------------------------------------------------------------------
# A zero-command trajectory is a harness error, never a clean result
# --------------------------------------------------------------------------

def test_zero_commands_is_never_reported_as_a_model_failure():
    """The original bug: stop_reason 'success', error '', and the run kept going."""
    traj = {"error": "", "model_patch": "", "stop_reason": "success",
            "final_text": REAL_ERROR}
    traj["error"] = run._zero_call_reason(traj)
    traj["stop_reason"] = "harness-error"
    assert run.classify_failure(traj, None, 0.0, False) == "harness-error"


def test_a_genuine_empty_patch_is_still_empty_patch():
    """Do not over-correct: a session that ran commands and produced nothing is a real
    model failure, not a harness error."""
    traj = {"error": "", "model_patch": "", "stop_reason": "end_turn"}
    assert run.classify_failure(traj, None, 0.0, False) == "empty-patch"
