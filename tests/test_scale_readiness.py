"""Fixes required before scaling past n=8.

Each test here corresponds to a defect that would have silently corrupted a
270-trajectory run. They exist because the n=8 pilot found them and a larger run would
only have made them more expensive.
"""

from __future__ import annotations

import json

import pytest

from dfc import flowlog, run, solver, version
from dfc.classifier import classify
from dfc.policy import ARM0, ARM1


# --------------------------------------------------------------------------
# Turn accounting and the cap
# --------------------------------------------------------------------------

def test_default_cap_raised():
    """At 40 the cap bound 2/8 in Arm 0 and 4/8 in Arm 1. A cap that binds harder on
    the treatment than the control makes the resolve-rate delta uninterpretable."""
    assert solver.DEFAULT_MAX_TURNS == 100


def test_turns_and_assistant_messages_are_separate_fields():
    t = solver.Trajectory(instance_id="x", arm="arm1")
    assert hasattr(t, "turns") and hasattr(t, "assistant_messages")
    assert t.turns == 0 and t.assistant_messages == 0


def test_trajectory_records_cap_context():
    """`stop_reason` alone required string-matching to detect the confound."""
    t = solver.Trajectory(instance_id="x", arm="arm1")
    for f in ("cap_bound", "max_turns"):
        assert hasattr(t, f), f


def test_cap_bound_appears_in_dict():
    t = solver.Trajectory(instance_id="x", arm="arm1", turns=100, max_turns=100,
                          cap_bound=True)
    assert t.as_dict()["cap_bound"] is True


# --------------------------------------------------------------------------
# Denial attribution
# --------------------------------------------------------------------------

def test_denial_names_the_offending_command():
    """`cd /repo && python - <<EOF` is denied for the python, not the cd."""
    d = classify("cd /testbed && python - <<'EOF'\nprint(1)\nEOF\n", ARM1)
    assert d.outcome.value == "denied"
    assert d.denied_by == "python"


@pytest.mark.parametrize("cmd,culprit", [
    ("python3 -c 'x'", "python3"),
    ("ls | xargs rm", "xargs"),
    ("cd /testbed && pip install regex", "pip"),
    ("git log --oneline", "git"),
])
def test_denial_attribution(cmd, culprit):
    assert classify(cmd, ARM1).denied_by == culprit


def test_denied_by_in_record():
    rec = classify("cd /testbed && python3 -c 'x'", ARM1).as_record()
    assert rec["denied_by"] == "python3"


def test_summary_credits_only_the_culprit(tmp_path):
    """The old behaviour credited every argv0 in a denied record, which put `cd` and
    `grep` near the top of a metric meant to name what the restriction blocks."""
    log = tmp_path / "f.jsonl"
    for cmd in ("cd /testbed && python - <<'EOF'\nx\nEOF\n",
                "cd /testbed && python3 -c 'y'",
                "cd /testbed && grep pat f"):
        flowlog.write(classify(cmd, ARM1), log)
    s = flowlog.summarize(flowlog.read(log))
    assert s["escape_targets"] == {"python": 1, "python3": 1}
    assert "cd" not in s["escape_targets"]
    assert "grep" not in s["escape_targets"]


def test_legacy_records_are_marked_not_guessed(tmp_path):
    """A record with no `denied_by` predates the fix. Mark it so a mixed corpus is
    visibly mixed rather than quietly wrong."""
    log = tmp_path / "f.jsonl"
    log.write_text(json.dumps({
        "outcome": "denied", "parse_ok": True,
        "actions": [{"verb": "execute", "argv0": "cd"}],
    }) + "\n")
    s = flowlog.summarize(flowlog.read(log))
    assert s["escape_targets"] == {"<unattributed>": 1}


# --------------------------------------------------------------------------
# Classifier fingerprint
# --------------------------------------------------------------------------

def test_fingerprint_is_stable_and_short():
    a, b = version.classifier_fingerprint(), version.classifier_fingerprint()
    assert a == b and len(a) == 12


def test_fingerprint_stamped_on_every_record():
    assert classify("ls", ARM0).as_record()["cls"] == version.classifier_fingerprint()


def test_same_fingerprint_is_comparable():
    ok, why = version.comparable("abc", "abc")
    assert ok and why == ""


def test_different_fingerprints_are_not_comparable():
    """Arm 0 and Arm 1 ran days apart on different classifier versions and nothing
    recorded it. Arm 0's log had zero `read` verbs because of a bug fixed in between."""
    ok, why = version.comparable("abc", "def")
    assert not ok
    assert "not comparable" in why
    assert "Resolve rates still are" in why


def test_missing_fingerprints_ignored():
    """Legacy runs have no stamp; one stamped run plus blanks is still one version."""
    assert version.comparable("abc", "", "")[0] is True


def test_version_block_shape():
    b = version.version_block()
    for k in ("dfc_version", "classifier_fingerprint", "fingerprinted_modules"):
        assert k in b
    assert "classifier.py" in b["fingerprinted_modules"]


def test_model_module_not_fingerprinted():
    """model.py defines vocabulary, not decisions. Churn there should not invalidate a
    comparison."""
    assert "model.py" not in version.FINGERPRINTED
