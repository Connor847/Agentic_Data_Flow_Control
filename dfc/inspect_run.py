"""Per-instance failure forensics.

`dfc_report.csv` says *which* category a failure fell into. This says *why*, by putting
the four things you need to read together on one screen:

1. the tests the harness actually ran and which ones failed
2. every command the agent issued, with exit codes
3. what the agent said it had achieved
4. what it actually changed

Point 3 against point 1 is the highest-yield comparison available. In the n=30 Arm 0
run, `mwaskom__seaborn-3407` closed with *"All 120 tests pass, no regressions"* and was
scored `applied-F2P-unfixed` - 120 PASS_TO_PASS did pass, and the one FAIL_TO_PASS test
the task existed to fix never ran in the agent's own testing. The agent was not
hallucinating; it was measuring the wrong thing.

    python -m dfc.run inspect --run-id <id> --instance mwaskom__seaborn-3407
    python -m dfc.run inspect --run-id <id> --failures      # triage every failure
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

MODEL_NAME = "dfc-sonnet5"


@dataclass
class InstanceView:
    instance_id: str
    run_id: str
    resolved: bool = False
    patch_applied: bool = False
    failure_class: str = ""
    stop_reason: str = ""
    turns: int = 0
    cap_bound: bool = False
    f2p_fail: list = field(default_factory=list)
    f2p_pass: list = field(default_factory=list)
    p2p_fail: list = field(default_factory=list)
    p2p_pass: list = field(default_factory=list)
    commands: list = field(default_factory=list)
    final_text: str = ""
    model_patch: str = ""
    dirty_paths: list = field(default_factory=list)
    error: str = ""

    @property
    def agent_claimed_success(self) -> bool:
        """Cheap heuristic over the agent's closing message. Used only to *rank*
        failures for reading, never as a result."""
        t = self.final_text.lower()
        claims = ("all tests pass", "tests pass", "no regressions", "all 1", "passes",
                  "fixed", "resolved", "works correctly", "successfully")
        return any(c in t for c in claims)

    @property
    def never_ran_target_test(self) -> bool:
        """Did the agent ever mention the failing target test in a command?

        The most actionable failure signature there is: the agent tested something,
        just not the thing the task was scored on."""
        if not self.f2p_fail:
            return False
        names = set()
        for t in self.f2p_fail:
            names.add(t.split("::")[-1])
            names.add(t.split("::")[0].split("/")[-1])
        blob = "\n".join(c["command"] for c in self.commands)
        return not any(n and n in blob for n in names)


def _eval_report(run_id: str, instance_id: str) -> dict | None:
    p = (Path("logs/run_evaluation") / run_id / MODEL_NAME / instance_id / "report.json")
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text())
        return data.get(instance_id, data)
    except Exception:
        return None


def test_output(run_id: str, instance_id: str, limit: int = 4000) -> str:
    """Raw harness test output - the ground truth on what failed."""
    p = (Path("logs/run_evaluation") / run_id / MODEL_NAME / instance_id
         / "test_output.txt")
    if not p.exists():
        return ""
    txt = p.read_text(errors="replace")
    return txt[-limit:] if len(txt) > limit else txt


def load(runs_dir: Path, run_id: str, instance_id: str) -> InstanceView | None:
    run = runs_dir / run_id
    trajs = {t["instance_id"]: t for t in
             json.loads((run / "trajectories.json").read_text())}
    if instance_id not in trajs:
        return None
    t = trajs[instance_id]

    v = InstanceView(instance_id=instance_id, run_id=run_id)
    v.turns = t.get("turns", 0)
    v.cap_bound = bool(t.get("cap_bound"))
    v.stop_reason = t.get("stop_reason", "")
    v.final_text = t.get("final_text", "")
    v.model_patch = t.get("model_patch", "")
    v.dirty_paths = t.get("dirty_paths", [])
    v.error = t.get("error", "")

    rep = _eval_report(run_id, instance_id)
    if rep:
        v.resolved = bool(rep.get("resolved"))
        v.patch_applied = bool(rep.get("patch_successfully_applied"))
        ts = rep.get("tests_status", {}) or {}
        v.f2p_fail = ts.get("FAIL_TO_PASS", {}).get("failure", [])
        v.f2p_pass = ts.get("FAIL_TO_PASS", {}).get("success", [])
        v.p2p_fail = ts.get("PASS_TO_PASS", {}).get("failure", [])
        v.p2p_pass = ts.get("PASS_TO_PASS", {}).get("success", [])

    log = run / "flow_log.jsonl"
    if log.exists():
        for line in log.open():
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            if r.get("instance_id") != instance_id:
                continue
            v.commands.append({
                "command": r.get("command", ""),
                "executed": r.get("executed", ""),
                "outcome": r.get("outcome", ""),
                "exit_code": r.get("exit_code"),
                "bytes": (r.get("return_channel") or {}).get("bytes"),
                "reason": r.get("reason", ""),
            })

    import csv
    csv_path = run / "dfc_report.csv"
    if csv_path.exists():
        for row in csv.DictReader(csv_path.open()):
            if row["instance_id"] == instance_id:
                v.failure_class = row.get("failure_class", "")
                break
    return v


def triage(runs_dir: Path, run_id: str) -> list[InstanceView]:
    """Every non-resolved instance, ordered so the most diagnosable read first."""
    run = runs_dir / run_id
    trajs = json.loads((run / "trajectories.json").read_text())
    views = []
    for t in trajs:
        v = load(runs_dir, run_id, t["instance_id"])
        if v and not v.resolved:
            views.append(v)

    def rank(v: InstanceView) -> tuple:
        # Agent claimed success but the target test never ran: the clearest signal.
        return (not (v.agent_claimed_success and v.never_ran_target_test),
                not v.agent_claimed_success,
                len(v.p2p_fail) == 0)

    return sorted(views, key=rank)


__all__ = ["load", "triage", "test_output", "InstanceView"]
