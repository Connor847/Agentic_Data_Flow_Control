"""`PreToolUse` hook - the gate and the instrumentation point (§6.1).

Reads the hook payload as JSON on stdin, prints a decision as JSON on stdout, exits 0.

Three outcomes map onto the hook protocol:

  passthrough -> permissionDecision "allow"
  rewritten   -> permissionDecision "allow" + hookSpecificOutput.updatedInput  (D2)
  denied      -> permissionDecision "deny"  + permissionDecisionReason

`updatedInput` is the mechanism that makes D2 possible: for `PreToolUse` it sits
directly under `hookSpecificOutput` and replaces the tool's arguments before the tool
runs, so `cat f` executes as `grep "" f` without the agent being told.

Two properties that make a `PreToolUse` deny the right enforcement point:

* a deny blocks the tool even under `bypassPermissions` / `--dangerously-skip-permissions`,
  so it is a policy the agent cannot route around;
* the SDK must be configured with `continueOnBlock: true` so the denial comes back to
  the model as a tool error it can adapt to. Without it a single reflexive `awk` ends
  the turn and kills an otherwise-viable trajectory, which would badly confound the
  cost measurement.

Configuration is by environment variable so a single hook binary serves every arm:

  DFC_ARM          arm0 | arm1 | arm2          (default arm1)
  DFC_FLOW_LOG     path to the JSONL flow log  (default ./flow_log.jsonl)
  DFC_INSTANCE_ID  SWE-bench instance under test
  DFC_STRICT       "0" to fail open on internal error (default: fail closed)
"""

from __future__ import annotations

import json
import os
import sys
import traceback

from . import flowlog
from .classifier import classify
from .model import Decision, Outcome
from .policy import ARMS, DENY_TOOLS

HOOK_EVENT = "PreToolUse"


def _out(decision: str, reason: str = "", updated: dict | None = None) -> dict:
    hso: dict = {
        "hookEventName": HOOK_EVENT,
        "permissionDecision": decision,
    }
    if reason:
        hso["permissionDecisionReason"] = reason
    if updated is not None:
        hso["updatedInput"] = updated
    return {"hookSpecificOutput": hso}


def _arm():
    name = os.environ.get("DFC_ARM", "arm1")
    if name not in ARMS:
        raise SystemExit(f"DFC_ARM={name!r} is not one of {sorted(set(ARMS))}")
    return ARMS[name]


def handle(payload: dict) -> dict:
    """Pure function: hook input -> hook output. Unit-testable without a subprocess."""
    arm = _arm()
    tool = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {}) or {}

    # Defence in depth (§6.1 layer 3). `disallowed_tools` in the SDK is the primary
    # block; if it was misconfigured, the built-in file tools would let the model read
    # and write without ever touching bash and the experiment would silently measure
    # nothing.
    if tool in DENY_TOOLS:
        return _out(
            "deny",
            f"`{tool}` bypasses the shell entirely. This experiment measures shell-level "
            "data flow, so all built-in file, search and subagent tools are denied. "
            "Use Bash.",
        )

    if tool not in ("Bash", "PowerShell"):
        return _out("allow")

    command = tool_input.get("command", "")
    if not command.strip():
        return _out("allow")

    decision = classify(
        command,
        arm,
        session_id=payload.get("session_id", ""),
        instance_id=os.environ.get("DFC_INSTANCE_ID", ""),
    )

    try:
        flowlog.write(decision)
    except Exception:  # logging must never change the agent's behaviour
        print(f"dfc: flow log write failed: {traceback.format_exc()}", file=sys.stderr)

    if decision.outcome is Outcome.DENIED:
        return _out("deny", decision.reason)

    if decision.outcome is Outcome.REWRITTEN:
        updated = dict(tool_input)
        updated["command"] = decision.updated_command
        # No permissionDecisionReason: the rewrite is silent by design (D2).
        return _out("allow", updated=updated)

    return _out("allow")


def main(argv: list[str] | None = None) -> int:
    raw = sys.stdin.read()
    try:
        payload = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError as exc:
        print(f"dfc: could not parse hook input: {exc}", file=sys.stderr)
        # Malformed hook input is our bug, not the agent's. Do not gate on it.
        print(json.dumps(_out("allow")))
        return 0

    try:
        result = handle(payload)
    except SystemExit:
        raise
    except Exception:
        strict = os.environ.get("DFC_STRICT", "1") != "0"
        arm_mode = ARMS.get(os.environ.get("DFC_ARM", "arm1"))
        observe = arm_mode is not None and arm_mode.mode == "observe"
        print(f"dfc: classifier error:\n{traceback.format_exc()}", file=sys.stderr)
        # D5: observe mode fails open so a classifier bug can never move the Arm 0
        # resolve rate. Enforcement fails closed.
        if observe or not strict:
            result = _out("allow")
        else:
            result = _out(
                "deny",
                "The command could not be classified, so it cannot be admitted. "
                "Rewrite it as separate, simpler commands.",
            )

    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
