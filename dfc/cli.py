"""Command-line front end.

    python -m dfc.cli classify 'grep pat f > out' --arm arm1
    python -m dfc.cli summarize runs/arm1/flow_log.jsonl
    python -m dfc.cli mine SWE-bench_Pro-os/traj --arm arm1
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

from . import flowlog
from .classifier import classify
from .model import Outcome
from .policy import ARMS


def cmd_classify(args) -> int:
    arm = ARMS[args.arm]
    d = classify(args.command, arm)
    if args.json:
        print(json.dumps(d.as_record(), indent=2))
        return 0
    print(f"outcome : {d.outcome.value}")
    if d.updated_command:
        print(f"rewrite : {d.updated_command}")
    if d.reason:
        print(f"reason  : {d.reason}")
    print(f"label   : {d.derived_label()}")
    print(f"trifecta: {d.trifecta()}")
    for a in d.actions:
        tgts = ", ".join(t.value + ("" if t.extractable else " [OPAQUE]") for t in a.targets)
        sink = f" -> {a.sink.value}" if a.sink else ""
        flag = "  !fidelity" if a.fidelity_risk else ""
        print(f"  {a.verb.value:9s}{sink:12s} {tgts}{flag}")
    return 0 if d.allowed else 1


def cmd_summarize(args) -> int:
    path = Path(args.path)
    summary = flowlog.summarize(flowlog.read(path))
    print(json.dumps(summary, indent=2))
    return 0


#: Extract bash command strings from a SWE-agent / mini-swe-agent trajectory file.
_ACTION_KEYS = ("action", "command", "thought_action", "content")


def _commands_from_traj(path: Path):
    try:
        data = json.loads(path.read_text())
    except Exception:
        return
    stack = [data]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            for k, v in node.items():
                if k in _ACTION_KEYS and isinstance(v, str) and v.strip():
                    yield from _split_actions(v)
                else:
                    stack.append(v)
        elif isinstance(node, list):
            stack.extend(node)


_FENCE = re.compile(r"```(?:bash|sh)?\n(.*?)```", re.S)


def _split_actions(text: str):
    blocks = _FENCE.findall(text) or [text]
    for block in blocks:
        for line in block.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                yield line


def cmd_mine(args) -> int:
    """§7: the defensible coverage claim is empirical and weighted by *invocation
    frequency*, not by command identity. Command usage is heavily Zipfian."""
    arm = ARMS[args.arm]
    root = Path(args.path)
    files = sorted(root.rglob("*.json")) + sorted(root.rglob("*.traj"))
    outcomes: Counter[str] = Counter()
    argv0s: Counter[str] = Counter()
    denied: Counter[str] = Counter()
    n_files = 0

    for f in files[: args.limit] if args.limit else files:
        cmds = list(_commands_from_traj(f))
        if not cmds:
            continue
        n_files += 1
        for c in cmds:
            d = classify(c, arm)
            outcomes[d.outcome.value] += 1
            for a in d.actions:
                if a.argv0:
                    argv0s[a.argv0] += 1
                    if d.outcome is Outcome.DENIED:
                        denied[a.argv0] += 1

    total = sum(outcomes.values())
    subsumed = outcomes["passthrough"] + outcomes["rewritten"]
    print(json.dumps({
        "files_with_commands": n_files,
        "invocations": total,
        "outcomes": dict(outcomes),
        "coverage_by_invocation": (subsumed / total) if total else None,
        "top_commands": argv0s.most_common(25),
        "top_denied": denied.most_common(25),
    }, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="dfc", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("classify", help="classify one shell command")
    c.add_argument("command")
    c.add_argument("--arm", default="arm1", choices=sorted(set(ARMS)))
    c.add_argument("--json", action="store_true")
    c.set_defaults(func=cmd_classify)

    s = sub.add_parser("summarize", help="metrics from a flow log")
    s.add_argument("path")
    s.set_defaults(func=cmd_summarize)

    m = sub.add_parser("mine", help="coverage over an existing trajectory corpus")
    m.add_argument("path")
    m.add_argument("--arm", default="arm1", choices=sorted(set(ARMS)))
    m.add_argument("--limit", type=int, default=0)
    m.set_defaults(func=cmd_mine)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
