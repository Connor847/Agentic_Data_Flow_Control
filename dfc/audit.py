"""Rewrite audit - find the rewrites that are quietly wrong.

The `find` defect (D16) was found by accident, after it had already contaminated a
30-instance run. It was visible in the flow log the whole time: the agent asked for a
bounded, filtered search and we ran an unbounded listing of the entire filesystem.
Nothing was looking.

This module looks. It compares each command against what was actually executed and
flags structural differences that a faithful rewrite should never produce. It cannot
prove a rewrite correct - only a fixture-based equivalence test can do that - but it
reliably surfaces the class of defect that D16 belonged to: **information present in
the agent's command that is absent from ours**.

    python -m dfc.run audit --run-id <id>
    python -m dfc.run audit --run-id <id> --kind dropped-operand
"""

from __future__ import annotations

import re
import shlex
from collections import Counter, defaultdict
from dataclasses import dataclass, field

#: Flags whose removal changes *what is touched*, not merely how it is displayed.
#: Dropping one of these is the signature of the `find` defect.
SCOPE_FLAGS = re.compile(
    r"(?<![\w-])-(?:maxdepth|mindepth|i?name|path|newer|prune|type|size|mtime"
    r"|include|exclude|max-count|m)\b"
)

def _redirect_shape(cmd: str) -> list[str]:
    """Redirect kinds, from the AST rather than a regex.

    A regex gets this wrong in exactly the way this module exists to catch: `awk
    'NR>=25&&NR<=60'` contains `>=` and `<=`, which are comparisons, not redirections.
    Matching them produced 47 false findings - the single largest group - and would
    have buried the real defect underneath noise. §10 already says the classifier must
    parse the AST because `>` is a redirect, not a command; the same applies here.
    """
    from .classifier import parse_commands
    cmds, ok, _ = parse_commands(cmd)
    if not ok:
        return []
    return sorted(r.kind for sc in cmds for r in sc.redirects)


@dataclass
class Finding:
    kind: str
    severity: str          # "high" - likely wrong answer; "low" - cosmetic
    command: str
    executed: str
    detail: str
    instance_id: str = ""
    rules: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return dict(self.__dict__)


def _tokens(cmd: str) -> list[str]:
    try:
        return shlex.split(cmd)
    except ValueError:
        return cmd.split()


def _operands(cmd: str) -> set[str]:
    """Non-flag words: roughly, the things a command touches."""
    return {t for t in _tokens(cmd)
            if not t.startswith("-") and t not in (">", ">>", "<", "|", "&&", ";")}


def inspect(command: str, executed: str, *, instance_id: str = "",
            rules: list[str] | None = None) -> list[Finding]:
    """Structural comparison of what was asked for against what was run."""
    rules = rules or []
    out: list[Finding] = []
    if not executed or executed == command:
        return out

    def add(kind, sev, detail):
        out.append(Finding(kind, sev, command, executed, detail, instance_id, rules))

    # 1. Scope-narrowing flags present in the request, absent from what ran. This is
    #    exactly the `find -maxdepth 6 -iname regex` -> `ls -R /` defect.
    lost_scope = {m.group(0) for m in SCOPE_FLAGS.finditer(command)} - {
        m.group(0) for m in SCOPE_FLAGS.finditer(executed)
    }
    if lost_scope:
        add("dropped-scope-flag", "high",
            f"request narrowed by {sorted(lost_scope)}; executed form does not")

    # 2. Operands that vanished. A rewrite may rename a command, never forget a path.
    lost = _operands(command) - _operands(executed)
    # Rewrites legitimately drop the command name itself and literal patterns they
    # translate, so only flag things that look like paths or globs.
    lost = {t for t in lost if "/" in t or "." in t or any(g in t for g in "*?[")}
    if lost:
        add("dropped-operand", "high",
            f"operands present in the request and missing from the executed form: "
            f"{sorted(lost)}")

    # 3. Root-scope escalation: a bounded request became an unbounded one.
    if re.search(r"\bls -R /(?:\s|$)", executed) and not re.search(r"\bls -R /(?:\s|$)", command):
        add("scope-escalation", "high",
            "executed form recurses from / though the request did not")

    # 4. Redirect structure changed - output may be landing somewhere else.
    a, b = _redirect_shape(command), _redirect_shape(executed)
    if a != b:
        add("redirect-shape-changed", "low",
            f"redirect shape {a or 'none'} became {b or 'none'}")

    # 5. Output framing changes that are faithful in content but not in shape. `grep`
    #    over several files prefixes every line with its filename, which breaks any
    #    downstream parse.
    if re.search(r'grep\s+""', executed):
        files = [t for t in _tokens(executed) if not t.startswith("-") and t not in
                 ("grep", "", "cd", "&&", ";")]
        if len(files) > 1:
            add("multifile-grep-prefix", "low",
                "grep over several files prefixes each line with its filename")
    return out


def audit_records(records) -> tuple[list[Finding], Counter]:
    findings: list[Finding] = []
    kinds: Counter = Counter()
    for rec in records:
        if rec.get("outcome") != "rewritten":
            continue
        fs = inspect(
            rec.get("command", ""),
            rec.get("executed") or rec.get("updated_command", ""),
            instance_id=rec.get("instance_id", ""),
            rules=rec.get("rules_applied", []),
        )
        for f in fs:
            kinds[f.kind] += 1
        findings.extend(fs)
    return findings, kinds


def group_by_shape(findings: list[Finding]) -> dict[str, list[Finding]]:
    """Collapse findings onto the command name that triggered them, so a systemic
    defect shows up as one large group rather than fifty separate lines."""
    groups: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        head = (_tokens(f.command) or ["?"])[0]
        if head in ("cd", "sudo") and len(_tokens(f.command)) > 2:
            rest = [t for t in _tokens(f.command) if t not in ("cd", "&&", ";")]
            head = rest[1] if len(rest) > 1 else head
        groups[f"{f.kind}:{head}"].append(f)
    return dict(sorted(groups.items(), key=lambda kv: -len(kv[1])))


__all__ = ["inspect", "audit_records", "group_by_shape", "Finding", "SCOPE_FLAGS"]
