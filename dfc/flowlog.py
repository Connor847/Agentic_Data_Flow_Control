"""Append-only flow log.

One JSONL record per Bash tool call, written by the hook on the way through. This is
the instrumentation point as well as the gate (§6.1) - the record is written whether
the command was allowed, rewritten or denied, because denials are a headline metric
(§7, "escape attempts per trajectory"), not an error path.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Iterable, Iterator

from .model import Decision, Outcome

DEFAULT_LOG = "flow_log.jsonl"


def log_path() -> Path:
    return Path(os.environ.get("DFC_FLOW_LOG", DEFAULT_LOG)).expanduser()


def write(decision: Decision, path: Path | None = None) -> None:
    p = path or log_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as fh:
        fh.write(decision.as_json() + "\n")


def read(path: Path | None = None) -> Iterator[dict]:
    p = path or log_path()
    if not p.exists():
        return iter(())

    def _gen() -> Iterator[dict]:
        with p.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    yield json.loads(line)

    return _gen()


# --------------------------------------------------------------------------
# Metrics (§7)
# --------------------------------------------------------------------------

def summarize(records: Iterable[dict]) -> dict:
    """The numbers the paper needs, computed straight off the log.

    `coverage` is the §7 coverage claim in its defensible form: the fraction of
    *invocations* - not of distinct command names - that the primitive set subsumes.
    Command usage is heavily Zipfian, so weighting by invocation frequency is the
    difference between a real result and coverage of our own imagination.
    """
    counts = {o.value: 0 for o in Outcome}
    total = 0
    fidelity = 0
    trifecta = 0
    parse_fail = 0
    denied_argv0: dict[str, int] = {}
    verb_counts: dict[str, int] = {}
    selectivity_sum = 0.0
    selectivity_n = 0

    for rec in records:
        total += 1
        counts[rec["outcome"]] = counts.get(rec["outcome"], 0) + 1
        fidelity += bool(rec.get("fidelity_risk"))
        trifecta += bool(rec.get("trifecta"))
        parse_fail += not rec.get("parse_ok", True)
        for a in rec.get("actions", []):
            verb_counts[a["verb"]] = verb_counts.get(a["verb"], 0) + 1
            if a.get("selectivity") is not None:
                selectivity_sum += a["selectivity"]
                selectivity_n += 1
        if rec["outcome"] == Outcome.DENIED.value:
            # Credit only the command that caused the denial. Counting every argv0 in
            # the record credited `cd` for `cd /repo && python - <<EOF`, which inverted
            # the ranking this metric exists to produce.
            culprit = rec.get("denied_by")
            if not culprit:
                # Pre-2026-08-11 records have no `denied_by`. Mark them rather than
                # guessing, so a mixed corpus is visibly mixed.
                culprit = "<unattributed>"
            denied_argv0[culprit] = denied_argv0.get(culprit, 0) + 1

    subsumed = counts.get(Outcome.PASSTHROUGH.value, 0) + counts.get(Outcome.REWRITTEN.value, 0)
    gated = total - counts.get(Outcome.OBSERVED.value, 0)

    return {
        "invocations": total,
        "outcomes": counts,
        # D2: report the three populations separately. `rewritten` sizes the
        # translation layer; `denied` is the restriction itself.
        "coverage_by_invocation": (subsumed / gated) if gated else None,
        "escape_attempts": counts.get(Outcome.DENIED.value, 0),
        "escape_targets": dict(sorted(denied_argv0.items(), key=lambda kv: -kv[1])),
        "fidelity_risk_records": fidelity,
        "trifecta_records": trifecta,
        "parse_failures": parse_fail,
        "verbs": verb_counts,
        "mean_selectivity": (selectivity_sum / selectivity_n) if selectivity_n else None,
        "cumulative_selectivity": selectivity_sum or None,
    }


__all__ = ["write", "read", "summarize", "log_path", "DEFAULT_LOG"]
