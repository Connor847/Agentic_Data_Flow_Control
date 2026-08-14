"""Command census - the natural distribution of bash an agent reaches for.

§7 argues the coverage claim has to be empirical rather than enumerated: *"our N
primitives subsume X% of observed bash invocations across M trajectories"*, weighted by
**invocation frequency, not command identity**, because command usage is heavily
Zipfian. This module produces that denominator from the flow logs.

Two rules make the number honest:

* **Count the command as the agent wrote it, never the rewritten form.** The flow log's
  `command` field is what the model emitted; `executed`/`updated_command` is what we
  substituted. Counting the latter would measure our own canonicalization table.
* **Count every command node, not the first word.** `cd /repo && grep x f | head -20`
  is three invocations. Taking the first token would report `cd` and lose the rest, and
  `cd` is the single most frequent token in every arm.

Only **Arm 0** is a natural distribution. In the enforcing arms the agent is told the
permitted set up front (D12) and adapts to denials, so those counts describe behaviour
*under* the restriction - interesting, but a different quantity.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ArmCensus:
    arm: str
    shell_lines: int = 0
    invocations: int = 0
    unparseable: int = 0
    counts: Counter = field(default_factory=Counter)
    instances: set = field(default_factory=set)
    runs: list = field(default_factory=list)

    @property
    def distinct(self) -> int:
        return len(self.counts)

    def share(self, name: str) -> float:
        return self.counts[name] / self.invocations if self.invocations else 0.0

    def head_share(self, k: int) -> float:
        """Fraction of invocations covered by the k most frequent commands - the
        Zipfian claim in one number."""
        if not self.invocations:
            return 0.0
        return sum(v for _, v in self.counts.most_common(k)) / self.invocations

    def rows(self) -> list[dict]:
        out, cum = [], 0
        for rank, (name, n) in enumerate(self.counts.most_common(), 1):
            cum += n
            out.append({
                "rank": rank, "command": name, "invocations": n,
                "share": round(n / self.invocations, 5),
                "cumulative_share": round(cum / self.invocations, 5),
            })
        return out


def _arm_of(run_dir: Path) -> str:
    try:
        return json.loads((run_dir / "sample.json").read_text()).get("arm", "unknown")
    except OSError:
        return "unknown"


def collect(runs_dir: Path = Path("runs"), *, arms: set[str] | None = None
            ) -> dict[str, ArmCensus]:
    """Walk every flow log under `runs_dir` and tally command invocations by arm."""
    from .classifier import parse_commands

    out: dict[str, ArmCensus] = defaultdict(lambda: ArmCensus(arm=""))
    for log in sorted(runs_dir.glob("*/flow_log.jsonl")):
        arm = _arm_of(log.parent)
        key = arm.split("-")[0]
        if arms and key not in arms:
            continue
        c = out[key]
        c.arm = key
        c.runs.append(log.parent.name)
        for line in log.open():
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            c.shell_lines += 1
            if rec.get("instance_id"):
                c.instances.add(rec["instance_id"])
            cmds, ok, _ = parse_commands(rec.get("command", ""))
            if not ok:
                c.unparseable += 1
                continue
            for sc in cmds:
                if sc.argv0:
                    c.counts[sc.argv0] += 1
                    c.invocations += 1
    return dict(out)


def coverage_of(census: ArmCensus, admitted: set[str]) -> dict:
    """What fraction of observed invocations a candidate primitive set subsumes.

    This is the §7 number in its defensible form. Reported by invocation, and also by
    distinct command name so the gap between the two is visible - that gap *is* the
    Zipfian argument.
    """
    hit = sum(n for k, n in census.counts.items() if k in admitted)
    names = sum(1 for k in census.counts if k in admitted)
    return {
        "by_invocation": hit / census.invocations if census.invocations else 0.0,
        "by_distinct_name": names / census.distinct if census.distinct else 0.0,
        "uncovered_invocations": census.invocations - hit,
        "top_uncovered": [
            {"command": k, "invocations": n}
            for k, n in census.counts.most_common() if k not in admitted
        ][:15],
    }


def write_csv(censuses: dict[str, ArmCensus], path: Path) -> Path:
    import csv
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=[
            "arm", "rank", "command", "invocations", "share", "cumulative_share",
        ])
        w.writeheader()
        for arm in sorted(censuses):
            for row in censuses[arm].rows():
                w.writerow({"arm": arm, **row})
    return path


__all__ = ["collect", "coverage_of", "write_csv", "ArmCensus"]
