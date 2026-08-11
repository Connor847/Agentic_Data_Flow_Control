"""Stratified instance sampling (§7, E3).

The previous run used `list(ds)[:5]` - the first five of Lite, all from one repo, no
randomization. That is not a sample, and it is the reason the results said nothing
about anything. This module stratifies across repositories with a fixed seed so the
selection is reproducible and defensible.

It also reports the **gold-patch size distribution** for the chosen subset, which §7
says to measure before committing compute: if the median patch touches 40+ lines across
3 files, the restricted arm's full-rewrite tax may drive it near zero and the
comparison degenerates before it starts.
"""

from __future__ import annotations

import random
import re
from collections import defaultdict
from dataclasses import dataclass

DATASET = "princeton-nlp/SWE-bench_Lite"
SPLIT = "test"
SEED = 20260811


def repo_of(instance_id: str) -> str:
    return instance_id.split("__", 1)[0] if "__" in instance_id else instance_id


def load(dataset: str = DATASET, split: str = SPLIT) -> list[dict]:
    from datasets import load_dataset
    return list(load_dataset(dataset, split=split))


def stratified(instances: list[dict], n: int, seed: int = SEED) -> list[dict]:
    """Round-robin across repos, sampling within each repo with a fixed seed.

    Round-robin rather than proportional allocation: at n=8 proportional sampling
    collapses onto the two largest repos, which reproduces exactly the single-repo
    problem this is meant to fix.
    """
    by_repo: dict[str, list[dict]] = defaultdict(list)
    for inst in instances:
        by_repo[repo_of(inst["instance_id"])].append(inst)

    rng = random.Random(seed)
    for repo in by_repo:
        by_repo[repo].sort(key=lambda i: i["instance_id"])
        rng.shuffle(by_repo[repo])

    repos = sorted(by_repo)
    rng.shuffle(repos)

    picked: list[dict] = []
    round_i = 0
    while len(picked) < n:
        progressed = False
        for repo in repos:
            if len(picked) >= n:
                break
            if round_i < len(by_repo[repo]):
                picked.append(by_repo[repo][round_i])
                progressed = True
        if not progressed:
            break
        round_i += 1
    return picked


# --------------------------------------------------------------------------
# Gold-patch size distribution (§7)
# --------------------------------------------------------------------------

_HUNK = re.compile(r"^@@ ", re.M)
_FILE = re.compile(r"^diff --git ", re.M)
_ADDED = re.compile(r"^\+(?!\+\+)", re.M)
_REMOVED = re.compile(r"^-(?!--)", re.M)


@dataclass
class PatchSize:
    instance_id: str
    files: int
    hunks: int
    added: int
    removed: int

    @property
    def touched(self) -> int:
        return self.added + self.removed


def patch_size(instance: dict) -> PatchSize:
    patch = instance.get("patch", "") or ""
    return PatchSize(
        instance_id=instance["instance_id"],
        files=len(_FILE.findall(patch)),
        hunks=len(_HUNK.findall(patch)),
        added=len(_ADDED.findall(patch)),
        removed=len(_REMOVED.findall(patch)),
    )


def _median(xs: list[int]) -> float:
    if not xs:
        return 0.0
    s = sorted(xs)
    mid = len(s) // 2
    return float(s[mid]) if len(s) % 2 else (s[mid - 1] + s[mid]) / 2


def size_report(instances: list[dict]) -> dict:
    sizes = [patch_size(i) for i in instances]
    touched = [s.touched for s in sizes]
    files = [s.files for s in sizes]
    return {
        "n": len(sizes),
        "median_lines_touched": _median(touched),
        "max_lines_touched": max(touched) if touched else 0,
        "median_files": _median(files),
        "max_files": max(files) if files else 0,
        # §7's warning threshold: a median of 40+ lines across 3 files means the
        # restricted arm's full-rewrite tax may degenerate the comparison.
        "degeneracy_risk": bool(_median(touched) >= 40 and _median(files) >= 3),
        "per_instance": [s.__dict__ | {"touched": s.touched} for s in sizes],
    }


def pick(n: int = 8, dataset: str = DATASET, split: str = SPLIT,
         seed: int = SEED) -> tuple[list[dict], dict]:
    instances = load(dataset, split)
    chosen = stratified(instances, n, seed)
    return chosen, size_report(chosen)


__all__ = ["pick", "stratified", "size_report", "patch_size", "repo_of",
           "DATASET", "SPLIT", "SEED"]
