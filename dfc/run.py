"""End-to-end runner: sample -> solve -> evaluate -> report.

    python -m dfc.run preflight
    python -m dfc.run solve --n 8 --arm arm0
    python -m dfc.run evaluate --run-id dfc-arm0-001
    python -m dfc.run report   --run-id dfc-arm0-001

`solve` and `evaluate` are separate commands on purpose. Solving costs subscription
quota; evaluation costs only local Docker time. Keeping them apart means a mistake in
the eval step never forces you to pay for the trajectories again.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
import time
from dataclasses import asdict
from pathlib import Path

from . import container as container_mod
from . import flowlog, sample, solver
from .policy import ARMS

MODEL_NAME = "dfc-sonnet5"
RUNS_DIR = Path(os.environ.get("DFC_RUNS_DIR", "runs"))


# --------------------------------------------------------------------------
# Failure taxonomy (E2)
# --------------------------------------------------------------------------

TAXONOMY = [
    "resolved",
    "empty-patch",            # agent produced no diff at all
    "patch-malformed",        # harness could not apply the diff
    "applied-broke-P2P",      # applied, but previously-passing tests now fail
    "applied-F2P-unfixed",    # applied cleanly, target tests still fail
    "harness-error",          # our bug, not the model's
    "turn-limit",             # ran out of turns
    "blocked-tool-deadlock",  # denials dominated; agent could not make progress
    "rewrite-infidelity",     # a lossy canonical rewrite is implicated (D4)
    "unknown",
]


def classify_failure(traj: dict, report: dict | None, denial_rate: float,
                     fidelity_hit: bool) -> str:
    """One label per instance. §4 showed 5 instances spanning 4 categories and a CSV
    that recorded none of them."""
    if traj.get("error"):
        return "harness-error"
    if not traj.get("model_patch"):
        return "turn-limit" if traj.get("stop_reason") == "turn-limit" else "empty-patch"
    if report is None:
        return "harness-error"
    if report.get("resolved"):
        return "resolved"
    if not report.get("patch_successfully_applied", False):
        return "patch-malformed"

    tests = report.get("tests_status", {}) or {}
    p2p_failing = tests.get("PASS_TO_PASS", {}).get("failure", [])
    f2p_failing = tests.get("FAIL_TO_PASS", {}).get("failure", [])
    if p2p_failing:
        # §10: `patch --fuzz=5` will apply a wrong patch in the wrong place and report
        # success. Always check PASS_TO_PASS regressions, not just FAIL_TO_PASS.
        return "rewrite-infidelity" if fidelity_hit else "applied-broke-P2P"
    if f2p_failing:
        if denial_rate > 0.25:
            return "blocked-tool-deadlock"
        return "rewrite-infidelity" if fidelity_hit else "applied-F2P-unfixed"
    return "unknown"


# --------------------------------------------------------------------------
# preflight
# --------------------------------------------------------------------------

def cmd_preflight(args) -> int:
    """Check everything that costs nothing to check, before anything that costs quota."""
    ok = True

    print(f"python            : {sys.version.split()[0]}")
    if sys.version_info[:2] != (3, 11):
        print("  ! the guide flags 3.14 as a swebench compatibility risk; 3.11 is the "
              "tested version")

    present, info = container_mod.docker_available()
    print(f"docker            : {'ok - ' + info if present else 'MISSING - ' + info}")
    ok &= present

    try:
        import claude_agent_sdk  # noqa: F401
        print("claude-agent-sdk  : ok")
    except ImportError as exc:
        print(f"claude-agent-sdk  : MISSING ({exc})")
        ok = False

    has_oauth = bool(os.environ.get("CLAUDE_CODE_OAUTH_TOKEN"))
    has_key = bool(os.environ.get("ANTHROPIC_API_KEY"))
    if has_oauth and has_key:
        print("auth              : ! both CLAUDE_CODE_OAUTH_TOKEN and ANTHROPIC_API_KEY "
              "are set; set only one")
    elif has_oauth:
        print("auth              : ok - subscription OAuth token")
    elif has_key:
        print("auth              : ok - API key (usage-billed, not your subscription)")
    else:
        print("auth              : MISSING - run `claude setup-token` and export "
              "CLAUDE_CODE_OAUTH_TOKEN")
        ok = False

    try:
        import tree_sitter_bash  # noqa: F401
        from .classifier import classify
        from .policy import ARM1
        d = classify("cat setup.py", ARM1)
        print(f"classifier        : ok - {d.outcome.value} -> {d.updated_command!r}")
    except Exception as exc:
        print(f"classifier        : BROKEN ({exc})")
        ok = False

    try:
        import datasets  # noqa: F401
        print("datasets          : ok")
    except ImportError:
        print("datasets          : MISSING (needed for sampling)")
        ok = False

    try:
        import swebench  # noqa: F401
        print("swebench          : ok")
    except ImportError:
        print("swebench          : MISSING (needed for `evaluate`)")
        ok = False

    print("\npreflight:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


# --------------------------------------------------------------------------
# solve
# --------------------------------------------------------------------------

async def _solve_all(instances, arm, run_dir: Path, args) -> list[dict]:
    trajectories: list[dict] = []
    for i, inst in enumerate(instances, 1):
        iid = inst["instance_id"]
        print(f"[{i}/{len(instances)}] {iid} ... ", end="", flush=True)
        os.environ["DFC_FLOW_LOG"] = str(run_dir / "flow_log.jsonl")
        os.environ["DFC_INSTANCE_ID"] = iid

        cont = container_mod.InstanceContainer(
            instance_id=iid,
            platform=args.platform,
            network_none=args.network_none,
        )
        started = time.time()
        try:
            cont.start()
        except Exception as exc:
            print(f"container failed: {exc}")
            trajectories.append({
                "instance_id": iid, "arm": arm.name, "model_patch": "",
                "error": f"container: {exc}", "stop_reason": "harness-error",
                "turns": 0, "duration_s": time.time() - started,
                "tool_stats": {}, "dirty_paths": [], "final_text": "",
            })
            continue

        try:
            traj = await solver.solve(
                inst, cont, arm,
                max_turns=args.max_turns,
                include_hints=args.hints,
                settings_dir=str(Path.cwd()) if args.project_settings else None,
                command_timeout=args.command_timeout,
            )
            d = traj.as_dict()
            stats = d.get("tool_stats", {})
            print(f"{d['turns']} turns, {stats.get('calls', 0)} cmds, "
                  f"{stats.get('denials', 0)} denied, "
                  f"{len(d['model_patch'])}b patch"
                  + (f", ERROR {d['error']}" if d["error"] else ""))
            trajectories.append(d)
        finally:
            cont.stop()

        (run_dir / "trajectories.json").write_text(json.dumps(trajectories, indent=2))
    return trajectories


def cmd_solve(args) -> int:
    arm = solver.arm_from_name(args.arm)
    run_id = args.run_id or f"dfc-{arm.name}-{time.strftime('%Y%m%d-%H%M%S')}"
    run_dir = RUNS_DIR / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    instances, sizes = sample.pick(args.n, args.dataset, args.split, args.seed)
    (run_dir / "sample.json").write_text(json.dumps({
        "run_id": run_id, "arm": arm.name, "model": solver.MODEL,
        "dataset": args.dataset, "split": args.split, "seed": args.seed,
        "max_turns": args.max_turns,
        "instance_ids": [i["instance_id"] for i in instances],
        "gold_patch_sizes": sizes,
    }, indent=2))

    print(f"run       : {run_id}")
    print(f"arm       : {arm.name} (mode={arm.mode})")
    print(f"model     : {solver.MODEL}")
    print(f"instances : {len(instances)} across "
          f"{len({sample.repo_of(i['instance_id']) for i in instances})} repos")
    print(f"gold patch: median {sizes['median_lines_touched']:.0f} lines, "
          f"{sizes['median_files']:.0f} files"
          + ("  ! degeneracy risk (§7)" if sizes["degeneracy_risk"] else ""))
    print()

    trajectories = asyncio.run(_solve_all(instances, arm, run_dir, args))

    predictions = [
        {"instance_id": t["instance_id"], "model_name_or_path": MODEL_NAME,
         "model_patch": t["model_patch"]}
        for t in trajectories
    ]
    (run_dir / "predictions.json").write_text(json.dumps(predictions, indent=2))
    (run_dir / "trajectories.json").write_text(json.dumps(trajectories, indent=2))

    print(f"\nwrote {run_dir}/predictions.json")
    log = run_dir / "flow_log.jsonl"
    if log.exists():
        print(json.dumps(flowlog.summarize(flowlog.read(log)), indent=2))
    else:
        print("! flow log is empty - the Phase 2 acceptance criterion requires it to "
              "be non-empty")
    print(f"\nnext: python -m dfc.run evaluate --run-id {run_id}")
    return 0


# --------------------------------------------------------------------------
# evaluate
# --------------------------------------------------------------------------

def cmd_evaluate(args) -> int:
    run_dir = RUNS_DIR / args.run_id
    preds = run_dir / "predictions.json"
    if not preds.exists():
        print(f"no predictions at {preds}", file=sys.stderr)
        return 1
    meta = json.loads((run_dir / "sample.json").read_text())

    cmd = [
        sys.executable, "-m", "swebench.harness.run_evaluation",
        "--dataset_name", meta["dataset"],
        "--split", meta["split"],
        "--predictions_path", str(preds),
        "--max_workers", str(args.max_workers),
        "--run_id", args.run_id,
        "--cache_level", args.cache_level,
        "--instance_ids", *meta["instance_ids"],
    ]
    print(" ".join(cmd), "\n")
    proc = subprocess.run(cmd)
    return proc.returncode


# --------------------------------------------------------------------------
# report
# --------------------------------------------------------------------------

def _instance_report(run_id: str, instance_id: str) -> dict | None:
    base = Path("logs/run_evaluation") / run_id / MODEL_NAME / instance_id / "report.json"
    if not base.exists():
        return None
    try:
        data = json.loads(base.read_text())
        return data.get(instance_id, data)
    except Exception:
        return None


def cmd_report(args) -> int:
    run_dir = RUNS_DIR / args.run_id
    trajectories = json.loads((run_dir / "trajectories.json").read_text())
    log_path = run_dir / "flow_log.jsonl"
    records = list(flowlog.read(log_path)) if log_path.exists() else []

    by_instance: dict[str, list[dict]] = {}
    for rec in records:
        by_instance.setdefault(rec.get("instance_id", ""), []).append(rec)

    rows = []
    for traj in trajectories:
        iid = traj["instance_id"]
        recs = by_instance.get(iid, [])
        denials = sum(1 for r in recs if r["outcome"] == "denied")
        rewrites = sum(1 for r in recs if r["outcome"] == "rewritten")
        passthrough = sum(1 for r in recs if r["outcome"] == "passthrough")
        observed = sum(1 for r in recs if r["outcome"] == "observed")
        gated = denials + rewrites + passthrough
        fidelity_hit = any(r.get("fidelity_risk") for r in recs)
        denial_rate = (denials / gated) if gated else 0.0

        report = _instance_report(args.run_id, iid)
        # dfc_observed: the verbs actually seen, from the flow log. This column was
        # empty in every row of the previous run - there was no detector behind the
        # dependent variable (§4.1).
        verbs: dict[str, int] = {}
        for r in recs:
            for a in r.get("actions", []):
                verbs[a["verb"]] = verbs.get(a["verb"], 0) + 1

        sel = [a["selectivity"] for r in recs for a in r.get("actions", [])
               if a.get("selectivity") is not None]

        rows.append({
            "instance_id": iid,
            "arm": traj["arm"],
            "resolved": bool(report and report.get("resolved")),
            "patch_applied": bool(report and report.get("patch_successfully_applied")),
            "failure_class": classify_failure(traj, report, denial_rate, fidelity_hit),
            "turns": traj.get("turns", 0),
            "commands": len(recs),
            "dfc_observed": "|".join(f"{k}:{v}" for k, v in sorted(verbs.items())),
            "passthrough": passthrough,
            "rewritten": rewrites,
            "denied": denials,
            "observed": observed,
            "coverage": round((passthrough + rewrites) / gated, 4) if gated else "",
            "denial_rate": round(denial_rate, 4),
            "fidelity_risk": fidelity_hit,
            "trifecta": any(r.get("trifecta") for r in recs),
            "cumulative_selectivity": round(sum(sel), 4) if sel else "",
            "patch_bytes": len(traj.get("model_patch", "")),
            "duration_s": round(traj.get("duration_s", 0), 1),
            "stop_reason": traj.get("stop_reason", ""),
            "error": traj.get("error", ""),
        })

    import csv
    out = run_dir / "dfc_report.csv"
    with out.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()) if rows else ["instance_id"])
        w.writeheader()
        w.writerows(rows)

    resolved = sum(r["resolved"] for r in rows)
    empty_observed = sum(1 for r in rows if not r["dfc_observed"])
    print(f"wrote {out}")
    print(f"resolved        : {resolved}/{len(rows)}")
    print(f"empty dfc_observed cells: {empty_observed}  "
          f"(Phase 3 accepts only at 0)")
    print()
    for r in rows:
        print(f"  {r['instance_id']:38s} {r['failure_class']:22s} "
              f"turns={r['turns']:3d} cmds={r['commands']:3d} "
              f"cov={r['coverage']} denied={r['denied']}")
    if records:
        print()
        print(json.dumps(flowlog.summarize(records), indent=2))
    return 0


# --------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="dfc.run", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("preflight", help="check docker, auth and deps").set_defaults(
        func=cmd_preflight)

    s = sub.add_parser("solve", help="run trajectories")
    s.add_argument("--n", type=int, default=8)
    s.add_argument("--arm", default="arm0", choices=sorted(set(ARMS)))
    s.add_argument("--run-id", default=None)
    s.add_argument("--dataset", default=sample.DATASET)
    s.add_argument("--split", default=sample.SPLIT)
    s.add_argument("--seed", type=int, default=sample.SEED)
    s.add_argument("--max-turns", type=int, default=40)
    s.add_argument("--command-timeout", type=int, default=300)
    s.add_argument("--platform", default=container_mod.DEFAULT_PLATFORM)
    s.add_argument("--hints", action="store_true",
                   help="include hints_text (off by default: it is not available in a "
                        "realistic setting and inflates the baseline)")
    s.add_argument("--network-none", action="store_true",
                   help="Phase 2b: empty netns inside the container")
    s.add_argument("--project-settings", action="store_true",
                   help="load .claude/settings.json via setting_sources=['project']")
    s.set_defaults(func=cmd_solve)

    e = sub.add_parser("evaluate", help="official swebench harness")
    e.add_argument("--run-id", required=True)
    e.add_argument("--max-workers", type=int, default=4)
    e.add_argument("--cache-level", default="env")
    e.set_defaults(func=cmd_evaluate)

    r = sub.add_parser("report", help="join results into dfc_report.csv")
    r.add_argument("--run-id", required=True)
    r.set_defaults(func=cmd_report)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
