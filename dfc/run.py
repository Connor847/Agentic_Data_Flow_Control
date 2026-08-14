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
from . import audit, census, flowlog, inspect_run, sample, solver, version
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

def _check_auth() -> bool:
    """Validate the token's *shape*, not just its presence.

    A token pasted from a wrapped terminal carries an embedded newline. The CLI then
    fails with `Invalid Authorization header value ... it contains a line break`, the
    model gets no tools, and every trajectory returns one turn, zero commands and zero
    cost - which looks exactly like a harness bug and is not one.
    """
    oauth = os.environ.get("CLAUDE_CODE_OAUTH_TOKEN", "")
    key = os.environ.get("ANTHROPIC_API_KEY", "")

    if oauth and key:
        print("auth              : ! both CLAUDE_CODE_OAUTH_TOKEN and ANTHROPIC_API_KEY "
              "are set; set only one")

    for name, value in (("CLAUDE_CODE_OAUTH_TOKEN", oauth), ("ANTHROPIC_API_KEY", key)):
        if not value:
            continue
        bad = [c for c in ("\n", "\r", "\t", " ") if c in value]
        if bad or value != value.strip():
            where = value.find("\n") if "\n" in value else value.find(" ")
            print(f"auth              : BROKEN - {name} contains whitespace"
                  f"{f' at character {where}' if where >= 0 else ''}. "
                  f"({len(value)} chars, {len(value.splitlines())} lines)")
            print("                    fix: export "
                  f"{name}=$(claude setup-token | tr -d '[:space:]')")
            return False

    if oauth:
        if not oauth.startswith("sk-ant-"):
            print(f"auth              : ! CLAUDE_CODE_OAUTH_TOKEN does not start with "
                  f"sk-ant- (starts {oauth[:8]!r})")
        print(f"auth              : ok - subscription OAuth token ({len(oauth)} chars, "
              "single line)")
        return True
    if key:
        print("auth              : ok - API key (usage-billed, NOT your subscription)")
        return True

    # No environment token is not a failure. The CLI has its own stored credential from
    # `claude login`, and the SDK spawns that CLI. An env token is one way to
    # authenticate, not the only one - and it is the way that breaks when pasted.
    print("auth              : no env token - the Claude Code CLI's own login will be "
          "used if you are signed in")
    print("                    `python -m dfc.run doctor` is the ground truth here")
    return True


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

    ok &= _check_auth()

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
    if ok:
        print("next: python -m dfc.run doctor   (one live call - proves auth and MCP "
              "wiring before you spend quota on 8 instances)")
    return 0 if ok else 1


# --------------------------------------------------------------------------
# doctor - one live round trip, no Docker
# --------------------------------------------------------------------------

async def _doctor() -> tuple[bool, str]:
    """Prove auth *and* MCP tool wiring with a single cheap call.

    Deliberately does not touch Docker. If this passes and a real run still shows zero
    commands, the problem is the container layer, not the SDK.
    """
    from claude_agent_sdk import (ClaudeAgentOptions, ClaudeSDKClient,
                                  create_sdk_mcp_server, tool as sdk_tool)

    seen: list[str] = []
    stderr_lines: list[str] = []

    @sdk_tool("ping", "Return the word PONG. Call this exactly once.", {"note": str})
    async def _ping(args):
        seen.append(args.get("note", ""))
        return {"content": [{"type": "text", "text": "PONG"}]}

    server = create_sdk_mcp_server(name="doctor", version="0.1.0", tools=[_ping])
    options = ClaudeAgentOptions(
        model=solver.MODEL,
        system_prompt="You are a test harness. Use the tools you are given.",
        mcp_servers={"doctor": server},
        allowed_tools=["mcp__doctor__ping"],
        disallowed_tools=solver.DISALLOWED,
        permission_mode="bypassPermissions",
        max_turns=3,
        setting_sources=[],
        strict_mcp_config=True,
        stderr=lambda line: stderr_lines.append(line),
    )

    text = ""
    async with ClaudeSDKClient(options=options) as client:
        await client.query("Call the ping tool once with note='hello', then reply DONE.")
        async for message in client.receive_response():
            if type(message).__name__ == "AssistantMessage":
                for block in getattr(message, "content", []) or []:
                    if getattr(block, "text", None):
                        text = block.text
    return bool(seen), (text or "\n".join(stderr_lines[-5:]))


def cmd_doctor(args) -> int:
    try:
        called, text = asyncio.run(_doctor())
    except Exception as exc:
        print(f"doctor: FAILED to start a session\n  {type(exc).__name__}: {exc}")
        return 1

    if called:
        print("doctor: PASS - the model authenticated and called the MCP tool")
        return 0

    print("doctor: FAIL - session ran but the tool was never called")
    print(f"  model said: {text[:400]}")
    if "auth" in text.lower() or "token" in text.lower():
        print("  -> this is an auth problem, not a tool-wiring problem. "
              "Re-export the token on a single line.")
    return 1


# --------------------------------------------------------------------------
# solve
# --------------------------------------------------------------------------

async def _solve_all(instances, arm, run_dir: Path, args) -> list[dict]:
    # Resume: a long run will be interrupted - docker hiccup, rate limit, laptop
    # sleep - and without this a single failure at instance 200 discards 200
    # trajectories. Only trajectories that actually ran commands are kept; a
    # harness-error record is retried rather than cemented.
    trajectories: list[dict] = []
    done: set[str] = set()
    existing = run_dir / "trajectories.json"
    if existing.exists():
        try:
            prior = json.loads(existing.read_text())
        except json.JSONDecodeError:
            prior = []
        for t in prior:
            if t.get("tool_stats", {}).get("calls", 0) > 0:
                trajectories.append(t)
                done.add(t["instance_id"])
        if done:
            print(f"resuming  : {len(done)} trajectory(ies) already complete, "
                  f"{len(instances) - len(done)} to go\n")

    dead = 0
    for i, inst in enumerate(instances, 1):
        iid = inst["instance_id"]
        if iid in done:
            continue
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

            # A trajectory that never ran a command is not a model failure - it is a
            # broken session. Reporting it as a clean result is how a bad auth token
            # burns a whole run before anyone notices.
            if stats.get("calls", 0) == 0:
                d["error"] = d["error"] or _zero_call_reason(d)
                d["stop_reason"] = "harness-error"
                dead += 1
            else:
                dead = 0

            cap = " CAP" if d.get("cap_bound") else ""
            print(f"{d['turns']} turns{cap}, {stats.get('calls', 0)} cmds, "
                  f"{stats.get('denials', 0)} denied, "
                  f"{len(d['model_patch'])}b patch"
                  + (f", ERROR {d['error'][:120]}" if d["error"] else ""))
            trajectories.append(d)
        finally:
            cont.stop()

        (run_dir / "trajectories.json").write_text(json.dumps(trajectories, indent=2))

        if dead >= 2:
            print(f"\nAborting: {dead} consecutive trajectories ran zero commands. "
                  "The session is broken, not the model.\n"
                  "Run `python -m dfc.run doctor` to isolate auth from tool wiring.")
            break
    return trajectories


def _zero_call_reason(traj: dict) -> str:
    """Turn the model's own error text into a diagnosis."""
    text = (traj.get("final_text") or "").strip()
    low = text.lower()
    if "line break" in low or "invalid authorization header" in low:
        return ("auth: the token contains a line break. Re-export with "
                "`export CLAUDE_CODE_OAUTH_TOKEN=$(claude setup-token | tr -d '[:space:]')`"
                f" | model said: {text[:200]}")
    if "auth" in low or "token" in low or "credit" in low or "rate limit" in low:
        return f"auth or quota problem | model said: {text[:200]}"
    return f"session produced no tool calls | model said: {text[:200]}"


def cmd_solve(args) -> int:
    arm = solver.arm_from_name(args.arm)
    run_id = args.run_id or f"dfc-{arm.name}-{time.strftime('%Y%m%d-%H%M%S')}"
    run_dir = RUNS_DIR / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    instances, sizes = sample.pick(args.n, args.dataset, args.split, args.seed)
    meta = {
        "run_id": run_id, "arm": arm.name, "model": solver.MODEL,
        "dataset": args.dataset, "split": args.split, "seed": args.seed,
        "max_turns": args.max_turns,
        "instance_ids": [i["instance_id"] for i in instances],
        "gold_patch_sizes": sizes,
        **version.version_block(),
    }
    (run_dir / "sample.json").write_text(json.dumps(meta, indent=2))

    print(f"run       : {run_id}")
    print(f"classifier: {meta['classifier_fingerprint']}")
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
            "assistant_messages": traj.get("assistant_messages", ""),
            "cap_bound": traj.get("cap_bound", ""),
            "max_turns": traj.get("max_turns", ""),
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
    capped = sum(1 for r in rows if r["cap_bound"] is True)
    fps = {rec.get("cls", "") for rec in records}
    print(f"wrote {out}")
    print(f"resolved        : {resolved}/{len(rows)}")
    print(f"hit turn cap    : {capped}/{len(rows)}"
          + ("   ! a binding cap penalises restricted arms structurally (\u00a77)"
             if capped else ""))
    ok, why = version.comparable(*fps)
    print(f"classifier      : {', '.join(sorted(f for f in fps if f)) or 'unstamped'}")
    if not ok:
        print(f"  ! {why}")
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

def cmd_audit(args) -> int:
    """Surface rewrites that quietly changed what the agent asked for.

    The `find` defect (D16) sat in the flow log for a whole 30-instance run before
    anyone noticed. This is the check that would have caught it on the first trajectory.
    """
    run_dir = RUNS_DIR / args.run_id
    log = run_dir / "flow_log.jsonl"
    if not log.exists():
        print(f"no flow log at {log}", file=sys.stderr)
        return 1
    records = list(flowlog.read(log))
    findings, kinds = audit.audit_records(records)
    rewritten = sum(1 for r in records if r.get("outcome") == "rewritten")

    print(f"{len(records)} records, {rewritten} rewritten, {len(findings)} findings\n")
    if not findings:
        print("no structural divergence found between requested and executed commands")
        return 0

    high = [f for f in findings if f.severity == "high"]
    print(f"{'kind':26s} {'count':>6s}  severity")
    for k, v in kinds.most_common():
        sev = next(f.severity for f in findings if f.kind == k)
        print(f"  {k:24s} {v:6d}  {sev}")
    print(f"\nhigh severity: {len(high)} (these likely returned the wrong answer)\n")

    groups = audit.group_by_shape(findings if not args.high_only else high)
    for name, fs in list(groups.items())[: args.groups]:
        if args.kind and not name.startswith(args.kind):
            continue
        inst = {f.instance_id for f in fs if f.instance_id}
        print(f"--- {name}  ({len(fs)} occurrences, {len(inst)} instances) ---")
        print(f"    {fs[0].detail}")
        for f in fs[: args.examples]:
            print(f"    IN : {f.command[:110]}")
            print(f"    OUT: {f.executed[:110]}")
        print()
    return 0


def cmd_census(args) -> int:
    """The natural distribution of bash the agent reaches for (\u00a77)."""
    censuses = census.collect(RUNS_DIR)
    if not censuses:
        print(f"no flow logs under {RUNS_DIR}", file=sys.stderr)
        return 1

    out = RUNS_DIR / "command_census.csv"
    census.write_csv(censuses, out)

    for arm in sorted(censuses):
        c = censuses[arm]
        natural = " (natural distribution)" if arm == "arm0" else \
                  " (behaviour under restriction, not natural)"
        print(f"\n=== {arm}{natural} ===")
        print(f"{c.shell_lines} shell lines -> {c.invocations} command invocations, "
              f"{c.distinct} distinct, {len(c.instances)} instances, "
              f"{c.unparseable} unparseable")
        print(f"top 10 cover {c.head_share(10):.1%} of invocations; "
              f"top 20 cover {c.head_share(20):.1%}")
        print()
        print(f"  {'#':>3s}  {'command':14s} {'n':>6s}  {'share':>7s}  {'cum':>7s}")
        for r in c.rows()[: args.top]:
            print(f"  {r['rank']:3d}. {r['command']:14s} {r['invocations']:6d}  "
                  f"{r['share']:6.2%}  {r['cumulative_share']:6.2%}")
        if args.coverage:
            from .policy import ARM1, INFRA_ALLOWLIST
            admitted = set(ARM1.primitives) | set(INFRA_ALLOWLIST)
            cov = census.coverage_of(c, admitted)
            print(f"\n  primitive set + infra allowlist covers "
                  f"{cov['by_invocation']:.1%} of invocations "
                  f"({cov['by_distinct_name']:.1%} of distinct names)")
            if cov["top_uncovered"]:
                top = ", ".join(f"{u['command']}({u['invocations']})"
                                for u in cov["top_uncovered"][:8])
                print(f"  most frequent uncovered: {top}")
    print(f"\nwrote {out}")
    return 0


def _print_instance(v, args) -> None:
    bar = "=" * 78
    print(bar)
    print(f"{v.instance_id}   [{v.failure_class or ('resolved' if v.resolved else '?')}]")
    print(bar)
    print(f"turns {v.turns}{'  CAP' if v.cap_bound else ''} | stop {v.stop_reason} | "
          f"patch {len(v.model_patch)}b | applied {v.patch_applied} | "
          f"files {', '.join(v.dirty_paths) or 'none'}")
    if v.error:
        print(f"harness error: {v.error[:160]}")

    print(f"\nTESTS  FAIL_TO_PASS {len(v.f2p_pass)} passed / {len(v.f2p_fail)} failed"
          f"   PASS_TO_PASS {len(v.p2p_pass)} passed / {len(v.p2p_fail)} failed")
    for t in v.f2p_fail[: args.tests]:
        print(f"   still failing : {t}")
    for t in v.p2p_fail[: args.tests]:
        print(f"   REGRESSION    : {t}")

    if v.never_ran_target_test:
        print("\n  ! the agent never referenced the failing target test in any command")
    if v.agent_claimed_success:
        print("  ! the agent's closing message claims success")

    print(f"\nCOMMANDS ({len(v.commands)})")
    for i, c in enumerate(v.commands, 1):
        rc = c["exit_code"]
        mark = " " if rc in (0, None) else "!"
        line = c["command"].replace("\n", " ; ")[: args.width]
        print(f" {mark}{i:3d}. [{c['outcome'][:4]}] rc={rc if rc is not None else '-':>3} {line}")
        if c["outcome"] == "denied" and args.verbose:
            print(f"        denied: {c['reason'][:110]}")
        if args.verbose and c["executed"] and c["executed"] != c["command"]:
            print(f"        ran   : {c['executed'].replace(chr(10), ' ; ')[: args.width]}")

    print("\nAGENT'S CLOSING MESSAGE")
    print("  " + (v.final_text[: args.text].replace("\n", "\n  ") or "(none)"))

    if args.patch and v.model_patch:
        print("\nPATCH")
        print(v.model_patch[:3000])
    if args.test_output:
        out = inspect_run.test_output(v.run_id, v.instance_id)
        if out:
            print("\nHARNESS TEST OUTPUT (tail)")
            print(out[-args.text * 3:])
    print()


def cmd_inspect(args) -> int:
    if args.failures:
        views = inspect_run.triage(RUNS_DIR, args.run_id)
        if not args.instance:
            print(f"{len(views)} unresolved instance(s) in {args.run_id}, "
                  "most diagnosable first\n")
            print(f"  {'instance':34s} {'class':22s} {'F2P':>5s} {'P2P':>5s} flags")
            for v in views:
                flags = []
                if v.agent_claimed_success:
                    flags.append("claimed-success")
                if v.never_ran_target_test:
                    flags.append("never-ran-target")
                if v.cap_bound:
                    flags.append("cap")
                print(f"  {v.instance_id:34s} {v.failure_class:22s} "
                      f"{len(v.f2p_fail):5d} {len(v.p2p_fail):5d} {' '.join(flags)}")
            print("\nread one with: python -m dfc.run inspect --run-id "
                  f"{args.run_id} --instance <id>")
            return 0
        for v in views:
            _print_instance(v, args)
        return 0

    if not args.instance:
        print("give --instance <id> or --failures", file=sys.stderr)
        return 1
    v = inspect_run.load(RUNS_DIR, args.run_id, args.instance)
    if v is None:
        print(f"{args.instance} not found in {args.run_id}", file=sys.stderr)
        return 1
    _print_instance(v, args)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="dfc.run", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("preflight", help="check docker, auth and deps").set_defaults(
        func=cmd_preflight)
    sub.add_parser("doctor", help="one live SDK call, no Docker - proves auth and MCP "
                                  "wiring").set_defaults(func=cmd_doctor)

    s = sub.add_parser("solve", help="run trajectories")
    s.add_argument("--n", type=int, default=8)
    s.add_argument("--arm", default="arm0", choices=sorted(set(ARMS)))
    s.add_argument("--run-id", default=None)
    s.add_argument("--dataset", default=sample.DATASET)
    s.add_argument("--split", default=sample.SPLIT)
    s.add_argument("--seed", type=int, default=sample.SEED)
    s.add_argument("--max-turns", type=int, default=solver.DEFAULT_MAX_TURNS)
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

    a = sub.add_parser("audit", help="find rewrites that changed what was asked for")
    a.add_argument("--run-id", required=True)
    a.add_argument("--kind", default="", help="filter to one finding kind")
    a.add_argument("--high-only", action="store_true")
    a.add_argument("--groups", type=int, default=12)
    a.add_argument("--examples", type=int, default=2)
    a.set_defaults(func=cmd_audit)

    cs = sub.add_parser("census", help="natural distribution of bash commands used")
    cs.add_argument("--top", type=int, default=40)
    cs.add_argument("--coverage", action="store_true",
                    help="also report what the primitive set would subsume")
    cs.set_defaults(func=cmd_census)

    ins = sub.add_parser("inspect", help="per-instance failure forensics")
    ins.add_argument("--run-id", required=True)
    ins.add_argument("--instance", default="")
    ins.add_argument("--failures", action="store_true",
                     help="triage every unresolved instance")
    ins.add_argument("--verbose", action="store_true",
                     help="show denial reasons and rewritten forms")
    ins.add_argument("--patch", action="store_true")
    ins.add_argument("--test-output", action="store_true",
                     help="tail of the harness test output")
    ins.add_argument("--tests", type=int, default=6)
    ins.add_argument("--width", type=int, default=100)
    ins.add_argument("--text", type=int, default=1200)
    ins.set_defaults(func=cmd_inspect)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
