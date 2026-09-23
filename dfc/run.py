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

from . import bench as bench_mod
from . import container as container_mod
from . import audit, census, flowlog, inspect_run, sample, solver, transcript, version
from .policy import ARMS

MODEL_NAME = "dfc-sonnet5"
RUNS_DIR = Path(os.environ.get("DFC_RUNS_DIR", "runs"))


# --------------------------------------------------------------------------
# Failure taxonomy (E2)
# --------------------------------------------------------------------------

TAXONOMY = [
    "resolved",
    "empty-patch",            # agent produced no diff at all
    "empty-patch-after-success",  # D19: trajectory ended cleanly but no diff came back
    "patch-malformed",        # harness could not apply the diff
    "applied-broke-P2P",      # applied, but previously-passing tests now fail
    "environment-suspect",    # D25: the P2P tests that failed also fail with NO patch
    "applied-F2P-unfixed",    # applied cleanly, target tests still fail
    "harness-error",          # our bug, not the model's
    "turn-limit",             # ran out of turns
    "blocked-tool-deadlock",  # denials dominated; agent could not make progress
    "rewrite-infidelity",     # a lossy canonical rewrite is implicated (D4)
    "unknown",
]


# --------------------------------------------------------------------------
# D25 - environment baseline: which tests fail on the pristine container?
# --------------------------------------------------------------------------

#: The harness run-id that holds no-patch evaluations. One per instance, reused.
ENVCHECK_RUN_ID = "dfc-envcheck"
ENVCHECK_DIR = RUNS_DIR / "envcheck"

#: The official harness skips an empty model_patch, so the "no patch" condition is
#: expressed as a patch that creates one inert file. It touches nothing the tests
#: import and nothing a test patch could collide with.
NOOP_PATCH = (
    "diff --git a/dfc_envcheck.txt b/dfc_envcheck.txt\n"
    "new file mode 100644\n"
    "index 0000000..e69de29\n"
    "--- /dev/null\n"
    "+++ b/dfc_envcheck.txt\n"
    "@@ -0,0 +1 @@\n"
    "+dfc environment baseline: no model patch applied\n"
)


def load_baseline() -> dict:
    """{instance_id: {"p2p_failures": [...], "f2p_failures": [...]}} or {}."""
    path = ENVCHECK_DIR / "baseline.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError:
        return {}


def merge_baseline(existing: dict, instance_id: str, report: dict) -> dict:
    """Union a fresh no-patch report into the baseline. Union, not replace, because an
    environment that fails intermittently (live-service tests) is still an
    environment failure; every test ever seen failing without a patch counts."""
    tests = report.get("tests_status", {}) or {}
    cur = existing.get(instance_id, {"p2p_failures": [], "f2p_failures": [], "runs": 0})
    cur["p2p_failures"] = sorted(set(cur["p2p_failures"])
                                 | set(tests.get("PASS_TO_PASS", {}).get("failure", [])))
    cur["f2p_failures"] = sorted(set(cur["f2p_failures"])
                                 | set(tests.get("FAIL_TO_PASS", {}).get("failure", [])))
    cur["runs"] = cur.get("runs", 0) + 1
    existing[instance_id] = cur
    return existing


def environment_explains(instance_id: str, p2p_failing: list[str], baseline: dict) -> bool:
    """True when every PASS_TO_PASS failure in this report also failed on the pristine
    container. A patch cannot have caused a failure that happens without it."""
    base = baseline.get(instance_id)
    if not base or not p2p_failing:
        return False
    return set(p2p_failing) <= set(base.get("p2p_failures", []))


def classify_failure(traj: dict, report: dict | None, denial_rate: float,
                     fidelity_hit: bool, baseline: dict | None = None) -> str:
    """One label per instance. §4 showed 5 instances spanning 4 categories and a CSV
    that recorded none of them."""
    if traj.get("error"):
        return "harness-error"
    if not traj.get("model_patch"):
        if traj.get("stop_reason") == "turn-limit" or traj.get("cap_bound"):
            return "turn-limit"
        # D19: a trajectory that ran to completion, issued commands and then yielded
        # no diff is a patch-extraction failure until proven otherwise, not a model
        # that declined to edit anything. The first instance of this was `git add -A`
        # running in the agent's last cwd (`/tmp/...`) instead of the repo. Separated
        # from `empty-patch` so it cannot be silently scored as a model failure again.
        if traj.get("stop_reason") == "success" and (traj.get("tool_stats") or {}).get("calls", 0) > 0:
            return "empty-patch-after-success"
        return "empty-patch"
    if report is None:
        return "harness-error"
    if report.get("error"):
        return "harness-error"          # D28: e.g. hidden tests not installed
    if report.get("resolved"):
        return "resolved"
    if not report.get("patch_successfully_applied", False):
        return "patch-malformed"

    tests = report.get("tests_status", {}) or {}
    p2p_failing = tests.get("PASS_TO_PASS", {}).get("failure", [])
    f2p_failing = tests.get("FAIL_TO_PASS", {}).get("failure", [])
    if p2p_failing:
        # D25: if the same P2P tests fail with no patch at all, the patch did not
        # break them. Checked first - an environment failure is not a rewrite issue
        # and not a regression, whatever else the trajectory did. F2P results on such
        # an instance are untrustworthy too (the same broken service or dependency
        # sits under them), so the whole row is set aside rather than scored.
        if environment_explains(traj.get("instance_id", ""), p2p_failing, baseline or {}):
            return "environment-suspect"
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

def _retryable_harness_failure(traj: dict) -> bool:
    """A completed-looking trajectory that is really one of our failures (D19)."""
    if traj.get("model_patch"):
        return False
    if traj.get("cap_bound") or traj.get("stop_reason") == "turn-limit":
        return False          # a genuine turn-limit result, not our bug
    return traj.get("stop_reason") == "success"


def _prune_flow_log(path: Path, instance_ids: set[str]) -> int:
    """Drop records for instances about to be re-run. The log is append-only, so
    without this a retry leaves both attempts in it."""
    if not path.exists():
        return 0
    kept, dropped = [], 0
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        try:
            if json.loads(line).get("instance_id") in instance_ids:
                dropped += 1
                continue
        except json.JSONDecodeError:
            pass
        kept.append(line)
    if dropped:
        path.write_text("\n".join(kept) + ("\n" if kept else ""))
    return dropped


def _csv_ids(text: str | None) -> set[str]:
    return {x.strip() for x in (text or "").split(",") if x.strip()}


def _bench_for(run_id: str) -> "bench_mod.Benchmark":
    """The benchmark a run was solved on, from its sample.json (D27). Runs older than
    D27 carry no `benchmark` key and are Lite."""
    meta_path = RUNS_DIR / run_id / "sample.json"
    if meta_path.exists():
        try:
            meta = json.loads(meta_path.read_text())
            return bench_mod.get(meta.get("benchmark", "lite"),
                                 tuple(meta["repos"]) if meta.get("repos") else None)
        except (json.JSONDecodeError, KeyError):
            pass
    return bench_mod.LITE


def _eval_instance_dir(run_id: str, instance_id: str, bench=None) -> Path:
    """Where the grader keeps one instance's output. Lite: the swebench layout.
    Pro: `<run>/pro/<iid>/` written by swe_bench_pro_eval.py."""
    bench = bench or _bench_for(run_id)
    if bench.name == "pro":
        return Path("logs/run_evaluation") / run_id / "pro" / instance_id
    return Path("logs/run_evaluation") / run_id / MODEL_NAME / instance_id


def _forget_evaluation(run_id: str, instance_ids: set[str]) -> int:
    """Drop the grader's per-instance output so `evaluate` re-grades a retried
    trajectory instead of reusing the stale result (D23)."""
    import shutil
    dropped = 0
    for iid in instance_ids:
        d = _eval_instance_dir(run_id, iid)
        if d.exists():
            shutil.rmtree(d)
            dropped += 1
    return dropped


async def _solve_all(instances, arm, run_dir: Path, args, bench=None) -> list[dict]:
    bench = bench or bench_mod.LITE
    # Resume: a long run will be interrupted - docker hiccup, rate limit, laptop
    # sleep - and without this a single failure at instance 200 discards 200
    # trajectories. Only trajectories that actually ran commands are kept; a
    # harness-error record is retried rather than cemented.
    trajectories: list[dict] = []
    done: set[str] = set()
    retried: set[str] = set()
    # D23: explicit retries. The record is discarded and the instance re-solved; the
    # only legitimate reason is that the original was not a valid measurement (a
    # harness defect fixed since). Re-running a genuine failure and keeping the
    # better result is selection on the outcome - use --instances into a separate
    # run-id for diagnosis instead.
    forced = _csv_ids(getattr(args, "retry", None))
    existing = run_dir / "trajectories.json"
    if existing.exists():
        try:
            prior = json.loads(existing.read_text())
        except json.JSONDecodeError:
            prior = []
        for t in prior:
            if t.get("tool_stats", {}).get("calls", 0) <= 0:
                continue
            if t["instance_id"] in forced:
                retried.add(t["instance_id"])
                continue
            if _retryable_harness_failure(t):
                # D19: commands ran, the trajectory ended cleanly, and no diff came
                # back. That was our patch extraction following the agent's cwd out of
                # the repo, not a model that declined to edit. Same argument as the
                # harness-error case above: retry it rather than cement it.
                retried.add(t["instance_id"])
                continue
            trajectories.append(t)
            done.add(t["instance_id"])
        if done or retried:
            print(f"resuming  : {len(done)} trajectory(ies) already complete, "
                  f"{len(instances) - len(done)} to go")
            if retried - forced:
                print(f"retrying  : {len(retried - forced)} with an empty patch after a "
                      f"clean finish (D19): {', '.join(sorted(retried - forced))}")
            if retried & forced:
                print(f"retrying  : {len(retried & forced)} by --retry (D23): "
                      f"{', '.join(sorted(retried & forced))}")
            print()
        # Keep the flow log consistent with trajectories.json: a retried instance
        # would otherwise contribute two sets of records and inflate the coverage
        # denominator it feeds. The harness's own log dir goes too, or `evaluate`
        # silently keeps the old report.
        if retried:
            _prune_flow_log(run_dir / "flow_log.jsonl", retried)
            _forget_evaluation(run_dir.name, retried)
    missing = forced - {i["instance_id"] for i in instances}
    if missing:
        print(f"warning   : --retry names instances not in this sample, ignored: "
              f"{', '.join(sorted(missing))}")

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
            image=bench.image_for(inst),
            repo_dir=bench.repo_dir,
            run_extra=bench.docker_run_extra(),
            run_cmd=bench.docker_run_cmd(),
            platform=args.platform,
            network_none=args.network_none,
            # D21: the harness owns every path its test patch touches.
            reserved_paths=container_mod.paths_in_patch(inst.get("test_patch", "")),
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
                capture_reasoning=not args.no_reasoning,
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

    repos = tuple(r.strip() for r in (getattr(args, "repos", None) or "").split(",") if r.strip()) or None
    bench = bench_mod.get(getattr(args, "bench", "lite"), repos)
    if bench.name == "pro" and args.dataset == sample.DATASET:
        args.dataset = bench.dataset          # --dataset default is Lite's; follow --bench
    explicit = _csv_ids(getattr(args, "instances", None))
    if explicit:
        # D23: a hand-picked set for diagnosis. Not a sample - never pool it with the
        # seeded runs. `report` carries the flag so it cannot be mistaken for one.
        pool = {i["instance_id"]: i for i in sample.load(args.dataset, args.split, bench)}
        unknown = sorted(explicit - set(pool))
        if unknown:
            print(f"unknown instance id(s): {', '.join(unknown)}", file=sys.stderr)
            return 2
        instances = [pool[i] for i in sorted(explicit)]
        sizes = sample.size_report(instances)
    else:
        instances, sizes = sample.pick(args.n, args.dataset, args.split, args.seed, bench)
    # Pro rows are large (dockerfiles, run scripts); keep what the grader and the
    # solver need so sample.json stays readable and the instances travel with the run.
    keep_keys = ("instance_id", "repo", "base_commit", "problem_statement", "hints_text",
                 "patch", "test_patch", "fail_to_pass", "pass_to_pass", "dockerhub_tag",
                 "before_repo_set_cmd", "selected_test_files_to_run")
    meta = {
        "run_id": run_id, "arm": arm.name, "model": solver.MODEL,
        "benchmark": bench.name, "repo_dir": bench.repo_dir, "repos": list(bench.repos),
        "dataset": args.dataset, "split": args.split, "seed": args.seed,
        "instances": [{k: i[k] for k in keep_keys if k in i} for i in instances],
        "max_turns": args.max_turns,
        "instance_ids": [i["instance_id"] for i in instances],
        "gold_patch_sizes": sizes,
        "selection": "explicit" if explicit else "stratified",
        **version.version_block(),
    }
    (run_dir / "sample.json").write_text(json.dumps(meta, indent=2))

    print(f"run       : {run_id}")
    print(f"classifier: {meta['classifier_fingerprint']}")
    print(f"arm       : {arm.name} (mode={arm.mode})")
    print(f"model     : {solver.MODEL}")
    print(f"benchmark : {bench.name} (repo at {bench.repo_dir}"
          + (f", repos {', '.join(bench.repos)}" if bench.repos else "") + ")")
    print(f"instances : {len(instances)} across "
          f"{len({i.get('repo') or sample.repo_of(i['instance_id']) for i in instances})} repos")
    print(f"gold patch: median {sizes['median_lines_touched']:.0f} lines, "
          f"{sizes['median_files']:.0f} files"
          + ("  ! degeneracy risk (§7)" if sizes["degeneracy_risk"] else ""))
    print()

    trajectories = asyncio.run(_solve_all(instances, arm, run_dir, args, bench))

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

def _pro_evaluate(run_id: str, ids: list[str], preds: list[dict], meta: dict,
                  out_root: Path, *, max_workers: int, redo: bool) -> int:
    """Grade with the Scale repo's script (D27). Writes the sampled rows as the
    `raw_sample` JSONL it expects (lowercase list columns, stringified), the patches
    as its `[{instance_id, patch, prefix}]` JSON, and runs it with cwd=PRO_ROOT
    because it resolves `dockerfiles/` and `helper_code` relatively."""
    root = bench_mod.PRO_ROOT
    script = root / "swe_bench_pro_eval.py"
    if not script.exists():
        print(f"Pro grader not found at {script}; clone SWE-bench_Pro-os into the repo root",
              file=sys.stderr)
        return 1
    by_id = {i["instance_id"]: i for i in meta.get("instances", [])}
    run_dir = RUNS_DIR / run_id
    rows_path = (run_dir / "pro_samples.jsonl").resolve()
    with rows_path.open("w") as fh:
        for iid in ids:
            r = dict(by_id[iid])
            # D28: install the HF test patch ourselves; the rows' own last line names a
            # file that is not in the DockerHub images.
            r["before_repo_set_cmd"] = bench_mod.pro_setup_cmd(r)
            r["fail_to_pass"] = json.dumps(r.get("fail_to_pass", []))
            r["pass_to_pass"] = json.dumps(r.get("pass_to_pass", []))
            if isinstance(r.get("selected_test_files_to_run"), list):
                r["selected_test_files_to_run"] = json.dumps(r["selected_test_files_to_run"])
            fh.write(json.dumps(r) + "\n")
    patches_path = (run_dir / "pro_patches.json").resolve()
    patches_path.write_text(json.dumps([
        {"instance_id": p["instance_id"], "patch": p["model_patch"], "prefix": MODEL_NAME}
        for p in preds if p["instance_id"] in set(ids)
    ], indent=2))
    out_root = out_root.resolve()
    out_root.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable, str(script.resolve()),
        "--raw_sample_path", str(rows_path),
        "--patch_path", str(patches_path),
        "--output_dir", str(out_root),
        "--scripts_dir", str((root / "run_scripts").resolve()),
        "--dockerhub_username", bench_mod.PRO_DOCKERHUB_USER,
        "--use_local_docker", "--docker_platform", container_mod.DEFAULT_PLATFORM,
        "--num_workers", str(max_workers),
    ]
    if redo:
        cmd.append("--redo")
    print(" ".join(cmd), "\n")
    return subprocess.run(cmd, cwd=str(root)).returncode


def cmd_evaluate(args) -> int:
    run_dir = RUNS_DIR / args.run_id
    preds = run_dir / "predictions.json"
    if not preds.exists():
        print(f"no predictions at {preds}", file=sys.stderr)
        return 1
    meta = json.loads((run_dir / "sample.json").read_text())
    ids = list(meta["instance_ids"])
    regrade = _csv_ids(getattr(args, "regrade", None))
    if regrade == {"all"}:
        regrade = set(ids)          # D28: re-grade every trajectory in the run
    bench = _bench_for(args.run_id)
    if bench.name == "pro":
        if regrade:
            n = _forget_evaluation(args.run_id, regrade)
            ids = sorted(regrade & set(ids))
            print(f"regrade   : {len(ids)} instance(s), {n} stale output(s) removed (D26)")
        return _pro_evaluate(args.run_id, ids, json.loads(preds.read_text()), meta,
                             Path("logs/run_evaluation") / args.run_id / "pro",
                             max_workers=args.max_workers, redo=bool(regrade))
    if regrade:
        # D26: re-grade the SAME patch. For instances whose tests depend on a live
        # service, the grade is a property of the service on the day, not of the
        # patch; re-grading is the only way to separate the two without re-solving.
        # The harness skips an instance with an existing report, so forget it first.
        n = _forget_evaluation(args.run_id, regrade)
        ids = sorted(regrade & set(ids))
        print(f"regrade   : {len(ids)} instance(s), {n} stale report(s) removed (D26)")

    cmd = [
        sys.executable, "-m", "swebench.harness.run_evaluation",
        "--dataset_name", meta["dataset"],
        "--split", meta["split"],
        "--predictions_path", str(preds),
        "--max_workers", str(args.max_workers),
        "--run_id", args.run_id,
        "--cache_level", args.cache_level,
        "--instance_ids", *ids,
    ]
    print(" ".join(cmd), "\n")
    proc = subprocess.run(cmd)
    return proc.returncode


# --------------------------------------------------------------------------
# envcheck (D25)
# --------------------------------------------------------------------------

def _p2p_broken_instances(run_id: str) -> list[str]:
    """Instances in a run whose report shows PASS_TO_PASS failures."""
    run_dir = RUNS_DIR / run_id
    out = []
    for t in json.loads((run_dir / "trajectories.json").read_text()):
        rep = _instance_report(run_id, t["instance_id"])
        if rep and (rep.get("tests_status", {}) or {}).get("PASS_TO_PASS", {}).get("failure"):
            out.append(t["instance_id"])
    return sorted(set(out))


def cmd_envcheck(args) -> int:
    """Evaluate the named instances with NO model patch and record which tests fail
    anyway. Costs Docker time only - no agent, no quota."""
    run_dir = RUNS_DIR / args.run_id
    meta = json.loads((run_dir / "sample.json").read_text())
    ids = sorted(_csv_ids(getattr(args, "instances", None))) or _p2p_broken_instances(args.run_id)
    if not ids:
        print("no instances with PASS_TO_PASS failures in this run; nothing to check")
        return 0
    if getattr(args, "force", False):
        _forget_evaluation(ENVCHECK_RUN_ID, set(ids))
    if getattr(args, "reset", False):
        # D28: a baseline taken while the hidden tests were not installed lists every
        # P2P test as failing, and the union rule would keep that forever. Drop the
        # named instances' entries before merging fresh ones.
        b = load_baseline()
        dropped = [i for i in ids if b.pop(i, None) is not None]
        ENVCHECK_DIR.mkdir(parents=True, exist_ok=True)
        (ENVCHECK_DIR / "baseline.json").write_text(json.dumps(b, indent=2))
        print(f"reset     : dropped {len(dropped)} stale baseline entr{'y' if len(dropped)==1 else 'ies'}")

    bench = _bench_for(args.run_id)
    if bench.name == "pro":
        # D27: same idea, Scale's grader. Baseline output lives under the source
        # run-id's pro dir with an `envcheck` prefix so `_instance_report` can find it
        # via a synthetic run-id; simplest is a sibling run-id per source run.
        env_rid = f"{ENVCHECK_RUN_ID}-{args.run_id}"
        (RUNS_DIR / env_rid).mkdir(parents=True, exist_ok=True)
        (RUNS_DIR / env_rid / "sample.json").write_text(json.dumps(
            {**meta, "run_id": env_rid, "instance_ids": ids}, indent=2))
        started = time.time()
        rc = _pro_evaluate(env_rid, ids,
                           [{"instance_id": i, "model_patch": NOOP_PATCH} for i in ids],
                           meta, Path("logs/run_evaluation") / env_rid / "pro",
                           max_workers=args.max_workers, redo=bool(getattr(args, "force", False)))
        baseline = load_baseline()
        for iid in ids:
            rep = _instance_report(env_rid, iid)
            if rep is None:
                print(f"  {iid:38s} no report (grader error?)")
                continue
            baseline = merge_baseline(baseline, iid, rep)
            n = len(baseline[iid]["p2p_failures"])
            print(f"  {iid:38s} P2P failing with no patch: {n}" + ("   <- environment" if n else ""))
        ENVCHECK_DIR.mkdir(parents=True, exist_ok=True)
        (ENVCHECK_DIR / "baseline.json").write_text(json.dumps(baseline, indent=2))
        print(f"\nwrote {ENVCHECK_DIR / 'baseline.json'}; re-run `report` on affected run-ids")
        return rc

    ENVCHECK_DIR.mkdir(parents=True, exist_ok=True)
    preds_path = ENVCHECK_DIR / "predictions.json"
    preds = {}
    if preds_path.exists():
        preds = {p["instance_id"]: p for p in json.loads(preds_path.read_text())}
    for iid in ids:
        preds[iid] = {"instance_id": iid, "model_name_or_path": MODEL_NAME,
                      "model_patch": NOOP_PATCH}
    preds_path.write_text(json.dumps(list(preds.values()), indent=2))

    print(f"envcheck  : {len(ids)} instance(s) with no model patch -> "
          f"logs/run_evaluation/{ENVCHECK_RUN_ID}/")
    started = time.time()
    cmd = [
        sys.executable, "-m", "swebench.harness.run_evaluation",
        "--dataset_name", meta["dataset"], "--split", meta["split"],
        "--predictions_path", str(preds_path),
        "--max_workers", str(args.max_workers),
        "--run_id", ENVCHECK_RUN_ID, "--cache_level", args.cache_level,
        "--instance_ids", *ids,
    ]
    print(" ".join(cmd), "\n")
    rc = subprocess.run(cmd).returncode

    baseline = load_baseline()
    for iid in ids:
        rep = _instance_report(ENVCHECK_RUN_ID, iid)
        if rep is None:
            print(f"  {iid:38s} no report (harness error?)")
            continue
        report_path = _eval_instance_dir(ENVCHECK_RUN_ID, iid, bench_mod.LITE) / "report.json"
        if report_path.stat().st_mtime >= started:
            baseline = merge_baseline(baseline, iid, rep)
        elif iid not in baseline:
            baseline = merge_baseline(baseline, iid, rep)
        n = len(baseline[iid]["p2p_failures"])
        print(f"  {iid:38s} P2P failing with no patch: {n}"
              + ("   <- environment" if n else ""))
    (ENVCHECK_DIR / "baseline.json").write_text(json.dumps(baseline, indent=2))
    print(f"\nwrote {ENVCHECK_DIR / 'baseline.json'}; re-run `report` on affected run-ids")
    return rc


# --------------------------------------------------------------------------
# report
# --------------------------------------------------------------------------

def _instance_report(run_id: str, instance_id: str) -> dict | None:
    bench = _bench_for(run_id)
    if bench.name == "pro":
        d = _eval_instance_dir(run_id, instance_id, bench)
        out = d / f"{MODEL_NAME}_output.json"
        if not out.exists():
            return None
        try:
            output = json.loads(out.read_text())
        except Exception:
            return None
        stderr_path = d / f"{MODEL_NAME}_stderr.log"
        stderr = stderr_path.read_text(errors="replace") if stderr_path.exists() else ""
        meta = json.loads((RUNS_DIR / run_id / "sample.json").read_text())
        inst = next((i for i in meta.get("instances", []) if i["instance_id"] == instance_id), {})
        ws = d / "workspace"
        def _read(name):
            f = ws / name
            return f.read_text(errors="replace") if f.exists() else None
        patch_file = d / f"{MODEL_NAME}_patch.diff"
        model_patch = patch_file.read_text(errors="replace") if patch_file.exists() else ""
        return bench_mod.pro_report(output, stderr, inst,
                                    model_status=_read(bench_mod.PRO_MODEL_STATUS),
                                    test_apply_log=_read(bench_mod.PRO_TEST_APPLY_LOG),
                                    model_patch=model_patch)
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
    baseline = load_baseline()

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
            "failure_class": classify_failure(traj, report, denial_rate, fidelity_hit, baseline),
            "env_checked": iid in baseline,
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
    env_suspect = sum(1 for r in rows if r["failure_class"] == "environment-suspect")
    unchecked_p2p = [r["instance_id"] for r in rows
                     if r["failure_class"] == "applied-broke-P2P" and not r["env_checked"]]
    empty_observed = sum(1 for r in rows if not r["dfc_observed"])
    capped = sum(1 for r in rows if r["cap_bound"] is True)
    fps = {rec.get("cls", "") for rec in records}
    print(f"wrote {out}")
    print(f"resolved        : {resolved}/{len(rows)}")
    if env_suspect:
        print(f"env-suspect     : {env_suspect}   (P2P failures reproduce with no patch; "
              f"excluded from the model's record, D25)")
    if unchecked_p2p:
        print(f"unchecked P2P   : {len(unchecked_p2p)} applied-broke-P2P row(s) never tested "
              f"against a no-patch baseline - run `envcheck --run-id {args.run_id}`")
    print(f"hit turn cap    : {capped}/{len(rows)}"
          + ("   ! a binding cap penalises restricted arms structurally (\u00a77)"
             if capped else ""))
    ok, why = version.comparable(*fps)
    print(f"classifier      : {', '.join(sorted(f for f in fps if f)) or 'unstamped'}")
    sample_meta = run_dir / "sample.json"
    if sample_meta.exists():
        _m = json.loads(sample_meta.read_text())
        sel = _m.get("selection", "stratified")
        print(f"benchmark       : {_m.get('benchmark', 'lite')}"
              + (f"  repos={','.join(_m['repos'])}" if _m.get("repos") else ""))
        if sel == "explicit":
            print("selection       : explicit   ! diagnostic set, not a sample - "
                  "do not pool with seeded runs (D23)")
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

    if args.reasoning and v.reasoning:
        print(f"\nREASONING ({len(v.reasoning)} assistant turns)")
        for st in v.reasoning:
            print(f"  --- turn {st['n']} ---")
            if st.get("thinking"):
                print("   [thinking] " + st["thinking"][: args.text]
                      .replace("\n", "\n              "))
            if st.get("text"):
                print("   [says]     " + st["text"][: args.text]
                      .replace("\n", "\n              "))
            for c in st.get("calls", []):
                print(f"   [runs]     {c[: args.width]}")
    elif args.reasoning:
        print("\nREASONING: not captured for this run.")
        print("  Recover it from Claude Code's session store:")
        print(f"    python -m dfc.run transcript --instance {v.instance_id}")

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


def cmd_transcript(args) -> int:
    """Recover the agent's reasoning from Claude Code's own session store."""
    cwd = args.cwd or str(Path.cwd())
    root = transcript.store_root() / "projects" / transcript.project_dir(cwd)
    files = transcript.transcripts_for(cwd)

    if args.list or not args.instance:
        print(f"store : {root}")
        print(f"found : {len(files)} transcript file(s)\n")
        if not files:
            print("Nothing here. Either the runs used a different working directory,\n"
                  "CLAUDE_CONFIG_DIR moved the store, or the 30-day retention\n"
                  "(cleanupPeriodDays) has already deleted them.")
            return 1
        import time
        for f in files[-args.limit:]:
            age = (time.time() - f.stat().st_mtime) / 86400
            print(f"  {f.name}  {f.stat().st_size/1e6:6.2f} MB  {age:4.1f} days old")
        print("\nread one with: python -m dfc.run transcript --instance <instance-id>")
        return 0

    ts = transcript.find_for_instance(args.instance, args.match, cwd)
    if not ts:
        print(f"no transcript matched {args.instance}", file=sys.stderr)
        print(f"searched {len(files)} file(s) under {root}", file=sys.stderr)
        return 1
    for t in ts[: args.max]:
        print(transcript.render(t, thinking=not args.no_thinking,
                                results=args.results, width=args.width))
        print()
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
    s.add_argument("--bench", default="lite", choices=sorted(bench_mod.BENCHMARKS),
                   help="D27: which benchmark profile - image naming, repo path, grader")
    s.add_argument("--repos", default=None, metavar="owner/name,owner/name",
                   help="D27: restrict the sample to these repos (Pro default: the two "
                        "pytest repos, openlibrary and qutebrowser)")
    s.add_argument("--dataset", default=sample.DATASET)
    s.add_argument("--split", default=sample.SPLIT)
    s.add_argument("--seed", type=int, default=sample.SEED)
    s.add_argument("--max-turns", type=int, default=solver.DEFAULT_MAX_TURNS)
    s.add_argument("--retry", default=None, metavar="ID,ID",
                   help="D23: discard these instances' records in an existing run-id "
                        "and re-solve them; only for trajectories invalidated by a "
                        "harness fix")
    s.add_argument("--instances", default=None, metavar="ID,ID",
                   help="D23: solve exactly these instances instead of a seeded "
                        "sample; a diagnostic set, never pooled with seeded runs")
    s.add_argument("--command-timeout", type=int, default=300)
    s.add_argument("--platform", default=container_mod.DEFAULT_PLATFORM)
    s.add_argument("--hints", action="store_true",
                   help="include hints_text (off by default: it is not available in a "
                        "realistic setting and inflates the baseline)")
    s.add_argument("--no-reasoning", action="store_true",
                   help="do not capture per-turn thinking (smaller trajectories.json)")
    s.add_argument("--network-none", action="store_true",
                   help="Phase 2b: empty netns inside the container")
    s.add_argument("--project-settings", action="store_true",
                   help="load .claude/settings.json via setting_sources=['project']")
    s.set_defaults(func=cmd_solve)

    e = sub.add_parser("evaluate", help="official swebench harness")
    e.add_argument("--run-id", required=True)
    e.add_argument("--max-workers", type=int, default=4)
    e.add_argument("--cache-level", default="env")
    e.add_argument("--regrade", default=None, metavar="ID,ID",
                   help="D26: discard these instances' harness reports and grade the "
                        "same patches again (live-service flakiness); 'all' for every "
                        "instance in the run (D28)")
    e.set_defaults(func=cmd_evaluate)

    ec = sub.add_parser("envcheck", help="D25: evaluate instances with NO patch to learn "
                                          "which tests fail on the pristine environment")
    ec.add_argument("--run-id", required=True,
                    help="run whose P2P-broken instances to check (or use --instances)")
    ec.add_argument("--instances", default=None, metavar="ID,ID")
    ec.add_argument("--force", action="store_true", help="re-evaluate even if a baseline "
                                                          "report exists (union the results)")
    ec.add_argument("--reset", action="store_true", help="D28: drop the named instances' "
                                                          "existing baseline entries first")
    ec.add_argument("--max-workers", type=int, default=4)
    ec.add_argument("--cache-level", default="env")
    ec.set_defaults(func=cmd_envcheck)

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
    ins.add_argument("--reasoning", action="store_true",
                     help="per-turn thinking, if the run captured it")
    ins.add_argument("--test-output", action="store_true",
                     help="tail of the harness test output")
    ins.add_argument("--tests", type=int, default=6)
    ins.add_argument("--width", type=int, default=100)
    ins.add_argument("--text", type=int, default=1200)
    ins.set_defaults(func=cmd_inspect)

    tr = sub.add_parser("transcript",
                        help="recover agent reasoning from Claude Code session files")
    tr.add_argument("--instance", default="")
    tr.add_argument("--list", action="store_true")
    tr.add_argument("--match", default="", help="extra text to match in the first prompt")
    tr.add_argument("--cwd", default="", help="working directory the run used")
    tr.add_argument("--results", action="store_true", help="include tool output")
    tr.add_argument("--no-thinking", action="store_true")
    tr.add_argument("--width", type=int, default=2000)
    tr.add_argument("--limit", type=int, default=40)
    tr.add_argument("--max", type=int, default=1)
    tr.set_defaults(func=cmd_transcript)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
