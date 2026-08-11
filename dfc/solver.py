"""Agent SDK trajectory loop - the solver (§6, §8 Phase 2).

Replaces the one-shot diff generation that made the previous run unmeasurable. The
model now explores a real repository through a real shell, and the patch is produced by
`git diff` at the end of the trajectory rather than by the model emitting diff text.
That single change removes the entire failure mode that killed the last run: invented
file paths and fabricated blob hashes cannot survive `git diff`.

Layers of authority, in order (§6.1):

1. `disallowed_tools` removes every built-in tool that would bypass the shell. If
   `Read`/`Edit`/`Write`/`Glob`/`Grep`/`WebFetch`/`NotebookEdit` are left available the
   model performs reads and writes that never touch bash and the experiment silently
   measures nothing. `Bash` itself is denied too, because our executor is the MCP tool.
2. The MCP `bash` tool gates and logs every command (see `bashtool.py`).
3. `.claude/settings.json` deny rules as defence in depth, which requires
   `setting_sources=["project"]` - the SDK does not load filesystem settings otherwise.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field

from . import bashtool
from .bashtool import BashTool
from .container import InstanceContainer
from .policy import ARMS, Arm, DENY_TOOLS

MODEL = os.environ.get("DFC_MODEL", "claude-sonnet-5")

#: Every built-in tool that could bypass the shell, plus Bash itself (our executor is
#: the MCP tool) and Task (a subagent call is simultaneously an external write and an
#: untrusted read; denied in v1, it is the v2 marquee experiment - §6.5).
DISALLOWED = sorted(DENY_TOOLS | {"Bash", "BashOutput", "KillShell", "PowerShell",
                                  "SlashCommand", "TodoWrite"})

SYSTEM_PROMPT = """You are an expert software engineer fixing a bug in a Python repository.

The repository is checked out at /testbed and is your working directory. You interact \
with it exclusively through the `bash` tool - there are no file-editing tools available, \
so read and modify files using shell commands.

Method:
1. Explore the repository to locate the code responsible for the issue.
2. Read the relevant code before changing it.
3. Make the minimal change that fixes the issue.
4. Run the relevant tests to confirm the fix and to confirm you have not broken anything.

Guidance that matters:
- When writing a file, prefer a quoted heredoc: `tee path/to/file.py <<'EOF' ... EOF`. \
This avoids the shell mangling tabs, backslashes and Python indentation, which is the \
usual cause of syntax errors introduced by `echo` or `printf` into `>`.
- Do not create new files unless the fix requires them.
- Do not commit. Leave your changes in the working tree.
- Stop when the tests relevant to the issue pass."""

USER_PROMPT = """Fix the following issue in the repository at /testbed.

<issue>
{problem_statement}
</issue>
{hints}
Work through it with the `bash` tool. When you are done, briefly state which files you \
changed and why."""


@dataclass
class Trajectory:
    instance_id: str
    arm: str
    model_patch: str = ""
    turns: int = 0
    duration_s: float = 0.0
    stop_reason: str = ""
    total_cost_usd: float | None = None
    usage: dict = field(default_factory=dict)
    tool_stats: dict = field(default_factory=dict)
    dirty_paths: list[str] = field(default_factory=list)
    error: str = ""
    final_text: str = ""
    #: Last lines of CLI stderr. Kept because a session that fails to authenticate
    #: reports it here and nowhere else, and without it a broken run looks like a
    #: model failure.
    stderr_tail: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        d = dict(self.__dict__)
        d["model_patch_bytes"] = len(self.model_patch)
        return d


def _build_user_prompt(instance: dict, include_hints: bool) -> str:
    hints = ""
    if include_hints and instance.get("hints_text"):
        hints = f"\n<hints>\n{instance['hints_text']}\n</hints>\n"
    return USER_PROMPT.format(
        problem_statement=instance["problem_statement"].strip(),
        hints=hints,
    )


async def solve(
    instance: dict,
    container: InstanceContainer,
    arm: Arm,
    *,
    max_turns: int = 40,
    include_hints: bool = False,
    settings_dir: str | None = None,
    command_timeout: int = 300,
) -> Trajectory:
    """Run one instance to completion and return the trajectory."""
    from claude_agent_sdk import ClaudeAgentOptions, ClaudeSDKClient

    instance_id = instance["instance_id"]
    traj = Trajectory(instance_id=instance_id, arm=arm.name)

    tool = BashTool(
        container=container,
        arm=arm,
        instance_id=instance_id,
        timeout=command_timeout,
    )
    server = bashtool.make_server(tool)

    stderr_lines: list[str] = []

    options = ClaudeAgentOptions(
        model=MODEL,
        system_prompt=SYSTEM_PROMPT,
        mcp_servers={bashtool.SERVER_NAME: server},
        allowed_tools=[bashtool.QUALIFIED],
        disallowed_tools=DISALLOWED,
        # Auto-approve our own tool; the gate is inside it, not in the permission flow.
        permission_mode="bypassPermissions",
        max_turns=max_turns,
        # The SDK does not load filesystem settings unless told to (§10).
        setting_sources=["project"] if settings_dir else [],
        strict_mcp_config=True,
        cwd=settings_dir or os.getcwd(),
        env={"DFC_ARM": arm.name, "DFC_INSTANCE_ID": instance_id},
        stderr=lambda line: stderr_lines.append(line),
    )

    started = time.time()
    try:
        async with ClaudeSDKClient(options=options) as client:
            await client.query(_build_user_prompt(instance, include_hints))
            async for message in client.receive_response():
                kind = type(message).__name__
                if kind == "AssistantMessage":
                    traj.turns += 1
                    for block in getattr(message, "content", []) or []:
                        if getattr(block, "text", None):
                            traj.final_text = block.text
                elif kind == "ResultMessage":
                    traj.stop_reason = getattr(message, "subtype", "") or "end_turn"
                    traj.total_cost_usd = getattr(message, "total_cost_usd", None)
                    traj.usage = getattr(message, "usage", {}) or {}
    except Exception as exc:  # harness error, not a model failure - record as such
        traj.error = f"{type(exc).__name__}: {exc}"
        traj.stop_reason = traj.stop_reason or "harness-error"

    traj.duration_s = time.time() - started
    traj.tool_stats = tool.stats()
    traj.stderr_tail = stderr_lines[-20:]

    # §8 R5 - the patch comes from git, never from the model.
    try:
        traj.dirty_paths = container.dirty_paths()
        traj.model_patch = container.model_patch()
    except Exception as exc:
        traj.error = (traj.error + " | " if traj.error else "") + f"patch extraction: {exc}"

    if traj.turns >= max_turns and not traj.stop_reason:
        traj.stop_reason = "turn-limit"

    return traj


def arm_from_name(name: str) -> Arm:
    if name not in ARMS:
        raise SystemExit(f"unknown arm {name!r}; choose from {sorted(set(ARMS))}")
    return ARMS[name]


__all__ = ["solve", "Trajectory", "arm_from_name", "DISALLOWED", "MODEL",
           "SYSTEM_PROMPT"]
