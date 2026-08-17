"""Recover the agent's reasoning from Claude Code session transcripts.

The trajectory records only `final_text` - the last text block. Everything the agent
thought on the way there lives in Claude Code's own session store:

    ~/.claude/projects/<cwd-with-non-alphanumerics-as-dashes>/<session-id>.jsonl

Agent SDK sessions are written there too. **Default retention is 30 days**
(`cleanupPeriodDays`), so transcripts for a run older than that are gone.

The docs are explicit that this on-disk format is internal to Claude Code and changes
between releases, so every field access here is defensive and the parser reports what it
could not understand rather than guessing. For runs going forward, `solver.py` captures
reasoning directly from the SDK message stream, which is a supported interface; this
module exists to rescue runs that predate that.

Transcripts are matched to instances by searching for the problem statement, because
the runs that need rescuing never recorded their session IDs.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path


def project_dir(cwd: Path | str) -> str:
    """`/Users/x/DFC` -> `-Users-x-DFC`, Claude Code's escaping."""
    return re.sub(r"[^a-zA-Z0-9]", "-", str(cwd))


def store_root() -> Path:
    cfg = os.environ.get("CLAUDE_CONFIG_DIR")
    return Path(cfg) if cfg else Path.home() / ".claude"


def transcripts_for(cwd: Path | str | None = None) -> list[Path]:
    root = store_root() / "projects"
    if not root.exists():
        return []
    if cwd is None:
        return sorted(root.rglob("*.jsonl"), key=lambda p: p.stat().st_mtime)
    d = root / project_dir(cwd)
    return sorted(d.glob("*.jsonl"), key=lambda p: p.stat().st_mtime) if d.exists() else []


@dataclass
class Turn:
    index: int
    thinking: str = ""
    text: str = ""
    tool_calls: list = field(default_factory=list)
    tool_results: list = field(default_factory=list)


@dataclass
class Transcript:
    path: Path
    session_id: str = ""
    first_prompt: str = ""
    turns: list = field(default_factory=list)
    unparsed_lines: int = 0
    unknown_block_types: set = field(default_factory=set)

    @property
    def has_thinking(self) -> bool:
        return any(t.thinking for t in self.turns)


def _blocks(content):
    if isinstance(content, str):
        return [{"type": "text", "text": content}]
    return content if isinstance(content, list) else []


def parse(path: Path, *, max_result_chars: int = 4000) -> Transcript:
    """Defensive read of one transcript file."""
    t = Transcript(path=path)
    turn_i = 0
    for line in path.open(errors="replace"):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            t.unparsed_lines += 1
            continue

        t.session_id = t.session_id or rec.get("sessionId") or rec.get("session_id", "")
        msg = rec.get("message") if isinstance(rec.get("message"), dict) else rec
        role = msg.get("role") or rec.get("type", "")

        if role == "user" and not t.first_prompt:
            for b in _blocks(msg.get("content")):
                if b.get("type") == "text":
                    t.first_prompt = b.get("text", "")[:4000]
                    break

        if role != "assistant":
            # Tool results arrive as user-role messages; attach to the last turn.
            if t.turns:
                for b in _blocks(msg.get("content")):
                    if b.get("type") == "tool_result":
                        c = b.get("content")
                        txt = c if isinstance(c, str) else json.dumps(c)[:max_result_chars]
                        t.turns[-1].tool_results.append(txt[:max_result_chars])
            continue

        turn_i += 1
        turn = Turn(index=turn_i)
        for b in _blocks(msg.get("content")):
            kind = b.get("type", "")
            if kind == "thinking":
                turn.thinking += b.get("thinking", "") or b.get("text", "")
            elif kind == "redacted_thinking":
                turn.thinking += "[redacted thinking block]"
            elif kind == "text":
                turn.text += b.get("text", "")
            elif kind == "tool_use":
                turn.tool_calls.append({
                    "name": b.get("name", ""),
                    "input": b.get("input", {}),
                })
            elif kind:
                t.unknown_block_types.add(kind)
        t.turns.append(turn)
    return t


def find_for_instance(instance_id: str, problem_statement: str = "",
                      cwd: Path | str | None = None) -> list[Transcript]:
    """Match transcripts to an instance.

    The runs that most need this never recorded a session ID, so matching is by
    content: the instance id, or a distinctive slice of the problem statement, appearing
    in the first user prompt.
    """
    needles = [instance_id]
    repo = instance_id.split("__")[0] if "__" in instance_id else ""
    if problem_statement:
        needles.append(problem_statement.strip()[:120])
    out = []
    for p in transcripts_for(cwd):
        try:
            head = p.open(errors="replace").read(200_000)
        except OSError:
            continue
        if any(n and n in head for n in needles) or (repo and repo in head):
            out.append(parse(p))
    return out


def render(t: Transcript, *, thinking: bool = True, results: bool = False,
           width: int = 2000) -> str:
    lines = [f"transcript {t.path.name}  session={t.session_id or '?'}  "
             f"{len(t.turns)} assistant turns"]
    if t.unparsed_lines:
        lines.append(f"  ! {t.unparsed_lines} unparseable line(s)")
    if t.unknown_block_types:
        lines.append(f"  ! unrecognised block types: {sorted(t.unknown_block_types)} "
                     "(the on-disk format is internal and changes between releases)")
    if not t.has_thinking:
        lines.append("  ! no thinking blocks found - extended thinking may have been "
                     "off, or this Claude Code version does not persist them")
    for turn in t.turns:
        lines.append(f"\n{'-' * 70}\nturn {turn.index}")
        if thinking and turn.thinking:
            lines.append("  [thinking]")
            lines.append("    " + turn.thinking[:width].replace("\n", "\n    "))
        if turn.text:
            lines.append("  [says]")
            lines.append("    " + turn.text[:width].replace("\n", "\n    "))
        for c in turn.tool_calls:
            cmd = c["input"].get("command", json.dumps(c["input"])[:300])
            lines.append(f"  [calls {c['name']}] {str(cmd)[:400]}")
        if results:
            for r in turn.tool_results:
                lines.append("  [result]")
                lines.append("    " + r[:width].replace("\n", "\n    "))
    return "\n".join(lines)


__all__ = ["transcripts_for", "parse", "find_for_instance", "render",
           "project_dir", "store_root", "Transcript", "Turn"]
