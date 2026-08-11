"""Shell string -> list of (verb, target, label) flow edges.

Backed by tree-sitter-bash. `bashlex` was the plan's first choice but cannot parse
heredocs at all - it raises `ParsingError: here-document ... delimited by end-of-file`
on `tee f <<'EOF' ... EOF`, which Phase 2 mandates for every write. tree-sitter-bash
parses heredocs natively, isolates the body as data, and exposes `has_error` so the
classifier can fail closed on malformed input.

Two properties this module exists to provide, neither of which string matching can:

* ``>`` is a redirect, not a command. ``grep pat f > out`` is simultaneously a SEARCH
  of ``f`` and a WRITE to ``out`` - two edges from one command (§10).
* A heredoc body is *data*. It must be captured as the payload of the write, because
  ``tee`` a script then ``execute`` it is how the primitive set gets composed into an
  unaudited command (§6.4).
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field

import tree_sitter_bash as _tsb
from tree_sitter import Language, Parser

from . import canon, policy
from .model import (
    Action,
    Confidentiality,
    Decision,
    DEFAULT_FILE,
    Integrity,
    Label,
    Outcome,
    Sink,
    Target,
    TargetKind,
    UNTRUSTED_NETWORK,
    Verb,
)

_LANGUAGE = Language(_tsb.language())


def _parser() -> Parser:
    return Parser(_LANGUAGE)


# --------------------------------------------------------------------------
# Word extraction
# --------------------------------------------------------------------------

#: Node types that can appear as an argv word.
_WORD_TYPES = frozenset({
    "word", "raw_string", "string", "number", "concatenation",
    "simple_expansion", "expansion", "command_substitution",
    "arithmetic_expansion", "process_substitution",
})

#: Node types whose value cannot be known without running something.
_OPAQUE_TYPES = {
    "simple_expansion": "shell variable expansion",
    "expansion": "shell parameter expansion",
    "command_substitution": "command substitution",
    "arithmetic_expansion": "arithmetic expansion",
    "process_substitution": "process substitution",
}

_GLOB_CHARS = ("*", "?", "[")


@dataclass
class Word:
    text: str
    literal: bool = True
    why_opaque: str = ""
    is_glob: bool = False

    @property
    def is_flag(self) -> bool:
        return self.literal and self.text.startswith("-") and self.text != "-"


def _node_text(node, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", "replace")


def _extract_word(node, src: bytes) -> Word:
    """Turn one argv node into a Word, marking anything runtime-determined as opaque."""
    t = node.type
    if t in _OPAQUE_TYPES:
        return Word(_node_text(node, src), literal=False, why_opaque=_OPAQUE_TYPES[t])

    if t == "raw_string":                       # '...' - no expansion possible
        raw = _node_text(node, src)
        return Word(raw[1:-1] if len(raw) >= 2 else raw)

    if t == "string":                           # "..." - may contain expansions
        for child in node.children:
            if child.type in _OPAQUE_TYPES:
                return Word(
                    _node_text(node, src),
                    literal=False,
                    why_opaque=_OPAQUE_TYPES[child.type] + " inside a double-quoted string",
                )
        raw = _node_text(node, src)
        return Word(raw[1:-1] if len(raw) >= 2 else raw)

    if t == "concatenation":
        parts, literal, why = [], True, ""
        for child in node.children:
            w = _extract_word(child, src)
            parts.append(w.text)
            if not w.literal:
                literal, why = False, w.why_opaque
        joined = "".join(parts)
        return Word(joined, literal=literal, why_opaque=why,
                    is_glob=literal and any(c in joined for c in _GLOB_CHARS))

    text = _node_text(node, src)
    return Word(text, is_glob=any(c in text for c in _GLOB_CHARS))


# --------------------------------------------------------------------------
# Simple commands and redirects
# --------------------------------------------------------------------------

@dataclass
class Redirect:
    kind: str                  # ">" | ">>" | "<" | "heredoc"
    target: Word | None = None
    body: str | None = None    # heredoc payload
    fd: int | None = None


@dataclass
class SimpleCommand:
    argv: list[Word] = field(default_factory=list)
    redirects: list[Redirect] = field(default_factory=list)
    raw: str = ""
    start: int = 0             # byte span of the `command` node, for rewrite splicing
    end: int = 0
    in_substitution: bool = False

    @property
    def argv0(self) -> str:
        if not self.argv:
            return ""
        w = self.argv[0]
        return os.path.basename(w.text) if w.literal else w.text

    def args(self) -> list[Word]:
        return self.argv[1:]


def _collect_commands(node, src: bytes, out: list[SimpleCommand], in_sub: bool = False):
    """Depth-first walk collecting every `command` node, including those inside
    substitutions, subshells and loop bodies."""
    if node.type == "command":
        argv = [
            _extract_word(child.children[0] if child.type == "command_name" else child, src)
            for child in node.children
            if child.type in _WORD_TYPES or child.type == "command_name"
        ]
        # `grep '' f` yields an empty-string word, and that word is exactly what makes
        # it a full READ rather than a SEARCH. Never filter empty words out.
        sc = SimpleCommand(
            argv=argv,
            raw=_node_text(node, src),
            start=node.start_byte,
            end=node.end_byte,
            in_substitution=in_sub,
        )
        out.append(sc)
        for child in node.children:
            if child.type in ("command_substitution", "process_substitution"):
                _collect_commands(child, src, out, in_sub=True)
            elif child.type in ("string", "concatenation"):
                for g in child.children:
                    if g.type in ("command_substitution", "process_substitution"):
                        _collect_commands(g, src, out, in_sub=True)
        return

    if node.type == "redirected_statement":
        inner: list[SimpleCommand] = []
        redirects: list[Redirect] = []
        for child in node.children:
            if child.type == "file_redirect":
                redirects.append(_file_redirect(child, src))
            elif child.type == "heredoc_redirect":
                redirects.append(_heredoc_redirect(child, src))
            else:
                _collect_commands(child, src, inner, in_sub)
        if inner:
            inner[-1].redirects.extend(redirects)   # redirect binds the last command
        out.extend(inner)
        return

    sub = node.type in ("command_substitution", "process_substitution")
    for child in node.children:
        _collect_commands(child, src, out, in_sub or sub)


def _file_redirect(node, src: bytes) -> Redirect:
    fd = None
    op = ">"
    target = None
    for child in node.children:
        if child.type == "file_descriptor":
            fd = int(_node_text(child, src))
        elif child.type in (">", ">>", "<", "&>", ">&", "<&", "<<<"):
            op = child.type
        elif child.type in _WORD_TYPES:
            target = _extract_word(child, src)

    # `2>&1` and `>&2` duplicate a file descriptor. They are not writes to files named
    # "1" or "2" - treating them as such fabricates write edges in the flow log, which
    # is exactly the kind of invented dependent variable this rewrite exists to remove.
    if op in (">&", "<&") and target is not None and target.text.isdigit():
        return Redirect(kind="fd-dup", target=target, fd=fd)

    kind = {">": ">", ">>": ">>", "<": "<", "&>": ">", ">&": ">", "<&": "<",
            "<<<": "<"}.get(op, op)
    return Redirect(kind=kind, target=target, fd=fd)


def _heredoc_redirect(node, src: bytes) -> Redirect:
    body = ""
    for child in node.children:
        if child.type == "heredoc_body":
            body = _node_text(child, src)
    return Redirect(kind="heredoc", body=body)


# --------------------------------------------------------------------------
# Scope
# --------------------------------------------------------------------------

#: Paths outside the envelope. Empty by default: §6.4 makes external filesystem
#: writes impossible via a read-only rootfs, so the only external sink is the
#: network. Populate for host-side runs where that guarantee does not hold.
EXTERNAL_PATH_PREFIXES: tuple[str, ...] = ()


def _sink_for_path(path: str) -> Sink:
    if EXTERNAL_PATH_PREFIXES and path.startswith(EXTERNAL_PATH_PREFIXES):
        return Sink.EXTERNAL
    return Sink.INTERNAL


def _path_target(path: str, word: Word | None = None) -> Target:
    return Target(
        kind=TargetKind.PATH,
        value=path,
        label=DEFAULT_FILE,
        extractable=(word.literal if word else True),
        why_opaque=(word.why_opaque if word else ""),
    )


def _heredoc_target(body: str) -> Target:
    digest = hashlib.sha256(body.encode()).hexdigest()[:12]
    return Target(
        kind=TargetKind.LITERAL,
        value=f"heredoc:{len(body)}b:sha256:{digest}",
        label=Label(Confidentiality.INTERNAL, Integrity.UNKNOWN),
    )


# --------------------------------------------------------------------------
# Per-command classification
# --------------------------------------------------------------------------

#: grep flags that consume the following argument.
_GREP_VALUE_FLAGS = frozenset({"-m", "-A", "-B", "-C", "-e", "-f", "--regexp", "--file"})
_AWK_VALUE_FLAGS = frozenset({"-F", "-v", "-f", "--field-separator", "--assign", "--file"})
_SED_VALUE_FLAGS = frozenset({"-e", "-f", "--expression", "--file"})


def _positional(args: list[Word], value_flags: frozenset[str]) -> list[Word]:
    """Positional arguments, skipping flags and the values they consume."""
    out, skip = [], False
    for w in args:
        if skip:
            skip = False
            continue
        if w.is_flag:
            base = w.text.split("=", 1)[0]
            if base in value_flags and "=" not in w.text and len(w.text) <= 3:
                skip = True
            continue
        out.append(w)
    return out


@dataclass
class CmdResult:
    actions: list[Action]
    admissible: bool
    reason: str = ""


def _classify_one(sc: SimpleCommand, arm: policy.Arm) -> CmdResult:
    argv0 = sc.argv0
    args = sc.args()
    acts: list[Action] = []

    def act(verb: Verb, targets: list[Target], sink: Sink | None = None) -> Action:
        return Action(verb=verb, targets=targets, raw=sc.raw, sink=sink, argv0=argv0)

    if not argv0:
        return CmdResult([], False, "empty command")

    if not sc.argv[0].literal:
        return CmdResult(
            [act(Verb.EXECUTE, [Target(TargetKind.OPAQUE, sc.argv[0].text,
                                       extractable=False,
                                       why_opaque=sc.argv[0].why_opaque)])],
            False,
            "command name is not statically extractable "
            f"({sc.argv[0].why_opaque})",
        )

    if sc.in_substitution:
        # The command runs, but its output is spliced into another command line, so the
        # outer command's targets are not statically extractable. Classify it anyway so
        # the flow log records the read; admissibility is decided by the outer command.
        pass

    # ---- hard denials -------------------------------------------------
    if argv0 in policy.HARD_DENY and argv0 not in ("wget", "find", "chmod", "chown"):
        return CmdResult(
            [act(Verb.EXECUTE, [Target(TargetKind.OPAQUE, sc.raw, extractable=False,
                                       why_opaque=f"`{argv0}` admits arbitrary behaviour")])],
            False,
            f"`{argv0}` is outside the policed primitive set: it does not map to exactly "
            "one verb with statically extractable targets",
        )

    # ---- ls -----------------------------------------------------------
    if argv0 == "ls":
        paths = _positional(args, frozenset()) or [Word(".")]
        acts.append(act(Verb.LOCATE, [_path_target(w.text, w) for w in paths]))
        return CmdResult(acts, True)

    # ---- grep ---------------------------------------------------------
    if argv0 == "grep":
        if any(w.text in ("-f", "--file") for w in args):
            return CmdResult(
                [act(Verb.SEARCH, [Target(TargetKind.OPAQUE, sc.raw, extractable=False,
                                          why_opaque="grep -f: patterns come from a file")])],
                False,
                "grep -f loads patterns from a file; the pattern is the "
                "audit record and must be on the command line")
        pos = _positional(args, _GREP_VALUE_FLAGS)
        pattern = pos[0].text if pos else ""
        files = pos[1:]
        # §2: `grep "" f` is a full read (selectivity 1.0); a real pattern is a search.
        verb = Verb.READ if pattern == "" else Verb.SEARCH
        targets = [_path_target(w.text, w) for w in files] or [
            Target(TargetKind.STDIN, "-", label=DEFAULT_FILE)
        ]
        a = act(verb, targets)
        a.notes = f"pattern={pattern!r}"
        acts.append(a)
        return CmdResult(acts, True)

    # ---- tee ----------------------------------------------------------
    if argv0 == "tee":
        files = _positional(args, frozenset())
        targets = [_path_target(w.text, w) for w in files]
        sink = Sink.EXTERNAL if any(
            _sink_for_path(t.value) is Sink.EXTERNAL for t in targets
        ) else Sink.INTERNAL
        acts.append(act(Verb.WRITE, targets or [Target(TargetKind.STDOUT, "-")], sink))
        return CmdResult(acts, True)

    # ---- curl ---------------------------------------------------------
    if argv0 == "curl":
        return _classify_curl(sc, args, act)

    # ---- awk (D3, restricted) -----------------------------------------
    if argv0 == "awk":
        if "awk" not in arm.primitives and arm.mode == "enforce":
            return CmdResult([], False, "awk is not admitted in this arm")
        pos = _positional(args, _AWK_VALUE_FLAGS)
        program = pos[0].text if pos else ""
        files = pos[1:]
        ok, why = policy.awk_admissible(program, [w.text for w in args])
        targets = [_path_target(w.text, w) for w in files] or [
            Target(TargetKind.STDIN, "-", label=DEFAULT_FILE)
        ]
        a = act(Verb.TRANSFORM, targets)
        a.notes = "awk reads each input stream in full; label as a full read"
        acts.append(a)
        return CmdResult(acts, ok, "" if ok else why)

    # ---- head / tail (D11, stdin form only) ---------------------------
    if argv0 in policy.STREAM_TRUNCATORS:
        if argv0 not in arm.primitives and arm.mode == "enforce":
            return CmdResult([], False, f"`{argv0}` is not admitted in this arm")
        files = [w for w in _positional(args, frozenset({"-n", "-c"})) if not w.is_flag]
        ok, why = policy.stream_truncator_admissible([w.text for w in files])
        if not ok:
            # Named a file, so it is a READ. Denied here so the canon table can fold it
            # onto `grep -m N ""`, which is the admissible form.
            return CmdResult([act(Verb.READ, [_path_target(w.text, w) for w in files])],
                             False, why)
        a = act(Verb.TRANSFORM, [Target(TargetKind.STDIN, "-", label=DEFAULT_FILE)])
        a.notes = ("stream truncation: no file operand, so no target to extract and no "
                   "data reachable that the upstream command did not already log")
        return CmdResult([a], True)

    # ---- sed ----------------------------------------------------------
    if argv0 == "sed":
        arg_texts = [w.text for w in args]
        in_place = any(t == "-i" or t.startswith("-i") for t in arg_texts)
        pos = _positional(args, _SED_VALUE_FLAGS)
        script = pos[0].text if pos else ""
        files = pos[1:]
        if not in_place:
            # Still a READ of every input file. Emitting nothing here left a silent
            # hole in the flow log: `sed -n '55,100p' f` is the agent's most common
            # read idiom and it was recorded with no flow edge at all.
            targets = [_path_target(w.text, w) for w in files] or [
                Target(TargetKind.STDIN, "-", label=DEFAULT_FILE)
            ]
            a = act(Verb.READ, targets)
            a.notes = f"stream sed script={script!r}"
            return CmdResult([a], False,
                             "stream `sed` is not a primitive; fold onto restricted awk")
        ok, why = policy.sed_admissible(script, arg_texts, arm)
        targets = [_path_target(w.text, w) for w in files]
        a = act(Verb.WRITE, targets, Sink.INTERNAL)
        a.notes = f"sed -i script={script!r}"
        acts.append(a)
        return CmdResult(acts, ok, "" if ok else why)

    # ---- git ----------------------------------------------------------
    if argv0 == "git":
        pos = _positional(args, frozenset())
        sub = pos[0].text if pos else ""
        if sub in policy.GIT_NETWORK_SUBCOMMANDS:
            sink = Sink.EXTERNAL if sub in ("push", "remote") else None
            verb = Verb.WRITE if sink else Verb.FETCH
            a = act(verb, [Target(TargetKind.URL, f"git:{sub}", label=UNTRUSTED_NETWORK)], sink)
            return CmdResult([a], False,
                             f"`git {sub}` is a network edge, not an infrastructure command")
        if sub in policy.GIT_ALLOWED_SUBCOMMANDS:
            return CmdResult([act(Verb.NONFLOW, [_path_target(".")])], True)
        return CmdResult([act(Verb.READ, [_path_target(".git")])], False,
                         f"`git {sub}` is not on the infrastructure allowlist")

    # ---- python / pytest ----------------------------------------------
    if argv0 in policy.PYTHON_NAMES:
        arg_texts = [w.text for w in args]
        if "-c" in arg_texts:
            return CmdResult(
                [act(Verb.EXECUTE, [Target(TargetKind.OPAQUE, sc.raw, extractable=False,
                                           why_opaque="python3 -c is the canonical escape")])],
                False,
                "`python3 -c` admits arbitrary behaviour behind one opaque token",
            )
        if arg_texts[:2] == ["-m", "pytest"] or "pytest" in arg_texts[:2]:
            return CmdResult([_execute_action(sc, argv0)], True)
        # `python - <<'EOF'` reads its program from stdin. It is `python3 -c` wearing a
        # heredoc, and it is the composition escape of §6.4 appearing as the agent's
        # main editing path - so it must be recorded, not silently dropped.
        why = ("python reads its program from stdin (`python -`)"
               if "-" in arg_texts else f"`{argv0}` is not a test entry point")
        return CmdResult(
            [act(Verb.EXECUTE, [Target(TargetKind.OPAQUE, sc.raw, extractable=False,
                                       why_opaque=why)])],
            False,
            "`python` is admissible only as `-m pytest`, the test entry point")

    if argv0 == "pytest":
        return CmdResult([_execute_action(sc, argv0)], True)

    # ---- infrastructure ------------------------------------------------
    if argv0 in policy.INFRA_ALLOWLIST:
        verb = policy.INFRA_ALLOWLIST[argv0]
        targets = [_path_target(w.text, w) for w in _positional(args, frozenset())]
        return CmdResult([act(verb, targets)], True)

    # ---- anything else -------------------------------------------------
    return CmdResult(
        [act(Verb.EXECUTE, [Target(TargetKind.OPAQUE, sc.raw, extractable=False,
                                   why_opaque=f"`{argv0}` is not a primitive")])],
        False,
        f"`{argv0}` is outside the policed primitive set. Allowed: ls, grep, curl, "
        "tee/> (use `tee path <<'EOF'` to write a file), restricted awk, "
        "head/tail on a pipe"
        + (", address-scoped sed -i" if arm.allow_sed_inplace else "")
        + ". Tests run with pytest.",
    )


def _execute_action(sc: SimpleCommand, argv0: str) -> Action:
    """EXECUTE is opaque by construction (§6.4). The command line is the audit record;
    containment is the envelope's job, not the classifier's."""
    a = Action(
        verb=Verb.EXECUTE,
        targets=[Target(TargetKind.OPAQUE, sc.raw, label=DEFAULT_FILE, extractable=False,
                        why_opaque="execute node - read set bounded by the envelope mount set")],
        raw=sc.raw,
        argv0=argv0,
    )
    a.notes = "read set bounded, not observed; write set observed via container diff"
    return a


def _classify_curl(sc: SimpleCommand, args: list[Word], act) -> CmdResult:
    arg_texts = [w.text for w in args]
    form = policy.curl_form(arg_texts)

    if form == "opaque":
        return CmdResult(
            [act(Verb.FETCH, [Target(TargetKind.OPAQUE, sc.raw, extractable=False,
                                     why_opaque="curl -K loads options from a file")])],
            False,
            "`curl -K/--config` loads its URLs, methods and output paths from a file, so "
            "the targets are not on the command line",
        )

    urls = [w for w in _positional(args, frozenset())
            if "://" in w.text or w.text.startswith("www.")]
    acts: list[Action] = []

    # `curl file://...` is a local READ, not a network fetch (§2).
    local = [w for w in urls if w.text.startswith("file://")]
    remote = [w for w in urls if not w.text.startswith("file://")]

    for w in local:
        acts.append(act(Verb.READ, [_path_target(w.text[len("file://"):], w)]))

    if form == "egress":
        payload: list[Target] = []
        for i, t in enumerate(arg_texts):
            base = t.split("=", 1)[0]
            if base in policy.CURL_EGRESS_FLAGS and i + 1 < len(arg_texts):
                val = arg_texts[i + 1]
                if val.startswith("@"):
                    acts.append(act(Verb.READ, [_path_target(val[1:])]))
                    payload.append(_path_target(val[1:]))
                else:
                    payload.append(Target(TargetKind.LITERAL, val))
        sinks = [Target(TargetKind.URL, w.text, label=UNTRUSTED_NETWORK) for w in remote]
        a = act(Verb.WRITE, sinks or payload, Sink.EXTERNAL)
        a.notes = "HIGHEST-PRIORITY boundary: curl -d/-F/-T is egress"
        acts.append(a)
        return CmdResult(acts, True)

    if form == "sink":
        for w in remote:
            acts.append(act(Verb.FETCH, [Target(TargetKind.URL, w.text,
                                                label=UNTRUSTED_NETWORK)]))
        out_paths: list[Target] = []
        for i, t in enumerate(arg_texts):
            if t in ("-o", "--output") and i + 1 < len(arg_texts):
                out_paths.append(_path_target(arg_texts[i + 1]))
            elif t in ("-O", "--remote-name"):
                for w in remote:
                    out_paths.append(_path_target(os.path.basename(w.text.split("?")[0])))
        a = act(Verb.WRITE, out_paths, Sink.INTERNAL)
        # Content written came off the network: integrity is untrusted.
        for t in a.targets:
            t.label = t.label.join(UNTRUSTED_NETWORK)
        acts.append(a)
        return CmdResult(acts, True)

    for w in remote:
        acts.append(act(Verb.FETCH, [Target(TargetKind.URL, w.text, label=UNTRUSTED_NETWORK)]))
    if not acts:
        return CmdResult([], False, "curl with no extractable URL")
    return CmdResult(acts, True)


def _redirect_actions(sc: SimpleCommand) -> list[Action]:
    """Redirects are edges in their own right. `>` is not a command (§10)."""
    out: list[Action] = []
    for r in sc.redirects:
        if r.kind == "fd-dup":
            a = Action(verb=Verb.NONFLOW, targets=[], raw=sc.raw, argv0=sc.argv0)
            a.notes = f"file-descriptor duplication {r.fd or ''}>&{r.target.text if r.target else ''}"
            out.append(a)
        elif r.kind in (">", ">>"):
            if r.target is None:
                continue
            t = _path_target(r.target.text, r.target)
            a = Action(verb=Verb.WRITE, targets=[t], raw=sc.raw,
                       sink=_sink_for_path(t.value), argv0=sc.argv0)
            a.notes = f"shell redirect {r.kind}" + (f" fd={r.fd}" if r.fd else "")
            out.append(a)
        elif r.kind == "<":
            if r.target is None:
                continue
            a = Action(verb=Verb.READ, targets=[_path_target(r.target.text, r.target)],
                       raw=sc.raw, argv0=sc.argv0)
            a.notes = "shell redirect <"
            out.append(a)
        elif r.kind == "heredoc":
            a = Action(verb=Verb.WRITE, targets=[_heredoc_target(r.body or "")],
                       raw=sc.raw, sink=Sink.INTERNAL, argv0=sc.argv0)
            a.notes = ("heredoc payload - content supplied inline; this is the write half "
                       "of the tee-then-execute composition (§6.4)")
            out.append(a)
    return out


# --------------------------------------------------------------------------
# Top level
# --------------------------------------------------------------------------

def parse_commands(command: str) -> tuple[list[SimpleCommand], bool, str]:
    """Returns (commands, parse_ok, error). `parse_ok=False` must fail closed under
    enforcement and fail open under observation (D5)."""
    src = command.encode()
    tree = _parser().parse(src)
    if tree.root_node.has_error:
        return [], False, "shell parse error: input is not well-formed bash"
    cmds: list[SimpleCommand] = []
    _collect_commands(tree.root_node, src, cmds)
    return cmds, True, ""


def classify(command: str, arm: policy.Arm, *, session_id: str = "",
             instance_id: str = "") -> Decision:
    """Classify, then decide. This is the whole gate."""
    cmds, ok, err = parse_commands(command)

    if not ok:
        if arm.mode == "observe":
            return Decision(Outcome.OBSERVED, command, [], arm=arm.name,
                            parse_ok=False, parse_error=err,
                            reason="observe mode fails open", session_id=session_id,
                            instance_id=instance_id)
        return Decision(Outcome.DENIED, command, [], arm=arm.name, parse_ok=False,
                        parse_error=err,
                        reason="Command could not be parsed, so its targets cannot be "
                               "extracted. Rewrite it as separate, simpler commands.",
                        session_id=session_id, instance_id=instance_id)

    results = [(sc, _classify_one(sc, arm)) for sc in cmds]

    # Safety net. A command that produces no flow edge is invisible in the flow log,
    # and under observe mode (D5) that silently shrinks the coverage denominator and
    # leaves a real read unaudited. Nothing may pass through unrecorded.
    for sc, res in results:
        if not res.actions:
            res.actions.append(Action(
                verb=Verb.EXECUTE, raw=sc.raw, argv0=sc.argv0,
                targets=[Target(TargetKind.OPAQUE, sc.raw, extractable=False,
                                why_opaque="unclassified command")],
            ))

    actions: list[Action] = []
    for sc, res in results:
        actions.extend(res.actions)
        actions.extend(_redirect_actions(sc))

    # Command substitution makes the *outer* command's targets unextractable.
    substituted = [sc for sc in cmds if sc.in_substitution]

    if arm.mode == "observe":
        d = Decision(Outcome.OBSERVED, command, actions, arm=arm.name,
                     session_id=session_id, instance_id=instance_id)
        d.reason = "observe-only: classified and logged, not gated"
        return d

    bad = [(sc, res) for sc, res in results if not res.admissible]
    if substituted and not bad:
        bad = [(cmds[0], CmdResult([], False,
                                   "command substitution: the outer command's targets are "
                                   "not statically extractable"))]

    if not bad:
        return Decision(Outcome.PASSTHROUGH, command, actions, arm=arm.name,
                        session_id=session_id, instance_id=instance_id)

    if not arm.allow_rewrite:
        return Decision(Outcome.DENIED, command, actions, arm=arm.name,
                        reason=bad[0][1].reason, session_id=session_id,
                        instance_id=instance_id)

    return _try_rewrite(command, cmds, results, bad, arm, session_id, instance_id)


def _try_rewrite(command, cmds, results, bad, arm, session_id, instance_id) -> Decision:
    """D2: fold the inadmissible segments onto the primitive set and splice.

    The rewritten command is re-classified by this same function's caller path before
    being accepted. A rewrite that does not itself pass the gate is not a rewrite.
    """
    src = command
    replacements: list[tuple[int, int, str, canon.Rule]] = []
    for sc, res in bad:
        if sc.in_substitution:
            return Decision(Outcome.DENIED, command, _all_actions(results), arm=arm.name,
                            reason="command substitution cannot be canonicalized; its "
                                   "output is not statically extractable",
                            session_id=session_id, instance_id=instance_id)
        folded, rule = canon.canonicalize(sc.raw)
        if rule is None or folded == sc.raw:
            return Decision(Outcome.DENIED, command, _all_actions(results), arm=arm.name,
                            reason=res.reason, session_id=session_id,
                            instance_id=instance_id)
        if rule.lands_in == "python3-c":
            return Decision(Outcome.DENIED, command, _all_actions(results), arm=arm.name,
                            reason=(f"{res.reason}. The canonical rewrite for this command "
                                    "targets `python3 -c`, which is not admitted (D3)."),
                            session_id=session_id, instance_id=instance_id)
        replacements.append((sc.start, sc.end, folded, rule))

    out = src
    for start, end, new, _rule in sorted(replacements, key=lambda r: -r[0]):
        out = out[:start] + new + out[end:]

    # Re-verify: the rewritten form must itself pass the gate.
    recheck = classify(out, policy.Arm(
        name=arm.name, mode="enforce", primitives=arm.primitives,
        allow_sed_inplace=arm.allow_sed_inplace, allow_rewrite=False,
        sed_require_address_for_delete=arm.sed_require_address_for_delete,
    ), session_id=session_id, instance_id=instance_id)
    if recheck.outcome is Outcome.DENIED:
        return Decision(Outcome.DENIED, command, _all_actions(results), arm=arm.name,
                        reason=(f"{bad[0][1].reason}. A canonical rewrite exists but does "
                                f"not itself pass the gate: {recheck.reason}"),
                        session_id=session_id, instance_id=instance_id)

    actions = recheck.actions
    for a in actions:
        for _s, _e, _n, rule in replacements:
            if a.rule is None:
                a.rule, a.csv_row, a.status = rule.name, rule.csv_row, rule.status
                a.police, a.fidelity_risk, a.notes = rule.police, rule.fidelity_risk, rule.notes
                break

    return Decision(Outcome.REWRITTEN, command, actions, updated_command=out,
                    arm=arm.name,
                    reason="folded onto the primitive set: "
                           + ", ".join(r[3].name for r in replacements),
                    session_id=session_id, instance_id=instance_id)


def _all_actions(results) -> list[Action]:
    out: list[Action] = []
    for sc, res in results:
        out.extend(res.actions)
        out.extend(_redirect_actions(sc))
    return out


__all__ = ["classify", "parse_commands", "SimpleCommand", "Word", "Redirect",
           "EXTERNAL_PATH_PREFIXES"]
