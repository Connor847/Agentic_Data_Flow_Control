"""Core vocabulary for the DFC flow model.

Two orthogonal axes, per §2 of DFC_STATUS_AND_BUILD_PLAN.md. Conflating them was an
early mistake, so they are separate types here and never collapse into one enum:

  Axis 1 - Verb   : a property of the *command*
  Axis 2 - Label  : a property of the *resource touched*

`unknown` integrity is the default for anything without a provenance record, and the
combination rule is **join, not meet** - conservative in the direction that over-taints
rather than under-taints.
"""

from __future__ import annotations

import enum
import json
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any


# --------------------------------------------------------------------------
# Axis 1 - verbs
# --------------------------------------------------------------------------

class Verb(str, enum.Enum):
    """A property of the command. The admission criterion (§2) requires that an
    admissible command map to *exactly one* of these."""

    LOCATE = "locate"        # ls - metadata only, names/sizes/perms
    SEARCH = "search"        # grep PAT f - partial read; the pattern is the audit record
    READ = "read"            # grep "" f - selectivity 1.0
    WRITE = "write"          # tee / > / scoped sed -i
    FETCH = "fetch"          # curl GET, no body - always taints integrity untrusted
    TRANSFORM = "transform"  # restricted awk - stream to stream, no boundary crossed
    EXECUTE = "execute"      # pytest, build - opaque; governed by the envelope (§6.4)
    NONFLOW = "nonflow"      # cd, pwd, rm, chmod - existence/access/process, not content


#: Verbs that read content out of a resource. Used to decide whose labels flow.
INGRESS_VERBS = frozenset({Verb.SEARCH, Verb.READ, Verb.FETCH, Verb.TRANSFORM})

#: Verbs that move content into a sink.
EGRESS_VERBS = frozenset({Verb.WRITE})


class Sink(str, enum.Enum):
    """Where a WRITE lands. The exfil check fires on EXTERNAL."""

    INTERNAL = "internal"    # in-scope path: repo, scratch
    EXTERNAL = "external"    # network, out-of-boundary path, subagent call


# --------------------------------------------------------------------------
# Axis 2 - labels
# --------------------------------------------------------------------------

class Confidentiality(enum.IntEnum):
    """public < internal < sensitive. Join is max."""

    PUBLIC = 0
    INTERNAL = 1
    SENSITIVE = 2


class Integrity(enum.IntEnum):
    """trusted < unknown < untrusted. Join is max. `UNKNOWN` is the default."""

    TRUSTED = 0
    UNKNOWN = 1
    UNTRUSTED = 2


@dataclass(frozen=True)
class Label:
    """A point in the product lattice. Defaults are the conservative ones."""

    c: Confidentiality = Confidentiality.INTERNAL
    i: Integrity = Integrity.UNKNOWN

    def join(self, other: "Label") -> "Label":
        """Least upper bound. Conservative: over-taints, never under-taints."""
        return Label(
            c=Confidentiality(max(int(self.c), int(other.c))),
            i=Integrity(max(int(self.i), int(other.i))),
        )

    def leq(self, other: "Label") -> bool:
        """Lattice ordering: self flows to other without violating policy."""
        return int(self.c) <= int(other.c) and int(self.i) <= int(other.i)

    @staticmethod
    def bottom() -> "Label":
        return Label(Confidentiality.PUBLIC, Integrity.TRUSTED)

    @staticmethod
    def join_all(labels) -> "Label":
        out = Label.bottom()
        for lab in labels:
            out = out.join(lab)
        return out

    def as_dict(self) -> dict[str, str]:
        return {"c": self.c.name.lower(), "i": self.i.name.lower()}

    def __str__(self) -> str:  # pragma: no cover - display only
        return f"{self.c.name.lower()}/{self.i.name.lower()}"


#: Label carried by anything arriving over the network. Fetch always taints integrity.
UNTRUSTED_NETWORK = Label(Confidentiality.PUBLIC, Integrity.UNTRUSTED)

#: Default for a repo file with no provenance record.
DEFAULT_FILE = Label(Confidentiality.INTERNAL, Integrity.UNKNOWN)


# --------------------------------------------------------------------------
# Targets and actions
# --------------------------------------------------------------------------

class TargetKind(str, enum.Enum):
    PATH = "path"
    URL = "url"
    STDIN = "stdin"
    STDOUT = "stdout"
    LITERAL = "literal"      # heredoc body / argv payload - content supplied inline
    SUBAGENT = "subagent"
    OPAQUE = "opaque"        # could not be statically extracted


@dataclass
class Target:
    """One resource touched by one action.

    `extractable=False` means the admission criterion (§2) is violated: the target
    could not be determined from the command line without running it. Under enforcement
    that is a hard denial, not a warning.
    """

    kind: TargetKind
    value: str
    label: Label = field(default_factory=lambda: DEFAULT_FILE)
    extractable: bool = True
    why_opaque: str = ""

    def as_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "kind": self.kind.value,
            "value": self.value,
            "label": self.label.as_dict(),
            "extractable": self.extractable,
        }
        if self.why_opaque:
            d["why_opaque"] = self.why_opaque
        return d


@dataclass
class Action:
    """One (verb, targets) edge extracted from one simple command.

    A single shell command can produce several: `grep pat f > out` is simultaneously a
    SEARCH of `f` and a WRITE to `out`, and that is the point of parsing the AST rather
    than matching strings.
    """

    verb: Verb
    targets: list[Target] = field(default_factory=list)
    raw: str = ""                     # the sub-command exactly as written
    sink: Sink | None = None          # set for WRITE
    argv0: str = ""

    # Provenance from the canonicalization table (dfc/canon.py), when a rule matched.
    rule: str | None = None
    csv_row: int | None = None
    status: str | None = None         # Verified / Native / Partial / Limitation / ...
    police: str = "LOW"
    fidelity_risk: bool = False       # D4: status in {Partial, Limitation}
    notes: str = ""

    # §2 finding 1: log selectivity per call and track the running total.
    # bytes_returned / bytes_in_source, filled in post-execution by the PostToolUse side.
    selectivity: float | None = None

    def derived_label(self) -> Label:
        """Join of every label this action touched. Used for taint propagation."""
        return Label.join_all(t.label for t in self.targets)

    def has_opaque_target(self) -> bool:
        return any(not t.extractable for t in self.targets)

    def as_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "verb": self.verb.value,
            "argv0": self.argv0,
            "raw": self.raw,
            "targets": [t.as_dict() for t in self.targets],
            "derived_label": self.derived_label().as_dict(),
        }
        if self.sink is not None:
            d["sink"] = self.sink.value
        if self.rule:
            d.update(
                rule=self.rule,
                csv_row=self.csv_row,
                status=self.status,
                police=self.police,
                fidelity_risk=self.fidelity_risk,
            )
            if self.notes:
                d["notes"] = self.notes
        if self.selectivity is not None:
            d["selectivity"] = self.selectivity
        return d


# --------------------------------------------------------------------------
# Decisions
# --------------------------------------------------------------------------

class Outcome(str, enum.Enum):
    """D2: three populations, reported separately.

    `REWRITTEN` is the size of the translation layer. `DENIED` is the restriction.
    Only `DENIED` counts as an escape attempt in the §7 metrics.
    """

    PASSTHROUGH = "passthrough"   # already canonical, ran as written
    REWRITTEN = "rewritten"       # folded onto the primitive set, silently
    DENIED = "denied"             # no admissible rewrite exists
    OBSERVED = "observed"         # Arm 0: classified and logged, never gated


@dataclass
class Decision:
    """What the hook returns, and what goes in the flow log."""

    outcome: Outcome
    command: str
    actions: list[Action] = field(default_factory=list)
    updated_command: str | None = None
    reason: str = ""
    arm: str = ""
    parse_ok: bool = True
    parse_error: str = ""
    ts: float = field(default_factory=time.time)
    id: str = field(default_factory=lambda: f"act-{uuid.uuid4().hex[:8]}")
    session_id: str = ""
    instance_id: str = ""

    @property
    def allowed(self) -> bool:
        return self.outcome is not Outcome.DENIED

    def derived_label(self) -> Label:
        return Label.join_all(a.derived_label() for a in self.actions)

    def trifecta(self) -> bool:
        """§2 trifecta predicate, computed over this command's flow graph.

        True iff sensitive taint AND untrusted taint are both present in a value
        reaching an external sink. Computed, not heuristic.
        """
        ingress = Label.join_all(
            t.label
            for a in self.actions
            if a.verb in INGRESS_VERBS
            for t in a.targets
        )
        external = any(
            a.verb in EGRESS_VERBS and a.sink is Sink.EXTERNAL for a in self.actions
        )
        return (
            external
            and ingress.c is Confidentiality.SENSITIVE
            and ingress.i is Integrity.UNTRUSTED
        )

    def as_record(self) -> dict[str, Any]:
        """One line of the flow log (JSONL)."""
        rec: dict[str, Any] = {
            "id": self.id,
            "ts": self.ts,
            "arm": self.arm,
            "session_id": self.session_id,
            "instance_id": self.instance_id,
            "outcome": self.outcome.value,
            "command": self.command,
            "parse_ok": self.parse_ok,
            "actions": [a.as_dict() for a in self.actions],
            "derived_label": self.derived_label().as_dict(),
            "trifecta": self.trifecta(),
            "fidelity_risk": any(a.fidelity_risk for a in self.actions),
        }
        if self.updated_command is not None:
            rec["updated_command"] = self.updated_command
        if self.reason:
            rec["reason"] = self.reason
        if self.parse_error:
            rec["parse_error"] = self.parse_error
        return rec

    def as_json(self) -> str:
        return json.dumps(self.as_record(), separators=(",", ":"), sort_keys=False)
