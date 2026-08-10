"""DFC - data-flow control for agent shell usage.

See DFC_STATUS_AND_BUILD_PLAN.md for the research question and DECISIONS.md for the
design decisions that resolve the ambiguities it left open.
"""

__version__ = "0.1.0"

from .model import (  # noqa: F401
    Action, Confidentiality, Decision, Integrity, Label, Outcome, Sink,
    Target, TargetKind, Verb,
)
from .policy import ARMS, ARM0, ARM1, ARM2, Arm  # noqa: F401
from .classifier import classify, parse_commands  # noqa: F401

__all__ = [
    "Action", "Confidentiality", "Decision", "Integrity", "Label", "Outcome",
    "Sink", "Target", "TargetKind", "Verb",
    "ARMS", "ARM0", "ARM1", "ARM2", "Arm",
    "classify", "parse_commands",
]
