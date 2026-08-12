"""Classifier fingerprint.

Arm 0 and Arm 1 were run days apart with different versions of the classifier, and
nothing anywhere recorded that fact. The resolve-rate comparison survived it - observe
mode never alters a command, so Arm 0's trajectories were unaffected - but every
flow-derived number was silently incomparable: Arm 0's log recorded zero `read` verbs
because of a bug that was fixed before Arm 1 ran.

A hash of the three modules that decide what a command *means* is stamped into run
metadata and into every flow record, so a mixed corpus announces itself instead of
quietly producing a wrong number.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

#: The modules whose contents change how a command is classified. `model.py` is
#: excluded deliberately: it defines the vocabulary, not the decisions, and churn there
#: (new fields, docstrings) should not invalidate a comparison.
FINGERPRINTED = ("classifier.py", "policy.py", "canon.py")


def _read(name: str) -> bytes:
    return (Path(__file__).with_name(name)).read_bytes()


def classifier_fingerprint() -> str:
    """Short content hash of the classification logic."""
    h = hashlib.sha256()
    for name in FINGERPRINTED:
        h.update(name.encode())
        try:
            h.update(_read(name))
        except OSError:
            h.update(b"<missing>")
    return h.hexdigest()[:12]


def version_block() -> dict:
    from . import __version__
    return {
        "dfc_version": __version__,
        "classifier_fingerprint": classifier_fingerprint(),
        "fingerprinted_modules": list(FINGERPRINTED),
    }


def comparable(*fingerprints: str) -> tuple[bool, str]:
    """Whether flow-derived metrics from these runs may be compared.

    Returns (ok, reason). Resolve rates remain comparable across fingerprints -
    classification never alters what the agent ran under observe mode, and under
    enforce mode the fingerprint *is* the treatment. This check is specifically about
    coverage, verb histograms, selectivity and denial attribution.
    """
    present = {f for f in fingerprints if f}
    if len(present) <= 1:
        return True, ""
    return False, (
        "runs were produced by different classifier versions "
        f"({', '.join(sorted(present))}), so flow-derived metrics - coverage, verb "
        "counts, selectivity, denial attribution - are not comparable between them. "
        "Resolve rates still are. Re-run the older arm to compare the rest."
    )


__all__ = ["classifier_fingerprint", "version_block", "comparable", "FINGERPRINTED"]
