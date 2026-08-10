#!/usr/bin/env python3
"""Run ONLY the bash-canonicalization self-test from swe_bench_dfc.ipynb.

This is the fast path for "is the bash canonicalization still working?" — it needs
nothing but plain Python (stdlib only). No datasets, requests, swebench, Ollama, or
Docker required.

It pulls the two relevant code cells out of the notebook JSON and runs them:
  - §3 (cell f440c33a): the RULES table + CANONICAL_COMMANDS
  - §5 (cell e26b3e3d): substitute_patch() + the demo self-test
so the printed output is exactly the §5 self-test.

Usage:
    python3 run_canon_test.py
"""
import json
import sys
from pathlib import Path

# The notebook lives next to this script.
NB = Path(__file__).resolve().parent / "swe_bench_dfc.ipynb"

# The two code cells that define + exercise canonicalization.
WANT = {"f440c33a", "e26b3e3d"}


def main() -> int:
    if not NB.exists():
        print(f"error: notebook not found at {NB}", file=sys.stderr)
        return 1

    nb = json.loads(NB.read_text())
    sources = {
        cell["id"]: "".join(cell["source"])
        for cell in nb["cells"]
        if cell.get("cell_type") == "code" and cell.get("id") in WANT
    }

    missing = WANT - set(sources)
    if missing:
        print(
            f"error: could not find cell(s) {sorted(missing)} in the notebook.\n"
            "The cell ids may have changed if the notebook was edited/re-saved.",
            file=sys.stderr,
        )
        return 1

    # Preamble: the config constant the self-test's default arg needs, plus stdlib.
    # (Avoids running §0/§1, which import datasets/requests.)
    preamble = "import re\nfrom collections import Counter\nDEFAULT_INJECT = True\n"

    ns: dict = {}
    exec(preamble, ns)
    exec(sources["f440c33a"], ns)  # §3: RULES + CANONICAL_COMMANDS
    print("\n----- running §5 self-test (substitute_patch on the demo diff) -----\n")
    exec(sources["e26b3e3d"], ns)  # §5: substitute_patch + the demo self-test
    print("\n----- self-test completed without error -----")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
