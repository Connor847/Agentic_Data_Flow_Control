"""Canonicalization table integrity (D1, D4).

This table is the asset carried over from the old pipeline. These tests exist so that
edits to it are visible rather than silent.
"""

from __future__ import annotations

import pytest

from dfc import canon


def test_rule_count():
    """The source of truth is `big ballin - Sheet6.csv`, 56 rules. D30 added two
    forms of the same CSV row (7, sed range read): the stream form and the
    single-line form. They carry the CSV row number, not a new one."""
    assert len(canon.RULES) == 58
    assert sum(1 for r in canon.RULES if r.csv_row == 7) == 3


def test_rule_names_unique():
    names = [r.name for r in canon.RULES]
    assert len(names) == len(set(names))


def test_csv_provenance_preserved():
    for r in canon.RULES:
        assert 1 <= r.csv_row <= 56, r.name


def test_bucket_histogram_stable():
    assert canon.bucket_histogram() == {
        "python3-c": 6, "curl": 9, "grep": 11, "tee": 9, "ls": 7, "awk": 10,
        "non-flow": 6,   # grep 9 -> 11: D30 stream/single-line sed reads
    }


def test_lossy_rules_flagged():
    """D4: Partial and Limitation are the non-equivalent rewrites.

    Went from 14 to 16 when the rules were widened on 2026-08-11: `cat_read` now
    accepts multiple files (grep prefixes each line with the filename) and
    `find_enumerate` now accepts name filters (ls -R returns a superset). Both
    widenings buy coverage at the price of fidelity, so both must carry the flag.
    """
    lossy = [r.name for r in canon.RULES if r.fidelity_risk]
    assert len(lossy) == 16
    assert "cp_copy" not in lossy          # Verified: byte-identical content
    assert "du_size" in lossy              # Partial: du aggregates, ls does not
    assert "file_magic" in lossy           # Limitation: reads content, not metadata
    assert "cat_read" in lossy             # Partial since the multi-file widening
    assert "find_enumerate" in lossy       # Partial: name filter dropped


def test_only_binary_dump_lands_in_python3c_among_rewrites():
    """D3: python3 -c is not readmitted, so a rewrite targeting it is unusable.
    `binary_dump` is the only *rewriting* rule in that position; the rest are escapes
    with no rewrite at all."""
    rewriting = [r for r in canon.RULES if r.rewrite is not None]
    assert [r.name for r in rewriting if r.lands_in == "python3-c"] == ["binary_dump"]


def test_awk_targeting_rewrites_are_now_usable():
    """D3: restricted awk is admitted, so these rewrites have a legal target."""
    awk_targeted = [r.name for r in canon.RULES
                    if r.rewrite is not None and r.lands_in == "awk"]
    assert "tail_last_n" in awk_targeted
    assert "cut_fields" in awk_targeted
    assert "sed_range_read" in awk_targeted


def test_order_is_load_bearing():
    """Escapes must be declared before the general forms they would otherwise fall
    through to: `xargs` before `ls`, `find -exec` before `find -type f`."""
    names = [r.name for r in canon.RULES]
    assert names.index("xargs_build") < names.index("ls_native")
    assert names.index("find_exec") < names.index("find_enumerate")
    assert names.index("curl_post_egress") < names.index("curl_get_ingress")
    assert names.index("sed_inplace") < names.index("sed_sub_stream")


@pytest.mark.parametrize("cmd,expected", [
    ("cat foo.py", 'grep "" foo.py'),
    ("head -n 20 foo.py", 'grep -m 20 "" foo.py'),
    ("wc -l foo.py", 'grep -c "" foo.py'),
    ("less foo.py", 'grep "" foo.py'),
    ("nl foo.py", 'grep -n "" foo.py'),
    ("wget https://x/y", "curl -O https://x/y"),
    ("wget -O out https://x/y", "curl -o out https://x/y"),
    ("cp a b", "tee b < a >/dev/null"),
    ("tree src", "ls -R src"),
    ("test -f foo.py", "ls foo.py"),
])
def test_known_rewrites(cmd, expected):
    out, rule = canon.canonicalize(cmd)
    assert out == expected, f"{cmd} -> {out}"
    assert rule is not None


@pytest.mark.parametrize("cmd", ["eval x", "xargs rm", "find . -exec rm {} ;", "perl -e 1"])
def test_escapes_have_no_rewrite(cmd):
    out, rule = canon.canonicalize(cmd)
    assert rule is not None
    assert out == cmd
    assert rule.flow_class == "ESCAPE"


def test_unmatched_command_returns_unchanged():
    out, rule = canon.canonicalize("cmake --build .")
    assert out == "cmake --build ."
    assert rule is None


# --------------------------------------------------------------------------
# D24 - cat flags must not be pasted into the grep rewrite
# --------------------------------------------------------------------------

import pytest as _pytest
from dfc.canon import canonicalize as _canon


@_pytest.mark.parametrize("cmd", [
    "cat -A f.py", "cat f.py -A", "cat -s f.py", "cat -b f.py", "cat -A -n f.py",
    "cat --show-all f.py", "cat -A 2>/dev/null f.py", "cat -A",
])
def test_flagged_cat_is_not_rewritten(cmd):
    """`cat -A f` became `grep "" -A f` - grep's -A wants a count - 15 times in the
    scale run. No cat flag has a grep equivalent; the rule must not match."""
    out, rule = _canon(cmd)
    assert out == cmd and (rule is None or rule.name != "cat_read"), (out, rule)


@_pytest.mark.parametrize("cmd,expected", [
    ("cat f.py", 'grep "" f.py'),
    ("cat -- f.py", 'grep "" -- f.py'),
    ("cat foo-bar.py", 'grep "" foo-bar.py'),
    ("cat a.py b.py", 'grep "" a.py b.py'),
    ("cat dir/*.rst", 'grep "" dir/*.rst'),
])
def test_unflagged_cat_still_rewrites(cmd, expected):
    out, rule = _canon(cmd)
    assert out == expected and rule.name == "cat_read"


def test_cat_n_still_goes_to_cat_numbered():
    out, rule = _canon("cat -n f.py")
    assert out == 'grep -n "" f.py' and rule.name == "cat_numbered"


# --------------------------------------------------------------------------
# D30 - sed -n line-range reads on a pipeline are rewritten, not denied
# --------------------------------------------------------------------------

import pytest as _pytest30


@_pytest30.mark.parametrize("cmd,expected", [
    ("sed -n '10,20p'", "awk 'NR>=10&&NR<=20'"),
    ('sed -n "10,20p"', "awk 'NR>=10&&NR<=20'"),
    ("sed -n '10,$p'", "awk 'NR>=10'"),
    ("sed -n '15p'", "awk 'NR==15'"),
    ("sed -n '15p' f.py", "awk 'NR==15' f.py"),
    ("sed -n '10,$p' f.py", "awk 'NR>=10' f.py"),
    ("sed -n '10,20p' f.py", "awk 'NR>=10&&NR<=20' f.py"),
])
def test_sed_range_forms_fold_onto_awk(cmd, expected):
    out, rule = canon.canonicalize(cmd)
    assert out == expected and rule.csv_row == 7, (out, rule)


@_pytest30.mark.parametrize("cmd", [
    "sed -n '10,20s/a/b/p'",          # substitute-and-print, not a range read
    "sed -n '/start/,/end/p'",        # regex addresses: not statically bounded
    "sed -i '10,20p' f.py",           # in-place is an edit, policy's job
    "sed -n '10,20p' f.py g.py",      # two files: grep would prefix; leave to policy
])
def test_non_range_sed_is_left_alone(cmd):
    out, rule = canon.canonicalize(cmd)
    assert rule is None or rule.csv_row != 7, (out, rule)
