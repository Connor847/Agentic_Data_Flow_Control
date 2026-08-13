"""Canonicalization table - the 56 rules from `big ballin - Sheet6.csv`.

Ported verbatim from notebook cell `f440c33a`, with `csv_row` provenance preserved.

Per D1 in DECISIONS.md this table has exactly one job: **propose a rewrite** that folds
an ordinary shell command onto the primitive set. It does not decide admissibility -
`dfc/policy.py` does that, and a rule whose rewrite lands outside the primitive set is
simply not usable (see `target_bucket`).

Per D4 lossy rules still fire, but carry `fidelity_risk=True` so that failure analysis
can separate restriction cost from our own rewrite being wrong.

Per D3 rewrites targeting `awk` are usable (restricted awk is admitted); rewrites
targeting `python3 -c` are not.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Callable, Pattern

#: Statuses that mean "this rewrite is not output-equivalent". D4.
LOSSY_STATUSES = frozenset({"Partial", "Limitation"})


@dataclass(frozen=True)
class Rule:
    name: str
    csv_row: int
    bucket: str            # canonical base command this folds onto
    flow_class: str        # CSV taxonomy: READ/WRITE/METADATA/INGRESS/EGRESS/...
    police: str            # LOW / MED / HIGH
    benign: bool
    pattern: Pattern[str]
    rewrite: Callable | None   # None = already canonical / native / non-flow
    status: str
    notes: str
    target_bucket: str = ""    # bucket the *rewritten* form lands in; "" => same as bucket
    #: D16. Some rules are faithful for one input shape and lossy for another:
    #: `cat f` -> `grep "" f` is byte-faithful, but `cat a b` -> `grep "" a b` prefixes
    #: every line with its filename. Flagging the whole rule made `fidelity_risk` fire
    #: on 3.7% of records while appearing in 53% of resolved and 67% of failed
    #: trajectories - nearly useless as a discriminator. When set, this predicate
    #: decides per match instead.
    lossy_when: Callable | None = None

    @property
    def fidelity_risk(self) -> bool:
        """Worst-case risk for this rule, ignoring the specific match."""
        return self.status in LOSSY_STATUSES or self.lossy_when is not None

    def fidelity_for(self, m: "re.Match | None") -> bool:
        """D4, per match. Falls back to the rule's status when no predicate is set."""
        if self.lossy_when is not None and m is not None:
            return bool(self.lossy_when(m))
        return self.status in LOSSY_STATUSES

    @property
    def lands_in(self) -> str:
        return self.target_bucket or self.bucket

    def apply(self, cmd: str) -> str | None:
        """Return the rewritten command, or None if this rule leaves it unchanged."""
        m = self.pattern.search(cmd)
        if not m:
            return None
        if self.rewrite is None:
            return None
        return self.pattern.sub(lambda mm: self.rewrite(mm), cmd, count=1)

    def matches(self, cmd: str) -> re.Match | None:
        return self.pattern.search(cmd)


def _cut_to_awk(m: re.Match) -> str:
    d = m.group("d")
    fields = m.group("fields").split(",")
    expr = ('"%s"' % d).join("$" + n for n in fields)
    tail = (" " + m.group("f")) if m.group("f") else ""
    return "awk -F%s '{print %s}'%s" % (d, expr, tail)


def _rx(p: str) -> Pattern[str]:
    return re.compile(p)


# --------------------------------------------------------------------------
# Order matters: escapes and specific forms are tried before general ones.
# --------------------------------------------------------------------------

RULES: list[Rule] = [
    # ---- ESCAPE: dynamic / polymorphic, cannot canonicalize by name -------
    Rule("eval_exec", 50, "python3-c", "ESCAPE", "HIGH", False,
         _rx(r"^(eval\b|bash\s+-c\b|sh\s+-c\b)"), None, "Escape",
         "Code from data. Inspect body or sandbox; python3 -c hatch."),
    Rule("find_exec", 46, "python3-c", "ESCAPE", "HIGH", False,
         _rx(r"^find\b.*\s-exec\b"), None, "Escape",
         "Read+transform+write/exec in one; not safely canonicalizable."),
    Rule("find_delete", 46, "python3-c", "ESCAPE", "HIGH", False,
         _rx(r"^find\b.*\s-delete\b"), None, "Escape",
         "find -delete is a mutation, not metadata; escape."),
    Rule("xargs_build", 47, "python3-c", "ESCAPE", "HIGH", False,
         _rx(r"\bxargs\b"), None, "Escape",
         "Constructs arbitrary commands from stdin."),
    Rule("inline_interp", 49, "python3-c", "ESCAPE", "HIGH", False,
         _rx(r"^(perl|ruby|node)\s+-e\b"), None, "Escape",
         "Arbitrary inline interpreter; same gap as python3 -c."),
    Rule("complex_pipe", 48, "python3-c", "ESCAPE", "HIGH", False,
         _rx(r"^[^|]*\|[^|]*\|"), None, "Escape",
         "Composed pipeline (2+ stages): decompose if each stage maps to a base, "
         "else escape."),

    # ---- NETWORK: curl is the canonical boundary --------------------------
    Rule("wget_to_path", 26, "curl", "INGRESS", "MED", False,
         _rx(r"^wget\s+-O\s+(?P<o>\S+)\s+(?P<u>\S+)"),
         lambda m: "curl -o %s %s" % (m.group("o"), m.group("u")), "Form",
         "Ingress + local sink."),
    Rule("wget_download", 25, "curl", "INGRESS", "MED", False,
         _rx(r"^wget\s+(?P<u>\S+)"),
         lambda m: "curl -O %s" % m.group("u"), "Form",
         "Default GET = untrusted ingress."),
    Rule("curl_post_egress", 28, "curl", "EGRESS", "HIGH", False,
         _rx(r"^curl\b.*(\s-d\b|\s-F\b|\s-T\b|--data\b|--upload-file\b)"), None, "Native",
         "HIGHEST-PRIORITY boundary: -d/-F/-T/--data/--upload-file = egress."),
    Rule("scp_egress", 29, "curl", "EGRESS", "HIGH", False,
         _rx(r"^scp\s+(?P<f>\S+)\s+(?P<host>[^:\s]+):(?P<path>\S+)"),
         lambda m: "curl -T %s sftp://%s/%s"
                   % (m.group("f"), m.group("host"), m.group("path")), "Partial",
         "Upload = egress; same class as curl -T regardless of protocol."),
    Rule("git_push_egress", 31, "curl", "EGRESS", "HIGH", False,
         _rx(r"^git\s+push\b"), None, "Partial",
         "Repo EGRESS over https; same priority as curl -d."),
    Rule("git_ingress", 30, "curl", "INGRESS", "MED", False,
         _rx(r"^git\s+(clone|fetch|pull)\b"), None, "Partial",
         "Repo ingress channel; govern as network ingress."),
    Rule("nc_socket", 32, "curl", "EGRESS", "HIGH", False,
         _rx(r"^nc\s+(?P<host>\S+)\s+(?P<port>\d+)"), None, "Partial",
         "Arbitrary socket egress; prefer to block."),
    Rule("pkg_install", 33, "curl", "COMPOUND", "HIGH", False,
         _rx(r"^(pip3?|npm|apt(-get)?)\s+install\b"), None, "Compound",
         "Two boundaries: network ingress AND code execution. Police both."),
    Rule("curl_get_ingress", 27, "curl", "INGRESS", "MED", False,
         _rx(r"^curl\b"), None, "Native",
         "Bare curl = GET = untrusted ingress."),

    # ---- READ: grep is the canonical reader -------------------------------
    Rule("cat_numbered", 3, "grep", "READ", "MED", True,
         _rx(r"^(cat\s+-n|nl)\s+(?P<f>\S+)"),
         lambda m: 'grep -n "" %s' % m.group("f"), "Partial",
         "grep -n 'N:' vs nl padded tab; content equivalent."),
    # WIDENED 2026-08-11: the original regex required the `-n` form with an explicit
    # file, so `head -50 f.py` and `head f.py` both fell through to a denial. Row 2
    # plainly intends to cover `head` reading a named file; this matches all three
    # spellings. Pipeline `head` (no file operand) is handled by D11, not here.
    Rule("head_first_n", 2, "grep", "READ", "MED", True,
         _rx(r"^head\s+(?:-n\s*(?P<n>\d+)|-(?P<n2>\d+))?\s*(?P<f>[^\s|<>-]\S*)\s*$"),
         lambda m: 'grep -m %s "" %s' % (m.group("n") or m.group("n2") or "10",
                                         m.group("f")), "Verified",
         "grep -m stops after N matches = head for line text. Default N=10 matches "
         "head's own default."),
    Rule("pager_read", 4, "grep", "READ", "MED", True,
         _rx(r"^(less|more)\s+(?P<f>\S+)"),
         lambda m: 'grep "" %s' % m.group("f"), "Verified",
         "Pager UI dropped; emitted content identical."),
    Rule("wc_lines", 5, "grep", "READ", "MED", True,
         _rx(r"^wc\s+-l\s+(?P<f>\S+)"),
         lambda m: 'grep -c "" %s' % m.group("f"), "Verified",
         "grep -c counts matching lines = line count."),
    Rule("grep_recursive", 6, "grep", "READ", "MED", True,
         _rx(r"^grep\s+-r\s+(?P<rest>.+)"),
         lambda m: "grep -R %s" % m.group("rest"), "Verified",
         "Decomposes to ls (enumerate) + grep (read)."),
    Rule("sed_range_read", 7, "grep", "READ", "MED", True,
         _rx(r"^sed\s+-n\s+'?(?P<a>\d+),(?P<b>\d+)p'?\s+(?P<f>\S+)"),
         lambda m: "awk 'NR>=%s&&NR<=%s' %s"
                   % (m.group("a"), m.group("b"), m.group("f")), "Verified",
         "awk slice reproduces the range; READ mode only (no -i).",
         target_bucket="awk"),
    Rule("binary_dump", 8, "grep", "READ", "MED", True,
         _rx(r"^(od|xxd|strings)\s+(?P<f>\S+)"),
         lambda m: 'python3 -c \'import sys;sys.stdout.buffer.write('
                   'open("%s","rb").read())\'' % m.group("f"), "Limitation",
         "grep line-oriented, not byte-faithful; route binary through a reader. "
         "D3: python3 -c is NOT readmitted, so this rewrite is inadmissible.",
         target_bucket="python3-c"),
    Rule("file_magic", 15, "grep", "READ", "MED", True,
         _rx(r"^file\s+(?P<f>\S+)"), None, "Limitation",
         "`file` reads content bytes to classify -> READ, not metadata."),
    # WIDENED 2026-08-11: the original regex required exactly one operand, so
    # `cat a.py b.py` and `cat dir/*.rst` fell through to a denial. `grep ""` accepts
    # multiple files and globs, and row 1 plainly intends to cover reading files.
    # D16: the multi-operand case is the only lossy one - grep prefixes each line with
    # its filename - so the flag is decided per match rather than for the rule.
    Rule("cat_read", 1, "grep", "READ", "MED", True,
         _rx(r"^cat\s+(?P<f>[^|<>]+?)\s*$"),
         lambda m: 'grep "" %s' % m.group("f").strip(), "Verified",
         "Faithful for one file; grep adds a trailing newline if the source lacks one. "
         "For several files grep prefixes each line with the filename, so content is "
         "preserved but framing differs. grep . is NOT equivalent (drops blanks).",
         lossy_when=lambda m: len(m.group("f").split()) > 1
                              or any(g in m.group("f") for g in "*?[")),

    # ---- WRITE: > / tee (and in-place sed -i) -----------------------------
    Rule("echo_append", 18, "tee", "WRITE", "MED", True,
         _rx(r"^echo\s+(?P<x>.+?)\s+>>\s+(?P<f>\S+)"),
         lambda m: "echo %s | tee -a %s >/dev/null" % (m.group("x"), m.group("f")),
         "Verified", "Append mode; catch the sink."),
    Rule("cp_copy", 19, "tee", "WRITE", "MED", True,
         _rx(r"^cp\s+(?P<a>\S+)\s+(?P<b>\S+)"),
         lambda m: "tee %s < %s >/dev/null" % (m.group("b"), m.group("a")), "Verified",
         "Byte-identical; tee does NOT preserve mode/timestamps "
         "(Partial if perms matter)."),
    Rule("dd_copy", 23, "tee", "WRITE", "MED", True,
         _rx(r"^dd\s+if=(?P<a>\S+)\s+of=(?P<b>\S+)"),
         lambda m: "tee %s < %s" % (m.group("b"), m.group("a")), "Partial",
         "Copy for plain files; of= can target raw devices -> restrict to scoped paths."),
    Rule("echo_overwrite", 16, "tee", "WRITE", "MED", True,
         _rx(r"^echo\s+.+?\s+>\s+\S+"), None, "Native",
         "Truncate then write; sink must be inside writable scope."),
    Rule("printf_write", 17, "tee", "WRITE", "MED", True,
         _rx(r"^printf\s+.+>\s+\S+"), None, "Native",
         "Same sink discipline as >."),
    Rule("cat_concat", 20, "tee", "WRITE", "MED", True,
         _rx(r"^cat\s+\S+\s+.*>\s+\S+"), None, "Native",
         "Multi-source read -> single sink."),
    Rule("sed_inplace", 21, "tee", "WRITE", "MED", True,
         _rx(r"^sed\s+-i\b"), None, "Native",
         "Read-modify-write mutation; keep pre/post labels consistent. "
         "Arm 2 only, and only address-scoped s///, d, i, a."),
    Rule("truncate_file", 22, "tee", "WRITE", "MED", True,
         _rx(r"^(:\s*>\s*\S+|truncate\s+-s\s*0?\s+\S+)"), None, "Native",
         "Sink truncation."),
    Rule("tee_fanout", 24, "tee", "WRITE", "MED", True,
         _rx(r"^tee\s+\S+"), None, "Native",
         "tee writes file(s) AND stdout; policy must catch BOTH sinks."),

    # ---- METADATA: ls (names/sizes/perms only) ----------------------------
    # REWRITE WITHDRAWN 2026-08-11 (D16). The widening earlier the same day was a
    # mistake and an instructive one.
    #
    # `find` predicates are not decoration, they are the query. The rewrite kept only
    # the directory operand and dropped everything else, so
    #     find / -maxdepth 6 -iname "regex" -type d
    # became
    #     ls -R /
    # - an unbounded recursive listing of the whole container filesystem in place of a
    # bounded, filtered search. Documenting that as "returns a superset" badly
    # understated it. In the n=30 Arm 1 run this fired on 27 of 30 `find` rewrites and
    # touched 13 of 30 instances, including 5 of the 7 that Arm 1 lost.
    #
    # Before the widening, `find -iname` was denied and the agent adapted. After it,
    # the agent silently received the wrong answer. **A bad rewrite is worse than an
    # honest denial**, because denial is visible to the agent and to us while silent
    # corruption is visible to neither. `find` was never in the §2 primitive set; the
    # rule stays for labelling and coverage mining, but proposes no rewrite.
    Rule("find_enumerate", 10, "ls", "METADATA", "LOW", True,
         _rx(r"^find\b(?![^|;]*\s-(?:exec|execdir|delete|ok|fprint)\b)"),
         None, "Limitation",
         "No admissible rewrite: `ls` cannot express find's predicates, and dropping "
         "them silently returns the wrong path set. Denied rather than mistranslated. "
         "-exec/-delete are matched earlier and handled as escapes."),
    Rule("stat_size", 11, "ls", "METADATA", "LOW", True,
         _rx(r"^stat\s+-c\s+'?%s'?\s+(?P<f>\S+)"),
         lambda m: "ls -l %s" % m.group("f"), "Partial",
         "Size present in ls -l; numeric-only extraction needs awk."),
    Rule("du_size", 12, "ls", "METADATA", "LOW", True,
         _rx(r"^du\s+-\S+\s+(?P<d>\S+)"),
         lambda m: "ls -l %s" % m.group("d"), "Partial",
         "du aggregates recursively; ls is per-entry (aggregate via awk)."),
    Rule("tree_view", 13, "ls", "METADATA", "LOW", True,
         _rx(r"^tree\s+(?P<d>\S+)"),
         lambda m: "ls -R %s" % m.group("d"), "Partial",
         "Same information, different rendering."),
    Rule("test_exists", 14, "ls", "METADATA", "LOW", True,
         _rx(r"^test\s+-[ef]\s+(?P<f>\S+)"),
         lambda m: "ls %s" % m.group("f"), "Verified",
         "ls non-zero exit == absent. Pure metadata."),
    Rule("bracket_exists", 14, "ls", "METADATA", "LOW", True,
         _rx(r"^\[\s+-[ef]\s+(?P<f>\S+)\s+\]"),
         lambda m: "ls %s" % m.group("f"), "Verified",
         "[ -f x ] existence test -> ls exit code."),
    Rule("ls_native", 9, "ls", "METADATA", "LOW", True,
         _rx(r"^ls\b"), None, "Native",
         "Discloses names/sizes/perms only; lowest-sensitivity ingress."),

    # ---- TRANSFORM: awk (stream -> stream) --------------------------------
    # D3: admissible, but only in the restricted form enforced by policy.awk_admissible.
    Rule("tr_upper", 34, "awk", "TRANSFORM", "LOW", True,
         _rx(r"^tr\s+'?a-z'?\s+'?A-Z'?"),
         lambda m: "awk '{print toupper($0)}'", "Verified",
         "Stream->stream, no boundary crossed."),
    Rule("cut_fields", 35, "awk", "TRANSFORM", "LOW", True,
         _rx(r"^cut\s+-d(?P<d>\S)\s+-f(?P<fields>[\d,]+)(?:\s+(?P<f>\S+))?"),
         _cut_to_awk, "Verified",
         "Field projection; awk keeps the delimiter literal between fields."),
    Rule("uniq_count", 39, "awk", "TRANSFORM", "LOW", True,
         _rx(r"^uniq\s+-c\s+(?P<f>\S+)"),
         lambda m: "awk 'NR==1{p=$0;c=1;next} $0==p{c++;next} "
                   '{print c" "p;p=$0;c=1} END{if(NR)print c" "p}\' %s' % m.group("f"),
         "Verified", "Adjacent-dup counts reproduced."),
    Rule("uniq_dedupe", 38, "awk", "TRANSFORM", "LOW", True,
         _rx(r"^uniq\s+(?P<f>\S+)"),
         lambda m: "awk '$0!=p{print}{p=$0}' %s" % m.group("f"), "Verified",
         "Adjacent-dup removal."),
    Rule("tail_last_n", 41, "awk", "TRANSFORM", "LOW", True,
         _rx(r"^tail\s+-n\s+(?P<n>\d+)\s+(?P<f>\S+)"),
         lambda m: "awk '{b[NR]=$0}END{for(i=NR-%s+1;i<=NR;i++)if(i>0)print b[i]}' %s"
                   % (m.group("n"), m.group("f")), "Verified",
         "grep cannot do tail; awk index buffer can."),
    Rule("sed_sub_stream", 42, "awk", "TRANSFORM", "LOW", True,
         _rx(r"^sed\s+'?s/(?P<x>[^/]*)/(?P<y>[^/]*)/g'?\s+(?P<f>\S+)"),
         lambda m: "awk '{gsub(/%s/,\"%s\");print}' %s"
                   % (m.group("x"), m.group("y"), m.group("f")), "Verified",
         "Stream substitution (not in-place; -i belongs to the WRITE bucket)."),
    Rule("wc_words", 43, "awk", "TRANSFORM", "LOW", True,
         _rx(r"^wc\s+-w\s+(?P<f>\S+)"),
         lambda m: "awk '{w+=NF}END{print w}' %s" % m.group("f"), "Verified",
         "Field-count aggregation."),
    Rule("sort_lines", 37, "awk", "TRANSFORM", "LOW", True,
         _rx(r"^sort\s+(?P<f>\S+)"), None, "Partial",
         "POSIX awk has no sort builtin; keep sort as a recognized transform."),
    Rule("reencode", 44, "awk", "TRANSFORM", "HIGH", False,
         _rx(r"^(base64|gzip|gunzip|openssl\s+enc)\b"), None, "Limitation",
         "Re-encoding disguises data; label follows BYTES, flag as high-risk for exfil."),
    Rule("paste_join", 45, "awk", "TRANSFORM", "LOW", True,
         _rx(r"^(paste|join)\s+(?P<rest>.+)"), None, "Partial",
         "Cross-source derivation; labels from BOTH inputs propagate to output."),

    # ---- NON-FLOW: access / retention / process / env ---------------------
    Rule("remove", 51, "non-flow", "NON-FLOW", "MED", True,
         _rx(r"^(rm|rmdir)\b"), None, "-",
         "Mutates existence, not content. Separate retention policy class."),
    Rule("move", 52, "non-flow", "NON-FLOW", "LOW", True,
         _rx(r"^mv\b"), None, "-",
         "Relocation, not content flow (unless crossing a scope boundary)."),
    Rule("chmod_chown", 53, "non-flow", "NON-FLOW", "LOW", True,
         _rx(r"^(chmod|chown)\b"), None, "-",
         "Access-control mutation."),
    Rule("kill_proc", 54, "non-flow", "NON-FLOW", "LOW", True,
         _rx(r"^kill\b"), None, "-", "Process control."),
    Rule("export_secret", 55, "non-flow", "NON-FLOW", "HIGH", False,
         _rx(r"^export\s+\w+="), None, "Flag",
         "Secret-propagation vector to children; police separately."),
    Rule("env_dump", 56, "non-flow", "READ", "HIGH", False,
         _rx(r"^(env|printenv)\b"), None, "Flag",
         "Real leak vector; treat as content ingress of secrets, not benign metadata."),
]

#: Keyed lookup, for joining flow-log records back to rule provenance.
BY_NAME: dict[str, Rule] = {r.name: r for r in RULES}


def match(cmd: str) -> Rule | None:
    """First matching rule, in table order. Order is load-bearing: escapes and
    specific forms are declared before general ones."""
    cmd = cmd.strip()
    for rule in RULES:
        if rule.matches(cmd):
            return rule
    return None


def canonicalize(cmd: str) -> tuple[str, Rule | None]:
    """Fold `cmd` onto its base form. Returns (command, rule).

    The command is returned unchanged when no rule matches or when the matching rule
    is already canonical (`rewrite is None`). Admissibility of the *result* is not
    checked here - that is `dfc/policy.py`'s job (D1).
    """
    out, rule, _m = canonicalize_match(cmd)
    return out, rule


def canonicalize_match(cmd: str):
    """As `canonicalize`, but also returns the regex match.

    The match is what `Rule.fidelity_for` needs to decide whether *this particular*
    rewrite is lossy, rather than whether the rule ever can be (D16).
    """
    cmd = cmd.strip()
    rule = match(cmd)
    if rule is None:
        return cmd, None, None
    m = rule.matches(cmd)
    out = rule.apply(cmd)
    return (out if out is not None else cmd), rule, m


def bucket_histogram() -> dict[str, int]:
    return dict(Counter(r.bucket for r in RULES))


__all__ = [
    "Rule", "RULES", "BY_NAME", "match", "canonicalize", "canonicalize_match",
    "bucket_histogram", "LOSSY_STATUSES",
]
