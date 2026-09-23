"""Benchmark profiles: what differs between SWE-bench Lite and SWE-bench Pro (D27).

Everything that decides *what a command means* lives in the fingerprinted modules and
is benchmark-agnostic. Everything that decides *where the repo is, which image to
start, what the dataset row looks like and how the grader is invoked* lives here, so
that moving between benchmarks changes nothing the flow metrics depend on.

Lite:  princeton-nlp/SWE-bench_Lite, repo at /testbed, `swebench/sweb.eval.x86_64.*`
       images, graded by `swebench.harness.run_evaluation` (report.json per instance).
Pro:   ScaleAI/SWE-bench_Pro, repo at /app, `jefzda/sweap-images:<tag>` images whose
       ENTRYPOINT is /bin/bash, graded by the Scale repo's `swe_bench_pro_eval.py`
       (`<prefix>_output.json` per instance with a flat test list). Hidden tests are
       *checked out from a commit already in the image* (`before_repo_set_cmd`), not
       applied as a patch; `git apply -v` of the model patch has no fuzzy fallback.
"""

from __future__ import annotations

import ast
import base64
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

#: Where the Scale repo is cloned. Its eval script must run with this as cwd because it
#: opens `dockerfiles/...` and imports `helper_code` relatively.
PRO_ROOT = Path("SWE-bench_Pro-os")
PRO_DOCKERHUB_USER = "jefzda"

#: Pro repos by test runner. The Arm 1 execute rule admits `pytest` / `python -m
#: pytest`; a repo whose native runner is anything else cannot run its own tests
#: under the restriction, which would confound the comparison with a tooling gap
#: rather than measure the restriction. Ansible runs `python bin/ansible-test`.
PRO_PYTEST_REPOS = ("internetarchive/openlibrary", "qutebrowser/qutebrowser")
PRO_PYTHON_REPOS = PRO_PYTEST_REPOS + ("ansible/ansible",)


def _as_list(v) -> list[str]:
    """Pro ships test lists as JSON/Python-literal strings in some exports and as real
    lists in others. Accept both."""
    if v is None:
        return []
    if isinstance(v, list):
        return [str(x) for x in v]
    s = str(v).strip()
    if not s:
        return []
    for parser in (json.loads, ast.literal_eval):
        try:
            out = parser(s)
            if isinstance(out, list):
                return [str(x) for x in out]
        except Exception:
            pass
    return [s]


def _first(row: dict, *keys, default=None):
    for k in keys:
        if k in row and row[k] not in (None, ""):
            return row[k]
    return default


@dataclass(frozen=True)
class Benchmark:
    name: str
    dataset: str
    split: str
    repo_dir: str
    #: docker run: override the image ENTRYPOINT (Pro images set /bin/bash).
    entrypoint: str | None = None
    repos: tuple[str, ...] = field(default_factory=tuple)

    # -- dataset --------------------------------------------------------

    def normalize(self, row: dict) -> dict:
        """One canonical shape for both benchmarks. Raw keys are kept alongside so
        the Pro grader can be handed the columns it wants verbatim."""
        out = dict(row)
        out["instance_id"] = row["instance_id"]
        out["repo"] = _first(row, "repo", default=self.repo_of_id(row["instance_id"]))
        out["problem_statement"] = _first(row, "problem_statement", default="") or ""
        out["hints_text"] = _first(row, "hints_text", default="") or ""
        out["patch"] = _first(row, "patch", default="") or ""
        out["test_patch"] = _first(row, "test_patch", default="") or ""
        out["base_commit"] = _first(row, "base_commit", default="") or ""
        out["fail_to_pass"] = _as_list(_first(row, "FAIL_TO_PASS", "fail_to_pass"))
        out["pass_to_pass"] = _as_list(_first(row, "PASS_TO_PASS", "pass_to_pass"))
        return out

    def keep(self, row: dict) -> bool:
        return not self.repos or row.get("repo") in self.repos

    @staticmethod
    def repo_of_id(instance_id: str) -> str:
        iid = instance_id[len("instance_"):] if instance_id.startswith("instance_") else instance_id
        return iid.split("__", 1)[0] if "__" in iid else iid

    # -- container ------------------------------------------------------

    def image_for(self, inst: dict) -> str:
        raise NotImplementedError

    def docker_run_extra(self) -> list[str]:
        return ["--entrypoint", self.entrypoint] if self.entrypoint else []

    def docker_run_cmd(self) -> list[str]:
        return ["infinity"] if self.entrypoint == "sleep" else ["sleep", "infinity"]


class Lite(Benchmark):
    def image_for(self, inst: dict) -> str:
        key = inst["instance_id"].replace("__", "_1776_").lower()
        return f"swebench/sweb.eval.x86_64.{key}:latest"


class Pro(Benchmark):
    def image_for(self, inst: dict) -> str:
        tag = inst.get("dockerhub_tag")
        if tag:
            return f"{PRO_DOCKERHUB_USER}/sweap-images:{tag}"
        return f"{PRO_DOCKERHUB_USER}/sweap-images:{pro_image_tag(inst['instance_id'], inst.get('repo', ''))}"


def pro_image_tag(uid: str, repo_name: str) -> str:
    """Mirror of `helper_code/image_uri.get_dockerhub_image_uri` in the Scale repo,
    including its element-web special cases, so our solve container is the same image
    the grader will use."""
    repo_base, repo_name_only = repo_name.lower().split("/")
    hsh = uid.replace("instance_", "")
    if uid == "instance_element-hq__element-web-ec0f940ef0e8e3b61078f145f34dc40d1938e6c5-vnan":
        repo_name_only = "element-web"
    elif "element-hq" in repo_name.lower() and "element-web" in repo_name.lower():
        repo_name_only = "element"
        if hsh.endswith("-vnan"):
            hsh = hsh[:-5]
    elif hsh.endswith("-vnan"):
        hsh = hsh[:-5]
    tag = f"{repo_base}.{repo_name_only}-{hsh}"
    return tag[:128]


LITE = Lite(name="lite", dataset="princeton-nlp/SWE-bench_Lite", split="test",
            repo_dir="/testbed")
PRO = Pro(name="pro", dataset="ScaleAI/SWE-bench_Pro", split="test", repo_dir="/app",
          entrypoint="sleep", repos=PRO_PYTEST_REPOS)

BENCHMARKS = {"lite": LITE, "pro": PRO}


def get(name: str, repos: tuple[str, ...] | None = None) -> Benchmark:
    b = BENCHMARKS[name]
    if repos is not None:
        from dataclasses import replace
        b = replace(b, repos=tuple(repos))
    return b


# -- Pro: install the hidden tests ourselves (D28) ------------------------------

#: Files this line leaves in /workspace, which the Scale grader bind-mounts from the
#: host, so they survive the container and can be read back for the report.
PRO_MODEL_STATUS = "dfc_after_model_patch.txt"
PRO_TEST_APPLY_LOG = "dfc_test_apply.log"


def pro_setup_line(test_patch: str) -> str:
    """The single shell line the Scale entryscript runs after applying the model patch
    and before running the tests (it takes the LAST line of `before_repo_set_cmd`).

    The public HF rows say `git apply --verbose /tests/test_patch.patch`, a file that
    exists only in Scale's internal images - on the DockerHub images the hidden tests
    were never installed, so every grade in the first pilot was of the base commit's
    tests. This line carries the HF `test_patch` itself, base64 on one line, and
    applies it. It also records `git status` first, which is the only evidence of
    whether the *model* patch applied: the entryscript sends git's own output to the
    container's stdout, which the grader does not keep.
    """
    b64 = base64.b64encode(test_patch.encode()).decode()
    return (
        f"git status --porcelain > /workspace/{PRO_MODEL_STATUS}; "
        f"echo {b64} | base64 -d > /workspace/dfc_test_patch.diff; "
        f"git apply --verbose /workspace/dfc_test_patch.diff > /workspace/{PRO_TEST_APPLY_LOG} 2>&1; "
        f"echo \"exit=$?\" >> /workspace/{PRO_TEST_APPLY_LOG}"
    )


def pro_setup_cmd(row: dict) -> str:
    """`before_repo_set_cmd` with the last line replaced by ours. The reset/clean/
    checkout lines above it are kept verbatim; the entryscript only executes the last
    line anyway, but the field stays readable."""
    lines = (row.get("before_repo_set_cmd") or "").strip().split("\n")
    keep = [l for l in lines[:-1]] if len(lines) > 1 else []
    return "\n".join(keep + [pro_setup_line(row.get("test_patch", ""))])


# -- Pro grader output -> the report shape the rest of dfc expects --------------

_GIT_APPLY_ERR = re.compile(r"^error: .*(patch failed|does not apply|already exists|No such file)", re.M)


def pro_report(output: dict | None, stderr: str, inst: dict, *,
               model_status: str | None = None, test_apply_log: str | None = None,
               model_patch: str = "") -> dict | None:
    """Turn `<prefix>_output.json` (flat `tests: [{name, status}]`) into the dict
    `classify_failure` reads: resolved, patch_successfully_applied, tests_status with
    FAIL_TO_PASS / PASS_TO_PASS success and failure lists.

    Evidence, in order of preference (D28):
    * `model_status` - `git status --porcelain` taken after the model patch, before
      the tests were installed. The model patch applied iff every file it touches is
      dirty there. An empty status with a non-empty patch means `git apply` refused.
    * `test_apply_log` - our own `git apply --verbose` of the hidden tests, with its
      exit code. Non-zero means the grade is of the wrong tests: `error`, not a result.
    * `stderr` - the run script's stderr, kept as a weaker fallback.
    """
    if output is None:
        return None
    passed = {t.get("name") for t in output.get("tests", []) if t.get("status") == "PASSED"}
    f2p, p2p = inst.get("fail_to_pass", []), inst.get("pass_to_pass", [])
    ts = {
        "FAIL_TO_PASS": {"success": [t for t in f2p if t in passed],
                         "failure": [t for t in f2p if t not in passed]},
        "PASS_TO_PASS": {"success": [t for t in p2p if t in passed],
                         "failure": [t for t in p2p if t not in passed]},
    }
    error = ""
    if model_status is not None:
        dirty = {l[3:].strip() for l in model_status.splitlines() if len(l) > 3}
        touched = set(_DIFF_PATHS.findall(model_patch or ""))
        applied = (not touched) or all(any(d == t or t.startswith(d) for d in dirty) for t in touched)
    else:
        applied = not _GIT_APPLY_ERR.search(stderr or "")
    if test_apply_log is not None:
        m = re.search(r"^exit=(\d+)", test_apply_log, re.M)
        if m is None or m.group(1) != "0":
            error = "hidden tests not installed: " + test_apply_log.strip().splitlines()[-2:][0][:200] \
                if test_apply_log.strip() else "hidden tests not installed"
    resolved = applied and not error and not ts["FAIL_TO_PASS"]["failure"] \
        and not ts["PASS_TO_PASS"]["failure"]
    out = {"resolved": resolved, "patch_successfully_applied": applied, "tests_status": ts,
           "tests_reported": len(output.get("tests", []))}
    if error:
        out["error"] = error
    return out


_DIFF_PATHS = re.compile(r"^diff --git a/\S+ b/(\S+)$", re.M)


__all__ = ["Benchmark", "Lite", "Pro", "LITE", "PRO", "BENCHMARKS", "get", "pro_image_tag",
           "pro_report", "pro_setup_line", "pro_setup_cmd", "PRO_ROOT", "PRO_DOCKERHUB_USER",
           "PRO_PYTEST_REPOS", "PRO_PYTHON_REPOS", "PRO_MODEL_STATUS", "PRO_TEST_APPLY_LOG"]
