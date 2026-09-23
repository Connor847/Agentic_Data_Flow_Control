"""SWE-bench instance containers - the bash executor (§6.3).

Topology: the host runs the Agent SDK loop and owns the flow log; the executor is
`docker exec` into the instance container; at end of trajectory `git diff` inside the
container produces `model_patch`, which feeds the existing eval path unchanged.

Two things this module has to get right that are easy to get wrong:

* **`docker exec` is stateless.** Each call is a fresh process, so `cd` does not
  persist the way it does in Claude Code's built-in Bash tool. Working directory is
  tracked here and re-injected on every call, otherwise the agent's second command
  silently runs in the wrong place.
* **Repo state must be pristine at trajectory start.** SWE-bench images ship the repo
  at the base commit, but the eval harness also writes into `/testbed`. The container
  is created fresh per instance and destroyed after, so no state leaks between runs.
* **The hidden test patch owns some paths (D21).** The harness grades by applying the
  instance's test patch on top of the agent's. `git apply` is all-or-nothing and refuses
  to create a file that already exists, so an agent that wrote its own fixture at the
  same path the real PR chose (`flask-4992`: `tests/static/config.toml`) silently
  prevented every hidden test from being installed, and was scored as if it had failed
  them all. Paths the test patch touches are parsed up front and dropped from the
  submitted patch; the harness overwrites them anyway.
* **The image's tree is not always clean (D20).** Some images ship with untracked
  build output (`psf__requests-863`: a `build/` directory left by the package install,
  absent from that snapshot's `.gitignore`). `git add -A` at extraction swept it into
  an 873 KB, 69-file "patch" the harness could not apply, four times out of four. The
  write set is therefore snapshotted at container start and subtracted at extraction,
  and a patch above `MAX_PATCH_BYTES` is refused rather than submitted.
"""

from __future__ import annotations

import json
import re
import shlex
import subprocess
import time
import uuid
from dataclasses import dataclass, field

#: SWE-bench images place the repo checkout here.
TESTBED = "/testbed"

#: Official image namespace for SWE-bench (Lite and full share it).
IMAGE_FMT = "swebench/sweb.eval.x86_64.{key}:latest"

#: The images are x86 only. On Apple Silicon they run under emulation - correct but
#: slow. Prefer Modal for anything past a smoke test (§5 housekeeping).
DEFAULT_PLATFORM = "linux/amd64"


#: D20 - refuse to submit a patch larger than this. Calibrated on the 21 Aug scale
#: run: 176 of 180 trajectories were under 42 KB (median 1.9 KB, p90 4.1 KB, max
#: 41.6 KB); the four above it were all 873 KB and all pre-existing image state. A
#: patch in between is possible but would be a very unusual SWE-bench Lite fix, and
#: refusing it surfaces as `harness-error`, which is honest - it is visible and can be
#: re-run - where a silently submitted junk patch is not.
MAX_PATCH_BYTES = 250_000


_DIFF_HEADER = re.compile(r"^diff --git a/(.+?) b/(.+?)$", re.M)


def paths_in_patch(patch: str) -> list[str]:
    """Every path a unified diff touches, in order, deduplicated (D21).

    Reads the `diff --git a/X b/X` headers only, which is how the harness's own
    `git apply` decides what it is about to write. Both sides are taken so a rename
    reserves its old and new names.
    """
    out: list[str] = []
    for a, b in _DIFF_HEADER.findall(patch or ""):
        for path in (a, b):
            if path not in out:
                out.append(path)
    return out


_TEST_MODULE = re.compile(r"^(test_[^/]*|[^/]*_test)\.py$")


def is_collectible_scratch(path: str) -> bool:
    """Would pytest pick this *new* file up on its own during grading? (D22)

    Two shapes qualify. A `conftest.py` at any depth is loaded for every test under
    it, so one the agent left behind runs inside the grader's session. A test module
    at the repo root is collected by any bare `pytest` invocation. Test modules deeper
    in the tree are left alone: the grader names its test files explicitly, and a
    heuristic for "is this directory a test directory" is exactly the layout guess
    D16 warns against.
    """
    name = path.rsplit("/", 1)[-1]
    if name == "conftest.py":
        return True
    return "/" not in path and bool(_TEST_MODULE.match(name))


class DockerError(RuntimeError):
    pass


class PatchTooLarge(DockerError):
    """The extracted diff exceeds `MAX_PATCH_BYTES`. Raised rather than returned so the
    solver records it as a harness error instead of an empty patch (D19 made that
    distinction for the empty case; this is the oversized case)."""


def _run(args: list[str], timeout: int = 600) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)


def image_key(instance_id: str) -> str:
    """`astropy__astropy-12907` -> `astropy_1776_astropy-12907`.

    The official harness replaces `__` with `_1776_` when building image tags.
    """
    return instance_id.replace("__", "_1776_").lower()


def image_for(instance_id: str) -> str:
    return IMAGE_FMT.format(key=image_key(instance_id))


def docker_available() -> tuple[bool, str]:
    try:
        p = _run(["docker", "version", "--format", "{{.Server.Version}}"], timeout=30)
    except FileNotFoundError:
        return False, "docker executable not found on PATH"
    except subprocess.TimeoutExpired:
        return False, "docker did not respond within 30s (is the daemon running?)"
    if p.returncode != 0:
        return False, p.stderr.strip() or "docker daemon not reachable"
    return True, p.stdout.strip()


@dataclass
class InstanceContainer:
    """One running container for the duration of one trajectory."""

    instance_id: str
    image: str = ""
    platform: str = DEFAULT_PLATFORM
    workdir: str = TESTBED
    #: D27 - where the benchmark puts the checkout. Lite: /testbed. Pro: /app.
    repo_dir: str = TESTBED
    #: D27 - extra `docker run` flags and the container command. Pro images set
    #: ENTRYPOINT ["/bin/bash"], so `sleep infinity` has to be passed as
    #: `--entrypoint sleep` + `infinity` or bash tries to execute a file named sleep.
    run_extra: list[str] = field(default_factory=list)
    run_cmd: list[str] = field(default_factory=lambda: ["sleep", "infinity"])
    container_id: str = ""
    #: §6.4 - the envelope defaults. `--network none` makes egress impossible rather
    #: than merely bounded. Kept off by default in Phase 2 so `pip install` still works
    #: if an instance needs it; Phase 2b turns it on and proves the property.
    network_none: bool = False
    memory: str = "4g"
    cpus: str = "2"
    pids_limit: int = 512
    started: float = field(default_factory=time.time)
    #: D20 - paths already dirty when the container came up, before the agent ran
    #: anything. `git status --porcelain` entries, so an untracked directory appears
    #: once as `build/`. Subtracted from the patch and the write set.
    preexisting_dirty: list[str] = field(default_factory=list)
    #: D21 - paths the instance's hidden test patch will create or overwrite. The
    #: harness checks existing ones out from base and `git apply`s the rest, so any
    #: agent change to them is either discarded or breaks the apply. Excluded from the
    #: submitted patch; set from `paths_in_patch(instance["test_patch"])`.
    reserved_paths: list[str] = field(default_factory=list)
    #: D21 - filled by `model_patch()`: reserved paths the agent actually wrote to.
    #: Empty in the common case; when not, the exclusion changed the patch.
    reserved_collisions: list[str] = field(default_factory=list)
    #: D22 - filled by `model_patch()`: *new* files the agent left that pytest would
    #: collect during grading (`conftest.py` anywhere, `test_*.py` at the root).
    #: Excluded from the submitted patch; modifications are never touched.
    scratch_excluded: list[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.image:
            self.image = image_for(self.instance_id)

    # -- lifecycle ------------------------------------------------------

    def pull(self) -> None:
        p = _run(["docker", "pull", "--platform", self.platform, self.image], timeout=3600)
        if p.returncode != 0:
            raise DockerError(f"could not pull {self.image}:\n{p.stderr.strip()}")

    def start(self, pull_if_missing: bool = True) -> "InstanceContainer":
        if pull_if_missing and not self._image_present():
            self.pull()
        name = f"dfc-{self.instance_id.replace('__', '-')[:40]}-{uuid.uuid4().hex[:6]}"
        args = [
            "docker", "run", "-d", "--rm",
            "--platform", self.platform,
            "--name", name,
            "-w", self.repo_dir,
            "--memory", self.memory,
            "--cpus", self.cpus,
            "--pids-limit", str(self.pids_limit),
            # NEVER mount /var/run/docker.sock - full container escape, and it silently
            # voids every property in §6.4.
        ]
        if self.network_none:
            args += ["--network", "none"]
        args += list(self.run_extra)
        args += [self.image, *self.run_cmd]
        p = _run(args, timeout=600)
        if p.returncode != 0:
            raise DockerError(f"could not start container for {self.instance_id}:\n{p.stderr.strip()}")
        self.container_id = p.stdout.strip()
        self.workdir = self.repo_dir
        self.snapshot_start_state()
        return self

    def snapshot_start_state(self) -> list[str]:
        """D20: record what is already dirty before the agent's first command, so it
        can be told apart from the agent's work at extraction. Called by `start()`;
        exposed so a caller that constructs the container differently can still do it."""
        self.preexisting_dirty = self.dirty_paths()
        return self.preexisting_dirty

    def _image_present(self) -> bool:
        p = _run(["docker", "image", "inspect", self.image], timeout=60)
        return p.returncode == 0

    def stop(self) -> None:
        if self.container_id:
            _run(["docker", "kill", self.container_id], timeout=120)
            self.container_id = ""

    def __enter__(self) -> "InstanceContainer":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()

    # -- execution ------------------------------------------------------

    def exec(self, command: str, timeout: int = 300, *,
             workdir: str | None = None, track_cwd: bool = True) -> dict:
        """Run one shell command inside the container.

        `cd` is tracked across calls because `docker exec` is stateless. The command
        runs as `cd <workdir> && <command>`, and the resulting cwd is read back so the
        next call lands where the agent expects.

        `workdir` pins this one call to a directory without consulting the tracked
        cwd, and `track_cwd=False` stops it writing the tracked cwd back. Housekeeping
        that must run against the repo - patch extraction, the write set, reset - uses
        both, because the agent's tracked cwd is wherever *it* last wandered.

        D19: an agent that ended its trajectory with `cd /tmp/scratch` left `workdir`
        pointing outside the repo, so `git add -A` ran in a non-repo directory, exited
        non-zero, and `model_patch()` returned "". The trajectory was scored as an
        empty patch with `stop_reason: success`, indistinguishable from a model that
        simply never edited anything.
        """
        if not self.container_id:
            raise DockerError("container is not running")

        # Emit the post-command cwd on a private sentinel line so it can be stripped
        # from what the agent sees.
        sentinel = "__DFC_CWD__"
        start_dir = workdir if workdir is not None else self.workdir
        wrapped = (
            f"cd {shlex.quote(start_dir)} 2>/dev/null || cd {shlex.quote(self.repo_dir)}; "
            f"{{ {command}\n}}; __rc=$?; printf '\\n{sentinel}%s\\n' \"$PWD\"; exit $__rc"
        )
        args = ["docker", "exec", "-i", self.container_id, "bash", "-lc", wrapped]
        try:
            p = _run(args, timeout=timeout)
        except subprocess.TimeoutExpired:
            return {
                "exit_code": 124,
                "stdout": "",
                "stderr": f"command exceeded the {timeout}s timeout and was killed",
                "timed_out": True,
            }

        stdout, cwd = _split_sentinel(p.stdout, sentinel)
        if cwd and track_cwd:
            self.workdir = cwd
        return {
            "exit_code": p.returncode,
            "stdout": stdout,
            "stderr": p.stderr,
            "timed_out": False,
            "cwd": self.workdir,
        }

    # -- patch extraction ------------------------------------------------

    def _repo_exec(self, command: str, timeout: int = 120) -> dict:
        """Run housekeeping against the repo, wherever the agent left its cwd (D19)."""
        return self.exec(command, timeout=timeout, workdir=self.repo_dir, track_cwd=False)

    def model_patch(self) -> str:
        """§8 R5: the patch is produced by `git diff` at the end of the trajectory, not
        by the model emitting diff text. This is what killed the previous run - invented
        paths and fabricated blob hashes cannot happen when the diff comes from git.

        `git add -A` is still needed - plain `git diff` misses files the agent created -
        but its buried assumption, that everything untracked is the agent's work, is
        false when the image ships a dirty tree (D20). Paths recorded by
        `snapshot_start_state()` are unstaged again before the diff is taken.

        New files pytest would collect on its own - a `conftest.py`, a root-level test
        module - are unstaged as well (D22). They are scratch the agent left behind
        and would otherwise run inside the grader's session. Only additions qualify.

        Paths owned by the hidden test patch are unstaged too (D21). The harness will
        `git checkout` the existing ones from base and `git apply` the new ones; an
        agent-created file at a new one makes that apply fail wholesale, and the
        trajectory is then graded against tests that were never installed.

        Known limit: if the agent edits a file that was *already modified* at start,
        that file is excluded wholesale and the agent's change to it is lost from the
        patch. `preexisting_dirty` is stored on the trajectory so the case is visible
        and can be checked against the flow log's write set.
        """
        add = self._repo_exec("git add -A", timeout=120)
        if add["exit_code"] != 0:
            return ""
        # D21: what did the agent write at a path the test patch owns? Read before
        # anything is unstaged so the record reflects the agent's actual behaviour.
        if self.reserved_paths:
            reserved = set(self.reserved_paths)
            staged = self._repo_exec("git diff --cached --name-only", timeout=120)
            self.reserved_collisions = [
                p.strip() for p in staged["stdout"].splitlines() if p.strip() in reserved
            ]
        # D22: new files pytest would load on its own. Only additions (--diff-filter=A)
        # are candidates, so a modified source file can never be caught by this.
        added = self._repo_exec("git diff --cached --name-only --diff-filter=A", timeout=120)
        self.scratch_excluded = [
            p.strip() for p in added["stdout"].splitlines()
            if p.strip() and is_collectible_scratch(p.strip())
            and p.strip() not in self.reserved_paths
        ]
        excluded: list[str] = []
        for group in (self.preexisting_dirty, self.reserved_paths, self.scratch_excluded):
            for p in group:
                if p not in excluded:
                    excluded.append(p)
        if excluded:
            paths = " ".join(shlex.quote(p) for p in excluded)
            self._repo_exec(f"git reset -q -- {paths}", timeout=120)
        res = self._repo_exec("git diff --cached --no-color", timeout=120)
        if res["exit_code"] != 0:
            return ""
        patch = res["stdout"]
        if len(patch) > MAX_PATCH_BYTES:
            headers = patch.count("\ndiff --git ") + patch.startswith("diff --git ")
            raise PatchTooLarge(
                f"extracted patch is {len(patch)} bytes across {headers} files, over "
                f"the {MAX_PATCH_BYTES}-byte limit; pre-existing dirty paths were "
                f"{self.preexisting_dirty or 'none'}"
            )
        return patch

    def dirty_paths(self) -> list[str]:
        """Write set as git sees it, including anything dirty before the agent ran.
        §6.4 prefers this over `docker diff` for a repo."""
        res = self._repo_exec("git status --porcelain", timeout=120)
        out = []
        for line in res["stdout"].splitlines():
            if len(line) > 3:
                out.append(line[3:].strip())
        return out

    def agent_dirty_paths(self) -> list[str]:
        """The write set attributable to the agent: `dirty_paths()` minus the start-state
        snapshot (D20). This is what belongs in the trajectory record."""
        pre = set(self.preexisting_dirty)
        return [p for p in self.dirty_paths() if p not in pre]

    def reset(self) -> None:
        self._repo_exec("git checkout -- . && git clean -fd", timeout=180)


def _split_sentinel(stdout: str, sentinel: str) -> tuple[str, str]:
    cwd = ""
    lines = stdout.splitlines()
    keep = []
    for line in lines:
        if line.startswith(sentinel):
            cwd = line[len(sentinel):].strip()
        else:
            keep.append(line)
    text = "\n".join(keep)
    if stdout.endswith("\n") and text:
        text += "\n"
    return text, cwd


__all__ = ["InstanceContainer", "DockerError", "docker_available", "image_for",
           "image_key", "TESTBED", "DEFAULT_PLATFORM"]
