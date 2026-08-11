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
"""

from __future__ import annotations

import json
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


class DockerError(RuntimeError):
    pass


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
    container_id: str = ""
    #: §6.4 - the envelope defaults. `--network none` makes egress impossible rather
    #: than merely bounded. Kept off by default in Phase 2 so `pip install` still works
    #: if an instance needs it; Phase 2b turns it on and proves the property.
    network_none: bool = False
    memory: str = "4g"
    cpus: str = "2"
    pids_limit: int = 512
    started: float = field(default_factory=time.time)

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
            "-w", TESTBED,
            "--memory", self.memory,
            "--cpus", self.cpus,
            "--pids-limit", str(self.pids_limit),
            # NEVER mount /var/run/docker.sock - full container escape, and it silently
            # voids every property in §6.4.
        ]
        if self.network_none:
            args += ["--network", "none"]
        args += [self.image, "sleep", "infinity"]
        p = _run(args, timeout=600)
        if p.returncode != 0:
            raise DockerError(f"could not start container for {self.instance_id}:\n{p.stderr.strip()}")
        self.container_id = p.stdout.strip()
        self.workdir = TESTBED
        return self

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

    def exec(self, command: str, timeout: int = 300) -> dict:
        """Run one shell command inside the container.

        `cd` is tracked across calls because `docker exec` is stateless. The command
        runs as `cd <workdir> && <command>`, and the resulting cwd is read back so the
        next call lands where the agent expects.
        """
        if not self.container_id:
            raise DockerError("container is not running")

        # Emit the post-command cwd on a private sentinel line so it can be stripped
        # from what the agent sees.
        sentinel = "__DFC_CWD__"
        wrapped = (
            f"cd {shlex.quote(self.workdir)} 2>/dev/null || cd {TESTBED}; "
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
        if cwd:
            self.workdir = cwd
        return {
            "exit_code": p.returncode,
            "stdout": stdout,
            "stderr": p.stderr,
            "timed_out": False,
            "cwd": self.workdir,
        }

    # -- patch extraction ------------------------------------------------

    def model_patch(self) -> str:
        """§8 R5: the patch is produced by `git diff` at the end of the trajectory, not
        by the model emitting diff text. This is what killed the previous run - invented
        paths and fabricated blob hashes cannot happen when the diff comes from git."""
        add = self.exec("git add -A", timeout=120)
        if add["exit_code"] != 0:
            return ""
        res = self.exec("git diff --cached --no-color", timeout=120)
        return res["stdout"] if res["exit_code"] == 0 else ""

    def dirty_paths(self) -> list[str]:
        """Write set, cheaply. §6.4 prefers this over `docker diff` for a repo."""
        res = self.exec("git status --porcelain", timeout=120)
        out = []
        for line in res["stdout"].splitlines():
            if len(line) > 3:
                out.append(line[3:].strip())
        return out

    def reset(self) -> None:
        self.exec("git checkout -- . && git clean -fd", timeout=180)


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
