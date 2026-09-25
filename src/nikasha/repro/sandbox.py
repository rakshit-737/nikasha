# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Container-engine access (SPEC §13.1). The only module besides ``code/gitio.py`` that may
spawn processes.

Engine detection (M0) feeds ``nikasha doctor``. M5 adds engine selection, the hardened
``run`` argv (SPEC §13.4, with the per-engine spellings verified in
docs/research/2026-09-23-m0-verification.md §6), image builds and a container runner that
enforces a wall-clock timeout by killing the container and caps captured output.

Nothing here ever executes a proof of concept on the host: the only programs spawned are
the container engine itself.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import shutil
import subprocess
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any, Literal

from nikasha.errors import ExternalToolError, NikashaError
from nikasha.model.evidence import CommandRecord

EngineName = Literal["podman", "docker"]

#: Detection order: rootless podman is preferred when present (SPEC §5, §13.1).
ENGINE_ORDER: tuple[EngineName, ...] = ("podman", "docker")

_INFO_ARGV: dict[EngineName, tuple[str, ...]] = {
    "podman": ("info", "--format", "json"),
    "docker": ("info", "--format", "{{json .}}"),
}

_INFO_TIMEOUT_S = 20.0


@dataclass(frozen=True, slots=True)
class EngineInfo:
    """What ``nikasha doctor`` reports about one container engine."""

    name: EngineName
    available: bool
    version: str | None = None
    rootless: bool | None = None
    cgroup_version: str | None = None
    error: str | None = None
    #: Whether the engine reports that it can enforce ``--memory`` and ``--pids-limit``
    #: (``None`` when it did not say). Rootless cgroup v1 setups cannot.
    memory_limit: bool | None = None
    pids_limit: bool | None = None


def _normalize_cgroup(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip().lower()
    if not text:
        return None
    return text if text.startswith("v") else f"v{text}"


def _parse_podman(info: dict[str, Any]) -> EngineInfo:
    host = info.get("host", {})
    security = host.get("security", {})
    controllers = host.get("cgroupControllers")
    known = isinstance(controllers, list)
    return EngineInfo(
        memory_limit=("memory" in controllers) if known else None,
        pids_limit=("pids" in controllers) if known else None,
        name="podman",
        available=True,
        version=info.get("version", {}).get("Version"),
        rootless=security.get("rootless"),
        cgroup_version=_normalize_cgroup(host.get("cgroupVersion")),
    )


def _parse_docker(info: dict[str, Any]) -> EngineInfo:
    errors = info.get("ServerErrors") or []
    if errors:
        return EngineInfo(name="docker", available=False, error="; ".join(map(str, errors)))
    options = [str(o) for o in info.get("SecurityOptions") or []]
    mem = info.get("MemoryLimit")
    pids = info.get("PidsLimit")
    return EngineInfo(
        memory_limit=mem if isinstance(mem, bool) else None,
        pids_limit=pids if isinstance(pids, bool) else None,
        name="docker",
        available=True,
        version=info.get("ServerVersion"),
        rootless=any("name=rootless" in o for o in options),
        cgroup_version=_normalize_cgroup(info.get("CgroupVersion")),
    )


def probe_engine(name: EngineName) -> EngineInfo:
    """Ask one engine for its version, rootless mode and cgroup version. Never raises."""
    exe = shutil.which(name)
    if exe is None:
        return EngineInfo(name=name, available=False, error="not found on PATH")
    try:
        proc = subprocess.run(
            [exe, *_INFO_ARGV[name]],
            capture_output=True,
            timeout=_INFO_TIMEOUT_S,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return EngineInfo(name=name, available=False, error=type(exc).__name__)
    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", "replace").strip().splitlines()
        return EngineInfo(
            name=name,
            available=False,
            error=detail[-1] if detail else f"exit status {proc.returncode}",
        )
    try:
        info = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return EngineInfo(name=name, available=False, error="unparsable `info` output")
    if not isinstance(info, dict):
        return EngineInfo(name=name, available=False, error="unexpected `info` output")
    return _parse_podman(info) if name == "podman" else _parse_docker(info)


def detect_engines() -> list[EngineInfo]:
    """Probe every supported engine, in preference order."""
    return [probe_engine(name) for name in ENGINE_ORDER]


def preferred_engine(engines: list[EngineInfo]) -> EngineInfo | None:
    """Return the first available engine in preference order, or ``None``."""
    return next((e for e in engines if e.available), None)


# --------------------------------------------------------------------------------------
# M5: selection, facts, hardened argv, runner (SPEC §13.1, §13.4)
# --------------------------------------------------------------------------------------

SANDBOX_CHOICES: tuple[str, ...] = ("auto", "podman", "docker")


class NoEngineError(NikashaError):
    """``--repro`` was asked for but no usable container engine exists (SPEC §13.1)."""


class SandboxError(NikashaError):
    """A container could not be prepared or started."""


def _engine_rank(engine: EngineInfo) -> int:
    """Rootless podman first, then docker, then rootful podman (SPEC §13.1)."""
    if engine.name == "podman" and engine.rootless:
        return 0
    return 1 if engine.name == "docker" else 2


def select_engine(choice: str = "auto", engines: Sequence[EngineInfo] | None = None) -> EngineInfo:
    """Pick the engine ``--repro`` will use, or raise :class:`NoEngineError`.

    ``choice`` is the ``--sandbox`` value. ``auto`` prefers rootless podman, then docker.
    Naming an engine that is unavailable is refused rather than silently falling back.
    PoCs are never run on the host, so there is no "none" engine (P5).
    """
    if choice not in SANDBOX_CHOICES:
        raise NikashaError(f"--sandbox must be one of {', '.join(SANDBOX_CHOICES)}")
    probed = list(engines) if engines is not None else detect_engines()
    if choice != "auto":
        named = [e for e in probed if e.name == choice]
        engine = named[0] if named else probe_engine("podman" if choice == "podman" else "docker")
        if not engine.available:
            raise NoEngineError(
                f"--sandbox {choice} was requested but {choice} is unavailable "
                f"({engine.error or 'unknown reason'}); refusing to run the PoC. "
                "PoCs are never run on the host."
            )
        return engine
    available = sorted((e for e in probed if e.available), key=_engine_rank)
    if not available:
        details = "; ".join(f"{e.name}: {e.error or 'unavailable'}" for e in probed)
        raise NoEngineError(
            "no container engine is available (install rootless podman or docker); "
            f"refusing to run the PoC. PoCs are never run on the host. [{details}]"
        )
    return available[0]


@dataclass(frozen=True, slots=True)
class EngineFacts:
    """Doctor-grade facts about one engine (SPEC §13.1)."""

    name: str
    version: str | None
    rootless: bool | None
    cgroup_version: str | None
    memory_limit_enforced: bool | None
    pids_limit_enforced: bool | None

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "version": self.version,
            "rootless": self.rootless,
            "cgroup_version": self.cgroup_version,
            "memory_limit_enforced": self.memory_limit_enforced,
            "pids_limit_enforced": self.pids_limit_enforced,
        }


def _enforced(reported: bool | None, engine: EngineInfo) -> bool | None:
    if reported is not None:
        return reported
    if engine.rootless and engine.cgroup_version == "v1":
        return False  # rootless cgroup v1 cannot delegate the memory or pids controller
    if engine.cgroup_version == "v2" and engine.rootless is False:
        return True
    return None


def engine_facts(engine: EngineInfo) -> EngineFacts:
    """Summarize an :class:`EngineInfo`, deciding whether the limits are really enforced.

    The engine's own report wins (docker ``MemoryLimit``/``PidsLimit``, podman's delegated
    ``cgroupControllers``). Without one, rootless on cgroup v1 means "not enforced", rootful
    on cgroup v2 means "enforced", and anything else is ``None``: unknown, never guessed.
    """
    return EngineFacts(
        name=engine.name,
        version=engine.version,
        rootless=engine.rootless,
        cgroup_version=engine.cgroup_version,
        memory_limit_enforced=_enforced(engine.memory_limit, engine),
        pids_limit_enforced=_enforced(engine.pids_limit, engine),
    )


@dataclass(frozen=True, slots=True)
class Mount:
    """A bind mount of a host directory into the container."""

    host: Path
    target: str
    read_only: bool = True


@dataclass(frozen=True, slots=True)
class Limits:
    cpus: float = 2.0
    memory: str = "2g"
    pids: int = 256
    output_bytes: int = 1024 * 1024


@dataclass(frozen=True, slots=True)
class ContainerSpec:
    """Everything that varies between two sandboxed containers. The rest is fixed."""

    image: str
    cmd: tuple[str, ...]
    mounts: tuple[Mount, ...] = ()
    env: Mapping[str, str] = field(default_factory=dict)
    limits: Limits = Limits()
    work_size: str = "256m"
    workdir: str = "/work"
    user: str = "65534:65534"


#: Container paths the sandbox owns; a mount may not shadow them.
_RESERVED_TARGETS = frozenset({"/", "/tmp", "/work", "/proc", "/sys", "/dev", "/etc", "/usr"})  # noqa: S108 - container paths
_SIZE_RE = re.compile(r"[0-9]{1,15}[kmgKMG]?")
_NAME_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.")
_MAX_NAME = 128
_MAX_SIZE_LEN = 16
_DRIVE_PREFIX = 2


def _check_size(value: str, what: str) -> str:
    if len(value) > _MAX_SIZE_LEN or _SIZE_RE.fullmatch(value) is None:
        raise SandboxError(f"invalid {what}: {value!r}")
    return value


def _check_mount(mount: Mount) -> None:
    target = mount.target
    if (
        not target.startswith("/")
        or target.rstrip("/") in _RESERVED_TARGETS
        or target == "/"
        or ".." in target.split("/")
        or any(ch in target for ch in ":,\n\0")
    ):
        raise SandboxError(f"refusing mount target {target!r}")
    host = str(mount.host)
    body = host[_DRIVE_PREFIX:] if len(host) > 1 and host[1] == ":" else host
    if not mount.host.is_absolute() or any(ch in body for ch in ":,\n\0"):
        raise SandboxError("refusing a host path that is relative or contains ':' or ','")


def _check_env(env: Mapping[str, str]) -> None:
    for key, value in env.items():
        if not key or not (key[0].isalpha() or key[0] == "_"):
            raise SandboxError(f"invalid environment variable name {key!r}")
        if not all(ch.isalnum() or ch == "_" for ch in key) or "\0" in value:
            raise SandboxError(f"invalid environment variable {key!r}")


def _check_name(value: str, what: str) -> str:
    if not value or len(value) > _MAX_NAME or not set(value) <= _NAME_CHARS or value[0] == "-":
        raise SandboxError(f"invalid {what} {value!r}")
    return value


def no_new_privileges_opt(engine: EngineName) -> str:
    """The ``--security-opt`` spelling each engine documents (research §6)."""
    return "no-new-privileges" if engine == "podman" else "no-new-privileges=true"


def run_argv(
    engine: EngineName,
    spec: ContainerSpec,
    *,
    name: str,
    runtime: str | None = None,
    exe: str | None = None,
) -> list[str]:
    """Compose the hardened ``run`` argv of SPEC §13.4 for ``engine``.

    Per-engine adjustments (docs/research/2026-09-23-m0-verification.md §6):

    * podman needs ``--read-only-tmpfs=false``, or ``--read-only`` still mounts writable
      tmpfs on /dev, /dev/shm, /run, /tmp and /var/tmp;
    * ``--runtime`` is a *global* podman flag but a ``run`` flag for docker;
    * no-new-privileges is ``no-new-privileges`` (podman) / ``no-new-privileges=true``.

    Two additions to the SPEC list: ``--pull never`` keeps the run offline (P3; images are
    built beforehand) and ``--name`` lets a timed-out container be killed by name.
    """
    if engine not in ENGINE_ORDER:
        raise SandboxError(f"unknown engine {engine!r}")
    _check_name(name, "container name")
    if runtime is not None:
        _check_name(runtime, "--runtime")
    if not spec.cmd or not spec.image or spec.image.startswith("-"):
        raise SandboxError("a container needs an image and a command")
    for mount in spec.mounts:
        _check_mount(mount)
    _check_env(spec.env)
    limits = spec.limits
    if limits.pids < 1 or limits.cpus <= 0 or limits.output_bytes < 1:
        raise SandboxError("limits must be positive")
    argv: list[str] = [exe or engine]
    if engine == "podman" and runtime:
        argv += ["--runtime", runtime]
    argv += ["run", "--rm", "--init", "--pull", "never", "--name", name]
    if engine == "docker" and runtime:
        argv += ["--runtime", runtime]
    argv += ["--network", "none", "--read-only"]
    if engine == "podman":
        argv.append("--read-only-tmpfs=false")
    argv += [
        "--tmpfs",
        "/tmp:rw,size=64m",  # noqa: S108 - a tmpfs inside the container
        "--tmpfs",
        f"/work:rw,exec,size={_check_size(spec.work_size, 'work size')}",
        "--cap-drop",
        "ALL",
        "--security-opt",
        no_new_privileges_opt(engine),
        "--pids-limit",
        str(limits.pids),
        "--memory",
        _check_size(limits.memory, "memory limit"),
        "--cpus",
        f"{limits.cpus:g}",
        "--user",
        spec.user,
        "--ulimit",
        "core=0",
        "--workdir",
        spec.workdir,
    ]
    for key in sorted(spec.env):
        argv += ["--env", f"{key}={spec.env[key]}"]
    for mount in spec.mounts:
        argv += ["-v", f"{mount.host}:{mount.target}:{'ro' if mount.read_only else 'rw'}"]
    argv += [spec.image, *spec.cmd]
    return argv


#: What the random container name becomes in a recorded argv.
REDACTED_NAME = "<name>"
#: What a host path becomes in a recorded argv (the same marker ``gitio`` uses).
REDACTED_HOST_PATH = "<path>"


def redact_container_argv(argv: Sequence[str], host_paths: Sequence[Path] = ()) -> tuple[str, ...]:
    """Machine-independent form of an engine argv for a :class:`CommandRecord` (P2, P3, P6).

    Mirrors ``gitio.redact_argv``: argv[0] becomes the bare engine name, the random
    container name becomes :data:`REDACTED_NAME`, and every host path (the source of each
    ``-v`` and any argument equal to one of ``host_paths``) becomes
    :data:`REDACTED_HOST_PATH`. Container-side paths such as ``/build/hdrcat`` are kept:
    they are what a reader needs to re-run the command.
    """
    if not argv:
        return ()
    exe = Path(argv[0].replace("\\", "/")).name.lower().removesuffix(".exe")
    out: list[str] = [exe]
    known = {str(p) for p in host_paths}
    previous = ""
    for arg in argv[1:]:
        if previous == "--name":
            out.append(REDACTED_NAME)
        elif previous == "-v":
            head, _, mode = arg.rpartition(":")
            target = head.rpartition(":")[2]
            out.append(f"{REDACTED_HOST_PATH}:{target}:{mode}")
        else:
            out.append(REDACTED_HOST_PATH if arg in known else arg)
        previous = arg
    return tuple(out)


@dataclass(frozen=True, slots=True)
class ContainerResult:
    """One container run, with its captured (and possibly truncated) output."""

    argv: tuple[str, ...]
    recorded_argv: tuple[str, ...]
    exit_code: int
    stdout: bytes
    stderr: bytes
    timed_out: bool
    truncated: bool
    duration_ms: int

    def record(self) -> CommandRecord:
        """The evidence record: redacted argv, output hashes, no duration (P2)."""
        return CommandRecord(
            argv=self.recorded_argv,
            exit_code=self.exit_code,
            stdout_sha256=hashlib.sha256(self.stdout).hexdigest(),
            stderr_sha256=hashlib.sha256(self.stderr).hexdigest(),
            truncated=self.truncated,
        )


class CappedReader(threading.Thread):
    """Drain a pipe, keeping only the first ``cap`` bytes; the rest is read and dropped."""

    def __init__(self, stream: IO[bytes], cap: int) -> None:
        super().__init__(daemon=True)
        self._stream = stream
        self._cap = cap
        self.data = bytearray()
        self.truncated = False

    def run(self) -> None:
        while chunk := self._stream.read(65536):
            room = max(self._cap - len(self.data), 0)
            if room:
                self.data += chunk[:room]
            if len(chunk) > room:
                self.truncated = True


def new_container_name(prefix: str = "nikasha") -> str:
    """A unique name, so a timed-out container can be killed by name."""
    return f"{prefix}-{secrets.token_hex(8)}"


def engine_executable(engine: EngineInfo) -> str:
    """The engine's executable, or :class:`NoEngineError` (never a host fallback)."""
    exe = shutil.which(engine.name)
    if exe is None or not engine.available:
        raise NoEngineError(f"{engine.name} is not available; PoCs are never run on the host")
    return exe


_KILL_TIMEOUT_S = 30.0


def _cleanup(exe: str, name: str) -> None:
    for args in (("kill", name), ("rm", "-f", name)):
        try:
            subprocess.run([exe, *args], capture_output=True, timeout=_KILL_TIMEOUT_S, check=False)
        except (OSError, subprocess.TimeoutExpired):
            continue


def run_container(
    engine: EngineInfo,
    spec: ContainerSpec,
    *,
    timeout_s: float,
    runtime: str | None = None,
    name: str | None = None,
) -> ContainerResult:
    """Run one fresh container; kill it at ``timeout_s``; cap each stream's output.

    The container is started with ``--rm``; after a timeout it is also killed and removed
    by name, so none is left running.
    """
    exe = engine_executable(engine)
    cname = name or new_container_name()
    argv = run_argv(engine.name, spec, name=cname, runtime=runtime, exe=exe)
    recorded = redact_container_argv(argv, [m.host for m in spec.mounts])
    started = time.monotonic()
    try:
        proc = subprocess.Popen(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
    except OSError as exc:
        raise SandboxError(f"could not start {engine.name}: {type(exc).__name__}") from exc
    if proc.stdout is None or proc.stderr is None:  # pragma: no cover - PIPE was asked for
        raise SandboxError("container output pipes are missing")
    cap = spec.limits.output_bytes
    readers = [CappedReader(proc.stdout, cap), CappedReader(proc.stderr, cap)]
    for reader in readers:
        reader.start()
    timed_out = False
    try:
        code = proc.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        timed_out = True
        _cleanup(exe, cname)
        try:
            code = proc.wait(timeout=_KILL_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            proc.kill()
            code = proc.wait()
    for reader in readers:
        reader.join(timeout=_KILL_TIMEOUT_S)
    return ContainerResult(
        argv=tuple(argv),
        recorded_argv=recorded,
        exit_code=code,
        stdout=bytes(readers[0].data),
        stderr=bytes(readers[1].data),
        timed_out=timed_out,
        truncated=readers[0].truncated or readers[1].truncated,
        duration_ms=int((time.monotonic() - started) * 1000),
    )


def container_exists(engine: EngineInfo, name: str) -> bool:
    """Whether any container (running or stopped) named exactly ``name`` exists."""
    exe = engine_executable(engine)
    _check_name(name, "container name")
    proc = subprocess.run(
        [exe, "ps", "-a", "--filter", f"name=^{name}$", "--format", "{{.Names}}"],
        capture_output=True,
        timeout=_INFO_TIMEOUT_S,
        check=False,
    )
    return name in proc.stdout.decode("utf-8", "replace").split()


def check_image_tag(tag: str) -> str:
    """Refuse an image tag that could be read as an option or split into two arguments."""
    if not tag or tag.startswith("-") or any(c.isspace() or c == "\0" for c in tag):
        raise SandboxError(f"invalid image tag {tag!r}")
    return tag


def image_exists(engine: EngineInfo, tag: str) -> bool:
    """Whether the engine already has the image ``tag`` locally."""
    exe = engine_executable(engine)
    try:
        proc = subprocess.run(
            [exe, "image", "inspect", check_image_tag(tag)],
            capture_output=True,
            timeout=_INFO_TIMEOUT_S,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0


def build_image_argv(engine: EngineName, dockerfile: Path, context: Path, tag: str) -> list[str]:
    """``<engine> build -f <dockerfile> -t <tag> <context>``."""
    return [engine, "build", "-f", str(dockerfile), "-t", check_image_tag(tag), str(context)]


_IMAGE_BUILD_TIMEOUT_S = 3600.0


def build_image(
    engine: EngineInfo, dockerfile: Path, context: Path, tag: str, *, online: bool
) -> CommandRecord:
    """Build a recipe image. That pulls a base image, so it needs ``--online`` (P3)."""
    if not online:
        raise NikashaError(
            f"image {tag} is not built, and building it downloads a base image; "
            "re-run with --online, or build it yourself with "
            f"`{engine.name} build -f docker/recipes/{dockerfile.name} -t {tag} .`"
        )
    exe = engine_executable(engine)
    argv = build_image_argv(engine.name, dockerfile, context, tag)
    argv[0] = exe
    try:
        proc = subprocess.run(
            argv, capture_output=True, timeout=_IMAGE_BUILD_TIMEOUT_S, check=False
        )
    except subprocess.TimeoutExpired as exc:
        raise ExternalToolError(f"building image {tag} timed out") from exc
    if proc.returncode != 0:
        tail = proc.stderr.decode("utf-8", "replace").strip().splitlines()[-1:] or ["?"]
        raise SandboxError(f"building image {tag} failed: {tail[0]}")
    return CommandRecord(
        argv=redact_container_argv(argv, [dockerfile, context]),
        exit_code=proc.returncode,
        stdout_sha256=hashlib.sha256(proc.stdout).hexdigest(),
        stderr_sha256=hashlib.sha256(proc.stderr).hexdigest(),
    )
