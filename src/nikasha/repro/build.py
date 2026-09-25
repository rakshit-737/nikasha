# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Sandboxed builds of a project at one commit (SPEC §13.3, ADR 0006).

1. The tree at the commit is materialized with :meth:`GitRepo.export_tree` (plumbing
   only; never ``git archive`` or ``checkout``, so no hooks, filters or tar commands run).
2. The build runs in the recipe image with the full hardened flag set and
   ``--network none``; all toolchain dependencies are baked into the image.
3. The source is mounted read-only at ``/src`` and copied into the writable ``/work``
   tmpfs; each declared output is copied to ``/out/<basename>`` (later ``/build``).
4. The log is captured, truncated to the recipe's ``output_bytes``.
5. Outputs are cached under ``cache_dir()/repro/builds`` keyed by
   ``(recipe_id, recipe_sha256, commit)``.
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import stat
import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from nikasha.code.gitio import GitRepo
from nikasha.config import cache_dir, ensure_private_dir
from nikasha.errors import NikashaError
from nikasha.model.evidence import CommandRecord
from nikasha.repro import sandbox
from nikasha.repro.recipes import LoadedRecipe, Recipe

_SHA_CHARS = frozenset("0123456789abcdef")
_MIN_SHA_LEN = 40
_COMPLETE = "complete.json"
_LOG = "build.log"
_OUT_MODE = 0o777  # the build runs as uid 65534, which must be able to write /out
_TREE_MODE = 0o755
_FILE_MODE = 0o644
_EXEC_BITS = 0o111
_OPEN_OUT_TRAP = "trap 'chmod -R a+rwX /out 2>/dev/null || true' EXIT"
#: Empties ``/out`` from inside a container, as the uid that wrote it. Used when the host
#: cannot delete what the build left (the trap did not run: timeout kill, or the build
#: removed it). uid 65534 owns every entry, so it can make each one writable first.
SCRUB_SCRIPT = "chmod -R u+rwX /out 2>/dev/null; rm -rf /out/* /out/.[!.]* /out/..?*; true"
_SCRUB_TIMEOUT_S = 120.0
_SCRUB_LIMITS = sandbox.Limits(cpus=1, memory="256m", pids=64, output_bytes=64 * 1024)


class BuildFailedError(NikashaError):
    """The project did not build with the recipe. The log tail is in the message."""


@dataclass(frozen=True, slots=True)
class BuildResult:
    """Where a build's outputs live and how they were produced."""

    outputs_dir: Path
    cached: bool
    log: str
    record: CommandRecord | None


def _check_commit(commit: str) -> str:
    if len(commit) < _MIN_SHA_LEN or not set(commit) <= _SHA_CHARS:
        raise NikashaError(f"expected a full commit SHA, got {commit!r}")
    return commit


def build_key(recipe_id: str, recipe_sha256: str, commit: str) -> PurePosixPath:
    """The cache path, relative to ``cache_dir()``, of one ``(recipe, sha, commit)`` build."""
    _check_commit(commit)
    if not set(recipe_sha256) <= _SHA_CHARS or len(recipe_sha256) != 64:  # noqa: PLR2004
        raise NikashaError("recipe sha256 must be 64 hex digits")
    return PurePosixPath("repro", "builds", recipe_id, recipe_sha256[:16], commit)


def build_dir(loaded: LoadedRecipe, commit: str, cache_root: Path | None = None) -> Path:
    root = cache_root or cache_dir()
    return root.joinpath(*build_key(loaded.recipe.id, loaded.sha256, commit).parts)


def build_script(recipe: Recipe) -> str:
    """The ``sh -c`` body run inside the build container.

    Steps are recipe-authored shell (recipes are reviewed files in this repository, not
    report input). Output paths are validated by the recipe model and quoted here anyway.
    """
    lines = [
        _OPEN_OUT_TRAP,  # before set -eu: the host must be able to delete /out afterwards
        "set -eu",
        "cp -R /src/. /work/",
        "cd /work",
        *recipe.build.steps,
    ]
    for output in recipe.build.outputs:
        src = "/work/" + output.rstrip("/")
        dest = "/out/" + PurePosixPath(output).name
        lines.append(f"cp -R {shlex.quote(src)} {shlex.quote(dest)}")
    return "\n".join(lines) + "\n"


def build_spec(recipe: Recipe, src: Path, out: Path) -> sandbox.ContainerSpec:
    """The container that builds ``recipe``: hardened, offline, source read-only."""
    limits = recipe.limits
    return sandbox.ContainerSpec(
        image=recipe.image.tag,
        cmd=("/bin/sh", "-c", build_script(recipe)),
        mounts=(
            sandbox.Mount(src, "/src", read_only=True),
            sandbox.Mount(out, "/out", read_only=False),
        ),
        env={**recipe.build.env, "HOME": "/tmp"},  # noqa: S108 - inside the container
        limits=sandbox.Limits(
            cpus=limits.cpus,
            memory=limits.memory,
            pids=limits.pids,
            output_bytes=limits.output_bytes,
        ),
        work_size=recipe.build.work_size,
    )


def load_cached(target: Path) -> BuildResult | None:
    """A previously completed build, or ``None``."""
    marker = target / _COMPLETE
    outputs = target / "outputs"
    if not marker.is_file() or not outputs.is_dir():
        return None
    try:
        meta = json.loads(marker.read_text(encoding="utf-8"))
        record = CommandRecord.model_validate(meta["record"]) if meta.get("record") else None
    except (OSError, ValueError, KeyError):
        return None
    log = (target / _LOG).read_text("utf-8", "replace") if (target / _LOG).is_file() else ""
    return BuildResult(outputs, cached=True, log=log, record=record)


def _open_tree(path: Path) -> None:
    """Let uid 65534 read the exported tree (the parent stays private)."""
    for dirpath, dirnames, filenames in os.walk(path):
        Path(dirpath).chmod(_TREE_MODE)
        for name in dirnames:
            (Path(dirpath) / name).chmod(_TREE_MODE)
        for name in filenames:
            file = Path(dirpath) / name
            file.chmod(file.stat().st_mode | 0o444)


@contextmanager
def _key_lock(target: Path) -> Iterator[None]:
    """Serialize installs of one build key across processes and threads.

    The lock file sits next to the build directory. The OS drops the lock when the file
    descriptor closes, so a crashed process never leaves a stale lock behind.
    """
    fd = os.open(target.with_name(f".{target.name}.lock"), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        if sys.platform == "win32":
            import msvcrt  # noqa: PLC0415 - platform-specific

            msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
        else:
            import fcntl  # noqa: PLC0415 - platform-specific

            fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def _install(staging: Path, target: Path) -> None:
    """Move a finished build into place; an existing complete build wins (cache hit).

    Concurrent builds of the same key are expected (two ``nikasha repro`` runs on one
    report), so the check-and-rename runs under a per-key lock: a complete build is never
    removed, and only an incomplete leftover (from a crash) is replaced.
    """
    try:
        with _key_lock(target):
            if load_cached(target) is not None:
                return
            if target.exists():
                shutil.rmtree(target)  # an incomplete leftover from a crashed build
            staging.replace(target)
    except OSError as exc:
        raise BuildFailedError(
            f"could not install the build into the cache: {type(exc).__name__}"
        ) from exc


def _copy_regular(src: Path, dest: Path) -> None:
    """Copy one regular file, opened without following links; keep only its exec bits.

    setuid, setgid and sticky bits and group/other write never reach the cache.
    """
    fd = os.open(src, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
    with os.fdopen(fd, "rb") as reader:
        mode = os.fstat(reader.fileno()).st_mode
        if not stat.S_ISREG(mode):
            raise BuildFailedError(f"build output {src.name!r} is not a regular file")
        with dest.open("xb") as writer:
            shutil.copyfileobj(reader, writer)
    dest.chmod(_FILE_MODE | (_EXEC_BITS if mode & _EXEC_BITS else 0))


def copy_outputs(out: Path, dest: Path) -> None:
    """Copy the build container's ``/out`` to ``dest`` without following any link.

    ``/out`` is written by project code, so it is hostile: a symlink could make the host
    read one of its own files into the cache (and from there into the PoC container).
    Anything but plain directories and regular files refuses the build. Files keep only
    their executable bit (the PoC container runs ``/build/<tool>``).
    """
    try:
        for dirpath, dirnames, filenames in os.walk(out, followlinks=False):
            for name in (*dirnames, *filenames):
                mode = os.lstat(Path(dirpath) / name).st_mode
                if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
                    rel = (Path(dirpath) / name).relative_to(out).as_posix()
                    raise BuildFailedError(
                        f"build output {rel!r} is not a regular file or directory "
                        "(links, devices, FIFOs and sockets are refused)"
                    )
        dest.mkdir()
        for dirpath, dirnames, filenames in os.walk(out, followlinks=False):
            sub = Path(dirpath).relative_to(out)
            for name in dirnames:
                (dest / sub / name).mkdir()
            for name in filenames:
                _copy_regular(Path(dirpath) / name, dest / sub / name)
    except (OSError, shutil.Error) as exc:
        raise BuildFailedError(f"could not copy build outputs: {exc}") from exc


def scrub_spec(image: str, out: Path) -> sandbox.ContainerSpec:
    """The hardened, offline container that empties ``out`` (mounted at ``/out``)."""
    return sandbox.ContainerSpec(
        image=image,
        cmd=("/bin/sh", "-c", SCRUB_SCRIPT),
        mounts=(sandbox.Mount(out, "/out", read_only=False),),
        limits=_SCRUB_LIMITS,
        work_size="16m",
    )


def remove_out(
    engine: sandbox.EngineInfo, image: str, out: Path, *, runtime: str | None = None
) -> bool:
    """Delete the build container's ``/out`` from the host; return whether it is gone.

    The build runs as uid 65534 (a subordinate uid under rootless podman), so a directory
    it created is not writable by the host user unless the exit trap opened it. When the
    host cannot delete the tree, the same image empties it from inside a container.
    """
    try:
        shutil.rmtree(out)
    except FileNotFoundError:
        return True
    except OSError:
        try:
            sandbox.run_container(
                engine, scrub_spec(image, out), timeout_s=_SCRUB_TIMEOUT_S, runtime=runtime
            )
        except NikashaError:
            return False
        shutil.rmtree(out, ignore_errors=True)
    return not out.exists()


def _run_build(
    engine: sandbox.EngineInfo,
    recipe: Recipe,
    commit: str,
    dirs: tuple[Path, Path],
    runtime: str | None,
) -> tuple[sandbox.ContainerResult, str]:
    src, out = dirs
    result = sandbox.run_container(
        engine,
        build_spec(recipe, src, out),
        timeout_s=float(recipe.build.timeout_s),
        runtime=runtime,
    )
    log = (result.stdout + result.stderr).decode("utf-8", "replace")
    if result.timed_out or result.exit_code != 0:
        tail = "\n".join(log.strip().splitlines()[-20:])
        why = "timed out" if result.timed_out else f"exited with {result.exit_code}"
        raise BuildFailedError(f"build of {recipe.id} at {commit[:12]} {why}:\n{tail}")
    return result, log


def _stage(target: Path, out: Path, log: str, meta: dict[str, object]) -> None:
    """Copy the outputs into a private staging directory and install it at ``target``."""
    ensure_private_dir(target.parent)
    staging = Path(tempfile.mkdtemp(dir=target.parent, prefix=".staging-"))
    try:
        copy_outputs(out, staging / "outputs")
        _open_tree(staging / "outputs")  # readable by uid 65534 before anyone can see it
        (staging / _LOG).write_text(log, encoding="utf-8")
        (staging / _COMPLETE).write_text(json.dumps(meta, sort_keys=True), encoding="utf-8")
        _install(staging, target)
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def build(
    repo: GitRepo,
    commit: str,
    loaded: LoadedRecipe,
    engine: sandbox.EngineInfo,
    *,
    cache_root: Path | None = None,
    runtime: str | None = None,
) -> BuildResult:
    """Build ``commit`` with ``loaded`` in ``engine``, or return the cached outputs."""
    _check_commit(commit)
    target = build_dir(loaded, commit, cache_root)
    cached = load_cached(target)
    if cached is not None:
        return cached
    recipe = loaded.recipe
    try:
        scratch_root = ensure_private_dir((cache_root or cache_dir()) / "repro" / "tmp")
        work = Path(tempfile.mkdtemp(dir=scratch_root, prefix="build-"))
    except OSError as exc:
        raise BuildFailedError(f"cannot create a build directory: {exc}") from exc
    src = work / "src"
    out = work / "out"
    try:
        src.mkdir()
        out.mkdir()
        repo.export_tree(commit, src)
        _open_tree(src)
        work.chmod(_TREE_MODE)
        out.chmod(_OUT_MODE)
        result, log = _run_build(engine, recipe, commit, (src, out), runtime)
        record = result.record()
        meta: dict[str, object] = {
            "commit": commit,
            "recipe_id": recipe.id,
            "recipe_sha256": loaded.sha256,
            "record": record.model_dump(mode="json"),
        }
        _stage(target, out, log, meta)
    except OSError as exc:
        raise BuildFailedError(f"build of {recipe.id} failed: {type(exc).__name__}: {exc}") from exc
    finally:
        # Never raises: a failure to clean up must not hide why the build failed.
        remove_out(engine, recipe.image.tag, out, runtime=runtime)
        shutil.rmtree(work, ignore_errors=True)
    installed = load_cached(target)
    if installed is None:  # pragma: no cover - _install raises instead
        raise BuildFailedError(f"build of {recipe.id} did not reach the cache")
    if installed.record != record:
        return installed  # a concurrent build of the same key landed first
    return BuildResult(installed.outputs_dir, cached=False, log=log, record=record)


__all__ = [
    "BuildFailedError",
    "BuildResult",
    "build",
    "build_dir",
    "build_key",
    "build_script",
    "build_spec",
    "copy_outputs",
    "load_cached",
    "remove_out",
    "scrub_spec",
]
