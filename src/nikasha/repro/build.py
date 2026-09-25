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
import tempfile
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
_OPEN_OUT_TRAP = "trap 'chmod -R a+rwX /out 2>/dev/null || true' EXIT"


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


def _install(staging: Path, target: Path) -> None:
    """Move a finished build into place; an existing complete build wins (cache hit)."""
    if load_cached(target) is not None:
        return
    if target.exists():
        shutil.rmtree(target)  # an incomplete leftover
    try:
        staging.chmod(0o700)
        staging.replace(target)
    except OSError:
        if load_cached(target) is None:  # lost a race to a complete build otherwise
            raise


def copy_outputs(out: Path, dest: Path) -> None:
    """Copy the build container's ``/out`` to ``dest`` without following any link.

    ``/out`` is written by project code, so it is hostile: a symlink could make the host
    read one of its own files into the cache (and from there into the PoC container).
    Anything but plain directories and regular files refuses the build.
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
                shutil.copyfile(Path(dirpath) / name, dest / sub / name, follow_symlinks=False)
    except (OSError, shutil.Error) as exc:
        raise BuildFailedError(f"could not copy build outputs: {exc}") from exc


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
    scratch_root = ensure_private_dir((cache_root or cache_dir()) / "repro" / "tmp")
    with tempfile.TemporaryDirectory(dir=scratch_root, ignore_cleanup_errors=True) as tmp:
        work = Path(tmp)
        src = work / "src"
        out = work / "out"
        src.mkdir()
        out.mkdir()
        repo.export_tree(commit, src)
        _open_tree(src)
        work.chmod(_TREE_MODE)
        out.chmod(_OUT_MODE)
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
        ensure_private_dir(target.parent)
        staging = Path(tempfile.mkdtemp(dir=target.parent, prefix=".staging-"))
        try:
            copy_outputs(out, staging / "outputs")
            (staging / _LOG).write_text(log, encoding="utf-8")
            record = result.record()
            meta = {
                "commit": commit,
                "recipe_id": recipe.id,
                "recipe_sha256": loaded.sha256,
                "record": record.model_dump(mode="json"),
            }
            (staging / _COMPLETE).write_text(json.dumps(meta, sort_keys=True), encoding="utf-8")
            _install(staging, target)
        finally:
            shutil.rmtree(staging, ignore_errors=True)
        winner = load_cached(target)
        if winner is not None and winner.record != record:
            return winner  # a concurrent build of the same key landed first
    _open_tree(target / "outputs")
    return BuildResult(target / "outputs", cached=False, log=log, record=record)


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
]
