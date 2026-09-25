# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Run one proof of concept in a fresh hardened container (SPEC §13.4).

The PoC is hostile (P5). It is copied into a private staging directory mounted read-only
at ``/poc``; the build outputs are mounted read-only at ``/build``; everything else is the
fixed flag set of :func:`nikasha.repro.sandbox.run_argv`. Nothing here executes the PoC on
the host: the only process started is the container engine.
"""

from __future__ import annotations

import shlex
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

from nikasha.config import cache_dir, ensure_private_dir
from nikasha.errors import NikashaError
from nikasha.model.evidence import CommandRecord
from nikasha.repro import sandbox
from nikasha.repro.recipes import ARGS_PLACEHOLDER, FILE_PLACEHOLDER, Recipe, RunKind

MAX_POC_BYTES = 64 * 1024 * 1024
MAX_POC_FILES = 1000
MAX_ARGS = 256
_SAFE_NAME = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.+")
_HARNESS_NAME = "poc.c"
_FALLBACK_NAME = "poc.bin"
_DIR_MODE = 0o755
_FILE_MODE = 0o644


class PocError(NikashaError):
    """The PoC or its arguments cannot be staged safely."""


@dataclass(frozen=True, slots=True)
class ReproRun:
    """One PoC execution. ``stdout``/``stderr`` are capped at the recipe's output limit."""

    kind: str
    exit_code: int
    timed_out: bool
    truncated: bool
    stdout: str
    stderr: str
    record: CommandRecord


def _safe_name(name: str) -> str:
    if name and set(name) <= _SAFE_NAME and not name.startswith((".", "-")):
        return name
    return _FALLBACK_NAME


def choose_kind(recipe: Recipe, poc: Path, kind: str | None) -> str:
    """``--kind`` if given, else ``c_harness`` for a ``.c`` file, else ``file_input``."""
    kinds = recipe.run.kinds
    if kind is not None:
        if kind not in kinds:
            raise PocError(f"recipe {recipe.id} has no kind {kind!r} (has: {', '.join(kinds)})")
        return kind
    if poc.suffix == ".c" and "c_harness" in kinds:
        return "c_harness"
    for candidate in ("file_input", "cli"):
        if candidate in kinds:
            return candidate
    return sorted(kinds)[0]


def stage_poc(poc: Path, kind: str, dest: Path) -> str | None:
    """Copy the PoC into ``dest`` (later ``/poc``); return the name ``{file}`` refers to.

    Symlinks are never followed or copied, sizes and counts are capped, and every file is
    made world-readable so uid 65534 in the container can read it.
    """
    dest.chmod(_DIR_MODE)
    if poc.is_symlink():
        raise PocError("the PoC must not be a symbolic link")
    if poc.is_file():
        if poc.stat().st_size > MAX_POC_BYTES:
            raise PocError(f"the PoC is larger than {MAX_POC_BYTES} bytes")
        name = _HARNESS_NAME if kind == "c_harness" else _safe_name(poc.name)
        shutil.copyfile(poc, dest / name, follow_symlinks=False)
        (dest / name).chmod(_FILE_MODE)
        return name
    if not poc.is_dir():
        raise PocError("the PoC path does not exist")
    total = 0
    count = 0
    for item in sorted(poc.rglob("*")):
        if item.is_symlink():
            continue
        rel = item.relative_to(poc)
        if any(_safe_name(part) != part for part in rel.parts):
            raise PocError(f"unsupported file name in the PoC directory: {rel.as_posix()!r}")
        target = dest / rel
        if item.is_dir():
            target.mkdir(mode=_DIR_MODE, exist_ok=True)
            target.chmod(_DIR_MODE)
            continue
        count += 1
        total += item.stat().st_size
        if count > MAX_POC_FILES or total > MAX_POC_BYTES:
            raise PocError("the PoC directory is too large")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(item, target, follow_symlinks=False)
        target.chmod(_FILE_MODE)
    return None


def _expand(parts: tuple[str, ...], args: tuple[str, ...], file: str | None) -> list[str]:
    out: list[str] = []
    for part in parts:
        if part == ARGS_PLACEHOLDER:
            out.extend(args)
            continue
        if FILE_PLACEHOLDER in part:
            if file is None:
                raise PocError("this kind needs a single PoC file ({file}); pass a file")
            part = part.replace(FILE_PLACEHOLDER, file)  # noqa: PLW2901
        out.append(part)
    return out


def poc_command(
    run_kind: RunKind, *, args: tuple[str, ...] = (), file: str | None = None
) -> tuple[str, ...]:
    """The container command for one kind, with placeholders filled.

    Arguments are passed as separate argv entries, never through a shell. Only a kind with
    a ``compile`` step uses ``/bin/sh -c``, and then every word is ``shlex.quote``d.
    """
    if len(args) > MAX_ARGS or any("\0" in a for a in args):
        raise PocError("too many PoC arguments, or an argument with a NUL byte")
    cmd = _expand(run_kind.cmd, args, file)
    if run_kind.compile is None:
        return tuple(cmd)
    compile_cmd = _expand(run_kind.compile, args, file)
    script = f"{shlex.join(compile_cmd)} && exec {shlex.join(cmd)}"
    return ("/bin/sh", "-c", script)


def run_spec(
    recipe: Recipe, build_outputs: Path, poc_dir: Path, command: tuple[str, ...]
) -> sandbox.ContainerSpec:
    limits = recipe.limits
    return sandbox.ContainerSpec(
        image=recipe.image.tag,
        cmd=command,
        mounts=(
            sandbox.Mount(poc_dir, "/poc", read_only=True),
            sandbox.Mount(build_outputs, "/build", read_only=True),
        ),
        env=dict(recipe.run.env),
        limits=sandbox.Limits(
            cpus=limits.cpus,
            memory=limits.memory,
            pids=limits.pids,
            output_bytes=limits.output_bytes,
        ),
    )


def run_poc(
    engine: sandbox.EngineInfo,
    recipe: Recipe,
    build_outputs: Path,
    poc: Path,
    *,
    kind: str | None = None,
    args: tuple[str, ...] = (),
    timeout_s: float | None = None,
    runtime: str | None = None,
    cache_root: Path | None = None,
) -> ReproRun:
    """Stage ``poc``, run it once in a fresh container, and return the capped result."""
    chosen = choose_kind(recipe, poc, kind)
    scratch_root = ensure_private_dir((cache_root or cache_dir()) / "repro" / "tmp")
    with tempfile.TemporaryDirectory(dir=scratch_root) as tmp:
        base = Path(tmp)
        base.chmod(_DIR_MODE)
        poc_dir = base / "poc"
        poc_dir.mkdir()
        file = stage_poc(poc, chosen, poc_dir)
        command = poc_command(recipe.run.kinds[chosen], args=args, file=file)
        result = sandbox.run_container(
            engine,
            run_spec(recipe, build_outputs, poc_dir, command),
            timeout_s=float(recipe.run.timeout_s if timeout_s is None else timeout_s),
            runtime=runtime,
        )
    return ReproRun(
        kind=chosen,
        exit_code=result.exit_code,
        timed_out=result.timed_out,
        truncated=result.truncated,
        stdout=result.stdout.decode("utf-8", "replace"),
        stderr=result.stderr.decode("utf-8", "replace"),
        record=result.record(),
    )


__all__ = ["PocError", "ReproRun", "choose_kind", "poc_command", "run_poc", "stage_poc"]
