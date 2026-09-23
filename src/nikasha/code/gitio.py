# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The single hardened entry point for running git (SPEC §19.3).

Every git invocation in Nikasha MUST go through :func:`run_git`, which a test enforces by
scanning the source tree. Repositories are attacker-controlled input, so the wrapper:

* allows only a fixed set of read-mostly plumbing subcommands;
* overrides risky repository config on the command line (``-c`` beats repo config);
* disables external diff drivers and textconv on commands that could invoke them;
* scrubs inherited ``GIT_*`` variables and ignores system and global config by default.

Verified against git 2.55 docs and source on 2026-09-23 (see
``docs/research/2026-09-23-m0-verification.md``). ``-c diff.external=`` is deliberately
*not* used: an empty value does not disable external diff, ``--no-ext-diff`` does.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from nikasha.errors import ExternalToolError, ForbiddenCommandError

#: Subcommands production code may run.
ALLOWED_SUBCOMMANDS: frozenset[str] = frozenset(
    {
        "archive",  # §13.3 materializes trees with `git archive`, never checkout
        "cat-file",
        "clone",
        "fetch",
        "for-each-ref",
        "grep",
        "log",
        "ls-tree",
        "rev-list",
        "rev-parse",
        "show",
        "tag",
    }
)

#: Subcommands only the test-suite may run (``allow_test_only=True``).
TEST_ONLY_SUBCOMMANDS: frozenset[str] = frozenset({"apply", "worktree"})

#: Config overrides applied to every invocation. Command-line ``-c`` takes precedence
#: over repository, global and system config.
HARDENING_CONFIG: tuple[str, ...] = (
    "core.fsmonitor=false",
    "core.hooksPath=/dev/null",
    "core.pager=cat",
    "core.sshCommand=false",
    "credential.helper=",
    "protocol.file.allow=never",
    "submodule.recurse=false",
)

#: Extra flags inserted right after the subcommand, for subcommands that can run
#: external diff drivers or textconv filters configured by the repository.
_SUBCOMMAND_GUARDS: Mapping[str, tuple[str, ...]] = {
    "log": ("--no-ext-diff", "--no-textconv"),
    "show": ("--no-ext-diff", "--no-textconv"),
}

DEFAULT_TIMEOUT_S = 30.0


@dataclass(frozen=True, slots=True)
class GitResult:
    """Outcome of one git invocation."""

    argv: tuple[str, ...]
    returncode: int
    stdout: bytes
    stderr: bytes
    duration_ms: int


def git_executable() -> str | None:
    """Return the path of the git executable on ``PATH``, or ``None``."""
    return shutil.which("git")


def hardened_env(*, use_user_config: bool = False) -> dict[str, str]:
    """Build the environment for a git child process.

    Inherited ``GIT_*`` variables are dropped (they could redirect the repository, the
    pager, ssh or diff drivers). System config is always ignored; global config is
    ignored unless ``use_user_config`` is set (``--git-use-user-config``).
    """
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("GIT_")}
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_OPTIONAL_LOCKS"] = "0"
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    if not use_user_config:
        env["GIT_CONFIG_GLOBAL"] = os.devnull
    return env


def build_argv(
    args: Sequence[str],
    *,
    git_dir: Path | None = None,
    allow_test_only: bool = False,
) -> list[str]:
    """Return the full, hardened argv for ``git <args>`` without running it."""
    if not args:
        raise ForbiddenCommandError("empty git command")
    subcommand, *rest = args
    allowed = ALLOWED_SUBCOMMANDS | (TEST_ONLY_SUBCOMMANDS if allow_test_only else frozenset())
    if subcommand not in allowed:
        raise ForbiddenCommandError(f"git subcommand not allowed: {subcommand!r}")

    exe = git_executable()
    if exe is None:
        raise ExternalToolError("git was not found on PATH")

    argv = [exe, "--no-pager"]
    for setting in HARDENING_CONFIG:
        argv += ["-c", setting]
    if git_dir is not None:
        resolved = str(git_dir.resolve())
        argv += ["-c", f"safe.directory={resolved}", f"--git-dir={resolved}"]
    argv.append(subcommand)
    argv += _SUBCOMMAND_GUARDS.get(subcommand, ())
    argv += rest
    return argv


def run_git(
    args: Sequence[str],
    *,
    git_dir: Path | None = None,
    timeout: float = DEFAULT_TIMEOUT_S,
    stdin: bytes | None = None,
    use_user_config: bool = False,
    allow_test_only: bool = False,
) -> GitResult:
    """Run ``git <args>`` with every hardening measure applied.

    Raises :class:`ForbiddenCommandError` for subcommands outside the allowlist and
    :class:`ExternalToolError` when git is missing or times out. A non-zero exit status is
    *not* an exception; callers inspect :attr:`GitResult.returncode`.
    """
    argv = build_argv(args, git_dir=git_dir, allow_test_only=allow_test_only)
    started = time.monotonic()
    try:
        proc = subprocess.run(
            argv,
            input=stdin,
            capture_output=True,
            timeout=timeout,
            env=hardened_env(use_user_config=use_user_config),
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ExternalToolError(f"git {args[0]} timed out after {timeout:g}s") from exc
    return GitResult(
        argv=tuple(argv),
        returncode=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
        duration_ms=int((time.monotonic() - started) * 1000),
    )


def git_version() -> str | None:
    """Return git's version string (e.g. ``"2.55.0"``), or ``None`` if git is unavailable."""
    exe = git_executable()
    if exe is None:
        return None
    try:
        proc = subprocess.run(
            [exe, "--version"],
            capture_output=True,
            timeout=DEFAULT_TIMEOUT_S,
            env=hardened_env(),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    text = proc.stdout.decode("utf-8", "replace").strip()
    prefix = "git version "
    return text[len(prefix) :] if text.startswith(prefix) else text
