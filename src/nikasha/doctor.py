# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Environment self-check behind ``nikasha doctor``. Makes no network calls."""

from __future__ import annotations

import os
import platform
import stat
import sys
import tempfile
from dataclasses import asdict, dataclass
from typing import Literal

from nikasha import config
from nikasha.code import gitio
from nikasha.repro import sandbox

Status = Literal["ok", "warn", "fail"]

MIN_PYTHON = (3, 11)


@dataclass(frozen=True, slots=True)
class DoctorCheck:
    """One line of the doctor report."""

    name: str
    status: Status
    detail: str
    required: bool


@dataclass(frozen=True, slots=True)
class DoctorReport:
    """All checks, plus whether every required check passed."""

    checks: tuple[DoctorCheck, ...]

    @property
    def ok(self) -> bool:
        return all(c.status != "fail" for c in self.checks if c.required)

    def to_dict(self) -> dict[str, object]:
        return {"ok": self.ok, "checks": [asdict(c) for c in self.checks]}


def _check_python() -> DoctorCheck:
    version = platform.python_version()
    good = sys.version_info[:2] >= MIN_PYTHON
    return DoctorCheck(
        name="python",
        status="ok" if good else "fail",
        detail=f"{platform.python_implementation()} {version}"
        + ("" if good else f" (need >= {MIN_PYTHON[0]}.{MIN_PYTHON[1]})"),
        required=True,
    )


def _check_git() -> DoctorCheck:
    version = gitio.git_version()
    if version is None:
        return DoctorCheck("git", "fail", "git not found on PATH (required)", required=True)
    return DoctorCheck("git", "ok", f"git {version}", required=True)


def _check_cache() -> DoctorCheck:
    path = config.cache_dir()
    try:
        config.ensure_private_dir(path)
        with tempfile.NamedTemporaryFile(dir=path, prefix=".doctor-", delete=True):
            pass
    except OSError as exc:
        return DoctorCheck("cache", "fail", f"{path} is not writable: {exc}", required=True)
    if os.name == "posix":
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o077:
            return DoctorCheck(
                "cache",
                "warn",
                f"{path} is writable but has mode {mode:o}; "
                "the filesystem may not support owner-only permissions",
                required=True,
            )
        return DoctorCheck("cache", "ok", f"{path} (mode {mode:o})", required=True)
    return DoctorCheck("cache", "ok", str(path), required=True)


def _check_engines() -> list[DoctorCheck]:
    engines = sandbox.detect_engines()
    preferred = sandbox.preferred_engine(engines)
    checks: list[DoctorCheck] = []
    for engine in engines:
        if engine.available:
            parts = [f"{engine.name} {engine.version or '?'}"]
            if engine.rootless is not None:
                parts.append("rootless" if engine.rootless else "rootful")
            if engine.cgroup_version:
                parts.append(f"cgroup {engine.cgroup_version}")
            if preferred is engine:
                parts.append("preferred for --repro")
            checks.append(DoctorCheck(engine.name, "ok", ", ".join(parts), required=False))
        else:
            checks.append(
                DoctorCheck(
                    engine.name, "warn", f"unavailable: {engine.error or 'unknown'}", required=False
                )
            )
    if preferred is None:
        checks.append(
            DoctorCheck(
                "sandbox",
                "warn",
                "no container engine available; static checks work, --repro will refuse to run",
                required=False,
            )
        )
    return checks


def run_doctor() -> DoctorReport:
    """Run every check. Only Python, git and the cache are required."""
    checks = [
        _check_python(),
        DoctorCheck("platform", "ok", platform.platform(terse=True), required=False),
        _check_git(),
        _check_cache(),
        *_check_engines(),
        DoctorCheck(
            "network",
            "ok",
            "offline by default; network is used only with --online (none used here)",
            required=False,
        ),
    ]
    return DoctorReport(checks=tuple(checks))
