# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Container-engine access (SPEC §13.1). The only module besides ``code/gitio.py`` that may
spawn processes.

M0 provides engine detection for ``nikasha doctor``. Building images and running
proofs of concept arrive in M5, with the hardened flag set verified per engine.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any, Literal

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
    return EngineInfo(
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
    return EngineInfo(
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
