# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Engine detection. The JSON samples are trimmed from real `info` output captured on
Fedora 44 (podman 5.8.4 rootless, docker 29.7.2 rootful) on 2026-09-23."""

import pytest

from nikasha.repro import sandbox

PODMAN_INFO = {
    "host": {
        "cgroupVersion": "v2",
        "cgroupManager": "systemd",
        "security": {"rootless": True, "seccompEnabled": True},
    },
    "version": {"Version": "5.8.4"},
}

DOCKER_INFO = {
    "ServerVersion": "29.7.2",
    "CgroupVersion": "2",
    "SecurityOptions": ["name=seccomp,profile=builtin", "name=cgroupns"],
    "ServerErrors": None,
}


def test_parse_podman() -> None:
    info = sandbox._parse_podman(PODMAN_INFO)
    assert info == sandbox.EngineInfo(
        name="podman", available=True, version="5.8.4", rootless=True, cgroup_version="v2"
    )


def test_parse_docker_rootful_and_cgroup_normalized() -> None:
    info = sandbox._parse_docker(DOCKER_INFO)
    assert info.available
    assert info.version == "29.7.2"
    assert info.rootless is False
    assert info.cgroup_version == "v2"


def test_parse_docker_rootless() -> None:
    data = {**DOCKER_INFO, "SecurityOptions": ["name=seccomp,profile=builtin", "name=rootless"]}
    assert sandbox._parse_docker(data).rootless is True


def test_parse_docker_daemon_unreachable() -> None:
    data = {"ServerErrors": ["Cannot connect to the Docker daemon"]}
    info = sandbox._parse_docker(data)
    assert not info.available
    assert "Cannot connect" in (info.error or "")


def test_missing_engine_is_reported_not_raised(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sandbox.shutil, "which", lambda _name: None)  # type: ignore[attr-defined]
    engines = sandbox.detect_engines()
    assert [e.name for e in engines] == ["podman", "docker"]
    assert not any(e.available for e in engines)
    assert sandbox.preferred_engine(engines) is None


@pytest.mark.parametrize(
    ("first", "second", "expected"),
    [(True, True, "podman"), (False, True, "docker"), (True, False, "podman")],
)
def test_podman_is_preferred(first: bool, second: bool, expected: str) -> None:
    engines = [
        sandbox.EngineInfo(name="podman", available=first),
        sandbox.EngineInfo(name="docker", available=second),
    ]
    chosen = sandbox.preferred_engine(engines)
    assert chosen is not None
    assert chosen.name == expected
