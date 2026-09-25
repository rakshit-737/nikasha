# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Engine selection, refusal without an engine, and doctor-grade facts (SPEC §13.1)."""

from __future__ import annotations

import pytest

from nikasha.errors import NikashaError
from nikasha.repro import sandbox
from nikasha.repro.sandbox import EngineInfo, NoEngineError

PODMAN_ROOTLESS = EngineInfo("podman", True, "5.4.0", True, "v2")
PODMAN_ROOTFUL = EngineInfo("podman", True, "5.4.0", False, "v2")
DOCKER = EngineInfo("docker", True, "27.3.1", False, "v2")
NO_PODMAN = EngineInfo("podman", False, error="not found on PATH")
NO_DOCKER = EngineInfo("docker", False, error="not found on PATH")


def test_auto_prefers_rootless_podman():
    assert sandbox.select_engine("auto", [DOCKER, PODMAN_ROOTLESS]) is PODMAN_ROOTLESS


def test_auto_prefers_docker_over_rootful_podman():
    assert sandbox.select_engine("auto", [PODMAN_ROOTFUL, DOCKER]) is DOCKER


def test_auto_falls_back_to_the_only_engine():
    assert sandbox.select_engine("auto", [NO_PODMAN, DOCKER]) is DOCKER
    assert sandbox.select_engine("auto", [PODMAN_ROOTFUL, NO_DOCKER]) is PODMAN_ROOTFUL


def test_override_names_the_engine():
    assert sandbox.select_engine("docker", [PODMAN_ROOTLESS, DOCKER]) is DOCKER
    assert sandbox.select_engine("podman", [PODMAN_ROOTLESS, DOCKER]) is PODMAN_ROOTLESS


def test_override_never_falls_back():
    with pytest.raises(NoEngineError, match="--sandbox docker"):
        sandbox.select_engine("docker", [PODMAN_ROOTLESS, NO_DOCKER])


def test_refuses_without_any_engine():
    with pytest.raises(NoEngineError, match="never run on the host"):
        sandbox.select_engine("auto", [NO_PODMAN, NO_DOCKER])


def test_rejects_unknown_choice():
    with pytest.raises(NikashaError, match="--sandbox"):
        sandbox.select_engine("host", [DOCKER])


def test_real_detection_with_an_empty_path_refuses(tmp_path, monkeypatch):
    """No mocks of the probe: an empty PATH really has no engine, so selection refuses."""
    monkeypatch.setenv("PATH", str(tmp_path))
    with pytest.raises(NoEngineError):
        sandbox.select_engine("auto")
    with pytest.raises(NoEngineError):
        sandbox.select_engine("podman")


def test_engine_executable_refuses_unavailable_engine():
    with pytest.raises(NoEngineError):
        sandbox.engine_executable(NO_DOCKER)


def test_facts_use_the_engine_report_first():
    info = EngineInfo("docker", True, "27", False, "v1", memory_limit=False, pids_limit=True)
    facts = sandbox.engine_facts(info)
    assert facts.memory_limit_enforced is False
    assert facts.pids_limit_enforced is True
    assert facts.as_dict()["version"] == "27"


def test_facts_rootless_cgroup_v1_is_not_enforced():
    facts = sandbox.engine_facts(EngineInfo("podman", True, "4", True, "v1"))
    assert facts.memory_limit_enforced is False
    assert facts.pids_limit_enforced is False


def test_facts_rootful_cgroup_v2_is_enforced_and_unknown_stays_unknown():
    assert sandbox.engine_facts(DOCKER).memory_limit_enforced is True
    assert sandbox.engine_facts(PODMAN_ROOTLESS).memory_limit_enforced is None


def test_parsers_read_limit_support():
    podman = sandbox._parse_podman(
        {
            "version": {"Version": "5.4.0"},
            "host": {
                "cgroupVersion": "v2",
                "cgroupControllers": ["cpu", "memory", "pids"],
                "security": {"rootless": True},
            },
        }
    )
    assert (podman.memory_limit, podman.pids_limit) == (True, True)
    partial = sandbox._parse_podman({"host": {"cgroupControllers": ["cpu"]}})
    assert (partial.memory_limit, partial.pids_limit) == (False, False)
    docker = sandbox._parse_docker({"ServerVersion": "27", "MemoryLimit": True, "PidsLimit": False})
    assert (docker.memory_limit, docker.pids_limit) == (True, False)
    assert sandbox._parse_docker({"ServerVersion": "27"}).memory_limit is None
