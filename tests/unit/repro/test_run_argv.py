# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The hardened ``run`` argv per engine (SPEC §13.4, research §6) and its redaction."""

from __future__ import annotations

import io
import itertools
from pathlib import Path

import pytest

from nikasha.repro import sandbox
from nikasha.repro.sandbox import ContainerSpec, Limits, Mount, SandboxError

HOST = Path(__file__).resolve().parent  # any absolute, colon-free-enough directory
POC = HOST / "poc"
BUILD = HOST / "build"


def _spec(**kw: object) -> ContainerSpec:
    base: dict[str, object] = {
        "image": "nikasha/recipe-c:1",
        "cmd": ("/build/hdrcat", "/poc/x"),
        "mounts": (Mount(POC, "/poc"), Mount(BUILD, "/build")),
        "env": {"ASAN_OPTIONS": "abort_on_error=1"},
    }
    base.update(kw)
    return ContainerSpec(**base)  # type: ignore[arg-type]


def _pairs(argv: list[str]) -> list[tuple[str, str]]:
    return list(itertools.pairwise(argv))


@pytest.mark.parametrize("engine", ["podman", "docker"])
def test_every_hardened_flag_is_present(engine):
    argv = sandbox.run_argv(engine, _spec(), name="nikasha-abc")
    pairs = _pairs(argv)
    for flag in ("--rm", "--init", "--read-only"):
        assert flag in argv
    for pair in [
        ("--network", "none"),
        ("--tmpfs", "/tmp:rw,size=64m,mode=1777"),
        ("--tmpfs", "/work:rw,exec,size=256m,mode=1777"),
        ("--cap-drop", "ALL"),
        ("--pids-limit", "256"),
        ("--memory", "2g"),
        ("--cpus", "2"),
        ("--user", "65534:65534"),
        ("--ulimit", "core=0"),
        ("--pull", "never"),
        ("--env", "ASAN_OPTIONS=abort_on_error=1"),
    ]:
        assert pair in pairs, pair
    assert argv[-3:] == ["nikasha/recipe-c:1", "/build/hdrcat", "/poc/x"]


def test_podman_specifics():
    argv = sandbox.run_argv("podman", _spec(), name="n1")
    assert "--read-only-tmpfs=false" in argv
    assert ("--security-opt", "no-new-privileges") in _pairs(argv)


def test_docker_specifics():
    argv = sandbox.run_argv("docker", _spec(), name="n1")
    assert "--read-only-tmpfs=false" not in argv
    assert ("--security-opt", "no-new-privileges=true") in _pairs(argv)


def test_runtime_is_global_for_podman_and_a_run_flag_for_docker():
    podman = sandbox.run_argv("podman", _spec(), name="n1", runtime="runsc")
    assert podman[1:4] == ["--runtime", "runsc", "run"]
    docker = sandbox.run_argv("docker", _spec(), name="n1", runtime="runsc")
    assert docker[1] == "run"
    assert ("--runtime", "runsc") in _pairs(docker)
    assert docker.index("--runtime") > docker.index("run")


def test_mounts_are_read_only_unless_asked():
    argv = sandbox.run_argv("docker", _spec(), name="n1")
    assert ("-v", f"{POC}:/poc:ro") in _pairs(argv)
    rw = sandbox.run_argv("docker", _spec(mounts=(Mount(POC, "/out", read_only=False),)), name="n")
    assert ("-v", f"{POC}:/out:rw") in _pairs(rw)


def test_limits_come_from_the_spec():
    argv = sandbox.run_argv(
        "docker", _spec(limits=Limits(cpus=1.5, memory="512m", pids=64)), name="n1"
    )
    pairs = _pairs(argv)
    assert ("--cpus", "1.5") in pairs
    assert ("--memory", "512m") in pairs
    assert ("--pids-limit", "64") in pairs


@pytest.mark.parametrize(
    "bad",
    [
        {"mounts": (Mount(POC, "/tmp"),)},
        {"mounts": (Mount(POC, "/"),)},
        {"mounts": (Mount(POC, "/work"),)},
        {"mounts": (Mount(POC, "/a/../etc"),)},
        {"mounts": (Mount(POC, "/poc:rw"),)},
        {"mounts": (Mount(Path("relative"), "/poc"),)},
        {"mounts": (Mount(HOST / "a,b", "/poc"),)},
        {"env": {"BAD NAME": "x"}},
        {"env": {"1X": "x"}},
        {"image": "--privileged"},
        {"cmd": ()},
        {"work_size": "1g;rm"},
        {"limits": Limits(memory="lots")},
        {"limits": Limits(pids=0)},
    ],
)
def test_unsafe_specs_are_refused(bad):
    with pytest.raises(SandboxError):
        sandbox.run_argv("docker", _spec(**bad), name="n1")


@pytest.mark.parametrize("name", ["", "-x", "a b", "a/b", "x" * 200])
def test_bad_names_and_runtimes_are_refused(name):
    with pytest.raises(SandboxError):
        sandbox.run_argv("docker", _spec(), name=name)
    with pytest.raises(SandboxError):
        sandbox.run_argv("docker", _spec(), name="ok", runtime=name or "--x")


def test_recorded_argv_has_no_host_paths_or_random_name():
    exe = str(HOST / "bin" / "podman")
    argv = sandbox.run_argv("podman", _spec(), name="nikasha-0123abcd", exe=exe)
    recorded = sandbox.redact_container_argv(argv, [POC, BUILD])
    assert recorded[0] == "podman"
    assert "nikasha-0123abcd" not in recorded
    assert "<name>" in recorded
    assert "<path>:/poc:ro" in recorded
    assert "<path>:/build:ro" in recorded
    assert not any(str(HOST) in arg for arg in recorded)
    assert "/build/hdrcat" in recorded  # container paths are kept


def test_recorded_argv_is_identical_across_machines_and_names():
    a = sandbox.run_argv("docker", _spec(), name="nikasha-1", exe="/usr/bin/docker")
    other = _spec(mounts=(Mount(HOST / "e" / "p", "/poc"), Mount(HOST / "x" / "b", "/build")))
    b = sandbox.run_argv("docker", other, name="nikasha-2", exe="/opt/docker")
    assert sandbox.redact_container_argv(a) == sandbox.redact_container_argv(b)


def test_windows_executable_and_build_paths_are_redacted():
    argv = ["C:\\Program Files\\Docker\\docker.exe", "build", "-f", "C:\\r\\x.Dockerfile"]
    assert sandbox.redact_container_argv(argv, [Path("C:\\r\\x.Dockerfile")]) == (
        "docker",
        "build",
        "-f",
        "<path>",
    )


def test_container_result_record_hashes_and_marks_truncation():
    result = sandbox.ContainerResult(
        argv=("docker", "run"),
        recorded_argv=("docker", "run"),
        exit_code=1,
        stdout=b"",
        stderr=b"boom",
        timed_out=False,
        truncated=True,
        duration_ms=5,
    )
    record = result.record()
    assert record.truncated is True
    assert record.duration_ms is None  # durations never enter evidence (P2)
    assert record.stdout_sha256 == sandbox.hashlib.sha256(b"").hexdigest()


def test_capped_reader_keeps_the_first_bytes_and_drains_the_rest():
    stream = io.BytesIO(b"a" * 200_000)
    reader = sandbox.CappedReader(stream, 1024)
    reader.run()
    assert bytes(reader.data) == b"a" * 1024
    assert reader.truncated is True
    assert stream.read() == b""  # the pipe was fully drained, so the child never blocks


def test_capped_reader_exact_fit_is_not_truncated():
    reader = sandbox.CappedReader(io.BytesIO(b"x" * 10), 10)
    reader.run()
    assert reader.truncated is False


def test_image_tags_are_checked():
    with pytest.raises(SandboxError):
        sandbox.build_image_argv("docker", POC, HOST, "--rm")
    argv = sandbox.build_image_argv("podman", POC, HOST, "nikasha/recipe-c:1")
    assert argv[:2] == ["podman", "build"]


def test_image_build_needs_online():
    with pytest.raises(sandbox.NikashaError, match="--online"):
        sandbox.build_image(
            sandbox.EngineInfo("docker", True), POC, HOST, "nikasha/recipe-c:1", online=False
        )
