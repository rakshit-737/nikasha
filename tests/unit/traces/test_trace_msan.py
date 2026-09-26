# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""MSAN parser: API-contract tests and value tests on the real fixtures (ADR 0009).

No hand-written MSAN traces are used (CLAUDE.md: trace fixtures are real output only). The
fixture tests read `tests/fixtures/traces/msan/`, which only
`scripts/capture_sanitizer_fixtures.py` writes.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from nikasha.extract.traces import PARSERS
from nikasha.extract.traces.msan import MsanParser
from nikasha.repro import sandbox

FIXTURES = Path(__file__).parents[2] / "fixtures" / "traces" / "msan"
PARSER = MsanParser()
HEADER = "==1==WARNING: MemorySanitizer: use-of-uninitialized-value"


def test_registered() -> None:
    assert isinstance(PARSERS["msan"], type(PARSER))  # ADR 0009: real fixtures committed
    assert PARSER.format == "msan"


@pytest.mark.parametrize("text", ["", "\n", "hello world", "#0 0x1 in main /a.c:1:2", "=" * 80])
def test_no_trace_without_header(text: str) -> None:
    assert PARSER.parse(text) == []


def test_header_alone_is_one_trace_without_frames() -> None:
    traces = PARSER.parse("noise\n" + HEADER + "\n")
    assert len(traces) == 1
    trace = traces[0]
    assert trace.data.format == "msan"
    assert trace.data.frames == ()
    assert ("noise\n" + HEADER + "\n")[: trace.end] == "noise\n" + HEADER


def test_output_is_deterministic() -> None:
    text = ("x\n" + HEADER + "\n#0 0x1 in f /a.c:1:2\n") * 3
    assert PARSER.parse(text) == PARSER.parse(text)


@given(st.text(max_size=400))
@settings(max_examples=200, deadline=None)
def test_never_raises_on_arbitrary_text(text: str) -> None:
    PARSER.parse(text)
    PARSER.parse(HEADER + "\n" + text)


@pytest.mark.parametrize(
    "seed",
    ["#0 0x1 in ", "    #0 ", HEADER + "\n", "(a+0x1) ", ":1:2 ", "SUMMARY: ", "a" * 7 + ":"],
)
def test_linear_time_on_hostile_input(seed: str) -> None:
    text = HEADER + "\n" + seed * (200_000 // len(seed))
    started = time.perf_counter()
    PARSER.parse(text)
    assert time.perf_counter() - started < 5.0


def _fixtures() -> list[Path]:
    return sorted(FIXTURES.glob("*.txt")) if FIXTURES.is_dir() else []


def test_real_fixtures_parse() -> None:
    fixtures = _fixtures()
    assert fixtures, "real msan fixtures are committed (ADR 0009)"
    assert len(fixtures) >= 3  # SPEC §9.5
    for path in fixtures:
        traces = PARSER.parse(path.read_text(encoding="utf-8"))
        assert traces, path.name
        data = traces[0].data
        assert data.format == "msan"
        assert data.frames, path.name
        assert any(not f.is_runtime and f.path and f.line for f in data.frames), path.name
        assert data.summary, path.name


@pytest.mark.sandbox
@pytest.mark.network
def test_capture_image_has_msan_runtime() -> None:
    """Whether the capture image can link and run an MSan program (unknown until run).

    Marked ``network``: building the Fedora capture image downloads packages, so the
    ``sandbox and not network`` CI job does not run it (ADR 0009).
    """
    engine = sandbox.select_engine()
    image = "localhost/nikasha-capture:latest"
    if not sandbox.image_exists(engine, image):
        containerfile = Path(__file__).parents[3] / "docker" / "capture" / "Containerfile"
        sandbox.build_image(engine, containerfile, containerfile.parent, image, online=True)
    script = (
        "printf 'int main(){int x;return x?1:0;}' >/work/m.c && "
        "clang -fsanitize=memory -g -o /work/m /work/m.c && /work/m"
    )
    result = sandbox.run_container(
        engine, sandbox.ContainerSpec(image=image, cmd=("bash", "-c", script)), timeout_s=120.0
    )
    assert b"MemorySanitizer: use-of-uninitialized-value" in result.stderr, result.stderr[-2000:]


# --- values from the real fixtures (tests/fixtures/traces/msan/README.md) -----------------

MSAN_CASES = [
    # name, pid, top frame (function, file, line, col), frame count
    ("01-jq-check-literal.txt", 4072, ("check_literal", "/work/tree/src/jv_parse.c", 517, 24), 7),
    ("02-zlib-gzclose-next-in.txt", 118, ("deflate", "/work/tree/deflate.c", 679, 34), 9),
    ("03-libjpeg-turbo-ppm-rescale.txt", 332,
     ("rgb_ycc_convert_internal", "/work/tree/jccolext.c", 61, 33), 9),
]  # fmt: skip


@pytest.mark.parametrize(("name", "pid", "top", "count"), MSAN_CASES)
def test_fixture_values(name: str, pid: int, top: tuple[str, str, int, int], count: int) -> None:
    text = (FIXTURES / name).read_text(encoding="utf-8")
    traces = PARSER.parse(text)
    assert len(traces) == 1
    trace = traces[0]
    data = trace.data
    assert trace.start == 0
    assert text[trace.start : trace.end].endswith("\nExiting")
    assert trace.end == len(text.rstrip("\n"))
    assert (data.bug_type, data.message, data.pid, data.pids_seen) == (
        "use-of-uninitialized-value",
        "use-of-uninitialized-value",
        pid,
        (pid,),
    )
    assert len(data.frames) == count
    frame = data.frames[0]
    assert (frame.function, frame.path, frame.line, frame.col) == top
    assert not frame.is_runtime
    assert (data.summary_path, data.summary_line, data.summary_function) == (
        top[1],
        top[2],
        top[0],
    )
    assert data.summary is not None
    assert data.summary.startswith("SUMMARY: MemorySanitizer: use-of-uninitialized-value /work/")
    # built without -fsanitize-memory-track-origins: no origin stacks
    assert data.alloc_frames == ()
    assert data.other_stacks == ()
    assert [f.function for f in data.frames[-3:]] == [
        "__libc_start_call_main",
        "__libc_start_main",
        "_start",
    ]
    assert all(f.is_runtime for f in data.frames[-3:])
