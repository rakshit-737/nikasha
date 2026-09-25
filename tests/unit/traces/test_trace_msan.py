# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""MSAN parser: API-contract tests here, real-fixture tests under `sandbox` (ADR 0009).

No hand-written MSAN traces are used (CLAUDE.md: trace fixtures are real output only). The
fixture tests read `tests/fixtures/traces/msan/`, which only
`scripts/capture_sanitizer_fixtures.py` writes, and skip until that capture has run.
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


def test_not_registered_by_default():
    assert "msan" not in PARSERS  # ADR 0009: registered only once real fixtures pass
    assert PARSER.format == "msan"


@pytest.mark.parametrize("text", ["", "\n", "hello world", "#0 0x1 in main /a.c:1:2", "=" * 80])
def test_no_trace_without_header(text):
    assert PARSER.parse(text) == []


def test_header_alone_is_one_trace_without_frames():
    traces = PARSER.parse("noise\n" + HEADER + "\n")
    assert len(traces) == 1
    trace = traces[0]
    assert trace.data.format == "msan"
    assert trace.data.frames == ()
    assert ("noise\n" + HEADER + "\n")[: trace.end] == "noise\n" + HEADER


def test_output_is_deterministic():
    text = ("x\n" + HEADER + "\n#0 0x1 in f /a.c:1:2\n") * 3
    assert PARSER.parse(text) == PARSER.parse(text)


@given(st.text(max_size=400))
@settings(max_examples=200, deadline=None)
def test_never_raises_on_arbitrary_text(text):
    PARSER.parse(text)
    PARSER.parse(HEADER + "\n" + text)


@pytest.mark.parametrize(
    "seed",
    ["#0 0x1 in ", "    #0 ", HEADER + "\n", "(a+0x1) ", ":1:2 ", "SUMMARY: ", "a" * 7 + ":"],
)
def test_linear_time_on_hostile_input(seed):
    text = HEADER + "\n" + seed * (200_000 // len(seed))
    started = time.perf_counter()
    PARSER.parse(text)
    assert time.perf_counter() - started < 5.0


def _fixtures() -> list[Path]:
    return sorted(FIXTURES.glob("*.txt")) if FIXTURES.is_dir() else []


@pytest.mark.sandbox
def test_real_fixtures_parse():
    fixtures = _fixtures()
    if not fixtures:
        pytest.skip("no real msan fixtures yet: run scripts/capture_sanitizer_fixtures.py")
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
def test_capture_image_has_msan_runtime():
    """Whether the capture image can link and run an MSan program (unknown until run)."""
    engine = sandbox.select_engine()
    image = "localhost/nikasha-capture:latest"
    if not sandbox.image_exists(engine, image):
        pytest.fail(f"{image} is not built; build docker/capture/Containerfile first")
    script = (
        "printf 'int main(){int x;return x?1:0;}' >/work/m.c && "
        "clang -fsanitize=memory -g -o /work/m /work/m.c && /work/m"
    )
    result = sandbox.run_container(
        engine, sandbox.ContainerSpec(image=image, cmd=("bash", "-c", script)), timeout_s=120.0
    )
    assert b"MemorySanitizer: use-of-uninitialized-value" in result.stderr, result.stderr[-2000:]
