# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""TSAN parser: API-contract tests here, real-fixture tests skip until captured (ADR 0009).

No hand-written TSAN traces are used (CLAUDE.md: trace fixtures are real output only). The
fixture tests read `tests/fixtures/traces/tsan/`, which only
`scripts/capture_sanitizer_fixtures.py` writes, and skip until that capture has run.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from nikasha.extract.traces import PARSERS
from nikasha.extract.traces.tsan import TsanParser, parse_tsan_frame

FIXTURES = Path(__file__).parents[2] / "fixtures" / "traces" / "tsan"
PARSER = TsanParser()
HEADER = "WARNING: ThreadSanitizer: data race (pid=1)"


def test_not_registered_by_default():
    assert "tsan" not in PARSERS  # ADR 0009: registered only once real fixtures pass
    assert PARSER.format == "tsan"


@pytest.mark.parametrize("text", ["", "\n", "hello world", "#0 0x1 in main /a.c:1:2", "=" * 80])
def test_no_trace_without_header(text):
    assert PARSER.parse(text) == []


def test_header_alone_is_one_trace_without_frames():
    traces = PARSER.parse("noise\n" + HEADER + "\n")
    assert len(traces) == 1
    trace = traces[0]
    assert trace.data.format == "tsan"
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


def test_real_fixtures_parse():
    fixtures = _fixtures()
    if not fixtures:
        pytest.skip("no real tsan fixtures yet: run scripts/capture_sanitizer_fixtures.py")
    assert len(fixtures) >= 3  # SPEC §9.5
    for path in fixtures:
        traces = PARSER.parse(path.read_text(encoding="utf-8"))
        assert traces, path.name
        data = traces[0].data
        assert data.format == "tsan"
        assert data.frames, path.name
        assert any(not f.is_runtime and f.path and f.line for f in data.frames), path.name
        assert data.summary, path.name


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("    #0 Thread1 /tmp/r.c:8:10 (a.out+0xd0b7c)", ("Thread1", "/tmp/r.c", 8, 10, "a.out")),
        ("    #1 f /a/b.cc:3 (libstdc++.so.6+0x12) (BuildId: ab)",
         ("f", "/a/b.cc", 3, None, "libstdc++.so.6")),
        ("    #2 <null> <null> (libc.so.6+0x29d8f)", (None, None, None, None, "libc.so.6")),
    ],
)  # fmt: skip
def test_frame_fields_with_module_suffix(line, expected):
    frame = parse_tsan_frame(line)
    assert frame is not None
    assert (frame.function, frame.path, frame.line, frame.col, frame.module) == expected


@pytest.mark.parametrize("line", ["    #0 f /a.c:1 (m+zz)", "    #0 f /a.c:1 (+0x1)", "x"])
def test_frame_rejects_malformed_module_suffix(line):
    frame = parse_tsan_frame(line)
    assert frame is None or frame.module is None
