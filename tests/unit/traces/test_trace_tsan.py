# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""TSAN parser: API-contract tests and value tests on the real fixtures (ADR 0009).

No hand-written TSAN traces are used (CLAUDE.md: trace fixtures are real output only). The
fixture tests read `tests/fixtures/traces/tsan/`, which only
`scripts/capture_sanitizer_fixtures.py` writes.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from nikasha.extract import extract_claims
from nikasha.extract.traces import PARSERS
from nikasha.extract.traces.tsan import TsanParser, parse_tsan_frame
from nikasha.ingest import ingest_string
from nikasha.model.claims import TraceClaim

FIXTURES = Path(__file__).parents[2] / "fixtures" / "traces" / "tsan"
PARSER = TsanParser()
HEADER = "WARNING: ThreadSanitizer: data race (pid=1)"


def test_registered() -> None:
    assert isinstance(PARSERS["tsan"], type(PARSER))  # ADR 0009: real fixtures committed
    assert PARSER.format == "tsan"


@pytest.mark.parametrize("text", ["", "\n", "hello world", "#0 0x1 in main /a.c:1:2", "=" * 80])
def test_no_trace_without_header(text: str) -> None:
    assert PARSER.parse(text) == []


def test_header_alone_is_one_trace_without_frames() -> None:
    traces = PARSER.parse("noise\n" + HEADER + "\n")
    assert len(traces) == 1
    trace = traces[0]
    assert trace.data.format == "tsan"
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
    assert fixtures, "real tsan fixtures are committed (ADR 0009)"
    assert len(fixtures) >= 3  # SPEC §9.5
    for path in fixtures:
        traces = PARSER.parse(path.read_text(encoding="utf-8"))
        assert traces, path.name
        data = traces[0].data
        assert data.format == "tsan"
        assert data.frames, path.name
        # libvpx's library objects carry no line info, so look at every stack of the report
        stacks = [data.frames, data.alloc_frames, *(s.frames for s in data.other_stacks)]
        assert any(not f.is_runtime and f.path and f.line for s in stacks for f in s), path.name
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
def test_frame_fields_with_module_suffix(
    line: str, expected: tuple[str | None, str | None, int | None, int | None, str | None]
) -> None:
    frame = parse_tsan_frame(line)
    assert frame is not None
    assert (frame.function, frame.path, frame.line, frame.col, frame.module) == expected


@pytest.mark.parametrize("line", ["    #0 f /a.c:1 (m+zz)", "    #0 f /a.c:1 (+0x1)", "x"])
def test_frame_rejects_malformed_module_suffix(line: str) -> None:
    frame = parse_tsan_frame(line)
    assert frame is None or frame.module is None


# --- values from the real fixtures (tests/fixtures/traces/tsan/README.md) -----------------


def _load(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_xz_data_race_values() -> None:
    text = _load("03-xz-mt-decoder-progress.txt")
    traces = PARSER.parse(text)
    assert len(traces) == 1
    trace = traces[0]
    data = trace.data
    assert text[trace.start : trace.end].startswith("=" * 18 + "\nWARNING: ThreadSanitizer")
    assert text[trace.start : trace.end].endswith("in stream_decode_mt\n" + "=" * 18)
    assert (data.bug_type, data.pid, data.pids_seen, data.thread) == (
        "data-race",
        937,
        (937,),
        "T0",
    )
    assert data.access is not None
    assert (data.access.kind, data.access.size, data.access_address) == ("WRITE", 8, 0x726C000009C8)
    top = data.frames[0]
    assert (top.function, top.path, top.line, top.col, top.module) == (
        "stream_decode_mt",
        "/work/tree/src/liblzma/common/stream_decoder_mt.c",
        1071,
        22,
        "xz",
    )
    assert [f.function for f in data.frames] == [
        "stream_decode_mt",
        "lzma_code",
        "coder_normal",
        "coder_run",
        "main",
    ]
    assert data.alloc_frames[0].function == "malloc"
    assert data.alloc_frames[0].is_runtime
    assert (data.alloc_frames[1].function, data.alloc_frames[1].line) == ("lzma_alloc", 50)
    labels = [s.label for s in data.other_stacks]
    assert labels[0].startswith("Previous write of size 8")
    assert data.other_stacks[0].frames[0].function == "worker_decoder"
    assert data.other_stacks[0].frames[0].line == 460
    assert labels[1] == "Mutex M0 (0x726c00000928) created"
    assert labels[2] == "Thread T1 (tid=952, running) created by main thread"
    assert data.other_stacks[2].frames[0].function == "pthread_create"
    assert data.other_stacks[2].frames[0].is_runtime
    assert (data.summary_path, data.summary_line, data.summary_function) == (
        "/work/tree/src/liblzma/common/stream_decoder_mt.c",
        1071,
        "stream_decode_mt",
    )


def test_libvpx_every_report_is_split_and_null_paths_stay_empty() -> None:
    text = _load("01-libvpx-vp8-psnr-loopfilter.txt")
    traces = PARSER.parse(text)
    assert len(traces) == text.count("WARNING: ThreadSanitizer: ") == 8
    for trace in traces:
        body = text[trace.start : trace.end]
        assert body.count("WARNING: ThreadSanitizer") == 1
        assert "Stream 0 PSNR" not in body and "reported 8 warnings" not in body
    data = traces[0].data
    assert (data.bug_type, data.thread) == ("data-race", "T4")
    assert data.access is not None
    assert (data.access.kind, data.access.size) == ("WRITE", 1)
    top = data.frames[0]
    # ``mbloop_filter_horizontal_edge_c <null> (vpxenc+0x4a02a8)``: no file, module kept
    assert (top.function, top.path, top.line, top.module) == (
        "mbloop_filter_horizontal_edge_c",
        None,
        None,
        "vpxenc",
    )
    assert data.frames[-1].function == "thread_loopfilter"
    assert data.summary_function == "mbloop_filter_horizontal_edge_c"
    assert data.summary_path is None  # the SUMMARY names the module, not a source line
    previous = data.other_stacks[0]
    assert previous.label.startswith("Previous read of size 1")
    # ``encode_frame /work/tree/vpxenc.c:1450 (vpxenc+0x…)``: line without a column
    frame = previous.frames[5]
    assert (frame.function, frame.path, frame.line, frame.col) == (
        "encode_frame",
        "/work/tree/vpxenc.c",
        1450,
        None,
    )
    assert data.alloc_frames[-1].function == "main"
    assert data.alloc_frames[-1].line == 1857


def test_pigz_lock_order_inversion_takes_the_first_mutex_stack() -> None:
    text = _load("02-pigz-lock-order.txt")
    traces = PARSER.parse(text)
    assert len(traces) == text.count("WARNING: ThreadSanitizer: ") == 20
    for trace in traces:
        data = trace.data
        assert data.bug_type == "lock-order-inversion"
        assert data.access is None
        assert data.frames, "the first 'Mutex ... acquired here' stack is primary"
        assert data.frames[0].function == "pthread_mutex_lock"
        assert data.frames[0].is_runtime  # intercepted inside the binary: the name tells
        assert data.frames[1].function == "possess"
        assert (data.frames[1].path, data.frames[1].line) == ("/work/tree/yarn.c", 115)
        assert data.other_stacks[0].label.startswith("Mutex M")
        assert data.summary_function == "pthread_mutex_lock"
    first = traces[0].data
    assert first.thread == "T1"
    assert [f.function for f in first.frames] == [
        "pthread_mutex_lock",
        "possess",
        "drop_space",
        "write_thread",
        "ignition",
    ]
    assert traces[1].data.other_stacks[0].label.endswith("in main thread")


def test_real_report_is_found_in_markdown_by_the_pipeline() -> None:
    trace_text = _load("03-xz-mt-decoder-progress.txt")
    md = f"# Race in the xz MT decoder\n\n```\n{trace_text}```\n"
    claims = extract_claims(ingest_string(md, input_format="markdown")).claims
    traces = [c for c in claims if isinstance(c, TraceClaim)]
    assert len(traces) == 1
    assert traces[0].extractor.endswith("traces:tsan")
    assert traces[0].frames[0].function == "stream_decode_mt"
