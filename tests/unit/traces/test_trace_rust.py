# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Rust panic parser: real fixtures (RUST_BACKTRACE=1/full), variants, embedding, robustness."""

from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from nikasha.extract import extract_claims
from nikasha.extract.traces import PARSERS, rust_panic
from nikasha.ingest import ingest_string
from nikasha.model.claims import TraceClaim

FIXTURES = Path(__file__).parents[2] / "fixtures" / "traces" / "rust"
PARSER = PARSERS["rust"]
NOTE_FULL = (
    "note: Some details are omitted, run with `RUST_BACKTRACE=full` for a verbose backtrace."
)


def _load(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def _one(text: str):
    traces = PARSER.parse(text)
    assert len(traces) == 1, traces
    return traces[0]


def _first_app(frames):
    return next(f for f in frames if not f.is_runtime)


FIXTURE_CASES = [
    # name, thread, message, frame count, first app (index, function, path, line, col), last line
    (
        "01-index-oob-backtrace.txt",
        "main",
        "index out of bounds: the len is 3 but the index is 3",
        7,
        (3, "index_oob::pick", "/src/programs/rust/index_oob.rs", 5, 5),
        NOTE_FULL,
    ),
    (
        "02-unwrap-none-backtrace-full.txt",
        "main",
        "called `Option::unwrap()` on a `None` value",
        40,
        (19, "unwrap_none::lookup", "/src/programs/rust/unwrap_none.rs", 7, 21),
        "  39:                0x0 - <unknown>",
    ),
    (
        "03-thread-panic.txt",
        "<unnamed>",
        "job {job} has no owner",
        4,
        (1, "thread_panic::check", "/src/programs/rust/thread_panic.rs", 8, 9),
        NOTE_FULL,
    ),
]


@pytest.mark.parametrize("case", FIXTURE_CASES, ids=[c[0] for c in FIXTURE_CASES])
def test_fixture(case):
    name, thread, message, count, app, last_line = case
    text = _load(name)
    trace = _one(text)
    data = trace.data
    assert trace.start == text.index("thread '")
    assert text[trace.start : trace.end].endswith(last_line)
    assert trace.end == len(text.rstrip("\n"))
    assert data.format == "rust"
    assert (data.bug_type, data.message, data.thread) == ("panic", message, thread)
    assert len(data.frames) == count
    assert [f.index for f in data.frames] == list(range(count))
    first = _first_app(data.frames)
    assert (first.index, first.function, first.path, first.line, first.col) == app
    assert data.frames[0].is_runtime
    assert data.other_stacks == ()


def test_full_backtrace_hashes_stripped_and_runtime_frames() -> None:
    data = _one(_load("02-unwrap-none-backtrace-full.txt")).data
    frames = data.frames
    assert frames[19].raw.startswith(
        "  19:     0x55d7d187c5d5 - unwrap_none[1d7891cca4ec4e71]::lookup"
    )
    assert frames[0].function == "std::backtrace_rs::backtrace::libunwind::trace"
    assert (frames[5].function, frames[5].path, frames[5].is_runtime) == (
        "core::fmt::write",
        None,
        True,
    )
    assert frames[25].is_runtime  # <&dyn core::ops::function::Fn<…> as …>::call_once
    assert [(f.function, f.is_runtime) for f in frames[35:39]] == [
        ("main", False),
        ("__libc_start_call_main", True),
        ("__libc_start_main_impl", True),
        ("_start", True),
    ]
    assert frames[39].function is None  # <unknown>
    assert [f.function for f in frames if not f.is_runtime and f.path] == [
        "unwrap_none::lookup",
        "unwrap_none::timeout",
        "unwrap_none::main",
    ]


def test_compiler_warnings_before_the_panic_are_not_part_of_it() -> None:
    text = _load("03-thread-panic.txt")
    trace = _one(text)
    assert "warning:" not in text[trace.start : trace.end]
    assert trace.data.frames[3].function == "thread_panic::main::{closure#0}"


def test_fixture_embedded_in_markdown_is_found_by_the_pipeline() -> None:
    trace_text = _load("01-index-oob-backtrace.txt")
    md = f"Output:\n\n```console-output\n{trace_text}```\n\npick() trusts the index.\n"
    report = ingest_string(md, input_format="markdown")
    claims = [c for c in extract_claims(report).claims if isinstance(c, TraceClaim)]
    assert len(claims) == 1
    expected = trace_text.strip("\n")
    start = report.body.index(expected)
    assert (claims[0].spans[0].start, claims[0].spans[0].text) == (start, expected)
    assert _first_app(claims[0].frames).function == "index_oob::pick"


# --- variants ---------------------------------------------------------------------------


def test_no_backtrace_synthesizes_the_panic_location() -> None:
    text = (
        "thread 'main' panicked at src/main.rs:2:5:\n"
        "explicit panic\n"
        "second message line\n"
        "note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace\n"
        "after\n"
    )
    trace = _one(text)
    data = trace.data
    assert data.message == "explicit panic\nsecond message line"
    frame = data.frames[0]
    assert (frame.index, frame.function, frame.path, frame.line, frame.col, frame.is_runtime) == (
        0,
        None,
        "src/main.rs",
        2,
        5,
        False,
    )
    assert text[trace.start : trace.end].endswith("to display a backtrace")


def test_pre_1_73_header_with_quoted_message_and_legacy_hash() -> None:
    text = (
        "thread 'worker' panicked at 'bad input', src/lib.rs:10:9\n"
        "stack backtrace:\n"
        "   0: mylib::parse::h0123456789abcdef\n"
        "             at ./src/lib.rs:10:9\n"
        "   1: std::rt::lang_start\n"
    )
    data = _one(text).data
    assert (data.message, data.thread) == ("bad input", "worker")
    assert (data.frames[0].function, data.frames[0].path) == ("mylib::parse", "src/lib.rs")
    assert data.frames[1].is_runtime


def test_two_panics_and_unparseable_location() -> None:
    text = "thread 'a' panicked at nowhere:\nfirst\nthread 'b' (3) panicked at x.rs:1:1:\nsecond\n"
    first, second = PARSER.parse(text)
    assert (first.data.message, first.data.frames) == ("first", ())
    assert (second.data.thread, second.data.frames[0].path) == ("b", "x.rs")


@pytest.mark.parametrize(
    ("function", "path", "runtime"),
    [
        ("<fn() as core::ops::function::FnOnce<()>>::call_once", None, True),
        ("<fn() as core::ops::function::FnOnce<()>>::call_once", "/src/main.rs", False),
        ("alloc::vec::Vec<T>::push", None, True),
        ("myapp::run", "/rustc/abc/library/std/src/rt.rs", True),
        ("myapp::run", "/src/main.rs", False),
    ],
)
def test_is_rust_runtime(function, path, runtime):
    assert rust_panic.is_rust_runtime(function, path) is runtime


# --- robustness -------------------------------------------------------------------------

ALL_LINES = [line for p in sorted(FIXTURES.glob("*.txt")) for line in p.read_text().splitlines()]


@pytest.mark.parametrize("name", [c[0] for c in FIXTURE_CASES])
def test_every_truncation_parses(name):
    lines = _load(name).splitlines(keepends=True)
    for n in range(len(lines) + 1):
        text = "".join(lines[:n])
        for trace in PARSER.parse(text):
            assert 0 <= trace.start < trace.end <= len(text)
            assert trace.data.frames


@pytest.mark.parametrize(
    "text", ["", "thread '", "thread 'x' panicked at ", "stack backtrace:\n  0:"]
)
def test_garbage_does_not_raise(text):
    for trace in PARSER.parse(text):
        assert 0 <= trace.start <= trace.end <= len(text)


def _check(text: str) -> None:
    for parse in (PARSER.parse, rust_panic._parse):
        for trace in parse(text):
            assert 0 <= trace.start <= trace.end <= len(text)


@given(st.text())
def test_hypothesis_random_text(text):
    _check(text)


@settings(max_examples=200)
@given(st.lists(st.one_of(st.sampled_from(ALL_LINES), st.text(max_size=30)), max_size=40))
def test_hypothesis_shuffled_report_lines(lines):
    _check("\n".join(lines))
