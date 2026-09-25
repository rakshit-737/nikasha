# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""UndefinedBehaviorSanitizer parser: real fixtures, slugs, embedding and robustness."""

from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from nikasha.extract import extract_claims
from nikasha.extract.traces import PARSERS, ubsan
from nikasha.ingest import ingest_string
from nikasha.model.claims import TraceClaim

FIXTURES = Path(__file__).parents[2] / "fixtures" / "traces" / "ubsan"
PARSER = PARSERS["ubsan"]


def _load(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def _one(text: str):
    traces = PARSER.parse(text)
    assert len(traces) == 1, traces
    return traces[0]


FIXTURE_CASES = [
    # name, bug_type, message, source file, frames [(function, line, col)] up to main
    (
        "01-signed-integer-overflow.txt",
        "signed-integer-overflow",
        "signed integer overflow: 1073741823 * 4 cannot be represented in type 'int'",
        "/src/programs/ubsan/signed_overflow.c",
        [("scale", 9, 18), ("accumulate", 14, 12), ("main", 19, 20)],
    ),
    (
        "02-shift-exponent.txt",
        "shift-exponent",
        "shift exponent 40 is too large for 32-bit type 'int'",
        "/src/programs/ubsan/shift_exponent.c",
        [("shift_left", 8, 18), ("encode_flags", 13, 12), ("main", 19, 20)],
    ),
    (
        "03-divide-by-zero-halt.txt",
        "integer-divide-by-zero",
        "division by zero",
        "/src/programs/ubsan/divide_by_zero.c",
        [("divide", 8, 18), ("average", 16, 12), ("main", 23, 20)],
    ),
]


@pytest.mark.parametrize(("name", "bug_type", "message", "path", "app"), FIXTURE_CASES)
def test_fixture(name, bug_type, message, path, app):
    text = _load(name)
    trace = _one(text)
    data = trace.data
    assert trace.start == 0
    assert text[trace.start : trace.end] == text.rstrip("\n")  # through the SUMMARY line
    assert data.format == "ubsan"
    assert data.bug_type == bug_type
    assert data.message == message
    assert len(data.frames) == 6
    assert [(f.function, f.line, f.col) for f in data.frames[:3]] == app
    assert all(f.path == path and not f.is_runtime for f in data.frames[:3])
    assert [f.function for f in data.frames[3:]] == [
        "__libc_start_call_main",
        "__libc_start_main",
        "_start",
    ]
    assert all(f.is_runtime for f in data.frames[3:])
    assert data.summary.startswith("SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior ")
    assert (data.summary_path, data.summary_line) == (path, app[0][1])
    assert data.summary_function is None
    assert data.alloc_frames == data.free_frames == data.other_stacks == ()
    assert data.pid is None


def test_fixture_embedded_in_markdown_is_found_by_the_pipeline() -> None:
    trace_text = _load("02-shift-exponent.txt")
    md = (
        "## Summary\n\nencode_flags shifts by an attacker-controlled amount.\n\n"
        f"```text\n{trace_text}```\n\nFixed by masking the exponent.\n"
    )
    report = ingest_string(md, input_format="markdown")
    claims = [c for c in extract_claims(report).claims if isinstance(c, TraceClaim)]
    assert len(claims) == 1
    expected = trace_text.rstrip("\n")
    start = report.body.index(expected)
    span = claims[0].spans[0]
    assert (span.start, span.end, span.text) == (start, start + len(expected), expected)
    assert claims[0].bug_type == "shift-exponent"
    assert claims[0].frames[0].function == "shift_left"


def test_header_without_stack_synthesizes_frame_zero() -> None:
    text = "src/lib/parse.c:42:7: runtime error: load of null pointer of type 'char'\nnext line\n"
    trace = _one(text)
    frame = trace.data.frames[0]
    assert (frame.index, frame.function, frame.path, frame.line, frame.col) == (
        0,
        None,
        "src/lib/parse.c",
        42,
        7,
    )
    assert trace.data.bug_type == "null-pointer-dereference"
    assert text[trace.start : trace.end] == text.splitlines()[0]


def test_unknown_location_and_missing_column() -> None:
    trace = _one("<unknown>:0: runtime error: something new\n")
    assert trace.data.bug_type == "unknown"
    assert trace.data.frames[0].path is None
    assert trace.data.frames[0].col is None


def test_notes_are_kept_and_several_reports_split() -> None:
    text = (
        "a.c:5:3: runtime error: load of misaligned address 0x01 for type 'int'\n"
        "0x000000000001: note: pointer points here\n"
        " 00 00 00 00\n"
        "              ^\n"
        "    #0 0x1 in f /src/a.c:5:3\n"
        "b.c:9:1: runtime error: index 5 out of bounds for type 'int[4]'\n"
        "    #0 0x2 in g /src/b.c:9:1\n"
        "    #0 0x3 in h /src/b.c:1:1\n"
        "SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior /src/b.c:9:1 in g\n"
    )
    first, second = PARSER.parse(text)
    assert first.data.bug_type == "misaligned-address"
    assert [f.function for f in first.data.frames] == ["f"]
    assert text[first.start : first.end].endswith("in f /src/a.c:5:3")
    assert second.data.bug_type == "array-bounds"
    assert [f.function for f in second.data.frames] == ["g"]  # a second #0 ends the stack
    assert second.data.summary is None


def test_prose_after_report_ends_it() -> None:
    text = "x.c:1:1: runtime error: division by zero\n    #0 0x1 in f /x.c:1:1\nThis is prose.\n"
    trace = _one(text)
    assert text[trace.start : trace.end].endswith("/x.c:1:1")


def test_summary_with_function() -> None:
    text = (
        "x.c:1:1: runtime error: division by zero\n"
        "SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior /x.c:1:1 in f\n"
    )
    data = _one(text).data
    assert (data.summary_path, data.summary_line, data.summary_function) == ("/x.c", 1, "f")


@pytest.mark.parametrize(
    ("message", "slug"),
    [
        (
            "signed integer overflow: 1 + 2147483647 cannot be represented",
            "signed-integer-overflow",
        ),
        ("unsigned integer overflow: 0 - 1 cannot be represented", "unsigned-integer-overflow"),
        ("negation of -2147483648 cannot be represented in type 'int'", "signed-integer-overflow"),
        ("shift exponent 40 is too large for 32-bit type 'int'", "shift-exponent"),
        ("left shift of negative value -1", "shift-base"),
        ("division by zero", "integer-divide-by-zero"),
        ("division of -2147483648 by -1 cannot be represented", "signed-integer-overflow"),
        (
            "null pointer passed as argument 1, which is declared to never be null",
            "nonnull-attribute",
        ),
        ("member access within null pointer of type 'struct s'", "null-pointer-dereference"),
        ("applying non-zero offset 8 to null pointer", "pointer-overflow"),
        ("load of misaligned address 0x01 for type 'int'", "misaligned-address"),
        ("index 5 out of bounds for type 'int[4]'", "array-bounds"),
        ("load of value 7, which is not a valid value for type 'bool'", "invalid-value-load"),
        (
            "1e+100 is outside the range of representable values of type 'int'",
            "float-cast-overflow",
        ),
        ("execution reached an unreachable program point", "unreachable"),
        ("something else entirely", "unknown"),
    ],
)
def test_bug_type_slugs(message, slug):
    assert ubsan.bug_type_for(message) == slug


# --- robustness -------------------------------------------------------------------------

ALL_LINES = [line for p in sorted(FIXTURES.glob("*.txt")) for line in p.read_text().splitlines()]


@pytest.mark.parametrize("name", [c[0] for c in FIXTURE_CASES])
def test_every_truncation_parses(name):
    lines = _load(name).splitlines(keepends=True)
    for n in range(len(lines) + 1):
        text = "".join(lines[:n])
        traces = PARSER.parse(text)
        assert len(traces) == (1 if n else 0)
        for trace in traces:
            assert 0 <= trace.start < trace.end <= len(text)
            assert trace.data.frames


@pytest.mark.parametrize("text", ["", "\n", ": runtime error: ", "a.c:x:1: runtime error: y"])
def test_garbage_does_not_raise(text):
    assert PARSER.parse(text) == []


def _check(text: str) -> None:
    for parse in (PARSER.parse, ubsan._parse):
        for trace in parse(text):
            assert 0 <= trace.start <= trace.end <= len(text)


@given(st.text())
def test_hypothesis_random_text(text):
    _check(text)


@settings(max_examples=200)
@given(st.lists(st.one_of(st.sampled_from(ALL_LINES), st.text(max_size=30)), max_size=30))
def test_hypothesis_shuffled_report_lines(lines):
    _check("\n".join(lines))
