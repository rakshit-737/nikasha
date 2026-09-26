# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Shared trace machinery: path normalization, runtime frames, helpers, and parse_traces."""

import time
from itertools import pairwise
from pathlib import Path
from typing import get_args

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

import nikasha.extract.traces as traces_pkg
from nikasha.extract import extract_claims
from nikasha.extract.traces import PARSERS, ParsedTrace, common, parse_traces
from nikasha.extract.traces.common import (
    MAX_TRACE_TEXT,
    is_runtime_frame,
    line_offsets,
    make_frame,
    normalize_path,
    parse_int,
    register,
    run_guarded,
    split_lines,
    split_location,
)
from nikasha.ingest import ingest_string
from nikasha.model.claims import TraceClaim, TraceData, TraceFormat

TRACES = Path(__file__).parents[2] / "fixtures" / "traces"
FORMATS = (
    "asan",
    "ubsan",
    "lsan",
    "msan",
    "tsan",
    "valgrind",
    "gdb",
    "python",
    "java",
    "go",
    "rust",
    "node",
)


# --- normalize_path ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "normalized"),
    [
        (None, None),
        ("", None),
        ("   ", None),
        ("./", None),
        ("src/a.c", "src/a.c"),
        ("  src/a.c\n", "src/a.c"),
        ("./src/a.c", "src/a.c"),
        ("././src/a.c", "src/a.c"),
        ("/proc/self/cwd/lib/http.c", "lib/http.c"),
        ("C:\\build\\src\\a.c", "/build/src/a.c"),
        ("c:/build/a.c", "/build/a.c"),
        ("src\\lib\\a.c", "src/lib/a.c"),
        ("/work//libhdr///src/util.c", "/work/libhdr/src/util.c"),
        ("/a/./b/././c.c", "/a/b/c.c"),
        ("/usr/src/debug/glibc/csu/../sysdeps/x.h", "/usr/src/debug/glibc/csu/../sysdeps/x.h"),
    ],
)
def test_normalize_path(raw: str | None, normalized: str | None) -> None:
    assert normalize_path(raw) == normalized


def test_make_frame_keeps_the_original_path_only_when_it_changed() -> None:
    changed = make_frame(index=0, raw="x\r\n", function="f", path="./src/a.c")
    assert (changed.path, changed.original_path, changed.raw) == ("src/a.c", "./src/a.c", "x")
    same = make_frame(index=0, raw="x", function="f", path="src/a.c")
    assert same.original_path is None
    empty = make_frame(index=0, raw="x", function="", module="")
    assert (empty.function, empty.module) == (None, None)


# --- runtime classification -------------------------------------------------------------


@pytest.mark.parametrize(
    ("function", "path", "module", "runtime"),
    [
        ("main", "/src/main.c", None, False),
        ("main", None, None, False),
        ("util_copy_value", "/work/src/util.c", None, False),
        ("__asan_memcpy", None, "/work/hdrcat", True),
        ("__interceptor_strcpy", None, None, True),
        ("__sanitizer::Die", None, None, True),
        ("__libc_start_main", None, None, True),
        ("_start", None, None, True),
        ("start_thread", None, None, True),
        ("f", "/usr/src/debug/glibc-2.43/csu/libc-start.c", None, True),
        ("f", None, "/lib64/libc.so.6", True),
        ("f", None, "/usr/lib/x86_64-linux-gnu/libstdc++.so.6", True),
        ("memmove", "vg_replace_strmem.c", None, True),
        ("malloc", "vg_replace_malloc.c", None, True),
        (None, None, None, False),
    ],
)
def test_is_runtime_frame(
    function: str | None, path: str | None, module: str | None, runtime: bool
) -> None:
    assert is_runtime_frame(function, path, module) is runtime


def test_is_runtime_frame_extra_prefixes() -> None:
    assert not is_runtime_frame("myrt_init", None, None)
    assert is_runtime_frame("myrt_init", None, None, extra_prefixes=("myrt_",))


@pytest.mark.parametrize(
    ("function", "runtime"),
    [
        ("malloc", True),
        ("printf", True),
        ("__GI_raise", True),
        ("_IO_new_file_xsputn", True),
        ("__vfprintf_internal", True),
        ("malloc_printerr", True),
        ("operator new(unsigned long)", True),
        ("main", False),
        ("hdr_parse_line", False),
        (None, False),
    ],
)
def test_is_native_runtime_frame(function: str | None, runtime: bool) -> None:
    assert common.is_native_runtime_frame(function, None, None) is runtime


# --- small helpers ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "value"),
    [("0", 0), ("42", 42), ("", None), ("x", None), ("-1", None), ("²", None), ("9" * 19, None)],
)
def test_parse_int(text: str, value: int | None) -> None:
    assert parse_int(text) == value


@pytest.mark.parametrize(
    ("text", "parsed"),
    [
        ("/src/a.c:12:5", ("/src/a.c", 12, 5)),
        ("a.c:12", ("a.c", 12, None)),
        ("C:\\src\\a.c:12", ("C:\\src\\a.c", 12, None)),
        (
            "node:internal/modules/cjs/loader:1871:14",
            ("node:internal/modules/cjs/loader", 1871, 14),
        ),
        (":12", None),
        ("a.c", None),
        ("a.c:x", None),
        ("", None),
    ],
)
def test_split_location(text: str, parsed: tuple[str, int, int | None] | None) -> None:
    assert split_location(text) == parsed


def test_split_lines_keeps_exact_offsets() -> None:
    text = "a\r\nbb\n\nccc"
    lines = split_lines(text)
    assert [line.text for line in lines] == ["a", "bb", "", "ccc"]
    for line in lines:
        assert text[line.start : line.end] == line.text


def test_line_offsets() -> None:
    assert line_offsets("ab\ncd") == [0, 3, 5]
    assert line_offsets("ab\n") == [0, 3]
    assert line_offsets("") == [0]


def test_run_guarded_caps_input_and_swallows_parser_errors() -> None:
    seen: list[int] = []

    def boom(text: str) -> list[ParsedTrace]:
        seen.append(len(text))
        raise IndexError("bad")

    assert run_guarded(boom, "x" * (MAX_TRACE_TEXT + 10)) == []
    assert seen == [MAX_TRACE_TEXT]


def test_register_rejects_duplicates() -> None:
    class Duplicate:
        format: TraceFormat = "asan"

        def parse(self, text: str) -> list[ParsedTrace]:
            return []

    with pytest.raises(ValueError, match="duplicate"):
        register(Duplicate)


def test_registered_formats() -> None:
    # All 12 formats of the TraceFormat literal are registered (ADR 0009), and each has the
    # three real fixtures SPEC §9.5 requires.
    assert set(PARSERS) == set(FORMATS) == set(get_args(TraceFormat))
    for fmt in FORMATS:
        assert len(list((TRACES / fmt).glob("*.txt"))) >= 3, fmt


# --- parse_traces overlap handling ------------------------------------------------------


class _Fake:
    def __init__(self, fmt: TraceFormat, spans: list[tuple[int, int]]) -> None:
        self.format = fmt
        self.spans = spans

    def parse(self, text: str) -> list[ParsedTrace]:
        return [
            ParsedTrace(start=s, end=e, data=TraceData(format=self.format)) for s, e in self.spans
        ]


def _run(monkeypatch: pytest.MonkeyPatch, *fakes: _Fake) -> list[tuple[str, int, int]]:
    monkeypatch.setattr(traces_pkg, "PARSERS", {f.format: f for f in fakes})
    return [(t.data.format, t.start, t.end) for t in parse_traces("x" * 100)]


def test_overlap_larger_trace_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    kept = _run(monkeypatch, _Fake("asan", [(0, 50)]), _Fake("gdb", [(10, 20), (60, 70)]))
    assert kept == [("asan", 0, 50), ("gdb", 60, 70)]


def test_overlap_equal_size_prefers_earlier_then_format_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kept = _run(monkeypatch, _Fake("node", [(0, 10), (5, 15)]), _Fake("java", [(0, 10)]))
    assert kept == [("java", 0, 10)]


def test_adjacent_and_disjoint_traces_are_all_kept_in_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kept = _run(monkeypatch, _Fake("rust", [(10, 20)]), _Fake("go", [(20, 30), (0, 10)]))
    assert kept == [("go", 0, 10), ("rust", 10, 20), ("go", 20, 30)]


def test_real_mixed_text_keeps_every_format() -> None:
    parts = [
        (TRACES / "asan" / "01-vulnlab-heap-overflow-v1.2.0.txt").read_text(),
        "Some prose between traces.\n",
        (TRACES / "python" / "02-chained-exception.txt").read_text(),
        "\n",
        (TRACES / "java" / "03-caused-by.txt").read_text(),
        "\n",
        (TRACES / "go" / "01-index-out-of-range.txt").read_text(),
        "\n",
        (TRACES / "node" / "01-type-error.txt").read_text(),
        "\n",
        (TRACES / "rust" / "01-index-oob-backtrace.txt").read_text(),
        (TRACES / "gdb" / "02-sigfpe-divide.txt").read_text(),
        (TRACES / "ubsan" / "01-signed-integer-overflow.txt").read_text(),
        (TRACES / "valgrind" / "01-vulnlab-invalid-write-v1.2.0.txt").read_text(),
    ]
    text = "".join(parts)
    found = parse_traces(text)
    assert [t.data.format for t in found] == [
        "asan", "python", "java", "go", "node", "rust", "gdb", "ubsan", "valgrind",
    ]  # fmt: skip
    for earlier, later in pairwise(found):
        assert earlier.end <= later.start


def test_unindented_sanitizer_frames_prefer_the_full_asan_report() -> None:
    text = (
        "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x10 at pc 0x1\n"
        "#0 0x1 in f /src/a.c:1:1\n"
        "#1 0x2 in main /src/a.c:9:1\n"
        "SUMMARY: AddressSanitizer: heap-buffer-overflow /src/a.c:1:1 in f\n"
    )
    assert PARSERS["gdb"].parse(text)  # gdb alone would claim the frame lines…
    found = parse_traces(text)
    assert [t.data.format for t in found] == ["asan"]  # …but the larger ASan report wins
    assert found[0].data.frames[0].path == "/src/a.c"


def test_trace_in_plain_text_prose_is_found() -> None:
    trace = (TRACES / "go" / "02-nil-map.txt").read_text()
    body = f"The service crashed with:\n{trace}\nPlease advise.\n"
    report = ingest_string(body, input_format="text")
    claims = [c for c in extract_claims(report).claims if isinstance(c, TraceClaim)]
    assert len(claims) == 1
    assert claims[0].spans[0].text == trace.rstrip("\n")
    assert claims[0].frames[0].function == "main.(*registry).add"


# --- every parser, every input ----------------------------------------------------------

ALL_LINES = sorted(
    {line for p in TRACES.glob("*/*.txt") for line in p.read_text(encoding="utf-8").splitlines()}
)


def _check(text: str) -> None:
    found = parse_traces(text)
    for trace in found:
        assert 0 <= trace.start < trace.end <= len(text)
    for earlier, later in pairwise(found):
        assert earlier.end <= later.start


@given(st.text())
def test_parse_traces_random_text(text: str) -> None:
    _check(text)


@settings(max_examples=300)
@given(st.lists(st.one_of(st.sampled_from(ALL_LINES), st.text(max_size=20)), max_size=60))
def test_parse_traces_on_mixed_fixture_lines(lines: list[str]) -> None:
    _check("\n".join(lines))


def test_large_repetitive_input_is_fast() -> None:
    text = "\n".join(ALL_LINES) * 40
    started = time.perf_counter()
    _check(text[:MAX_TRACE_TEXT])
    assert time.perf_counter() - started < 10


def test_libc_named_project_function_stays_an_app_frame() -> None:
    assert common.is_native_runtime_frame("strdup", None, "/lib64/libc.so.6")
    assert common.is_native_runtime_frame("malloc_printerr", "malloc.c", None)
    assert not common.is_native_runtime_frame("strdup", "src/str.c", None)
    assert not common.is_native_runtime_frame("printf", "lib/compat/printf.c", None)
