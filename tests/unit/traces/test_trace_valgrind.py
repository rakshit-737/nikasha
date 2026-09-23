# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Valgrind parser: real fixtures (with a trailing internal assertion), variants, robustness."""

from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from nikasha.extract import extract_claims
from nikasha.extract.traces import PARSERS, valgrind
from nikasha.ingest import ingest_string
from nikasha.model.claims import TraceClaim

FIXTURES = Path(__file__).parents[2] / "fixtures" / "traces" / "valgrind"
PARSER = PARSERS["valgrind"]
LAST_ALLOC_LINE = "==1==    by 0x4009EC: main (hdrcat.c:122)"


def _load(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def _first_app(frames):
    return next(f for f in frames if not f.is_runtime)


def _assert_block(region, address, distance):
    # "Address A is N bytes after a block of size 64": block = [A - N - 64, A - N)
    assert region.relation == "right"
    assert region.size == 64
    assert region.distance == distance
    assert region.end == address - distance
    assert region.start == address - distance - 64


@pytest.mark.parametrize(
    ("name", "write_line", "alloc_line", "caller_line"),
    [
        ("01-vulnlab-invalid-write-v1.2.0.txt", 15, 11, 104),
        ("02-vulnlab-invalid-write-v1.2.1.txt", 29, 24, 112),
    ],
)
def test_fixture_with_internal_assertion(name, write_line, alloc_line, caller_line):
    text = _load(name)
    traces = PARSER.parse(text)
    assert len(traces) == 1  # the host stacktrace / "Thread 1: status" frames are not traces
    trace = traces[0]
    data = trace.data
    assert trace.start == text.index("==1== Invalid write of size 2")
    alloc_main = text.index(LAST_ALLOC_LINE, text.index("alloc'd"))
    assert trace.end == alloc_main + len(LAST_ALLOC_LINE)
    assert "valgrind:" not in text[trace.start : trace.end]

    assert data.format == "valgrind"
    assert data.bug_type == "invalid-write"
    assert data.message == "Invalid write of size 2"
    assert (data.access.kind, data.access.size) == ("WRITE", 2)
    assert data.address == data.access_address == data.region_address == 0x4A5E7B0
    _assert_block(data.region, 0x4A5E7B0, 0)
    assert data.pid == 1
    assert data.pids_seen == (1,)

    assert [f.function for f in data.frames] == [
        "memmove",
        "util_copy_value",
        "hdr_parse_line",
        "hdr_parse_block",
        "main",
    ]
    assert data.frames[0].is_runtime  # vg_replace_strmem.c
    app = _first_app(data.frames)
    assert (app.index, app.function, app.path, app.line) == (
        1,
        "util_copy_value",
        "util.c",
        write_line,
    )
    assert data.frames[2].line == caller_line
    assert len(data.alloc_frames) == 5
    assert data.alloc_frames[0].function == "malloc"
    assert data.alloc_frames[0].is_runtime
    assert _first_app(data.alloc_frames).line == alloc_line
    assert data.free_frames == ()
    assert data.other_stacks == ()


def test_fixture_with_five_errors():
    text = _load("03-vulnlab-small-overflow-v1.2.0.txt")
    traces = PARSER.parse(text)
    expected = [
        # bug_type, size, address, distance, frame count, first app (function, line)
        ("invalid-write", 2, 0x4A5E770, 0, 5, ("util_copy_value", 15)),
        ("invalid-write", 1, 0x4A5E776, 6, 4, ("util_copy_value", 16)),
        ("invalid-read", 1, 0x4A5E770, 0, 5, ("main", 125)),
        ("invalid-read", 1, 0x4A5E770, 0, 7, ("main", 125)),
        ("invalid-read", 1, 0x4A5E771, 1, 7, ("main", 125)),
    ]
    assert len(traces) == len(expected)
    for trace, (bug, size, address, distance, n_frames, app) in zip(traces, expected, strict=True):
        data = trace.data
        assert data.bug_type == bug
        assert data.access.size == size
        assert data.address == address
        _assert_block(data.region, address, distance)
        assert len(data.frames) == n_frames
        first = _first_app(data.frames)
        assert (first.function, first.line) == app
        assert len(data.alloc_frames) == 5
        assert text[trace.start : trace.end].startswith("==1== Invalid ")
        assert text[trace.start : trace.end].endswith(LAST_ALLOC_LINE)
    # printf's internals (memcpy, __printf_buffer, __vfprintf_internal) are runtime frames
    assert [f.is_runtime for f in traces[3].data.frames] == [True] * 6 + [False]
    # every error block shares one heap block
    assert len({t.data.region.start for t in traces}) == 1
    assert "HEAP SUMMARY" not in text[traces[-1].start : traces[-1].end]


def test_fixture_embedded_in_markdown_is_found_by_the_pipeline():
    trace_text = _load("01-vulnlab-invalid-write-v1.2.0.txt")
    md = f"Valgrind says:\n\n```\n{trace_text}```\n\nThat is all.\n"
    report = ingest_string(md, input_format="markdown")
    claims = [c for c in extract_claims(report).claims if isinstance(c, TraceClaim)]
    assert len(claims) == 1
    base = report.body.index(trace_text.rstrip("\n"))
    start = base + trace_text.index("==1== Invalid write")
    end = (
        base + trace_text.index(LAST_ALLOC_LINE, trace_text.index("alloc'd")) + len(LAST_ALLOC_LINE)
    )
    assert (claims[0].spans[0].start, claims[0].spans[0].end) == (start, end)
    assert _first_app(claims[0].frames).function == "util_copy_value"


# --- variants ---------------------------------------------------------------------------

USE_AFTER_FREE = """\
==77== Invalid read of size 4
==77==    at 0x10916D: use (uaf.c:12)
==77==    by 0x1091A0: main (uaf.c:20)
==77==  Address 0x4a8d048 is 8 bytes inside a block of size 16 free'd
==77==    at 0x484B27F: free (vg_replace_malloc.c:872)
==77==    by 0x109190: main (uaf.c:19)
==77==  Block was alloc'd at
==77==    at 0x4848899: malloc (vg_replace_malloc.c:381)
==77==    by 0x109181: main (uaf.c:18)
==77==
"""


def test_use_after_free_block_stacks():
    trace = PARSER.parse(USE_AFTER_FREE)[0]
    data = trace.data
    assert data.region.relation == "inside"
    assert (data.region.start, data.region.end) == (0x4A8D048 - 8, 0x4A8D048 + 8)
    assert [f.function for f in data.free_frames] == ["free", "main"]
    assert [f.function for f in data.alloc_frames] == ["malloc", "main"]
    assert data.pid == 77
    assert USE_AFTER_FREE[trace.start : trace.end].endswith("main (uaf.c:18)")


def test_before_block_region_and_library_frames():
    text = (
        "==3== Invalid write of size 1\n"
        "==3==    at 0x4C2: ??? (in /usr/lib64/libfoo.so.1)\n"
        "==3==    by 0x4C3: helper (in /usr/lib64/libc.so.6)\n"
        "==3==    by 0x1002D98F92: ???\n"
        "==3==  Address 0x1000 is 2 bytes before a block of size 10 alloc'd\n"
    )
    data = PARSER.parse(text)[0].data
    assert (data.region.start, data.region.end, data.region.relation) == (0x1002, 0x100C, "left")
    frames = data.frames
    assert (frames[0].function, frames[0].module, frames[0].is_runtime) == (
        None,
        "/usr/lib64/libfoo.so.1",
        False,
    )
    assert frames[1].is_runtime  # libc.so
    assert (frames[2].function, frames[2].module) == (None, None)


def test_segv_uninitialised_and_leak_errors():
    text = (
        "==9== Process terminating with default action of signal 11 (SIGSEGV)\n"
        "==9==  Access not within mapped region at address 0x0\n"
        "==9==    at 0x401136: crash (segv.c:4)\n"
        "==9==  Address 0x0 is not stack'd, malloc'd or (recently) free'd\n"
        "==9== \n"
        "==9== Conditional jump or move depends on uninitialised value(s)\n"
        "==9==    at 0x401150: check (u.c:7)\n"
        "==9==  Uninitialised value was created by a heap allocation\n"
        "==9==    at 0x4848899: malloc (vg_replace_malloc.c:381)\n"
        "==9==    by 0x401140: main (u.c:3)\n"
        "==9== \n"
        "==9== 40 bytes in 1 blocks are definitely lost in loss record 1 of 1\n"
        "==9==    at 0x4848899: malloc (vg_replace_malloc.c:381)\n"
        "==9==    by 0x401160: leak (l.c:5)\n"
        "==9== Use of uninitialised value of size 8\n"
        "==9==    at 0x401170: use (u.c:9)\n"
    )
    segv, cond, leak, uninit = PARSER.parse(text)
    assert segv.data.bug_type == "SIGSEGV"
    assert segv.data.frames[0].function == "crash"
    assert segv.data.address == 0
    assert segv.data.region is None
    assert cond.data.bug_type == "uninitialised-conditional"
    assert cond.data.other_stacks[0].label == "Uninitialised value was created by a heap allocation"
    assert [f.function for f in cond.data.other_stacks[0].frames] == ["malloc", "main"]
    assert leak.data.bug_type == "leak-definitely-lost"
    assert [f.function for f in leak.data.frames] == ["malloc", "leak"]
    assert uninit.data.bug_type == "uninitialised-value"
    assert text[leak.start : leak.end].endswith("leak (l.c:5)")  # the next error starts anew


@pytest.mark.parametrize(
    ("line", "bug_type"),
    [
        ("Invalid free() / delete / delete[] / realloc()", "invalid-free"),
        ("Mismatched free() / delete / delete []", "mismatched-free"),
        ("Syscall param write(buf) points to uninitialised byte(s)", "syscall-param"),
        ("Source and destination overlap in memcpy(0x1, 0x2, 8)", "overlapping-copy"),
        ("Jump to the invalid address stated on the next line", "invalid-jump"),
        (
            "Argument 'size' of function malloc has a fishy (possibly negative) value",
            "fishy-argument",
        ),
        ("HEAP SUMMARY:", None),
    ],
)
def test_classify(line, bug_type):
    kind = valgrind.classify(line)
    assert (kind[0] if kind else None) == bug_type


def test_other_pids_and_labels_end_or_extend_an_error():
    text = (
        "==1== Invalid read of size 8\n"
        "==1==    at 0x1: f (a.c:1)\n"
        "==1==  Some unknown detail\n"
        "==1==    at 0x2: g (a.c:2)\n"
        "==1==  Another detail\n"
        "==1==    at 0x3: h (a.c:3)\n"
        "==2==    at 0x4: other_process (b.c:1)\n"
    )
    data = PARSER.parse(text)[0].data
    assert [s.label for s in data.other_stacks] == ["Some unknown detail", "Another detail"]
    assert data.pids_seen == (1,)


# --- robustness -------------------------------------------------------------------------

ALL_LINES = [line for p in sorted(FIXTURES.glob("*.txt")) for line in p.read_text().splitlines()]
ALL_LINES += USE_AFTER_FREE.splitlines()


@pytest.mark.parametrize("name", sorted(p.name for p in FIXTURES.glob("*.txt")))
def test_every_truncation_parses(name):
    lines = _load(name).splitlines(keepends=True)
    for n in range(len(lines) + 1):
        text = "".join(lines[:n])
        for trace in PARSER.parse(text):
            assert 0 <= trace.start < trace.end <= len(text)
    assert PARSER.parse("".join(lines[:5])) == []  # banner only
    assert PARSER.parse("".join(lines[:7]))[0].data.frames[0].function == "memmove"


@pytest.mark.parametrize("text", ["", "==1==", "==1== Invalid read of size", "==x== Invalid"])
def test_garbage_does_not_raise(text):
    assert PARSER.parse(text) == []


def _check(text: str) -> None:
    for parse in (PARSER.parse, valgrind._parse):
        for trace in parse(text):
            assert 0 <= trace.start <= trace.end <= len(text)


@given(st.text())
def test_hypothesis_random_text(text):
    _check(text)


@settings(max_examples=200)
@given(st.lists(st.one_of(st.sampled_from(ALL_LINES), st.text(max_size=30)), max_size=40))
def test_hypothesis_shuffled_report_lines(lines):
    _check("\n".join(lines))
