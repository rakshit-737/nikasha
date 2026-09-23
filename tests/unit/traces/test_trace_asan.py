# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""AddressSanitizer parser: real fixtures, report variants, embedding and robustness."""

from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from nikasha.extract import extract_claims
from nikasha.extract.traces import PARSERS, asan
from nikasha.ingest import ingest_string
from nikasha.model.claims import TraceClaim

FIXTURES = Path(__file__).parents[2] / "fixtures" / "traces" / "asan"
PARSER = PARSERS["asan"]


def _load(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def _one(text: str):
    traces = PARSER.parse(text)
    assert len(traces) == 1, traces
    return traces[0]


def _first_app(frames):
    return next(f for f in frames if not f.is_runtime)


# --- the real fixtures ------------------------------------------------------------------

FIXTURE_CASES = [
    # name, address, util.c write line, util.c malloc line, hdr_parse_line line
    ("01-vulnlab-heap-overflow-v1.2.0.txt", 0x7BC73B5E00C0, 15, 11, 104),
    ("02-vulnlab-heap-overflow-v1.2.1.txt", 0x7BAA1DDE00C0, 29, 24, 112),
    ("03-vulnlab-heap-overflow-v1.2.0-O0-fold.txt", 0x7BFDA55E00C0, 15, 11, 104),
]


@pytest.mark.parametrize(
    ("name", "address", "write_line", "alloc_line", "caller_line"), FIXTURE_CASES
)
def test_fixture(name, address, write_line, alloc_line, caller_line):
    text = _load(name)
    trace = _one(text)
    data = trace.data

    # span: from the ===== separator above the header to ==1==ABORTING, nothing after
    assert trace.start == 0
    assert text[trace.start : trace.end].startswith("=" * 65 + "\n==1==ERROR: AddressSanitizer")
    assert text[trace.start : trace.end].endswith("==1==ABORTING")
    assert trace.end == len(text.rstrip("\n"))

    assert data.format == "asan"
    assert data.bug_type == "heap-buffer-overflow"
    assert data.message.startswith(f"heap-buffer-overflow on address {address:#x} at pc 0x")
    assert data.access.kind == "WRITE"
    assert data.access.size == 96
    assert data.address == address
    assert data.access_address == address
    assert data.region_address == address
    # "0 bytes after 64-byte region [start,end)": the write starts exactly at end
    assert data.region.relation == "right"
    assert data.region.distance == 0
    assert data.region.size == 64
    assert data.region.end == address
    assert data.region.start == address - 64
    assert data.pid == 1
    assert data.pids_seen == (1,)
    assert data.thread == "T0"
    assert data.free_frames == ()
    assert data.other_stacks == ()

    assert len(data.frames) == 8
    assert [f.index for f in data.frames] == list(range(8))
    assert data.frames[0].function == "__asan_memcpy"
    assert data.frames[0].is_runtime
    assert data.frames[0].module == "/work/libhdr/build/hdrcat"
    app = _first_app(data.frames)
    assert (app.index, app.function, app.path, app.line, app.col) == (
        1,
        "util_copy_value",
        "/work/libhdr/src/util.c",
        write_line,
        5,
    )
    assert data.frames[2].line == caller_line
    main = data.frames[4]
    assert (main.function, main.path, main.line, main.is_runtime) == (
        "main",
        "/work/libhdr/tools/hdrcat.c",
        122,
        False,
    )
    # the symbol version is stripped; glibc and _start are runtime
    assert data.frames[6].function == "__libc_start_main"
    assert all(f.is_runtime for f in data.frames[5:])

    assert len(data.alloc_frames) == 8
    assert data.alloc_frames[0].function == "malloc"
    assert data.alloc_frames[0].is_runtime
    alloc_app = _first_app(data.alloc_frames)
    assert (alloc_app.function, alloc_app.line, alloc_app.col) == (
        "util_copy_value",
        alloc_line,
        17,
    )

    assert data.summary.startswith("SUMMARY: AddressSanitizer: heap-buffer-overflow (/work/")
    assert data.summary_function == "__asan_memcpy"
    assert data.summary_path is None  # current ASan names the module, not a source line
    assert data.summary_line is None


def test_fixture_embedded_in_markdown_is_found_by_the_pipeline():
    trace_text = _load("01-vulnlab-heap-overflow-v1.2.0.txt")
    md = (
        "# Heap overflow in hdr_parse_line\n\n"
        "Running `hdrcat` on the attached input crashes:\n\n"
        f"```\n{trace_text}```\n\n"
        "The copy in util_copy_value ignores the buffer size.\n"
    )
    report = ingest_string(md, input_format="markdown")
    claims = [c for c in extract_claims(report).claims if isinstance(c, TraceClaim)]
    assert len(claims) == 1
    claim = claims[0]
    expected = trace_text.rstrip("\n")
    start = report.body.index(expected)
    assert claim.extractor.endswith("traces:asan")
    assert (claim.spans[0].start, claim.spans[0].end) == (start, start + len(expected))
    assert claim.spans[0].text == expected
    assert _first_app(claim.frames).function == "util_copy_value"
    assert len(claim.alloc_frames) == 8


# --- report variants --------------------------------------------------------------------

UAF = """\
==4242==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000010 at pc 0x4c1
READ of size 4 at 0x602000000010 thread T1
    #0 0x4c1a2f in reader /src/app/worker.c:40:12
    #1 0x7f00 in start_thread (/lib64/libc.so.6+0x8a1b3)

0x602000000010 is located 0 bytes inside of 16-byte region [0x602000000010,0x602000000020)
freed by thread T0 here:
    #0 0x49d in free (/src/app/a.out+0x49d)
    #1 0x4c2 in cleanup /src/app/main.c:22:3

previously allocated by thread T0 here:
    #0 0x49e in malloc (/src/app/a.out+0x49e)
    #1 0x4c3 in setup /src/app/main.c:10:9

Thread T1 created by T0 here:
    #0 0x48a in pthread_create (/src/app/a.out+0x48a)
    #1 0x4c4 in main /src/app/main.c:30:5

SUMMARY: AddressSanitizer: heap-use-after-free /src/app/worker.c:40:12 in reader
==4242==ABORTING
"""


def test_use_after_free_with_free_alloc_and_thread_stacks():
    data = _one(UAF).data
    assert data.bug_type == "heap-use-after-free"
    assert data.access.kind == "READ"
    assert data.access.size == 4
    assert data.thread == "T1"
    assert data.region.relation == "inside"
    assert data.region.distance == 0
    assert (data.region.start, data.region.end) == (0x602000000010, 0x602000000020)
    assert [f.function for f in data.frames] == ["reader", "start_thread"]
    assert [f.function for f in data.free_frames] == ["free", "cleanup"]
    assert data.free_frames[0].is_runtime
    assert [f.function for f in data.alloc_frames] == ["malloc", "setup"]
    assert len(data.other_stacks) == 1
    assert data.other_stacks[0].label == "Thread T1 created by T0"
    assert [f.function for f in data.other_stacks[0].frames] == ["pthread_create", "main"]
    assert (data.summary_path, data.summary_line, data.summary_function) == (
        "/src/app/worker.c",
        40,
        "reader",
    )
    assert data.pid == 4242


def test_old_style_to_the_right_of_region():
    text = (
        "==7==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60300000eff4 at pc 0x1\n"
        "WRITE of size 1 at 0x60300000eff4 thread T0\n"
        "    #0 0x400b1e in main /tmp/t.c:5:3\n"
        "0x60300000eff4 is located 4 bytes to the right of 16-byte region "
        "[0x60300000efe0,0x60300000eff0)\n"
        "SUMMARY: AddressSanitizer: heap-buffer-overflow /tmp/t.c:5:3 in main\n"
    )
    data = _one(text).data
    assert data.region.relation == "right"
    assert data.region.distance == 4
    assert data.region.size == 16
    assert data.region_address - data.region.end == 4


@pytest.mark.parametrize(
    ("words", "relation"),
    [("before", "left"), ("to the left of", "left"), ("inside of", "inside"), ("after", "right")],
)
def test_region_relations(words, relation):
    text = (
        "==7==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x100 at pc 0x1\n"
        f"0x100 is located 8 bytes {words} 32-byte region [0x108,0x128)\n"
    )
    assert _one(text).data.region.relation == relation


def test_global_variable_region():
    text = (
        "==9==ERROR: AddressSanitizer: global-buffer-overflow on address 0x5000 at pc 0x1\n"
        "READ of size 4 at 0x5000 thread T0\n"
        "    #0 0x1 in main /src/g.c:4:10\n"
        "0x5000 is located 0 bytes after global variable 'table' defined in "
        "'/src/g.c:1:5' (0x4fd8) of size 40\n"
    )
    region = _one(text).data.region
    assert (region.start, region.end, region.size, region.relation) == (0x4FD8, 0x5000, 40, "right")


def test_segv_on_unknown_address_takes_access_from_signal_line():
    text = (
        "==31==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 "
        "(pc 0x55d bp 0x7ff sp 0x7fe T0)\n"
        "==31==The signal is caused by a READ memory access.\n"
        "==31==Hint: address points to the zero page.\n"
        "    #0 0x55d in parse_hdr /src/p.c:77:9\n"
        "    #1 0x55e in main /src/p.c:90:3\n"
        "\n"
        "AddressSanitizer can not provide additional info.\n"
        "SUMMARY: AddressSanitizer: SEGV /src/p.c:77:9 in parse_hdr\n"
        "==31==ABORTING\n"
    )
    data = _one(text).data
    assert data.bug_type == "SEGV"
    assert data.address == 0
    assert data.access.kind == "READ"
    assert data.access.size is None
    assert data.thread == "T0"
    assert data.frames[0].function == "parse_hdr"


def test_attempting_double_free_without_summary_uses_header_type():
    text = (
        "==5==ERROR: AddressSanitizer: attempting double-free on 0x6020 in thread T0:\n"
        "    #0 0x1 in free (/a.out+0x1)\n"
        "    #1 0x2 in main /src/d.c:9:3\n"
    )
    trace = _one(text)
    assert trace.data.bug_type == "double-free"
    assert trace.data.address == 0x6020
    assert trace.end == len(text) - 1  # the last frame line, not the trailing newline


def test_unsymbolized_and_null_location_frames():
    text = (
        "==5==ERROR: AddressSanitizer: stack-overflow on address 0x7ffe at pc 0x1\n"
        "    #0 0x4a44a1  (/work/hdrcat+0x4a44a1)\n"
        "    #1 0x4a44a2 in recurse <null>\n"
        "    #2 0x4a44a3 in std::vector<int, std::allocator<int> >::at(unsigned long) const "
        "/usr/include/c++/v1/vector:1234:5\n"
        "    #3 0x4a44a4 in weird(int)\n"
    )
    frames = _one(text).data.frames
    assert (frames[0].function, frames[0].module) == (None, "/work/hdrcat")
    assert (frames[1].function, frames[1].path) == ("recurse", None)
    assert frames[2].function.startswith("std::vector<int, std::allocator<int> >::at(")
    assert (frames[2].path, frames[2].line) == ("/usr/include/c++/v1/vector", 1234)
    assert (frames[3].function, frames[3].path) == ("weird(int)", None)


def test_consecutive_stacks_without_labels_and_multiple_pids():
    text = (
        "==5==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x10 at pc 0x1\n"
        "    #0 0x1 in a /src/a.c:1:1\n"
        "    #0 0x2 in b /src/b.c:2:2\n"
        "==6==Note: forked child\n"
    )
    data = _one(text).data
    assert [f.function for f in data.frames] == ["a"]
    assert data.other_stacks[0].label == "stack 1"
    assert data.pids_seen == (5, 6)


def test_trailing_prose_is_not_swallowed():
    text = (
        "==5==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x10 at pc 0x1\n"
        "    #0 0x1 in a /src/a.c:1:1\n"
        "The root cause is below.\n"
        "Root cause:\n"
        "we forgot the length.\n"
        "It is bad.\n"
        "Really.\n"
        "SUMMARY: AddressSanitizer: heap-buffer-overflow /src/a.c:1:1 in a\n"
    )
    trace = _one(text)
    assert text[trace.start : trace.end].endswith("in a /src/a.c:1:1")
    assert trace.data.summary is None


def test_two_reports_and_foreign_sanitizer_header_split():
    first = "==1==ERROR: AddressSanitizer: SEGV on unknown address 0x0 (pc 0x1 T0)\n"
    lsan = "==1==ERROR: LeakSanitizer: detected memory leaks\n"
    text = first + "    #0 0x1 in f /a.c:1:1\n" + lsan + first + "    #0 0x1 in g /a.c:2:1\n"
    traces = PARSER.parse(text)
    assert [t.data.frames[0].function for t in traces] == ["f", "g"]
    assert text[traces[0].start : traces[0].end].endswith("f /a.c:1:1")


# --- robustness -------------------------------------------------------------------------

ALL_LINES = [line for p in sorted(FIXTURES.glob("*.txt")) for line in p.read_text().splitlines()]
ALL_LINES += UAF.splitlines()


@pytest.mark.parametrize("name", [c[0] for c in FIXTURE_CASES])
def test_every_truncation_parses(name):
    lines = _load(name).splitlines(keepends=True)
    for n in range(len(lines) + 1):
        text = "".join(lines[:n])
        for trace in PARSER.parse(text):
            assert 0 <= trace.start < trace.end <= len(text)
    five = "".join(lines[:5])
    assert _one(five).data.frames[1].function == "util_copy_value"


@pytest.mark.parametrize(
    "text", ["", "\n", "==1==ERROR: AddressSanitizer: ", "#0 0x1 in", "\x00퟿" * 50]
)
def test_garbage_does_not_raise(text):
    for trace in PARSER.parse(text):
        assert 0 <= trace.start <= trace.end <= len(text)


def _check(text: str) -> None:
    for parse in (PARSER.parse, asan._parse):
        for trace in parse(text):
            assert 0 <= trace.start <= trace.end <= len(text)


@given(st.text())
def test_hypothesis_random_text(text):
    _check(text)


@settings(max_examples=200)
@given(st.lists(st.one_of(st.sampled_from(ALL_LINES), st.text(max_size=30)), max_size=40))
def test_hypothesis_shuffled_report_lines(lines):
    _check("\n".join(lines))
