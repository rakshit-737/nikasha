# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""gdb backtrace parser: real fixtures (bt and bt full), variants, embedding, robustness."""

from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from nikasha.extract import extract_claims
from nikasha.extract.traces import PARSERS, gdb
from nikasha.ingest import ingest_string
from nikasha.model.claims import TraceClaim

FIXTURES = Path(__file__).parents[2] / "fixtures" / "traces" / "gdb"
PARSER = PARSERS["gdb"]


def _load(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def _one(text: str):
    traces = PARSER.parse(text)
    assert len(traces) == 1, traces
    return traces[0]


def _first_app(frames):
    return next(f for f in frames if not f.is_runtime)


FIXTURE_CASES = [
    # name, signal, message, frame count, first app (index, function, path, line), last line
    (
        "01-vulnlab-heap-corruption-abort-v1.2.0.txt",
        "SIGABRT",
        "Aborted",
        21,
        (20, "main", "tools/hdrcat.c", 125),
        "#20 0x0000000000400a2e in main (argc=2, argv=0x7ffdbd7e2ab8) at tools/hdrcat.c:125",
    ),
    (
        "02-sigfpe-divide.txt",
        "SIGFPE",
        "Arithmetic exception",
        3,
        (0, "ratio", "/src/programs/gdb/divide_sigfpe.c", 8),
        "#2  0x0000000000400496 in main (argc=1, argv=0x7ffdfbdf58f8) at "
        "/src/programs/gdb/divide_sigfpe.c:19",
    ),
    (
        "03-failed-assert-abort.txt",
        "SIGABRT",
        "Aborted",
        10,
        (7, "check_config", "/src/programs/gdb/failed_assert.c", 9),
        "No locals.",
    ),
]


@pytest.mark.parametrize("case", FIXTURE_CASES, ids=[c[0] for c in FIXTURE_CASES])
def test_fixture(case):
    name, signal, message, count, app, last_line = case
    text = _load(name)
    trace = _one(text)
    data = trace.data
    covered = text[trace.start : trace.end]
    assert trace.start == text.index("Program received signal")
    assert covered.endswith(last_line)
    assert "warning:" not in covered.splitlines()[-1]
    assert "Error disabling address space randomization" not in covered
    assert data.format == "gdb"
    assert data.bug_type == signal
    assert data.message == message
    assert len(data.frames) == count
    assert [f.index for f in data.frames] == list(range(count))
    first = _first_app(data.frames)
    assert (first.index, first.function, first.path, first.line) == app
    assert data.frames[-1].function == "main"
    assert data.other_stacks == ()


def test_heap_corruption_frames_are_glibc_runtime():
    data = _one(_load("01-vulnlab-heap-corruption-abort-v1.2.0.txt")).data
    assert all(f.is_runtime for f in data.frames[:20])
    # inlined frame without an address; argument strings with parentheses are skipped
    printerr = data.frames[6]
    assert (printerr.function, printerr.path, printerr.line) == (
        "malloc_printerr",
        "malloc.c",
        5341,
    )
    assert data.frames[11].path == "/usr/src/debug/glibc-2.43-8.fc44.x86_64/libio/libioP.h"


def test_bt_full_locals_are_skipped():
    data = _one(_load("03-failed-assert-abort.txt")).data
    assert [f.function for f in data.frames[5:]] == [
        "__libc_message_wrapper",
        "__assert_fail",
        "check_config",
        "load_config",
        "main",
    ]
    assert [f.line for f in data.frames[7:]] == [9, 14, 21]


def test_fixture_embedded_in_markdown_is_found_by_the_pipeline():
    trace_text = _load("02-sigfpe-divide.txt")
    md = f"# Crash\n\nUnder gdb:\n\n```\n{trace_text}```\n\nratio() divides by zero.\n"
    report = ingest_string(md, input_format="markdown")
    claims = [c for c in extract_claims(report).claims if isinstance(c, TraceClaim)]
    assert len(claims) == 1
    base = report.body.index(trace_text.rstrip("\n"))
    covered = trace_text[trace_text.index("Program received") : trace_text.index("\nwarning:")]
    start = base + trace_text.index("Program received")
    assert (claims[0].spans[0].start, claims[0].spans[0].text) == (start, covered)
    assert claims[0].bug_type == "SIGFPE"
    assert claims[0].frames[0].function == "ratio"


# --- variants ---------------------------------------------------------------------------


def test_from_library_unknown_and_signal_handler_frames():
    text = (
        "#0  0x00007ffff7a42e97 in raise () from /lib64/libc.so.6\n"
        "#1  0x0000555555555189 in ?? ()\n"
        "#2  <signal handler called>\n"
        '#3  handler (c=40 \'(\', s=0x1 "a) b\\" (") at src/h.c:7\n'
        "#4  0x0000555555555200 in main\n"
        "(More stack frames follow...)\n"
    )
    trace = _one(text)
    frames = trace.data.frames
    assert trace.data.bug_type is None
    assert (frames[0].function, frames[0].module, frames[0].is_runtime) == (
        "raise",
        "/lib64/libc.so.6",
        True,
    )
    assert (frames[1].function, frames[1].path) == (None, None)
    assert (frames[2].function, frames[2].is_runtime) == (None, True)
    assert (frames[3].function, frames[3].path, frames[3].line) == ("handler", "src/h.c", 7)
    assert frames[4].function == "main"
    assert text[trace.start : trace.end].endswith("(More stack frames follow...)")


def test_wrapped_location_is_attached():
    text = (
        "#0  0x0000555555555189 in parse_header (buf=0x5555, len=4096)\n"
        "    at lib/hdr.c:412\n"
        "#1  0x00005555555551a0 in main (argc=1, argv=0x7ffe)\n"
        "    at tools/main.c:30\n"
    )
    frames = _one(text).data.frames
    assert [(f.function, f.path, f.line) for f in frames] == [
        ("parse_header", "lib/hdr.c", 412),
        ("main", "tools/main.c", 30),
    ]
    assert frames[0].raw.endswith("at lib/hdr.c:412")


def test_unparsable_continuation_is_kept_but_not_attached():
    text = "#0  0x1 in f (a=1)\n    at nowhere\n"
    trace = _one(text)
    assert trace.data.frames[0].path is None
    assert text[trace.start : trace.end].endswith("at nowhere")


def test_thread_apply_all_bt():
    text = (
        'Thread 2 "worker" received signal SIGSEGV, Segmentation fault.\n'
        "[Switching to Thread 0x7ffff7d8a640 (LWP 12)]\n"
        "0x0000555555555189 in work (p=0x0) at w.c:5\n"
        "5\t  return *p;\n"
        "\n"
        'Thread 2 (Thread 0x7ffff7d8a640 (LWP 12) "worker"):\n'
        "#0  0x0000555555555189 in work (p=0x0) at w.c:5\n"
        "#1  0x00007ffff7e1b1c4 in start_thread () from /lib64/libc.so.6\n"
        "\n"
        'Thread 1 (Thread 0x7ffff7d8b740 (LWP 11) "prog"):\n'
        "#0  0x00007ffff7e1f0cd in __futex_abstimed_wait_common () from /lib64/libc.so.6\n"
        "#1  0x0000555555555200 in main () at m.c:9\n"
        "\n"
        "Some prose after the backtrace.\n"
    )
    trace = _one(text)
    data = trace.data
    assert (data.bug_type, data.message, data.thread) == ("SIGSEGV", "Segmentation fault", "2")
    assert [f.function for f in data.frames] == ["work", "start_thread"]
    assert len(data.other_stacks) == 1
    other = data.other_stacks[0]
    assert other.label.startswith("Thread 1 (Thread 0x7ffff7d8b740")
    assert [f.function for f in other.frames] == ["__futex_abstimed_wait_common", "main"]
    assert text[trace.start : trace.end].startswith('Thread 2 "worker" received signal')
    assert text[trace.start : trace.end].endswith("in main () at m.c:9")


def test_core_file_and_unlabelled_second_stack():
    text = (
        "Program terminated with signal SIGSEGV, Segmentation fault.\n"
        "#0  f () at a.c:1\n"
        "#1  g () at a.c:2\n"
        "\n"
        "#0  h () at b.c:3\n"
    )
    data = _one(text).data
    assert data.bug_type == "SIGSEGV"
    assert [s.label for s in data.other_stacks] == ["stack at #0"]


def test_frames_not_starting_at_zero_are_ignored():
    assert PARSER.parse("#3  f () at a.c:1\n#4  g () at a.c:2\n") == []


# --- robustness -------------------------------------------------------------------------

ALL_LINES = [line for p in sorted(FIXTURES.glob("*.txt")) for line in p.read_text().splitlines()]


@pytest.mark.parametrize("name", [c[0] for c in FIXTURE_CASES])
def test_every_truncation_parses(name):
    lines = _load(name).splitlines(keepends=True)
    for n in range(len(lines) + 1):
        text = "".join(lines[:n])
        for trace in PARSER.parse(text):
            assert 0 <= trace.start < trace.end <= len(text)
    assert _one("".join(lines[:7])).data.frames[0].index == 0


@pytest.mark.parametrize(
    "text", ["", "#", "#0", "#0  (", '#0  f ("unterminated', "Program received"]
)
def test_garbage_does_not_raise(text):
    for trace in PARSER.parse(text):
        assert 0 <= trace.start <= trace.end <= len(text)


def _check(text: str) -> None:
    for parse in (PARSER.parse, gdb._parse):
        for trace in parse(text):
            assert 0 <= trace.start <= trace.end <= len(text)


@given(st.text())
def test_hypothesis_random_text(text):
    _check(text)


@settings(max_examples=200)
@given(st.lists(st.one_of(st.sampled_from(ALL_LINES), st.text(max_size=30)), max_size=40))
def test_hypothesis_shuffled_report_lines(lines):
    _check("\n".join(lines))
