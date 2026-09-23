# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Go panic parser: real fixtures (multi-goroutine dumps), variants, embedding, robustness."""

from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from nikasha.extract import extract_claims
from nikasha.extract.traces import PARSERS, go_panic
from nikasha.ingest import ingest_string
from nikasha.model.claims import TraceClaim

FIXTURES = Path(__file__).parents[2] / "fixtures" / "traces" / "go"
PARSER = PARSERS["go"]


def _load(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def _one(text: str):
    traces = PARSER.parse(text)
    assert len(traces) == 1, traces
    return traces[0]


FIXTURE_CASES = [
    (
        "01-index-out-of-range.txt",
        "runtime error: index out of range [3] with length 3",
        "/src/programs/go/index_out_of_range.go",
        [("main.pick", 10), ("main.last", 14), ("main.main", 18)],
    ),
    (
        "02-nil-map.txt",
        "assignment to entry in nil map",
        "/src/programs/go/nil_map.go",
        [("main.(*registry).add", 12), ("main.register", 17), ("main.main", 22)],
    ),
]


@pytest.mark.parametrize(("name", "message", "path", "frames"), FIXTURE_CASES)
def test_single_goroutine_fixture(name, message, path, frames):
    text = _load(name)
    trace = _one(text)
    data = trace.data
    # through "exit status 2" (go run's own last line)
    assert (trace.start, trace.end) == (0, len(text.rstrip("\n")))
    assert text[trace.start : trace.end].endswith("exit status 2")
    assert data.format == "go"
    assert (data.bug_type, data.message, data.thread) == ("panic", message, "goroutine 1")
    assert [(f.function, f.line) for f in data.frames] == frames
    assert all(f.path == path and not f.is_runtime for f in data.frames)
    assert data.other_stacks == ()


def test_multi_goroutine_fixture():
    text = _load("03-goroutine-panic-traceback-all.txt")
    trace = _one(text)
    data = trace.data
    assert (trace.start, trace.end) == (0, len(text.rstrip("\n")))
    assert (data.bug_type, data.message, data.thread) == (
        "panic",
        "job 3 has no owner",
        "goroutine 8",
    )
    worker, created_by = data.frames
    assert (worker.index, worker.function, worker.path, worker.line) == (
        0,
        "main.worker",
        "/src/programs/go/goroutine_panic.go",
        22,
    )
    # "created by main.main in goroutine 1" is kept as the goroutine's origin frame
    assert (created_by.function, created_by.line) == ("main.main", 30)
    assert [s.label for s in data.other_stacks] == [
        "goroutine 1 [sync.WaitGroup.Wait]",
        "goroutine 7 [runnable]",
    ]
    waiting, runnable = data.other_stacks
    assert [(f.function, f.is_runtime) for f in waiting.frames] == [
        ("sync.runtime_SemacquireWaitGroup", True),
        ("sync.(*WaitGroup).Wait", True),
        ("main.main", False),
    ]
    assert [(f.function, f.is_runtime) for f in runnable.frames] == [
        ("main.main.gowrap1", False),
        ("runtime.goexit", True),
        ("main.main", False),
    ]


def test_fixture_embedded_in_markdown_is_found_by_the_pipeline():
    trace_text = _load("03-goroutine-panic-traceback-all.txt")
    md = f"With GOTRACEBACK=all:\n\n```\n{trace_text}```\n\nThe worker has no owner check.\n"
    report = ingest_string(md, input_format="markdown")
    claims = [c for c in extract_claims(report).claims if isinstance(c, TraceClaim)]
    assert len(claims) == 1
    expected = trace_text.rstrip("\n")
    start = report.body.index(expected)
    assert (claims[0].spans[0].start, claims[0].spans[0].text) == (start, expected)
    assert claims[0].frames[0].function == "main.worker"
    assert len(claims[0].other_stacks) == 2


# --- variants ---------------------------------------------------------------------------


def test_fatal_error_signal_preamble_and_no_running_goroutine():
    text = (
        "fatal error: all goroutines are asleep - deadlock!\n"
        "[signal SIGSEGV: segmentation violation code=0x1 addr=0x0 pc=0x1]\n"
        "\n"
        "goroutine 1 gp=0xc000002380 m=0 mp=0x5b2f40 [chan receive]:\n"
        "main.main()\n"
        "\t/home/u/app/main.go:9 +0x2d\n"
        "...additional frames elided...\n"
        "Then some prose.\n"
    )
    trace = _one(text)
    data = trace.data
    assert (data.bug_type, data.message, data.thread) == (
        "fatal error",
        "all goroutines are asleep - deadlock!",
        "goroutine 1",
    )
    assert [(f.function, f.path) for f in data.frames] == [("main.main", "/home/u/app/main.go")]
    assert text[trace.start : trace.end].endswith("main.go:9 +0x2d")


def test_function_line_without_arguments():
    text = "panic: x\n\ngoroutine 1 [running]:\nmain.f\n\t/a.go:3\n"
    assert _one(text).data.frames[0].function == "main.f"


@pytest.mark.parametrize(
    ("function", "path", "runtime"),
    [
        ("runtime/debug.Stack", "/x/y.go", True),
        ("net/http.(*conn).serve", "/usr/local/go/src/net/http/server.go", True),
        ("main.main", "/root/go/pkg/mod/golang.org/toolchain@v0.0.1/src/x.go", True),
        ("main.main", "/src/app/main.go", False),
        (None, None, False),
    ],
)
def test_goroot_detection(function, path, runtime):
    assert go_panic.is_goroot_frame(function, path) is runtime


@pytest.mark.parametrize(
    "text",
    [
        "Don't panic: it is fine.\n",  # no goroutine dump follows
        "panic: x\n\ngoroutine 1 [running]:\nmain.f()\n\tnot-a-location\n",
    ],
)
def test_prose_and_broken_dumps(text):
    for trace in PARSER.parse(text):
        assert trace.data.frames == ()


# --- robustness -------------------------------------------------------------------------

ALL_LINES = [line for p in sorted(FIXTURES.glob("*.txt")) for line in p.read_text().splitlines()]


@pytest.mark.parametrize("name", sorted(p.name for p in FIXTURES.glob("*.txt")))
def test_every_truncation_parses(name):
    lines = _load(name).splitlines(keepends=True)
    for n in range(len(lines) + 1):
        text = "".join(lines[:n])
        for trace in PARSER.parse(text):
            assert 0 <= trace.start < trace.end <= len(text)
    assert _one("".join(lines[:5])).data.frames[0].function.startswith("main.")


@pytest.mark.parametrize("text", ["", "panic:", "goroutine 1 [running]:\n", "panic: \n\ngoroutine"])
def test_garbage_does_not_raise(text):
    for trace in PARSER.parse(text):
        assert 0 <= trace.start <= trace.end <= len(text)


def _check(text: str) -> None:
    for parse in (PARSER.parse, go_panic._parse):
        for trace in parse(text):
            assert 0 <= trace.start <= trace.end <= len(text)


@given(st.text())
def test_hypothesis_random_text(text):
    _check(text)


@settings(max_examples=200)
@given(st.lists(st.one_of(st.sampled_from(ALL_LINES), st.text(max_size=30)), max_size=40))
def test_hypothesis_shuffled_report_lines(lines):
    _check("\n".join(lines))
