# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Java stack-trace parser: real fixtures (Caused by), variants, embedding, robustness."""

from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from nikasha.extract import extract_claims
from nikasha.extract.traces import PARSERS, java
from nikasha.ingest import ingest_string
from nikasha.model.claims import TraceClaim

FIXTURES = Path(__file__).parents[2] / "fixtures" / "traces" / "java"
PARSER = PARSERS["java"]


def _load(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def _one(text: str):
    traces = PARSER.parse(text)
    assert len(traces) == 1, traces
    return traces[0]


FIXTURE_CASES = [
    (
        "01-null-pointer.txt",
        "java.lang.NullPointerException",
        'Cannot invoke "String.length()" because "<parameter1>.user" is null',
        [("NullField.nameLength", 10), ("NullField.describe", 14), ("NullField.main", 18)],
        "NullField.java",
    ),
    (
        "02-array-index.txt",
        "java.lang.ArrayIndexOutOfBoundsException",
        "Index 3 out of bounds for length 3",
        [
            ("IndexOutOfBounds.pick", 6),
            ("IndexOutOfBounds.last", 10),
            ("IndexOutOfBounds.summarize", 14),
            ("IndexOutOfBounds.main", 18),
        ],
        "IndexOutOfBounds.java",
    ),
    (
        "03-caused-by.txt",
        "CausedBy$StorageException",
        "bad port setting",
        [("CausedBy.readPort", 19), ("CausedBy.start", 24), ("CausedBy.main", 28)],
        "CausedBy.java",
    ),
]


@pytest.mark.parametrize(("name", "bug_type", "message", "frames", "path"), FIXTURE_CASES)
def test_fixture(name, bug_type, message, frames, path):
    text = _load(name)
    trace = _one(text)
    data = trace.data
    assert (trace.start, trace.end) == (0, len(text.rstrip("\n")))
    assert data.format == "java"
    assert (data.bug_type, data.message, data.thread) == (bug_type, message, "main")
    assert [(f.function, f.line) for f in data.frames] == frames
    assert all(f.path == path and f.module is None and not f.is_runtime for f in data.frames)
    assert [f.index for f in data.frames] == list(range(len(frames)))


def test_caused_by_stack() -> None:
    data = _one(_load("03-caused-by.txt")).data
    assert len(data.other_stacks) == 1
    cause = data.other_stacks[0]
    assert cause.label == "caused by: java.lang.NumberFormatException"
    assert len(cause.frames) == 12
    first = cause.frames[0]
    assert (first.function, first.path, first.line, first.module, first.is_runtime) == (
        "NumberFormatException.forInputString",
        "java/lang/NumberFormatException.java",
        67,
        "java.base",
        True,
    )
    app = next(f for f in cause.frames if not f.is_runtime)
    assert (app.index, app.function, app.path, app.line) == (
        3,
        "CausedBy.parsePort",
        "CausedBy.java",
        12,
    )
    launcher = cause.frames[-1]
    assert (launcher.module, launcher.path, launcher.is_runtime) == (
        "jdk.compiler",
        "com/sun/tools/javac/launcher/SourceLauncher.java",
        True,
    )


def test_fixture_embedded_in_markdown_is_found_by_the_pipeline() -> None:
    trace_text = _load("01-null-pointer.txt")
    md = f"When the user is missing:\n\n```java\n{trace_text}```\n\nThe NPE leaks the parameter.\n"
    report = ingest_string(md, input_format="markdown")
    claims = [c for c in extract_claims(report).claims if isinstance(c, TraceClaim)]
    assert len(claims) == 1
    expected = trace_text.rstrip("\n")
    start = report.body.index(expected)
    assert (claims[0].spans[0].start, claims[0].spans[0].text) == (start, expected)
    assert claims[0].frames[0].function == "NullField.nameLength"


# --- variants ---------------------------------------------------------------------------

BARE = """\
Log: request failed
java.lang.IllegalStateException: boom
\tat app//com.example.Service.handle(Service.java:42)
\tat java.base@17.0.2/java.lang.Thread.run(Thread.java:833)
\tat com.example.Native.call(Native Method)
\tat com.example.Gen$$Lambda$14/0x0000000800c1840.accept(Unknown Source)
\tat com.example.Outer$Inner.<init>(Outer.java)
\tSuppressed: java.io.IOException: close failed
\t\tat com.example.Res.close(Res.java:7)
\t\t... 2 more
Caused by: java.lang.RuntimeException
\tat com.example.Service.inner(Service.java:50)
\t... 1 more
Next log line
"""


def test_bare_header_suppressed_and_frame_shapes() -> None:
    trace = _one(BARE)
    data = trace.data
    assert BARE[trace.start : trace.end].startswith("java.lang.IllegalStateException: boom")
    assert BARE[trace.start : trace.end].endswith("... 1 more")
    assert (data.bug_type, data.message, data.thread) == (
        "java.lang.IllegalStateException",
        "boom",
        None,
    )
    service, thread, native, lam, inner = data.frames
    assert (service.function, service.path, service.module, service.is_runtime) == (
        "Service.handle",
        "com/example/Service.java",
        None,
        False,
    )
    assert (thread.module, thread.is_runtime, thread.function) == ("java.base", True, "Thread.run")
    assert (native.path, native.line) == (None, None)
    assert (lam.path, lam.module) == (None, None)
    assert (inner.function, inner.path, inner.line) == (
        "Outer$Inner.<init>",
        "com/example/Outer.java",
        None,
    )
    assert [s.label for s in data.other_stacks] == [
        "suppressed: java.io.IOException",
        "caused by: java.lang.RuntimeException",
    ]
    assert data.other_stacks[1].frames[0].function == "Service.inner"


@pytest.mark.parametrize(
    "text",
    [
        "IllegalStateException: boom\nnext\n",  # no frame follows
        "not a type!: boom\n\tat a.B.c(B.java:1)\n",  # not a class name
        "foo: bar\n\tat a.B.c(B.java:1)\n",  # bare lowercase word is not a throwable
        'Exception in thread "main" 12: x\n\tat a.B.c(B.java:1)\n',
        "\tat userName (/src/x.js:7:23)\n",  # a Node frame
    ],
)
def test_non_java_headers(text):
    assert PARSER.parse(text) == []


def test_split_header_and_bare_type() -> None:
    assert java.split_header("java.lang.Error") == ("java.lang.Error", None)
    assert java.split_header("MyError:") == ("MyError", None)
    trace = _one("MyError: x\n\tat Foo.bar(Foo.java:3)\n")
    assert trace.data.frames[0].path == "Foo.java"
    assert PARSER.parse("MyError: x\n\tat bar(Foo.java:3)\n") == []  # no Class.method


# --- robustness -------------------------------------------------------------------------

ALL_LINES = [line for p in sorted(FIXTURES.glob("*.txt")) for line in p.read_text().splitlines()]
ALL_LINES += BARE.splitlines()


@pytest.mark.parametrize("name", [c[0] for c in FIXTURE_CASES])
def test_every_truncation_parses(name):
    lines = _load(name).splitlines(keepends=True)
    for n in range(len(lines) + 1):
        text = "".join(lines[:n])
        for trace in PARSER.parse(text):
            assert 0 <= trace.start < trace.end <= len(text)
    assert _one("".join(lines[:2])).data.frames[0].line is not None


@pytest.mark.parametrize("text", ["", "\tat (", 'Exception in thread "', "\tat a(b)\n"])
def test_garbage_does_not_raise(text):
    assert PARSER.parse(text) == []


def _check(text: str) -> None:
    for parse in (PARSER.parse, java._parse):
        for trace in parse(text):
            assert 0 <= trace.start <= trace.end <= len(text)


@given(st.text())
def test_hypothesis_random_text(text):
    _check(text)


@settings(max_examples=200)
@given(st.lists(st.one_of(st.sampled_from(ALL_LINES), st.text(max_size=30)), max_size=40))
def test_hypothesis_shuffled_report_lines(lines):
    _check("\n".join(lines))
