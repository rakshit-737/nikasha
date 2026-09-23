# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Python traceback parser: real fixtures (chains, caret lines), variants, robustness."""

from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from nikasha.extract import extract_claims
from nikasha.extract.traces import PARSERS, python_tb
from nikasha.ingest import ingest_string
from nikasha.model.claims import TraceClaim

FIXTURES = Path(__file__).parents[2] / "fixtures" / "traces" / "python"
PARSER = PARSERS["python"]


def _load(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def _one(text: str):
    traces = PARSER.parse(text)
    assert len(traces) == 1, traces
    return traces[0]


def _where(frames):
    return [(f.function, f.line) for f in frames]


def test_zero_division():
    text = _load("01-zero-division.txt")
    trace = _one(text)
    data = trace.data
    assert (trace.start, trace.end) == (0, len(text.rstrip("\n")))
    assert data.format == "python"
    assert (data.bug_type, data.message) == ("ZeroDivisionError", "division by zero")
    # innermost first: index 0 is the frame that raised
    assert _where(data.frames) == [
        ("divide", 7),
        ("success_rate", 11),
        ("main", 15),
        ("<module>", 19),
    ]
    assert [f.index for f in data.frames] == [0, 1, 2, 3]
    assert all(f.path == "/src/programs/python/zero_division.py" for f in data.frames)
    assert not any(f.is_runtime for f in data.frames)
    assert data.other_stacks == ()


def test_chained_context():
    text = _load("02-chained-exception.txt")
    trace = _one(text)
    data = trace.data
    assert (trace.start, trace.end) == (0, len(text.rstrip("\n")))
    assert (data.bug_type, data.message) == ("ValueError", "timeout is not configured")
    assert _where(data.frames) == [("read_timeout", 16), ("main", 20), ("<module>", 24)]
    assert data.frames[0].path == "/src/programs/python/chained_exception.py"
    assert len(data.other_stacks) == 1
    context = data.other_stacks[0]
    assert context.label == "context: KeyError"
    assert _where(context.frames) == [("lookup", 9), ("read_timeout", 14)]


def test_chained_cause_through_stdlib():
    text = _load("03-stdlib-json-cause.txt")
    trace = _one(text)
    data = trace.data
    assert (trace.start, trace.end) == (0, len(text.rstrip("\n")))
    assert (data.bug_type, data.message) == ("ConfigError", "config is not valid JSON")
    assert _where(data.frames) == [
        ("parse_config", 17),
        ("load", 21),
        ("main", 25),
        ("<module>", 29),
    ]
    cause = data.other_stacks[0]
    assert cause.label == "cause: json.decoder.JSONDecodeError"
    assert _where(cause.frames) == [
        ("raw_decode", 361),
        ("decode", 345),
        ("loads", 352),
        ("parse_config", 15),
    ]
    # /usr/lib64/python3.14/json/… is the interpreter's own library
    assert [f.is_runtime for f in cause.frames] == [True, True, True, False]
    assert cause.frames[0].path == "/usr/lib64/python3.14/json/decoder.py"


def test_fixture_embedded_in_markdown_is_found_by_the_pipeline():
    trace_text = _load("02-chained-exception.txt")
    md = f"Steps: run it.\n\n```python\n{trace_text}```\n\nExpected: a default timeout.\n"
    report = ingest_string(md, input_format="markdown")
    claims = [c for c in extract_claims(report).claims if isinstance(c, TraceClaim)]
    assert len(claims) == 1
    expected = trace_text.rstrip("\n")
    start = report.body.index(expected)
    assert (claims[0].spans[0].start, claims[0].spans[0].text) == (start, expected)
    assert claims[0].frames[0].function == "read_timeout"
    assert claims[0].other_stacks[0].label == "context: KeyError"


# --- variants ---------------------------------------------------------------------------


def test_indented_traceback_three_link_chain_and_trailing_prose():
    text = (
        "Some log line\n"
        "    Traceback (most recent call last):\n"
        '      File "a.py", line 1, in f\n'
        "    OSError: disk\n"
        "\n"
        "    The above exception was the direct cause of the following exception:\n"
        "\n"
        "    Traceback (most recent call last):\n"
        '      File "b.py", line 2, in g\n'
        "        [Previous line repeated 996 more times]\n"
        "    RuntimeError\n"
        "\n"
        "    During handling of the above exception, another exception occurred:\n"
        "\n"
        "    Traceback (most recent call last):\n"
        '      File "<frozen importlib._bootstrap>", line 3, in _load\n'
        '      File "/venv/lib/python3.12/site-packages/lib/x.py", line 4\n'
        "    pkg.CustomError: it: broke\n"
        "That was the trace.\n"
    )
    trace = _one(text)
    data = trace.data
    assert text[trace.start : trace.end].startswith("    Traceback")
    assert text[trace.start : trace.end].endswith("pkg.CustomError: it: broke")
    assert (data.bug_type, data.message) == ("pkg.CustomError", "it: broke")
    assert [s.label for s in data.other_stacks] == ["cause: OSError", "context: RuntimeError"]
    assert data.other_stacks[1].frames[0].function == "g"
    site, frozen = data.frames
    assert (site.function, site.line, site.is_runtime) == (None, 4, False)
    assert frozen.is_runtime


def test_truncated_without_exception_line_and_header_only():
    text = 'Traceback (most recent call last):\n  File "a.py", line 1, in f\n    f()\n'
    trace = _one(text)
    assert trace.data.bug_type is None
    assert text[trace.start : trace.end].endswith("line 1, in f")
    assert PARSER.parse("Traceback (most recent call last):\nnothing\n") == []


def test_marker_without_following_traceback_ends_chain():
    text = (
        "Traceback (most recent call last):\n"
        '  File "a.py", line 1, in f\n'
        "KeyError: 'x'\n"
        "\n"
        "During handling of the above exception, another exception occurred:\n"
        "\n"
        "(output truncated)\n"
    )
    trace = _one(text)
    assert trace.data.bug_type == "KeyError"
    assert text[trace.start : trace.end].endswith("KeyError: 'x'")


@pytest.mark.parametrize(
    ("path", "stdlib"),
    [
        ("/usr/lib/python3.11/json/decoder.py", True),
        ("/usr/lib64/python3/os.py", True),
        ("/Python312/Lib/json/decoder.py", True),
        ("/usr/lib/python3.11/site-packages/requests/api.py", False),
        ("/usr/lib/python3/dist-packages/yaml/x.py", False),
        ("<frozen runpy>", True),
        ("/src/app/main.py", False),
        (None, False),
    ],
)
def test_is_stdlib_path(path, stdlib):
    assert python_tb.is_stdlib_path(path) is stdlib


# --- robustness -------------------------------------------------------------------------

ALL_LINES = [line for p in sorted(FIXTURES.glob("*.txt")) for line in p.read_text().splitlines()]


@pytest.mark.parametrize("name", sorted(p.name for p in FIXTURES.glob("*.txt")))
def test_every_truncation_parses(name):
    lines = _load(name).splitlines(keepends=True)
    for n in range(len(lines) + 1):
        text = "".join(lines[:n])
        for trace in PARSER.parse(text):
            assert 0 <= trace.start < trace.end <= len(text)
            assert trace.data.frames
    assert _one("".join(lines[:5])).data.frames


@pytest.mark.parametrize("text", ["", "Traceback (most recent call last):", '  File "', "\t\n\t"])
def test_garbage_does_not_raise(text):
    assert PARSER.parse(text) == []


def _check(text: str) -> None:
    for parse in (PARSER.parse, python_tb._parse):
        for trace in parse(text):
            assert 0 <= trace.start <= trace.end <= len(text)


@given(st.text())
def test_hypothesis_random_text(text):
    _check(text)


@settings(max_examples=200)
@given(st.lists(st.one_of(st.sampled_from(ALL_LINES), st.text(max_size=30)), max_size=40))
def test_hypothesis_shuffled_report_lines(lines):
    _check("\n".join(lines))
