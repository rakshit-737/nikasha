# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Node.js error parser: real fixtures (source excerpt, caret, footer), variants, robustness."""

from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from nikasha.extract import extract_claims
from nikasha.extract.traces import PARSERS, node
from nikasha.ingest import ingest_string
from nikasha.model.claims import TraceClaim

FIXTURES = Path(__file__).parents[2] / "fixtures" / "traces" / "node"
PARSER = PARSERS["node"]


def _load(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def _one(text: str):
    traces = PARSER.parse(text)
    assert len(traces) == 1, traces
    return traces[0]


LOADER = [
    "Module._compile",
    "Module._extensions..js",
    "Module.load",
    "Module._load",
    "wrapModuleLoad",
    "Module.executeUserEntryPoint",
]
FIXTURE_CASES = [
    (
        "01-type-error.txt",
        "TypeError",
        "Cannot read properties of undefined (reading 'name')",
        [
            ("userName", 7, 23),
            ("greeting", 11, 21),
            ("main", 15, 15),
            ("Object.<anonymous>", 18, 1),
        ],
        LOADER,
    ),
    (
        "02-custom-error.txt",
        "ConfigError",
        "missing key: port",
        [
            ("requireKey", 15, 11),
            ("loadPort", 21, 17),
            ("main", 25, 15),
            ("Object.<anonymous>", 28, 1),
        ],
        LOADER,
    ),
    (
        "03-unhandled-rejection.txt",
        "Error",
        "record 7 not found",
        [("fetchRecord", 8, 9), ("loadProfile", 12, 18), ("main", 17, 3)],
        [],
    ),
]


@pytest.mark.parametrize(("name", "bug_type", "message", "app", "runtime"), FIXTURE_CASES)
def test_fixture(name, bug_type, message, app, runtime):
    text = _load(name)
    trace = _one(text)
    data = trace.data
    # from the "path:line" source header through the "Node.js vNN" footer
    assert (trace.start, trace.end) == (0, len(text.rstrip("\n")))
    assert text[trace.start : trace.end].endswith("Node.js v24.18.0")
    assert data.format == "node"
    assert (data.bug_type, data.message) == (bug_type, message)
    assert len(data.frames) == len(app) + len(runtime)
    path = f"/src/programs/node/{name[3:].replace('-', '_').removesuffix('.txt')}.js"
    assert [(f.function, f.line, f.col) for f in data.frames[: len(app)]] == app
    assert all(f.path == path and not f.is_runtime for f in data.frames[: len(app)])
    assert [f.function for f in data.frames[len(app) :]] == runtime
    assert all(
        f.is_runtime and f.path.startswith("node:internal/") for f in data.frames[len(app) :]
    )


def test_fixture_embedded_in_markdown_is_found_by_the_pipeline() -> None:
    trace_text = _load("03-unhandled-rejection.txt")
    md = f"Unhandled rejection:\n\n```\n{trace_text}```\n\nNo catch around fetchRecord.\n"
    report = ingest_string(md, input_format="markdown")
    claims = [c for c in extract_claims(report).claims if isinstance(c, TraceClaim)]
    assert len(claims) == 1
    expected = trace_text.rstrip("\n")
    start = report.body.index(expected)
    assert (claims[0].spans[0].start, claims[0].spans[0].text) == (start, expected)
    assert [f.function for f in claims[0].frames] == ["fetchRecord", "loadProfile", "main"]


# --- variants ---------------------------------------------------------------------------

PROPS = """\
Error [ERR_INVALID_ARG_TYPE]: The "path" argument must be of type string
    at new NodeError (node:internal/errors:405:5)
    at file:///srv/app/index.mjs:3:9
    at Array.forEach (<anonymous>)
    at eval (eval at <anonymous> (/srv/app/a.js:1:1), <anonymous>:1:1)
    at Object.openSync (node:fs:596:3) {
  code: 'ERR_INVALID_ARG_TYPE'
}

Node.js v18.19.0
trailing prose
"""


def test_error_code_property_block_and_frame_shapes() -> None:
    trace = _one(PROPS)
    data = trace.data
    assert PROPS[trace.start : trace.end].endswith("Node.js v18.19.0")
    assert (data.bug_type, data.message) == ("Error", 'The "path" argument must be of type string')
    new_err, esm, anon, ev, fs = data.frames
    assert (new_err.function, new_err.path, new_err.is_runtime) == (
        "NodeError",
        "node:internal/errors",
        True,
    )
    assert (esm.function, esm.path, esm.line, esm.col) == (None, "/srv/app/index.mjs", 3, 9)
    assert (anon.function, anon.path) == ("Array.forEach", None)
    assert ev.function == "eval"
    assert (fs.function, fs.path, fs.line, fs.is_runtime) == (
        "Object.openSync",
        "node:fs",
        596,
        True,
    )


def test_no_header_no_footer_and_prose_around() -> None:
    text = (
        "We saw this:\n"
        "Uncaught RangeError: Maximum call stack size exceeded\n"
        "    at recurse (/app/r.js:2:3)\n"
        "    at <anonymous>\n"
        "and then it stopped.\n"
    )
    trace = _one(text)
    assert text[trace.start : trace.end] == (
        "Uncaught RangeError: Maximum call stack size exceeded\n"
        "    at recurse (/app/r.js:2:3)\n"
        "    at <anonymous>"
    )
    assert trace.data.bug_type == "RangeError"
    assert trace.data.frames[1].function is None


def test_header_needs_caret_and_location() -> None:
    text = "just a line\nno caret here\n\nTypeError: x\n    at f (/a.js:1:1)\n"
    assert _one(text).start == text.index("TypeError")
    text = "not a location\n  src\n  ^\n\nTypeError: x\n    at f (/a.js:1:1)\n"
    assert _one(text).start == text.index("TypeError")


@pytest.mark.parametrize(
    "text",
    [
        "TypeError: x\n    at Foo.bar(Foo.java:1)\n",  # a Java frame
        "TypeError: x\n",
        "TypeError: x\n    at somewhere weird\n",
        "not an error line!\n    at f (/a.js:1:1)\n",
    ],
)
def test_not_node_traces(text):
    assert PARSER.parse(text) == []


# --- robustness -------------------------------------------------------------------------

ALL_LINES = [line for p in sorted(FIXTURES.glob("*.txt")) for line in p.read_text().splitlines()]
ALL_LINES += PROPS.splitlines()


@pytest.mark.parametrize("name", [c[0] for c in FIXTURE_CASES])
def test_every_truncation_parses(name):
    lines = _load(name).splitlines(keepends=True)
    for n in range(len(lines) + 1):
        text = "".join(lines[:n])
        for trace in PARSER.parse(text):
            assert 0 <= trace.start < trace.end <= len(text)
            assert trace.data.frames
    assert _one("".join(lines[:6])).data.frames[0].line is not None


@pytest.mark.parametrize("text", ["", "    at ", "E: x\n    at (", "^\n\nE: x\n    at f (a:1:2)"])
def test_garbage_does_not_raise(text):
    for trace in PARSER.parse(text):
        assert 0 <= trace.start <= trace.end <= len(text)


def _check(text: str) -> None:
    for parse in (PARSER.parse, node._parse):
        for trace in parse(text):
            assert 0 <= trace.start <= trace.end <= len(text)


@given(st.text())
def test_hypothesis_random_text(text):
    _check(text)


@settings(max_examples=200)
@given(st.lists(st.one_of(st.sampled_from(ALL_LINES), st.text(max_size=30)), max_size=40))
def test_hypothesis_shuffled_report_lines(lines):
    _check("\n".join(lines))
