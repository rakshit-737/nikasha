# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""JavaScript: functions, bound arrows, classes, methods and calls (SPEC §11.2)."""

from __future__ import annotations

from code_helpers import assert_clean, calls, parse_fixture, symbols

from nikasha.code.languages import Lang
from nikasha.code.parser import parse_file

FACTS = parse_fixture(Lang.JAVASCRIPT, "javascript/sample.js")


def test_parses_cleanly() -> None:
    assert_clean(FACTS)


def test_symbols() -> None:
    assert symbols(FACTS) == [
        ("function", "parseQuery", "parseQuery", 5, 7),
        ("function", "decodePair", "decodePair", 9, 12),
        ("function", "legacy", "legacy", 14, 16),
        ("class", "Router", "Router", 18, 31),
        ("method", "constructor", "Router.constructor", 19, 21),
        ("method", "match", "Router.match", 23, 26),
        ("method", "handle", "Router.handle", 28, 30),
        ("method", "wrap", "helpers.wrap", 34, 36),
        ("method", "twice", "helpers.twice", 37, 37),
    ]


def test_calls() -> None:
    assert calls(FACTS) == [
        ("parseQuery", "split", 6, True),
        ("parseQuery", "map", 6, True),
        ("decodePair", "split", 10, True),
        ("decodePair", "decodeURIComponent", 11, False),
        ("legacy", "parseQuery", 15, False),
        ("Router.match", "parseQuery", 24, False),
        ("Router.match", "lookup", 25, True),
        ("Router.handle", "match", 29, True),
        ("helpers.wrap", "fn", 35, False),
        ("helpers.twice", "double", 37, False),
        ("helpers.twice", "double", 37, False),
        (None, "Router", 40, False),  # `new Router([])`
    ]


def test_nested_functions_and_callbacks() -> None:
    src = b"""function outer() {
  function inner() { return helper(); }
  [1, 2].forEach(function (x) { log(x); });
  return inner();
}
exports.make = function () { return outer(); };
"""
    facts = parse_file(Lang.JAVASCRIPT, src)
    assert symbols(facts) == [
        ("function", "outer", "outer", 1, 5),
        ("function", "inner", "outer.inner", 2, 2),
        ("function", "make", "make", 6, 6),
    ]
    assert calls(facts) == [
        ("outer.inner", "helper", 2, False),
        ("outer", "forEach", 3, True),
        ("outer", "log", 3, False),  # anonymous callbacks belong to their named enclosure
        ("outer", "inner", 4, False),
        ("make", "outer", 6, False),
    ]


def test_jsx_file_parses() -> None:
    facts = parse_file(Lang.JAVASCRIPT, b"const App = () => <div>{render(1)}</div>;\n")
    assert_clean(facts)
    assert calls(facts) == [("App", "render", 1, False)]
