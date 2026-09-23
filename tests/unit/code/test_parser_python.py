# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Python: functions, classes, methods, nested functions and calls (SPEC §11.2)."""

from __future__ import annotations

from code_helpers import assert_clean, calls, flags, parse_fixture, symbols

from nikasha.code.languages import Lang
from nikasha.code.parser import parse_file

FACTS = parse_fixture(Lang.PYTHON, "python/sample.py")


def test_parses_cleanly():
    assert_clean(FACTS)
    assert FACTS.n_lines == 38


def test_symbols():
    assert symbols(FACTS) == [
        ("function", "load", "load", 6, 8),
        ("class", "Store", "Store", 11, 29),
        ("method", "__init__", "Store.__init__", 14, 15),
        # A decorated method's span starts at `def` (the decorator is on line 17).
        ("method", "size", "Store.size", 18, 19),
        ("method", "fetch", "Store.fetch", 21, 25),
        ("function", "pick", "Store.fetch.pick", 22, 23),
        ("class", "Meta", "Store.Meta", 27, 29),
        ("method", "describe", "Store.Meta.describe", 28, 29),
        ("function", "main", "main", 32, 35),
    ]
    assert flags(FACTS, "Store.fetch") == {"async"}


def test_calls():
    assert calls(FACTS) == [
        ("load", "open", 7, False),
        ("load", "load", 8, True),  # json.load: attribute call, last attribute name
        ("Store.__init__", "load", 15, False),
        ("Store.size", "len", 19, False),
        ("Store.fetch.pick", "get", 23, True),
        ("Store.fetch", "pick", 25, False),
        ("Store.Meta.describe", "repr", 29, False),
        ("main", "Store", 33, False),
        ("main", "print", 34, False),
        ("main", "fetch", 35, True),
        (None, "main", 38, False),
    ]


def test_enclosing_prefers_innermost():
    inner = FACTS.enclosing(23)
    assert inner is not None
    assert inner.qname == "Store.fetch.pick"


def test_chained_calls_in_source_order():
    facts = parse_file(Lang.PYTHON, b"def f(x):\n    return x.strip().lower().split(sep())\n")
    assert calls(facts) == [
        ("f", "strip", 2, True),
        ("f", "lower", 2, True),
        ("f", "split", 2, True),
        ("f", "sep", 2, False),
    ]


def test_syntax_error_is_partial_not_fatal():
    facts = parse_file(Lang.PYTHON, b"def ok():\n    run()\n\ndef broken(:\n    pass\n")
    assert not facts.parsed_ok
    assert facts.error_nodes >= 1
    assert ("function", "ok", "ok", 1, 2) in symbols(facts)
    assert ("ok", "run", 2, False) in calls(facts)
