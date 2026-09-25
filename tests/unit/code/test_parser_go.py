# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Go: functions, methods with receivers ((*T).M / T.M), types and calls (SPEC §11.2)."""

from __future__ import annotations

from code_helpers import assert_clean, calls, parse_fixture, symbols

from nikasha.code.languages import Lang
from nikasha.code.parser import parse_file

FACTS = parse_fixture(Lang.GO, "go/sample.go")


def test_parses_cleanly() -> None:
    assert_clean(FACTS)


def test_symbols() -> None:
    assert symbols(FACTS) == [
        ("type", "Buffer", "Buffer", 7, 10),
        ("type", "Sizer", "Sizer", 12, 14),
        ("function", "New", "New", 16, 18),
        ("method", "Push", "(*Buffer).Push", 20, 23),
        ("method", "Size", "Buffer.Size", 25, 27),
        ("function", "wrap", "wrap", 29, 34),
        ("function", "Dump", "Dump", 36, 39),
    ]


def test_calls() -> None:
    assert calls(FACTS) == [
        ("New", "make", 17, False),
        ("(*Buffer).Push", "wrap", 22, False),
        ("(*Buffer).Push", "len", 22, False),
        ("Buffer.Size", "len", 26, False),
        # Selector calls record the method name and are indirect; calls in a func
        # literal belong to the enclosing function.
        ("Dump", "Println", 37, True),
        ("Dump", "Size", 37, True),
        ("Dump", "show", 38, False),
    ]


def test_generic_receiver() -> None:
    src = b"package s\n\nfunc (s *Stack[T]) Push(v T) {\n\ts.items = append(s.items, v)\n}\n"
    facts = parse_file(Lang.GO, src)
    assert symbols(facts) == [("method", "Push", "(*Stack).Push", 3, 5)]
    assert calls(facts) == [("(*Stack).Push", "append", 4, False)]
