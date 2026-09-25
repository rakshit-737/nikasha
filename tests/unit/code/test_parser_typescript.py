# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""TypeScript and TSX: JavaScript's definitions plus interfaces, types and enums (§11.2)."""

from __future__ import annotations

from code_helpers import assert_clean, calls, flags, parse_fixture, symbols

from nikasha.code.languages import Lang
from nikasha.code.parser import parse_file

FACTS = parse_fixture(Lang.TYPESCRIPT, "typescript/sample.ts")
TSX = parse_fixture(Lang.TSX, "typescript/sample.tsx")


def test_parses_cleanly() -> None:
    assert_clean(FACTS)
    assert_clean(TSX)
    assert TSX.lang == "tsx"


def test_symbols() -> None:
    assert symbols(FACTS) == [
        ("type", "Token", "Token", 3, 6),
        ("type", "Kind", "Kind", 8, 8),
        ("type", "Level", "Level", 10, 13),
        ("function", "tokenize", "tokenize", 15, 17),
        ("function", "toToken", "toToken", 19, 19),
        ("class", "Lexer", "Lexer", 21, 34),
        ("method", "constructor", "Lexer.constructor", 24, 24),
        ("method", "next", "Lexer.next", 26, 29),
        ("method", "create", "Lexer.create", 31, 33),
    ]
    assert flags(FACTS, "Lexer.create") == {"static"}


def test_calls() -> None:
    assert calls(FACTS) == [
        ("tokenize", "split", 16, True),
        ("tokenize", "map", 16, True),
        ("toToken", "classify", 19, False),
        ("Lexer.next", "tokenize", 27, False),
        ("Lexer.create", "Lexer", 32, False),  # `new Lexer(src)`
    ]


def test_tsx() -> None:
    assert symbols(TSX) == [
        ("type", "Props", "Props", 5, 5),
        ("function", "Greeting", "Greeting", 7, 9),
        ("function", "Panel", "Panel", 11, 14),
    ]
    # JSX elements (`<Greeting />`) are not calls.
    assert calls(TSX) == [("Greeting", "formatName", 8, False), ("Panel", "trim", 12, True)]


def test_namespace_and_abstract_class() -> None:
    src = b"""namespace Geo {
  export abstract class Shape {
    abstract area(): number;
    describe(): string { return fmt(this.area()); }
  }
}
"""
    facts = parse_file(Lang.TYPESCRIPT, src)
    assert symbols(facts) == [
        ("module", "Geo", "Geo", 1, 6),
        ("class", "Shape", "Geo.Shape", 2, 5),
        ("method", "describe", "Geo.Shape.describe", 4, 4),
    ]
    assert calls(facts) == [
        ("Geo.Shape.describe", "fmt", 4, False),
        ("Geo.Shape.describe", "area", 4, True),
    ]
