# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Java: classes, interfaces, enums, methods, constructors and invocations (§11.2)."""

from __future__ import annotations

from code_helpers import assert_clean, calls, flags, parse_fixture, symbols

from nikasha.code.languages import Lang

FACTS = parse_fixture(Lang.JAVA, "java/Sample.java")


def test_parses_cleanly():
    assert_clean(FACTS)


def test_symbols():
    assert symbols(FACTS) == [
        ("class", "Sample", "Sample", 8, 42),
        ("method", "Sample", "Sample.Sample", 11, 13),
        ("method", "add", "Sample.add", 15, 17),
        ("method", "normalize", "Sample.normalize", 19, 21),
        # `void visit(String item);` in the interface has no body: not a definition.
        ("type", "Visitor", "Sample.Visitor", 23, 25),
        ("type", "Kind", "Sample.Kind", 27, 34),
        ("method", "isA", "Sample.Kind.isA", 31, 33),
        ("class", "Walker", "Sample.Walker", 36, 41),
        ("method", "visit", "Sample.Walker.visit", 37, 40),
    ]
    assert flags(FACTS, "Sample.Sample") == {"constructor"}
    assert flags(FACTS, "Sample.normalize") == {"static"}


def test_calls():
    assert calls(FACTS) == [
        ("Sample.Sample", "ArrayList", 12, False),  # `new ArrayList<>()`
        ("Sample.add", "add", 16, True),
        ("Sample.add", "normalize", 16, False),
        ("Sample.normalize", "trim", 20, True),
        ("Sample.normalize", "toLowerCase", 20, True),
        ("Sample.Walker.visit", "println", 39, True),
    ]
