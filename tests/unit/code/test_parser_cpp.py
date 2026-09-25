# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""C++: namespaces, classes, methods (inline and out-of-line), templates (SPEC §11.2)."""

from __future__ import annotations

from code_helpers import assert_clean, calls, flags, parse_fixture, symbols

from nikasha.code.facts import MacroDef
from nikasha.code.languages import Lang
from nikasha.code.parser import parse_file

FACTS = parse_fixture(Lang.CPP, "cpp/sample.cpp")


def test_parses_cleanly() -> None:
    assert_clean(FACTS)
    assert FACTS.lang == "cpp"


def test_symbols() -> None:
    assert symbols(FACTS) == [
        ("macro", "CHECK", "CHECK", 6, 6),
        ("module", "net", "net", 8, 36),
        ("module", "wire", "net::wire", 9, 32),
        ("class", "Header", "net::wire::Header", 11, 13),
        ("class", "Reader", "net::wire::Reader", 15, 24),
        ("method", "Reader", "net::wire::Reader::Reader", 17, 17),
        ("method", "next", "net::wire::Reader::next", 18, 18),
        # The template's span starts at its `template <typename T>` line.
        ("function", "clamp", "net::wire::clamp", 26, 30),
        # Out-of-line definitions keep their written qualifier.
        ("method", "peek", "net::wire::Reader::peek", 38, 42),
        ("method", "~Reader", "net::wire::Reader::~Reader", 44, 47),
        ("function", "on_event", "on_event", 49, 52),
        ("function", "run", "run", 54, 61),
    ]


def test_declarations_in_class_body_are_not_definitions() -> None:
    # `int peek() const;` and `~Reader();` are declared at lines 19-20, defined out of line.
    assert [s.start_line for s in FACTS.definitions("peek")] == [38]
    assert FACTS.definitions("Reader_helper") == []


def test_calls() -> None:
    assert calls(FACTS) == [
        ("net::wire::Reader::next", "decode", 18, False),
        ("net::wire::Reader::peek", "CHECK", 40, False),
        ("net::wire::Reader::peek", "decode", 41, False),
        # Qualified calls are direct; the callee is the last component.
        ("net::wire::Reader::~Reader", "memset", 46, False),
        ("run", "push_back", 57, True),
        ("run", "next", 57, True),
        ("run", "clamp", 58, False),
        ("run", "peek", 58, True),
        ("run", "cb", 59, False),
    ]


def test_macros_and_address_taken() -> None:
    assert FACTS.macros == (MacroDef(name="CHECK", line=6, calls=("fail_hard",)),)
    assert FACTS.addr_taken == {"on_event"}
    assert flags(FACTS, "on_event") == {"static"}


def test_namespace_function_defined_out_of_line_stays_a_function() -> None:
    src = b"namespace util {\nint twice(int);\n}\nint util::twice(int x)\n{\n    return x * 2;\n}\n"
    facts = parse_file(Lang.CPP, src)
    assert symbols(facts) == [
        ("module", "util", "util", 1, 3),
        ("function", "twice", "util::twice", 4, 7),
    ]


def test_template_class_members_and_operators() -> None:
    src = b"""template <typename T>
struct Box {
    T get() const { return value; }
    bool operator<(const Box &o) const { return value < o.value; }
    T value;
};

template <typename T>
void Box<T>::set(T v) { value = std::move(v); }
"""
    facts = parse_file(Lang.CPP, src)
    assert symbols(facts) == [
        ("class", "Box", "Box", 1, 6),
        ("method", "get", "Box::get", 3, 3),
        ("method", "operator<", "Box::operator<", 4, 4),
        ("method", "set", "Box::set", 8, 9),
    ]
    assert calls(facts) == [("Box::set", "move", 9, False)]


def test_member_call_through_qualified_name_is_direct() -> None:
    facts = parse_file(Lang.CPP, b"void f(D &d) { d.Base::run(); d.go(); }\n")
    assert calls(facts) == [("f", "run", 1, False), ("f", "go", 1, True)]
