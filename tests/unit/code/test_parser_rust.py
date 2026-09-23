# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Rust: fn items, impl/trait methods, macro_rules!, types, modules and calls (§11.2)."""

from __future__ import annotations

from code_helpers import assert_clean, calls, parse_fixture, symbols

from nikasha.code.facts import MacroDef
from nikasha.code.languages import Lang
from nikasha.code.parser import parse_file

FACTS = parse_fixture(Lang.RUST, "rust/sample.rs")


def test_parses_cleanly():
    assert_clean(FACTS)


def test_symbols():
    assert symbols(FACTS) == [
        ("macro", "bail", "bail", 5, 9),
        ("type", "Cache", "Cache", 11, 13),
        ("type", "Mode", "Mode", 15, 18),
        ("type", "Store", "Store", 20, 25),
        # A trait's provided method; `fn get` (line 21) has no body and is not a definition.
        ("method", "has", "Store::has", 22, 24),
        ("method", "new", "Cache::new", 28, 30),
        ("method", "put", "Cache::put", 32, 34),
        ("function", "make_error", "make_error", 37, 39),
        ("function", "run", "run", 41, 48),
        ("module", "util", "util", 50, 54),
        ("function", "helper", "util::helper", 51, 53),
    ]


def test_calls():
    assert calls(FACTS) == [
        ("Store::has", "get", 23, True),
        ("Store::has", "is_some", 23, True),
        ("Cache::new", "new", 29, False),  # HashMap::new(): qualified, direct
        ("Cache::put", "insert", 33, True),
        ("make_error", "to_string", 38, True),
        ("run", "is_empty", 42, True),
        # `bail!` and `println!` are macro invocations, not calls; a call written in a
        # macro's arguments is.
        ("run", "checksum", 45, False),
        ("run", "parse_num", 46, False),
        ("run", "Ok", 47, False),
        ("util::helper", "make_error", 52, False),
        ("util::helper", "len", 52, True),
    ]


def test_macro_rules_body_calls():
    assert FACTS.macros == (MacroDef(name="bail", line=5, calls=("Err", "make_error")),)


def test_trait_impl_for_generic_type():
    src = (
        b"impl<T: Clone> fmt::Display for Wrapper<T> {\n"
        b"    fn fmt(&self) -> u8 {\n        self.0.render()\n    }\n}\n"
    )
    facts = parse_file(Lang.RUST, src)
    assert symbols(facts) == [("method", "fmt", "Wrapper::fmt", 2, 4)]
    assert calls(facts) == [("Wrapper::fmt", "render", 3, True)]


def test_method_call_inside_macro_arguments_is_indirect():
    src = b'fn f(v: &V) {\n    assert!(v.check(1), "bad");\n    vec![build(2)];\n}\n'
    facts = parse_file(Lang.RUST, src)
    assert calls(facts) == [("f", "check", 2, True), ("f", "build", 3, False)]
