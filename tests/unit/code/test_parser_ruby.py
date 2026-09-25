# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Ruby: methods (Mod::Class#m), singleton methods (Mod::Class.m), classes, modules (§11.2)."""

from __future__ import annotations

from code_helpers import assert_clean, calls, flags, parse_fixture, symbols

from nikasha.code.languages import Lang
from nikasha.code.parser import parse_file

FACTS = parse_fixture(Lang.RUBY, "ruby/sample.rb")


def test_parses_cleanly() -> None:
    assert_clean(FACTS)


def test_symbols() -> None:
    assert symbols(FACTS) == [
        ("module", "Billing", "Billing", 5, 31),
        ("class", "Invoice", "Billing::Invoice", 6, 26),
        ("method", "initialize", "Billing::Invoice#initialize", 9, 11),
        ("method", "parse", "Billing::Invoice.parse", 13, 15),
        ("method", "to_s", "Billing::Invoice#to_s", 17, 19),
        ("method", "sum", "Billing::Invoice#sum", 23, 25),
        ("method", "version", "Billing.version", 28, 30),
        ("function", "helper", "helper", 33, 35),
    ]
    assert flags(FACTS, "Billing::Invoice.parse") == {"singleton"}


def test_calls() -> None:
    assert calls(FACTS) == [
        (None, "require", 3, False),
        (None, "attr_reader", 7, False),
        ("Billing::Invoice#initialize", "sum", 10, False),
        ("Billing::Invoice.parse", "new", 14, False),
        ("Billing::Invoice.parse", "parse", 14, True),
        ("Billing::Invoice#to_s", "format", 18, False),
        ("Billing::Invoice#sum", "map", 24, True),
        ("Billing::Invoice#sum", "fetch", 24, True),
        ("Billing::Invoice#sum", "sum", 24, True),
        ("helper", "puts", 34, False),
        ("helper", "parse", 34, True),
    ]


def test_compact_class_name() -> None:
    src = b"class Api::V1::Users\n  def index\n    render json: all\n  end\nend\n"
    facts = parse_file(Lang.RUBY, src)
    assert symbols(facts) == [
        ("class", "Users", "Api::V1::Users", 1, 5),
        ("method", "index", "Api::V1::Users#index", 2, 4),
    ]
    assert calls(facts) == [("Api::V1::Users#index", "render", 3, False)]
