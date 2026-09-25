# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""C: definitions, macros, calls and address-taken functions (SPEC §11.2)."""

from __future__ import annotations

import pytest
from code_helpers import VULNLAB, assert_clean, callees, calls, flags, parse_fixture, symbols

from nikasha.code.facts import MacroDef
from nikasha.code.languages import Lang, detect_language
from nikasha.code.parser import parse_file

FACTS = parse_fixture(Lang.C, "c/sample.c")


def test_parses_cleanly() -> None:
    assert_clean(FACTS)
    assert FACTS.lang == "c"
    assert FACTS.n_lines == 73


def test_symbols() -> None:
    assert symbols(FACTS) == [
        ("macro", "BUF_MAX", "BUF_MAX", 6, 6),
        ("macro", "CLAMP", "CLAMP", 7, 7),
        ("macro", "LOG_CALL", "LOG_CALL", 8, 9),
        ("type", "packet", "packet", 11, 14),
        ("type", "session_t", "session_t", 16, 16),
        ("type", "word", "word", 18, 21),
        ("type", "mode", "mode", 23, 23),
        ("type", "handler_fn", "handler_fn", 25, 25),
        ("type", "ops", "ops", 27, 30),
        ("function", "clamp_hi", "clamp_hi", 34, 37),
        ("function", "handle_packet", "handle_packet", 39, 45),
        ("function", "handle_close", "handle_close", 47, 49),
        ("function", "split_words", "split_words", 56, 63),
        ("function", "dispatch", "dispatch", 65, 73),
    ]


def test_prototypes_and_bodyless_structs_are_not_definitions() -> None:
    assert [s.start_line for s in FACTS.definitions("clamp_hi")] == [34]
    assert FACTS.definitions("session") == []


def test_flags() -> None:
    assert flags(FACTS, "clamp_hi") == {"static", "inline"}
    assert flags(FACTS, "handle_packet") == {"static"}
    assert flags(FACTS, "dispatch") == frozenset()
    assert flags(FACTS, "CLAMP") == {"function_like"}
    assert flags(FACTS, "BUF_MAX") == frozenset()


def test_calls() -> None:
    assert calls(FACTS) == [
        ("handle_packet", "malloc", 41, False),
        ("handle_packet", "memcpy", 42, False),
        ("handle_packet", "free", 43, False),
        ("handle_packet", "CLAMP", 44, False),
        ("split_words", "calloc", 59, False),
        ("dispatch", "on_packet", 68, True),
        ("dispatch", "fp", 69, True),
        ("dispatch", "register_handler", 70, False),
        ("dispatch", "on_close", 71, True),
    ]


def test_macros_record_calls_in_replacement_text() -> None:
    assert FACTS.macros == (
        MacroDef(name="BUF_MAX", line=6, calls=()),
        # `v` and `hi` are parameters, not calls.
        MacroDef(name="CLAMP", line=7, calls=("clamp_hi",)),
        # `fn(arg)` calls a parameter; `while (0)` is a keyword; `#fn` is stringification.
        MacroDef(name="LOG_CALL", line=8, calls=("trace_enter",)),
    )


def test_address_taken() -> None:
    # `.on_packet = handle_packet`, `register_handler(handle_packet)`, `.on_close = ...`;
    # `fallback` is a parameter used as a value, not a function of this file.
    assert FACTS.addr_taken == {"handle_packet", "handle_close"}


def test_address_taken_through_prototype_and_address_of() -> None:
    src = b"""
static void on_tick(int);
extern int later(void);
void setup(void) { install(on_tick); void *p = &later; int n = count; }
static void on_tick(int x) { (void)x; }
"""
    facts = parse_file(Lang.C, src)
    assert facts.addr_taken == {"on_tick", "later"}


def test_enclosing_uses_full_span() -> None:
    enclosing = FACTS.enclosing(57)
    assert enclosing is not None
    assert enclosing.qname == "split_words"
    assert FACTS.enclosing(52) is None


def test_function_returning_function_pointer() -> None:
    src = b"void (*lookup(const char *name))(int)\n{\n    return find(name);\n}\n"
    facts = parse_file(Lang.C, src)
    assert symbols(facts) == [("function", "lookup", "lookup", 1, 4)]
    assert calls(facts) == [("lookup", "find", 3, False)]


def test_calls_at_file_scope_have_no_caller() -> None:
    facts = parse_file(Lang.C, b"int table[] = { [0] = sizeof(int) };\nint x = init();\n")
    assert calls(facts) == [(None, "init", 2, False)]


def test_signature_hash_ignores_body_and_whitespace() -> None:
    base = parse_file(Lang.C, b"int f(int a, char *b)\n{\n    return a;\n}\n").symbols[0]
    body = parse_file(Lang.C, b"int f(int a, char *b)\n{\n    return a + 1;\n}\n").symbols[0]
    spaced = parse_file(Lang.C, b"int  f( int a,\n       char *b )\n{ return a; }\n").symbols[0]
    changed = parse_file(Lang.C, b"int f(int a, size_t b)\n{\n    return a;\n}\n").symbols[0]
    assert len(base.signature_hash) == 16
    assert base.signature_hash == body.signature_hash
    assert changed.signature_hash != base.signature_hash
    # Whitespace inside the declaration is collapsed, not removed: `( int` still differs.
    assert spaced.signature_hash != changed.signature_hash


def test_n_lines() -> None:
    assert parse_file(Lang.C, b"").n_lines == 0
    assert parse_file(Lang.C, b"int x;").n_lines == 1
    assert parse_file(Lang.C, b"int x;\n").n_lines == 1
    assert parse_file(Lang.C, b"int x;\n\nint y;").n_lines == 3


def test_deterministic() -> None:
    again = parse_fixture(Lang.C, "c/sample.c")
    assert again == FACTS


# --- vulnlab v1.2.0 (examples/vulnlab, read-only) -------------------------------------------

V120 = VULNLAB / "v1.2.0"


def _vulnlab(relpath: str):
    path = V120 / relpath
    lang = detect_language(relpath, path.read_bytes())
    assert lang is Lang.C
    return parse_file(lang, path.read_bytes())


def test_vulnlab_util_copy_value() -> None:
    facts = _vulnlab("src/util.c")
    assert_clean(facts)
    (sym,) = facts.definitions("util_copy_value")
    assert (sym.kind, sym.start_line, sym.end_line) == ("function", 8, 18)
    assert callees(facts, "util_copy_value") == ["strlen", "malloc", "memcpy"]


def test_vulnlab_hdr_get_does_not_call_util_copy_value() -> None:
    facts = _vulnlab("src/hdr.c")
    assert_clean(facts)
    assert callees(facts, "hdr_get") == ["strncpy", "hdr_find_line", "util_strip"]
    assert "util_copy_value" not in callees(facts, "hdr_get")


def test_vulnlab_hdr_parse_line_calls_util_copy_value() -> None:
    facts = _vulnlab("src/hdr.c")
    assert "util_copy_value" in callees(facts, "hdr_parse_line")
    assert ("hdr_parse_line", "util_copy_value", 104, False) in calls(facts)


def test_vulnlab_static_helper_exists() -> None:
    facts = _vulnlab("src/hdr.c")
    (sym,) = facts.definitions("hdr_find_line")
    assert (sym.kind, sym.start_line, sym.end_line) == ("function", 39, 48)
    assert sym.flags == {"static"}


def test_vulnlab_headers() -> None:
    facts = _vulnlab("include/hdr.h")
    assert_clean(facts)
    assert [(s.kind, s.name, s.start_line, s.end_line) for s in facts.symbols] == [
        ("macro", "HDR_H", 4, 4),
        ("type", "hdr_field", 9, 12),
        ("type", "hdr_field", 9, 12),
        ("type", "hdr_list", 15, 19),
        ("type", "hdr_list", 15, 19),
    ]
    util = _vulnlab("src/util.h")
    assert [m.name for m in util.macros] == ["HDR_UTIL_H", "HDR_VALUE_MAX"]


@pytest.mark.parametrize("path", sorted(VULNLAB.glob("*/**/*.[ch]")), ids=str)
def test_every_vulnlab_source_parses(path):
    facts = parse_file(Lang.C, path.read_bytes())
    assert_clean(facts)
    assert any(s.kind == "function" for s in facts.symbols) or path.suffix == ".h"
