# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""parse_file on hostile input: never raises, never hangs, always says why (SPEC §11.2, P7)."""

from __future__ import annotations

import random
import time

import pytest

from nikasha.code.languages import Lang
from nikasha.code.parser import MAX_FILE_BYTES, language, parse_file, query

TWO_MB = 2 * 1024 * 1024
# Generous bounds: these run in about a second locally; CI machines are slower.
FEW_SECONDS = 15.0

_rng = random.Random(1234)  # noqa: S311 (seeded fuzz input, not security)
GARBAGE = {
    "empty": b"",
    "nul": b"\x00" * 4096,
    "invalid_utf8": b"\xff\xfe\xc3\x28\xa0\xa1\xe2\x28\xa1\xf0\x28\x8c\x28" * 300,
    "bom_crlf": b"\xef\xbb\xbfint main(void)\r\n{\r\n  return f();\r\n}\r\n",
    "random": bytes(_rng.getrandbits(8) for _ in range(20_000)),
    "punctuation": bytes(_rng.choice(b"(){}[];,.:=<>\"'#$@!?a1 \n\t") for _ in range(20_000)),
    "long_line": b"x = " + b"a+" * 200_000 + b"a\n",
    "unterminated": b'def f(:\n  """\n  /* {{{ [[[ ((( \'',
}


def test_every_grammar_and_query_loads() -> None:
    for lang in Lang:
        assert language(lang) is not None
        assert query(lang).pattern_count > 0


@pytest.mark.parametrize("lang", list(Lang), ids=str)
@pytest.mark.parametrize("name", sorted(GARBAGE))
def test_garbage_never_raises(lang, name):
    source = GARBAGE[name]
    facts = parse_file(lang, source)
    assert facts.lang == lang.value
    assert facts.n_lines == (
        source.count(b"\n") + (0 if source.endswith(b"\n") else 1) if source else 0
    )
    assert parse_file(lang, source) == facts  # deterministic
    for sym in facts.symbols:
        assert 1 <= sym.start_line <= sym.end_line <= max(facts.n_lines, 1)


def test_non_ascii_names_and_invalid_bytes() -> None:
    facts = parse_file(Lang.PYTHON, "def café():\n    return naïve()\n".encode())
    assert [(s.name, s.qname) for s in facts.symbols] == [("café", "café")]
    assert [c.callee for c in facts.calls] == ["naïve"]
    # An invalid byte ends the identifier; the file is partial, never an exception.
    broken = parse_file(
        Lang.C, b"int bad\xe9(void) { return run(); }\nint ok(void) { return 1; }\n"
    )
    assert not broken.parsed_ok
    assert "ok" in [s.name for s in broken.symbols]


def test_over_the_size_cap_is_not_parsed() -> None:
    source = b"int x;\n" * (MAX_FILE_BYTES // 7 + 1)
    assert len(source) > MAX_FILE_BYTES
    facts = parse_file(Lang.C, source)
    assert not facts.parsed_ok
    assert facts.symbols == ()
    assert facts.n_lines == MAX_FILE_BYTES // 7 + 1
    assert "exceeds" in facts.notes[0]


@pytest.mark.parametrize(("lang", "unit"), [(Lang.C, b"("), (Lang.C, b"{"), (Lang.PYTHON, b"(")])
def test_two_megabytes_of_open_brackets(lang, unit):
    source = unit * TWO_MB
    assert len(source) <= MAX_FILE_BYTES
    start = time.monotonic()
    facts = parse_file(lang, source)
    assert time.monotonic() - start < FEW_SECONDS
    assert not facts.parsed_ok
    assert facts.error_nodes >= 1
    assert any("pathologically wide" in note for note in facts.notes)


def test_quadratic_error_recovery_is_cut_off_by_the_time_budget() -> None:
    # 64 KB of `}{` takes ~20 s in the Python grammar; the budget stops it.
    source = b"}{" * 32_768
    start = time.monotonic()
    facts = parse_file(Lang.PYTHON, source, time_budget_s=0.2)
    assert time.monotonic() - start < FEW_SECONDS
    assert not facts.parsed_ok
    assert any("time budget" in note for note in facts.notes)


def test_deep_nesting_beyond_the_query_cursor_limit() -> None:
    # 100k nested calls: the query cursor's 16-bit depth would overflow without the cap.
    source = b"int x = " + b"(a)" * 100_000 + b";\n"
    start = time.monotonic()
    facts = parse_file(Lang.C, source)
    assert time.monotonic() - start < FEW_SECONDS
    assert facts.parsed_ok


def test_deep_valid_nesting() -> None:
    source = b"x = " + b"f(" * 20_000 + b"1" + b")" * 20_000 + b"\n"
    facts = parse_file(Lang.PYTHON, source)
    assert facts.parsed_ok
    assert len(facts.calls) == 20_000
    assert {c.caller_qname for c in facts.calls} == {None}


def test_many_calls_regression_for_point_accessor_crash() -> None:
    # py-tree-sitter 0.26.0 segfaults after a few hundred `node.start_point.row` reads.
    body = "".join(f"int f{i}(void)\n{{\n    return g{i}(h(), k());\n}}\n" for i in range(3000))
    facts = parse_file(Lang.C, body.encode())
    assert len(facts.symbols) == 3000
    assert len(facts.calls) == 9000
    assert facts.calls[-1].line == 3000 * 4 - 1


def test_unknown_language_is_reported_not_raised() -> None:
    facts = parse_file("cobol", b"IDENTIFICATION DIVISION.")  # type: ignore[arg-type]
    assert not facts.parsed_ok
    assert facts.notes and "internal error" in facts.notes[0]


def test_language_given_as_string_value() -> None:
    assert parse_file("c", b"int f(void) { return 0; }\n").symbols[0].name == "f"  # type: ignore[arg-type]
