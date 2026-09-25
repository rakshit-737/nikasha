# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Attribute-like macros in C/C++ function headers (code/preproc.py; P4)."""

from __future__ import annotations

import time

import pytest

from nikasha.code.languages import Lang
from nikasha.code.parser import parse_file
from nikasha.code.preproc import blank_attribute_macros


def _blanked(src: bytes) -> tuple[str, int]:
    out, n = blank_attribute_macros(src)
    assert len(out) == len(src)  # offsets and line numbers never move
    assert out.count(b"\n") == src.count(b"\n")
    return out.decode(), n


@pytest.mark.parametrize(
    ("src", "expected"),
    [
        # libxml2: a format attribute with arguments, the name on the next line
        (b"static void LIBXML_ATTR_FORMAT(3,0)\nxmlErrValid(int a)\n{\n}\n",
         "static void                        \nxmlErrValid(int a)\n{\n}\n"),
        # SQLite: an attribute between the type and the name
        (b"static int SQLITE_NOINLINE helper(int x)\n{\n}\n",
         "static int                 helper(int x)\n{\n}\n"),
        # between storage class and type: the type after it remains
        (b"static SQLITE_NOINLINE int helper(int x)\n{\n}\n",
         "static                 int helper(int x)\n{\n}\n"),
        # curl: UNITTEST expands to `static` or nothing
        (b"UNITTEST CURLcode Curl_x(int a)\n{\n}\n", "         CURLcode Curl_x(int a)\n{\n}\n"),
        # pointer return with an attribute
        (b"char * ATTR_MALLOC\ndup(const char *s)\n{\n}\n",
         "char * " + " " * len("ATTR_MALLOC") + "\ndup(const char *s)\n{\n}\n"),
    ],
)  # fmt: skip
def test_attribute_macros_are_blanked(src: bytes, expected: str) -> None:
    out, n = _blanked(src)
    assert out == expected
    assert n == 1


def test_two_capitalised_words_keep_one_as_the_type() -> None:
    out, n = _blanked(b"static UINT32 WINAPI win(void)\n{\n}\n")
    assert n == 1
    assert out == "static        WINAPI win(void)\n{\n}\n"


@pytest.mark.parametrize(
    "src",
    [
        b"static BOOL flag(void)\n{\n}\n",  # the only type
        b"UINT32 value(void)\n{\n}\n",  # the only type
        b"int MAX(int a)\n{\n}\n",  # the function's own name
        b"static int PREFIX(name)(int a)\n{\n}\n",  # a name-generating macro
        b"#define WRAP(x) call(x)\n",  # preprocessor line
        b"    return FOO(x) + bar(y);\n",  # indented: not a file-scope declaration
        b"static const char *NAMES[] = {\n};\n",  # not a function
        b"/* ATTR_X foo(void) */\n",  # comment
        b"typedef int (*CALLBACK)(int);\n",
        b"struct FOO bar(void);\n",  # `struct FOO` is the type
        b"static enum MODE get_mode(void)\n{\n}\n",
        b"",
    ],
)
def test_other_capitalised_words_are_left_alone(src: bytes) -> None:
    out, n = _blanked(src)
    assert n == 0
    assert out == src.decode()


def test_blanking_is_deterministic_and_idempotent() -> None:
    src = b"static void A_ATTR(1) f(void)\n{\n}\nstatic int B_NOINLINE g(int x)\n{\n}\n"
    first, n = blank_attribute_macros(src)
    assert n == 2
    assert blank_attribute_macros(src) == (first, 2)
    assert blank_attribute_macros(first) == (first, 0)


@pytest.mark.parametrize(
    "src",
    [
        b"static void ATTR(1) " * 100_000,
        b"A" * 2_000_000,
        b"static int AB_CD " * 120_000,  # one enormous line of candidates
        (b"static void ATTR(3,0)\n" + b"\n" * 3) * 50_000,
    ],
    ids=["repeated-heads", "one-token", "long-line", "no-names"],
)
def test_hostile_input_is_linear(src: bytes) -> None:
    started = time.perf_counter()
    blank_attribute_macros(src)
    assert time.perf_counter() - started < 5.0


LIBXML_STYLE = b"""static void LIBXML_ATTR_FORMAT(3,0)
xmlErrValid(xmlParserCtxtPtr ctxt, int error,
            const char *msg)
{
    xmlCtxtErr(ctxt, NULL, error, msg);
}

static int SQLITE_NOINLINE helper(int x)
{
    return other(x);
}

static BOOL flag(void)
{
    return 1;
}

int after(void)
{
    return xmlErrValid(0, 1, "m");
}
"""


def test_parser_recovers_functions_behind_attribute_macros() -> None:
    facts = parse_file(Lang.C, LIBXML_STYLE)
    assert [(s.name, s.start_line, s.end_line) for s in facts.symbols] == [
        ("xmlErrValid", 1, 6),
        ("helper", 8, 11),
        ("flag", 13, 16),
        ("after", 18, 21),
    ]
    assert [(c.caller_qname, c.callee) for c in facts.calls] == [
        ("xmlErrValid", "xmlCtxtErr"),
        ("helper", "other"),
        ("after", "xmlErrValid"),
    ]
    assert facts.parsed_ok
    assert "2 attribute-like macro(s) read as whitespace" in facts.notes
    assert facts.enclosing(4) is not None
    assert facts.enclosing(4).name == "xmlErrValid"  # type: ignore[union-attr]


def test_clean_files_are_never_rewritten() -> None:
    # `static BOOL flag(void)` parses cleanly, so the blanked text is never used.
    facts = parse_file(Lang.C, b"static BOOL flag(void)\n{\n    return 1;\n}\n")
    assert facts.parsed_ok
    assert facts.notes == ()


def test_blanking_is_kept_only_when_it_helps() -> None:
    # A body-level `#if` breaks braces whatever we do; no macro is blanked, nothing changes.
    src = b"int f(int *d)\n{\n#if V\n  if(d[0]) {\n#else\n  if(d[1]) {\n#endif\n  }\n}\n"
    facts = parse_file(Lang.C, src)
    assert not facts.parsed_ok
    assert not any("attribute-like" in n for n in facts.notes)
