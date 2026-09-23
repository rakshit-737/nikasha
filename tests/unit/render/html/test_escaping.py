# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The escaping contract of the HTML report (SPEC §15.2, P7).

Every other test in this package trusts these functions, so they are pinned here at the
character level rather than "it looks escaped". Four sinks, four escapes, and the usual
way a report renderer gets owned is using one where another was meant:

* :func:`text` -- character data. Quotes may survive; angle brackets may not.
* :func:`attr` -- an attribute value, always inside double quotes.
* :func:`url` -- an ``href``, where escaping is useless against ``javascript:`` and the
  *scheme* is what has to be checked.
* :func:`script_json` -- data inside ``<script>``, where the HTML tokenizer ignores JSON
  escapes but stops dead at ``</script`` and at ``<!--``.

Two things here are not obvious. The property-based tests run arbitrary text through each
function and assert the invariant that matters for its sink, because a hand-written list
of payloads only ever covers the payloads someone thought of. And the module's own source
is checked for invisible characters: a module whose job is deleting bidi overrides and
zero-width joiners is the last place one should be able to hide.
"""

from __future__ import annotations

import html as stdlib_html
import io
import json
import re
import tokenize
import unicodedata
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from nikasha.render.html import escaping
from nikasha.render.html.escaping import (
    SAFE_SCHEMES,
    attr,
    attrs,
    clean,
    css_ident,
    script_json,
    text,
    url,
)

#: Property tests get a generous budget: they are cheap and this is the safety net.
PROPERTY = settings(max_examples=400, deadline=None, suppress_health_check=[HealthCheck.too_slow])

#: URLs that must never reach an ``href``. Scheme tricks, whitespace tricks, case tricks.
HOSTILE_URLS = (
    "javascript:alert(1)",
    "JAVASCRIPT:alert(1)",
    "JaVaScRiPt:alert(1)",
    "  javascript:alert(1)  ",
    "\tjavascript:alert(1)",
    "\njavascript:alert(1)",
    "java\nscript:alert(1)",
    "java\tscript:alert(1)",
    "java\rscript:alert(1)",
    "java\x00script:alert(1)",
    "jav\u200bascript:alert(1)",
    "vbscript:msgbox(1)",
    "VBScript:msgbox(1)",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    "data:image/svg+xml,<svg onload=alert(1)>",
    "//evil.example/x",
    "\\\\evil.example\\x",
    "/relative/path",
    "../relative/path",
    "#fragment",
    "file:///etc/passwd",
    "chrome://settings",
    "about:blank",
    "",
    "   ",
    'https://ok.example/" onmouseover="alert(1)',
    "https://ok.example/<script>",
    "https://ok.example/ javascript:alert(1)",
    "https://ok.example/\njavascript:alert(1)",
)

#: Characters that must not survive :func:`clean`: C0/C1 controls, zero-width, bidi, BOM.
INVISIBLE = (
    "\x00",
    "\x01",
    "\x08",
    "\x0b",
    "\x0c",
    "\x0e",
    "\x1b",
    "\x1f",
    "\x7f",
    "\x80",
    "\x9f",
    "\u200b",
    "\u200c",
    "\u200d",
    "\u200e",
    "\u200f",
    "\u2028",
    "\u2029",
    "\u202a",
    "\u202b",
    "\u202c",
    "\u202d",
    "\u202e",
    "\u2066",
    "\u2067",
    "\u2068",
    "\u2069",
    "\ufeff",
)


# --- text() ------------------------------------------------------------------------------


def test_text_escapes_the_three_characters_that_matter() -> None:
    assert text("a & b < c > d") == "a &amp; b &lt; c &gt; d"


def test_text_does_not_double_escape() -> None:
    # `&` is substituted first, so an entity in the input is escaped exactly once.
    assert text("&amp;") == "&amp;amp;"
    assert stdlib_html.unescape(text("&amp;")) == "&amp;"


def test_text_closes_no_tag() -> None:
    assert "<" not in text("</script><script>alert(1)</script>")
    assert ">" not in text("</style></textarea></title>")


def test_text_coerces_non_strings() -> None:
    assert text(42) == "42"
    assert text(None) == "None"
    assert text(3.5) == "3.5"


def test_text_leaves_quotes_alone_because_they_are_harmless_between_tags() -> None:
    # Documented and deliberate: use attr() inside an attribute, never text().
    assert text('"it\'s"') == '"it\'s"'


# --- attr() ------------------------------------------------------------------------------


def test_attr_escapes_both_quote_styles_and_the_breakout_characters() -> None:
    assert attr('"') == "&quot;"
    assert attr("'") == "&#x27;"
    assert attr("`") == "&#x60;"
    assert attr("=") == "&#x3d;"
    assert attr("<") == "&lt;"


def test_attr_defuses_the_classic_breakout() -> None:
    out = attr('"><img src=x onerror=alert(1)>')
    for char in ('"', "<", ">", "="):
        assert char not in out


def test_attr_does_not_double_escape() -> None:
    assert stdlib_html.unescape(attr('a"b&c<d=e')) == 'a"b&c<d=e'


def test_attr_is_a_superset_of_text() -> None:
    # Anything text() would have escaped, attr() escapes too.
    for char in ("&", "<", ">"):
        assert attr(char) == text(char)


# --- url() -------------------------------------------------------------------------------


@pytest.mark.parametrize("hostile", HOSTILE_URLS)
def test_url_refuses_everything_that_is_not_plainly_safe(hostile: str) -> None:
    assert url(hostile) == ""
    assert url(hostile, fallback="#nope") == "#nope"


@pytest.mark.parametrize(
    "safe",
    [
        "https://example.invalid/a/b",
        "http://example.invalid/a/b",
        "HTTPS://example.invalid/a/b",
        "mailto:security@example.invalid",
        "https://github.invalid/o/r/commit/0123456789abcdef",
        "https://example.invalid/a?b=c&d=e#frag",
        "https://example.invalid/a%20b",
    ],
)
def test_url_accepts_ordinary_upstream_links(safe: str) -> None:
    out = url(safe)
    assert out != ""
    # What comes back is attribute-escaped, and decodes to exactly what went in.
    assert '"' not in out
    assert "<" not in out
    assert stdlib_html.unescape(out) == safe


def test_url_escapes_what_it_accepts() -> None:
    out = url("https://example.invalid/a?b=c&d=e")
    assert "&amp;" in out
    assert "&#x3d;" in out


def test_url_is_length_bounded() -> None:
    assert url("https://example.invalid/" + "a" * 4000) == ""


def test_url_strips_before_it_judges() -> None:
    assert url("  https://example.invalid/a  ") != ""
    assert url("\u200bjavascript:alert(1)") == ""


def test_safe_schemes_excludes_data_and_javascript() -> None:
    lowered = tuple(scheme.lower() for scheme in SAFE_SCHEMES)
    assert "data:" not in lowered
    assert "javascript:" not in lowered
    assert "vbscript:" not in lowered


# --- script_json() -----------------------------------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        "</script>",
        "</script >",
        "</SCRIPT ",
        "</ script>",
        "<!--",
        "-->",
        "<!--<script>",
        "<script>alert(1)</script>",
        "\u2028",
        "\u2029",
        "]]>",
        "\\u003c/script\\u003e",
    ],
)
def test_script_json_can_never_close_the_script_element(payload: str) -> None:
    out = script_json(payload)
    assert "<" not in out
    assert ">" not in out
    assert "&" not in out
    assert "\u2028" not in out
    assert "\u2029" not in out
    assert re.search(r"</\s*script", out, re.IGNORECASE) is None
    # And it is still the same value once JavaScript parses it back.
    assert json.loads(out) == payload


def test_script_json_survives_a_lone_surrogate() -> None:
    # A lone surrogate cannot be encoded as UTF-8, so a renderer that passed it through
    # would raise when the page is written. json.dumps escapes it instead.
    lone = "\ud800"
    out = script_json({"path": "src/\ud800.c", "name": lone})
    assert lone not in out
    out.encode("utf-8")  # must not raise
    assert "\\ud800" in out


def test_script_json_handles_nested_structures() -> None:
    payload = {"b": ["</script>", {"a": "<!--"}], "a": 1}
    out = script_json(payload)
    assert "<" not in out
    assert json.loads(out) == payload


def test_script_json_is_deterministic() -> None:
    # Sorted keys and no spaces: the same data must give the same bytes (P2).
    assert script_json({"b": 1, "a": 2}) == '{"a":2,"b":1}'
    assert script_json({"a": 2, "b": 1}) == '{"a":2,"b":1}'


def test_script_json_falls_back_to_str_for_unknown_types() -> None:
    assert script_json(Path("src/hdr.c")) == json.dumps(str(Path("src/hdr.c")))


# --- clean() -----------------------------------------------------------------------------


@pytest.mark.parametrize("char", INVISIBLE)
def test_clean_strips_every_invisible_character(char: str) -> None:
    assert clean(f"a{char}b") == "ab"


def test_clean_strips_a_bidi_override_run() -> None:
    # The Trojan Source shape: an override makes a path read as a different path.
    spoofed = "src/\u202ecod.txt\u202c"
    assert clean(spoofed) == "src/cod.txt"
    assert "\u202e" not in clean(spoofed)


def test_clean_keeps_tab_and_newline_because_code_excerpts_need_them() -> None:
    assert clean("a\tb\nc") == "a\tb\nc"


def test_clean_keeps_ordinary_text_including_non_ascii() -> None:
    readable = "\u00e9\u00e0\u00fc\u00df \u2014 \u00a7 \u4f60\u597d \U0001f512"
    assert clean(readable) == readable


def test_clean_coerces_non_strings() -> None:
    assert clean(7) == "7"
    assert clean(None) == "None"


def test_text_and_attr_both_clean_first() -> None:
    assert "\u202e" not in text("a\u202eb")
    assert "\u202e" not in attr("a\u202eb")
    assert "\x00" not in text("a\x00b")


# --- css_ident() -------------------------------------------------------------------------


def test_css_ident_keeps_only_identifier_characters() -> None:
    assert css_ident("a b<c>{d}") == "abcd"
    assert css_ident("ok-name_9") == "ok-name_9"


def test_css_ident_cannot_escape_a_selector() -> None:
    for payload in ('" onload="', "}</style><script>", "a{color:red}", "a;b:c"):
        out = css_ident(payload)
        assert re.fullmatch(r"[A-Za-z0-9_-]{1,64}", out)


def test_css_ident_falls_back_when_nothing_survives() -> None:
    assert css_ident("") == "x"
    assert css_ident("!!!") == "x"
    assert css_ident("!!!", fallback="ev") == "ev"


def test_css_ident_is_length_bounded() -> None:
    assert len(css_ident("a" * 500)) == 64


# --- attrs() -----------------------------------------------------------------------------


def test_attrs_renders_escaped_pairs_and_turns_underscores_into_dashes() -> None:
    out = attrs(id="hero", aria_label='a"b', data_kind="x")
    assert out == 'id="hero" aria-label="a&quot;b" data-kind="x"'


def test_attrs_skips_none_but_keeps_empty_strings() -> None:
    assert attrs(id=None, title="") == 'title=""'


def test_attrs_preserves_keyword_order_for_determinism() -> None:
    assert attrs(b="1", a="2") == 'b="1" a="2"'
    assert attrs(b="1", a="2") == attrs(b="1", a="2")


def test_attrs_values_cannot_start_a_new_attribute() -> None:
    out = attrs(title='" onmouseover="alert(1)')
    assert out.count('"') == 2


# --- the module's own source -------------------------------------------------------------


SOURCE_PATH = Path(escaping.__file__)
SOURCE = SOURCE_PATH.read_text(encoding="utf-8")


def test_escaping_source_contains_no_invisible_character() -> None:
    """The stripper survives itself.

    ``clean`` deletes exactly the characters that can make source read as something it is
    not. Running it over this module must therefore be a no-op -- otherwise a bidi
    override or a zero-width joiner is sitting in the one file nobody would think to look
    at, which is how Trojan Source works.
    """
    assert clean(SOURCE) == SOURCE


def test_escaping_source_has_no_formatting_or_control_characters() -> None:
    """Belt and braces: nothing from Unicode's invisible categories, by category."""
    offenders = sorted(
        {
            char
            for char in SOURCE
            if (
                char not in "\t\n"
                and unicodedata.category(char) in {"Cc", "Cf", "Co", "Cs", "Zl", "Zp"}
            )
            or (unicodedata.category(char) == "Zs" and char != " ")
        }
    )
    assert offenders == [], [hex(ord(c)) for c in offenders]


def test_escaping_executable_source_is_pure_ascii() -> None:
    """Every non-ASCII character is prose, never code.

    The file is not ASCII-only -- the docstrings use an em dash and a section sign -- but
    no identifier, literal that reaches the page, or operator may be non-ASCII. Anything
    outside a docstring or a comment would be a homoglyph waiting to happen, so this test
    asserts the non-ASCII characters live in STRING and COMMENT tokens and nowhere else.
    """
    stray: list[tuple[int, str, str]] = []
    for token in tokenize.generate_tokens(io.StringIO(SOURCE).readline):
        if token.type in {tokenize.STRING, tokenize.COMMENT}:
            continue
        for char in token.string:
            if ord(char) > 127:
                stray.append((token.start[0], tokenize.tok_name[token.type], hex(ord(char))))
    assert stray == []


def test_escaping_exports_no_mark_safe_helper() -> None:
    """There is no escape hatch, and adding one is the bug this test exists to catch."""
    names = {name.lower() for name in dir(escaping) if not name.startswith("_")}
    for forbidden in ("safe", "mark_safe", "raw", "unsafe", "nofilter", "verbatim"):
        assert forbidden not in names


# --- properties --------------------------------------------------------------------------


@PROPERTY
@given(st.text())
def test_property_text_never_leaves_a_bare_angle_bracket(value: str) -> None:
    out = text(value)
    assert "<" not in out
    assert ">" not in out


@PROPERTY
@given(st.text())
def test_property_text_round_trips_through_unescape(value: str) -> None:
    assert stdlib_html.unescape(text(value)) == clean(value)


@PROPERTY
@given(st.text())
def test_property_attr_never_leaves_a_bare_quote(value: str) -> None:
    out = attr(value)
    for char in ('"', "'", "<", ">", "`", "="):
        assert char not in out


@PROPERTY
@given(st.text())
def test_property_attr_stays_inside_its_quotes(value: str) -> None:
    # The value, put in a double-quoted attribute, decodes back to the cleaned input.
    markup = f'x="{attr(value)}"'
    assert markup.count('"') == 2
    assert stdlib_html.unescape(markup[3:-1]) == clean(value)


@PROPERTY
@given(st.text())
def test_property_url_is_either_a_safe_scheme_or_the_fallback(value: str) -> None:
    out = url(value, fallback="#")
    if out == "#":
        return
    decoded = stdlib_html.unescape(out)
    assert decoded.lower().startswith(SAFE_SCHEMES)
    for char in ('"', "'", "<", ">", " ", "\t", "\n", "\\"):
        assert char not in decoded


@PROPERTY
@given(st.text())
def test_property_script_json_cannot_break_out_of_a_script(value: str) -> None:
    out = script_json(value)
    for char in ("<", ">", "&", "\u2028", "\u2029"):
        assert char not in out
    out.encode("utf-8")


@PROPERTY
@given(
    st.recursive(
        st.none() | st.booleans() | st.integers() | st.text(),
        lambda child: st.lists(child, max_size=4) | st.dictionaries(st.text(), child, max_size=4),
        max_leaves=8,
    )
)
def test_property_script_json_round_trips(value: object) -> None:
    assert json.loads(script_json(value)) == value


@PROPERTY
@given(st.text())
def test_property_css_ident_is_always_an_identifier(value: str) -> None:
    assert re.fullmatch(r"[A-Za-z0-9_-]{1,64}", css_ident(value))


@PROPERTY
@given(st.text(), st.text())
def test_property_attrs_emits_exactly_two_quotes_per_pair(one: str, two: str) -> None:
    assert attrs(alpha=one, beta=two).count('"') == 4
