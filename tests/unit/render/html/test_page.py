# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The page shell: CSP, the one script, the one stylesheet, the two themes (SPEC §15.2).

The shell is what makes the report's promises enforceable rather than aspirational. Three
of them get pinned here.

**The hash.** ``script-src 'sha256-...'`` only works if the digest is the one a browser
computes: base64 of the SHA-256 of the script element's text, encoded as UTF-8. The test
uses the vector from the CSP documentation rather than recomputing the hash the same way
:func:`script_hash` does, since a test that repeats the implementation proves nothing.

**One of each.** Exactly one ``<script>`` and one ``<style>``. A second script element
would not be covered by the hash and would simply not run, so "there is only one" is a
structural invariant, not a style rule.

**Both themes.** Light and dark are defined twice over -- once under
``prefers-color-scheme`` for the system setting and once under ``[data-theme]`` for the
toggle -- and the two must define the same variables, or toggling produces a half-themed
page. That comparison is done by parsing the stylesheet, so adding a variable to one block
and forgetting the other fails here.
"""

from __future__ import annotations

import base64
import hashlib
import re

import pytest

from nikasha.render.html.context import Fragment
from nikasha.render.html.page import (
    BASE_CSS,
    BASE_JS,
    MAX_BYTES,
    build_page,
    csp,
    script_hash,
)

#: From the CSP documentation's worked example: the hash of ``alert('Hello, world.');``.
#: An independent vector, so this test fails if the digest, the encoding or the base64
#: alphabet ever drifts from what a browser does.
MDN_SCRIPT = "alert('Hello, world.');"
MDN_HASH = "sha256-qznLcsROx4GACP2dm0UCKCzCG+HiZ1guq6ZZDob/Tng="

#: The SHA-256 of the empty string, the most-published digest there is.
EMPTY_HASH = "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="

#: U+00E9 encoded as UTF-8 (0xC3 0xA9), not as Latin-1 (0xE9).
UTF8_HASH = "sha256-SplVfkAzw1Od4utlRyAXytX5VX96BiWgnxw/biumnEw="

THEME_VARIABLE = re.compile(r"--([a-z0-9-]{1,40})\s*:")


def block_after(css: str, marker: str) -> str:
    """The brace-matched body of the block introduced by ``marker``."""
    start = css.index("{", css.index(marker))
    depth = 0
    for index in range(start, len(css)):
        if css[index] == "{":
            depth += 1
        elif css[index] == "}":
            depth -= 1
            if depth == 0:
                return css[start + 1 : index]
    raise AssertionError(f"unbalanced braces after {marker!r}")


def variables(block: str) -> set[str]:
    return set(THEME_VARIABLE.findall(block))


def page(*fragments: Fragment, title: str = "Nikasha: GROUNDED") -> str:
    return build_page(title=title, fragments=fragments, description="a description")


def script_of(html: str) -> str:
    match = re.search(r"<script>(.*)</script>", html, re.DOTALL)
    assert match is not None, "the page has no script element"
    return match.group(1)


def csp_of(html: str) -> str:
    match = re.search(r'<meta http-equiv="Content-Security-Policy" content="([^"]*)"', html)
    assert match is not None, "the page has no Content-Security-Policy"
    return match.group(1)


# --- the hash a browser computes ---------------------------------------------------------


@pytest.mark.parametrize(
    ("script", "expected"),
    [(MDN_SCRIPT, MDN_HASH), ("", EMPTY_HASH), ("é", UTF8_HASH)],
)
def test_script_hash_matches_the_published_vectors(script: str, expected: str) -> None:
    assert script_hash(script) == expected


def test_script_hash_is_base64_of_the_raw_digest_not_of_the_hex() -> None:
    digest = hashlib.sha256(MDN_SCRIPT.encode("utf-8")).digest()
    assert script_hash(MDN_SCRIPT) == "sha256-" + base64.b64encode(digest).decode("ascii")
    assert script_hash(MDN_SCRIPT) != "sha256-" + base64.b64encode(
        hashlib.sha256(MDN_SCRIPT.encode("utf-8")).hexdigest().encode("ascii")
    ).decode("ascii")


def test_script_hash_changes_with_one_byte_of_the_script() -> None:
    assert script_hash("alert(1)") != script_hash("alert(1) ")


def test_csp_embeds_the_hash_of_exactly_that_script() -> None:
    policy = csp(MDN_SCRIPT)
    assert f"script-src '{MDN_HASH}'" in policy


def test_csp_blocks_everything_the_report_does_not_need() -> None:
    policy = csp(BASE_JS)
    assert policy.startswith("default-src 'none'")
    assert "base-uri 'none'" in policy
    assert "form-action 'none'" in policy
    # Images may be inline data URIs; nothing may be fetched.
    assert "img-src data:" in policy
    assert "http://" not in policy
    assert "https://" not in policy
    assert "*" not in policy


def test_csp_script_src_has_no_escape_hatch() -> None:
    directive = next(d for d in csp(BASE_JS).split("; ") if d.startswith("script-src"))
    for hatch in ("'unsafe-inline'", "'unsafe-eval'", "'unsafe-hashes'", "'strict-dynamic'", "*"):
        assert hatch not in directive


# --- the shell -----------------------------------------------------------------------------


def test_build_page_emits_one_script_and_one_style() -> None:
    html = page(Fragment(html="<p>a</p>", css=".a{}", js="var a=1;"))
    assert len(re.findall(r"<\s*script", html, re.IGNORECASE)) == 1
    assert len(re.findall(r"<\s*/\s*script", html, re.IGNORECASE)) == 1
    assert len(re.findall(r"<\s*style", html, re.IGNORECASE)) == 1
    assert len(re.findall(r"<\s*/\s*style", html, re.IGNORECASE)) == 1


def test_build_page_emits_the_document_preamble() -> None:
    html = page()
    assert html.startswith("<!doctype html>")
    assert '<html lang="en">' in html
    assert '<meta charset="utf-8">' in html
    assert '<meta name="viewport" content="width=device-width, initial-scale=1">' in html
    assert '<meta name="referrer" content="no-referrer">' in html


def test_build_page_csp_matches_the_script_it_actually_served() -> None:
    html = page(Fragment(html="<p>a</p>", js="var fromComponent = 1;"))
    served = script_of(html)
    assert "var fromComponent = 1;" in served
    assert f"script-src '{script_hash(served)}'" in csp_of(html)


def test_build_page_concatenates_fragment_css_and_js_into_the_single_elements() -> None:
    html = page(
        Fragment(html="<p>one</p>", css=".one{color:red}", js="var one=1;"),
        Fragment(html="<p>two</p>", css=".two{color:blue}", js="var two=2;"),
    )
    assert ".one{color:red}" in html
    assert ".two{color:blue}" in html
    assert "var one=1;" in script_of(html)
    assert "var two=2;" in script_of(html)
    assert html.index("<p>one</p>") < html.index("<p>two</p>")


def test_build_page_ignores_fragments_with_nothing_to_contribute() -> None:
    bare = page(Fragment(html="<p>a</p>"))
    assert script_of(bare) == BASE_JS
    assert "<style>" + BASE_CSS + "</style>" in bare


def test_build_page_places_the_title_and_description() -> None:
    html = build_page(title="Nikasha: MIXED", fragments=(), description="a summary")
    assert "<title>Nikasha: MIXED</title>" in html
    assert '<meta name="description" content="a summary">' in html


def test_build_page_is_deterministic() -> None:
    fragments = (Fragment(html="<p>a</p>", css=".a{}", js="var a=1;"),)
    assert build_page(title="t", fragments=fragments) == build_page(title="t", fragments=fragments)


def test_build_page_output_is_utf8_encodable() -> None:
    html = page(Fragment(html="<p>café 你好</p>"))
    assert "café" in html.encode("utf-8").decode("utf-8")


def test_max_bytes_is_the_spec_budget() -> None:
    assert MAX_BYTES == 1_500_000


# --- the base script and stylesheet --------------------------------------------------------


def test_base_js_cannot_close_its_own_script_element() -> None:
    assert re.search(r"</\s*script", BASE_JS, re.IGNORECASE) is None
    assert "<!--" not in BASE_JS
    assert "]]>" not in BASE_JS


def test_base_css_cannot_close_its_own_style_element_or_fetch_anything() -> None:
    assert re.search(r"</\s*style", BASE_CSS, re.IGNORECASE) is None
    assert "@import" not in BASE_CSS
    assert "url(" not in BASE_CSS
    assert "expression(" not in BASE_CSS
    assert "http://" not in BASE_CSS
    assert "https://" not in BASE_CSS


def test_fonts_are_the_system_stack_and_never_fetched() -> None:
    assert "@font-face" not in BASE_CSS
    assert "fonts.googleapis" not in BASE_CSS
    assert "system-ui" in BASE_CSS


def test_base_js_stores_nothing_without_a_guard() -> None:
    # A file:// page in a private window throws on localStorage; the report must survive.
    assert BASE_JS.count("localStorage") == BASE_JS.count("try {")


# --- light, dark and print -----------------------------------------------------------------


def test_light_theme_defines_every_documented_variable() -> None:
    light = variables(block_after(BASE_CSS, ":root {"))
    expected = {
        "fg",
        "bg",
        "panel",
        "border",
        "muted",
        "ok",
        "bad",
        "warn",
        "unknown",
        "link",
        "mono",
        "sans",
        "radius",
    }
    assert expected <= light


def test_dark_is_defined_both_by_preference_and_by_attribute() -> None:
    preference = block_after(BASE_CSS, "@media (prefers-color-scheme: dark)")
    attribute = block_after(BASE_CSS, ':root[data-theme="dark"]')
    assert ':root:not([data-theme="light"])' in preference
    assert variables(preference) == variables(attribute), (
        "the system-preference dark theme and the toggled dark theme define different "
        "variables, so one of the two paths renders half-themed"
    )
    assert variables(attribute)


def test_the_dark_theme_only_redefines_variables_the_light_theme_declared() -> None:
    light = variables(block_after(BASE_CSS, ":root {"))
    dark = variables(block_after(BASE_CSS, ':root[data-theme="dark"]'))
    assert dark <= light, sorted(dark - light)


def test_the_two_themes_differ() -> None:
    light = block_after(BASE_CSS, ":root {")
    dark = block_after(BASE_CSS, ':root[data-theme="dark"]')
    assert light != dark


def test_color_scheme_is_declared_so_form_controls_follow() -> None:
    assert "color-scheme: light dark" in block_after(BASE_CSS, ":root {")


def test_there_is_a_print_stylesheet() -> None:
    printed = block_after(BASE_CSS, "@media print")
    assert printed.strip()
    # Print goes back to ink on paper, and the chrome that means nothing on paper goes.
    assert "--bg: #fff" in printed
    assert "#theme-toggle" in printed
    # Links are useless on paper unless their target is spelled out.
    assert "attr(href)" in printed


def test_focus_is_always_visible() -> None:
    assert ":focus-visible" in BASE_CSS
    assert "outline: none" not in BASE_CSS


def test_there_is_a_skip_link_for_keyboard_users() -> None:
    assert 'class="skip"' in page()
    assert ".skip:focus" in BASE_CSS
