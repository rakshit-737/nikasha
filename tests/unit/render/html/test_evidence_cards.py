# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The evidence cards, the right column of the HTML report (SPEC §15.2).

Two of these tests are the reason the file exists.

``test_pygments_output_is_escaped`` runs ``<script>``, ``</style>`` and an ``onerror``
attribute through the syntax-highlighting path. Pygments escapes the source text it marks
up, but SPEC §15.2 asks for a test that says so rather than a comment that assumes it, and
the highlighter is the one place in this component where a value reaches the page without
passing through :mod:`nikasha.render.html.escaping` first.

``test_card_id_is_the_evidence_id`` pins ``id="ev-<evidence id>"``. The report pane links
to exactly that anchor, so it is a contract between two components and not a detail.

Everything is built from model objects directly: no pipeline, no git, no network. The
control characters under test are written as ``chr(...)`` so that this file does not itself
contain the bidi override and the escapes it is asserting about.
"""

from __future__ import annotations

import re
from typing import Any

import pytest

from nikasha.ingest import ingest_string
from nikasha.model.evidence import CodeLocation, CommandRecord, Evidence
from nikasha.model.result import Result
from nikasha.render.html.components import evidence_cards
from nikasha.render.html.context import HtmlContext
from nikasha.render.html.page import build_page

REPORT = ingest_string("some text", input_format="text")

BIDI = chr(0x202E)  # right-to-left override: makes a path read as something it is not
ANSI = chr(0x1B)  # the start of a terminal escape sequence
NUL = chr(0)

#: Markup that closes elements, an event handler, ANSI escapes, a bidi override and an
#: unbroken run long enough to blow out a layout (P7).
HOSTILE = (
    '</script><img src=x onerror=alert(1)>"><script>alert(1)</script>'
    f"</style><!-- {ANSI}[31mansi{ANSI}[0m {BIDI} gnitirw {NUL} " + "A" * 500
)

#: An attribute of the form ``onsomething=`` inside a real tag. Input-derived ``onerror=``
#: survives as *text* (only ``<``, ``>`` and ``&`` are escaped), so looking for the bare
#: string would be a false positive; what must never happen is it landing inside a tag.
INLINE_HANDLER = re.compile(r"<[a-zA-Z][^>]{0,400}\son\w{1,20}\s*=")


def make_evidence(**kwargs: Any) -> Evidence:
    fields: dict[str, Any] = {
        "id": "abc123def456",
        "check_id": "C06",
        "claim_ids": ("c0ffee000001",),
        "outcome": "REFUTES",
        "strength": -0.8,
        "group": "lines",
        "summary": "the quoted line is not in the tree at v1.2.0",
    }
    fields.update(kwargs)
    return Evidence(**fields)


def make_location(**kwargs: Any) -> CodeLocation:
    fields: dict[str, Any] = {
        "repo": "https://github.com/o/r",
        "ref": "v1.2.0",
        "commit": "0123456789abcdef0123456789abcdef01234567",
        "path": "src/parse.c",
        "start_line": 10,
        "end_line": 11,
    }
    fields.update(kwargs)
    return CodeLocation(**fields)


def make_context(*items: Evidence, excerpts: Any = None) -> HtmlContext:
    result = Result(tool_version="0.1.0", report=REPORT, evidence=tuple(items))
    return HtmlContext(result=result, excerpts=excerpts)


def render(*items: Evidence, excerpts: Any = None) -> str:
    fragment = evidence_cards.render(make_context(*items, excerpts=excerpts))
    assert fragment is not None
    return fragment.html


def lines_from(*texts: str, first: int = 8) -> Any:
    """An excerpt provider returning ``texts`` numbered from ``first``."""
    return lambda _location: [(first + i, text) for i, text in enumerate(texts)]


# --- the component contract ---------------------------------------------------------------


def test_order_is_thirty() -> None:
    assert evidence_cards.ORDER == 30


def test_no_evidence_renders_nothing() -> None:
    assert evidence_cards.render(make_context()) is None


def test_fragment_carries_css_and_no_js() -> None:
    fragment = evidence_cards.render(make_context(make_evidence()))
    assert fragment is not None
    assert ".ev-card" in fragment.css
    assert fragment.js == ""


def test_css_cannot_close_the_style_element() -> None:
    fragment = evidence_cards.render(make_context(make_evidence()))
    assert fragment is not None
    assert "</style" not in fragment.css.lower()
    assert "<" not in fragment.css


def test_card_id_is_the_evidence_id() -> None:
    html = render(make_evidence(id="feedfacecafe"))
    assert 'id="ev-feedfacecafe"' in html


def test_card_id_survives_a_hostile_evidence_id() -> None:
    html = render(make_evidence(id='"><script>'))
    assert '"><script>' not in html
    assert re.search(r'id="ev-[A-Za-z0-9_-]*"', html)


# --- grouping and ordering ------------------------------------------------------------------


def test_grouped_by_check_group_in_the_context_order() -> None:
    # `locus` precedes `version` in GROUP_ORDER, so it must come first on the page even
    # though the evidence tuple is the other way round.
    html = render(
        make_evidence(id="aaa000000001", group="version", check_id="C01"),
        make_evidence(id="bbb000000002", group="locus", check_id="C02"),
    )
    assert html.index("Files and symbols") < html.index("Versions")
    assert html.index('id="ev-bbb000000002"') < html.index('id="ev-aaa000000001"')


def test_group_heading_carries_the_label_and_the_count() -> None:
    html = render(
        make_evidence(id="aaa000000001", group="trace"),
        make_evidence(id="bbb000000002", group="trace"),
    )
    assert "Stack trace" in html
    assert "(2)" in html


def test_unknown_group_still_gets_a_heading() -> None:
    html = render(make_evidence(group="brand_new_group"))
    assert "Brand New Group" in html


def test_strongest_evidence_comes_first_within_a_group() -> None:
    html = render(
        make_evidence(id="aaa000000001", strength=0.1),
        make_evidence(id="bbb000000002", strength=-0.9),
    )
    assert html.index('id="ev-bbb000000002"') < html.index('id="ev-aaa000000001"')


# --- card contents --------------------------------------------------------------------------


def test_card_shows_outcome_check_id_and_summary() -> None:
    html = render(make_evidence(check_id="C06", summary="a plain sentence"))
    assert "REFUTES" in html
    assert "C06" in html
    assert "a plain sentence" in html


def test_outcome_pill_uses_the_context_class() -> None:
    for outcome, klass in (
        ("SUPPORTS", "ok"),
        ("REFUTES", "bad"),
        ("NEUTRAL", "warn"),
        ("ERROR", "unknown"),
    ):
        html = render(make_evidence(outcome=outcome, strength=0.5))
        assert f'<span class="pill {klass}">{outcome}</span>' in html


def test_strength_is_shown_as_a_signed_number() -> None:
    assert "strength -0.80" in render(make_evidence(strength=-0.8))
    assert "strength +0.35" in render(make_evidence(strength=0.35))


def test_negative_zero_strength_renders_as_positive_zero() -> None:
    # -0.0 and 0.0 are the same result; they must not produce two different pages (P2).
    assert render(make_evidence(strength=-0.0)) == render(make_evidence(strength=0.0))
    assert "strength +0.00" in render(make_evidence(strength=-0.0))


def test_model_evidence_is_marked_as_never_decisive() -> None:
    html = render(make_evidence(produced_by="llm", group="llm"))
    assert "model review, never decisive" in html
    assert "model review" not in render(make_evidence())


# --- code excerpts ---------------------------------------------------------------------------


def test_missing_excerpt_renders_the_card_without_code() -> None:
    # An offline report built from a saved RESULT.json has no repository to read.
    html = render(make_evidence(locations=(make_location(),)), excerpts=lambda _loc: None)
    assert "<pre" not in html
    assert "src/parse.c:10-11" in html


def test_no_provider_at_all_renders_the_card_without_code() -> None:
    html = render(make_evidence(locations=(make_location(),)))
    assert "<pre" not in html


def test_excerpt_stored_on_the_location_is_used() -> None:
    location = make_location(start_line=3, end_line=3, excerpt="int a;\nint b;\nint c;")
    html = render(make_evidence(locations=(location,)))
    assert 'data-ln="3"' in html
    assert 'data-ln="5"' in html


def test_lines_are_numbered_and_the_cited_lines_are_highlighted() -> None:
    location = make_location(start_line=9, end_line=10)
    html = render(
        make_evidence(locations=(location,)),
        excerpts=lines_from("one", "two", "three", "four", first=8),
    )
    assert 'class="ev-l" data-ln="8"' in html
    assert 'class="ev-l ev-hit" data-ln="9"' in html
    assert 'class="ev-l ev-hit" data-ln="10"' in html
    assert 'class="ev-l" data-ln="11"' in html


def test_reversed_line_range_still_highlights() -> None:
    location = make_location(start_line=10, end_line=9)
    html = render(make_evidence(locations=(location,)), excerpts=lines_from("a", "b", "c", first=9))
    assert html.count("ev-hit") == 2


def test_the_highlight_accent_follows_the_outcome() -> None:
    html = render(
        make_evidence(outcome="SUPPORTS", strength=0.5, locations=(make_location(),)),
        excerpts=lines_from("int a;", first=10),
    )
    assert 'class="ev-code ev-ok"' in html


def test_syntax_highlighting_marks_c_tokens() -> None:
    html = render(
        make_evidence(locations=(make_location(),)),
        excerpts=lines_from("int total = 1; /* note */", first=10),
    )
    assert 'class="kt"' in html  # keyword type
    assert 'class="cm"' in html  # multiline comment


def test_an_unknown_extension_falls_back_to_plain_text() -> None:
    location = make_location(path="data/thing.no-such-extension")
    html = render(make_evidence(locations=(location,)), excerpts=lines_from("a < b & c", first=10))
    assert "a &lt; b &amp; c" in html


def test_a_pathless_location_does_not_raise() -> None:
    html = render(
        make_evidence(
            locations=(make_location(path=""),),
        ),
        excerpts=lines_from("x", first=10),
    )
    assert "<pre" in html


def test_pygments_output_is_escaped() -> None:
    """SPEC §15.2: repo code reaches the page through Pygments, and it must be inert."""
    payloads = (
        "<script>alert(1)</script>",
        "</style><style>body{display:none}</style>",
        '"><img src=x onerror=alert(1)>',
        "</script><!--",
        f"/* {BIDI} evil */",
    )
    for path in ("src/parse.c", "web/app.js", "page.html", "conf.yaml", "no.extension"):
        html = render(
            make_evidence(locations=(make_location(path=path),)),
            excerpts=lines_from(*payloads, first=10),
        )
        lowered = html.lower()
        assert "<script" not in lowered
        assert "</script" not in lowered
        assert "<style" not in lowered
        assert "</style" not in lowered
        assert "<img" not in lowered
        assert "<!--" not in html
        assert INLINE_HANDLER.search(html) is None
        assert BIDI not in html
        # The payload is still *visible*, just not executable: every `<` came back escaped.
        assert "&lt;" in html
        assert "script" in html
        assert html.count("<") == html.count(">")


def test_a_very_long_line_is_cut() -> None:
    html = render(
        make_evidence(locations=(make_location(),)),
        excerpts=lines_from("x" * 5000, first=10),
    )
    assert "x" * 5000 not in html
    assert "x" * evidence_cards.MAX_LINE_CHARS in html
    assert "Long lines are cut" in html


def test_a_very_long_excerpt_is_cut() -> None:
    many = [f"line {n}" for n in range(200)]
    html = render(
        make_evidence(locations=(make_location(),)),
        excerpts=lines_from(*many, first=1),
    )
    assert html.count("data-ln=") == evidence_cards.MAX_EXCERPT_LINES
    assert "more lines not shown" in html


def test_only_the_first_few_locations_are_shown() -> None:
    locations = tuple(make_location(start_line=n, end_line=n) for n in range(1, 10))
    html = render(make_evidence(locations=locations), excerpts=lines_from("int a;", first=1))
    assert html.count("<pre") == evidence_cards.MAX_LOCATIONS
    assert "more locations not shown" in html


def test_code_stops_when_the_page_budget_runs_out(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(evidence_cards, "MAX_CODE_CHARS", 10)
    html = render(
        make_evidence(locations=(make_location(),)), excerpts=lines_from("int a;", first=10)
    )
    assert "<pre" not in html
    assert "left out to keep this file small" in html


# --- permalinks -------------------------------------------------------------------------------


def test_a_safe_permalink_becomes_a_link() -> None:
    link = "https://github.com/o/r/blob/0123456789ab/src/parse.c#L10-L11"
    html = render(make_evidence(locations=(make_location(permalink=link),)))
    assert f'href="{link}"' in html
    assert 'rel="noreferrer noopener"' in html


def test_a_missing_permalink_is_simply_absent() -> None:
    html = render(make_evidence(locations=(make_location(permalink=None),)))
    assert "<a " not in html


def test_a_hostile_permalink_is_dropped() -> None:
    for bad in (
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        'https://x/" onmouseover="alert(1)',
        "vbscript:msgbox(1)",
        "  JaVaScRiPt:alert(1)",
    ):
        html = render(make_evidence(locations=(make_location(permalink=bad),)))
        assert "<a " not in html
        assert "javascript:" not in html.lower()
        assert INLINE_HANDLER.search(html) is None


# --- details and commands -----------------------------------------------------------------------


def test_no_details_renders_nothing() -> None:
    assert "<details" not in render(make_evidence())


def test_details_are_collapsed_and_sorted() -> None:
    html = render(make_evidence(details={"zeta": 1, "alpha_key": "two", "mid": [1, 2]}))
    assert "<details>" in html
    assert "What the check found (3 fields)" in html
    assert html.index("alpha key") < html.index("mid") < html.index("zeta")
    assert "[1,2]" in html


def test_a_long_detail_value_is_cut() -> None:
    html = render(make_evidence(details={"blob": "z" * 3000}))
    assert "z" * 3000 not in html
    assert "characters)" in html


def test_too_many_detail_keys_are_counted() -> None:
    details = {f"k{n:03d}": n for n in range(60)}
    html = render(make_evidence(details=details))
    assert "more fields not shown" in html


def test_an_empty_command_tuple_renders_nothing() -> None:
    html = render(make_evidence(commands=()))
    assert "Commands run" not in html
    assert "<ol" not in html


def test_commands_are_rendered_collapsed() -> None:
    record = CommandRecord(
        argv=("git", "grep", "-n", "-F", "-e", "needle haystack"),
        exit_code=0,
        stdout_sha256="a" * 64,
        stderr_sha256="b" * 64,
        duration_ms=42,
    )
    html = render(make_evidence(commands=(record,)))
    assert "Commands run (1)" in html
    assert "git grep -n -F -e 'needle haystack'" in html
    assert "exit 0" in html
    assert "42 ms" in html
    assert "a" * 12 in html


def test_a_truncated_command_says_so() -> None:
    record = CommandRecord(
        argv=("git", "log"),
        exit_code=1,
        stdout_sha256="c" * 64,
        stderr_sha256="d" * 64,
        duration_ms=1,
        truncated=True,
    )
    assert "output truncated" in render(make_evidence(commands=(record,)))


def test_a_very_long_argv_is_cut() -> None:
    record = CommandRecord(
        argv=("git", "grep", "-e", "q" * 4000),
        exit_code=0,
        stdout_sha256="e" * 64,
        stderr_sha256="f" * 64,
        duration_ms=1,
    )
    html = render(make_evidence(commands=(record,)))
    assert "q" * 4000 not in html
    assert len(html) < 20_000


# --- hostile input, determinism, degradation ------------------------------------------------------


def test_hostile_input_is_inert_everywhere() -> None:
    record = CommandRecord(
        argv=("git", HOSTILE),
        exit_code=0,
        stdout_sha256=HOSTILE,
        stderr_sha256=HOSTILE,
        duration_ms=0,
    )
    item = make_evidence(
        check_id=HOSTILE,
        summary=HOSTILE,
        group=HOSTILE,
        details={HOSTILE: HOSTILE, "nested": {"k": HOSTILE}},
        locations=(make_location(path=HOSTILE, ref=HOSTILE, commit=HOSTILE, permalink=HOSTILE),),
        commands=(record,),
    )
    html = render(item, excerpts=lines_from(HOSTILE, "plain", first=10))
    lowered = html.lower()
    for dangerous in ("<script", "</script", "<img", "<style", "</style", "<!--"):
        assert dangerous not in lowered
    assert INLINE_HANDLER.search(html) is None
    assert "javascript:" not in lowered
    assert BIDI not in html
    assert ANSI not in html
    assert NUL not in html
    assert html.count("<") == html.count(">")
    # The payload is present, but only as escaped text.
    assert "&lt;" in html


def test_hostile_input_cannot_break_out_of_an_attribute() -> None:
    item = make_evidence(locations=(make_location(path='" onload="alert(1)'),))
    html = render(item, excerpts=lines_from("int a;", first=10))
    assert INLINE_HANDLER.search(html) is None
    assert 'onload="alert(1)"' not in html


def test_rendering_is_deterministic() -> None:
    item = make_evidence(
        details={"b": 2, "a": 1, "hostile": HOSTILE},
        locations=(make_location(permalink="https://github.com/o/r/blob/abc/p.c#L1"),),
    )
    first = render(item, excerpts=lines_from("int a;", "int b;", first=9))
    second = render(item, excerpts=lines_from("int a;", "int b;", first=9))
    assert first == second

    one = evidence_cards.render(make_context(item))
    two = evidence_cards.render(make_context(item))
    assert one is not None and two is not None
    assert one.css == two.css


def test_degenerate_values_do_not_raise() -> None:
    item = make_evidence(
        id="",
        check_id="",
        claim_ids=(),
        summary="",
        group="",
        strength=0.0,
        details={},
        locations=(make_location(path="", ref=None, commit="", permalink=None),),
        commands=(),
    )
    html = render(item)
    assert "ev-card" in html


def test_it_fits_in_a_page_with_one_script() -> None:
    fragment = evidence_cards.render(make_context(make_evidence(locations=(make_location(),))))
    assert fragment is not None
    page = build_page(title="t", fragments=[fragment])
    assert page.count("<script") == 1
    assert 'id="ev-abc123def456"' in page
    assert "script-src 'sha256-" in page


def test_an_unmeasured_duration_is_not_shown_as_zero() -> None:
    """P6: a record whose clock was never read prints no duration, not \"0 ms\"."""
    unmeasured = CommandRecord(
        argv=("git", "log"), exit_code=0, stdout_sha256="a" * 64, stderr_sha256="b" * 64
    )
    measured = unmeasured.model_copy(update={"duration_ms": 42})
    assert " ms" not in render(make_evidence(commands=(unmeasured,)))
    assert " ms" not in evidence_cards._command(unmeasured)
    assert "exit 0 · stdout" in evidence_cards._command(unmeasured)
    assert "42 ms" in evidence_cards._command(measured)
