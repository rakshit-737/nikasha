# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The HTML claims table (SPEC §15.2): one row per claim, linked to its evidence.

Three properties are load-bearing and get their own tests. The **anchors** are a contract
with the other views — the report pane links to ``#claim-<id>`` and this table links out to
``#ev-<id>`` — so a renamed id silently breaks navigation in a file nobody will open again.
The **order** must match the terminal view, because a maintainer who read one and then
opened the other must see the same rows in the same places. And the **outcome** must be
readable without colour (WCAG 1.4.1), so every pill carries a word.

Markup is checked by parsing it, not by grepping it: :class:`html.parser.HTMLParser` sees
what a browser sees, so "no ``<script>``" and "no ``onerror=``" are asserted about real
tags and real attributes rather than about substrings that hostile *text* also contains.
"""

from __future__ import annotations

from html.parser import HTMLParser

import pytest

from nikasha.ingest import ingest_string
from nikasha.model.claims import Claim, FileClaim, SymbolClaim, VersionClaim
from nikasha.model.evidence import Evidence
from nikasha.model.report import Span
from nikasha.model.result import Result
from nikasha.model.verdict import Verdict
from nikasha.render.html.components import claims_table
from nikasha.render.html.context import Fragment, HtmlContext

SPAN = Span(start=0, end=4, text="some")
REPORT = ingest_string("some text", input_format="text")

#: An ANSI escape and a right-to-left override, written as code points so that this
#: source file does not itself contain the control characters it is testing for.
ESC = chr(0x1B)
BIDI = chr(0x202E)

#: A script close, an image handler, an attribute break-out, a URL scheme, an ANSI escape,
#: a right-to-left override and an unbounded run (P7).
HOSTILE = (
    '</script><img src=x onerror=alert(1)>"><script>alert(1)</script>'
    "javascript:alert(1)" + ESC + "[31m" + BIDI + "gnp.exe" + "A" * 500
)

#: Words that describe a person rather than a claim (P1).
BANNED_WORDS = ("slop", "fake", "fabricat", " ai ")


class Scan(HTMLParser):
    """Every tag and attribute a browser would actually see in a fragment."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: list[str] = []
        self.attributes: list[tuple[str, str, str | None]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append(tag)
        for name, value in attrs:
            self.attributes.append((tag, name, value))


def scan(html: str) -> Scan:
    parser = Scan()
    parser.feed(html)
    parser.close()
    return parser


def assert_inert(html: str) -> None:
    """No executable tag, no event handler, no ``javascript:`` target."""
    seen = scan(html)
    assert "script" not in seen.tags
    assert "img" not in seen.tags
    assert "iframe" not in seen.tags
    assert "object" not in seen.tags
    for tag, name, value in seen.attributes:
        assert not name.startswith("on"), f"inline handler {name} on <{tag}>"
        assert name != "style", f"inline style on <{tag}>"
        if name in {"href", "src"}:
            assert value is not None
            assert not value.lower().lstrip().startswith("javascript:")


def symbol(cid: str, name: str, *, role: str = "supporting") -> SymbolClaim:
    return SymbolClaim(
        id=cid,
        spans=(SPAN,),
        extractor="test",
        confidence=1.0,
        role=role,  # type: ignore[arg-type]
        name=name,
    )


def evidence(
    eid: str,
    *claim_ids: str,
    outcome: str = "REFUTES",
    strength: float = -2.0,
    summary: str = "not defined in any release v1.0.0-v1.3.0",
    group: str = "locus",
    check_id: str = "C03",
) -> Evidence:
    return Evidence(
        id=eid,
        check_id=check_id,
        claim_ids=claim_ids,
        outcome=outcome,  # type: ignore[arg-type]
        strength=strength,
        group=group,
        summary=summary,
    )


def context(
    claims: tuple[Claim, ...] = (),
    items: tuple[Evidence, ...] = (),
    *,
    verdict: Verdict | None = None,
) -> HtmlContext:
    result = Result(
        tool_version="0.0.0-test",
        report=REPORT,
        claims=claims,
        evidence=items,
        verdict=verdict,
    )
    return HtmlContext(result=result, source="report.md", tool_version="0.0.0-test")


def render(ctx: HtmlContext) -> str:
    fragment = claims_table.render(ctx)
    assert fragment is not None
    return fragment.html


def sample() -> HtmlContext:
    """One claim of each outcome, plus one nothing could be said about."""
    claims: tuple[Claim, ...] = (
        symbol("c1", "hdr_decode_chunked_value", role="core"),
        FileClaim(id="c2", spans=(SPAN,), extractor="test", confidence=1.0, path="src/hdr.c"),
        VersionClaim(
            id="c3",
            spans=(SPAN,),
            extractor="test",
            confidence=1.0,
            raw="1.2.0",
            relation="tested_on",
            role="peripheral",
        ),
        symbol("c4", "hdr_unchecked", role="peripheral"),
    )
    items = (
        evidence("e1", "c1", summary="not defined in any release v1.0.0-v1.3.0"),
        evidence(
            "e2",
            "c2",
            outcome="SUPPORTS",
            strength=1.25,
            summary="src/hdr.c exists at v1.2.0",
            check_id="C02",
        ),
        evidence(
            "e3",
            "c3",
            outcome="NEUTRAL",
            strength=0.0,
            summary="v1.2.0 is a released tag",
            check_id="C01",
        ),
    )
    return context(claims, items)


# --- shape -------------------------------------------------------------------------------


def test_returns_none_when_there_are_no_claims() -> None:
    assert claims_table.render(context()) is None


def test_returns_a_fragment_with_css_and_no_js() -> None:
    fragment = claims_table.render(sample())
    assert isinstance(fragment, Fragment)
    assert ".ct" in fragment.css
    assert fragment.js == ""


def test_sits_full_width_under_the_hero() -> None:
    """Before the two-column band (report pane at 20, evidence at 30), not inside it."""
    assert claims_table.ORDER == 15
    assert not hasattr(claims_table, "COLUMN")


def test_one_row_per_claim() -> None:
    html = render(sample())
    assert html.count("<tr id=") == 4


def test_every_claim_carries_its_anchor() -> None:
    html = render(sample())
    for claim_id in ("c1", "c2", "c3", "c4"):
        assert f'<tr id="claim-{claim_id}">' in html


def test_core_claims_come_first_then_supporting_then_peripheral() -> None:
    html = render(sample())
    order = [html.index(f'id="claim-{cid}"') for cid in ("c1", "c2", "c3", "c4")]
    assert order == sorted(order)


def test_ties_inside_a_role_break_on_claim_id() -> None:
    claims: tuple[Claim, ...] = (symbol("zz", "late"), symbol("aa", "early"))
    html = render(context(claims))
    assert html.index('id="claim-aa"') < html.index('id="claim-zz"')


# --- outcomes ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("outcome", "word", "klass"),
    [
        ("SUPPORTS", "supported", "ok"),
        ("REFUTES", "contradicted", "bad"),
        ("NEUTRAL", "unclear", "warn"),
        ("ERROR", "not checked", "unknown"),
    ],
)
def test_outcome_has_a_word_beside_its_colour(outcome: str, word: str, klass: str) -> None:
    """A coloured glyph alone carries nothing to a reader who cannot see it (WCAG 1.4.1)."""
    ctx = context((symbol("c1", "hdr_get"),), (evidence("e1", "c1", outcome=outcome),))
    html = render(ctx)
    assert f'<span class="pill {klass}">' in html
    assert word in html


def test_the_glyph_is_hidden_from_assistive_technology() -> None:
    """The word is already announced; the mark would be read out twice."""
    html = render(sample())
    assert '<span class="ct-mark" aria-hidden="true">' in html


def test_a_claim_with_no_evidence_still_gets_a_row() -> None:
    """The report pane links to every claim, so a dropped row is a dead link."""
    html = render(sample())
    assert '<tr id="claim-c4">' in html
    assert "no check produced evidence about this claim" in html


def test_refutation_outranks_support_at_equal_strength() -> None:
    ctx = context(
        (symbol("c1", "hdr_get"),),
        (
            evidence("e1", "c1", outcome="SUPPORTS", strength=2.0, summary="found at v1.2.0"),
            evidence("e2", "c1", outcome="REFUTES", strength=-2.0, summary="absent at v1.2.0"),
        ),
    )
    html = render(ctx)
    assert "absent at v1.2.0" in html
    assert "found at v1.2.0" not in html


def test_the_strongest_evidence_wins() -> None:
    ctx = context(
        (symbol("c1", "hdr_get"),),
        (
            evidence("e1", "c1", outcome="SUPPORTS", strength=0.5, summary="weak support"),
            evidence("e2", "c1", outcome="SUPPORTS", strength=3.0, summary="strong support"),
        ),
    )
    assert "strong support" in render(ctx)


# --- links -------------------------------------------------------------------------------


def test_each_row_links_to_its_evidence_card() -> None:
    html = render(sample())
    assert 'href="#ev-e1"' in html
    assert 'href="#ev-e2"' in html
    assert 'href="#ev-e3"' in html


def test_the_check_id_is_shown_beside_the_summary() -> None:
    html = render(sample())
    assert "C03" in html
    assert "C02" in html


def test_counts_line_summarises_the_table() -> None:
    html = render(sample())
    assert "4 claims" in html
    assert "1 contradicted" in html
    assert "1 supported" in html
    assert "1 unclear" in html
    assert "1 with no evidence" in html


def test_counts_line_is_singular_for_one_claim() -> None:
    html = render(context((symbol("c1", "hdr_get"),)))
    assert "1 claim ·" in html


# --- P1, P2, P7 --------------------------------------------------------------------------


def test_rendering_twice_is_byte_identical() -> None:
    first, second = render(sample()), render(sample())
    assert first == second


def test_wording_is_about_claims_not_people() -> None:
    html = render(sample()).lower()
    for word in BANNED_WORDS:
        assert word not in html


def test_hostile_input_is_inert() -> None:
    ctx = context(
        (symbol(HOSTILE, HOSTILE, role="core"),),
        (evidence(HOSTILE, HOSTILE, summary=HOSTILE, check_id=HOSTILE),),
    )
    html = render(ctx)
    assert_inert(html)
    assert "<script" not in html.lower()
    assert "<img" not in html
    assert ESC not in html
    assert BIDI not in html
    assert "&lt;" in html  # the angle brackets survived, escaped


def test_hostile_ids_cannot_break_out_of_an_anchor() -> None:
    ctx = context(
        (symbol('x" onmouseover="alert(1)', "hdr_get"),),
        (evidence('y"><script>', 'x" onmouseover="alert(1)'),),
    )
    html = render(ctx)
    assert_inert(html)
    assert 'href="#ev-yscript"' in html
    assert '<tr id="claim-xonmouseoveralert1">' in html


def test_an_unbounded_string_is_clipped() -> None:
    ctx = context((symbol("c1", "A" * 500),), (evidence("e1", "c1", summary="B" * 500),))
    html = render(ctx)
    assert "A" * 400 not in html
    assert "B" * 400 not in html
    assert "…" in html


def test_a_summary_spanning_lines_becomes_one_line() -> None:
    ctx = context((symbol("c1", "hdr_get"),), (evidence("e1", "c1", summary="a\r\n\tb   c"),))
    assert "a b c" in render(ctx)


def test_no_inline_handlers_in_benign_output() -> None:
    assert_inert(render(sample()))
