# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The "Report" pane of the HTML report (SPEC §15.2).

This component renders attacker-written prose verbatim, so most of these tests assert two
properties that must hold for *any* input:

* **Round trip.** Stripping the markup and unescaping the entities gives back exactly the
  report body (after :func:`nikasha.render.html.escaping.clean` drops the characters that
  may never reach a document). Nothing is added, nothing is lost, nothing is re-ordered.
* **Well-formed, flat markup.** Claim spans overlap and nest, and the output must still
  parse to balanced tags with no nested ``<a>``, whatever the spans do.

The hostile-input tests are deliberately *structural* rather than substring-based: the
string ``onerror=`` is perfectly safe as character data (it is the ``<`` that matters), so
the tests parse the output and assert on the tags and attribute names that actually exist.
"""

from __future__ import annotations

import html as html_lib
import itertools
import re
from html.parser import HTMLParser
from typing import Any

import pytest

from nikasha.ingest import ingest_string
from nikasha.model.claims import ClaimBase, FileClaim, SymbolClaim
from nikasha.model.evidence import Evidence
from nikasha.model.report import Report, Span
from nikasha.model.result import Result
from nikasha.render.html.components import report_pane
from nikasha.render.html.context import Fragment, HtmlContext
from nikasha.render.html.escaping import clean

#: Written as ``chr()`` so the source file itself stays free of invisible characters.
BIDI_OVERRIDE = chr(0x202E)
ZERO_WIDTH = chr(0x200B)

#: Script injection, an event handler, tags that end a raw-text element, a bidi override
#: and a long unbroken run — all of them in the *body*, which is the worst place (P7).
HOSTILE_BODY = (
    "<script>alert(1)</script>\n"
    "<img src=x onerror=alert(1)>\n"
    "</textarea></style></title>\n"
    f"a{BIDI_OVERRIDE}b{ZERO_WIDTH}c & <b>bold</b> \"quoted\" 'single'\n" + "A" * 300 + "\n"
)

#: The same hazards in a field that ends up inside an attribute.
HOSTILE_SUMMARY = f'"><img src=x onerror=alert(1)> & </script> {BIDI_OVERRIDE}'

#: Every tag this component is allowed to emit.
ALLOWED_TAGS = {"section", "div", "h2", "p", "ul", "li", "span", "a"}


# --- fixtures ---------------------------------------------------------------------------


def report_of(body: str) -> Report:
    return ingest_string(body, input_format="text")


def expected_text(body: str) -> str:
    """What the pane must render: the ingested body, minus characters ``clean`` drops."""
    return clean(report_of(body).body)


def span_of(body: str, needle: str, occurrence: int = 0) -> Span:
    """The span of ``needle`` in ``body``, honouring the ``Span`` text invariant."""
    start = -1
    for _ in range(occurrence + 1):
        start = body.index(needle, start + 1)
    return Span(start=start, end=start + len(needle), text=needle)


def symbol(cid: str, spans: tuple[Span, ...], name: str = "hdr_get") -> SymbolClaim:
    return SymbolClaim(id=cid, spans=spans, extractor="test", confidence=1.0, name=name)


def file_claim(cid: str, spans: tuple[Span, ...], path: str = "src/hdr.c") -> FileClaim:
    return FileClaim(id=cid, spans=spans, extractor="test", confidence=1.0, path=path)


def evidence(
    eid: str,
    claim_id: str,
    *,
    outcome: str = "REFUTES",
    strength: float = -2.0,
    summary: str = "not defined in any release v1.0.0-v1.3.0",
) -> Evidence:
    return Evidence(
        id=eid,
        check_id="C03",
        claim_ids=(claim_id,),
        outcome=outcome,  # type: ignore[arg-type]
        strength=strength,
        group="locus",
        summary=summary,
    )


def result_of(
    body: str,
    claims: tuple[ClaimBase, ...] = (),
    items: tuple[Evidence, ...] = (),
) -> Result:
    return Result(
        tool_version="0.0.0-test",
        report=report_of(body),
        claims=claims,  # type: ignore[arg-type]
        evidence=items,
    )


def render(result: Result, **kwargs: Any) -> Fragment:
    fragment = report_pane.render(HtmlContext(result=result, **kwargs))
    assert fragment is not None
    return fragment


# --- helpers ----------------------------------------------------------------------------

_TAG_RE = re.compile(r"<[^>]{0,4000}>")


def body_of(fragment: Fragment) -> str:
    """Just the scrollable text container, without its wrapper tag."""
    start = fragment.html.index('<div class="rp-text')
    start = fragment.html.index(">", start) + 1
    return fragment.html[start : fragment.html.index("</div>", start)]


def visible_text(markup: str) -> str:
    """The character data of ``markup``: tags removed, entities decoded."""
    return html_lib.unescape(_TAG_RE.sub("", markup))


class _Checker(HTMLParser):
    """Parses the output and records what a browser would actually build from it."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[str] = []
        self.tags: set[str] = set()
        self.attr_names: set[str] = set()
        self.max_anchor_depth = 0
        self.errors: list[str] = []
        self._anchors = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.add(tag)
        self.attr_names.update(name for name, _ in attrs)
        if tag in {"br", "img", "hr", "meta", "input", "link"}:
            return  # void elements never nest
        self.stack.append(tag)
        if tag == "a":
            self._anchors += 1
            self.max_anchor_depth = max(self.max_anchor_depth, self._anchors)

    def handle_endtag(self, tag: str) -> None:
        if not self.stack or self.stack[-1] != tag:
            self.errors.append(f"unbalanced </{tag}> with stack {self.stack}")
            return
        self.stack.pop()
        if tag == "a":
            self._anchors -= 1


def parsed(markup: str) -> _Checker:
    checker = _Checker()
    checker.feed(markup)
    checker.close()
    return checker


def assert_inert(markup: str) -> _Checker:
    """The markup builds only the elements this component emits, and no handlers."""
    checker = parsed(markup)
    assert checker.errors == []
    assert checker.stack == []
    assert checker.tags <= ALLOWED_TAGS, checker.tags - ALLOWED_TAGS
    assert [name for name in checker.attr_names if name.startswith("on")] == []
    assert checker.max_anchor_depth <= 1
    assert "javascript:" not in markup
    return checker


# --- the body is rendered, always -------------------------------------------------------


def test_renders_the_body_with_no_claims() -> None:
    body = "A plain report with no claims at all.\n\n  Indented second paragraph.\n"
    fragment = render(result_of(body))
    assert visible_text(body_of(fragment)) == expected_text(body)
    assert "No checkable claim was extracted from this report." in fragment.html


def test_a_claim_with_no_usable_span_is_reported_as_such() -> None:
    body = report_of(NEST_BODY).body
    far_away = Span(start=len(body) + 10, end=len(body) + 14, text="gone")
    fragment = render(result_of(NEST_BODY, claims=(symbol("c1", (far_away,)),)))
    assert "No claim in this report could be tied to a span of its text." in fragment.html


def test_empty_body_renders_nothing() -> None:
    assert report_pane.render(HtmlContext(result=result_of(""))) is None
    assert report_pane.render(HtmlContext(result=result_of("   \n\t\n "))) is None


def test_order_is_the_left_column() -> None:
    assert report_pane.ORDER == 20


def test_whitespace_is_preserved_by_css_not_by_markup() -> None:
    body = "line one\n\tindented\n\n\nafter blank lines"
    fragment = render(result_of(body))
    assert "white-space: pre-wrap" in fragment.css
    # No <br>, no <p>, no &nbsp;: the newlines in the body are the newlines on the page.
    assert visible_text(body_of(fragment)) == expected_text(body)
    assert "<br" not in fragment.html


# --- overlapping and nested spans -------------------------------------------------------

NEST_BODY = "The function hdr_decode() in src/hdr.c overflows the buffer here.\n"


def nested_result() -> Result:
    body = report_of(NEST_BODY).body
    outer = symbol("c-outer", (span_of(body, "hdr_decode() in src/hdr.c"),))
    inner = symbol("c-inner", (span_of(body, "hdr_decode"),))
    path = file_claim("c-path", (span_of(body, "src/hdr.c"),))
    # Neither contains the other: it starts inside `outer` and ends after it.
    crossing = file_claim("c-cross", (span_of(body, "src/hdr.c overflows the buffer"),))
    return result_of(
        NEST_BODY,
        claims=(outer, inner, path, crossing),
        items=(
            evidence("e-outer", "c-outer", outcome="REFUTES", strength=-2.0),
            evidence("e-inner", "c-inner", outcome="SUPPORTS", strength=1.5),
            evidence("e-path", "c-path", outcome="NEUTRAL", strength=0.4),
            evidence("e-cross", "c-cross", outcome="ERROR", strength=0.1),
        ),
    )


def test_nested_and_crossing_spans_round_trip() -> None:
    fragment = render(nested_result())
    assert visible_text(body_of(fragment)) == expected_text(NEST_BODY)


def test_no_nested_anchors_and_balanced_tags() -> None:
    checker = assert_inert(render(nested_result()).html)
    assert checker.max_anchor_depth == 1


def test_the_innermost_claim_wins_a_segment() -> None:
    markup = body_of(render(nested_result()))
    # `hdr_decode` sits inside the longer `c-outer` span; the shorter claim paints over it.
    assert re.search(r'<a class="rp-c rp-ok[^"]*"[^>]*>hdr_decode</a>', markup) is not None
    # The crossing claim overlaps the others, so at least one segment is marked multi.
    assert "rp-multi" in markup


def test_every_outcome_class_reaches_the_markup() -> None:
    markup = body_of(render(nested_result()))
    for klass in ("rp-ok", "rp-bad", "rp-warn", "rp-unknown"):
        assert klass in markup, klass


def test_segments_are_contiguous_and_disjoint() -> None:
    """Concatenating the rendered pieces reproduces the body exactly once."""
    body = report_of(NEST_BODY).body
    pieces = report_pane._pieces(HtmlContext(result=nested_result()), len(body))
    cuts = list(report_pane._segments(pieces, len(body)))
    assert cuts[0][0] == 0
    assert cuts[-1][1] == len(body)
    assert all(a[1] == b[0] for a, b in itertools.pairwise(cuts))
    assert "".join(body[start:end] for start, end, _ in cuts) == body
    # Every cut's claims really do cover it, shortest first.
    for start, end, active in cuts:
        assert all(p.start <= start and p.end >= end for p in active)
        lengths = [p.end - p.start for p in active]
        assert lengths == sorted(lengths)


# --- anchors and links ------------------------------------------------------------------


def test_the_pane_does_not_claim_the_claims_table_ids() -> None:
    """``id="claim-…"`` belongs to ``claims_table``; two of them would shadow each other."""
    markup = render(nested_result()).html
    assert 'id="claim-' not in markup


def test_every_claim_with_evidence_links_to_its_card() -> None:
    markup = body_of(render(nested_result()))
    for eid in ("e-outer", "e-inner", "e-path", "e-cross"):
        assert f'href="#ev-{eid}"' in markup, eid


def test_a_claim_links_to_its_strongest_evidence_card() -> None:
    body = report_of(NEST_BODY).body
    result = result_of(
        NEST_BODY,
        claims=(symbol("c1", (span_of(body, "hdr_decode"),)),),
        items=(
            evidence("e-weak", "c1", outcome="SUPPORTS", strength=0.2, summary="weak"),
            evidence("e-strong", "c1", outcome="REFUTES", strength=-3.0, summary="strong"),
        ),
    )
    markup = body_of(render(result))
    assert 'href="#ev-e-strong"' in markup
    assert "#ev-e-weak" not in markup
    assert 'title="strong"' in markup
    assert 'aria-label="strong"' in markup
    assert "rp-bad" in markup


def test_a_claim_without_evidence_is_marked_but_not_a_link() -> None:
    body = report_of(NEST_BODY).body
    result = result_of(NEST_BODY, claims=(symbol("c1", (span_of(body, "hdr_decode"),)),))
    markup = body_of(render(result))
    assert "<a " not in markup
    assert f'title="{report_pane.NO_EVIDENCE_SUMMARY}"' in markup
    assert "rp-unknown" in markup


def test_a_claim_in_several_places_is_underlined_in_each() -> None:
    body_text = "hdr_get is called here, and hdr_get again there.\n"
    body = report_of(body_text).body
    claim = symbol("c1", (span_of(body, "hdr_get", 0), span_of(body, "hdr_get", 1)))
    result = result_of(body_text, claims=(claim,), items=(evidence("e1", "c1"),))
    markup = body_of(render(result))
    assert markup.count('href="#ev-e1"') == 2
    assert visible_text(markup) == expected_text(body_text)


def test_a_long_summary_is_collapsed_and_bounded() -> None:
    body = report_of(NEST_BODY).body
    long_summary = "line one\nline two " + "B" * 1000
    result = result_of(
        NEST_BODY,
        claims=(symbol("c1", (span_of(body, "hdr_decode"),)),),
        items=(evidence("e1", "c1", summary=long_summary),),
    )
    title = re.search(r'title="([^"]*)"', body_of(render(result)))
    assert title is not None
    assert "\n" not in title.group(1)
    assert len(title.group(1)) <= report_pane.MAX_SUMMARY_CHARS


# --- broken and hostile data ------------------------------------------------------------


@pytest.mark.parametrize(
    ("start", "end"),
    [(10_000, 10_010), (0, 0), (5, 5), (60, 10_000)],
    ids=["past-the-end", "empty-at-zero", "empty-inside", "end-past-the-end"],
)
def test_out_of_range_spans_are_skipped_not_fatal(start: int, end: int) -> None:
    body = report_of(NEST_BODY).body
    text = body[start:end] if end <= len(body) else " " * (end - start)
    span = Span(start=start, end=end, text=text)
    result = result_of(NEST_BODY, claims=(symbol("c1", (span,)),), items=(evidence("e1", "c1"),))
    fragment = render(result)
    # The body is rendered whole either way, and the claim is simply not underlined.
    assert visible_text(body_of(fragment)) == expected_text(NEST_BODY)
    assert_inert(fragment.html)


def test_a_repeated_claim_id_is_rendered_once() -> None:
    body = report_of(NEST_BODY).body
    claim = symbol("c1", (span_of(body, "hdr_decode"),))
    other = file_claim("c1", (span_of(body, "src/hdr.c"),))
    fragment = render(result_of(NEST_BODY, claims=(claim, other), items=(evidence("e1", "c1"),)))
    assert body_of(fragment).count('href="#ev-e1"') == 1  # the second claim is a duplicate
    assert visible_text(body_of(fragment)) == expected_text(NEST_BODY)


def test_hostile_body_is_inert() -> None:
    body = report_of(HOSTILE_BODY).body
    claim = symbol("c1", (span_of(body, "alert(1)"),))
    fragment = render(result_of(HOSTILE_BODY, claims=(claim,), items=(evidence("e1", "c1"),)))
    markup = fragment.html
    assert_inert(markup)
    for dangerous in ("<script", "</script", "<img", "</textarea", "</style", "</title", "<b>"):
        assert dangerous not in markup, dangerous
    # Bidi overrides and zero-width characters never reach the document at all: a path
    # that reads as one thing and is another is exactly the hazard this report is about.
    assert BIDI_OVERRIDE not in markup
    assert ZERO_WIDTH not in markup
    # It is all still *there*, just as character data. The claim span splits the escaped
    # run in two, which is precisely the case a naive highlighter gets wrong.
    assert "&lt;script&gt;" in markup
    assert "&lt;/script&gt;" in markup
    assert ">alert(1)</a>" in markup
    assert visible_text(body_of(fragment)) == expected_text(HOSTILE_BODY)


def test_a_span_covering_part_of_a_tag_like_run_stays_escaped() -> None:
    body = report_of(HOSTILE_BODY).body
    # The claim covers the middle of `<img src=x onerror=alert(1)>`, so the escaped run is
    # split across a segment boundary — the classic way a highlighter reopens a tag.
    claim = symbol("c1", (span_of(body, "src=x onerror"),))
    fragment = render(result_of(HOSTILE_BODY, claims=(claim,), items=(evidence("e1", "c1"),)))
    assert_inert(fragment.html)
    # `<img ` stays character data on one side of the cut, the claim text on the other.
    assert "&lt;img " in fragment.html
    assert ">src=x onerror</a>" in fragment.html
    assert visible_text(body_of(fragment)) == expected_text(HOSTILE_BODY)


def test_a_span_that_starts_inside_an_escaped_entity_is_still_safe() -> None:
    body_text = "value & other <tag> here\n"
    body = report_of(body_text).body
    # Starts on the `&`, which becomes `&amp;` — a naive offset-based splice would cut a
    # five-character entity out of a one-character span.
    claim = symbol("c1", (span_of(body, "& other <ta"),))
    fragment = render(result_of(body_text, claims=(claim,), items=(evidence("e1", "c1"),)))
    assert_inert(fragment.html)
    assert visible_text(body_of(fragment)) == expected_text(body_text)


def test_hostile_evidence_summary_cannot_break_out_of_the_attribute() -> None:
    body = report_of(NEST_BODY).body
    result = result_of(
        NEST_BODY,
        claims=(symbol("c1", (span_of(body, "hdr_decode"),)),),
        items=(evidence("e1", "c1", summary=HOSTILE_SUMMARY),),
    )
    markup = render(result).html
    assert_inert(markup)
    assert '"><img' not in markup
    assert "&quot;&gt;&lt;img" in markup
    assert BIDI_OVERRIDE not in markup


def test_hostile_ids_cannot_forge_an_attribute() -> None:
    body = report_of(NEST_BODY).body
    hostile_id = 'c" onmouseover="alert(1)'
    claim = symbol(hostile_id, (span_of(body, "hdr_decode"),))
    result = result_of(NEST_BODY, claims=(claim,), items=(evidence('e" x="y', hostile_id),))
    markup = render(result).html
    assert_inert(markup)
    assert hostile_id not in markup  # the quotes and spaces are gone, not just escaped
    assert 'href="#ev-exy"' in markup  # the id is sanitized, not escaped, for a fragment


def test_a_very_long_unbroken_run_cannot_widen_the_page() -> None:
    fragment = render(result_of("x" + "A" * 50_000))
    assert "overflow-wrap: anywhere" in fragment.css


# --- truncation -------------------------------------------------------------------------


def test_a_long_body_is_cut_and_says_so(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(report_pane, "MAX_BODY_CHARS", 40)
    body_text = "head " + "z" * 100 + " tail hdr_decode here\n"
    body = report_of(body_text).body
    inside = symbol("c-in", (span_of(body, "head"),))
    straddling = symbol("c-straddle", (Span(start=0, end=60, text=body[0:60]),))
    outside = symbol("c-out", (span_of(body, "hdr_decode"),))
    fragment = render(
        result_of(body_text, claims=(inside, straddling, outside), items=(evidence("e1", "c-in"),))
    )
    assert visible_text(body_of(fragment)) == clean(body[:40])
    assert "Showing the first 40 of" in fragment.html
    # The claim straddling the cut is underlined up to it, and the one past it is dropped.
    assert body_of(fragment).count('href="#ev-e1"') == 1
    assert_inert(fragment.html)


def test_a_body_within_the_cap_says_nothing_about_truncation() -> None:
    assert "Showing the first" not in render(nested_result()).html


# --- the page contract ------------------------------------------------------------------


def test_deterministic() -> None:
    first = render(nested_result())
    second = render(nested_result())
    assert first.html == second.html
    assert first.css == second.css
    assert first.js == second.js


def test_emits_no_script_and_no_inline_handler() -> None:
    fragment = render(nested_result())
    assert fragment.js == ""
    assert "<script" not in fragment.html
    assert_inert(fragment.html)


def test_makes_no_network_request() -> None:
    fragment = render(nested_result())
    for scheme in ("http://", "https://", "//cdn", "url(http", "@import"):
        assert scheme not in fragment.html + fragment.css, scheme


def test_hard_codes_no_colour() -> None:
    assert re.search(r"#[0-9a-fA-F]{3,8}\b", report_pane.CSS) is None
    assert "rgb(" not in report_pane.CSS


def test_the_pane_is_reachable_and_labelled() -> None:
    markup = render(nested_result()).html
    assert 'id="rp-heading"' in markup
    assert 'aria-labelledby="rp-heading"' in markup
    assert 'role="region"' in markup
    assert 'tabindex="0"' in markup  # a scrollable region must take keyboard focus


def test_the_legend_counts_claims_once_each() -> None:
    markup = render(nested_result()).html
    assert "1 supported" in markup
    assert "1 refuted" in markup
    assert "1 noted" in markup
    assert "1 not checked" in markup
    assert "4 of 4 claims are underlined" in markup
    assert "the claims table" in markup


def test_says_nothing_about_the_person_who_wrote_the_report() -> None:
    text = render(nested_result()).html.lower()
    for word in ("slop", "fake", "fabricat", " ai ", "llm"):
        assert word not in text, word
