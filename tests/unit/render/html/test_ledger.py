# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The HTML evidence ledger (SPEC §14.5, §15.2): the arithmetic behind the score.

The point of this view is that a reader can redo the sum by hand, so the tests check the
numbers rather than the prose: the prior, one row per contribution with its printed
strength, damping weight and contribution, a running total that lands exactly on
``ledger.log_odds``, and the score that follows from it (P6).

The **damping weight** column gets its own tests because it is the claim this tool makes
about itself — that ten correlated findings in one group were not counted ten times. A
column showing 1.000, 0.500, 0.250 with no explanation would be noise, so the sentence
above the table is asserted too.

Markup is checked by parsing it: :class:`html.parser.HTMLParser` sees what a browser sees,
so "no ``<script>``" and "no inline handler" are asserted about real tags and attributes
rather than about substrings that hostile *text* also contains.
"""

from __future__ import annotations

from html.parser import HTMLParser

from nikasha.fuse.scoring import Ledger, fuse
from nikasha.ingest import ingest_string
from nikasha.model.evidence import Evidence
from nikasha.model.result import Result
from nikasha.model.verdict import Verdict
from nikasha.render.html.components import ledger as ledger_view
from nikasha.render.html.context import Fragment, HtmlContext

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
BANNED_WORDS = ("slop", "fake", "fabricat")


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


def evidence(
    eid: str,
    *,
    check_id: str = "C03",
    group: str = "locus",
    outcome: str = "REFUTES",
    strength: float = -2.5,
    summary: str = "not defined in any release",
) -> Evidence:
    return Evidence(
        id=eid,
        check_id=check_id,
        claim_ids=(f"claim-{eid}",),
        outcome=outcome,  # type: ignore[arg-type]
        strength=strength,
        group=group,
        summary=summary,
    )


#: Two groups, a damped second finding inside one of them, and a NEUTRAL item that must
#: never take a damping slot (SPEC §14.1).
EVIDENCE: tuple[Evidence, ...] = (
    evidence("e1", check_id="C03", group="locus", strength=-2.5, summary="not defined anywhere"),
    evidence(
        "e2",
        check_id="C01",
        group="version",
        outcome="SUPPORTS",
        strength=1.25,
        summary="v1.2.0 is a released tag",
    ),
    evidence(
        "e3",
        check_id="C04",
        group="locus",
        strength=-0.5,
        summary="line 412 is past the end of the file",
    ),
    evidence(
        "e4",
        check_id="C21",
        group="meta",
        outcome="NEUTRAL",
        strength=0.0,
        summary="the report cites no upstream issue",
    ),
)

VERDICT = Verdict(
    label="UNGROUNDED",
    score=18,
    confidence="medium",
    rule="3a: a core locus that never existed",
)


def context(
    items: tuple[Evidence, ...] = EVIDENCE,
    *,
    ledger: Ledger | None = None,
    verdict: Verdict | None = VERDICT,
    build: bool = True,
) -> HtmlContext:
    result = Result(tool_version="0.0.0-test", report=REPORT, evidence=items, verdict=verdict)
    if ledger is None and build:
        ledger = fuse(items)
    return HtmlContext(result=result, ledger=ledger, tool_version="0.0.0-test")


def render(ctx: HtmlContext) -> str:
    fragment = ledger_view.render(ctx)
    assert fragment is not None
    return fragment.html


# --- shape -------------------------------------------------------------------------------


def test_order_is_90() -> None:
    assert ledger_view.ORDER == 90


def test_returns_none_without_a_ledger() -> None:
    """A report rendered from a saved RESULT.json has no ledger to show."""
    assert ledger_view.render(context(build=False)) is None


def test_returns_a_fragment_with_css_and_no_js() -> None:
    fragment = ledger_view.render(context())
    assert isinstance(fragment, Fragment)
    assert ".lg" in fragment.css
    assert fragment.js == ""


def test_it_ships_collapsed() -> None:
    """A triager wants the verdict; the reader who distrusts it opens this."""
    seen = scan(render(context()))
    assert "details" in seen.tags
    assert [name for tag, name, _ in seen.attributes if tag == "details"] == []


def test_the_summary_carries_the_headline_numbers() -> None:
    html = render(context())
    assert "How this score was computed" in html
    assert "score 18/100" in html
    assert "3 scoring findings" in html
    assert "2 groups" in html


# --- the damping weight, which is the point ----------------------------------------------


def test_the_weight_column_is_explained_above_the_table() -> None:
    html = render(context())
    assert "damping weight" in html
    assert "halved" in html
    assert "ten times the certainty" in html


def test_the_weight_column_has_a_header() -> None:
    assert "Damping weight" in render(context())


def test_the_strongest_finding_in_a_group_counts_in_full() -> None:
    html = render(context())
    assert "1.000" in html
    assert "counted in full" in html


def test_the_second_finding_in_a_group_is_halved() -> None:
    """-0.50 at half weight contributes -0.250, not -0.500."""
    html = render(context())
    assert "0.500" in html
    assert "1/2 of full" in html
    assert "-0.250" in html


def test_a_deep_rank_is_described_rather_than_shown_as_a_fraction() -> None:
    assert ledger_view._fraction(0) == "counted in full"
    assert ledger_view._fraction(1) == "1/2 of full"
    assert ledger_view._fraction(3) == "1/8 of full"
    assert ledger_view._fraction(40) == "the weakest of many here"


# --- the arithmetic ----------------------------------------------------------------------


def test_the_prior_starts_the_running_column() -> None:
    html = render(context())
    assert "Prior, before any evidence" in html
    assert "+0.000" in html


def test_every_contribution_gets_a_row_with_its_numbers() -> None:
    html = render(context())
    for check_id in ("C03", "C04", "C01"):
        assert check_id in html
    for strength in ("-2.50", "-0.50", "+1.25"):
        assert strength in html
    for contribution in ("-2.500", "-0.250", "+1.250"):
        assert contribution in html


def test_the_running_total_ends_on_the_log_odds() -> None:
    built = fuse(EVIDENCE)
    html = render(context(ledger=built))
    assert f"{built.log_odds:+.3f}" in html
    assert "-1.500" in html
    assert f"{built.score}/100" in html


def test_neutral_evidence_never_takes_a_damping_slot() -> None:
    """Three rows of arithmetic for four pieces of evidence (SPEC §14.1)."""
    html = render(context())
    assert "the report cites no upstream issue" not in html
    assert "C21" not in html


def test_groups_are_labelled_for_a_human() -> None:
    html = render(context())
    assert "Files and symbols" in html
    assert "Versions" in html


def test_the_rule_that_fired_is_named() -> None:
    html = render(context())
    assert "UNGROUNDED" in html
    assert "3a: a core locus that never existed" in html


def test_the_metadata_needed_to_redo_the_sum_is_present() -> None:
    html = render(context())
    assert "locus, version" in html
    assert "4.25" in html  # Σ|strength| before damping
    assert "defaults-v1" in html
    assert "medium" in html


def test_each_finding_links_to_its_evidence_card() -> None:
    html = render(context())
    assert 'href="#ev-e1"' in html
    assert 'href="#ev-e3"' in html


def test_a_contribution_whose_evidence_is_missing_shows_its_id() -> None:
    built = fuse(EVIDENCE)
    ctx = context((), ledger=built)
    html = render(ctx)
    assert "e1" in html
    assert 'href="#ev-e1"' not in html


# --- degradation -------------------------------------------------------------------------


def test_an_empty_ledger_still_renders() -> None:
    html = render(context((), ledger=fuse(())))
    assert "No evidence moved the score" in html
    assert "+0.000" in html
    assert "50/100" in html


def test_a_ledger_without_a_verdict_omits_the_rule() -> None:
    html = render(context(verdict=None))
    assert "The verdict" not in html
    assert "Confidence" not in html
    assert "Damping weight" in html


def test_a_verdict_without_a_rule_omits_the_rule() -> None:
    plain = Verdict(label="MIXED", score=50, confidence="low")
    html = render(context(verdict=plain))
    assert "came from rule" not in html


# --- P1, P2, P7 --------------------------------------------------------------------------


def test_rendering_twice_is_byte_identical() -> None:
    assert render(context()) == render(context())


def test_wording_is_about_claims_not_people() -> None:
    html = render(context()).lower()
    for word in BANNED_WORDS:
        assert word not in html


def test_hostile_input_is_inert() -> None:
    items = (evidence(HOSTILE, check_id=HOSTILE, group=HOSTILE, summary=HOSTILE),)
    built = fuse(items, calibration=HOSTILE)
    hostile_verdict = Verdict(label="UNGROUNDED", score=4, confidence="low", rule=HOSTILE)
    html = render(context(items, ledger=built, verdict=hostile_verdict))
    assert_inert(html)
    assert "<script" not in html.lower()
    assert "<img" not in html
    assert ESC not in html
    assert BIDI not in html
    assert "&lt;" in html  # the angle brackets survived, escaped


def test_hostile_ids_cannot_break_out_of_an_anchor() -> None:
    items = (evidence('y"><script>', summary="absent at v1.2.0"),)
    html = render(context(items, ledger=fuse(items)))
    assert_inert(html)
    assert 'href="#ev-yscript"' in html


def test_an_unbounded_summary_is_clipped() -> None:
    items = (evidence("e1", summary="B" * 500),)
    html = render(context(items, ledger=fuse(items)))
    assert "B" * 400 not in html
    assert "…" in html


def test_no_inline_handlers_in_benign_output() -> None:
    assert_inert(render(context()))
