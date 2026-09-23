# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The symbol timeline strip (SPEC §15.2 special views).

Three properties get most of the attention here.

*Uncertainty must not read as absence.* The strip exists to make "this function never
existed" visible, which is exactly why a release whose files did not parse cleanly has to
look different from a release that genuinely lacks the symbol (P4). Several tests assert
that the word "absent" never appears for such a release and that its cell carries a
different class from an absent one.

*The strip says nothing to a screen reader*, so the whole run is spelled out in the
``aria-label`` and repeated verbatim in visible text; a test compares the two.

*Release names come from the report*, so they are hostile (P7). The hostile test parses
the output with a real HTML parser and asserts no element and no event-handler attribute
was created, rather than grepping for substrings that legitimately survive as escaped text.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Any

import pytest

from nikasha.ingest import ingest_string
from nikasha.model.claims import SymbolClaim
from nikasha.model.evidence import Evidence
from nikasha.model.report import Span
from nikasha.model.result import ResolvedTarget, Result
from nikasha.render.html.components import timeline_strip
from nikasha.render.html.context import HtmlContext

REPORT = ingest_string("hdr_get is missing at v1.3.0", input_format="text")
SPAN = Span(start=0, end=7, text="hdr_get")

#: The vulnlab demo lab (examples/vulnlab/README.md): five releases, oldest first.
VULNLAB = ["v1.0.0", "v1.1.0", "v1.2.0", "v1.2.1", "v1.3.0"]

#: A bidi override, built rather than written: a literal one in the source is itself a hazard.
BIDI = chr(0x202E)

#: Markup, a URL scheme, a bidi override and an unbounded run, all through report fields.
HOSTILE = '</script><img src=x onerror=alert(1)>"><b>' + BIDI + "reversed"


def claim(name: str = "hdr_get", claim_id: str = "cl-000000000001") -> SymbolClaim:
    return SymbolClaim(
        id=claim_id,
        spans=(SPAN,),
        extractor="test",
        confidence=0.9,
        name=name,
        role="core",
        provenance="project_attributed",
    )


def evidence(
    details: dict[str, Any],
    *,
    claim_id: str = "cl-000000000001",
    outcome: str = "REFUTES",
    strength: float = -3.0,
    evidence_id: str = "ev000000000001",
    check_id: str = "C03",
) -> Evidence:
    return Evidence(
        id=evidence_id,
        check_id=check_id,
        claim_ids=(claim_id,),
        outcome=outcome,  # type: ignore[arg-type]
        strength=strength,
        group="locus",
        summary="a summary the strip does not use",
        details=details,
    )


def build(
    items: list[Evidence],
    *,
    claims: list[SymbolClaim] | None = None,
    ref: str | None = "v1.3.0",
) -> HtmlContext:
    result = Result(
        tool_version="0.0.0-test",
        report=REPORT,
        claims=tuple(claims if claims is not None else [claim()]),
        evidence=tuple(items),
        target=ResolvedTarget(
            repo_url="https://example.invalid/libhdr.git",
            ref_name=ref,
            commit="0" * 40,
            method="tag",
            confidence="high",
        ),
    )
    return HtmlContext(result=result)


def render(
    items: list[Evidence],
    *,
    claims: list[SymbolClaim] | None = None,
    ref: str | None = "v1.3.0",
) -> str:
    fragment = timeline_strip.render(build(items, claims=claims, ref=ref))
    assert fragment is not None
    return fragment.html


# --- the vulnlab shapes ------------------------------------------------------------------


def absent_elsewhere(
    symbol: str = "hdr_get",
    defined: tuple[str, ...] = ("v1.0.0", "v1.1.0", "v1.2.0", "v1.2.1"),
    **extra: Any,
) -> dict[str, Any]:
    """C03's ``absent_here_present_elsewhere`` details: the symbol moved out of the tree."""
    return {
        "outcome": "absent_here_present_elsewhere",
        "symbol": symbol,
        "releases_searched": list(VULNLAB),
        "runs": [[defined[0], defined[-1]]],
        "defined_in": list(defined),
        **extra,
    }


def never_in_history(symbol: str = "hdr_parse_headers", **extra: Any) -> dict[str, Any]:
    """C03's ``never_in_history_core`` details: nothing defines it and history is complete."""
    return {
        "outcome": "never_in_history_core",
        "symbol": symbol,
        "releases_searched": list(VULNLAB),
        "suggestions": [],
        "history_complete": True,
        "never_in_history": True,
        **extra,
    }


def uncertain(symbol: str = "hdr_fold", releases: tuple[str, ...] = ("v1.2.0",)) -> dict[str, Any]:
    """C03's ``uncertain`` details: mentioned in files that did not parse cleanly."""
    return {
        "outcome": "uncertain",
        "symbol": symbol,
        "releases_searched": list(VULNLAB),
        "uncertain_releases": list(releases),
    }


# --- nothing to show ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "details",
    [
        {},
        {"outcome": "defined", "symbol": "hdr_get", "n_definitions": 2},
        {"symbol": "hdr_get", "releases_searched": []},
        {"symbol": "hdr_get", "releases_searched": "v1.0.0"},
        {"symbol": "hdr_get", "releases_searched": [1, 2, 3]},
        {"symbol": "hdr_get", "releases_searched": None},
    ],
    ids=["empty", "defined", "no-releases", "not-a-list", "not-strings", "null"],
)
def test_returns_none_without_timeline_data(details: dict[str, Any]) -> None:
    assert timeline_strip.render(build([evidence(details)])) is None


def test_returns_none_for_other_checks() -> None:
    other = evidence(absent_elsewhere(), check_id="C05")
    assert timeline_strip.render(build([other])) is None


def test_returns_none_with_no_evidence_at_all() -> None:
    assert timeline_strip.render(build([])) is None


def test_returns_none_when_the_symbol_cannot_be_named() -> None:
    """Neither the details nor the claim say which symbol this is: draw nothing, not "None"."""
    details = {"releases_searched": list(VULNLAB), "defined_in": ["v1.0.0"]}
    assert timeline_strip.render(build([evidence(details)], claims=[])) is None


def test_symbol_falls_back_to_the_claim() -> None:
    details = {"releases_searched": list(VULNLAB), "defined_in": ["v1.0.0"]}
    html = render([evidence(details)], claims=[claim(name="util_strip")])
    assert "util_strip" in html


# --- the three states ---------------------------------------------------------------------


def test_present_and_absent_cells() -> None:
    html = render([evidence(absent_elsewhere())])
    assert html.count("tl-present") == 4 + 1  # four cells plus the legend swatch
    assert html.count("tl-absent") == 1 + 1
    assert "tl-uncertain" not in html
    assert "tl-unknown" not in html


def test_the_run_is_spelled_out() -> None:
    html = render([evidence(absent_elsewhere())])
    assert "hdr_get is defined in v1.0.0 through v1.2.1, absent in v1.3.0." in html
    assert "The report names v1.3.0, where it is absent." in html


def test_a_symbol_that_appears_later() -> None:
    """util_copy_value arrives in v1.1.0; a report naming v1.0.0 gets the leading gap."""
    details = absent_elsewhere(
        symbol="util_copy_value", defined=("v1.1.0", "v1.2.0", "v1.2.1", "v1.3.0")
    )
    html = render([evidence(details)], ref="v1.0.0")
    assert "util_copy_value is absent in v1.0.0, defined in v1.1.0 through v1.3.0." in html
    assert "The report names v1.0.0, where it is absent." in html


def test_a_symbol_defined_in_exactly_one_release() -> None:
    details = absent_elsewhere(symbol="util_trim", defined=("v1.0.0",))
    html = render([evidence(details)], ref="v1.1.0")
    assert "util_trim is defined in v1.0.0, absent in v1.1.0 through v1.3.0." in html


def test_never_in_history_says_so() -> None:
    html = render([evidence(never_in_history())])
    assert (
        "hdr_parse_headers is defined in none of the 5 sampled releases,"
        " v1.0.0 through v1.3.0." in html
    )
    assert "It never appears anywhere in this repository&#x27;s history." in html
    assert html.count("tl-absent") == 5 + 1
    assert "tl-present" not in html


def test_uncertain_is_not_absent() -> None:
    """P4: a release whose files did not parse is hatched, and is never called absent."""
    html = render([evidence(uncertain(), outcome="NEUTRAL", strength=0.0)])
    assert "tl-uncertain" in html
    assert "tl-absent" not in html
    assert "not established in v1.2.0" in html
    assert "absent" not in html
    assert "did not parse cleanly" in html


def test_uncertain_does_not_invent_absence_for_the_other_releases() -> None:
    """C03's uncertain branch drops ``defined_in``, so the rest is unknown, not absent."""
    html = render([evidence(uncertain(), outcome="NEUTRAL", strength=0.0)])
    assert "tl-unknown" in html
    assert "not determined in v1.0.0 through v1.1.0" in html
    assert "not determined in v1.2.1 through v1.3.0" in html


def test_uncertain_and_absent_look_different() -> None:
    """Whatever the palette does, the two must not resolve to the same cell class."""
    assert timeline_strip.STATE_CLASS["uncertain"] != timeline_strip.STATE_CLASS["absent"]
    assert timeline_strip.STATE_CLASS["unknown"] != timeline_strip.STATE_CLASS["absent"]
    html = render([evidence(uncertain(), outcome="NEUTRAL", strength=0.0)])
    assert f'fill="url(#{timeline_strip.HATCH_ID})"' in html
    assert f'id="{timeline_strip.HATCH_ID}"' in html


def test_legend_lists_only_the_states_used() -> None:
    html = render([evidence(absent_elsewhere())])
    assert "defined in this release" in html
    assert "not defined in this release" in html
    assert "so absence is not established" not in html
    uncertain_html = render([evidence(uncertain(), outcome="NEUTRAL", strength=0.0)])
    assert "so absence is not established" in uncertain_html
    assert "this evidence does not say" in uncertain_html


# --- the claimed release --------------------------------------------------------------------


def test_the_claimed_release_is_marked() -> None:
    html = render([evidence(absent_elsewhere())])
    assert "tl-claimed" in html
    assert "tl-named" in html
    assert "the release the report names" in html


def test_the_claimed_marker_carries_the_outcome_colour() -> None:
    absent_at_claim = render([evidence(absent_elsewhere())], ref="v1.3.0")
    assert 'class="tl-claimed bad"' in absent_at_claim
    present_at_claim = render([evidence(absent_elsewhere())], ref="v1.2.0")
    assert 'class="tl-claimed ok"' in present_at_claim


def test_a_claimed_release_outside_the_sample_is_said_in_words() -> None:
    html = render([evidence(absent_elsewhere())], ref="v9.9.9")
    assert "The report names v9.9.9, which is not among the sampled releases." in html
    assert "tl-claimed" not in html


def test_no_resolved_ref_at_all() -> None:
    html = render([evidence(absent_elsewhere())], ref=None)
    assert "The report names" not in html
    assert "tl-claimed" not in html


# --- accessibility ----------------------------------------------------------------------------


def test_aria_label_repeats_the_visible_sentence() -> None:
    html = render([evidence(absent_elsewhere())])
    label = re.search(r'role="img" aria-label="([^"]*)"', html)
    assert label is not None
    said = re.search(r'<p class="tl-says">([^<]*)</p>', html)
    assert said is not None
    # The two escapes differ (attr() also escapes = and quotes), so compare the plain text.
    assert label.group(1).replace("&#x27;", "'") == said.group(1).replace("&#x27;", "'")
    assert "defined in v1.0.0 through v1.2.1" in said.group(1)


def test_the_svg_is_an_image_with_a_name() -> None:
    html = render([evidence(absent_elsewhere())])
    assert 'role="img"' in html
    assert "aria-label=" in html
    assert 'aria-labelledby="tl-title"' in html


def test_the_scroll_container_is_reachable_by_keyboard() -> None:
    html = render([evidence(absent_elsewhere())])
    assert 'class="tl-scroll" role="group" tabindex="0"' in html


# --- notes -------------------------------------------------------------------------------------


def test_incomplete_history_is_never_silently_dropped() -> None:
    details = never_in_history(
        history_complete=False,
        never_in_history=None,
        history_gap="the repository is a shallow clone",
    )
    html = render([evidence(details, outcome="NEUTRAL", strength=0.0)])
    assert "History could not be searched exhaustively" in html
    assert "the repository is a shallow clone" in html
    assert "never appears anywhere" not in html


def test_suggestions_are_shown() -> None:
    details = never_in_history(suggestions=["hdr_parse_header", "hdr_parse_block"])
    html = render([evidence(details)])
    assert "Similar names in the code: hdr_parse_header, hdr_parse_block." in html


# --- geometry and bounds -----------------------------------------------------------------------


def test_viewbox_depends_on_the_release_count_not_the_name_length() -> None:
    short = render([evidence(absent_elsewhere())])
    long_names = absent_elsewhere()
    long_names["releases_searched"] = ["A" * 400, "B" * 400, "C" * 400, "D" * 400, "E" * 400]
    long_names["defined_in"] = ["A" * 400]
    wide = render([evidence(long_names)])
    box = re.search(r'viewBox="0 0 (\d+) (\d+)"', short)
    assert box is not None
    assert box.group(0) in wide
    # 2*PAD + 5 cells + 4 gaps, and the three bands of the strip.
    assert box.group(1) == "424"
    assert box.group(2) == "60"


def test_a_long_release_name_is_truncated_and_clamped() -> None:
    details = absent_elsewhere()
    details["releases_searched"] = ["A" * 400, *VULNLAB[1:]]
    details["defined_in"] = ["v1.1.0"]
    html = render([evidence(details)])
    labels = re.findall(r"<text[^>]*>([^<]*)</text>", html)
    assert labels
    assert all(len(label) <= timeline_strip.LABEL_CHARS for label in labels)
    assert "…" in html
    # Prose gets a longer budget than a cell label, but it is still a budget.
    assert "A" * (timeline_strip.PROSE_CHARS + 5) not in html
    # A label that is still wide for its cell is squeezed rather than allowed to overflow.
    assert 'textLength="78" lengthAdjust="spacingAndGlyphs"' in html


def test_many_releases_are_windowed_around_what_matters() -> None:
    releases = [f"v0.{index}" for index in range(60)]
    details = {
        "outcome": "absent_here_present_elsewhere",
        "symbol": "hdr_old",
        "releases_searched": releases,
        "defined_in": ["v0.50"],
    }
    html = render([evidence(details)], ref="v0.55")
    assert html.count('class="tl-cell') == timeline_strip.MAX_RELEASES + 2  # + 2 swatches
    assert "12 earlier releases not shown." in html
    assert 'viewBox="0 0 919 60"' in html
    assert "v0.50" in html and "v0.55" in html
    assert "v0.0<" not in html


def test_compact_mode_labels_only_the_edges_and_the_claim() -> None:
    releases = [f"v0.{index}" for index in range(20)]
    details = {
        "symbol": "hdr_old",
        "releases_searched": releases,
        "defined_in": ["v0.9"],
    }
    html = render([evidence(details)], ref="v0.10")
    assert html.count('class="tl-label') == 3
    assert 'text-anchor="start"' in html
    assert 'text-anchor="end"' in html


def test_compact_labels_get_more_room_than_one_thin_cell() -> None:
    """A 16px cell is not a label budget; the clearance rule buys four cells of room."""
    releases = ["release-candidate-" + f"{index}" for index in range(20)]
    details = {"symbol": "hdr_old", "releases_searched": releases, "defined_in": [releases[0]]}
    html = render([evidence(details)], ref=releases[10])
    assert f'textLength="{timeline_strip.COMPACT_LABEL_ROOM}"' in html
    assert f'textLength="{timeline_strip.COMPACT_CELL}"' not in html


def test_only_so_many_strips() -> None:
    items = [
        evidence(
            never_in_history(symbol=f"sym_{index:02d}"),
            claim_id=f"cl-{index:014d}",
            evidence_id=f"ev{index:012d}",
        )
        for index in range(12)
    ]
    claims = [claim(name=f"sym_{index:02d}", claim_id=f"cl-{index:014d}") for index in range(12)]
    html = render(items, claims=claims)
    assert html.count('class="tl-strip panel"') == timeline_strip.MAX_STRIPS
    assert "4 more symbol timelines are in the evidence column." in html


def test_one_strip_per_symbol() -> None:
    first = evidence(absent_elsewhere(), evidence_id="ev000000000001")
    second = evidence(absent_elsewhere(), evidence_id="ev000000000002", strength=-1.0)
    html = render([first, second])
    assert html.count('class="tl-strip panel"') == 1


def test_strip_ids_are_unique() -> None:
    items = [
        evidence(
            never_in_history(symbol=f"sym_{index}"),
            claim_id=f"cl-{index:014d}",
            evidence_id="",  # css_ident falls back to a constant: the index must still split them
        )
        for index in range(3)
    ]
    claims = [claim(name=f"sym_{index}", claim_id=f"cl-{index:014d}") for index in range(3)]
    html = render(items, claims=claims)
    ids = re.findall(r'id="(tl-\d+-[^"]*)"', html)
    assert len(ids) == len(set(ids)) == 3


# --- ordering and determinism -------------------------------------------------------------------


def test_refutations_come_first() -> None:
    weak = evidence(
        never_in_history(symbol="aaa_first_alphabetically"),
        claim_id="cl-00000000000a",
        evidence_id="ev00000000000a",
        outcome="NEUTRAL",
        strength=0.0,
    )
    strong = evidence(
        absent_elsewhere(symbol="zzz_last_alphabetically"),
        claim_id="cl-00000000000z",
        evidence_id="ev00000000000z",
    )
    claims = [
        claim(name="aaa_first_alphabetically", claim_id="cl-00000000000a"),
        claim(name="zzz_last_alphabetically", claim_id="cl-00000000000z"),
    ]
    html = render([weak, strong], claims=claims)
    assert html.index("zzz_last_alphabetically") < html.index("aaa_first_alphabetically")


def test_rendering_twice_is_byte_identical() -> None:
    items = [
        evidence(absent_elsewhere(), evidence_id="ev000000000001"),
        evidence(
            uncertain(symbol="hdr_fold"),
            claim_id="cl-000000000002",
            evidence_id="ev000000000002",
            outcome="NEUTRAL",
            strength=0.0,
        ),
    ]
    claims = [claim(), claim(name="hdr_fold", claim_id="cl-000000000002")]
    first = timeline_strip.render(build(items, claims=claims))
    second = timeline_strip.render(build(items, claims=claims))
    assert first is not None and second is not None
    assert first.html == second.html
    assert first.css == second.css
    assert first.js == second.js


# --- hostile input --------------------------------------------------------------------------------


class _Collector(HTMLParser):
    """Every element and attribute the browser would actually build from our output."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: list[str] = []
        self.attributes: list[tuple[str, str | None]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append(tag)
        self.attributes.extend(attrs)

    handle_startendtag = handle_starttag


def parse(html: str) -> _Collector:
    collector = _Collector()
    collector.feed(html)
    collector.close()
    return collector


#: What we draw with. Anything else in the output came from the input, which is the bug.
ALLOWED_TAGS = {
    "section", "h2", "h3", "p", "div", "ul", "li", "span",
    "svg", "defs", "pattern", "line", "rect", "path", "text", "g", "title",
}  # fmt: skip


def test_hostile_input_is_inert() -> None:
    details = {
        "outcome": "absent_here_present_elsewhere",
        "symbol": HOSTILE,
        "releases_searched": [HOSTILE, "javascript:alert(1)", "v1.0.0", "A" * 400],
        "defined_in": ["v1.0.0"],
        "history_complete": False,
        "history_gap": "</p><svg onload=alert(1)>",
        "suggestions": ["<b>bold</b>", BIDI + "evil"],
    }
    html = render([evidence(details)], ref=HOSTILE)
    parsed = parse(html)

    assert set(parsed.tags) <= ALLOWED_TAGS, set(parsed.tags) - ALLOWED_TAGS
    assert not [name for name, _ in parsed.attributes if name.startswith("on")]
    # A release literally named "javascript:alert(1)" is fine as text; what must never
    # happen is it reaching a URL sink. The strip renders no links, so there are none.
    assert not [name for name, _ in parsed.attributes if name in {"href", "src", "xlink:href"}]
    # The escaped text is still there, as text: nothing was silently dropped.
    assert "&lt;img src=x onerror=alert(1)&gt;" in html
    # Controls, bidi overrides and unbounded runs do not survive.
    assert BIDI not in html
    assert "A" * 45 not in html


def test_hostile_input_does_not_raise_for_any_field() -> None:
    """Each field on its own, so a crash cannot hide behind another field's escaping."""
    for field in ("symbol", "history_gap"):
        details = {
            "symbol": "ok_symbol",
            "releases_searched": list(VULNLAB),
            "defined_in": ["v1.0.0"],
            "history_complete": False,
            "history_gap": "fine",
            field: HOSTILE,
        }
        assert timeline_strip.render(build([evidence(details)])) is not None


def test_no_script_element_and_no_inline_handlers() -> None:
    html = render([evidence(absent_elsewhere()), evidence(uncertain(), evidence_id="ev2")])
    assert "<script" not in html.lower()
    assert re.search(r"\son[a-z]+\s*=\s*[\"']", html) is None
    assert "style=" not in html


def test_the_component_emits_no_javascript() -> None:
    fragment = timeline_strip.render(build([evidence(absent_elsewhere())]))
    assert fragment is not None
    assert fragment.js == ""


# --- the module contract ----------------------------------------------------------------


def test_module_contract() -> None:
    assert timeline_strip.ORDER == 40
    assert callable(timeline_strip.render)


def test_only_theme_variables_are_used() -> None:
    """No hard-coded colour: light and dark both have to work."""
    css = timeline_strip.CSS
    assert re.search(r"#[0-9a-fA-F]{3,8}\b", css) is None
    assert re.search(r"\brgba?\(", css) is None
    for variable in re.findall(r"var\((--[a-z-]+)\)", css):
        assert variable in {"--ok", "--bad", "--warn", "--muted", "--border", "--sans"}
