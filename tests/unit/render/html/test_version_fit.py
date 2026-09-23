# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The version fit chart (SPEC §15.2), built from C10 evidence alone.

Every fixture here builds :class:`Evidence` by hand rather than running C10: the component
is a pure function of ``details``, and a test that needed git would only prove that the
check still works.

Three hazards get their own tests. Release names are tag names from a repository the
report chose, so they are hostile input (P7) and the chart must stay inert and still parse
as XML. ``scan_complete: False`` must be visible, because a chart that hid a truncated
scan would show "no other release fits" — the one thing a truncated scan cannot support
(P4). And a project with hundreds of releases must still produce a chart that fits on a
page, without quietly dropping marks.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Any

import pytest

from nikasha.ingest import ingest_string
from nikasha.model.evidence import Evidence
from nikasha.model.result import Result
from nikasha.render.html.components import version_fit
from nikasha.render.html.context import Fragment, HtmlContext

REPORT = ingest_string("a report mentioning a crash", input_format="text")

#: Tag names an attacker could get into the repository, plus the transports that carry
#: them into the page: an attribute (aria-label, title) and character data.
HOSTILE = (
    "</script><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    '"><script>alert(1)</script>',
    "javascript:alert(1)",
    "v1.0.0\x1b[31m\x07",
    "v1.0.0\u202e0.0.1v",
    "v" + "A" * 400,
)

#: Wording that describes a person or guesses at intent rather than stating evidence (P1).
BANNED_WORDS = ("slop", "fake", "fabricat")


def details(
    ratios: dict[str, Any],
    *,
    claimed: Any = "v1.2.0",
    best: Any = "v1.2.1",
    claimed_ratio: Any = 0.5,
    best_ratio: Any = 1.0,
    perfect: Any = None,
    scored: Any = None,
    radius: Any = 15,
    complete: Any = True,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """C10's details dict, with the exact keys the check records."""
    out: dict[str, Any] = {
        "claimed_release": claimed,
        "claimed_ratio": claimed_ratio,
        "best_release": best,
        "best_ratio": best_ratio,
        "perfect_releases": [best] if perfect is None else perfect,
        "ratios": ratios,
        "releases_scored": len(ratios) if scored is None else scored,
        "window_radius": radius,
        "scan_complete": complete,
        "outcome": "other_release_fits",
    }
    out.update(extra or {})
    return out


def evidence(
    payload: dict[str, Any],
    *,
    eid: str = "e1",
    check_id: str = "C10",
    strength: float = -0.3,
) -> Evidence:
    return Evidence(
        id=eid,
        check_id=check_id,
        claim_ids=("c1",),
        outcome="REFUTES",
        strength=strength,
        group="trace",
        summary="this trace matches v1.2.1 exactly",
        details=payload,
    )


def context(*items: Evidence) -> HtmlContext:
    result = Result(tool_version="0.0.0-test", report=REPORT, evidence=items)
    return HtmlContext(result=result)


def render(*items: Evidence) -> Fragment:
    fragment = version_fit.render(context(*items))
    assert fragment is not None
    return fragment


def html_of(*items: Evidence) -> str:
    return render(*items).html


def svg_of(markup: str) -> ET.Element:
    """The chart parsed as XML: escaping bugs usually show up as a parse error first.

    The input is markup this package just wrote, from a fixture with no entities and no
    doctype, so the stdlib parser has nothing to be tricked by.
    """
    start = markup.index("<svg")
    end = markup.index("</svg>") + len("</svg>")
    return ET.fromstring(markup[start:end])  # noqa: S314


def tags(markup: str) -> list[str]:
    return re.findall(r"<[^>]*>", markup)


def rects(markup: str) -> list[tuple[str, float, float]]:
    """``(class, width, height)`` for every bar, in document order."""
    found = re.findall(
        r'<rect class="([^"]*)" x="([-\d.]+)" y="([-\d.]+)" width="([\d.]+)" height="([\d.]+)"',
        markup,
    )
    return [(klass, float(width), float(height)) for klass, _x, _y, width, height in found]


def simple_ratios(count: int = 5) -> dict[str, float]:
    return {f"v1.{i}.0": round(i / (count - 1), 3) for i in range(count)}


# --- the contract -----------------------------------------------------------------------


def test_order_is_the_assigned_slot() -> None:
    assert version_fit.ORDER == 60


def test_no_evidence_at_all_renders_nothing() -> None:
    assert version_fit.render(context()) is None


def test_other_checks_are_not_drawn() -> None:
    assert version_fit.render(context(evidence(details(simple_ratios()), check_id="C08"))) is None


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"ratios": {}},
        {"ratios": None},
        {"ratios": []},
        {"ratios": "v1.0.0"},
        {"ratios": {"v1.0.0": "0.9"}},
        {"ratios": {"v1.0.0": None}},
        {"ratios": {"v1.0.0": True}},
        {"ratios": {"v1.0.0": float("nan")}},
        {"ratios": {"v1.0.0": float("inf")}},
        {"ratios": {7: 0.5}},
    ],
)
def test_unusable_details_render_nothing_rather_than_raising(payload: dict[str, Any]) -> None:
    assert version_fit.render(context(evidence(payload))) is None


def test_every_detail_key_may_be_the_wrong_type() -> None:
    """A ``Result`` can be loaded from a JSON file this process did not write."""
    payload = details(
        {"v1.0.0": 0.5, "v1.1.0": 1},
        claimed=["v1.0.0"],
        best=None,
        claimed_ratio="high",
        best_ratio={"r": 1},
        perfect="v1.1.0",
        scored=True,
        radius="fifteen",
        complete="yes",
    )
    markup = html_of(evidence(payload))
    assert len(rects(markup)) == 2
    # scan_complete is not True, so the chart must not claim a complete scan.
    assert "partial scan" in markup


def test_fragment_carries_css_and_no_script() -> None:
    fragment = render(evidence(details(simple_ratios())))
    assert fragment.js == ""
    assert ".vf-bar" in fragment.css
    assert "<script" not in fragment.html
    assert not [tag for tag in tags(fragment.html) if re.search(r"\son\w+\s*=", tag)]


# --- the chart --------------------------------------------------------------------------


def test_one_mark_per_release_in_release_order() -> None:
    ratios = {"v2.0.0": 0.2, "v1.0.0": 0.9, "v1.5.0": 0.0}  # C10's order, not sorted
    markup = html_of(evidence(details(ratios, claimed="v1.0.0", best="v1.0.0", best_ratio=0.9)))
    labels = re.findall(r'<text class="vf-name"[^>]*>([^<]*)</text>', markup)
    assert labels == ["v2.0.0", "v1.0.0", "v1.5.0"]
    assert len(rects(markup)) == 3


def test_bar_height_is_proportional_to_the_ratio() -> None:
    ratios = {"v1.0.0": 0.0, "v1.1.0": 0.5, "v1.2.0": 1.0}
    markup = html_of(evidence(details(ratios, claimed="v1.0.0", best="v1.2.0")))
    heights = [height for _klass, _width, height in rects(markup)]
    assert heights[2] == pytest.approx(version_fit._PLOT_H)
    assert heights[1] == pytest.approx(version_fit._PLOT_H / 2)
    # A zero score still draws a stub: "scored, nothing fitted" is not "never scored".
    assert 0 < heights[0] < 2


def test_claimed_and_best_are_marked_distinctly() -> None:
    markup = html_of(evidence(details(simple_ratios(), claimed="v1.0.0", best="v1.4.0")))
    classes = [klass for klass, _w, _h in rects(markup)]
    assert classes.count("vf-bar vf-claimed") == 1
    assert classes.count("vf-bar vf-best") == 1
    assert classes.count("vf-bar") == 3
    assert markup.count('class="vf-mark-claimed"') == 1
    assert markup.count('class="vf-mark-best"') == 1


def test_one_release_can_be_both_claimed_and_best() -> None:
    markup = html_of(
        evidence(details(simple_ratios(), claimed="v1.4.0", best="v1.4.0", claimed_ratio=1.0))
    )
    assert [klass for klass, _w, _h in rects(markup)].count("vf-bar vf-claimed vf-best") == 1
    assert markup.count('class="vf-mark-claimed"') == 1
    assert markup.count('class="vf-mark-best"') == 1


def test_gridlines_carry_the_scale() -> None:
    markup = html_of(evidence(details(simple_ratios())))
    ticks = re.findall(r'<text class="vf-tick"[^>]*>([^<]*)</text>', markup)
    assert ticks == ["100%", "50%", "0"]


def test_marks_stay_inside_the_viewbox() -> None:
    markup = html_of(evidence(details(simple_ratios(9))))
    chart = svg_of(markup)
    assert chart.get("viewBox") == "0 0 1000 230"
    drawn = list(chart.iter("rect"))
    assert len(drawn) == 9
    for rect in drawn:
        left = float(rect.get("x") or 0)
        top = float(rect.get("y") or 0)
        assert left >= 0
        assert left + float(rect.get("width") or 0) <= version_fit._VIEW_W
        assert top >= version_fit._PAD_T
        assert top + float(rect.get("height") or 0) <= version_fit._BASE_Y


def test_a_crafted_ratio_outside_zero_to_one_cannot_escape_the_plot() -> None:
    markup = html_of(evidence(details({"v1.0.0": 9.0, "v1.1.0": -4.0}, best_ratio=9.0)))
    heights = [height for _klass, _width, height in rects(markup)]
    assert max(heights) <= version_fit._PLOT_H
    assert min(heights) > 0


# --- the wording ------------------------------------------------------------------------


def test_claimed_release_fitting_exactly_is_said_plainly() -> None:
    markup = html_of(
        evidence(
            details(
                {"v1.1.0": 0.5, "v1.2.0": 1.0},
                claimed="v1.2.0",
                best="v1.2.0",
                claimed_ratio=1.0,
            )
        )
    )
    assert "fits v1.2.0, the release the report names, exactly" in markup


def test_a_neighbouring_release_fitting_is_framed_as_a_version_mismatch() -> None:
    """The most useful sentence on the page: a real bug reported against the wrong version."""
    markup = html_of(evidence(details({"v1.2.0": 0.5, "v1.2.1": 1.0})))
    assert "fits v1.2.1 exactly" in markup
    assert "against 50% for v1.2.0, the release the report names" in markup
    assert "names a different version from the build it came from" in markup
    assert "rather than that the bug is not real" in markup


def test_no_release_fitting_is_stated_without_overreach() -> None:
    markup = html_of(
        evidence(
            details(
                {"v1.1.0": 0.2, "v1.2.0": 0.25},
                claimed="v1.1.0",
                claimed_ratio=0.2,
                best="v1.2.0",
                best_ratio=0.25,
                perfect=[],
            )
        )
    )
    assert "No scored release fits this trace well: the best is v1.2.0" in markup
    assert "25% of its frames land in the function they name" in markup
    assert "against 20% for v1.1.0, the release the report names" in markup


def test_a_claimed_release_that_is_merely_the_least_bad_is_not_called_a_fit() -> None:
    """The finding is about every release, so "best of a bad set" must not swallow it."""
    markup = html_of(
        evidence(
            details(
                {"v1.1.0": 0.2, "v1.2.0": 0.25},
                claimed="v1.2.0",
                claimed_ratio=0.25,
                best="v1.2.0",
                best_ratio=0.25,
                perfect=[],
            )
        )
    )
    assert "No scored release fits this trace well: the best is v1.2.0" in markup
    assert "is also the best fit" not in markup


def test_a_partial_fit_says_no_release_fits_every_frame() -> None:
    markup = html_of(
        evidence(details({"v1.2.0": 0.5, "v1.2.1": 0.75}, best_ratio=0.75, perfect=[]))
    )
    assert "fits v1.2.1 best" in markup
    assert "No scored release fits every frame." in markup


def test_other_exact_fits_are_named_so_the_view_never_implies_uniqueness() -> None:
    markup = html_of(
        evidence(
            details(
                {"v1.2.0": 1.0, "v1.2.1": 1.0, "v1.3.0": 1.0},
                claimed_ratio=1.0,
                perfect=["v1.2.0", "v1.2.1", "v1.3.0"],
            )
        )
    )
    assert "Other releases fit exactly too: v1.2.0, v1.3.0." in markup


def test_wording_is_about_the_claim_not_the_reporter() -> None:
    markup = html_of(evidence(details(simple_ratios()))).lower()
    for word in BANNED_WORDS:
        assert word not in markup


# --- an incomplete scan (P4) ------------------------------------------------------------


def test_a_truncated_scan_is_visible_on_the_page() -> None:
    markup = html_of(evidence(details(simple_ratios(4), complete=False, scored=4)))
    assert '<span class="pill warn">partial scan</span>' in markup
    assert "stopped at its time budget after 4 releases" in markup
    assert "cannot say that none of them fits" in markup


def test_a_truncated_scan_is_in_the_accessible_label_too() -> None:
    label = aria_label(html_of(evidence(details(simple_ratios(4), complete=False))))
    assert "The scan did not finish" in label


def test_a_missing_scan_complete_key_is_treated_as_incomplete() -> None:
    payload = details(simple_ratios())
    del payload["scan_complete"]
    assert "partial scan" in html_of(evidence(payload))


def test_a_complete_scan_still_says_how_many_releases_were_scored() -> None:
    markup = html_of(evidence(details(simple_ratios(5), radius=15)))
    assert "partial scan" not in markup
    assert "5 releases scored in the window it searched" in markup
    assert "plus or minus 15 final releases" in markup


def test_one_release_scored_is_singular() -> None:
    assert "1 release scored" in html_of(evidence(details({"v1.0.0": 1.0}, best="v1.0.0")))


def test_a_claimed_release_that_was_never_scored_is_named() -> None:
    markup = html_of(
        evidence(details({"v2.0.0": 0.4, "v2.1.0": 1.0}, claimed="v9.9.9", claimed_ratio=None))
    )
    assert "v9.9.9, the release the report names, is not among them." in markup
    assert "vf-mark-claimed" not in markup
    assert "against not scored for v9.9.9" in markup


# --- many releases ----------------------------------------------------------------------


def big_ratios(count: int) -> dict[str, float]:
    return {f"v1.{i}.0": round((i % 7) / 7, 3) for i in range(count)}


def test_two_hundred_releases_still_render_a_sane_chart() -> None:
    markup = html_of(evidence(details(big_ratios(200), claimed="v1.10.0", best="v1.20.0")))
    bars = rects(markup)
    assert len(bars) == 200
    assert min(width for _klass, width, _h in bars) >= 1.5
    assert len(markup) < 100_000
    svg_of(markup)


def test_far_too_many_releases_are_capped_and_the_page_says_so() -> None:
    markup = html_of(evidence(details(big_ratios(500), claimed="v1.250.0", best="v1.251.0")))
    assert len(rects(markup)) == version_fit.MAX_MARKS
    assert "The chart draws 200 of them, the run nearest the claimed release" in markup
    assert "500 releases scored" in markup
    # The drawn run stays contiguous and contains the claimed release.
    assert "vf-mark-claimed" in markup
    labels = re.findall(r'<text class="vf-name"[^>]*>([^<]*)</text>', markup)
    assert labels == ["v1.150.0", "v1.349.0"]


def test_axis_labels_give_way_to_the_range_when_there_are_many_marks() -> None:
    few = html_of(evidence(details(simple_ratios(8), claimed="v1.0.0", best="v1.7.0")))
    many = html_of(evidence(details(simple_ratios(9), claimed="v1.0.0", best="v1.8.0")))
    assert len(re.findall(r'<text class="vf-name"', few)) == 8
    assert len(re.findall(r'<text class="vf-name"', many)) == 2


def test_a_very_long_release_name_is_truncated_on_the_axis_only() -> None:
    name = "v1.0.0-" + "A" * 400
    markup = html_of(evidence(details({name: 1.0}, claimed=name, best=name)))
    labels = re.findall(r'<text class="vf-name"[^>]*>([^<]*)</text>', markup)
    assert len(labels[0]) == version_fit.MAX_LABEL
    assert labels[0].endswith("…")
    assert f'<th scope="row">{name}</th>' in markup  # the table keeps the full name


# --- the accessible table ---------------------------------------------------------------


def aria_label(markup: str) -> str:
    found = re.search(r'aria-label="([^"]*)"', markup)
    assert found is not None
    return found.group(1)


def test_the_svg_is_one_image_whose_label_states_the_conclusion() -> None:
    markup = html_of(evidence(details({"v1.2.0": 0.5, "v1.2.1": 1.0})))
    assert svg_of(markup).get("role") == "img"
    label = aria_label(markup)
    assert label.startswith("Version fit chart.")
    assert "fits v1.2.1 exactly" in label
    assert "2 releases scored." in label
    assert "table below the chart" in label


def test_every_release_appears_in_a_real_table() -> None:
    markup = html_of(
        evidence(details({"v1.2.0": 0.5, "v1.2.1": 1.0, "v1.3.0": 0.25}, perfect=["v1.2.1"]))
    )
    assert "<details" in markup and "<summary>Fit for each release (3)</summary>" in markup
    assert '<table class="vf-table">' in markup
    assert '<th scope="col">Release</th>' in markup
    rows = re.findall(r"<tr[^>]*>(.*?)</tr>", markup)
    assert len(rows) == 4  # one header row, three releases
    assert '<th scope="row">v1.2.0</th><td class="vf-num">50%</td><td>named by the report' in markup
    assert "best fit, every checked frame fits" in markup
    assert '<td class="vf-num">25%</td><td></td>' in markup


def test_rows_for_the_claimed_and_best_releases_are_marked() -> None:
    markup = html_of(evidence(details(simple_ratios(), claimed="v1.0.0", best="v1.4.0")))
    assert '<tr class="vf-row-claimed">' in markup
    assert '<tr class="vf-row-best">' in markup


def test_the_legend_names_what_the_marks_mean() -> None:
    markup = html_of(evidence(details(simple_ratios(), claimed="v1.0.0", best="v1.4.0")))
    assert "▲ v1.0.0, the release the report names" in markup
    assert "◆ v1.4.0, the best fit" in markup
    assert "dashed line: the 50% mark" in markup


# --- hostile input (P7) -----------------------------------------------------------------


def hostile_evidence() -> Evidence:
    ratios = {name: index / 10 for index, name in enumerate(HOSTILE)}
    return evidence(
        details(
            ratios,
            claimed=HOSTILE[0],
            best=HOSTILE[1],
            perfect=[HOSTILE[1], HOSTILE[2]],
            best_ratio=1.0,
        )
    )


def test_hostile_release_names_are_inert() -> None:
    markup = html_of(hostile_evidence())
    for payload in HOSTILE:
        if "<" in payload:  # anything that could open a tag must not survive verbatim
            assert payload not in markup
    assert "<script" not in markup.lower()
    assert "<img" not in markup.lower()
    assert "&lt;script&gt;" in markup
    assert "\u202e" not in markup  # the bidi override never reaches the document
    assert "\x1b" not in markup and "\x07" not in markup


def test_no_hostile_value_lands_inside_a_tag() -> None:
    """Inside an attribute is where ``onerror=`` would actually fire."""
    for tag in tags(html_of(hostile_evidence())):
        assert not re.search(r"\son\w+\s*=", tag)
        assert "<script" not in tag.lower()


def test_the_view_emits_no_url_at_all() -> None:
    """``javascript:`` is inert as character data and lethal in an ``href``.

    This component has no link and no image to put one in, and that is the reason a
    release name called ``javascript:alert(1)`` may safely appear as text.
    """
    markup = html_of(hostile_evidence())
    for tag in tags(markup):
        assert not re.search(r"\s(href|src|xlink:href)\s*=", tag)
    assert "url(" not in version_fit.CSS


def test_the_chart_still_parses_as_xml_with_hostile_names() -> None:
    """An escaping bug in the SVG shows up here first: the tree stops being well formed."""
    chart = svg_of(html_of(hostile_evidence()))
    titles = [node.text or "" for node in chart.iter("title")]
    assert len(titles) == len(HOSTILE)
    # The parser hands back the unescaped text, which proves it was text and not markup.
    assert titles[0].startswith("</script><script>alert(1)</script>")


def test_a_hostile_name_is_escaped_for_the_sink_it_lands_in() -> None:
    markup = html_of(hostile_evidence())
    # Character data in the table: the angle brackets go, the rest stays readable.
    assert "&lt;img src=x onerror=alert(1)&gt;" in markup
    # The same name inside the aria-label additionally loses its quotes and equals signs.
    assert "&lt;img src&#x3d;x onerror&#x3d;alert(1)&gt;" in aria_label(markup)
    # A quote-breakout payload cannot close the attribute it is interpolated into.
    quoted = html_of(evidence(details({HOSTILE[2]: 1.0}, claimed=HOSTILE[2], best=HOSTILE[2])))
    assert "&quot;&gt;&lt;script&gt;" in aria_label(quoted)
    assert '"><script>' not in quoted


# --- determinism (P2) -------------------------------------------------------------------


def test_rendering_twice_is_byte_identical() -> None:
    item = evidence(details(simple_ratios(30), claimed="v1.3.0", best="v1.29.0"))
    first = version_fit.render(context(item))
    second = version_fit.render(context(item))
    assert first is not None and second is not None
    assert first.html == second.html
    assert first.css == second.css


def test_several_findings_are_ordered_by_strength_then_id() -> None:
    weak = evidence(details(simple_ratios(), best="v1.4.0"), eid="e9", strength=-0.3)
    strong = evidence(details(simple_ratios(), best="v1.3.0"), eid="e2", strength=-1.5)
    markup = html_of(weak, strong)
    assert markup.count('<figure class="vf-fig">') == 2
    assert markup.index("v1.3.0, the best fit") < markup.index("v1.4.0, the best fit")
    assert html_of(strong, weak) == markup


def test_the_section_is_labelled_once_for_several_findings() -> None:
    markup = html_of(
        evidence(details(simple_ratios()), eid="e1"),
        evidence(details(simple_ratios()), eid="e2"),
    )
    assert markup.count('id="vf-heading"') == 1
