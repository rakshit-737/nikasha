# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The HTML patch view (SPEC §15.2, ``render/html/components/patch_view.py``).

Three properties matter more than the markup and get the most tests.

**Nothing in a diff is trusted.** A suggested patch is the one part of a report where
``<``, ``&`` and ``"`` are ordinary characters, so every line, path and section header is
fed hostile text and the output is checked for the dangerous substring, not merely for the
escaped one.

**"Already applied" must not read as a failure.** C12 reports it when the *reverse* patch
applies, and SPEC §14.3 rule 4 caps the verdict at MIXED because it nearly always means a
real problem that is already fixed. The wording tests assert the plain sentence is there
and that the red failure styling and the phrase "does not apply" are not.

**The view may never raise.** A component that raises is skipped and the maintainer loses
the whole patch view, so malformed, truncated and absent evidence are all rendered rather
than refused.
"""

from __future__ import annotations

import re
from typing import Any

import pytest

from nikasha.ingest import ingest_string
from nikasha.model.claims import PatchClaim, PatchHunk, PatchLine, SymbolClaim
from nikasha.model.evidence import Evidence
from nikasha.model.report import Span
from nikasha.model.result import ResolvedTarget, Result
from nikasha.render.html.components import patch_view
from nikasha.render.html.context import HtmlContext

SPAN = Span(start=0, end=4, text="some")
REPORT = ingest_string("some text", input_format="text")

#: A closing script tag, an event handler, a broken-out attribute, a `javascript:` URL, two
#: ANSI escapes, a bidi override and an unbroken run longer than the line cap (P7).
HOSTILE = (
    '</script><img src=x onerror=alert(1)> "><script>alert(1)</script>'
    " javascript:alert(1) \x1b[31mred\x1b[0m \u202eevil " + "A" * 500
)

#: Substrings that must never survive into the document in a form a parser would act on.
#: ``onerror=alert(1)`` is deliberately absent: once the ``<`` around it is escaped it is
#: ordinary prose, and the real assertion about handlers is :func:`tags` below.
DANGEROUS = ("<script", "</script", "<img", "\x1b", "\u202e")

CTX = " "
ADD = "+"
DEL = "-"


def lines(*spec: tuple[str, str]) -> tuple[PatchLine, ...]:
    return tuple(PatchLine(op=op, text=text) for op, text in spec)


DEFAULT_LINES = lines(
    (CTX, "    if (dst == NULL)"),
    (CTX, "        return NULL;"),
    (ADD, "    if (len >= HDR_VALUE_MAX)"),
    (DEL, "    size_t n = len;"),
    (CTX, "    memcpy(dst, value, len);"),
)


def hunk(
    *,
    path: str = "src/util.c",
    start: int = 26,
    body: tuple[PatchLine, ...] = DEFAULT_LINES,
    header: str | None = None,
) -> PatchHunk:
    return PatchHunk(
        path=path,
        source_start=start,
        source_length=sum(1 for line in body if line.op != ADD),
        target_start=start,
        target_length=sum(1 for line in body if line.op != DEL),
        section_header=header,
        lines=body,
    )


def patch(
    *hunks: PatchHunk,
    claim_id: str = "p1",
    files: tuple[str, ...] = ("src/util.c",),
    diff: str = "--- a/src/util.c\n+++ b/src/util.c\n",
) -> PatchClaim:
    return PatchClaim(
        id=claim_id,
        spans=(SPAN,),
        extractor="test",
        confidence=0.9,
        role="supporting",
        provenance="project_attributed",
        diff=diff,
        files=files,
        hunks=hunks,
    )


def evidence(
    details: dict[str, Any],
    *,
    claim_id: str = "p1",
    summary: str = "1 hunk of the patch applies cleanly to src/util.c at v1.3.0",
    outcome: str = "SUPPORTS",
    strength: float = 1.0,
) -> Evidence:
    return Evidence(
        id="ev1",
        check_id="C12",
        claim_ids=(claim_id,),
        outcome=outcome,  # type: ignore[arg-type]
        strength=strength,
        group="patch",
        summary=summary,
        details=details,
    )


def context(
    *,
    claims: tuple[Any, ...] = (),
    items: tuple[Evidence, ...] = (),
    ref_name: str | None = "v1.3.0",
) -> HtmlContext:
    result = Result(
        tool_version="0.0.0-test",
        report=REPORT,
        claims=claims,
        evidence=items,
        target=ResolvedTarget(
            repo_url="https://example.test/libhdr.git",
            ref_name=ref_name,
            commit="0" * 40,
            method="tag",
            confidence="high",
        ),
    )
    return HtmlContext(result=result, source="report.md")


def render(ctx: HtmlContext) -> str:
    fragment = patch_view.render(ctx)
    assert fragment is not None
    return fragment.html


def one_status(status: str, *, body: tuple[PatchLine, ...] = DEFAULT_LINES, **detail: Any) -> str:
    """The view for a single hunk that C12 reported with ``status``."""
    claim = patch(hunk(body=body))
    details: dict[str, Any] = {
        "status": status,
        "outcome": status,
        "files": ["src/util.c"],
        "hunks": [{"path": "src/util.c", "source_start": 26, "status": status, **detail}],
        "hunks_checked": 1,
        "hunks_total": 1,
    }
    return render(context(claims=(claim,), items=(evidence(details),)))


def marks(html: str, css_class: str) -> int:
    return len(re.findall(rf'class="pv-mark {css_class}"', html))


def tags(html: str) -> list[str]:
    """Every real tag in the output.

    Input-derived text can contain ``onerror=`` and ``javascript:`` and still be inert,
    because its angle brackets are escaped and it is therefore character data. What must
    never happen is such a thing appearing *inside a tag*, so the handler and URL
    assertions look at the tags rather than at the whole document.
    """
    return re.findall(r"<[a-zA-Z/][^>]*>", html)


def assert_no_handlers(html: str) -> None:
    for tag in tags(html):
        assert re.search(r"\son\w+=", tag) is None, tag
        assert "javascript:" not in tag, tag


# --- nothing to show ------------------------------------------------------------------------


def test_returns_none_without_a_patch_claim() -> None:
    symbol = SymbolClaim(
        id="s1", spans=(SPAN,), extractor="test", confidence=0.5, name="util_copy_value"
    )
    assert patch_view.render(context(claims=(symbol,))) is None
    assert patch_view.render(context()) is None


def test_a_diff_with_no_hunks_says_so_rather_than_vanishing() -> None:
    html = render(context(claims=(patch(),)))
    assert "could not be read as hunks" in html
    assert "<table" not in html


def test_evidence_about_another_claim_is_not_borrowed() -> None:
    claim = patch(hunk())
    stray = evidence({"status": "applies_clean", "hunks": []}, claim_id="other")
    html = render(context(claims=(claim,), items=(stray,)))
    assert "not applied, so its lines are unmarked" in html
    assert marks(html, "pv-unk") == len(DEFAULT_LINES)


# --- the marks ------------------------------------------------------------------------------


def test_applies_clean_marks_the_source_side_found() -> None:
    html = one_status("applies_clean", line=26, offset=0, fuzz=0)
    # Four source lines (context and removed) were looked for; the added line was not.
    assert marks(html, "pv-yes") == 4
    assert marks(html, "pv-na") == 1
    assert marks(html, "pv-no") == 0
    assert "applies cleanly" in html
    assert "found at line 26" in html
    assert "4 of 4 lines this hunk expects are in the file" in html


def test_context_not_found_marks_every_expected_line_missing() -> None:
    html = one_status("context_not_found")
    assert marks(html, "pv-no") == 4
    assert marks(html, "pv-yes") == 0
    assert "context not found" in html
    assert "0 of 4 lines this hunk expects are in the file" in html
    assert 'class="pill bad"' in html


def test_fuzz_marks_the_context_lines_that_were_skipped() -> None:
    body = lines(
        (CTX, "one"),
        (CTX, "two"),
        (CTX, "three"),
        (ADD, "inserted"),
        (CTX, "four"),
        (CTX, "five"),
        (CTX, "six"),
    )
    html = one_status("applies_with_fuzz", body=body, line=30, offset=4, fuzz=2)
    assert marks(html, "pv-skip") == 4  # two leading and two trailing context lines
    assert marks(html, "pv-yes") == 2
    assert "2 of 6 lines this hunk expects are in the file" in html
    assert "+4 lines from the cited position" in html
    assert "2 context lines skipped at each end" in html


def test_fuzz_never_skips_more_context_than_the_hunk_has() -> None:
    body = lines((CTX, "only context"), (ADD, "inserted"), (CTX, "tail"), (CTX, "tail two"))
    html = one_status("applies_with_fuzz", body=body, line=26, fuzz=2)
    assert marks(html, "pv-skip") == 3  # one leading, two trailing
    assert marks(html, "pv-yes") == 0


def test_already_applied_marks_the_patched_side_and_the_removed_line_as_gone() -> None:
    html = one_status("already_applied", line=26, offset=0, fuzz=0)
    # Context and added lines are in the file; the removed line is already gone.
    assert marks(html, "pv-yes") == 4
    assert marks(html, "pv-na") == 1
    assert "already gone from the file" in html
    assert "the patched text is at line 26" in html
    assert "4 of 4 lines of the patched text are already in the file" in html


def test_unchecked_statuses_mark_nothing_either_way() -> None:
    for status in ("generated", "file_missing", "search_incomplete"):
        html = one_status(status, reason="not in the tree")
        assert marks(html, "pv-unk") == len(DEFAULT_LINES), status
        assert marks(html, "pv-no") == 0, status
        assert "lines this hunk expects" not in html, status


# --- wording: a version mismatch is a question, not a failure -------------------------------


def test_already_applied_reads_as_already_fixed_not_as_a_failure() -> None:
    html = one_status("already_applied", line=26)
    assert "This patch is already applied at v1.3.0." in html
    assert "appears to be in place already" in html
    assert "which version was tested" in html
    assert "does not apply" not in html
    assert 'class="pill bad"' not in html
    assert 'class="pv-note warn"' in html


def test_other_release_only_names_the_releases_and_is_not_drawn_as_a_failure() -> None:
    html = one_status("other_release_only", releases=["v1.2.0", "v1.2.1"])
    assert "fits another release" in html
    assert "applies at v1.2.0, v1.2.1" in html
    assert "question about which version was tested" in html
    assert 'class="pill bad"' not in html


def test_only_context_not_found_is_drawn_as_a_failure() -> None:
    failures = [
        status for status in patch_view._STATUS if patch_view._STATUS[status].klass == "bad"
    ]
    assert failures == ["context_not_found"]


def test_the_searched_releases_and_an_unfinished_search_are_stated() -> None:
    claim = patch(hunk())
    details = {
        "status": "search_incomplete",
        "hunks": [{"path": "src/util.c", "source_start": 26, "status": "search_incomplete"}],
        "searched_releases": ["v1.0.0", "v1.1.0"],
        "search_complete": False,
        "hunks_total": 1,
    }
    html = render(context(claims=(claim,), items=(evidence(details),)))
    assert "Also searched: v1.0.0, v1.1.0." in html
    assert "The search did not finish." in html


# --- layout and accessibility ----------------------------------------------------------------


def test_line_numbers_track_both_sides_of_the_diff() -> None:
    html = one_status("applies_clean", line=26)
    rows = re.findall(r'<tr class="(pv-r-\w+)">(.*?)</tr>', html, re.S)
    numbers = [re.findall(r'<td class="pv-ln">(\d*)</td>', row) for _klass, row in rows]
    assert numbers == [["26", "26"], ["27", "27"], ["", "28"], ["28", ""], ["29", "29"]]


def test_every_mark_and_operation_carries_words_not_only_colour() -> None:
    html = one_status("context_not_found")
    cells = re.findall(r'<td class="pv-(?:mark|op)[^"]*">(.*?)</td>', html)
    assert cells
    for cell in cells:
        assert 'aria-hidden="true"' in cell
        assert '<span class="pv-sr">' in cell
    assert "not found in the file" in html
    assert "<ins>" in html and "<del>" in html


def test_the_legend_lists_only_the_marks_the_page_used() -> None:
    html = one_status("applies_clean")
    legend = re.search(r'<ul class="pv-legend">(.*?)</ul>', html, re.S)
    assert legend is not None
    assert "found in the file" in legend.group(1)
    assert "not found in the file" not in legend.group(1)


def test_the_table_is_named_and_has_a_fixed_geometry() -> None:
    html = one_status("applies_clean")
    assert '<caption class="pv-sr">Hunk 1 of src/util.c at v1.3.0' in html
    assert "<colgroup>" in html
    assert '<thead class="pv-sr">' in html
    assert html.count("<colgroup>") == html.count("<table")


def test_a_repository_with_no_ref_name_falls_back_to_the_commit() -> None:
    claim = patch(hunk())
    details = {"status": "applies_clean", "hunks": [{"status": "applies_clean"}]}
    html = render(context(claims=(claim,), items=(evidence(details),), ref_name=None))
    assert "000000000000" in html


# --- caps: a diff is attacker-controlled and often enormous ---------------------------------


def test_a_long_line_is_truncated_and_says_so() -> None:
    body = lines((CTX, "x" * 5000))
    html = one_status("applies_clean", body=body)
    assert "x" * patch_view.MAX_LINE_CHARS in html
    assert "x" * (patch_view.MAX_LINE_CHARS + 1) not in html
    assert "(line truncated)" in html


def test_too_many_hunks_are_capped_and_counted() -> None:
    hunks = tuple(hunk(start=10 * n) for n in range(1, 26))
    claim = patch(*hunks)
    details = {
        "status": "applies_clean",
        "hunks": [{"path": "src/util.c", "status": "applies_clean"} for _ in hunks],
        "hunks_total": len(hunks),
    }
    html = render(context(claims=(claim,), items=(evidence(details),)))
    assert html.count("<table") == patch_view.MAX_HUNKS
    assert "15 further hunks are not shown." in html
    assert "25 hunks touching src/util.c" in html


def test_too_many_lines_in_one_hunk_are_capped_and_counted() -> None:
    body = lines(*((CTX, f"line {n}") for n in range(200)))
    html = one_status("applies_clean", body=body)
    assert html.count('<tr class="pv-r-ctx">') == patch_view.MAX_HUNK_LINES
    assert "150 further lines of this hunk are not shown" in html


def test_too_many_patch_claims_are_capped_and_counted() -> None:
    claims = tuple(patch(hunk(), claim_id=f"p{n}") for n in range(5))
    html = render(context(claims=claims))
    assert html.count("<h3>") == patch_view.MAX_CLAIMS
    assert "3 further patches are not shown." in html


# --- hostile input ---------------------------------------------------------------------------


def test_hostile_diff_text_is_inert() -> None:
    body = lines((CTX, HOSTILE), (ADD, HOSTILE), (DEL, HOSTILE))
    claim = patch(hunk(path=HOSTILE, body=body, header=HOSTILE), files=(HOSTILE,), diff=HOSTILE)
    details = {
        "status": "context_not_found",
        "files": [HOSTILE],
        "hunks": [{"path": HOSTILE, "status": "context_not_found", "reason": HOSTILE}],
        "searched_releases": [HOSTILE],
        "hunks_total": 1,
    }
    html = render(
        context(claims=(claim,), items=(evidence(details, summary=HOSTILE),), ref_name=HOSTILE)
    )
    for needle in DANGEROUS:
        assert needle not in html, needle
    assert "&lt;script&gt;" in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html
    # The view emits no links at all, so a `javascript:` URL can never reach an href.
    assert "href=" not in html
    assert_no_handlers(html)


def test_a_hostile_status_cannot_reach_a_class_attribute() -> None:
    html = one_status('bad" onload="alert(1)')
    assert 'class="pill unknown"' in html
    assert_no_handlers(html)
    assert 'bad" onload="alert(1)' in html  # present, but only as character data


def test_the_view_emits_no_script_and_no_javascript() -> None:
    fragment = patch_view.render(context(claims=(patch(hunk()),)))
    assert fragment is not None
    assert fragment.js == ""
    assert "<script" not in fragment.html
    assert "javascript:" not in fragment.html
    assert "</" not in fragment.css


# --- malformed and truncated evidence ---------------------------------------------------------


@pytest.mark.parametrize(
    "details",
    [
        {},
        {"status": 17, "hunks": "not a list", "files": {"a": 1}},
        {"status": "applies_clean", "hunks": [None, 3, "x"]},
        {"status": "applies_clean", "hunks": [{"fuzz": "two", "line": None, "offset": []}]},
        {"status": "applies_clean", "hunks": [{"releases": [1, "v1.0.0"]}], "hunks_total": "many"},
        {"status": "unheard_of_status", "hunks": [{"status": "unheard_of_status"}]},
    ],
)
def test_malformed_details_render_rather_than_raise(details: dict[str, Any]) -> None:
    html = render(context(claims=(patch(hunk()),), items=(evidence(details),)))
    assert "<table" in html
    assert_no_handlers(html)


def test_a_truncated_hunk_list_leaves_the_rest_unchecked() -> None:
    claim = patch(hunk(start=10), hunk(start=20), hunk(start=30))
    details = {
        "status": "applies_clean",
        "hunks": [{"path": "src/util.c", "status": "applies_clean"}],
        "hunks_checked": 1,
        "hunks_total": 3,
    }
    html = render(context(claims=(claim,), items=(evidence(details),)))
    assert html.count("<table") == 3
    assert marks(html, "pv-unk") == 2 * len(DEFAULT_LINES)
    assert "not checked" in html


def test_a_resolved_path_different_from_the_diffs_is_shown_with_both() -> None:
    claim = patch(hunk(path="util.c"))
    details = {
        "status": "applies_clean",
        "hunks": [{"path": "src/util.c", "status": "applies_clean"}],
        "hunks_total": 1,
    }
    html = render(context(claims=(claim,), items=(evidence(details),)))
    assert "src/util.c" in html
    assert "(the diff names util.c)" in html


# --- determinism ------------------------------------------------------------------------------


def test_rendering_twice_is_byte_identical() -> None:
    claim = patch(hunk(start=10), hunk(start=99, path="src/hdr.c"))
    details = {
        "status": "applies_with_fuzz",
        "files": ["src/hdr.c", "src/util.c"],
        "hunks": [
            {"path": "src/util.c", "status": "applies_clean", "line": 10},
            {"path": "src/hdr.c", "status": "applies_with_fuzz", "line": 99, "fuzz": 1},
        ],
        "searched_releases": ["v1.0.0", "v1.1.0"],
        "hunks_total": 2,
    }
    ctx = context(claims=(claim,), items=(evidence(details),))
    first = render(ctx)
    second = render(context(claims=(claim,), items=(evidence(details),)))
    assert first == render(ctx)
    assert first == second
