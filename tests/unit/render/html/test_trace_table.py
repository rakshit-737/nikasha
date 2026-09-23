# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The trace alignment table (SPEC §15.2).

The fixtures in ``FABRICATED`` and ``GENUINE`` are the real ``details`` payloads C08 and
C09 emit for ``examples/reports/fabricated_hdr_overflow.md`` and
``genuine_hdr_overflow.md`` against the vulnlab demo repository at ``v1.2.0``. Testing the
view against invented shapes would only prove the view agrees with itself; these pin it to
what the checks actually write.

The load-bearing test here is :func:`test_uncertain_and_skipped_frames_are_never_crossed`.
C08 keeps third-party and unparsed frames out of its ratio on purpose (ADR 0003), and a
table that drew them as ✗ would put back exactly the false contradiction the check went to
some trouble to avoid.
"""

from __future__ import annotations

import re
from typing import Any

from nikasha.ingest import ingest_string
from nikasha.model.claims import ClaimBase, Frame, TraceClaim
from nikasha.model.evidence import Evidence
from nikasha.model.report import Span
from nikasha.model.result import Result
from nikasha.render.html.components import trace_table
from nikasha.render.html.context import Fragment, HtmlContext

SPAN = Span(start=0, end=4, text="some")
REPORT = ingest_string("some text", input_format="text")

#: Written with chr() so no formatter can turn them into literal characters:
#: a bidi override sitting in a source file is itself the hazard (P7).
BIDI = chr(0x202E)
ZWSP = chr(0x200B)
ELLIPSIS = chr(0x2026)

#: Report-derived strings that must never come out of this view as markup (P7).
HOSTILE = (
    '</script><img src=x onerror=alert(1)>"><script>javascript:alert(1)'
    f"\x1b[31mred\x1b[0m{BIDI}evil{ZWSP} " + "A" * 4000
)

#: The wording may describe claims, never the person who wrote them (P1).
BANNED_WORDS = ("slop", "fake", "fabricat")

#: Read back from the module, so changing a glyph there fails loudly here.
CROSS = trace_table.MARKS["no"][0]

# --- real check output --------------------------------------------------------------------

FABRICATED_FRAMES: dict[str, Any] = {
    "app_frames": 3,
    "checked_frames": 3,
    "consistent_frames": 0,
    "frames": [
        {
            "claimed_path": "/src/libhdr/src/util.c",
            "function": "util_copy_value",
            "index": 1,
            "line": 77,
            "matched": ["src/util.c exists at this commit"],
            "mismatched": [
                "src/util.c has 36 lines",
                "util_copy_value is defined at src/util.c:8-18; line 77 is outside it",
            ],
            "resolved_path": "src/util.c",
            "status": "inconsistent",
        },
        {
            "claimed_path": "/src/libhdr/src/hdr.c",
            "function": "hdr_get",
            "index": 2,
            "line": 412,
            "matched": ["src/hdr.c exists at this commit"],
            "mismatched": [
                "src/hdr.c has 156 lines",
                "hdr_get is defined at src/hdr.c:145-156; line 412 is outside it",
            ],
            "resolved_path": "src/hdr.c",
            "status": "inconsistent",
        },
        {
            "claimed_path": "/src/libhdr/tools/hdrcat.c",
            "function": "main",
            "index": 3,
            "line": 58,
            "matched": [
                "tools/hdrcat.c exists at this commit",
                "line 58 is inside the file (130 lines)",
            ],
            "mismatched": [
                "main is defined at tools/hdrcat.c:81-130; line 58 is outside it",
            ],
            "resolved_path": "tools/hdrcat.c",
            "status": "inconsistent",
        },
    ],
    "outcome": "inconsistent",
    "ratio": 0.0,
    "skipped_frames": 0,
    "trace_format": "asan",
    "trace_frames": 4,
    "uncertain_frames": 0,
}

FABRICATED_EDGES: dict[str, Any] = {
    "edges": [
        {
            "callee": "util_copy_value",
            "callee_frame": 1,
            "callee_path": "src/util.c",
            "caller": "hdr_get",
            "caller_calls": ["hdr_find_line", "strncpy", "util_strip"],
            "caller_frame": 2,
            "caller_path": "src/hdr.c",
            "kind": "none",
            "sites": [],
        },
        {
            "callee": "hdr_get",
            "callee_frame": 2,
            "callee_path": "src/hdr.c",
            "caller": "main",
            "caller_calls": ["cap_lines", "fold_lines", "read_file"],
            "caller_frame": 3,
            "caller_path": "tools/hdrcat.c",
            "kind": "none",
            "sites": [],
        },
    ],
    "n_checked": 2,
    "n_indirect": 0,
    "n_missing": 2,
    "n_pairs": 2,
    "outcome": "missing_edge",
    "skipped": [],
    "trace_format": "asan",
    "unknown": [],
}

GENUINE_FRAMES: dict[str, Any] = {
    "app_frames": 2,
    "checked_frames": 2,
    "consistent_frames": 2,
    "frames": [
        {
            "claimed_path": "/work/libhdr/src/util.c",
            "function": "util_copy_value",
            "index": 1,
            "line": 15,
            "matched": [
                "src/util.c exists at this commit",
                "line 15 is inside the file (36 lines)",
                "line 15 is inside util_copy_value",
            ],
            "mismatched": [],
            "resolved_path": "src/util.c",
            "status": "consistent",
        },
        {
            "claimed_path": "/work/libhdr/src/hdr.c",
            "function": "hdr_parse_line",
            "index": 2,
            "line": 104,
            "matched": [
                "src/hdr.c exists at this commit",
                "line 104 is inside the file (156 lines)",
                "line 104 is inside hdr_parse_line",
            ],
            "mismatched": [],
            "resolved_path": "src/hdr.c",
            "status": "consistent",
        },
    ],
    "outcome": "all_consistent",
    "ratio": 1.0,
    "skipped_frames": 0,
    "trace_format": "asan",
    "trace_frames": 8,
    "uncertain_frames": 0,
}

GENUINE_EDGES: dict[str, Any] = {
    "edges": [
        {
            "callee": "util_copy_value",
            "callee_frame": 1,
            "callee_path": "src/util.c",
            "caller": "hdr_parse_line",
            "caller_frame": 2,
            "caller_path": "src/hdr.c",
            "kind": "direct",
            "sites": ["src/hdr.c:104 direct call"],
        },
    ],
    "n_checked": 1,
    "n_indirect": 0,
    "n_missing": 0,
    "n_pairs": 1,
    "outcome": "all_edges_real",
    "skipped": [],
    "trace_format": "asan",
    "unknown": [],
}


# --- fixtures ------------------------------------------------------------------------------


def trace_claim(claim_id: str = "t1") -> TraceClaim:
    return TraceClaim(
        id=claim_id,
        spans=(SPAN,),
        extractor="test",
        confidence=1.0,
        role="core",
        provenance="project_attributed",
        format="asan",
        frames=(Frame(index=1, function="util_copy_value", raw="#1 util_copy_value"),),
    )


def evidence(
    eid: str,
    *,
    check_id: str,
    claim_id: str = "t1",
    details: dict[str, Any],
    outcome: str = "REFUTES",
    strength: float = -2.0,
    summary: str = "0 of 3 application frames fit the code at v1.2.0",
) -> Evidence:
    return Evidence(
        id=eid,
        check_id=check_id,
        claim_ids=(claim_id,),
        outcome=outcome,  # type: ignore[arg-type]
        strength=strength,
        group="trace",
        summary=summary,
        details=details,
    )


def context(*items: Evidence, claims: tuple[ClaimBase, ...] = ()) -> HtmlContext:
    result = Result(
        tool_version="0.0.0-test",
        report=REPORT,
        claims=claims or (trace_claim(),),  # type: ignore[arg-type]
        evidence=items,
    )
    return HtmlContext(result=result)


def render(*items: Evidence, claims: tuple[ClaimBase, ...] = ()) -> Fragment:
    fragment = trace_table.render(context(*items, claims=claims))
    assert fragment is not None
    return fragment


def fabricated() -> tuple[Evidence, Evidence]:
    return (
        evidence("e08", check_id="C08", details=FABRICATED_FRAMES),
        evidence("e09", check_id="C09", details=FABRICATED_EDGES),
    )


def genuine() -> tuple[Evidence, Evidence]:
    return (
        evidence(
            "g08",
            check_id="C08",
            details=GENUINE_FRAMES,
            outcome="SUPPORTS",
            strength=1.5,
            summary="2 of 2 application frames fit the code at v1.2.0",
        ),
        evidence(
            "g09",
            check_id="C09",
            details=GENUINE_EDGES,
            outcome="SUPPORTS",
            strength=1.5,
            summary="all 1 call edges in the trace exist at v1.2.0",
        ),
    )


def marks(html: str) -> list[str]:
    """The palette class of every mark cell, in document order: ok / bad / unknown."""
    return [chunk.split('"', 1)[0] for chunk in html.split('<td class="tt-mark ')[1:]]


def rows(html: str) -> list[str]:
    """Every ``<tr>``'s inner markup, in document order."""
    return [chunk.split("</tr>", 1)[0] for chunk in html.split("<tr ")[1:]]


# --- nothing to show ------------------------------------------------------------------------


def test_returns_none_without_any_trace_evidence() -> None:
    assert trace_table.render(context()) is None


def test_returns_none_when_the_frame_list_is_empty() -> None:
    empty = evidence("e0", check_id="C08", details={"frames": [], "trace_format": "asan"})
    assert trace_table.render(context(empty)) is None


def test_returns_none_when_details_are_missing_entirely() -> None:
    bare = evidence("e0", check_id="C08", details={})
    assert trace_table.render(context(bare)) is None


def test_order_is_fifty() -> None:
    assert trace_table.ORDER == 50


# --- the marks -------------------------------------------------------------------------------


def test_consistent_trace_is_all_ticks() -> None:
    html = render(*genuine()).html
    assert marks(html) == ["ok"] * 6
    assert "does not match" not in html


def test_fabricated_trace_marks_match_what_c08_found() -> None:
    """File exists in every frame; the functions are elsewhere; two lines are past EOF."""
    html = render(*fabricated()).html
    assert marks(html) == [
        "ok",
        "bad",
        "bad",  # util_copy_value: file ok, function elsewhere, line 77 past 36
        "ok",
        "bad",
        "bad",  # hdr_get: file ok, function elsewhere, line 412 past 156
        "ok",
        "bad",
        "ok",  # main: file ok, function elsewhere, line 58 is inside the file
    ]


def test_missing_file_is_crossed_for_the_file_column() -> None:
    detail = {
        "claimed_path": "src/invented.c",
        "function": "hdr_get",
        "index": 1,
        "line": 9,
        "matched": [],
        "mismatched": ["no file matching src/invented.c exists at this commit"],
        "resolved_path": None,
        "status": "inconsistent",
    }
    html = render(evidence("e1", check_id="C08", details={"frames": [detail]})).html
    # Only the file question was answered; the other two are unknown, not failures.
    assert marks(html) == ["bad", "unknown", "unknown"]
    assert "no such file at this version" in html


def test_function_not_defined_in_that_file_is_crossed() -> None:
    detail = {
        "claimed_path": "src/hdr.c",
        "function": "hdr_ghost",
        "index": 1,
        "line": 9,
        "matched": ["src/hdr.c exists at this commit", "line 9 is inside the file (156 lines)"],
        "mismatched": ["hdr_ghost is not defined in src/hdr.c"],
        "resolved_path": "src/hdr.c",
        "status": "inconsistent",
    }
    html = render(evidence("e1", check_id="C08", details={"frames": [detail]})).html
    assert marks(html) == ["ok", "bad", "ok"]


def test_line_belongs_to_another_function_is_crossed() -> None:
    detail = {
        "claimed_path": "src/hdr.c",
        "function": "hdr_get",
        "index": 1,
        "line": 9,
        "matched": ["src/hdr.c exists at this commit", "line 9 is inside the file (156 lines)"],
        "mismatched": ["line 9 is inside hdr_parse_line, not hdr_get"],
        "resolved_path": "src/hdr.c",
        "status": "inconsistent",
    }
    html = render(evidence("e1", check_id="C08", details={"frames": [detail]})).html
    assert marks(html) == ["ok", "bad", "ok"]


# --- the third state (ADR 0003) ---------------------------------------------------------------


def test_uncertain_and_skipped_frames_are_never_crossed() -> None:
    """A frame C08 left out of its ratio is "not checked" in all three columns.

    An unparsed file and a libc frame say nothing about the report. Drawing either as ✗
    would be a contradiction nobody computed (P4, ADR 0003).
    """
    unparsed = {
        "claimed_path": "/work/libhdr/src/gnarly.c",
        "function": "hdr_weird",
        "index": 1,
        "line": 4100,
        "reason": "src/gnarly.c did not parse cleanly at this commit",
        "resolved_path": "src/gnarly.c",
        "status": "uncertain",
    }
    libc = {
        "claimed_path": "/usr/src/debug/glibc/csu/libc-start.c",
        "function": "__libc_start_main",
        "index": 2,
        "line": 360,
        "reason": "the file is under usr/src, outside the repository",
        "resolved_path": None,
        "status": "skipped",
    }
    details = {"frames": [unparsed, libc], "trace_format": "asan"}
    html = render(evidence("e1", check_id="C08", details=details)).html

    assert marks(html) == ["unknown"] * 6
    assert "bad" not in marks(html)
    assert html.count('class="pill unknown">not checked') == 2
    assert "did not parse cleanly" in html
    assert "outside the repository" in html
    # The glyph itself must not be the cross (the legend outside the table shows all three).
    assert all(CROSS not in row for row in rows(html))


def test_generated_file_frame_is_not_checked() -> None:
    detail = {
        "claimed_path": "src/parser.gen.c",
        "function": "yyparse",
        "index": 1,
        "line": 900,
        "reason": "generated/release-only file, not in source control (matches src/*.gen.c)",
        "resolved_path": "src/parser.gen.c",
        "status": "skipped",
    }
    html = render(evidence("e1", check_id="C08", details={"frames": [detail]})).html
    assert marks(html) == ["unknown"] * 3
    assert "not in source control" in html


def test_unrecognised_wording_degrades_to_not_checked() -> None:
    """If C08's sentences ever change, the view loses marks rather than inventing them."""
    detail = {
        "claimed_path": "src/hdr.c",
        "function": "hdr_get",
        "index": 1,
        "line": 9,
        "matched": ["something this view has never seen"],
        "mismatched": ["and neither is this"],
        "resolved_path": "src/hdr.c",
        "status": "inconsistent",
    }
    html = render(evidence("e1", check_id="C08", details={"frames": [detail]})).html
    assert marks(html) == ["unknown"] * 3


def test_a_question_answered_both_ways_is_not_checked() -> None:
    detail = {
        "claimed_path": "src/hdr.c",
        "function": "hdr_get",
        "index": 1,
        "line": 9,
        "matched": ["line 9 is inside the file (156 lines)"],
        "mismatched": ["src/hdr.c has 8 lines"],
        "resolved_path": "src/hdr.c",
        "status": "inconsistent",
    }
    assert trace_table._marks(detail)["line"] == "unknown"


def test_legend_explains_the_third_state() -> None:
    html = render(*fabricated()).html
    assert "never counted against a report" in html
    assert "not checked" in html


# --- accessibility ----------------------------------------------------------------------------


def test_every_mark_carries_text_for_a_screen_reader() -> None:
    html = render(*fabricated()).html
    cells = html.split('<td class="tt-mark ')[1:]
    assert cells
    for cell in cells:
        body = cell.split("</td>", 1)[0]
        assert '<span class="tt-sr">' in body
        assert 'aria-hidden="true"' in body
        words = body.split('<span class="tt-sr">', 1)[1].split("</span>", 1)[0]
        assert words.split(": ")[0] in ("File", "Function", "Line")
        assert words.split(": ")[1] in ("matches", "does not match", "not checked")


def test_table_has_a_caption_and_column_headers() -> None:
    html = render(*fabricated()).html
    assert "<caption>Stack trace alignment (asan)" in html
    for label in ("#", "Frame", "Claimed location", "Actual location", "File", "Line"):
        assert f">{label}</th>" in html
    assert html.count('scope="col"') == 7
    assert 'aria-labelledby="tt-heading"' in html


def test_the_summary_sentence_is_shown() -> None:
    html = render(*fabricated()).html
    assert "0 of 3 application frames fit the code at v1.2.0" in html


# --- the edges ---------------------------------------------------------------------------------


def test_real_call_edge_is_shown_with_its_call_site() -> None:
    html = render(*genuine()).html
    edge = [row for row in rows(html) if 'class="tt-edge"' in row]
    assert len(edge) == 1
    assert "a direct call" in edge[0]
    assert "src/hdr.c:104 direct call" in edge[0]
    assert ">hdr_parse_line</span>" in edge[0]
    assert ">util_copy_value</span>" in edge[0]
    assert '<span class="tt-sr"> calls </span>' in edge[0]


def test_missing_call_edge_names_what_the_caller_really_calls() -> None:
    html = render(*fabricated()).html
    edges = [row for row in rows(html) if 'class="tt-edge"' in row]
    assert len(edges) == 2
    assert all("no such call at this version" in row for row in edges)
    assert "hdr_get calls: hdr_find_line, strncpy, util_strip" in edges[0]


def test_edge_rows_sit_between_the_frames_they_join() -> None:
    html = render(*fabricated()).html
    kinds = ["edge" if 'class="tt-edge"' in row else "frame" for row in rows(html)]
    assert kinds == ["frame", "edge", "frame", "edge", "frame"]


def test_skipped_edge_is_not_checked() -> None:
    edges = {
        "edges": [],
        "skipped": [
            {
                "caller": "__libc_start_main",
                "callee": "main",
                "caller_frame": 2,
                "callee_frame": 1,
                "reasons": ["/usr/src/libc-start.c is not in the tree at v1.2.0"],
            }
        ],
        "unknown": [],
    }
    frames = {
        "frames": [
            {
                "claimed_path": "tools/hdrcat.c",
                "function": "main",
                "index": 1,
                "line": 122,
                "matched": [
                    "tools/hdrcat.c exists at this commit",
                    "line 122 is inside the file (130 lines)",
                    "line 122 is inside main",
                ],
                "mismatched": [],
                "resolved_path": "tools/hdrcat.c",
                "status": "consistent",
            },
            {
                "claimed_path": "/usr/src/libc-start.c",
                "function": "__libc_start_main",
                "index": 2,
                "line": 59,
                "reason": "the file is under usr/src, outside the repository",
                "resolved_path": None,
                "status": "skipped",
            },
        ]
    }
    html = render(
        evidence("e1", check_id="C08", details=frames),
        evidence("e2", check_id="C09", details=edges),
    ).html
    edge = next(row for row in rows(html) if 'class="tt-edge"' in row)
    assert '<span class="pill unknown">not checked</span>' in edge
    assert "is not in the tree at v1.2.0" in edge
    assert CROSS not in edge


def test_indirect_edge_is_a_warning_not_a_failure() -> None:
    edges = {
        "edges": [
            {
                "caller": "hdr_parse_line",
                "callee": "util_copy_value",
                "caller_frame": 2,
                "callee_frame": 1,
                "kind": "indirect_possible",
                "sites": ["src/hdr.c:104 call through a function pointer"],
            }
        ],
        "skipped": [],
        "unknown": [],
    }
    html = render(
        evidence("e1", check_id="C08", details=GENUINE_FRAMES),
        evidence("e2", check_id="C09", details=edges),
    ).html
    edge = next(row for row in rows(html) if 'class="tt-edge"' in row)
    assert '<span class="pill warn">possible only indirectly</span>' in edge


def test_edge_without_c09_makes_no_claim() -> None:
    html = render(evidence("e1", check_id="C08", details=FABRICATED_FRAMES)).html
    edges = [row for row in rows(html) if 'class="tt-edge"' in row]
    assert len(edges) == 2
    for row in edges:
        assert "called by the frame below" in row
        assert "pill" not in row


def test_edges_only_join_the_pair_they_belong_to() -> None:
    """A record for frames 9 and 8 must not be drawn between frames 1 and 2."""
    edges = {
        "edges": [
            {
                "caller": "elsewhere",
                "callee": "also_elsewhere",
                "caller_frame": 9,
                "callee_frame": 8,
                "kind": "direct",
                "sites": [],
            }
        ],
        "skipped": [],
        "unknown": [],
    }
    html = render(
        evidence("e1", check_id="C08", details=GENUINE_FRAMES),
        evidence("e2", check_id="C09", details=edges),
    ).html
    assert "elsewhere" not in html
    assert "called by the frame below" in html


# --- hostile input ------------------------------------------------------------------------------


def hostile_details() -> dict[str, Any]:
    return {
        "trace_format": HOSTILE,
        "frames": [
            {
                "claimed_path": HOSTILE,
                "function": HOSTILE,
                "index": 1,
                "line": 9,
                "matched": [HOSTILE],
                "mismatched": [HOSTILE],
                "resolved_path": HOSTILE,
                "status": "inconsistent",
            },
            {
                "claimed_path": HOSTILE,
                "function": HOSTILE,
                "index": 2,
                "line": 9,
                "reason": HOSTILE,
                "resolved_path": None,
                "status": "skipped",
            },
        ],
    }


def hostile_edges() -> dict[str, Any]:
    return {
        "edges": [
            {
                "caller": HOSTILE,
                "callee": HOSTILE,
                "caller_frame": 2,
                "callee_frame": 1,
                "caller_calls": [HOSTILE],
                "kind": "none",
                "sites": [HOSTILE],
            }
        ],
        "skipped": [],
        "unknown": [],
    }


def test_hostile_frame_text_is_inert() -> None:
    fragment = render(
        evidence("e1", check_id="C08", details=hostile_details(), summary=HOSTILE),
        evidence("e2", check_id="C09", details=hostile_edges()),
    )
    html = fragment.html
    # Nothing the report supplied opened a tag: every tag in the output is one this
    # module wrote, and none of them carries an event handler or fetches anything.
    tags = re.findall(r"<[a-zA-Z/][^>]*>", html)
    names = {tag.lstrip("</").split(" ", 1)[0].rstrip(">") for tag in tags}
    assert names <= {
        "section",
        "h2",
        "p",
        "div",
        "table",
        "caption",
        "thead",
        "tbody",
        "tr",
        "th",
        "td",
        "ul",
        "li",
        "span",
    }
    assert [tag for tag in tags if re.search(r"\son\w+\s*=", tag)] == []
    assert [tag for tag in tags if re.search(r"\s(href|src|style)\s*=", tag)] == []
    assert "<script" not in html
    assert "</script" not in html
    assert "<img" not in html
    # The payload is present, inert: the angle brackets that made it markup are gone.
    assert "&lt;img src=x onerror=alert(1)&gt;" in html
    # Control characters, bidi overrides and zero-width characters never reach the page.
    assert "\x1b" not in html
    assert BIDI not in html
    assert ZWSP not in html


def test_pathological_strings_are_capped() -> None:
    fragment = render(
        evidence("e1", check_id="C08", details=hostile_details(), summary=HOSTILE),
        evidence("e2", check_id="C09", details=hostile_edges()),
    )
    html = fragment.html
    assert "A" * (trace_table.MAX_NOTE + 1) not in html
    assert ELLIPSIS in html  # something was elided
    # A 4000-character function name may not set the width of the page. Escaping expands
    # the text, so the cap is measured in the characters the cap is about.
    for chunk in html.split('<span class="tt-fn">')[1:]:
        assert chunk.split("</span>", 1)[0].count("A") < trace_table.MAX_FUNCTION
    assert len(html) < 20_000


def test_frames_are_capped_and_the_cut_is_declared() -> None:
    frames = [
        {
            "claimed_path": f"src/f{n}.c",
            "function": f"fn_{n}",
            "index": n,
            "line": 1,
            "matched": [f"src/f{n}.c exists at this commit"],
            "mismatched": [],
            "resolved_path": f"src/f{n}.c",
            "status": "consistent",
        }
        for n in range(trace_table.MAX_FRAMES + 40)
    ]
    html = render(evidence("e1", check_id="C08", details={"frames": frames})).html
    assert html.count('<tr class="tt-frame">') == trace_table.MAX_FRAMES
    assert "40 further frames are not shown here." in html


def test_tables_are_capped() -> None:
    items = [
        evidence(f"e{n:03d}", check_id="C08", claim_id="t1", details=FABRICATED_FRAMES)
        for n in range(trace_table.MAX_TABLES + 5)
    ]
    html = render(*items).html
    assert html.count("<caption>") == trace_table.MAX_TABLES


def test_garbage_details_do_not_raise() -> None:
    details: dict[str, Any] = {
        "trace_format": 7,
        "frames": [
            {"index": "one", "function": None, "line": "nine", "status": 3},
            {"index": 2, "matched": "not a list", "mismatched": {"a": 1}, "status": "consistent"},
            "not a mapping",
        ],
    }
    edges: dict[str, Any] = {"edges": "not a list", "skipped": None, "unknown": [{"kind": 4}]}
    html = render(
        evidence("e1", check_id="C08", details=details),
        evidence("e2", check_id="C09", details=edges),
    ).html
    assert "<table" in html
    assert marks(html) == ["unknown"] * 3 + ["unknown"] * 3


# --- determinism, layering, tone --------------------------------------------------------------


def test_rendering_twice_is_byte_identical() -> None:
    first = render(*fabricated())
    second = render(*fabricated())
    assert first.html == second.html
    assert first.css == second.css


def test_tables_follow_the_order_of_the_claims() -> None:
    claims = (trace_claim("t2"), trace_claim("t1"))
    items = (
        evidence("zz", check_id="C08", claim_id="t2", details=GENUINE_FRAMES),
        evidence("aa", check_id="C08", claim_id="t1", details=FABRICATED_FRAMES),
    )
    html = render(*items, claims=claims).html  # type: ignore[arg-type]
    assert html.index("hdr_parse_line") < html.index("hdr_get")


def test_component_emits_no_script_and_no_inline_handlers() -> None:
    fragment = render(*fabricated())
    assert fragment.js == ""
    assert "<script" not in fragment.html
    assert re.search(r"\son\w+\s*=", fragment.html) is None
    assert "style=" not in fragment.html
    assert "url(" not in fragment.css  # no external fetch from CSS either


def test_css_is_namespaced_to_this_component() -> None:
    selectors = re.findall(r"\.[a-zA-Z][\w-]*", render(*fabricated()).css)
    allowed = {".ok", ".bad", ".warn", ".unknown", ".pill", ".panel", ".muted", ".mono"}
    assert all(name.startswith(".tt-") or name in allowed for name in selectors), selectors


def test_wording_is_about_claims_not_people() -> None:
    fragment = render(*fabricated())
    lowered = (fragment.html + fragment.css).lower()
    for word in BANNED_WORDS:
        assert word not in lowered
