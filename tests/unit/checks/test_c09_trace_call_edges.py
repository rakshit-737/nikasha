# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""C09 TRACE_CALL_EDGES, against the real vulnlab tree (SPEC §12).

The call chain the fixtures assert is the one documented in ``examples/vulnlab/README.md``:
``main -> hdr_parse_block -> hdr_parse_line -> util_copy_value -> memcpy`` at v1.2.0.
"""

from __future__ import annotations

from pathlib import Path

from check_helpers import ROOT, MakeContext, claim

from nikasha.checks.base import run_checks
from nikasha.checks.c09_trace_call_edges import TraceCallEdges, file_is_certain, score_edges
from nikasha.checks.strengths import default_strengths
from nikasha.code.facts import FileFacts
from nikasha.extract.traces import parse_traces
from nikasha.model.claims import Frame, TraceClaim

ASAN = ROOT / "tests" / "fixtures" / "traces" / "asan"
GENUINE = ASAN / "01-vulnlab-heap-overflow-v1.2.0.txt"
FABRICATED = ROOT / "examples" / "reports" / "fabricated_hdr_overflow.md"


def frame(
    index: int,
    function: str,
    path: str | None = None,
    line: int | None = None,
    *,
    is_runtime: bool = False,
) -> Frame:
    return Frame(
        index=index,
        function=function,
        path=path,
        line=line,
        is_runtime=is_runtime,
        raw=f"    #{index} 0x0 in {function} {path}:{line}",
    )


def stack(*frames: Frame, **overrides: object) -> TraceClaim:
    """A trace claim over ``frames``, innermost first (as every real stack is printed)."""
    return claim(TraceClaim, format="asan", frames=tuple(frames), **overrides)


def real_trace(path: Path, **overrides: object) -> TraceClaim:
    """The one trace in a captured fixture or an example report, parsed for real."""
    (parsed,) = parse_traces(path.read_text(encoding="utf-8"))
    return claim(TraceClaim, **parsed.data.model_dump(), **overrides)


def run(make_ctx: MakeContext, trace: TraceClaim, tag: str = "v1.2.0") -> list:
    ctx = make_ctx(claims=[trace], tag=tag)
    return TraceCallEdges().run(ctx, [trace])


# --- the real chains ----------------------------------------------------------------------


def test_the_captured_asan_chain_supports(make_ctx: MakeContext) -> None:
    (evidence,) = run(make_ctx, real_trace(GENUINE))
    assert evidence.outcome == "SUPPORTS"
    assert evidence.strength == 1.5
    assert evidence.check_id == "C09"
    assert evidence.group == "trace"
    assert [(e["caller"], e["callee"], e["kind"]) for e in evidence.details["edges"]] == [
        ("hdr_parse_line", "util_copy_value", "direct"),
        ("hdr_parse_block", "hdr_parse_line", "direct"),
        ("main", "hdr_parse_block", "direct"),
    ]
    assert evidence.details["n_missing"] == 0
    assert "v1.2.0" in evidence.summary


def test_every_edge_records_its_call_site_for_the_report(make_ctx: MakeContext) -> None:
    (evidence,) = run(make_ctx, real_trace(GENUINE))
    sites = {e["callee"]: e["sites"] for e in evidence.details["edges"]}
    assert sites["util_copy_value"] == ["src/hdr.c:104 direct call"]
    assert sites["hdr_parse_line"] == ["src/hdr.c:134 direct call"]
    assert sites["hdr_parse_block"] == ["tools/hdrcat.c:122 direct call"]
    assert [e["caller_path"] for e in evidence.details["edges"]] == [
        "src/hdr.c",
        "src/hdr.c",
        "tools/hdrcat.c",
    ]


def test_runtime_frames_are_not_edges(make_ctx: MakeContext) -> None:
    """The captured trace's ``__asan_memcpy``, ``__libc_start_main`` and ``_start`` frames."""
    (evidence,) = run(make_ctx, real_trace(GENUINE))
    seen = {e["caller_frame"] for e in evidence.details["edges"]}
    seen |= {e["callee_frame"] for e in evidence.details["edges"]}
    assert seen == {1, 2, 3, 4}
    assert evidence.details["skipped"] == []
    assert evidence.details["unknown"] == []


def test_a_libc_frame_between_two_app_frames_does_not_break_the_edge(
    make_ctx: MakeContext,
) -> None:
    trace = stack(
        frame(0, "util_copy_value", "/work/libhdr/src/util.c", 15),
        frame(1, "malloc", is_runtime=True),
        frame(2, "hdr_parse_line", "/work/libhdr/src/hdr.c", 104),
    )
    (evidence,) = run(make_ctx, trace)
    assert evidence.outcome == "SUPPORTS"
    assert [e["kind"] for e in evidence.details["edges"]] == ["direct"]


def test_an_inlined_two_hop_edge_counts_as_real(make_ctx: MakeContext) -> None:
    """``hdr_get`` reaches ``hdr_casecmp`` through the small ``hdr_find_line`` helper."""
    trace = stack(
        frame(0, "hdr_casecmp", "/work/libhdr/src/hdr.c", 29),
        frame(1, "hdr_get", "/work/libhdr/src/hdr.c", 152),
    )
    (evidence,) = run(make_ctx, trace)
    assert evidence.outcome == "SUPPORTS"
    assert evidence.strength == 1.5
    assert evidence.details["edges"][0]["kind"] == "inlined_2hop"
    assert evidence.details["edges"][0]["sites"] == [
        "src/hdr.c:152 via hdr_find_line (src/hdr.c:39)"
    ]


def test_the_fabricated_report_chain_is_refuted(make_ctx: MakeContext) -> None:
    """``hdr_get -> util_copy_value`` and ``main -> hdr_get`` are calls neither function makes."""
    (evidence,) = run(make_ctx, real_trace(FABRICATED))
    assert evidence.outcome == "REFUTES"
    assert evidence.strength == -2.0
    assert [(e["caller"], e["callee"], e["kind"]) for e in evidence.details["edges"]] == [
        ("hdr_get", "util_copy_value", "none"),
        ("main", "hdr_get", "none"),
    ]
    assert "hdr_get -> util_copy_value" in evidence.summary
    assert "v1.2.0" in evidence.summary


def test_a_missing_edge_lists_what_the_caller_really_calls(make_ctx: MakeContext) -> None:
    (evidence,) = run(make_ctx, real_trace(FABRICATED))
    calls = evidence.details["edges"][0]["caller_calls"]
    assert "hdr_find_line" in calls and "util_strip" in calls
    assert "util_copy_value" not in calls
    assert calls == sorted(calls)


def test_missing_edges_are_capped_at_three(make_ctx: MakeContext) -> None:
    """Four impossible edges between functions that all really exist at v1.2.0."""
    trace = stack(
        frame(0, "util_copy_value", "/work/libhdr/src/util.c", 15),
        frame(1, "usage", "/work/libhdr/tools/hdrcat.c", 78),
        frame(2, "cap_lines", "/work/libhdr/tools/hdrcat.c", 64),
        frame(3, "fold_lines", "/work/libhdr/tools/hdrcat.c", 46),
        frame(4, "read_file", "/work/libhdr/tools/hdrcat.c", 19),
    )
    (evidence,) = run(make_ctx, trace)
    assert evidence.details["n_missing"] == 4
    assert evidence.strength == -3.0
    assert "and 1 more" in evidence.summary


def test_a_missing_edge_is_located_at_the_callers_body(make_ctx: MakeContext) -> None:
    (evidence,) = run(make_ctx, real_trace(FABRICATED))
    first = evidence.locations[0]
    assert (first.path, first.start_line, first.end_line) == ("src/hdr.c", 145, 156)
    assert first.commit == make_ctx().commit
    assert first.permalink is not None and first.permalink.endswith("/src/hdr.c#L145-L156")


# --- what must never become a refutation ---------------------------------------------------


def test_frames_outside_the_repository_are_skipped_not_missing(make_ctx: MakeContext) -> None:
    """The third-party boundary that ADR 0003 exists to protect."""
    trace = stack(
        frame(0, "util_copy_value", "/work/libhdr/src/util.c", 15),
        frame(1, "ngx_http_parse_header_line", "/build/nginx/src/http/ngx_http_parse.c", 1234),
        frame(2, "main", "/work/libhdr/tools/hdrcat.c", 122),
    )
    (evidence,) = run(make_ctx, trace)
    assert evidence.outcome == "NEUTRAL"
    assert evidence.strength == 0.0
    assert evidence.details["edges"] == []
    assert len(evidence.details["skipped"]) == 2
    assert "not in the tree" in evidence.details["skipped"][0]["reasons"][0]
    assert "no call edge in the trace could be checked" in evidence.summary


def test_a_frame_with_no_file_is_skipped(make_ctx: MakeContext) -> None:
    trace = stack(
        frame(0, "util_copy_value", "/work/libhdr/src/util.c", 15),
        frame(1, "hdr_dispatch"),
    )
    (evidence,) = run(make_ctx, trace)
    assert evidence.outcome == "NEUTRAL"
    assert len(evidence.details["skipped"]) == 1


def test_a_generated_file_is_never_judged(make_ctx: MakeContext) -> None:
    trace = stack(
        frame(0, "util_copy_value", "/work/libhdr/src/util.c", 15),
        frame(1, "hdr_config_init", "work/libhdr/src/config.h", 42),
        frame(2, "main", "/work/libhdr/tools/hdrcat.c", 122),
    )
    (evidence,) = run(make_ctx, trace)
    assert evidence.outcome == "NEUTRAL"
    assert len(evidence.details["unknown"]) == 2
    assert "generated" in evidence.details["unknown"][0]["reasons"][0]


def test_a_file_without_facts_is_unknown_not_missing(make_ctx: MakeContext) -> None:
    """``Makefile`` is in the tree, but nothing parses it, so absence proves nothing (P4)."""
    trace = stack(
        frame(0, "util_copy_value", "/work/libhdr/src/util.c", 15),
        frame(1, "build_all", "Makefile", 3),
        frame(2, "main", "/work/libhdr/tools/hdrcat.c", 122),
    )
    (evidence,) = run(make_ctx, trace)
    assert evidence.outcome == "NEUTRAL"
    assert evidence.details["n_checked"] == 0
    assert len(evidence.details["unknown"]) == 2
    assert "did not parse cleanly" in evidence.details["unknown"][0]["reasons"][0]


def test_an_invented_function_is_left_to_c03(make_ctx: MakeContext) -> None:
    """A function that is not defined anywhere cannot make C09 claim a missing call edge."""
    trace = stack(
        frame(0, "util_copy_value", "/work/libhdr/src/util.c", 15),
        frame(1, "hdr_decode_chunked_value", "/work/libhdr/src/hdr.c", 412),
        frame(2, "main", "/work/libhdr/tools/hdrcat.c", 122),
    )
    (evidence,) = run(make_ctx, trace)
    assert evidence.outcome == "NEUTRAL"
    assert evidence.details["edges"] == []
    reasons = [r for record in evidence.details["unknown"] for r in record["reasons"]]
    assert all("hdr_decode_chunked_value" in reason for reason in reasons)
    assert "C03" in reasons[0]


def test_a_partially_parsed_file_can_never_settle_an_edge() -> None:
    """P4 in one function: the parser's own verdict decides whether absence means anything."""
    assert file_is_certain(FileFacts(lang="c", n_lines=10, parsed_ok=True)) is True
    assert file_is_certain(FileFacts(lang="c", n_lines=10, parsed_ok=False)) is False
    assert file_is_certain(None) is False


def test_fewer_than_two_app_frames_assert_no_edge(make_ctx: MakeContext) -> None:
    assert run(make_ctx, stack(frame(0, "util_copy_value", "/work/libhdr/src/util.c", 15))) == []
    assert run(make_ctx, stack()) == []


# --- the scoring rule ----------------------------------------------------------------------


class TestScoreEdges:
    """SPEC §12's arithmetic, isolated: vulnlab has no function pointers to exercise it with."""

    def test_every_real_kind_supports(self) -> None:
        for kind in ("direct", "macro", "inlined_2hop"):
            assert score_edges([kind], default_strengths()) == ("SUPPORTS", 1.5)
        assert score_edges(["direct", "macro", "inlined_2hop"], default_strengths()) == (
            "SUPPORTS",
            1.5,
        )

    def test_an_indirect_edge_scores_zero(self) -> None:
        assert score_edges(["indirect_possible"], default_strengths()) == ("NEUTRAL", 0.0)
        assert score_edges(["direct", "indirect_possible"], default_strengths()) == (
            "NEUTRAL",
            0.0,
        )

    def test_missing_edges_add_up_to_the_cap(self) -> None:
        strengths = default_strengths()
        assert score_edges(["none"], strengths) == ("REFUTES", -1.0)
        assert score_edges(["none", "none"], strengths) == ("REFUTES", -2.0)
        assert score_edges(["none"] * 3, strengths) == ("REFUTES", -3.0)
        assert score_edges(["none"] * 9, strengths) == ("REFUTES", -3.0)
        assert score_edges(["direct", "none", "indirect_possible"], strengths) == (
            "REFUTES",
            -1.0,
        )

    def test_nothing_checkable_is_neutral(self) -> None:
        assert score_edges([], default_strengths()) == ("NEUTRAL", 0.0)

    def test_a_truncated_walk_cannot_claim_every_edge_is_real(self) -> None:
        strengths = default_strengths()
        assert score_edges(["direct"], strengths, truncated=True) == ("NEUTRAL", 0.0)
        assert score_edges(["direct", "none"], strengths, truncated=True) == ("REFUTES", -1.0)


# --- the framework's rules ------------------------------------------------------------------


class TestRefutationGate:
    """ADR 0003: only project-attributed, non-negated claims may be refuted."""

    def test_reporter_artifact_is_not_refuted(self, make_ctx: MakeContext) -> None:
        trace = real_trace(FABRICATED, provenance="reporter_artifact")
        (evidence,) = run(make_ctx, trace)
        assert evidence.outcome == "NEUTRAL"
        assert evidence.strength == 0.0
        assert evidence.details["gated"] == ["reporter_artifact"]
        assert evidence.details["withheld_strength"] == -2.0

    def test_negated_claim_is_not_refuted(self, make_ctx: MakeContext) -> None:
        (evidence,) = run(make_ctx, real_trace(FABRICATED, negated=True))
        assert evidence.outcome == "NEUTRAL"
        assert evidence.details["gated"] == ["negated"]

    def test_support_is_not_gated(self, make_ctx: MakeContext) -> None:
        (evidence,) = run(make_ctx, real_trace(GENUINE, provenance="third_party"))
        assert evidence.outcome == "SUPPORTS"
        assert evidence.strength == 1.5


def test_identical_input_gives_identical_evidence(make_ctx: MakeContext) -> None:
    first = run(make_ctx, real_trace(FABRICATED))
    second = run(make_ctx, real_trace(FABRICATED))
    assert [e.id for e in first] == [e.id for e in second]
    assert first[0].model_dump() == second[0].model_dump()


def test_registered_and_runnable_through_the_runner(make_ctx: MakeContext) -> None:
    trace = real_trace(FABRICATED)
    ctx = make_ctx(claims=[trace])
    (run_result,) = run_checks(ctx, checks=[TraceCallEdges()])
    assert run_result.check_id == "C09"
    assert run_result.error is None
    assert [e.outcome for e in run_result.evidence] == ["REFUTES"]


def test_the_chain_still_holds_at_the_next_release(make_ctx: MakeContext) -> None:
    """v1.2.1 only moves lines; the call edges the trace asserts are unchanged."""
    (evidence,) = run(make_ctx, real_trace(GENUINE), tag="v1.2.1")
    assert evidence.outcome == "SUPPORTS"
    assert [e["kind"] for e in evidence.details["edges"]] == ["direct", "direct", "direct"]
