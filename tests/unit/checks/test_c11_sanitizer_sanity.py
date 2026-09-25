# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""C11 SANITIZER_SANITY, against the real captured traces (SPEC §12, ADR 0005).

Every trace here is real output: the ASan, UBSan and valgrind fixtures captured by
``scripts/capture_trace_fixtures.py``, and the traces embedded in ``examples/reports``. The
deliberately wrong report (``fabricated_hdr_overflow.md``) is the fixture for the violation
side, so the rules are tested against text a reporter could actually paste rather than
against strings written to make them fire.

Rules that no fixture violates (a mixed PID, a gap in the frame numbering, disagreeing
addresses, an impossible access size) are exercised by rebuilding a claim from a real
parsed trace with exactly one field changed — the trace stays real, the contradiction is
the only thing added.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from check_helpers import MakeContext, claim

from nikasha.checks.base import run_checks
from nikasha.checks.c11_sanitizer_sanity import RULES, SanitizerSanity
from nikasha.extract import extract_claims
from nikasha.extract.traces import parse_traces
from nikasha.ingest import load_report
from nikasha.model.claims import TraceClaim
from nikasha.model.evidence import Evidence

ROOT = Path(__file__).resolve().parents[3]
TRACES = ROOT / "tests" / "fixtures" / "traces"
REPORTS = ROOT / "examples" / "reports"


def _trace_claim(fixture: str, **overrides: Any) -> TraceClaim:
    """The trace in a real fixture file, as a claim, optionally with one field changed."""
    parsed = parse_traces((TRACES / fixture).read_text(encoding="utf-8"))
    assert len(parsed) == 1, fixture
    fields = {**parsed[0].data.model_dump(), **overrides}
    return claim(TraceClaim, **fields)


def _report_traces(name: str) -> list[TraceClaim]:
    """Every trace claim the extractor finds in one of the example reports."""
    extraction = extract_claims(load_report(REPORTS / name))
    return [c for c in extraction.claims if isinstance(c, TraceClaim)]


def _run(make_ctx: MakeContext, claims: list[TraceClaim]) -> list[Evidence]:
    ctx = make_ctx(claims=claims)
    return SanitizerSanity().run(ctx, list(claims))


def _violated(evidence: Evidence) -> list[str]:
    return [violation["rule"] for violation in evidence.details["violations"]]


# --- the genuine, modern-wording ASan output (the M2 carry-over) --------------------------


@pytest.mark.parametrize(
    "fixture",
    [
        "asan/01-vulnlab-heap-overflow-v1.2.0.txt",
        "asan/02-vulnlab-heap-overflow-v1.2.1.txt",
        "asan/03-vulnlab-heap-overflow-v1.2.0-O0-fold.txt",
    ],
)
def test_real_asan_output_is_consistent(make_ctx: MakeContext, fixture: str) -> None:
    (evidence,) = _run(make_ctx, [_trace_claim(fixture)])
    assert evidence.outcome == "SUPPORTS"
    assert evidence.strength == 0.3
    assert evidence.check_id == "C11"
    assert evidence.group == "trace_meta"
    assert evidence.details["violations"] == []


def test_modern_wording_is_not_a_violation(make_ctx: MakeContext) -> None:
    """ADR 0005: "0 bytes after" and a SUMMARY naming ``__asan_memcpy`` are valid output."""
    trace = _trace_claim("asan/01-vulnlab-heap-overflow-v1.2.0.txt")
    # The captured text really does use the modern spellings the older form did not have.
    assert trace.region is not None and trace.region.relation == "right"
    assert trace.summary_function == "__asan_memcpy"
    assert trace.summary_path is None
    assert trace.frames[0].function == "__asan_memcpy"
    (evidence,) = _run(make_ctx, [trace])
    assert evidence.outcome == "SUPPORTS"
    assert "region_arithmetic" in evidence.details["rules_checked"]
    assert "summary_matches_frames" in evidence.details["rules_checked"]


def test_the_genuine_report_trace_is_consistent(make_ctx: MakeContext) -> None:
    (trace,) = _report_traces("genuine_hdr_overflow.md")
    (evidence,) = _run(make_ctx, [trace])
    assert evidence.outcome == "SUPPORTS"
    assert evidence.details["bug_type"] == "heap-buffer-overflow"


def test_ubsan_output_is_consistent_on_the_rules_that_apply(make_ctx: MakeContext) -> None:
    """UBSan prints no PID, address or region, so only two rules can be applied."""
    (evidence,) = _run(make_ctx, [_trace_claim("ubsan/01-signed-integer-overflow.txt")])
    assert evidence.outcome == "SUPPORTS"
    assert evidence.details["rules_checked"] == ["frame_indices", "summary_matches_frames"]


# --- the fabricated report: the violations SPEC §12 names ---------------------------------


def test_the_fabricated_report_trace_is_refuted(make_ctx: MakeContext) -> None:
    (trace,) = _report_traces("fabricated_hdr_overflow.md")
    (evidence,) = _run(make_ctx, [trace])
    assert evidence.outcome == "REFUTES"
    assert _violated(evidence) == [
        "region_arithmetic",
        "summary_matches_frames",
        "stacks_present",
    ]
    assert evidence.strength == pytest.approx(-2.1)


def test_wrong_region_arithmetic_states_the_real_distance(make_ctx: MakeContext) -> None:
    """SPEC §12 rule 4: 0x…51 is 17 bytes past the end at 0x…40, not the 1 claimed."""
    (trace,) = _report_traces("fabricated_hdr_overflow.md")
    (evidence,) = _run(make_ctx, [trace])
    (detail,) = [
        v["detail"] for v in evidence.details["violations"] if v["rule"] == "region_arithmetic"
    ]
    assert "0x606000000051 is 17 bytes past the end of the region at 0x606000000040" in detail
    assert "not the stated 1" in detail


def test_summary_that_names_no_frame_is_a_violation(make_ctx: MakeContext) -> None:
    """SPEC §12 rule 5: the SUMMARY names hdr_decode_chunked_value, which is in no frame."""
    (trace,) = _report_traces("fabricated_hdr_overflow.md")
    (evidence,) = _run(make_ctx, [trace])
    (detail,) = [
        v["detail"] for v in evidence.details["violations"] if v["rule"] == "summary_matches_frames"
    ]
    assert "hdr_decode_chunked_value" in detail
    assert "__asan_memcpy" in detail and "util_copy_value" in detail


def test_heap_bug_without_an_allocation_stack_is_a_violation(make_ctx: MakeContext) -> None:
    """SPEC §12 rule 6: a heap-buffer-overflow that reached its SUMMARY had an alloc stack."""
    (trace,) = _report_traces("fabricated_hdr_overflow.md")
    assert trace.alloc_frames == ()
    (evidence,) = _run(make_ctx, [trace])
    (detail,) = [
        v["detail"] for v in evidence.details["violations"] if v["rule"] == "stacks_present"
    ]
    assert "an allocation stack" in detail


# --- one changed field on a real trace, for the rules no fixture violates -----------------


def test_mixed_process_ids_are_a_violation(make_ctx: MakeContext) -> None:
    trace = _trace_claim("asan/01-vulnlab-heap-overflow-v1.2.0.txt", pids_seen=(1, 4242))
    (evidence,) = _run(make_ctx, [trace])
    assert _violated(evidence) == ["pid_consistent"]
    assert evidence.strength == pytest.approx(-0.7)
    assert "1, 4242" in evidence.summary


def test_a_gap_in_the_frame_numbering_is_a_violation(make_ctx: MakeContext) -> None:
    real = _trace_claim("asan/01-vulnlab-heap-overflow-v1.2.0.txt")
    kept = [f.model_dump() for f in real.frames if f.index != 2]
    trace = _trace_claim("asan/01-vulnlab-heap-overflow-v1.2.0.txt", frames=kept)
    (evidence,) = _run(make_ctx, [trace])
    assert _violated(evidence) == ["frame_indices"]
    assert "the crash stack is numbered #0, #1, #3" in evidence.summary


def test_a_stack_not_starting_at_zero_is_a_violation(make_ctx: MakeContext) -> None:
    real = _trace_claim("asan/01-vulnlab-heap-overflow-v1.2.0.txt")
    kept = [f.model_dump() for f in real.alloc_frames if f.index != 0]
    trace = _trace_claim("asan/01-vulnlab-heap-overflow-v1.2.0.txt", alloc_frames=kept)
    (evidence,) = _run(make_ctx, [trace])
    assert _violated(evidence) == ["frame_indices"]
    assert "the allocation stack is numbered #1" in evidence.summary


def test_disagreeing_addresses_are_a_violation(make_ctx: MakeContext) -> None:
    trace = _trace_claim("asan/01-vulnlab-heap-overflow-v1.2.0.txt", access_address=0xDEADBEEF)
    (evidence,) = _run(make_ctx, [trace])
    # The access address also breaks nothing else: the region line still carries the address.
    assert "addresses_agree" in _violated(evidence)
    detail = next(
        v["detail"] for v in evidence.details["violations"] if v["rule"] == "addresses_agree"
    )
    assert "the access line says 0xdeadbeef" in detail


def test_a_region_whose_size_is_not_its_span_is_a_violation(make_ctx: MakeContext) -> None:
    real = _trace_claim("asan/01-vulnlab-heap-overflow-v1.2.0.txt")
    assert real.region is not None
    region = {**real.region.model_dump(), "size": 48}
    trace = _trace_claim("asan/01-vulnlab-heap-overflow-v1.2.0.txt", region=region)
    (evidence,) = _run(make_ctx, [trace])
    assert _violated(evidence) == ["region_arithmetic"]
    detail = evidence.details["violations"][0]["detail"]
    assert "spans 64 bytes, not the stated 48" in detail


def test_an_inside_relation_beyond_the_region_is_a_violation(make_ctx: MakeContext) -> None:
    """SPEC §12 rule 4: "inside of" means 0 <= addr - start < size."""
    real = _trace_claim("asan/01-vulnlab-heap-overflow-v1.2.0.txt")
    assert real.region is not None
    region = {**real.region.model_dump(), "relation": "inside", "distance": 64}
    trace = _trace_claim("asan/01-vulnlab-heap-overflow-v1.2.0.txt", region=region)
    (evidence,) = _run(make_ctx, [trace])
    assert _violated(evidence) == ["region_arithmetic"]
    assert "so it is not inside it" in evidence.summary


def test_an_impossible_access_size_is_a_violation(make_ctx: MakeContext) -> None:
    real = _trace_claim("asan/01-vulnlab-heap-overflow-v1.2.0.txt")
    assert real.access is not None
    access = {**real.access.model_dump(), "size": 0}
    trace = _trace_claim("asan/01-vulnlab-heap-overflow-v1.2.0.txt", access=access)
    (evidence,) = _run(make_ctx, [trace])
    assert "access_size" in _violated(evidence)


def test_the_group_total_is_capped(make_ctx: MakeContext) -> None:
    """Seven violated rules would be -4.9; SPEC §12 caps the group at -2.5."""
    real = _trace_claim("asan/01-vulnlab-heap-overflow-v1.2.0.txt")
    assert real.region is not None and real.access is not None
    trace = _trace_claim(
        "asan/01-vulnlab-heap-overflow-v1.2.0.txt",
        pids_seen=(1, 2),
        access_address=0xDEADBEEF,
        access={**real.access.model_dump(), "size": 0},
        region={**real.region.model_dump(), "size": 48, "distance": 9},
        alloc_frames=[],
        summary_function="not_a_frame_in_this_trace",
    )
    (evidence,) = _run(make_ctx, [trace])
    assert len(evidence.details["violations"]) >= 5
    assert evidence.strength == -2.5


# --- not checkable is never a violation (P4) ----------------------------------------------


def test_a_trace_with_nothing_checkable_yields_no_evidence(make_ctx: MakeContext) -> None:
    trace = _trace_claim(
        "ubsan/01-signed-integer-overflow.txt", frames=[], summary=None, summary_path=None
    )
    assert _run(make_ctx, [trace]) == []


def test_missing_fields_are_not_checked_rather_than_failed(make_ctx: MakeContext) -> None:
    """A trimmed paste with no region line cannot fail rules 3, 4 or 6."""
    trace = _trace_claim(
        "asan/01-vulnlab-heap-overflow-v1.2.0.txt",
        region=None,
        region_address=None,
        access_address=None,
        alloc_frames=[],
    )
    (evidence,) = _run(make_ctx, [trace])
    assert evidence.outcome == "SUPPORTS"
    checked = evidence.details["rules_checked"]
    assert "addresses_agree" not in checked
    assert "region_arithmetic" not in checked
    assert "stacks_present" not in checked


def test_valgrind_and_other_formats_are_left_to_the_trace_checks(make_ctx: MakeContext) -> None:
    """valgrind derives the block bounds from the address, so judging them proves nothing."""
    for fixture in (
        "valgrind/01-vulnlab-invalid-write-v1.2.0.txt",
        "gdb/01-vulnlab-heap-corruption-abort-v1.2.0.txt",
    ):
        assert _run(make_ctx, [_trace_claim(fixture)]) == []


# --- the framework contracts ---------------------------------------------------------------


class TestRefutationGate:
    """ADR 0003: only project-attributed, non-negated claims may be refuted."""

    def test_reporter_artifact_is_not_refuted(self, make_ctx: MakeContext) -> None:
        trace = _trace_claim(
            "asan/01-vulnlab-heap-overflow-v1.2.0.txt",
            pids_seen=(1, 4242),
            provenance="reporter_artifact",
        )
        (evidence,) = _run(make_ctx, [trace])
        assert evidence.outcome == "NEUTRAL"
        assert evidence.strength == 0.0
        assert evidence.details["gated"] == ["reporter_artifact"]
        assert evidence.details["withheld_strength"] == pytest.approx(-0.7)

    def test_negated_claim_is_not_refuted(self, make_ctx: MakeContext) -> None:
        trace = _trace_claim(
            "asan/01-vulnlab-heap-overflow-v1.2.0.txt", pids_seen=(1, 4242), negated=True
        )
        (evidence,) = _run(make_ctx, [trace])
        assert evidence.outcome == "NEUTRAL"
        assert evidence.details["gated"] == ["negated"]

    def test_support_is_not_gated(self, make_ctx: MakeContext) -> None:
        trace = _trace_claim("asan/01-vulnlab-heap-overflow-v1.2.0.txt", provenance="third_party")
        (evidence,) = _run(make_ctx, [trace])
        assert evidence.outcome == "SUPPORTS"


def test_identical_input_gives_identical_evidence_ids(make_ctx: MakeContext) -> None:
    (trace,) = _report_traces("fabricated_hdr_overflow.md")
    first = _run(make_ctx, [trace])
    second = _run(make_ctx, [trace])
    assert [e.id for e in first] == [e.id for e in second]
    assert first[0].model_dump() == second[0].model_dump()


def test_every_spec_rule_has_an_entry(make_ctx: MakeContext) -> None:
    """SPEC §12 lists seven rules; all seven are applied, and the details name each one."""
    assert [key for key, _, _ in RULES] == [
        "pid_consistent",
        "frame_indices",
        "addresses_agree",
        "region_arithmetic",
        "summary_matches_frames",
        "stacks_present",
        "access_size",
    ]
    (evidence,) = _run(make_ctx, [_trace_claim("asan/01-vulnlab-heap-overflow-v1.2.0.txt")])
    assert evidence.details["rules_total"] == 7
    assert evidence.details["rules_checked"] == [
        "pid_consistent",
        "frame_indices",
        "addresses_agree",
        "region_arithmetic",
        "summary_matches_frames",
        "stacks_present",
        "access_size",
    ]


def test_registered_and_runnable_through_the_runner(make_ctx: MakeContext) -> None:
    (trace,) = _report_traces("fabricated_hdr_overflow.md")
    ctx = make_ctx(claims=[trace])
    (run,) = run_checks(ctx, checks=[SanitizerSanity()])
    assert run.check_id == "C11"
    assert run.error is None
    assert [e.outcome for e in run.evidence] == ["REFUTES"]


def test_the_check_needs_no_repository(make_ctx: MakeContext) -> None:
    """C11 judges the trace alone, so it cites no code location."""
    (trace,) = _report_traces("genuine_hdr_overflow.md")
    (evidence,) = _run(make_ctx, [trace])
    assert evidence.locations == ()
    assert evidence.commands == ()


# --- genuine output the rules must not call a contradiction (P4) --------------------------

ASAN_01 = "asan/01-vulnlab-heap-overflow-v1.2.0.txt"


def _pasted_claim(text: str) -> TraceClaim:
    """The trace in ``text`` as a claim whose span carries that text, as extraction builds it."""
    (parsed,) = parse_traces(text)
    return claim(TraceClaim, text=text[parsed.start : parsed.end], **parsed.data.model_dump())


def _fixture_text() -> str:
    return (TRACES / ASAN_01).read_text(encoding="utf-8")


def test_an_access_running_past_the_end_is_described_from_the_end(make_ctx: MakeContext) -> None:
    """ASan reports the region line from the first byte past the end for such an access.

    ``GetAccessToHeapChunkInformation`` adds a negative offset back to ``bad_addr``: a
    96-byte write starting 2 bytes before the end is "on address end-2" in the header and
    "end is located 0 bytes after" in the region line. One address, two views.
    """
    real = _trace_claim(ASAN_01)
    assert real.region is not None
    start = real.region.end - 2
    trace = _trace_claim(ASAN_01, address=start, access_address=start)
    (evidence,) = _run(make_ctx, [trace])
    assert evidence.outcome == "SUPPORTS"
    assert "addresses_agree" in evidence.details["rules_checked"]


def test_an_access_that_ends_inside_the_region_is_still_a_disagreement(
    make_ctx: MakeContext,
) -> None:
    """The clamp only explains an access that actually reaches past the end."""
    real = _trace_claim(ASAN_01)
    assert real.region is not None and real.access is not None
    start = real.region.end - 2
    trace = _trace_claim(
        ASAN_01,
        address=start,
        access_address=start,
        access={**real.access.model_dump(), "size": 1},
    )
    (evidence,) = _run(make_ctx, [trace])
    assert "addresses_agree" in _violated(evidence)


def test_a_source_path_with_a_space_is_not_a_summary_mismatch(make_ctx: MakeContext) -> None:
    """``/work/My Projects/src/util.c`` splits at the wrong space; the text still agrees."""
    text = _fixture_text().replace("/work/libhdr/", "/work/My Projects/libhdr/")
    text = text.replace(
        "heap-buffer-overflow (/work/My Projects/libhdr/build/hdrcat+0x4a44a1)"
        " (BuildId: 4eac29a79b503833186b91f005f9af73315aab2e) in __asan_memcpy",
        "heap-buffer-overflow /work/My Projects/libhdr/src/util.c:15:5 in util_copy_value",
    )
    (evidence,) = _run(make_ctx, [_pasted_claim(text)])
    assert evidence.outcome == "SUPPORTS"
    assert "summary_matches_frames" in evidence.details["rules_checked"]


def test_a_summary_naming_another_function_still_fails_with_a_spaced_path(
    make_ctx: MakeContext,
) -> None:
    text = _fixture_text().replace("/work/libhdr/", "/work/My Projects/libhdr/")
    text = text.replace(
        "heap-buffer-overflow (/work/My Projects/libhdr/build/hdrcat+0x4a44a1)"
        " (BuildId: 4eac29a79b503833186b91f005f9af73315aab2e) in __asan_memcpy",
        "heap-buffer-overflow /work/My Projects/libhdr/src/hdr.c:77:5 in hdr_decode",
    )
    (evidence,) = _run(make_ctx, [_pasted_claim(text)])
    assert "summary_matches_frames" in _violated(evidence)


@pytest.mark.parametrize("marker", ["    ...", "    [...]", "    <snip>", "(3 frames omitted)"])
def test_frames_the_reporter_marked_as_cut_are_not_a_numbering_gap(
    make_ctx: MakeContext, marker: str
) -> None:
    lines = _fixture_text().split("\n")
    first_frame_2 = next(i for i, line in enumerate(lines) if line.lstrip().startswith("#2 "))
    lines[first_frame_2 : first_frame_2 + 2] = [marker]  # crash stack #2 and #3 cut
    (evidence,) = _run(make_ctx, [_pasted_claim("\n".join(lines))])
    assert evidence.outcome == "SUPPORTS"
    assert "frame_indices" in evidence.details["rules_checked"]


def test_an_unmarked_gap_in_pasted_text_is_still_a_violation(make_ctx: MakeContext) -> None:
    lines = _fixture_text().split("\n")
    first_frame_2 = next(i for i, line in enumerate(lines) if line.lstrip().startswith("#2 "))
    del lines[first_frame_2 : first_frame_2 + 2]
    (evidence,) = _run(make_ctx, [_pasted_claim("\n".join(lines))])
    assert _violated(evidence) == ["frame_indices"]


def test_a_marked_cut_does_not_excuse_numbers_running_backwards(make_ctx: MakeContext) -> None:
    lines = _fixture_text().split("\n")
    first_frame_4 = next(i for i, line in enumerate(lines) if line.lstrip().startswith("#4 "))
    lines.insert(first_frame_4 + 1, "    ...")
    lines.insert(first_frame_4 + 2, lines[first_frame_4].replace("#4 ", "#3 "))
    (evidence,) = _run(make_ctx, [_pasted_claim("\n".join(lines))])
    assert "frame_indices" in _violated(evidence)


def test_an_empty_allocation_stack_is_not_a_missing_one(make_ctx: MakeContext) -> None:
    """With ``malloc_context_size=0`` ASan prints ``<empty stack>`` under the label."""
    text = _fixture_text()
    head, _, rest = text.partition("allocated by thread T0 here:\n")
    _, _, tail = rest.partition("\n\n")
    trace = _pasted_claim(f"{head}allocated by thread T0 here:\n    <empty stack>\n\n{tail}")
    assert trace.alloc_frames == ()
    (evidence,) = _run(make_ctx, [trace])
    assert evidence.outcome == "SUPPORTS"
    assert "stacks_present" not in evidence.details["rules_checked"]
