# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""C10 TRACE_VERSION_FIT, against the real vulnlab history (SPEC §12).

vulnlab is built for exactly this check: v1.2.1 changes nothing but comments and blank lines,
which moves every function in ``hdr.c`` and ``util.c`` without changing what they do, and v1.3.0
puts ``hdr_find`` where ``hdr_get`` used to sit. A trace captured on v1.2.1 therefore fits v1.2.1
and nothing else, and a report naming v1.2.0 for it is the "genuine report, wrong version" case
C10 exists to recognise.
"""

from __future__ import annotations

import json
import time

from check_helpers import MakeContext, claim

from nikasha.checks.base import run_checks
from nikasha.checks.c10_trace_version_fit import TraceVersionFit
from nikasha.model.claims import Frame, TraceClaim
from nikasha.model.evidence import Evidence

#: Frame lines as they are at v1.2.0: the memcpy, the call to it, the block loop and main.
FITS_V120 = (
    ("util_copy_value", "src/util.c", 15),
    ("hdr_parse_line", "src/hdr.c", 104),
    ("hdr_parse_block", "src/hdr.c", 134),
    ("main", "tools/hdrcat.c", 122),
)
#: A lookup-path trace as v1.2.1 numbers it. Only v1.2.1 fits it: the comment-only release
#: moved every function in hdr.c, and v1.3.0 replaced hdr_get with hdr_find at the same lines.
FITS_V121 = (
    ("hdr_casecmp", "src/hdr.c", 42),
    ("hdr_find_line", "src/hdr.c", 52),
    ("hdr_get", "src/hdr.c", 160),
    ("main", "tools/hdrcat.c", 125),
)
#: Real function names in real files, but never in the same place in any release.
FITS_NOWHERE = (
    ("hdr_parse_line", "src/util.c", 15),
    ("util_strip", "tools/hdrcat.c", 20),
    ("main", "src/hdr.c", 50),
    ("hdr_list_grow", "include/hdr.h", 5),
)
#: v1.2.0 frames with one frame pointing into cap_lines instead of main.
FITS_PARTLY = (*FITS_V120[:3], ("main", "tools/hdrcat.c", 60))


def trace(frames: tuple[tuple[str, str, int | None], ...], **fields: object) -> TraceClaim:
    """An ASan-shaped trace claim over ``(function, path, line)`` frames."""
    return claim(
        TraceClaim,
        text="heap-buffer-overflow",
        format="asan",
        bug_type="heap-buffer-overflow",
        frames=tuple(
            Frame(
                index=i,
                function=function,
                path=path,
                line=line,
                raw=f"    #{i} 0x0 in {function} {path}:{line}",
            )
            for i, (function, path, line) in enumerate(frames)
        ),
        **fields,
    )


def _run(make_ctx: MakeContext, claims: list[TraceClaim], tag: str = "v1.2.0") -> list[Evidence]:
    ctx = make_ctx(claims=claims, tag=tag)
    return TraceVersionFit().run(ctx, claims)


def test_a_trace_that_fits_the_claimed_release_supports(make_ctx: MakeContext) -> None:
    c = trace(FITS_V120)
    (evidence,) = _run(make_ctx, [c])
    assert evidence.outcome == "SUPPORTS"
    assert evidence.strength == 1.0
    assert evidence.check_id == "C10"
    assert evidence.group == "trace"
    assert evidence.claim_ids == (c.id,)
    assert evidence.details["best_release"] == "v1.2.0"
    assert evidence.details["best_ratio"] == 1.0
    assert evidence.details["claimed_ratio"] == 1.0
    assert evidence.details["scan_complete"] is True
    assert evidence.details["releases_scored"] == 5


def test_a_perfect_fit_on_another_release_is_reported_mildly(make_ctx: MakeContext) -> None:
    (evidence,) = _run(make_ctx, [trace(FITS_V121)])
    assert evidence.outcome == "REFUTES"
    assert evidence.strength == -0.3
    assert evidence.details["best_release"] == "v1.2.1"
    assert evidence.details["best_ratio"] == 1.0
    assert evidence.details["claimed_release"] == "v1.2.0"
    assert evidence.details["claimed_ratio"] < 1.0
    assert "v1.2.1" in evidence.details["perfect_releases"]
    assert "v1.2.0" not in evidence.details["perfect_releases"]


def test_the_other_release_finding_names_the_release_and_stays_neutral(
    make_ctx: MakeContext,
) -> None:
    (evidence,) = _run(make_ctx, [trace(FITS_V121)])
    assert "this trace matches v1.2.1 exactly" in evidence.summary
    assert "names a different version" in evidence.summary
    # P1: the wording is about the report's version, never about the reporter.
    for word in ("fabricat", "fake", "false", "invent", "AI"):
        assert word not in evidence.summary


def test_a_trace_no_release_fits_refutes(make_ctx: MakeContext) -> None:
    (evidence,) = _run(make_ctx, [trace(FITS_NOWHERE)])
    assert evidence.outcome == "REFUTES"
    assert evidence.strength == -1.5
    assert evidence.details["best_ratio"] < 0.5
    assert evidence.details["scan_complete"] is True
    assert evidence.details["releases_scored"] == 5


def test_a_partial_fit_is_reported_without_strength(make_ctx: MakeContext) -> None:
    (evidence,) = _run(make_ctx, [trace(FITS_PARTLY)])
    assert evidence.outcome == "NEUTRAL"
    assert evidence.strength == 0.0
    assert 0.5 <= evidence.details["best_ratio"] < 1.0
    assert evidence.details["perfect_releases"] == []


def test_fewer_than_three_frames_with_lines_produces_nothing(make_ctx: MakeContext) -> None:
    assert _run(make_ctx, [trace(FITS_V120[:2])]) == []


def test_frames_without_line_numbers_do_not_reach_the_minimum(make_ctx: MakeContext) -> None:
    frames = (*FITS_V120[:2], ("main", "tools/hdrcat.c", None))
    assert _run(make_ctx, [trace(frames)]) == []


def test_the_best_fitting_releases_commit_is_what_the_locations_pin(
    make_ctx: MakeContext, commits: dict[str, str]
) -> None:
    (evidence,) = _run(make_ctx, [trace(FITS_V121)])
    assert evidence.locations
    for location in evidence.locations:
        assert location.commit == commits["v1.2.1"]
        assert location.ref == "v1.2.1"
        assert location.permalink is not None
        assert commits["v1.2.1"] in location.permalink


def test_every_release_scanned_is_in_the_details_in_release_order(make_ctx: MakeContext) -> None:
    (evidence,) = _run(make_ctx, [trace(FITS_V120)])
    ratios = evidence.details["ratios"]
    assert list(ratios) == ["v1.0.0", "v1.1.0", "v1.2.0", "v1.2.1", "v1.3.0"]
    assert ratios["v1.2.0"] == 1.0


def test_release_order_survives_a_sorted_key_json_round_trip(make_ctx: MakeContext) -> None:
    """``Result.to_json`` sorts keys; the ordered list keeps the release order regardless."""
    (evidence,) = _run(make_ctx, [trace(FITS_V120)])
    ordered = evidence.details["ratios_in_release_order"]
    assert [name for name, _ in ordered] == list(evidence.details["ratios"])
    assert dict(ordered) == evidence.details["ratios"]
    loaded = json.loads(json.dumps(evidence.details, sort_keys=True))
    assert loaded["ratios_in_release_order"] == [list(pair) for pair in ordered]


class TestP4Safeguards:
    """Absence of a fit is only a finding when the search was complete."""

    def test_a_truncated_scan_never_says_no_release_fits(self, make_ctx: MakeContext) -> None:
        c = trace(FITS_NOWHERE)
        ctx = make_ctx(claims=[c])
        ctx.deadline = time.monotonic() - 1.0  # the budget is already spent
        (evidence,) = TraceVersionFit().run(ctx, [c])
        assert evidence.outcome == "NEUTRAL"
        assert evidence.strength == 0.0
        assert evidence.details["scan_complete"] is False
        assert evidence.details["releases_scored"] == 1
        assert "time budget" in evidence.details["uncertain"][0]
        assert "incomplete" in evidence.summary

    def test_a_truncated_scan_still_scores_the_claimed_release_first(
        self, make_ctx: MakeContext
    ) -> None:
        c = trace(FITS_V120)
        ctx = make_ctx(claims=[c])
        ctx.deadline = time.monotonic() - 1.0
        (evidence,) = TraceVersionFit().run(ctx, [c])
        assert list(evidence.details["ratios"]) == ["v1.2.0"]
        assert evidence.details["claimed_ratio"] == 1.0
        assert "the scan stopped after 1 release" in evidence.summary


class TestRefutationGate:
    """ADR 0003: only project-attributed, non-negated claims may be refuted."""

    def test_reporter_artifact_is_not_refuted(self, make_ctx: MakeContext) -> None:
        c = trace(FITS_NOWHERE, provenance="reporter_artifact")
        (evidence,) = _run(make_ctx, [c])
        assert evidence.outcome == "NEUTRAL"
        assert evidence.strength == 0.0
        assert evidence.details["gated"] == ["reporter_artifact"]
        assert evidence.details["withheld_strength"] == -1.5

    def test_a_negated_claim_is_not_refuted(self, make_ctx: MakeContext) -> None:
        c = trace(FITS_V121, negated=True)
        (evidence,) = _run(make_ctx, [c])
        assert evidence.outcome == "NEUTRAL"
        assert evidence.details["gated"] == ["negated"]
        assert evidence.details["withheld_strength"] == -0.3

    def test_support_is_not_gated(self, make_ctx: MakeContext) -> None:
        c = trace(FITS_V120, provenance="third_party")
        (evidence,) = _run(make_ctx, [c])
        assert evidence.outcome == "SUPPORTS"
        assert evidence.strength == 1.0


def test_identical_input_gives_identical_evidence(make_ctx: MakeContext) -> None:
    c = trace(FITS_V121)
    first = _run(make_ctx, [c])
    second = _run(make_ctx, [c])
    assert [e.id for e in first] == [e.id for e in second]
    assert first[0].model_dump() == second[0].model_dump()


def test_registered_and_runnable_through_the_runner(make_ctx: MakeContext) -> None:
    ctx = make_ctx(claims=[trace(FITS_V121)])
    (run,) = run_checks(ctx, checks=[TraceVersionFit()])
    assert run.check_id == "C10"
    assert run.error is None
    assert [e.outcome for e in run.evidence] == ["REFUTES"]
