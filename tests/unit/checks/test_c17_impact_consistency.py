# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""C17 IMPACT_CONSISTENCY (SPEC §12).

The arithmetic is checked against base scores published by FIRST and NVD, not against this
implementation's own output: a self-consistent CVSS calculator that gets the scope-changed
impact formula or the round-up wrong would pass every test that only compares it to itself.
"""

from __future__ import annotations

import math
from pathlib import Path

import pytest
from check_helpers import MakeContext, claim

from nikasha.checks.base import run_checks
from nikasha.checks.c17_impact_consistency import (
    ImpactConsistency,
    base_score,
    echo,
    modifying_metrics,
    parse_vector,
    roundup,
    severity_band,
)
from nikasha.extract.pipeline import extract_claims
from nikasha.ingest import load_report
from nikasha.model.claims import ImpactClaim
from nikasha.model.evidence import Evidence

REPORTS = Path(__file__).resolve().parents[3] / "examples" / "reports"

#: The vector of the genuine fixture report, which states 5.5 (Medium) next to it.
GENUINE = "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
#: The vector of the fabricated fixture, printed next to "9.8 (Critical)" (SPEC appendix B).
FABRICATED = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"


def _run(make_ctx: MakeContext, claims: list[ImpactClaim]) -> list[Evidence]:
    ctx = make_ctx(claims=claims)
    return ImpactConsistency().run(ctx, claims)


def _score(vector: str) -> float:
    metrics, reason = parse_vector(vector)
    assert metrics is not None, reason
    return base_score(metrics)


# --- the CVSS v3.x base score ------------------------------------------------------------

#: (vector, published base score). Every score here is one FIRST or NVD publishes for that
#: exact vector, so the table fails if the formula drifts.
PUBLISHED = [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),  # unauthenticated RCE
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),  # CVE-2014-0160 (Heartbleed)
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),  # CVE-2021-44228 (Log4Shell), S:C
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),  # reflected XSS, S:C
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9),  # S:C with PR:L, the changed weight
    ("CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L", 5.1),  # S:C, every metric off its default
    ("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),  # local privilege escalation (v3.0)
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H", 5.9),  # remote DoS behind a race
    ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0.0),  # no impact at all
    (GENUINE, 5.5),
    (FABRICATED, 7.5),
]


@pytest.mark.parametrize(("vector", "score"), PUBLISHED, ids=[v for v, _ in PUBLISHED])
def test_the_base_score_matches_the_published_one(vector: str, score: float) -> None:
    assert _score(vector) == score


def test_the_scope_changed_impact_formula_is_not_the_unchanged_one() -> None:
    """Same metrics but for Scope: 5.4 unchanged, 6.1 changed (the canonical XSS pair)."""
    assert _score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N") == 5.4
    assert _score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N") == 6.1


def test_privileges_required_is_weighted_by_scope() -> None:
    """PR:L is 0.62 when the scope is unchanged and 0.68 when it changed."""
    assert _score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H") == 8.8
    assert _score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H") == 9.9


def test_roundup_rounds_up_to_one_decimal() -> None:
    assert roundup(0.0) == 0.0
    assert roundup(4.0) == 4.0
    assert roundup(4.001) == 4.1
    assert roundup(9.999) == 10.0


def test_roundup_is_the_v31_integer_procedure_not_a_ceiling() -> None:
    """Appendix A exists because ``ceil(x * 10) / 10`` turns float noise into a tenth."""
    assert math.ceil(6.000000000000001 * 10) / 10 == 6.1
    assert roundup(6.000000000000001) == 6.0


@pytest.mark.parametrize(
    ("score", "band"),
    [
        (0.0, "None"),
        (0.1, "Low"),
        (3.9, "Low"),
        (4.0, "Medium"),
        (6.9, "Medium"),
        (7.0, "High"),
        (8.9, "High"),
        (9.0, "Critical"),
        (10.0, "Critical"),
    ],
)
def test_the_v3_severity_bands(score: float, band: str) -> None:
    assert severity_band(score, "3.1") == band


def test_v2_uses_its_own_band_table() -> None:
    """CVSS v2 has no Critical band: NVD calls everything from 7.0 up High."""
    assert severity_band(9.5, "2.0") == "High"
    assert severity_band(0.0, "2.0") == "Low"


def test_temporal_and_environmental_metrics_are_accepted_and_ignored() -> None:
    assert _score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C") == 9.8


@pytest.mark.parametrize(
    ("vector", "fragment"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N", "no S, C, I, A metric"),
        ("CVSS:3.1/AV:N/AC:Z/PR:N/UI:N/S:U/C:H/I:H/A:H", "AC:Z is not a CVSS v3 value"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:X/C:H/I:H/A:H", "S:X is not a Scope value"),
        ("CVSS:3.1/AV:N/AC:L/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", "the AC metric appears twice"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H!", "'A:H!' is not a metric"),
    ],
)
def test_a_malformed_vector_says_what_is_wrong_with_it(vector: str, fragment: str) -> None:
    metrics, reason = parse_vector(vector)
    assert metrics is None
    assert fragment in reason


# --- the check ----------------------------------------------------------------------------


def test_a_vector_that_matches_the_stated_score_is_a_neutral_note(make_ctx: MakeContext) -> None:
    c = claim(
        ImpactClaim,
        cvss_vector=GENUINE,
        cvss_version="3.1",
        cvss_score=5.5,
        severity_word="Medium",
    )
    (evidence,) = _run(make_ctx, [c])
    assert evidence.outcome == "NEUTRAL"
    assert evidence.strength == 0.0
    assert evidence.check_id == "C17"
    assert evidence.group == "meta"
    assert evidence.claim_ids == (c.id,)
    assert evidence.details["computed_score"] == 5.5
    assert evidence.details["band"] == "Medium"
    assert "5.5 (Medium)" in evidence.summary


def test_a_score_the_vector_does_not_support_is_refuted(make_ctx: MakeContext) -> None:
    c = claim(
        ImpactClaim,
        cvss_vector=FABRICATED,
        cvss_version="3.1",
        cvss_score=9.8,
        severity_word="Critical",
    )
    (evidence,) = _run(make_ctx, [c])
    assert evidence.outcome == "REFUTES"
    assert evidence.strength == -0.6
    assert evidence.details["finding"] == "score_mismatch"
    assert evidence.details["computed_score"] == 7.5
    assert evidence.details["claimed_score"] == 9.8
    assert evidence.details["computed_severity"] == "High"
    assert "7.5" in evidence.summary
    assert "9.8" in evidence.summary


def test_a_difference_of_exactly_one_tenth_is_not_a_mismatch(make_ctx: MakeContext) -> None:
    """SPEC §12 says "more than 0.1", and binary floats must not turn 0.1 into more."""
    c = claim(ImpactClaim, cvss_vector=FABRICATED, cvss_version="3.1", cvss_score=7.6)
    (evidence,) = _run(make_ctx, [c])
    assert evidence.outcome == "NEUTRAL"
    assert evidence.details["computed_score"] == 7.5


def test_a_difference_of_two_tenths_is_a_mismatch(make_ctx: MakeContext) -> None:
    c = claim(ImpactClaim, cvss_vector=FABRICATED, cvss_version="3.1", cvss_score=7.7)
    (evidence,) = _run(make_ctx, [c])
    assert evidence.outcome == "REFUTES"
    assert evidence.details["finding"] == "score_mismatch"


def test_an_unparseable_vector_is_refuted_weakly(make_ctx: MakeContext) -> None:
    c = claim(ImpactClaim, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N", cvss_version="3.1")
    (evidence,) = _run(make_ctx, [c])
    assert evidence.outcome == "REFUTES"
    assert evidence.strength == -0.3
    assert evidence.details["finding"] == "vector_unparseable"
    assert "does not parse" in evidence.summary
    assert "S, C, I, A" in evidence.details["reason"]


def test_a_severity_word_outside_the_band_is_refuted(make_ctx: MakeContext) -> None:
    c = claim(
        ImpactClaim,
        cvss_vector=GENUINE,
        cvss_version="3.1",
        cvss_score=5.5,
        severity_word="Critical",
    )
    (evidence,) = _run(make_ctx, [c])
    assert evidence.outcome == "REFUTES"
    assert evidence.strength == -0.3
    assert evidence.details["finding"] == "severity_mismatch"
    assert evidence.details["band"] == "Medium"
    assert "Critical" in evidence.summary


def test_moderate_is_accepted_for_the_medium_band(make_ctx: MakeContext) -> None:
    """GitHub and Red Hat print "Moderate"; that is not an inconsistency."""
    c = claim(ImpactClaim, cvss_score=5.5, severity_word="Moderate")
    (evidence,) = _run(make_ctx, [c])
    assert evidence.outcome == "NEUTRAL"


def test_a_severity_word_is_judged_against_the_score_the_report_itself_gives(
    make_ctx: MakeContext,
) -> None:
    low = claim(ImpactClaim, cvss_score=9.1, severity_word="Low")
    (evidence,) = _run(make_ctx, [low])
    assert evidence.outcome == "REFUTES"
    assert evidence.details["band"] == "Critical"

    right = claim(ImpactClaim, cvss_score=9.1, severity_word="Critical")
    (evidence,) = _run(make_ctx, [right])
    assert evidence.outcome == "NEUTRAL"
    assert "Critical band" in evidence.summary


def test_a_wrong_score_is_reported_once_not_twice(make_ctx: MakeContext) -> None:
    """The severity word follows the stated score, so a wrong score is one mistake."""
    c = claim(
        ImpactClaim,
        cvss_vector=FABRICATED,
        cvss_version="3.1",
        cvss_score=9.8,
        severity_word="Critical",
    )
    evidence = _run(make_ctx, [c])
    assert [e.details["finding"] for e in evidence] == ["score_mismatch"]


def test_a_claim_with_nothing_checkable_produces_no_evidence(make_ctx: MakeContext) -> None:
    assert _run(make_ctx, [claim(ImpactClaim, severity_word="High")]) == []
    assert _run(make_ctx, [claim(ImpactClaim, cvss_score=7.5)]) == []
    assert _run(make_ctx, [claim(ImpactClaim, cwe="CWE-122")]) == []


class TestVersionsWithoutAFormulaHere:
    """P4: not knowing how to score a vector says nothing about the report."""

    def test_a_v4_vector_is_neutral_not_unparseable(self, make_ctx: MakeContext) -> None:
        c = claim(
            ImpactClaim,
            cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            cvss_version="4.0",
            cvss_score=9.3,
            severity_word="Critical",
        )
        (evidence,) = _run(make_ctx, [c])
        assert evidence.outcome == "NEUTRAL"
        assert evidence.strength == 0.0
        assert "not scored" in evidence.summary
        assert "finding" not in evidence.details

    def test_a_malformed_v4_vector_is_still_neutral(self, make_ctx: MakeContext) -> None:
        c = claim(ImpactClaim, cvss_vector="CVSS:4.0/AV:N", cvss_version="4.0")
        (evidence,) = _run(make_ctx, [c])
        assert evidence.outcome == "NEUTRAL"

    def test_a_v2_vector_is_not_scored_and_keeps_the_v2_bands(self, make_ctx: MakeContext) -> None:
        c = claim(
            ImpactClaim,
            cvss_vector="AV:N/AC:L/Au:N/C:C/I:C/A:C",
            cvss_version="2.0",
            cvss_score=9.5,
            severity_word="High",  # v3 would call 9.5 Critical; v2 has no such band
        )
        (evidence,) = _run(make_ctx, [c])
        assert evidence.outcome == "NEUTRAL"
        assert evidence.details["band"] == "High"

    def test_a_vector_with_no_version_is_not_scored(self, make_ctx: MakeContext) -> None:
        c = claim(ImpactClaim, cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", cvss_score=9.8)
        (evidence,) = _run(make_ctx, [c])
        assert evidence.outcome == "NEUTRAL"
        assert "which CVSS version" in evidence.summary


class TestRefutationGate:
    """ADR 0003: only project-attributed, non-negated claims may be refuted."""

    def test_reporter_artifact_is_not_refuted(self, make_ctx: MakeContext) -> None:
        c = claim(
            ImpactClaim,
            cvss_vector=FABRICATED,
            cvss_version="3.1",
            cvss_score=9.8,
            provenance="reporter_artifact",
        )
        (evidence,) = _run(make_ctx, [c])
        assert evidence.outcome == "NEUTRAL"
        assert evidence.strength == 0.0
        assert evidence.details["gated"] == ["reporter_artifact"]
        assert evidence.details["withheld_strength"] == -0.6

    def test_negated_claim_is_not_refuted(self, make_ctx: MakeContext) -> None:
        c = claim(
            ImpactClaim, cvss_vector=GENUINE, cvss_version="3.1", cvss_score=5.5,
            severity_word="Critical", negated=True,
        )  # fmt: skip
        (evidence,) = _run(make_ctx, [c])
        assert evidence.outcome == "NEUTRAL"
        assert evidence.details["gated"] == ["negated"]
        assert evidence.details["withheld_strength"] == -0.3

    def test_a_note_on_a_third_party_claim_stays_a_note(self, make_ctx: MakeContext) -> None:
        c = claim(
            ImpactClaim,
            cvss_vector=GENUINE,
            cvss_version="3.1",
            cvss_score=5.5,
            provenance="third_party",
        )
        (evidence,) = _run(make_ctx, [c])
        assert evidence.outcome == "NEUTRAL"
        assert "gated" not in evidence.details


def test_reporter_text_in_a_summary_is_bounded(make_ctx: MakeContext) -> None:
    c = claim(
        ImpactClaim,
        cvss_vector="CVSS:3.1/" + "AV:N/" * 2000,
        cvss_version="3.1",
    )
    (evidence,) = _run(make_ctx, [c])
    assert evidence.outcome == "REFUTES"
    assert len(evidence.summary) < 200
    assert evidence.details["vector"].endswith("...")


# --- the fixture reports, end to end -------------------------------------------------------


def _impact_claims(name: str) -> list[ImpactClaim]:
    extraction = extract_claims(load_report(REPORTS / name))
    return [c for c in extraction.claims if isinstance(c, ImpactClaim)]


def test_the_fabricated_fixture_claims_98_for_a_vector_worth_75(make_ctx: MakeContext) -> None:
    """SPEC appendix B lists this mismatch as one of the fixture's deliberate defects."""
    claims = _impact_claims("fabricated_hdr_overflow.md")
    (evidence,) = _run(make_ctx, claims)
    assert evidence.outcome == "REFUTES"
    assert evidence.strength == -0.6
    assert (evidence.details["claimed_score"], evidence.details["computed_score"]) == (9.8, 7.5)


def test_the_genuine_fixture_is_arithmetically_consistent(make_ctx: MakeContext) -> None:
    claims = _impact_claims("genuine_hdr_overflow.md")
    (evidence,) = _run(make_ctx, claims)
    assert evidence.outcome == "NEUTRAL"
    assert evidence.details["computed_score"] == 5.5


def test_identical_input_gives_identical_evidence_ids(make_ctx: MakeContext) -> None:
    c = claim(ImpactClaim, cvss_vector=FABRICATED, cvss_version="3.1", cvss_score=9.8)
    first = _run(make_ctx, [c])
    second = _run(make_ctx, [c])
    assert [e.id for e in first] == [e.id for e in second]
    assert first[0].model_dump() == second[0].model_dump()


def test_registered_and_runnable_through_the_runner(make_ctx: MakeContext) -> None:
    c = claim(ImpactClaim, cvss_vector=FABRICATED, cvss_version="3.1", cvss_score=9.8)
    ctx = make_ctx(claims=[c])
    (run,) = run_checks(ctx, checks=[ImpactConsistency()])
    assert run.check_id == "C17"
    assert run.error is None
    assert run.seconds >= 0.0
    assert [e.outcome for e in run.evidence] == ["REFUTES"]


# --- review regressions -------------------------------------------------------------------


def test_a_trailing_slash_is_not_a_malformed_vector() -> None:
    metrics, reason = parse_vector(GENUINE + "/")
    assert metrics is not None, reason
    assert round(base_score(metrics), 1) == 5.5


def test_echo_drops_control_characters() -> None:
    flat = echo("Crit\x1b[31mical\x00" + chr(0x202E))
    assert "\x1b" not in flat
    assert "\x00" not in flat
    assert chr(0x202E) not in flat


@pytest.mark.parametrize("score", [math.nan, math.inf])
def test_a_non_finite_score_is_never_refuted(make_ctx: MakeContext, score: float) -> None:
    c = claim(ImpactClaim, cvss_score=score, severity_word="Low")
    assert all(e.outcome != "REFUTES" for e in _run(make_ctx, [c]))


def test_temporal_score_next_to_a_temporal_vector_is_not_refuted(make_ctx: MakeContext) -> None:
    # Base 9.8; with E:U/RL:O/RC:C the temporal score is lower, and a report may print it.
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C"
    c = claim(ImpactClaim, cvss_vector=vector, cvss_version="3.1", cvss_score=8.2)
    [ev] = _run(make_ctx, [c])
    assert ev.outcome == "NEUTRAL"
    assert ev.strength == 0.0
    assert ev.details["modifying_metrics"] == ["E", "RC", "RL"]


def test_not_defined_modifiers_still_leave_a_mismatch_refutable(make_ctx: MakeContext) -> None:
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:X/RL:X"
    c = claim(ImpactClaim, cvss_vector=vector, cvss_version="3.1", cvss_score=5.0)
    [ev] = _run(make_ctx, [c])
    assert ev.outcome == "REFUTES"
    assert ev.details["finding"] == "score_mismatch"


def test_an_unknown_metric_key_is_not_a_modifier() -> None:
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/ZZ:Q"
    assert modifying_metrics(vector, "3.1") == []
    assert modifying_metrics(vector + "/E:U/MAV:L", "3.1") == ["E", "MAV"]


def test_modifier_keys_follow_the_vector_version() -> None:
    assert modifying_metrics("AV:N/AC:L/Au:N/C:P/I:P/A:P/CDP:H/MAV:L", "2.0") == ["CDP"]
    assert modifying_metrics("CVSS:3.1/AV:N/CDP:H/MAV:L", "3.1") == ["MAV"]


def test_a_garbage_key_does_not_shield_a_score_mismatch(make_ctx: MakeContext) -> None:
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/ZZ:Q"
    c = claim(ImpactClaim, cvss_vector=vector, cvss_version="3.1", cvss_score=5.0)
    [ev] = _run(make_ctx, [c])
    assert ev.outcome == "REFUTES"
