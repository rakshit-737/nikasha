# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""C16 VERSION_RANGE_CONSISTENCY, against the real vulnlab history (SPEC §12).

The vulnlab releases give every case a real shape: ``util_copy_value`` arrives in v1.1.0,
``hdr_get`` disappears in v1.3.0, ``src/hdr.c`` is byte-identical at v1.1.0 and v1.2.0, and
v1.2.1 only adds comments, so functions there keep their exact text while the file changes.
"""

from __future__ import annotations

from typing import Any

from check_helpers import MakeContext, claim

from nikasha.checks.base import CheckContext, run_checks
from nikasha.checks.c16_version_range_consistency import VersionRangeConsistency
from nikasha.code.timeline import ReleasePresence
from nikasha.model.claims import Claim, SymbolClaim, VersionClaim, VersionSpec
from nikasha.model.evidence import Evidence


def spec(raw: str) -> VersionSpec:
    return VersionSpec(numbers=tuple(int(p) for p in raw.split(".")), raw=raw)


def core(name: str = "util_copy_value", **fields: Any) -> SymbolClaim:
    return claim(SymbolClaim, name=name, role="core", **fields)


def affected(raw: str, **fields: Any) -> VersionClaim:
    return claim(VersionClaim, raw=raw, relation="affected_range", **fields)


def fixed_in(raw: str, **fields: Any) -> VersionClaim:
    return claim(VersionClaim, raw=raw, relation="fixed_in", parsed=spec(raw), **fields)


def _run(
    make_ctx: MakeContext, claims: list[Claim], tag: str = "v1.2.0"
) -> tuple[CheckContext, list[Evidence]]:
    ctx = make_ctx(claims=claims, tag=tag)
    return ctx, VersionRangeConsistency().run(ctx, claims)


def _only(make_ctx: MakeContext, claims: list[Claim], tag: str = "v1.2.0") -> Evidence:
    _ctx, evidence = _run(make_ctx, claims, tag)
    assert len(evidence) == 1, evidence
    return evidence[0]


class TestAffectedRange:
    def test_range_starting_before_the_symbol_existed_refutes(self, make_ctx: MakeContext) -> None:
        version = affected("1.0.0", lower=spec("1.0.0"))
        symbol = core("util_copy_value")
        evidence = _only(make_ctx, [version, symbol])
        assert evidence.outcome == "REFUTES"
        assert evidence.strength == -1.0
        assert evidence.check_id == "C16"
        assert evidence.group == "version"
        assert evidence.claim_ids == tuple(sorted({version.id, symbol.id}))
        assert evidence.details["first_affected_release"] == "v1.0.0"
        assert evidence.details["introduced_in"] == "v1.1.0"
        assert "v1.1.0" in evidence.summary

    def test_an_open_lower_bound_is_measured_from_the_earliest_release(
        self, make_ctx: MakeContext
    ) -> None:
        version = affected("1.2.0 and earlier", upper=spec("1.2.0"), upper_inclusive=True)
        evidence = _only(make_ctx, [version, core("util_copy_value")])
        assert evidence.outcome == "REFUTES"
        assert evidence.details["first_affected_release"] == "v1.0.0"

    def test_range_starting_at_the_introduction_is_consistent(self, make_ctx: MakeContext) -> None:
        evidence = _only(make_ctx, [affected("1.1.0", lower=spec("1.1.0")), core()])
        assert evidence.outcome == "SUPPORTS"
        assert evidence.strength == 0.3
        assert evidence.details["introduced_in"] == "v1.1.0"

    def test_range_starting_after_the_introduction_is_consistent(
        self, make_ctx: MakeContext
    ) -> None:
        evidence = _only(make_ctx, [affected("1.2.0", lower=spec("1.2.0")), core()])
        assert evidence.outcome == "SUPPORTS"

    def test_an_exclusive_lower_bound_moves_to_the_next_release(
        self, make_ctx: MakeContext
    ) -> None:
        version = affected("> 1.0.0", lower=spec("1.0.0"), lower_inclusive=False)
        evidence = _only(make_ctx, [version, core()])
        assert evidence.outcome == "SUPPORTS"
        assert evidence.details["first_affected_release"] == "v1.1.0"

    def test_a_version_between_releases_starts_at_the_next_one(self, make_ctx: MakeContext) -> None:
        evidence = _only(make_ctx, [affected("1.0.5", lower=spec("1.0.5")), core()])
        assert evidence.outcome == "SUPPORTS"
        assert evidence.details["first_affected_release"] == "v1.1.0"

    def test_a_version_beyond_every_release_is_left_to_c01(self, make_ctx: MakeContext) -> None:
        _ctx, evidence = _run(make_ctx, [affected("9.9.9", lower=spec("9.9.9")), core()])
        assert evidence == []

    def test_a_range_ending_below_every_release_covers_nothing_here(
        self, make_ctx: MakeContext
    ) -> None:
        # "before 0.9" names no release of this repository, so it is not read as "v1.0.0".
        version = affected("before 0.9", upper=spec("0.9"))
        _ctx, evidence = _run(make_ctx, [version, core()])
        assert evidence == []

    def test_evidence_points_at_the_definition_at_the_resolved_commit(
        self, make_ctx: MakeContext
    ) -> None:
        ctx, evidence = _run(make_ctx, [affected("1.0.0", lower=spec("1.0.0")), core()])
        (location,) = evidence[0].locations
        assert location.commit == ctx.commit
        assert location.path == "src/util.c"
        assert location.permalink is not None
        assert location.permalink.startswith(f"{ctx.repo_url}/blob/{ctx.commit}/src/util.c#L")


class TestFixedIn:
    def test_a_fix_release_that_left_the_file_untouched_refutes(
        self, make_ctx: MakeContext
    ) -> None:
        # src/hdr.c is the same blob at v1.1.0 and v1.2.0.
        evidence = _only(make_ctx, [fixed_in("1.2.0"), core("hdr_parse_block")])
        assert evidence.outcome == "REFUTES"
        assert evidence.strength == -0.6
        assert evidence.details["locus"] == "file_unchanged"
        assert evidence.details["previous_release"] == "v1.1.0"

    def test_a_fix_release_that_only_added_comments_refutes(self, make_ctx: MakeContext) -> None:
        # v1.2.1 rewrites hdr.c's comments; hdr_parse_block's own lines do not change.
        evidence = _only(make_ctx, [fixed_in("1.2.1"), core("hdr_parse_block")], tag="v1.2.1")
        assert evidence.outcome == "REFUTES"
        assert evidence.details["locus"] == "definition_unchanged"

    def test_a_fix_release_that_changed_the_locus_is_consistent(
        self, make_ctx: MakeContext
    ) -> None:
        evidence = _only(make_ctx, [fixed_in("1.3.0"), core()], tag="v1.3.0")
        assert evidence.outcome == "SUPPORTS"
        assert evidence.strength == 0.3
        assert evidence.details["locus"] == "edited"

    def test_a_fix_release_that_removed_the_symbol_is_consistent(
        self, make_ctx: MakeContext
    ) -> None:
        evidence = _only(make_ctx, [fixed_in("1.3.0"), core("hdr_get")], tag="v1.3.0")
        assert evidence.outcome == "SUPPORTS"
        assert evidence.details["locus"] == "removed"

    def test_the_earliest_release_has_nothing_to_compare_against(
        self, make_ctx: MakeContext
    ) -> None:
        evidence = _only(make_ctx, [fixed_in("1.0.0"), core("hdr_get")], tag="v1.0.0")
        assert evidence.outcome == "NEUTRAL"
        assert evidence.strength == 0.0
        assert "earliest release" in evidence.summary

    def test_a_symbol_absent_from_both_releases_is_not_judged(self, make_ctx: MakeContext) -> None:
        evidence = _only(make_ctx, [fixed_in("1.1.0"), core("hdr_find")])
        assert evidence.outcome == "NEUTRAL"
        assert "defined in neither" in evidence.summary

    def test_a_fix_release_that_is_no_release_here_is_left_to_c01(
        self, make_ctx: MakeContext
    ) -> None:
        _ctx, evidence = _run(make_ctx, [fixed_in("4.0.0"), core()])
        assert evidence == []

    def test_a_fix_without_a_version_produces_nothing(self, make_ctx: MakeContext) -> None:
        version = claim(VersionClaim, raw="master", relation="fixed_in", special_ref="master")
        _ctx, evidence = _run(make_ctx, [version, core()])
        assert evidence == []


class TestSelection:
    def test_without_a_core_symbol_nothing_is_produced(self, make_ctx: MakeContext) -> None:
        supporting = claim(SymbolClaim, name="util_copy_value")
        _ctx, evidence = _run(make_ctx, [affected("1.0.0", lower=spec("1.0.0")), supporting])
        assert evidence == []

    def test_an_external_symbol_is_not_a_core_symbol(self, make_ctx: MakeContext) -> None:
        external = core("util_copy_value", external=True)
        _ctx, evidence = _run(make_ctx, [affected("1.0.0", lower=spec("1.0.0")), external])
        assert evidence == []

    def test_without_a_range_claim_nothing_is_produced(self, make_ctx: MakeContext) -> None:
        tested = claim(VersionClaim, raw="1.0.0", relation="tested_on", parsed=spec("1.0.0"))
        _ctx, evidence = _run(make_ctx, [tested, core()])
        assert evidence == []

    def test_a_range_about_another_product_is_ignored(self, make_ctx: MakeContext) -> None:
        other = affected("1.0.0", lower=spec("1.0.0"), product="curl")
        _ctx, evidence = _run(make_ctx, [other, core()])
        assert evidence == []

    def test_the_earliest_introduced_core_symbol_is_the_yardstick(
        self, make_ctx: MakeContext
    ) -> None:
        # hdr_get exists from v1.0.0, so a range starting there predates nothing.
        claims: list[Claim] = [
            affected("1.0.0", lower=spec("1.0.0")),
            core("util_copy_value"),
            core("hdr_get"),
        ]
        evidence = _only(make_ctx, claims)
        assert evidence.outcome == "SUPPORTS"
        assert evidence.details["symbol"] == "hdr_get"

    def test_a_fix_in_any_core_symbol_is_not_refuted_by_another(
        self, make_ctx: MakeContext
    ) -> None:
        # hdr_parse_block is untouched in v1.3.0 but util_copy_value changed there: the fix
        # may be in either, so the earlier-introduced one must not refute the release (P4).
        claims: list[Claim] = [fixed_in("1.3.0"), core("hdr_parse_block"), core()]
        evidence = _only(make_ctx, claims, tag="v1.3.0")
        assert evidence.outcome == "SUPPORTS"
        assert evidence.details["symbol"] == "util_copy_value"
        assert evidence.details["locus"] == "edited"

    def test_every_core_symbol_untouched_still_refutes(self, make_ctx: MakeContext) -> None:
        claims: list[Claim] = [fixed_in("1.2.0"), core("hdr_parse_block"), core("hdr_get")]
        evidence = _only(make_ctx, claims)
        assert evidence.outcome == "REFUTES"


class TestP4Safeguards:
    """Absence is never proof: an incomplete or uncertain history refutes nothing."""

    def test_an_incomplete_history_is_not_a_refutation(self, make_ctx: MakeContext) -> None:
        claims: list[Claim] = [affected("1.0.0", lower=spec("1.0.0")), core()]
        ctx = make_ctx(claims=claims)
        # The real timeline, with the flag a timed-out or shallow history would leave.
        timeline = ctx.timeline("util_copy_value")
        timeline.history_complete = False
        timeline.notes.append("history search timed out after 20s")
        (evidence,) = VersionRangeConsistency().run(ctx, claims)
        assert evidence.outcome == "NEUTRAL"
        assert evidence.strength == 0.0
        assert "incomplete" in evidence.summary
        assert "timed out" in evidence.summary

    def test_an_uncertain_introduction_is_not_a_refutation(self, make_ctx: MakeContext) -> None:
        claims: list[Claim] = [affected("1.0.0", lower=spec("1.0.0")), core()]
        ctx = make_ctx(claims=claims)
        timeline = ctx.timeline("util_copy_value")
        # v1.0.0 mentions the name in a file that did not parse cleanly: absence is unproven.
        timeline.presence[0] = ReleasePresence(
            "v1.0.0", defined=False, referenced=True, partial=("src/util.c",)
        )
        (evidence,) = VersionRangeConsistency().run(ctx, claims)
        assert evidence.outcome == "NEUTRAL"
        assert evidence.details["uncertain_releases"] == ["v1.0.0"]
        assert "did not parse cleanly" in evidence.summary

    def test_an_uncertain_fix_release_is_not_a_refutation(self, make_ctx: MakeContext) -> None:
        claims: list[Claim] = [fixed_in("1.2.0"), core("hdr_parse_block")]
        ctx = make_ctx(claims=claims)
        timeline = ctx.timeline("hdr_parse_block")
        timeline.presence[2] = ReleasePresence(
            "v1.2.0", defined=False, referenced=True, partial=("src/hdr.c",)
        )
        (evidence,) = VersionRangeConsistency().run(ctx, claims)
        assert evidence.outcome == "NEUTRAL"
        assert evidence.details["uncertain_releases"] == ["v1.2.0"]

    def test_a_symbol_never_located_is_not_a_refutation(self, make_ctx: MakeContext) -> None:
        evidence = _only(make_ctx, [affected("1.0.0", lower=spec("1.0.0")), core("hdr_nope")])
        assert evidence.outcome == "NEUTRAL"
        assert evidence.strength == 0.0
        assert "not located in any release" in evidence.summary


class TestRefutationGate:
    """ADR 0003: only project-attributed, non-negated claims may be refuted."""

    def test_a_reporter_artifact_version_is_not_refuted(self, make_ctx: MakeContext) -> None:
        version = affected("1.0.0", lower=spec("1.0.0"), provenance="reporter_artifact")
        evidence = _only(make_ctx, [version, core()])
        assert evidence.outcome == "NEUTRAL"
        assert evidence.strength == 0.0
        assert evidence.details["gated"] == ["reporter_artifact"]
        assert evidence.details["withheld_strength"] == -1.0

    def test_a_negated_version_is_not_refuted(self, make_ctx: MakeContext) -> None:
        version = affected("1.0.0", lower=spec("1.0.0"), negated=True)
        evidence = _only(make_ctx, [version, core()])
        assert evidence.outcome == "NEUTRAL"
        assert evidence.details["gated"] == ["negated"]

    def test_a_third_party_core_symbol_gates_the_refutation_too(
        self, make_ctx: MakeContext
    ) -> None:
        symbol = core("hdr_parse_block", provenance="third_party")
        evidence = _only(make_ctx, [fixed_in("1.2.0"), symbol])
        assert evidence.outcome == "NEUTRAL"
        assert evidence.details["gated"] == ["third_party"]
        assert evidence.details["withheld_strength"] == -0.6

    def test_support_is_not_gated(self, make_ctx: MakeContext) -> None:
        version = affected("1.1.0", lower=spec("1.1.0"), provenance="third_party")
        evidence = _only(make_ctx, [version, core()])
        assert evidence.outcome == "SUPPORTS"


def test_identical_input_gives_identical_evidence(make_ctx: MakeContext) -> None:
    claims: list[Claim] = [affected("1.0.0", lower=spec("1.0.0")), fixed_in("1.2.1"), core()]
    _first_ctx, first = _run(make_ctx, claims)
    _second_ctx, second = _run(make_ctx, claims)
    assert [e.id for e in first] == [e.id for e in second]
    assert [e.model_dump() for e in first] == [e.model_dump() for e in second]


def test_registered_and_runnable_through_the_runner(make_ctx: MakeContext) -> None:
    claims: list[Claim] = [affected("1.0.0", lower=spec("1.0.0")), core()]
    ctx = make_ctx(claims=claims)
    (run,) = run_checks(ctx, checks=[VersionRangeConsistency()])
    assert run.check_id == "C16"
    assert run.error is None
    assert [e.outcome for e in run.evidence] == ["REFUTES"]
