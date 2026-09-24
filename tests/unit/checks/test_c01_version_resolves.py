# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""C01 VERSION_RESOLVES, against the real vulnlab release history (SPEC §12).

vulnlab's five tags carry fixed dates, which is what makes "future release" testable:
``v1.0.0`` 2026-01-06, ``v1.1.0`` 2026-02-10, ``v1.2.0`` 2026-03-15, ``v1.2.1`` 2026-03-20,
``v1.3.0`` 2026-04-25. A report dated 2026-03-18 therefore predates ``v1.2.1``.
"""

from __future__ import annotations

from datetime import date
from typing import Any

import pytest
from check_helpers import REPORTS, MakeContext, claim

from nikasha.checks.base import CheckContext, run_checks
from nikasha.checks.c01_version_resolves import VersionResolves
from nikasha.code.gitio import GitRepo, TagRef
from nikasha.extract.versions import parse_version
from nikasha.ingest import load_report
from nikasha.model.claims import VersionClaim
from nikasha.model.evidence import Evidence
from nikasha.model.report import Report
from nikasha.resolve.refs import ReleaseList

#: After v1.2.0 (2026-03-15) and before v1.2.1 (2026-03-20).
REPORT_DATE = date(2026, 3, 18)


def _version(raw: str, **fields: Any) -> VersionClaim:
    fields.setdefault("relation", "tested_on")
    fields.setdefault("parsed", parse_version(raw))
    return claim(VersionClaim, text=raw, raw=raw, **fields)


def _dated(day: date | None = REPORT_DATE) -> Report:
    """The demo report, with a reporting date the fixture file does not carry."""
    report = load_report(REPORTS / "genuine_hdr_overflow.md")
    return report.model_copy(update={"reported_at": day})


def _run(
    make_ctx: MakeContext,
    claims: list[VersionClaim],
    *,
    report: Report | None = None,
) -> list[Evidence]:
    ctx = make_ctx(claims=claims, report=report)
    return VersionResolves().run(ctx, claims)


def _one(make_ctx: MakeContext, c: VersionClaim, *, report: Report | None = None) -> Evidence:
    (evidence,) = _run(make_ctx, [c], report=report)
    return evidence


def test_a_released_version_resolves_to_its_tag(make_ctx: MakeContext) -> None:
    c = _version("1.2.0")
    evidence = _one(make_ctx, c)
    assert evidence.outcome == "SUPPORTS"
    assert evidence.strength == 0.2
    assert evidence.check_id == "C01"
    assert evidence.group == "version"
    assert evidence.claim_ids == (c.id,)
    assert evidence.details["tag"] == "v1.2.0"
    assert evidence.details["tagged_at"] == "2026-03-15"


def test_trailing_zeros_do_not_stop_a_version_resolving(make_ctx: MakeContext) -> None:
    assert _one(make_ctx, _version("1.2")).details["tag"] == "v1.2.0"


class TestFutureRelease:
    """A version that did not exist on the report date (SPEC §12: -1.5)."""

    def test_a_version_tagged_after_the_report_refutes(self, make_ctx: MakeContext) -> None:
        evidence = _one(make_ctx, _version("1.3.0"), report=_dated())
        assert evidence.outcome == "REFUTES"
        assert evidence.strength == -1.5
        assert evidence.details["latest_release_then"] == "v1.2.0"
        assert evidence.details["tag"] == "v1.3.0"
        assert evidence.details["tagged_at"] == "2026-04-25"
        assert "2026-04-25" in evidence.summary

    def test_the_comparison_is_against_the_report_date_not_the_clone(
        self, make_ctx: MakeContext
    ) -> None:
        """v1.2.1 is in the clone, so only the date can show it did not exist yet."""
        dated = _one(make_ctx, _version("1.2.1"), report=_dated())
        undated = _one(make_ctx, _version("1.2.1"))
        assert dated.outcome == "REFUTES"
        assert dated.details["latest_release_then"] == "v1.2.0"
        assert undated.outcome == "SUPPORTS"

    def test_a_version_with_no_tag_at_all_still_refutes(self, make_ctx: MakeContext) -> None:
        evidence = _one(make_ctx, _version("1.5.0"), report=_dated())
        assert evidence.outcome == "REFUTES"
        assert "tag" not in evidence.details

    def test_without_a_report_date_it_is_never_claimed(self, make_ctx: MakeContext) -> None:
        """P4: an undated report cannot establish what was released when."""
        evidence = _one(make_ctx, _version("9.9.9"), report=_dated(None))
        assert evidence.outcome == "NEUTRAL"
        assert evidence.strength == 0.0
        assert evidence.details["reported_at"] is None
        assert "no date" in evidence.summary

    def test_a_fix_release_may_not_have_been_cut_yet(self, make_ctx: MakeContext) -> None:
        c = _version("1.3.0", relation="fixed_in")
        evidence = _one(make_ctx, c, report=_dated())
        assert evidence.outcome == "NEUTRAL"
        assert evidence.details["latest_release_then"] == "v1.2.0"


class TestGapInReleases:
    """A version with real releases on both sides and none of its own (SPEC §12: -1.0)."""

    def test_a_version_between_two_releases_refutes(self, make_ctx: MakeContext) -> None:
        evidence = _one(make_ctx, _version("1.1.5"))
        assert evidence.outcome == "REFUTES"
        assert evidence.strength == -1.0
        assert evidence.details["below"] == "v1.1.0"
        assert evidence.details["above"] == "v1.2.0"

    def test_a_gap_is_still_a_gap_on_a_dated_report(self, make_ctx: MakeContext) -> None:
        evidence = _one(make_ctx, _version("1.1.5"), report=_dated())
        assert evidence.outcome == "REFUTES"
        assert evidence.strength == -1.0

    def test_a_missing_fix_release_inside_the_line_is_neutral(self, make_ctx: MakeContext) -> None:
        """P4: a fix version named in advance may ship under another number."""
        c = _version("1.1.5", relation="fixed_in")
        evidence = _one(make_ctx, c)
        assert evidence.outcome == "NEUTRAL"
        assert evidence.details["outcome"] == "fix_release_not_cut"

    def test_a_version_above_every_release_is_not_a_gap(self, make_ctx: MakeContext) -> None:
        evidence = _one(make_ctx, _version("9.9.9"))
        assert evidence.outcome == "NEUTRAL"
        assert evidence.details["above"] is None

    def test_a_version_below_every_release_is_not_a_gap(self, make_ctx: MakeContext) -> None:
        evidence = _one(make_ctx, _version("0.9.0"))
        assert evidence.outcome == "NEUTRAL"
        assert evidence.details["below"] is None

    def test_an_unpublished_pre_release_tag_is_uncertain(self, make_ctx: MakeContext) -> None:
        """P4: rc and snapshot tags are routinely built and never pushed."""
        evidence = _one(make_ctx, _version("1.1.5-rc1"))
        assert evidence.outcome == "NEUTRAL"
        assert "pre-release" in evidence.summary


class TestRangeBounds:
    """An exclusive bound names a boundary, not a release the report says shipped."""

    def test_an_inclusive_upper_bound_is_an_existence_claim(self, make_ctx: MakeContext) -> None:
        c = _version(
            "1.1.5",
            relation="affected_range",
            parsed=None,
            upper=parse_version("1.1.5"),
            upper_inclusive=True,
        )
        assert _one(make_ctx, c).outcome == "REFUTES"

    def test_an_exclusive_upper_bound_is_not(self, make_ctx: MakeContext) -> None:
        c = _version(
            "1.1.5",
            relation="affected_range",
            parsed=None,
            upper=parse_version("1.1.5"),
            upper_inclusive=False,
        )
        evidence = _one(make_ctx, c)
        assert evidence.outcome == "NEUTRAL"
        assert "boundary" in evidence.summary

    def test_all_versions_before_an_unreleased_major_is_not_a_future_release(
        self, make_ctx: MakeContext
    ) -> None:
        """ "affected: all versions before 2.0.0" says nothing about 2.0.0 existing."""
        c = _version(
            "2.0.0",
            relation="affected_range",
            parsed=None,
            upper=parse_version("2.0.0"),
            upper_inclusive=False,
        )
        assert _one(make_ctx, c, report=_dated()).outcome == "NEUTRAL"

    def test_a_lower_bound_is_checked_when_no_upper_bound_is_given(
        self, make_ctx: MakeContext
    ) -> None:
        c = _version(
            "1.1.0",
            relation="affected_range",
            parsed=None,
            lower=parse_version("1.1.0"),
        )
        evidence = _one(make_ctx, c)
        assert evidence.outcome == "SUPPORTS"
        assert evidence.details["tag"] == "v1.1.0"


class TestRefsAndCommits:
    """Branch refs and commits cannot "fail to resolve" into a refutation."""

    def test_a_branch_ref_resolves_to_its_tip(
        self, make_ctx: MakeContext, commits: dict[str, str]
    ) -> None:
        c = _version("the main branch", relation="latest", special_ref="main")
        evidence = _one(make_ctx, c)
        assert evidence.outcome == "SUPPORTS"
        assert evidence.details["commit"] == commits["v1.3.0"]

    def test_a_branch_the_clone_does_not_have_is_neutral(self, make_ctx: MakeContext) -> None:
        c = _version("master", relation="latest", special_ref="master")
        evidence = _one(make_ctx, c)
        assert evidence.outcome == "NEUTRAL"
        assert evidence.strength == 0.0

    def test_latest_resolves_to_the_newest_release(self, make_ctx: MakeContext) -> None:
        c = _version("the latest release", relation="latest", special_ref="latest")
        assert _one(make_ctx, c).details["tag"] == "v1.3.0"

    def test_latest_is_read_as_of_the_report_date(self, make_ctx: MakeContext) -> None:
        c = _version("the latest release", relation="latest", special_ref="latest")
        assert _one(make_ctx, c, report=_dated()).details["tag"] == "v1.2.0"

    def test_a_claimed_commit_that_exists_supports(
        self, make_ctx: MakeContext, commits: dict[str, str]
    ) -> None:
        c = _version(commits["v1.2.0"], commit=commits["v1.2.0"])
        evidence = _one(make_ctx, c)
        assert evidence.outcome == "SUPPORTS"
        assert evidence.strength == 0.2
        assert evidence.details["commit"] == commits["v1.2.0"]

    def test_a_commit_the_clone_lacks_is_left_to_c15(self, make_ctx: MakeContext) -> None:
        c = _version("0" * 40, commit="0" * 40)
        evidence = _one(make_ctx, c)
        assert evidence.outcome == "NEUTRAL"
        assert evidence.strength == 0.0

    def test_a_claim_with_nothing_to_resolve_is_skipped(self, make_ctx: MakeContext) -> None:
        assert _run(make_ctx, [_version("some version", parsed=None, relation="unspecified")]) == []


def test_a_repository_with_no_tags_is_neutral(make_ctx: MakeContext) -> None:
    ctx = make_ctx(claims=[_version("1.1.5")])
    ctx.resolution.releases = ReleaseList.from_tags([])
    (evidence,) = VersionResolves().run(ctx, list(ctx.claims))
    assert evidence.outcome == "NEUTRAL"
    assert evidence.strength == 0.0
    assert "no release tags" in evidence.summary


def _variant_line(ctx: CheckContext) -> None:
    """Rewrite the release list so the main line is ``libhdr-*`` with one FIPS variant.

    ``main_line_families()`` keeps ``libhdr-fips`` off the main line, so its versions must
    still resolve through ``match()`` and must never be read as holes in ``libhdr``'s line.
    """
    tags = [
        TagRef(f"libhdr-{r.name.removeprefix('v').replace('.', '_')}", r.commit, r.epoch)
        for r in ctx.resolution.releases.releases
    ]
    base = ctx.resolution.releases.releases[1]
    tags.append(TagRef("libhdr-fips-1_1_5", base.commit, base.epoch))
    ctx.resolution.releases = ReleaseList.from_tags(tags)


def test_a_variant_line_version_resolves_instead_of_looking_like_a_gap(
    make_ctx: MakeContext,
) -> None:
    ctx = make_ctx(claims=[_version("1.1.5")])
    _variant_line(ctx)
    assert ctx.resolution.releases.main_families == frozenset({"libhdr"})
    (evidence,) = VersionResolves().run(ctx, list(ctx.claims))
    assert evidence.outcome == "SUPPORTS"
    assert evidence.details["tag"] == "libhdr-fips-1_1_5"


def test_a_gap_on_the_main_line_still_refutes_with_a_variant_line_present(
    make_ctx: MakeContext,
) -> None:
    ctx = make_ctx(claims=[_version("1.1.6")])
    _variant_line(ctx)
    (evidence,) = VersionResolves().run(ctx, list(ctx.claims))
    assert evidence.outcome == "REFUTES"
    assert evidence.details["below"] == "libhdr-1_1_0"
    assert evidence.details["above"] == "libhdr-1_2_0"


class TestRefutationGate:
    """ADR 0003: only project-attributed, non-negated claims may be refuted."""

    def test_reporter_artifact_is_not_refuted(self, make_ctx: MakeContext) -> None:
        c = _version("1.3.0", provenance="reporter_artifact")
        evidence = _one(make_ctx, c, report=_dated())
        assert evidence.outcome == "NEUTRAL"
        assert evidence.strength == 0.0
        assert evidence.details["gated"] == ["reporter_artifact"]
        assert evidence.details["withheld_strength"] == -1.5

    def test_negated_claim_is_not_refuted(self, make_ctx: MakeContext) -> None:
        c = _version("1.1.5", negated=True)
        evidence = _one(make_ctx, c)
        assert evidence.outcome == "NEUTRAL"
        assert evidence.details["gated"] == ["negated"]
        assert evidence.details["withheld_strength"] == -1.0

    def test_support_is_not_gated(self, make_ctx: MakeContext) -> None:
        c = _version("1.2.0", provenance="third_party")
        assert _one(make_ctx, c).outcome == "SUPPORTS"


def test_identical_input_gives_identical_evidence_ids(make_ctx: MakeContext) -> None:
    c = _version("1.1.5")
    first = _run(make_ctx, [c], report=_dated())
    second = _run(make_ctx, [c], report=_dated())
    assert [e.id for e in first] == [e.id for e in second]
    assert first[0].model_dump() == second[0].model_dump()


def test_registered_and_runnable_through_the_runner(make_ctx: MakeContext) -> None:
    ctx = make_ctx(claims=[_version("1.1.5"), _version("1.2.0")], report=_dated())
    (run,) = run_checks(ctx, checks=[VersionResolves()])
    assert run.check_id == "C01"
    assert run.error is None
    assert run.seconds >= 0.0
    assert sorted(e.outcome for e in run.evidence) == ["REFUTES", "SUPPORTS"]


def _retag(ctx: CheckContext, extra: list[TagRef], *, drop: str = "", epoch_of: Any = None) -> None:
    rel = ctx.resolution.releases
    tags = [
        TagRef(r.name, r.commit, epoch_of(r) if epoch_of else r.epoch)
        for r in rel.releases
        if r.name != drop
    ]
    ctx.resolution.releases = ReleaseList.from_tags([*tags, *extra])


class TestReviewFindings:
    """Regressions for false refutations and determinism found in review (P4, P2, P7)."""

    def test_a_next_release_candidate_is_not_a_future_release(self, make_ctx: MakeContext) -> None:
        evidence = _one(make_ctx, _version("1.3.0-rc1"), report=_dated())
        assert evidence.outcome == "NEUTRAL"

    def test_a_pre_release_tagged_before_the_report_resolves(self, make_ctx: MakeContext) -> None:
        ctx = make_ctx(claims=[_version("1.3.0-rc1")], report=_dated())
        base = ctx.resolution.releases.releases[2]
        _retag(ctx, [TagRef("v1.3.0-rc1", base.commit, base.epoch)])
        (evidence,) = VersionResolves().run(ctx, list(ctx.claims))
        assert evidence.outcome == "SUPPORTS"

    def test_a_variant_final_tagged_before_the_report_resolves(self, make_ctx: MakeContext) -> None:
        ctx = make_ctx(claims=[_version("1.4.0")], report=_dated())
        _variant_line(ctx)
        base = ctx.resolution.releases.releases[1]
        tags = [TagRef(r.name, r.commit, r.epoch) for r in ctx.resolution.releases.releases]
        tags.append(TagRef("libhdr-fips-1_4_0", base.commit, base.epoch))
        ctx.resolution.releases = ReleaseList.from_tags(tags)
        (evidence,) = VersionResolves().run(ctx, list(ctx.claims))
        assert evidence.outcome == "SUPPORTS"

    def test_a_tag_made_after_its_commit_is_not_refuted(self, make_ctx: MakeContext) -> None:
        """The tag date is only a lower bound on the release date."""
        ctx = make_ctx(claims=[_version("1.2.1")], report=_dated())
        v120 = ctx.resolution.releases.releases[2]
        _retag(ctx, [TagRef("v1.2.1", v120.commit, v120.epoch + 90 * 86_400)], drop="v1.2.1")
        (evidence,) = VersionResolves().run(ctx, list(ctx.claims))
        assert evidence.outcome == "NEUTRAL"
        assert evidence.details["outcome"] == "tag_postdates_commit"

    def test_a_shallow_clone_never_refutes(
        self, make_ctx: MakeContext, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(GitRepo, "is_shallow", lambda self: True)
        gap = _one(make_ctx, _version("1.1.5"))
        future = _one(make_ctx, _version("1.5.0"), report=_dated())
        assert (gap.outcome, gap.details["outcome"]) == ("NEUTRAL", "tags_incomplete")
        assert (future.outcome, future.details["outcome"]) == ("NEUTRAL", "tags_incomplete")

    def test_an_unparsed_tag_naming_the_version_blocks_a_gap(self, make_ctx: MakeContext) -> None:
        ctx = make_ctx(claims=[_version("1.1.5")])
        base = ctx.resolution.releases.releases[1]
        _retag(ctx, [TagRef("v1.1.5-hotfix", base.commit, base.epoch)])
        assert "v1.1.5-hotfix" in ctx.resolution.releases.ignored
        (evidence,) = VersionResolves().run(ctx, list(ctx.claims))
        assert evidence.outcome == "NEUTRAL"
        assert evidence.details["unparsed_tags"] == ["v1.1.5-hotfix"]

    def test_a_version_of_another_shape_is_not_a_gap(self, make_ctx: MakeContext) -> None:
        evidence = _one(make_ctx, _version("1.2.0.1"))
        assert evidence.outcome == "NEUTRAL"
        assert evidence.details["outcome"] == "version_shape_differs"

    @pytest.mark.parametrize(
        ("epoch", "shown"),
        [(99_999_999_999_999, "an out-of-range date"), (253_402_300_799, "9999-12-31")],
    )
    def test_extreme_tag_dates_render_identically_and_never_raise(
        self, make_ctx: MakeContext, epoch: int, shown: str
    ) -> None:
        ctx = make_ctx(claims=[_version("1.2.0")])
        _retag(ctx, [], epoch_of=lambda r: epoch if r.name == "v1.2.0" else r.epoch)
        (evidence,) = VersionResolves().run(ctx, list(ctx.claims))
        assert evidence.outcome == "SUPPORTS"
        assert evidence.details["tagged_at"] == shown

    def test_summaries_do_not_carry_the_local_repository_path(self, make_ctx: MakeContext) -> None:
        ctx = make_ctx(claims=[_version("0" * 40, commit="0" * 40)])
        (evidence,) = VersionResolves().run(ctx, list(ctx.claims))
        assert ctx.repo_url not in evidence.summary

    def test_latest_before_the_first_release_is_labelled_honestly(
        self, make_ctx: MakeContext
    ) -> None:
        c = _version("the latest release", relation="latest", special_ref="latest")
        evidence = _one(make_ctx, c, report=_dated(date(2025, 1, 1)))
        assert evidence.outcome == "NEUTRAL"
        assert evidence.details["outcome"] == "no_release_by_report_date"

    def test_one_missing_version_is_refuted_once(self, make_ctx: MakeContext) -> None:
        a = _version("1.1.5")
        b = _version(
            "1.1.5",
            relation="affected_range",
            parsed=None,
            upper=parse_version("1.1.5"),
            upper_inclusive=True,
        )
        evidence = _run(make_ctx, [a, b])
        assert len(evidence) == 1
        assert evidence[0].outcome == "REFUTES"
        assert set(evidence[0].claim_ids) == {a.id, b.id}

    def test_a_tag_cut_the_day_after_the_report_is_not_refuted(self, make_ctx: MakeContext) -> None:
        """Time-zone slack: the reporter's day and the tag's UTC day can differ."""
        evidence = _one(make_ctx, _version("1.2.1"), report=_dated(date(2026, 3, 19)))
        assert evidence.outcome != "REFUTES"

    @pytest.mark.parametrize("raw", ["1.1.0", "1.5.0"])
    def test_a_report_the_day_before_the_first_release_is_not_refuted(
        self, make_ctx: MakeContext, raw: str
    ) -> None:
        """P4: v1.0.0 (2026-01-06) falls inside the slack, but nothing existed on the day."""
        evidence = _one(make_ctx, _version(raw), report=_dated(date(2026, 1, 5)))
        assert evidence.outcome != "REFUTES"

    def test_the_future_summary_names_the_slack_day_truthfully(self, make_ctx: MakeContext) -> None:
        evidence = _one(make_ctx, _version("1.3.0"), report=_dated())
        assert "the latest release by 2026-03-19 was v1.2.0" in evidence.summary
