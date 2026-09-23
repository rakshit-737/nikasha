# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""C01 VERSION_RESOLVES: does the version the report names exist at all? (SPEC §12)

Every other check measures something *at a version*, so this is the first question worth
asking: "libhdr 1.4.0" pins nothing if no such release was ever cut, and a report built on
a version that never shipped cannot be about the code that did.

Two answers earn a refutation.

A **future release** is a version newer than anything tagged on the day the report was
written. It is judged against ``ReleaseList.latest_before(report date)``, never against the
clone's newest tag — the whole point is that ``v1.3.0`` may well be sitting in the clone
today and still not have existed when the reporter says they tested it.

A **gap in the releases** is a version with real releases on both sides of it and nothing
of its own: 8.4.7 where 8.4.6 and 8.5.0 exist.

Everything else is NEUTRAL, because absence here is rarely proof (P4):

- **no report date** means "newer than the latest release" is unknowable, so it is never
  claimed — this is the single most common way to get "future release" wrong;
- a **pre-release or letter-suffixed** version that matches no tag is uncertain, not
  absent: ``-rc1`` and snapshot tags are routinely built and never pushed;
- an **exclusive range bound** ("all versions before 2.0.0") names a boundary, not a
  release, so it asserts nothing about 2.0.0 having shipped;
- **"fixed in X"** may legitimately name a release that has not been cut yet;
- a **branch ref** (``main``, ``HEAD``, ``latest``) is not a version that can fail to
  exist, and a commit the clone does not carry is C15's finding, not a refutation here.

Variant release lines are :mod:`nikasha.resolve.refs`' business, and the order of the tests
below respects it: ``match()`` searches every tag family, while ``neighbours()`` and
``latest_before()`` run over ``finals()``, which ``main_line_families()`` has already
narrowed to the project's own line. So ``tiny-curl-8_4_0`` resolves on its own line and is
never reported as a hole in curl's.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from datetime import UTC, date, datetime, time
from typing import Any

from nikasha.checks.base import BaseCheck, CheckContext, make_evidence, register
from nikasha.checks.strengths import Strengths, default_strengths
from nikasha.model.claims import Claim, ClaimKind, VersionClaim, VersionSpec
from nikasha.model.evidence import Evidence, Outcome
from nikasha.resolve.refs import Release, spec_to_key

CHECK_ID = "C01"
GROUP = "version"

#: A commit as report text spells it; anything else never reaches ``git rev-parse``.
_SHA_RE = re.compile(r"\A[0-9a-fA-F]{7,40}\Z")
#: ``special_ref`` values that name a branch rather than a release.
_BRANCH_REFS = frozenset({"HEAD", "main", "master", "trunk"})
#: Subject roles that assert the version was actually released (see the module docstring).
_ASSERTS_RELEASE = frozenset({"named", "upper", "lower"})


def _report_epoch(day: date) -> int:
    """``day`` as an epoch, taken at end of day so a release cut that morning counts.

    The same convention as :mod:`nikasha.resolve.target`, so C01 and target resolution can
    never disagree about which releases existed on the report date.
    """
    return int(datetime.combine(day, time.max, tzinfo=UTC).timestamp())


def _tagged_on(release: Release) -> str:
    """The UTC date a release was tagged, for a summary a reporter can check."""
    return datetime.fromtimestamp(release.epoch, UTC).date().isoformat()


def _subject(claim: VersionClaim) -> tuple[VersionSpec, str] | None:
    """The version this claim is about, and what naming it asserts.

    A range bound is an existence claim only when it is inclusive: "all versions before
    2.0.0" is a boundary that may perfectly well name a release nobody has cut yet.
    """
    if claim.parsed is not None:
        return claim.parsed, "named"
    if claim.upper is not None:
        return claim.upper, "upper" if claim.upper_inclusive else "upper_exclusive"
    if claim.lower is not None:
        return claim.lower, "lower" if claim.lower_inclusive else "lower_exclusive"
    return None


@register
class VersionResolves(BaseCheck):
    id = CHECK_ID
    name = "VERSION_RESOLVES"
    group = GROUP
    applies_to: frozenset[ClaimKind] = frozenset({"version"})
    description = "Checks that the version a report names resolves to a release tag or a commit."

    def __init__(self, strengths: Strengths | None = None) -> None:
        self.strengths = strengths or default_strengths()

    def run(self, ctx: CheckContext, claims: Sequence[Claim]) -> list[Evidence]:
        out: list[Evidence] = []
        for claim in claims:
            if not isinstance(claim, VersionClaim):
                continue
            evidence = self._one(ctx, claim)
            if evidence is not None:
                out.append(evidence)
        return out

    # --- one claim ----------------------------------------------------------------------

    def _one(self, ctx: CheckContext, claim: VersionClaim) -> Evidence | None:
        subject = _subject(claim)
        if subject is None:
            return self._without_a_version(ctx, claim)
        spec, role = subject
        releases = ctx.resolution.releases
        if not releases.releases:
            return self._say(
                claim,
                "NEUTRAL",
                f"{ctx.repo_url} has no release tags, so {spec.raw} cannot be matched to one",
                {"version": spec.raw},
                key="no_tags",
            )
        families = ctx.resolution.project.tag_families if ctx.resolution.project else ()
        matches = releases.match(spec, preferred_families=families)
        if role in _ASSERTS_RELEASE:
            # Asked before the match, because a tag that exists *now* still did not exist
            # on the report date — that is exactly the fabrication this catches.
            future = self._future(ctx, claim, spec, matches)
            if future is not None:
                return future
        if matches:
            best = matches[0]
            return self._say(
                claim,
                "SUPPORTS",
                f"{spec.raw} resolves to tag {best.name} ({best.commit[:12]}),"
                f" tagged {_tagged_on(best)}",
                {
                    "version": spec.raw,
                    "tag": best.name,
                    "commit": best.commit,
                    "tagged_at": _tagged_on(best),
                    "also_matched": [other.name for other in matches[1:]],
                },
                key="resolves",
            )
        return self._absent(ctx, claim, spec, role)

    # --- the two refutations ------------------------------------------------------------

    def _future(
        self,
        ctx: CheckContext,
        claim: VersionClaim,
        spec: VersionSpec,
        matches: Sequence[Release],
    ) -> Evidence | None:
        """A version that did not exist yet on the report date, or ``None`` if it did."""
        day = ctx.report.reported_at
        if day is None:
            return None  # P4: undated reports make "newer than the latest release" unknowable
        current = ctx.resolution.releases.latest_before(_report_epoch(day))
        if current is None or spec_to_key(spec)[0] <= current.tag.trimmed:
            return None
        details: dict[str, Any] = {
            "version": spec.raw,
            "reported_at": day.isoformat(),
            "latest_release_then": current.name,
            "latest_release_then_tagged_at": _tagged_on(current),
        }
        note = ""
        if matches:
            details["tag"] = matches[0].name
            details["tagged_at"] = _tagged_on(matches[0])
            note = f"; {matches[0].name} was not tagged until {_tagged_on(matches[0])}"
        if claim.relation == "fixed_in":
            return self._say(
                claim,
                "NEUTRAL",
                f"{spec.raw} is newer than {current.name}, the latest release on"
                f" {day.isoformat()}, but a fix release need not have been cut yet{note}",
                details,
                label="fix_release_not_cut",
            )
        return self._say(
            claim,
            "REFUTES",
            f"the latest release on {day.isoformat()} was {current.name}"
            f" ({_tagged_on(current)}); the report names {spec.raw}{note}",
            details,
            key="future_release",
        )

    def _absent(
        self, ctx: CheckContext, claim: VersionClaim, spec: VersionSpec, role: str
    ) -> Evidence:
        """No tag matches: a hole between two releases, or something less certain."""
        day = ctx.report.reported_at
        below, above = ctx.resolution.releases.neighbours(spec)
        details: dict[str, Any] = {
            "version": spec.raw,
            "below": below.name if below is not None else None,
            "above": above.name if above is not None else None,
            "reported_at": day.isoformat() if day is not None else None,
        }
        if above is None:
            undated = "; the report carries no date, so it cannot be called a future release"
            return self._say(
                claim,
                "NEUTRAL",
                f"{spec.raw} matches no tag and is newer than every release in the clone"
                f"{undated if day is None else ''}",
                details,
                label="newer_than_all_releases",
            )
        if below is None:
            return self._say(
                claim,
                "NEUTRAL",
                f"{spec.raw} matches no tag and is older than every release in the clone",
                details,
                label="older_than_all_releases",
            )
        if spec.qualifier:
            return self._say(
                claim,
                "NEUTRAL",
                f"no tag matches the pre-release {spec.raw}, and pre-release tags are not"
                f" always published",
                details,
                label="prerelease_unmatched",
            )
        if role not in _ASSERTS_RELEASE:
            return self._say(
                claim,
                "NEUTRAL",
                f"{spec.raw} is a range boundary, not a version the report says shipped;"
                f" no release of that name exists",
                details,
                label="range_boundary",
            )
        return self._say(
            claim,
            "REFUTES",
            f"no release {spec.raw} was ever cut: the releases either side of it are"
            f" {below.name} and {above.name}",
            details,
            key="gap_in_releases",
        )

    # --- claims that name something other than a version --------------------------------

    def _without_a_version(self, ctx: CheckContext, claim: VersionClaim) -> Evidence | None:
        if claim.commit:
            return self._commit(ctx, claim, claim.commit)
        if claim.special_ref is not None:
            return self._special(ctx, claim, claim.special_ref)
        return None

    def _commit(self, ctx: CheckContext, claim: VersionClaim, text: str) -> Evidence | None:
        if _SHA_RE.match(text) is None:
            return None
        resolved = ctx.resolution.repo.rev_parse(text)
        if resolved is None:
            # A commit the clone does not carry is C15's finding, and never a refutation
            # here: mirrors, forks and rewritten history all produce it innocently.
            return self._say(
                claim,
                "NEUTRAL",
                f"commit {text} is not in this clone of {ctx.repo_url}",
                {"commit": text},
                label="commit_not_in_clone",
            )
        return self._say(
            claim,
            "SUPPORTS",
            f"commit {text} exists in {ctx.repo_url} ({resolved[:12]})",
            {"commit": resolved},
            key="resolves",
        )

    def _special(self, ctx: CheckContext, claim: VersionClaim, ref: str) -> Evidence:
        if ref == "latest":
            day = ctx.report.reported_at
            finals = ctx.resolution.releases.finals()
            newest = (
                ctx.resolution.releases.latest_before(_report_epoch(day))
                if day is not None
                else (finals[-1] if finals else None)
            )
            if newest is None:
                return self._say(
                    claim,
                    "NEUTRAL",
                    'the report says "latest", and there is no release tag to pin that to',
                    {"special_ref": ref},
                    key="no_tags",
                )
            return self._say(
                claim,
                "SUPPORTS",
                f'"latest" resolves to {newest.name} ({_tagged_on(newest)})',
                {"special_ref": ref, "tag": newest.name, "commit": newest.commit},
                key="resolves",
            )
        resolved = ctx.resolution.repo.rev_parse(ref) if ref in _BRANCH_REFS else None
        if resolved is None:
            return self._say(
                claim,
                "NEUTRAL",
                f"{ref} is not a ref in this clone, which mirrors may name differently",
                {"special_ref": ref},
                label="ref_not_in_clone",
            )
        return self._say(
            claim,
            "SUPPORTS",
            f"{ref} resolves to {resolved[:12]} in this clone",
            {"special_ref": ref, "commit": resolved},
            key="resolves",
        )

    # --- evidence -----------------------------------------------------------------------

    def _say(
        self,
        claim: VersionClaim,
        outcome: Outcome,
        summary: str,
        details: dict[str, Any],
        *,
        key: str | None = None,
        label: str | None = None,
    ) -> Evidence:
        """One piece of evidence about one claim; ``key`` names its row in the LR table.

        ``label`` names the outcome of a finding that has no row in the table, so that every
        item records in ``details['outcome']`` what it concluded, rather than leaving the
        fuser to infer it from a strength of zero (SPEC §14.3).
        """
        return make_evidence(
            check_id=CHECK_ID,
            group=GROUP,
            claims=[claim],
            outcome=outcome,
            strength=self.strengths.get(CHECK_ID, key) if key is not None else 0.0,
            summary=summary,
            details={**details, "outcome": key if key is not None else label},
        )
