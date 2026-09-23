# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""C21 REPORT_HYGIENE: what the report does not say (SPEC §12, §14.3, §14.4)

Only *structural absence* is measured: whether a version is pinned, whether a file, line or
symbol is named, whether a trace is attached, whether a proof-of-concept is included.
There are no style, tone, phrasing or "was this written by a machine" heuristics here, and
there never will be — Nikasha judges claims, not people (P1). A terse, ungrammatical or
machine-translated report is perfectly clean by this check's standard, and a long polished
one with no version in it is not.

The strength is 0, because a thin report is not a false one (P4). What this evidence does
is feed the INSUFFICIENT rule (SPEC §14.3 rule 2) and choose the questions the reporter is
asked (§14.4), which is why ``details["missing"]`` is a stable list of machine-readable
keys rather than prose: the question templates key off it.

The evidence cites no individual claim. What is absent is a property of the report as a
whole, and attaching it to every claim would repeat one line on every row of the per-claim
view (SPEC §15.1).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import get_args

from nikasha.checks.base import BaseCheck, CheckContext, make_evidence, register
from nikasha.checks.strengths import Strengths, default_strengths
from nikasha.model.claims import Claim, ClaimKind, VersionClaim
from nikasha.model.evidence import Evidence

CHECK_ID = "C21"
GROUP = "info"

#: Claim kinds that put the reader in front of some code.
_LOCATION_KINDS: frozenset[ClaimKind] = frozenset({"file", "line", "symbol"})

#: Categories counted in ``details["counts"]``. ``snippet`` and ``patch`` are not flagged
#: as missing — SPEC §12 names four — but they are counted, because SPEC §14.3 rule 2
#: accepts either of them as the artifact that keeps a thin report out of INSUFFICIENT.
CATEGORIES: tuple[str, ...] = ("version", "location", "trace", "poc", "snippet", "patch")

#: The categories C21 reports on, in the order SPEC §12 lists them. Fixed rather than
#: sorted, so the output is both stable (P2) and reads the way the spec reads.
FLAGGED: tuple[str, ...] = ("version", "poc", "trace", "location")

#: How each category is worded. The subject is always the report, never the reporter.
_NOUNS = {
    "version": "an affected version",
    "poc": "a proof-of-concept",
    "trace": "a crash trace",
    "location": "a file, line or symbol",
}


@register
class ReportHygiene(BaseCheck):
    id = CHECK_ID
    name = "REPORT_HYGIENE"
    group = GROUP
    # Every kind: hygiene is about the whole claim set, so no kind may filter this check
    # out, and a kind added later must not silently escape it.
    applies_to: frozenset[ClaimKind] = frozenset(get_args(ClaimKind))
    # A report with *no* claims at all is exactly the case this check exists to describe,
    # and it is what drives SPEC §14.3 rule 2. Without this the runner would skip C21 for
    # precisely the emptiest reports.
    runs_on_empty = True
    description = "Flags a missing version, proof-of-concept, trace or code location."

    def __init__(self, strengths: Strengths | None = None) -> None:
        self.strengths = strengths or default_strengths()

    def run(self, ctx: CheckContext, claims: Sequence[Claim]) -> list[Evidence]:
        # ``claims`` is every claim, since ``applies_to`` covers every kind; reading the
        # context makes that explicit and keeps the answer right if it is ever called with
        # a subset.
        counts = _counts(ctx.claims)
        missing = [name for name in FLAGGED if counts[name] == 0]
        present = [name for name in FLAGGED if counts[name] > 0]
        return [
            make_evidence(
                check_id=CHECK_ID,
                group=GROUP,
                claims=(),
                outcome="NEUTRAL",
                strength=self.strengths.get(CHECK_ID, "hygiene"),
                summary=_summary(missing, present),
                details={
                    "outcome": "hygiene",
                    "missing": missing,
                    "present": present,
                    "counts": counts,
                },
            )
        ]


def _counts(claims: Sequence[Claim]) -> dict[str, int]:
    """How many claims satisfy each category."""
    counts = dict.fromkeys(CATEGORIES, 0)
    for claim in claims:
        if isinstance(claim, VersionClaim):
            if _pins_a_version(claim):
                counts["version"] += 1
        elif claim.kind in _LOCATION_KINDS:
            counts["location"] += 1
        elif claim.kind in counts:
            counts[claim.kind] += 1
    return counts


def _pins_a_version(claim: VersionClaim) -> bool:
    """Whether a version claim names something the target resolver can act on.

    A claim with no parsed version, no range bound, no commit and no branch is a version
    *word* — "affected versions", "the current release" — and leaves C01 nothing to
    resolve, so hygiene counts it as absent rather than as a version.
    """
    return any((claim.parsed, claim.lower, claim.upper, claim.commit, claim.special_ref))


def _summary(missing: Sequence[str], present: Sequence[str]) -> str:
    if not missing:
        return "the report gives " + _join([_NOUNS[name] for name in present], "and")
    text = "the report does not give " + _join([_NOUNS[name] for name in missing], "or")
    if present:
        text += "; it does give " + _join([_NOUNS[name] for name in present], "and")
    return text


def _join(items: Sequence[str], conjunction: str) -> str:
    if not items:
        return ""
    if len(items) == 1:
        return items[0]
    return f"{', '.join(items[:-1])} {conjunction} {items[-1]}"
