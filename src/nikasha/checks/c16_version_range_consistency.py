# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""C16 VERSION_RANGE_CONSISTENCY: do the claimed versions fit the symbol's history? (SPEC §12)

Two things a report says about versions can be measured against the repository itself:

* code cannot be vulnerable before it exists, so an affected range that starts before the
  core symbol was introduced is wrong about something concrete ("all versions up to 1.2.0"
  against a function added in 1.1.0);
* a release that left the locus byte-identical to the release before it fixed nothing in
  it, whatever the report's "fixed in" line says.

Both are statements about *history*, which is where P4 bites hardest. A timeline whose
history search was cut short, a release that mentions the symbol only in files that did not
parse cleanly, and a symbol that was never located at all all mean the same thing here: say
the timeline is incomplete and refute nothing.

Neighbouring checks are left alone: a version that names no release at all is C01's
finding, and whether the symbol exists at the resolved commit is C03's. Re-deciding either
here would double-count against the report, which is what group damping (SPEC §14.1) exists
to undo — this check avoids creating it.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from nikasha.checks.base import BaseCheck, CheckContext, make_evidence, register
from nikasha.checks.strengths import Strengths, default_strengths
from nikasha.code.index import FileEntry
from nikasha.code.timeline import ReleasePresence, Timeline
from nikasha.model.claims import Claim, ClaimKind, SymbolClaim, VersionClaim
from nikasha.model.evidence import CodeLocation, Evidence
from nikasha.resolve.refs import Release, spec_to_key

CHECK_ID = "C16"
GROUP = "version"

#: The relations that bound a range of versions; "tested_on" and "latest" say nothing here.
RANGE_RELATIONS = frozenset({"affected_range", "fixed_in"})
LABELS = {"affected_range": "affected range", "fixed_in": "fix release"}


@dataclass(frozen=True, slots=True)
class _Locus:
    """Whether the symbol's definition differs between two releases, and how it was decided."""

    changed: bool
    reason: str


@register
class VersionRangeConsistency(BaseCheck):
    id = CHECK_ID
    name = "VERSION_RANGE_CONSISTENCY"
    group = GROUP
    applies_to: frozenset[ClaimKind] = frozenset({"version", "symbol"})
    description = (
        "Compares a claimed affected range or fix release with the core symbol's timeline."
    )

    def __init__(self, strengths: Strengths | None = None) -> None:
        self.strengths = strengths or default_strengths()

    def run(self, ctx: CheckContext, claims: Sequence[Claim]) -> list[Evidence]:
        ranges = [
            claim
            for claim in claims
            if isinstance(claim, VersionClaim) and claim.relation in RANGE_RELATIONS
        ]
        cores = [
            claim
            for claim in claims
            if isinstance(claim, SymbolClaim) and claim.role == "core" and not claim.external
        ]
        if not ranges or not cores:
            return []  # a range is only checkable against a symbol, and vice versa
        chosen = self._core(ctx, cores)
        if chosen is None:
            return []
        core, timeline = chosen
        out: list[Evidence] = []
        for claim in ranges:
            if ctx.expired():
                break
            if not _about_target(ctx, claim):
                continue  # a version of some other product is not this repository's history
            if claim.relation == "fixed_in":
                evidence = self._fixed_in(ctx, claim, core, timeline)
            else:
                evidence = self._affected_range(ctx, claim, core, timeline)
            if evidence is not None:
                out.append(evidence)
        return out

    def _core(
        self, ctx: CheckContext, cores: Sequence[SymbolClaim]
    ) -> tuple[SymbolClaim, Timeline] | None:
        """The core symbol the ranges are measured against, with its timeline.

        Reports normally name one. When they name several, the earliest introduced one is
        the conservative choice: a range that starts before *that* symbol existed starts
        before every symbol the report calls central (P4).
        """
        scored: list[tuple[tuple[int, int, int], SymbolClaim, Timeline]] = []
        for order, symbol in enumerate(cores):
            if ctx.expired():
                break
            timeline = ctx.timeline(symbol.name)
            introduced = _introduced(timeline)
            key = (1 if introduced is None else 0, introduced or 0, order)
            scored.append((key, symbol, timeline))
        if not scored:
            return None
        scored.sort(key=lambda entry: entry[0])
        return scored[0][1], scored[0][2]

    # --- "affected from X" ---------------------------------------------------------------

    def _affected_range(
        self, ctx: CheckContext, claim: VersionClaim, core: SymbolClaim, timeline: Timeline
    ) -> Evidence | None:
        blocked = _blocked(timeline)
        if blocked is not None:
            return self._incomplete(claim, core, blocked)
        first = self._first_affected(ctx, claim)
        start = _release_index(timeline, first.name) if first is not None else None
        introduced = _introduced(timeline)
        if start is None or introduced is None:
            return None  # the range covers no release of this repository: C01's finding
        details: dict[str, Any] = {
            "symbol": core.name,
            "relation": claim.relation,
            "range": claim.raw,
            "first_affected_release": timeline.presence[start].release,
            "introduced_in": timeline.presence[introduced].release,
        }
        if start >= introduced:
            return self._verdict(ctx, claim, core, "consistent", details)
        uncertain = [p.release for p in timeline.presence[start:introduced] if p.uncertain]
        if uncertain:
            details["uncertain_releases"] = uncertain
            return self._incomplete(claim, core, _partial_note(uncertain), details)
        return self._verdict(ctx, claim, core, "range_predates_symbol", details)

    def _first_affected(self, ctx: CheckContext, claim: VersionClaim) -> Release | None:
        """The earliest release the claimed range covers, or ``None`` when it covers none.

        The candidate has to sit inside the *upper* bound too: "everything before 0.9" on a
        repository whose oldest tag is 1.0.0 names no release here, and reading it as one
        would refute a claim the report never made.
        """
        start = self._lower_start(ctx, claim)
        return start if start is not None and _within_upper(claim, start) else None

    def _lower_start(self, ctx: CheckContext, claim: VersionClaim) -> Release | None:
        """The first release at or above the range's lower bound (the earliest when open)."""
        releases = ctx.resolution.releases
        finals = releases.finals()
        if not finals:
            return None
        if claim.lower is None:
            return finals[0]
        named = {release.name for release in finals}
        matched = [release for release in releases.match(claim.lower) if release.name in named]
        if not matched:
            return releases.neighbours(claim.lower)[1]  # the first release above the bound
        if claim.lower_inclusive:
            return matched[0]
        above = [r for r in finals if r.tag.sort_key > matched[0].tag.sort_key]
        return above[0] if above else None

    # --- "fixed in X" ----------------------------------------------------------------------

    def _fixed_in(
        self, ctx: CheckContext, claim: VersionClaim, core: SymbolClaim, timeline: Timeline
    ) -> Evidence | None:
        blocked = _blocked(timeline)
        if blocked is not None:
            return self._incomplete(claim, core, blocked)
        by_name = {release.name: release for release in ctx.resolution.releases.finals()}
        fixed = self._fixed_release(ctx, claim, by_name)
        index = _release_index(timeline, fixed.name) if fixed is not None else None
        if fixed is None or index is None:
            return None  # "fixed in master", or a version that is no release here: C01's
        if index == 0:
            summary = (
                f"{fixed.name} is the earliest release known here, so there is nothing to"
                f" compare {core.name} against"
            )
            return self._neutral(
                claim, core, summary, {"fixed_in": fixed.name}, label="no_previous_release"
            )
        previous = by_name.get(timeline.presence[index - 1].release)
        if previous is None:
            return None
        pair = (timeline.presence[index - 1], timeline.presence[index])
        return self._compare(ctx, claim, core, pair, (previous, fixed))

    def _fixed_release(
        self, ctx: CheckContext, claim: VersionClaim, by_name: dict[str, Release]
    ) -> Release | None:
        """The release the report says the fix shipped in, if it is a release of this repo."""
        spec = claim.parsed or claim.lower or claim.upper
        if spec is None:
            return None
        matched = [r for r in ctx.resolution.releases.match(spec) if r.name in by_name]
        return matched[0] if matched else None

    def _compare(
        self,
        ctx: CheckContext,
        claim: VersionClaim,
        core: SymbolClaim,
        pair: tuple[ReleasePresence, ReleasePresence],
        releases: tuple[Release, Release],
    ) -> Evidence:
        before, here = pair
        details: dict[str, Any] = {
            "symbol": core.name,
            "relation": claim.relation,
            "range": claim.raw,
            "fixed_in": here.release,
            "previous_release": before.release,
        }
        uncertain = [p.release for p in (before, here) if p.uncertain]
        if uncertain:
            details["uncertain_releases"] = uncertain
            return self._incomplete(claim, core, _partial_note(uncertain), details)
        if not here.defined and not before.defined:
            summary = (
                f"{core.name} is defined in neither {before.release} nor {here.release},"
                f" so the claimed fix release is not judged"
            )
            return self._neutral(claim, core, summary, details, label="symbol_not_defined")
        if here.defined != before.defined:
            locus = _Locus(True, "removed" if before.defined else "added")
        else:
            found = self._locus(ctx, core.name, releases, before.paths, here.paths)
            if found is None:
                return self._incomplete(
                    claim, core, "its definition could not be compared", details
                )
            locus = found
        details["locus"] = locus.reason
        outcome = "consistent" if locus.changed else "fixed_in_unchanged"
        return self._verdict(ctx, claim, core, outcome, details)

    def _locus(
        self,
        ctx: CheckContext,
        name: str,
        releases: tuple[Release, Release],
        before_paths: tuple[str, ...],
        here_paths: tuple[str, ...],
    ) -> _Locus | None:
        """Whether the symbol's definition changed between the two releases (``None``: unknown).

        The comparison is exact text, never a normalized or token-level one: a real fix can
        be a single changed constant (``64`` to ``sizeof buf``), and normalizing literals
        away would turn that into a refutation of a true "fixed in" line (P4).
        """
        previous, fixed = releases
        if set(before_paths) != set(here_paths):
            return _Locus(True, "moved")
        only_comments = False
        for path in sorted(here_paths):
            if ctx.expired():
                return None
            was = ctx.index.file_at(previous.commit, path)
            now = ctx.index.file_at(fixed.commit, path)
            if was is None or now is None:
                return None
            if was.blob == now.blob:
                continue  # the whole file is untouched, so the definition in it is too
            before_text = _definition_text(ctx, was, path, name)
            after_text = _definition_text(ctx, now, path, name)
            if before_text is None or after_text is None:
                return None
            if before_text != after_text:
                return _Locus(True, "edited")
            only_comments = True
        return _Locus(False, "definition_unchanged" if only_comments else "file_unchanged")

    # --- evidence --------------------------------------------------------------------------

    def _verdict(
        self,
        ctx: CheckContext,
        claim: VersionClaim,
        core: SymbolClaim,
        outcome: str,
        details: dict[str, Any],
    ) -> Evidence:
        return make_evidence(
            check_id=CHECK_ID,
            group=GROUP,
            claims=[claim, core],
            outcome="SUPPORTS" if outcome == "consistent" else "REFUTES",
            strength=self.strengths.get(CHECK_ID, outcome),
            summary=_summary(outcome, claim, core, details),
            details={**details, "outcome": outcome},
            locations=_locations(ctx, core.name),
        )

    def _incomplete(
        self,
        claim: VersionClaim,
        core: SymbolClaim,
        reason: str,
        details: dict[str, Any] | None = None,
    ) -> Evidence:
        """A P4 refusal: something about the history is unknown, so nothing is refuted."""
        label = LABELS[claim.relation]
        summary = (
            f"the release timeline for {core.name} is incomplete ({reason}), so the claimed"
            f" {label} {claim.raw!r} is not judged"
        )
        return self._neutral(claim, core, summary, details, label="timeline_incomplete")

    def _neutral(
        self,
        claim: VersionClaim,
        core: SymbolClaim,
        summary: str,
        details: dict[str, Any] | None = None,
        *,
        label: str,
    ) -> Evidence:
        """``label`` is what this NEUTRAL finding concluded, recorded as ``details['outcome']``
        so nothing has to be read back from a strength of zero (SPEC §14.3)."""
        payload: dict[str, Any] = {
            "outcome": label,
            "symbol": core.name,
            "relation": claim.relation,
            "range": claim.raw,
        }
        payload.update(details or {})
        return make_evidence(
            check_id=CHECK_ID,
            group=GROUP,
            claims=[claim, core],
            outcome="NEUTRAL",
            strength=0.0,
            summary=summary,
            details=payload,
        )


def _summary(outcome: str, claim: VersionClaim, core: SymbolClaim, details: dict[str, Any]) -> str:
    name = core.name
    if outcome == "range_predates_symbol":
        return (
            f"{claim.raw!r} makes {details['first_affected_release']} affected, but {name}"
            f" first appears in {details['introduced_in']}"
        )
    if outcome == "fixed_in_unchanged":
        where = "the file defining it is" if details["locus"] == "file_unchanged" else "it is"
        return (
            f"{claim.raw!r} names {details['fixed_in']} as the fix, but {where} byte-identical"
            f" to {details['previous_release']}, so {name} was not changed there"
        )
    if claim.relation == "fixed_in":
        return (
            f"{name} changed between {details['previous_release']} and {details['fixed_in']},"
            f" which is consistent with a fix in {details['fixed_in']}"
        )
    return (
        f"{name} is defined from {details['introduced_in']} onwards, which is consistent with"
        f" an affected range starting at {details['first_affected_release']}"
    )


def _introduced(timeline: Timeline) -> int | None:
    """The index of the release that first defines the symbol."""
    return next((i for i, p in enumerate(timeline.presence) if p.defined), None)


def _release_index(timeline: Timeline, release: str) -> int | None:
    return next((i for i, p in enumerate(timeline.presence) if p.release == release), None)


def _blocked(timeline: Timeline) -> str | None:
    """Why this timeline cannot support a refutation, or ``None`` when it can (P4)."""
    if not timeline.history_complete:
        return "; ".join(timeline.notes) or "the search over history did not finish"
    if not timeline.ever_defined:
        return "it was not located in any release"
    return None


def _within_upper(claim: VersionClaim, release: Release) -> bool:
    """Whether ``release`` is inside the range's upper bound (an absent bound is open)."""
    if claim.upper is None:
        return True
    bound = spec_to_key(claim.upper)[0]
    return release.tag.trimmed < bound or (claim.upper_inclusive and release.tag.trimmed == bound)


def _partial_note(releases: Sequence[str]) -> str:
    return f"{', '.join(releases)} mentions it only in files that did not parse cleanly"


def _about_target(ctx: CheckContext, claim: VersionClaim) -> bool:
    """Whether a version claim is about the project that was resolved.

    "OpenSSL 1.1.1 is affected" in a libhdr report says nothing about libhdr's history, and
    judging it against this repository's tags would be a refutation of the wrong thing.
    """
    project = ctx.resolution.project
    if claim.product is None or project is None:
        return True
    named = claim.product.strip().lower()
    return named == project.name.lower() or named in {a.lower() for a in project.aliases}


def _definition_text(
    ctx: CheckContext, entry: FileEntry, path: str, name: str
) -> tuple[bytes, ...] | None:
    """The exact source lines of every definition of ``name`` in ``entry``.

    ``None`` when the file did not parse cleanly, defines nothing by that name, or cannot be
    read: a definition missing from a half-parsed file is uncertainty, not a change (P4).
    """
    facts = ctx.index.facts(entry.blob, path)
    if facts is None or not facts.parsed_ok:
        return None
    defs = facts.definitions(name)
    blob = ctx.resolution.repo.read_blob(entry.blob)
    if not defs or blob is None:
        return None
    lines = blob.split(b"\n")
    return tuple(sorted(b"\n".join(lines[d.start_line - 1 : d.end_line]) for d in defs))


def _locations(ctx: CheckContext, name: str) -> list[CodeLocation]:
    """The symbol's definition at the resolved commit, when it has one (P6)."""
    found = ctx.index.definitions(ctx.commit, name)
    return [ctx.location(path, symbol.start_line, symbol.end_line) for path, symbol in found[:1]]
