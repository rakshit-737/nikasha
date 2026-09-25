# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""C10 TRACE_VERSION_FIT: which release does this stack trace actually come from? (SPEC §12)

A stack trace is a fingerprint of one build. C08 asks whether it fits the *claimed* release;
C10 asks which release it fits **best**, by scoring the same frame-consistency ratio r over a
window of releases around the claimed one. The interesting answer is rarely "fabricated": a
trace that fits v1.2.1 exactly while the report says v1.2.0 is almost always a genuine report
naming the wrong version, so that outcome is deliberately mild (-0.3) and its wording says so
plainly. SPEC §14.3 rule 4 reads it as a version-mismatch cap on the verdict, not as a
refutation of the bug, and takes the release name from ``details['best_release']``.

Three rules shape the implementation:

* **Three frames minimum.** Two frames cannot tell releases apart: a comment-only release
  moves one function and leaves the other, and every release scores the same. Below the
  minimum this check says nothing at all rather than adding a neutral row to the ledger.
* **Anchor first.** The window is scanned outwards from the claimed release, so a scan that
  runs out of budget still knows how the claimed release itself did — every outcome here
  compares something against it.
* **A truncated or uncertain scan never refutes (P4).** "No release fits" is a statement
  about *every* release; if the budget ran out, or a frame's file did not parse completely,
  the finding is still reported but carries no strength and says what was missing.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from nikasha.checks.base import BaseCheck, CheckContext, make_evidence, permalink, register
from nikasha.checks.strengths import Strengths, default_strengths
from nikasha.code.trace_forensics import FrameCheck, TraceAnalysis, analyze_trace, app_frames
from nikasha.model.claims import Claim, ClaimKind, TraceClaim
from nikasha.model.evidence import CodeLocation, Evidence, Outcome
from nikasha.resolve.refs import Release

CHECK_ID = "C10"
GROUP = "trace"

#: Fewer application frames with line numbers than this cannot discriminate between releases.
MIN_FRAMES = 3
#: The window SPEC §12 names: the claimed release ±15 final releases, doubled while no release
#: reaches a usable fit.
WINDOW_RADIUS = 15
#: r at or above this is a usable fit; below it for every release scored is the refutation.
USABLE_FIT = 0.5
#: r at this is a perfect fit: every checkable frame lands in the function it names.
PERFECT_FIT = 1.0
#: Locations kept for the best-fitting release (a trace can be forty frames deep).
MAX_LOCATIONS = 5


@dataclass(frozen=True, slots=True)
class _Fit:
    """How one release scored, kept with its place in the release line."""

    release: Release
    ratio: float
    analysis: TraceAnalysis
    order: int
    distance: int


@dataclass(frozen=True, slots=True)
class _Scan:
    """What one pass over the release window measured.

    ``fits`` is in release order, ``complete`` is false when the budget ran out, and
    ``partially_parsed`` names ``release:path`` pairs whose parse was incomplete — either
    makes a "no release fits" refutation unsafe (P4).
    """

    fits: dict[str, _Fit]
    partially_parsed: tuple[str, ...]
    complete: bool
    radius: int

    def best(self) -> _Fit | None:
        """Highest r; ties go to the claimed release, then to the nearest, then the oldest."""
        if not self.fits:
            return None
        return max(self.fits.values(), key=lambda fit: (fit.ratio, -fit.distance, -fit.order))


@register
class TraceVersionFit(BaseCheck):
    id = CHECK_ID
    name = "TRACE_VERSION_FIT"
    group = GROUP
    applies_to: frozenset[ClaimKind] = frozenset({"trace"})
    description = "Finds which release a stack trace fits best, and whether it is the claimed one."

    def __init__(self, strengths: Strengths | None = None) -> None:
        self.strengths = strengths or default_strengths()

    def run(self, ctx: CheckContext, claims: Sequence[Claim]) -> list[Evidence]:
        out: list[Evidence] = []
        for claim in claims:
            if not isinstance(claim, TraceClaim):
                continue
            evidence = self._one(ctx, claim)
            if evidence is not None:
                out.append(evidence)
        return out

    def _one(self, ctx: CheckContext, claim: TraceClaim) -> Evidence | None:  # noqa: PLR0911
        frames = [f for f in app_frames(claim) if f.path is not None and f.line is not None]
        if len(frames) < MIN_FRAMES:
            return None
        anchor = _anchor(ctx)
        if anchor is None:
            return None  # no claimed release to centre a window on; C01 owns the version
        scan = self._scan(ctx, claim, anchor)
        best = scan.best()
        if best is None:
            return None  # no frame was checkable anywhere: nothing to compare between releases
        claimed = scan.fits.get(anchor.name)
        checked, fitting = _counts(best.analysis)
        details = _details(anchor, claimed, best, scan, len(frames))
        locations = _locations(ctx, best)
        scored = len(scan.fits)
        note = _scope_note(scan)

        if best.release.name == anchor.name and best.ratio >= PERFECT_FIT:
            return self._say(
                claim,
                "SUPPORTS",
                "claimed_release_fits",
                f"the trace fits {anchor.name}, the claimed release, exactly: all {checked}"
                f" checked frames land in the function they name, and none of the"
                f" {_n_releases(scored)} scored fits better{note}",
                details=details,
                locations=locations,
            )
        if best.ratio >= PERFECT_FIT:
            return self._say(
                claim,
                "REFUTES",
                "other_release_fits",
                f"this trace matches {best.release.name} exactly ({fitting} of {checked} frames)"
                f"{_also(details)}, while {anchor.name}, the claimed release, fits"
                f" {_share(claimed)}; a trace that matches a neighbouring release usually means"
                f" the report names a different version from the build it came from{note}",
                details=details,
                locations=locations,
            )
        if best.ratio < USABLE_FIT:
            reasons = _reasons(scan)
            if reasons:
                # P4: absence of a fit is only a finding when the search was complete.
                details["uncertain"] = reasons
                return self._say(
                    claim,
                    "NEUTRAL",
                    None,
                    f"no release scored fits this trace — the best is {best.release.name} at"
                    f" {_share(best)} — but the scan was incomplete: {'; '.join(reasons)}",
                    details=details,
                    locations=locations,
                    label="scan_incomplete",
                )
            return self._say(
                claim,
                "REFUTES",
                "no_release_fits",
                f"none of the {_n_releases(scored)} scored fits this trace: the best is"
                f" {best.release.name}, where {_share(best)} of the frames land in the function"
                f" they name{note}",
                details=details,
                locations=locations,
            )
        return self._say(
            claim,
            "NEUTRAL",
            None,
            f"the trace fits {best.release.name} best ({_share(best)} of the frames), and no"
            f" release scored fits every frame{note}",
            details=details,
            locations=locations,
            label="partial_fit",
        )

    def _say(
        self,
        claim: TraceClaim,
        outcome: Outcome,
        key: str | None,
        summary: str,
        *,
        details: dict[str, Any],
        locations: Sequence[CodeLocation],
        label: str | None = None,
    ) -> Evidence:
        """``key`` names the row in the LR table, ``label`` the outcome of a finding without
        one, so ``details['outcome']`` always records what this check concluded (SPEC §14.3)."""
        return make_evidence(
            check_id=CHECK_ID,
            group=GROUP,
            claims=[claim],
            outcome=outcome,
            strength=self.strengths.get(CHECK_ID, key) if key else 0.0,
            summary=summary,
            details={**details, "outcome": key if key else label},
            locations=locations,
        )

    def _scan(self, ctx: CheckContext, claim: TraceClaim, anchor: Release) -> _Scan:
        """Score every release in the window, widening while nothing reaches a usable fit."""
        releases = ctx.resolution.releases
        finals = releases.finals()
        order = {release.name: i for i, release in enumerate(finals)}
        home = order.get(anchor.name)
        if home is None:
            return _Scan({}, (), True, WINDOW_RADIUS)  # a pre-release anchor has no window
        fits: dict[str, _Fit] = {}
        partial: set[str] = set()
        radius, complete, attempted = WINDOW_RADIUS, True, 0
        while True:
            window = releases.window(anchor, radius)
            for release in _outwards(window, order, home, seen=fits):
                # Poll *before* scoring: a scan that already scored every release in the
                # window is complete, whatever the clock says afterwards. Polling after the
                # last release made identical inputs flip ``scan_complete`` (and so the
                # summary and the content-derived evidence ID) on timing alone (P2). The
                # claimed release is always scored, so every outcome has its baseline.
                if attempted and ctx.expired():
                    complete = False
                    break
                attempted += 1
                analysis = analyze_trace(
                    ctx.index, release.commit, claim, project=ctx.resolution.project
                )
                partial |= _partial_parses(ctx, release, analysis)
                if analysis.ratio is not None:
                    rank = order[release.name]
                    fits[release.name] = _Fit(
                        release, analysis.ratio, analysis, rank, abs(rank - home)
                    )
            reached = max((fit.ratio for fit in fits.values()), default=0.0)
            if not complete or reached >= USABLE_FIT or len(window) >= len(finals):
                break
            radius *= 2
        ordered = {name: fits[name] for name in sorted(fits, key=lambda n: order[n])}
        return _Scan(ordered, tuple(sorted(partial)), complete, radius)


def _anchor(ctx: CheckContext) -> Release | None:
    """The release the window centres on: the one the report targets, or the resolved ref."""
    if ctx.resolution.release is not None:
        return ctx.resolution.release
    return next((r for r in ctx.resolution.releases.finals() if r.commit == ctx.commit), None)


def _outwards(
    window: Sequence[Release], order: dict[str, int], home: int, *, seen: dict[str, _Fit]
) -> list[Release]:
    """The window ordered by distance from the claimed release, closest first.

    Scoring the claimed release first is what lets a truncated scan still say something: every
    outcome compares the best fit against it.
    """
    pending = [release for release in window if release.name not in seen]
    return sorted(pending, key=lambda r: (abs(order[r.name] - home), order[r.name]))


def _partial_parses(ctx: CheckContext, release: Release, analysis: TraceAnalysis) -> set[str]:
    """``release:path`` for every frame whose file did not parse completely (P4)."""
    found: set[str] = set()
    for check in analysis.frames:
        path = check.resolved_path
        if path is None:
            continue
        facts = ctx.index.facts_at(release.commit, path)
        if facts is not None and not facts.parsed_ok:
            found.add(f"{release.name}:{path}")
    return found


def _counts(analysis: TraceAnalysis) -> tuple[int, int]:
    """``(checked, fitting)`` application frames: the denominator and numerator of r."""
    checkable = [frame for frame in analysis.frames if frame.checkable]
    return len(checkable), sum(frame.consistent for frame in checkable)


def _share(fit: _Fit | None) -> str:
    if fit is None:
        return "no checkable frame"
    checked, fitting = _counts(fit.analysis)
    return f"{fitting} of {checked}"


def _also(details: dict[str, Any]) -> str:
    """Name the other releases that fit exactly, so the summary never implies uniqueness."""
    others = [name for name in details["perfect_releases"] if name != details["best_release"]]
    return f" (so do {', '.join(others)})" if others else ""


def _reasons(scan: _Scan) -> list[str]:
    """Why a "no release fits" refutation would overreach, if it would."""
    reasons: list[str] = []
    if not scan.complete:
        reasons.append(f"it stopped at its time budget after {_n_releases(len(scan.fits))}")
    if scan.partially_parsed:
        shown = ", ".join(scan.partially_parsed[:3])
        reasons.append(f"some files did not parse completely ({shown})")
    return reasons


def _scope_note(scan: _Scan) -> str:
    return "" if scan.complete else f" (the scan stopped after {_n_releases(len(scan.fits))})"


def _n_releases(releases: int) -> str:
    return f"{releases} release" if releases == 1 else f"{releases} releases"


def _details(
    anchor: Release, claimed: _Fit | None, best: _Fit, scan: _Scan, frames: int
) -> dict[str, Any]:
    """The stable keys behind every outcome; ``best_release`` is what SPEC §14.3 rule 4 reads."""
    checked, fitting = _counts(best.analysis)
    details: dict[str, Any] = {
        "claimed_release": anchor.name,
        "claimed_ratio": _round(claimed.ratio) if claimed is not None else None,
        "best_release": best.release.name,
        "best_ratio": _round(best.ratio),
        "best_frames_fitting": fitting,
        "best_frames_checked": checked,
        "perfect_releases": [n for n, f in scan.fits.items() if f.ratio >= PERFECT_FIT],
        "ratios": {name: _round(fit.ratio) for name, fit in scan.fits.items()},
        # ``Result.to_json`` sorts object keys, which loses the release order of ``ratios``
        # (``v1.10.0`` sorts before ``v1.9.0``); this list keeps it through a round trip.
        "ratios_in_release_order": [[name, _round(fit.ratio)] for name, fit in scan.fits.items()],
        "releases_scored": len(scan.fits),
        "window_radius": scan.radius,
        "scan_complete": scan.complete,
        "frames_with_lines": frames,
    }
    if scan.partially_parsed:
        details["partially_parsed"] = list(scan.partially_parsed)
    return details


def _locations(ctx: CheckContext, best: _Fit) -> list[CodeLocation]:
    """Where the best-fitting release puts the frames, pinned to *that* release's commit."""
    out: list[CodeLocation] = []
    for check in _fitting_frames(best.analysis):
        line = max(1, check.line or 1)
        path = check.resolved_path or ""
        out.append(
            CodeLocation(
                repo=ctx.repo_url,
                ref=best.release.name,
                commit=best.release.commit,
                path=path,
                start_line=line,
                end_line=line,
                permalink=permalink(ctx.repo_url, best.release.commit, path, line, line),
            )
        )
        if len(out) >= MAX_LOCATIONS:
            break
    return out


def _fitting_frames(analysis: TraceAnalysis) -> Iterable[FrameCheck]:
    return (
        check
        for check in analysis.frames
        if check.resolved_path is not None and check.line is not None and check.consistent
    )


def _round(ratio: float) -> float:
    return round(ratio, 3)
