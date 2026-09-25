# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""C12 PATCH_APPLIES: do the report's hunks apply to the blobs at the claimed version?

A suggested patch is the most testable thing a report can carry: it names a file, a line and
the exact text expected around the change. Applying it is a fact, so this check applies it
*in memory* — never to the working tree, never through ``patch`` or ``git apply``, both of
which would let a hostile diff write outside the repository (P5, P7).

The ladder mirrors GNU patch, because that is what a reporter's patch was written for:
exactly at the cited line, then an offset search of +/-200 lines, then fuzz 1 and 2 (that
many leading and trailing context lines ignored).

One deviation is deliberate: **"already applied" is tested before fuzz.** By far the
commonest reason a genuine fix does not apply is that it is already merged at the ref, and a
fuzzed match will happily "apply" such a patch a second time. Calling that fabricated would
be exactly the P4 failure Nikasha exists to avoid, so the reverse patch is tried first and
the result is NEUTRAL with a note rather than a refutation.

No ``CommandRecord`` is attached (ADR 0007 decision 4): every blob is read through the one
long-lived ``git cat-file --batch`` process behind :meth:`~nikasha.code.gitio.GitRepo.read_file`,
so there is no per-file :class:`~nikasha.code.gitio.GitResult` with an exit code and output
to hash, and none is invented. The evidence location pins the commit, path and line range,
which is everything a reader needs to repeat the comparison (P6).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from nikasha.checks.base import BaseCheck, CheckContext, make_evidence, register
from nikasha.checks.strengths import Strengths, default_strengths
from nikasha.model.claims import Claim, ClaimKind, PatchClaim, PatchHunk
from nikasha.model.evidence import CodeLocation, Evidence, Outcome
from nikasha.resolve.refs import Release

CHECK_ID = "C12"
GROUP = "patch"

#: How far from the cited line the context may sit and still count as the same hunk (SPEC §12).
OFFSET_RADIUS = 200
#: GNU patch's default maximum fuzz: that many leading and trailing context lines may be
#: dropped before matching.
MAX_FUZZ = 2
#: Final releases either side of the claimed one that are searched when a hunk does not apply
#: at the ref. A fixed window, rather than "as many as fit in the budget", keeps the answer
#: byte-identical between runs (P2).
RELEASE_RADIUS = 15
#: A hostile report can carry a diff with thousands of hunks (P7).
MAX_HUNKS = 100
#: Locations shown for a patch that touches many places.
MAX_LOCATIONS = 10

#: What happened to one hunk. ``_ORDER`` is the severity order: a multi-hunk patch is
#: reported as its worst hunk.
_Status = Literal[
    "applies_clean",
    "applies_with_fuzz",
    "already_applied",
    "context_elsewhere_in_file",
    "generated",
    "file_missing",
    "search_incomplete",
    "other_release_only",
    "context_not_found",
]

_ORDER: tuple[_Status, ...] = (
    "applies_clean",
    "applies_with_fuzz",
    "already_applied",
    "context_elsewhere_in_file",
    "generated",
    "file_missing",
    "search_incomplete",
    "other_release_only",
    "context_not_found",
)

#: Outcome and strength key per status. ``None`` means no strength key applies: the finding
#: is still reported, it just counts for nothing.
_OUTCOMES: dict[_Status, tuple[Outcome, str | None]] = {
    "applies_clean": ("SUPPORTS", "applies_clean"),
    "applies_with_fuzz": ("SUPPORTS", "applies_with_fuzz"),
    "already_applied": ("NEUTRAL", "already_applied"),
    "context_elsewhere_in_file": ("NEUTRAL", None),
    "generated": ("NEUTRAL", None),
    "file_missing": ("NEUTRAL", None),
    "search_incomplete": ("NEUTRAL", None),
    "other_release_only": ("REFUTES", "other_release_only"),
    "context_not_found": ("REFUTES", "context_not_found"),
}

#: The match ladder: (direction, fuzz levels, search radius). A ``None`` radius scans the
#: whole file; that rung only ever downgrades a refutation, it never claims a patch applies.
_LADDER: tuple[tuple[Literal["forward", "reverse"], tuple[int, ...], int | None], ...] = (
    ("forward", (0,), OFFSET_RADIUS),
    ("reverse", (0,), OFFSET_RADIUS),
    ("forward", tuple(range(1, MAX_FUZZ + 1)), OFFSET_RADIUS),
    ("reverse", tuple(range(1, MAX_FUZZ + 1)), OFFSET_RADIUS),
    ("forward", (0,), None),
)

_LineCache = dict[tuple[str, str], list[str] | None]


@dataclass(frozen=True, slots=True)
class _Match:
    """Where a hunk's text was found, and how much slack it took to find it."""

    line: int
    offset: int
    fuzz: int
    span: int


@dataclass(frozen=True, slots=True)
class _HunkResult:
    hunk: PatchHunk
    path: str
    status: _Status
    match: _Match | None = None
    releases: tuple[str, ...] = ()
    reason: str | None = None

    @property
    def rank(self) -> int:
        return _ORDER.index(self.status)

    def detail(self) -> dict[str, object]:
        out: dict[str, object] = {
            "path": self.path,
            "source_start": self.hunk.source_start,
            "status": self.status,
        }
        if self.match is not None:
            out["line"] = self.match.line
            out["offset"] = self.match.offset
            out["fuzz"] = self.match.fuzz
        if self.releases:
            out["releases"] = list(self.releases)
        if self.reason:
            out["reason"] = self.reason
        return out


def _norm(text: str) -> str:
    """Normalize one line: trailing whitespace is ignored on both sides.

    Markdown editors, mail clients and issue templates eat trailing spaces routinely. A lost
    trailing space is a transport artefact, not a sign that a patch was invented (P4).
    """
    return text.rstrip()


def _to_lines(blob: bytes) -> list[str]:
    text = blob.decode("utf-8", "replace")
    lines = text.split("\n")
    if lines and lines[-1] == "":  # a trailing newline does not start a line
        lines.pop()
    return [_norm(line) for line in lines]


def _path_ok(path: str) -> bool:
    """Reject the paths a diff header can carry that must never reach git (P7)."""
    return bool(path) and path != "/dev/null" and "\n" not in path and not path.startswith("-")


def _sides(hunk: PatchHunk) -> tuple[list[str], list[str], int, int]:
    """The text the hunk expects before and after it, plus its leading/trailing context."""
    source = [_norm(line.text) for line in hunk.lines if line.op != "+"]
    target = [_norm(line.text) for line in hunk.lines if line.op != "-"]
    ops = [line.op for line in hunk.lines]
    changed = [i for i, op in enumerate(ops) if op != " "]
    if not changed:  # a context-only hunk has nothing to fuzz around
        return source, target, 0, 0
    return source, target, changed[0], len(ops) - 1 - changed[-1]


def _locate(lines: list[str], body: list[str], expected: int, radius: int | None) -> int | None:
    """The 1-based line where ``body`` sits, searched outward from ``expected``.

    Backward before forward at each distance, as GNU patch's ``locate_hunk`` does, so the
    offset reported is the one a reporter running ``patch`` would have been shown. A ``None``
    radius scans the whole file instead — bounded by the file, never by the cited line, which
    a report is free to put at line 10^9 (P7).
    """
    n = len(lines)
    if not body:  # a pure insertion needs only a position inside the file
        return expected if 0 <= expected <= n else None
    last = n - len(body) + 1
    if last < 1:
        return None

    def fits(start: int) -> bool:
        return 1 <= start <= last and lines[start - 1 : start - 1 + len(body)] == body

    if radius is None:
        hits = [start for start in range(1, last + 1) if fits(start)]
        return min(hits, key=lambda start: (abs(start - expected), start)) if hits else None
    if fits(expected):
        return expected
    for distance in range(1, radius + 1):
        for candidate in (expected - distance, expected + distance):
            if fits(candidate):
                return candidate
    return None


def _try_side(
    lines: list[str],
    body: list[str],
    lead: int,
    trail: int,
    start: int,
    *,
    fuzz_levels: Sequence[int],
    radius: int | None,
) -> _Match | None:
    """Match one side of a hunk, trying each fuzz level in turn."""
    for fuzz in fuzz_levels:
        drop_lead, drop_trail = min(fuzz, lead), min(fuzz, trail)
        trimmed = body[drop_lead : len(body) - drop_trail]
        if body and not trimmed:  # fuzzing away the whole hunk would prove nothing
            continue
        found = _locate(lines, trimmed, start + drop_lead, radius)
        if found is not None:
            return _Match(
                line=found - drop_lead,
                offset=found - (start + drop_lead),
                fuzz=fuzz,
                span=len(body),
            )
    return None


def _local_match(lines: list[str], hunk: PatchHunk) -> tuple[_Status, _Match] | None:
    """Walk the ladder for one hunk against one file's lines."""
    source, target, lead, trail = _sides(hunk)
    sides = {"forward": (source, hunk.source_start), "reverse": (target, hunk.target_start)}
    for direction, fuzz_levels, radius in _LADDER:
        if direction == "reverse" and source == target:
            continue  # nothing changes, so "already applied" is not a distinct state
        body, start = sides[direction]
        found = _try_side(lines, body, lead, trail, start, fuzz_levels=fuzz_levels, radius=radius)
        if found is None:
            continue
        if direction == "reverse":
            return "already_applied", found
        if radius is None:
            return "context_elsewhere_in_file", found
        clean = found.offset == 0 and found.fuzz == 0
        return ("applies_clean" if clean else "applies_with_fuzz"), found
    return None


def _hunk_count(n: int) -> str:
    return "1 hunk" if n == 1 else f"{n} hunks"


@register
class PatchApplies(BaseCheck):
    id = CHECK_ID
    name = "PATCH_APPLIES"
    group = GROUP
    applies_to: frozenset[ClaimKind] = frozenset({"patch"})
    description = "Applies a report's diff hunks in memory to the blobs at the resolved commit."

    def __init__(self, strengths: Strengths | None = None) -> None:
        self.strengths = strengths or default_strengths()

    def run(self, ctx: CheckContext, claims: Sequence[Claim]) -> list[Evidence]:
        out: list[Evidence] = []
        for claim in claims:
            if not isinstance(claim, PatchClaim):
                continue
            evidence = self._one(ctx, claim)
            if evidence is not None:
                out.append(evidence)
        return out

    # --- one patch claim ------------------------------------------------------------------

    def _one(self, ctx: CheckContext, claim: PatchClaim) -> Evidence | None:
        if not claim.hunks:
            return None  # a diff nothing could parse is a hygiene finding (C21), not a refutation
        cache: _LineCache = {}
        window = self._window(ctx)
        results: list[_HunkResult] = []
        searched = False
        for hunk in claim.hunks[:MAX_HUNKS]:
            result, did_search = self._hunk(ctx, hunk, window, cache)
            searched = searched or did_search
            results.append(result)
            if ctx.expired():
                break
        worst = max(results, key=lambda result: result.rank)
        outcome, key = _OUTCOMES[worst.status]
        details: dict[str, object] = {
            # The strengths key this outcome was scored with, or the status when it has no
            # key: SPEC §14.3 rule 4 must not have to reverse-map a strength of 0.0.
            "outcome": key if key is not None else worst.status,
            "status": worst.status,
            "files": sorted({result.path for result in results}),
            "hunks": [result.detail() for result in results],
            "hunks_checked": len(results),
            "hunks_total": len(claim.hunks),
        }
        if searched:
            details["searched_releases"] = [r.name for r in window if r.commit != ctx.commit]
            details["search_complete"] = worst.status != "search_incomplete"
        if worst.status == "already_applied":
            details["note"] = "possibly already fixed at the ref"
        return make_evidence(
            check_id=CHECK_ID,
            group=GROUP,
            claims=[claim],
            outcome=outcome,
            strength=self.strengths.get(CHECK_ID, key) if key is not None else 0.0,
            summary=self._summary(ctx, worst, results),
            details=details,
            locations=self._locations(ctx, results),
        )

    def _summary(self, ctx: CheckContext, worst: _HunkResult, results: list[_HunkResult]) -> str:
        """One sentence naming the file, the ref and the exact slack the match needed."""
        ref = ctx.ref_name or ctx.commit[:12]
        count, path, cited = _hunk_count(len(results)), worst.path, worst.hunk.source_start
        verb = "applies" if len(results) == 1 else "apply"
        match = worst.match or _Match(line=cited, offset=0, fuzz=0, span=0)
        wording: dict[_Status, str] = {
            "applies_clean": f"{count} of the patch {verb} cleanly to {path} at {ref}",
            "applies_with_fuzz": (
                f"{count} of the patch {verb} to {path} at {ref}, the loosest at line"
                f" {match.line} (offset {match.offset:+d}, fuzz {match.fuzz})"
            ),
            "already_applied": (
                f"the patch is already applied to {path} at {ref}: the reverse patch applies"
                f" at line {match.line} — possibly already fixed at the ref"
            ),
            "context_elsewhere_in_file": (
                f"the patch context is in {path} at {ref} at line {match.line}, more than"
                f" {OFFSET_RADIUS} lines from the cited line {cited}"
            ),
            "generated": f"{path} is {worst.reason}, so the patch is not judged",
            "file_missing": f"the patch touches {path}, which is {worst.reason} at {ref}",
            "search_incomplete": (
                f"the patch does not apply to {path} at {ref}, and the search of the other"
                " releases did not finish, so its context may still exist in one of them"
            ),
            "other_release_only": (
                f"the patch does not apply to {path} at {ref}; it applies at"
                f" {', '.join(worst.releases)}"
            ),
            "context_not_found": (
                f"the patch context at {path}:{cited} is not in the file at {ref}, nor in"
                " the other releases searched"
            ),
        }
        return wording[worst.status]

    def _locations(self, ctx: CheckContext, results: list[_HunkResult]) -> list[CodeLocation]:
        found = [result for result in results if result.match is not None][:MAX_LOCATIONS]
        return [
            ctx.location(result.path, match.line, match.line + max(1, match.span) - 1)
            for result in found
            if (match := result.match) is not None
        ]

    # --- one hunk -------------------------------------------------------------------------

    def _hunk(
        self,
        ctx: CheckContext,
        hunk: PatchHunk,
        window: list[Release],
        cache: _LineCache,
    ) -> tuple[_HunkResult, bool]:
        """One hunk's result, and whether other releases had to be searched for it."""
        candidates = ctx.resolve_path(hunk.path) if _path_ok(hunk.path) else []
        path = candidates[0] if len(candidates) == 1 else hunk.path
        settled = self._at_ref(ctx, hunk, path, candidates, cache)
        if settled is not None:
            return settled, False
        matched, complete = self._other_releases(ctx, hunk, path, window, cache)
        status: _Status = "context_not_found"
        releases: tuple[str, ...] = ()
        reason: str | None = None
        if matched:
            status, releases = "other_release_only", matched
        elif not complete:
            status = "search_incomplete"
        elif self._lines_at(ctx, ctx.commit, path, cache) is None:
            status = "file_missing"
            reason = "not readable" if candidates else "not in the tree"
        return _HunkResult(hunk, path, status, releases=releases, reason=reason), True

    def _at_ref(
        self,
        ctx: CheckContext,
        hunk: PatchHunk,
        path: str,
        candidates: list[str],
        cache: _LineCache,
    ) -> _HunkResult | None:
        """The hunk's result at the resolved commit, or ``None`` if other releases must speak."""
        if len(candidates) == 1:
            generated = ctx.generated(path)
            if generated is not None:
                return _HunkResult(hunk, path, "generated", reason=generated.reason)
        lines = self._lines_at(ctx, ctx.commit, path, cache)
        if lines is None:
            if all(line.op == "+" for line in hunk.lines):
                # The patch creates this file: having nothing to match against is the point.
                return _HunkResult(hunk, path, "applies_clean", match=_Match(1, 0, 0, 0))
            return None
        local = _local_match(lines, hunk)
        if local is None:
            return None
        status, match = local
        return _HunkResult(hunk, path, status, match=match)

    def _other_releases(
        self,
        ctx: CheckContext,
        hunk: PatchHunk,
        path: str,
        window: list[Release],
        cache: _LineCache,
    ) -> tuple[tuple[str, ...], bool]:
        """The releases whose blobs the hunk applies to, and whether the search finished.

        An unfinished search is never "the context is nowhere": absence counts only when the
        search that looked for it was complete (P4).
        """
        source, _target, lead, trail = _sides(hunk)
        fuzz_levels = tuple(range(MAX_FUZZ + 1))
        matched: list[str] = []
        for release in window:
            if release.commit == ctx.commit:
                continue
            if ctx.expired():
                return tuple(matched), False
            lines = self._lines_at(ctx, release.commit, path, cache)
            if lines is None:
                continue
            found = _try_side(
                lines,
                source,
                lead,
                trail,
                hunk.source_start,
                fuzz_levels=fuzz_levels,
                radius=OFFSET_RADIUS,
            )
            if found is not None:
                matched.append(release.name)
        return tuple(matched), True

    # --- repository access ------------------------------------------------------------------

    def _window(self, ctx: CheckContext) -> list[Release]:
        """The releases searched when a hunk does not apply at the ref, in version order."""
        releases = ctx.resolution.releases
        current = ctx.resolution.release
        if current is not None:
            window = releases.window(current, RELEASE_RADIUS)
            if window:
                return window
        return releases.finals()[-(2 * RELEASE_RADIUS + 1) :]

    def _lines_at(
        self, ctx: CheckContext, rev: str, path: str, cache: _LineCache
    ) -> list[str] | None:
        key = (rev, path)
        if key not in cache:
            blob = ctx.resolution.repo.read_file(rev, path) if _path_ok(path) else None
            cache[key] = _to_lines(blob) if blob is not None else None
        return cache[key]
