# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""C06 LINE_CONTENT: is the quoted line really the line the report points at? (SPEC §12)

A report that writes ``util.c:15`` *and* pastes the line it means gives the cheapest strong
signal there is: at that commit the two either agree or they do not. Reporters re-indent,
wrap and trim what they paste, so everything is compared after whitespace normalization,
and a quote that is only part of a line still counts as quoting that line.

The ladder runs from "here it is" down to "this text is nowhere in the project", and every
rung below the top is a statement about *where the text is*, never about the reporter:

* at the stated line (``exact``) and within ±3 lines (``near_by_offset``) are support — a
  line number that drifted by two is a stale copy, not a fabrication;
* elsewhere at the ref (``elsewhere_in_file``) is a weak refutation: the code is real, the
  location is not;
* only in another release (``other_release_only``) is a *version* finding, which C01 and
  C10 are the checks that make something of;
* nowhere in history (``nowhere_in_history``) is the only strong refutation, and P4 makes
  it expensive to reach: it needs a claimed path (ADR 0003), a non-shallow clone and a
  pickaxe that ran to completion. Any doubt downgrades it to NEUTRAL with the reason
  recorded, because an inconclusive search is not evidence of invention.

Paths and bounds are left to their owners: an unresolvable path is C02's finding and a line
past the end of the file is C04's, so neither is refuted a second time here (SPEC §14.1).
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from typing import Any

from rapidfuzz import fuzz

from nikasha.checks.base import BaseCheck, CheckContext, make_evidence, register
from nikasha.checks.strengths import Strengths, default_strengths
from nikasha.code.gitio import GrepHit, HistoryTimeoutError
from nikasha.code.literal import literal_search, searchable
from nikasha.model.claims import Claim, ClaimKind, LineClaim
from nikasha.model.evidence import CodeLocation, CommandRecord, Evidence, Outcome

CHECK_ID = "C06"
GROUP = "code_quotes"

#: A quote and a line count as the same line at or above this similarity (SPEC §12 C06).
MATCH_RATIO = 0.9
#: How far either side of the stated line a match still counts as near (SPEC §12 C06).
NEAR_RADIUS = 3
#: Shorter normalized quotes (``}``, ``break;``) match half the tree and prove nothing.
MIN_QUOTE_CHARS = 8
#: Hits listed in the details. Counts stay exact; only the listing is capped.
MAX_REPORTED_HITS = 5
#: Characters of the quote echoed into the details, so one pathological line cannot bloat
#: the result JSON.
MAX_QUOTE_CHARS = 200
#: A pickaxe with less time left than this cannot answer, so it is not started.
MIN_HISTORY_BUDGET_S = 0.5
#: ``git log -S`` refuses control characters, so a quote holding one is unsearchable.
MIN_PRINTABLE = 0x20


def normalize(text: str) -> str:
    """Collapse every whitespace run to a single space and trim the ends.

    ``str.split`` rather than a regex: it is linear on any input with no backtracking to
    reason about, and it treats tabs, re-indentation and the trailing ``\\r`` of a CRLF
    paste identically.
    """
    return " ".join(text.split())


def line_similarity(quote: str, line: str) -> float:
    """How much a normalized ``quote`` looks like a normalized ``line``, in ``[0, 1]``.

    A quote contained in the line scores 1.0: reports routinely paste the interesting half
    of a statement (``memcpy(dst, value, len)`` for a line that ends in ``;``), and that is
    still a quote *of that line*. Everything else is rapidfuzz's indel ratio.
    """
    if quote and quote in line:
        return 1.0
    return fuzz.ratio(quote, line) / 100.0


@register
class LineContent(BaseCheck):
    id = CHECK_ID
    name = "LINE_CONTENT"
    group = GROUP
    applies_to: frozenset[ClaimKind] = frozenset({"line"})
    description = "Checks quoted line contents against the file at the resolved commit."

    def __init__(self, strengths: Strengths | None = None) -> None:
        self.strengths = strengths or default_strengths()

    def run(self, ctx: CheckContext, claims: Sequence[Claim]) -> list[Evidence]:
        out: list[Evidence] = []
        for claim in claims:
            if not isinstance(claim, LineClaim) or not claim.quoted_line:
                continue
            evidence = self._one(ctx, claim)
            if evidence is not None:
                out.append(evidence)
        return out

    # -- one claim -----------------------------------------------------------------------

    def _one(self, ctx: CheckContext, claim: LineClaim) -> Evidence | None:
        quote = normalize(claim.quoted_line or "")
        if len(quote) < MIN_QUOTE_CHARS or claim.line < 1:
            return None
        path: str | None = None
        if claim.path is not None:
            candidates = ctx.resolve_path(claim.path)
            if len(candidates) != 1:
                # Missing, or ambiguous: C02 owns that finding.
                return None
            path = candidates[0]
            generated = ctx.generated(path)
            if generated is not None:
                return self._evidence(
                    claim,
                    outcome="NEUTRAL",
                    strength=0.0,
                    summary=f"{path} is {generated.kind}, so its contents are not judged",
                    details={
                        "outcome": "generated",
                        "path": path,
                        "generated": generated.reason,
                        "quote": _clip(quote),
                    },
                )
            in_file = self._in_file(ctx, claim, path, quote)
            if in_file is not None:
                return in_file
        return self._elsewhere(ctx, claim, path, quote)

    # -- the claimed file at the ref ------------------------------------------------------

    def _in_file(
        self, ctx: CheckContext, claim: LineClaim, path: str, quote: str
    ) -> Evidence | None:
        """Exact, near, or elsewhere in the file; ``None`` when the file lacks the quote."""
        blob = ctx.resolution.repo.read_file(ctx.commit, path)
        if blob is None or b"\0" in blob[:4096]:
            return None  # absent, oversized or binary: there is nothing to compare
        lines = [normalize(line) for line in blob.decode("utf-8", "replace").splitlines()]
        where = ctx.ref_name or ctx.commit[:12]
        stated = claim.line

        if 1 <= stated <= len(lines):
            similarity = line_similarity(quote, lines[stated - 1])
            if similarity >= MATCH_RATIO:
                return self._evidence(
                    claim,
                    outcome="SUPPORTS",
                    strength=self.strengths.get(CHECK_ID, "exact"),
                    summary=f"{path}:{stated} at {where} is the quoted line",
                    details={
                        "outcome": "exact",
                        "path": path,
                        "line": stated,
                        "similarity": round(similarity, 4),
                        "quote": _clip(quote),
                    },
                    locations=[ctx.location(path, stated, excerpt=lines[stated - 1])],
                )

        near = self._nearest(lines, quote, stated)
        if near is not None:
            found, offset, similarity = near
            return self._evidence(
                claim,
                outcome="SUPPORTS",
                strength=self.strengths.get(CHECK_ID, "near_by_offset"),
                summary=f"the quoted line is {path}:{found} at {where},"
                f" {_offset_phrase(offset)} the cited line {stated}",
                details={
                    "outcome": "near_by_offset",
                    "path": path,
                    "line": stated,
                    "found_line": found,
                    "offset": offset,
                    "similarity": round(similarity, 4),
                    "quote": _clip(quote),
                },
                locations=[ctx.location(path, found, excerpt=lines[found - 1])],
            )

        matches = [
            number
            for number, line in enumerate(lines, start=1)
            if line_similarity(quote, line) >= MATCH_RATIO
        ]
        if not matches:
            return None
        listed = matches[:MAX_REPORTED_HITS]
        return self._evidence(
            claim,
            outcome="REFUTES",
            strength=self.strengths.get(CHECK_ID, "elsewhere_in_file"),
            summary=f"the quoted line is in {path} at {where}, but at"
            f" line{'s' if len(matches) > 1 else ''} {', '.join(str(n) for n in listed)},"
            f" not the cited line {stated}",
            details={
                "outcome": "elsewhere_in_file",
                "path": path,
                "line": stated,
                "scope": "same_file",
                "found_lines": listed,
                "match_count": len(matches),
                "quote": _clip(quote),
            },
            locations=[ctx.location(path, matches[0], excerpt=lines[matches[0] - 1])],
        )

    @staticmethod
    def _nearest(lines: list[str], quote: str, stated: int) -> tuple[int, int, float] | None:
        """The best match within ±:data:`NEAR_RADIUS` lines, as ``(line, offset, ratio)``.

        Offsets are visited nearest first and above before below, so ties resolve the same
        way on every run (P2).
        """
        best: tuple[int, int, float] | None = None
        for offset in sorted(range(-NEAR_RADIUS, NEAR_RADIUS + 1), key=lambda o: (abs(o), o)):
            number = stated + offset
            if offset == 0 or not 1 <= number <= len(lines):
                continue
            similarity = line_similarity(quote, lines[number - 1])
            if similarity >= MATCH_RATIO and (best is None or similarity > best[2]):
                best = (number, offset, similarity)
        return best

    # -- the rest of the tree, the other releases, then history ---------------------------

    def _elsewhere(
        self, ctx: CheckContext, claim: LineClaim, path: str | None, quote: str
    ) -> Evidence | None:
        """Search outwards: the whole tree at the ref, the other releases, then history."""
        text = searchable(claim.quoted_line or "")
        if text is None:
            return None  # empty, multi-line or over-long: not a searchable quote
        base: dict[str, Any] = {"path": path, "line": claim.line, "quote": _clip(quote)}
        where = ctx.ref_name or ctx.commit[:12]

        # ``literal_search`` hands back the equivalent command as a *string* only, so the
        # ref-level search stays in ``details['command']``; the release sweep and the
        # pickaxe below go through ``GitRepo`` directly and yield real records (P6).
        at_ref = literal_search(ctx.resolution.repo, text, ctx.commit)
        if at_ref is not None and at_ref.hits:
            return self._at_ref(ctx, claim, path, at_ref.hits, {**base, "command": at_ref.command})

        records: list[CommandRecord] = []
        found_in = self._other_releases(ctx, text, records)
        if found_in:
            return self._evidence(
                claim,
                outcome="REFUTES",
                strength=self.strengths.get(CHECK_ID, "other_release_only"),
                summary=f"the quoted line is not in the tree at {where};"
                f" it is in {', '.join(found_in[:MAX_REPORTED_HITS])}",
                details={**base, "outcome": "other_release_only", "found_in_releases": found_in},
                commands=records,
            )
        return self._history(ctx, claim, path, text, base, records=records)

    def _at_ref(
        self,
        ctx: CheckContext,
        claim: LineClaim,
        path: str | None,
        hits: Sequence[GrepHit],
        base: dict[str, Any],
    ) -> Evidence:
        """The text is at the ref; decide whether it is where the report puts it.

        Reached when the claimed file could not be compared line by line (oversized or
        binary), and for claims that name no file at all — there ``git grep`` is the only
        way to find the stated line.
        """
        where = ctx.ref_name or ctx.commit[:12]
        scoped = [hit for hit in hits if path is None or hit.path == path]
        nearest = min(
            scoped, key=lambda hit: (abs(hit.line - claim.line), hit.path, hit.line), default=None
        )
        if nearest is not None and abs(nearest.line - claim.line) <= NEAR_RADIUS:
            offset = nearest.line - claim.line
            exact = offset == 0
            key = "exact" if exact else "near_by_offset"
            return self._evidence(
                claim,
                outcome="SUPPORTS",
                strength=self.strengths.get(CHECK_ID, key),
                summary=f"{nearest.path}:{nearest.line} at {where} is the quoted line"
                + ("" if exact else f", {_offset_phrase(offset)} the cited line {claim.line}"),
                details={
                    **base,
                    "outcome": key,
                    "found_line": nearest.line,
                    "offset": offset,
                    "found_path": nearest.path,
                },
                locations=[ctx.location(nearest.path, nearest.line)],
            )

        places = sorted({f"{hit.path}:{hit.line}" for hit in hits})
        if path is None:
            # Without a claimed path there is nothing to contradict: a line number alone
            # cannot be wrong about a file the report never named (ADR 0003).
            return self._evidence(
                claim,
                outcome="NEUTRAL",
                strength=self.strengths.get(CHECK_ID, "elsewhere_in_file"),
                summary=f"the quoted line is at {where} in {', '.join(places[:MAX_REPORTED_HITS])},"
                f" but the report names no file, so its line {claim.line} is not judged",
                details={
                    **base,
                    "outcome": "elsewhere_in_file",
                    "scope": "no_path",
                    "found_at": places[:MAX_REPORTED_HITS],
                    "match_count": len(places),
                },
            )
        first = min(hits, key=lambda hit: (hit.path, hit.line))
        return self._evidence(
            claim,
            outcome="REFUTES",
            strength=self.strengths.get(CHECK_ID, "elsewhere_in_file"),
            summary=f"the quoted line is at {where} in"
            f" {', '.join(places[:MAX_REPORTED_HITS])}, not at {path}:{claim.line}",
            details={
                **base,
                "outcome": "elsewhere_in_file",
                "scope": "same_file" if scoped else "other_file",
                "found_at": places[:MAX_REPORTED_HITS],
                "match_count": len(places),
            },
            locations=[ctx.location(first.path, first.line, excerpt=first.text.strip() or None)],
        )

    def _other_releases(
        self, ctx: CheckContext, text: str, records: list[CommandRecord]
    ) -> list[str]:
        """Release names whose tree holds ``text``, sorted; empty when the budget is spent."""
        by_commit = {
            release.commit: release.name
            for release in ctx.resolution.releases.finals()
            if release.commit != ctx.commit
        }
        if not by_commit or ctx.expired():
            return []
        hits = ctx.resolution.repo.grep(text, sorted(by_commit), files_only=True, record=records)
        return sorted({by_commit[hit.rev] for hit in hits if hit.rev in by_commit})

    def _history(
        self,
        ctx: CheckContext,
        claim: LineClaim,
        path: str | None,
        text: str,
        base: dict[str, Any],
        *,
        records: list[CommandRecord],
    ) -> Evidence:
        """The last rung: only a search that truly finished may say "nowhere" (P4)."""
        where = ctx.ref_name or ctx.commit[:12]
        reason = self._history_blocker(ctx, path, text)
        if reason is None:
            try:
                first = ctx.resolution.repo.pickaxe_first(
                    text, timeout=self._budget(ctx), record=records
                )
            except HistoryTimeoutError:
                reason = "the history search timed out"
            else:
                return self._searched_history(ctx, claim, first, base, records)
        # P4: an inconclusive search is not evidence of invention. Say what was and was not
        # searched; the fuser sees the withheld strength without being able to count it.
        return self._evidence(
            claim,
            outcome="NEUTRAL",
            strength=self.strengths.get(CHECK_ID, "nowhere_in_history"),
            summary=f"the quoted line is not at {where} or in any other release,"
            f" but {reason}, so it is not called absent",
            details={
                **base,
                "outcome": "nowhere_in_history",
                "history_complete": False,
                "incomplete": reason,
            },
            commands=records,
        )

    def _searched_history(
        self,
        ctx: CheckContext,
        claim: LineClaim,
        first: str | None,
        base: dict[str, Any],
        records: list[CommandRecord],
    ) -> Evidence:
        where = ctx.ref_name or ctx.commit[:12]
        if first is not None:
            # In history but in no release tree: a development-only line, which is still a
            # version finding rather than an invented one.
            return self._evidence(
                claim,
                outcome="REFUTES",
                strength=self.strengths.get(CHECK_ID, "other_release_only"),
                summary=f"the quoted line is in no release tree, including {where};"
                f" history has it only in {first[:12]} and its neighbours",
                details={
                    **base,
                    "outcome": "other_release_only",
                    "found_in_releases": [],
                    "first_commit_with_text": first,
                },
                commands=records,
            )
        return self._evidence(
            claim,
            outcome="REFUTES",
            strength=self.strengths.get(CHECK_ID, "nowhere_in_history"),
            summary=f"the quoted line is not at {where}, in any other release, or anywhere"
            " in the repository's history",
            details={
                **base,
                "outcome": "nowhere_in_history",
                "history_complete": True,
                "never_in_history": True,
            },
            commands=records,
        )

    @staticmethod
    def _history_blocker(ctx: CheckContext, path: str | None, text: str) -> str | None:
        """Why "nowhere in history" may not be attempted at all, or ``None`` if it may."""
        if path is None:
            # ADR 0003: the strong refutation needs a location the reporter attributed to
            # the project, not a quote floating free of any file.
            return "the report names no file for it"
        if any(ord(char) < MIN_PRINTABLE for char in text):
            return "the quote holds control characters that a pickaxe cannot search for"
        if ctx.resolution.repo.is_shallow():
            return "the clone is shallow"
        if ctx.expired() or LineContent._budget(ctx) < MIN_HISTORY_BUDGET_S:
            return "there was no time left to search history"
        return None

    @staticmethod
    def _budget(ctx: CheckContext) -> float:
        """Seconds the pickaxe may take: its own cap, inside whatever the check has left."""
        if ctx.deadline is None:
            return ctx.history_timeout
        return min(ctx.history_timeout, max(0.0, ctx.deadline - time.monotonic()))

    # -- construction ---------------------------------------------------------------------

    def _evidence(
        self,
        claim: LineClaim,
        *,
        outcome: Outcome,
        strength: float,
        summary: str,
        details: dict[str, Any],
        locations: Sequence[CodeLocation] = (),
        commands: Sequence[CommandRecord] = (),
    ) -> Evidence:
        return make_evidence(
            check_id=CHECK_ID,
            group=GROUP,
            claims=[claim],
            outcome=outcome,
            strength=strength,
            summary=summary,
            details=details,
            locations=locations,
            commands=commands,
        )


def _offset_phrase(offset: int) -> str:
    return (
        f"{abs(offset)} line{'s' if abs(offset) != 1 else ''} {'below' if offset > 0 else 'above'}"
    )


def _clip(quote: str) -> str:
    return quote[:MAX_QUOTE_CHARS]
