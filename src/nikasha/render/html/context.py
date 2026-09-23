# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""What every HTML component is given, and what it must hand back (SPEC §15.2).

A component is a pure function ``(HtmlContext) -> Fragment``. It returns its markup plus
any CSS and JS it needs, and :mod:`nikasha.render.html.page` collects those into the one
stylesheet and the one script the page is allowed to have.

There is exactly one script element because the Content-Security-Policy pins it by hash
(``script-src 'sha256-…'``). A component that emits its own ``<script>`` tag, or an inline
``onclick=``, breaks the policy and the page stops working — so components return ``js``
and let the page assemble it.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from functools import cached_property

from nikasha.fuse.scoring import Ledger
from nikasha.model.claims import Claim
from nikasha.model.evidence import CodeLocation, Evidence
from nikasha.model.result import Result
from nikasha.model.verdict import Verdict

#: Numbered source lines for one location, or ``None`` when they cannot be read.
ExcerptProvider = Callable[[CodeLocation], Sequence[tuple[int, str]] | None]

#: How many lines of context to show around a cited line.
EXCERPT_CONTEXT = 4

#: The outcome each claim is drawn in. These are names, not colours: the palette lives in
#: CSS so the light and dark themes can differ.
OUTCOME_CLASS = {
    "SUPPORTS": "ok",
    "REFUTES": "bad",
    "NEUTRAL": "warn",
    "ERROR": "unknown",
}

#: Human labels for the check groups, in the order the evidence column shows them.
GROUP_ORDER = (
    "locus",
    "lines",
    "code_quotes",
    "trace",
    "trace_meta",
    "patch",
    "version",
    "behavior",
    "refs",
    "meta",
    "dynamic",
    "llm",
    "info",
)

GROUP_LABELS = {
    "locus": "Files and symbols",
    "lines": "Line numbers",
    "code_quotes": "Quoted code",
    "trace": "Stack trace",
    "trace_meta": "Sanitizer output",
    "patch": "Proposed patch",
    "version": "Versions",
    "behavior": "Described behaviour",
    "refs": "References",
    "meta": "Impact",
    "dynamic": "Reproduction",
    "llm": "Model review",
    "info": "For the maintainer",
}


@dataclass(frozen=True, slots=True)
class Fragment:
    """One component's contribution to the page."""

    html: str
    css: str = ""
    js: str = ""


@dataclass
class HtmlContext:
    """Everything a component may read. Built once per report."""

    result: Result
    ledger: Ledger | None = None
    excerpts: ExcerptProvider | None = None
    source: str = ""
    tool_version: str = ""
    _excerpt_cache: dict[tuple[str, str, int, int], Sequence[tuple[int, str]] | None] = field(
        default_factory=dict, repr=False
    )

    # --- the verdict --------------------------------------------------------------------

    @property
    def verdict(self) -> Verdict | None:
        return self.result.verdict

    @property
    def claims(self) -> tuple[Claim, ...]:
        return self.result.claims

    @property
    def evidence(self) -> tuple[Evidence, ...]:
        return self.result.evidence

    # --- lookups ------------------------------------------------------------------------

    @cached_property
    def by_id(self) -> dict[str, Evidence]:
        return {item.id: item for item in self.evidence}

    @cached_property
    def claim_by_id(self) -> dict[str, Claim]:
        return {claim.id: claim for claim in self.claims}

    @cached_property
    def by_claim(self) -> dict[str, list[Evidence]]:
        """Evidence about each claim, strongest first, then by ID for stability."""
        out: dict[str, list[Evidence]] = {}
        for item in self.evidence:
            for claim_id in item.claim_ids:
                out.setdefault(claim_id, []).append(item)
        for items in out.values():
            items.sort(key=lambda e: (-abs(e.strength), e.id))
        return out

    @cached_property
    def by_group(self) -> list[tuple[str, list[Evidence]]]:
        """Evidence grouped by check group, in :data:`GROUP_ORDER`, strongest first."""
        buckets: dict[str, list[Evidence]] = {}
        for item in self.evidence:
            buckets.setdefault(item.group, []).append(item)
        ordered = sorted(
            buckets,
            key=lambda g: (GROUP_ORDER.index(g) if g in GROUP_ORDER else len(GROUP_ORDER), g),
        )
        return [
            (group, sorted(buckets[group], key=lambda e: (-abs(e.strength), e.id)))
            for group in ordered
        ]

    def outcome_of(self, claim_id: str) -> str:
        """The outcome class for a claim: its strongest evidence decides."""
        items = self.by_claim.get(claim_id)
        if not items:
            return "unknown"
        decisive = min(items, key=lambda e: (-abs(e.strength), e.outcome != "REFUTES", e.id))
        return OUTCOME_CLASS.get(decisive.outcome, "unknown")

    def group_label(self, group: str) -> str:
        return GROUP_LABELS.get(group, group.replace("_", " ").title())

    # --- source excerpts ----------------------------------------------------------------

    def excerpt(self, location: CodeLocation) -> Sequence[tuple[int, str]] | None:
        """Numbered source lines for ``location``, cached per (commit, path, range).

        Falls back to the excerpt the check recorded. Returns ``None`` when neither is
        available, and components must render the card without code rather than failing:
        an offline report built from a JSON file has no repository to read.
        """
        key = (location.commit, location.path, location.start_line, location.end_line)
        if key in self._excerpt_cache:
            return self._excerpt_cache[key]
        lines: Sequence[tuple[int, str]] | None = None
        if self.excerpts is not None:
            lines = self.excerpts(location)
        if lines is None and location.excerpt:
            start = max(1, location.start_line)
            lines = [
                (start + offset, line) for offset, line in enumerate(location.excerpt.splitlines())
            ]
        self._excerpt_cache[key] = lines
        return lines


__all__ = [
    "EXCERPT_CONTEXT",
    "GROUP_LABELS",
    "GROUP_ORDER",
    "OUTCOME_CLASS",
    "ExcerptProvider",
    "Fragment",
    "HtmlContext",
]
