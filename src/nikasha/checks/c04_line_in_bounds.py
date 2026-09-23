# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""C04 LINE_IN_BOUNDS: is a cited line inside the file at the claimed version? (SPEC §12)

A line past the end of the file is one of the few unambiguous signals: a report citing
``http.c:2143`` when that file has 1,944 lines at the claimed tag is wrong about something
concrete. The check says so with the real length, never more.

Files the file-level checks already own are left alone: a path that does not resolve is
C02's finding, not a second refutation here (that double-counting is exactly what group
damping in SPEC §14.1 exists to stop, and this check avoids creating it at all).
"""

from __future__ import annotations

from collections.abc import Sequence

from nikasha.checks.base import BaseCheck, CheckContext, make_evidence, register
from nikasha.checks.strengths import Strengths, default_strengths
from nikasha.model.claims import Claim, ClaimKind, LineClaim
from nikasha.model.evidence import Evidence

CHECK_ID = "C04"
GROUP = "lines"


@register
class LineInBounds(BaseCheck):
    id = CHECK_ID
    name = "LINE_IN_BOUNDS"
    group = GROUP
    applies_to: frozenset[ClaimKind] = frozenset({"line"})
    description = "Checks that a cited line number exists in the file at the resolved commit."

    def __init__(self, strengths: Strengths | None = None) -> None:
        self.strengths = strengths or default_strengths()

    def run(self, ctx: CheckContext, claims: Sequence[Claim]) -> list[Evidence]:
        out: list[Evidence] = []
        for claim in claims:
            if not isinstance(claim, LineClaim):
                continue
            evidence = self._one(ctx, claim)
            if evidence is not None:
                out.append(evidence)
        return out

    def _one(self, ctx: CheckContext, claim: LineClaim) -> Evidence | None:
        if claim.path is None or claim.line < 1:
            return None
        candidates = ctx.resolve_path(claim.path)
        if len(candidates) != 1:
            # Missing, or ambiguous: C02 owns that finding.
            return None
        path = candidates[0]
        generated = ctx.generated(path)
        if generated is not None:
            return make_evidence(
                check_id=CHECK_ID,
                group=GROUP,
                claims=[claim],
                outcome="NEUTRAL",
                strength=0.0,
                summary=f"{path} is {generated.kind}, so its line numbers are not judged",
                details={"outcome": "generated", "path": path, "generated": generated.reason},
            )
        n_lines = ctx.line_count(path)
        if n_lines is None:
            return None
        cited = claim.end_line if claim.end_line is not None else claim.line
        if cited <= n_lines:
            return make_evidence(
                check_id=CHECK_ID,
                group=GROUP,
                claims=[claim],
                outcome="SUPPORTS",
                strength=self.strengths.get(CHECK_ID, "in_bounds"),
                summary=f"{path} has {n_lines} lines at {ctx.ref_name or ctx.commit[:12]};"
                f" line {cited} is inside it",
                details={"outcome": "in_bounds", "path": path, "line": cited, "n_lines": n_lines},
                locations=[ctx.location(path, claim.line, cited)],
            )
        return make_evidence(
            check_id=CHECK_ID,
            group=GROUP,
            claims=[claim],
            outcome="REFUTES",
            strength=self.strengths.get(CHECK_ID, "past_end"),
            summary=f"{path} has {n_lines} lines at {ctx.ref_name or ctx.commit[:12]};"
            f" the report cites line {cited}",
            details={
                "outcome": "past_end",
                "path": path,
                "line": cited,
                "n_lines": n_lines,
                "past_end_by": cited - n_lines,
            },
            locations=[ctx.location(path, max(1, n_lines))],
        )
