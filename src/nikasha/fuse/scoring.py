# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Evidence fusion: log-odds with group damping (SPEC §14.1).

Each piece of evidence carries a natural-log likelihood ratio. Summing them naively would
let one fabricated trace count as ten independent findings, so evidence is **damped within
its group**: sorted by |strength| descending and weighted 1, 1/2, 1/4, ... The first
finding in a group counts fully, the second half as much, and a pile of correlated
findings cannot manufacture certainty.

``lambda`` is the total log-odds; the grounding score is ``round(100 * sigmoid(lambda))``.
Every step is recorded in a :class:`Ledger` so ``nikasha explain`` can print the arithmetic
line by line (P6): a verdict nobody can audit is not evidence.
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from nikasha.model.evidence import Evidence

#: The prior log-odds before any evidence. 0.0 means "no opinion" (SPEC §14.1); a project
#: may set its own from its historical rate of valid reports.
DEFAULT_PRIOR = 0.0

#: Weight of the i-th strongest piece of evidence within one group.
DAMPING_BASE = 0.5

#: Confidence bands (SPEC §14.3): "high" needs both a large |lambda| and several groups.
HIGH_LOG_ODDS = 4.0
HIGH_GROUPS = 3
MEDIUM_LOG_ODDS = 2.0


@dataclass(frozen=True, slots=True)
class Contribution:
    """One piece of evidence's damped contribution to the total log-odds."""

    evidence_id: str
    check_id: str
    group: str
    strength: float
    rank: int
    weight: float
    contribution: float


@dataclass(frozen=True, slots=True)
class Ledger:
    """The full arithmetic behind a score, in the order it was applied."""

    prior: float
    contributions: tuple[Contribution, ...]
    log_odds: float
    score: int
    calibration: str = "defaults-v1"

    @property
    def groups(self) -> tuple[str, ...]:
        """The groups that actually moved the score, sorted."""
        return tuple(sorted({c.group for c in self.contributions if c.contribution != 0.0}))

    @property
    def total_absolute(self) -> float:
        """``sum |strength|`` over scoring evidence, before damping (SPEC §14.3 rule 6)."""
        return sum(abs(c.strength) for c in self.contributions)

    def running(self) -> list[tuple[Contribution, float]]:
        """Each contribution with the running log-odds after it, for the explain view."""
        out: list[tuple[Contribution, float]] = []
        total = self.prior
        for contribution in self.contributions:
            total += contribution.contribution
            out.append((contribution, total))
        return out


def sigmoid(x: float) -> float:
    """The logistic function, written to not overflow on large negative input."""
    if x >= 0.0:
        return 1.0 / (1.0 + math.exp(-x))
    exp_x = math.exp(x)
    return exp_x / (1.0 + exp_x)


def scoring_evidence(evidence: Iterable[Evidence]) -> list[Evidence]:
    """The evidence that may move the score: non-zero strength, and not an error.

    ``NEUTRAL`` and ``ERROR`` items are kept in the result for the reader, but they never
    contribute, and they must not consume a damping slot — otherwise an informational
    finding would silently halve the weight of a real one.
    """
    return [e for e in evidence if e.strength != 0.0 and e.outcome in {"SUPPORTS", "REFUTES"}]


def fuse(
    evidence: Sequence[Evidence],
    *,
    prior: float = DEFAULT_PRIOR,
    calibration: str = "defaults-v1",
) -> Ledger:
    """Combine ``evidence`` into a :class:`Ledger`. Deterministic for a given input set."""
    scoring = scoring_evidence(evidence)
    by_group: dict[str, list[Evidence]] = {}
    for item in scoring:
        by_group.setdefault(item.group, []).append(item)

    contributions: list[Contribution] = []
    for group in sorted(by_group):
        # Strongest first; ties broken by evidence ID so the order never depends on how
        # the checks happened to be scheduled.
        ranked = sorted(by_group[group], key=lambda e: (-abs(e.strength), e.id))
        for rank, item in enumerate(ranked):
            weight = DAMPING_BASE**rank
            contributions.append(
                Contribution(
                    evidence_id=item.id,
                    check_id=item.check_id,
                    group=group,
                    strength=item.strength,
                    rank=rank,
                    weight=weight,
                    contribution=round(item.strength * weight, 6),
                )
            )

    log_odds = round(prior + sum(c.contribution for c in contributions), 6)
    return Ledger(
        prior=prior,
        contributions=tuple(contributions),
        log_odds=log_odds,
        score=round(100 * sigmoid(log_odds)),
        calibration=calibration,
    )


def confidence_of(ledger: Ledger) -> str:
    """``high`` when the evidence is both strong and varied, else ``medium``/``low``.

    Requiring three groups for "high" is deliberate: a large lambda from a single group is
    exactly the correlated-evidence case damping is meant to distrust.
    """
    magnitude = abs(ledger.log_odds)
    if magnitude >= HIGH_LOG_ODDS and len(ledger.groups) >= HIGH_GROUPS:
        return "high"
    if magnitude >= MEDIUM_LOG_ODDS:
        return "medium"
    return "low"
