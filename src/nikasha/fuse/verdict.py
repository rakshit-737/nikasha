# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Verdict rules (SPEC §14.3): ordered, first match wins.

The rules are deliberately asymmetric. Calling a genuine report fabricated is the one
mistake this tool must not make (P4), so ``UNGROUNDED`` is the hardest verdict to reach:
it needs a low score *and* corroboration from several independent groups, because
slopcheck's negative result showed that any single structural signal fires on roughly as
many genuine reports as fabricated ones. ``MIXED`` and ``INSUFFICIENT`` are the honest
answers when the evidence does not separate, and they are where the reporter questions do
the real work.

Thresholds live in :class:`Thresholds` and are chosen during calibration (SPEC §14.2) so
that false ``UNGROUNDED`` on genuine reports stays at or below 1%.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from nikasha.checks.strengths import Strengths, default_strengths
from nikasha.fuse.scoring import Ledger, confidence_of
from nikasha.model.claims import Claim
from nikasha.model.evidence import Evidence
from nikasha.model.verdict import VerdictLabel

#: Check/outcome pairs that mean "the report is about a different version than it says".
#: Each one caps the verdict at MIXED (SPEC §14.3 rule 4) rather than refuting anything:
#: a trace that fits v1.1.0 exactly is usually a real bug with the wrong version in the
#: header, which is a question to ask, not a fabrication to allege.
VERSION_MISMATCH: frozenset[tuple[str, str]] = frozenset(
    {
        ("C10", "other_release_fits"),
        ("C12", "already_applied"),
        ("C12", "other_release_only"),
        ("C02", "missing_here_present_elsewhere"),
        ("C03", "absent_here_present_elsewhere"),
    }
)

#: Outcomes that assert a core locus never existed at all — the only refutations strong
#: enough to open the UNGROUNDED door (rule 3a).
NEVER_EXISTED: frozenset[tuple[str, str]] = frozenset(
    {
        ("C02", "never_in_history"),
        ("C03", "never_in_history_core"),
        ("C03", "never_in_history_supporting"),
        ("C06", "nowhere_in_history"),
        ("C07", "absent_everywhere"),
        ("C14", "never_in_history"),
    }
)

#: Claim kinds that make a report substantive enough to judge (rule 2).
SUBSTANTIVE_KINDS = frozenset({"trace", "snippet", "patch", "poc"})


@dataclass(frozen=True, slots=True)
class Thresholds:
    """Every number SPEC §14.3 makes configurable, in one place."""

    ungrounded_score: int = 15
    ungrounded_score_strict: int = 10
    ungrounded_core_strength: float = -2.0
    ungrounded_core_groups: int = 2
    ungrounded_strong_strength: float = -1.5
    ungrounded_strong_groups: int = 3
    grounded_score: int = 75
    grounded_max_refutation: float = -1.2
    min_checkable_claims: int = 2
    insufficient_total: float = 1.5


@dataclass(frozen=True, slots=True)
class Decision:
    """The verdict plus the rule that produced it and why."""

    label: VerdictLabel
    score: int
    confidence: str
    rule: str
    notes: tuple[str, ...] = ()
    key_evidence: tuple[str, ...] = ()
    capped: bool = False
    triggers: tuple[str, ...] = field(default=())


def outcome_key(evidence: Evidence, strengths: Strengths | None = None) -> str | None:
    """The strengths-table key an evidence item came from.

    Checks record it in ``details['outcome']``. When an older item does not carry it, fall
    back to matching the strength against that check's row, which is unambiguous except
    for zero-strength outcomes.
    """
    recorded = evidence.details.get("outcome")
    if isinstance(recorded, str):
        return recorded
    table = (strengths or default_strengths()).outcomes(evidence.check_id)
    withheld = evidence.details.get("withheld_strength")
    target = withheld if isinstance(withheld, (int, float)) else evidence.strength
    matches = [key for key, value in table.items() if value == target]
    if len(matches) != 1:
        return None
    # A zero-strength outcome (C12's "already applied") carries no signal in its number,
    # so it is only identifiable when the check has exactly one such key. That is the case
    # today, but it is why every check should record its key explicitly.
    return matches[0]


def _refutations(evidence: Sequence[Evidence]) -> list[Evidence]:
    """Deterministic refutations only.

    A model's answer may nudge the score (capped at 0.5), but it must never count as an
    independent group toward UNGROUNDED: that would make the LLM decisive (P2, P4).
    """
    return [
        e
        for e in evidence
        if e.outcome == "REFUTES" and e.strength < 0.0 and e.produced_by == "deterministic"
    ]


def _groups(items: Sequence[Evidence]) -> set[str]:
    return {e.group for e in items}


def _reproduced(evidence: Sequence[Evidence]) -> Evidence | None:
    for item in evidence:
        if (
            item.check_id == "C19"
            and item.outcome == "SUPPORTS"
            and item.produced_by == "deterministic"
            and outcome_key(item) == "signature_match"
        ):
            return item
    return None


def _version_mismatches(evidence: Sequence[Evidence], strengths: Strengths) -> list[Evidence]:
    out = [
        item
        for item in evidence
        if (item.check_id, outcome_key(item, strengths) or "") in VERSION_MISMATCH
    ]
    return sorted(out, key=lambda e: e.id)


def decide(  # noqa: PLR0911 - SPEC §14.3 is an ordered ladder; one return per rule is the point
    ledger: Ledger,
    evidence: Sequence[Evidence],
    claims: Sequence[Claim],
    *,
    thresholds: Thresholds | None = None,
    strengths: Strengths | None = None,
) -> Decision:
    """Apply SPEC §14.3 in order and return the first rule that matches."""
    limits = thresholds or Thresholds()
    table = strengths or default_strengths()
    score = ledger.score
    confidence = confidence_of(ledger)
    notes: list[str] = []

    # Rule 1: a reproduced crash settles it.
    reproduced = _reproduced(evidence)
    if reproduced is not None:
        return Decision(
            label="REPRODUCED",
            score=score,
            confidence="high",
            rule="1: the PoC reproduced the claimed crash signature",
            key_evidence=(reproduced.id,),
        )

    # Rule 2: too little to judge.
    checkable = {cid for item in evidence if item.outcome != "ERROR" for cid in item.claim_ids}
    substantive = any(claim.kind in SUBSTANTIVE_KINDS for claim in claims)
    if len(checkable) < limits.min_checkable_claims and not substantive:
        return Decision(
            label="INSUFFICIENT",
            score=score,
            confidence=confidence,
            rule="2: fewer than "
            f"{limits.min_checkable_claims} checkable claims, and no trace, snippet, "
            "patch or PoC",
            notes=("There is not enough in the report to check against the code.",),
        )

    refutations = _refutations(evidence)
    mismatches = _version_mismatches(evidence, table)

    # Rule 3: UNGROUNDED, the hardest verdict to reach (P4).
    core_never = [
        item
        for item in refutations
        if (item.check_id, outcome_key(item, table) or "") in NEVER_EXISTED
        and item.strength <= limits.ungrounded_core_strength
    ]
    strong = [item for item in refutations if item.strength <= limits.ungrounded_strong_strength]
    rule_3a = (
        score < limits.ungrounded_score
        and bool(core_never)
        and len(_groups(refutations)) >= limits.ungrounded_core_groups
    )
    rule_3b = (
        score < limits.ungrounded_score_strict
        and len(_groups(strong)) >= limits.ungrounded_strong_groups
    )
    if rule_3a or rule_3b:
        which = "3a: a core locus that never existed, corroborated across groups"
        if not rule_3a:
            which = "3b: strong refutations from three or more independent groups"
        return Decision(
            label="UNGROUNDED",
            score=score,
            confidence=confidence,
            rule=which,
            key_evidence=tuple(sorted({e.id for e in (core_never or strong)})),
        )

    # Rule 4: a version mismatch can never be GROUNDED, only MIXED.
    if mismatches:
        return Decision(
            label="MIXED",
            score=score,
            confidence=confidence,
            rule="4: the evidence fits a different version than the report names",
            notes=(
                "The findings look like a real issue reported against the wrong version. "
                "Confirming the exact version would resolve this quickly.",
            ),
            key_evidence=tuple(e.id for e in mismatches),
            capped=True,
            triggers=tuple(sorted({f"{e.check_id}:{outcome_key(e, table)}" for e in mismatches})),
        )

    # Rule 5: GROUNDED needs a high score and no real refutation anywhere.
    worst = min((item.strength for item in evidence), default=0.0)
    if score >= limits.grounded_score and worst > limits.grounded_max_refutation:
        return Decision(
            label="GROUNDED",
            score=score,
            confidence=confidence,
            rule="5: a high grounding score with no substantial refutation",
            key_evidence=tuple(
                e.id for e in sorted(evidence, key=lambda e: (-e.strength, e.id))[:5]
            ),
        )

    # Rule 6: not enough total signal is INSUFFICIENT; anything else is MIXED.
    if ledger.total_absolute < limits.insufficient_total:
        return Decision(
            label="INSUFFICIENT",
            score=score,
            confidence=confidence,
            rule=f"6: the total evidence weight is below {limits.insufficient_total}",
            notes=("The claims that could be checked did not settle the question.",),
        )
    notes.append("Some claims check out and others do not.")
    return Decision(
        label="MIXED",
        score=score,
        confidence=confidence,
        rule="6: evidence on both sides",
        notes=tuple(notes),
        key_evidence=tuple(
            e.id for e in sorted(evidence, key=lambda e: (-abs(e.strength), e.id))[:5]
        ),
    )
