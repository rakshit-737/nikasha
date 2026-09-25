# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""C20 LLM_REVIEW: an optional model's reading of a behavior claim (SPEC §12, §16.6).

Off by default, and inert until the pipeline attaches a provider to the context
(``ctx.llm``). The deterministic core already locates a behavior claim's subject and
settles ``calls_api`` (C18); the other four predicates — a missing bounds check, a missing
NULL check, a use after free, an integer overflow — need a reading of the code that a
name-based call graph cannot give. This check shows the model the subject's definition,
numbered, at the resolved commit, and asks one question about it.

What comes back is advisory, in three enforced ways:

* every prompt and answer goes through :mod:`nikasha.llm.guard`: delimited data, schema
  validation, cited lines and quotes checked against the excerpt, and the SHA-256 of both
  the prompt and the response recorded in the evidence;
* |strength| is capped at ``C20.llm_cap`` and never above 0.5, whichever is lower — under
  every verdict threshold, so a model can tilt a score but never decide a verdict (P2);
* a refutation still passes the ADR 0003 gate in :func:`make_evidence`, and a model that
  cannot be reached yields ``ERROR`` evidence with strength 0, never a refutation (P4).

Symbols the tree does not define, and generated files, are never sent anywhere: there is
nothing to review, and the deterministic checks own those findings.
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from typing import Any

from nikasha.checks.base import BaseCheck, CheckContext, make_evidence, register
from nikasha.checks.strengths import Strengths, default_strengths
from nikasha.code.facts import SymbolDef
from nikasha.llm.guard import (
    DEFAULT_MAX_TOKENS,
    DEFAULT_TIMEOUT_S,
    Excerpt,
    GuardedReview,
    ReviewRequest,
    review,
    strength_cap,
)
from nikasha.llm.provider import LLMError, LLMProvider
from nikasha.model.claims import BehaviorClaim, Claim, ClaimKind
from nikasha.model.evidence import CodeLocation, Evidence, Outcome

CHECK_ID = "C20"
GROUP = "llm"

#: Lines of context shown around the subject's definition.
CONTEXT_LINES = 3
#: Definitions sent per claim (a name defined in more files than this is rare, and a
#: prompt is not the place to settle which one the report meant).
MAX_SITES = 3
#: Lines per excerpt; a longer function is cut and the model is told so.
MAX_EXCERPT_LINES = 160
#: Characters per excerpt line (minified or generated-looking lines are cut, not dropped).
MAX_LINE_CHARS = 300
#: Characters of the report sentence shown to the model.
MAX_CLAIM_CHARS = 500
#: A request with less budget than this left is not worth starting.
MIN_TIMEOUT_S = 1.0

#: What each predicate asserts, in the words the prompt and the summary use.
PREDICATE_PROSE: dict[str, str] = {
    "calls_api": "the claimed call",
    "missing_bounds_check": "a missing bounds check",
    "missing_null_check": "a missing NULL check",
    "uses_freed": "a use after free",
    "integer_overflow": "an integer overflow",
}

#: The guard's verdict, mapped onto evidence outcomes and the strengths-table key.
OUTCOMES: dict[str, tuple[Outcome, str]] = {
    "supported": ("SUPPORTS", "supported"),
    "refuted": ("REFUTES", "refuted"),
    "unclear": ("NEUTRAL", "unclear"),
}


@register
class LlmReview(BaseCheck):
    id = CHECK_ID
    name = "LLM_REVIEW"
    group = GROUP
    applies_to: frozenset[ClaimKind] = frozenset({"behavior"})
    description = (
        "Asks the optional model whether the subject's code at the resolved commit shows the"
        " claimed behavior; capped at |0.5| and never decisive."
    )

    def __init__(
        self,
        strengths: Strengths | None = None,
        *,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        timeout: float = DEFAULT_TIMEOUT_S,
    ) -> None:
        self.strengths = strengths or default_strengths()
        self.max_tokens = max_tokens
        self.timeout = timeout

    def cap(self) -> float:
        """The effective |strength| ceiling: ``C20.llm_cap``, never above 0.5."""
        return strength_cap(self.strengths.get(CHECK_ID, "llm_cap"))

    def run(self, ctx: CheckContext, claims: Sequence[Claim]) -> list[Evidence]:
        provider: LLMProvider | None = getattr(ctx, "llm", None)
        if provider is None:
            return []
        cap = self.cap()
        out: list[Evidence] = []
        for claim in claims:
            if not isinstance(claim, BehaviorClaim):
                continue
            if ctx.expired():  # each claim is one model round trip; the budget is real
                break
            out.append(self._one(ctx, provider, claim, cap))
        return out

    # -- one claim -----------------------------------------------------------------------

    def _one(
        self, ctx: CheckContext, provider: LLMProvider, claim: BehaviorClaim, cap: float
    ) -> Evidence:
        sites = _sites(ctx, claim.subject_symbol)
        locations = [ctx.location(path, s.start_line, s.end_line) for path, s in sites]
        subject = claim.subject_symbol
        if not sites:
            return self._skipped(
                claim,
                f"{subject} is not defined at {_at(ctx)}, so there is nothing for the model"
                " to review",
                {"suggestions": ctx.suggest_symbols(subject)},
                locations,
            )
        for path, _symbol in sites:
            generated = ctx.generated(path)
            if generated is not None:
                return self._skipped(
                    claim,
                    f"{subject} is defined in {path}, which is {generated.kind}, so its code"
                    " is not judged",
                    {"path": path, "generated": generated.reason},
                    locations,
                )
        excerpts = tuple(
            excerpt
            for excerpt in (_excerpt(ctx, path, s) for path, s in sites[:MAX_SITES])
            if excerpt is not None
        )
        if not excerpts:
            return self._skipped(
                claim,
                f"the definition of {subject} at {_at(ctx)} could not be read, so there is"
                " nothing for the model to review",
                {"paths": [path for path, _ in sites]},
                locations,
            )
        request = ReviewRequest(
            subject=subject,
            predicate=claim.predicate,
            prose=PREDICATE_PROSE[claim.predicate],
            claim_text=_claim_text(claim),
            excerpts=excerpts,
            commit=ctx.commit,
            object=claim.object,
        )
        try:
            guarded = review(
                provider,
                request,
                cap=cap,
                max_tokens=self.max_tokens,
                timeout=self._timeout(ctx),
            )
        except LLMError as exc:
            return self._failed(claim, provider, exc, locations)
        return self._judged(ctx, claim, guarded, excerpts, locations)

    def _judged(
        self,
        ctx: CheckContext,
        claim: BehaviorClaim,
        guarded: GuardedReview,
        excerpts: Sequence[Excerpt],
        locations: Sequence[CodeLocation],
    ) -> Evidence:
        outcome, key = OUTCOMES[guarded.verdict]
        prose = PREDICATE_PROSE[claim.predicate]
        subject, at = claim.subject_symbol, _at(ctx)
        cited = _cited_locations(ctx, guarded.cited_lines, excerpts)
        lines = ", ".join(str(n) for n in guarded.cited_lines) or "none"
        if guarded.downgraded is not None:
            summary = f"the model review of {subject} at {at} is not counted: {guarded.downgraded}"
        elif guarded.verdict == "supported":
            summary = (
                f"model review: the excerpt of {subject} at {at} shows {prose}"
                f" (lines {lines}); advisory only"
            )
        elif guarded.verdict == "refuted":
            summary = (
                f"model review: the excerpt of {subject} at {at} does not show {prose}"
                f" (lines {lines}); advisory only"
            )
        else:
            summary = f"model review: the excerpt of {subject} at {at} does not settle {prose}"
        evidence = make_evidence(
            check_id=CHECK_ID,
            group=GROUP,
            claims=[claim],
            outcome=outcome,
            strength=guarded.strength,
            summary=summary,
            details={
                "outcome": key,
                "subject": subject,
                "predicate": claim.predicate,
                "paths": sorted({excerpt.path for excerpt in excerpts}),
                **guarded.details(),
            },
            locations=_dedupe([*locations, *cited]),
        )
        return evidence.model_copy(update={"produced_by": "llm"})

    def _failed(
        self,
        claim: BehaviorClaim,
        provider: LLMProvider,
        exc: LLMError,
        locations: Sequence[CodeLocation],
    ) -> Evidence:
        """``ERROR`` at strength 0: a model that did not answer refutes nothing (P4)."""
        evidence = make_evidence(
            check_id=CHECK_ID,
            group=GROUP,
            claims=[claim],
            outcome="ERROR",
            strength=0.0,
            summary=f"the model review of {claim.subject_symbol} could not run: {exc}",
            details={
                "outcome": "error",
                "subject": claim.subject_symbol,
                "predicate": claim.predicate,
                "model": str(provider.name),
                "error": str(exc),
            },
            locations=locations,
        )
        return evidence.model_copy(update={"produced_by": "llm"})

    def _skipped(
        self,
        claim: BehaviorClaim,
        summary: str,
        details: dict[str, Any],
        locations: Sequence[CodeLocation],
    ) -> Evidence:
        """NEUTRAL without a model call: nothing was sent, so this stays deterministic."""
        return make_evidence(
            check_id=CHECK_ID,
            group=GROUP,
            claims=[claim],
            outcome="NEUTRAL",
            strength=0.0,
            summary=summary,
            details={
                "outcome": "skipped",
                "subject": claim.subject_symbol,
                "predicate": claim.predicate,
                **details,
            },
            locations=locations,
        )

    def _timeout(self, ctx: CheckContext) -> float:
        """The request timeout: the check's own default, shortened to the budget left.

        This is the one place the clock is read, and it only bounds how long a request may
        take; nothing about the verdict depends on it.
        """
        if ctx.deadline is None:
            return self.timeout
        remaining = ctx.deadline - time.monotonic()
        return max(MIN_TIMEOUT_S, min(self.timeout, remaining))


# --- helpers ---------------------------------------------------------------------------------


def _sites(ctx: CheckContext, name: str) -> list[tuple[str, SymbolDef]]:
    """Every function-like definition of ``name`` at the commit, ordered by path and line."""
    found = [
        (path, symbol)
        for path, symbol in ctx.index.definitions(ctx.commit, name)
        if symbol.kind in ("function", "method")
    ]
    return sorted(found, key=lambda site: (site[0], site[1].start_line))


def _excerpt(ctx: CheckContext, path: str, symbol: SymbolDef) -> Excerpt | None:
    """The definition with a little context, numbered from the real file, or ``None``."""
    entry = ctx.index.file_at(ctx.commit, path)
    if entry is None:
        return None
    blob = ctx.resolution.repo.read_blob(entry.blob)
    if blob is None:
        return None
    lines = blob.decode("utf-8", "replace").splitlines()
    start = max(1, symbol.start_line - CONTEXT_LINES)
    end = min(len(lines), symbol.end_line + CONTEXT_LINES)
    if end < start:
        return None
    selected = lines[start - 1 : end]
    truncated = len(selected) > MAX_EXCERPT_LINES
    if truncated:
        selected = selected[:MAX_EXCERPT_LINES]
    return Excerpt(
        path=path,
        start_line=start,
        lines=tuple(line[:MAX_LINE_CHARS] for line in selected),
        truncated=truncated,
    )


def _claim_text(claim: BehaviorClaim) -> str:
    """The report sentence(s) the claim came from, clipped."""
    return " ".join(span.text for span in claim.spans)[:MAX_CLAIM_CHARS]


def _cited_locations(
    ctx: CheckContext, cited: Sequence[int], excerpts: Sequence[Excerpt]
) -> list[CodeLocation]:
    """One location per excerpt that shows a cited line, carrying the line's text.

    The model cites bare line numbers. When excerpts from two files both show a number,
    nothing says which file was meant, so every candidate is cited rather than guessing
    the first one and pointing the reader at the wrong code (P6).
    """
    out: list[CodeLocation] = []
    for number in cited:
        for excerpt in excerpts:
            if excerpt.has_line(number):
                out.append(ctx.location(excerpt.path, number, excerpt=excerpt.line(number)))
    return out


def _at(ctx: CheckContext) -> str:
    return ctx.ref_name or ctx.commit[:12]


def _dedupe(locations: Sequence[CodeLocation]) -> list[CodeLocation]:
    by_span = {(loc.path, loc.start_line, loc.end_line): loc for loc in locations}
    return [by_span[key] for key in sorted(by_span)]
