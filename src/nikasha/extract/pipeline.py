# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The extraction pipeline (SPEC §9 general rules; ADR 0003).

1. Run every registered extractor (a failing extractor becomes a warning, never a crash).
2. Merge claims that assert the same thing (same content ID, or same symbol name / path).
3. Drop mentions that sit inside a more specific claim (a path inside a trace or patch).
4. Scope, polarity and role passes.
5. Cap the claim count (500, SPEC §19.2) and sort deterministically.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import cast

from nikasha.extract.polarity import is_negated
from nikasha.extract.products import Product, product_table
from nikasha.extract.registry import EXTRACTORS, ExtractContext, claim_id
from nikasha.extract.roles import role_for
from nikasha.extract.scope import scope_claim
from nikasha.extract.spans import IntervalIndex
from nikasha.extract.symbols import KIND_PRIORITY
from nikasha.model.claims import (
    NON_IDENTITY_FIELDS,
    Claim,
    ClaimBase,
    FileClaim,
    OptionClaim,
    PatchClaim,
    Provenance,
    SymbolClaim,
    TraceClaim,
)
from nikasha.model.report import Report, Span

MAX_CLAIMS = 500

_PROVENANCE_RANK: dict[Provenance, int] = {
    "project_attributed": 0,
    "unscoped": 1,
    "reporter_artifact": 2,
    "third_party": 3,
}


@dataclass(frozen=True, slots=True)
class Extraction:
    claims: tuple[Claim, ...]
    warnings: tuple[str, ...]


def _union_spans(claims: list[ClaimBase]) -> tuple[Span, ...]:
    """All spans, sorted, dropping any span that overlaps one already kept.

    Sorted by start, kept spans are disjoint, so only the last kept span can overlap the next
    candidate: ``O(n log n)``.
    """
    kept: list[Span] = []
    for span in sorted((s for c in claims for s in c.spans), key=lambda s: (s.start, -s.end)):
        if not kept or kept[-1].end <= span.start:
            kept.append(span)
    return tuple(kept)


def _best_provenance(claims: list[ClaimBase]) -> Provenance:
    return min((c.provenance for c in claims), key=_PROVENANCE_RANK.__getitem__)


def _merge_group(group: list[ClaimBase]) -> ClaimBase:
    first = min(group, key=lambda c: (c.extractor, c.id))
    update: dict[str, object] = {
        "spans": _union_spans(group),
        "confidence": max(c.confidence for c in group),
        "provenance": _best_provenance(group),
    }
    if isinstance(first, SymbolClaim):
        symbols = [c for c in group if isinstance(c, SymbolClaim)]
        update["symbol_kind_hint"] = min(
            (s.symbol_kind_hint for s in symbols), key=KIND_PRIORITY.__getitem__
        )
        update["context_path"] = next((s.context_path for s in symbols if s.context_path), None)
        update["external"] = any(s.external for s in symbols)
        update["extractor"] = min(s.extractor for s in symbols)
    merged = first.model_copy(update=update)
    payload = merged.model_dump(mode="json", exclude=set(NON_IDENTITY_FIELDS))
    kind = str(payload.pop("kind"))
    return merged.model_copy(update={"id": claim_id(kind, payload)})


def merge(claims: list[ClaimBase]) -> list[ClaimBase]:
    """Symbols merge by name, files by path, everything else by content ID."""
    groups: dict[tuple[str, str], list[ClaimBase]] = defaultdict(list)
    for c in claims:
        if isinstance(c, SymbolClaim):
            key = ("symbol", c.name)
        elif isinstance(c, FileClaim):
            key = ("file", c.path)
        else:
            key = ("id", c.id)
        groups[key].append(c)
    return [_merge_group(g) if len(g) > 1 else g[0] for g in groups.values()]


def drop_contained(claims: list[ClaimBase]) -> list[ClaimBase]:
    """Remove mentions that sit inside a trace or patch claim, and symbols that are really
    project constants already captured as option claims."""
    containers = IntervalIndex(
        [
            (s.start, s.end)
            for c in claims
            if isinstance(c, (TraceClaim, PatchClaim))
            for s in c.spans
        ]
    )
    option_spans = IntervalIndex(
        [(s.start, s.end) for c in claims if isinstance(c, OptionClaim) for s in c.spans]
    )
    out: list[ClaimBase] = []
    for c in claims:
        if isinstance(c, (TraceClaim, PatchClaim)):
            out.append(c)
            continue
        spans = [s for s in c.spans if not containers.contains((s.start, s.end))]
        if isinstance(c, SymbolClaim):
            spans = [s for s in spans if not option_spans.overlaps((s.start, s.end))]
        if not spans:
            continue
        out.append(
            c if len(spans) == len(c.spans) else c.model_copy(update={"spans": tuple(spans)})
        )
    return out


def _sort_key(c: ClaimBase) -> tuple[int, int, str, str]:
    return (c.spans[0].start, c.spans[0].end, str(getattr(c, "kind", "")), c.id)


def extract_claims(
    report: Report,
    *,
    product: str | None = None,
    products: tuple[Product, ...] | None = None,
) -> Extraction:
    """Run the full extraction pipeline on ``report``. Deterministic: the same report always
    yields the same claims in the same order."""
    ctx = ExtractContext(report=report, product_hint=product, products=products or product_table())
    warnings: list[str] = []
    raw: list[ClaimBase] = []
    for name in sorted(EXTRACTORS):
        try:
            raw.extend(EXTRACTORS[name](ctx))
        except Exception as exc:
            warnings.append(f"extractor {name} failed: {type(exc).__name__}: {exc}")
    claims = drop_contained(merge(raw))
    scoped = [c.model_copy(update={"provenance": scope_claim(ctx, c, claims)}) for c in claims]
    negated = [c.model_copy(update={"negated": is_negated(report.body, c)}) for c in scoped]
    final = [c.model_copy(update={"role": role_for(ctx, c)}) for c in negated]
    final.sort(key=_sort_key)
    if len(final) > MAX_CLAIMS:
        warnings.append(f"claim count capped at {MAX_CLAIMS} (found {len(final)})")
        final = final[:MAX_CLAIMS]
    # Every element is one of the concrete claim classes that make up the ``Claim`` union.
    return Extraction(claims=cast("tuple[Claim, ...]", tuple(final)), warnings=tuple(warnings))
