# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Extractor registry and claim construction (SPEC §9 general rules).

An extractor is a pure function ``(ExtractContext) -> list[Claim]``. Claim IDs are derived
from *what* a claim asserts (kind plus content fields), never from where it was found, so a
symbol mentioned five times becomes one claim with five spans, and IDs are identical
across runs.
"""

from __future__ import annotations

import bisect
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import cached_property
from typing import Any, TypeVar

from nikasha.extract.products import Product, alias_regex, product_table
from nikasha.extract.spans import IntervalIndex, Region, prose_regions, url_regions
from nikasha.model.claims import NON_IDENTITY_FIELDS, ClaimBase
from nikasha.model.ids import stable_id
from nikasha.model.report import Report, Span

ClaimT = TypeVar("ClaimT", bound=ClaimBase)


@dataclass(frozen=True)
class ExtractContext:
    """Everything an extractor may look at. Built once per report."""

    report: Report
    product_hint: str | None = None
    products: tuple[Product, ...] = field(default_factory=product_table)

    @cached_property
    def prose(self) -> list[Region]:
        return prose_regions(self.report)

    @cached_property
    def urls(self) -> list[Region]:
        return url_regions(self.report)

    @cached_property
    def url_index(self) -> IntervalIndex:
        return IntervalIndex(self.urls)

    @cached_property
    def block_index(self) -> list[tuple[int, int, str]]:
        """``(start, end, role)`` of every code block, sorted by start."""
        return sorted((b.span.start, b.span.end, b.role_guess) for b in self.report.code_blocks)

    def block_role_at(self, region: Region) -> str | None:
        """Role of the code block that contains ``region``, if any (``O(log n)``)."""
        blocks = self.block_index
        i = bisect.bisect_right(blocks, (region[0], float("inf"), "")) - 1
        if i >= 0 and blocks[i][0] <= region[0] and region[1] <= blocks[i][1]:
            return blocks[i][2]
        return None

    @cached_property
    def alias_re(self) -> re.Pattern[str]:
        return alias_regex(self.products)

    @cached_property
    def attribution_re(self) -> re.Pattern[str]:
        """Product aliases *and* the programs they ship (``hdrcat``, ``xmllint``)."""
        words = sorted(
            {a for p in self.products for a in (*p.aliases, *p.programs)},
            key=lambda w: (-len(w), w),
        )
        if self.product_hint:
            words.append(self.product_hint)
        alternation = "|".join(re.escape(w) for w in words)
        return re.compile(rf"(?<![\w.-])(?:{alternation})(?![\w-])", re.IGNORECASE)

    @cached_property
    def product_names(self) -> tuple[str, ...]:
        names = {p.name for p in self.products}
        if self.product_hint:
            names.add(self.product_hint)
        return tuple(sorted(names))


def claim_id(kind: str, fields: dict[str, Any]) -> str:
    identity = {k: v for k, v in fields.items() if k not in NON_IDENTITY_FIELDS and k != "kind"}
    return stable_id(f"claim:{kind}", identity)


def make_claim(
    cls: type[ClaimT],
    *,
    spans: list[Span] | tuple[Span, ...],
    extractor: str,
    confidence: float,
    **fields: object,
) -> ClaimT:
    """Construct a claim of ``cls`` whose ID is derived from its full content."""
    claim = cls.model_validate(
        {
            "id": "0" * 12,
            "spans": tuple(spans),
            "extractor": f"deterministic:{extractor}",
            "confidence": confidence,
            **fields,
        }
    )
    payload = claim.model_dump(mode="json", exclude=set(NON_IDENTITY_FIELDS))
    kind = str(payload.pop("kind"))
    return claim.model_copy(update={"id": claim_id(kind, payload)})


Extractor = Callable[[ExtractContext], list[Any]]

EXTRACTORS: dict[str, Extractor] = {}


def register(name: str) -> Callable[[Extractor], Extractor]:
    """Register an extractor under ``name`` (names must be unique)."""

    def deco(fn: Extractor) -> Extractor:
        if name in EXTRACTORS:
            raise ValueError(f"duplicate extractor {name!r}")
        EXTRACTORS[name] = fn
        return fn

    return deco
