# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Behaviour claims (SPEC §9.8): a small, conservative set of patterns.

Extracting too little is fine; extracting too much is not. Subjects must be written as code
(backticks or ``name()``), so ordinary prose never becomes a behaviour claim.
"""

from __future__ import annotations

import re

from nikasha.extract.registry import ExtractContext, make_claim, register
from nikasha.extract.spans import finditer_in
from nikasha.model.claims import BehaviorClaim, BehaviorPredicate

NAME = "behavior"

_CODE = r"(?:`(?P<{g}>[A-Za-z_]\w{{2,100}}+)(?:\(\))?`|(?P<{g}2>[A-Za-z_]\w{{2,100}}+)\(\))"


def _code(group: str) -> str:
    return _CODE.format(g=group)


_VERB = r"(?:directly\s{1,3})?(?:calls|invokes|uses|passes\s{1,3}\S{1,40}\s{1,3}to)"
_CALLS_RE = re.compile(rf"{_code('s')}\s{{1,3}}{_VERB}\s{{1,3}}{_code('o')}")
_LOCATION = r"(?:\s{1,3}(?:\([^)\n]{0,80}\)|in\s{1,3}`[^`\n]{1,200}`))?"
_FAILS = r"(?:does\s{1,3}not|doesn't|fails\s{1,3}to|never)"
_WHAT = r"(?:the\s{1,3})?(?:\w{1,20}\s{1,3})?(?:length|size|bounds?)"
_BOUNDS_RE = re.compile(
    rf"(?:missing|no|lacks?(?:\s{{1,3}}a)?|without(?:\s{{1,3}}a)?)\s{{1,3}}(?:bounds?|length|size)"
    rf"[ -]check(?:s|ing)?\s{{1,3}}(?:in|inside|within)\s{{1,3}}"
    rf"(?:the\s{{1,3}}function\s{{1,3}})?{_code('s')}"
    rf"|{_code('t')}{_LOCATION}\s{{1,3}}{_FAILS}\s{{1,3}}(?:check|validate|verify|bound)\s{{1,3}}{_WHAT}",
    re.IGNORECASE,
)
_NULL_RE = re.compile(
    rf"(?:missing|no)\s{{1,3}}NULL[ -]check\s{{1,3}}in\s{{1,3}}{_code('s')}"
    rf"|{_code('t')}\s{{1,3}}{_FAILS}\s{{1,3}}check\s{{1,3}}(?:for\s{{1,3}})?NULL",
    re.IGNORECASE,
)
_UAF_RE = re.compile(rf"use[- ]after[- ]free\s{{1,3}}in\s{{1,3}}{_code('s')}", re.IGNORECASE)
_INTOVF_RE = re.compile(
    rf"integer\s{{1,3}}(?:overflow|wraparound|underflow)\s{{1,3}}in\s{{1,3}}{_code('s')}", re.I
)


def _group(m: re.Match[str], *names: str) -> str | None:
    for n in names:
        for key in (n, f"{n}2"):
            value = m.groupdict().get(key)
            if value:
                return value
    return None


@register(NAME)
def extract_behavior(ctx: ExtractContext) -> list[BehaviorClaim]:
    report, body = ctx.report, ctx.report.body
    claims: list[BehaviorClaim] = []
    patterns: tuple[tuple[re.Pattern[str], BehaviorPredicate], ...] = (
        (_CALLS_RE, "calls_api"),
        (_BOUNDS_RE, "missing_bounds_check"),
        (_NULL_RE, "missing_null_check"),
        (_UAF_RE, "uses_freed"),
        (_INTOVF_RE, "integer_overflow"),
    )
    for pattern, predicate in patterns:
        for m in finditer_in(pattern, body, ctx.prose):
            subject = _group(m, "s", "t")
            if subject is None:
                continue
            obj = _group(m, "o") if predicate == "calls_api" else None
            claims.append(
                make_claim(
                    BehaviorClaim,
                    spans=[report.span(m.start(), m.end())],
                    extractor=NAME,
                    confidence=0.7,
                    subject_symbol=subject,
                    predicate=predicate,
                    object=obj,
                )
            )
    return claims
