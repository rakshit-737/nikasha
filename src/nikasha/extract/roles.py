# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Claim roles (SPEC §9.3): ``core`` claims carry the report's central assertion and weigh
more in checks (e.g. C03 multiplies a core "never existed" by 1.5 ).

A symbol, file, line or option is core when it appears in the title or first paragraph, or in
a sentence that also names the bug ("overflow", "use after free", "crash"…). External APIs,
references and impact metadata are peripheral. Everything else is supporting. (Making the
top application frame of a trace core needs the repository, so it happens in M3.)
"""

from __future__ import annotations

import re

from nikasha.extract.registry import ExtractContext
from nikasha.extract.spans import first_paragraph, sentence_bounds
from nikasha.model.claims import (
    ClaimBase,
    ClaimRole,
    FileClaim,
    ImpactClaim,
    LineClaim,
    OptionClaim,
    ReferenceClaim,
    SymbolClaim,
)

_BUG_WORDS_RE = re.compile(
    r"\b(?:vulnerab\w{0,8}|overflow\w{0,3}|overrun\w{0,3}|underflow\w{0,3}|out[- ]of[- ]bounds|"
    r"use[- ]after[- ]free|double[- ]free|uaf|oob|crash\w{0,3}|segfault\w{0,3}|sigsegv|bug|flaw|"
    r"null[- ]pointer|dereferenc\w{0,5}|corrupt\w{0,5}|leak\w{0,3}|race|injection|rce|dos|"
    r"exploit\w{0,5}|uninitiali[sz]ed|memory[- ]safety|heap|stack[- ]buffer)\b",
    re.IGNORECASE,
)
_CORE_ELIGIBLE = (SymbolClaim, FileClaim, LineClaim, OptionClaim)


def role_for(ctx: ExtractContext, claim: ClaimBase) -> ClaimRole:  # noqa: PLR0911
    if isinstance(claim, (ReferenceClaim, ImpactClaim)):
        return "peripheral"
    if isinstance(claim, SymbolClaim) and claim.external:
        return "peripheral"
    if not isinstance(claim, _CORE_ELIGIBLE) or claim.negated:
        return "supporting"
    body = ctx.report.body
    lead = first_paragraph(ctx.report)
    title = (ctx.report.title or "").strip()
    for span in claim.spans:
        if lead[0] <= span.start < lead[1]:
            return "core"
        if title and span.text.strip("`()") and span.text.strip("`()") in title:
            return "core"
        start, end = sentence_bounds(body, span.start, span.end)
        if _BUG_WORDS_RE.search(body, start, end):
            return "core"
    return "supporting"
