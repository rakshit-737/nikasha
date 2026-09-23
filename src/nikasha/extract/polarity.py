# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Polarity: negated or absence statements never become existence claims (ADR 0003).

slopcheck's clearest failure was "There is no `smb_conns_match` equivalent in …": the tool
confirmed that the symbol did not exist and reported that as a contradiction. A mention is
*negated* when a negation cue sits right before it ("there is no", "no such", "without a",
"lacks") or an absence predicate right after it ("does not exist", "is missing.", "is not
defined"). "X is missing a bounds check" is **not** negated: X exists and lacks something.
A claim is negated only if *every* one of its mentions is.
"""

from __future__ import annotations

import re

from nikasha.extract.spans import clause_bounds
from nikasha.model.claims import ClaimBase, FileClaim, OptionClaim, SymbolClaim
from nikasha.model.report import Span

_WINDOW = 48
_BEFORE_RE = re.compile(
    r"(?:\bthere\s{1,3}(?:is|are|was|were)\s{1,3}no|\bthere's\s{1,3}no"
    r"|\bno(?:\s{1,3}such)?(?:\s{1,3}(?:equivalent|counterpart|function|method|macro|symbol|"
    r"file|option|flag|field|member|call|matching|corresponding)"
    r"(?:\s{1,3}(?:of|to|for|named|called))?)?"
    r"|\bwithout(?:\s{1,3}(?:a|an|any))?|\blacks?(?:\s{1,3}(?:a|an|any))?|\bnonexistent"
    r"|\bnon-existent|\b(?:does\s{1,3}not|doesn't)\s{1,3}(?:have|define|export|provide)"
    r"(?:\s{1,3}(?:a|an|any))?)\s{1,3}(?:the\s{1,3})?[`\"'(]{0,2}$",
    re.IGNORECASE,
)
_AFTER_RE = re.compile(
    r"^[`\"')]{0,3}(?:\(\))?\s{0,2}(?:equivalent\s{1,3}|function\s{1,3}|option\s{1,3}|file\s{1,3})?"
    r"(?:(?:does\s{1,3}not|doesn't|did\s{1,3}not|didn't|no\s{1,3}longer)\s{1,3}exists?"
    r"|(?:is|was|are|were)\s{1,3}(?:not\s{1,3}(?:present|defined|declared|exported|available|"
    r"found|implemented)|missing|absent|undefined|nonexistent|removed|gone)"
    r"(?=\s{0,3}(?:[.,;:!?)]|$|\s(?:from|in|at|since|anymore)\b)))",
    re.IGNORECASE,
)

#: Claim kinds whose meaning is "this thing exists".
EXISTENCE_KINDS = (SymbolClaim, FileClaim, OptionClaim)


def span_is_negated(body: str, span: Span) -> bool:
    clause = clause_bounds(body, span.start, span.end)
    before = body[max(clause[0], span.start - _WINDOW) : span.start]
    after = body[span.end : min(clause[1], span.end + _WINDOW)]
    return bool(_BEFORE_RE.search(before) or _AFTER_RE.match(after))


def is_negated(body: str, claim: ClaimBase) -> bool:
    """True when every mention of an existence claim is negated."""
    if not isinstance(claim, EXISTENCE_KINDS):
        return False
    return all(span_is_negated(body, s) for s in claim.spans)
