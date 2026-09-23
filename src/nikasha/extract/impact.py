# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Impact claims (SPEC §9.7): CVSS v2/v3.x/v4.0 vectors, numeric scores near "CVSS" or a
vector, severity words in unambiguous positions, and a CWE on the same line."""

from __future__ import annotations

import re

from nikasha.extract.registry import ExtractContext, make_claim, register
from nikasha.extract.spans import IntervalIndex, Region, finditer_in
from nikasha.model.claims import ImpactClaim

NAME = "impact"

_VECTOR_RE = re.compile(
    r"\bCVSS:(?P<ver>3\.[01]|4\.0)(?P<metrics>(?:/[A-Za-z]{1,3}:[A-Za-z]{1,2}){4,40}+)"
)
_V2_RE = re.compile(r"\(?\bAV:[LAN]/AC:[HML]/Au:[MSN]/C:[NPC]/I:[NPC]/A:[NPC]\b\)?")
_SCORE = r"(?P<score>10(?:\.0)?|\d\.\d)(?![\d.])"
_SCORE_AFTER_RE = re.compile(rf"[\s\u2014\u2013:=*,(-]{{0,8}}{_SCORE}")
_CVSS_SCORE_RE = re.compile(
    rf"\bCVSS(?:\s{{0,2}}v?(?:[234](?:\.[01])?))?(?:\s{{1,3}}(?:base\s{{1,3}})?score)?"
    rf"(?:\s{{1,3}}of)?\s{{0,3}}[:=]?\s{{0,3}}\**{_SCORE}",
    re.IGNORECASE,
)
_SEV_WORDS = "critical|high|medium|moderate|low|none"
_SEV_PAREN_RE = re.compile(rf"\s{{0,3}}\(\s{{0,2}}(?P<sev>{_SEV_WORDS})\s{{0,2}}\)", re.I)
_SEVERITY_RE = re.compile(
    rf"\bseverity\s{{0,3}}[:=]?\s{{0,3}}\**(?P<a>{_SEV_WORDS})\b"
    rf"|\b(?P<b>{_SEV_WORDS})[ -]severity\b"
    rf"|\brated\s{{1,3}}(?:as\s{{1,3}})?(?P<c>{_SEV_WORDS})\b",
    re.IGNORECASE,
)
_CWE_RE = re.compile(r"\bCWE-(?P<n>\d{1,5})\b", re.IGNORECASE)


def _line_of(body: str, start: int, end: int) -> Region:
    ls = body.rfind("\n", 0, start) + 1
    le = body.find("\n", end)
    return (ls, le if le >= 0 else len(body))


def _score_and_severity(
    body: str, after: int, line_end: int
) -> tuple[float | None, str | None, int]:
    """Score (and a parenthesized severity) right after ``after``; returns the end offset."""
    m = _SCORE_AFTER_RE.match(body, after, line_end)
    if not m:
        return None, None, after
    score = float(m.group("score"))
    end = m.end()
    sev = _SEV_PAREN_RE.match(body, end, line_end)
    if sev:
        return score, sev.group("sev").capitalize(), sev.end()
    return score, None, end


@register(NAME)
def extract_impact(ctx: ExtractContext) -> list[ImpactClaim]:
    report, body = ctx.report, ctx.report.body
    claims: list[ImpactClaim] = []
    taken = IntervalIndex()

    for pattern, version in ((_VECTOR_RE, None), (_V2_RE, "2.0")):
        for m in finditer_in(pattern, body, ctx.prose):
            line = _line_of(body, m.start(), m.end())
            score, sev, end = _score_and_severity(body, m.end(), line[1])
            cwe = _CWE_RE.search(body, line[0], line[1])
            taken.add((m.start(), end))
            vector = m.group(0).strip("()")
            claims.append(
                make_claim(
                    ImpactClaim,
                    spans=[report.span(m.start(), end)],
                    extractor=NAME,
                    confidence=0.95,
                    cvss_vector=vector,
                    cvss_version=version or m.group("ver"),
                    cvss_score=score,
                    severity_word=sev,
                    cwe=f"CWE-{int(cwe.group('n'))}" if cwe else None,
                )
            )

    for m in finditer_in(_CVSS_SCORE_RE, body, ctx.prose):
        if taken.overlaps((m.start(), m.end())):
            continue
        line = _line_of(body, m.start(), m.end())
        sev_m = _SEV_PAREN_RE.match(body, m.end(), line[1])
        end = sev_m.end() if sev_m else m.end()
        taken.add((m.start(), end))
        claims.append(
            make_claim(
                ImpactClaim,
                spans=[report.span(m.start(), end)],
                extractor=NAME,
                confidence=0.85,
                cvss_score=float(m.group("score")),
                severity_word=sev_m.group("sev").capitalize() if sev_m else None,
            )
        )

    for m in finditer_in(_SEVERITY_RE, body, ctx.prose):
        if taken.overlaps((m.start(), m.end())):
            continue
        word = next(g for g in (m.group("a"), m.group("b"), m.group("c")) if g)
        claims.append(
            make_claim(
                ImpactClaim,
                spans=[report.span(m.start(), m.end())],
                extractor=NAME,
                confidence=0.7,
                severity_word=word.capitalize(),
            )
        )
    return claims
