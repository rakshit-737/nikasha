# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Version claims (SPEC §9.2).

Recognized forms: ``<product> <version>``, ``version X``, ``vX.Y.Z``, bare ``X.Y.Z`` after a
cue word, ranges (``from A to B``, ``>= A, < B``, ``before B``, ``A and earlier``), tag-style
refs (``curl-8_5_0``), branch refs (``master``/``main``/``HEAD``/``trunk``/``latest``) in
context, dates (``as of 2026-05-02``) and commit SHAs **only in context**. ``0x…`` values
and sanitizer addresses are never taken as SHAs.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from datetime import date

from nikasha.extract.products import product_for_alias
from nikasha.extract.registry import ExtractContext, make_claim, register
from nikasha.extract.spans import IntervalIndex, Region, block_regions, finditer_in
from nikasha.model.claims import VersionClaim, VersionSpec

NAME = "versions"

# A dotted version: 2 to 5 numeric parts, optional pre-release qualifier or a single letter
# suffix (OpenSSL's 1.1.1w). Every quantifier is bounded; alternatives start with distinct
# characters, so matching is linear.
_V = r"\d{1,5}(?:\.\d{1,5}){1,4}(?:-?(?:rc|beta|alpha|pre|dev|post)\.?\d{0,4}|[a-z](?![\w.]))?"
_AFTER_ALIAS_RE = re.compile(rf"\s{{1,3}}(?:version\s{{1,3}}|v)?(?P<v>{_V})(?![\w.]?\d)", re.I)
_V_PREFIXED_RE = re.compile(rf"(?<![\w.-])v(?P<v>{_V})\b")
_TAG_RE = re.compile(
    r"(?<![\w.-])(?P<tag>[A-Za-z][A-Za-z0-9]{1,30}[-_]\d{1,4}(?:_\d{1,4}){1,3}[a-z]?)(?![\w.])"
)
_VERSION_WORD_RE = re.compile(rf"\b(?:version|ver\.|release|tag)\s{{1,3}}(?:`|v)?(?P<v>{_V})", re.I)
_CUE_RE = re.compile(
    rf"\b(?P<cue>tested(?:\s{{1,3}}(?:on|with|against))?|affect(?:s|ed|ing)?|before|"
    rf"prior\s{{1,3}}to|up\s{{1,3}}to|through|thru|since|fixed\s{{1,3}}in|introduced\s{{1,3}}in|"
    rf"until|<=|>=|<|>)"
    rf"\s{{0,3}}(?:version\s{{1,3}}|v|`)?(?P<v>{_V})",
    re.IGNORECASE,
)
_VPREFIX = r"(?:version\s{1,3}|v)?"
_RANGE_FROM_TO_RE = re.compile(
    rf"\bfrom\s{{1,3}}{_VPREFIX}(?P<a>{_V})\s{{1,3}}"
    rf"(?:to|through|until|up\s{{1,3}}to)\s{{1,3}}{_VPREFIX}(?P<b>{_V})",
    re.I,
)
_RANGE_CMP_RE = re.compile(
    rf">=\s{{0,2}}(?P<a>{_V})\s{{0,2}},?\s{{0,3}}(?P<op><=|<)\s{{0,2}}(?P<b>{_V})"
)
_AND_EARLIER_RE = re.compile(
    rf"(?P<v>{_V})\s{{1,3}}and\s{{1,3}}(?:all\s{{1,3}})?(?:earlier|prior|older|below|previous)\b",
    re.I,
)
_ALL_BEFORE_RE = re.compile(
    rf"\ball\s{{1,3}}versions?\s{{1,3}}(?:before|prior\s{{1,3}}to|up\s{{1,3}}to|through)"
    rf"\s{{1,3}}{_VPREFIX}(?P<v>{_V})",
    re.I,
)
_SPECIAL_RE = re.compile(
    r"\b(?:(?:on|at|against|of|from|current|git|tip\s{1,3}of)\s{1,3}(?:the\s{1,3})?`?"
    r"(?P<a>master|main|HEAD|trunk)`?(?:\s{1,3}branch)?|`?(?P<b>master|main|trunk)`?\s{1,3}branch"
    r"|\b(?P<c>HEAD)\b|(?P<d>latest)\s{1,3}(?:version|release|master|git|commit|code|source))",
)
_DATE_RE = re.compile(
    r"\b(?:as\s{1,3}of|tested\s{1,3}on|checked\s{1,3}on|built\s{1,3}on|on)\s{1,3}"
    r"(?P<d>\d{4}-\d{2}-\d{2})\b",
    re.I,
)
_COMMIT_CTX_RE = re.compile(
    r"\b(?:commit|rev(?:ision)?|sha|hash|at)\s{0,3}[:#]?\s{0,3}`?(?P<sha>[0-9a-f]{7,40})`?(?![\w])",
    re.I,
)
_COMMIT_URL_RE = re.compile(
    r"https?://(?:github\.com|gitlab\.com)/[\w.-]{1,100}/[\w.-]{1,100}/(?:-/)?commit/"
    r"(?P<sha>[0-9a-f]{7,40})\b"
)
_QUAL_RE = re.compile(r"-?(rc|beta|alpha|pre|dev|post)\.?(\d{0,4})$|([a-z])$")

_FIXED_CUES = ("fixed",)
_UPPER_EXCLUSIVE = ("before", "prior", "<", "until")
_UPPER_INCLUSIVE = ("up", "through", "thru", "<=")
_LOWER = ("since", ">=", ">", "introduced")


def parse_version(raw: str) -> VersionSpec | None:
    """Parse ``8.5.0``, ``1.1.1w``, ``3.45.1-rc2`` or ``8_5_0`` into a :class:`VersionSpec`."""
    text = raw.strip().lstrip("vV")
    qualifier: str | None = None
    m = _QUAL_RE.search(text)
    if m and (m.group(1) or m.group(3)):
        qualifier = (m.group(1) or "") + (m.group(2) or "") if m.group(1) else m.group(3)
        text = text[: m.start()]
    parts = re.split(r"[._]", text)
    if not parts or not all(p.isdigit() for p in parts):
        return None
    return VersionSpec(numbers=tuple(int(p) for p in parts), qualifier=qualifier, raw=raw)


def _is_address_context(body: str, start: int) -> bool:
    return body[max(0, start - 2) : start].lower().endswith("0x")


def _product_before(ctx: ExtractContext, start: int) -> str | None:
    window_start = max(0, start - 40)
    last: str | None = None
    for m in ctx.alias_re.finditer(ctx.report.body, window_start, start):
        # The alias must be immediately followed by the version (only spaces or "version").
        between = ctx.report.body[m.end() : start].strip().lower().rstrip("v").strip()
        if between in ("", "version", "ver."):
            product = product_for_alias(m.group(0), ctx.products)
            last = product.name if product else m.group(0).lower()
    return last


Add = Callable[..., None]
_MIN_TAG_PARTS = 2
_MIN_AT_SHA_LEN = 12


def _ranges(ctx: ExtractContext, regions: list[Region], add: Add) -> None:
    body = ctx.report.body
    for m in finditer_in(_RANGE_FROM_TO_RE, body, regions):
        a, b = parse_version(m.group("a")), parse_version(m.group("b"))
        if a and b:
            product = _product_before(ctx, m.start()) or ctx.product_hint
            add(m.start(), m.end(), raw=m.group(0), relation="affected_range", lower=a,
                upper=b, upper_inclusive=True, product=product)  # fmt: skip
    for m in finditer_in(_RANGE_CMP_RE, body, regions):
        a, b = parse_version(m.group("a")), parse_version(m.group("b"))
        if a and b:
            inclusive = m.group("op") == "<="
            add(m.start(), m.end(), raw=m.group(0), relation="affected_range", lower=a,
                upper=b, upper_inclusive=inclusive, product=ctx.product_hint)  # fmt: skip
    for m in finditer_in(_ALL_BEFORE_RE, body, regions):
        v = parse_version(m.group("v"))
        if v:
            inclusive = bool(re.search(r"up\s+to|through", m.group(0), re.I))
            add(m.start(), m.end(), raw=m.group(0), relation="affected_range", upper=v,
                upper_inclusive=inclusive, product=ctx.product_hint)  # fmt: skip
    for m in finditer_in(_AND_EARLIER_RE, body, regions):
        v = parse_version(m.group("v"))
        if not v:
            continue
        start = m.start()
        product = _product_before(ctx, start)
        if product:
            prefix = ctx.alias_re.search(body, max(0, start - 40), start)
            start = prefix.start() if prefix else start
        add(start, m.end(), raw=body[start : m.end()], relation="affected_range", upper=v,
            upper_inclusive=True, product=product or ctx.product_hint)  # fmt: skip


def _cue_fields(cue: str, v: VersionSpec) -> dict[str, object]:
    if cue.startswith(_FIXED_CUES):
        return {"relation": "fixed_in", "parsed": v}
    if cue.startswith(_UPPER_INCLUSIVE):
        return {"relation": "affected_range", "upper": v, "upper_inclusive": True}
    if cue.startswith(_UPPER_EXCLUSIVE):
        return {"relation": "affected_range", "upper": v, "upper_inclusive": False}
    if cue.startswith(_LOWER):
        return {"relation": "affected_range", "lower": v, "lower_inclusive": cue != ">"}
    if cue.startswith("affect"):
        return {"relation": "affected_range", "lower": v, "upper": v, "upper_inclusive": True}
    return {"relation": "tested_on", "parsed": v}


def _cues(ctx: ExtractContext, regions: list[Region], add: Add) -> None:
    body = ctx.report.body
    for m in finditer_in(_CUE_RE, body, regions):
        v = parse_version(m.group("v"))
        if v is None or _is_address_context(body, m.start("v")):
            continue
        product = _product_before(ctx, m.start()) or ctx.product_hint
        fields = _cue_fields(m.group("cue").lower(), v)
        add(m.start("v"), m.end("v"), raw=m.group("v"), product=product, **fields)


def _product_versions(ctx: ExtractContext, regions: list[Region], add: Add) -> None:
    body = ctx.report.body
    for m in finditer_in(ctx.alias_re, body, regions):
        rest = _AFTER_ALIAS_RE.match(body, m.end())
        v = parse_version(rest.group("v")) if rest else None
        if rest is None or v is None:
            continue
        product = product_for_alias(m.group(0), ctx.products)
        name = product.name if product else m.group(0).lower()
        add(m.start(), rest.end(), raw=body[m.start() : rest.end()], relation="tested_on",
            parsed=v, product=name)  # fmt: skip
    for pattern in (_VERSION_WORD_RE, _V_PREFIXED_RE):
        for m in finditer_in(pattern, body, regions):
            v = parse_version(m.group("v"))
            if v:
                add(m.start(), m.end(), raw=m.group(0), relation="tested_on", parsed=v,
                    product=ctx.product_hint)  # fmt: skip
    for m in finditer_in(_TAG_RE, body, regions):
        tag = m.group("tag")
        numeric = re.search(r"[-_](\d.*)$", tag)
        v = parse_version(numeric.group(1)) if numeric else None
        if v and len(v.numbers) >= _MIN_TAG_PARTS:
            add(m.start(), m.end(), raw=tag, relation="tested_on", parsed=v,
                product=ctx.product_hint)  # fmt: skip


def _refs(ctx: ExtractContext, regions: list[Region], add: Add) -> None:
    body = ctx.report.body
    for m in finditer_in(_SPECIAL_RE, body, regions):
        ref = next(g for g in (m.group("a"), m.group("b"), m.group("c"), m.group("d")) if g)
        add(m.start(), m.end(), raw=m.group(0), relation="latest", special_ref=ref,
            product=ctx.product_hint)  # fmt: skip
    for m in finditer_in(_DATE_RE, body, regions):
        try:
            as_of = date.fromisoformat(m.group("d"))
        except ValueError:
            continue
        add(m.start(), m.end(), raw=m.group(0), relation="unspecified", as_of=as_of,
            product=ctx.product_hint)  # fmt: skip
    for pattern in (_COMMIT_URL_RE, _COMMIT_CTX_RE):
        for m in finditer_in(pattern, body, regions):
            sha = m.group("sha").lower()
            if sha.isdigit() or _is_address_context(body, m.start("sha")):
                continue
            weak_cue = pattern is _COMMIT_CTX_RE and m.group(0).lower().startswith("at")
            if weak_cue and len(sha) < _MIN_AT_SHA_LEN:
                continue  # "at <hex>" is only trusted for long SHAs
            add(m.start("sha"), m.end("sha"), raw=sha, relation="tested_on", commit=sha,
                product=ctx.product_hint)  # fmt: skip


@register(NAME)
def extract_versions(ctx: ExtractContext) -> list[VersionClaim]:
    """Extract version claims. Earlier, more specific patterns win overlapping text."""
    report = ctx.report
    # Versions are read from prose, and from log/PoC blocks (e.g. `curl -V` output), never
    # from traces or patches.
    regions: list[Region] = sorted(ctx.prose + block_regions(report, ("log", "poc")))
    claims: list[VersionClaim] = []
    taken = IntervalIndex()

    def add(start: int, end: int, **fields: object) -> None:
        if taken.overlaps((start, end)):
            return
        taken.add((start, end))
        span = report.span(start, end)
        claims.append(
            make_claim(VersionClaim, spans=[span], extractor=NAME, confidence=0.9, **fields)
        )

    for step in (_ranges, _cues, _product_versions, _refs):
        step(ctx, regions, add)
    return claims
