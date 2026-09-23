# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Reference claims (SPEC §9.7): URLs (classified), CVE, CWE and GHSA IDs, and commit SHAs
written in context."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from nikasha.extract.registry import ExtractContext, make_claim, register
from nikasha.extract.spans import IntervalIndex, finditer_in
from nikasha.model.claims import ReferenceClaim, ReferenceKind

NAME = "references"

_CVE_RE = re.compile(r"\bCVE-(?P<y>\d{4})-(?P<n>\d{4,7})\b", re.IGNORECASE)
_CWE_RE = re.compile(r"\bCWE-(?P<n>\d{1,5})\b", re.IGNORECASE)
_GHSA_RE = re.compile(r"\bGHSA(?:-[23456789cfghjmpqrvwx]{4}){3}\b", re.IGNORECASE)
_SHA_CTX_RE = re.compile(
    r"\b(?:commit|revision|rev)\s{0,3}[:#]?\s{0,3}`?(?P<sha>[0-9a-f]{7,40})`?(?![\w])", re.I
)
_FORGES = ("github.com", "gitlab.com", "codeberg.org", "bitbucket.org")
_ADVISORY_HOSTS = (
    "nvd.nist.gov",
    "cve.org",
    "www.cve.org",
    "cve.mitre.org",
    "osv.dev",
    "security-tracker.debian.org",
    "access.redhat.com",
    "ubuntu.com",
)


#: Forge path segment (after owner/repo, GitLab's "-" skipped) -> (kind, minimum segments).
_FORGE_KINDS: dict[str, tuple[ReferenceKind, int]] = {
    "commit": ("commit", 2),
    "commits": ("commit", 2),
    "pull": ("pr", 2),
    "merge_requests": ("pr", 2),
    "issues": ("issue", 2),
    "blob": ("blob", 1),
    "compare": ("compare", 1),
}


def _forge_kind(rest: list[str], url: str) -> tuple[ReferenceKind, str]:
    if len(rest) >= 2 and rest[:2] == ["security", "advisories"]:  # noqa: PLR2004
        return "advisory", url
    if rest and rest[0] in _FORGE_KINDS:
        kind, needed = _FORGE_KINDS[rest[0]]
        if len(rest) >= needed:
            return kind, rest[1].lower() if kind == "commit" else url
    return "url", url


def classify_url(url: str) -> tuple[ReferenceKind, str, str | None]:
    """Return ``(kind, value, repo_url)`` for a URL."""
    parts = urlsplit(url)
    host = parts.netloc.lower()
    segments = [s for s in parts.path.split("/") if s]
    if host in _FORGES and len(segments) >= 2:  # noqa: PLR2004
        repo_url = f"https://{host}/{segments[0]}/{segments[1].removesuffix('.git')}"
        rest = segments[2:]
        if rest and rest[0] == "-":  # GitLab's /-/ separator
            rest = rest[1:]
        kind, value = _forge_kind(rest, url)
        return kind, value, repo_url
    if host in _ADVISORY_HOSTS or host.endswith(".cve.org"):
        return "advisory", url, None
    return "url", url, None


@register(NAME)
def extract_references(ctx: ExtractContext) -> list[ReferenceClaim]:
    report, body = ctx.report, ctx.report.body
    claims: list[ReferenceClaim] = []

    def add(start: int, end: int, kind: ReferenceKind, value: str, repo: str | None) -> None:
        claims.append(
            make_claim(
                ReferenceClaim,
                spans=[report.span(start, end)],
                extractor=NAME,
                confidence=0.95,
                ref_kind=kind,
                value=value,
                repo_url=repo,
            )
        )

    prose_index = IntervalIndex(ctx.prose)
    prose_urls = [r for r in ctx.urls if prose_index.overlaps(r)]
    url_index = IntervalIndex(prose_urls)
    for start, end in prose_urls:
        kind, value, repo = classify_url(body[start:end])
        add(start, end, kind, value, repo)
    for m in finditer_in(_CVE_RE, body, ctx.prose):
        if not url_index.overlaps((m.start(), m.end())):
            add(m.start(), m.end(), "cve", f"CVE-{m.group('y')}-{m.group('n')}", None)
    for m in finditer_in(_CWE_RE, body, ctx.prose):
        if not url_index.overlaps((m.start(), m.end())):
            add(m.start(), m.end(), "cwe", f"CWE-{int(m.group('n'))}", None)
    for m in finditer_in(_GHSA_RE, body, ctx.prose):
        if not url_index.overlaps((m.start(), m.end())):
            add(m.start(), m.end(), "ghsa", "GHSA" + m.group(0)[4:].lower(), None)
    for m in finditer_in(_SHA_CTX_RE, body, ctx.prose):
        sha = m.group("sha").lower()
        if sha.isdigit() or url_index.overlaps((m.start(), m.end())):
            continue
        add(m.start("sha"), m.end("sha"), "commit", sha, None)
    return claims
