# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""GitHub private vulnerability reports (SPEC §8, §16.5): ``nikasha gh-advisories OWNER/REPO``.

**Read-only, local only.** The command lists a repository's security advisories
(``GET /repos/{owner}/{repo}/security-advisories?state=triage`` on the GitHub REST API,
over stdlib ``urllib`` with a token from ``GITHUB_TOKEN`` or ``GH_TOKEN``), turns each one
into a :class:`~nikasha.model.report.Report` and prints them as Markdown (or JSON). It never
writes to GitHub: there is no comment endpoint for private reports, and private content
must not be posted anywhere. The ``gh`` CLI is deliberately not used: only the git and
sandbox wrappers may spawn processes.

The same refusal rules as :mod:`nikasha.integrations.h1` apply: no request without
``--online`` and a token, HTTPS only, one host (pagination follows ``Link: rel="next"``
only when it points back at ``api.github.com``, so the token can never travel elsewhere),
a timeout, a size cap and a page cap. Advisory authors, publishers and credits are never
read (SPEC §7): no login can reach a result.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console

from nikasha.errors import NikashaError
from nikasha.ingest.markdown import ingest_markdown
from nikasha.ingest.text import report_id as content_report_id
from nikasha.integrations.h1 import (
    check_and_render,
    emit_utf8,
    fail,
    fetch_json,
    intake_dir,
    intake_markdown,
    iso_date,
    report_json,
    require_online,
    write_private,
)
from nikasha.model.report import DeclaredTarget, Report, ReportSource

API_BASE = "https://api.github.com/repos/"
ENV_TOKENS = ("GITHUB_TOKEN", "GH_TOKEN")
API_VERSION = "2022-11-28"
STATES = ("triage", "draft", "published", "closed")
#: The one state GitHub serves anonymously.
PUBLIC_STATE = "published"
PER_PAGE = 100
#: Pages beyond this are not fetched (a warning says so).
MAX_PAGES = 10
HTTP_HINTS: Mapping[int, str] = {
    401: "the token in GITHUB_TOKEN/GH_TOKEN was rejected",
    403: (
        "the token lacks read access to repository security advisories, or you are rate "
        "limited (anonymous requests for published advisories share a small hourly limit; "
        "set GITHUB_TOKEN to raise it)"
    ),
    404: "repository not found, or its advisories are not visible to this token",
    429: "rate limited; try again later",
}

_OWNER_REPO_RE = re.compile(r"\A([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/([A-Za-z0-9._-]{1,100})\Z")
_TOKEN_RE = re.compile(r"\A[!-~]{1,512}\Z")
_GHSA_RE = re.compile(r"\AGHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}\Z")
_HTML_URL_RE = re.compile(r"\Ahttps://github\.com/[A-Za-z0-9._/-]{1,300}\Z")
_LINK_NEXT_RE = re.compile(r'<(https://api\.github\.com/[^>\s]{1,1000})>;\s{0,10}rel="next"')
_MAX_LIST = 50


def token_from_env(env: Mapping[str, str] | None = None) -> str:
    """The first of ``GITHUB_TOKEN``/``GH_TOKEN``; refused when missing or not printable ASCII."""
    source = os.environ if env is None else env
    for name in ENV_TOKENS:
        token = source.get(name, "")
        if token:
            if not _TOKEN_RE.match(token):
                raise NikashaError(
                    f"{name} must be printable ASCII without spaces (nothing was requested)"
                )
            return token
    raise NikashaError(
        "no GitHub token: export GITHUB_TOKEN (or GH_TOKEN) with read access to repository "
        "security advisories (nothing was requested)"
    )


def _optional_token(state: str, env: Mapping[str, str] | None) -> str | None:
    """The token, or ``None`` for an anonymous request.

    Published advisories are public, and GitHub serves them without authentication (at the
    anonymous rate limit), so ``state=published`` works without a token. Every other state is
    private and still refuses before any request when no token is set.
    """
    source = os.environ if env is None else env
    if state == PUBLIC_STATE and not any(source.get(name, "") for name in ENV_TOKENS):
        return None
    return token_from_env(env)


def validate_owner_repo(text: str) -> tuple[str, str]:
    """``OWNER/REPO`` in GitHub's own character set; anything else could reshape the URL."""
    match = _OWNER_REPO_RE.match(text.strip())
    if match is None or match.group(2) in (".", ".."):
        raise NikashaError(f"not an OWNER/REPO name: {text!r}")
    return match.group(1), match.group(2)


def validate_state(state: str) -> str:
    value = state.strip().lower()
    if value not in STATES:
        raise NikashaError(f"--state must be one of {', '.join(STATES)}; got {state!r}")
    return value


def _text(value: object, limit: int) -> str:
    return value[:limit] if isinstance(value, str) else ""


def _one_line(value: str, limit: int = 500) -> str:
    flat = " ".join(value.split())
    return "".join(ch for ch in flat if ch == " " or ch.isprintable())[:limit].strip()


def _dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: object) -> list[Any]:
    return value[:_MAX_LIST] if isinstance(value, list) else []


def _strings(values: object, limit: int = 100) -> tuple[str, ...]:
    found = [_one_line(v, limit) for v in _list(values) if isinstance(v, str)]
    return tuple(dict.fromkeys(v for v in found if v))


@dataclass(frozen=True, slots=True)
class ParsedAdvisory:
    """The fields Nikasha keeps. Author, publisher and credits are never read."""

    ghsa_id: str
    cve_id: str
    summary: str
    description: str
    state: str
    severity: str
    cvss_vector: str
    cvss_score: str
    cwes: tuple[str, ...]
    created_at: date | None
    html_url: str
    packages: tuple[str, ...]
    ranges: tuple[str, ...]
    patched: tuple[str, ...]
    functions: tuple[str, ...]


def parse_advisory(item: object) -> ParsedAdvisory:
    """Pick the advisory fields out of one (untrusted) list entry."""
    data = _dict(item)
    cvss = _dict(data.get("cvss"))
    score = cvss.get("score")
    cwes: list[str] = []
    for cwe in _list(data.get("cwes")):
        entry = _dict(cwe)
        label = " ".join(
            p
            for p in (
                _one_line(_text(entry.get("cwe_id"), 20)),
                _one_line(_text(entry.get("name"), 120)),
            )
            if p
        )
        if label:
            cwes.append(label)
    packages: list[str] = []
    ranges: list[str] = []
    patched: list[str] = []
    functions: list[str] = []
    for vuln in _list(data.get("vulnerabilities")):
        entry = _dict(vuln)
        package = _dict(entry.get("package"))
        name = _one_line(_text(package.get("name"), 200))
        ecosystem = _one_line(_text(package.get("ecosystem"), 50))
        if name:
            packages.append(f"{name} ({ecosystem})" if ecosystem else name)
        vulnerable_range = _one_line(_text(entry.get("vulnerable_version_range"), 200))
        if vulnerable_range:
            ranges.append(vulnerable_range)
        fixed = _one_line(_text(entry.get("patched_versions"), 200))
        if fixed:
            patched.append(fixed)
        functions.extend(_strings(entry.get("vulnerable_functions"), 200))
    ghsa_id = _one_line(_text(data.get("ghsa_id"), 30))
    return ParsedAdvisory(
        ghsa_id=ghsa_id if _GHSA_RE.match(ghsa_id) else "",
        cve_id=_one_line(_text(data.get("cve_id"), 30)),
        summary=_one_line(_text(data.get("summary"), 1000)),
        description=_text(data.get("description"), 4_000_000),
        state=_one_line(_text(data.get("state"), 30)),
        severity=_one_line(_text(data.get("severity"), 30)),
        cvss_vector=_one_line(_text(cvss.get("vector_string"), 120)),
        cvss_score=str(score)
        if isinstance(score, int | float) and not isinstance(score, bool)
        else "",
        cwes=tuple(dict.fromkeys(cwes[:_MAX_LIST])),
        created_at=iso_date(data.get("created_at")),
        html_url=_text(data.get("html_url"), 400),
        packages=tuple(dict.fromkeys(packages)),
        ranges=tuple(dict.fromkeys(ranges)),
        patched=tuple(dict.fromkeys(patched)),
        functions=tuple(dict.fromkeys(functions[:_MAX_LIST])),
    )


def advisory_uri(parsed: ParsedAdvisory, owner: str, repo: str) -> str:
    """The advisory's page on github.com (validated, never taken from the JSON blindly)."""
    base = f"https://github.com/{owner}/{repo}/security/advisories"
    if _HTML_URL_RE.match(parsed.html_url) and parsed.html_url.startswith(base):
        return parsed.html_url
    return f"{base}/{parsed.ghsa_id}" if parsed.ghsa_id else base


def build_report(parsed: ParsedAdvisory, owner: str, repo: str) -> Report:
    """A :class:`Report` whose body is the advisory description (the reporter's Markdown)."""
    uri = advisory_uri(parsed, owner, repo)
    base = ingest_markdown(parsed.description, uri=uri)
    warnings = list(base.warnings)
    if not parsed.description.strip():
        warnings.append("the advisory has no description text")
    return Report(
        id=content_report_id("gh_advisory", base.body),
        source=ReportSource(kind="gh_advisory", uri=uri),
        title=parsed.summary or base.title,
        body=base.body,
        source_map=base.source_map,
        code_blocks=base.code_blocks,
        reported_at=parsed.created_at,
        declared_target=DeclaredTarget(
            repo_url=f"https://github.com/{owner}/{repo}", versions=parsed.ranges
        ),
        warnings=tuple(warnings),
    )


def metadata_fields(parsed: ParsedAdvisory) -> tuple[tuple[str, str], ...]:
    severity = parsed.severity
    if parsed.cvss_score:
        severity = f"{severity} ({parsed.cvss_score})".strip()
    return (
        ("advisory", parsed.ghsa_id),
        ("cve", parsed.cve_id),
        ("state", parsed.state),
        ("created", parsed.created_at.isoformat() if parsed.created_at else ""),
        ("severity", severity),
        ("cvss", parsed.cvss_vector),
        ("cwe", "; ".join(parsed.cwes)),
        ("packages", "; ".join(parsed.packages)),
        ("vulnerable versions", "; ".join(parsed.ranges)),
        ("patched versions", "; ".join(parsed.patched)),
        ("vulnerable functions", ", ".join(parsed.functions)),
    )


@dataclass(frozen=True, slots=True)
class FetchedAdvisories:
    owner: str
    repo: str
    state: str
    reports: tuple[Report, ...]
    parsed: tuple[ParsedAdvisory, ...]
    fetched_urls: tuple[str, ...]
    warnings: tuple[str, ...] = ()

    def markdown_for(self, index: int) -> str:
        parsed = self.parsed[index]
        label = parsed.ghsa_id or f"advisory {index + 1}"
        return intake_markdown(
            self.reports[index],
            source_label=f"GitHub advisory {label} in {self.owner}/{self.repo}",
            fields=metadata_fields(parsed),
            fetched_urls=self.fetched_urls,
        )

    def markdown(self) -> str:
        """Every advisory, separated by thematic breaks (empty listings say so)."""
        if not self.reports:
            return (
                f"<!-- nikasha intake: no {self.state} advisories in {self.owner}/{self.repo} -->\n"
            )
        return "\n---\n\n".join(self.markdown_for(i) for i in range(len(self.reports)))


def next_link(link_header: str | None) -> str | None:
    """The ``rel="next"`` URL of a ``Link`` header, only when it stays on api.github.com."""
    if not link_header:
        return None
    match = _LINK_NEXT_RE.search(link_header[:8000])
    return match.group(1) if match else None


def fetch_advisories(
    owner_repo: str,
    *,
    state: str = "triage",
    online: bool,
    token: str | None = None,
    env: Mapping[str, str] | None = None,
) -> FetchedAdvisories:
    """List advisories. Refuses (without any request) unless online, and unless authenticated
    for any state but ``published``."""
    owner, repo = validate_owner_repo(owner_repo)
    wanted = validate_state(state)
    require_online(online, "GitHub")
    secret = token if token is not None else _optional_token(wanted, env)
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": API_VERSION,
    }
    if secret is not None:
        headers["Authorization"] = f"Bearer {secret}"
    url: str | None = (
        f"{API_BASE}{owner}/{repo}/security-advisories?state={wanted}&per_page={PER_PAGE}"
    )
    fetched: list[str] = []
    entries: list[object] = []
    warnings: list[str] = []
    for _ in range(MAX_PAGES):
        if url is None:
            break
        payload, response_headers = fetch_json(
            url, headers=headers, service="GitHub", hints=HTTP_HINTS
        )
        fetched.append(url)
        if not isinstance(payload, list):
            raise NikashaError(f"GitHub answer for {url} is not a list of advisories")
        entries.extend(payload)
        url = next_link(response_headers.get("link"))
    else:
        if url is not None:
            warnings.append(f"more than {MAX_PAGES} pages of advisories; the rest were not fetched")
    parsed = tuple(parse_advisory(item) for item in entries)
    reports = tuple(build_report(p, owner, repo) for p in parsed)
    return FetchedAdvisories(
        owner=owner,
        repo=repo,
        state=wanted,
        reports=reports,
        parsed=parsed,
        fetched_urls=tuple(fetched),
        warnings=tuple(warnings),
    )


# --- CLI ------------------------------------------------------------------------------------------


def register(app: typer.Typer) -> None:
    """Add the ``gh-advisories`` command to ``app``."""

    @app.command("gh-advisories")
    def gh_advisories(  # noqa: PLR0917 - a CLI command's options are its signature
        owner_repo: Annotated[str, typer.Argument(help="Repository as OWNER/REPO.")],
        state: Annotated[
            str, typer.Option("--state", help="triage (default), draft, published or closed.")
        ] = "triage",
        online: Annotated[
            bool, typer.Option("--online", help="Allow the HTTPS requests (required).")
        ] = False,
        as_json: Annotated[
            bool, typer.Option("--json", help="Emit the reports as JSON instead of Markdown.")
        ] = False,
        out: Annotated[
            str | None, typer.Option("--out", "-o", help="Write to this file instead of stdout.")
        ] = None,
        out_dir: Annotated[
            str | None,
            typer.Option("--out-dir", help="Write one Markdown file per advisory into this dir."),
        ] = None,
        check: Annotated[
            bool,
            typer.Option("--check", help="Also fact-check each advisory and print the replies."),
        ] = False,
        repo: Annotated[
            str | None,
            typer.Option("--repo", help="Repository to check against (default: the GitHub one)."),
        ] = None,
        ref: Annotated[str | None, typer.Option("--ref", help="Exact git ref to check.")] = None,
        version: Annotated[
            str | None, typer.Option("--version", help="Release the advisories are about.")
        ] = None,
        product: Annotated[str | None, typer.Option("--product", help="Product name.")] = None,
    ) -> None:
        """List a repository's private vulnerability reports (read-only) as Markdown.

        The token comes from GITHUB_TOKEN (or GH_TOKEN); --online is required, and nothing is
        requested without both (--state published alone may run anonymously: those advisories
        are public). Results are processed locally only and never written back to
        GitHub. With --check, each advisory is fact-checked against the repository (the
        GitHub one unless --repo says otherwise) and the reply Markdown is printed for a
        human to paste.

        Example:
            nikasha gh-advisories curl/curl --online
            nikasha gh-advisories curl/curl --online --state triage --check --version 8.5.0
        """
        try:
            fetched = fetch_advisories(owner_repo, state=state, online=online)
            for warning in fetched.warnings:
                Console(stderr=True).print(f"[yellow]warning:[/] {warning}", highlight=False)
            if out_dir:
                written = _write_dir(fetched, Path(out_dir))
                Console(stderr=True).print(
                    f"wrote {len(written)} advisories to {out_dir}", highlight=False
                )
                return
            if check:
                text = _check_all(
                    fetched,
                    repo=repo or f"https://github.com/{fetched.owner}/{fetched.repo}",
                    ref=ref,
                    version=version,
                    product=product,
                    online=online,
                )
            else:
                text = report_json(fetched.reports) if as_json else fetched.markdown()
        except NikashaError as exc:
            fail(exc)
        if out:
            Path(out).write_text(text, encoding="utf-8")
        else:
            emit_utf8(text)


def _file_name(fetched: FetchedAdvisories, index: int) -> str:
    return f"{fetched.parsed[index].ghsa_id or f'advisory-{index + 1}'}.md"


def _write_dir(fetched: FetchedAdvisories, directory: Path) -> tuple[Path, ...]:
    return tuple(
        write_private(directory / _file_name(fetched, i), fetched.markdown_for(i))
        for i in range(len(fetched.reports))
    )


def _check_all(
    fetched: FetchedAdvisories,
    *,
    repo: str,
    ref: str | None,
    version: str | None,
    product: str | None,
    online: bool,
) -> str:
    if not fetched.reports:
        return fetched.markdown()
    replies: list[str] = []
    for index in range(len(fetched.reports)):
        saved = write_private(
            intake_dir("github", fetched.owner, fetched.repo) / _file_name(fetched, index),
            fetched.markdown_for(index),
        )
        replies.append(
            check_and_render(
                saved, repo=repo, ref=ref, version=version, product=product, online=online
            )
        )
    return "\n\n---\n\n".join(replies)


__all__ = [
    "API_BASE",
    "ENV_TOKENS",
    "STATES",
    "FetchedAdvisories",
    "ParsedAdvisory",
    "advisory_uri",
    "build_report",
    "fetch_advisories",
    "metadata_fields",
    "next_link",
    "parse_advisory",
    "register",
    "token_from_env",
    "validate_owner_repo",
    "validate_state",
]
