# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""HackerOne intake (SPEC §8, §16.5): ``nikasha h1 REPORT_ID``.

**Read-only.** The command fetches one report through the documented program-owner API
(``GET https://api.hackerone.com/v1/reports/{id}``, HTTP Basic auth from the environment
variables ``HACKERONE_USER`` and ``HACKERONE_TOKEN``), turns it into a
:class:`~nikasha.model.report.Report`, and prints it as Markdown (or JSON). It never posts
anything back: the fact-check reply is printed for a human to paste.

Rules that are enforced here, each with a test:

* **No request without ``--online`` and without credentials** (P3). The refusal happens
  before any socket is opened, and the error names the variables instead of guessing.
* **HTTPS only**, one host, a timeout and a response-size cap; a redirect off HTTPS is
  refused after the fact. Every URL that was fetched is reported so it can be logged into
  ``result.environment.fetched_urls``.
* **The reporter is never read** (SPEC §7): the ``reporter`` relationship is not looked at,
  so no username, name or handle can end up in a result or in the Markdown.
* **Attachments** are downloaded from their pre-signed ``expiring_url`` (no credentials
  are sent to that host), under the caps of :mod:`nikasha.ingest.attachments`.

The Markdown this prints *is the report* (the reporter's ``vulnerability_information``,
unchanged, so ``nikasha check`` can read it back), with the intake metadata in a leading
HTML comment that the extractors ignore. Only that comment is escaped; escaping the body
would destroy the claims the checker needs. The reply Markdown that quotes report text
(``nikasha check --format markdown``) is where every value is escaped.

The HTTPS and output helpers here (:func:`fetch_bytes`, :func:`fetch_json`,
:func:`intake_markdown`, :func:`write_private`, :func:`emit_utf8`) are shared with
:mod:`nikasha.integrations.gh_advisories` until a common network module exists.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import sys
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Annotated, Any, NoReturn

import typer
from rich.console import Console

from nikasha.config import cache_dir, ensure_private_dir
from nikasha.errors import NikashaError
from nikasha.ingest.attachments import AttachmentLimits, store_attachments
from nikasha.ingest.markdown import ingest_markdown
from nikasha.ingest.text import report_id as content_report_id
from nikasha.model.report import Attachment, DeclaredTarget, Report, ReportSource
from nikasha.version import __version__

API_BASE = "https://api.hackerone.com/v1/reports/"
REPORT_URL_BASE = "https://hackerone.com/reports/"
ENV_USER = "HACKERONE_USER"
ENV_TOKEN = "HACKERONE_TOKEN"  # noqa: S105 - the variable's name, not a secret
USER_AGENT = f"nikasha/{__version__} (+https://github.com/rakshit-737/nikasha)"
REQUEST_TIMEOUT_S = 30.0
#: An API answer larger than this is refused (a report body is capped at 2 MB anyway).
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
#: Attachments beyond this many are listed but not downloaded.
MAX_ATTACHMENTS = 20
HTTP_HINTS: Mapping[int, str] = {
    401: f"the credentials in {ENV_USER}/{ENV_TOKEN} were rejected",
    403: "the API identifier has no access to this report",
    404: "no such report, or it is not visible to this program",
    429: "rate limited; try again later",
}

_REPORT_ID_RE = re.compile(r"\A[1-9][0-9]{0,11}\Z")
#: Printable ASCII without whitespace: a credential can never carry a header line break.
_CREDENTIAL_RE = re.compile(r"\A[!-~]{1,256}\Z")
_GITHUB_SCOPE_RE = re.compile(
    r"\A(?:https://)?github\.com/([A-Za-z0-9._-]{1,100})/([A-Za-z0-9._-]{1,100})/?\Z"
)
_MAX_TITLE_CHARS = 500


# --- shared helpers (also used by gh_advisories) -----------------------------------------------


def require_online(online: bool, service: str) -> None:
    """Refuse before any socket is opened unless the user passed ``--online`` (P3)."""
    if not online:
        raise NikashaError(
            f"fetching from {service} needs network access: pass --online to allow it "
            "(nothing was requested)"
        )


def _headers_of(response: object) -> dict[str, str]:
    raw = getattr(response, "headers", None)
    items = getattr(raw, "items", None)
    if not callable(items):
        return {}
    found: dict[str, str] = {}
    for key, value in items():
        found[str(key).lower()] = str(value)
    return found


def redact_url(url: str) -> str:
    """``url`` without its query and fragment, for messages and logs: a pre-signed download
    URL carries its signature there, and that is a credential while it lasts."""
    base = url.split("#", 1)[0]
    if "?" in base:
        return base.split("?", 1)[0] + "?[redacted]"
    return base


def fetch_bytes(
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    timeout: float = REQUEST_TIMEOUT_S,
    max_bytes: int = MAX_RESPONSE_BYTES,
    service: str = "the server",
    hints: Mapping[int, str] | None = None,
) -> tuple[bytes, dict[str, str]]:
    """One capped HTTPS GET. Returns the body and the lower-cased response headers.

    Any failure is a :class:`NikashaError` whose message never contains a credential.
    ``Authorization`` is sent as an *unredirected* header: urllib copies ordinary headers
    onto a redirected request, which would hand the credential to whatever host the
    redirect names.
    """
    shown = redact_url(url)
    if not url.startswith("https://"):
        raise NikashaError(f"refusing a non-HTTPS URL: {shown!r}")
    plain = {k: v for k, v in (headers or {}).items() if k.lower() != "authorization"}
    request = urllib.request.Request(  # noqa: S310 - https-only, checked just above
        url, headers={"User-Agent": USER_AGENT, **plain}
    )
    for key, value in (headers or {}).items():
        if key.lower() == "authorization":
            request.add_unredirected_header("Authorization", value)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            body: bytes = response.read(max_bytes + 1)
            final_url = str(getattr(response, "url", None) or url)
            response_headers = _headers_of(response)
    except urllib.error.HTTPError as exc:
        hint = (hints or HTTP_HINTS).get(int(exc.code))
        detail = f": {hint}" if hint else ""
        raise NikashaError(f"{service} answered HTTP {exc.code} for {shown}{detail}") from None
    except (urllib.error.URLError, OSError, ValueError) as exc:
        reason = getattr(exc, "reason", None)
        kind = type(reason).__name__ if isinstance(reason, BaseException) else type(exc).__name__
        raise NikashaError(f"could not fetch {shown}: {kind}") from None
    if not final_url.startswith("https://"):
        raise NikashaError(f"{service} redirected {shown} to a non-HTTPS URL; refused")
    if len(body) > max_bytes:
        raise NikashaError(f"{service} answer for {shown} exceeds {max_bytes:,} bytes; refused")
    return body, response_headers


def fetch_json(
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    timeout: float = REQUEST_TIMEOUT_S,
    max_bytes: int = MAX_RESPONSE_BYTES,
    service: str = "the server",
    hints: Mapping[int, str] | None = None,
) -> tuple[Any, dict[str, str]]:
    """:func:`fetch_bytes` plus a JSON decode. The value is untrusted data."""
    body, response_headers = fetch_bytes(
        url, headers=headers, timeout=timeout, max_bytes=max_bytes, service=service, hints=hints
    )
    try:
        return json.loads(body.decode("utf-8")), response_headers
    except (ValueError, RecursionError) as exc:  # includes JSONDecodeError, huge ints, nesting
        raise NikashaError(
            f"{service} answer for {redact_url(url)} is not JSON ({type(exc).__name__})"
        ) from None


def _text(value: object, limit: int | None = None) -> str:
    if not isinstance(value, str):
        return ""
    return value if limit is None else value[:limit]


def _one_line(value: str, limit: int = _MAX_TITLE_CHARS) -> str:
    flat = " ".join(value.split())
    return "".join(ch for ch in flat if ch == " " or ch.isprintable())[:limit].strip()


def _comment_safe(value: str, limit: int = 600) -> str:
    """One printable line that cannot close the HTML comment it sits in (only ``>`` can)."""
    return _one_line(value, limit).replace(">", "&gt;")


def iso_date(value: object) -> date | None:
    """The calendar day of an ISO-8601 timestamp such as ``2026-01-02T03:04:05.000Z``."""
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).date()
    except ValueError:
        return None


def intake_markdown(
    report: Report,
    *,
    source_label: str,
    fields: Sequence[tuple[str, str]],
    fetched_urls: Sequence[str],
) -> str:
    """The report as a Markdown file ``nikasha check`` can read back.

    The title becomes the first heading; the intake metadata sits in an HTML comment (which
    the extractors skip, so ``state: triaged`` never becomes a claim); the body follows
    unchanged. Only the comment is escaped: it is the one part this module writes itself.
    """
    lines: list[str] = []
    if report.title:
        lines += [f"# {_one_line(report.title)}", ""]
    lines += ["<!--", f"nikasha intake: {_comment_safe(source_label)}"]
    lines += [f"{label}: {_comment_safe(value)}" for label, value in fields if value]
    lines += [f"fetched: {_comment_safe(url)}" for url in fetched_urls]
    lines += ["The reporter's identity was not recorded.", "-->", ""]
    lines.append(report.body)
    return "\n".join(lines).rstrip("\n") + "\n"


def report_json(reports: Sequence[Report]) -> str:
    """Reports as sorted-key JSON (one object, or a list when several)."""
    data = [r.model_dump(mode="json", by_alias=True) for r in reports]
    payload: object = data[0] if len(data) == 1 else data
    return json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False) + "\n"


def write_private(path: Path, text: str) -> Path:
    """Write ``text`` to ``path`` as a 0600 file (created or replaced) inside a 0700 dir."""
    ensure_private_dir(path.parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(text.encode("utf-8"))
    return path


def intake_dir(*parts: str) -> Path:
    """``<cache>/intake/<parts…>``, private; fetched reports are kept for offline re-checks."""
    return ensure_private_dir(cache_dir().joinpath("intake", *parts))


def emit_utf8(text: str) -> None:
    """Write output as UTF-8 bytes whatever the console encoding (e.g. cp1252)."""
    stream = sys.stdout
    buffer = getattr(stream, "buffer", None)
    if buffer is None:
        stream.write(text)
    else:
        stream.flush()
        buffer.write(text.encode("utf-8"))
        buffer.flush()


def fail(exc: NikashaError) -> NoReturn:
    """Print an expected failure and exit 1 (the CLI contract for :class:`NikashaError`)."""
    Console(stderr=True).print(f"[red]error:[/] {exc}", markup=True, highlight=False)
    raise typer.Exit(code=1)


def check_and_render(
    path: Path,
    *,
    repo: str | None,
    ref: str | None,
    version: str | None,
    product: str | None,
    online: bool,
) -> str:
    """Run the full pipeline over a saved intake file and return the reply Markdown."""
    from nikasha.pipeline import check_report  # noqa: PLC0415 - keeps intake imports light
    from nikasha.render.markdown import render_markdown  # noqa: PLC0415

    checked = check_report(
        path, repo=repo, ref=ref, version=version, product=product, online=online
    )
    return render_markdown(checked)


# --- HackerOne ----------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Credentials:
    """API identifier and token. ``basic_auth`` is the only thing ever put on the wire."""

    user: str
    token: str

    def basic_auth(self) -> str:
        raw = f"{self.user}:{self.token}".encode()
        return "Basic " + base64.b64encode(raw).decode("ascii")


def credentials_from_env(env: Mapping[str, str] | None = None) -> Credentials:
    """Read ``HACKERONE_USER`` and ``HACKERONE_TOKEN``; refuse when either is missing or
    contains anything but printable ASCII (which could otherwise inject a header)."""
    source = os.environ if env is None else env
    user = source.get(ENV_USER, "")
    token = source.get(ENV_TOKEN, "")
    if not user or not token:
        raise NikashaError(
            f"HackerOne credentials are not set: export {ENV_USER} (the API identifier) and "
            f"{ENV_TOKEN} (the API token) (nothing was requested)"
        )
    if not _CREDENTIAL_RE.match(user) or not _CREDENTIAL_RE.match(token):
        raise NikashaError(
            f"{ENV_USER} and {ENV_TOKEN} must be printable ASCII without spaces "
            "(nothing was requested)"
        )
    return Credentials(user=user, token=token)


def validate_report_id(report_id_text: str) -> str:
    """HackerOne report IDs are decimal numbers; anything else could reshape the URL."""
    candidate = report_id_text.strip().lstrip("#")
    if not _REPORT_ID_RE.match(candidate):
        raise NikashaError(f"not a HackerOne report ID (digits only): {report_id_text!r}")
    return candidate


@dataclass(frozen=True, slots=True)
class AttachmentInfo:
    file_name: str
    content_type: str
    file_size: int | None
    expiring_url: str


@dataclass(frozen=True, slots=True)
class ParsedReport:
    """The fields Nikasha keeps from the API answer. There is no reporter field on purpose."""

    report_id: str
    title: str
    body: str
    state: str
    created_at: date | None
    program: str
    severity_rating: str
    severity_score: str
    weakness_name: str
    weakness_id: str
    asset_identifier: str
    asset_type: str
    attachments: tuple[AttachmentInfo, ...]


def _dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _is_number(value: object) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool)


def _attributes(relationships: dict[str, Any], name: str) -> dict[str, Any]:
    return _dict(_dict(_dict(relationships.get(name)).get("data")).get("attributes"))


def parse_report(payload: object, report_id_text: str) -> ParsedReport:
    """Pick the report fields out of the (untrusted) API JSON. Missing pieces stay empty."""
    data = _dict(_dict(payload).get("data"))
    attributes = _dict(data.get("attributes"))
    relationships = _dict(data.get("relationships"))
    severity = _attributes(relationships, "severity")
    weakness = _attributes(relationships, "weakness")
    program = _attributes(relationships, "program")
    scope = _attributes(relationships, "structured_scope")
    attachments: list[AttachmentInfo] = []
    items = _dict(relationships.get("attachments")).get("data")
    for item in items[: MAX_ATTACHMENTS * 5] if isinstance(items, list) else ():
        entry = _dict(_dict(item).get("attributes"))
        size = entry.get("file_size")
        attachments.append(
            AttachmentInfo(
                file_name=_one_line(_text(entry.get("file_name"), 255), 255),
                content_type=_one_line(_text(entry.get("content_type"), 100), 100),
                file_size=size if isinstance(size, int) and not isinstance(size, bool) else None,
                expiring_url=_text(entry.get("expiring_url"), 2000),
            )
        )
    score = severity.get("score")
    return ParsedReport(
        report_id=report_id_text,
        title=_one_line(_text(attributes.get("title"))),
        body=_text(attributes.get("vulnerability_information")),
        state=_one_line(_text(attributes.get("state"), 50)),
        created_at=iso_date(attributes.get("created_at")),
        program=_one_line(_text(program.get("handle"), 100)),
        severity_rating=_one_line(_text(severity.get("rating"), 50)),
        severity_score=str(score) if _is_number(score) else "",
        weakness_name=_one_line(_text(weakness.get("name"), 200)),
        weakness_id=_one_line(_text(weakness.get("external_id"), 50)),
        asset_identifier=_one_line(_text(scope.get("asset_identifier"), 500)),
        asset_type=_one_line(_text(scope.get("asset_type"), 50)),
        attachments=tuple(attachments),
    )


def repo_url_from_scope(asset_identifier: str, asset_type: str) -> str | None:
    """A GitHub repository URL when the structured scope is a source-code asset there."""
    if asset_type.upper() != "SOURCE_CODE":
        return None
    match = _GITHUB_SCOPE_RE.match(asset_identifier)
    if match is None:
        return None
    return f"https://github.com/{match.group(1)}/{match.group(2)}"


def download_attachments(
    items: Sequence[AttachmentInfo],
    run_dir: Path,
    limits: AttachmentLimits = AttachmentLimits(),  # noqa: B008  (immutable dataclass)
) -> tuple[tuple[Attachment, ...], tuple[str, ...], tuple[str, ...]]:
    """Fetch pre-signed attachment URLs (HTTPS only, no credentials) under the caps.

    Returns the stored attachments, the warnings for those skipped, and the fetched URLs.
    """
    fetched: list[str] = []
    warnings: list[str] = []
    payloads: list[tuple[str, bytes]] = []
    for index, item in enumerate(items):
        name = item.file_name or f"attachment-{index + 1}"
        if index >= MAX_ATTACHMENTS:
            warnings.append(f"attachment {name} not downloaded: more than {MAX_ATTACHMENTS}")
            continue
        if item.file_size is not None and item.file_size > limits.per_file_bytes:
            warnings.append(
                f"attachment {name} not downloaded: {item.file_size:,} bytes exceeds the cap"
            )
            continue
        if not item.expiring_url.startswith("https://"):
            warnings.append(f"attachment {name} not downloaded: no HTTPS URL")
            continue
        try:
            body, _ = fetch_bytes(
                item.expiring_url, max_bytes=limits.per_file_bytes, service="HackerOne"
            )
        except NikashaError as exc:
            warnings.append(f"attachment {name} not downloaded: {exc}")
            continue
        fetched.append(redact_url(item.expiring_url))
        payloads.append((name, body))
    stored, skipped = store_attachments(payloads, run_dir, limits)
    return stored, tuple(warnings) + skipped, tuple(fetched)


def build_report(
    parsed: ParsedReport,
    attachments: tuple[Attachment, ...] = (),
    warnings: Sequence[str] = (),
) -> Report:
    """A :class:`Report` from the parsed fields: the body is the reporter's Markdown."""
    uri = REPORT_URL_BASE + parsed.report_id
    base = ingest_markdown(parsed.body, uri=uri)
    extra = list(warnings)
    if not parsed.body.strip():
        extra.append("the HackerOne report has no vulnerability information text")
    repo_url = repo_url_from_scope(parsed.asset_identifier, parsed.asset_type)
    return Report(
        id=content_report_id("hackerone", base.body),
        source=ReportSource(kind="hackerone", uri=uri),
        title=parsed.title or base.title,
        body=base.body,
        source_map=base.source_map,
        code_blocks=base.code_blocks,
        attachments=attachments,
        reported_at=parsed.created_at,
        declared_target=DeclaredTarget(repo_url=repo_url) if repo_url else None,
        warnings=base.warnings + tuple(extra),
    )


def metadata_fields(parsed: ParsedReport) -> tuple[tuple[str, str], ...]:
    """The intake metadata lines for :func:`intake_markdown` (empty values are dropped)."""
    severity = parsed.severity_rating
    if parsed.severity_score:
        severity = f"{severity} ({parsed.severity_score})".strip()
    weakness = " ".join(p for p in (parsed.weakness_id.upper(), parsed.weakness_name) if p)
    names = ", ".join(a.file_name or "(unnamed)" for a in parsed.attachments)
    return (
        ("report", REPORT_URL_BASE + parsed.report_id),
        ("program", parsed.program),
        ("state", parsed.state),
        ("created", parsed.created_at.isoformat() if parsed.created_at else ""),
        ("severity", severity),
        ("weakness", weakness),
        ("scope", " ".join(p for p in (parsed.asset_type, parsed.asset_identifier) if p)),
        ("attachments", f"{len(parsed.attachments)} ({names})" if parsed.attachments else ""),
    )


@dataclass(frozen=True, slots=True)
class Fetched:
    report: Report
    parsed: ParsedReport
    fetched_urls: tuple[str, ...]

    def markdown(self) -> str:
        return intake_markdown(
            self.report,
            source_label=f"HackerOne report {self.parsed.report_id}",
            fields=metadata_fields(self.parsed),
            fetched_urls=self.fetched_urls,
        )


def fetch_report(
    report_id_text: str,
    *,
    online: bool,
    credentials: Credentials | None = None,
    env: Mapping[str, str] | None = None,
    with_attachments: bool = True,
    run_dir: Path | None = None,
    limits: AttachmentLimits = AttachmentLimits(),  # noqa: B008  (immutable dataclass)
) -> Fetched:
    """Fetch one report. Refuses (without any request) unless online and authenticated."""
    rid = validate_report_id(report_id_text)
    require_online(online, "HackerOne")
    creds = credentials if credentials is not None else credentials_from_env(env)
    url = API_BASE + rid
    payload, _ = fetch_json(
        url,
        headers={"Authorization": creds.basic_auth(), "Accept": "application/json"},
        service="HackerOne",
    )
    parsed = parse_report(payload, rid)
    fetched = [url]
    stored: tuple[Attachment, ...] = ()
    warnings: tuple[str, ...] = ()
    if with_attachments and parsed.attachments:
        target = run_dir if run_dir is not None else _default_run_dir(rid)
        stored, warnings, urls = download_attachments(parsed.attachments, target, limits)
        fetched.extend(urls)
    return Fetched(
        report=build_report(parsed, stored, warnings), parsed=parsed, fetched_urls=tuple(fetched)
    )


def _default_run_dir(rid: str) -> Path:
    digest = hashlib.sha256(rid.encode("utf-8")).hexdigest()[:16]
    root = ensure_private_dir(cache_dir() / "attachments")
    run_dir = root / f"hackerone-{digest}"
    if run_dir.exists():
        shutil.rmtree(run_dir, ignore_errors=True)
    return run_dir


# --- CLI ------------------------------------------------------------------------------------------


def register(app: typer.Typer) -> None:
    """Add the ``h1`` command to ``app``."""

    @app.command("h1")
    def h1(  # noqa: PLR0917 - a CLI command's options are its signature
        report_id: Annotated[
            str, typer.Argument(help="HackerOne report ID (digits only), e.g. 123456.")
        ],
        online: Annotated[
            bool, typer.Option("--online", help="Allow the HTTPS request (required).")
        ] = False,
        as_json: Annotated[
            bool, typer.Option("--json", help="Emit the report as JSON instead of Markdown.")
        ] = False,
        out: Annotated[
            str | None, typer.Option("--out", "-o", help="Write to this file instead of stdout.")
        ] = None,
        no_attachments: Annotated[
            bool, typer.Option("--no-attachments", help="Do not download attachments.")
        ] = False,
        repo: Annotated[
            str | None,
            typer.Option("--repo", help="Also fact-check against this repository (URL or path)."),
        ] = None,
        ref: Annotated[str | None, typer.Option("--ref", help="Exact git ref to check.")] = None,
        version: Annotated[
            str | None, typer.Option("--version", help="Release the report is about.")
        ] = None,
        product: Annotated[str | None, typer.Option("--product", help="Product name.")] = None,
    ) -> None:
        """Fetch a HackerOne report (program owners; read-only) and print it as Markdown.

        Credentials come from HACKERONE_USER and HACKERONE_TOKEN; --online is required, and
        nothing is requested without both. Nothing is ever posted back to HackerOne. With
        --repo, the report is also fact-checked and the reply Markdown is printed instead,
        ready to paste into the report by hand.

        Example:
            nikasha h1 123456 --online -o report.md
            nikasha h1 123456 --online --repo https://github.com/curl/curl
        """
        try:
            fetched = fetch_report(report_id, online=online, with_attachments=not no_attachments)
            markdown = fetched.markdown()
            if repo is not None:
                saved = write_private(
                    intake_dir("hackerone") / f"report-{fetched.parsed.report_id}.md", markdown
                )
                Console(stderr=True).print(f"report saved to {saved}", highlight=False)
                text = check_and_render(
                    saved, repo=repo, ref=ref, version=version, product=product, online=online
                )
            else:
                text = report_json([fetched.report]) if as_json else markdown
        except NikashaError as exc:
            fail(exc)
        if out:
            Path(out).write_text(text, encoding="utf-8")
        else:
            emit_utf8(text)


__all__ = [
    "API_BASE",
    "ENV_TOKEN",
    "ENV_USER",
    "AttachmentInfo",
    "Credentials",
    "Fetched",
    "ParsedReport",
    "build_report",
    "credentials_from_env",
    "download_attachments",
    "fetch_bytes",
    "fetch_json",
    "fetch_report",
    "intake_markdown",
    "metadata_fields",
    "parse_report",
    "redact_url",
    "register",
    "report_json",
    "require_online",
    "validate_report_id",
]
