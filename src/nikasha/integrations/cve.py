# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""``nikasha cve``: a CVE JSON 5.x record, checked like any other report (SPEC §8, §16.1).

A CVE record is a report with structure. The numbering authority's container carries the prose
(``descriptions``), the affected products with their version ranges, the references, the
problem types (CWE) and the metrics (CVSS). This module turns one record into a
:class:`~nikasha.model.report.Report` whose body is Markdown the ordinary extractors
already read, carries the affected products and versions as the report's
:class:`~nikasha.model.report.DeclaredTarget`, and then runs the normal check pipeline on
it. Nothing about how claims are checked or fused is special-cased for CVE input.

Three rules shape the module:

* **The record is hostile input (P7).** Nothing about its shape is assumed: every field is
  type-checked, every list is capped, and every string that lands in the body is cleaned
  of control characters and, for the structured lines, of the Markdown that could hide the
  sections after it. A record that cannot be read at all is an error, never a verdict.
* **Offline by default (P3).** A file is read in place. A bare CVE ID needs ``--online``;
  without it the command refuses *before* touching the network, and no request is made.
  Online, the record comes from the CVE Program's own store over HTTPS with stdlib
  ``urllib`` (ADR 0002), under a timeout and a size cap. The URL is built by
  :func:`nikasha.checks.c15_references.cve_url`, the one place that knows the layout.
* **A record does not vouch for itself.** The body never repeats the record's own CVE
  ID, so C15 cannot fetch that record and count it as support for the report it came
  from. The structured lines never carry it, and every mention of it in the free prose
  (descriptions, rejection notices) is replaced by ``this record``. The ID lives in the
  report title and in the source URI instead.

The heavy imports (pipeline, checks, tree-sitter) are deferred to the functions that need
them, so registering the command keeps ``nikasha version`` fast.
"""

from __future__ import annotations

import json
import re
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import date
from hashlib import sha256
from http.client import HTTPMessage, HTTPResponse
from pathlib import Path
from typing import IO, TYPE_CHECKING, Annotated, Any

import typer
from rich.console import Console
from rich.text import Text

from nikasha.errors import NikashaError

if TYPE_CHECKING:
    from nikasha.fuse.verdict import Thresholds
    from nikasha.model.report import DeclaredTarget, Report
    from nikasha.pipeline import CheckReport

#: ``CVE-YYYY-NNNN`` with four to seven digits, as the CVE Program defines it.
CVE_ID_RE = re.compile(r"\ACVE-(?P<year>\d{4})-(?P<number>\d{4,7})\Z", re.IGNORECASE)

# --- caps: a record can be 4 MB of anything, and the body stays readable regardless -------
MAX_TITLE_CHARS = 300
MAX_DESCRIPTIONS = 8
MAX_DESCRIPTION_CHARS = 20_000
MAX_AFFECTED = 64
MAX_VERSIONS = 64
MAX_REFERENCES = 64
MAX_TAGS = 8
MAX_PROBLEM_TYPES = 16
MAX_PROBLEM_CHARS = 200
MAX_METRICS = 8
MAX_NAME_CHARS = 120
MAX_DECLARED_VERSIONS = 50
#: How long a value is quoted in a warning about it.
_QUOTE_CHARS = 40

# Every pattern is anchored and every quantifier bounded (SPEC §9, §19.2).
_VERSION_RE = re.compile(r"\A[0-9A-Za-z][0-9A-Za-z._+~:-]{0,63}\Z")
_URL_RE = re.compile(r"\Ahttps?://[0-9A-Za-z._~:/?#\[\]@!$&'()*+,;=%-]{1,2000}\Z")
_CWE_RE = re.compile(r"\ACWE-(?P<n>\d{1,5})\Z", re.IGNORECASE)
_DATE_PREFIX_RE = re.compile(r"\A(?P<y>\d{4})-(?P<m>\d{2})-(?P<d>\d{2})")
_STATE_RE = re.compile(r"\A[A-Z]{1,16}\Z")
_TAG_RE = re.compile(r"\A[0-9A-Za-z_.-]{1,40}\Z")
_CVSS_RE = re.compile(r"\ACVSS:(?P<ver>3\.[01]|4\.0)(?:/[A-Za-z]{1,3}:[A-Za-z]{1,2}){4,40}\Z")
_CVSS2_RE = re.compile(r"\AAV:[LAN]/AC:[HML]/Au:[MSN]/C:[NPC]/I:[NPC]/A:[NPC]\Z")

_STATUSES = frozenset({"affected", "unaffected", "unknown"})
_SEVERITIES = frozenset({"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"})
#: The CVSS blocks a metrics entry may carry, in the order they are read.
_CVSS_KEYS = ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0")
#: Ranges written as ``version: "0"`` (or ``"*"``) mean "from the first release".
_UNBOUNDED = frozenset({"0", "*"})
_MAX_SCORE = 10.0

_FORMATS = ("terminal", "json", "markdown", "html")
_VERDICT_ORDER = ("GROUNDED", "REPRODUCED", "MIXED", "UNGROUNDED", "INSUFFICIENT")


# --- the parsed record ---------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AffectedVersion:
    """One ``affected[].versions[]`` entry: a version or a range, with its status."""

    version: str
    status: str
    less_than: str | None = None
    less_than_or_equal: str | None = None
    version_type: str | None = None


@dataclass(frozen=True, slots=True)
class AffectedProduct:
    """One ``affected[]`` entry. Placeholder names (``n/a``) are already dropped."""

    vendor: str | None = None
    product: str | None = None
    package_name: str | None = None
    repo: str | None = None
    default_status: str | None = None
    versions: tuple[AffectedVersion, ...] = ()


@dataclass(frozen=True, slots=True)
class Reference:
    url: str
    tags: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ProblemType:
    cwe: str | None
    description: str | None


@dataclass(frozen=True, slots=True)
class Metric:
    cvss_version: str
    vector: str
    base_score: float | None = None
    severity: str | None = None


@dataclass(frozen=True, slots=True)
class CveRecord:
    """The validated parts of a CVE JSON 5.x record (SPEC §8).

    ``warnings`` lists everything that was skipped or looked off, so a run stays
    explainable (P6) even when the record was not what it claimed to be.
    """

    cve_id: str
    state: str | None
    title: str | None
    descriptions: tuple[str, ...]
    rejected_reasons: tuple[str, ...]
    affected: tuple[AffectedProduct, ...]
    references: tuple[Reference, ...]
    problem_types: tuple[ProblemType, ...]
    metrics: tuple[Metric, ...]
    date_published: date | None
    body_sha256: str
    warnings: tuple[str, ...] = ()


# --- hostile-shape helpers -----------------------------------------------------------------


def _dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def _text(value: object) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _quote(value: object) -> str:
    return repr(_one_line(str(value), _QUOTE_CHARS))


def _one_line(text: str, cap: int) -> str:
    """Printable text on one line: whitespace collapsed, control and format characters
    dropped, and the fence and code-span characters removed so a name can never open a
    Markdown block that swallows the sections after it."""
    kept = "".join(ch for ch in text if (ch.isprintable() or ch.isspace()) and ch not in "`~")
    return " ".join(kept.split())[:cap].rstrip()


def _prose(text: str, cap: int) -> str:
    """Multi-line prose: newlines and tabs kept, other whitespace normalized to a space,
    every other non-printable character dropped, capped."""
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    kept = "".join(
        ch if ch.isprintable() or ch in "\n\t" else (" " if ch.isspace() else "")
        for ch in normalized
    )
    return kept[:cap].strip()


def _cve_id(value: object) -> str | None:
    text = _text(value)
    match = CVE_ID_RE.match(text.strip()) if text else None
    if match is None:
        return None
    return f"CVE-{match.group('year')}-{match.group('number')}"


def _version(value: object) -> str | None:
    text = _text(value)
    if text is None:
        return None
    text = text.strip()
    return text if text == "*" or _VERSION_RE.match(text) else None


def _status(value: object) -> str | None:
    text = _text(value)
    lowered = text.strip().lower() if text else ""
    return lowered if lowered in _STATUSES else None


def _url(value: object, *, https_only: bool = False) -> str | None:
    text = _text(value)
    url = text.strip() if text else ""
    if not _URL_RE.match(url) or (https_only and not url.startswith("https://")):
        return None
    return url


def _cwe(value: object) -> str | None:
    text = _text(value)
    match = _CWE_RE.match(text.strip()) if text else None
    return f"CWE-{int(match.group('n'))}" if match else None


def _date(value: object) -> date | None:
    text = _text(value)
    match = _DATE_PREFIX_RE.match(text.strip()) if text else None
    if match is None:
        return None
    try:
        return date(int(match.group("y")), int(match.group("m")), int(match.group("d")))
    except ValueError:
        return None


def _score(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    if not 0.0 <= value <= _MAX_SCORE:
        return None
    return round(float(value), 1)


def _severity(value: object) -> str | None:
    text = _text(value)
    word = text.strip().upper() if text else ""
    return word.capitalize() if word in _SEVERITIES else None


def _capped(items: list[Any], cap: int, what: str, notes: list[str]) -> list[Any]:
    if len(items) > cap:
        notes.append(f"{len(items)} {what} in the record; the first {cap} were kept")
        return items[:cap]
    return items


def _skipped(count: int, what: str, notes: list[str]) -> None:
    if count:
        noun = "entry was" if count == 1 else "entries were"
        notes.append(f"{count} {what} {noun} skipped: not readable")


# --- the numbering authority's container, block by block ------------------------------------


def _self_id_re(cve_id: str) -> re.Pattern[str]:
    """The record's own ID as a whole word (a fixed literal between word boundaries: linear)."""
    return re.compile(rf"\b{re.escape(cve_id)}\b", re.IGNORECASE)


def _descriptions(
    raw: object, notes: list[str], field: str, cve_id: str | None = None
) -> tuple[str, ...]:
    """English descriptions when the record has any, otherwise whatever language it has.

    Mentions of the record's own ``cve_id`` become ``this record`` (a record does not
    vouch for itself; see the module docstring)."""
    self_id = _self_id_re(cve_id) if cve_id else None
    if raw is not None and not isinstance(raw, list):
        notes.append(f"{field} is not a list and was ignored")
    english: list[str] = []
    other: list[str] = []
    skipped = 0
    for entry in _list(raw):
        item = _dict(entry)
        value = _text(item.get("value"))
        if value is None:
            skipped += 1
            continue
        lang = item.get("lang")
        bucket = english if isinstance(lang, str) and lang.lower().startswith("en") else other
        text = _prose(value, MAX_DESCRIPTION_CHARS)
        if self_id is not None:
            text = self_id.sub("this record", text)
        bucket.append(text)
    _skipped(skipped, field, notes)
    chosen = list(dict.fromkeys(english or other))
    return tuple(_capped(chosen, MAX_DESCRIPTIONS, field, notes))


def _name(value: object, placeholders: frozenset[str]) -> str | None:
    text = _text(value)
    cleaned = _one_line(text, MAX_NAME_CHARS) if text else ""
    return cleaned if cleaned and cleaned.lower() not in placeholders else None


def _versions(raw: object, notes: list[str]) -> tuple[AffectedVersion, ...]:
    out: list[AffectedVersion] = []
    skipped = 0
    for entry in _list(raw):
        item = _dict(entry)
        version = _version(item.get("version"))
        if version is None:
            skipped += 1
            continue
        kind = _text(item.get("versionType"))
        out.append(
            AffectedVersion(
                version=version,
                status=_status(item.get("status")) or "unknown",
                less_than=_version(item.get("lessThan")),
                less_than_or_equal=_version(item.get("lessThanOrEqual")),
                version_type=_one_line(kind, 32) if kind else None,
            )
        )
    _skipped(skipped, "version", notes)
    return tuple(_capped(out, MAX_VERSIONS, "versions of one product", notes))


def _derived_affected(product: AffectedProduct) -> AffectedVersion | None:
    """The affected range a ``defaultStatus: affected`` product implies, or ``None``.

    Many numbering authorities list only where the fix landed: ``defaultStatus`` is
    ``affected`` and one ``unaffected`` entry runs from a version upwards with no end
    (``1.3.0``, ``lessThan: *``). Everything below that version is then affected. Only
    that one unambiguous shape is read; several open-ended branches, or any explicit
    ``affected`` entry, leave the record as written (P4).
    """
    if product.default_status != "affected":
        return None
    if any(v.status == "affected" for v in product.versions):
        return None
    open_ended = [
        v
        for v in product.versions
        if v.status == "unaffected"
        and v.version not in _UNBOUNDED
        and v.less_than_or_equal is None
        and v.less_than in _UNBOUNDED
    ]
    if len(open_ended) != 1:
        return None
    fixed = open_ended[0]
    return AffectedVersion(
        version="0", status="affected", less_than=fixed.version, version_type=fixed.version_type
    )


def _affected(raw: object, notes: list[str]) -> tuple[AffectedProduct, ...]:
    from nikasha.checks.c15_references import PLACEHOLDER_PRODUCTS  # noqa: PLC0415

    out: list[AffectedProduct] = []
    skipped = 0
    for entry in _list(raw):
        item = _dict(entry)
        product = AffectedProduct(
            vendor=_name(item.get("vendor"), PLACEHOLDER_PRODUCTS),
            product=_name(item.get("product"), PLACEHOLDER_PRODUCTS),
            package_name=_name(item.get("packageName"), PLACEHOLDER_PRODUCTS),
            repo=_url(item.get("repo"), https_only=True),
            default_status=_status(item.get("defaultStatus")),
            versions=_versions(item.get("versions"), notes) if item else (),
        )
        if product == AffectedProduct():
            skipped += 1
            continue
        derived = _derived_affected(product)
        if derived is not None:
            notes.append(
                f"{product.product or product.package_name or 'a product'}: affected before "
                f"{derived.less_than}, derived from defaultStatus 'affected' and the one "
                "open-ended unaffected range"
            )
            product = replace(product, versions=(derived, *product.versions))
        out.append(product)
    _skipped(skipped, "affected", notes)
    return tuple(_capped(out, MAX_AFFECTED, "affected entries", notes))


def _references(raw: object, notes: list[str]) -> tuple[Reference, ...]:
    seen: dict[str, Reference] = {}
    skipped = 0
    for entry in _list(raw):
        item = _dict(entry)
        url = _url(item.get("url"))
        if url is None:
            skipped += 1
            continue
        tags = tuple(t for t in _list(item.get("tags")) if isinstance(t, str) and _TAG_RE.match(t))
        seen.setdefault(url, Reference(url=url, tags=tags[:MAX_TAGS]))
    _skipped(skipped, "reference", notes)
    return tuple(_capped(list(seen.values()), MAX_REFERENCES, "references", notes))


def _problem_types(raw: object, notes: list[str]) -> tuple[ProblemType, ...]:
    seen: dict[tuple[str | None, str | None], ProblemType] = {}
    skipped = 0
    for entry in _list(raw):
        for description in _list(_dict(entry).get("descriptions")):
            item = _dict(description)
            cwe = _cwe(item.get("cweId"))
            text = _text(item.get("description"))
            words = _one_line(text, MAX_PROBLEM_CHARS) if text else ""
            if cwe and words.upper().startswith(cwe):
                words = words[len(cwe) :].lstrip(" :-")
            if cwe is None and not words:
                skipped += 1
                continue
            key = (cwe, words or None)
            seen.setdefault(key, ProblemType(cwe=cwe, description=words or None))
    _skipped(skipped, "problem type", notes)
    return tuple(_capped(list(seen.values()), MAX_PROBLEM_TYPES, "problem types", notes))


def _metric(block: dict[str, Any]) -> Metric | None:
    vector = _text(block.get("vectorString"))
    if vector is None:
        return None
    vector = vector.strip()
    match = _CVSS_RE.match(vector)
    if match is not None:
        version = match.group("ver")
    elif _CVSS2_RE.match(vector):
        version = "2.0"
    else:
        return None
    return Metric(
        cvss_version=version,
        vector=vector,
        base_score=_score(block.get("baseScore")),
        severity=_severity(block.get("baseSeverity")),
    )


def _metrics(raw: object, notes: list[str]) -> tuple[Metric, ...]:
    seen: dict[str, Metric] = {}
    skipped = 0
    for entry in _list(raw):
        item = _dict(entry)
        for key in _CVSS_KEYS:
            block = _dict(item.get(key))
            if not block:
                continue
            metric = _metric(block)
            if metric is None:
                skipped += 1
                continue
            seen.setdefault(metric.vector, metric)
    _skipped(skipped, "CVSS metric", notes)
    return tuple(_capped(list(seen.values()), MAX_METRICS, "CVSS metrics", notes))


# --- reading a record ------------------------------------------------------------------------


def parse_record(
    data: object, *, body_sha256: str = "", expected_id: str | None = None
) -> CveRecord:
    """Validate a decoded JSON document as a CVE 5.x record.

    Only ``cveMetadata`` with a readable ``cveId`` is required (``expected_id`` stands in
    when the record was fetched by ID). Everything else is optional, and whatever is
    missing or malformed becomes a warning rather than an error, because a record with
    an odd shape is still a record someone published.
    """
    if not isinstance(data, dict):
        raise NikashaError("not a CVE JSON record: the top level is not a JSON object")
    notes: list[str] = []
    meta = _dict(data.get("cveMetadata"))
    if not meta:
        raise NikashaError("not a CVE JSON 5.x record: cveMetadata is missing")
    if data.get("dataType") != "CVE_RECORD":
        notes.append(f"dataType is {_quote(data.get('dataType'))}, not 'CVE_RECORD'")
    data_version = data.get("dataVersion")
    if not (isinstance(data_version, str) and data_version.startswith("5.")):
        notes.append(f"dataVersion is {_quote(data_version)}, not 5.x; fields were read as 5.x")
    cve_id = _cve_id(meta.get("cveId"))
    if cve_id is None:
        if expected_id is None:
            raise NikashaError(
                "not a CVE JSON 5.x record: cveMetadata.cveId is missing or malformed"
            )
        notes.append(f"the record carries no readable cveMetadata.cveId; using {expected_id}")
        cve_id = expected_id
    elif expected_id is not None and cve_id.upper() != expected_id.upper():
        notes.append(f"the record is for {cve_id}, not the requested {expected_id}")
    state_text = _text(meta.get("state"))
    state = _one_line(state_text, 16).upper() if state_text else ""
    containers = _dict(data.get("containers"))
    authority = _dict(containers.get("cna"))  # codespell:ignore cna
    if not authority:
        notes.append("the record has no numbering-authority container; only its metadata was read")
    title_text = _text(authority.get("title"))
    title = _one_line(title_text, MAX_TITLE_CHARS) if title_text else ""
    record = CveRecord(
        cve_id=cve_id,
        state=state if _STATE_RE.match(state) else None,
        title=title or None,
        descriptions=_descriptions(authority.get("descriptions"), notes, "descriptions", cve_id),
        rejected_reasons=_descriptions(
            authority.get("rejectedReasons"), notes, "rejectedReasons", cve_id
        ),
        affected=_affected(authority.get("affected"), notes),
        references=_references(authority.get("references"), notes),
        problem_types=_problem_types(authority.get("problemTypes"), notes),
        metrics=_metrics(authority.get("metrics"), notes),
        date_published=_date(meta.get("datePublished")),
        body_sha256=body_sha256,
    )
    if record.state == "REJECTED":
        notes.append(
            f"{cve_id} is REJECTED: the CVE Program withdrew this record, so its content "
            "is the withdrawal notice rather than a description of a vulnerability"
        )
    return replace(record, warnings=tuple(dict.fromkeys(notes)))


def read_record(body: bytes, *, expected_id: str | None = None) -> CveRecord:
    """Decode and validate one record's bytes; anything unreadable is a clear error."""
    from nikasha.checks.c15_references import MAX_CVE_BYTES  # noqa: PLC0415

    if len(body) > MAX_CVE_BYTES:
        raise NikashaError(f"the record exceeds the {MAX_CVE_BYTES:,}-byte cap")
    digest = sha256(body).hexdigest()
    try:
        data = json.loads(body.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise NikashaError(f"not a CVE JSON record: {_one_line(str(exc), 120)}") from exc
    return parse_record(data, body_sha256=digest, expected_id=expected_id)


class _HttpsOnlyRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse a redirect off HTTPS *before* following it, so no body travels in the clear."""

    def redirect_request(  # noqa: PLR0917 - the stdlib signature
        self,
        req: urllib.request.Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: HTTPMessage,
        newurl: str,
    ) -> urllib.request.Request | None:
        if not newurl.startswith("https://"):
            raise urllib.error.URLError("redirect off HTTPS refused")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _open(request: urllib.request.Request, timeout: float) -> HTTPResponse:
    """Open ``request`` with an opener whose redirects must stay on HTTPS."""
    opener = urllib.request.build_opener(_HttpsOnlyRedirect())
    response: HTTPResponse = opener.open(request, timeout=timeout)
    return response


def fetch_record(cve_id: str, *, timeout: float | None = None) -> tuple[CveRecord, str]:
    """GET one record from the CVE Program's cvelistV5 store (online only, P3).

    HTTPS only, stdlib ``urllib`` (ADR 0002), a timeout and a size cap; the URL comes
    from :func:`nikasha.checks.c15_references.cve_url`. Returns the record and the URL
    it came from, for ``environment.fetched_urls``.
    """
    from nikasha.checks.c15_references import (  # noqa: PLC0415
        CVE_TIMEOUT_S,
        HTTP_NOT_FOUND,
        HTTP_OK,
        MAX_CVE_BYTES,
        USER_AGENT,
        cve_url,
    )

    match = CVE_ID_RE.match(cve_id.strip())
    if match is None:
        raise NikashaError(f"{_quote(cve_id)} is not a CVE ID (expected CVE-YYYY-NNNN)")
    wanted = f"CVE-{match.group('year')}-{match.group('number')}"
    url = cve_url(match.group("year"), match.group("number"))
    if not url.startswith("https://"):  # pragma: no cover - the base URL is a constant
        raise NikashaError(f"refusing a non-HTTPS CVE URL: {url!r}")
    request = urllib.request.Request(  # noqa: S310 - built from CVE_LIST_BASE, https-only
        url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"}
    )
    try:
        with _open(request, CVE_TIMEOUT_S if timeout is None else timeout) as response:
            body: bytes = response.read(MAX_CVE_BYTES + 1)
            status = int(response.status or HTTP_OK)
            final_url = str(getattr(response, "url", url))
    except urllib.error.HTTPError as exc:
        if exc.code == HTTP_NOT_FOUND:
            raise NikashaError(
                f"{wanted}: no record at {url} (HTTP 404); the ID may be reserved, "
                "unpublished, or mistyped"
            ) from exc
        raise NikashaError(f"{wanted}: HTTP {exc.code} from {url}") from exc
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise NikashaError(f"{wanted}: could not fetch {url}: {_one_line(str(exc), 200)}") from exc
    if not final_url.startswith("https://"):  # belt and braces: the opener refuses first
        raise NikashaError(f"{wanted}: the record was redirected off HTTPS; refusing it")
    if status != HTTP_OK:
        raise NikashaError(f"{wanted}: HTTP {status} from {url}")
    return read_record(body, expected_id=wanted), url


def load_source(source: str, *, online: bool = False) -> tuple[CveRecord, str | None, str | None]:
    """Read ``source`` as a CVE ID, ``-`` (stdin) or a file path.

    Returns ``(record, uri, fetched_url)``. A bare CVE ID is refused without ``online``
    before any network code runs, so an offline run makes no request (P3).
    """
    from nikasha.checks.c15_references import MAX_CVE_BYTES  # noqa: PLC0415

    # An existing file wins over the ID reading: a record saved as ``CVE-2026-00001``
    # (no extension) is read offline, not refused.
    match = None if source == "-" or Path(source).is_file() else CVE_ID_RE.match(source.strip())
    if match is not None:
        cve_id = f"CVE-{match.group('year')}-{match.group('number')}"
        if not online:
            raise NikashaError(
                f"{cve_id} is a CVE ID, and fetching its record needs --online; Nikasha makes "
                "no network request without it. To stay offline, save the record from "
                f"cvelistV5 and pass the file: nikasha cve ./{cve_id}.json"
            )
        record, url = fetch_record(cve_id)
        return record, url, url
    if source == "-":
        data = sys.stdin.buffer.read(MAX_CVE_BYTES + 1)
        return read_record(data), None, None
    path = Path(source)
    try:
        size = path.stat().st_size
        if size > MAX_CVE_BYTES:
            raise NikashaError(f"{source} is {size:,} bytes; the limit is {MAX_CVE_BYTES:,}")
        data = path.read_bytes()
    except OSError as exc:
        raise NikashaError(f"cannot read {source}: {exc.strerror or exc}") from exc
    return read_record(data), source, None


# --- the record as a report ------------------------------------------------------------------


def _bounds(entry: AffectedVersion) -> tuple[str | None, str | None, bool]:
    """``(lower, upper, upper_inclusive)`` with the record's "0" and "*" markers resolved."""
    lower = None if entry.version in _UNBOUNDED else entry.version
    inclusive = bool(entry.less_than_or_equal)
    upper: str | None = entry.less_than_or_equal or entry.less_than
    if upper in _UNBOUNDED:
        upper = None
    return lower, upper, inclusive


def _affected_text(entry: AffectedVersion) -> str:
    """An affected version in the forms the version extractor reads (SPEC §9.2)."""
    lower, upper, inclusive = _bounds(entry)
    ranged = bool(entry.less_than or entry.less_than_or_equal)
    if lower and upper:
        text = f">= {lower}, {'<=' if inclusive else '<'} {upper}"
    elif lower:
        text = f"since {lower}" if ranged else f"version {lower}"
    elif upper:
        text = f"{'up to' if inclusive else 'before'} {upper}"
    else:
        text = "all versions"
    return f"{text} (affected)"


def _other_text(entry: AffectedVersion) -> str:
    """An unaffected or unknown version, worded so no cue turns it into a version claim:
    the record says nothing about the code at these versions (P4)."""
    lower, upper, inclusive = _bounds(entry)
    ranged = bool(entry.less_than or entry.less_than_or_equal)
    if lower and upper:
        text = f"{lower} to {upper}" + ("" if inclusive else " (exclusive)")
    elif lower:
        text = f"{lower} onwards" if ranged else lower
    elif upper:
        text = f"{upper} or lower" if inclusive else f"below {upper}"
    else:
        text = "all versions"
    return f"{entry.status}: {text}"


def version_text(entry: AffectedVersion) -> str:
    """How one version entry is written into the report body."""
    return _affected_text(entry) if entry.status == "affected" else _other_text(entry)


def _affected_line(product: AffectedProduct) -> str:
    name = product.product or product.package_name or "unnamed product"
    head = name
    if product.vendor and product.vendor.lower() != name.lower():
        head += f" by {product.vendor}"
    if product.package_name and product.package_name != name:
        head += f" (package {product.package_name})"
    if product.repo:
        head += f", repository {product.repo}"
    parts = [version_text(v) for v in product.versions]
    if product.default_status:
        parts.append(f"default status: {product.default_status}")
    return f"{head}: {'; '.join(parts)}" if parts else head


def _metric_line(metric: Metric, cwe: str | None) -> str:
    text = metric.vector
    if metric.base_score is not None:
        text += f" {metric.base_score:.1f}"
    if metric.severity:
        text += f" ({metric.severity})"
    return f"{text} · {cwe}" if cwe else text


def _problem_line(problem: ProblemType) -> str:
    if problem.cwe and problem.description:
        return f"{problem.cwe}: {problem.description}"
    return problem.cwe or problem.description or ""


def _reference_line(reference: Reference) -> str:
    return f"{reference.url} ({', '.join(reference.tags)})" if reference.tags else reference.url


def render_body(record: CveRecord) -> str:
    """The Markdown body the extractors read. Structured sections come first, the free
    prose last, so nothing in a description can hide a section (P7); the CVE ID itself is
    deliberately absent (see the module docstring)."""
    lines: list[str] = [f"# {record.title or 'CVE record'}", ""]
    meta = []
    if record.state:
        meta.append(f"State: {record.state}")
    if record.date_published:
        meta.append(f"Published: {record.date_published.isoformat()}")
    if meta:
        lines += [" · ".join(meta), ""]
    if record.affected:
        lines += ["## Affected", "", *(f"- {_affected_line(p)}" for p in record.affected), ""]
    if record.metrics or record.problem_types:
        first_cwe = next((p.cwe for p in record.problem_types if p.cwe), None)
        lines += ["## Impact", ""]
        lines += [f"- {_metric_line(m, first_cwe)}" for m in record.metrics]
        lines += [f"- {_problem_line(p)}" for p in record.problem_types]
        lines.append("")
    if record.references:
        lines += ["## References", "", *(f"- {_reference_line(r)}" for r in record.references), ""]
    if record.descriptions:
        lines += ["## Description", ""]
        for text in record.descriptions:
            lines += [text, ""]
    if record.rejected_reasons:
        lines += ["## Rejected", ""]
        for text in record.rejected_reasons:
            lines += [text, ""]
    return "\n".join(lines).rstrip("\n") + "\n"


def _declared_version(entry: AffectedVersion) -> str:
    lower, upper, inclusive = _bounds(entry)
    if lower and upper:
        return f">={lower} {'<=' if inclusive else '<'}{upper}"
    if lower:
        return f">={lower}" if entry.less_than or entry.less_than_or_equal else lower
    if upper:
        return f"{'<=' if inclusive else '<'}{upper}"
    return "*"


def declared_target(record: CveRecord) -> DeclaredTarget | None:
    """The intake metadata: the first named product, the first HTTPS ``repo``, and every
    affected version or range as written."""
    from nikasha.model.report import DeclaredTarget  # noqa: PLC0415

    product: str | None = None
    repo: str | None = None
    versions: list[str] = []
    for entry in record.affected:
        product = product or entry.product or entry.package_name
        repo = repo or entry.repo
        versions += [_declared_version(v) for v in entry.versions if v.status == "affected"]
    versions = list(dict.fromkeys(versions))[:MAX_DECLARED_VERSIONS]
    if product is None and repo is None and not versions:
        return None
    return DeclaredTarget(product=product, repo_url=repo, versions=tuple(versions))


def to_report(record: CveRecord, *, uri: str | None = None) -> Report:
    """Convert a record into a :class:`~nikasha.model.report.Report` of kind ``cve_json``."""
    from nikasha.ingest import ingest_string  # noqa: PLC0415
    from nikasha.ingest.text import report_id  # noqa: PLC0415
    from nikasha.model.report import ReportSource  # noqa: PLC0415

    draft = ingest_string(render_body(record), input_format="markdown", uri=uri)
    title = f"{record.cve_id}: {record.title}" if record.title else record.cve_id
    return draft.model_copy(
        update={
            "id": report_id("cve_json", draft.body),
            "source": ReportSource(kind="cve_json", uri=uri),
            "title": title,
            "reported_at": record.date_published,
            "declared_target": declared_target(record),
            "warnings": tuple(dict.fromkeys((*draft.warnings, *record.warnings))),
        }
    )


# --- the check pipeline on a converted report --------------------------------------------


@dataclass
class _Timer:
    """Wall-clock stage timings, kept apart from everything the verdict depends on (P2)."""

    timings: dict[str, float]

    @contextmanager
    def stage(self, name: str) -> Iterator[None]:
        started = time.perf_counter()
        try:
            yield
        finally:
            self.timings[name] = round(time.perf_counter() - started, 4)


def _product_hint(report: Report, product: str | None) -> str | None:
    """``--product`` wins; otherwise the record's own product, by its known-project name
    when ``known_projects.yaml`` lists it, so scoping and resolution see one spelling."""
    if product:
        return product
    declared = report.declared_target
    if declared is None or not declared.product:
        return None
    from nikasha.resolve.products import load_known_projects  # noqa: PLC0415

    known = load_known_projects().by_alias(declared.product)
    return known.name if known else declared.product


def check_converted(
    report: Report,
    *,
    repo: str | None = None,
    ref: str | None = None,
    version: str | None = None,
    product: str | None = None,
    online: bool = False,
    prior: float = 0.0,
    thresholds: Thresholds | None = None,
    check_timeout: float = 10.0,
    index_path: Path | None = None,
    fetched_urls: Sequence[str] = (),
    llm: object | None = None,
) -> CheckReport:
    """Run the ordinary pipeline stages after intake on an already built report.

    This is :func:`nikasha.pipeline.check_report` from extraction onwards: the same
    extractors, resolution, index, checks, fusion and questions, in the same order.
    """
    from nikasha.checks import load_checks  # noqa: PLC0415
    from nikasha.checks.base import CheckContext, CheckRun, run_checks  # noqa: PLC0415
    from nikasha.code.index import CodeIndex  # noqa: PLC0415
    from nikasha.extract import extract_claims  # noqa: PLC0415
    from nikasha.fuse.scoring import fuse  # noqa: PLC0415
    from nikasha.fuse.verdict import decide  # noqa: PLC0415
    from nikasha.model.result import Environment, Result  # noqa: PLC0415
    from nikasha.pipeline import CheckReport, build_questions, build_verdict  # noqa: PLC0415
    from nikasha.resolve.target import resolve_target  # noqa: PLC0415
    from nikasha.version import __version__  # noqa: PLC0415

    timer = _Timer({})
    hint = _product_hint(report, product)
    with timer.stage("extract"):
        extraction = extract_claims(report, product=hint)
        claims = extraction.claims
        loaded = report.model_copy(update={"warnings": report.warnings + extraction.warnings})
    with timer.stage("resolve"):
        resolution = resolve_target(
            loaded, claims, repo=repo, ref=ref, version=version, product=hint, online=online
        )

    # No resolvable version is an INSUFFICIENT verdict, not a crash (SPEC §14.3 rule 2).
    commit = resolution.target.commit
    runs: list[CheckRun] = []
    if commit is not None:
        with resolution.repo, CodeIndex(resolution.repo, index_path) as index:
            with timer.stage("index"):
                index.index_commit(commit)
            ctx = CheckContext(
                report=loaded,
                claims=claims,
                resolution=resolution,
                index=index,
                online=online,
                llm=llm,
            )
            with timer.stage("checks"):
                load_checks()
                runs = run_checks(ctx, timeout=check_timeout)
    evidence = tuple(sorted((e for run in runs for e in run.evidence), key=lambda e: e.id))

    with timer.stage("fuse"):
        ledger = fuse(evidence, prior=prior)
        decision = decide(ledger, evidence, claims, thresholds=thresholds)
        if commit is None:
            decision = replace(
                decision,
                rule="2: the report does not name a version that resolves to a commit",
                notes=(
                    *decision.notes,
                    "No version in the report resolves to a released tag or commit, so "
                    "nothing could be checked against the code.",
                ),
            )
    with timer.stage("questions"):
        questions = build_questions(decision, evidence, claims)
    for run in runs:
        timer.timings[f"check.{run.check_id}"] = run.seconds

    result = Result(
        tool_version=__version__,
        report=loaded,
        claims=claims,
        target=resolution.target,
        evidence=evidence,
        verdict=build_verdict(decision, questions),
        timings=timer.timings,
        environment=Environment(
            mode="online" if online else "offline", fetched_urls=tuple(fetched_urls)
        ),
    )
    return CheckReport(
        result=result,
        ledger=ledger,
        decision=decision,
        runs=tuple(runs),
        resolution=resolution,
    )


def check_cve(
    source: str,
    *,
    repo: str | None = None,
    ref: str | None = None,
    version: str | None = None,
    product: str | None = None,
    online: bool = False,
    prior: float = 0.0,
    thresholds: Thresholds | None = None,
    check_timeout: float = 10.0,
    index_path: Path | None = None,
    llm: object | None = None,
) -> CheckReport:
    """Read a record (ID, file or stdin), convert it, and check it end to end."""
    record, uri, fetched = load_source(source, online=online)
    report = to_report(record, uri=uri)
    return check_converted(
        report,
        repo=repo,
        ref=ref,
        version=version,
        product=product,
        online=online,
        prior=prior,
        thresholds=thresholds,
        check_timeout=check_timeout,
        index_path=index_path,
        fetched_urls=(fetched,) if fetched else (),
        llm=llm,
    )


# --- the command ------------------------------------------------------------------------------


def _emit(text: str, out: str | None) -> None:
    """Write to ``out`` or to stdout as UTF-8 bytes, whatever the console encoding."""
    if out:
        Path(out).write_text(text, encoding="utf-8")
        return
    buffer = getattr(sys.stdout, "buffer", None)
    if buffer is None:
        sys.stdout.write(text)
    else:
        sys.stdout.flush()
        buffer.write(text.encode("utf-8"))
        buffer.flush()


#: How many of a report's warnings the terminal repeats; the JSON carries them all.
_MAX_NOTES = 8


def _notes(warnings: Sequence[str]) -> None:
    """Report warnings on stderr, as plain text: they quote the record (P7)."""
    console = Console(stderr=True)
    for warning in warnings[:_MAX_NOTES]:
        console.print(Text.assemble(("note: ", "yellow"), warning))


def _fail(exc: NikashaError) -> typer.Exit:
    # The message may quote a server's status line or a file name: plain Text, never markup.
    Console(stderr=True).print(Text.assemble(("error: ", "red"), str(exc)))
    raise typer.Exit(code=1)


def exit_code_for(label: str, fail_on: str | None) -> int:
    """The process exit code for a verdict, with ``--fail-on`` (SPEC §15.1)."""
    from nikasha.render.terminal import exit_code  # noqa: PLC0415

    if not fail_on:
        return exit_code(label)
    if label not in _VERDICT_ORDER:
        return 1
    return 1 if _VERDICT_ORDER.index(label) >= _VERDICT_ORDER.index(fail_on.upper()) else 0


def format_report(checked: CheckReport, output_format: str, source: str = "") -> str:
    """The json, markdown or html document for a finished run (same renderers as `check`)."""
    if output_format == "json":
        return checked.result.to_json()
    if output_format == "html":
        from nikasha.render.html import render_html  # noqa: PLC0415
        from nikasha.render.html.excerpts import repo_excerpts  # noqa: PLC0415

        try:
            with repo_excerpts(
                checked.result.target.repo_url if checked.result.target else ""
            ) as excerpts:
                return render_html(checked, excerpts=excerpts, source=source)
        except NikashaError:
            return render_html(checked, source=source)
    from nikasha.render.markdown import render_markdown  # noqa: PLC0415

    return render_markdown(checked)


def _report_only(source: str, *, online: bool, output_format: str, out: str | None) -> None:
    from nikasha.model.result import Result  # noqa: PLC0415
    from nikasha.version import __version__  # noqa: PLC0415

    record, uri, _ = load_source(source, online=online)
    report = to_report(record, uri=uri)
    if output_format == "json":
        _emit(Result(tool_version=__version__, report=report).to_json(include_timings=False), out)
    else:
        _emit(report.body, out)
    _notes(report.warnings)


def cve(  # noqa: PLR0917 - a CLI command's options are its signature
    source: Annotated[
        str,
        typer.Argument(
            help="A CVE ID such as CVE-2026-00001 (needs --online), a CVE JSON 5.x file, "
            "or - for stdin."
        ),
    ],
    repo: Annotated[
        str | None, typer.Option("--repo", help="Repository URL (https) or local path.")
    ] = None,
    ref: Annotated[
        str | None, typer.Option("--ref", help="Exact git ref to check against.")
    ] = None,
    version: Annotated[
        str | None,
        typer.Option(
            "--version", help="Release to check against, e.g. 1.2.0 (overrides the record)."
        ),
    ] = None,
    product: Annotated[
        str | None, typer.Option("--product", help="Product name, e.g. curl or libhdr.")
    ] = None,
    output_format: Annotated[
        str, typer.Option("--format", help="terminal, json, markdown or html.")
    ] = "terminal",
    out: Annotated[
        str | None, typer.Option("--out", "-o", help="Write the output to a file instead.")
    ] = None,
    online: Annotated[
        bool,
        typer.Option(
            "--online", help="Allow network access: fetch a record by ID, clone the repository."
        ),
    ] = False,
    report_only: Annotated[
        bool,
        typer.Option(
            "--report-only",
            help="Print the converted report (Markdown, or JSON with --format json; not html) "
            "and stop.",
        ),
    ] = False,
    ascii_only: Annotated[bool, typer.Option("--ascii", help="ASCII symbols only.")] = False,
    quiet: Annotated[bool, typer.Option("--quiet", help="Print only the verdict line.")] = False,
    explain: Annotated[
        bool, typer.Option("--explain", help="Also print the log-odds ledger.")
    ] = False,
    fail_on: Annotated[
        str | None,
        typer.Option("--fail-on", help="Exit non-zero at this verdict or worse (for CI)."),
    ] = None,
    config: Annotated[
        str | None,
        typer.Option("--config", help="A nikasha.toml to use instead of the nearest one."),
    ] = None,
    llm: Annotated[
        str | None,
        typer.Option("--llm", help="Optional LLM review (off by default; never decisive)."),
    ] = None,
) -> None:
    """Fact-check a CVE record (JSON 5.x) against the code at the versions it names.

    A file is read offline. A bare CVE ID is fetched from the CVE Program's cvelistV5
    store, which needs --online. Exit codes: 0 GROUNDED/REPRODUCED, 10 MIXED,
    20 UNGROUNDED, 30 INSUFFICIENT, 1 error.

    Example:
        nikasha cve CVE-2026-00001.json --repo ./libhdr.git
        nikasha cve CVE-2026-00001 --online --repo https://github.com/example/libhdr
        nikasha cve CVE-2026-00001.json --report-only
    """
    if output_format not in _FORMATS:
        raise typer.BadParameter("must be terminal, json, markdown or html", param_hint="--format")
    if fail_on and fail_on.upper() not in _VERDICT_ORDER:
        raise typer.BadParameter(
            f"must be one of {', '.join(_VERDICT_ORDER)}", param_hint="--fail-on"
        )
    if report_only and output_format == "html":
        raise typer.BadParameter(
            "--report-only prints markdown (terminal, markdown) or json", param_hint="--format"
        )
    try:
        if report_only:
            _report_only(source, online=online, output_format=output_format, out=out)
            return
        # The same configuration `nikasha check` honours, so both commands reach the same
        # verdict on the same report (thresholds and prior move it).
        from nikasha.cli import _llm_provider, _load_settings  # noqa: PLC0415

        settings = _load_settings(config)
        checked = check_cve(
            source,
            repo=repo,
            ref=ref,
            version=version,
            product=product,
            online=online,
            thresholds=settings.thresholds() if settings is not None else None,
            prior=settings.prior() if settings is not None else 0.0,
            llm=_llm_provider(llm, settings),
        )
    except NikashaError as exc:
        _fail(exc)

    if output_format == "terminal":
        from nikasha.render.explain_view import render_explain  # noqa: PLC0415
        from nikasha.render.terminal import render_check  # noqa: PLC0415

        console = Console()
        render_check(console, checked.result, ascii_only=ascii_only, quiet=quiet, source=source)
        if explain:
            render_explain(
                console, checked.ledger, checked.verdict, {e.id: e for e in checked.evidence}
            )
        # What the record itself said about its state (REJECTED, skipped entries) belongs
        # next to the verdict; the Markdown and JSON outputs already carry it.
        _notes(checked.result.report.warnings)
    else:
        _emit(format_report(checked, output_format, source), out)
    raise typer.Exit(code=exit_code_for(checked.verdict.label, fail_on))


def register(app: typer.Typer) -> None:
    """Add the ``cve`` command to ``app`` (the CLI wires every integration this way)."""
    app.command(name="cve")(cve)


__all__ = [
    "CVE_ID_RE",
    "AffectedProduct",
    "AffectedVersion",
    "CveRecord",
    "Metric",
    "ProblemType",
    "Reference",
    "check_converted",
    "check_cve",
    "declared_target",
    "exit_code_for",
    "fetch_record",
    "format_report",
    "load_source",
    "parse_record",
    "read_record",
    "register",
    "render_body",
    "to_report",
    "version_text",
]
