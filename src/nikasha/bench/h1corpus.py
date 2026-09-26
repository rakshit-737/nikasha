# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Fetch publicly disclosed HackerOne reports into the gitignored bench cache (ADR 0011).

This is the only code that reads the public ``https://hackerone.com/reports/{id}.json``
endpoint, and it obeys every condition of ADR 0011:

* **Online only.** Nothing is requested without ``online=True`` (P3).
* **Publicly disclosed reports only.** A payload whose ``disclosed_at`` is empty, or that
  is not marked public, is dropped and never written.
* **Polite.** One request at a time, at least :data:`MIN_DELAY_S` seconds between the start
  of consecutive requests, and the honest ``User-Agent`` of :mod:`nikasha.integrations.h1`
  (it names Nikasha and the repository URL).
* **Capped.** A response over :data:`MAX_RESPONSE_BYTES` or a report body over
  :data:`MAX_REPORT_CHARS` is refused.
* **Minimal cache.** Only the title and ``vulnerability_information`` are kept, as
  ``<cache>/<id>.md`` (0600 in a 0700 directory). The reporter, comments and every other
  field are never stored. The cache lives under ``bench/cache/`` (gitignored); manifests
  carry IDs, URLs and labels only.

The transport and the clock are injectable so the tests never open a socket.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path

from nikasha.config import ensure_private_dir
from nikasha.errors import NikashaError
from nikasha.integrations.h1 import fetch_bytes, require_online, write_private

PUBLIC_REPORT_JSON = "https://hackerone.com/reports/{id}.json"
#: Minimum seconds between the starts of two requests (ADR 0011). Callers may go slower,
#: never faster.
MIN_DELAY_S = 2.0
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_REPORT_CHARS = 500_000
MAX_TITLE_CHARS = 300
#: The default cache, relative to the repository root (gitignored).
DEFAULT_CACHE = Path("bench") / "cache" / "h1"

_ID_RE = re.compile(r"\A[1-9][0-9]{0,11}\Z")
_URL_RE = re.compile(r"\Ahttps://hackerone\.com/reports/([1-9][0-9]{0,11})\Z")

Transport = Callable[[str], bytes]


class CorpusError(NikashaError):
    """The corpus fetch was refused or a report id is malformed."""


def report_id_from_url(url: str) -> str | None:
    """The numeric id of a ``https://hackerone.com/reports/<id>`` URL, else ``None``."""
    match = _URL_RE.match(url)
    return match.group(1) if match else None


def _check_id(report_id: str) -> str:
    if not _ID_RE.match(report_id):
        raise CorpusError(f"bad HackerOne report id {report_id!r}")
    return report_id


def cache_file(cache: Path, report_id: str) -> Path:
    """Where one report's text is cached."""
    return cache / f"{_check_id(report_id)}.md"


def load_cached(cache: Path, report_id: str) -> str | None:
    """The cached report text, or ``None`` when it was never fetched (or was dropped)."""
    path = cache_file(cache, report_id)
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def _default_transport(url: str) -> bytes:
    body, _ = fetch_bytes(
        url,
        headers={"Accept": "application/json"},
        max_bytes=MAX_RESPONSE_BYTES,
        service="HackerOne",
    )
    return body


def report_markdown(payload: object, report_id: str) -> str | None:
    """The cacheable text of one public report payload, or ``None`` if it must be dropped.

    Dropped: not a mapping, a different id, not publicly disclosed, no body, or a body over
    the cap. Only the title and the body are kept.
    """
    if not isinstance(payload, dict):
        return None
    if str(payload.get("id", "")) != report_id:
        return None
    if not payload.get("disclosed_at") or payload.get("public") is False:
        return None
    body = payload.get("vulnerability_information")
    if not isinstance(body, str) or not body.strip() or len(body) > MAX_REPORT_CHARS:
        return None
    title = payload.get("title")
    title_text = " ".join(title.split())[:MAX_TITLE_CHARS] if isinstance(title, str) else ""
    heading = f"# {title_text}\n\n" if title_text else ""
    return heading + body.replace("\r\n", "\n") + ("" if body.endswith("\n") else "\n")


@dataclass
class FetchSummary:
    """What one corpus fetch did: ids newly fetched, already cached, and dropped (reason)."""

    fetched: list[str] = field(default_factory=list)
    cached: list[str] = field(default_factory=list)
    dropped: dict[str, str] = field(default_factory=dict)


def fetch_corpus(
    report_ids: Iterable[str],
    cache: Path,
    *,
    online: bool,
    delay: float = MIN_DELAY_S,
    transport: Transport | None = None,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> FetchSummary:
    """Fetch each public report not yet cached, sequentially and rate limited.

    Resumable: a report already in ``cache`` is never requested again. A failure on one
    report is recorded in ``dropped`` and the run goes on.
    """
    require_online(online, "HackerOne")
    if delay < MIN_DELAY_S:
        raise CorpusError(f"delay {delay}s is below the ADR 0011 minimum of {MIN_DELAY_S}s")
    ids = sorted({_check_id(i) for i in report_ids}, key=int)
    get = transport or _default_transport
    ensure_private_dir(cache)
    summary = FetchSummary()
    last_start: float | None = None
    for rid in ids:
        if cache_file(cache, rid).exists():
            summary.cached.append(rid)
            continue
        if last_start is not None:
            wait = delay - (clock() - last_start)
            if wait > 0:
                sleep(wait)
        last_start = clock()
        try:
            raw = get(PUBLIC_REPORT_JSON.format(id=rid))
        except NikashaError as exc:
            summary.dropped[rid] = f"fetch failed: {type(exc).__name__}"
            continue
        if len(raw) > MAX_RESPONSE_BYTES:
            summary.dropped[rid] = "response too large"
            continue
        try:
            payload = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            summary.dropped[rid] = "not JSON"
            continue
        text = report_markdown(payload, rid)
        if text is None:
            summary.dropped[rid] = "not a publicly disclosed report with a body"
            continue
        write_private(cache_file(cache, rid), text)
        summary.fetched.append(rid)
    return summary


def purge(cache: Path) -> int:
    """Delete every cached report file (ADR 0011: stop and purge on objection)."""
    removed = 0
    if cache.is_dir():
        for path in cache.glob("*.md"):
            if _ID_RE.match(path.stem):
                path.unlink()
                removed += 1
    return removed
