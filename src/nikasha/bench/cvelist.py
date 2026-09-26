# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Fetch cvelistV5 records pinned to a commit into the gitignored bench cache.

S3 entries may name a record as ``{cve_id, cvelist_commit}``: the record as it stood at
that commit of https://github.com/CVEProject/cvelistV5, for example the last version
before it was rejected (ADR 0011, addendum). This module is the only code that reads those
pinned records, and it keeps to the same rules as the HackerOne corpus:

* **Online only.** Nothing is requested without ``online=True`` (P3).
* **Pinned.** The URL is built from a validated CVE ID and a full 40-hex commit SHA, so
  the content cannot drift; the payload's ``cveMetadata.cveId`` must match.
* **Capped and polite.** One request at a time, a size cap, and at least
  :data:`MIN_DELAY_S` seconds between request starts.
* **Cache only under ``bench/cache/``** (0600 files in a 0700 directory). Manifests carry
  IDs, commit SHAs and labels only; no record text is committed.

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

RAW_URL = (
    "https://raw.githubusercontent.com/CVEProject/cvelistV5/"
    "{commit}/cves/{year}/{bucket}/{cve}.json"
)
MIN_DELAY_S = 1.0
MAX_RECORD_BYTES = 1024 * 1024
#: The default cache, relative to the repository root (gitignored).
DEFAULT_CACHE = Path("bench") / "cache" / "cvelist"

_CVE_RE = re.compile(r"\ACVE-(?P<year>[0-9]{4})-(?P<number>[0-9]{4,7})\Z")
_COMMIT_RE = re.compile(r"\A[0-9a-f]{40}\Z")

Transport = Callable[[str], bytes]


class CvelistError(NikashaError):
    """A pinned record reference is malformed or the fetch was refused."""


def _check(cve_id: str, commit: str) -> re.Match[str]:
    match = _CVE_RE.match(cve_id)
    if match is None:
        raise CvelistError(f"bad CVE ID {cve_id!r}")
    if not _COMMIT_RE.match(commit):
        raise CvelistError(f"bad cvelistV5 commit {commit!r}; use the full 40-hex SHA")
    return match


def record_url(cve_id: str, commit: str) -> str:
    """The raw URL of ``cve_id`` at ``commit`` (cvelistV5 buckets by thousands)."""
    match = _check(cve_id, commit)
    number = match.group("number")
    bucket = f"{int(number) // 1000}xxx"
    return RAW_URL.format(commit=commit, year=match.group("year"), bucket=bucket, cve=cve_id)


def cache_file(cache: Path, cve_id: str, commit: str) -> Path:
    """Where one pinned record is cached: ``<cache>/<CVE>@<commit>.json``."""
    _check(cve_id, commit)
    return cache / f"{cve_id}@{commit}.json"


def _matches(raw: bytes, cve_id: str) -> bool:
    try:
        data = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return False
    if not isinstance(data, dict):
        return False
    meta = data.get("cveMetadata")
    return isinstance(meta, dict) and str(meta.get("cveId", "")).upper() == cve_id


def load_cached(cache: Path, cve_id: str, commit: str) -> str | None:
    """The cached record rendered as the report body the checks read, else ``None``."""
    from nikasha.integrations.cve import read_record, render_body  # noqa: PLC0415

    try:
        raw = cache_file(cache, cve_id, commit).read_bytes()
    except OSError:
        return None
    if len(raw) > MAX_RECORD_BYTES or not _matches(raw, cve_id):
        return None
    try:
        return render_body(read_record(raw, expected_id=cve_id))
    except NikashaError:
        return None


def _default_transport(url: str) -> bytes:
    body, _ = fetch_bytes(
        url,
        headers={"Accept": "application/json"},
        max_bytes=MAX_RECORD_BYTES,
        service="cvelistV5",
    )
    return body


@dataclass
class FetchSummary:
    """What one fetch did, keyed by ``<CVE>@<commit>``."""

    fetched: list[str] = field(default_factory=list)
    cached: list[str] = field(default_factory=list)
    dropped: dict[str, str] = field(default_factory=dict)


def fetch_records(
    pins: Iterable[tuple[str, str]],
    cache: Path,
    *,
    online: bool,
    delay: float = MIN_DELAY_S,
    transport: Transport | None = None,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> FetchSummary:
    """Fetch each ``(cve_id, commit)`` record not yet cached, sequentially.

    Resumable: a cached record is never requested again. A failure on one record is
    recorded in ``dropped`` and the run goes on.
    """
    require_online(online, "cvelistV5")
    if delay < MIN_DELAY_S:
        raise CvelistError(f"delay {delay}s is below the minimum of {MIN_DELAY_S}s")
    wanted = sorted({(c, s) for c, s in pins})
    for cve_id, commit in wanted:
        _check(cve_id, commit)
    get = transport or _default_transport
    ensure_private_dir(cache)
    summary = FetchSummary()
    last_start: float | None = None
    for cve_id, commit in wanted:
        key = f"{cve_id}@{commit}"
        target = cache_file(cache, cve_id, commit)
        if target.exists():
            summary.cached.append(key)
            continue
        if last_start is not None:
            wait = delay - (clock() - last_start)
            if wait > 0:
                sleep(wait)
        last_start = clock()
        try:
            raw = get(record_url(cve_id, commit))
        except NikashaError as exc:
            summary.dropped[key] = f"fetch failed: {type(exc).__name__}"
            continue
        if len(raw) > MAX_RECORD_BYTES:
            summary.dropped[key] = "response too large"
            continue
        if not _matches(raw, cve_id):
            summary.dropped[key] = "not a CVE record for this ID"
            continue
        write_private(target, raw.decode("utf-8-sig"))
        summary.fetched.append(key)
    return summary
