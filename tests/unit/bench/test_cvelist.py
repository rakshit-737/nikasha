# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Pinned cvelistV5 records for S3 (ADR 0011 addendum): synthetic payloads, no socket."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nikasha.bench.cvelist import (
    CvelistError,
    cache_file,
    fetch_records,
    load_cached,
    record_url,
)
from nikasha.bench.manifests import Manifest
from nikasha.bench.runner import collect_cases
from nikasha.errors import NikashaError

SHA = "0123456789abcdef0123456789abcdef01234567"
CVE = "CVE-2026-00042"


def _record(cve_id: str = CVE, state: str = "PUBLISHED") -> bytes:
    return json.dumps(
        {
            "dataType": "CVE_RECORD",
            "dataVersion": "5.1",
            "cveMetadata": {"cveId": cve_id, "state": state},
            "containers": {
                "cna": {
                    "descriptions": [
                        {"lang": "en", "value": "Heap overflow in hdr_parse in libhdr 1.2.0."}
                    ],
                    "affected": [
                        {
                            "product": "libhdr",
                            "versions": [{"version": "1.2.0", "status": "affected"}],
                        }
                    ],
                }
            },
        }
    ).encode()


def test_record_url_is_pinned_and_bucketed() -> None:
    assert record_url(CVE, SHA) == (
        f"https://raw.githubusercontent.com/CVEProject/cvelistV5/{SHA}/cves/2026/0xxx/{CVE}.json"
    )
    assert record_url("CVE-2026-51296", SHA).endswith("/cves/2026/51xxx/CVE-2026-51296.json")


@pytest.mark.parametrize(
    ("cve_id", "commit"),
    [
        ("CVE-2026-1", SHA),
        ("cve-2026-00042", SHA),
        ("CVE-2026-00042/../x", SHA),
        (CVE, "main"),
        (CVE, SHA[:12]),
        (CVE, SHA.upper()),
    ],
)
def test_bad_pins_are_refused(cve_id: str, commit: str) -> None:
    with pytest.raises(CvelistError):
        record_url(cve_id, commit)


def test_offline_refuses_before_any_request(tmp_path: Path) -> None:
    def boom(url: str) -> bytes:
        raise AssertionError("no request offline")

    with pytest.raises(NikashaError, match="--online"):
        fetch_records([(CVE, SHA)], tmp_path, online=False, transport=boom)


def test_fetch_caches_resumes_and_drops_mismatches(tmp_path: Path) -> None:
    other = "CVE-2026-00043"
    calls: list[str] = []

    def transport(url: str) -> bytes:
        calls.append(url)
        return _record(CVE) if CVE in url else _record("CVE-2026-99999")

    sleeps: list[float] = []
    summary = fetch_records(
        [(CVE, SHA), (other, SHA)],
        tmp_path,
        online=True,
        transport=transport,
        sleep=sleeps.append,
        clock=lambda: 0.0,
    )
    assert summary.fetched == [f"{CVE}@{SHA}"]
    assert summary.dropped == {f"{other}@{SHA}": "not a CVE record for this ID"}
    assert cache_file(tmp_path, CVE, SHA).is_file()
    assert not cache_file(tmp_path, other, SHA).exists()
    assert sleeps  # the second request waited
    again = fetch_records(
        [(CVE, SHA)], tmp_path, online=True, transport=transport, sleep=sleeps.append
    )
    assert again.cached == [f"{CVE}@{SHA}"]
    assert len(calls) == 2


def test_load_cached_renders_the_record_body(tmp_path: Path) -> None:
    assert load_cached(tmp_path, CVE, SHA) is None
    cache_file(tmp_path, CVE, SHA).write_bytes(_record())
    text = load_cached(tmp_path, CVE, SHA)
    assert text is not None
    assert "hdr_parse" in text and "libhdr" in text
    cache_file(tmp_path, CVE, SHA).write_bytes(_record("CVE-2026-11111"))
    assert load_cached(tmp_path, CVE, SHA) is None


def _manifest(**entry: object) -> Manifest:
    base: dict[str, object] = {"id": "cve-x", "label": "fabricated"}
    base.update(entry)
    return Manifest.model_validate(
        {"source": "S3", "title": "t", "terms_checked": True, "entries": [base]}
    )


def test_manifest_accepts_a_pinned_record_and_rejects_mixed_locators() -> None:
    m = _manifest(cve_id=CVE, cvelist_commit=SHA)
    assert m.entries[0].cvelist_commit == SHA
    with pytest.raises(ValueError, match="go together"):
        _manifest(cve_id=CVE)
    with pytest.raises(ValueError, match="exactly one"):
        _manifest(cve_id=CVE, cvelist_commit=SHA, path="r.md")
    with pytest.raises(ValueError, match="full lowercase SHA-1"):
        _manifest(cve_id=CVE, cvelist_commit="HEAD")
    with pytest.raises(ValueError, match="text"):
        _manifest(cve_id=CVE, cvelist_commit=SHA, text="leaked body")


def test_pinned_entry_needs_terms_checked() -> None:
    with pytest.raises(ValueError, match="terms_checked"):
        Manifest.model_validate(
            {
                "source": "S3",
                "title": "t",
                "entries": [
                    {"id": "a", "label": "fabricated", "cve_id": CVE, "cvelist_commit": SHA}
                ],
            }
        )


def test_collect_cases_uses_the_cache_or_skips(tmp_path: Path) -> None:
    m = _manifest(cve_id=CVE, cvelist_commit=SHA)
    cases, skipped = collect_cases((m,), tmp_path)
    assert cases == () and skipped == ("cve-x",)
    cache_file(tmp_path, CVE, SHA).write_bytes(_record())
    cases, skipped = collect_cases((m,), tmp_path, cvelist_cache=tmp_path)
    assert skipped == ()
    assert [(c.id, c.label, c.source) for c in cases] == [("cve-x", "fabricated", "S3")]
    assert "hdr_parse" in cases[0].text
