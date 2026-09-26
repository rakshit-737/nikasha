# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Regressions found by running the M7 network paths against the real services.

Every payload here is synthetic: it mirrors the *shape* of a real answer (CVE JSON 5.x from
cvelistV5, the GitHub REST API) about the fictional demo library ``libhdr``, and carries no
third-party report text.

* A CVE ``versions[]`` entry whose exclusive end equals its start is an empty range. A real
  record carries that shape by mistake; it must not become the version claim ``>= X, < X``.
* A ``changes[]`` list (status switches inside one range) must be read, not dropped, and an
  unreadable ``lessThan`` bound must not be guessed.
* C15 must survive any body (deep nesting, a BOM) and must follow redirects only on HTTPS.
* Published GitHub advisories are public: listing them works without a token, and sends no
  ``Authorization`` header; every other state still refuses without one.
* An exhausted rate limit is reported as such, with the reset time.
"""

from __future__ import annotations

import email.message
import http.client
import io
import json
import urllib.error
import urllib.request
from typing import Any

import pytest

from nikasha.checks import c15_references as c15
from nikasha.errors import NikashaError
from nikasha.integrations import cve as cve_module
from nikasha.integrations.cve import (
    AffectedVersion,
    declared_target,
    parse_record,
    render_body,
)
from nikasha.integrations.gh_advisories import fetch_advisories
from nikasha.integrations.h1 import fetch_bytes

CVE = "CVE-2026-00001"


def _record(versions: list[dict[str, Any]], **product: Any) -> dict[str, Any]:
    return {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.1",
        "cveMetadata": {"cveId": CVE, "state": "PUBLISHED"},
        "containers": {
            "cna": {  # codespell:ignore cna
                "affected": [
                    {"vendor": "libhdr", "product": "libhdr", "versions": versions, **product}
                ],
                "descriptions": [{"lang": "en", "value": "Synthetic record."}],
            }
        },
    }


# --- CVE versions ---------------------------------------------------------------------------


def test_an_empty_exclusive_range_is_skipped_with_a_note() -> None:
    # The shape of a real record: {"version": X, "lessThan": X} for both entries.
    record = parse_record(
        _record(
            [
                {"version": "1.4.0", "status": "affected", "lessThan": "1.4.0"},
                {"version": "1.0.0", "status": "unaffected", "lessThan": "1.0.0"},
            ]
        )
    )
    (product,) = record.affected
    assert product.versions == ()
    assert any("empty version range" in w for w in record.warnings)
    assert ">= 1.4.0, < 1.4.0" not in render_body(record)
    target = declared_target(record)
    assert target is not None and target.versions == ()


def test_an_inclusive_single_version_range_is_kept() -> None:
    record = parse_record(
        _record([{"version": "1.4.0", "status": "affected", "lessThanOrEqual": "1.4.0"}])
    )
    assert record.affected[0].versions == (
        AffectedVersion(version="1.4.0", status="affected", less_than_or_equal="1.4.0"),
    )


def test_changes_split_a_range_and_an_unreadable_bound_is_not_guessed() -> None:
    # The shape of a real record: a custom lessThan that is no version, plus changes[].
    record = parse_record(
        _record(
            [
                {
                    "version": "1.0-beta1",
                    "status": "affected",
                    "lessThan": "libhdr-core*",
                    "versionType": "custom",
                    "changes": [
                        {"at": "1.1.1", "status": "unaffected"},
                        {"at": "1.2", "status": "affected"},
                        {"at": "1.3.0", "status": "unaffected"},
                    ],
                }
            ]
        )
    )
    versions = record.affected[0].versions
    assert [(v.version, v.status, v.less_than) for v in versions] == [
        ("1.0-beta1", "affected", "1.1.1"),
        ("1.1.1", "unaffected", "1.2"),
        ("1.2", "affected", "1.3.0"),
    ]
    assert any("unreadable lessThan" in w for w in record.warnings)
    assert any("no readable upper bound" in w for w in record.warnings)
    target = declared_target(record)
    assert target is not None
    assert target.versions == (">=1.0-beta1 <1.1.1", ">=1.2 <1.3.0")
    body = render_body(record)
    assert ">= 1.0-beta1, < 1.1.1 (affected)" in body
    assert "unaffected: 1.1.1 to 1.2 (exclusive)" in body


def test_changes_with_a_readable_bound_keep_the_last_segment() -> None:
    record = parse_record(
        _record(
            [
                {
                    "version": "1.0.0",
                    "status": "affected",
                    "lessThan": "*",
                    "changes": [{"at": "1.2.1", "status": "unaffected"}],
                }
            ]
        )
    )
    versions = record.affected[0].versions
    assert [(v.version, v.status, v.less_than) for v in versions] == [
        ("1.0.0", "affected", "1.2.1"),
        ("1.2.1", "unaffected", "*"),
    ]


def test_an_unreadable_change_leaves_the_entry_as_written() -> None:
    record = parse_record(
        _record(
            [
                {
                    "version": "1.0.0",
                    "status": "affected",
                    "lessThan": "1.3.0",
                    "changes": [{"at": "1.1.0", "status": "bogus"}],
                }
            ]
        )
    )
    assert record.affected[0].versions == (
        AffectedVersion(version="1.0.0", status="affected", less_than="1.3.0"),
    )
    assert any("changes ignored" in w for w in record.warnings)


# --- C15 ------------------------------------------------------------------------------------


def test_c15_survives_absurd_nesting_and_accepts_a_bom() -> None:
    url = "https://example.invalid/cve.json"
    deep = c15._read_cve(CVE, url, 200, b"[" * 100_000 + b"]" * 100_000)
    assert deep.error is not None and "unreadable JSON" in deep.error
    body = json.dumps(_record([])).encode("utf-8")
    bom = c15._read_cve(CVE, url, 200, b"\xef\xbb\xbf" + body)
    assert bom.error is None and bom.state == "PUBLISHED" and bom.products == ("libhdr",)


def test_c15_fetches_through_the_https_only_opener(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[str] = []

    def fake_open(request: urllib.request.Request, timeout: float) -> Any:
        seen.append(request.full_url)
        raise urllib.error.URLError("redirect off HTTPS refused")

    monkeypatch.setattr(cve_module, "_open", fake_open)
    lookup = c15.fetch_cve("CVE-2026-1234")
    assert seen == [c15.cve_url("2026", "1234")]
    assert lookup.status == 0 and lookup.error is not None


def test_the_redirect_handler_refuses_plain_http() -> None:
    handler = cve_module._HttpsOnlyRedirect()
    request = urllib.request.Request("https://example.invalid/a")
    with pytest.raises(urllib.error.URLError):
        handler.redirect_request(
            request,
            io.BytesIO(),
            302,
            "Found",
            http.client.HTTPMessage(),
            "http://example.invalid/b",
        )


# --- GitHub advisories ----------------------------------------------------------------------


class _Response:
    def __init__(self, body: bytes, url: str) -> None:
        self.body, self.url, self.status = body, url, 200
        self.headers = email.message.Message()

    def read(self, n: int = -1) -> bytes:
        return self.body if n < 0 else self.body[:n]

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *args: object) -> None:
        return None


def _published() -> dict[str, Any]:
    return {
        "ghsa_id": "GHSA-abcd-efgh-2jkm",
        "cve_id": None,
        "html_url": "https://github.com/libhdr/libhdr/security/advisories/GHSA-abcd-efgh-2jkm",
        "summary": "Synthetic advisory",
        "description": "Synthetic text.",
        "severity": "medium",
        "state": "published",
        "published_at": "2026-01-02T03:04:05Z",
        "vulnerabilities": [
            {"package": {"ecosystem": "pip", "name": "libhdr"}, "vulnerable_version_range": "<=1"}
        ],
    }


def test_published_advisories_are_listed_anonymously(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, str]] = []

    def fake_urlopen(request: urllib.request.Request, timeout: float | None = None) -> Any:
        calls.append({k.lower(): v for k, v in request.header_items()})
        return _Response(json.dumps([_published()]).encode(), request.full_url)

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    fetched = fetch_advisories("libhdr/libhdr", state="published", online=True, env={})
    assert len(fetched.reports) == 1
    assert calls and all("authorization" not in headers for headers in calls)


def test_private_states_still_refuse_without_a_token(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*args: object, **kwargs: object) -> None:
        raise AssertionError("no request may be made without a token")

    monkeypatch.setattr("urllib.request.urlopen", boom)
    for state in ("triage", "draft", "closed"):
        with pytest.raises(NikashaError, match="no GitHub token"):
            fetch_advisories("libhdr/libhdr", state=state, online=True, env={})
    with pytest.raises(NikashaError, match="--online"):
        fetch_advisories("libhdr/libhdr", state="published", online=False, env={})


def test_a_token_is_still_sent_for_published(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[urllib.request.Request] = []

    def fake_urlopen(request: urllib.request.Request, timeout: float | None = None) -> Any:
        calls.append(request)
        return _Response(b"[]", request.full_url)

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    fetch_advisories(
        "libhdr/libhdr", state="published", online=True, env={"GITHUB_TOKEN": "ghp_synthetic"}
    )
    assert calls[0].unredirected_hdrs.get("Authorization") == "Bearer ghp_synthetic"


def _http_error(code: int, headers: dict[str, str]) -> urllib.error.HTTPError:
    message = email.message.Message()
    for key, value in headers.items():
        message[key] = value
    return urllib.error.HTTPError("https://api.github.com/x", code, "Forbidden", message, None)


@pytest.mark.parametrize("code", [403, 429])
def test_an_exhausted_rate_limit_says_so(monkeypatch: pytest.MonkeyPatch, code: int) -> None:
    error = _http_error(code, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1790403141"})

    def fake_urlopen(request: urllib.request.Request, timeout: float | None = None) -> Any:
        raise error

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    with pytest.raises(NikashaError, match=r"rate limit exhausted .*1790403141"):
        fetch_bytes("https://api.github.com/x", service="GitHub")


def test_a_forbidden_answer_with_quota_left_keeps_its_own_hint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    error = _http_error(403, {"X-RateLimit-Remaining": "12", "X-RateLimit-Reset": "<script>"})

    def fake_urlopen(request: urllib.request.Request, timeout: float | None = None) -> Any:
        raise error

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    with pytest.raises(NikashaError) as caught:
        fetch_bytes("https://api.github.com/x", service="GitHub", hints={403: "custom hint"})
    assert "custom hint" in str(caught.value)
    assert "<script>" not in str(caught.value)
