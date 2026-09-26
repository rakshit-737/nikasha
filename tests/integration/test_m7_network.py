# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The M7 network paths against the real services, read-only (nightly, ``-m network``).

Only public data is touched: published CVE records from cvelistV5 and published GitHub
advisories. Nothing is written anywhere. Assertions are about shape (a record parses, a
known-missing ID is a 404, a lookup names a product), never about the text of a record.
HackerOne needs program credentials that CI does not hold, so only its refusal is covered.
"""

from __future__ import annotations

import os

import pytest

from nikasha.checks.c15_references import fetch_cve
from nikasha.errors import NikashaError
from nikasha.integrations.cve import declared_target, fetch_record, render_body
from nikasha.integrations.gh_advisories import fetch_advisories
from nikasha.integrations.h1 import fetch_report

pytestmark = pytest.mark.network

#: Published curl CVEs (curl's own numbering authority) and one with a ``changes[]`` list.
CURL_CVES = ("CVE-2023-38545", "CVE-2024-2398")
CHANGES_CVE = "CVE-2021-44228"
MISSING_CVE = "CVE-2099-99999"


@pytest.mark.parametrize("cve_id", [*CURL_CVES, CHANGES_CVE])
def test_real_cve_records_parse(cve_id: str) -> None:
    record, url = fetch_record(cve_id)
    assert url.startswith("https://raw.githubusercontent.com/CVEProject/cvelistV5/")
    assert record.cve_id == cve_id
    assert record.state == "PUBLISHED"
    assert record.affected
    body = render_body(record)
    assert cve_id not in body  # a record never vouches for itself
    for product in record.affected:
        for version in product.versions:
            assert version.less_than != version.version or version.version in {"0", "*"}
    assert declared_target(record) is not None


def test_a_changes_list_is_split_into_ranges() -> None:
    record, _ = fetch_record(CHANGES_CVE)
    statuses = [v.status for p in record.affected for v in p.versions]
    assert statuses.count("affected") >= 2 and "unaffected" in statuses


def test_a_missing_cve_is_an_error_not_a_record() -> None:
    with pytest.raises(NikashaError, match="HTTP 404"):
        fetch_record(MISSING_CVE)


@pytest.mark.parametrize("cve_id", CURL_CVES)
def test_c15_lookup_names_curl(cve_id: str) -> None:
    lookup = fetch_cve(cve_id)
    assert lookup.error is None, lookup.error
    assert lookup.status == 200 and lookup.state == "PUBLISHED"
    assert "curl" in {p.lower() for p in lookup.products}
    assert lookup.body_sha256 is not None


def test_c15_lookup_of_a_missing_cve_is_a_404() -> None:
    lookup = fetch_cve(MISSING_CVE)
    assert lookup.error is None and lookup.status == 404


def test_published_advisories_list_anonymously_or_with_the_ci_token() -> None:
    env = {k: v for k in ("GITHUB_TOKEN", "GH_TOKEN") if (v := os.environ.get(k))}
    try:
        fetched = fetch_advisories("pallets/jinja", state="published", online=True, env=env)
    except NikashaError as exc:
        if "rate limit exhausted" in str(exc):
            pytest.skip(f"GitHub rate limit: {exc}")
        raise
    assert fetched.reports
    assert all(p.ghsa_id.startswith("GHSA-") for p in fetched.parsed)


def test_hackerone_without_credentials_refuses_before_any_request() -> None:
    with pytest.raises(NikashaError, match="nothing was requested"):
        fetch_report("2199174", online=True, env={})
