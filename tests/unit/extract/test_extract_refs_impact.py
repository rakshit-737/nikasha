# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
import pytest
from helpers import claims, one

from nikasha.extract.references import classify_url


@pytest.mark.parametrize(
    ("url", "kind", "value", "repo"),
    [
        (
            "https://github.com/curl/curl/commit/ABCDEF1234",
            "commit",
            "abcdef1234",
            "https://github.com/curl/curl",
        ),
        ("https://github.com/curl/curl/pull/42", "pr", None, "https://github.com/curl/curl"),
        ("https://gitlab.com/g/p/-/issues/7", "issue", None, "https://gitlab.com/g/p"),
        ("https://github.com/o/r/blob/main/a.c", "blob", None, "https://github.com/o/r"),
        ("https://github.com/o/r/compare/a...b", "compare", None, "https://github.com/o/r"),
        (
            "https://github.com/o/r/security/advisories/GHSA-abcd-efgh-ijkl",
            "advisory",
            None,
            "https://github.com/o/r",
        ),
        ("https://nvd.nist.gov/vuln/detail/CVE-2024-1", "advisory", None, None),
        ("https://example.com/x", "url", None, None),
        ("https://github.com/o/r", "url", None, "https://github.com/o/r"),
    ],
)
def test_classify_url(url: str, kind: str, value: str | None, repo: str | None) -> None:
    got_kind, got_value, got_repo = classify_url(url)
    assert (got_kind, got_repo) == (kind, repo)
    if value is not None:
        assert got_value == value


def test_ids_and_urls() -> None:
    text = (
        "Related: CVE-2023-38545, CWE-0122, GHSA-9pq7-rjm4-p6gf and "
        "https://github.com/curl/curl/commit/fb4415d8aee6c1 (commit fb4415d)."
    )
    found = {(c.ref_kind, c.value) for c in claims(text, "reference")}
    assert ("cve", "CVE-2023-38545") in found
    assert ("cwe", "CWE-122") in found
    assert ("ghsa", "GHSA-9pq7-rjm4-p6gf") in found
    assert ("commit", "fb4415d8aee6c1") in found
    assert ("commit", "fb4415d") in found


def test_cve_inside_url_is_not_double_counted() -> None:
    found = claims("See https://nvd.nist.gov/vuln/detail/CVE-2024-0001 now.", "reference")
    assert [c.ref_kind for c in found] == ["advisory"]


class TestImpact:
    def test_vector_score_severity_and_cwe(self) -> None:
        text = "**CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H — 9.8 (Critical)** · CWE-122"
        c = one(text, "impact")
        assert c.cvss_version == "3.1"
        assert c.cvss_vector.endswith("A:H")
        assert (c.cvss_score, c.severity_word, c.cwe) == (9.8, "Critical", "CWE-122")

    def test_v4_vector(self) -> None:
        c = one("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "impact")
        assert c.cvss_version == "4.0"

    def test_v2_vector(self) -> None:
        c = one("Vector (AV:N/AC:L/Au:N/C:P/I:P/A:P) here.", "impact")
        assert c.cvss_version == "2.0"

    def test_score_without_vector(self) -> None:
        c = one("We rate this CVSS base score 7.5 (High).", "impact")
        assert (c.cvss_score, c.severity_word) == (7.5, "High")

    def test_severity_word_only_in_clear_positions(self) -> None:
        assert one("Severity: High", "impact").severity_word == "High"
        assert claims("The CPU load was high and memory low.", "impact") == []


class TestBehavior:
    def test_calls_api(self) -> None:
        c = one("`hdr_parse_line()` calls `memcpy()` with an unchecked length.", "behavior")
        assert (c.subject_symbol, c.predicate, c.object) == (
            "hdr_parse_line",
            "calls_api",
            "memcpy",
        )

    @pytest.mark.parametrize(
        "text",
        [
            "There is a missing bounds check in `util_copy_value()`.",
            "`util_copy_value()` in `src/util.c` fails to validate the chunk length.",
            "`util_copy_value` does not check the size before copying.",
        ],
    )
    def test_missing_bounds_check(self, text: str) -> None:
        c = one(text, "behavior")
        assert (c.subject_symbol, c.predicate) == ("util_copy_value", "missing_bounds_check")

    def test_null_uaf_intovf(self) -> None:
        preds = {c.predicate for c in claims(
            "Missing NULL check in `hdr_find()`. A use after free in `hdr_free()`. "
            "An integer overflow in `size_calc()`.", "behavior")}  # fmt: skip
        assert preds == {"missing_null_check", "uses_freed", "integer_overflow"}

    def test_plain_prose_is_not_behavior(self) -> None:
        assert claims("The parser calls the helper without checking anything.", "behavior") == []
