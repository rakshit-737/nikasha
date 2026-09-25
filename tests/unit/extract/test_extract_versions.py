# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
import pytest
from helpers import claims, one

from nikasha.extract.versions import parse_version


@pytest.mark.parametrize(
    ("raw", "numbers", "qualifier"),
    [
        ("8.5.0", (8, 5, 0), None),
        ("v2.4.58", (2, 4, 58), None),
        ("1.1.1w", (1, 1, 1), "w"),
        ("3.45.1-rc2", (3, 45, 1), "rc2"),
        ("1.2.3beta", (1, 2, 3), "beta"),
        ("8_5_0", (8, 5, 0), None),
    ],
)
def test_parse_version(raw, numbers, qualifier):
    spec = parse_version(raw)
    assert spec is not None
    assert (spec.numbers, spec.qualifier) == (numbers, qualifier)


@pytest.mark.parametrize("raw", ["abc", "1.x", ""])
def test_parse_version_rejects(raw):
    assert parse_version(raw) is None


def test_product_version() -> None:
    c = one("Tested with curl 8.5.0 on Linux.", "version")
    assert (c.product, c.relation, c.parsed.numbers) == ("curl", "tested_on", (8, 5, 0))


def test_affected_range_and_earlier() -> None:
    c = one("**Affected:** libhdr 1.2.0 and all earlier versions", "version")
    assert c.relation == "affected_range"
    assert c.upper.numbers == (1, 2, 0)
    assert c.upper_inclusive
    assert c.product == "libhdr"


@pytest.mark.parametrize(
    ("text", "lower", "upper", "inclusive"),
    [
        ("Affects versions from 7.69.0 to 8.3.0.", (7, 69, 0), (8, 3, 0), True),
        ("Range: >= 1.2, < 1.3 only.", (1, 2), (1, 3), False),
        ("All versions before 3.45.1 are affected.", None, (3, 45, 1), False),
    ],
)
def test_ranges(text, lower, upper, inclusive):
    c = one(text, "version")
    assert c.relation == "affected_range"
    assert (c.lower.numbers if c.lower else None) == lower
    assert c.upper.numbers == upper
    assert c.upper_inclusive is inclusive


def test_cue_words() -> None:
    by_raw = {c.raw: c for c in claims("It was fixed in 8.4.0 and introduced in 7.1.0.", "version")}
    assert by_raw["8.4.0"].relation == "fixed_in"
    assert by_raw["7.1.0"].lower.numbers == (7, 1, 0)


def test_tag_and_v_prefix() -> None:
    raws = {c.raw for c in claims("Built from curl-8_5_0 and also v2.4.58.", "version")}
    assert raws == {"curl-8_5_0", "v2.4.58"}


def test_special_refs_need_context() -> None:
    refs = {
        c.special_ref for c in claims("Reproduced on the master branch and at HEAD.", "version")
    }
    assert refs == {"master", "HEAD"}
    assert claims("This is the main loop of the parser.", "version") == []


def test_date() -> None:
    c = one("Checked as of 2026-05-02 today.", "version")
    assert str(c.as_of) == "2026-05-02"


def test_commit_only_in_context() -> None:
    c = one("Tested at commit 3f2a9c1d.", "version")
    assert c.commit == "3f2a9c1d"
    assert claims("The value deadbeef appears.", "version") == []


def test_addresses_are_never_versions_or_shas() -> None:
    text = "Crash at 0x606000000051 with sha 0xdeadbeef1234."
    assert all(c.commit is None for c in claims(text, "version"))


def test_versions_skip_traces_and_patches() -> None:
    text = (
        "Report.\n\n```diff\n--- a/x.c\n+++ b/x.c\n@@ -1 +1 @@\n"
        "-version 1.2.3\n+version 1.2.4\n```\n"
    )
    assert claims(text, "version") == []


def test_cvss_numbers_are_not_versions() -> None:
    assert claims("Score CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H — 9.8", "version") == []
