# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Tag parsing and matching (SPEC §10, Appendix C), including real tag lists captured with
``git ls-remote --tags`` in tests/fixtures/tags/ (2026-09-23)."""

from __future__ import annotations

from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from nikasha.code.gitio import TagRef
from nikasha.extract.versions import parse_version
from nikasha.resolve.refs import ReleaseList, parse_tag

TAGS = Path(__file__).parents[2] / "fixtures" / "tags"


@pytest.mark.parametrize(
    ("tag", "family", "numbers", "kind", "letter"),
    [
        # Appendix C
        ("curl-8_5_0", "curl", (8, 5, 0), "final", ""),
        ("version-3.45.1", "version", (3, 45, 1), "final", ""),
        ("OpenSSL_1_1_1w", "openssl", (1, 1, 1), "post", "w"),
        ("openssl-3.0.13", "openssl", (3, 0, 13), "final", ""),
        ("v2.4.58", "v", (2, 4, 58), "final", ""),
        ("release-1.25.3", "release", (1, 25, 3), "final", ""),
        ("v20.11.1", "v", (20, 11, 1), "final", ""),
        ("5.0.1", "", (5, 0, 1), "final", ""),
        ("v2.12.5", "v", (2, 12, 5), "final", ""),
        ("v1.3.1", "v", (1, 3, 1), "final", ""),
        ("1.2.3-rc1", "", (1, 2, 3), "rc", ""),
        # Seen in the real tag lists
        ("2.4.53-rc2-candidate", "", (2, 4, 53), "rc", ""),
        ("candidate-2.4.52-rc1", "", (2, 4, 52), "rc", ""),
        ("APACHE_2_0_ALPHA_7", "apache", (2, 0), "alpha", ""),
        ("LIBXML_2_4_2", "libxml", (2, 4, 2), "final", ""),
        ("1.7a2", "", (1, 7), "alpha", ""),
        ("v4.0.0-rc.2", "v", (4, 0, 0), "rc", ""),
        ("OpenSSL-fips-2_0_9", "opensslfips", (2, 0, 9), "final", ""),
        ("OpenSSL_1_1_0-pre5", "openssl", (1, 1, 0), "pre", ""),
        ("version-3.1.3.1", "version", (3, 1, 3, 1), "final", ""),
        ("v1.0-pre", "v", (1, 0), "pre", ""),
    ],
)
def test_parse_tag(tag: str, family: str, numbers: tuple[int, ...], kind: str, letter: str) -> None:
    parsed = parse_tag(tag)
    assert parsed is not None
    assert (parsed.family, parsed.numbers, parsed.kind, parsed.qual_letter) == (
        family,
        numbers,
        kind,
        letter,
    )


@pytest.mark.parametrize(
    "tag",
    [
        "latest",
        "stable",
        "nightly-2026-01-01",
        "CVE-2015-7941_2",
        "stable/1.9.x",
        "cvs-to-fossil-cutover",
        "mountain-lion",
        "3.0-POST-CLANG-FORMAT-WEBKIT",
        "",
        "v",
    ],
)
def test_non_release_tags_are_ignored(tag: str) -> None:
    assert parse_tag(tag) is None


def test_ordering_appendix_c() -> None:
    order = ["1.2.3-rc1", "1.2.3", "1.2.3a"]
    parsed = [parse_tag(t) for t in order]
    assert all(parsed)
    keys = [p.sort_key for p in parsed if p]
    assert keys == sorted(keys)
    ranks = ["1.0-dev1", "1.0a1", "1.0b2", "1.0rc1", "1.0", "1.0p1"]
    keys = [parse_tag(t).sort_key for t in ranks]  # type: ignore[union-attr]
    assert keys == sorted(keys)
    # "pre" ranks with beta: both sit between alpha and rc.
    pre, beta = parse_tag("1.0-pre1"), parse_tag("1.0b1")
    assert pre is not None
    assert beta is not None
    assert pre.sort_key[1] == beta.sort_key[1]


def test_trailing_zeros_are_equal() -> None:
    assert parse_tag("8.5").trimmed == parse_tag("curl-8_5_0").trimmed  # type: ignore[union-attr]


_TAG_TEXT = st.from_regex(r"\A(v|curl-|release-)?\d{1,3}([._]\d{1,3}){0,3}(-rc\d|a\d|[a-z])?\Z")


@given(st.lists(_TAG_TEXT, min_size=1, max_size=30))
def test_sort_key_is_a_total_order(tags: list[str]) -> None:
    parsed = [p for p in (parse_tag(t) for t in tags) if p is not None]
    keys = [p.sort_key for p in parsed]
    ordered = sorted(keys)
    # Sorting twice is stable and antisymmetric: re-sorting the sorted list changes nothing,
    # and the order of any two elements agrees with pairwise comparison.
    assert sorted(ordered) == ordered
    for a in keys:
        for b in keys:
            assert (a < b) + (a == b) + (a > b) == 1


def _releases(project: str) -> ReleaseList:
    names = (TAGS / f"{project}.txt").read_text(encoding="utf-8").split()
    return ReleaseList.from_tags(TagRef(n, f"c-{n}", i) for i, n in enumerate(names))


@pytest.mark.parametrize(
    ("project", "claim", "expected", "families"),
    [
        ("curl", "8.5.0", "curl-8_5_0", ()),
        ("curl", "8.5", "curl-8_5_0", ()),
        ("sqlite", "3.45.1", "version-3.45.1", ()),
        ("openssl", "1.1.1w", "OpenSSL_1_1_1w", ("openssl",)),
        ("openssl", "3.0.13", "openssl-3.0.13", ("openssl",)),
        ("httpd", "2.4.58", "2.4.58", ()),
        ("nginx", "1.25.3", "release-1.25.3", ()),
        ("node", "20.11.1", "v20.11.1", ()),
        ("django", "5.0.1", "5.0.1", ()),
        ("libxml2", "2.12.5", "v2.12.5", ()),
        ("zlib", "1.3.1", "v1.3.1", ()),
    ],
)
def test_real_tag_lists_match_claims(
    project: str, claim: str, expected: str, families: tuple[str, ...]
) -> None:
    releases = _releases(project)
    spec = parse_version(claim)
    assert spec is not None
    matches = releases.match(spec, preferred_families=families)
    assert matches, f"no match for {claim}"
    assert matches[0].name == expected


@pytest.mark.parametrize(
    "project", ["curl", "sqlite", "openssl", "httpd", "nginx", "node", "django", "libxml2", "zlib"]
)
def test_real_tag_lists_parse_mostly(project: str) -> None:
    names = (TAGS / f"{project}.txt").read_text(encoding="utf-8").split()
    releases = _releases(project)
    assert len(releases.releases) >= 0.5 * len(names)
    keys = [r.tag.sort_key for r in releases.releases]
    assert keys == sorted(keys)


def test_prereleases_only_match_when_named() -> None:
    releases = _releases("node")
    assert all(not r.tag.is_prerelease for r in releases.match(parse_version("4.0.0")))  # type: ignore[arg-type]
    rc = releases.match(parse_version("4.0.0-rc2"))  # type: ignore[arg-type]
    assert rc
    assert rc[0].name == "v4.0.0-rc.2"


def test_neighbours_window_and_latest_before() -> None:
    releases = _releases("curl")
    below, above = releases.neighbours(parse_version("8.4.7"))  # type: ignore[arg-type]
    assert below is not None
    assert above is not None
    assert below.name == "curl-8_4_0"
    assert above.name == "curl-8_5_0"
    target = releases.match(parse_version("8.5.0"))[0]  # type: ignore[arg-type]
    window = releases.window(target, 2)
    assert [r.name for r in window][2] == "curl-8_5_0"
    assert len(window) == 5
    assert releases.latest_before(-1) is None


def test_family_filter() -> None:
    releases = ReleaseList.from_tags(
        [TagRef("OpenSSL-fips-2_0_9", "a", 1), TagRef("OpenSSL_1_1_1w", "b", 2)],
        families=["openssl"],
    )
    assert [r.name for r in releases.releases] == ["OpenSSL_1_1_1w"]
    assert releases.ignored == ["OpenSSL-fips-2_0_9"]


@pytest.mark.parametrize(
    ("project", "included", "excluded"),
    [
        ("curl", {"curl"}, {"tinycurl"}),
        ("libxml2", {"libxml", "v"}, set()),
        ("openssl", {"openssl"}, {"opensslfips"}),
        ("node", {"v"}, set()),
    ],
)
def test_main_release_line(project: str, included: set[str], excluded: set[str]) -> None:
    main = _releases(project).main_families
    assert included <= main
    assert not (excluded & main)
