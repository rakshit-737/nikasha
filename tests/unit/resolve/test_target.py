# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Target resolution against the vulnlab history (SPEC §10)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nikasha.extract import extract_claims
from nikasha.ingest import ingest_string, load_report
from nikasha.resolve.repo import RepoNotAvailableError, acquire, canonical_url
from nikasha.resolve.target import TargetNotFoundError, resolve_target

ROOT = Path(__file__).resolve().parents[3]
EXPECTED = json.loads((ROOT / "examples" / "vulnlab" / "expected.json").read_text())
REPORTS = ROOT / "examples" / "reports"


def _resolve(text_or_path, vulnlab_repo, **kwargs):
    if isinstance(text_or_path, Path):
        report = load_report(text_or_path)
    else:
        report = ingest_string(text_or_path, input_format="markdown")
    claims = extract_claims(report).claims
    return resolve_target(report, claims, repo=str(vulnlab_repo), **kwargs)


@pytest.mark.parametrize(
    ("report", "tag"),
    [
        ("genuine_hdr_overflow.md", "v1.2.0"),
        ("fabricated_hdr_overflow.md", "v1.2.0"),  # "1.2.0 and all earlier" -> upper bound
        ("mixed_wrong_version.md", "v1.1.0"),
        ("already_fixed.md", "v1.3.0"),
    ],
)
def test_fixture_reports_resolve_to_claimed_versions(vulnlab_repo, report, tag):
    res = _resolve(REPORTS / report, vulnlab_repo)
    assert res.target.ref_name == tag
    assert res.target.commit == EXPECTED[tag]
    assert res.release is not None
    assert res.release.name == tag


def test_vague_report_has_no_version(vulnlab_repo):
    res = _resolve(REPORTS / "vague.md", vulnlab_repo)
    assert res.target.commit is None
    assert res.target.confidence == "low"
    assert "no version" in res.target.method


def test_explicit_flags_win(vulnlab_repo):
    res = _resolve(REPORTS / "genuine_hdr_overflow.md", vulnlab_repo, version="1.3")
    assert res.target.ref_name == "v1.3.0"
    res = _resolve(REPORTS / "genuine_hdr_overflow.md", vulnlab_repo, ref="v1.0.0")
    assert res.target.commit == EXPECTED["v1.0.0"]
    with pytest.raises(TargetNotFoundError):
        _resolve("text", vulnlab_repo, ref="nope")
    with pytest.raises(TargetNotFoundError):
        _resolve("text", vulnlab_repo, version="9.9.9")


def test_unknown_version_warns_but_does_not_guess(vulnlab_repo):
    res = _resolve("Tested on libhdr 1.2.7.", vulnlab_repo)
    assert res.target.commit is None
    assert any("1.2.7" in w for w in res.target.warnings)


def test_commit_claim(vulnlab_repo):
    short = EXPECTED["v1.1.0"][:10]
    res = _resolve(f"Crash at commit {short} in libhdr.", vulnlab_repo)
    assert res.target.commit == EXPECTED["v1.1.0"]


def test_missing_commit_is_a_warning(vulnlab_repo):
    res = _resolve("Tested at commit deadbeefcafe0123 and libhdr 1.1.0.", vulnlab_repo)
    assert res.target.ref_name == "v1.1.0"
    assert any("fork" in w for w in res.target.warnings)


def test_branch_ref(vulnlab_repo):
    res = _resolve("Reproduced on the master branch.", vulnlab_repo)
    assert res.target.ref_name == "main"
    assert res.target.commit == EXPECTED["v1.3.0"]
    assert res.target.confidence == "low"
    assert res.target.warnings


def test_multiple_versions_are_recorded(vulnlab_repo):
    res = _resolve("Tested on libhdr 1.1.0 and libhdr 1.2.1.", vulnlab_repo)
    assert res.target.ref_name == "v1.1.0"
    assert res.target.alternatives == ("v1.2.1",)
    assert res.target.confidence == "medium"


def test_no_repository_is_an_actionable_error():
    report = ingest_string("A crash in some library.", input_format="markdown")
    with pytest.raises(TargetNotFoundError, match="--repo"):
        resolve_target(report, extract_claims(report).claims)


def test_repo_from_known_project_needs_the_cache(tmp_path, monkeypatch):
    monkeypatch.setenv("NIKASHA_CACHE_DIR", str(tmp_path))
    report = ingest_string("Tested on curl 8.5.0.", input_format="markdown")
    with pytest.raises(RepoNotAvailableError, match="--online"):
        resolve_target(report, extract_claims(report).claims)


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://github.com/curl/curl.git", "https://github.com/curl/curl"),
        ("https://github.com/curl/curl/tree/master/lib", "https://github.com/curl/curl"),
        (
            "https://gitlab.gnome.org/GNOME/libxml2/-/blob/x.c",
            "https://gitlab.gnome.org/GNOME/libxml2",
        ),
    ],
)
def test_canonical_url(url, expected):
    assert canonical_url(url) == expected


@pytest.mark.parametrize(
    "url",
    [
        "http://x.org/a/b",
        "file:///etc",
        "ext::sh -c x",
        "git@github.com:a/b",
        "https://github.com/../x",
    ],
)
def test_unsafe_urls_are_refused(url):
    with pytest.raises(RepoNotAvailableError):
        canonical_url(url)


def test_local_repositories(vulnlab_repo, tmp_path):
    assert acquire(str(vulnlab_repo)).git_dir == vulnlab_repo.resolve()
    with pytest.raises(RepoNotAvailableError):
        acquire(str(tmp_path))
    with pytest.raises(RepoNotAvailableError):
        acquire(str(tmp_path / "missing"))
