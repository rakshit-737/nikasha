# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Fixtures for the checks suite.

Every check test runs against the real vulnlab history (a deterministic 5-release C
repository built by ``scripts/build_vulnlab.py``), never against mocks: a check that
passes on a fake tree proves nothing about git, the index or the parser.

The importable helpers live in ``check_helpers`` (see its docstring for why not here).
"""

from __future__ import annotations

import shutil
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from check_helpers import DEFAULT_TAG, REPO_URL, REPORTS, TAGS, MakeContext

from nikasha.checks.base import CheckContext
from nikasha.code.gitio import GitRepo
from nikasha.code.index import CodeIndex
from nikasha.ingest import load_report
from nikasha.model.claims import Claim
from nikasha.model.report import Report
from nikasha.model.result import ResolvedTarget
from nikasha.resolve.products import load_known_projects
from nikasha.resolve.refs import ReleaseList
from nikasha.resolve.target import Resolution

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")


@pytest.fixture(scope="session")
def _session_repo(vulnlab_repo: Path) -> Iterator[GitRepo]:
    repo = GitRepo(vulnlab_repo)
    with repo:
        yield repo


@pytest.fixture(scope="session")
def releases(_session_repo: GitRepo) -> ReleaseList:
    return ReleaseList.from_tags(_session_repo.tags())


@pytest.fixture(scope="session")
def commits(_session_repo: GitRepo) -> dict[str, str]:
    """Tag name to commit SHA, for asserting against exact commits."""
    resolved: dict[str, str] = {}
    for tag in TAGS:
        sha = _session_repo.rev_parse(tag)
        assert sha is not None, tag
        resolved[tag] = sha
    return resolved


@pytest.fixture
def index(vulnlab_repo: Path, tmp_path: Path) -> Iterator[CodeIndex]:
    repo = GitRepo(vulnlab_repo)
    with repo, CodeIndex(repo, tmp_path / "index.sqlite") as idx:
        yield idx


@pytest.fixture
def make_ctx(
    index: CodeIndex,
    releases: ReleaseList,
    commits: dict[str, str],
) -> MakeContext:
    """Build a :class:`CheckContext` at a tag, with whatever claims a test needs.

    Usage::

        ctx = make_ctx(claims=[claim])                 # at v1.2.0
        ctx = make_ctx(claims=[claim], tag="v1.3.0")   # at another release
    """

    def build(
        *,
        claims: list[Claim] | tuple[Claim, ...] = (),
        tag: str = DEFAULT_TAG,
        report: Report | None = None,
        online: bool = False,
    ) -> CheckContext:
        commit = commits[tag]
        release = next((r for r in releases.releases if r.name == tag), None)
        target = ResolvedTarget(
            repo_url=REPO_URL,
            ref_name=tag,
            commit=commit,
            method="test fixture",
            confidence="high",
        )
        resolution = Resolution(
            repo=index.repo,
            releases=releases,
            target=target,
            project=load_known_projects().by_alias("libhdr"),
            release=release,
        )
        return CheckContext(
            report=report
            if report is not None
            else load_report(REPORTS / "genuine_hdr_overflow.md"),
            claims=tuple(claims),
            resolution=resolution,
            index=index,
            online=online,
        )

    return build


@pytest.fixture
def ctx(make_ctx: MakeContext) -> CheckContext:
    """A context at v1.2.0 with no claims; tests that need claims use ``make_ctx``."""
    return make_ctx()
