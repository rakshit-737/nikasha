# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Repository acquisition (SPEC §10; ADR 0006).

* A **local path** (bare repository, ``.git`` directory, or a checkout) is read in place,
  through plumbing only.
* A **remote URL** (``https://`` only) is cloned once into the cache as a *full* bare
  clone: ``<cache>/repos/<host>/<owner>/<repo>.git``. Offline runs use the cache or explain
  how to warm it; ``--online`` refreshes it with ``git fetch --tags --prune``.

Full rather than ``--filter=blob:none`` clones (a deviation from §10, ADR 0006): a partial
clone fetches blobs lazily over the network, which breaks offline mode (P3) and makes history
searches crawl.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from nikasha.code.gitio import GitRepo, run_git
from nikasha.config import cache_dir, ensure_private_dir
from nikasha.errors import NikashaError

_SEGMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
_FORGES = {"github.com", "gitlab.com", "codeberg.org", "bitbucket.org", "gitlab.gnome.org"}
CLONE_TIMEOUT_S = 1800.0
FETCH_TIMEOUT_S = 600.0


class RepoNotAvailableError(NikashaError):
    """The repository cannot be read (not cached offline, bad URL, not a git repository)."""


@dataclass(frozen=True, slots=True)
class RepoLocation:
    git_dir: Path
    url: str | None  # canonical https URL for remote repositories
    local: bool


def canonical_url(url: str) -> str:
    """``https://github.com/curl/curl.git/tree/master`` → ``https://github.com/curl/curl``."""
    parts = urlsplit(url.strip())
    if parts.scheme != "https":
        raise RepoNotAvailableError(f"only https:// repository URLs are supported, not {url!r}")
    host = parts.hostname or ""
    segments = [s for s in parts.path.split("/") if s]
    if host in _FORGES and len(segments) >= 2:  # noqa: PLR2004
        # GitLab groups can nest; stop at the first "-" separator or forge keyword.
        keep: list[str] = []
        for seg in segments:
            if seg in (
                "-",
                "tree",
                "blob",
                "commit",
                "commits",
                "issues",
                "pull",
                "merge_requests",
            ):
                break
            keep.append(seg)
        segments = keep if host.startswith("gitlab") else keep[:2]
    if not segments:
        raise RepoNotAvailableError(f"cannot find owner/repository in {url!r}")
    segments[-1] = segments[-1].removesuffix(".git")
    for seg in (host, *segments):
        if not _SEGMENT_RE.match(seg) or seg in (".", ".."):
            raise RepoNotAvailableError(f"unsafe repository URL component {seg!r}")
    return f"https://{host}/{'/'.join(segments)}"


def cache_path(url: str, root: Path | None = None) -> Path:
    canonical = canonical_url(url)
    host_and_path = canonical.removeprefix("https://")
    base = (root or cache_dir() / "repos").joinpath(*host_and_path.split("/"))
    return base.with_name(base.name + ".git")


def _local_git_dir(path: Path) -> Path:
    if (path / "HEAD").is_file() and (path / "objects").is_dir():
        return path  # bare repository or a .git directory
    dot_git = path / ".git"
    if dot_git.is_dir():
        return dot_git
    if dot_git.is_file():  # worktree: "gitdir: <path>"
        text = dot_git.read_text(encoding="utf-8", errors="replace").strip()
        if text.startswith("gitdir:"):
            target = (path / text.removeprefix("gitdir:").strip()).resolve()
            if target.is_dir():
                return target
    raise RepoNotAvailableError(f"{path} is not a git repository")


def acquire(repo: str, *, online: bool = False, cache_root: Path | None = None) -> RepoLocation:
    """Return a readable git directory for ``repo`` (a local path or an https URL)."""
    if "://" not in repo:
        path = Path(repo).expanduser()
        if not path.exists():
            raise RepoNotAvailableError(f"{repo} does not exist")
        return RepoLocation(_local_git_dir(path.resolve()), None, True)
    url = canonical_url(repo)
    dest = cache_path(url, cache_root)
    if (dest / "HEAD").is_file():
        if online:
            _fetch(dest)
        return RepoLocation(dest, url, False)
    if not online:
        raise RepoNotAvailableError(
            f"{url} is not in the cache. Nikasha works offline by default; "
            f"warm the cache once with: nikasha index --repo {url} --online"
        )
    ensure_private_dir(dest.parent)
    result = run_git(
        ["clone", "--bare", "--quiet", url, str(dest)], timeout=CLONE_TIMEOUT_S, online=True
    )
    if result.returncode != 0 or not (dest / "HEAD").is_file():
        message = result.stderr.decode("utf-8", "replace").strip().splitlines()[-1:] or ["?"]
        raise RepoNotAvailableError(f"clone of {url} failed: {message[0]}")
    return RepoLocation(dest, url, False)


def _fetch(git_dir: Path) -> None:
    run_git(
        [
            "fetch",
            "--quiet",
            "--tags",
            "--prune",
            "--force",
            "origin",
            "+refs/heads/*:refs/heads/*",
        ],
        git_dir=git_dir,
        timeout=FETCH_TIMEOUT_S,
        online=True,
    )


def open_repo(repo: str, *, online: bool = False, cache_root: Path | None = None) -> GitRepo:
    """:func:`acquire` then wrap in a :class:`GitRepo`."""
    location = acquire(repo, online=online, cache_root=cache_root)
    return GitRepo(location.git_dir, online=online)
