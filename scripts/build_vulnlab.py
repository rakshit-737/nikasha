# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Build the hermetic ``vulnlab`` demo repository (the fictional ``libhdr`` library).

The commit plan lives in ``examples/vulnlab/history.toml`` and the per-version source
trees live under ``examples/vulnlab/src/<tree>/``. This script replays that plan onto the
``main`` branch of a fresh **bare** repository by generating a ``git fast-import`` stream.

Author, committer, dates and messages are fixed, and file contents are normalised to LF,
so the resulting commit SHAs are byte-for-byte identical on every machine and every git
version. That determinism is what lets Nikasha's fixtures pin exact commits.

Usage::

    python scripts/build_vulnlab.py DEST [--write-expected]

``DEST`` is the (new) path of the bare repository to create. The tag -> commit SHA map is
printed. With ``--write-expected`` it is also written to ``examples/vulnlab/expected.json``
with sorted keys.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tomllib
from datetime import datetime
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_VULNLAB = _REPO_ROOT / "examples" / "vulnlab"
_SRC_ROOT = _VULNLAB / "src"
_HISTORY = _VULNLAB / "history.toml"
_EXPECTED = _VULNLAB / "expected.json"
_LICENSE_SRC = _REPO_ROOT / "LICENSES" / "Apache-2.0.txt"

_MODE = "100644"


def _git_env() -> dict[str, str]:
    """Return a scrubbed environment so git ignores inherited and system/global config."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    env["GIT_TERMINAL_PROMPT"] = "0"
    return env


def _git(args: list[str], cwd: Path, env: dict[str, str], stdin: bytes | None = None) -> bytes:
    """Run git in ``cwd`` with the scrubbed ``env`` and return its stdout."""
    result = subprocess.run(
        ["git", *args],
        cwd=cwd,
        env=env,
        input=stdin,
        capture_output=True,
        check=True,
    )
    return result.stdout


def _read_lf(path: Path) -> bytes:
    """Read a file and normalise CRLF and lone CR to LF."""
    return path.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def _tree_files(tree_dir: Path) -> list[tuple[str, bytes]]:
    """Return ``(repo_path, content)`` for every file in ``tree_dir``, sorted by path.

    The Apache-2.0 licence text is injected as ``LICENSE`` at the repository root; the
    per-tree sources deliberately do not carry their own copy.
    """
    files: list[tuple[str, bytes]] = [("LICENSE", _read_lf(_LICENSE_SRC))]
    for path in tree_dir.rglob("*"):
        if path.is_file():
            files.append((path.relative_to(tree_dir).as_posix(), _read_lf(path)))
    files.sort(key=lambda item: item[0])
    return files


def _epoch(iso: str) -> int:
    """Convert an ISO-8601 timestamp (with an explicit offset) to whole Unix seconds."""
    return int(datetime.fromisoformat(iso).timestamp())


def _blob(content: bytes) -> bytes:
    return b"data " + str(len(content)).encode() + b"\n" + content + b"\n"


def _fast_import_stream(commits: list[dict[str, object]], author: str, branch: str) -> bytes:
    """Build the complete ``git fast-import`` stream for the commit plan."""
    out = bytearray()
    for index, commit in enumerate(commits, start=1):
        message = str(commit["message"]).encode() + b"\n"
        when = f"{_epoch(str(commit['date']))} +0000"
        ident = author.encode()
        out += b"commit refs/heads/" + branch.encode() + b"\n"
        out += b"mark :" + str(index).encode() + b"\n"
        out += b"author " + ident + b" " + when.encode() + b"\n"
        out += b"committer " + ident + b" " + when.encode() + b"\n"
        out += _blob(message)
        if index > 1:
            out += b"from :" + str(index - 1).encode() + b"\n"
        out += b"deleteall\n"
        for repo_path, content in _tree_files(_SRC_ROOT / str(commit["tree"])):
            out += b"M " + _MODE.encode() + b" inline " + repo_path.encode() + b"\n"
            out += _blob(content)
        out += b"\n"
        tag = commit.get("tag")
        if tag is not None:
            out += b"reset refs/tags/" + str(tag).encode() + b"\n"
            out += b"from :" + str(index).encode() + b"\n\n"
    return bytes(out)


def build_vulnlab(dest: Path) -> dict[str, str]:
    """Create a bare vulnlab repository at ``dest`` and return the tag -> commit SHA map."""
    plan = tomllib.loads(_HISTORY.read_text(encoding="utf-8"))
    commits: list[dict[str, object]] = plan["commits"]
    branch = str(plan.get("branch", "main"))
    author = str(plan["author"])

    dest = dest.resolve()
    env = _git_env()
    _git(
        ["-c", f"init.defaultBranch={branch}", "init", "--bare", str(dest)], cwd=_REPO_ROOT, env=env
    )
    _git(
        ["fast-import", "--quiet"],
        cwd=dest,
        env=env,
        stdin=_fast_import_stream(commits, author, branch),
    )

    tags: dict[str, str] = {}
    for commit in commits:
        tag = commit.get("tag")
        if tag is not None:
            sha = _git(["rev-parse", f"refs/tags/{tag}"], cwd=dest, env=env)
            tags[str(tag)] = sha.decode().strip()
    return tags


def main(argv: list[str]) -> int:
    """CLI entry point. See the module docstring for usage."""
    args = argv[1:]
    write_expected = False
    if "--write-expected" in args:
        write_expected = True
        args = [a for a in args if a != "--write-expected"]
    if len(args) != 1:
        print("usage: build_vulnlab.py DEST [--write-expected]", file=sys.stderr)
        return 2

    tags = build_vulnlab(Path(args[0]))
    for tag in sorted(tags):
        print(f"{tag} {tags[tag]}")
    if write_expected:
        _EXPECTED.write_text(json.dumps(tags, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"wrote {_EXPECTED}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
