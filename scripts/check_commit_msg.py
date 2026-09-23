# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Check commit messages: a Conventional Commits header and a DCO ``Signed-off-by`` trailer.

Used as a pre-commit ``commit-msg`` hook (``check_commit_msg.py <message-file>``) and in CI
(``check_commit_msg.py --stdin`` once per commit message).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

TYPES = "build|chore|ci|docs|feat|fix|perf|refactor|revert|style|test"
HEADER_RE = re.compile(rf"^(?:{TYPES})(?:\([a-z0-9._/-]+\))?!?: \S.{{0,98}}$")
SIGNOFF_RE = re.compile(r"^Signed-off-by: [^<>\n]+ <[^<>@\s]+@[^<>\s]+>$", re.MULTILINE)
EXEMPT_PREFIXES = ("Merge ", 'Revert "', "fixup! ", "squash! ")


def problems(message: str) -> list[str]:
    """Return a list of human-readable problems with ``message`` (empty if it is fine)."""
    lines = [ln for ln in message.splitlines() if not ln.startswith("#")]
    header = lines[0].strip() if lines else ""
    if header.startswith(EXEMPT_PREFIXES):
        return []
    found: list[str] = []
    if not HEADER_RE.match(header):
        found.append(
            f"header {header!r} is not a Conventional Commit (e.g. 'feat(extract): add parser')"
        )
    if not SIGNOFF_RE.search("\n".join(lines)):
        found.append("missing DCO sign-off; commit with `git commit -s`")
    return found


def main(argv: list[str]) -> int:
    if argv[1:] == ["--stdin"]:
        message = sys.stdin.read()
    elif len(argv) == 2:  # noqa: PLR2004
        message = Path(argv[1]).read_text(encoding="utf-8")
    else:
        print("usage: check_commit_msg.py <message-file> | --stdin", file=sys.stderr)
        return 2
    issues = problems(message)
    for issue in issues:
        print(f"commit message: {issue}", file=sys.stderr)
    return 1 if issues else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
