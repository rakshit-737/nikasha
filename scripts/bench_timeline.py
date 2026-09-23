# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Benchmark the two symbol-timeline strategies (SPEC §11.4, ADR 0004).

Runs the *lazy* strategy (grep, then parse only matching files) and the *full* strategy
(index every final release, then query) on cached clones, cold and warm, and prints a Markdown
table. Uses a fresh index database per strategy so the cold numbers are honest.

Usage:
    python scripts/bench_timeline.py https://github.com/curl/curl Curl_http_readwrite_headers …
"""

from __future__ import annotations

import os
import platform
import sys
import tempfile
import time
from pathlib import Path

from nikasha.code.gitio import GitRepo
from nikasha.code.index import CodeIndex
from nikasha.code.timeline import build_timeline
from nikasha.resolve.products import load_known_projects
from nikasha.resolve.refs import ReleaseList
from nikasha.resolve.repo import acquire


def _machine() -> str:
    cpu = platform.processor() or platform.machine()
    system = f"{platform.system()} {platform.release()}"
    return f"{system}, {os.cpu_count()} CPUs ({cpu}), Python {platform.python_version()}"


def main(argv: list[str]) -> int:
    if len(argv) < 3:  # noqa: PLR2004
        print(__doc__)
        return 2
    repo_arg, symbols = argv[1], argv[2:]
    location = acquire(repo_arg)
    project = load_known_projects().by_repo(location.url) if location.url else None
    with GitRepo(location.git_dir) as repo:
        releases = ReleaseList.from_tags(
            repo.tags(), families=project.tag_families if project else None
        )
        n = len(releases.finals())
        print(f"## {repo_arg}: {n} final releases\n\nMachine: {_machine()}\n")
        print("| Strategy | Symbol | Cold (s) | Warm (s) | Runs |")
        print("|---|---|---:|---:|---|")
        for strategy in ("lazy", "full"):
            with (
                tempfile.TemporaryDirectory() as tmp,
                CodeIndex(repo, Path(tmp) / "i.sqlite") as idx,
            ):
                for symbol in symbols:
                    started = time.perf_counter()
                    tl = build_timeline(idx, releases, symbol, strategy=strategy)  # type: ignore[arg-type]
                    cold = time.perf_counter() - started
                    started = time.perf_counter()
                    build_timeline(idx, releases, symbol, strategy=strategy)  # type: ignore[arg-type]
                    warm = time.perf_counter() - started
                    runs = ", ".join(f"{a}..{b}" for a, b in tl.runs) or (
                        "never (history: " + ("absent" if tl.never_in_history else "present") + ")"
                    )
                    print(f"| {strategy} | `{symbol}` | {cold:.1f} | {warm:.1f} | {runs[:80]} |")
                    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
