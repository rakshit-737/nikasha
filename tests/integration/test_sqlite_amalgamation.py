# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The banner format and line mapping against the real SQLite 3.45.1 amalgamation.

Downloads the official zip and a few sources at ``version-3.45.1`` (sqlite.org's own
Fossil ``raw`` endpoint) into a temporary directory; nothing is committed. Network only."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from nikasha.code.amalgamation import BEGIN_RE, load_amalgamation
from nikasha.integrations.h1 import fetch_bytes

pytestmark = pytest.mark.network

RAW = "https://www.sqlite.org/src/raw?ci=version-3.45.1&filename="
# mksqlite3c.tcl rewrites some lines in place (storage-class macros, commented-out
# includes); line positions never change, so compare modulo those rewrites.
_PREFIX = re.compile(r"^(?:SQLITE_PRIVATE|SQLITE_API|static|extern) {1,4}")


def _norm(line: str) -> str:
    s = line.rstrip("\r").strip()
    if s.startswith("/*") and s.endswith("*/") and "include" in s:
        s = s[2:-2].strip()
    return _PREFIX.sub("", s)


def _get(url: str) -> str:
    body, _headers = fetch_bytes(url, max_bytes=16 << 20, service="sqlite.org", timeout=60)
    return body.decode("utf-8", errors="replace")


def test_real_amalgamation_maps_to_sources(tmp_path: Path) -> None:
    amap = load_amalgamation("3.45.1", [2024], online=True, cache=tmp_path)
    text = (tmp_path / "sqlite-amalgamation-3450100" / "sqlite3.c").read_text("utf-8")
    lines = text.split("\n")
    assert sum(1 for ln in lines if BEGIN_RE.match(ln.rstrip("\r"))) >= 130
    assert {"sqliteInt.h", "btree.c", "where.c", "fts5.c", "parse.c"} <= set(amap.files)
    for name, path in [
        ("where.c", "src/where.c"),
        ("btree.h", "src/btree.h"),
        ("sqliteInt.h", "src/sqliteInt.h"),
    ]:
        src = _get(RAW + path).split("\n")
        pairs = [
            (n, hit.line)
            for n in range(1, amap.n_lines + 1)
            if (hit := amap.lookup(n)) is not None and hit.file == name
        ]
        assert len(pairs) > 100
        bad = [n for n, s in pairs if _norm(src[s - 1]) != _norm(lines[n - 1])]
        assert len(bad) <= len(pairs) // 100, (name, bad[:5])
