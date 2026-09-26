# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""SQLite amalgamation line mapping on a small synthetic amalgamation (SPEC §11.5)."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from nikasha.code.amalgamation import (
    AmalgamationMap,
    amalgamation_url,
    extract_sqlite3_c,
    load_amalgamation,
    resolve_source,
    version_code,
)
from nikasha.errors import NikashaError


def _banner(text: str) -> str:
    head = "/" + "*" * 14 + " " + text + " "
    return head + "*" * max(1, 79 - len(head)) + "/"


# Sources as they would be in git. sqliteInt.h includes msvc.h at its line 2.
INT_H = ["/* sqliteInt.h 1 */", '#include "msvc.h"', "int int_h_3;", "int int_h_4;"]
MSVC_H = ["/* msvc.h 1 */", "int msvc_2;"]
MAIN_C = ["/* main.c 1 */", "int main_2;", "\f", "int main_4;"]

AMAL = [
    "/* licence preamble */",  # 1
    _banner("Begin file sqliteInt.h"),  # 2
    INT_H[0],  # 3 -> sqliteInt.h:1
    _banner("Include msvc.h in the middle of sqliteInt.h"),  # 4 (stands for line 2)
    _banner("Begin file msvc.h"),  # 5
    MSVC_H[0],  # 6 -> msvc.h:1
    MSVC_H[1],  # 7 -> msvc.h:2
    _banner("End of msvc.h"),  # 8
    _banner("Continuing where we left off in sqliteInt.h"),  # 9
    INT_H[2],  # 10 -> sqliteInt.h:3
    INT_H[3],  # 11 -> sqliteInt.h:4
    _banner("End of sqliteInt.h"),  # 12
    _banner("Begin file main.c"),  # 13
    *MAIN_C,  # 14..17 -> main.c:1..4 (a form feed must not split a line)
    _banner("End of main.c"),  # 18
]
TEXT = "\n".join(AMAL) + "\n"


def test_maps_every_source_line_back() -> None:
    amap = AmalgamationMap.from_text(TEXT)
    sources = {"sqliteInt.h": INT_H, "msvc.h": MSVC_H, "main.c": MAIN_C}
    got = {}
    for n, text in enumerate(AMAL, start=1):
        hit = amap.lookup(n)
        if hit is None:
            continue
        assert sources[hit.file][hit.line - 1] == text, (n, hit)
        got[n] = (hit.file, hit.line)
    assert got == {
        3: ("sqliteInt.h", 1),
        6: ("msvc.h", 1),
        7: ("msvc.h", 2),
        10: ("sqliteInt.h", 3),
        11: ("sqliteInt.h", 4),
        14: ("main.c", 1),
        15: ("main.c", 2),
        16: ("main.c", 3),
        17: ("main.c", 4),
    }
    assert amap.files == ("sqliteInt.h", "msvc.h", "main.c")
    assert amap.n_lines == len(AMAL)


@pytest.mark.parametrize("line", [0, -1, 1, 2, 4, 5, 8, 9, 12, 13, 18, 19, 10**9])
def test_banners_preamble_and_out_of_range_map_to_nothing(line: int) -> None:
    assert AmalgamationMap.from_text(TEXT).lookup(line) is None


def test_crlf_matches_lf() -> None:
    crlf = AmalgamationMap.from_text(TEXT.replace("\n", "\r\n"))
    lf = AmalgamationMap.from_text(TEXT)
    assert [crlf.lookup(n) for n in range(20)] == [lf.lookup(n) for n in range(20)]


def test_short_star_markers_are_not_file_boundaries() -> None:
    # The 8-star markers inside the generated sqlite3.h stay part of sqlite3.h.
    text = "\n".join([_banner("Begin file sqlite3.h"), "a", "/******** Begin file x.h ****/", "b"])
    hit = AmalgamationMap.from_text(text).lookup(4)
    assert hit is not None
    assert (hit.file, hit.line) == ("sqlite3.h", 3)


def test_resolve_source() -> None:
    tree = ["src/main.c", "ext/fts3/fts3.c", "a/dup.c", "b/dup.c", "tool/main.c"]
    assert resolve_source("main.c", tree) == "src/main.c"
    assert resolve_source("fts3.c", tree) == "ext/fts3/fts3.c"
    assert resolve_source("dup.c", tree) is None
    assert resolve_source("parse.c", tree) is None


@pytest.mark.parametrize(
    ("version", "code"),
    [("3.45.1", "3450100"), ("version-3.45.1", "3450100"), ("3.8.11.1", "3081101")],
)
def test_version_code(version: str, code: str) -> None:
    assert version_code(version) == code


@pytest.mark.parametrize("bad", ["3.7.3", "2.8.17", "latest", "3.45", "--upload-pack=x"])
def test_version_code_refuses(bad: str) -> None:
    with pytest.raises(NikashaError):
        version_code(bad)


def test_url() -> None:
    url = amalgamation_url("3.45.1", 2024)
    assert url == "https://www.sqlite.org/2024/sqlite-amalgamation-3450100.zip"
    with pytest.raises(NikashaError):
        amalgamation_url("3.45.1", 1970)


def _zip(members: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, body in members.items():
            zf.writestr(name, body)
    return buf.getvalue()


def test_offline_never_fetches(tmp_path: Path) -> None:
    def fetcher(url: str) -> bytes:
        raise AssertionError("fetched while offline")

    with pytest.raises(NikashaError, match="--online"):
        load_amalgamation("3.45.1", [2024], online=False, cache=tmp_path, fetcher=fetcher)


def test_online_fetch_tries_years_then_caches(tmp_path: Path) -> None:
    body = _zip({"sqlite-amalgamation-3450100/sqlite3.c": TEXT, "../escape.c": "no"})
    seen: list[str] = []

    def fetcher(url: str) -> bytes:
        seen.append(url)
        if "/2023/" in url:
            raise NikashaError("404")
        return body

    amap = load_amalgamation("3.45.1", [2023, 2024], online=True, cache=tmp_path, fetcher=fetcher)
    assert seen == [
        "https://www.sqlite.org/2023/sqlite-amalgamation-3450100.zip",
        "https://www.sqlite.org/2024/sqlite-amalgamation-3450100.zip",
    ]
    assert amap.lookup(15) is not None
    assert not (tmp_path.parent / "escape.c").exists()
    # The cached copy is then used offline, with no request.
    again = load_amalgamation("3.45.1", [2024], online=False, cache=tmp_path)
    assert again.lookup(15) == amap.lookup(15)


def test_all_years_missing(tmp_path: Path) -> None:
    def fetcher(url: str) -> bytes:
        raise NikashaError("404")

    with pytest.raises(NikashaError, match="no amalgamation"):
        load_amalgamation("3.45.1", [2024], online=True, cache=tmp_path, fetcher=fetcher)


def test_zip_member_checks() -> None:
    with pytest.raises(NikashaError):
        extract_sqlite3_c(b"not a zip", "3450100")
    with pytest.raises(NikashaError):
        extract_sqlite3_c(_zip({"other/sqlite3.c": "x"}), "3450100")
