# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""known_projects.yaml and generated/release-only files (SPEC §10, §11.5)."""

from __future__ import annotations

import pytest

from nikasha.code.generated import generated_match, glob_match
from nikasha.errors import NikashaError
from nikasha.extract.products import BUILTIN_PRODUCTS
from nikasha.resolve.products import load_known_projects, parse_known_projects


def test_builtin_table_loads_and_resolves() -> None:
    kp = load_known_projects()
    assert {p.name for p in kp.projects} >= {"libhdr", "curl", "sqlite", "libxml2", "openssl"}
    assert kp.by_alias("LibCurl").name == "curl"  # type: ignore[union-attr]
    assert kp.by_alias("nope") is None
    assert kp.by_repo("https://github.com/curl/curl.git/").name == "curl"  # type: ignore[union-attr]
    assert kp.by_repo("https://example.com/x") is None
    assert kp.by_alias("sqlite").tag_families == ("version",)  # type: ignore[union-attr]


def test_extraction_products_come_from_the_yaml() -> None:
    names = {p.name for p in BUILTIN_PRODUCTS}
    assert names == {p.name for p in load_known_projects().projects}
    curl = next(p for p in BUILTIN_PRODUCTS if p.name == "curl")
    assert "CURLOPT_" in curl.constant_prefixes


@pytest.mark.parametrize(
    "text",
    [
        "version: 2\nprojects: []",
        "- not a mapping",
        "version: 1\nprojects: [{aliases: [x]}]",
        "version: 1\nprojects: [{name: x, generated: [{kind: generated}]}]",
        "version: 1\nprojects: [{name: x, generated: [{path_glob: a, kind: bogus}]}]",
        "version: 1\nprojects: [{name: x, generated: {path_glob: a}}]",
        "version: 1\nprojects: [{name: x, aliases: notalist}]",
    ],
)
def test_invalid_documents_are_rejected(text: str) -> None:
    with pytest.raises(NikashaError):
        parse_known_projects(text)


def test_yaml_is_loaded_safely() -> None:
    with pytest.raises(NikashaError):
        parse_known_projects("!!python/object/apply:os.system ['true']")


@pytest.mark.parametrize(
    ("glob", "path", "ok"),
    [
        ("sqlite3.c", "sqlite3.c", True),
        ("sqlite3.c", "bld/sqlite3.c", True),
        ("sqlite3.c", "src/sqlite3.cc", False),
        ("**/config.h", "a/b/config.h", True),
        ("**/config.h", "config.h", True),
        ("dist/**", "dist/js/app.js", True),
        ("dist/**", "src/dist.c", False),
        ("lib/*.h", "lib/x.h", True),
        ("lib/*.h", "lib/sub/x.h", False),
    ],
)
def test_glob_match(glob: str, path: str, ok: bool) -> None:
    assert glob_match(glob, path) is ok


def test_sqlite_amalgamation_is_generated_anywhere() -> None:
    sqlite = load_known_projects().by_alias("sqlite")
    for path in ("sqlite3.c", "bld/sqlite3.c", "/home/me/sqlite-amalgamation-3450100/sqlite3.c"):
        match = generated_match(path, project=sqlite)
        assert match is not None
        assert match.kind == "amalgamation"
    assert generated_match("src/btree.c", project=sqlite) is None


def test_template_sibling_rule() -> None:
    tree = {"lib/curl_config.h.cmake", "src/gram.y", "include/v.h.in", "lib/x-cmake.h.in"}
    assert generated_match("src/gram.c", tree_paths=tree) is not None
    assert generated_match("include/v.h", tree_paths=tree) is not None
    assert generated_match("lib/x.h", tree_paths=tree) is not None
    # A file that is itself in the tree is not "generated" by the sibling rule.
    assert generated_match("src/gram.y", tree_paths=tree) is None
    assert generated_match("src/other.c", tree_paths=tree) is None


def test_build_roots_do_not_hide_generated_files() -> None:
    """Traces cite absolute build paths; the P4 safeguards must still apply."""
    curl = load_known_projects().by_alias("curl")
    tree = {"lib/http.c", "src/gram.y"}
    # A project glob with a directory part matches a trailing run of path components.
    match = generated_match("/home/u/curl-8.5.0/lib/curl_config.h", project=curl, tree_paths=tree)
    assert match is not None
    assert match.kind == "generated"
    # Templates are found through the caller's suffix resolver.

    def resolve(path: str) -> list[str]:
        return sorted(t for t in tree if path == t or path.endswith("/" + t))

    match = generated_match("/build/src/gram.c", tree_paths=tree, resolve=resolve)
    assert match is not None
    assert match.reason == "built from src/gram.y"
    # Without a resolver, the build root still hides the template: the caller must pass one.
    assert generated_match("/build/src/gram.c", tree_paths=tree) is None
    # Suffix matching is only for paths missing from the tree.
    assert generated_match("lib/http.c", project=curl, tree_paths=tree) is None
    assert (
        generated_match("/build/lib/other.c", project=curl, tree_paths=tree, resolve=resolve)
        is None
    )
