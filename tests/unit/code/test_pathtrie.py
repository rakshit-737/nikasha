# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""PathTrie: longest whole-component suffix resolution (SPEC §11.4)."""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from nikasha.code.pathtrie import PathTrie, normalize_components

VULNLAB = ["src/hdr.c", "src/util.c", "src/util.h", "include/util.h", "tests/util.c", "README"]

# Repository components come from a small alphabet so collisions (shared suffixes) are common;
# prefix components use a disjoint alphabet so they can never extend a match.
_repo_part = st.text(alphabet="abc.", min_size=1, max_size=3).filter(lambda s: s not in {".", ".."})
_prefix_part = st.text(alphabet="XYZ", min_size=1, max_size=4)
_repo_path = st.lists(_repo_part, min_size=1, max_size=4).map("/".join)
_repo = st.lists(_repo_path, min_size=1, max_size=25, unique=True)


def _suffix_depth(a: tuple[str, ...], b: tuple[str, ...]) -> int:
    depth = 0
    while depth < min(len(a), len(b)) and a[-1 - depth] == b[-1 - depth]:
        depth += 1
    return depth


def _brute_force(paths: list[str], query: str) -> tuple[int, list[str]]:
    q = normalize_components(query)
    depths = {p: _suffix_depth(normalize_components(p), q) for p in paths}
    best = max(depths.values(), default=0)
    return best, sorted(p for p, d in depths.items() if d == best) if best else []


# --- examples ------------------------------------------------------------------------------


def test_spec_example_build_root_prefix() -> None:
    trie = PathTrie(["lib/http.c", "lib/url.c", "src/tool_main.c"])
    assert trie.resolve("/src/curl/lib/http.c") == ["lib/http.c"]
    assert trie.match_depth("/src/curl/lib/http.c") == 2


def test_vulnlab_reporter_path() -> None:
    trie = PathTrie(VULNLAB)
    assert trie.resolve("/work/libhdr/src/util.c") == ["src/util.c"]
    assert trie.match_depth("/work/libhdr/src/util.c") == 2


def test_basename_only_match() -> None:
    trie = PathTrie(VULNLAB)
    assert trie.resolve("/home/me/elsewhere/hdr.c") == ["src/hdr.c"]
    assert trie.match_depth("/home/me/elsewhere/hdr.c") == 1


def test_no_match_returns_empty() -> None:
    trie = PathTrie(VULNLAB)
    assert trie.resolve("/src/curl/lib/http.c") == []
    assert trie.match_depth("lib/http.c") == 0
    assert trie.resolve("") == []
    assert trie.resolve("/") == []


def test_ambiguous_basename_returns_all_sorted() -> None:
    trie = PathTrie(VULNLAB)
    assert trie.resolve("util.c") == ["src/util.c", "tests/util.c"]
    assert trie.resolve("/x/y/util.h") == ["include/util.h", "src/util.h"]


def test_deeper_match_wins_over_basename() -> None:
    trie = PathTrie(VULNLAB)
    assert trie.resolve("tests/util.c") == ["tests/util.c"]


def test_whole_components_only() -> None:
    trie = PathTrie(["src/util.c"])
    assert trie.resolve("myutil.c") == []
    assert trie.resolve("/x/mysrc/util.c") == ["src/util.c"]


def test_longer_repo_paths_share_the_suffix() -> None:
    trie = PathTrie(["a/b.c", "x/a/b.c"])
    assert trie.resolve("/build/a/b.c") == ["a/b.c", "x/a/b.c"]
    assert trie.resolve("/x/a/b.c") == ["x/a/b.c"]


@pytest.mark.parametrize(
    "query",
    [
        "/src/curl/lib/http.c",
        "./lib/http.c",
        "lib/./http.c",
        "../../lib/http.c",
        "/src/curl/tmp/../lib/http.c",
        "lib//http.c",
        "\\src\\curl\\lib\\http.c",
        "C:\\build\\curl\\lib\\http.c",
        "c:/build/curl/lib/http.c",
        "D:lib\\http.c",
        "lib/sub/../http.c",
    ],
)
def test_query_normalization(query: str) -> None:
    trie = PathTrie(["lib/http.c", "src/http.c"])
    assert trie.resolve(query) == ["lib/http.c"]
    assert trie.match_depth(query) == 2


def test_dotdot_is_lexical() -> None:
    trie = PathTrie(["lib/http.c", "src/http.c"])
    # lib/../src/http.c is src/http.c, not lib/http.c
    assert trie.resolve("/curl/lib/../src/http.c") == ["src/http.c"]


def test_normalize_components() -> None:
    assert normalize_components("C:\\a\\.\\b\\..\\c.c") == ("a", "c.c")
    assert normalize_components("../../x") == ("x",)
    assert normalize_components("/") == ()
    assert normalize_components("a:b/c") == ("b", "c")  # a drive-like prefix is dropped


def test_repo_paths_are_normalized_and_deduplicated() -> None:
    trie = PathTrie(["./lib/http.c", "lib/http.c", "lib\\http.c", "", "/"])
    assert len(trie) == 1
    assert "lib/http.c" in trie
    assert "./lib/http.c" in trie
    assert "lib/url.c" not in trie
    assert 42 not in trie
    assert trie.resolve("http.c") == ["lib/http.c"]


def test_add_after_resolve_resorts() -> None:
    trie = PathTrie(["b/x.c"])
    assert trie.resolve("x.c") == ["b/x.c"]
    trie.add("a/x.c")
    assert trie.resolve("x.c") == ["a/x.c", "b/x.c"]
    result = trie.resolve("x.c")
    result.append("mutated")
    assert trie.resolve("x.c") == ["a/x.c", "b/x.c"]


def test_empty_trie() -> None:
    trie = PathTrie()
    assert len(trie) == 0
    assert trie.resolve("a.c") == []
    assert trie.match_depth("a.c") == 0


# --- disambiguation ------------------------------------------------------------------------


def test_disambiguate_keeps_the_defining_file() -> None:
    trie = PathTrie(VULNLAB)
    defines = {"src/util.c": True, "tests/util.c": False}
    assert trie.disambiguate("util.c", None, defines.__getitem__) == ["src/util.c"]


def test_disambiguate_keeps_all_when_none_define() -> None:
    trie = PathTrie(VULNLAB)
    assert trie.disambiguate("util.c", None, lambda _: False) == ["src/util.c", "tests/util.c"]


def test_disambiguate_with_explicit_candidates() -> None:
    trie = PathTrie(VULNLAB)
    candidates = ["tests/util.c", "src/util.c", "src/util.c"]
    assert trie.disambiguate("util.c", candidates, lambda p: p.startswith("tests/")) == [
        "tests/util.c"
    ]
    assert trie.disambiguate("util.c", [], lambda _: True) == []


def test_disambiguate_several_defining_files() -> None:
    trie = PathTrie(["a/u.c", "b/u.c", "c/u.c"])
    assert trie.disambiguate("u.c", None, lambda p: p != "b/u.c") == ["a/u.c", "c/u.c"]


# --- properties ----------------------------------------------------------------------------


@given(
    paths=_repo,
    data=st.data(),
    prefix=st.lists(_prefix_part, max_size=4),
    absolute=st.booleans(),
)
@settings(max_examples=300)
def test_prefixed_repo_path_resolves_to_itself(
    paths: list[str], data: st.DataObject, prefix: list[str], absolute: bool
) -> None:
    target = data.draw(st.sampled_from(paths))
    query = ("/" if absolute else "") + "/".join([*prefix, target])
    trie = PathTrie(paths)
    result = trie.resolve(query)
    assert target in result
    assert trie.match_depth(query) == len(normalize_components(target))


@given(paths=_repo, query=st.lists(st.one_of(_repo_part, _prefix_part), max_size=6))
@settings(max_examples=300)
def test_resolve_equals_brute_force(paths: list[str], query: list[str]) -> None:
    q = "/".join(query)
    trie = PathTrie(paths)
    depth, expected = _brute_force(paths, q)
    assert trie.resolve(q) == expected
    assert trie.match_depth(q) == depth
    # Every result shares exactly the maximal depth; nothing else shares a deeper one.
    qc = normalize_components(q)
    for p in trie.resolve(q):
        assert _suffix_depth(normalize_components(p), qc) == depth
    for p in paths:
        assert _suffix_depth(normalize_components(p), qc) <= depth


@given(paths=_repo, data=st.data())
@settings(max_examples=100)
def test_insertion_order_does_not_matter(paths: list[str], data: st.DataObject) -> None:
    shuffled = data.draw(st.permutations(paths))
    query = data.draw(st.sampled_from(paths))
    assert PathTrie(paths).resolve(query) == PathTrie(shuffled).resolve(query)


@given(
    parts=st.lists(_repo_part, min_size=1, max_size=4),
    junk=st.lists(_prefix_part, max_size=3),
    drive=st.sampled_from(["", "C:", "z:"]),
    sep=st.sampled_from(["/", "\\"]),
)
@settings(max_examples=200)
def test_normalization_variants_resolve_identically(
    parts: list[str], junk: list[str], drive: str, sep: str
) -> None:
    target = "/".join(parts)
    trie = PathTrie([target])
    noisy = [*junk, *(f"{j}{sep}.." for j in junk), ".", *parts]
    query = drive + sep + sep.join(noisy)
    assert trie.resolve(query) == [target]
