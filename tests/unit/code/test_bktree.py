# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""BK-tree "did you mean" suggestions (SPEC §11.4), checked against brute force."""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from rapidfuzz.distance import Levenshtein

from nikasha.code.bktree import BKTree, name_parts, token_jaccard

#: Every function defined in examples/vulnlab/src/*/src/*.c.
VULNLAB_FUNCTIONS = [
    "dup_str",
    "hdr_casecmp",
    "hdr_find",
    "hdr_find_line",
    "hdr_get",
    "hdr_list_free",
    "hdr_list_grow",
    "hdr_list_init",
    "hdr_parse_block",
    "hdr_parse_line",
    "is_ws",
    "util_copy_value",
    "util_strip",
    "util_trim",
]

_word = st.text(alphabet="abAB_c", max_size=8)


def _brute_force(words, query, radius):
    """Every distinct word within *radius*, as sorted (distance, word) pairs."""
    pairs = {(Levenshtein.distance(w.lower(), query.lower()), w) for w in words}
    return sorted((d, w) for d, w in pairs if d <= radius)


# --- name parts and Jaccard ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "parts"),
    [
        ("hdr_decode_chunked_value", {"hdr", "decode", "chunked", "value"}),
        ("readHTTPHeader", {"read", "http", "header"}),
        ("HTTPServer2", {"http", "server", "2"}),
        ("XMLHttpRequest", {"xml", "http", "request"}),
        ("__init__", {"init"}),
        ("ALL_CAPS_NAME", {"all", "caps", "name"}),
        ("", set()),
        ("___", set()),
    ],
)
def test_name_parts(name, parts):
    assert name_parts(name) == frozenset(parts)


def test_token_jaccard():
    assert token_jaccard("hdr_parse_line", "hdrParseLine") == 1.0
    assert token_jaccard("hdr_parse_line", "hdr_find_line") == pytest.approx(2 / 4)
    assert token_jaccard("", "") == 0.0
    assert token_jaccard("abc", "") == 0.0


def test_name_parts_linear_on_long_input():
    # Parts are capped at 64 characters (bounded quantifiers keep the regex linear).
    assert name_parts("A" * 100_000) == frozenset({"a" * 64, "a" * (100_000 % 64)})
    assert name_parts("aB" * 50_000) == frozenset({"a", "ba", "b"})


# --- search --------------------------------------------------------------------------------


def test_empty_tree():
    tree = BKTree()
    assert len(tree) == 0
    assert tree.search("anything", 5) == []
    assert tree.suggest("anything") == []


def test_search_basic():
    tree = BKTree(VULNLAB_FUNCTIONS)
    assert tree.search("hdr_parse_lines", 1) == [(1, "hdr_parse_line")]
    assert tree.search("HDR_GET", 0) == [(0, "hdr_get")]
    assert tree.search("hdr_get", -1) == []


def test_duplicates_keep_every_original_spelling():
    tree = BKTree(["Foo", "foo", "FOO", "foo", "bar"])
    assert len(tree) == 4
    assert tree.search("foo", 0) == [(0, "FOO"), (0, "Foo"), (0, "foo")]
    assert tree.suggest("fooo") == ["FOO", "Foo", "foo"]
    tree.add("Foo")
    assert len(tree) == 4


@given(words=st.lists(_word, max_size=40), query=_word, radius=st.integers(-1, 6))
@settings(max_examples=400)
def test_search_equals_brute_force(words, query, radius):
    tree = BKTree(words)
    expected = _brute_force(words, query, radius)
    assert tree.search(query, radius) == expected


@given(words=st.lists(_word, max_size=30), query=_word)
@settings(max_examples=200)
def test_suggest_is_brute_force_ranking(words, query):
    radius = max(1, len(query) // 4)
    hits = _brute_force(words, query, radius)
    ranked = sorted(hits, key=lambda h: (h[0], -token_jaccard(query, h[1]), h[1]))
    assert BKTree(words).suggest(query) == [w for _, w in ranked[:3]]


@given(words=st.lists(_word, max_size=30), data=st.data())
@settings(max_examples=100)
def test_insertion_order_does_not_change_results(words, data):
    shuffled = data.draw(st.permutations(words))
    query = data.draw(_word)
    assert BKTree(words).search(query, 3) == BKTree(shuffled).search(query, 3)


# --- suggest -------------------------------------------------------------------------------


def test_suggest_ranks_by_distance_then_jaccard_then_word():
    # Radius 11 // 4 == 2: parse_hdr and zzz are too far; distance ranks the rest.
    tree = BKTree(["parse_hdr", "hdr_parse", "hdr_prse_x", "zzz"])
    query = "hdr_parse_x"
    assert [Levenshtein.distance(query, w) for w in ["hdr_parse", "hdr_prse_x"]] == [2, 1]
    assert tree.suggest(query) == ["hdr_prse_x", "hdr_parse"]


def test_suggest_jaccard_tiebreak():
    # Equal distance (1) from "read_hdr_x": "read_hdr_y" shares {read, hdr}, "read_hdrx" shares
    # {read}; the higher Jaccard wins even though it sorts later alphabetically.
    tree = BKTree(["read_hdrx", "read_hdr_y"])
    query = "read_hdr_x"
    assert {Levenshtein.distance(query, w) for w in ["read_hdrx", "read_hdr_y"]} == {1}
    assert token_jaccard(query, "read_hdr_y") > token_jaccard(query, "read_hdrx")
    assert tree.suggest(query) == ["read_hdr_y", "read_hdrx"]


def test_suggest_word_tiebreak_is_deterministic():
    tree = BKTree(["ab", "ac", "ad", "ae"])
    assert tree.suggest("a") == ["ab", "ac", "ad"]
    assert tree.suggest("a", k=10) == ["ab", "ac", "ad", "ae"]
    assert tree.suggest("a", k=0) == []


def test_suggest_radius_is_quarter_length_at_least_one():
    tree = BKTree(["abcdefgh", "abcdefxx", "abcdexxx"])
    # len 8 → radius 2
    assert tree.suggest("abcdefgh") == ["abcdefgh", "abcdefxx"]
    # len 1 → radius 1
    assert BKTree(["a", "b", "cc"]).suggest("x") == ["a", "b"]


def test_vulnlab_typos():
    tree = BKTree(VULNLAB_FUNCTIONS)
    assert tree.suggest("hdr_parse_lines") == ["hdr_parse_line"]
    assert tree.suggest("hdr_prase_line") == ["hdr_parse_line"]
    assert tree.suggest("util_copy_val") == ["util_copy_value"]
    assert tree.suggest("Hdr_Parse_Line") == ["hdr_parse_line"]


def test_vulnlab_fabricated_name_has_no_suggestion():
    # len("hdr_decode_chunked_value") == 24 → radius 6. The nearest real names are 16 edits
    # away (hdr_find_line, hdr_parse_line, util_copy_value) and hdr_parse_block is 17, so the
    # "did you mean" list is honestly empty rather than a misleading guess.
    tree = BKTree(VULNLAB_FUNCTIONS)
    query = "hdr_decode_chunked_value"
    assert Levenshtein.distance(query, "hdr_parse_line") == 16
    assert Levenshtein.distance(query, "hdr_parse_block") == 17
    assert tree.search(query, 6) == []
    assert tree.suggest(query) == []
    nearest = tree.search(query, 16)
    assert nearest == [(16, "hdr_find_line"), (16, "hdr_parse_line"), (16, "util_copy_value")]
