# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Literal search (SPEC §11.4) on the vulnlab history."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nikasha.code.gitio import GitRepo
from nikasha.code.literal import MAX_LITERAL_CHARS, literal_search, searchable

ROOT = Path(__file__).resolve().parents[2]
EXPECTED = json.loads((ROOT / "examples" / "vulnlab" / "expected.json").read_text())
V120 = EXPECTED["v1.2.0"]


@pytest.fixture
def repo(vulnlab_repo):
    with GitRepo(vulnlab_repo) as r:
        yield r


def test_quoted_line_is_found_with_its_location(repo):
    result = literal_search(repo, "    char *dst = malloc(HDR_VALUE_MAX);\n", V120)
    assert result is not None
    assert result.literal == "char *dst = malloc(HDR_VALUE_MAX);"
    assert [(h.path, h.line) for h in result.hits] == [("src/util.c", 11)]
    assert not result.truncated
    assert result.command == (
        f"git grep -n -I -F -e 'char *dst = malloc(HDR_VALUE_MAX);' {V120} --"
    )


def test_literal_is_never_a_pattern_or_an_option(repo):
    for hostile in ("--open-files-in-pager=touch /tmp/x", "-e", ".*", "dst[len]"):
        result = literal_search(repo, hostile, V120)
        assert result is not None
        assert all(hostile in h.text for h in result.hits)


def test_word_match_and_pathspecs(repo):
    everywhere = literal_search(repo, "util_copy_value", V120)
    assert everywhere is not None
    assert len(everywhere.paths) >= 2
    only_src = literal_search(repo, "util_copy_value", V120, pathspecs=["src/util.c"])
    assert only_src is not None
    assert only_src.paths == ("src/util.c",)
    partial = literal_search(repo, "util_copy", V120, word=True)
    assert partial is not None
    assert partial.hits == ()


def test_cap_is_reported(repo):
    result = literal_search(repo, "return", V120, max_hits=2)
    assert result is not None
    assert len(result.hits) == 2
    assert result.truncated


def test_absent_literal(repo):
    result = literal_search(repo, "hdr_decode_chunked_value(", V120)
    assert result is not None
    assert result.hits == ()
    assert not result.truncated


@pytest.mark.parametrize(
    "literal", ["", "   ", "two\nlines", "cr\rline", "nul\0byte", "x" * (MAX_LITERAL_CHARS + 1)]
)
def test_unsearchable_literals(repo, literal):
    assert searchable(literal) is None
    assert literal_search(repo, literal, V120) is None
