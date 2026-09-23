# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Winnowing fingerprints and snippet alignment (SPEC §11.4)."""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from nikasha.code.fingerprint import (
    DEFAULT_K,
    DEFAULT_W,
    Alignment,
    Fingerprint,
    Token,
    align,
    containment,
    fingerprint,
    fingerprint_tokens,
    kgram_hashes,
    tokenize,
    winnow,
)
from nikasha.code.languages import Lang

ROOT = Path(__file__).resolve().parents[3]
UTIL_C = ROOT / "examples/vulnlab/src/v1.2.0/src/util.c"

UTIL_COPY_VALUE = """\
char *util_copy_value(const char *value)
{
    size_t len = strlen(value);
    char *dst = malloc(HDR_VALUE_MAX);

    if (dst == NULL)
        return NULL;
    memcpy(dst, value, len);
    dst[len] = '\\0';
    return dst;
}
"""


def _texts(code: str, lang: str | None = "c") -> list[str]:
    return [t.text for t in tokenize(code, lang)]


def _tokens(texts: list[str]) -> list[Token]:
    return [Token(text, i + 1) for i, text in enumerate(texts)]


def _hashes(fps: list[Fingerprint]) -> set[int]:
    return {fp.hash for fp in fps}


# --- lexer ---------------------------------------------------------------------------------


def test_c_tokens_comments_literals_and_lines():
    code = '/* head */\nint x = 0x1F; // trailing\nchar *s = "a \\" b";\nchar c = \'\\n\';\n'
    assert [(t.text, t.line) for t in tokenize(code, "c")] == [
        ("int", 2),
        ("x", 2),
        ("=", 2),
        ("NUM", 2),
        (";", 2),
        ("char", 3),
        ("*", 3),
        ("s", 3),
        ("=", 3),
        ("STR", 3),
        (";", 3),
        ("char", 4),
        ("c", 4),
        ("=", 4),
        ("STR", 4),
        (";", 4),
    ]


def test_c_preprocessor_hash_is_kept():
    assert _texts('#include "util.h"\n#define A(x) x ## 1') == [
        *["#", "include", "STR", "#", "define", "A", "(", "x", ")", "x", "##", "NUM"],
    ]


def test_multichar_operators():
    assert _texts("p->n <<= 2; a::b; x++ != y--; i >>>= 1") == [
        *["p", "->", "n", "<<=", "NUM", ";", "a", "::", "b", ";"],
        *["x", "++", "!=", "y", "--", ";", "i", ">>>=", "NUM"],
    ]


@pytest.mark.parametrize("number", ["0", "42", "0x1Fu", "1.5e-3", ".5f", "1_000", "10ULL", "0b101"])
def test_numbers_become_placeholders(number):
    assert _texts(f"x = {number};") == ["x", "=", "NUM", ";"]


def test_python_comments_strings_and_floor_division():
    code = 'x = a // 2  # halve\ns = r"raw\\"q" + f\'{x}\'\n"""doc\nstring"""\ny = 1\n'
    assert [(t.text, t.line) for t in tokenize(code, Lang.PYTHON)] == [
        ("x", 1),
        ("=", 1),
        ("a", 1),
        ("//", 1),
        ("NUM", 1),
        ("s", 2),
        ("=", 2),
        ("STR", 2),
        ("+", 2),
        ("STR", 2),
        ("STR", 3),
        ("y", 5),
        ("=", 5),
        ("NUM", 5),
    ]


def test_hash_is_a_comment_only_in_hash_languages():
    assert _texts("# note\nx", "py") == ["x"]
    assert _texts("# note\nx", "ruby") == ["x"]
    assert _texts("# note\nx", "bash") == ["x"]
    assert _texts("# note\nx", None) == ["#", "note", "x"]
    assert _texts("# a\n// b\n/* c */ x", "php") == ["x"]


def test_slash_comments_are_not_comments_in_python():
    assert _texts("a /* b */", "python") == ["a", "/", "*", "b", "*", "/"]


def test_rust_lifetime_is_not_a_char_literal():
    assert _texts("fn f<'a>(x: &'a str) -> char { 'z' }", "rust") == [
        *["fn", "f", "<", "'", "a", ">", "(", "x", ":", "&", "'", "a", "str", ")"],
        *["->", "char", "{", "STR", "}"],
    ]


def test_single_quote_is_a_string_outside_c_like_languages():
    assert _texts("x = 'hello world'", "javascript") == ["x", "=", "STR"]
    assert _texts("x = 'hello world'", "c") == ["x", "=", "'", "hello", "world", "'"]


def test_backtick_strings_span_lines():
    tokens = tokenize("a = `x\n${y}\n`; b", "js")
    assert [(t.text, t.line) for t in tokens] == [
        ("a", 1),
        ("=", 1),
        ("STR", 1),
        (";", 3),
        ("b", 3),
    ]
    assert _texts("a `b` c", "c") == ["a", "`", "b", "`", "c"]


def test_unterminated_string_stops_at_end_of_line():
    tokens = tokenize('s = "never closed\nnext;', "c")
    assert [(t.text, t.line) for t in tokens] == [
        ("s", 1),
        ("=", 1),
        ("STR", 1),
        ("next", 2),
        (";", 2),
    ]


def test_unterminated_block_comment_and_triple_quote_run_to_end():
    assert _texts("a /* open\nb c") == ["a"]
    assert _texts('a """ open\nb c', "python") == ["a", "STR"]


def test_prefix_like_identifier_without_quote_is_an_identifier():
    assert _texts("r = b + u8", "c") == ["r", "=", "b", "+", "u8"]
    assert _texts("L'x' u8\"s\"", "c") == ["STR", "STR"]


def test_unicode_identifiers_and_dollar():
    assert _texts("$élan = naïve;", "php") == ["$élan", "=", "naïve", ";"]


def test_empty_and_whitespace_only():
    assert tokenize("") == []
    assert tokenize(" \n\t \n") == []


def test_line_numbers_after_multiline_comment():
    tokens = tokenize("/*\n\n\n*/ x\n\ny", "c")
    assert [(t.text, t.line) for t in tokens] == [("x", 4), ("y", 6)]


@pytest.mark.parametrize(
    ("unit", "lang", "size"),
    [
        # The shapes named in the task, at the full 1 MB.
        ("/*", "c", 1_000_000),
        ('"', "c", 1_000_000),
        ("a", "c", 1_000_000),
        ("'", "c", 1_000_000),
        # More hostile shapes at 256 KB to keep the fast suite fast.
        ('"', "python", 256_000),
        ("'", "python", 256_000),
        ("`", "js", 256_000),
        ("#", "c", 256_000),
        ("#", "python", 256_000),
        ("\\", "c", 256_000),
        ('"\\', "c", 256_000),
        ("0x", "c", 256_000),
        ("1e", "c", 256_000),
        ("/", "c", 256_000),
        ("a ", None, 256_000),
        ("'a", "rust", 256_000),
        ("r'", "python", 256_000),
    ],
)
@pytest.mark.no_cover  # the budget measures the lexer, not coverage.py's tracer (~5x)
def test_lexer_is_linear_on_hostile_input(unit, lang, size):
    code = unit * (size // len(unit))
    started = time.perf_counter()
    tokenize(code, lang)
    elapsed = time.perf_counter() - started
    # Linear: a few seconds at most for 1 MB; a quadratic lexer would need hours.
    assert elapsed < 10, f"{unit!r} x {size} took {elapsed:.2f}s"


def test_lexer_scales_linearly():
    def cost(n: int) -> float:
        code = "x = '\"' + s[1] /* c */ ; // d\n" * n
        started = time.perf_counter()
        tokenize(code, "c")
        return time.perf_counter() - started

    small, large = cost(5_000), cost(40_000)  # 40k lines is about 1.2 MB
    assert large < 8 * small * 4  # 8x input; a quadratic lexer would be ~64x


# --- hashing and winnowing -----------------------------------------------------------------


def test_kgram_hashes_are_64_bit_and_deterministic():
    tokens = _tokens(list("abcdefg"))
    hashes = kgram_hashes(tokens, 5)
    assert len(hashes) == 3
    assert all(0 <= h < 2**64 for h in hashes)
    assert hashes == kgram_hashes(_tokens(list("abcdefg")), 5)
    assert len(set(hashes)) == 3
    assert kgram_hashes(tokens[:4], 5) == []


def test_kgram_hashes_do_not_depend_on_lines():
    a = [Token(t, 1) for t in "abcde"]
    b = [Token(t, 99) for t in "abcde"]
    assert kgram_hashes(a) == kgram_hashes(b)


def test_kgram_join_is_unambiguous():
    assert kgram_hashes(_tokens(["ab", "c"]), 2) != kgram_hashes(_tokens(["a", "bc"]), 2)


def test_invalid_parameters():
    with pytest.raises(ValueError, match="k must be"):
        kgram_hashes([], 0)
    with pytest.raises(ValueError, match="w must be"):
        winnow([1, 2], 0)
    with pytest.raises(ValueError, match="min_block must be"):
        align([], [], min_block=0)


def test_winnow_rightmost_minimum_and_robust_ties():
    # Windows of 3: [5,1,1] picks index 2 (rightmost 1); [1,1,7] and [1,7,1] keep index 2
    # (still minimal, tie with the new 1 at index 4 is not re-selected); [7,1,0] picks 5.
    assert winnow([5, 1, 1, 7, 1, 0], 3) == [Fingerprint(1, 2), Fingerprint(0, 5)]
    # The selection leaves the window: the new window's rightmost minimum is chosen.
    assert winnow([1, 3, 2, 2, 9], 2) == [
        Fingerprint(1, 0),
        Fingerprint(2, 2),
        Fingerprint(2, 3),
    ]
    assert winnow([4, 4, 4, 4], 4) == [Fingerprint(4, 3)]
    assert winnow([1, 2, 3], 4) == []
    assert winnow([], 1) == []
    assert winnow([3, 1, 2], 1) == [Fingerprint(3, 0), Fingerprint(1, 1), Fingerprint(2, 2)]


def _reference_winnow(hashes: list[int], w: int) -> list[Fingerprint]:
    """Quadratic robust winnowing straight from the definition."""
    out: list[Fingerprint] = []
    current = -1
    for start in range(len(hashes) - w + 1):
        window = hashes[start : start + w]
        low = min(window)
        if current >= start and hashes[current] == low:
            continue
        current = start + max(i for i, h in enumerate(window) if h == low)
        out.append(Fingerprint(low, current))
    return out


_small_hashes = st.lists(st.integers(0, 6), max_size=60)


@given(hashes=_small_hashes, w=st.integers(1, 8))
@settings(max_examples=500)
def test_winnow_equals_reference(hashes, w):
    assert winnow(hashes, w) == _reference_winnow(hashes, w)


@given(hashes=_small_hashes, w=st.integers(1, 8))
@settings(max_examples=300)
def test_every_window_holds_a_selected_minimum(hashes, w):
    fps = winnow(hashes, w)
    positions = [fp.position for fp in fps]
    assert positions == sorted(set(positions))
    for fp in fps:
        assert hashes[fp.position] == fp.hash
    for start in range(len(hashes) - w + 1):
        low = min(hashes[start : start + w])
        assert any(start <= p < start + w and hashes[p] == low for p in positions)


_token_text = st.sampled_from(["a", "b", "c", "(", ")", ";", "NUM", "STR", "x"])


_filler = st.lists(_token_text, max_size=30)


@given(
    fillers=st.tuples(_filler, _filler, _filler, _filler),
    k=st.integers(1, 7),
    w=st.integers(1, 7),
    extra=st.integers(0, 10),
    data=st.data(),
)
@settings(max_examples=500)
def test_guarantee_shared_run_of_w_plus_k_minus_1_is_detected(fillers, k, w, extra, data):
    """SPEC §11.4 required test: a shared token run of length >= w + k - 1 is always detected."""
    prefix_a, suffix_a, prefix_b, suffix_b = fillers
    run = data.draw(st.lists(_token_text, min_size=w + k - 1 + extra, max_size=w + k - 1 + extra))
    a = _tokens(prefix_a + run + suffix_a)
    b = _tokens(prefix_b + run + suffix_b)
    shared = _hashes(fingerprint_tokens(a, k, w)) & _hashes(fingerprint_tokens(b, k, w))
    assert shared
    # Specifically, some shared hash comes from the common run itself.
    run_hashes = set(kgram_hashes(_tokens(run), k))
    assert shared & run_hashes


@given(tokens=st.lists(_token_text, max_size=40), k=st.integers(1, 6), w=st.integers(1, 6))
def test_fingerprints_exist_iff_enough_tokens(tokens, k, w):
    fps = fingerprint_tokens(_tokens(tokens), k, w)
    assert bool(fps) == (len(tokens) >= w + k - 1)


# --- containment ---------------------------------------------------------------------------


def test_identical_code_has_full_containment():
    fps = fingerprint(UTIL_COPY_VALUE, "c")
    assert fps
    assert containment(fps, fps) == 1.0


def test_formatting_comments_and_literals_do_not_matter():
    variant = """\
/* copied from upstream */ char*util_copy_value(const char*value){
  size_t len=strlen(value); // length
  char*dst=malloc(HDR_VALUE_MAX);
  if(dst==NULL) return NULL;
  memcpy(dst,value,len); dst[len]='x'; return dst; }
"""
    original = fingerprint(UTIL_COPY_VALUE, "c")
    assert _texts(variant) == _texts(UTIL_COPY_VALUE)
    assert containment(fingerprint(variant, "c"), original) == 1.0
    literal_changed = UTIL_COPY_VALUE.replace("'\\0'", '"zzz"')
    assert containment(fingerprint(literal_changed, "c"), original) == 1.0


def test_renamed_identifiers_do_matter():
    original = fingerprint(UTIL_COPY_VALUE, "c")
    renamed = UTIL_COPY_VALUE.replace("dst", "out").replace("len", "n")
    score = containment(fingerprint(renamed, "c"), original)
    assert 0.0 <= score < 1.0


def test_snippet_inside_whole_file():
    whole = fingerprint(UTIL_C.read_text(), "c")
    assert containment(fingerprint(UTIL_COPY_VALUE, "c"), whole) == 1.0


def test_containment_of_empty_snippet_is_zero():
    assert containment([], fingerprint(UTIL_COPY_VALUE, "c")) == 0.0
    assert containment(fingerprint(UTIL_COPY_VALUE, "c"), []) == 0.0


def test_tiny_snippet_has_no_fingerprints_and_needs_align():
    # memcpy ( dst , v ) ; is 7 tokens, one short of w + k - 1 == 8: no full window.
    tiny = "memcpy(dst, v);"
    assert len(tokenize(tiny, "c")) == 7 < DEFAULT_W + DEFAULT_K - 1
    assert fingerprint(tiny, "c") == []
    assert containment(fingerprint(tiny, "c"), fingerprint(UTIL_C.read_text(), "c")) == 0.0
    # Callers fall back to align, which still locates a tiny snippet.
    line = "dst[len] = '\\0';"
    assert len(tokenize(line, "c")) == 7
    assert fingerprint(line, "c") == []
    found = align(tokenize(line, "c"), tokenize(UTIL_C.read_text(), "c"))
    assert found.containment == 1.0
    assert found.line_range == (16, 16)
    # Eight tokens is the smallest snippet with a fingerprint.
    assert len(fingerprint("memcpy(dst, value, n)", "c")) == 1


# --- alignment -----------------------------------------------------------------------------


def test_align_util_copy_value_lines_8_to_18():
    result = align(tokenize(UTIL_COPY_VALUE, "c"), tokenize(UTIL_C.read_text(), "c"))
    assert isinstance(result, Alignment)
    assert result.containment == 1.0
    assert result.matched == result.snippet_tokens == len(tokenize(UTIL_COPY_VALUE))
    assert result.line_range == (8, 18)
    assert (result.start_line, result.end_line) == (8, 18)


def test_align_reformatted_snippet_still_maps_to_8_to_18():
    reformatted = "char *util_copy_value(const char *value) { size_t len = strlen(value);\n"
    reformatted += "char *dst = malloc(HDR_VALUE_MAX); if (dst == NULL) return NULL;\n"
    reformatted += "memcpy(dst, value, len); dst[len] = 0; return dst; }"
    result = align(tokenize(reformatted, "c"), tokenize(UTIL_C.read_text(), "c"))
    # '\0' (STR) became 0 (NUM): one token differs, the rest matches.
    assert result.snippet_tokens - result.matched == 1
    assert result.line_range == (8, 18)


def test_align_partial_snippet_line_range():
    body = "    if (dst == NULL)\n        return NULL;\n    memcpy(dst, value, len);\n"
    result = align(tokenize(body, "c"), tokenize(UTIL_C.read_text(), "c"))
    assert result.containment == 1.0
    assert result.line_range == (13, 15)


def test_align_ignores_short_spurious_blocks():
    snippet = tokenize("return totally_unrelated(thing);", "c")
    file_tokens = tokenize(UTIL_C.read_text(), "c")
    strict = align(snippet, file_tokens)
    assert strict.matched == 0
    assert strict.containment == 0.0
    assert strict.line_range is None
    loose = align(snippet, file_tokens, min_block=1)
    assert loose.matched > 0
    assert loose.containment < 1.0


def test_align_empty_inputs():
    empty = align([], tokenize(UTIL_COPY_VALUE))
    assert (empty.containment, empty.matched, empty.line_range) == (0.0, 0, None)
    nothing = align(tokenize(UTIL_COPY_VALUE), [])
    assert (nothing.containment, nothing.line_range, nothing.blocks) == (0.0, None, ())


@given(
    before=st.lists(_token_text, max_size=30),
    run=st.lists(_token_text, min_size=3, max_size=30),
    after=st.lists(_token_text, max_size=30),
)
@settings(max_examples=200)
def test_align_finds_an_embedded_snippet(before, run, after):
    file_tokens = [Token(t, i + 1) for i, t in enumerate(before + run + after)]
    snippet = [Token(t, 1) for t in run]
    result = align(snippet, file_tokens, min_block=1)
    assert result.containment == 1.0
    assert result.matched == len(run)
    assert result.line_range is not None
    start, end = result.line_range
    assert 1 <= start <= end <= len(file_tokens)
    assert end - start + 1 >= 1
