# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Winnowing fingerprints for snippet provenance (SPEC §11.4; Schleimer et al., MOSS).

Question answered: *does this quoted code snippet come from that file, and where?*

1. :func:`tokenize` turns code into :class:`Token` s. This module's regex lexer is the
   fallback; a tree-sitter tokenizer can produce the same ``Token(text, line)`` values and
   feed every later step unchanged. Comments and whitespace are dropped and literals become
   placeholders (``STR``, ``NUM``), so reformatting, re-commenting or changing a constant
   does not change the fingerprint, while renaming an identifier does.
2. :func:`kgram_hashes` hashes every run of ``k`` consecutive token texts (64-bit blake2b).
3. :func:`winnow` keeps, from every window of ``w`` consecutive hashes, the minimum
   (robust winnowing: the rightmost minimum when a new one is chosen, the previous choice
   kept on ties).
4. :func:`containment` compares fingerprint sets cheaply to rank candidate files;
   :func:`align` then aligns the token sequences to measure containment exactly and map it
   to a file line range.

**Guarantee.** Two token sequences sharing a run of at least ``w + k - 1`` tokens share at
least one winnowed hash: the run yields ``w`` identical consecutive k-gram hashes, i.e. one
identical window, and both sides select a hash of that window's minimum value.

**Tiny snippets.** A snippet of fewer than ``w + k - 1`` tokens (8 with the defaults) has no
full window and therefore **no fingerprints**; callers must fall back to :func:`align` (or a
literal search) for those.

Complexity (``n`` = characters or tokens):

* :func:`tokenize`: ``O(n)`` on any input. Every regex quantifier is possessive or bounded,
  and block comments, triple-quoted strings and template strings are closed with
  ``str.find``; an unterminated one runs to the end of input (or of the line, for ordinary
  strings), so nothing is ever rescanned;
* :func:`kgram_hashes`: ``O(n · k)``; :func:`winnow`: ``O(n)`` with a monotonic deque;
* :func:`containment`: ``O(|snippet| + |file|)``;
* :func:`align`: ``difflib.SequenceMatcher``, worst case ``O(|snippet| · |file|)``; narrow
  the file to the region around shared fingerprints first when the file is large.
"""

from __future__ import annotations

import difflib
import hashlib
import re
from collections import deque
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

__all__ = [
    "DEFAULT_K",
    "DEFAULT_W",
    "Alignment",
    "Fingerprint",
    "Token",
    "align",
    "containment",
    "fingerprint",
    "fingerprint_tokens",
    "kgram_hashes",
    "tokenize",
    "winnow",
]

DEFAULT_K = 5
DEFAULT_W = 4
#: Joins the token texts of a k-gram before hashing. It is whitespace, so no lexer token
#: (whitespace is dropped) can contain it, and k-gram encodings are unambiguous.
_JOIN = "\x1f"

STR = "STR"
NUM = "NUM"


@dataclass(frozen=True, slots=True)
class Token:
    """One lexical token: its (normalized) text and the 1-based line where it starts."""

    text: str
    line: int


@dataclass(frozen=True, slots=True)
class Fingerprint:
    """A selected k-gram hash and the index of the k-gram's first token."""

    hash: int
    position: int


@dataclass(frozen=True, slots=True)
class Alignment:
    """How much of a snippet a file contains, and where.

    ``blocks`` are ``(snippet_index, file_index, size)`` token runs, in order;
    ``start_line``/``end_line`` span the file lines those runs cover (``None`` when nothing
    matched).
    """

    containment: float
    matched: int
    snippet_tokens: int
    start_line: int | None
    end_line: int | None
    blocks: tuple[tuple[int, int, int], ...]

    @property
    def line_range(self) -> tuple[int, int] | None:
        if self.start_line is None or self.end_line is None:
            return None
        return (self.start_line, self.end_line)


# --- lexer -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Style:
    c_comments: bool  # // and /* */
    hash_comments: bool  # # to end of line
    triple_quotes: bool  # Python """ and '''
    char_quotes: bool  # 'x' is a short character literal, otherwise ' is punctuation
    backticks: bool  # `...` is a (multi-line) string


_ALIASES = {
    "c++": "cpp",
    "cc": "cpp",
    "py": "python",
    "js": "javascript",
    "jsx": "javascript",
    "ts": "typescript",
    "rb": "ruby",
    "rs": "rust",
    "golang": "go",
    "bash": "sh",
    "shell": "sh",
    "zsh": "sh",
}
_HASH_ONLY = frozenset({"python", "ruby", "sh", "perl", "make", "cmake", "yaml", "toml", "r"})
_CHAR_LANGS = frozenset({"c", "cpp", "java", "rust", "go", "csharp"})
_BACKTICK_LANGS = frozenset({"javascript", "typescript", "tsx", "go", "sh", "ruby", "php"})


def _style(lang: str | None) -> _Style:
    key = str(lang or "").lower()
    key = _ALIASES.get(key, key)
    return _Style(
        c_comments=key not in _HASH_ONLY,
        hash_comments=key in _HASH_ONLY or key == "php",
        triple_quotes=key == "python",
        char_quotes=key in _CHAR_LANGS,
        backticks=key in _BACKTICK_LANGS,
    )


_WS_RE = re.compile(r"\s+")
#: Ordinary strings stop at an unescaped quote or at the end of the line (unterminated).
_DQ_RE = re.compile(r'"(?:[^"\\\n]|\\[\s\S])*+"?')
_SQ_RE = re.compile(r"'(?:[^'\\\n]|\\[\s\S])*+'?")
_BT_RE = re.compile(r"`(?:[^`\\]|\\[\s\S])*+`?")
#: A character literal: one escape plus a few characters, or up to four plain characters
#: (C multi-character constants). Bounded, so a lone ' (a Rust lifetime) fails in O(1).
_CHAR_RE = re.compile(r"'(?:\\[^\n][^'\\\n]{0,8}|[^'\\\n]{1,4})'")
_NUM_RE = re.compile(
    r"(?:0[xXbBoO][0-9a-fA-F_]*+|[0-9][0-9_]*+(?:\.[0-9_]*+)?|\.[0-9][0-9_]*+)"
    r"(?:[eEpP][+-]?[0-9_]++)?\w*+"
)
_IDENT_RE = re.compile(r"(?:[^\W\d]|\$)[\w$]*+")
_OPERATORS = """
    >>>= <<= >>= ... **= //= ->* <=> ->  ++ -- << >> <= >= == != && || :: += -= *= /= %= &=
    |= ^= => ** // ## .* ?? ?. :=
""".split()
_OP_RE = re.compile(
    "|".join(re.escape(op) for op in sorted(_OPERATORS, key=len, reverse=True)) + r"|\S"
)
_STRING_PREFIXES = frozenset({"r", "b", "u", "f", "br", "rb", "fr", "rf", "l", "u8"})


def _comment_end(code: str, pos: int, style: _Style) -> int | None:
    """Where a comment starting at *pos* ends (exclusive), or ``None`` if none starts."""
    if style.c_comments and code.startswith("//", pos):
        return _line_end(code, pos)
    if style.c_comments and code.startswith("/*", pos):
        close = code.find("*/", pos + 2)
        return len(code) if close < 0 else close + 2
    if style.hash_comments and code[pos] == "#":
        return _line_end(code, pos)
    return None


def _line_end(code: str, pos: int) -> int:
    newline = code.find("\n", pos)
    return len(code) if newline < 0 else newline


def _literal_end(code: str, pos: int, style: _Style) -> int | None:
    """Where a string or character literal starting at *pos* ends, or ``None``."""
    char = code[pos]
    if char in "\"'" and style.triple_quotes and code.startswith(char * 3, pos):
        close = code.find(char * 3, pos + 3)
        return len(code) if close < 0 else close + 3
    match: re.Match[str] | None = None
    if char == '"':
        match = _DQ_RE.match(code, pos)
    elif char == "'":
        match = (_CHAR_RE if style.char_quotes else _SQ_RE).match(code, pos)
    elif char == "`" and style.backticks:
        match = _BT_RE.match(code, pos)
    return match.end() if match else None


def _lex_token(code: str, pos: int, style: _Style) -> tuple[str, int]:
    """The normalized text and end offset of the (non-space, non-comment) token at *pos*."""
    literal = _literal_end(code, pos, style)
    if literal is not None:
        return STR, literal
    number = _NUM_RE.match(code, pos) if code[pos] in "0123456789." else None
    if number is not None:
        return NUM, number.end()
    ident = _IDENT_RE.match(code, pos)
    if ident is not None:
        end = ident.end()
        if end < len(code) and ident.group().lower() in _STRING_PREFIXES:
            prefixed = _literal_end(code, end, style)
            if prefixed is not None:
                return STR, prefixed
        return ident.group(), end
    operator = _OP_RE.match(code, pos)  # \S matches every non-space character
    text = operator.group() if operator else code[pos]
    return text, pos + len(text)


def tokenize(code: str, lang: str | None = None) -> list[Token]:
    """Lex *code* into tokens with 1-based start lines (regex fallback lexer). ``O(n)``.

    *lang* is a :class:`~nikasha.code.languages.Lang` value or a common alias (``py``,
    ``js``, ``sh``, ...). It selects comment syntax (``//``/``/* */`` for C-like languages
    and for unknown ones; ``#`` for Python, Ruby and shell-like languages; both for PHP) and
    quote rules (``'x'`` is a short character literal in C-like languages, a string
    elsewhere). Identifiers, keywords and punctuation are kept verbatim; string and character
    literals become ``STR`` and numbers ``NUM``.
    """
    style = _style(lang)
    tokens: list[Token] = []
    pos, size = 0, len(code)
    line, counted = 1, 0
    while pos < size:
        space = _WS_RE.match(code, pos)
        if space is not None:
            pos = space.end()
            continue
        comment = _comment_end(code, pos, style)
        if comment is not None:
            pos = comment
            continue
        text, end = _lex_token(code, pos, style)
        line += code.count("\n", counted, pos)
        counted = pos
        tokens.append(Token(text, line))
        pos = end
    return tokens


# --- hashing and winnowing -------------------------------------------------------------


def _check_positive(name: str, value: int) -> None:
    if value < 1:
        raise ValueError(f"{name} must be at least 1, got {value}")


def kgram_hashes(tokens: Sequence[Token], k: int = DEFAULT_K) -> list[int]:
    """The 64-bit blake2b hash of every k-gram of token texts, in order. ``O(n · k)``.

    Hash ``i`` covers ``tokens[i:i + k]``; fewer than *k* tokens give ``[]``.
    """
    _check_positive("k", k)
    texts = [token.text for token in tokens]
    return [
        int.from_bytes(
            hashlib.blake2b(_JOIN.join(texts[i : i + k]).encode(), digest_size=8).digest(),
            "big",
        )
        for i in range(len(texts) - k + 1)
    ]


def winnow(hashes: Sequence[int], w: int = DEFAULT_W) -> list[Fingerprint]:
    """Robust winnowing: one minimum hash per window of *w*, de-duplicated by position.

    When the previously selected hash leaves the window, the **rightmost** minimum of the
    new window is selected; while it stays, it is replaced only by a strictly smaller hash
    (so runs of equal hashes are not re-selected). Fewer than *w* hashes give ``[]``.
    ``O(n)``: a deque holds candidate indices with strictly increasing hashes, the rightmost
    index of each value surviving.
    """
    _check_positive("w", w)
    selected: list[Fingerprint] = []
    window: deque[int] = deque()
    current = -1
    for i, value in enumerate(hashes):
        while window and hashes[window[-1]] >= value:
            window.pop()
        window.append(i)
        start = i - w + 1
        if window[0] < start:
            window.popleft()
        if start < 0:
            continue
        if current < start:
            current = window[0]
            selected.append(Fingerprint(hashes[current], current))
        elif value < hashes[current]:
            current = i
            selected.append(Fingerprint(value, current))
    return selected


def fingerprint_tokens(
    tokens: Sequence[Token], k: int = DEFAULT_K, w: int = DEFAULT_W
) -> list[Fingerprint]:
    """Winnowed fingerprints of an existing token sequence (e.g. from tree-sitter)."""
    return winnow(kgram_hashes(tokens, k), w)


def fingerprint(
    code: str, lang: str | None = None, k: int = DEFAULT_K, w: int = DEFAULT_W
) -> list[Fingerprint]:
    """Tokenize *code* and winnow it. ``[]`` for fewer than ``w + k - 1`` tokens."""
    return fingerprint_tokens(tokenize(code, lang), k, w)


def containment(snippet_fps: Iterable[Fingerprint], file_fps: Iterable[Fingerprint]) -> float:
    """The fraction of the snippet's distinct fingerprint hashes found in the file.

    ``0.0`` for a snippet without fingerprints (see "Tiny snippets" above).
    """
    wanted = {fp.hash for fp in snippet_fps}
    if not wanted:
        return 0.0
    present = {fp.hash for fp in file_fps}
    return len(wanted & present) / len(wanted)


def align(
    snippet_tokens: Sequence[Token], file_tokens: Sequence[Token], min_block: int = 3
) -> Alignment:
    """Align a snippet's tokens inside a file's and report containment and line range.

    Uses ``difflib.SequenceMatcher(autojunk=False)`` on token texts. Matching runs shorter
    than *min_block* tokens are ignored: single ``(`` or ``;`` matches occur everywhere and
    would inflate containment and stretch the line range across the file. Pass
    ``min_block=1`` to count every matched token. ``containment`` is matched snippet tokens
    over all snippet tokens (``0.0`` for an empty snippet); the line range spans the first
    to the last file token of the kept runs, e.g. ``(8, 18)`` for "found at util.c:8-18".
    """
    _check_positive("min_block", min_block)
    matcher = difflib.SequenceMatcher(
        None,
        [token.text for token in snippet_tokens],
        [token.text for token in file_tokens],
        autojunk=False,
    )
    blocks = tuple(
        (block.a, block.b, block.size)
        for block in matcher.get_matching_blocks()
        if block.size >= min_block
    )
    matched = sum(size for _, _, size in blocks)
    ratio = matched / len(snippet_tokens) if snippet_tokens else 0.0
    if not blocks:
        return Alignment(ratio, matched, len(snippet_tokens), None, None, blocks)
    first, last = blocks[0], blocks[-1]
    start = file_tokens[first[1]].line
    end = file_tokens[last[1] + last[2] - 1].line
    return Alignment(ratio, matched, len(snippet_tokens), start, end, blocks)
