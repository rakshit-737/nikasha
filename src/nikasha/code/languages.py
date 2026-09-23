# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Language detection from path and content (SPEC §11.2).

The extension decides; a shebang decides for extension-less scripts. ``.h`` is C unless the
file shows C++ constructs (or the project config says C++).
"""

from __future__ import annotations

import re
from enum import StrEnum
from pathlib import PurePosixPath


class Lang(StrEnum):
    C = "c"
    CPP = "cpp"
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    TSX = "tsx"
    GO = "go"
    RUST = "rust"
    JAVA = "java"
    PHP = "php"
    RUBY = "ruby"


EXTENSIONS: dict[str, Lang] = {
    ".c": Lang.C,
    ".h": Lang.C,
    ".cc": Lang.CPP,
    ".cpp": Lang.CPP,
    ".cxx": Lang.CPP,
    ".c++": Lang.CPP,
    ".hh": Lang.CPP,
    ".hpp": Lang.CPP,
    ".hxx": Lang.CPP,
    ".ipp": Lang.CPP,
    ".tcc": Lang.CPP,
    ".py": Lang.PYTHON,
    ".pyi": Lang.PYTHON,
    ".js": Lang.JAVASCRIPT,
    ".mjs": Lang.JAVASCRIPT,
    ".cjs": Lang.JAVASCRIPT,
    ".jsx": Lang.JAVASCRIPT,
    ".ts": Lang.TYPESCRIPT,
    ".mts": Lang.TYPESCRIPT,
    ".cts": Lang.TYPESCRIPT,
    ".tsx": Lang.TSX,
    ".go": Lang.GO,
    ".rs": Lang.RUST,
    ".java": Lang.JAVA,
    ".php": Lang.PHP,
    ".rb": Lang.RUBY,
}

_SHEBANGS: tuple[tuple[str, Lang], ...] = (
    ("python", Lang.PYTHON),
    ("node", Lang.JAVASCRIPT),
    ("deno", Lang.TYPESCRIPT),
    ("ruby", Lang.RUBY),
    ("php", Lang.PHP),
)
_CPP_MARKERS_RE = re.compile(
    rb"^\s{0,40}(?:class\s{1,10}\w|namespace\s{1,10}\w|template\s{0,10}<|public:|private:|"
    rb"protected:|using\s{1,10}namespace\b)|::\w",
    re.MULTILINE,
)
_HEADER_SNIFF_BYTES = 64 * 1024


def detect_language(path: str, head: bytes = b"", *, headers_are_cpp: bool = False) -> Lang | None:
    """Return the language of ``path`` (using ``head``, the first bytes, when needed)."""
    suffix = PurePosixPath(path.lower()).suffix
    lang = EXTENSIONS.get(suffix)
    if lang is Lang.C and suffix == ".h":
        if headers_are_cpp or _CPP_MARKERS_RE.search(head[:_HEADER_SNIFF_BYTES]):
            return Lang.CPP
        return Lang.C
    if lang is not None:
        return lang
    if head.startswith(b"#!"):
        first = head.split(b"\n", 1)[0].decode("utf-8", "replace").lower()
        for marker, shebang_lang in _SHEBANGS:
            if marker in first:
                return shebang_lang
    return None
