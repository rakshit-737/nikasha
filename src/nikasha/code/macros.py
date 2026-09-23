# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Macro definitions and the names their replacement text calls (SPEC §11.2).

tree-sitter keeps a C/C++ macro's replacement text as one opaque ``preproc_arg``, so the
calls in it are the ``name(`` tokens found by a linear scan: the macro's own parameters,
C keywords and operators that look like calls (``sizeof(x)``, ``while (0)``) are excluded.
For Rust, ``macro_rules!`` bodies are token trees and their calls come from the query
(``@call.token``) instead; see :func:`nikasha.code.calls.attribute_calls`.
"""

from __future__ import annotations

import re

from tree_sitter import Node

from nikasha.code.symbols import node_text

MAX_MACRO_BODY_BYTES = 64 * 1024

# `name (` in replacement text. Possessive quantifiers keep the scan linear; the lookbehind
# rejects starts inside a longer identifier or after `.`/`->` member access, `#` stringify
# or `##` pasting.
_CALL_TOKEN_RE = re.compile(r"(?<![\w.#>$])([A-Za-z_]\w*+)\s*+\(")
_NOT_CALLS = frozenset(
    {
        "if",
        "while",
        "for",
        "switch",
        "return",
        "sizeof",
        "alignof",
        "_Alignof",
        "offsetof",
        "typeof",
        "__typeof__",
        "decltype",
        "defined",
        "__attribute__",
        "__declspec",
        "_Generic",
        "_Static_assert",
        "static_assert",
        "do",
        "else",
        "case",
        "int",
        "char",
        "long",
        "short",
        "unsigned",
        "signed",
        "void",
        "float",
        "double",
        "const",
        "volatile",
        "struct",
        "union",
        "enum",
    }
)


def macro_parameters(source: bytes, node: Node) -> frozenset[str]:
    params = node.child_by_field_name("parameters")
    if params is None:
        return frozenset()
    return frozenset(node_text(source, p) for p in params.named_children)


def replacement_calls(source: bytes, node: Node) -> tuple[str, ...]:
    """Names called in a C/C++ macro's replacement text, in order, without duplicates."""
    value = node.child_by_field_name("value")
    if value is None:
        return ()
    text = node_text(source, value, MAX_MACRO_BODY_BYTES)
    params = macro_parameters(source, node)
    out: dict[str, None] = {}  # insertion-ordered set
    for match in _CALL_TOKEN_RE.finditer(text):
        name = match.group(1)
        if name not in _NOT_CALLS and name not in params and name != "__VA_ARGS__":
            out[name] = None
    return tuple(out)
