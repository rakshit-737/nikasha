# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Definitions: names, qualified names, kinds, spans, flags and signature hashes (SPEC §11.2).

The query files mark each definition node (``@def.<kind>[.<flag>]``) and its name (``@name``,
a C declarator to descend (``@declarator``) or a Go receiver type (``@receiver``)). Pure
scopes (``@scope``, e.g. a Rust ``impl`` block) only qualify what they contain.
Qualification is one sweep over the definitions in source order with a stack of open scopes,
so it is O(n log n) and never walks parent chains (the input is attacker-controlled and may be
nested arbitrarily deep).

Naming conventions (the ``qname`` of a definition):

* C: the plain name (C has no scopes).
* C++: ``ns::Class::method``; an out-of-line ``A::B::m`` keeps its written qualifier, prefixed
  by any enclosing namespaces; template arguments are dropped (``A<T>::m`` -> ``A::m``).
* Python: ``Class.method``, nested functions ``outer.inner``.
* JavaScript/TypeScript: ``Class.method``, ``outer.inner``, and ``obj.m`` for functions in an
  object literal bound to ``obj``.
* Go: ``F`` for functions; ``(*T).M`` / ``T.M`` for pointer / value receivers (the runtime's
  traceback format, without the package).
* Rust: ``Type::method`` (from ``impl``), ``Trait::method``, ``module::fn``.
* Java: ``Outer.Inner.method``; a constructor is ``Class.Class`` (flag ``constructor``).
* PHP: ``Class::method``.
* Ruby: ``Mod::Class#method`` and ``Mod::Class.singleton`` (Ruby's backtrace style).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from tree_sitter import Node

from nikasha.code.facts import SymbolDef, SymbolKind
from nikasha.code.languages import Lang

MAX_NAME_CHARS = 512
MAX_SIGNATURE_BYTES = 4096
_MAX_DECLARATOR_STEPS = 64

_KINDS: dict[str, SymbolKind] = {
    "function": "function",
    "method": "method",
    "macro": "macro",
    "type": "type",
    "class": "class",
    "field": "field",
    "constant": "constant",
    "module": "module",
}
# Keywords collected into ``SymbolDef.flags`` when they modify a definition.
_FLAG_WORDS = frozenset({"static", "inline", "virtual", "async", "unsafe", "extern", "abstract"})
_FLAG_CHILD_TYPES = frozenset(
    {
        "storage_class_specifier",  # C/C++ static, inline, extern
        "virtual",
        "virtual_function_specifier",
        "modifiers",  # Java
        "function_modifiers",  # Rust async/unsafe/extern
        "static_modifier",  # PHP
        "abstract_modifier",
        "async",
        "static",
    }
)
_C_NAME_TYPES = frozenset(
    {
        "identifier",
        "field_identifier",
        "type_identifier",
        "qualified_identifier",
        "destructor_name",
        "operator_name",
        "template_function",
        "primitive_type",
    }
)
_C_DECLARATOR_WRAPPERS = frozenset(
    {
        "pointer_declarator",
        "reference_declarator",
        "parenthesized_declarator",
        "attributed_declarator",
        "array_declarator",
        "function_declarator",
    }
)


@dataclass(frozen=True, slots=True)
class LangRules:
    """How one language qualifies names."""

    sep: str
    # Definition kinds that qualify what they contain.
    scope_kinds: frozenset[str]
    # Definition kinds (plus every pure @scope) whose functions are methods.
    method_parents: frozenset[str]
    strip_generics: bool = False


_NO_SCOPES = LangRules(sep="::", scope_kinds=frozenset(), method_parents=frozenset())
_JS_RULES = LangRules(
    sep=".",
    scope_kinds=frozenset({"class", "function", "method", "module"}),
    method_parents=frozenset({"class"}),
)
RULES: dict[Lang, LangRules] = {
    Lang.C: _NO_SCOPES,
    Lang.CPP: LangRules(
        sep="::",
        scope_kinds=frozenset({"module", "class", "type"}),
        method_parents=frozenset({"class", "type"}),
        strip_generics=True,
    ),
    Lang.PYTHON: LangRules(
        sep=".",
        scope_kinds=frozenset({"class", "function", "method"}),
        method_parents=frozenset({"class"}),
    ),
    Lang.JAVASCRIPT: _JS_RULES,
    Lang.TYPESCRIPT: _JS_RULES,
    Lang.TSX: _JS_RULES,
    Lang.GO: LangRules(sep=".", scope_kinds=frozenset(), method_parents=frozenset()),
    Lang.RUST: LangRules(
        sep="::",
        scope_kinds=frozenset({"module", "type"}),
        method_parents=frozenset({"type"}),
    ),
    Lang.JAVA: LangRules(
        sep=".",
        scope_kinds=frozenset({"class", "type"}),
        method_parents=frozenset({"class", "type"}),
    ),
    Lang.PHP: LangRules(
        sep="::",
        scope_kinds=frozenset({"class", "type"}),
        method_parents=frozenset({"class", "type"}),
    ),
    Lang.RUBY: LangRules(
        sep="::",
        scope_kinds=frozenset({"class", "module"}),
        method_parents=frozenset({"class", "module"}),
    ),
}


@dataclass(slots=True)
class RawDef:
    """A definition (or pure scope) as captured, before qualification."""

    node: Node
    start: int
    end: int
    kind: str
    flags: frozenset[str]
    written: str  # the name as written (may itself be qualified, e.g. ``A::B::m``)
    pure_scope: bool = False
    fixed_qname: str | None = None  # Go methods: the receiver-derived qname
    qname: str = ""
    name: str = ""
    extra: dict[str, str] = field(default_factory=dict)


def node_text(source: bytes, node: Node, limit: int = MAX_NAME_CHARS * 4) -> str:
    """The node's source text, decoded leniently and capped (never copies a huge span)."""
    end = min(node.end_byte, node.start_byte + limit)
    return source[node.start_byte : end].decode("utf-8", "replace")


def strip_generics(text: str) -> str:
    """Drop ``<...>`` template arguments, leaving ``operator<`` and friends intact."""
    head, marker, tail = text.partition("operator")
    out: list[str] = []
    depth = 0
    for ch in head:
        if ch == "<":
            depth += 1
        elif ch == ">" and depth:
            depth -= 1
        elif depth == 0:
            out.append(ch)
    cleaned = "".join(out)
    while "::::" in cleaned:
        cleaned = cleaned.replace("::::", "::")
    return cleaned + marker + tail


def clean_name(text: str, *, generics: bool = False) -> str:
    """Normalise a written name: no whitespace, optionally no template arguments, capped."""
    text = "".join(text[: MAX_NAME_CHARS * 4].split())
    if generics and "<" in text:
        text = strip_generics(text)
    return text[:MAX_NAME_CHARS]


def last_component(text: str, seps: tuple[str, ...]) -> str:
    """The part after the last separator (``a::b::c`` -> ``c``)."""
    best = text
    for sep in seps:
        if sep in best:
            best = best.rsplit(sep, 1)[1] or best
    return best


def c_declarator_name(node: Node) -> Node | None:
    """Descend a C/C++ declarator to the declared name (``char **(*f(int))(void)`` -> ``f``).

    Pointer, reference, parenthesised, array and attributed declarators are unwrapped; for a
    function declarator the innermost declarator that is a plain name wins, so a function
    returning a function pointer yields the function's own name.
    """
    current: Node | None = node
    for _ in range(_MAX_DECLARATOR_STEPS):
        if current is None:
            return None
        kind = current.type
        if kind in _C_NAME_TYPES:
            return current
        if kind not in _C_DECLARATOR_WRAPPERS:
            return None
        inner = current.child_by_field_name("declarator")
        if inner is None:
            named = current.named_children
            inner = named[-1] if named else None
        current = inner
    return None


def go_receiver_qname(source: bytes, receiver: Node, method: str) -> str:
    """``(*T).M`` for a pointer receiver, ``T.M`` otherwise; type parameters dropped."""
    pointer = False
    current: Node | None = receiver
    for _ in range(8):
        if current is None:
            break
        if current.type == "pointer_type":
            pointer = True
            named = current.named_children
            current = named[0] if named else None
        elif current.type == "generic_type":
            current = current.child_by_field_name("type")
        elif current.type == "parenthesized_type":
            named = current.named_children
            current = named[0] if named else None
        else:
            break
    base = clean_name(node_text(source, current)) if current is not None else "?"
    if "[" in base:
        base = base.split("[", 1)[0]
    return f"(*{base}).{method}" if pointer else f"{base}.{method}"


def _signature_end(node: Node) -> int | None:
    body = node.child_by_field_name("body")
    if body is not None:
        return body.start_byte
    value = node.child_by_field_name("value")
    if value is not None:
        inner = value.child_by_field_name("body")
        return inner.start_byte if inner is not None else value.start_byte
    return None


def signature_hash(source: bytes, node: Node) -> str:
    """A short blake2b of the declaration text up to the body, whitespace collapsed."""
    start = node.start_byte
    end = _signature_end(node)
    if end is None:
        newline = source.find(b"\n", start, node.end_byte)
        end = node.end_byte if newline < 0 else newline
    end = min(end, start + MAX_SIGNATURE_BYTES)
    text = b" ".join(source[start:end].split())
    return hashlib.blake2b(text, digest_size=8).hexdigest()


def definition_flags(source: bytes, node: Node, extra: frozenset[str]) -> frozenset[str]:
    """Modifier keywords (``static``, ``inline``, ``async`` ...) plus capture-name flags."""
    words: set[str] = set(extra)
    for child in node.children:
        if child.type in ("compound_statement", "block", "body", "field_declaration_list"):
            break
        if child.type in _FLAG_CHILD_TYPES:
            words.update(w for w in node_text(source, child, 256).split() if w in _FLAG_WORDS)
    return frozenset(words)


def start_line(node: Node) -> int:
    """The 1-based line a node starts on.

    Points are indexed, never read as ``point.row``: in py-tree-sitter 0.26.0 the chained
    ``node.start_point.row`` on a temporary Point corrupts memory and segfaults after a few
    hundred calls (``node.start_point[0]`` and unpacking are safe).
    """
    return node.start_point[0] + 1


def line_span(node: Node) -> tuple[int, int]:
    """1-based inclusive lines; a node ending at column 0 ends on the previous line."""
    start = start_line(node)
    end_row, end_column = node.end_point
    end = end_row + 1
    if end_column == 0 and end > start:
        end -= 1
    return start, end


def raw_definition(
    lang: Lang, source: bytes, capture: str, captures: dict[str, list[Node]]
) -> RawDef | None:
    """Build a :class:`RawDef` from one query match (``capture`` is its ``def.*`` key)."""
    node = captures[capture][0]
    parts = capture.split(".")
    kind = parts[1] if len(parts) > 1 else ""
    if kind not in _KINDS:
        return None
    rules = RULES[lang]
    name_node: Node | None = None
    if "name" in captures:
        name_node = captures["name"][0]
    elif "declarator" in captures:
        name_node = c_declarator_name(captures["declarator"][0])
    if name_node is None:
        return None
    written = clean_name(node_text(source, name_node), generics=rules.strip_generics)
    if not written:
        return None
    fixed: str | None = None
    if "receiver" in captures:
        fixed = go_receiver_qname(source, captures["receiver"][0], written)
    start = node.start_byte
    # A C++ template's span starts at its `template <...>` line.
    parent = node.parent if lang is Lang.CPP else None
    if parent is not None and parent.type == "template_declaration":
        start = parent.start_byte
    raw = RawDef(
        node=node,
        start=start,
        end=node.end_byte,
        kind=kind,
        flags=frozenset(parts[2:]),
        written=written,
        fixed_qname=fixed,
    )
    if parent is not None and parent.type == "template_declaration":
        raw.extra["template_start"] = str(start_line(parent))
    return raw


def raw_scope(lang: Lang, source: bytes, captures: dict[str, list[Node]]) -> RawDef | None:
    node = captures["scope"][0]
    names = captures.get("name")
    if not names:
        return None
    written = clean_name(node_text(source, names[0]), generics=RULES[lang].strip_generics)
    if not written:
        return None
    return RawDef(
        node=node,
        start=node.start_byte,
        end=node.end_byte,
        kind="scope",
        flags=frozenset(),
        written=written,
        pure_scope=True,
    )


def _joiner(lang: Lang, rules: LangRules, raw: RawDef) -> str:
    if lang is Lang.RUBY and raw.kind in ("function", "method"):
        return "." if "singleton" in raw.flags else "#"
    return rules.sep


def _qname(lang: Lang, rules: LangRules, raw: RawDef, parent: RawDef | None) -> str:
    if raw.fixed_qname is not None:
        return raw.fixed_qname
    if parent is None:
        return raw.written
    return parent.qname + _joiner(lang, rules, raw) + raw.written


def qualify(lang: Lang, raws: list[RawDef]) -> list[RawDef]:
    """Assign ``name``/``qname`` and final kinds; returns the definitions in source order.

    ``raws`` holds definitions and pure scopes; pure scopes are dropped from the result.
    """
    rules = RULES[lang]
    ordered = sorted(raws, key=lambda r: (r.start, -r.end, r.pure_scope is False))
    stack: list[RawDef] = []
    namespaces: set[str] = set()
    out: list[RawDef] = []
    for raw in ordered:
        while stack and (stack[-1].end <= raw.start or stack[-1].end < raw.end):
            stack.pop()
        parent = stack[-1] if stack else None
        raw.qname = _qname(lang, rules, raw, parent)
        raw.name = last_component(raw.written, (rules.sep,))
        if (
            raw.kind == "function"
            and parent is not None
            and (parent.pure_scope or parent.kind in rules.method_parents)
        ):
            raw.kind = "method"
        if raw.kind == "module":
            namespaces.add(raw.qname)
        if raw.pure_scope or raw.kind in rules.scope_kinds:
            stack.append(raw)
        if not raw.pure_scope:
            out.append(raw)
    if lang is Lang.CPP:
        _cpp_out_of_line_methods(out, namespaces)
    return out


def _cpp_out_of_line_methods(defs: list[RawDef], namespaces: set[str]) -> None:
    """An out-of-line ``A::B::m`` is a method unless its qualifier names a namespace."""
    for raw in defs:
        if raw.kind == "function" and "::" in raw.written:
            qualifier = raw.qname.rsplit("::", 1)[0]
            if qualifier not in namespaces:
                raw.kind = "method"


def to_symbol(source: bytes, raw: RawDef) -> SymbolDef:
    start, end = line_span(raw.node)
    if "template_start" in raw.extra:
        start = int(raw.extra["template_start"])
    return SymbolDef(
        name=raw.name,
        qname=raw.qname,
        kind=_KINDS[raw.kind],
        start_line=start,
        end_line=end,
        flags=definition_flags(source, raw.node, raw.flags),
        signature_hash=signature_hash(source, raw.node),
    )
