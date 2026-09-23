# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Parse one source file into :class:`~nikasha.code.facts.FileFacts` (SPEC §11.2).

``parse_file(lang, source)`` never raises: the source is attacker-controlled, so a broken,
binary, huge or pathological file yields ``parsed_ok=False`` with whatever was recovered and
a note saying why. Grammars come from the per-language wheels (offline, ADR 0002) and the
queries from ``code/queries/<lang>.scm``; both are compiled once per process.

Guards:

* files over :data:`MAX_FILE_BYTES` are not parsed;
* tree-sitter's query engine is quadratic in the width of error-recovery nodes (2 MB of
  ``((((`` takes hours), so before querying we sum ``child_count**2`` over the nodes that
  contain errors and skip extraction above :data:`MAX_ERROR_WIDTH_COST`. Valid code, however
  deep or wide, is not affected. This guard is deterministic;
* some grammars' error recovery is itself quadratic (64 KB of ``}{`` takes ~20 s in the
  Python grammar, 64 KB of ``"a`` ~9 s in C++), so the source is fed through a read
  callback that stops supplying input once :data:`PARSE_TIME_BUDGET_S` has elapsed. The
  parser then finishes on what it has and the file is marked ``parsed_ok=False``. This is
  the one wall-clock dependence: legitimate files parse in well under a second, so only
  hostile input can reach it, and its outcome is always the conservative "not parsed";
* the query cursor keeps depths in 16 bits and degrades catastrophically past 65,535 levels
  (256 KB of ``(a)`` repeated takes ~50 s to query), so queries only start at depths up to
  :data:`MAX_QUERY_DEPTH`. Real code stays below ~200 (the deepest file in /usr/include is
  155, the Python standard library 32); definitions and calls nested deeper are not seen.

py-tree-sitter 0.26.0's ``progress_callback`` (for both ``Parser.parse`` and
``QueryCursor``) segfaults on first use, so it cannot be used for cancellation.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import cache
from importlib import resources

import tree_sitter_c
import tree_sitter_cpp
import tree_sitter_go
import tree_sitter_java
import tree_sitter_javascript
import tree_sitter_php
import tree_sitter_python
import tree_sitter_ruby
import tree_sitter_rust
import tree_sitter_typescript
from tree_sitter import Language, Node, Parser, Point, Query, QueryCursor, Tree

from nikasha.code.calls import Enclosing, RawCall, attribute_calls, raw_call
from nikasha.code.facts import CallSite, FileFacts, MacroDef, SymbolDef
from nikasha.code.languages import Lang
from nikasha.code.macros import replacement_calls
from nikasha.code.preproc import blank_attribute_macros
from nikasha.code.symbols import (
    RULES,
    RawDef,
    node_text,
    qualify,
    raw_definition,
    raw_scope,
    start_line,
    to_symbol,
)

MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_ERROR_WIDTH_COST = 200_000_000
PARSE_TIME_BUDGET_S = 10.0
MAX_QUERY_DEPTH = 50_000
_READ_CHUNK = 1024

_GRAMMARS: dict[Lang, Callable[[], object]] = {
    Lang.C: tree_sitter_c.language,
    Lang.CPP: tree_sitter_cpp.language,
    Lang.PYTHON: tree_sitter_python.language,
    Lang.JAVASCRIPT: tree_sitter_javascript.language,
    Lang.TYPESCRIPT: tree_sitter_typescript.language_typescript,
    Lang.TSX: tree_sitter_typescript.language_tsx,
    Lang.GO: tree_sitter_go.language,
    Lang.RUST: tree_sitter_rust.language,
    Lang.JAVA: tree_sitter_java.language,
    Lang.PHP: tree_sitter_php.language_php,
    Lang.RUBY: tree_sitter_ruby.language,
}
# TSX shares the TypeScript query file (compiled against the TSX grammar).
_QUERY_FILES: dict[Lang, str] = {lang: lang.value for lang in Lang} | {Lang.TSX: "typescript"}
_C_FAMILY = frozenset({Lang.C, Lang.CPP})
_FUNCTION_KINDS = frozenset({"function", "method"})
_CALL_KEYS = ("call", "call.direct", "call.indirect", "call.token")


@cache
def language(lang: Lang) -> Language:
    """The tree-sitter grammar for ``lang`` (keyed by our enum: ``Language.name`` is None)."""
    return Language(_GRAMMARS[lang]())


def query_source(lang: Lang) -> str:
    package = resources.files("nikasha.code.queries")
    return package.joinpath(f"{_QUERY_FILES[lang]}.scm").read_text(encoding="utf-8")


@cache
def query(lang: Lang) -> Query:
    """The compiled extraction query for ``lang``."""
    return Query(language(lang), query_source(lang))


def count_lines(source: bytes) -> int:
    """Newlines, plus one for a final line without a trailing newline; 0 for empty input."""
    if not source:
        return 0
    return source.count(b"\n") + (0 if source.endswith(b"\n") else 1)


def error_scan(root: Node) -> tuple[int, int]:
    """Count ERROR/MISSING nodes and the width cost (sum of ``child_count**2``) of error areas.

    Only subtrees that contain an error are visited. Stops early once the cost exceeds
    :data:`MAX_ERROR_WIDTH_COST`, before materialising the children of a too-wide node.
    """
    if not root.has_error:
        return 0, 0
    errors = 0
    cost = 0
    stack = [root]
    while stack:
        node = stack.pop()
        if node.is_error or node.is_missing:
            errors += 1
        width = node.child_count
        cost += width * width
        if cost > MAX_ERROR_WIDTH_COST:
            return errors, cost
        if width:
            stack.extend(child for child in node.children if child.has_error)
    return errors, cost


def parse_file(
    lang: Lang, source: bytes, *, time_budget_s: float = PARSE_TIME_BUDGET_S
) -> FileFacts:
    """Parse ``source`` as ``lang``. Never raises."""
    lang_name = str(lang)
    n_lines = 0
    try:
        lang = Lang(lang)
        lang_name = lang.value
        n_lines = count_lines(source)
        return _parse(lang, bytes(source), n_lines, time_budget_s)
    except Exception as exc:  # the input is hostile; report, never crash the caller
        return FileFacts(
            lang=lang_name,
            n_lines=n_lines,
            parsed_ok=False,
            notes=(f"internal error while parsing: {type(exc).__name__}",),
        )


def parse_tree(lang: Lang, source: bytes, time_budget_s: float) -> tuple[Tree, bool]:
    """Parse with a time budget; returns the tree and whether input was cut off."""
    deadline = time.monotonic() + time_budget_s
    cut = False

    def read(offset: int, _point: Point) -> bytes:
        nonlocal cut
        if cut or time.monotonic() > deadline:
            cut = True
            return b""
        return source[offset : offset + _READ_CHUNK]

    tree = Parser(language(lang)).parse(read)
    return tree, cut


def _parse(lang: Lang, source: bytes, n_lines: int, time_budget_s: float) -> FileFacts:
    if len(source) > MAX_FILE_BYTES:
        return FileFacts(
            lang=lang.value,
            n_lines=n_lines,
            parsed_ok=False,
            notes=(f"not parsed: {len(source)} bytes exceeds the {MAX_FILE_BYTES}-byte limit",),
        )
    tree, cut = parse_tree(lang, source, time_budget_s)
    root = tree.root_node
    errors, cost = error_scan(root)
    notes: list[str] = []
    if errors and not cut and lang in _C_FAMILY:
        blanked, n_blanked = blank_attribute_macros(source)
        if n_blanked:
            tree2, cut2 = parse_tree(lang, blanked, time_budget_s)
            errors2, cost2 = error_scan(tree2.root_node)
            if errors2 < errors and not cut2:
                source, tree, root, errors, cost = blanked, tree2, tree2.root_node, errors2, cost2
                notes.append(f"{n_blanked} attribute-like macro(s) read as whitespace")
    parsed_ok = not root.has_error and not cut
    if cut:
        notes.append(f"parse stopped: exceeded the {time_budget_s:g}-second time budget")
    if cost > MAX_ERROR_WIDTH_COST:
        return FileFacts(
            lang=lang.value,
            n_lines=n_lines,
            parsed_ok=False,
            error_nodes=errors,
            notes=(
                *notes,
                "not extracted: syntax-error recovery produced a pathologically wide tree",
            ),
        )
    if errors:
        notes.append(f"syntax errors: {errors} error node(s); extraction is partial")
    symbols, calls, addr_taken, macros = _extract(lang, source, root)
    return FileFacts(
        lang=lang.value,
        n_lines=n_lines,
        parsed_ok=parsed_ok,
        symbols=symbols,
        calls=calls,
        addr_taken=addr_taken,
        macros=macros,
        error_nodes=errors,
        notes=tuple(notes),
    )


@dataclass(slots=True)
class _Collected:
    """Everything one query run yields, before qualification and attribution."""

    raws: list[RawDef] = field(default_factory=list)
    seen: set[tuple[int, int, str, str]] = field(default_factory=set)
    calls: list[RawCall] = field(default_factory=list)
    refs: set[str] = field(default_factory=set)
    init_refs: set[str] = field(default_factory=set)
    protos: set[str] = field(default_factory=set)


def _collect_match(
    lang: Lang, source: bytes, captures: dict[str, list[Node]], out: _Collected
) -> None:
    def_key = next((k for k in captures if k.startswith("def.")), None)
    if def_key is not None:
        raw = raw_definition(lang, source, def_key, captures)
        if raw is not None:
            key = (raw.node.start_byte, raw.end, raw.kind, raw.written)
            if key not in out.seen:
                out.seen.add(key)
                out.raws.append(raw)
    elif "scope" in captures:
        scope = raw_scope(lang, source, captures)
        if scope is not None:
            out.raws.append(scope)
    elif any(k in captures for k in _CALL_KEYS):
        call = raw_call(source, captures, generics=RULES[lang].strip_generics)
        if call is not None:
            out.calls.append(call)
    elif "ref" in captures:
        out.refs.add(node_text(source, captures["ref"][0]))
    elif "ref.init" in captures:
        name = node_text(source, captures["ref.init"][0])
        if not _is_constant_name(name):
            out.init_refs.add(name)
    elif "proto" in captures:
        out.protos.add(node_text(source, captures["proto"][0]))


def _is_constant_name(name: str) -> bool:
    """``FOO_BAR`` (all capitals) is conventionally a constant or macro, not a function."""
    return name.upper() == name


def _extract(
    lang: Lang, source: bytes, root: Node
) -> tuple[tuple[SymbolDef, ...], tuple[CallSite, ...], frozenset[str], tuple[MacroDef, ...]]:
    collected = _Collected()
    cursor = QueryCursor(query(lang))
    cursor.set_max_start_depth(MAX_QUERY_DEPTH)
    for _pattern, captures in cursor.matches(root):
        _collect_match(lang, source, captures, collected)

    defs = qualify(lang, collected.raws)
    symbols = tuple(to_symbol(source, raw) for raw in defs)

    enclosers: list[Enclosing] = []
    macro_defs: list[RawDef] = []
    for raw in defs:
        if raw.kind in _FUNCTION_KINDS:
            enclosers.append(Enclosing(raw.node.start_byte, raw.node.end_byte, raw.qname))
        elif raw.kind == "macro":
            enclosers.append(
                Enclosing(raw.node.start_byte, raw.node.end_byte, raw.qname, len(macro_defs))
            )
            macro_defs.append(raw)
    sites, body_calls = attribute_calls(collected.calls, enclosers)

    macros: list[MacroDef] = []
    for index, raw in enumerate(macro_defs):
        if lang in _C_FAMILY:
            called = replacement_calls(source, raw.node)
        else:
            called = tuple(body_calls.get(index, ()))
        macros.append(MacroDef(name=raw.name, line=start_line(raw.node), calls=called))

    addr_taken: frozenset[str] = frozenset()
    if lang in _C_FAMILY:
        functions = {s.name for s in symbols if s.kind in _FUNCTION_KINDS} | collected.protos
        addr_taken = frozenset((collected.refs & functions) | collected.init_refs)
    return symbols, tuple(sites), addr_taken, tuple(macros)
