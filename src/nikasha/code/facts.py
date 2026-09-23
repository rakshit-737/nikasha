# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""What code intelligence learns from one file (SPEC §11.2), independent of git and SQLite.

The parser turns ``(language, bytes)`` into a :class:`FileFacts`. The index stores it keyed by
the blob SHA, so a file that never changes is parsed once across every release (§11.3).
Plain frozen dataclasses rather than pydantic: these are created by the hundred thousand
while indexing a large repository.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

SymbolKind = Literal[
    "function", "method", "macro", "type", "class", "field", "constant", "module"
]  # fmt: skip


@dataclass(frozen=True, slots=True)
class SymbolDef:
    """A definition. Lines are 1-based and inclusive (SPEC §11.2).

    ``qname`` is the qualified name (``ns::Class::method``, ``pkg.Class.method``,
    ``(*T).Method``); ``name`` is its last component. ``flags`` holds facts such as
    ``static``, ``inline`` or ``function_like`` (for macros).
    """

    name: str
    qname: str
    kind: SymbolKind
    start_line: int
    end_line: int
    flags: frozenset[str] = frozenset()
    signature_hash: str = ""


@dataclass(frozen=True, slots=True)
class CallSite:
    """A call from ``caller_qname`` (``None`` at file scope) to ``callee`` on ``line``.

    ``indirect`` marks calls through a pointer or field (``ctx->cb(x)``, ``obj.fn(x)`` where
    the target is not statically named); ``callee`` is then the field or method name.
    """

    caller_qname: str | None
    callee: str
    line: int
    indirect: bool = False


@dataclass(frozen=True, slots=True)
class MacroDef:
    """A macro definition and the names its replacement text calls (``name(`` tokens)."""

    name: str
    line: int
    calls: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class FileFacts:
    lang: str
    n_lines: int
    parsed_ok: bool
    symbols: tuple[SymbolDef, ...] = ()
    calls: tuple[CallSite, ...] = ()
    addr_taken: frozenset[str] = frozenset()
    macros: tuple[MacroDef, ...] = ()
    error_nodes: int = 0
    notes: tuple[str, ...] = field(default=())

    def definitions(self, name: str) -> list[SymbolDef]:
        return [s for s in self.symbols if name in (s.name, s.qname)]

    def enclosing(self, line: int) -> SymbolDef | None:
        """The innermost function-like definition containing ``line``."""
        best: SymbolDef | None = None
        for s in self.symbols:
            if s.kind not in ("function", "method") or not s.start_line <= line <= s.end_line:
                continue
            if best is None or (s.end_line - s.start_line) < (best.end_line - best.start_line):
                best = s
        return best
