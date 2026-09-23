# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Call sites: callee names, directness and the enclosing caller (SPEC §11.2).

A call's ``callee`` is always a plain name, the last component of what was written:
``ns::f(x)`` and ``pkg.F(x)`` both record ``f``/``F``. It is ``indirect`` when the target is
reached through a value rather than named statically: a field or member (``ctx->cb(x)``,
``obj.m()``, ``fmt.Println()``), a parenthesised or dereferenced pointer (``(*fp)(x)``).
Qualified calls (``ns::f()``, ``Foo::new()``, ``Class::m()`` in PHP) are direct.

The caller is found with one sweep over calls and function-like definitions in byte order
(nesting is proper in a syntax tree), never by walking parent pointers.
"""

from __future__ import annotations

from dataclasses import dataclass

from tree_sitter import Node

from nikasha.code.facts import CallSite
from nikasha.code.symbols import clean_name, last_component, node_text, start_line

_CALLEE_SEPS = ("::", "\\", "->", ".")
_MAX_RESOLVE_STEPS = 16

_NAME_TYPES = frozenset(
    {
        "identifier",
        "field_identifier",
        "property_identifier",
        "private_property_identifier",
        "type_identifier",
        "name",
        "constant",
    }
)
_QUALIFIED_TYPES = frozenset(
    {"qualified_identifier", "scoped_identifier", "qualified_name", "scope_resolution"}
)
# Member access: node type -> the field holding the member name.
_MEMBER_FIELDS = {
    "field_expression": "field",
    "member_expression": "property",
    "selector_expression": "field",
    "attribute": "attribute",
}
# Wrappers that hide the target behind a value: descend, and the call is indirect.
_WRAPPER_FIELDS = {"parenthesized_expression": None, "pointer_expression": "argument"}
# Explicit template/generic arguments: descend, directness unchanged.
_GENERIC_FIELDS = {"template_function": "name", "generic_function": "function"}


@dataclass(frozen=True, slots=True)
class RawCall:
    pos: int  # byte offset of the callee's name: orders `a.f().g()` as f, g
    callee: str
    line: int
    indirect: bool


def _callee_name(source: bytes, node: Node, generics: bool) -> str:
    return last_component(clean_name(node_text(source, node), generics=generics), _CALLEE_SEPS)


def resolve_callee(source: bytes, fn: Node, *, generics: bool) -> tuple[Node, str, bool] | None:
    """Resolve a call's function expression to ``(name node, callee, indirect)``.

    Returns ``None`` for shapes with no usable name (``f()()``, ``table[i](x)``).
    """
    indirect = False
    current: Node | None = fn
    for _ in range(_MAX_RESOLVE_STEPS):
        if current is None:
            return None
        kind = current.type
        if kind in _NAME_TYPES or kind in _QUALIFIED_TYPES:
            name = _callee_name(source, current, generics)
            return (current, name, indirect) if name else None
        member_field = _MEMBER_FIELDS.get(kind)
        if member_field is not None:
            member = current.child_by_field_name(member_field)
            if member is None:
                return None
            name = _callee_name(source, member, generics)
            # `obj.Base::m()` in C++ names its target statically.
            qualified = member.type in _QUALIFIED_TYPES
            return (member, name, indirect or not qualified) if name else None
        if kind in _WRAPPER_FIELDS:
            wrapper_field = _WRAPPER_FIELDS[kind]
            if wrapper_field is None:
                named = current.named_children
                current = named[0] if len(named) == 1 else None
            else:
                current = current.child_by_field_name(wrapper_field)
            indirect = True
            continue
        generic_field = _GENERIC_FIELDS.get(kind)
        if generic_field is not None:
            current = current.child_by_field_name(generic_field)
            continue
        return None
    return None


def raw_call(source: bytes, captures: dict[str, list[Node]], *, generics: bool) -> RawCall | None:
    """Build a :class:`RawCall` from one query match."""
    if "call" in captures and "fn" in captures:
        resolved = resolve_callee(source, captures["fn"][0], generics=generics)
        if resolved is None:
            return None
        name_node, callee, indirect = resolved
    elif "call.token" in captures:
        # Rust: `ident (..)` inside a macro's token tree.
        name_node = captures["call.token"][0]
        args = captures.get("args")
        if not args or source[args[0].start_byte : args[0].start_byte + 1] != b"(":
            return None
        prev = name_node.prev_sibling
        indirect = prev is not None and prev.type == "."
        callee = _callee_name(source, name_node, generics)
    else:
        key = "call.direct" if "call.direct" in captures else "call.indirect"
        if key not in captures or "callee" not in captures:
            return None
        name_node = captures["callee"][0]
        callee = _callee_name(source, name_node, generics)
        indirect = key == "call.indirect"
    if not callee:
        return None
    return RawCall(
        pos=name_node.start_byte,
        callee=callee,
        line=start_line(name_node),
        indirect=indirect,
    )


@dataclass(frozen=True, slots=True)
class Enclosing:
    """A function-like definition (or a macro, whose calls are attributed to it)."""

    start: int
    end: int
    qname: str
    macro_index: int | None = None


def attribute_calls(
    calls: list[RawCall], enclosers: list[Enclosing]
) -> tuple[list[CallSite], dict[int, list[str]]]:
    """Attach each call to its innermost enclosing function (or macro).

    Returns the call sites in source order, and for each macro index the callees written in
    its body (in order, without duplicates).
    """
    ordered_calls = sorted(set(calls), key=lambda c: (c.pos, c.callee, c.indirect))
    ordered_defs = sorted(enclosers, key=lambda e: (e.start, -e.end))
    stack: list[Enclosing] = []
    i = 0
    sites: list[CallSite] = []
    macro_calls: dict[int, dict[str, None]] = {}  # insertion-ordered sets
    for call in ordered_calls:
        while i < len(ordered_defs) and ordered_defs[i].start <= call.pos:
            opening = ordered_defs[i]
            while stack and stack[-1].end <= opening.start:
                stack.pop()
            stack.append(opening)
            i += 1
        while stack and stack[-1].end <= call.pos:
            stack.pop()
        inner = stack[-1] if stack else None
        if inner is not None and inner.macro_index is not None:
            macro_calls.setdefault(inner.macro_index, {})[call.callee] = None
            continue
        sites.append(
            CallSite(
                caller_qname=inner.qname if inner is not None else None,
                callee=call.callee,
                line=call.line,
                indirect=call.indirect,
            )
        )
    return sites, {index: list(names) for index, names in macro_calls.items()}
