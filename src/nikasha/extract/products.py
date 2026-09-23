# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Product aliases for extraction (SPEC §9.2, §9.7), taken from ``known_projects.yaml``.

Aliases are matched case-insensitively as whole words.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Product:
    name: str
    aliases: tuple[str, ...]
    #: Prefixes of project constants that count as option claims (e.g. ``CURLOPT_``).
    constant_prefixes: tuple[str, ...] = ()
    #: Program names shipped by the project (a command starting with one is about the project).
    programs: tuple[str, ...] = ()


def _from_known_projects() -> tuple[Product, ...]:
    from nikasha.resolve.products import load_known_projects  # noqa: PLC0415 (avoid cycle)

    return tuple(
        Product(p.name, p.aliases, p.constant_prefixes, p.programs)
        for p in load_known_projects().projects
    )


#: Built from ``nikasha/data/known_projects.yaml``, the single source of truth (M2).
BUILTIN_PRODUCTS: tuple[Product, ...] = _from_known_projects()


def product_table(extra: tuple[Product, ...] = ()) -> tuple[Product, ...]:
    return extra + BUILTIN_PRODUCTS


def alias_regex(products: tuple[Product, ...]) -> re.Pattern[str]:
    """One alternation of every alias, longest first, matched as whole words."""
    aliases = sorted({a for p in products for a in p.aliases}, key=lambda a: (-len(a), a))
    alternation = "|".join(re.escape(a) for a in aliases)
    return re.compile(rf"(?<![\w.-])(?:{alternation})(?![\w-])", re.IGNORECASE)


def product_for_alias(alias: str, products: tuple[Product, ...]) -> Product | None:
    low = alias.lower()
    for p in products:
        if low in (a.lower() for a in p.aliases):
            return p
    return None
