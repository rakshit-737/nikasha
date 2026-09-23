# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Built-in product aliases for extraction (SPEC §9.2, §9.7).

This is a deliberately small seed table so M1 extraction works on its own; M2 introduces
``known_projects.yaml``, which extends and overrides it. Aliases are matched
case-insensitively as whole words.
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


BUILTIN_PRODUCTS: tuple[Product, ...] = (
    Product("libhdr", ("libhdr", "vulnlab"), ("HDR_",), ("hdrcat",)),
    Product(
        "curl",
        ("curl", "libcurl"),
        ("CURLOPT_", "CURLINFO_", "CURLE_", "CURLMOPT_", "CURLSHOPT_", "CURLU_", "CURLUE_"),
        ("curl",),
    ),
    Product("sqlite", ("sqlite", "sqlite3"), ("SQLITE_",), ("sqlite3",)),
    Product("openssl", ("openssl", "libssl", "libcrypto"), ("SSL_", "EVP_"), ("openssl",)),
    Product("libxml2", ("libxml2", "libxml"), ("XML_",), ("xmllint",)),
    Product("zlib", ("zlib",), ("Z_",), ()),
    Product("nginx", ("nginx",), ("NGX_",), ("nginx",)),
    Product(
        "httpd", ("apache httpd", "httpd", "apache http server"), ("APR_",), ("httpd", "apachectl")
    ),
    Product("node", ("node.js", "nodejs"), (), ("node",)),
    Product("django", ("django",), (), ("django-admin",)),
)  # fmt: skip


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
