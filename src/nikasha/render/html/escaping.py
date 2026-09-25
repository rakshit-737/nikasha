# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The escaping contract for the HTML report (SPEC §15.2, P7).

**Everything in the report is untrusted.** The report body was written by a stranger; the
code excerpts, paths and symbol names come from a repository that stranger chose; the
commands were built from both. There is no "safe" string in this document except the
literal markup this package writes itself.

So this module has exactly one rule: *a value reaches the page through one of these
functions, or it does not reach the page.* There is no "mark safe" helper here, and there
will not be one — every escaping bug in a report renderer starts with someone adding it.

The four sinks need four different escapes, and mixing them up is the usual way this goes
wrong:

* :func:`text` — character data between tags.
* :func:`attr` — an attribute value, always used with double quotes.
* :func:`script_json` — data embedded in a ``<script>`` block, where the HTML parser stops
  at the first ``</script>`` **inside a string literal** and where ``<!--`` also ends the
  element.
* :func:`url` — an ``href``/``src`` value, which must additionally be checked for its
  scheme, since escaping does nothing to stop ``javascript:``.
"""

from __future__ import annotations

import json
import re

#: Schemes an attacker-supplied URL may use. `data:` is deliberately absent for links:
#: the page generates its own `data:` download URL, but never trusts one from input.
SAFE_SCHEMES = ("https://", "http://", "mailto:")

#: Characters that must never appear literally in HTML character data.
_TEXT_MAP = {
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
}

#: Attribute values additionally need both quote styles escaped, plus the characters that
#: let a value break out of an unquoted attribute. We always quote, but defence in depth.
_ATTR_MAP = {
    **_TEXT_MAP,
    '"': "&quot;",
    "'": "&#x27;",
    "`": "&#x60;",
    "=": "&#x3d;",
}

#: A conservative URL shape: no quotes, angle brackets, backslashes, whitespace or control
#: characters, and bounded so a pathological URL cannot bloat the page.
_URL_RE = re.compile(r"\A[A-Za-z0-9:/?#\[\]@!$&()*+,;=._~%\-]{1,2048}\Z")

#: Control characters that must not survive into the document at all. Bidi overrides and
#: zero-width characters can make a rendered path read as something it is not, which in a
#: document whose whole purpose is "this path does not exist" is a real problem.
_STRIP_RE = re.compile(
    "["
    "\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f"  # C0/C1 controls; tab and newline survive
    "\u200b-\u200f\u2028-\u202e\u2066-\u2069\ufeff"  # zero-width, bidi, BOM
    "\ud800-\udfff"  # lone surrogates: a JSON round-trip can carry them; UTF-8 cannot
    "]"
)


def clean(value: object) -> str:
    """Coerce to ``str`` and drop characters that must never reach the document.

    Tabs and newlines survive: they are meaningful inside a code excerpt.
    """
    return _STRIP_RE.sub("", str(value))


def text(value: object) -> str:
    """Escape character data. Use for anything between two tags."""
    out = clean(value)
    for char, entity in _TEXT_MAP.items():
        out = out.replace(char, entity)
    return out


def attr(value: object) -> str:
    """Escape an attribute value. Always interpolate inside double quotes."""
    out = clean(value)
    for char, entity in _ATTR_MAP.items():
        out = out.replace(char, entity)
    return out


def url(value: object, *, fallback: str = "") -> str:
    """An ``href`` value, or ``fallback`` when the URL is not plainly safe.

    Escaping is not enough for a URL: ``javascript:alert(1)`` contains nothing that needs
    escaping. The scheme is checked first, then the shape, and only then is it escaped.
    """
    raw = clean(value).strip()
    if not raw.lower().startswith(SAFE_SCHEMES) or not _URL_RE.match(raw):
        return fallback
    return attr(raw)


def script_json(value: object) -> str:
    """Serialize ``value`` for embedding inside a ``<script>`` element.

    HTML escaping does not apply inside ``<script>``; the parser instead looks for the
    literal ``</script`` and for ``<!--``. JSON string escapes are honoured by the
    JavaScript parser but ignored by the HTML tokenizer, so escaping ``<`` and ``>`` as
    ``\\u003c``/``\\u003e`` makes both parsers agree.
    """
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return (
        encoded.replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
        .replace(chr(0x2028), "\\u2028")
        .replace(chr(0x2029), "\\u2029")
    )


def css_ident(value: object, *, fallback: str = "x") -> str:
    """A value safe to put in a CSS class name or id (letters, digits, dash, underscore)."""
    out = re.sub(r"[^A-Za-z0-9_-]", "", clean(value))[:64]
    return out or fallback


def attrs(**pairs: object) -> str:
    """Render ``key="value"`` pairs, skipping ``None``. Underscores become dashes."""
    parts = [
        f'{key.replace("_", "-")}="{attr(value)}"'
        for key, value in pairs.items()
        if value is not None
    ]
    return " ".join(parts)


__all__ = [
    "SAFE_SCHEMES",
    "attr",
    "attrs",
    "clean",
    "css_ident",
    "script_json",
    "text",
    "url",
]
