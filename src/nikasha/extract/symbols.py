# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Symbol claims from prose (SPEC §9.3).

Candidates come from inline code spans, ``identifier(`` in prose, and phrases such as "the
function X", "X macro" or "in X()". A plain word only counts when it *looks like code*
(backticks, ``()``, an underscore, a digit or camelCase). Names on the external-API lists are
kept but marked ``external``. Symbols inside code blocks are not taken from here: traces and
patches have their own claims, PoC code is the reporter's, and snippet *definitions* come
from :mod:`.snippets`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from nikasha.extract.external_apis import is_external
from nikasha.extract.paths import PATH_RE, is_path_candidate
from nikasha.extract.registry import ExtractContext, make_claim, register
from nikasha.extract.spans import Region, clause_bounds, finditer_in, inline_code_spans
from nikasha.model.claims import SymbolClaim, SymbolKindHint
from nikasha.model.report import Span

NAME = "symbols"

_IDENT = r"[A-Za-z_][A-Za-z0-9_]{0,100}+"
#: ``name``, ``ns::Class::method``, ``obj.method`` or ``Class#method`` (possessive: linear).
QUALIFIED = rf"{_IDENT}(?:(?:::|\.|#){_IDENT}){{0,5}}+"
_QUALIFIED_FULL_RE = re.compile(rf"^(?P<name>{QUALIFIED})(?P<call>\s{{0,2}}\([^()]{{0,200}}\))?$")
_CALL_IN_PROSE_RE = re.compile(rf"(?<![\w.:>#-])(?P<name>{QUALIFIED})\((?=[^()\n]{{0,200}}\))")
_KIND_WORDS: dict[str, SymbolKindHint] = {
    "function": "function",
    "func": "function",
    "routine": "function",
    "callback": "function",
    "handler": "function",
    "method": "method",
    "macro": "macro",
    "struct": "type",
    "structure": "type",
    "type": "type",
    "typedef": "type",
    "class": "class",
    "field": "field",
    "member": "field",
    "constant": "constant",
    "variable": "unknown",
}
_KIND_ALT = "|".join(sorted(_KIND_WORDS, key=len, reverse=True))
_PHRASE_BEFORE_RE = re.compile(
    rf"\b(?P<kw>{_KIND_ALT})\s{{1,3}}`?(?P<name>{QUALIFIED})`?(?:\(\))?", re.IGNORECASE
)
_PHRASE_AFTER_RE = re.compile(
    rf"`?(?P<name>{QUALIFIED})(?:\(\))?`?\s{{1,3}}(?P<kw>{_KIND_ALT})\b", re.IGNORECASE
)
_CAMEL_RE = re.compile(r"[a-z][A-Z]")
_MIN_LEN = 3
KIND_PRIORITY: dict[SymbolKindHint, int] = {
    "function": 0,
    "method": 1,
    "macro": 2,
    "type": 3,
    "class": 4,
    "field": 5,
    "constant": 6,
    "unknown": 9,
}

STOPWORDS = frozenset(
    """
    the and for with this that from into over under when then than there their they them
    null NULL nullptr nil true false TRUE FALSE None none self void int char long short
    float double bool boolean size_t ssize_t off_t uint8_t uint16_t uint32_t uint64_t int8_t
    int16_t int32_t int64_t uintptr_t intptr_t const static inline struct union enum typedef
    return sizeof if else while for switch case break continue goto extern unsigned signed
    auto register volatile def class import print len str list dict set tuple object main
    function method macro value values data buffer buf len length size count index error
    errors warning note see also example examples here code file files line lines version
    input output string strings number bytes byte type types field fields var let new delete
    ASan UBSan MSan TSan LSan AddressSanitizer UndefinedBehaviorSanitizer MemorySanitizer
    ThreadSanitizer LeakSanitizer Valgrind valgrind gdb lldb HackerOne GitHub GitLab CVE CVSS
    CWE PoC POC RCE DoS TODO README Makefile JSON HTTP HTTPS URL URI API SDK CLI GET POST PUT
    HEAD UTF ASCII EOF OOB UAF
    """.split()
)


@dataclass
class _Candidate:
    spans: list[Span] = field(default_factory=list)
    kind: SymbolKindHint = "unknown"
    context_path: str | None = None


def looks_like_code(name: str) -> bool:
    """Heuristic for unmarked prose words: ``foo_bar``, ``fooBar``, ``foo2``, ``ns::x``."""
    return (
        "_" in name
        or "::" in name
        or any(ch.isdigit() for ch in name)
        or bool(_CAMEL_RE.search(name))
    )


#: File extensions that make a dotted name a file, not ``obj.method`` (``poc.txt``).
DATA_EXTENSIONS = frozenset(
    "txt md rst log json yaml yml toml ini cfg conf xml html htm csv tsv pdf png jpg jpeg gif "
    "svg zip tar gz tgz bz2 xz 7z bin dat raw poc crash out err so dll dylib exe o a lib "
    "patch diff".split()
)


def _bare(name: str) -> str:
    return re.split(r"::|\.|#", name)[-1]


def acceptable(name: str, ctx: ExtractContext) -> bool:
    """Identifier grammar, minimum length, stoplist, and not a path, product or program."""
    bare = _bare(name)
    if len(bare) < _MIN_LEN or bare in STOPWORDS or name in STOPWORDS:
        return False
    if name.lower() in {p.lower() for p in ctx.product_names}:
        return False
    programs = {prog for p in ctx.products for prog in p.programs}
    aliases = {a.lower() for p in ctx.products for a in p.aliases}
    if name in programs or name.lower() in aliases:
        return False
    if "." in name and name.rsplit(".", 1)[-1].lower() in DATA_EXTENSIONS:
        return False
    return not ("." in name and is_path_candidate(name))


def _context_path(ctx: ExtractContext, region: Region) -> str | None:
    clause = clause_bounds(ctx.report.body, region[0], region[1])
    for m in PATH_RE.finditer(ctx.report.body, clause[0], clause[1]):
        if is_path_candidate(m.group("path")):
            return m.group("path")
    return None


@register(NAME)
def extract_symbols(ctx: ExtractContext) -> list[SymbolClaim]:
    report, body = ctx.report, ctx.report.body
    candidates: dict[str, _Candidate] = {}

    def add(name: str, start: int, end: int, kind: SymbolKindHint) -> None:
        if ctx.url_index.overlaps((start, end)) or not acceptable(name, ctx):
            return
        cand = candidates.setdefault(name, _Candidate())
        span = report.span(start, end)
        if not any(s.start < end and start < s.end for s in cand.spans):
            cand.spans.append(span)
        if KIND_PRIORITY[kind] < KIND_PRIORITY[cand.kind]:
            cand.kind = kind
        if cand.context_path is None:
            cand.context_path = _context_path(ctx, (start, end))

    # 1. Inline code spans: `name`, `name()`, `ns::name(args)`.
    for code in inline_code_spans(report, ctx.prose):
        m = _QUALIFIED_FULL_RE.match(code.text.strip())
        if m is None:
            continue
        kind: SymbolKindHint = "function" if m.group("call") else "unknown"
        add(m.group("name"), code.span.start, code.span.end, kind)

    # 2. name( in prose.
    for m in finditer_in(_CALL_IN_PROSE_RE, body, ctx.prose):
        add(m.group("name"), m.start("name"), m.end("name"), "function")

    # 3. "the function X", "X macro" (plain words must look like code).
    for pattern in (_PHRASE_BEFORE_RE, _PHRASE_AFTER_RE):
        for m in finditer_in(pattern, body, ctx.prose):
            name = m.group("name")
            marked = "`" in m.group(0) or "()" in m.group(0)
            if not marked and not looks_like_code(name):
                continue
            add(name, m.start("name"), m.end("name"), _KIND_WORDS[m.group("kw").lower()])

    claims: list[SymbolClaim] = []
    for name in sorted(candidates):
        cand = candidates[name]
        spans = sorted(cand.spans, key=lambda s: (s.start, s.end))
        claims.append(
            make_claim(
                SymbolClaim,
                spans=spans,
                extractor=NAME,
                confidence=0.85 if cand.kind != "unknown" else 0.7,
                name=name,
                symbol_kind_hint=cand.kind,
                context_path=cand.context_path,
                external=is_external(name),
            )
        )
    return claims
