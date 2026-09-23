# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Claim scoping: is a claim about the *project* at all? (ADR 0003)

slopcheck found that a static checker "cannot tell which parts of a report are claims about
the project" (reporter PoC code, third-party APIs and prose read alike). Every claim gets
a ``provenance``:

* ``project_attributed``: tied to the project by a project path, a trace, an attributed
  snippet, or the product's name in the same sentence;
* ``reporter_artifact``: the reporter's own PoC, build commands or local paths;
* ``third_party``: an external API or a system path;
* ``unscoped``: none of the above can be shown.

Checks may refute only ``project_attributed`` claims (M3). Values an extractor already set
(e.g. options, which depend on the command they appear in) are kept.
"""

from __future__ import annotations

import re

from nikasha.extract.registry import ExtractContext
from nikasha.extract.spans import Region, sentence_bounds
from nikasha.model.claims import (
    ClaimBase,
    FileClaim,
    LineClaim,
    PatchClaim,
    PocClaim,
    Provenance,
    ReferenceClaim,
    SnippetClaim,
    SymbolClaim,
    TraceClaim,
    VersionClaim,
)

_SYSTEM_PATH_RE = re.compile(
    r"^(?:/usr/|/lib|/opt/|/System/|/Library/|/nix/store/|[A-Za-z]:/Windows/|/Applications/)"
)
_REPORTER_PATH_RE = re.compile(r"^(?:/tmp/|/var/tmp/|/private/tmp/|/var/folders/|/dev/shm/)")
_HOME_PATH_RE = re.compile(r"^(?:~/|/home/|/Users/|/root/)")


def classify_path(path: str | None) -> Provenance:
    """System paths are third-party, temp paths the reporter's; home-directory paths are
    unscoped (a build tree under ``~`` may still be the project); relative paths are the
    project's."""
    if path is None:
        return "unscoped"
    if _SYSTEM_PATH_RE.match(path):
        return "third_party"
    if _REPORTER_PATH_RE.match(path):
        return "reporter_artifact"
    if _HOME_PATH_RE.match(path):
        return "unscoped"
    return "project_attributed"


def _in_reporter_block(ctx: ExtractContext, claim: ClaimBase) -> bool:
    return all(ctx.block_role_at((s.start, s.end)) in ("poc", "log") for s in claim.spans)


def _product_in_sentence(ctx: ExtractContext, claim: ClaimBase) -> bool:
    body = ctx.report.body
    for span in claim.spans:
        start, end = sentence_bounds(body, span.start, span.end)
        if ctx.attribution_re.search(body, start, end):
            return True
    return False


def _trace_functions(claims: list[ClaimBase]) -> set[str]:
    names: set[str] = set()
    for c in claims:
        if isinstance(c, TraceClaim):
            names |= {f.function for f in c.frames if f.function and not f.is_runtime}
    return names


def _symbol(ctx: ExtractContext, c: SymbolClaim, trace_funcs: set[str]) -> Provenance:
    if c.external:
        return "third_party"
    if _in_reporter_block(ctx, c):
        return "reporter_artifact"
    if c.context_path and classify_path(c.context_path) == "project_attributed":
        return "project_attributed"
    if c.name in trace_funcs or _product_in_sentence(ctx, c):
        return "project_attributed"
    return "unscoped"


def scope_claim(  # noqa: PLR0911 (one return per claim kind reads best)
    ctx: ExtractContext, claim: ClaimBase, all_claims: list[ClaimBase]
) -> Provenance:
    """Decide the provenance of one claim (pure function of the report and claims)."""
    if claim.provenance != "unscoped":
        return claim.provenance
    match claim:
        case PocClaim():
            return "reporter_artifact"
        case TraceClaim() | PatchClaim():
            return "project_attributed"
        case SnippetClaim():
            attributed = claim.attributed_path or claim.attributed_function
            return "project_attributed" if attributed else "unscoped"
        case SymbolClaim():
            return _symbol(ctx, claim, _trace_functions(all_claims))
        case LineClaim() if claim.permalink is not None:
            return "project_attributed"
        case FileClaim() | LineClaim():
            return (
                "reporter_artifact" if _in_reporter_block(ctx, claim) else classify_path(claim.path)
            )
        case VersionClaim():
            if claim.product and ctx.product_hint and claim.product != ctx.product_hint:
                known = {p.name for p in ctx.products}
                return "third_party" if claim.product in known else "unscoped"
            return "project_attributed"
        case ReferenceClaim() if claim.ref_kind == "commit":
            return "project_attributed"
        case _:
            return "unscoped" if isinstance(claim, ReferenceClaim) else "project_attributed"


def region_of(claim: ClaimBase) -> Region:
    return (min(s.start for s in claim.spans), max(s.end for s in claim.spans))
