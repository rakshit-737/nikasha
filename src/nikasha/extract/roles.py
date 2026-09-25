# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Claim roles (SPEC §9.3): ``core`` claims carry the report's central assertion and weigh
more in checks (e.g. C03 multiplies a core "never existed" by 1.5 ).

A symbol, file, line or option is core when it appears in the title or first paragraph, or in
a sentence that also names the bug ("overflow", "use after free", "crash"…). External APIs,
references and impact metadata are peripheral. Everything else is supporting.

The top application frame of a pasted trace is where the crash happened, so a symbol or file
claim naming that frame's function or file is core too (M3 carry-over). Only frames that are
plainly the project's count: runtime frames, frames without a function, and frames whose
module or path says they belong to a shared library or the system are skipped, so a libc or
dependency frame never promotes anything (P4). No claim is invented for the frame: only
claims already extracted from prose are promoted, because a synthesized symbol could be a
third-party name and C03 would weigh its absence as core.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from nikasha.extract.registry import ExtractContext
from nikasha.extract.spans import first_paragraph, sentence_bounds
from nikasha.model.claims import (
    ClaimBase,
    ClaimRole,
    FileClaim,
    Frame,
    ImpactClaim,
    LineClaim,
    OptionClaim,
    ReferenceClaim,
    SymbolClaim,
    TraceClaim,
)

_BUG_WORDS_RE = re.compile(
    r"\b(?:vulnerab\w{0,8}|overflow\w{0,3}|overrun\w{0,3}|underflow\w{0,3}|out[- ]of[- ]bounds|"
    r"use[- ]after[- ]free|double[- ]free|uaf|oob|crash\w{0,3}|segfault\w{0,3}|sigsegv|bug|flaw|"
    r"null[- ]pointer|dereferenc\w{0,5}|corrupt\w{0,5}|leak\w{0,3}|race|injection|rce|dos|"
    r"exploit\w{0,5}|uninitiali[sz]ed|memory[- ]safety|heap|stack[- ]buffer)\b",
    re.IGNORECASE,
)
_CORE_ELIGIBLE = (SymbolClaim, FileClaim, LineClaim, OptionClaim)

#: Path prefixes and module markers that say a frame is not the project's own code.
_FOREIGN_PATH_PREFIXES = ("/usr/", "/lib/", "/lib64/", "/opt/", "/System/", "C:\\Windows\\")
_FOREIGN_MODULE_MARKERS = (".so", ".dylib", ".dll")


@dataclass(frozen=True)
class TopFrames:
    """Bare function names and file basenames of every trace's top application frame."""

    functions: frozenset[str] = frozenset()
    files: frozenset[str] = frozenset()


def _bare_function(name: str) -> str:
    """``ns::Class::method(int) const`` -> ``method``; no regex, so linear by construction."""
    text = name.split("(", 1)[0].split("<", 1)[0].strip()
    for sep in ("::", "."):
        text = text.rsplit(sep, 1)[-1]
    return text.strip("*&() ")


def _basename(path: str) -> str:
    return path.replace("\\", "/").rsplit("/", 1)[-1]


def _is_foreign(frame: Frame) -> bool:
    if frame.module is not None:
        module = frame.module.lower()
        if any(marker in module for marker in _FOREIGN_MODULE_MARKERS):
            return True
    path = frame.original_path or frame.path
    return path is not None and path.startswith(_FOREIGN_PATH_PREFIXES)


def top_app_frame(trace: TraceClaim) -> Frame | None:
    """The first frame of the primary stack that is plainly the project's, if any."""
    for frame in trace.frames:
        if frame.is_runtime or not frame.function or _is_foreign(frame):
            continue
        return frame
    return None


def top_frames(claims: Sequence[ClaimBase]) -> TopFrames:
    functions: set[str] = set()
    files: set[str] = set()
    for claim in claims:
        if not isinstance(claim, TraceClaim):
            continue
        frame = top_app_frame(claim)
        if frame is None:
            continue
        bare = _bare_function(frame.function or "")
        if bare:
            functions.add(bare)
        if frame.path:
            files.add(_basename(frame.path))
    return TopFrames(frozenset(functions), frozenset(files))


def _names_top_frame(claim: ClaimBase, top: TopFrames) -> bool:
    if isinstance(claim, SymbolClaim):
        return _bare_function(claim.name) in top.functions
    if isinstance(claim, FileClaim):
        return _basename(claim.path) in top.files
    return False


def role_for(  # noqa: PLR0911
    ctx: ExtractContext, claim: ClaimBase, top: TopFrames | None = None
) -> ClaimRole:
    if isinstance(claim, (ReferenceClaim, ImpactClaim)):
        return "peripheral"
    if isinstance(claim, SymbolClaim) and claim.external:
        return "peripheral"
    if not isinstance(claim, _CORE_ELIGIBLE) or claim.negated:
        return "supporting"
    if top is not None and _names_top_frame(claim, top):
        return "core"
    body = ctx.report.body
    lead = first_paragraph(ctx.report)
    title = (ctx.report.title or "").strip()
    for span in claim.spans:
        if lead[0] <= span.start < lead[1]:
            return "core"
        if title and span.text.strip("`()") and span.text.strip("`()") in title:
            return "core"
        start, end = sentence_bounds(body, span.start, span.end)
        if _BUG_WORDS_RE.search(body, start, end):
            return "core"
    return "supporting"
