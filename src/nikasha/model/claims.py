# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Claims: the checkable statements a report makes (SPEC §7, §9; ADR 0003).

Every claim carries the exact spans it came from, the extractor that produced it, a
``role`` (how central it is to the report) and a ``provenance`` (whether it is a claim
about the *project* at all). Checks may only refute ``project_attributed``, non-negated
claims: slopcheck's measurements showed that the reporter's own PoC code, third-party
APIs and negated statements are the main sources of false contradictions.
"""

from __future__ import annotations

from datetime import date
from typing import Annotated, Literal

from pydantic import Field

from nikasha.model.base import Model
from nikasha.model.report import Span

ClaimKind = Literal[
    "version",
    "symbol",
    "file",
    "line",
    "trace",
    "snippet",
    "patch",
    "poc",
    "reference",
    "option",
    "impact",
    "behavior",
]
ClaimRole = Literal["core", "supporting", "peripheral"]
Provenance = Literal["project_attributed", "reporter_artifact", "third_party", "unscoped"]


class ClaimBase(Model):
    """Fields shared by every claim."""

    id: str
    spans: tuple[Span, ...] = Field(min_length=1)
    extractor: str
    confidence: float = Field(ge=0.0, le=1.0)
    role: ClaimRole = "supporting"
    provenance: Provenance = "unscoped"
    negated: bool = False


# --- versions ---------------------------------------------------------------------------


class VersionSpec(Model):
    """A parsed version: numeric components, an optional qualifier, and the raw text."""

    numbers: tuple[int, ...]
    qualifier: str | None = None
    raw: str


class VersionClaim(ClaimBase):
    kind: Literal["version"] = "version"
    product: str | None = None
    raw: str
    relation: Literal["tested_on", "affected_range", "fixed_in", "latest", "unspecified"]
    parsed: VersionSpec | None = None
    lower: VersionSpec | None = None
    lower_inclusive: bool = True
    upper: VersionSpec | None = None
    upper_inclusive: bool = False
    special_ref: Literal["latest", "master", "main", "HEAD", "trunk"] | None = None
    commit: str | None = None
    as_of: date | None = None


# --- code locations ---------------------------------------------------------------------

SymbolKindHint = Literal[
    "function", "macro", "type", "field", "method", "class", "constant", "unknown"
]


class SymbolClaim(ClaimBase):
    kind: Literal["symbol"] = "symbol"
    name: str
    symbol_kind_hint: SymbolKindHint = "unknown"
    lang_hint: str | None = None
    context_path: str | None = None
    external: bool = False


class FileClaim(ClaimBase):
    kind: Literal["file"] = "file"
    path: str


class Permalink(Model):
    """A GitHub or GitLab blob URL, which pins repo, ref, path and lines."""

    host: str
    owner: str
    repo: str
    ref: str
    path: str
    start_line: int | None = None
    end_line: int | None = None
    url: str


class LineClaim(ClaimBase):
    kind: Literal["line"] = "line"
    path: str | None
    line: int = Field(ge=0)
    end_line: int | None = None
    col: int | None = None
    function_hint: str | None = None
    quoted_line: str | None = None
    permalink: Permalink | None = None


# --- traces -----------------------------------------------------------------------------

TraceFormat = Literal[
    "asan",
    "ubsan",
    "lsan",
    "msan",
    "tsan",
    "valgrind",
    "gdb",
    "python",
    "java",
    "go",
    "rust",
    "node",
]


class Frame(Model):
    """One stack frame, normalized across formats (SPEC §9.5)."""

    index: int
    function: str | None = None
    path: str | None = None
    original_path: str | None = None
    line: int | None = None
    col: int | None = None
    module: str | None = None
    is_runtime: bool = False
    raw: str


class Stack(Model):
    """A labelled stack other than the primary one (e.g. TSan's "previous write")."""

    label: str
    frames: tuple[Frame, ...]


class MemoryAccess(Model):
    kind: Literal["READ", "WRITE"]
    size: int | None = None


class MemoryRegion(Model):
    """ASan's ``0x… is located N bytes to the right of M-byte region [start,end)``."""

    start: int
    end: int
    size: int
    relation: Literal["right", "left", "inside"]
    distance: int


class TraceData(Model):
    """Everything a trace parser recovers from one trace."""

    format: TraceFormat
    bug_type: str | None = None
    message: str | None = None
    access: MemoryAccess | None = None
    address: int | None = None
    access_address: int | None = None
    region_address: int | None = None
    region: MemoryRegion | None = None
    frames: tuple[Frame, ...] = ()
    alloc_frames: tuple[Frame, ...] = ()
    free_frames: tuple[Frame, ...] = ()
    other_stacks: tuple[Stack, ...] = ()
    summary: str | None = None
    summary_path: str | None = None
    summary_line: int | None = None
    summary_function: str | None = None
    pid: int | None = None
    pids_seen: tuple[int, ...] = ()
    thread: str | None = None


class TraceClaim(ClaimBase, TraceData):
    kind: Literal["trace"] = "trace"


# --- quoted code, patches, PoCs -----------------------------------------------------------


class SnippetClaim(ClaimBase):
    kind: Literal["snippet"] = "snippet"
    code: str
    lang_hint: str | None = None
    attributed_path: str | None = None
    attributed_function: str | None = None
    n_lines: int = Field(ge=0)


class PatchLine(Model):
    op: Literal[" ", "+", "-"]
    text: str


class PatchHunk(Model):
    path: str
    source_start: int
    source_length: int
    target_start: int
    target_length: int
    section_header: str | None = None
    lines: tuple[PatchLine, ...]


class PatchClaim(ClaimBase):
    kind: Literal["patch"] = "patch"
    diff: str
    files: tuple[str, ...]
    hunks: tuple[PatchHunk, ...]


PocKind = Literal[
    "cli", "file_input", "c_harness", "python", "shell", "libfuzzer_input", "http_sidecar"
]


class PocClaim(ClaimBase):
    kind: Literal["poc"] = "poc"
    poc_kind: PocKind
    content: str | None = None
    attachment_ref: str | None = None
    entry: str | None = None


# --- references, options, impact, behavior -----------------------------------------------

ReferenceKind = Literal[
    "url", "commit", "cve", "cwe", "ghsa", "issue", "pr", "blob", "compare", "advisory"
]


class ReferenceClaim(ClaimBase):
    kind: Literal["reference"] = "reference"
    ref_kind: ReferenceKind
    value: str
    repo_url: str | None = None


class OptionClaim(ClaimBase):
    kind: Literal["option"] = "option"
    token: str
    option_kind: Literal["cli_flag", "constant", "config_key"]


class ImpactClaim(ClaimBase):
    kind: Literal["impact"] = "impact"
    cvss_vector: str | None = None
    cvss_version: str | None = None
    cvss_score: float | None = None
    severity_word: str | None = None
    cwe: str | None = None


BehaviorPredicate = Literal[
    "calls_api",
    "missing_bounds_check",
    "missing_null_check",
    "uses_freed",
    "integer_overflow",
]


class BehaviorClaim(ClaimBase):
    kind: Literal["behavior"] = "behavior"
    subject_symbol: str
    predicate: BehaviorPredicate
    object: str | None = None


Claim = Annotated[
    VersionClaim
    | SymbolClaim
    | FileClaim
    | LineClaim
    | TraceClaim
    | SnippetClaim
    | PatchClaim
    | PocClaim
    | ReferenceClaim
    | OptionClaim
    | ImpactClaim
    | BehaviorClaim,
    Field(discriminator="kind"),
]

#: Fields excluded when computing a claim's content ID (they describe *where* and *how*
#: the claim was found or judged, not *what* it asserts).
NON_IDENTITY_FIELDS = frozenset(
    {"id", "spans", "extractor", "confidence", "role", "provenance", "negated"}
)
