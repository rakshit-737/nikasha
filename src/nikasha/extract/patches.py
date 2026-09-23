# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Patch claims (SPEC §9.6).

Unified diffs are taken from ``patch`` code blocks and, for plain-text reports, from diff
regions found directly in the body. ``unidiff`` parses well-formed diffs; a tolerant
fallback keeps malformed ones (wrong hunk counts, context lines whose leading space was
eaten by a Markdown editor), because a fabricated patch is exactly what C12 must be able to
refute.
"""

from __future__ import annotations

import re
from typing import Literal

from unidiff.errors import UnidiffParseError
from unidiff.patch import PatchSet

from nikasha.extract.registry import ExtractContext, make_claim, register
from nikasha.extract.spans import Region
from nikasha.model.claims import PatchClaim, PatchHunk, PatchLine

NAME = "patches"

_HUNK_RE = re.compile(
    r"^@@ -(?P<ss>\d{1,9})(?:,(?P<sl>\d{1,9}))? \+(?P<ts>\d{1,9})(?:,(?P<tl>\d{1,9}))? @@"
    r" ?(?P<sec>.*)$"
)
_OPS: dict[str, Literal[" ", "+", "-"]] = {" ": " ", "+": "+", "-": "-"}
_OLD_RE = re.compile(r"^--- (?P<p>\S{1,1000})")
_NEW_RE = re.compile(r"^\+\+\+ (?P<p>\S{1,1000})")
_DIFF_START_RE = re.compile(r"^(?:diff --git |--- \S)", re.MULTILINE)
_DIFF_LINE_PREFIXES = (" ", "+", "-", "@@", "diff ", "index ", "\\", "new file", "deleted file",
                       "similarity", "rename ", "old mode", "new mode", "Binary files")  # fmt: skip


def _strip_prefix(path: str) -> str:
    if path in ("/dev/null",):
        return path
    return path[2:] if path.startswith(("a/", "b/")) else path


def _fix_blank_context(text: str) -> str:
    """Inside hunks, an empty line almost always was a context line (``" "``) whose
    trailing space an editor removed; restore it so strict parsers accept the diff."""
    out: list[str] = []
    in_hunk = False
    for line in text.split("\n"):
        if line.startswith("@@"):
            in_hunk = True
        elif line.startswith(("diff ", "--- ", "+++ ")):
            in_hunk = False
        out.append(" " if in_hunk and line == "" else line)
    return "\n".join(out)


def parse_with_unidiff(text: str) -> tuple[list[str], list[PatchHunk]] | None:
    try:
        patch = PatchSet(_fix_blank_context(text).strip("\n") + "\n")
    except UnidiffParseError:
        return None
    files: list[str] = []
    hunks: list[PatchHunk] = []
    for patched in patch:
        path = _strip_prefix(patched.path)
        files.append(path)
        for hunk in patched:
            lines = tuple(
                PatchLine(op=_OPS[line.line_type], text=line.value.rstrip("\n"))
                for line in hunk
                if line.line_type in (" ", "+", "-")
            )
            hunks.append(
                PatchHunk(
                    path=path,
                    source_start=hunk.source_start,
                    source_length=hunk.source_length,
                    target_start=hunk.target_start,
                    target_length=hunk.target_length,
                    section_header=hunk.section_header.strip() or None,
                    lines=lines,
                )
            )
    return (files, hunks) if hunks else None


def parse_leniently(text: str) -> tuple[list[str], list[PatchHunk]] | None:
    """Parse hunks without validating line counts."""
    files: list[str] = []
    hunks: list[PatchHunk] = []
    old_path: str | None = None
    path: str | None = None
    header: re.Match[str] | None = None
    lines: list[PatchLine] = []

    def flush() -> None:
        if header is not None and path is not None:
            hunks.append(
                PatchHunk(
                    path=path,
                    source_start=int(header.group("ss")),
                    source_length=int(header.group("sl") or 1),
                    target_start=int(header.group("ts")),
                    target_length=int(header.group("tl") or 1),
                    section_header=header.group("sec").strip() or None,
                    lines=tuple(lines),
                )
            )

    for raw in text.rstrip("\n").split("\n"):
        if (m := _OLD_RE.match(raw)) and not raw.startswith("--- -"):
            flush()
            header, lines = None, []
            old_path = _strip_prefix(m.group("p"))
            continue
        if m := _NEW_RE.match(raw):
            new_path = _strip_prefix(m.group("p"))
            path = old_path if new_path == "/dev/null" and old_path else new_path
            files.append(path)
            continue
        if m := _HUNK_RE.match(raw):
            flush()
            header, lines = m, []
            continue
        if header is None:
            continue
        if raw == "":
            lines.append(PatchLine(op=" ", text=""))
        elif raw[0] in " +-":
            lines.append(PatchLine(op=_OPS[raw[0]], text=raw[1:]))
    flush()
    return (files, hunks) if hunks else None


def diff_regions_in_prose(ctx: ExtractContext) -> list[Region]:
    """Contiguous diff-looking regions in prose (plain-text reports have no fences)."""
    body = ctx.report.body
    regions: list[Region] = []
    for start, end in ctx.prose:
        pos = start
        while (m := _DIFF_START_RE.search(body, pos, end)) is not None:
            cursor = m.start()
            last_good = cursor
            seen_hunk = False
            while cursor < end:
                nl = body.find("\n", cursor, end)
                line_end = nl if nl >= 0 else end
                line = body[cursor:line_end]
                if line.startswith("@@"):
                    seen_hunk = True
                if not (line.startswith(_DIFF_LINE_PREFIXES) or line.startswith("+++ ")):
                    break
                last_good = line_end
                cursor = line_end + 1
            if seen_hunk and last_good > m.start():
                regions.append((m.start(), last_good))
            pos = max(last_good, m.end()) + 1
            if pos >= end:
                break
    return regions


@register(NAME)
def extract_patches(ctx: ExtractContext) -> list[PatchClaim]:
    report = ctx.report
    regions: list[Region] = [
        (b.span.start, b.span.end) for b in report.code_blocks if b.role_guess == "patch"
    ]
    regions += diff_regions_in_prose(ctx)
    claims: list[PatchClaim] = []
    for start, end in sorted(set(regions)):
        text = report.body[start:end]
        parsed = parse_with_unidiff(text)
        confidence = 0.95
        if parsed is None:
            parsed = parse_leniently(text)
            confidence = 0.7
        if parsed is None:
            continue
        files, hunks = parsed
        claims.append(
            make_claim(
                PatchClaim,
                spans=[report.span(start, end)],
                extractor=NAME,
                confidence=confidence,
                diff=text,
                files=tuple(dict.fromkeys(files)),
                hunks=tuple(hunks),
            )
        )
    return claims
