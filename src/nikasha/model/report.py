# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The ingested report: normalized text, a map back to the original, and code blocks."""

from __future__ import annotations

import bisect
from datetime import date
from typing import Literal

from pydantic import Field, model_validator

from nikasha.model.base import Model

SourceKind = Literal["text", "markdown", "html", "eml", "hackerone", "gh_advisory", "cve_json"]
CodeBlockRole = Literal["trace", "patch", "poc", "snippet", "log"]


class Span(Model):
    """A half-open character range ``[start, end)`` of :attr:`Report.body`, with its text.

    Invariant (checked by :class:`Report`): ``report.body[start:end] == text``.
    """

    start: int = Field(ge=0)
    end: int = Field(ge=0)
    text: str

    @model_validator(mode="after")
    def _check(self) -> Span:
        if self.end < self.start:
            raise ValueError(f"span end {self.end} < start {self.start}")
        if len(self.text) != self.end - self.start:
            raise ValueError("span text length does not match its offsets")
        return self


class SourceSegment(Model):
    """``length`` characters copied verbatim from ``orig_start`` in the original input to
    ``norm_start`` in the normalized body."""

    norm_start: int = Field(ge=0)
    orig_start: int = Field(ge=0)
    length: int = Field(ge=0)


class SourceMap(Model):
    """Maps offsets in the normalized body back to offsets in the original input.

    Segments are sorted and non-overlapping. Offsets that fall into text the normalizer
    inserted (e.g. a newline standing in for ``<br>``) map to the start of the next
    verbatim segment, or to the end of the input.
    """

    segments: tuple[SourceSegment, ...]
    original_length: int = Field(ge=0)

    @classmethod
    def identity(cls, length: int) -> SourceMap:
        return cls(
            segments=(SourceSegment(norm_start=0, orig_start=0, length=length),),
            original_length=length,
        )

    @model_validator(mode="after")
    def _check_sorted(self) -> SourceMap:
        previous_end = 0
        for seg in self.segments:
            if seg.norm_start < previous_end:
                raise ValueError("source map segments overlap or are unsorted")
            if seg.orig_start + seg.length > self.original_length:
                raise ValueError("source map segment exceeds the original input")
            previous_end = seg.norm_start + seg.length
        return self

    def to_original(self, offset: int) -> int:
        """Map a normalized offset to an original offset. ``O(log n)`` in the segment count."""
        if not self.segments:
            return 0
        starts = [s.norm_start for s in self.segments]
        i = bisect.bisect_right(starts, offset) - 1
        if i >= 0:
            seg = self.segments[i]
            if offset < seg.norm_start + seg.length or (
                offset == seg.norm_start + seg.length and i == len(self.segments) - 1
            ):
                return seg.orig_start + (offset - seg.norm_start)
        if i + 1 < len(self.segments):
            return self.segments[i + 1].orig_start
        last = self.segments[-1]
        return last.orig_start + last.length


class CodeBlock(Model):
    """A fenced, indented or ``<pre>`` code block.

    ``span`` covers the block's raw lines in the body (without fence lines);
    ``content`` is the block text as the parser saw it (indentation of enclosing lists or
    blockquotes removed), which usually equals ``span.text``.
    """

    span: Span
    lang_hint: str | None = None
    content: str
    role_guess: CodeBlockRole


class Attachment(Model):
    """A sanitized attachment. ``stored_path`` is run-specific and excluded from output."""

    name_sanitized: str
    sha256: str
    size: int = Field(ge=0)
    media_type: str
    stored_path: str | None = Field(default=None, exclude=True)


class DeclaredTarget(Model):
    """Target metadata supplied by the intake (not extracted from prose)."""

    product: str | None = None
    repo_url: str | None = None
    versions: tuple[str, ...] = ()


class ReportSource(Model):
    kind: SourceKind
    uri: str | None = None


class Report(Model):
    """A normalized vulnerability report. The reporter's identity is never stored."""

    id: str
    source: ReportSource
    title: str | None = None
    body: str
    source_map: SourceMap
    code_blocks: tuple[CodeBlock, ...] = ()
    attachments: tuple[Attachment, ...] = ()
    reported_at: date | None = None
    declared_target: DeclaredTarget | None = None
    warnings: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _check_spans(self) -> Report:
        for block in self.code_blocks:
            if self.body[block.span.start : block.span.end] != block.span.text:
                raise ValueError("code block span does not match the report body")
        return self

    def span(self, start: int, end: int) -> Span:
        """Build a :class:`Span` over ``body[start:end]``."""
        return Span(start=start, end=end, text=self.body[start:end])

    def block_at(self, offset: int) -> CodeBlock | None:
        """Return the code block containing ``offset``, if any."""
        for block in self.code_blocks:
            if block.span.start <= offset < block.span.end:
                return block
        return None
