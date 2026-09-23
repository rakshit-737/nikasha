# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""HTML intake (SPEC §8): text extraction with the stdlib parser only. Nothing is rendered
or executed; ``<script>``/``<style>`` content is dropped; ``<pre>`` content is kept verbatim
as a code block; inline ``<code>`` is wrapped in backticks (the same hint Markdown gives)."""

from __future__ import annotations

import html
from html.parser import HTMLParser

from nikasha.ingest.blocks import guess_role
from nikasha.ingest.text import (
    MAX_BODY_CHARS,
    TextBuilder,
    first_line_title,
    normalize_text,
    report_id,
    truncate,
)
from nikasha.model.report import CodeBlock, Report, ReportSource, Span

_BLOCK_TAGS = frozenset(
    {
        "address", "article", "aside", "blockquote", "br", "dd", "div", "dl", "dt",
        "figcaption", "figure", "footer", "form", "h1", "h2", "h3", "h4", "h5", "h6",
        "header", "hr", "li", "main", "nav", "ol", "p", "pre", "section", "table", "tbody",
        "td", "tfoot", "th", "thead", "tr", "ul",
    }
)  # fmt: skip
_HEADINGS = frozenset({"h1", "h2", "h3", "h4", "h5", "h6"})
_SKIPPED = frozenset({"script", "style", "template", "noscript", "head"})


def _lang_from_class(value: str | None) -> str | None:
    for cls in (value or "").split():
        for prefix in ("language-", "lang-"):
            if cls.startswith(prefix) and len(cls) > len(prefix):
                return cls[len(prefix) :]
    return None


class _Extractor(HTMLParser):
    def __init__(self, original: str) -> None:
        super().__init__(convert_charrefs=False)
        self.original = original
        self.builder = TextBuilder(len(original))
        self.line_starts = [0] + [i + 1 for i, ch in enumerate(original) if ch == "\n"]
        self.skip_depth = 0
        self.pre_depth = 0
        self.pre_start = 0
        self.pre_lang: str | None = None
        self.in_title = False
        self.title_parts: list[str] = []
        self.heading_tag: str | None = None
        self.heading_parts: list[str] = []
        self.last_heading: str | None = None
        self.first_heading: str | None = None
        self.blocks: list[tuple[int, int, str | None, str | None]] = []

    # -- helpers ----------------------------------------------------------------------
    def _offset(self) -> int:
        line, col = self.getpos()
        return self.line_starts[line - 1] + col

    def _newline(self) -> None:
        text = self.builder.text()
        if text and not text.endswith("\n"):
            self.builder.add_inserted("\n")

    def _emit_inserted(self, text: str) -> None:
        if self.skip_depth:
            return
        self.builder.add_inserted(text)
        if self.heading_tag:
            self.heading_parts.append(text)

    # -- parser callbacks -------------------------------------------------------------
    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = dict(attrs)
        if tag in _SKIPPED:
            self.skip_depth += 1
            return
        if tag == "title":
            self.in_title = True
            return
        if self.skip_depth:
            return
        if tag in _BLOCK_TAGS and not self.pre_depth:
            self._newline()
        if tag in _HEADINGS:
            self.heading_tag, self.heading_parts = tag, []
        if tag == "pre":
            if self.pre_depth == 0:
                self.pre_start = self.builder.length
                self.pre_lang = _lang_from_class(attr.get("class"))
            self.pre_depth += 1
        elif tag == "code":
            if self.pre_depth:
                self.pre_lang = self.pre_lang or _lang_from_class(attr.get("class"))
            else:
                self._emit_inserted("`")

    def handle_endtag(self, tag: str) -> None:
        if tag in _SKIPPED:
            self.skip_depth = max(0, self.skip_depth - 1)
            return
        if tag == "title":
            self.in_title = False
            return
        if self.skip_depth:
            return
        if tag == "pre" and self.pre_depth:
            self.pre_depth -= 1
            if self.pre_depth == 0:
                self.blocks.append(
                    (self.pre_start, self.builder.length, self.pre_lang, self.last_heading)
                )
                self._newline()
            return
        if tag == "code" and not self.pre_depth:
            self._emit_inserted("`")
        if tag in _HEADINGS and self.heading_tag == tag:
            heading = " ".join("".join(self.heading_parts).split())
            self.last_heading = heading or self.last_heading
            if self.first_heading is None and heading:
                self.first_heading = heading
            self.heading_tag = None
        if tag in _BLOCK_TAGS and not self.pre_depth:
            self._newline()

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in ("br", "hr") and not self.skip_depth:
            if self.pre_depth:
                self.builder.add_inserted("\n")
            else:
                self._newline()

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.title_parts.append(data)
            return
        if self.skip_depth:
            return
        normalize_text(data, offset=self._offset(), builder=self.builder)
        if self.heading_tag:
            self.heading_parts.append(data)

    def handle_entityref(self, name: str) -> None:
        self._entity(f"&{name};")

    def handle_charref(self, name: str) -> None:
        self._entity(f"&#{name};")

    def _entity(self, raw: str) -> None:
        text = html.unescape(raw)
        if self.in_title:
            self.title_parts.append(text)
        else:
            self._emit_inserted(text)


def ingest_html(
    original: str, *, uri: str | None = None, max_chars: int = MAX_BODY_CHARS
) -> Report:
    parser = _Extractor(original)
    parser.feed(original)
    parser.close()
    body, source_map, warnings = truncate(
        parser.builder.text(), parser.builder.source_map(), max_chars
    )
    blocks: list[CodeBlock] = []
    for raw_start, raw_end, lang, heading in parser.blocks:
        # Trim one leading/trailing newline, which HTML treats as formatting inside <pre>.
        start, end = raw_start, raw_end
        if start < end and body[start : start + 1] == "\n":
            start += 1
        if end > start and body[end - 1 : end] == "\n":
            end -= 1
        if end > len(body) or start >= end:
            continue
        content = body[start:end]
        blocks.append(
            CodeBlock(
                span=Span(start=start, end=end, text=content),
                lang_hint=lang,
                content=content,
                role_guess=guess_role(content, lang, heading),
            )
        )
    title = " ".join("".join(parser.title_parts).split()) or parser.first_heading
    return Report(
        id=report_id("html", body),
        source=ReportSource(kind="html", uri=uri),
        title=title or first_line_title(body),
        body=body,
        source_map=source_map,
        code_blocks=tuple(blocks),
        warnings=tuple(warnings),
    )
