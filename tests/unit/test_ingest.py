# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from nikasha.errors import NikashaError
from nikasha.ingest import UnsupportedInputError, decode, detect_format, ingest_string, load_report
from nikasha.ingest.blocks import guess_role
from nikasha.ingest.html import ingest_html
from nikasha.ingest.markdown import ingest_markdown
from nikasha.ingest.text import ingest_text, normalize_text


def _assert_map_is_exact(original: str, report: Any) -> None:
    """Every verbatim segment maps body text back to identical original text."""
    for seg in report.source_map.segments:
        body_part = report.body[seg.norm_start : seg.norm_start + seg.length]
        assert original[seg.orig_start : seg.orig_start + seg.length] == body_part


class TestText:
    def test_crlf_and_controls_are_normalized(self) -> None:
        original = "a\r\nb\rc\x00d\x1b[31me\ufefff"
        report = ingest_text(original)
        assert report.body == "a\nb\ncd[31mef"
        _assert_map_is_exact(original, report)

    def test_offsets_map_back(self) -> None:
        original = "x\r\nfoo"
        report = ingest_text(original)
        i = report.body.index("foo")
        assert original[report.source_map.to_original(i) :].startswith("foo")

    def test_truncation_warns(self) -> None:
        report = ingest_text("abcdef" * 10, max_chars=10)
        assert len(report.body) == 10
        assert report.warnings
        assert "truncated" in report.warnings[0]

    def test_title_from_first_line(self) -> None:
        assert ingest_text("\n\n  Heap overflow in foo  \nbody").title == "Heap overflow in foo"
        assert ingest_text("x" * 300).title is None

    def test_report_id_depends_only_on_content(self) -> None:
        assert ingest_text("same", uri="a").id == ingest_text("same", uri="b").id
        assert ingest_text("same").id != ingest_text("other").id

    @given(st.text(max_size=300))
    @settings(max_examples=200)
    def test_normalizer_map_is_exact(self, original: str) -> None:
        builder = normalize_text(original)
        report_like = type("R", (), {"body": builder.text(), "source_map": builder.source_map()})
        _assert_map_is_exact(original, report_like)
        assert "\r" not in builder.text()


class TestMarkdown:
    SAMPLE = (
        "# Heap overflow in `foo()`\n\nSome text.\n\n    indented code\n\n```c\nint x;\n```\n\n"
        "- item\n\n  ```diff\n  --- a/x.c\n  +++ b/x.c\n  @@ -1 +1 @@\n  -a\n  +b\n  ```\n"
    )

    def test_blocks_and_spans(self) -> None:
        report = ingest_markdown(self.SAMPLE)
        assert report.title == "Heap overflow in `foo()`"
        roles = [(b.lang_hint, b.role_guess) for b in report.code_blocks]
        assert roles == [(None, "snippet"), ("c", "snippet"), ("diff", "patch")]
        for block in report.code_blocks:
            assert report.body[block.span.start : block.span.end] == block.span.text
        assert report.code_blocks[0].span.text == "    indented code"
        assert report.code_blocks[1].span.text == "int x;"
        # Inside a list item the raw span keeps its indentation; content does not.
        assert report.code_blocks[2].content.startswith("--- a/x.c")
        assert report.code_blocks[2].span.text.startswith("  --- a/x.c")

    def test_unclosed_fence_runs_to_end(self) -> None:
        report = ingest_markdown("text\n\n```\nunclosed\nstill")
        assert report.code_blocks[0].span.text == "unclosed\nstill"

    def test_empty_fence_is_skipped(self) -> None:
        assert ingest_markdown("```\n```\n").code_blocks == ()


class TestHtml:
    def test_text_pre_code_and_scripts(self) -> None:
        html = (
            "<html><head><title>T &amp; X</title><style>p{}</style></head><body>"
            "<h1>Bug in <code>foo()</code></h1><p>Line&nbsp;one<br>two</p>"
            "<script>alert(1)</script>"
            "<pre class='language-c'>int a = 1 &lt; 2;\nreturn a;</pre></body></html>"
        )
        report = ingest_html(html)
        assert report.title == "T & X"
        assert "alert" not in report.body
        assert "p{}" not in report.body
        assert "`foo()`" in report.body
        assert "one\ntwo" in report.body
        (block,) = report.code_blocks
        assert block.lang_hint == "c"
        assert block.span.text == "int a = 1 < 2;\nreturn a;"
        _assert_map_is_exact(html, report)

    def test_heading_title_fallback(self) -> None:
        assert ingest_html("<h1>Crash in bar</h1><p>x</p>").title == "Crash in bar"

    @given(st.text(alphabet="<>/ab&;#x \n=\"'pre", max_size=200))
    @settings(max_examples=200)
    def test_never_crashes(self, html: str) -> None:
        report = ingest_html(html)
        _assert_map_is_exact(html, report)


class TestRoles:
    @pytest.mark.parametrize(
        ("content", "lang", "heading", "role"),
        [
            ("--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b", None, None, "patch"),
            ("anything", "diff", None, "patch"),
            ("$ ./hdrcat poc.txt", None, None, "poc"),
            ("anything", "console", None, "poc"),
            ("==123==ERROR: AddressSanitizer: heap-buffer-overflow", None, None, "trace"),
            ("Traceback (most recent call last):\n  File", None, None, "trace"),
            ("x.c:3:5: runtime error: signed integer overflow", None, None, "trace"),
            ("#!/bin/sh\necho hi", None, None, "poc"),
            ("#include <x.h>\nint main(void) { return 0; }", "c", None, "poc"),
            ("GET /x HTTP/1.1\nHost: a", None, None, "poc"),
            ("X-Header: value", None, "Proof of concept", "poc"),
            ("some output", "log", None, "log"),
            ("static int f(void) { return 0; }", "c", None, "snippet"),
        ],
    )
    def test_guess_role(
        self, content: str, lang: str | None, heading: str | None, role: str
    ) -> None:
        assert guess_role(content, lang, heading) == role


class TestLoad:
    @pytest.mark.parametrize(
        ("text", "name", "fmt"),
        [
            ("# T", "r.md", "markdown"),
            ("x", "r.txt", "text"),
            ("<p>x</p>", "r.html", "html"),
            ("<!DOCTYPE html><p>x</p>", None, "html"),
            ("```\nx\n```", None, "markdown"),
            ("plain words", None, "text"),
        ],
    )
    def test_detect_format(self, text: str, name: str | None, fmt: str) -> None:
        assert detect_format(text, name) == fmt

    def test_eml_is_not_supported_yet(self) -> None:
        with pytest.raises(UnsupportedInputError):
            detect_format("x", "r.eml")

    def test_load_report_and_errors(self, tmp_path: Path) -> None:
        path = tmp_path / "r.md"
        path.write_bytes(b"\xef\xbb\xbf# Title\r\n\r\nBody \xff")
        report = load_report(path)
        assert report.title == "Title"
        assert report.source.uri == str(path)
        assert "\ufffd" in report.body
        with pytest.raises(NikashaError):
            load_report(tmp_path / "missing.md")

    def test_decode_limit(self) -> None:
        with pytest.raises(NikashaError):
            decode(b"x" * (20 * 1024 * 1024 + 1))

    def test_explicit_format_overrides(self) -> None:
        assert ingest_string("# not a heading", input_format="text").source.kind == "text"
