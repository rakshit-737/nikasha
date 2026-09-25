# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The ``nikasha extract`` view never passes control characters to the terminal (P7)."""

from __future__ import annotations

import io

from rich.console import Console

from nikasha.model.claims import SymbolClaim
from nikasha.model.report import Report, ReportSource, SourceMap, Span
from nikasha.render.extract_view import render_extract

HOSTILE = "a\x1b]0;pwn\x07b\x1b[31mred\u202e"


def test_hostile_body_title_and_warnings_emit_no_escape_sequences() -> None:
    body = f"{HOSTILE} hdr_decode()\tend"
    report = Report(
        id="r",
        source=ReportSource(kind="text", uri=None),
        title=HOSTILE,
        body=body,
        source_map=SourceMap.identity(len(body)),
    )
    start = body.index("hdr_decode")
    claim = SymbolClaim(
        id="c",
        spans=(Span(start=start, end=start + 10, text="hdr_decode"),),
        extractor="test",
        confidence=1.0,
        role="core",
        provenance="project_attributed",
        name="hdr_decode",
    )
    out = io.StringIO()
    console = Console(file=out, width=100, color_system=None, force_terminal=False)
    render_extract(console, report, (claim,), (HOSTILE,))
    text = out.getvalue()
    assert "\x1b" not in text and "\x07" not in text and "\u202e" not in text
    assert "hdr_decode" in text
