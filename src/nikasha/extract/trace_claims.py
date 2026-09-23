# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Trace claims: runs every registered trace parser (SPEC §9.5) over trace/log code blocks
and over prose (plain-text reports carry traces without fences)."""

from __future__ import annotations

from nikasha.extract.registry import ExtractContext, make_claim, register
from nikasha.extract.spans import Region
from nikasha.extract.traces import parse_traces
from nikasha.extract.traces.common import MAX_TRACE_TEXT
from nikasha.model.claims import TraceClaim

NAME = "traces"


@register(NAME)
def extract_trace_claims(ctx: ExtractContext) -> list[TraceClaim]:
    report = ctx.report
    regions: list[Region] = [
        (b.span.start, b.span.end)
        for b in report.code_blocks
        if b.role_guess in ("trace", "log", "snippet")
    ]
    regions += ctx.prose
    claims: list[TraceClaim] = []
    for start, end in sorted(regions):
        text = report.body[start : min(end, start + MAX_TRACE_TEXT)]
        for trace in parse_traces(text):
            span = report.span(start + trace.start, start + trace.end)
            claims.append(
                make_claim(
                    TraceClaim,
                    spans=[span],
                    extractor=f"{NAME}:{trace.data.format}",
                    confidence=0.95,
                    **trace.data.model_dump(),
                )
            )
    return claims
