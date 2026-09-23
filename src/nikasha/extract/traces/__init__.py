# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Trace parsers, one module per format, all sharing :mod:`.common` (SPEC §9.5).

Importing this package registers every parser in :data:`common.PARSERS`.
"""

from __future__ import annotations

# Parser modules register themselves on import; import each format module here. LSan, MSan
# and TSan have no parser yet: no real fixtures were captured for them (SPEC §9.5 requires 3).
from nikasha.extract.traces import (  # noqa: F401
    asan,
    gdb,
    go_panic,
    java,
    node,
    python_tb,
    rust_panic,
    ubsan,
    valgrind,
)
from nikasha.extract.traces.common import PARSERS, ParsedTrace, TraceParser

__all__ = ["PARSERS", "ParsedTrace", "TraceParser", "parse_traces"]


def parse_traces(text: str) -> list[ParsedTrace]:
    """Run every registered parser over ``text`` and return all traces, sorted by position.

    When two parsers claim overlapping regions, the one covering more text wins (a full
    ASan report beats a stray gdb-looking line inside it).
    """
    found: list[ParsedTrace] = []
    for fmt in sorted(PARSERS):
        found.extend(PARSERS[fmt].parse(text))
    found.sort(key=lambda t: (-(t.end - t.start), t.start, t.data.format))
    kept: list[ParsedTrace] = []
    for trace in found:
        if all(trace.end <= k.start or trace.start >= k.end for k in kept):
            kept.append(trace)
    kept.sort(key=lambda t: (t.start, t.end, t.data.format))
    return kept
