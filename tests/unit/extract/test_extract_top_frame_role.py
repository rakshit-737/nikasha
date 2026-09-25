# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The top application frame of a trace makes matching prose claims core (M3 carry-over)."""

from __future__ import annotations

from helpers import claims

from nikasha.extract import extract_claims
from nikasha.extract.products import product_table
from nikasha.extract.registry import ExtractContext
from nikasha.extract.roles import TopFrames, role_for, top_app_frame
from nikasha.ingest import ingest_string
from nikasha.model.claims import Frame, TraceClaim

LEAD = "Found while fuzzing the parser.\n\n"
TRACE = """```
==1234==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000011
READ of size 1 at 0x602000000011 thread T0
    #0 0x4f1e2a in __asan_memcpy (/tmp/a.out+0x4f1e2a)
    #1 0x55a1b2 in inflate_block /src/proj/lib/inflate.c:88:5
    #2 0x55a2c3 in decode_all /src/proj/lib/decode.c:40:3
    #3 0x55a3d4 in main /src/proj/tools/cli.c:12:3
```
"""


def _roles(text: str, kind: str) -> dict[str, str]:
    found = claims(text, kind)
    key = "name" if kind == "symbol" else "path"
    return {getattr(c, key): c.role for c in found}


def test_a_symbol_named_by_the_top_app_frame_is_core() -> None:
    text = LEAD + TRACE + "\nThe helper `inflate_block` is reached from `decode_all`.\n"
    roles = _roles(text, "symbol")
    assert roles.get("inflate_block") == "core"
    # A lower frame is not promoted by this rule.
    assert roles.get("decode_all") == "supporting"


def test_without_a_trace_the_same_prose_stays_supporting() -> None:
    text = LEAD + "The helper `inflate_block` is reached from `decode_all`.\n"
    assert _roles(text, "symbol").get("inflate_block") == "supporting"


def test_a_file_named_by_the_top_app_frame_is_core() -> None:
    text = LEAD + TRACE + "\nSee lib/inflate.c and tools/cli.c for context.\n"
    roles = _roles(text, "file")
    assert roles.get("lib/inflate.c") == "core"
    assert roles.get("tools/cli.c") == "supporting"


def _frame(index: int, function: str | None, **kw: object) -> Frame:
    return Frame(index=index, function=function, raw=f"#{index}", **kw)  # type: ignore[arg-type]


def _trace(*frames: Frame) -> TraceClaim:
    return TraceClaim.model_validate(
        {
            "id": "t",
            "format": "asan",
            "frames": frames,
            "spans": [{"start": 0, "end": 1, "text": "x"}],
            "extractor": "test",
            "confidence": 1.0,
        }
    )


def test_runtime_shared_library_and_system_frames_are_skipped() -> None:
    trace_frames = (
        _frame(0, "__asan_memcpy", is_runtime=True),
        _frame(1, "png_read", module="/usr/lib/libpng16.so.16"),
        _frame(2, "memchr_helper", path="/usr/include/string.h"),
        _frame(3, None, path="lib/x.c"),
        _frame(4, "real_fn", path="lib/x.c", line=3),
    )
    trace = _trace(*trace_frames)
    top = top_app_frame(trace)
    assert top is not None and top.function == "real_fn"


def test_a_trace_of_only_foreign_frames_has_no_top_frame() -> None:
    trace = _trace(_frame(0, "png_read", module="/usr/lib/libpng16.so.16"))
    assert top_app_frame(trace) is None


def test_a_negated_claim_is_never_promoted() -> None:
    text = "Found while fuzzing.\n\nThere is no `inflate_block` function."
    report = ingest_string(text, input_format="markdown")
    (claim,) = [c for c in extract_claims(report).claims if c.kind == "symbol"]
    assert claim.negated
    ctx = ExtractContext(report=report, product_hint=None, products=product_table())
    top = TopFrames(functions=frozenset({"inflate_block"}))
    assert role_for(ctx, claim, top) == "supporting"
