# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Pipeline invariants: determinism, exact spans, merging, containment, robustness."""

import time
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from nikasha.extract import MAX_CLAIMS, extract_claims
from nikasha.extract import pipeline as pipeline_module
from nikasha.extract.registry import EXTRACTORS
from nikasha.ingest import ingest_string
from nikasha.model.result import Result

APPENDIX_B = Path(__file__).parent / "appendix_b_sample.md"


def _extract(text: str, fmt: str = "markdown"):
    report = ingest_string(text, input_format=fmt)  # type: ignore[arg-type]
    return report, extract_claims(report)


def test_every_extractor_is_registered() -> None:
    assert set(EXTRACTORS) == {
        "behavior", "impact", "options", "paths", "patches", "pocs", "references", "snippets",
        "symbols", "traces", "versions",
    }  # fmt: skip


def test_spans_match_body_exactly() -> None:
    report, extraction = _extract(APPENDIX_B.read_text(encoding="utf-8"))
    assert extraction.claims
    for claim in extraction.claims:
        for span in claim.spans:
            assert report.body[span.start : span.end] == span.text


def test_byte_identical_json_across_runs() -> None:
    text = APPENDIX_B.read_text(encoding="utf-8")
    outputs = []
    for _ in range(2):
        report, extraction = _extract(text)
        outputs.append(
            Result(tool_version="t", report=report, claims=extraction.claims).to_json(
                include_timings=False
            )
        )
    assert outputs[0] == outputs[1]


def test_ids_are_stable_and_unique() -> None:
    _, a = _extract(APPENDIX_B.read_text(encoding="utf-8"))
    _, b = _extract("Preamble line.\n\n" + APPENDIX_B.read_text(encoding="utf-8"))
    ids_a = [c.id for c in a.claims]
    assert len(ids_a) == len(set(ids_a))
    # Moving text does not change what a claim asserts, so IDs stay the same.
    assert {c.id for c in a.claims if c.kind != "snippet"} <= {c.id for c in b.claims}


def test_claims_are_sorted_by_position() -> None:
    _, extraction = _extract(APPENDIX_B.read_text(encoding="utf-8"))
    starts = [c.spans[0].start for c in extraction.claims]
    assert starts == sorted(starts)


def test_same_symbol_mentions_merge() -> None:
    _, extraction = _extract("`foo_bar()` fails. Also foo_bar(x) and the function foo_bar.")
    symbols = [c for c in extraction.claims if c.kind == "symbol"]
    assert len(symbols) == 1
    assert len(symbols[0].spans) == 3


def test_paths_inside_patch_are_dropped() -> None:
    text = "Patch:\n--- a/src/x.c\n+++ b/src/x.c\n@@ -1 +1 @@\n-old\n+new\n"
    _, extraction = _extract(text, "text")
    kinds = [c.kind for c in extraction.claims]
    assert kinds == ["patch"]


def test_failing_extractor_becomes_a_warning(monkeypatch):
    def boom(ctx):
        raise RuntimeError("kaput")

    monkeypatch.setitem(EXTRACTORS, "zz_broken", boom)
    _, extraction = _extract("`foo_bar()` overflows.")
    assert any("zz_broken" in w for w in extraction.warnings)
    assert any(c.kind == "symbol" for c in extraction.claims)


def test_claim_cap(monkeypatch):
    monkeypatch.setattr(pipeline_module, "MAX_CLAIMS", 3)
    text = " ".join(f"`func_{i}()`" for i in range(10))
    _, extraction = _extract(text)
    assert len(extraction.claims) == 3
    assert any("capped" in w for w in extraction.warnings)
    assert MAX_CLAIMS == 500


@given(st.text(max_size=2000))
@settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_pipeline_never_crashes_on_arbitrary_text(text):
    for fmt in ("markdown", "text", "html"):
        report, extraction = _extract(text, fmt)
        assert not extraction.warnings, extraction.warnings
        for claim in extraction.claims:
            for span in claim.spans:
                assert report.body[span.start : span.end] == span.text


@pytest.mark.slow
def test_one_megabyte_report_extracts_in_budget() -> None:
    """SPEC §20.1: extraction on a 1 MB report must take under 1 s on the documented machine
    (measured 0.94 s including ingest, M1). This guard uses a loose budget because CI runner
    speed varies; the real benchmark arrives with pytest-benchmark in M3."""
    chunk = APPENDIX_B.read_text(encoding="utf-8")
    text = (chunk + "\n\n") * (1_000_000 // len(chunk))
    started = time.perf_counter()
    _extract(text)
    assert time.perf_counter() - started < 10.0
