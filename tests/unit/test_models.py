# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
import json

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import TypeAdapter, ValidationError

from nikasha.model import (
    Attachment,
    Claim,
    Report,
    ReportSource,
    Result,
    SourceMap,
    SourceSegment,
    Span,
    SymbolClaim,
)
from nikasha.model.ids import ID_LENGTH, canonical_json, stable_id


def _report(body: str = "hello world") -> Report:
    return Report(
        id="r",
        source=ReportSource(kind="text"),
        body=body,
        source_map=SourceMap.identity(len(body)),
    )


def test_models_are_frozen_and_strict() -> None:
    report = _report()
    with pytest.raises(ValidationError):
        report.body = "x"  # type: ignore[misc]
    with pytest.raises(ValidationError):
        ReportSource(kind="text", unexpected=1)  # type: ignore[call-arg]


def test_span_validation() -> None:
    assert Span(start=1, end=3, text="ab").end == 3
    with pytest.raises(ValidationError):
        Span(start=3, end=1, text="")
    with pytest.raises(ValidationError):
        Span(start=0, end=3, text="ab")


def test_report_span_helper_matches_body() -> None:
    report = _report("abc def")
    span = report.span(4, 7)
    assert span.text == "def"
    assert report.body[span.start : span.end] == span.text


def test_stable_id_is_deterministic_and_order_insensitive() -> None:
    a = stable_id("claim:symbol", {"name": "x", "external": False})
    b = stable_id("claim:symbol", {"external": False, "name": "x"})
    assert a == b
    assert len(a) == ID_LENGTH
    assert stable_id("claim:file", {"name": "x"}) != a


@given(st.dictionaries(st.text(max_size=5), st.integers() | st.text(max_size=5), max_size=5))
def test_canonical_json_roundtrips(payload):
    assert json.loads(canonical_json(payload)) == payload


def test_claim_union_discriminates_by_kind() -> None:
    span = Span(start=0, end=5, text="hello").model_dump()
    claim = TypeAdapter(Claim).validate_python(
        {
            "kind": "symbol",
            "id": "a" * 12,
            "spans": [span],
            "extractor": "t",
            "confidence": 1.0,
            "name": "hello",
        }
    )
    assert isinstance(claim, SymbolClaim)
    with pytest.raises(ValidationError):
        TypeAdapter(Claim).validate_python({"kind": "nope", "id": "a", "spans": [span]})


def test_claim_requires_a_span() -> None:
    with pytest.raises(ValidationError):
        SymbolClaim(id="a", spans=(), extractor="t", confidence=1.0, name="x")


def test_result_json_is_sorted_and_timings_optional() -> None:
    result = Result(tool_version="0", report=_report(), timings={"total": 1.5})
    text = result.to_json()
    data = json.loads(text)
    assert list(data) == sorted(data)
    assert data["schema"].endswith("result-v1.json")
    assert "timings" not in json.loads(result.to_json(include_timings=False))


def test_attachment_stored_path_is_not_serialized() -> None:
    att = Attachment(
        name_sanitized="a", sha256="0" * 64, size=1, media_type="x", stored_path="run/a"
    )
    assert "stored_path" not in att.model_dump()


class TestSourceMap:
    def test_identity(self):
        sm = SourceMap.identity(10)
        assert [sm.to_original(i) for i in (0, 5, 10)] == [0, 5, 10]

    def test_gap_maps_to_next_segment(self):
        sm = SourceMap(
            segments=(
                SourceSegment(norm_start=0, orig_start=0, length=3),
                SourceSegment(norm_start=4, orig_start=10, length=2),
            ),
            original_length=12,
        )
        assert sm.to_original(1) == 1
        assert sm.to_original(3) == 10  # inserted char maps to the next verbatim run
        assert sm.to_original(5) == 11
        assert sm.to_original(6) == 12

    def test_rejects_overlap(self):
        with pytest.raises(ValidationError):
            SourceMap(
                segments=(
                    SourceSegment(norm_start=0, orig_start=0, length=3),
                    SourceSegment(norm_start=2, orig_start=5, length=1),
                ),
                original_length=10,
            )

    def test_rejects_segment_past_original(self):
        with pytest.raises(ValidationError):
            SourceMap(
                segments=(SourceSegment(norm_start=0, orig_start=5, length=10),), original_length=8
            )

    def test_empty(self):
        assert SourceMap(segments=(), original_length=0).to_original(3) == 0
