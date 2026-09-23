# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""C05 LINE_IN_FUNCTION, against the real vulnlab tree (SPEC §12).

The spans these tests assert against are the ones the parser really produces for
``examples/vulnlab``. At ``v1.2.0`` ``src/util.c`` holds ``util_copy_value`` on lines
8-18, ``is_ws`` on 20-23 and ``util_strip`` on 25-36; ``util_copy_value`` moved to 26-39
in v1.1.0, 21-32 in v1.2.1 and 21-35 in v1.3.0, which is what makes the version-fit case
real rather than contrived.
"""

from __future__ import annotations

import dataclasses
from typing import Any

import pytest

from conftest import MakeContext, claim
from nikasha.checks.base import CheckContext, run_checks
from nikasha.checks.c05_line_in_function import LineInFunction
from nikasha.code.facts import FileFacts
from nikasha.model.claims import Claim, Frame, LineClaim, TraceClaim
from nikasha.model.evidence import Evidence


def _run(make_ctx: MakeContext, claims: list[Claim], tag: str = "v1.2.0") -> list[Evidence]:
    ctx = make_ctx(claims=claims, tag=tag)
    return LineInFunction().run(ctx, claims)


def _line(**fields: Any) -> LineClaim:
    fields.setdefault("path", "src/util.c")
    return claim(LineClaim, **fields)


def _trace(frames: list[Frame], **fields: Any) -> TraceClaim:
    return claim(TraceClaim, format="asan", frames=tuple(frames), **fields)


def _frame(index: int, function: str, line: int | None, **fields: Any) -> Frame:
    fields.setdefault("path", "src/util.c")
    return Frame(index=index, function=function, line=line, raw=f"#{index} {function}", **fields)


def test_line_inside_the_named_function_supports(make_ctx: MakeContext) -> None:
    c = _line(line=15, function_hint="util_copy_value")
    (evidence,) = _run(make_ctx, [c])
    assert evidence.outcome == "SUPPORTS"
    assert evidence.strength == 1.0
    assert evidence.check_id == "C05"
    assert evidence.group == "lines"
    assert evidence.claim_ids == (c.id,)
    assert evidence.details["function_span"] == [8, 18]
    assert "util_copy_value()" in evidence.summary


def test_a_function_name_written_with_parentheses_still_matches(make_ctx: MakeContext) -> None:
    (evidence,) = _run(make_ctx, [_line(line=15, function_hint="util_copy_value()")])
    assert evidence.outcome == "SUPPORTS"
    assert evidence.details["function_span"] == [8, 18]


def test_line_outside_the_function_refutes_and_names_what_is_there(
    make_ctx: MakeContext,
) -> None:
    # Line 20 is is_ws() at v1.2.0, and is outside util_copy_value() in every neighbour.
    (evidence,) = _run(make_ctx, [_line(line=20, function_hint="util_copy_value")])
    assert evidence.outcome == "REFUTES"
    assert evidence.strength == -0.8
    assert evidence.details["actual_function"] == "is_ws"
    assert evidence.details["actual_span"] == [20, 23]
    assert evidence.details["function_span"] == [8, 18]
    assert "is_ws()" in evidence.summary
    assert "version_fit_hint" not in evidence.details
    assert evidence.details["nearby_search_complete"] is True


def test_a_line_between_functions_refutes_without_naming_one(make_ctx: MakeContext) -> None:
    # Line 19 is the blank line between util_copy_value() and is_ws().
    (evidence,) = _run(make_ctx, [_line(line=19, function_hint="util_copy_value")])
    assert evidence.outcome == "REFUTES"
    assert evidence.details["actual_function"] is None
    assert "not inside any function" in evidence.summary


def test_a_fit_in_a_nearby_release_softens_and_hints_the_version(make_ctx: MakeContext) -> None:
    # Line 33 is util_strip() at v1.2.0, but util_copy_value() at v1.1.0 (26-39).
    (evidence,) = _run(make_ctx, [_line(line=33, function_hint="util_copy_value")])
    assert evidence.outcome == "REFUTES"
    assert evidence.strength == -0.3
    hint = evidence.details["version_fit_hint"]
    assert hint["release"] == "v1.1.0"
    assert hint["releases"] == ["v1.1.0", "v1.3.0"]
    assert hint["function_span"] == [26, 39]
    assert hint["line"] == 33
    assert "v1.1.0" in evidence.summary


def test_the_nearest_fitting_release_is_the_one_hinted(make_ctx: MakeContext) -> None:
    # At v1.1.0 line 24 is util_strip(); util_copy_value() covers it in v1.2.1 (21-32)
    # and v1.3.0 (21-35), and the nearer neighbour is the one C10 is pointed at.
    (evidence,) = _run(make_ctx, [_line(line=24, function_hint="util_copy_value")], tag="v1.1.0")
    assert evidence.outcome == "REFUTES"
    assert evidence.strength == -0.3
    assert evidence.details["version_fit_hint"]["release"] == "v1.2.1"


def test_evidence_locates_both_the_cited_line_and_the_real_span(make_ctx: MakeContext) -> None:
    ctx = make_ctx(claims=[_line(line=20, function_hint="util_copy_value")])
    (evidence,) = LineInFunction().run(ctx, list(ctx.claims))
    cited, span = evidence.locations
    assert cited.commit == ctx.commit and cited.start_line == 20
    assert cited.permalink is not None
    assert cited.permalink.endswith("/blob/" + ctx.commit + "/src/util.c#L20")
    assert (span.start_line, span.end_line) == (8, 18)


def test_a_partial_path_still_resolves(make_ctx: MakeContext) -> None:
    (evidence,) = _run(make_ctx, [_line(path="util.c", line=15, function_hint="util_copy_value")])
    assert evidence.outcome == "SUPPORTS"
    assert evidence.details["path"] == "src/util.c"


def test_claims_without_a_function_path_or_line_are_skipped(make_ctx: MakeContext) -> None:
    assert _run(make_ctx, [_line(line=15)]) == []
    assert _run(make_ctx, [_line(path=None, line=15, function_hint="util_copy_value")]) == []
    assert _run(make_ctx, [_line(line=0, function_hint="util_copy_value")]) == []


def test_an_unknown_path_is_left_to_c02(make_ctx: MakeContext) -> None:
    assert _run(make_ctx, [_line(path="src/nope.c", line=3, function_hint="f")]) == []


class TestConservatism:
    """P4: never turn uncertainty into a refutation."""

    def test_a_missing_function_is_neutral_and_left_to_c03(self, make_ctx: MakeContext) -> None:
        (evidence,) = _run(make_ctx, [_line(line=15, function_hint="hdr_find")])
        assert evidence.outcome == "NEUTRAL"
        assert evidence.strength == 0.0
        assert evidence.details["function_defined"] is False
        assert "not defined in src/util.c" in evidence.summary

    def test_a_file_that_did_not_parse_cleanly_is_neutral(
        self, make_ctx: MakeContext, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ctx = make_ctx(claims=[_line(line=20, function_hint="util_copy_value")])
        _mark_unparsed(monkeypatch, ctx)
        (evidence,) = LineInFunction().run(ctx, list(ctx.claims))
        assert evidence.outcome == "NEUTRAL"
        assert evidence.details["parsed_ok"] is False
        assert "did not parse cleanly" in evidence.summary

    def test_a_line_that_is_inside_still_supports_when_parsing_was_partial(
        self, make_ctx: MakeContext, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # An incomplete parse only makes *absence* uncertain; what it did find is real.
        ctx = make_ctx(claims=[_line(line=15, function_hint="util_copy_value")])
        _mark_unparsed(monkeypatch, ctx)
        (evidence,) = LineInFunction().run(ctx, list(ctx.claims))
        assert evidence.outcome == "SUPPORTS"

    def test_a_generated_file_is_never_judged(self, make_ctx: MakeContext) -> None:
        c = _line(path="src/config.h", line=5, function_hint="anything")
        (evidence,) = _run(make_ctx, [c])
        assert evidence.outcome == "NEUTRAL"
        assert evidence.strength == 0.0
        assert "config.h" in evidence.details["generated"]
        assert "not judged" in evidence.summary


def _mark_unparsed(monkeypatch: pytest.MonkeyPatch, ctx: CheckContext) -> None:
    """Keep the real tree and the real parse, but flip ``parsed_ok`` on what comes back."""
    original = ctx.index.facts

    def patched(blob: str, path: str) -> FileFacts | None:
        facts = original(blob, path)
        return None if facts is None else dataclasses.replace(facts, parsed_ok=False)

    monkeypatch.setattr(ctx.index, "facts", patched)


class TestTraceFrames:
    """Each application frame pairs a function with a line, so each one is a site."""

    def test_every_app_frame_is_judged(self, make_ctx: MakeContext) -> None:
        c = _trace(
            [
                _frame(0, "util_copy_value", 15),
                _frame(1, "hdr_parse_line", 100, path="src/hdr.c"),
                _frame(2, "hdr_get", 100, path="src/hdr.c"),
            ]
        )
        evidence = _run(make_ctx, [c])
        assert [e.outcome for e in evidence] == ["SUPPORTS", "SUPPORTS", "REFUTES"]
        assert [e.details["frame"] for e in evidence] == [0, 1, 2]
        assert evidence[2].details["actual_function"] == "hdr_parse_line"
        assert evidence[2].summary.startswith("frame #2: src/hdr.c:100 is inside hdr_parse_line()")
        assert all(e.claim_ids == (c.id,) for e in evidence)

    def test_runtime_and_incomplete_frames_are_skipped(self, make_ctx: MakeContext) -> None:
        c = _trace(
            [
                _frame(0, "__asan_memcpy", 1, path=None, is_runtime=True),
                _frame(1, "util_copy_value", None),
                Frame(index=2, path="src/util.c", line=15, raw="#2 <unknown>"),
                _frame(3, "util_copy_value", 15),
            ]
        )
        evidence = _run(make_ctx, [c])
        assert [e.details["frame"] for e in evidence] == [3]

    def test_a_repeated_frame_is_judged_once(self, make_ctx: MakeContext) -> None:
        c = _trace([_frame(0, "util_copy_value", 15), _frame(1, "util_copy_value", 15)])
        (evidence,) = _run(make_ctx, [c])
        assert evidence.details["frame"] == 0


class TestRefutationGate:
    """ADR 0003: only project-attributed, non-negated claims may be refuted."""

    def test_reporter_artifact_is_not_refuted(self, make_ctx: MakeContext) -> None:
        c = _line(line=20, function_hint="util_copy_value", provenance="reporter_artifact")
        (evidence,) = _run(make_ctx, [c])
        assert evidence.outcome == "NEUTRAL"
        assert evidence.strength == 0.0
        assert evidence.details["gated"] == ["reporter_artifact"]
        assert evidence.details["withheld_strength"] == -0.8

    def test_negated_claim_is_not_refuted(self, make_ctx: MakeContext) -> None:
        c = _line(line=20, function_hint="util_copy_value", negated=True)
        (evidence,) = _run(make_ctx, [c])
        assert evidence.outcome == "NEUTRAL"
        assert evidence.details["gated"] == ["negated"]

    def test_support_is_not_gated(self, make_ctx: MakeContext) -> None:
        c = _line(line=15, function_hint="util_copy_value", provenance="third_party")
        (evidence,) = _run(make_ctx, [c])
        assert evidence.outcome == "SUPPORTS"


def test_identical_input_gives_identical_evidence(make_ctx: MakeContext) -> None:
    claims: list[Claim] = [
        _line(line=33, function_hint="util_copy_value"),
        _trace([_frame(0, "util_copy_value", 15), _frame(1, "hdr_get", 100, path="src/hdr.c")]),
    ]
    first = _run(make_ctx, claims)
    second = _run(make_ctx, claims)
    assert [e.id for e in first] == [e.id for e in second]
    assert [e.model_dump() for e in first] == [e.model_dump() for e in second]


def test_registered_and_runnable_through_the_runner(make_ctx: MakeContext) -> None:
    ctx = make_ctx(claims=[_line(line=20, function_hint="util_copy_value")])
    (run,) = run_checks(ctx, checks=[LineInFunction()])
    assert run.check_id == "C05"
    assert run.error is None
    assert run.seconds >= 0.0
    assert [e.outcome for e in run.evidence] == ["REFUTES"]
