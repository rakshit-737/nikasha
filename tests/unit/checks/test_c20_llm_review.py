# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""C20 LLM_REVIEW, against the real vulnlab tree with a faked provider (SPEC §12, §16.6).

At v1.2.0 ``util_copy_value`` is defined at src/util.c:8-18 and the unchecked ``memcpy`` is
line 15. The provider is a fake that answers whatever a test tells it to, so every test
exercises the real excerpt, the real guard and the real evidence contract without a model.
"""

from __future__ import annotations

from typing import Any

import pytest
from check_helpers import MakeContext, claim

from nikasha.checks.base import CheckContext, run_checks
from nikasha.checks.c20_llm_review import (
    CONTEXT_LINES,
    MAX_EXCERPT_LINES,
    LlmReview,
    _cited_locations,
    _excerpt,
    _sites,
)
from nikasha.checks.strengths import Strengths, default_strengths
from nikasha.errors import ExternalToolError
from nikasha.llm.guard import (
    BEGIN_MARKER,
    DEFAULT_TIMEOUT_S,
    END_MARKER,
    MAX_LLM_STRENGTH,
    REVIEW_SCHEMA,
    Excerpt,
)
from nikasha.llm.provider import LLMError
from nikasha.model.claims import BehaviorClaim
from nikasha.model.evidence import Evidence

MEMCPY_LINE = 15
CLAIM_TEXT = "missing bounds check in `util_copy_value`"

SUPPORTED: dict[str, Any] = {
    "verdict": "supported",
    "cited_lines": [MEMCPY_LINE],
    "rationale": "`memcpy(dst, value, len)` copies len bytes into a 64-byte buffer unchecked.",
}
REFUTED: dict[str, Any] = {
    "verdict": "refuted",
    "cited_lines": [MEMCPY_LINE],
    "rationale": "The copy is bounded.",
}
UNCLEAR: dict[str, Any] = {"verdict": "unclear", "cited_lines": [], "rationale": ""}


class FakeProvider:
    name = "fake:echo"
    model = "echo"

    def __init__(self, response: dict[str, Any] | Exception) -> None:
        self.response = response
        self.calls: list[dict[str, Any]] = []

    def complete_json(
        self,
        system: str,
        user: str,
        json_schema: dict[str, Any],
        *,
        max_tokens: int,
        timeout: float,
    ) -> dict[str, Any]:
        self.calls.append(
            {
                "system": system,
                "user": user,
                "schema": json_schema,
                "max_tokens": max_tokens,
                "timeout": timeout,
            }
        )
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def _bounds(subject: str = "util_copy_value", **fields: Any) -> BehaviorClaim:
    return claim(
        BehaviorClaim,
        text=CLAIM_TEXT,
        subject_symbol=subject,
        predicate="missing_bounds_check",
        **fields,
    )


def _ctx(
    make_ctx: MakeContext,
    claims: list[BehaviorClaim],
    provider: FakeProvider | None,
    tag: str = "v1.2.0",
) -> CheckContext:
    ctx = make_ctx(claims=claims, tag=tag)
    ctx.llm = provider
    return ctx


def _run(
    make_ctx: MakeContext,
    claims: list[BehaviorClaim],
    provider: FakeProvider | None,
    *,
    tag: str = "v1.2.0",
    check: LlmReview | None = None,
) -> list[Evidence]:
    return (check or LlmReview()).run(_ctx(make_ctx, claims, provider, tag), claims)


# --- off by default -----------------------------------------------------------------------------


def test_without_a_provider_the_check_produces_nothing(make_ctx: MakeContext) -> None:
    assert _run(make_ctx, [_bounds()], None) == []


def test_a_context_without_the_attribute_at_all_produces_nothing(make_ctx: MakeContext) -> None:
    ctx = make_ctx(claims=[_bounds()])
    if hasattr(ctx, "llm"):
        ctx.llm = None
    assert LlmReview().run(ctx, list(ctx.claims)) == []


def test_only_behavior_claims_are_selected(ctx: CheckContext) -> None:
    check = LlmReview()
    assert check.applies_to == frozenset({"behavior"})
    assert check.id == "C20"
    assert check.group == "llm"
    assert check.name == "LLM_REVIEW"


# --- what the model is shown --------------------------------------------------------------------


def test_the_prompt_carries_the_numbered_definition_and_the_claim_inside_data_blocks(
    make_ctx: MakeContext,
) -> None:
    provider = FakeProvider(UNCLEAR)
    (evidence,) = _run(make_ctx, [_bounds()], provider)
    (call,) = provider.calls
    assert call["schema"] == REVIEW_SCHEMA
    assert call["timeout"] == DEFAULT_TIMEOUT_S
    user: str = call["user"]
    code_begin = user.index(BEGIN_MARKER.format(label="code_excerpt_1"))
    code_end = user.index(END_MARKER.format(label="code_excerpt_1"))
    assert code_begin < user.index("    15 |     memcpy(dst, value, len);") < code_end
    assert code_begin < user.index("     8 | char *util_copy_value(const char *value)") < code_end
    claim_begin = user.index(BEGIN_MARKER.format(label="claim"))
    claim_end = user.index(END_MARKER.format(label="claim"))
    assert claim_begin < user.index(CLAIM_TEXT) < claim_end
    assert "missing_bounds_check" in user
    assert f"src/util.c lines {8 - CONTEXT_LINES}-{18 + CONTEXT_LINES} at commit" in user
    assert evidence.outcome == "NEUTRAL"


def test_the_excerpt_is_the_real_file_with_context(ctx: CheckContext) -> None:
    ((path, symbol),) = _sites(ctx, "util_copy_value")
    assert (path, symbol.start_line, symbol.end_line) == ("src/util.c", 8, 18)
    excerpt = _excerpt(ctx, path, symbol)
    assert excerpt is not None
    assert (excerpt.start_line, excerpt.end_line) == (8 - CONTEXT_LINES, 18 + CONTEXT_LINES)
    assert excerpt.line(MEMCPY_LINE) == "    memcpy(dst, value, len);"
    assert excerpt.line(8) == "char *util_copy_value(const char *value)"
    assert excerpt.truncated is False
    assert len(excerpt.lines) <= MAX_EXCERPT_LINES


def test_the_excerpt_follows_the_version(make_ctx: MakeContext) -> None:
    """v1.2.1 only moved lines around; the excerpt is taken at the commit, not from memory."""
    provider = FakeProvider(UNCLEAR)
    _run(make_ctx, [_bounds()], provider, tag="v1.2.1")
    (call,) = provider.calls
    assert "memcpy(dst, value, len)" in call["user"]
    assert "    15 |     memcpy(dst, value, len);" not in call["user"]


# --- the three verdicts -------------------------------------------------------------------------


def test_a_supported_verdict_is_weak_support_produced_by_the_model(make_ctx: MakeContext) -> None:
    c = _bounds()
    provider = FakeProvider(SUPPORTED)
    ctx = _ctx(make_ctx, [c], provider)
    (evidence,) = LlmReview().run(ctx, [c])
    assert evidence.outcome == "SUPPORTS"
    assert evidence.strength == 0.5
    assert evidence.check_id == "C20"
    assert evidence.group == "llm"
    assert evidence.produced_by == "llm"
    assert evidence.claim_ids == (c.id,)
    assert evidence.details["outcome"] == "supported"
    assert evidence.details["model"] == "fake:echo"
    assert len(evidence.details["prompt_sha256"]) == 64
    assert len(evidence.details["response_sha256"]) == 64
    assert evidence.details["cited_lines"] == [MEMCPY_LINE]
    assert evidence.details["downgraded"] is None
    assert evidence.details["paths"] == ["src/util.c"]
    assert "advisory only" in evidence.summary
    assert "a missing bounds check" in evidence.summary
    spans = [(loc.path, loc.start_line, loc.end_line) for loc in evidence.locations]
    assert spans == [("src/util.c", 8, 18), ("src/util.c", MEMCPY_LINE, MEMCPY_LINE)]
    cited = evidence.locations[1]
    assert cited.commit == ctx.commit
    assert cited.excerpt == "    memcpy(dst, value, len);"
    assert cited.permalink is not None
    assert cited.permalink.endswith(f"/blob/{ctx.commit}/src/util.c#L{MEMCPY_LINE}")


def test_a_refuted_verdict_is_a_weak_refutation(make_ctx: MakeContext) -> None:
    (evidence,) = _run(make_ctx, [_bounds()], FakeProvider(REFUTED))
    assert evidence.outcome == "REFUTES"
    assert evidence.strength == -0.5
    assert evidence.produced_by == "llm"
    assert evidence.details["outcome"] == "refuted"
    assert "does not show a missing bounds check" in evidence.summary


def test_an_unclear_verdict_is_neutral(make_ctx: MakeContext) -> None:
    (evidence,) = _run(make_ctx, [_bounds()], FakeProvider(UNCLEAR))
    assert evidence.outcome == "NEUTRAL"
    assert evidence.strength == 0.0
    assert evidence.produced_by == "llm"
    assert evidence.details["outcome"] == "unclear"
    assert "does not settle" in evidence.summary


# --- the guard, exercised end to end -------------------------------------------------------------


def test_a_cited_line_outside_the_excerpt_is_not_counted(make_ctx: MakeContext) -> None:
    (evidence,) = _run(make_ctx, [_bounds()], FakeProvider({**SUPPORTED, "cited_lines": [9999]}))
    assert evidence.outcome == "NEUTRAL"
    assert evidence.strength == 0.0
    assert evidence.details["outcome"] == "unclear"
    assert "9999" in evidence.details["downgraded"]
    assert "is not counted" in evidence.summary
    assert [loc.start_line for loc in evidence.locations] == [8]


def test_quoted_code_that_is_not_in_the_file_is_not_counted(make_ctx: MakeContext) -> None:
    lying = {**SUPPORTED, "rationale": "It calls `strncpy(dst, value, HDR_VALUE_MAX)`."}
    (evidence,) = _run(make_ctx, [_bounds()], FakeProvider(lying))
    assert evidence.outcome == "NEUTRAL"
    assert "strncpy" in evidence.details["downgraded"]


def test_a_response_outside_the_schema_is_not_counted(make_ctx: MakeContext) -> None:
    (evidence,) = _run(make_ctx, [_bounds()], FakeProvider({"answer": "yes"}))
    assert evidence.outcome == "NEUTRAL"
    assert evidence.strength == 0.0
    assert "schema" in evidence.details["downgraded"]


def test_a_provider_failure_is_error_evidence_at_strength_zero(make_ctx: MakeContext) -> None:
    (evidence,) = _run(make_ctx, [_bounds()], FakeProvider(LLMError("ollama is not running")))
    assert evidence.outcome == "ERROR"
    assert evidence.strength == 0.0
    assert evidence.produced_by == "llm"
    assert evidence.details["outcome"] == "error"
    assert evidence.details["model"] == "fake:echo"
    assert "ollama is not running" in evidence.summary
    assert [loc.start_line for loc in evidence.locations] == [8]


# --- the cap (P2: never decisive) ---------------------------------------------------------------


def test_the_bundled_cap_is_half_a_nat() -> None:
    assert default_strengths().get("C20", "llm_cap") == 0.5
    assert LlmReview().cap() == 0.5


@pytest.mark.parametrize("table_cap", [0.5, 1.0, 5.0, 60.0])
def test_strength_never_exceeds_the_cap_whatever_the_table_says(
    make_ctx: MakeContext, table_cap: float
) -> None:
    check = LlmReview(Strengths(version="test", table={"C20": {"llm_cap": table_cap}}))
    (supports,) = _run(make_ctx, [_bounds()], FakeProvider(SUPPORTED), check=check)
    (refutes,) = _run(make_ctx, [_bounds()], FakeProvider(REFUTED), check=check)
    assert supports.strength == MAX_LLM_STRENGTH
    assert refutes.strength == -MAX_LLM_STRENGTH
    for evidence in (supports, refutes):
        assert abs(evidence.strength) <= MAX_LLM_STRENGTH


def test_a_lower_table_cap_is_honoured(make_ctx: MakeContext) -> None:
    check = LlmReview(Strengths(version="test", table={"C20": {"llm_cap": 0.25}}))
    (evidence,) = _run(make_ctx, [_bounds()], FakeProvider(REFUTED), check=check)
    assert evidence.strength == -0.25


# --- nothing to review: no model call at all ------------------------------------------------------


def test_an_undefined_subject_is_neutral_and_sends_nothing(make_ctx: MakeContext) -> None:
    provider = FakeProvider(SUPPORTED)
    (evidence,) = _run(make_ctx, [_bounds("util_copy_valu")], provider)
    assert provider.calls == []
    assert evidence.outcome == "NEUTRAL"
    assert evidence.strength == 0.0
    assert evidence.produced_by == "deterministic"
    assert evidence.details["outcome"] == "skipped"
    assert "util_copy_value" in evidence.details["suggestions"]
    assert evidence.locations == ()


def test_a_function_dropped_by_a_later_release_sends_nothing(make_ctx: MakeContext) -> None:
    provider = FakeProvider(SUPPORTED)
    c = claim(BehaviorClaim, subject_symbol="hdr_get", predicate="missing_null_check")
    (evidence,) = _run(make_ctx, [c], provider, tag="v1.3.0")
    assert provider.calls == []
    assert evidence.outcome == "NEUTRAL"
    assert "not defined at v1.3.0" in evidence.summary


def test_a_budget_already_spent_stops_before_any_call(make_ctx: MakeContext) -> None:
    provider = FakeProvider(SUPPORTED)
    ctx = _ctx(make_ctx, [_bounds()], provider)
    ctx.deadline = 0.0  # in the past for a monotonic clock
    assert LlmReview().run(ctx, list(ctx.claims)) == []
    assert provider.calls == []


# --- the framework contracts ----------------------------------------------------------------------


class TestRefutationGate:
    """ADR 0003: only project-attributed, non-negated claims may be refuted, model or not."""

    def test_reporter_artifact_is_not_refuted(self, make_ctx: MakeContext) -> None:
        c = _bounds(provenance="reporter_artifact")
        (evidence,) = _run(make_ctx, [c], FakeProvider(REFUTED))
        assert evidence.outcome == "NEUTRAL"
        assert evidence.strength == 0.0
        assert evidence.details["gated"] == ["reporter_artifact"]
        assert evidence.details["withheld_strength"] == -0.5
        assert evidence.produced_by == "llm"

    def test_negated_claim_is_not_refuted(self, make_ctx: MakeContext) -> None:
        (evidence,) = _run(make_ctx, [_bounds(negated=True)], FakeProvider(REFUTED))
        assert evidence.outcome == "NEUTRAL"
        assert evidence.details["gated"] == ["negated"]

    def test_support_is_not_gated(self, make_ctx: MakeContext) -> None:
        (evidence,) = _run(make_ctx, [_bounds(provenance="third_party")], FakeProvider(SUPPORTED))
        assert evidence.outcome == "SUPPORTS"
        assert evidence.strength == 0.5


def test_identical_answers_give_identical_evidence(make_ctx: MakeContext) -> None:
    claims = [_bounds(), claim(BehaviorClaim, subject_symbol="util_strip", predicate="uses_freed")]
    first = _run(make_ctx, claims, FakeProvider(UNCLEAR))
    second = _run(make_ctx, claims, FakeProvider(UNCLEAR))
    assert [e.id for e in first] == [e.id for e in second]
    assert [e.model_dump() for e in first] == [e.model_dump() for e in second]
    assert len(first) == 2


def test_registered_and_runnable_through_the_runner(make_ctx: MakeContext) -> None:
    ctx = _ctx(make_ctx, [_bounds()], FakeProvider(SUPPORTED))
    (run,) = run_checks(ctx, checks=[LlmReview()], timeout=5.0)
    assert run.check_id == "C20"
    assert run.error is None
    assert [e.outcome for e in run.evidence] == ["SUPPORTS"]
    assert run.evidence[0].produced_by == "llm"


def test_the_request_timeout_is_bounded_by_the_check_budget(make_ctx: MakeContext) -> None:
    provider = FakeProvider(UNCLEAR)
    ctx = _ctx(make_ctx, [_bounds()], provider)
    run_checks(ctx, checks=[LlmReview()], timeout=3.0)
    (call,) = provider.calls
    assert 0.0 < call["timeout"] <= 3.0


def test_summaries_describe_code_never_people(make_ctx: MakeContext) -> None:
    answers: list[dict[str, Any] | Exception] = [
        SUPPORTED,
        REFUTED,
        UNCLEAR,
        {**SUPPORTED, "cited_lines": [1]},
        LLMError("x"),
    ]
    for answer in answers:
        (evidence,) = _run(make_ctx, [_bounds()], FakeProvider(answer))
        text = evidence.summary.lower()
        for word in ("slop", "fake", "fabricat", "liar", "ai-generated", "hallucinat"):
            assert word not in text, evidence.summary


def test_a_line_number_shown_in_two_files_cites_both(ctx: CheckContext) -> None:
    """A bare cited number is ambiguous across files; neither file is guessed (P6)."""
    first = Excerpt(path="a.c", start_line=10, lines=("int a;", "int b;"), truncated=False)
    second = Excerpt(path="b.c", start_line=11, lines=("int c;",), truncated=False)
    cited = _cited_locations(ctx, [11], [first, second])
    assert [(loc.path, loc.start_line, loc.excerpt) for loc in cited] == [
        ("a.c", 11, "int b;"),
        ("b.c", 11, "int c;"),
    ]


def test_a_failed_definition_search_is_neutral_and_sends_nothing(
    make_ctx: MakeContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    provider = FakeProvider(SUPPORTED)
    bad, good = _bounds("util_copy_value"), _bounds("hdr_parse_line")
    ctx = _ctx(make_ctx, [bad, good], provider)
    real = ctx.index.definitions

    def definitions(commit: str, name: str) -> Any:
        if name == "util_copy_value":
            raise ExternalToolError("git grep failed with exit code 128")
        return real(commit, name)

    monkeypatch.setattr(ctx.index, "definitions", definitions)
    by_subject = {e.details["subject"]: e for e in LlmReview().run(ctx, [bad, good])}
    failed = by_subject["util_copy_value"]
    assert failed.outcome == "NEUTRAL"
    assert failed.strength == 0.0
    assert failed.details["outcome"] == "search_failed"
    assert "exit code 128" in failed.details["incomplete"]
    assert failed.details["history_complete"] is False
    assert len(provider.calls) == 1  # only the claim whose code could be read was sent
