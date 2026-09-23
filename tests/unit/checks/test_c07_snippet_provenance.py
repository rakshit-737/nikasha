# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""C07 SNIPPET_PROVENANCE, against the real vulnlab tree (SPEC §12).

Every snippet below is real ``libhdr`` code (or a deliberate forgery of it), so the
containments asserted here are what winnowing and alignment actually measure on a real
tree, not on a fixture built to agree with them.
"""

from __future__ import annotations

from typing import Any

import pytest

from conftest import MakeContext, claim
from nikasha.checks.base import CheckContext, run_checks
from nikasha.checks.c07_snippet_provenance import SnippetProvenance
from nikasha.code.generated import GeneratedMatch
from nikasha.code.gitio import HistoryTimeoutError
from nikasha.model.claims import SnippetClaim

#: ``util_copy_value()`` exactly as it stands at v1.2.0, src/util.c:8-18.
AT_V120 = """char *util_copy_value(const char *value)
{
    size_t len = strlen(value);
    char *dst = malloc(HDR_VALUE_MAX);

    if (dst == NULL)
        return NULL;
    memcpy(dst, value, len);
    dst[len] = '\\0';
    return dst;
}"""

#: The same function reflowed, re-commented and re-spaced, as a reporter's paste usually is.
REFLOWED = """char * util_copy_value( const char * value ) {
  /* copy the header value into the fixed-size buffer */
  size_t len = strlen( value );
  char * dst = malloc( HDR_VALUE_MAX );
  if ( dst == NULL ) return NULL;
  memcpy( dst, value, len );
  dst[ len ] = '\\0';
  return dst;
}"""

#: The *fixed* function from v1.3.0: the same code plus the bounds check v1.2.0 lacks.
FIXED_IN_V130 = """char *util_copy_value(const char *value)
{
    size_t len = strlen(value);
    char *dst = malloc(HDR_VALUE_MAX);

    if (dst == NULL)
        return NULL;

    if (len >= HDR_VALUE_MAX)
        len = HDR_VALUE_MAX - 1;

    memcpy(dst, value, len);
    dst[len] = '\\0';
    return dst;
}"""

#: Plausible libhdr-flavoured C that has never been in the repository.
FABRICATED = """static int hdr_validate_charset(const char *value, size_t vlen)
{
    unsigned int state = 0;

    while (vlen-- > 0) {
        state = charset_table[state][(unsigned char)*value++];
        if (state == HDR_CHARSET_REJECT)
            return -EILSEQ;
    }
    return state;
}"""

#: Two real lines of src/util.c: under three lines and under twenty-five tokens.
SMALL = """char *dst = malloc(HDR_VALUE_MAX);
memcpy(dst, value, len);"""

#: Seven tokens, fewer than one winnowing window (w + k - 1 = 8), so it has no fingerprints.
TINY = """dst[len] = '\\0';"""

#: Real identifiers in an order the code never had: some of it is in the tree, not enough.
SCRAMBLED = """util_strip(hdr_get(hdr_parse_line));"""


def _snippet(code: str, **fields: Any) -> SnippetClaim:
    return claim(SnippetClaim, code=code, lang_hint="c", n_lines=code.count("\n") + 1, **fields)


def _run(make_ctx: MakeContext, claims: list[SnippetClaim], tag: str = "v1.2.0") -> list:
    ctx = make_ctx(claims=claims, tag=tag)
    return SnippetProvenance().run(ctx, claims)


# --- the four SPEC outcomes ---------------------------------------------------------------


def test_a_quoted_function_is_located_and_supports(make_ctx: MakeContext) -> None:
    c = _snippet(AT_V120)
    (evidence,) = _run(make_ctx, [c])
    assert evidence.outcome == "SUPPORTS"
    assert evidence.strength == 2.0
    assert evidence.check_id == "C07"
    assert evidence.group == "code_quotes"
    assert evidence.claim_ids == (c.id,)
    assert evidence.details["outcome_key"] == "contained"
    assert evidence.details["here"] == {
        "ref": "v1.2.0",
        "path": "src/util.c",
        "containment": 1.0,
        "lines": [8, 18],
    }
    assert "src/util.c:8-18" in evidence.summary


def test_reformatting_and_re_commenting_do_not_break_the_match(make_ctx: MakeContext) -> None:
    (evidence,) = _run(make_ctx, [_snippet(REFLOWED)])
    assert evidence.outcome == "SUPPORTS"
    assert evidence.details["outcome_key"] == "contained"
    assert evidence.details["here"]["lines"] == [8, 18]


def test_a_modified_quote_is_partial(make_ctx: MakeContext) -> None:
    """The v1.3.0 fix quoted against v1.2.0: most of it is there, the bounds check is not."""
    (evidence,) = _run(make_ctx, [_snippet(FIXED_IN_V130)])
    assert evidence.outcome == "SUPPORTS"
    assert evidence.strength == 0.5
    assert evidence.details["outcome_key"] == "partial"
    assert 0.5 <= evidence.details["containment"] < 0.85
    assert "modified" in evidence.summary


def test_a_snippet_only_in_later_releases_refutes_weakly(make_ctx: MakeContext) -> None:
    """``util_copy_value()`` does not exist yet at v1.0.0; it arrives in v1.1.0."""
    (evidence,) = _run(make_ctx, [_snippet(AT_V120)], tag="v1.0.0")
    assert evidence.outcome == "REFUTES"
    assert evidence.strength == -0.5
    assert evidence.details["outcome_key"] == "other_release_only"
    assert evidence.details["containment"] == 0.0
    assert evidence.details["elsewhere"]["ref"] == "v1.1.0"
    assert evidence.details["elsewhere"]["containment"] == 1.0
    assert evidence.details["sampled_releases"] == ["v1.1.0", "v1.2.0", "v1.2.1", "v1.3.0"]
    assert evidence.locations == ()  # the match is at another commit, so it is not linked


def test_a_fabricated_snippet_is_absent_everywhere(make_ctx: MakeContext) -> None:
    (evidence,) = _run(make_ctx, [_snippet(FABRICATED)])
    assert evidence.outcome == "REFUTES"
    assert evidence.strength == -2.5
    assert evidence.details["outcome_key"] == "absent_everywhere"
    assert evidence.details["containment"] == 0.0
    assert evidence.details["elsewhere"] is None
    assert evidence.details["sampled_releases"] == ["v1.0.0", "v1.1.0", "v1.2.1", "v1.3.0"]
    assert evidence.details["history_complete"] is True
    assert evidence.details["history_term"] == "hdr_validate_charset"
    assert "anywhere in history" in evidence.summary


# --- the size rule (SPEC §12: 3+ lines or 25+ tokens) --------------------------------------


def test_a_small_snippet_keeps_its_verdict_at_reduced_weight(make_ctx: MakeContext) -> None:
    (evidence,) = _run(make_ctx, [_snippet(SMALL)])
    assert evidence.outcome == "SUPPORTS"
    assert evidence.details["outcome_key"] == "contained"
    assert evidence.details["small_snippet"] is True
    assert evidence.details["code_lines"] == 2
    assert evidence.details["tokens"] < 25
    assert evidence.strength == pytest.approx(2.0 * 0.3)
    assert "weight is reduced" in evidence.summary


def test_a_full_size_snippet_is_not_reduced(make_ctx: MakeContext) -> None:
    (evidence,) = _run(make_ctx, [_snippet(AT_V120)])
    assert evidence.details["small_snippet"] is False
    assert evidence.strength == 2.0


def test_a_snippet_below_one_window_falls_back_to_alignment(make_ctx: MakeContext) -> None:
    """Fewer than w + k - 1 tokens means no fingerprints at all (fingerprint module)."""
    (evidence,) = _run(make_ctx, [_snippet(TINY)])
    assert evidence.details["method"] == "align"
    assert evidence.details["tokens"] < 8
    assert evidence.details["here"]["lines"] == [16, 16]
    assert evidence.strength == pytest.approx(2.0 * 0.3)
    assert "no fingerprints" in evidence.summary


def test_a_partly_present_snippet_is_neutral(make_ctx: MakeContext) -> None:
    """Above "absent" but below "partial": say so, score nothing."""
    (evidence,) = _run(make_ctx, [_snippet(SCRAMBLED)])
    assert evidence.outcome == "NEUTRAL"
    assert evidence.strength == 0.0
    assert evidence.details["outcome_key"] is None
    assert 0.3 <= evidence.details["containment"] < 0.5
    assert "not enough of it" in evidence.summary


# --- evidence quality ---------------------------------------------------------------------


def test_evidence_carries_a_location_at_the_exact_commit(make_ctx: MakeContext) -> None:
    ctx = make_ctx(claims=[_snippet(AT_V120)])
    (evidence,) = SnippetProvenance().run(ctx, list(ctx.claims))
    (location,) = evidence.locations
    assert location.commit == ctx.commit
    assert location.path == "src/util.c"
    assert (location.start_line, location.end_line) == (8, 18)
    assert location.permalink is not None
    assert location.permalink.endswith("/blob/" + ctx.commit + "/src/util.c#L8-L18")


def test_the_git_commands_are_recorded(make_ctx: MakeContext) -> None:
    (evidence,) = _run(make_ctx, [_snippet(AT_V120)])
    searched = evidence.details["searched"]
    assert searched
    assert all(command.startswith("git grep -n -I -F -e ") for command in searched)


def test_a_snippet_with_no_code_is_skipped(make_ctx: MakeContext) -> None:
    assert _run(make_ctx, [_snippet("/* just a comment */\n")]) == []


# --- P4: absence is never certain -----------------------------------------------------------


class TestNeverSaysAbsentWithoutProof:
    """P4: ``absent_everywhere`` needs the ref, the releases *and* history to have run."""

    def test_a_spent_budget_downgrades_to_neutral(self, make_ctx: MakeContext) -> None:
        ctx = make_ctx(claims=[_snippet(FABRICATED)])
        ctx.deadline = 0.0  # every search this check would run is already out of time
        (evidence,) = SnippetProvenance().run(ctx, list(ctx.claims))
        assert evidence.outcome == "NEUTRAL"
        assert evidence.strength == 0.0
        assert evidence.details["history_complete"] is False
        assert evidence.details["sampled_releases"] == []
        assert "did not finish" in evidence.summary
        assert "not called absent" in evidence.summary

    def test_a_history_timeout_downgrades_to_neutral(
        self, make_ctx: MakeContext, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ctx = make_ctx(claims=[_snippet(FABRICATED)])

        def timeout(text: str, **_: object) -> str | None:
            raise HistoryTimeoutError("log -S ran out of budget")

        monkeypatch.setattr(ctx.resolution.repo, "pickaxe_first", timeout)
        (evidence,) = SnippetProvenance().run(ctx, list(ctx.claims))
        assert evidence.outcome == "NEUTRAL"
        assert evidence.strength == 0.0
        assert evidence.details["history_complete"] is False
        assert evidence.details["sampled_releases"] == ["v1.0.0", "v1.1.0", "v1.2.1", "v1.3.0"]
        assert "'hdr_validate_charset' did not finish" in evidence.summary

    def test_a_term_history_still_holds_is_not_called_absent(
        self, make_ctx: MakeContext, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ctx = make_ctx(claims=[_snippet(FABRICATED)])
        monkeypatch.setattr(ctx.resolution.repo, "pickaxe_first", lambda text, **_: "0" * 40)
        (evidence,) = SnippetProvenance().run(ctx, list(ctx.claims))
        assert evidence.outcome == "NEUTRAL"
        assert evidence.strength == 0.0
        assert evidence.details["history_complete"] is True
        assert "history still contains 'hdr_validate_charset'" in evidence.summary


class TestGeneratedFilesAreNeverJudged:
    """SPEC §11.5: a generated or release-only file is NEUTRAL with a note, never a verdict."""

    def test_a_snippet_attributed_to_a_generated_file(self, make_ctx: MakeContext) -> None:
        c = _snippet(FABRICATED, attributed_path="config.h")
        (evidence,) = _run(make_ctx, [c])
        assert evidence.outcome == "NEUTRAL"
        assert evidence.strength == 0.0
        assert evidence.details["generated"] == "matches 'config.h'"
        assert "not judged" in evidence.summary

    def test_a_snippet_found_in_a_generated_file(
        self, make_ctx: MakeContext, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ctx = make_ctx(claims=[_snippet(AT_V120)])
        monkeypatch.setattr(
            ctx,
            "generated",
            lambda path: GeneratedMatch(path, "amalgamation", f"matches {path!r}"),
        )
        (evidence,) = SnippetProvenance().run(ctx, list(ctx.claims))
        assert evidence.outcome == "NEUTRAL"
        assert evidence.strength == 0.0
        assert "src/util.c" in evidence.summary
        assert "amalgamation" in evidence.summary


# --- ADR 0003 and determinism ---------------------------------------------------------------


class TestRefutationGate:
    """ADR 0003: only project-attributed, non-negated claims may be refuted."""

    def test_reporter_artifact_is_not_refuted(self, make_ctx: MakeContext) -> None:
        c = _snippet(FABRICATED, provenance="reporter_artifact")
        (evidence,) = _run(make_ctx, [c])
        assert evidence.outcome == "NEUTRAL"
        assert evidence.strength == 0.0
        assert evidence.details["gated"] == ["reporter_artifact"]
        assert evidence.details["withheld_strength"] == -2.5

    def test_negated_claim_is_not_refuted(self, make_ctx: MakeContext) -> None:
        c = _snippet(FABRICATED, negated=True)
        (evidence,) = _run(make_ctx, [c])
        assert evidence.outcome == "NEUTRAL"
        assert evidence.details["gated"] == ["negated"]

    def test_support_is_not_gated(self, make_ctx: MakeContext) -> None:
        c = _snippet(AT_V120, provenance="third_party")
        (evidence,) = _run(make_ctx, [c])
        assert evidence.outcome == "SUPPORTS"
        assert evidence.strength == 2.0


def test_identical_input_gives_identical_evidence(make_ctx: MakeContext) -> None:
    claims = [_snippet(AT_V120), _snippet(FABRICATED)]
    first = _run(make_ctx, claims)
    second = _run(make_ctx, claims)
    assert [e.id for e in first] == [e.id for e in second]
    assert [e.model_dump() for e in first] == [e.model_dump() for e in second]


def test_registered_and_runnable_through_the_runner(make_ctx: MakeContext) -> None:
    ctx: CheckContext = make_ctx(claims=[_snippet(FABRICATED)])
    (run,) = run_checks(ctx, checks=[SnippetProvenance()])
    assert run.check_id == "C07"
    assert run.error is None
    assert run.seconds >= 0.0
    assert [e.outcome for e in run.evidence] == ["REFUTES"]
