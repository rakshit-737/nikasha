# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""C06 LINE_CONTENT, against the real vulnlab tree (SPEC §12).

``src/util.c`` at ``v1.2.0`` is the whole ladder in one file: line 15 is the unguarded
``memcpy``, the bounds check it lost lives only in ``v1.1.0`` and ``v1.3.0``, and
``src/hdr.c`` has a *different* ``memcpy`` to be confused with.
"""

from __future__ import annotations

import time
from types import SimpleNamespace
from typing import Any

import pytest
from check_helpers import MakeContext, claim

from nikasha.checks.base import run_checks
from nikasha.checks.c06_line_content import LineContent, git_lines, line_similarity, normalize
from nikasha.code.generated import GeneratedMatch
from nikasha.code.gitio import GrepHit
from nikasha.code.literal import LiteralResult
from nikasha.code.literal import literal_search as real_literal_search
from nikasha.model.claims import LineClaim

#: ``src/util.c:15`` at v1.2.0, the line the demo bug is on.
MEMCPY = "memcpy(dst, value, len);"
#: The bounds check v1.2.0 dropped: present at v1.1.0 and v1.3.0 only.
BOUNDS_CHECK = "if (len >= HDR_VALUE_MAX)"
#: Never written in any commit of the lab.
INVENTED = "frobnicate_widget(quux, 42);"


def _run(make_ctx: MakeContext, claims: list[LineClaim], tag: str = "v1.2.0") -> list[Any]:
    ctx = make_ctx(claims=claims, tag=tag)
    return LineContent().run(ctx, claims)


# --- the two support rungs ----------------------------------------------------------------


def test_the_quote_at_the_stated_line_supports(make_ctx: MakeContext) -> None:
    c = claim(LineClaim, path="src/util.c", line=15, quoted_line=f"    {MEMCPY}")
    (evidence,) = _run(make_ctx, [c])
    assert evidence.outcome == "SUPPORTS"
    assert evidence.strength == 1.5
    assert evidence.check_id == "C06"
    assert evidence.group == "code_quotes"
    assert evidence.claim_ids == (c.id,)
    assert evidence.details["similarity"] == 1.0
    assert evidence.details["path"] == "src/util.c"


def test_indentation_and_inner_spacing_are_normalized_away(make_ctx: MakeContext) -> None:
    quoted = "\t\tmemcpy(dst,   value,  len);   "
    (evidence,) = _run(make_ctx, [claim(LineClaim, path="src/util.c", line=15, quoted_line=quoted)])
    assert evidence.outcome == "SUPPORTS"
    assert evidence.details["quote"] == MEMCPY


def test_a_partial_quote_of_the_line_still_matches_it(make_ctx: MakeContext) -> None:
    partial = "memcpy(dst, value, len)"  # the reporter dropped the semicolon
    (evidence,) = _run(
        make_ctx, [claim(LineClaim, path="src/util.c", line=15, quoted_line=partial)]
    )
    assert evidence.outcome == "SUPPORTS"
    assert evidence.strength == 1.5


def test_a_partial_path_resolves_like_a_full_one(make_ctx: MakeContext) -> None:
    (evidence,) = _run(make_ctx, [claim(LineClaim, path="util.c", line=15, quoted_line=MEMCPY)])
    assert evidence.outcome == "SUPPORTS"
    assert evidence.details["path"] == "src/util.c"


@pytest.mark.parametrize(("cited", "offset", "phrase"), [(17, -2, "above"), (13, 2, "below")])
def test_a_match_within_three_lines_supports_and_notes_the_offset(
    make_ctx: MakeContext, cited: int, offset: int, phrase: str
) -> None:
    c = claim(LineClaim, path="src/util.c", line=cited, quoted_line=MEMCPY)
    (evidence,) = _run(make_ctx, [c])
    assert evidence.outcome == "SUPPORTS"
    assert evidence.strength == 0.8
    assert evidence.details["offset"] == offset
    assert evidence.details["found_line"] == 15
    assert phrase in evidence.summary


# --- the three refutation rungs -----------------------------------------------------------


def test_a_match_further_off_in_the_same_file_refutes_weakly(make_ctx: MakeContext) -> None:
    c = claim(LineClaim, path="src/util.c", line=30, quoted_line=MEMCPY)
    (evidence,) = _run(make_ctx, [c])
    assert evidence.outcome == "REFUTES"
    assert evidence.strength == -0.3
    assert evidence.details["scope"] == "same_file"
    assert evidence.details["found_lines"] == [15]
    assert "30" in evidence.summary


def test_a_quote_that_lives_in_another_file_refutes_weakly(make_ctx: MakeContext) -> None:
    # src/hdr.c:132 is a different memcpy; quoting it as util.c:15 is a wrong location.
    c = claim(LineClaim, path="src/util.c", line=15, quoted_line="memcpy(line, p, len);")
    (evidence,) = _run(make_ctx, [c])
    assert evidence.outcome == "REFUTES"
    assert evidence.strength == -0.3
    assert evidence.details["scope"] == "other_file"
    assert evidence.details["found_at"] == ["src/hdr.c:132"]
    assert "git grep" in evidence.details["command"]


def test_a_line_only_in_other_releases_is_a_version_finding(make_ctx: MakeContext) -> None:
    c = claim(LineClaim, path="src/util.c", line=15, quoted_line=f"    {BOUNDS_CHECK}")
    (evidence,) = _run(make_ctx, [c])
    assert evidence.outcome == "REFUTES"
    assert evidence.strength == -0.4
    assert evidence.details["found_in_releases"] == ["v1.1.0", "v1.3.0"]


def test_that_same_line_is_exact_at_the_release_that_has_it(make_ctx: MakeContext) -> None:
    c = claim(LineClaim, path="src/util.c", line=29, quoted_line=BOUNDS_CHECK)
    (evidence,) = _run(make_ctx, [c], tag="v1.3.0")
    assert evidence.outcome == "SUPPORTS"
    assert evidence.strength == 1.5


def test_a_line_nowhere_in_history_is_the_strong_refutation(make_ctx: MakeContext) -> None:
    c = claim(LineClaim, path="src/util.c", line=15, quoted_line=f"    {INVENTED}")
    (evidence,) = _run(make_ctx, [c])
    assert evidence.outcome == "REFUTES"
    assert evidence.strength == -2.0
    assert evidence.details["never_in_history"] is True
    assert evidence.details["history_complete"] is True


# --- what this check declines to judge ----------------------------------------------------


def test_an_unknown_path_is_left_to_c02(make_ctx: MakeContext) -> None:
    assert _run(make_ctx, [claim(LineClaim, path="src/nope.c", line=15, quoted_line=MEMCPY)]) == []


def test_claims_without_a_quote_or_a_line_are_skipped(make_ctx: MakeContext) -> None:
    assert _run(make_ctx, [claim(LineClaim, path="src/util.c", line=15)]) == []
    assert _run(make_ctx, [claim(LineClaim, path="src/util.c", line=0, quoted_line=MEMCPY)]) == []


def test_quotes_too_short_to_mean_anything_are_skipped(make_ctx: MakeContext) -> None:
    for text in ("}", "return;", "   "):
        assert (
            _run(make_ctx, [claim(LineClaim, path="src/util.c", line=15, quoted_line=text)]) == []
        )


def test_evidence_carries_a_location_at_the_exact_commit(make_ctx: MakeContext) -> None:
    ctx = make_ctx(claims=[claim(LineClaim, path="src/util.c", line=15, quoted_line=MEMCPY)])
    (evidence,) = LineContent().run(ctx, list(ctx.claims))
    (location,) = evidence.locations
    assert location.commit == ctx.commit
    assert location.path == "src/util.c"
    assert location.excerpt == MEMCPY
    assert location.permalink is not None
    assert location.permalink.endswith("/blob/" + ctx.commit + "/src/util.c#L15")


class TestWithoutAClaimedPath:
    """A quote the report never attached to a file: supportable, barely refutable."""

    def test_a_quote_at_the_stated_line_still_supports(self, make_ctx: MakeContext) -> None:
        c = claim(LineClaim, path=None, line=15, quoted_line=MEMCPY)
        (evidence,) = _run(make_ctx, [c])
        assert evidence.outcome == "SUPPORTS"
        assert evidence.strength == 1.5
        assert evidence.details["found_path"] == "src/util.c"

    def test_a_wrong_line_number_alone_is_not_judged(self, make_ctx: MakeContext) -> None:
        c = claim(LineClaim, path=None, line=99, quoted_line=MEMCPY)
        (evidence,) = _run(make_ctx, [c])
        assert evidence.outcome == "NEUTRAL"
        assert evidence.strength == 0.0
        assert evidence.details["scope"] == "no_path"
        assert evidence.details["withheld_strength"] == -0.3

    def test_the_strong_refutation_needs_a_project_location(self, make_ctx: MakeContext) -> None:
        # ADR 0003: -2.0 requires the claim to point at a place in the project.
        c = claim(LineClaim, path=None, line=15, quoted_line=INVENTED)
        (evidence,) = _run(make_ctx, [c])
        assert evidence.outcome == "NEUTRAL"
        assert evidence.details["withheld_strength"] == -2.0
        assert evidence.details["history_complete"] is False
        assert "names no file" in evidence.details["incomplete"]


class TestP4:
    """Absence is never proof: every doubt has to cost the strong refutation."""

    def test_generated_files_are_never_judged(
        self, make_ctx: MakeContext, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ctx = make_ctx(claims=[claim(LineClaim, path="src/util.c", line=15, quoted_line=INVENTED)])
        monkeypatch.setattr(
            ctx, "generated", lambda path: GeneratedMatch(path, "generated", "matches 'config.h'")
        )
        (evidence,) = LineContent().run(ctx, list(ctx.claims))
        assert evidence.outcome == "NEUTRAL"
        assert evidence.strength == 0.0
        assert evidence.details["generated"] == "matches 'config.h'"

    def test_a_spent_budget_downgrades_nowhere_in_history(self, make_ctx: MakeContext) -> None:
        ctx = make_ctx(claims=[claim(LineClaim, path="src/util.c", line=15, quoted_line=INVENTED)])
        ctx.deadline = time.monotonic() - 1.0
        (evidence,) = LineContent().run(ctx, list(ctx.claims))
        assert evidence.outcome == "NEUTRAL"
        assert evidence.details["history_complete"] is False
        assert evidence.details["withheld_strength"] == -2.0
        assert "no time left" in evidence.details["incomplete"]

    def test_a_spent_budget_never_calls_a_real_line_invented(self, make_ctx: MakeContext) -> None:
        # The bounds check is really in v1.1.0 and v1.3.0; with no time to look, the check
        # must say so rather than reach for -2.0.
        ctx = make_ctx(
            claims=[claim(LineClaim, path="src/util.c", line=15, quoted_line=BOUNDS_CHECK)]
        )
        ctx.deadline = time.monotonic() - 1.0
        (evidence,) = LineContent().run(ctx, list(ctx.claims))
        assert evidence.outcome == "NEUTRAL"
        assert evidence.strength == 0.0


class TestRefutationGate:
    """ADR 0003: only project-attributed, non-negated claims may be refuted."""

    def test_reporter_artifact_is_not_refuted(self, make_ctx: MakeContext) -> None:
        c = claim(
            LineClaim,
            path="src/util.c",
            line=15,
            quoted_line=INVENTED,
            provenance="reporter_artifact",
        )
        (evidence,) = _run(make_ctx, [c])
        assert evidence.outcome == "NEUTRAL"
        assert evidence.strength == 0.0
        assert evidence.details["gated"] == ["reporter_artifact"]
        assert evidence.details["withheld_strength"] == -2.0

    def test_negated_claim_is_not_refuted(self, make_ctx: MakeContext) -> None:
        c = claim(LineClaim, path="src/util.c", line=30, quoted_line=MEMCPY, negated=True)
        (evidence,) = _run(make_ctx, [c])
        assert evidence.outcome == "NEUTRAL"
        assert evidence.details["gated"] == ["negated"]
        assert evidence.details["withheld_strength"] == -0.3

    def test_support_is_not_gated(self, make_ctx: MakeContext) -> None:
        c = claim(
            LineClaim, path="src/util.c", line=15, quoted_line=MEMCPY, provenance="third_party"
        )
        (evidence,) = _run(make_ctx, [c])
        assert evidence.outcome == "SUPPORTS"
        assert evidence.strength == 1.5


# --- determinism and wiring ---------------------------------------------------------------


def test_identical_input_gives_identical_evidence(make_ctx: MakeContext) -> None:
    c = claim(LineClaim, path="src/util.c", line=15, quoted_line=f"    {BOUNDS_CHECK}")
    first = _run(make_ctx, [c])
    second = _run(make_ctx, [c])
    assert [e.id for e in first] == [e.id for e in second]
    assert first[0].model_dump() == second[0].model_dump()


def test_registered_and_runnable_through_the_runner(make_ctx: MakeContext) -> None:
    ctx = make_ctx(claims=[claim(LineClaim, path="src/util.c", line=15, quoted_line=INVENTED)])
    (run,) = run_checks(ctx, checks=[LineContent()])
    assert run.check_id == "C06"
    assert run.error is None
    assert run.seconds >= 0.0
    assert [e.outcome for e in run.evidence] == ["REFUTES"]


def test_normalization_and_similarity_are_pure_functions() -> None:
    assert normalize("  a\t b \r\n") == "a b"
    assert line_similarity("memcpy(dst, value, len)", MEMCPY) == 1.0
    assert line_similarity(MEMCPY, "memcpy(line, p, len);") < 0.9
    assert line_similarity(MEMCPY, MEMCPY) == 1.0


# --- review findings ----------------------------------------------------------------------


class TestReviewFindings:
    def test_lines_are_numbered_like_git_not_like_splitlines(
        self, make_ctx: MakeContext, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A form feed on its own line (GNU page break) is one line to git, C04 and GitHub;
        # str.splitlines() would count two and push the cited line off by one.
        ctx = make_ctx(claims=[claim(LineClaim, path="src/util.c", line=3, quoted_line=MEMCPY)])
        blob = f"int a;\n\x0c\n    {MEMCPY}\n".encode()
        monkeypatch.setattr(ctx.resolution.repo, "read_file", lambda commit, path: blob)
        (evidence,) = LineContent().run(ctx, list(ctx.claims))
        assert evidence.details["outcome"] == "exact"
        assert git_lines("a\n\x0cb\x1cc\n") == ["a", "\x0cb\x1cc"]

    def test_a_respaced_real_line_is_never_called_invented(self, make_ctx: MakeContext) -> None:
        # The bounds check is real (v1.1.0, v1.3.0); a paste that lost one space misses
        # every byte-exact search, which must not become -2.0 (P4).
        c = claim(LineClaim, path="src/util.c", line=15, quoted_line="if(len >= HDR_VALUE_MAX)")
        (evidence,) = _run(make_ctx, [c])
        assert evidence.outcome == "NEUTRAL"
        assert evidence.strength == 0.0
        assert evidence.details["history_complete"] is False
        assert "spacing" in evidence.details["incomplete"]

    def test_a_spent_budget_does_not_claim_the_releases_were_searched(
        self, make_ctx: MakeContext
    ) -> None:
        ctx = make_ctx(
            claims=[claim(LineClaim, path="src/util.c", line=15, quoted_line=BOUNDS_CHECK)]
        )
        ctx.deadline = time.monotonic() - 1.0
        (evidence,) = LineContent().run(ctx, list(ctx.claims))
        assert "other release" not in evidence.summary
        assert evidence.details["releases_searched"] is False

    def test_release_tags_sharing_a_commit_are_all_named(
        self, make_ctx: MakeContext, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ctx = make_ctx(
            claims=[claim(LineClaim, path="src/util.c", line=15, quoted_line=BOUNDS_CHECK)]
        )
        releases = list(ctx.resolution.releases.finals())
        v110 = next(r for r in releases if r.name == "v1.1.0")
        extra = SimpleNamespace(name="v1.1.0-retag", commit=v110.commit)
        monkeypatch.setattr(ctx.resolution.releases, "finals", lambda: [*releases, extra])
        (evidence,) = LineContent().run(ctx, list(ctx.claims))
        assert evidence.details["found_in_releases"] == ["v1.1.0", "v1.1.0-retag", "v1.3.0"]

    def test_a_capped_grep_listing_does_not_hide_the_claimed_file(
        self, make_ctx: MakeContext, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ctx = make_ctx(claims=[claim(LineClaim, path="src/util.c", line=15, quoted_line=MEMCPY)])
        monkeypatch.setattr(ctx.resolution.repo, "read_file", lambda commit, path: None)

        def capped(repo: Any, text: str, commit: str, **kw: Any) -> LiteralResult | None:
            if kw.get("pathspecs"):
                return real_literal_search(repo, text, commit, **kw)
            hit = GrepHit(commit, "src/hdr.c", 5, text)
            return LiteralResult(text, commit, (hit,), True, "git grep")

        monkeypatch.setattr("nikasha.checks.c06_line_content.literal_search", capped)
        (evidence,) = LineContent().run(ctx, list(ctx.claims))
        assert evidence.outcome == "SUPPORTS"
        assert evidence.details["found_path"] == "src/util.c"


def test_a_failed_grep_is_neutral_for_that_claim_only(
    make_ctx: MakeContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    """P4: a ``git grep`` that exits 128 is not "nowhere", and must not sink other claims."""
    from nikasha.code.gitio import GitRepo, GitResult  # noqa: PLC0415

    bad = claim(LineClaim, path=None, line=3, quoted_line=INVENTED)
    good = claim(LineClaim, path="src/util.c", line=15, quoted_line=f"    {MEMCPY}")
    ctx = make_ctx(claims=[bad, good])
    repo = ctx.resolution.repo
    real_run = type(repo).run

    def run(self: GitRepo, argv: list[str], **kw: Any) -> GitResult:
        if argv[:1] == ["grep"] and INVENTED in argv:
            return GitResult(tuple(argv), 128, b"", b"fatal: bad object", 0)
        return real_run(self, argv, **kw)

    monkeypatch.setattr(type(repo), "run", run)
    evidence = LineContent().run(ctx, [bad, good])
    by_line = {e.details["line"]: e for e in evidence}
    failed = by_line[3]
    assert failed.outcome == "NEUTRAL"
    assert failed.strength == 0.0
    assert failed.details["outcome"] == "search_failed"
    assert "exit code 128" in failed.details["incomplete"]
    assert by_line[15].outcome == "SUPPORTS"
