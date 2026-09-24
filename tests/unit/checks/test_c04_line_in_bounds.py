# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""C04 LINE_IN_BOUNDS, against the real vulnlab tree (SPEC §12)."""

from __future__ import annotations

import pytest
from check_helpers import MakeContext, claim

from nikasha.checks import c04_line_in_bounds as c04
from nikasha.checks.base import run_checks
from nikasha.checks.c04_line_in_bounds import LineInBounds
from nikasha.code.gitio import TreeEntry
from nikasha.model.claims import LineClaim, Permalink
from nikasha.model.evidence import Evidence


def _run(make_ctx: MakeContext, claims: list[LineClaim], tag: str = "v1.2.0") -> list[Evidence]:
    ctx = make_ctx(claims=claims, tag=tag)
    return LineInBounds().run(ctx, claims)


def test_line_inside_the_file_supports(make_ctx: MakeContext) -> None:
    c = claim(LineClaim, path="src/util.c", line=10)
    (evidence,) = _run(make_ctx, [c])
    assert evidence.outcome == "SUPPORTS"
    assert evidence.strength == 0.2
    assert evidence.check_id == "C04"
    assert evidence.group == "lines"
    assert evidence.claim_ids == (c.id,)
    assert evidence.details["path"] == "src/util.c"
    assert evidence.details["n_lines"] >= 10


def test_line_past_the_end_refutes_and_states_the_real_length(make_ctx: MakeContext) -> None:
    c = claim(LineClaim, path="src/util.c", line=9999)
    (evidence,) = _run(make_ctx, [c])
    assert evidence.outcome == "REFUTES"
    assert evidence.strength == -1.5
    n_lines = evidence.details["n_lines"]
    assert evidence.details["past_end_by"] == 9999 - n_lines
    assert str(n_lines) in evidence.summary
    assert "9999" in evidence.summary


def test_evidence_carries_a_location_at_the_exact_commit(make_ctx: MakeContext) -> None:
    ctx = make_ctx(claims=[claim(LineClaim, path="src/util.c", line=10)])
    (evidence,) = LineInBounds().run(ctx, list(ctx.claims))
    (location,) = evidence.locations
    assert location.commit == ctx.commit
    assert location.path == "src/util.c"
    assert location.permalink is not None
    assert location.permalink.endswith("/blob/" + ctx.commit + "/src/util.c#L10")


def test_end_line_is_what_gets_checked(make_ctx: MakeContext) -> None:
    c = claim(LineClaim, path="src/util.c", line=5, end_line=9999)
    (evidence,) = _run(make_ctx, [c])
    assert evidence.outcome == "REFUTES"
    assert evidence.details["line"] == 9999


def test_unknown_path_is_left_to_c02(make_ctx: MakeContext) -> None:
    assert _run(make_ctx, [claim(LineClaim, path="src/nope.c", line=3)]) == []


def test_pathless_and_zero_line_claims_are_skipped(make_ctx: MakeContext) -> None:
    assert _run(make_ctx, [claim(LineClaim, path=None, line=3)]) == []
    assert _run(make_ctx, [claim(LineClaim, path="src/util.c", line=0)]) == []


def test_a_partial_path_still_resolves(make_ctx: MakeContext) -> None:
    (evidence,) = _run(make_ctx, [claim(LineClaim, path="util.c", line=10)])
    assert evidence.outcome == "SUPPORTS"
    assert evidence.details["path"] == "src/util.c"


class TestRefutationGate:
    """ADR 0003: only project-attributed, non-negated claims may be refuted."""

    def test_reporter_artifact_is_not_refuted(self, make_ctx: MakeContext) -> None:
        c = claim(LineClaim, path="src/util.c", line=9999, provenance="reporter_artifact")
        (evidence,) = _run(make_ctx, [c])
        assert evidence.outcome == "NEUTRAL"
        assert evidence.strength == 0.0
        assert evidence.details["gated"] == ["reporter_artifact"]
        assert evidence.details["withheld_strength"] == -1.5

    def test_negated_claim_is_not_refuted(self, make_ctx: MakeContext) -> None:
        c = claim(LineClaim, path="src/util.c", line=9999, negated=True)
        (evidence,) = _run(make_ctx, [c])
        assert evidence.outcome == "NEUTRAL"
        assert evidence.details["gated"] == ["negated"]

    def test_support_is_not_gated(self, make_ctx: MakeContext) -> None:
        c = claim(LineClaim, path="src/util.c", line=10, provenance="third_party")
        (evidence,) = _run(make_ctx, [c])
        assert evidence.outcome == "SUPPORTS"


def test_identical_input_gives_identical_evidence_ids(make_ctx: MakeContext) -> None:
    c = claim(LineClaim, path="src/util.c", line=9999)
    first = _run(make_ctx, [c])
    second = _run(make_ctx, [c])
    assert [e.id for e in first] == [e.id for e in second]
    assert first[0].model_dump() == second[0].model_dump()


def test_registered_and_runnable_through_the_runner(make_ctx: MakeContext) -> None:
    ctx = make_ctx(claims=[claim(LineClaim, path="src/util.c", line=9999)])
    (run,) = run_checks(ctx, checks=[LineInBounds()])
    assert run.check_id == "C04"
    assert run.error is None
    assert run.seconds >= 0.0
    assert [e.outcome for e in run.evidence] == ["REFUTES"]


# --- review findings: never refute a length that was not measured (P4) ---------------------


def _link(ref: str, owner: str = "nikasha-demo", repo: str = "libhdr") -> Permalink:
    return Permalink(
        host="github.com",
        owner=owner,
        repo=repo,
        ref=ref,
        path="src/util.c",
        start_line=9999,
        url=f"https://github.com/{owner}/{repo}/blob/{ref}/src/util.c#L9999",
    )


def test_permalink_pinned_to_another_ref_is_not_refuted(make_ctx: MakeContext) -> None:
    c = claim(LineClaim, path="src/util.c", line=9999, permalink=_link("v1.0.0"))
    (evidence,) = _run(make_ctx, [c])
    assert evidence.outcome == "NEUTRAL"
    assert evidence.details["outcome"] == "permalink_elsewhere"


def test_permalink_into_another_repository_is_not_refuted(make_ctx: MakeContext) -> None:
    c = claim(LineClaim, path="src/util.c", line=9999, permalink=_link("v1.2.0", owner="other"))
    (evidence,) = _run(make_ctx, [c])
    assert evidence.outcome == "NEUTRAL"
    assert evidence.details["permalink"] == "other/libhdr@v1.2.0"


def test_permalink_at_the_target_ref_is_still_judged(make_ctx: MakeContext) -> None:
    c = claim(LineClaim, path="src/util.c", line=9999, permalink=_link("v1.2.0"))
    (evidence,) = _run(make_ctx, [c])
    assert evidence.outcome == "REFUTES"


def test_basename_only_match_is_not_judged_against_another_file(make_ctx: MakeContext) -> None:
    ctx = make_ctx(claims=[], tag="v1.2.0")
    assert ctx.resolve_path("tests/fuzz/util.c") == ["src/util.c"]  # the trie's basename match
    assert _run(make_ctx, [claim(LineClaim, path="tests/fuzz/util.c", line=9999)]) == []


@pytest.mark.parametrize("cited", ["/home/alice/libhdr/src/util.c", "../../src/util.c"])
def test_machine_prefixed_and_dotdot_paths_are_judged(make_ctx: MakeContext, cited: str) -> None:
    ctx = make_ctx(claims=[], tag="v1.2.0")
    assert ctx.resolve_path(cited) == ["src/util.c"]
    (evidence,) = _run(make_ctx, [claim(LineClaim, path=cited, line=10)])
    assert evidence.outcome == "SUPPORTS"
    assert evidence.details["outcome"] == "in_bounds"
    assert evidence.details["path"] == "src/util.c"
    (past,) = _run(make_ctx, [claim(LineClaim, path=cited, line=9999)])
    assert past.outcome == "REFUTES"
    assert past.details["outcome"] == "past_end"


@pytest.mark.parametrize(
    ("real", "cited", "expected"),
    [
        ("src/util.c", "util.c", True),
        ("src/util.c", "src/util.c", True),
        ("src/util.c", "/home/alice/libhdr/src/util.c", True),
        ("src/util.c", "../../src/util.c", True),
        ("src/util.c", "C:\\work\\libhdr\\src\\util.c", True),
        ("src/util.c", "tests/fuzz/util.c", False),
        ("src/util.c", "/home/alice/lib/util.c", False),
        ("src/util.c", "src/other.c", False),
        ("src/util.c", "", False),
    ],
)
def test_suffix_matches(real: str, cited: str, expected: bool) -> None:
    assert c04._suffix_matches(real, cited) is expected


def test_symlink_is_not_refuted_as_a_one_line_file(
    make_ctx: MakeContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    c = claim(LineClaim, path="src/util.c", line=9999)
    ctx = make_ctx(claims=[c], tag="v1.2.0")
    real = ctx.resolution.repo.ls_tree(ctx.commit)
    fake = [
        TreeEntry(e.path, e.sha, e.size, "120000" if e.path == "src/util.c" else e.mode)
        for e in real
    ]
    monkeypatch.setattr(c04, "_MODES", {})
    monkeypatch.setattr(type(ctx.resolution.repo), "ls_tree", lambda self, rev: fake)
    (evidence,) = LineInBounds().run(ctx, [c])
    assert evidence.outcome == "NEUTRAL"
    assert evidence.details == {
        "outcome": "not_regular_file",
        "path": "src/util.c",
        "line": 9999,
        "mode": "120000",
    }


def test_same_past_end_line_cited_twice_is_one_refutation(make_ctx: MakeContext) -> None:
    a = claim(LineClaim, path="src/util.c", line=9999)
    b = claim(LineClaim, path="util.c", line=9999, function_hint="util_copy_value")
    evidence = _run(make_ctx, [a, b])
    assert len(evidence) == 1
    assert evidence[0].outcome == "REFUTES"
    assert evidence[0].claim_ids == tuple(sorted({a.id, b.id}))
    assert evidence[0].details["cited_as"] == ["src/util.c", "util.c"]
