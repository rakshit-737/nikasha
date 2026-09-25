# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""C02 FILE_EXISTS, against the real vulnlab history (SPEC §12)."""

from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from check_helpers import TAGS, MakeContext, claim

from nikasha.checks.base import CheckContext, run_checks
from nikasha.checks.c02_file_exists import FileExists
from nikasha.code.gitio import GitRepo, HistoryUnavailableError
from nikasha.model.claims import Claim, FileClaim, Frame, LineClaim, Stack, TraceClaim
from nikasha.model.evidence import Evidence
from nikasha.resolve.refs import ReleaseList

#: A path that no vulnlab release has and whose name appears in no commit.
INVENTED = "src/hdr_crypto.c"


def _run(make_ctx: MakeContext, claims: list[Claim], tag: str = "v1.2.0") -> list[Evidence]:
    ctx = make_ctx(claims=claims, tag=tag)
    return FileExists().run(ctx, claims)


def _before_the_first_release(ctx: CheckContext) -> CheckContext:
    """The same context moved to the initial commit, which predates ``README``.

    Every tagged release carries ``README``; the first commit does not. That is the one
    real "missing here, present in other releases" case the vulnlab history offers.
    """
    first = ctx.resolution.repo.rev_parse("v1.0.0~1")
    assert first is not None
    target = ctx.resolution.target.model_copy(update={"commit": first, "ref_name": None})
    return CheckContext(
        report=ctx.report,
        claims=ctx.claims,
        resolution=replace(ctx.resolution, target=target, release=None),
        index=ctx.index,
    )


def test_a_path_in_the_tree_supports(make_ctx: MakeContext) -> None:
    c = claim(FileClaim, path="src/util.c")
    (evidence,) = _run(make_ctx, [c])
    assert evidence.outcome == "SUPPORTS"
    assert evidence.strength == 0.5
    assert evidence.check_id == "C02"
    assert evidence.group == "locus"
    assert evidence.claim_ids == (c.id,)
    assert evidence.details["matched"] == "src/util.c"
    assert "v1.2.0" in evidence.summary


def test_evidence_points_at_the_file_at_the_exact_commit(make_ctx: MakeContext) -> None:
    ctx = make_ctx(claims=[claim(FileClaim, path="src/util.c")])
    (evidence,) = FileExists().run(ctx, list(ctx.claims))
    (location,) = evidence.locations
    assert location.commit == ctx.commit
    assert location.path == "src/util.c"
    assert location.permalink is not None
    assert location.permalink.endswith("/blob/" + ctx.commit + "/src/util.c#L1")


def test_a_reporters_build_root_is_normalized_away(make_ctx: MakeContext) -> None:
    c = claim(FileClaim, path="/home/fuzz/build/libhdr/src/util.c")
    (evidence,) = _run(make_ctx, [c])
    assert evidence.outcome == "SUPPORTS"
    assert evidence.details["matched"] == "src/util.c"
    assert evidence.details["cited_as"] == "/home/fuzz/build/libhdr/src/util.c"
    assert evidence.details["matched_components"] == 2


def test_a_line_claims_path_is_checked(make_ctx: MakeContext) -> None:
    (evidence,) = _run(make_ctx, [claim(LineClaim, path="src/hdr.c", line=10)])
    assert evidence.outcome == "SUPPORTS"
    assert evidence.details["matched"] == "src/hdr.c"


def test_a_pathless_or_empty_path_claim_produces_nothing(make_ctx: MakeContext) -> None:
    assert _run(make_ctx, [claim(LineClaim, path=None, line=3)]) == []
    assert _run(make_ctx, [claim(FileClaim, path="../..")]) == []


class TestTraceFrames:
    """Every app frame is a path claim; runtime frames name files this repo never had."""

    def _trace(self) -> TraceClaim:
        return claim(
            TraceClaim,
            format="asan",
            bug_type="heap-buffer-overflow",
            frames=(
                Frame(index=0, function="util_copy_value", path="src/util.c", line=42, raw="#0"),
                Frame(index=1, function="hdr_parse_line", path="src/util.c", line=50, raw="#1"),
                Frame(index=2, function="hdr_parse_block", path="src/hdr.c", line=88, raw="#2"),
                Frame(index=3, function="__libc_start_main", path="/build/csu/libc.c",
                      is_runtime=True, raw="#3"),
            ),
            alloc_frames=(
                Frame(index=0, function="hdr_alloc", path=INVENTED, line=7, raw="#0"),
            ),
            other_stacks=(
                Stack(
                    label="previous write",
                    frames=(Frame(index=0, path="include/hdr.h", line=3, raw="#0"),),
                ),
            ),
        )  # fmt: skip

    def test_one_finding_per_app_file_in_frame_order(self, make_ctx: MakeContext) -> None:
        evidence = _run(make_ctx, [self._trace()])
        assert [e.details["path"] for e in evidence] == [
            "src/util.c",
            "src/hdr.c",
            INVENTED,
            "include/hdr.h",
        ]

    def test_runtime_frames_are_not_judged(self, make_ctx: MakeContext) -> None:
        evidence = _run(make_ctx, [self._trace()])
        assert not any("libc.c" in e.summary for e in evidence)

    def test_an_invented_path_in_the_allocation_stack_is_refuted(
        self, make_ctx: MakeContext
    ) -> None:
        found = [e for e in _run(make_ctx, [self._trace()]) if e.details["path"] == INVENTED]
        assert [e.outcome for e in found] == ["REFUTES"]
        assert found[0].strength == -2.0


def test_missing_here_but_present_in_other_releases(make_ctx: MakeContext) -> None:
    c = claim(FileClaim, path="README")
    ctx = _before_the_first_release(make_ctx(claims=[c]))
    (evidence,) = FileExists().run(ctx, [c])
    assert evidence.outcome == "REFUTES"
    assert evidence.strength == -0.8
    assert evidence.details["present_in"] == list(TAGS)
    assert evidence.details["present_as"] == ["README"]
    assert "v1.3.0" in evidence.details["version_note"]
    assert "not in the tree" in evidence.summary


def test_a_path_never_in_any_release_or_in_history_is_refuted(make_ctx: MakeContext) -> None:
    (evidence,) = _run(make_ctx, [claim(FileClaim, path=INVENTED)])
    assert evidence.outcome == "REFUTES"
    assert evidence.strength == -2.0
    assert evidence.details["never_in_history"] is True
    assert evidence.details["history_complete"] is True
    assert evidence.details["sampled_releases"] == len(TAGS)
    assert "nowhere in history" in evidence.summary


def test_a_core_claim_multiplies_the_never_in_history_strength(make_ctx: MakeContext) -> None:
    (evidence,) = _run(make_ctx, [claim(FileClaim, path=INVENTED, role="core")])
    assert evidence.strength == -3.0
    assert evidence.details["core_claim"] is True


def test_a_generated_file_is_never_judged(make_ctx: MakeContext) -> None:
    (evidence,) = _run(make_ctx, [claim(FileClaim, path="src/config.h")])
    assert evidence.outcome == "NEUTRAL"
    assert evidence.strength == 0.0
    assert evidence.details["generated"] == "generated"
    assert "not in source control" in evidence.summary
    assert "withheld_strength" not in evidence.details


class TestP4AbsenceIsNeverAssumed:
    """A "never existed" verdict needs a finished scan *and* a finished history search."""

    def test_a_timed_out_history_search_downgrades_the_refutation(
        self, make_ctx: MakeContext
    ) -> None:
        ctx = make_ctx(claims=[claim(FileClaim, path=INVENTED)])
        ctx.history_timeout = 1e-6  # no git process can finish in a microsecond
        (evidence,) = FileExists().run(ctx, list(ctx.claims))
        # Was REFUTES -0.8 keyed "missing_here_present_elsewhere", which fusion reads as a
        # version mismatch although no other version was found. A timeout establishes
        # nothing, so it carries no weight and a label that is not a table key.
        assert evidence.outcome == "NEUTRAL"
        assert evidence.strength == 0.0
        assert evidence.details["outcome"] == "absence_not_established"
        assert evidence.details["history_complete"] is False
        assert "never_in_history" not in evidence.details
        assert "absence is not established" in evidence.summary
        assert "timed out" in evidence.details["history_note"]

    def test_a_failed_pickaxe_is_not_called_a_timeout(
        self, make_ctx: MakeContext, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """P6: HistoryUnavailableError subclasses the timeout error but is not a timeout."""
        ctx = make_ctx(claims=[claim(FileClaim, path=INVENTED)])

        def pickaxe(name: str, **_: Any) -> str | None:
            raise HistoryUnavailableError("git was not found on PATH")

        monkeypatch.setattr(ctx.resolution.repo, "pickaxe_first", pickaxe)
        (evidence,) = FileExists().run(ctx, list(ctx.claims))
        assert evidence.outcome == "NEUTRAL"
        assert evidence.details["history_complete"] is False
        note = evidence.details["history_note"]
        assert "failed" in note
        assert "not found" in note
        assert "timed out" not in note

    def test_an_exhausted_budget_downgrades_the_refutation(self, make_ctx: MakeContext) -> None:
        ctx = make_ctx(claims=[claim(FileClaim, path=INVENTED)])
        ctx.deadline = time.monotonic() - 1.0
        (evidence,) = FileExists().run(ctx, list(ctx.claims))
        # Was REFUTES -0.8 with a version-mismatch key (see the test above). How far a cut
        # scan got depends on the clock, so the finding says so and nothing else (P2).
        assert evidence.outcome == "NEUTRAL"
        assert evidence.strength == 0.0
        assert evidence.details == {
            "outcome": "budget_expired",
            "path": INVENTED,
            "release_scan_complete": False,
        }
        assert "time budget ran out" in evidence.summary

    def test_a_name_history_knows_is_not_called_never_existed(self, make_ctx: MakeContext) -> None:
        # build/libhdr.a is in no release tree, but the Makefile names it, so log -S finds
        # it. A build artifact is exactly the kind of path a genuine report cites.
        (evidence,) = _run(make_ctx, [claim(FileClaim, path="build/libhdr.a")])
        assert evidence.outcome == "REFUTES"
        assert evidence.strength == -0.8
        assert evidence.details["history_complete"] is True
        assert "never_in_history" not in evidence.details
        assert len(evidence.details["first_commit_with_name"]) == 40
        assert "appears in history" in evidence.details["history_note"]


class TestRefutationGate:
    """ADR 0003: only project-attributed, non-negated claims may be refuted."""

    def test_reporter_artifact_is_not_refuted(self, make_ctx: MakeContext) -> None:
        c = claim(FileClaim, path=INVENTED, provenance="reporter_artifact")
        (evidence,) = _run(make_ctx, [c])
        assert evidence.outcome == "NEUTRAL"
        assert evidence.strength == 0.0
        assert evidence.details["gated"] == ["reporter_artifact"]
        assert evidence.details["withheld_strength"] == -2.0

    def test_negated_claim_is_not_refuted(self, make_ctx: MakeContext) -> None:
        c = claim(FileClaim, path=INVENTED, negated=True)
        (evidence,) = _run(make_ctx, [c])
        assert evidence.outcome == "NEUTRAL"
        assert evidence.details["gated"] == ["negated"]

    def test_support_is_not_gated(self, make_ctx: MakeContext) -> None:
        c = claim(FileClaim, path="src/util.c", provenance="third_party")
        (evidence,) = _run(make_ctx, [c])
        assert evidence.outcome == "SUPPORTS"


def test_identical_input_gives_identical_evidence(make_ctx: MakeContext) -> None:
    c = claim(FileClaim, path=INVENTED)
    first = _run(make_ctx, [c])
    second = _run(make_ctx, [c])
    assert [e.id for e in first] == [e.id for e in second]
    assert first[0].model_dump() == second[0].model_dump()


def test_registered_and_runnable_through_the_runner(make_ctx: MakeContext) -> None:
    ctx = make_ctx(claims=[claim(FileClaim, path=INVENTED)])
    (run,) = run_checks(ctx, checks=[FileExists()])
    assert run.check_id == "C02"
    assert run.error is None
    assert run.seconds >= 0.0
    assert [e.outcome for e in run.evidence] == ["REFUTES"]


def _git(repo: Path, *args: str, stdin: bytes | None = None) -> str:
    """Test-only plumbing on a private copy of vulnlab (never on the shared fixture)."""
    identity = ("-c", "user.name=Nikasha Tests", "-c", "user.email=tests@nikasha.invalid")
    out = subprocess.run(
        ["git", *identity, f"--git-dir={repo}", *args],
        input=stdin,
        capture_output=True,
        check=True,
    )
    return out.stdout.decode().strip()


def _on_copy(ctx: CheckContext, vulnlab_repo: Path, tmp_path: Path) -> tuple[CheckContext, Path]:
    copy = tmp_path / "copy.git"
    shutil.copytree(vulnlab_repo, copy)
    resolution = replace(ctx.resolution, repo=GitRepo(copy))
    return replace(ctx, resolution=resolution), copy


class TestHistoryIsSearchedByPath:
    """log -S reads file contents only; a file whose name nothing spells out is still real."""

    def test_a_file_only_on_a_branch_is_not_called_never_existed(
        self, make_ctx: MakeContext, vulnlab_repo: Path, tmp_path: Path
    ) -> None:
        c = claim(FileClaim, path="src/zz_dev_only.c", role="core")
        ctx, copy = _on_copy(make_ctx(claims=[c]), vulnlab_repo, tmp_path)
        blob = _git(copy, "hash-object", "-w", "--stdin", stdin=b"int x;\n")
        tree = _git(copy, "mktree", stdin=f"100644 blob {blob}\tzz_dev_only.c\n".encode())
        commit = _git(copy, "commit-tree", tree, "-m", "dev")
        _git(copy, "update-ref", "refs/heads/dev", commit)
        (evidence,) = FileExists().run(ctx, [c])
        assert evidence.details["outcome"] != "never_in_history"
        assert evidence.strength == -0.8
        assert evidence.details["first_commit_with_name"] == commit

    def test_a_failed_history_search_is_not_a_complete_one(
        self, make_ctx: MakeContext, vulnlab_repo: Path, tmp_path: Path
    ) -> None:
        c = claim(FileClaim, path=INVENTED, role="core")
        ctx, copy = _on_copy(make_ctx(claims=[c]), vulnlab_repo, tmp_path)
        (copy / "refs" / "heads" / "broken").write_text("1" * 40 + "\n")
        (evidence,) = FileExists().run(ctx, [c])
        assert evidence.outcome == "NEUTRAL"
        assert evidence.details["outcome"] == "absence_not_established"
        assert evidence.details["history_complete"] is False
        assert "failed" in evidence.details["history_note"]


def test_a_system_header_frame_is_not_refuted(make_ctx: MakeContext) -> None:
    header = "/usr/include/x86_64-linux-gnu/bits/string_fortified.h"
    trace = claim(
        TraceClaim,
        format="asan",
        bug_type="heap-buffer-overflow",
        frames=(
            Frame(index=0, function="memcpy", path=header, line=29, raw="#0"),
            Frame(index=1, function="util_copy_value", path="src/util.c", line=15, raw="#1"),
        ),
    )
    evidence = _run(make_ctx, [trace])
    assert [e.outcome for e in evidence] == ["NEUTRAL", "SUPPORTS"]
    assert evidence[0].details["outcome"] == "outside_repository"
    assert evidence[0].strength == 0.0


def test_an_oversized_frame_name_does_not_reach_the_argv(make_ctx: MakeContext) -> None:
    long_path = "/build/" + "a" * 140_000 + ".c"
    trace = claim(
        TraceClaim,
        format="asan",
        bug_type="heap-buffer-overflow",
        frames=(Frame(index=0, function="f", path=long_path, line=1, raw="#0"),),
    )
    (evidence,) = _run(make_ctx, [trace])
    assert evidence.outcome == "NEUTRAL"
    assert evidence.details["outcome"] == "absence_not_established"
    assert "cannot be searched" in evidence.details["history_note"]


def test_no_final_release_means_no_never_existed(make_ctx: MakeContext) -> None:
    c = claim(FileClaim, path=INVENTED, role="core")
    ctx = make_ctx(claims=[c])
    ctx = replace(ctx, resolution=replace(ctx.resolution, releases=ReleaseList.from_tags([])))
    (evidence,) = FileExists().run(ctx, [c])
    assert evidence.outcome == "NEUTRAL"
    assert evidence.details["sampled_releases"] == 0
    assert "never_in_history" not in evidence.details


def test_a_basename_match_elsewhere_is_not_called_the_cited_path(
    make_ctx: MakeContext,
) -> None:
    c = claim(FileClaim, path="docs/README")
    ctx = _before_the_first_release(make_ctx(claims=[c]))
    (evidence,) = FileExists().run(ctx, [c])
    assert evidence.details["present_as"] == ["README"]
    assert "but a file named README is in" in evidence.summary
    assert evidence.details["version_note"].startswith("a file named README exists in")


def test_one_path_cited_by_two_claims_is_one_finding(make_ctx: MakeContext) -> None:
    file_claim = claim(FileClaim, path=INVENTED)
    line_claim = claim(LineClaim, path=INVENTED, line=10)
    (evidence,) = _run(make_ctx, [file_claim, line_claim])
    assert evidence.claim_ids == tuple(sorted({file_claim.id, line_claim.id}))
    assert evidence.strength == -2.0
