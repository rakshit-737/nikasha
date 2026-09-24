# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""C12 PATCH_APPLIES, against the real vulnlab tree (SPEC §12).

Every in-memory verdict that says "this applies" is cross-checked against real
``git apply --check`` in a throwaway worktree, because an applier that only agrees with
itself proves nothing. ``subprocess`` is allowed *here*: production code applies hunks in
memory and never spawns anything.
"""

from __future__ import annotations

import subprocess
import time
from pathlib import Path

from check_helpers import REPORTS, MakeContext, claim

from nikasha.checks.base import run_checks
from nikasha.checks.c12_patch_applies import (
    OFFSET_RADIUS,
    PatchApplies,
    _local_match,
    _sides,
    _to_lines,
    _try_side,
)
from nikasha.extract import extract_claims
from nikasha.extract.patches import parse_with_unidiff
from nikasha.ingest import load_report
from nikasha.model.claims import PatchClaim

# --- fixtures written against the real v1.2.0 tree ------------------------------------------

#: src/util.c lines 13-17 at v1.2.0, with the missing bounds check added. Applies exactly.
CLEAN_FIX = r"""--- a/src/util.c
+++ b/src/util.c
@@ -13,5 +13,7 @@ char *util_copy_value(const char *value)
     if (dst == NULL)
         return NULL;
+    if (len >= HDR_VALUE_MAX)
+        len = HDR_VALUE_MAX - 1;
     memcpy(dst, value, len);
     dst[len] = '\0';
     return dst;
"""

#: The same fix, cited 100 lines too far down: found by the offset search.
OFFSET_FIX = CLEAN_FIX.replace("@@ -13,5 +13,7 @@", "@@ -113,5 +113,7 @@")

#: The same fix cited 487 lines away: outside the offset search, but plainly in the file.
FAR_FIX = CLEAN_FIX.replace("@@ -13,5 +13,7 @@", "@@ -500,5 +500,7 @@")

#: The same fix whose first and last context lines were retyped from memory: fuzz 1 finds it.
FUZZY_FIX = r"""--- a/src/util.c
+++ b/src/util.c
@@ -13,5 +13,7 @@ char *util_copy_value(const char *value)
     if (dst == 0)
         return NULL;
+    if (len >= HDR_VALUE_MAX)
+        len = HDR_VALUE_MAX - 1;
     memcpy(dst, value, len);
     dst[len] = '\0';
     return dst; /* the copy */
"""

#: Touches hdr_get(), which v1.3.0 renamed to hdr_find(). The changed line cannot be fuzzed
#: away, so this hunk can only ever apply to the releases that still have hdr_get().
HDR_GET_FIX = r"""--- a/src/hdr.c
+++ b/src/hdr.c
@@ -145,4 +145,4 @@
-const char *hdr_get(const hdr_list *list, const char *name)
+const char *hdr_get(const hdr_list *list, const char *name, int flags)
 {
     char key[HDR_NAME_MAX];
     int idx;
"""

#: A well-formed diff whose context was invented (the fixture report's fabricated patch,
#: rewritten with honest hunk counts so real git apply parses it).
INVENTED = r"""--- a/src/hdr.c
+++ b/src/hdr.c
@@ -410,2 +410,4 @@ static int hdr_decode_chunked_value(hdr_ctx *ctx, const char *in, size_t n)
     char tmp[64];
+    if (n > sizeof(tmp))
+        return HDR_ERR_TOO_LONG;
     memcpy(tmp, in + ctx->chunk_off, n);
"""

#: A patch against a file that is in no release.
MISSING_FILE = r"""--- a/src/nope.c
+++ b/src/nope.c
@@ -1,2 +1,3 @@
 int nope(void)
 {
+    return 1;
"""


def patch(diff: str, **fields: object) -> PatchClaim:
    """A claim carrying ``diff``, with the hunks the real extractor parses out of it."""
    parsed = parse_with_unidiff(diff)
    assert parsed is not None, diff
    files, hunks = parsed
    return claim(PatchClaim, text=diff, diff=diff, files=tuple(files), hunks=tuple(hunks), **fields)


def report_patch(name: str) -> PatchClaim:
    """The one patch claim of an ``examples/reports`` fixture, straight from the pipeline."""
    extraction = extract_claims(load_report(REPORTS / name), product="libhdr")
    claims = [c for c in extraction.claims if isinstance(c, PatchClaim)]
    assert len(claims) == 1, claims
    return claims[0]


def _run(make_ctx: MakeContext, claimed: PatchClaim, tag: str = "v1.2.0") -> list:
    ctx = make_ctx(claims=[claimed], tag=tag)
    return PatchApplies().run(ctx, [claimed])


# --- the ladder -----------------------------------------------------------------------------


def test_a_fix_that_applies_exactly_supports(make_ctx: MakeContext) -> None:
    claimed = patch(CLEAN_FIX)
    (evidence,) = _run(make_ctx, claimed)
    assert evidence.outcome == "SUPPORTS"
    assert evidence.strength == 1.5
    assert evidence.check_id == "C12"
    assert evidence.group == "patch"
    assert evidence.claim_ids == (claimed.id,)
    assert evidence.details["status"] == "applies_clean"
    assert evidence.details["files"] == ["src/util.c"]
    assert evidence.details["hunks"] == [
        {
            "path": "src/util.c",
            "source_start": 13,
            "status": "applies_clean",
            "line": 13,
            "offset": 0,
            "fuzz": 0,
        }
    ]


def test_a_hunk_cited_at_the_wrong_line_is_found_by_the_offset_search(
    make_ctx: MakeContext,
) -> None:
    (evidence,) = _run(make_ctx, patch(OFFSET_FIX))
    assert evidence.outcome == "SUPPORTS"
    assert evidence.strength == 0.6
    assert evidence.details["status"] == "applies_with_fuzz"
    assert evidence.details["hunks"][0]["offset"] == -100
    assert evidence.details["hunks"][0]["fuzz"] == 0
    assert "offset -100" in evidence.summary


def test_mistyped_context_lines_are_forgiven_by_fuzz(make_ctx: MakeContext) -> None:
    (evidence,) = _run(make_ctx, patch(FUZZY_FIX))
    assert evidence.outcome == "SUPPORTS"
    assert evidence.strength == 0.6
    assert evidence.details["hunks"][0]["fuzz"] == 1
    assert evidence.details["hunks"][0]["line"] == 13
    assert "fuzz 1" in evidence.summary


def test_evidence_carries_a_location_at_the_exact_commit(make_ctx: MakeContext) -> None:
    ctx = make_ctx(claims=[patch(CLEAN_FIX)])
    (evidence,) = PatchApplies().run(ctx, list(ctx.claims))
    (location,) = evidence.locations
    assert location.commit == ctx.commit
    assert location.path == "src/util.c"
    assert location.permalink is not None
    assert location.permalink.endswith("/blob/" + ctx.commit + "/src/util.c#L13-L17")


# --- already applied (P4: the commonest reason a real fix does not apply) --------------------


def test_the_reporters_fix_is_already_applied_at_the_release_they_target(
    make_ctx: MakeContext,
) -> None:
    claimed = report_patch("already_fixed.md")
    (evidence,) = _run(make_ctx, claimed, tag="v1.3.0")
    assert evidence.outcome == "NEUTRAL"
    assert evidence.strength == 0.0
    assert evidence.details["status"] == "already_applied"
    assert evidence.details["note"] == "possibly already fixed at the ref"
    assert "possibly already fixed at the ref" in evidence.summary
    assert evidence.details["hunks"][0]["line"] == 26


def test_the_same_patch_applies_cleanly_to_the_release_that_still_has_the_bug(
    make_ctx: MakeContext,
) -> None:
    (evidence,) = _run(make_ctx, report_patch("already_fixed.md"), tag="v1.2.1")
    assert evidence.outcome == "SUPPORTS"
    assert evidence.strength == 1.5
    assert evidence.details["status"] == "applies_clean"


def test_fuzz_would_have_applied_the_already_applied_patch_a_second_time(
    make_ctx: MakeContext,
) -> None:
    """Why the reverse patch is tried before fuzz: fuzz alone would call this a live bug."""
    claimed = report_patch("already_fixed.md")
    ctx = make_ctx(claims=[claimed], tag="v1.3.0")
    blob = ctx.resolution.repo.read_file(ctx.commit, "src/util.c")
    assert blob is not None
    hunk = claimed.hunks[0]
    source, _target, lead, trail = _sides(hunk)
    fuzzed = _try_side(
        _to_lines(blob),
        source,
        lead,
        trail,
        hunk.source_start,
        fuzz_levels=(1, 2),
        radius=OFFSET_RADIUS,
    )
    assert fuzzed is not None, "the fuzz rung must be the thing the reverse check outranks"


# --- refutations ----------------------------------------------------------------------------


def test_a_patch_that_only_fits_other_releases_is_refuted_weakly(make_ctx: MakeContext) -> None:
    (evidence,) = _run(make_ctx, patch(HDR_GET_FIX), tag="v1.3.0")
    assert evidence.outcome == "REFUTES"
    assert evidence.strength == -0.4
    assert evidence.details["status"] == "other_release_only"
    assert evidence.details["hunks"][0]["releases"] == ["v1.0.0", "v1.1.0", "v1.2.0", "v1.2.1"]
    assert evidence.details["search_complete"] is True
    assert "v1.2.0" in evidence.summary


def test_the_same_patch_applies_where_that_function_still_exists(make_ctx: MakeContext) -> None:
    (evidence,) = _run(make_ctx, patch(HDR_GET_FIX), tag="v1.2.0")
    assert evidence.outcome == "SUPPORTS"
    assert evidence.details["status"] == "applies_clean"


def test_invented_context_is_refuted(make_ctx: MakeContext) -> None:
    (evidence,) = _run(make_ctx, patch(INVENTED))
    assert evidence.outcome == "REFUTES"
    assert evidence.strength == -1.8
    assert evidence.details["status"] == "context_not_found"
    assert evidence.details["searched_releases"] == ["v1.0.0", "v1.1.0", "v1.2.1", "v1.3.0"]
    assert "src/hdr.c:410" in evidence.summary


def test_the_fabricated_reports_own_patch_is_refuted(make_ctx: MakeContext) -> None:
    """The fixture report's malformed diff, parsed by the lenient path (SPEC Appendix B)."""
    (evidence,) = _run(make_ctx, report_patch("fabricated_hdr_overflow.md"))
    assert evidence.outcome == "REFUTES"
    assert evidence.strength == -1.8
    assert evidence.details["status"] == "context_not_found"


# --- P4 safeguards --------------------------------------------------------------------------


def test_a_misnumbered_hunk_is_not_called_fabricated(make_ctx: MakeContext) -> None:
    """The context is right there in the file; only the line number is wrong."""
    (evidence,) = _run(make_ctx, patch(FAR_FIX))
    assert evidence.outcome == "NEUTRAL"
    assert evidence.strength == 0.0
    assert evidence.details["status"] == "context_elsewhere_in_file"
    assert evidence.details["hunks"][0]["line"] == 13
    assert f"more than {OFFSET_RADIUS} lines" in evidence.summary


def test_an_unfinished_release_search_is_never_a_refutation(make_ctx: MakeContext) -> None:
    claimed = patch(INVENTED)
    ctx = make_ctx(claims=[claimed])
    ctx.deadline = time.monotonic()  # the budget is already spent
    (evidence,) = PatchApplies().run(ctx, [claimed])
    assert evidence.outcome == "NEUTRAL"
    assert evidence.strength == 0.0
    assert evidence.details["status"] == "search_incomplete"
    assert evidence.details["search_complete"] is False
    assert "did not finish" in evidence.summary


def test_a_file_that_is_in_no_release_is_left_to_c02(make_ctx: MakeContext) -> None:
    (evidence,) = _run(make_ctx, patch(MISSING_FILE))
    assert evidence.outcome == "NEUTRAL"
    assert evidence.strength == 0.0
    assert evidence.details["status"] == "file_missing"
    assert evidence.details["hunks"][0]["reason"] == "not in the tree"


def test_a_diff_with_no_hunks_produces_nothing(make_ctx: MakeContext) -> None:
    empty = claim(PatchClaim, text="x", diff="not a diff", files=(), hunks=())
    assert _run(make_ctx, empty) == []


class TestRefutationGate:
    """ADR 0003: only project-attributed, non-negated claims may be refuted."""

    def test_reporter_artifact_is_not_refuted(self, make_ctx: MakeContext) -> None:
        (evidence,) = _run(make_ctx, patch(INVENTED, provenance="reporter_artifact"))
        assert evidence.outcome == "NEUTRAL"
        assert evidence.strength == 0.0
        assert evidence.details["gated"] == ["reporter_artifact"]
        assert evidence.details["withheld_strength"] == -1.8

    def test_negated_claim_is_not_refuted(self, make_ctx: MakeContext) -> None:
        (evidence,) = _run(make_ctx, patch(INVENTED, negated=True))
        assert evidence.outcome == "NEUTRAL"
        assert evidence.details["gated"] == ["negated"]

    def test_support_is_not_gated(self, make_ctx: MakeContext) -> None:
        (evidence,) = _run(make_ctx, patch(CLEAN_FIX, provenance="third_party"))
        assert evidence.outcome == "SUPPORTS"
        assert evidence.strength == 1.5


# --- determinism and registration -----------------------------------------------------------


def test_identical_input_gives_identical_evidence(make_ctx: MakeContext) -> None:
    claimed = patch(CLEAN_FIX)
    first = _run(make_ctx, claimed)
    second = _run(make_ctx, claimed)
    assert [e.id for e in first] == [e.id for e in second]
    assert first[0].model_dump() == second[0].model_dump()


def test_registered_and_runnable_through_the_runner(make_ctx: MakeContext) -> None:
    ctx = make_ctx(claims=[patch(INVENTED)])
    (run,) = run_checks(ctx, checks=[PatchApplies()])
    assert run.check_id == "C12"
    assert run.error is None
    assert run.seconds >= 0.0
    assert [e.outcome for e in run.evidence] == ["REFUTES"]


def test_only_patch_claims_are_handled() -> None:
    assert PatchApplies().applies_to == frozenset({"patch"})


# --- cross-check against real git apply ------------------------------------------------------


def git_apply_check(
    repo: Path, tag: str, paths: list[str], diff: str, work: Path, *, reverse: bool = False
) -> bool:
    """Whether ``git apply --check`` accepts ``diff`` against the blobs at ``tag``."""
    work.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q"], cwd=work, check=True, capture_output=True)
    for path in paths:
        blob = subprocess.run(
            ["git", "cat-file", "blob", f"{tag}:{path}"], cwd=repo, check=True, capture_output=True
        ).stdout
        dest = work / path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(blob)
    argv = ["git", "-c", "core.autocrlf=false", "apply", "--check"]
    if reverse:
        argv.append("--reverse")
    done = subprocess.run(argv, cwd=work, input=diff.encode(), capture_output=True, check=False)
    return done.returncode == 0


class TestAgainstGitApply:
    """SPEC §12: the in-memory result must agree with the real thing."""

    def test_a_clean_apply_is_a_clean_apply_for_git_too(
        self, make_ctx: MakeContext, vulnlab_repo: Path, tmp_path: Path
    ) -> None:
        (evidence,) = _run(make_ctx, patch(CLEAN_FIX))
        assert evidence.details["status"] == "applies_clean"
        assert git_apply_check(vulnlab_repo, "v1.2.0", ["src/util.c"], CLEAN_FIX, tmp_path)

    def test_git_finds_the_offset_hunk_as_well(
        self, make_ctx: MakeContext, vulnlab_repo: Path, tmp_path: Path
    ) -> None:
        (evidence,) = _run(make_ctx, patch(OFFSET_FIX))
        assert evidence.details["status"] == "applies_with_fuzz"
        assert git_apply_check(vulnlab_repo, "v1.2.0", ["src/util.c"], OFFSET_FIX, tmp_path)

    def test_git_agrees_the_patch_is_already_applied_at_v1_3_0(
        self, make_ctx: MakeContext, vulnlab_repo: Path, tmp_path: Path
    ) -> None:
        claimed = report_patch("already_fixed.md")
        (evidence,) = _run(make_ctx, claimed, tag="v1.3.0")
        assert evidence.details["status"] == "already_applied"
        diff = claimed.diff + "\n"
        assert not git_apply_check(vulnlab_repo, "v1.3.0", ["src/util.c"], diff, tmp_path / "fwd")
        assert git_apply_check(
            vulnlab_repo, "v1.3.0", ["src/util.c"], diff, tmp_path / "rev", reverse=True
        )

    def test_git_rejects_the_patch_that_only_fits_other_releases(
        self, make_ctx: MakeContext, vulnlab_repo: Path, tmp_path: Path
    ) -> None:
        (evidence,) = _run(make_ctx, patch(HDR_GET_FIX), tag="v1.3.0")
        assert evidence.details["status"] == "other_release_only"
        assert not git_apply_check(vulnlab_repo, "v1.3.0", ["src/hdr.c"], HDR_GET_FIX, tmp_path)
        assert git_apply_check(
            vulnlab_repo, "v1.2.0", ["src/hdr.c"], HDR_GET_FIX, tmp_path / "older"
        )

    def test_git_rejects_invented_context_too(
        self, make_ctx: MakeContext, vulnlab_repo: Path, tmp_path: Path
    ) -> None:
        (evidence,) = _run(make_ctx, patch(INVENTED))
        assert evidence.details["status"] == "context_not_found"
        assert not git_apply_check(vulnlab_repo, "v1.2.0", ["src/hdr.c"], INVENTED, tmp_path)

    def test_the_two_documented_disagreements(
        self, make_ctx: MakeContext, vulnlab_repo: Path, tmp_path: Path
    ) -> None:
        """git apply has no fuzz, and searches the whole file rather than +/-200 lines.

        Both differences are deliberate: C12 follows GNU patch, which is what a reporter's
        patch was written for, and neither disagreement turns into a refutation.
        """
        (fuzzy,) = _run(make_ctx, patch(FUZZY_FIX))
        assert fuzzy.details["status"] == "applies_with_fuzz"
        assert not git_apply_check(vulnlab_repo, "v1.2.0", ["src/util.c"], FUZZY_FIX, tmp_path)

        (far,) = _run(make_ctx, patch(FAR_FIX))
        assert far.details["status"] == "context_elsewhere_in_file"
        assert git_apply_check(vulnlab_repo, "v1.2.0", ["src/util.c"], FAR_FIX, tmp_path / "far")


def test_the_matcher_is_the_only_thing_that_touches_the_blob(make_ctx: MakeContext) -> None:
    """A sanity check on the helper the whole check rests on, at the real blob."""
    ctx = make_ctx()
    blob = ctx.resolution.repo.read_file(ctx.commit, "src/util.c")
    assert blob is not None
    hunk = patch(CLEAN_FIX).hunks[0]
    status, match = _local_match(_to_lines(blob), hunk) or ("none", None)
    assert status == "applies_clean"
    assert match is not None
    assert (match.line, match.offset, match.fuzz) == (13, 0, 0)
