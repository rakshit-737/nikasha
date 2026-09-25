# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""C14 OPTION_EXISTS, against the real vulnlab tree (SPEC §12).

``libhdr`` gives every outcome a real shape: ``--fold`` is documented in the README and
implemented in ``tools/hdrcat.c`` at every release, ``HDR_VALUE_MAX`` arrives in v1.1.0,
``hdr_find`` replaces ``hdr_get`` in v1.3.0 (while ``hdr_find_line`` exists throughout, so
a non-word search would find it everywhere), and no release has ever heard of
``--proxy-unsafe-fold``.
"""

from __future__ import annotations

import shutil
import time
from pathlib import Path

from check_helpers import MakeContext, claim

from nikasha.checks.base import CheckContext, run_checks
from nikasha.checks.c14_option_exists import OptionExists, generated_reasons, is_doc
from nikasha.code.gitio import GitRepo
from nikasha.model.claims import OptionClaim
from nikasha.model.evidence import Evidence

INVENTED = "--proxy-unsafe-fold"


def _flag(token: str, **fields: object) -> OptionClaim:
    fields.setdefault("option_kind", "cli_flag")
    return claim(OptionClaim, token=token, **fields)


def _run(make_ctx: MakeContext, claims: list[OptionClaim], tag: str = "v1.2.0") -> list[Evidence]:
    ctx = make_ctx(claims=claims, tag=tag)
    return OptionExists().run(ctx, claims)


def _one(make_ctx: MakeContext, token: str, tag: str = "v1.2.0", **fields: object) -> Evidence:
    (evidence,) = _run(make_ctx, [_flag(token, **fields)], tag=tag)
    return evidence


# --- present at the ref -----------------------------------------------------------------


def test_a_flag_in_the_tree_supports(make_ctx: MakeContext) -> None:
    c = _flag("--fold")
    (evidence,) = _run(make_ctx, [c])
    assert evidence.outcome == "SUPPORTS"
    assert evidence.strength == 0.4
    assert evidence.check_id == "C14"
    assert evidence.group == "locus"
    assert evidence.claim_ids == (c.id,)
    assert evidence.details["token"] == "--fold"
    assert evidence.details["option_kind"] == "cli_flag"


def test_documentation_is_searched_as_well_as_source(make_ctx: MakeContext) -> None:
    evidence = _one(make_ctx, "--fold")
    assert evidence.details["paths"] == ["README", "tools/hdrcat.c"]
    assert evidence.details["documented"] is True


def test_the_recorded_command_keeps_the_token_after_dash_e(make_ctx: MakeContext) -> None:
    """The token is report text: it may only ever reach git as data (SPEC §19.3)."""
    (command,) = _one(make_ctx, "--fold").details["commands"]
    assert "-e --fold" in command
    assert command.startswith("git grep -n -I -F -w -e ")


def test_evidence_points_at_the_matching_lines(make_ctx: MakeContext) -> None:
    ctx = make_ctx(claims=[_flag("--fold")])
    (evidence,) = OptionExists().run(ctx, list(ctx.claims))
    # Four hits, capped at three and ordered by (path, line) so the evidence is stable.
    assert [location.path for location in evidence.locations] == [
        "README",
        "README",
        "tools/hdrcat.c",
    ]
    for location in evidence.locations:
        assert location.commit == ctx.commit
        assert location.excerpt is not None and "--fold" in location.excerpt
        assert location.permalink is not None
        assert location.permalink.endswith(f"#L{location.start_line}")


def test_a_constant_present_at_the_ref_supports(make_ctx: MakeContext) -> None:
    evidence = _one(make_ctx, "HDR_VALUE_MAX", option_kind="constant")
    assert evidence.outcome == "SUPPORTS"
    assert evidence.details["paths"] == ["src/util.c", "src/util.h"]
    assert evidence.details["documented"] is False


# --- present only in other releases -------------------------------------------------------


def test_a_constant_added_later_is_only_in_other_releases(make_ctx: MakeContext) -> None:
    evidence = _one(make_ctx, "HDR_VALUE_MAX", tag="v1.0.0", option_kind="constant")
    assert evidence.outcome == "REFUTES"
    assert evidence.strength == -0.5
    assert evidence.details["releases"] == ["v1.1.0", "v1.2.0", "v1.2.1", "v1.3.0"]
    assert evidence.details["paths"] == ["src/util.c", "src/util.h"]
    assert "v1.0.0" in evidence.summary


def test_the_search_is_word_bounded(make_ctx: MakeContext) -> None:
    """``hdr_find_line`` exists at v1.0.0; ``hdr_find`` itself only arrives in v1.3.0."""
    evidence = _one(make_ctx, "hdr_find", tag="v1.0.0", option_kind="config_key")
    assert evidence.outcome == "REFUTES"
    assert evidence.details["releases"] == ["v1.3.0"]


def test_the_sweep_command_is_recorded_next_to_the_ref_search(make_ctx: MakeContext) -> None:
    commands = _one(make_ctx, "HDR_VALUE_MAX", tag="v1.0.0", option_kind="constant")
    ref_search, sweep = commands.details["commands"]
    assert ref_search.startswith("git grep -n -I -F -w -e HDR_VALUE_MAX ")
    assert sweep == "git grep -l -I -F -w -e HDR_VALUE_MAX v1.1.0 v1.2.0 v1.2.1 v1.3.0"


# --- nowhere in history --------------------------------------------------------------------


def test_an_invented_flag_is_refuted_as_never_in_history(make_ctx: MakeContext) -> None:
    evidence = _one(make_ctx, INVENTED)
    assert evidence.outcome == "REFUTES"
    assert evidence.strength == -2.0
    assert evidence.details["releases_searched"] == 5
    assert evidence.details["history_complete"] is True
    assert INVENTED in evidence.summary
    assert evidence.locations == ()


def test_the_pickaxe_command_is_recorded(make_ctx: MakeContext) -> None:
    commands = _one(make_ctx, INVENTED).details["commands"]
    assert commands[-2:] == [
        f"git log --all -1 -S{INVENTED}",
        f"git log --all -1 -i -S{INVENTED}",
    ]


# --- P4: absence is only absence when the search finished ------------------------------------


class TestIncompleteSearchesNeverSayNever:
    """P4: a search that did not finish is not evidence that the option never existed."""

    def test_an_unfinished_history_search_downgrades_to_neutral(
        self, make_ctx: MakeContext
    ) -> None:
        ctx = make_ctx(claims=[_flag(INVENTED)])
        ctx.history_timeout = 1e-6  # git cannot even start in a microsecond
        (evidence,) = OptionExists().run(ctx, list(ctx.claims))
        assert evidence.outcome == "NEUTRAL"
        assert evidence.strength == 0.0
        assert evidence.details["history_complete"] is False
        assert "did not finish" in evidence.details["incomplete"]
        assert evidence.details["withheld_strength"] == -2.0

    def test_a_shallow_clone_downgrades_to_neutral(
        self, make_ctx: MakeContext, tmp_path: Path, commits: dict[str, str]
    ) -> None:
        ctx = make_ctx(claims=[_flag(INVENTED)])
        shallow_dir = tmp_path / "shallow.git"
        shutil.copytree(ctx.resolution.repo.git_dir, shallow_dir)
        # A `shallow` file is exactly what `rev-parse --is-shallow-repository` looks for.
        (shallow_dir / "shallow").write_text(commits["v1.0.0"] + "\n", encoding="ascii")
        with GitRepo(shallow_dir) as shallow:
            assert shallow.is_shallow()
            ctx.resolution.repo = shallow
            (evidence,) = OptionExists().run(ctx, list(ctx.claims))
        assert evidence.outcome == "NEUTRAL"
        assert "shallow" in evidence.details["incomplete"]
        assert evidence.details["withheld_strength"] == -2.0

    def test_a_spent_budget_withholds_nothing_and_refutes_nothing(
        self, make_ctx: MakeContext
    ) -> None:
        ctx = make_ctx(claims=[_flag(INVENTED)])
        ctx.deadline = time.monotonic() - 1.0
        (evidence,) = OptionExists().run(ctx, list(ctx.claims))
        assert evidence.outcome == "NEUTRAL"
        assert evidence.strength == 0.0
        assert "budget" in evidence.details["incomplete"]
        assert "withheld_strength" not in evidence.details


class TestGeneratedFilesAreNotJudged:
    """SPEC §11.5: a constant seen only in a generated file proves nothing about a release."""

    def test_a_generated_path_gives_a_reason(self, ctx: CheckContext) -> None:
        assert generated_reasons(ctx, ["src/config.h"]) == ["src/config.h: matches 'config.h'"]

    def test_real_code_gives_no_reason(self, ctx: CheckContext) -> None:
        assert generated_reasons(ctx, ["src/util.c"]) == []

    def test_one_real_path_among_generated_ones_is_enough_to_judge(self, ctx: CheckContext) -> None:
        assert generated_reasons(ctx, ["src/config.h", "src/util.c"]) == []


# --- the ADR 0003 refutation gate -----------------------------------------------------------


class TestRefutationGate:
    """Only project-attributed, non-negated claims may be refuted."""

    def test_reporter_artifact_is_not_refuted(self, make_ctx: MakeContext) -> None:
        evidence = _one(make_ctx, INVENTED, provenance="reporter_artifact")
        assert evidence.outcome == "NEUTRAL"
        assert evidence.strength == 0.0
        assert evidence.details["gated"] == ["reporter_artifact"]
        assert evidence.details["withheld_strength"] == -2.0

    def test_negated_claim_is_not_refuted(self, make_ctx: MakeContext) -> None:
        evidence = _one(make_ctx, INVENTED, negated=True)
        assert evidence.outcome == "NEUTRAL"
        assert evidence.details["gated"] == ["negated"]

    def test_support_is_not_gated(self, make_ctx: MakeContext) -> None:
        evidence = _one(make_ctx, "--fold", provenance="third_party")
        assert evidence.outcome == "SUPPORTS"


# --- housekeeping ----------------------------------------------------------------------------


def test_an_unsearchable_token_produces_nothing(make_ctx: MakeContext) -> None:
    assert _run(make_ctx, [_flag("--fold\n--max-lines")]) == []
    assert _run(make_ctx, [_flag("   ")]) == []


def test_every_claim_gets_its_own_evidence(make_ctx: MakeContext) -> None:
    claims = [_flag("--fold"), _flag("--max-lines"), _flag(INVENTED)]
    outcomes = [e.outcome for e in _run(make_ctx, claims)]
    assert outcomes == ["SUPPORTS", "SUPPORTS", "REFUTES"]


def test_is_doc_separates_documentation_from_code() -> None:
    assert is_doc("README") and is_doc("docs/options.md") and is_doc("man/curl.1")
    assert not is_doc("src/util.c") and not is_doc("include/hdr.h")


def test_identical_input_gives_identical_evidence(make_ctx: MakeContext) -> None:
    c = _flag(INVENTED)
    first = _run(make_ctx, [c])
    second = _run(make_ctx, [c])
    assert [e.id for e in first] == [e.id for e in second]
    assert first[0].model_dump() == second[0].model_dump()


def test_registered_and_runnable_through_the_runner(make_ctx: MakeContext) -> None:
    ctx = make_ctx(claims=[_flag(INVENTED)])
    (run,) = run_checks(ctx, checks=[OptionExists()])
    assert run.check_id == "C14"
    assert run.error is None
    assert [e.outcome for e in run.evidence] == ["REFUTES"]


def test_a_mis_cased_real_flag_is_not_refuted(make_ctx: MakeContext) -> None:
    """P4: ``--FOLD`` for ``--fold`` is a transcription slip, not an invented option."""
    evidence = _one(make_ctx, "--FOLD")
    assert evidence.outcome == "NEUTRAL"
    assert evidence.details["outcome"] == "case_variant_only"
    assert any(" -i " in command for command in evidence.details["commands"])


def test_a_mis_cased_constant_is_not_refuted(make_ctx: MakeContext) -> None:
    evidence = _one(make_ctx, "hdr_value_max", option_kind="constant")
    assert evidence.outcome == "NEUTRAL"
    assert evidence.details["outcome"] == "case_variant_only"
