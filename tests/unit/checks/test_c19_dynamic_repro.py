# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""C19 DYNAMIC_REPRO over real report claims and real captured run output (SPEC §12, §13.5).

No container runs here: the sandbox result is a plain object carrying the real output of a
captured run (tests/fixtures/traces). Running a PoC for real is covered by the ``sandbox``
suite on CI.
"""

from __future__ import annotations

import inspect
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

from check_helpers import claim

from nikasha.checks.base import CheckContext, is_refutable
from nikasha.checks.c19_dynamic_repro import DynamicRepro, claimed_class, locus_function
from nikasha.extract.pipeline import extract_claims
from nikasha.ingest import ingest_string
from nikasha.model.claims import BehaviorClaim, Claim, ImpactClaim, PocClaim, SymbolClaim
from nikasha.model.evidence import CommandRecord, Evidence
from nikasha.pipeline import check_report
from nikasha.repro.run import ReproRun
from nikasha.repro.signature import ABORT_STATUS, ReproFailure

ROOT = Path(__file__).resolve().parents[3]
TRACES = ROOT / "tests" / "fixtures" / "traces"
REPORTS = ROOT / "examples" / "reports"
ASAN_RUN = (TRACES / "asan" / "01-vulnlab-heap-overflow-v1.2.0.txt").read_text(encoding="utf-8")
UBSAN_RUN = (TRACES / "ubsan" / "03-divide-by-zero-halt.txt").read_text(encoding="utf-8")


CMD = CommandRecord(
    argv=("podman", "run"), exit_code=1, stdout_sha256="0" * 64, stderr_sha256="1" * 64
)


def crashed(
    stderr: str,
    stdout: str = "",
    kind: str = "file_input",
    code: int = ABORT_STATUS,
    *,
    attested: bool | None = None,
    truncated: bool = False,
) -> ReproRun:
    """A crashed run. 134 (SIGABRT) is the status measured in the sandbox for a real ASan
    or UBSan report under the recipes' ``abort_on_error=1``. ``attested`` defaults to what
    the vulnlab recipe says for ``kind`` (only ``file_input`` is attested)."""
    if attested is None:
        attested = kind == "file_input"
    return ReproRun(kind, code, False, truncated, stdout, stderr, CMD, attested=attested)


def clean(timed_out: bool = False) -> ReproRun:
    return ReproRun("file_input", 0 if not timed_out else 137, timed_out, False, "ok\n", "", CMD)


FakeRepro = ReproRun | ReproFailure | None


def claims_of(name: str) -> tuple[Any, tuple[Claim, ...]]:
    report = ingest_string((REPORTS / name).read_text(encoding="utf-8"), uri=name)
    return report, extract_claims(report).claims


def run(name: str, repro: FakeRepro) -> list[Evidence]:
    report, claims = claims_of(name)
    ctx = cast(
        CheckContext,
        SimpleNamespace(report=report, claims=claims, repro=repro, expired=lambda: False),
    )
    check = DynamicRepro()
    return check.run(ctx, check.select(claims))


def only(items: list[Evidence]) -> Evidence:
    assert len(items) == 1
    return items[0]


def test_no_repro_attached_produces_nothing() -> None:
    assert run("genuine_hdr_overflow.md", None) == []


def test_genuine_report_signature_match() -> None:
    ev = only(run("genuine_hdr_overflow.md", crashed(ASAN_RUN)))
    assert ev.check_id == "C19" and ev.group == "dynamic"
    assert ev.outcome == "SUPPORTS"
    assert ev.strength == 6.0
    assert ev.details["outcome"] == "signature_match"
    assert ev.details["observed_signature"]["frame0"] == "util.c:15"
    assert ev.claim_ids


def test_fabricated_report_is_a_different_signature_flagged() -> None:
    ev = only(run("fabricated_hdr_overflow.md", crashed(ASAN_RUN)))
    assert ev.details["outcome"] == "different_signature"
    assert ev.strength == 0.5
    assert ev.details["flag"] == "different_crash"
    assert ev.summary.startswith("REVIEW:")


def test_different_bug_class_is_flagged() -> None:
    ev = only(run("genuine_hdr_overflow.md", crashed(UBSAN_RUN)))
    assert ev.details["outcome"] == "different_signature"
    assert ev.details["match"]["class_equivalent"] is False


def test_no_crash_weakens_the_project_attributed_trace() -> None:
    _, claims = claims_of("genuine_hdr_overflow.md")
    ev = only(run("genuine_hdr_overflow.md", clean()))
    assert ev.details["outcome"] == "no_crash"
    assert ev.outcome == "REFUTES"
    assert ev.strength == -0.5
    # It cites exactly the refutable trace/core-symbol claims: never the reporter's own PoC
    # (ADR 0003), and it is not the refutation gate that makes it so.
    by_id = {c.id: c for c in claims}
    cited = [by_id[i] for i in ev.claim_ids]
    assert cited and all(is_refutable(c) for c in cited)
    assert {c.kind for c in cited} <= {"trace", "symbol"}
    assert any(c.kind == "trace" for c in cited)
    assert any(c.kind == "poc" for c in claims)
    assert "gated" not in ev.details


def test_timeout_is_no_crash() -> None:
    ev = only(run("genuine_hdr_overflow.md", clean(timed_out=True)))
    assert ev.details["outcome"] == "no_crash" and ev.strength == -0.5


def test_no_crash_with_only_reporter_artifacts_is_informational() -> None:
    poc = claim(PocClaim, "hdrcat poc.txt", poc_kind="cli", provenance="reporter_artifact")
    ctx = cast(
        CheckContext,
        SimpleNamespace(report=SimpleNamespace(title=None), claims=(poc,), repro=clean()),
    )
    ev = only(DynamicRepro().run(ctx, (poc,)))
    assert ev.outcome == "NEUTRAL" and ev.strength == 0.0
    assert ev.details["withheld_strength"] == -0.5
    assert ev.claim_ids == ()
    assert "gated" not in ev.details


def test_no_crash_without_claims_is_informational() -> None:
    ctx = cast(
        CheckContext, SimpleNamespace(report=SimpleNamespace(title=None), claims=(), repro=clean())
    )
    ev = only(DynamicRepro().run(ctx, ()))
    assert ev.outcome == "NEUTRAL" and ev.strength == 0.0
    assert ev.details["outcome"] == "no_crash"
    assert ev.details["withheld_strength"] == -0.5
    assert ev.claim_ids == ()


def test_build_failure_is_error_without_strength() -> None:
    ev = only(run("genuine_hdr_overflow.md", ReproFailure("build_failed", "make: *** [x] 2")))
    assert ev.outcome == "ERROR"
    assert ev.strength == 0.0
    assert ev.details["outcome"] == "build_failed"


def test_engine_failure_exit_status_is_error() -> None:
    ev = only(run("genuine_hdr_overflow.md", crashed("", code=125)))
    assert ev.outcome == "ERROR" and ev.strength == 0.0
    assert ev.details["outcome"] == "infra_error"


def test_crash_without_parsable_trace_is_neutral() -> None:
    ev = only(run("genuine_hdr_overflow.md", crashed("Segmentation fault\n")))
    assert ev.outcome == "NEUTRAL"
    assert ev.details["outcome"] == "crash_unparsed"


def test_trace_on_stdout_is_ignored() -> None:
    ev = only(run("genuine_hdr_overflow.md", crashed("", stdout=ASAN_RUN)))
    assert ev.details["outcome"] == "crash_unparsed"


def test_forged_report_text_on_stdout_cannot_match() -> None:
    forged = (REPORTS / "fabricated_hdr_overflow.md").read_text(encoding="utf-8")
    ev = only(run("fabricated_hdr_overflow.md", crashed(UBSAN_RUN, stdout=forged)))
    assert ev.details["outcome"] != "signature_match"


def test_only_the_terminating_trace_counts() -> None:
    # A decoy matching the claim, then the real (different) crash that ended the run.
    ev = only(run("genuine_hdr_overflow.md", crashed(ASAN_RUN + "\n" + UBSAN_RUN)))
    assert ev.details["outcome"] == "different_signature"
    # The same trace last does match.
    ev2 = only(run("genuine_hdr_overflow.md", crashed(UBSAN_RUN + "\n" + ASAN_RUN)))
    assert ev2.details["outcome"] == "signature_match"


def test_report_with_the_wrong_exit_status_is_unattributed() -> None:
    # A target that echoes its input to stderr and exits 1 cannot pass off the echo.
    ev = only(run("genuine_hdr_overflow.md", crashed(ASAN_RUN, code=1)))
    assert ev.details["outcome"] == "crash_unattributed"
    assert ev.outcome == "NEUTRAL" and ev.strength == 0.0
    assert "exit status 1" in ev.summary


def test_report_followed_by_more_output_is_unattributed() -> None:
    ev = only(run("genuine_hdr_overflow.md", crashed(ASAN_RUN + "hdrcat: 2 headers read\n")))
    assert ev.details["outcome"] == "crash_unattributed"
    assert "more output follows" in ev.summary


def test_non_sanitizer_trace_is_unattributed() -> None:
    python = (TRACES / "python" / "01-zero-division.txt").read_text(encoding="utf-8")
    ev = only(run("genuine_hdr_overflow.md", crashed(python, code=1)))
    assert ev.details["outcome"] == "crash_unattributed"


def test_harness_match_is_never_a_reproduction() -> None:
    # A c_harness is the reporter's code in the target's process: it can print this exact
    # report and abort. The comparison is kept, but it does not count.
    ev = only(run("genuine_hdr_overflow.md", crashed(ASAN_RUN, kind="c_harness")))
    assert ev.details["outcome"] == "harness_unverified"
    assert ev.details["unverified_outcome"] == "signature_match"
    assert ev.outcome == "NEUTRAL" and ev.strength == 0.0
    assert ev.summary.startswith("REVIEW:")


def test_crash_inside_the_poc_harness_is_not_reproduced() -> None:
    harness = ASAN_RUN.replace("/work/libhdr/src/util.c", "/poc/poc.c").replace(
        "/work/libhdr/src/hdr.c", "/poc/poc.c"
    )
    ev = only(run("genuine_hdr_overflow.md", crashed(harness, kind="c_harness")))
    assert ev.details["outcome"] == "crash_not_in_project"
    assert ev.outcome == "NEUTRAL" and ev.strength == 0.0
    assert ev.details["run"]["kind"] == "c_harness"


def test_commands_are_carried() -> None:
    ev = only(run("genuine_hdr_overflow.md", crashed(ASAN_RUN)))
    assert ev.commands == (CMD,)


def test_deterministic() -> None:
    a = run("genuine_hdr_overflow.md", crashed(ASAN_RUN))
    b = run("genuine_hdr_overflow.md", crashed(ASAN_RUN))
    assert [e.model_dump_json() for e in a] == [e.model_dump_json() for e in b]


def test_real_context_carries_the_repro_field() -> None:
    report, claims = claims_of("genuine_hdr_overflow.md")
    ctx = CheckContext(
        report=report,
        claims=claims,
        resolution=cast(Any, None),
        index=cast(Any, None),
        repro=crashed(ASAN_RUN),
    )
    check = DynamicRepro()
    assert only(check.run(ctx, check.select(claims))).details["outcome"] == "signature_match"
    assert CheckContext.__dataclass_fields__["repro"].default is None


def test_pipeline_threads_an_optional_repro() -> None:
    param = inspect.signature(check_report).parameters["repro"]
    assert param.default is None
    assert param.kind is inspect.Parameter.KEYWORD_ONLY


def _sym(name: str, role: str = "core") -> SymbolClaim:
    return claim(SymbolClaim, name, name=name, role=role)


def test_no_trace_report_matches_on_class_and_locus() -> None:
    impact = claim(ImpactClaim, "CWE-122", cwe="CWE-122")
    claims: tuple[Claim, ...] = (impact, _sym("util_copy_value"))
    report = SimpleNamespace(title="overflow")
    assert claimed_class(claims, None) == "heap-overflow"
    assert locus_function(claims)[0] == "util_copy_value"
    ctx = cast(
        CheckContext,
        SimpleNamespace(report=report, claims=claims, repro=crashed(ASAN_RUN)),
    )
    ev = only(DynamicRepro().run(ctx, claims))
    assert ev.details["outcome"] == "signature_match"
    assert ev.details["match"]["mode"] == "locus"

    wrong: tuple[Claim, ...] = (impact, _sym("hdr_get"))
    ctx2 = cast(
        CheckContext,
        SimpleNamespace(report=report, claims=wrong, repro=crashed(ASAN_RUN)),
    )
    assert only(DynamicRepro().run(ctx2, wrong)).details["outcome"] == "different_signature"


def test_no_trace_no_class_no_locus_is_neutral() -> None:
    ctx = cast(
        CheckContext,
        SimpleNamespace(report=SimpleNamespace(title=None), claims=(), repro=crashed(ASAN_RUN)),
    )
    ev = only(DynamicRepro().run(ctx, ()))
    assert ev.outcome == "NEUTRAL" and ev.details["outcome"] == "crash_uncompared"


def test_behavior_without_mapping_falls_back_to_title() -> None:
    behavior = claim(
        BehaviorClaim, "calls memcpy", predicate="calls_api", subject_symbol="util_copy_value"
    )
    assert claimed_class((behavior,), "Heap buffer overflow in util_copy_value") == "heap-overflow"


def test_title_stack_overflow_is_ambiguous() -> None:
    assert claimed_class((), "Stack overflow in parse") == "stack-overflow-or-exhaustion"


def test_negated_class_in_title_is_skipped() -> None:
    title = "Not a use-after-free: heap buffer overflow in util_copy_value"
    assert claimed_class((), title) == "heap-overflow"


def test_unmapped_behavior_then_negated_behavior_fall_through_to_title() -> None:
    unmapped = claim(BehaviorClaim, "calls memcpy", predicate="calls_api", subject_symbol="f")
    negated = claim(
        BehaviorClaim, "no free", predicate="uses_freed", subject_symbol="f", negated=True
    )
    assert claimed_class((unmapped, negated), "Heap overflow in f") == "heap-overflow"


def test_unattested_file_input_is_never_a_reproduction() -> None:
    # e.g. sqlite's .read script can print this exact report and .exit 134 itself.
    ev = only(run("genuine_hdr_overflow.md", crashed(ASAN_RUN, attested=False)))
    assert ev.details["outcome"] == "harness_unverified"
    assert ev.details["unverified_outcome"] == "signature_match"
    assert ev.details["attested"] is False
    assert ev.outcome == "NEUTRAL" and ev.strength == 0.0
    assert "not attested" in ev.summary


def test_attested_default_is_false() -> None:
    assert ReproRun("file_input", 134, False, False, "", ASAN_RUN, CMD).attested is False


def test_attested_file_input_still_reproduces() -> None:
    ev = only(run("genuine_hdr_overflow.md", crashed(ASAN_RUN)))
    assert ev.details["outcome"] == "signature_match"
    assert "truncated_note" not in ev.details


def test_truncated_run_is_said_in_details() -> None:
    ev = only(run("genuine_hdr_overflow.md", crashed(ASAN_RUN, truncated=True)))
    assert ev.details["run"]["truncated"] is True
    assert "truncated" in ev.details["truncated_note"]
    assert "truncated" in ev.summary
