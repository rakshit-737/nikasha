# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""C08 TRACE_FRAMES, against the real vulnlab tree and real ASan output (SPEC §12).

Every trace here was produced by really running the PoC in the capture container
(``tests/fixtures/traces/asan``, embedded in ``examples/reports/*.md``); the frames added on
top of them are the ones a real report mixes in and vulnlab cannot produce — a libz frame, a
system header, a file that is simply not there.
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from check_helpers import ROOT, MakeContext, claim

from nikasha.checks.base import run_checks
from nikasha.checks.c08_trace_frames import (
    GENERATED_NOTE,
    MAX_TRACE_FRAMES,
    TraceFrames,
    _skip_reason,
)
from nikasha.code.gitio import HistoryTimeoutError, HistoryUnavailableError
from nikasha.code.index import CodeIndex
from nikasha.code.trace_forensics import FrameCheck
from nikasha.extract import extract_claims
from nikasha.ingest import load_report
from nikasha.model.claims import Frame, TraceClaim
from nikasha.model.evidence import Evidence

REPORTS = ROOT / "examples" / "reports"
GENUINE = REPORTS / "genuine_hdr_overflow.md"
FABRICATED = REPORTS / "fabricated_hdr_overflow.md"


def _source(path: Path) -> TraceClaim:
    """The trace the extractor finds in a real report."""
    claims = extract_claims(load_report(path)).claims
    return next(c for c in claims if isinstance(c, TraceClaim))


def _trace(
    path: Path = GENUINE, *, extra: Sequence[Frame] = (), only_runtime: bool = False, **fields: Any
) -> TraceClaim:
    """A trace claim built from a real report, optionally with extra frames appended."""
    source = _source(path)
    frames = tuple(f for f in source.frames if f.is_runtime or not only_runtime)
    return claim(TraceClaim, format=source.format, frames=frames + tuple(extra), **fields)


def _frame(
    index: int, function: str, path: str | None, line: int | None, *, module: str | None = None
) -> Frame:
    return Frame(
        index=index, function=function, path=path, line=line, module=module, raw=f"#{index}"
    )


#: A frame from zlib, linked in from ``/opt`` so only the shared library gives it away.
LIBZ = _frame(8, "inflate", "/build/zlib/inflate.c", 1234, module="/opt/app/lib/libz.so.1")
#: A frame in a system header: the path alone places it outside the repository.
SYSTEM_HEADER = _frame(9, "png_get_io_ptr", "/usr/include/png.h", 60)
#: A file that is in no release of libhdr and claims nothing about where it came from.
INVENTED = _frame(10, "hdr_decode_chunked_value", "/src/libhdr/src/hdr_chunked.c", 412)


def _run(make_ctx: MakeContext, trace: TraceClaim, tag: str = "v1.2.0") -> list[Evidence]:
    ctx = make_ctx(claims=[trace], tag=tag)
    return TraceFrames().run(ctx, [trace])


def _by_function(evidence: Evidence) -> dict[str | None, dict[str, Any]]:
    return {frame["function"]: frame for frame in evidence.details["frames"]}


def test_the_check_declares_itself_as_the_spec_names_it() -> None:
    check = TraceFrames()
    assert (check.id, check.name, check.group) == ("C08", "TRACE_FRAMES", "trace")
    assert check.applies_to == frozenset({"trace"})


def test_a_trace_whose_every_frame_fits_supports_the_report(make_ctx: MakeContext) -> None:
    (evidence,) = _run(make_ctx, _trace())
    assert evidence.outcome == "SUPPORTS"
    assert evidence.strength == 2.0
    assert evidence.check_id == "C08"
    assert evidence.group == "trace"
    assert evidence.details["ratio"] == 1.0
    assert evidence.details["checked_frames"] == 4
    assert evidence.details["consistent_frames"] == 4
    assert "4 of 4 application frames fit the code at v1.2.0" in evidence.summary


def test_runtime_frames_never_reach_the_ratio(make_ctx: MakeContext) -> None:
    """libc, ``_start`` and the sanitizer's own interceptor are four of this trace's eight."""
    (evidence,) = _run(make_ctx, _trace())
    assert evidence.details["trace_frames"] == 8
    assert evidence.details["app_frames"] == 4
    assert set(_by_function(evidence)) == {
        "util_copy_value",
        "hdr_parse_line",
        "hdr_parse_block",
        "main",
    }


def test_each_frame_is_kept_as_a_child_detail(make_ctx: MakeContext) -> None:
    (evidence,) = _run(make_ctx, _trace())
    frame = _by_function(evidence)["util_copy_value"]
    assert frame["status"] == "consistent"
    assert frame["index"] == 1
    assert frame["claimed_path"] == "/work/libhdr/src/util.c"
    assert frame["resolved_path"] == "src/util.c"
    assert frame["line"] == 15
    assert frame["mismatched"] == []
    assert "src/util.c exists at this commit" in frame["matched"]
    assert "line 15 is inside util_copy_value" in frame["matched"]
    assert frame["checks"] == {"file": True, "function": True, "line": True}


def test_evidence_locates_frames_at_the_exact_commit(make_ctx: MakeContext) -> None:
    ctx = make_ctx(claims=[_trace()])
    (evidence,) = TraceFrames().run(ctx, list(ctx.claims))
    assert [(loc.path, loc.start_line) for loc in evidence.locations] == [
        ("src/util.c", 15),
        ("src/hdr.c", 104),
        ("src/hdr.c", 134),
        ("tools/hdrcat.c", 122),
    ]
    assert all(loc.commit == ctx.commit for loc in evidence.locations)
    assert evidence.locations[0].permalink is not None
    assert evidence.locations[0].permalink.endswith(f"/blob/{ctx.commit}/src/util.c#L15")


@pytest.mark.parametrize("tag", ["v1.0.0", "v1.1.0", "v1.2.1", "v1.3.0"])
def test_the_same_trace_only_partly_fits_the_other_releases(
    make_ctx: MakeContext, tag: str
) -> None:
    """v1.2.1 is a comment-only change, so the line numbers drift but the files do not."""
    (evidence,) = _run(make_ctx, _trace(), tag=tag)
    assert evidence.outcome == "REFUTES"
    assert evidence.strength == -0.5
    assert 0.5 <= evidence.details["ratio"] < 0.8


def test_a_fabricated_trace_is_inconsistent(make_ctx: MakeContext) -> None:
    (evidence,) = _run(make_ctx, _trace(FABRICATED))
    assert evidence.outcome == "REFUTES"
    assert evidence.strength == -2.0
    assert evidence.details["ratio"] == 0.0
    assert evidence.details["checked_frames"] == 3
    mismatched = _by_function(evidence)["hdr_get"]["mismatched"]
    assert "src/hdr.c has 156 lines" in mismatched
    assert _by_function(evidence)["hdr_get"]["checks"]["line"] is False


def test_one_drifted_frame_in_five_is_only_mostly_consistent(make_ctx: MakeContext) -> None:
    (evidence,) = _run(make_ctx, _trace(extra=[INVENTED]))
    assert evidence.outcome == "SUPPORTS"
    assert evidence.strength == 0.8
    assert evidence.details["ratio"] == 0.8
    assert evidence.details["checked_frames"] == 5


class TestFramesOutsideTheRepository:
    """The M2 carry-over: a frame the project does not own is never counted (P4, ADR 0003)."""

    def test_a_shared_library_frame_is_skipped(self, make_ctx: MakeContext) -> None:
        (evidence,) = _run(make_ctx, _trace(extra=[LIBZ]))
        frame = _by_function(evidence)["inflate"]
        assert frame["status"] == "skipped"
        assert frame["reason"] == "the frame comes from the shared library /opt/app/lib/libz.so.1"
        assert evidence.details["checked_frames"] == 4
        assert evidence.outcome == "SUPPORTS"
        assert "1 outside the repository" in evidence.summary

    def test_a_system_header_frame_is_skipped(self, make_ctx: MakeContext) -> None:
        (evidence,) = _run(make_ctx, _trace(extra=[SYSTEM_HEADER]))
        frame = _by_function(evidence)["png_get_io_ptr"]
        assert frame["status"] == "skipped"
        assert "usr/include" in frame["reason"]
        assert evidence.details["checked_frames"] == 4
        assert evidence.details["ratio"] == 1.0

    def test_a_missing_file_with_nothing_to_say_for_itself_still_counts(
        self, make_ctx: MakeContext
    ) -> None:
        """Otherwise every invented path could hide behind the third-party exemption."""
        (evidence,) = _run(make_ctx, _trace(extra=[INVENTED]))
        frame = _by_function(evidence)["hdr_decode_chunked_value"]
        assert frame["status"] == "inconsistent"
        assert frame["mismatched"] == [
            "no file matching /src/libhdr/src/hdr_chunked.c exists at this commit"
        ]

    def test_a_generated_file_frame_is_skipped_with_the_spec_note(
        self, make_ctx: MakeContext
    ) -> None:
        generated = _frame(11, "hdr_config_init", "/work/libhdr/src/config.h", 40)
        (evidence,) = _run(make_ctx, _trace(extra=[generated]))
        frame = _by_function(evidence)["hdr_config_init"]
        assert frame["status"] == "skipped"
        assert frame["reason"].startswith(GENERATED_NOTE)
        assert evidence.details["checked_frames"] == 4

    def test_a_frame_without_a_file_name_is_skipped(self, make_ctx: MakeContext) -> None:
        (evidence,) = _run(make_ctx, _trace(extra=[_frame(12, "hdr_mystery", None, None)]))
        assert _by_function(evidence)["hdr_mystery"]["status"] == "skipped"
        assert evidence.details["checked_frames"] == 4

    def test_a_trace_of_only_foreign_frames_is_neutral(self, make_ctx: MakeContext) -> None:
        trace = claim(TraceClaim, format="asan", frames=(LIBZ, SYSTEM_HEADER))
        (evidence,) = _run(make_ctx, trace)
        assert evidence.outcome == "NEUTRAL"
        assert evidence.strength == 0.0
        assert evidence.details["checked_frames"] == 0
        assert evidence.details["skipped_frames"] == 2
        assert "no application frame in this trace can be checked" in evidence.summary

    def test_a_trace_of_only_runtime_frames_is_neutral(self, make_ctx: MakeContext) -> None:
        (evidence,) = _run(make_ctx, _trace(only_runtime=True))
        assert evidence.outcome == "NEUTRAL"
        assert evidence.details["app_frames"] == 0
        assert evidence.details["trace_frames"] == 4


class TestPartialParses:
    """P4: what a half-parsed file does not show is not a finding."""

    @staticmethod
    def _unparsed(index: CodeIndex, monkeypatch: pytest.MonkeyPatch, *paths: str) -> None:
        """Make ``paths`` look the way a file whose body is hidden behind ``#if`` looks."""
        original = index.facts_at

        def patched(commit: str, path: str) -> Any:
            facts = original(commit, path)
            if path in paths and facts is not None:
                return replace(facts, parsed_ok=False, symbols=())
            return facts

        monkeypatch.setattr(index, "facts_at", patched)

    def test_a_frame_in_an_unparsed_file_is_uncertain_not_inconsistent(
        self, make_ctx: MakeContext, index: CodeIndex, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._unparsed(index, monkeypatch, "src/util.c")
        (evidence,) = _run(make_ctx, _trace())
        frame = _by_function(evidence)["util_copy_value"]
        assert frame["status"] == "uncertain"
        assert frame["reason"] == "src/util.c did not parse cleanly at this commit"
        assert evidence.details["uncertain_frames"] == 1
        assert evidence.details["checked_frames"] == 3
        assert evidence.outcome == "SUPPORTS"
        assert "1 in a file that did not parse cleanly not counted" in evidence.summary

    def test_a_trace_over_only_unparsed_files_never_refutes(
        self, make_ctx: MakeContext, index: CodeIndex, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._unparsed(index, monkeypatch, "src/util.c", "src/hdr.c", "tools/hdrcat.c")
        (evidence,) = _run(make_ctx, _trace(FABRICATED))
        assert evidence.outcome == "NEUTRAL"
        assert evidence.strength == 0.0
        assert evidence.details["uncertain_frames"] == 3
        assert evidence.details["checked_frames"] == 0


class TestRefutationGate:
    """ADR 0003: only project-attributed, non-negated claims may be refuted."""

    def test_reporter_artifact_is_not_refuted(self, make_ctx: MakeContext) -> None:
        trace = _trace(FABRICATED, provenance="reporter_artifact")
        (evidence,) = _run(make_ctx, trace)
        assert evidence.outcome == "NEUTRAL"
        assert evidence.strength == 0.0
        assert evidence.details["gated"] == ["reporter_artifact"]
        assert evidence.details["withheld_strength"] == -2.0

    def test_negated_claim_is_not_refuted(self, make_ctx: MakeContext) -> None:
        (evidence,) = _run(make_ctx, _trace(FABRICATED, negated=True))
        assert evidence.outcome == "NEUTRAL"
        assert evidence.details["gated"] == ["negated"]

    def test_support_is_not_gated(self, make_ctx: MakeContext) -> None:
        (evidence,) = _run(make_ctx, _trace(provenance="third_party"))
        assert evidence.outcome == "SUPPORTS"
        assert evidence.strength == 2.0


def test_identical_input_gives_identical_evidence_ids(make_ctx: MakeContext) -> None:
    trace = _trace(FABRICATED, extra=[LIBZ, INVENTED])
    first = _run(make_ctx, trace)
    second = _run(make_ctx, trace)
    assert [e.id for e in first] == [e.id for e in second]
    assert first[0].model_dump() == second[0].model_dump()


def test_registered_and_runnable_through_the_runner(make_ctx: MakeContext) -> None:
    ctx = make_ctx(claims=[_trace(FABRICATED)])
    (run,) = run_checks(ctx, checks=[TraceFrames()])
    assert run.check_id == "C08"
    assert run.error is None
    assert run.seconds >= 0.0
    assert [e.outcome for e in run.evidence] == ["REFUTES"]


class TestReviewFindings:
    """P4, P2 and bounded work: the safeguards added after the line-level review."""

    def test_a_runtime_made_function_name_is_undecided_not_inconsistent(
        self, make_ctx: MakeContext
    ) -> None:
        """Python ``<module>``, Go ``run.func1`` and Rust closures never match a symbol."""
        extra = [
            _frame(20, "<module>", "/work/libhdr/src/util.c", 15),
            _frame(21, "main.run.func1", "/work/libhdr/src/util.c", 15),
            _frame(22, "hdr::main::{closure#0}", "/work/libhdr/src/util.c", 15),
        ]
        (evidence,) = _run(make_ctx, _trace(extra=extra))
        frames = {f["index"]: f for f in evidence.details["frames"]}
        for index in (20, 21, 22):
            assert frames[index]["status"] == "undecided"
            assert "runtime-made name" in frames[index]["reason"]
        assert evidence.details["undecided_frames"] == 3
        assert evidence.outcome == "SUPPORTS"
        assert evidence.strength == 2.0

    def test_an_unparsed_namesake_makes_an_ambiguous_frame_uncertain(self) -> None:
        parsed = {"contrib/hdr.c": True, "src/hdr.c": False}
        ctx: Any = SimpleNamespace(facts=lambda p: SimpleNamespace(parsed_ok=parsed[p]))
        frame = _frame(2, "hdr_parse_block", "hdr.c", 134)
        check = FrameCheck(
            index=2,
            function="hdr_parse_block",
            claimed_path="hdr.c",
            line=134,
            resolved_path="contrib/hdr.c",
            candidates=["contrib/hdr.c", "src/hdr.c"],
        )
        assert _skip_reason(ctx, frame, check) == (
            "uncertain",
            "src/hdr.c did not parse cleanly at this commit",
        )

    def test_a_missing_file_on_a_shallow_clone_is_undecided(
        self, make_ctx: MakeContext, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        trace = _trace(extra=[INVENTED])
        ctx = make_ctx(claims=[trace])
        monkeypatch.setattr(ctx.resolution.repo, "is_shallow", lambda: True)
        (evidence,) = TraceFrames().run(ctx, [trace])
        frame = _by_function(evidence)["hdr_decode_chunked_value"]
        assert frame["status"] == "undecided"
        assert "shallow" in frame["reason"]
        assert evidence.details["ratio"] == 1.0

    def test_a_missing_file_seen_in_history_or_after_a_timeout_is_undecided(
        self, make_ctx: MakeContext, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        trace = _trace(FABRICATED, extra=[INVENTED])
        for answer, words in (("a" * 40, "elsewhere in history"), (None, "timed out")):

            def pickaxe(name: str, *, answer: str | None = answer, **_: Any) -> str | None:
                if answer is None:
                    raise HistoryTimeoutError("slow")
                return answer

            ctx = make_ctx(claims=[trace])
            monkeypatch.setattr(ctx.resolution.repo, "is_shallow", lambda: False)
            monkeypatch.setattr(ctx.resolution.repo, "pickaxe_first", pickaxe)
            (evidence,) = TraceFrames().run(ctx, [trace])
            frame = _by_function(evidence)["hdr_decode_chunked_value"]
            assert frame["status"] == "undecided"
            assert words in frame["reason"]

    def test_a_failed_history_search_is_not_called_a_timeout(
        self, make_ctx: MakeContext, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """P6: a pickaxe git could not run did not time out; say what happened."""
        trace = _trace(FABRICATED, extra=[INVENTED])

        def pickaxe(name: str, **_: Any) -> str | None:
            raise HistoryUnavailableError("git log -S failed with exit code 128")

        ctx = make_ctx(claims=[trace])
        monkeypatch.setattr(ctx.resolution.repo, "is_shallow", lambda: False)
        monkeypatch.setattr(ctx.resolution.repo, "pickaxe_first", pickaxe)
        (evidence,) = TraceFrames().run(ctx, [trace])
        frame = _by_function(evidence)["hdr_decode_chunked_value"]
        assert frame["status"] == "undecided"
        assert "failed" in frame["reason"]
        assert "exit code 128" in frame["reason"]
        assert "timed out" not in frame["reason"]

    def test_an_expired_budget_gives_one_fixed_neutral(self, make_ctx: MakeContext) -> None:
        trace = _trace(FABRICATED)
        ctx = make_ctx(claims=[trace])
        ctx.deadline = time.monotonic() - 1.0
        (evidence,) = TraceFrames().run(ctx, [trace])
        assert evidence.outcome == "NEUTRAL"
        assert evidence.strength == 0.0
        assert evidence.details == {
            "outcome": "budget_expired",
            "trace_format": trace.format,
            "trace_frames": len(trace.frames),
        }

    def test_frames_past_the_cap_are_counted_but_never_judged(self, make_ctx: MakeContext) -> None:
        source = _trace()
        filler = tuple(
            _frame(100 + i, "util_copy_value", "/work/libhdr/src/util.c", 15)
            for i in range(MAX_TRACE_FRAMES)
        )
        trace = claim(TraceClaim, format=source.format, frames=source.frames + filler)
        (evidence,) = _run(make_ctx, trace)
        assert evidence.details["trace_frames"] == len(trace.frames)
        assert evidence.details["truncated_frames"] == len(trace.frames) - MAX_TRACE_FRAMES
        assert len(evidence.details["frames"]) <= MAX_TRACE_FRAMES
