# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Crash signature matching (SPEC §13.5) against real captured traces and example reports."""

from __future__ import annotations

import itertools
import time
from pathlib import Path

import pytest

from nikasha.extract.pipeline import extract_claims
from nikasha.ingest import ingest_string
from nikasha.model.claims import Frame, TraceClaim, TraceData
from nikasha.repro.signature import (
    ABORT_STATUS,
    MAX_FRAMES,
    MAX_OBSERVED,
    STACK_AMBIGUOUS,
    anchored_alignment,
    app_function_names,
    bug_class,
    bug_class_of_cwe,
    bug_class_of_text,
    classes_equivalent,
    crash_in_project,
    exit_status_fits,
    match_locus,
    match_traces,
    normalize_function,
    parse_run_output,
    signature,
    terminating_report,
    terminating_trace,
)

ROOT = Path(__file__).resolve().parents[3]
TRACES = ROOT / "tests" / "fixtures" / "traces"
REPORTS = ROOT / "examples" / "reports"


def fixture(rel: str) -> TraceData:
    traces = parse_run_output((TRACES / rel).read_text(encoding="utf-8"))
    assert traces, rel
    return traces[0]


def report_trace(name: str) -> TraceData:
    report = ingest_string((REPORTS / name).read_text(encoding="utf-8"), uri=name)
    traces = [c for c in extract_claims(report).claims if isinstance(c, TraceClaim)]
    assert len(traces) == 1
    return traces[0]


ASAN = "asan/01-vulnlab-heap-overflow-v1.2.0.txt"


def test_signature_of_real_asan_trace() -> None:
    sig = signature(fixture(ASAN))
    assert sig.sanitizer == "asan"
    assert sig.bug_class == "heap-overflow"
    assert (sig.access_kind, sig.access_size) == ("WRITE", 96)
    assert sig.top_functions == ("util_copy_value", "hdr_parse_line", "hdr_parse_block")
    assert (sig.frame0_file, sig.frame0_line) == ("util.c", 15)
    assert sig.as_dict()["frame0"] == "util.c:15"


def test_genuine_report_matches_observed_crash() -> None:
    result = match_traces(report_trace("genuine_hdr_overflow.md"), fixture(ASAN))
    assert result.matched
    assert result.alignment == 3


def test_fabricated_report_does_not_match_observed_crash() -> None:
    # Same bug class and it names util_copy_value, but hdr_get never ran: after dropping the
    # universal entry point "main", only one frame aligns.
    result = match_traces(report_trace("fabricated_hdr_overflow.md"), fixture(ASAN))
    assert result.class_equivalent
    assert not result.matched
    assert result.alignment == 1


def test_asan_matches_valgrind_capture_of_same_bug() -> None:
    grind = fixture("valgrind/01-vulnlab-invalid-write-v1.2.0.txt")
    assert classes_equivalent(bug_class(grind), "heap-overflow")
    assert match_traces(fixture(ASAN), grind).matched


def test_different_ubsan_bugs_do_not_match() -> None:
    a = fixture("ubsan/01-signed-integer-overflow.txt")
    b = fixture("ubsan/02-shift-exponent.txt")
    assert bug_class(a) == "integer-overflow"
    assert bug_class(b) == "invalid-shift"
    assert match_traces(a, a).matched
    assert not match_traces(a, b).matched


def test_crash_other_than_claimed_class_does_not_match() -> None:
    asan = fixture(ASAN)
    ub = fixture("ubsan/03-divide-by-zero-halt.txt")
    assert bug_class(ub) == "divide-by-zero"
    result = match_traces(asan, ub)
    assert not result.matched and not result.class_equivalent


@pytest.mark.parametrize(
    ("text", "cls"),
    [
        ("heap-buffer-overflow", "heap-overflow"),
        ("Heap overflow in parser", "heap-overflow"),
        ("heap-use-after-free", "use-after-free"),
        ("a use after free", "use-after-free"),
        ("stack-buffer-overflow", "stack-overflow"),
        ("stack-overflow", "stack-exhaustion"),
        ("NULL pointer dereference", "null-deref"),
        ("double-free", "double-free"),
        ("nothing to see", None),
        (None, None),
    ],
)
def test_bug_class_of_text(text: str | None, cls: str | None) -> None:
    assert bug_class_of_text(text) == cls


def test_cwe_classes() -> None:
    assert bug_class_of_cwe("cwe-122") == "heap-overflow"
    assert bug_class_of_cwe("CWE-9999") is None


def test_segv_near_zero_is_null_deref() -> None:
    near = TraceData(format="asan", bug_type="SEGV", address=0x10)
    far = TraceData(format="asan", bug_type="SEGV", address=0x7FFF0000)
    assert bug_class(near) == "null-deref"
    assert bug_class(far) == "segv"
    assert classes_equivalent(bug_class(near), bug_class_of_text("NULL pointer dereference"))


def test_generic_oob_equivalences() -> None:
    assert classes_equivalent("out-of-bounds", "heap-overflow")
    assert not classes_equivalent("out-of-bounds", "use-after-free")
    assert not classes_equivalent(None, None)


def test_normalize_function() -> None:
    assert normalize_function("foo.isra.0") == "foo"
    assert normalize_function("bar.part.1") == "bar"
    assert normalize_function("ns::Klass::method(int) const") == "method"
    assert normalize_function("main.pick") == "pick"


def test_app_frames_skip_runtime_and_entry_points() -> None:
    assert app_function_names(fixture(ASAN)) == [
        "util_copy_value",
        "hdr_parse_line",
        "hdr_parse_block",
    ]


def test_anchored_alignment_requires_claimed_frame_0_or_1() -> None:
    observed = ["a", "b", "c", "d"]
    assert anchored_alignment(["a", "b"], observed) == 2
    assert anchored_alignment(["x", "b", "c"], observed) == 2
    # c and d align, but neither is claimed frame 0 or 1.
    assert anchored_alignment(["x", "y", "c", "d"], observed) == 0
    assert anchored_alignment([], observed) == 0


def test_alignment_is_bounded_on_hostile_input() -> None:
    frames = tuple(Frame(index=i, function="f", raw=f"#{i} f") for i in range(10_000))
    trace = TraceData(format="asan", bug_type="heap-buffer-overflow", frames=frames)
    assert match_traces(trace, trace).alignment <= 64


def test_locus_match_without_trace() -> None:
    observed = fixture(ASAN)
    assert match_locus("heap-overflow", "util_copy_value", observed).matched
    assert match_locus("out-of-bounds", "hdr_parse_block", observed).matched
    assert not match_locus("heap-overflow", "hdr_get", observed).matched
    assert not match_locus("use-after-free", "util_copy_value", observed).matched
    assert not match_locus(None, "util_copy_value", observed).matched


def test_signature_is_deterministic() -> None:
    assert signature(fixture(ASAN)) == signature(fixture(ASAN))


def _poc_trace() -> TraceData:
    frames = (
        Frame(index=0, function="my_copy", path="/poc/poc.c", line=5, raw="#0 my_copy"),
        Frame(index=1, function="my_driver", path="/poc/poc.c", line=9, raw="#1 my_driver"),
        Frame(index=2, function="main", path="/poc/poc.c", line=12, raw="#2 main"),
    )
    return TraceData(format="asan", bug_type="heap-buffer-overflow", frames=frames)


def test_poc_frames_are_not_application_frames() -> None:
    trace = _poc_trace()
    assert app_function_names(trace) == []
    assert not match_traces(trace, trace).matched
    assert not crash_in_project(trace)
    assert not match_locus("heap-overflow", "my_copy", trace).matched


def test_crash_in_project_needs_a_non_poc_source_path() -> None:
    assert crash_in_project(fixture(ASAN))
    no_path = TraceData(
        format="asan",
        bug_type="heap-buffer-overflow",
        frames=(Frame(index=0, function="f", raw="#0 f"),),
    )
    assert not crash_in_project(no_path)


def test_terminating_trace_is_the_last_one() -> None:
    asan = (TRACES / ASAN).read_text(encoding="utf-8")
    ubsan = (TRACES / "ubsan" / "03-divide-by-zero-halt.txt").read_text(encoding="utf-8")
    last = terminating_trace(asan + "\n" + ubsan)
    assert last is not None and bug_class(last) == "divide-by-zero"
    assert terminating_trace("no trace here") is None


def test_observed_traces_are_capped() -> None:
    asan = (TRACES / ASAN).read_text(encoding="utf-8")
    assert len(parse_run_output("\n".join([asan] * 30))) == MAX_OBSERVED


def test_locus_ignores_runtime_and_entry_frames() -> None:
    observed = fixture(ASAN)
    assert not match_locus("heap-overflow", "main", observed).matched
    assert not match_locus("heap-overflow", "__asan_memcpy", observed).matched


def test_earliest_keyword_wins() -> None:
    assert bug_class_of_text("heap overflow, not a use after free") == "heap-overflow"


def test_prose_stack_overflow_is_ambiguous() -> None:
    cls = bug_class_of_text("stack overflow in parse()", prose=True)
    assert cls == STACK_AMBIGUOUS
    assert classes_equivalent(cls, "stack-overflow")
    assert classes_equivalent(cls, "stack-exhaustion")
    assert not classes_equivalent(cls, "heap-overflow")
    assert bug_class_of_text("stack-buffer-overflow", prose=True) == "stack-overflow"


def _lcs(a: list[str], b: list[str]) -> int:
    if not a or not b:
        return 0
    if a[0] == b[0]:
        return 1 + _lcs(a[1:], b[1:])
    return max(_lcs(a[1:], b), _lcs(a, b[1:]))


def _brute_anchored(claimed: list[str], observed: list[str]) -> int:
    best = 0
    for i, j in itertools.product(range(min(2, len(claimed))), range(len(observed))):
        if claimed[i] == observed[j]:
            length = _lcs(claimed[:i], observed[:j]) + 1 + _lcs(claimed[i + 1 :], observed[j + 1 :])
            best = max(best, length)
    return best


def _words(alphabet: str, max_len: int) -> list[list[str]]:
    return [list(w) for n in range(max_len + 1) for w in itertools.product(alphabet, repeat=n)]


def test_anchored_alignment_equals_the_definition() -> None:
    for alphabet, max_len in (("abc", 3), ("ab", 5)):
        words = _words(alphabet, max_len)
        for claimed, observed in itertools.product(words, words):
            assert anchored_alignment(claimed, observed) == _brute_anchored(claimed, observed)


def test_alignment_work_is_bounded_when_anchors_recur() -> None:
    # Every observed frame equals both anchors: the old per-anchor LCS was O(n^3).
    frames = tuple(Frame(index=i, function="f", raw=f"#{i} f") for i in range(10_000))
    trace = TraceData(format="asan", bug_type="heap-buffer-overflow", frames=frames)
    start = time.perf_counter()
    for _ in range(8):  # C19 compares at most 8 quoted traces
        assert match_traces(trace, trace).alignment == MAX_FRAMES
    assert time.perf_counter() - start < 1.0


@pytest.mark.parametrize(
    ("text", "cls"),
    [
        ("not a use after free but a heap overflow", "heap-overflow"),
        ("this is no use-after-free; heap-buffer-overflow", "heap-overflow"),
        ("rather than a double free, an invalid free", "invalid-free"),
        ("There is no NULL pointer check in f()", "null-deref"),
        ("not a use after free", None),
    ],
)
def test_negated_class_keywords_are_skipped(text: str, cls: str | None) -> None:
    assert bug_class_of_text(text, prose=True) == cls


def test_terminating_report_must_end_the_output() -> None:
    asan = (TRACES / ASAN).read_text(encoding="utf-8")
    ended = terminating_report(asan + "\n\n")
    assert ended is not None and ended.at_tail
    echoed = terminating_report(asan + "hdrcat: 2 headers\n")
    assert echoed is not None and not echoed.at_tail
    assert terminating_report("") is None


def test_exit_status_must_fit_the_report() -> None:
    asan = fixture(ASAN)
    assert exit_status_fits(asan, ABORT_STATUS)
    assert not exit_status_fits(asan, 1)
    assert not exit_status_fits(fixture("python/01-zero-division.txt"), 1)
    assert not exit_status_fits(fixture("valgrind/01-vulnlab-invalid-write-v1.2.0.txt"), 1)


def test_harness_frames_above_a_project_crash_are_dropped() -> None:
    frames = (
        Frame(index=0, function="util_copy_value", path="/work/src/util.c", line=15, raw="#0"),
        Frame(index=1, function="drive", path="/poc/poc.c", line=3, raw="#1"),
        Frame(index=2, function="main", path="/poc/poc.c", line=9, raw="#2"),
    )
    trace = TraceData(format="asan", bug_type="heap-buffer-overflow", frames=frames)
    assert crash_in_project(trace)
    assert app_function_names(trace) == ["util_copy_value"]
    assert signature(trace).top_functions == ("util_copy_value",)
