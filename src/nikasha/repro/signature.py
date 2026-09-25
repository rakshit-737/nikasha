# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Crash signatures and signature matching (SPEC §13.5).

Pure functions over :class:`~nikasha.model.claims.TraceData`: no I/O, no clock, no
container. The sandbox run's output is parsed with the same §9.5 trace parsers that read
the report, so the claimed crash and the observed crash are described in one vocabulary.

A **signature** is (sanitizer, bug class, access kind and size, the top 3 normalized
application frames, frame 0's ``file:line``). Two crashes **match** when their bug classes
are equivalent *and* an alignment (longest common subsequence) of their application-frame
names has length >= 2 and includes the claimed frame 0 or 1.

Two choices go beyond the letter of §13.5, both to keep a fabricated trace that merely
names one real function from "matching" (P4 cuts both ways: a wrong REPRODUCED is as bad
as a wrong UNGROUNDED):

* **Entry points are not evidence.** ``main``, ``_start``, ``<module>`` and friends appear
  in almost every native stack, so they are dropped before alignment.
* **Compiler clone suffixes are folded**: ``foo.isra.0`` and ``foo.part.1`` are ``foo``.
* **The reporter's own code is not evidence.** Frames under ``/poc`` (where the sandbox
  stages the PoC, e.g. a ``c_harness``) are dropped, and :func:`crash_in_project` says
  whether the crashing frame is project code at all. A crash inside the harness is not a
  reproduction of a bug in the project.
* **Only the terminating report counts** (:func:`terminating_report`): the last sanitizer
  report on stderr, and only when nothing but whitespace follows it. A hostile PoC can
  print decoy reports; they must not be able to lift the result by being "the best match"
  among many (P7).
* **The exit status must fit the report** (:func:`exit_status_fits`). Every shipped recipe
  builds with ASan/UBSan and ``abort_on_error=1``, so a report that really ended the
  process leaves exit status 134 (SIGABRT; measured in the sandbox for both ASan and
  UBSan). Formats without such a contract (valgrind, gdb, language runtimes) are not
  attributed at all until a recipe gives them one.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from nikasha.code.trace_forensics import bare_function
from nikasha.extract.traces import parse_traces
from nikasha.model.claims import Frame, TraceData
from nikasha.model.evidence import CommandRecord

#: How many application frames a signature keeps (SPEC §13.5).
SIGNATURE_FRAMES = 3
#: How deep a no-trace report's locus function may sit in the observed stack (SPEC §13.5).
LOCUS_DEPTH = 5
#: Shortest frame alignment that counts as a match (SPEC §13.5).
MIN_ALIGNMENT = 2
#: Frames considered per stack; bounds the quadratic alignment on hostile input (P7).
MAX_FRAMES = 64
#: Where the sandbox stages the PoC (``nikasha.repro.run``); code there is the reporter's.
POC_ROOT = "/poc"
#: Most traces taken from one run's stderr; bounds parsing and evidence size (P7).
MAX_OBSERVED = 8
#: Addresses below this are "near 0": a SEGV there is a NULL dereference (SPEC §13.5).
NULL_PAGE = 4096
#: Native sanitizer formats whose report, with ``abort_on_error=1``, ends in ``abort()``.
SANITIZER_FORMATS: frozenset[str] = frozenset({"asan", "ubsan", "msan", "tsan", "lsan"})
#: The container exit status of a process killed by SIGABRT (128 + 6).
ABORT_STATUS = 134

#: Functions present in nearly every stack, so sharing them says nothing.
ENTRY_FUNCTIONS: frozenset[str] = frozenset(
    {
        "main",
        "_start",
        "__libc_start_main",
        "__libc_start_call_main",
        "<module>",
        "<anonymous>",
        "LLVMFuzzerTestOneInput",
    }
)
#: GCC clone suffixes (``foo.isra.0``), folded to the base name.
_CLONE_SUFFIXES: frozenset[str] = frozenset(
    {"isra", "part", "constprop", "cold", "lto_priv", "localalias", "clone"}
)

#: Generic class: an out-of-bounds access whose memory kind the tool did not say.
OOB = "out-of-bounds"
#: Specific classes that a generic out-of-bounds report is equivalent to.
_OOB_FAMILY: frozenset[str] = frozenset({"heap-overflow", "stack-overflow", "global-overflow"})

#: (keyword, class), checked in order against the normalized text; first hit wins. Order
#: matters: "heap-use-after-free" must hit use-after-free before anything "heap".
_CLASS_KEYWORDS: tuple[tuple[str, str], ...] = (
    ("use after free", "use-after-free"),
    ("use after return", "use-after-return"),
    ("use after scope", "use-after-scope"),
    ("double free", "double-free"),
    ("invalid free", "invalid-free"),
    ("heap buffer overflow", "heap-overflow"),
    ("heap based buffer overflow", "heap-overflow"),
    ("heap overflow", "heap-overflow"),
    ("heap buffer overread", "heap-overflow"),
    ("heap overread", "heap-overflow"),
    ("stack buffer overflow", "stack-overflow"),
    ("stack buffer underflow", "stack-overflow"),
    ("stack based buffer overflow", "stack-overflow"),
    ("global buffer overflow", "global-overflow"),
    ("stack overflow", "stack-exhaustion"),
    ("stack exhaustion", "stack-exhaustion"),
    ("uncontrolled recursion", "stack-exhaustion"),
    ("null pointer", "null-deref"),
    ("null dereference", "null-deref"),
    ("null deref", "null-deref"),
    ("nullpointerexception", "null-deref"),
    ("nil pointer", "null-deref"),
    ("divide by zero", "divide-by-zero"),
    ("division by zero", "divide-by-zero"),
    ("zerodivisionerror", "divide-by-zero"),
    ("sigfpe", "divide-by-zero"),
    ("integer overflow", "integer-overflow"),
    ("signed integer overflow", "integer-overflow"),
    ("unsigned integer overflow", "integer-overflow"),
    ("shift exponent", "invalid-shift"),
    ("shift base", "invalid-shift"),
    ("memory leak", "memory-leak"),
    ("detected memory leaks", "memory-leak"),
    ("data race", "data-race"),
    ("uninitialized", "uninitialized-read"),
    ("use of uninitialised", "uninitialized-read"),
    ("out of bounds", OOB),
    ("buffer overflow", OOB),
    ("buffer overread", OOB),
    ("invalid write", OOB),
    ("invalid read", OOB),
    ("arrayindexoutofbounds", OOB),
    ("index out of range", OOB),
)

#: Prose "stack overflow" may mean either a stack buffer overflow or stack exhaustion.
STACK_AMBIGUOUS = "stack-overflow-or-exhaustion"

#: CWE numbers with an unambiguous class.
_CWE_CLASSES: dict[str, str] = {
    "CWE-121": "stack-overflow",
    "CWE-122": "heap-overflow",
    "CWE-119": OOB,
    "CWE-120": OOB,
    "CWE-125": OOB,
    "CWE-787": OOB,
    "CWE-416": "use-after-free",
    "CWE-415": "double-free",
    "CWE-476": "null-deref",
    "CWE-190": "integer-overflow",
    "CWE-369": "divide-by-zero",
    "CWE-674": "stack-exhaustion",
    "CWE-401": "memory-leak",
    "CWE-457": "uninitialized-read",
    "CWE-908": "uninitialized-read",
}


def _normalize_text(text: str) -> str:
    """Lowercase, with ``-``, ``_`` and runs of whitespace folded to one space."""
    return " ".join(text.lower().replace("-", " ").replace("_", " ").split())


#: A negation cue right before a class keyword: "not a use after free", "rather than a
#: heap overflow". Anchored at the end of a short window, bounded, linear-time (P7).
_NEGATION_BEFORE_RE = re.compile(
    r"(?:\bnot|\bno|\bnever|\bnor|\bneither|\bisn't|\bwasn't|\baren't|\brather than"
    r"|\binstead of|\bruled out)(?: (?:a|an|the|any))? $"
)
_NEGATION_WINDOW = 24


def _negated_at(norm: str, pos: int, keyword: str) -> bool:
    """Whether the keyword occurrence at ``pos`` is negated ("not a use after free").

    "no null pointer check" names a missing check, not the absence of the bug, so a
    keyword directly followed by "check" is never negated.
    """
    if norm.startswith(" check", pos + len(keyword)):
        return False
    return _NEGATION_BEFORE_RE.search(norm[max(0, pos - _NEGATION_WINDOW) : pos]) is not None


def _first_affirmed(norm: str, keyword: str) -> int:
    """Position of the first non-negated occurrence of ``keyword`` in ``norm``, or -1."""
    pos = norm.find(keyword)
    while pos >= 0:
        if not _negated_at(norm, pos, keyword):
            return pos
        pos = norm.find(keyword, pos + 1)
    return -1


def bug_class_of_text(text: str | None, *, prose: bool = False) -> str | None:
    """The equivalence class a free-text bug description names, or ``None``.

    The keyword that occurs *earliest* wins (the longest one on a tie), and negated
    occurrences are skipped, so "heap overflow, not a use after free" and "not a use after
    free but a heap overflow" are both heap overflows. With ``prose=True`` (report text
    rather than sanitizer output) a bare "stack overflow" is ambiguous: reporters use it for
    stack buffer overflows as often as for stack exhaustion.
    """
    if not text:
        return None
    norm = _normalize_text(text[:512])
    best: tuple[int, int, str] | None = None
    for keyword, cls in _CLASS_KEYWORDS:
        pos = _first_affirmed(norm, keyword)
        if pos < 0:
            continue
        key = (pos, -len(keyword), cls)
        if best is None or key[:2] < best[:2]:
            best = key
    if best is None:
        return None
    cls = best[2]
    if prose and cls == "stack-exhaustion" and norm.startswith("stack overflow", best[0]):
        return STACK_AMBIGUOUS
    return cls


def bug_class_of_cwe(cwe: str | None) -> str | None:
    if not cwe:
        return None
    return _CWE_CLASSES.get(cwe.strip().upper())


def bug_class(trace: TraceData) -> str | None:
    """The equivalence class of a parsed trace's bug (SPEC §13.5).

    A SEGV on an address near 0 is a NULL dereference; a valgrind invalid access that the
    tool placed against a heap block is a heap overflow.
    """
    raw = (trace.bug_type or "").lower()
    if raw in {"segv", "sigsegv"} or "segv" in raw:
        address = trace.address if trace.address is not None else trace.access_address
        if address is not None and 0 <= address < NULL_PAGE:
            return "null-deref"
        return "segv"
    cls = bug_class_of_text(trace.bug_type)
    if cls == OOB and trace.format == "valgrind" and trace.region is not None:
        return "heap-overflow"
    if cls is None:
        cls = bug_class_of_text(trace.message)
    if cls is None and trace.bug_type:
        return _normalize_text(trace.bug_type[:80]).replace(" ", "-")
    return cls


def classes_equivalent(left: str | None, right: str | None) -> bool:
    """Whether two bug classes describe the same bug (SPEC §13.5 equivalence classes).

    A generic out-of-bounds access is equivalent to any specific overflow; nothing is
    equivalent to an unknown class.
    """
    if left is None or right is None:
        return False
    if left == right:
        return True
    pair = {left, right}
    if STACK_AMBIGUOUS in pair:
        return bool(pair & {"stack-overflow", "stack-exhaustion"})
    return OOB in pair and bool(pair & _OOB_FAMILY)


def normalize_function(name: str) -> str:
    """``ns::f(int)`` -> ``f``; ``foo.isra.0`` -> ``foo``; ``main.pick`` -> ``pick``."""
    parts = name.strip().split(".")
    kept: list[str] = []
    for part in parts:
        if part in _CLONE_SUFFIXES or (kept and part.isdigit()):
            break
        kept.append(part)
    return bare_function(".".join(kept) if kept else name)


def _under_poc(path: str | None) -> bool:
    if not path:
        return False
    norm = path.replace("\\", "/")
    return norm == POC_ROOT or norm.startswith(POC_ROOT + "/")


def is_poc_frame(frame: Frame) -> bool:
    """Whether ``frame`` is in the reporter's staged PoC (``/poc``), not the project."""
    return _under_poc(frame.path) or _under_poc(frame.original_path) or _under_poc(frame.module)


def app_frames(frames: Sequence[Frame]) -> list[Frame]:
    """Application frames: not runtime, not the PoC, named, and not a universal entry point."""
    out: list[Frame] = []
    for frame in frames[:MAX_FRAMES]:
        if frame.is_runtime or not frame.function or is_poc_frame(frame):
            continue
        if normalize_function(frame.function) in ENTRY_FUNCTIONS:
            continue
        out.append(frame)
    return out


def crash_in_project(trace: TraceData) -> bool:
    """Whether the crashing frame is demonstrably project code.

    The first non-runtime frame must carry a source path, and that path must not be under
    ``/poc``. A frame without a path cannot be attributed, so this answers ``False`` (P4:
    a wrong REPRODUCED is as bad as a wrong UNGROUNDED).
    """
    for frame in trace.frames[:MAX_FRAMES]:
        if frame.is_runtime or not frame.function:
            continue
        return bool(frame.path) and not is_poc_frame(frame)
    return False


def app_function_names(trace: TraceData) -> list[str]:
    return [normalize_function(f.function or "") for f in app_frames(trace.frames)]


@dataclass(frozen=True, slots=True)
class Signature:
    """A crash signature (SPEC §13.5)."""

    sanitizer: str
    bug_class: str | None
    access_kind: str | None
    access_size: int | None
    top_functions: tuple[str, ...]
    frame0_file: str | None
    frame0_line: int | None

    def as_dict(self) -> dict[str, object]:
        return {
            "sanitizer": self.sanitizer,
            "bug_class": self.bug_class,
            "access_kind": self.access_kind,
            "access_size": self.access_size,
            "top_functions": list(self.top_functions),
            "frame0": (
                f"{self.frame0_file}:{self.frame0_line}"
                if self.frame0_file and self.frame0_line is not None
                else self.frame0_file
            ),
        }


def _basename(path: str) -> str:
    return path.replace("\\", "/").rsplit("/", 1)[-1]


def signature(trace: TraceData) -> Signature:
    """Build the signature of one trace. Frame 0 is the first application frame."""
    apps = app_frames(trace.frames)
    first = apps[0] if apps else None
    return Signature(
        sanitizer=trace.format,
        bug_class=bug_class(trace),
        access_kind=trace.access.kind if trace.access else None,
        access_size=trace.access.size if trace.access else None,
        top_functions=tuple(normalize_function(f.function or "") for f in apps[:SIGNATURE_FRAMES]),
        frame0_file=_basename(first.path) if first and first.path else None,
        frame0_line=first.line if first else None,
    )


def _prefix_lcs(a: Sequence[str], b: Sequence[str]) -> list[list[int]]:
    """``t[i][j]`` = LCS length of ``a[:i]`` and ``b[:j]``; one O(len(a) * len(b)) pass."""
    table = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i, x in enumerate(a):
        row, nxt = table[i], table[i + 1]
        for j, y in enumerate(b):
            nxt[j + 1] = row[j] + 1 if x == y else max(row[j + 1], nxt[j])
    return table


def anchored_alignment(claimed: Sequence[str], observed: Sequence[str]) -> int:
    """Longest alignment of ``claimed`` against ``observed`` that pairs claimed frame 0 or 1.

    For each anchor ``claimed[i]`` (i in 0, 1) paired with an equal ``observed[j]``, the
    alignment is ``LCS(before) + 1 + LCS(after)``. Returns 0 when neither anchor appears.
    Both LCS tables are built once, so the work is O(n * m) with n, m <= ``MAX_FRAMES``
    however many times the anchors recur (P7).
    """
    claimed = list(claimed[:MAX_FRAMES])
    observed = list(observed[:MAX_FRAMES])
    if not claimed or not observed:
        return 0
    before = _prefix_lcs(claimed, observed)
    # after[i][j] = LCS(claimed[i:], observed[j:]), via the prefix table of the reversals.
    rev = _prefix_lcs(claimed[::-1], observed[::-1])
    n, m = len(claimed), len(observed)
    best = 0
    for i in range(min(2, n)):
        for j, name in enumerate(observed):
            if name != claimed[i]:
                continue
            length = before[i][j] + 1 + rev[n - i - 1][m - j - 1]
            best = max(best, length)
    return best


@dataclass(frozen=True, slots=True)
class MatchResult:
    """The outcome of comparing an observed crash with what the report claimed."""

    matched: bool
    mode: str  # "trace" or "locus"
    class_equivalent: bool
    alignment: int
    reason: str


def match_traces(claimed: TraceData, observed: TraceData) -> MatchResult:
    """Match an observed crash against a trace the report quoted (SPEC §13.5)."""
    claimed_cls, observed_cls = bug_class(claimed), bug_class(observed)
    equivalent = classes_equivalent(claimed_cls, observed_cls)
    alignment = anchored_alignment(app_function_names(claimed), app_function_names(observed))
    matched = equivalent and alignment >= MIN_ALIGNMENT
    if matched:
        reason = f"same bug class ({observed_cls}) and {alignment} application frames align"
    elif not equivalent:
        reason = (
            f"bug class differs: claimed {claimed_cls or 'unknown'},"
            f" observed {observed_cls or 'unknown'}"
        )
    else:
        reason = (
            f"same bug class ({observed_cls}) but only {alignment} application frame(s)"
            f" align with the claimed top frames (need {MIN_ALIGNMENT})"
        )
    return MatchResult(matched, "trace", equivalent, alignment, reason)


def match_locus(
    claimed_class: str | None, locus_function: str | None, observed: TraceData
) -> MatchResult:
    """Match for a report without a trace: class plus the locus in the top 5 frames."""
    observed_cls = bug_class(observed)
    equivalent = classes_equivalent(claimed_class, observed_cls)
    top = [normalize_function(f.function or "") for f in app_frames(observed.frames)[:LOCUS_DEPTH]]
    locus = normalize_function(locus_function) if locus_function else None
    found = locus is not None and locus in top
    matched = equivalent and found
    if matched:
        reason = f"same bug class ({observed_cls}) and {locus} is in the top {LOCUS_DEPTH} frames"
    elif not equivalent:
        reason = (
            f"bug class differs: claimed {claimed_class or 'unknown'},"
            f" observed {observed_cls or 'unknown'}"
        )
    else:
        reason = f"the claimed function is not in the top {LOCUS_DEPTH} frames of the crash"
    return MatchResult(matched, "locus", equivalent, 1 if found else 0, reason)


def parse_run_output(output: str) -> list[TraceData]:
    """Every trace in some output, in order of appearance (at most ``MAX_OBSERVED``, last kept)."""
    return [parsed.data for parsed in parse_traces(output)][-MAX_OBSERVED:]


@dataclass(frozen=True, slots=True)
class TerminatingReport:
    """The last trace on a run's stderr, and whether anything but whitespace follows it."""

    trace: TraceData
    at_tail: bool


def terminating_report(stderr: str) -> TerminatingReport | None:
    """The report that ended the run: the last trace on stderr, or ``None``.

    stdout is never read: a PoC (or a target echoing its input) can print anything there.
    Earlier reports on stderr are ignored too, since with ``abort_on_error=1`` only the
    last one can have terminated the process; and a sanitizer that aborts prints nothing
    after its report, so text after it (``at_tail=False``) means the report did not end
    the process and was probably echoed (P7).
    """
    parsed = parse_traces(stderr)
    if not parsed:
        return None
    last = parsed[-1]
    return TerminatingReport(last.data, not stderr[last.end :].strip())


def terminating_trace(stderr: str) -> TraceData | None:
    """:func:`terminating_report`'s trace, or ``None``."""
    report = terminating_report(stderr)
    return report.trace if report else None


def exit_status_fits(trace: TraceData, exit_code: int) -> bool:
    """Whether ``exit_code`` is what the process leaves when ``trace`` ends it.

    Only native sanitizer reports have a contract here (``abort_on_error=1`` in every
    recipe, so SIGABRT: 134). Anything else is not attributed: a status the PoC could
    choose proves nothing about who printed the report.
    """
    return trace.format in SANITIZER_FORMATS and exit_code == ABORT_STATUS


@dataclass(frozen=True, slots=True)
class ReproFailure:
    """A repro attempt that did not get as far as running the PoC (build or infrastructure).

    ``stage`` is a short label such as ``"build_failed"`` or ``"infra_error"``; C19 turns
    it into ``ERROR`` evidence with no strength.
    """

    stage: str
    detail: str = ""
    commands: tuple[CommandRecord, ...] = ()
