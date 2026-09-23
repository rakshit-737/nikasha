# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Trace forensics (SPEC §11.4, feeding checks C08 to C10): does a stack trace fit the code?

For every application frame: resolve its path with the PathTrie (build roots stripped by
longest suffix), check the file exists, the line is within the file, and the line falls
inside the named function. For every consecutive pair of application frames, classify the
call edge ``caller (i+1) → callee (i)`` with the call graph. Frames in generated or
release-only files are *not checkable* (never refuted; §11.5).
"""

from __future__ import annotations

import itertools
import re
from dataclasses import dataclass, field

from nikasha.code.callgraph import Edge, edge
from nikasha.code.facts import SymbolDef
from nikasha.code.generated import GeneratedMatch, generated_match
from nikasha.code.index import CodeIndex
from nikasha.code.pathtrie import PathTrie
from nikasha.model.claims import Frame, TraceData
from nikasha.resolve.products import KnownProject

_PARAMS_RE = re.compile(r"\([^()]{0,500}\)\s{0,3}(?:const)?$")
_TEMPLATE_RE = re.compile(r"<[^<>]{0,500}>")


def bare_function(name: str) -> str:
    """``ns::Class::method(int) const`` → ``method``; ``main.(*T).M`` → ``M``."""
    text = _PARAMS_RE.sub("", name.strip())
    text = _TEMPLATE_RE.sub("", text)
    for sep in ("::", "."):
        text = text.rsplit(sep, 1)[-1]
    return text.strip("()*& ")


def same_function(frame_function: str, symbol: SymbolDef) -> bool:
    bare = bare_function(frame_function)
    return bare in (symbol.name, bare_function(symbol.qname))


@dataclass
class FrameCheck:
    index: int
    function: str | None
    claimed_path: str | None
    line: int | None
    resolved_path: str | None = None
    candidates: list[str] = field(default_factory=list)
    file_exists: bool | None = None
    n_lines: int | None = None
    line_in_bounds: bool | None = None
    actual_function: str | None = None
    function_matches: bool | None = None
    function_defined_elsewhere: str | None = None
    generated: GeneratedMatch | None = None

    @property
    def checkable(self) -> bool:
        """Generated files and pathless frames are never judged. A missing file is still
        "checkable" here; whether it is third-party or fabricated needs history (C02/C08)."""
        return self.generated is None and self.claimed_path is not None

    @property
    def consistent(self) -> bool:
        return bool(
            self.file_exists
            and self.line_in_bounds is not False
            and self.function_matches is not False
        )


@dataclass
class TraceAnalysis:
    commit: str
    frames: list[FrameCheck]
    edges: list[Edge]

    @property
    def ratio(self) -> float | None:
        """Share of checkable application frames that are fully consistent (C08's r)."""
        checkable = [f for f in self.frames if f.checkable]
        if not checkable:
            return None
        return sum(f.consistent for f in checkable) / len(checkable)


def app_frames(trace: TraceData) -> list[Frame]:
    return [f for f in trace.frames if not f.is_runtime and f.function]


def _check_frame(
    index: CodeIndex,
    commit: str,
    frame: Frame,
    *,
    trie: PathTrie,
    tree_paths: set[str],
    project: KnownProject | None,
) -> FrameCheck:
    check = FrameCheck(frame.index, frame.function, frame.path, frame.line)
    if frame.path is None:
        return check
    candidates = trie.resolve(frame.path)
    function = frame.function or ""
    if len(candidates) > 1 and function:

        def defines(path: str) -> bool:
            facts = index.facts_at(commit, path)
            return facts is not None and any(same_function(function, s) for s in facts.symbols)

        candidates = trie.disambiguate(frame.path, candidates, defines)
    check.candidates = candidates
    if not candidates:
        check.generated = generated_match(
            frame.path, project=project, tree_paths=tree_paths, resolve=trie.resolve
        )
        check.file_exists = False if check.generated is None else None
        return check
    path = candidates[0]
    check.resolved_path = path
    check.file_exists = True
    check.generated = generated_match(path, project=project, tree_paths=())
    if check.generated is not None:
        return check
    facts = index.facts_at(commit, path)
    if facts is None or frame.line is None:
        return check
    check.n_lines = facts.n_lines
    check.line_in_bounds = 1 <= frame.line <= facts.n_lines
    enclosing = facts.enclosing(frame.line)
    check.actual_function = enclosing.qname if enclosing else None
    if frame.function:
        check.function_matches = enclosing is not None and same_function(frame.function, enclosing)
        if not check.function_matches:
            defined = [s for s in facts.symbols if same_function(frame.function, s)]
            if defined:
                check.function_defined_elsewhere = (
                    f"{path}:{defined[0].start_line}-{defined[0].end_line}"
                )
    return check


def analyze_trace(
    index: CodeIndex, commit: str, trace: TraceData, *, project: KnownProject | None = None
) -> TraceAnalysis:
    """Check every application frame and every consecutive call edge at ``commit``."""
    files = index.files(commit)
    tree_paths = {f.path for f in files}
    trie = PathTrie(tree_paths)
    frames = app_frames(trace)
    checks = [
        _check_frame(index, commit, f, trie=trie, tree_paths=tree_paths, project=project)
        for f in frames
    ]
    edges: list[Edge] = []
    for callee_frame, caller_frame in itertools.pairwise(frames):
        pair = [c for c in checks if c.index in (callee_frame.index, caller_frame.index)]
        if any(c.generated is not None or c.resolved_path is None for c in pair):
            continue  # edges into files outside the repository are skipped (C09)
        edges.append(
            edge(
                index,
                commit,
                bare_function(caller_frame.function or ""),
                bare_function(callee_frame.function or ""),
            )
        )
    return TraceAnalysis(commit, checks, edges)
