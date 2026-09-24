# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The MCP server (SPEC §16.3): Nikasha's checks as tools for an MCP client, over stdio.

An MCP client (Claude Code, Claude Desktop or any other) starts ``nikasha mcp`` as a child
process and calls four tools: ``check_report``, ``check_trace``, ``symbol_timeline`` and
``explain``. Each returns a compact JSON object whose first field is a one-line ``summary``.
The tools are thin: ``check_report`` runs :func:`nikasha.pipeline.check_report` over a
temporary file, ``check_trace`` is :mod:`nikasha.code.trace_forensics`, ``symbol_timeline``
is :mod:`nikasha.code.timeline`, and ``explain`` replays the fusion ledger of a result this
server produced earlier. Nothing here changes what the engine concludes (P2).

Every argument is hostile (P7). A repository is a local path or an ``https://`` URL and
nothing else; versions and symbols go through :func:`nikasha.code.gitio.safe_rev` before
they get anywhere near git; report and trace text is capped exactly as the CLI caps it.
The server is offline unless started with ``--online`` (P3), keeps results only in memory,
and never registers reproduction unless ``NIKASHA_MCP_ALLOW_REPRO=1`` (and even then this
build answers "not available"). The ``mcp`` package is imported lazily, so a minimal
install keeps the whole CLI and the command explains how to install the ``[mcp]`` extra.

The tool functions live in :class:`NikashaTools` and need no ``mcp`` at all, so they are
testable without the extra; :func:`build_server` is the only place the SDK is touched.
"""

from __future__ import annotations

import importlib
import os
import re
import shutil
import tempfile
from collections import Counter, OrderedDict
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any

import typer
from rich.console import Console
from rich.markup import escape

from nikasha.code.gitio import safe_rev
from nikasha.errors import ForbiddenCommandError, NikashaError
from nikasha.model.ids import ID_LENGTH, stable_id
from nikasha.resolve.repo import canonical_url
from nikasha.version import __version__

if TYPE_CHECKING:
    from mcp.server import MCPServer  # type: ignore[import-not-found, unused-ignore]

    from nikasha.code.index import CodeIndex
    from nikasha.code.timeline import Timeline
    from nikasha.code.trace_forensics import TraceAnalysis
    from nikasha.model.claims import TraceClaim
    from nikasha.model.result import ResolvedTarget
    from nikasha.pipeline import CheckReport
    from nikasha.resolve.refs import ReleaseList
    from nikasha.resolve.target import Resolution

#: Set to ``1`` to register the ``reproduce`` tool (SPEC §16.3). It answers "not available"
#: until sandbox reproduction lands (M5), so a client can discover it without running anything.
ALLOW_REPRO_ENV = "NIKASHA_MCP_ALLOW_REPRO"
NOT_AVAILABLE = "not available in this build"
MISSING_EXTRA = "the MCP server needs the mcp package: install nikasha[mcp]"
#: Results kept for ``explain``, oldest evicted first. Bounded, so a client cannot grow the
#: process without limit by checking report after report.
MAX_STORED_RESULTS = 32
#: A repository argument longer than this is refused before anything looks at it.
MAX_REPO_CHARS = 4096
#: Commits are abbreviated to this many hex digits in summaries.
SHORT_SHA = 12
_CONTROL_LIMIT = 0x20
_RESULT_ID_RE = re.compile(rf"\A[0-9a-f]{{{ID_LENGTH}}}\Z")

#: What the client model is told about this server (P1: claims, never people).
INSTRUCTIONS = (
    "Nikasha checks the factual claims in a vulnerability report against the project's "
    "source code at the exact version the report names, and answers with evidence about "
    "claims, never with judgements about people. Repositories are local paths or https:// "
    "URLs; unless the server was started with --online, only local and already-cached "
    "repositories can be read. check_report returns a result_id; pass it to explain for the "
    "full evidence ledger. Verdicts: REPRODUCED, GROUNDED, MIXED, UNGROUNDED and "
    "INSUFFICIENT. When evidence is thin the answer is MIXED or INSUFFICIENT with questions "
    "for the reporter, not a refutation."
)


# -- argument validation (every argument is hostile, P7) --------------------------------


def _has_control(text: str) -> bool:
    return any(ord(ch) < _CONTROL_LIMIT or ch == "\x7f" for ch in text)


def validate_repo(repo: str) -> str:
    """A local path or an ``https://`` URL (SPEC §10, ADR 0006); anything else is refused.

    URLs are canonicalized by :func:`nikasha.resolve.repo.canonical_url`, which allows only
    ``https`` and validates every path component. Whether a local path is a repository is
    decided later by :func:`nikasha.resolve.repo.acquire`; here it only has to be a path.
    """
    value = repo.strip()
    if not value:
        raise NikashaError("repo must be a local path or an https:// repository URL")
    if len(value) > MAX_REPO_CHARS:
        raise NikashaError(f"repo is longer than {MAX_REPO_CHARS} characters")
    if _has_control(value):
        raise NikashaError("repo contains control characters")
    if "://" in value or value.startswith(("git@", "ext::")):
        return canonical_url(value)
    if value.startswith("-"):
        raise NikashaError("repo must be a path or an https:// URL, not an option")
    return value


def validate_rev(value: str, what: str = "version") -> str:
    """A revision or version from the client, checked by :func:`~nikasha.code.gitio.safe_rev`.

    The same rule the CLI applies to text taken from a report: no option-looking values,
    no control characters, no absurd lengths. The argument name goes into the message.
    """
    text = value.strip()
    try:
        return safe_rev(text)
    except ForbiddenCommandError as exc:
        raise NikashaError(f"{what}: {exc}") from exc


def validate_symbol(symbol: str) -> str:
    """A symbol name: the revision rules plus "one identifier", so a search term cannot
    smuggle whitespace-separated words into a batched grep."""
    text = validate_rev(symbol, "symbol")
    if any(ch.isspace() for ch in text):
        raise NikashaError("symbol must be a single identifier without whitespace")
    return text


def validate_text(text: str, what: str) -> str:
    """Report or trace text, capped like the CLI caps stdin (``ingest.MAX_INPUT_BYTES``)."""
    from nikasha.ingest import MAX_INPUT_BYTES  # noqa: PLC0415 (keeps the CLI import light)

    if not text.strip():
        raise NikashaError(f"{what} is empty")
    if len(text) > MAX_INPUT_BYTES or len(text.encode("utf-8", "surrogatepass")) > MAX_INPUT_BYTES:
        raise NikashaError(f"{what} is larger than the {MAX_INPUT_BYTES:,}-byte input limit")
    return text


def validate_result_id(result_id: str) -> str:
    """The ``result_id`` a check tool returned: exactly the hex digits of a content ID."""
    value = result_id.strip().lower()
    if not _RESULT_ID_RE.match(value):
        raise NikashaError(
            f"result_id must be the {ID_LENGTH}-character ID that check_report returned"
        )
    return value


def repro_allowed(environ: Mapping[str, str] | None = None) -> bool:
    """Whether ``NIKASHA_MCP_ALLOW_REPRO=1`` is set (the only way to register ``reproduce``)."""
    env: Mapping[str, str] = os.environ if environ is None else environ
    return env.get(ALLOW_REPRO_ENV, "").strip() == "1"


# -- the in-memory result store ----------------------------------------------------------


class ResultStore:
    """Results of this server session, keyed by content ID, in memory only (P3).

    The key is the ID of the result's own JSON (without timings), so the same report checked
    twice against the same commit gets the same ID (P2) and ``explain`` can be asked about
    either run. Nothing is written to disk: a report pasted into a client never outlives
    the server process. The store is bounded; the oldest result goes first.
    """

    def __init__(self, capacity: int = MAX_STORED_RESULTS) -> None:
        if capacity < 1:
            raise ValueError("capacity must be at least 1")
        self.capacity = capacity
        self._items: OrderedDict[str, CheckReport] = OrderedDict()

    @staticmethod
    def id_of(checked: CheckReport) -> str:
        """The content ID of a finished run: ``sha256("result" + JSON without timings)[:12]``."""
        return stable_id("result", checked.result.to_json(include_timings=False))

    def put(self, checked: CheckReport) -> str:
        result_id = self.id_of(checked)
        self._items.pop(result_id, None)
        self._items[result_id] = checked
        while len(self._items) > self.capacity:
            self._items.popitem(last=False)
        return result_id

    def get(self, result_id: str) -> CheckReport | None:
        return self._items.get(result_id)

    def __len__(self) -> int:
        return len(self._items)

    @property
    def ids(self) -> tuple[str, ...]:
        """Stored IDs, oldest first."""
        return tuple(self._items)


# -- payloads: compact JSON plus a one-line summary ---------------------------------------


def _count(n: int, noun: str) -> str:
    """``1 claim``, ``2 claims``."""
    return f"{n} {noun}" if n == 1 else f"{n} {noun}s"


def _where(target: ResolvedTarget | None) -> str:
    """``v1.2.0``, an abbreviated commit, or a plain statement that nothing resolved."""
    if target is None or target.commit is None:
        return "no resolved version"
    return target.ref_name or target.commit[:SHORT_SHA]


def _target_payload(target: ResolvedTarget | None) -> dict[str, Any] | None:
    if target is None:
        return None
    return {
        "repo_url": target.repo_url,
        "ref_name": target.ref_name,
        "commit": target.commit,
        "method": target.method,
        "confidence": target.confidence,
        "alternatives": list(target.alternatives),
        "warnings": list(target.warnings),
    }


def report_payload(checked: CheckReport, result_id: str) -> dict[str, Any]:
    """The compact answer of ``check_report``: verdict, target, claims, evidence, questions.

    The full dossier (locations, commands, details, the ledger) is one ``explain`` away, so
    this stays small enough to sit in a conversation.
    """
    from nikasha.render.terminal import claim_label  # noqa: PLC0415

    result = checked.result
    verdict = checked.verdict
    outcomes = Counter(item.outcome for item in result.evidence)
    kinds = Counter(claim.kind for claim in result.claims)
    summary = (
        f"{verdict.label} ({verdict.score}/100, confidence {verdict.confidence}) at "
        f"{_where(result.target)}: {_count(len(result.claims), 'claim')}, "
        f"{outcomes['SUPPORTS']} supported, {outcomes['REFUTES']} refuted, "
        f"{_count(len(verdict.questions), 'question')} for the reporter."
    )
    warnings = list(result.report.warnings)
    if result.target is not None:
        warnings += list(result.target.warnings)
    return {
        "summary": summary,
        "result_id": result_id,
        "verdict": {
            "label": verdict.label,
            "score": verdict.score,
            "confidence": verdict.confidence,
            "rule": verdict.rule,
            "notes": list(verdict.notes),
            "key_evidence": list(verdict.key_evidence),
        },
        "target": _target_payload(result.target),
        "claims": {
            "total": len(result.claims),
            "core": sum(claim.role == "core" for claim in result.claims),
            "by_kind": dict(sorted(kinds.items())),
            "items": [
                {
                    "id": claim.id,
                    "kind": claim.kind,
                    "role": claim.role,
                    "provenance": claim.provenance,
                    "label": claim_label(claim),
                }
                for claim in result.claims
            ],
        },
        "evidence": [
            {
                "id": item.id,
                "check_id": item.check_id,
                "outcome": item.outcome,
                "group": item.group,
                "strength": item.strength,
                "summary": item.summary,
                "claim_ids": list(item.claim_ids),
            }
            for item in result.evidence
        ],
        "questions": [
            {"text": question.text, "rationale": question.rationale}
            for question in verdict.questions
        ],
        "warnings": warnings,
        "mode": result.environment.mode,
        "tool_version": result.tool_version,
    }


def explain_payload(checked: CheckReport, result_id: str) -> dict[str, Any]:
    """Everything behind a verdict (P6): the ledger, every claim and every evidence item with
    its locations and commands. The report body is left out; the client already has it."""
    result = checked.result
    ledger = checked.ledger
    verdict = checked.verdict
    data = result.model_dump(mode="json", by_alias=True)
    contributions = [
        {
            "evidence_id": item.evidence_id,
            "check_id": item.check_id,
            "group": item.group,
            "strength": round(item.strength, 4),
            "rank": item.rank,
            "weight": round(item.weight, 4),
            "contribution": round(item.contribution, 4),
            "running": round(running, 4),
        }
        for item, running in ledger.running()
    ]
    summary = (
        f"{verdict.label} by rule {verdict.rule!r}: prior {ledger.prior:+.3f}, total "
        f"log-odds {ledger.log_odds:+.3f} from {len(contributions)} contributions in "
        f"{len(ledger.groups)} groups; score {ledger.score}/100, confidence "
        f"{verdict.confidence}."
    )
    return {
        "summary": summary,
        "result_id": result_id,
        "verdict": data["verdict"],
        "ledger": {
            "prior": round(ledger.prior, 4),
            "log_odds": round(ledger.log_odds, 4),
            "score": ledger.score,
            "calibration": ledger.calibration,
            "groups": list(ledger.groups),
            "total_absolute": round(ledger.total_absolute, 4),
            "contributions": contributions,
        },
        "target": data["target"],
        "claims": data["claims"],
        "evidence": data["evidence"],
        "report": {
            "id": result.report.id,
            "title": result.report.title,
            "kind": result.report.source.kind,
            "warnings": list(result.report.warnings),
        },
        "mode": result.environment.mode,
        "tool_version": result.tool_version,
    }


def trace_payload(
    traces: Sequence[TraceClaim],
    analyses: Sequence[TraceAnalysis],
    target: ResolvedTarget,
) -> dict[str, Any]:
    """Frame by frame and edge by edge, as ``nikasha trace --json`` reports it."""
    items: list[dict[str, Any]] = []
    checkable = consistent = generated = edges_total = edges_found = 0
    for claim, analysis in zip(traces, analyses, strict=True):
        frames: list[dict[str, Any]] = []
        for frame in analysis.frames:
            checkable += int(frame.checkable)
            consistent += int(frame.checkable and frame.consistent)
            generated += int(frame.generated is not None)
            frames.append(
                {
                    "index": frame.index,
                    "function": frame.function,
                    "claimed_path": frame.claimed_path,
                    "line": frame.line,
                    "resolved_path": frame.resolved_path,
                    "file_exists": frame.file_exists,
                    "n_lines": frame.n_lines,
                    "line_in_bounds": frame.line_in_bounds,
                    "actual_function": frame.actual_function,
                    "function_matches": frame.function_matches,
                    "function_defined_elsewhere": frame.function_defined_elsewhere,
                    "generated": frame.generated.reason if frame.generated else None,
                    "checkable": frame.checkable,
                    "consistent": frame.consistent,
                }
            )
        edges = [
            {
                "caller": edge.caller,
                "callee": edge.callee,
                "kind": edge.kind,
                "caller_calls": list(edge.caller_calls),
            }
            for edge in analysis.edges
        ]
        edges_total += len(edges)
        edges_found += sum(edge.kind != "none" for edge in analysis.edges)
        items.append(
            {
                "format": claim.format,
                "bug_type": claim.bug_type,
                "commit": analysis.commit,
                "ratio": analysis.ratio,
                "frames": frames,
                "edges": edges,
            }
        )
    commit = target.commit[:SHORT_SHA] if target.commit else "?"
    summary = (
        f"{_count(len(traces), 'trace')} at {_where(target)} ({commit}): {consistent} of "
        f"{checkable} checkable frames consistent; {edges_found} of {edges_total} call "
        f"edges found in the call graph."
    )
    if generated:
        summary += f" {_count(generated, 'frame')} in generated files not judged."
    return {"summary": summary, "target": _target_payload(target), "traces": items}


def timeline_payload(timeline: Timeline, suggestions: Sequence[str]) -> dict[str, Any]:
    """Where a symbol is defined, release by release, as ``nikasha timeline --json`` says it.

    Absence is worded conservatively (P4): an incomplete history search or a release whose
    files did not parse cleanly is reported as uncertainty, never as "never existed".
    """
    defined = sum(p.defined for p in timeline.presence)
    total = len(timeline.presence)
    if timeline.runs:
        ranges = ", ".join(f"{a} to {b}" if a != b else a for a, b in timeline.runs)
        summary = f"{timeline.symbol} is defined in {ranges} ({defined} of {total} releases)."
    else:
        summary = f"No release defines {timeline.symbol}"
        if timeline.never_in_history:
            summary += " and the name never appears anywhere in the git history"
        elif not timeline.history_complete:
            summary += "; the history search was incomplete, so absence is not established"
        elif timeline.first_commit_with_text:
            summary += (
                f"; the text first appears in commit {timeline.first_commit_with_text[:SHORT_SHA]}"
            )
        if suggestions:
            summary += "; did you mean: " + ", ".join(suggestions)
        summary += "."
    if timeline.uncertain_releases:
        summary += (
            f" Uncertain in {_count(len(timeline.uncertain_releases), 'release')} where the "
            "name appears in files that did not parse cleanly."
        )
    return {
        "summary": summary,
        "symbol": timeline.symbol,
        "strategy": timeline.strategy,
        "releases": total,
        "runs": [[first, last] for first, last in timeline.runs],
        "presence": [
            {
                "release": p.release,
                "defined": p.defined,
                "referenced": p.referenced,
                "paths": list(p.paths),
                "partial": list(p.partial),
                "uncertain": p.uncertain,
            }
            for p in timeline.presence
        ],
        "uncertain_releases": list(timeline.uncertain_releases),
        "history_complete": timeline.history_complete,
        "never_in_history": timeline.never_in_history,
        "first_commit_with_text": timeline.first_commit_with_text,
        "suggestions": list(suggestions),
        "notes": list(timeline.notes),
    }


# -- the tool functions (no mcp needed) ----------------------------------------------------


@contextmanager
def _temporary_report(text: str) -> Iterator[Path]:
    """Write the text to a private temporary file for the pipeline, then remove it.

    The pipeline reads reports from paths. The file has no extension, so the format is
    sniffed from the content exactly as for stdin, and ``mkdtemp`` creates the directory
    with owner-only permissions, so a pasted report is never readable by other users.
    """
    directory = Path(tempfile.mkdtemp(prefix="nikasha-mcp-"))
    try:
        path = directory / "report"
        path.write_bytes(text.encode("utf-8", "surrogatepass"))
        yield path
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def _forget_source_path(checked: CheckReport) -> CheckReport:
    """Drop the temporary path from the result. A run over pasted text records no URI, like
    a run over stdin, so two servers checking the same text produce the same bytes (P2) and
    no result ever names a directory on this machine (P3)."""
    report = checked.result.report
    if report.source.uri is None:
        return checked
    source = report.source.model_copy(update={"uri": None})
    result = checked.result.model_copy(
        update={"report": report.model_copy(update={"source": source})}
    )
    return replace(checked, result=result)


def _resolve(repo: str, *, version: str | None = None, online: bool = False) -> Resolution:
    """Resolve a repository (and optionally a version) with no report, as the CLI does."""
    from nikasha.ingest import ingest_string  # noqa: PLC0415
    from nikasha.resolve.target import resolve_target  # noqa: PLC0415

    empty = ingest_string("", input_format="text")
    return resolve_target(empty, [], repo=repo, version=version, online=online)


def _suggestions(index: CodeIndex, releases: ReleaseList, name: str) -> list[str]:
    """The "did you mean" names from the latest release, as ``nikasha timeline`` prints them."""
    from nikasha.code.bktree import BKTree  # noqa: PLC0415

    finals = releases.finals()
    if not finals:
        return []
    index.index_commit(finals[-1].commit)
    names = {str(row[0]) for row in index.db.execute("SELECT DISTINCT name FROM symbols")}
    return BKTree(sorted(names)).suggest(name)


@dataclass
class NikashaTools:
    """The functions behind the MCP tools, usable without the ``mcp`` package.

    ``online`` is the server-wide switch (``nikasha mcp --online``). ``check_trace`` and
    ``symbol_timeline`` follow it; ``check_report`` takes its own ``online`` argument, which
    is honoured only when the server allows the network and refused otherwise, so a client
    can never turn an offline server online (P3).
    """

    online: bool = False
    store: ResultStore = field(default_factory=ResultStore)

    def _network(self, requested: bool) -> bool:
        if requested and not self.online:
            raise NikashaError(
                "this server runs offline; start it with `nikasha mcp --online` to allow "
                "network access"
            )
        return requested

    def check_report(
        self,
        report_text: str,
        repo: str,
        version: str | None = None,
        online: bool = False,
    ) -> dict[str, Any]:
        """Run the whole pipeline over ``report_text`` and keep the result for ``explain``."""
        from nikasha.pipeline import check_report as run_pipeline  # noqa: PLC0415

        text = validate_text(report_text, "report_text")
        repo_arg = validate_repo(repo)
        rev = validate_rev(version, "version") if version else None
        use_network = self._network(online)
        with _temporary_report(text) as path:
            checked = run_pipeline(path, repo=repo_arg, version=rev, online=use_network)
        checked = _forget_source_path(checked)
        return report_payload(checked, self.store.put(checked))

    def check_trace(self, trace_text: str, repo: str, version: str) -> dict[str, Any]:
        """Check every stack trace in ``trace_text`` against the code at ``version``."""
        from nikasha.code.index import CodeIndex  # noqa: PLC0415
        from nikasha.code.trace_forensics import analyze_trace  # noqa: PLC0415
        from nikasha.extract import extract_claims  # noqa: PLC0415
        from nikasha.ingest import ingest_string  # noqa: PLC0415
        from nikasha.model.claims import TraceClaim  # noqa: PLC0415

        text = validate_text(trace_text, "trace_text")
        repo_arg = validate_repo(repo)
        rev = validate_rev(version, "version")
        report = ingest_string(text)
        traces = [c for c in extract_claims(report).claims if isinstance(c, TraceClaim)]
        if not traces:
            raise NikashaError(
                "no stack trace found in trace_text: paste the sanitizer, debugger or runtime "
                "output itself"
            )
        res = _resolve(repo_arg, version=rev, online=self.online)
        commit = res.target.commit
        if commit is None:
            raise NikashaError(f"version {rev!r} does not resolve to a commit")
        with res.repo, CodeIndex(res.repo) as index:
            analyses = [analyze_trace(index, commit, t, project=res.project) for t in traces]
        return trace_payload(traces, analyses, res.target)

    def symbol_timeline(self, repo: str, symbol: str) -> dict[str, Any]:
        """In which releases of ``repo`` is ``symbol`` defined?"""
        from nikasha.code.index import CodeIndex  # noqa: PLC0415
        from nikasha.code.timeline import build_timeline  # noqa: PLC0415

        repo_arg = validate_repo(repo)
        name = validate_symbol(symbol)
        res = _resolve(repo_arg, online=self.online)
        with res.repo, CodeIndex(res.repo) as index:
            timeline = build_timeline(index, res.releases, name)
            suggestions = [] if timeline.ever_defined else _suggestions(index, res.releases, name)
        return timeline_payload(timeline, suggestions)

    def explain(self, result_id: str) -> dict[str, Any]:
        """The full ledger and evidence behind a result this server produced."""
        key = validate_result_id(result_id)
        checked = self.store.get(key)
        if checked is None:
            raise NikashaError(
                f"no result {key} in this session: results live in memory only (the last "
                f"{self.store.capacity}), so run check_report first"
            )
        return explain_payload(checked, key)

    def reproduce(self, repo: str, version: str, poc_text: str = "") -> dict[str, Any]:
        """Sandbox reproduction (M5) is not part of this build; the tool says so."""
        validate_repo(repo)
        validate_rev(version, "version")
        if poc_text:
            validate_text(poc_text, "poc_text")
        return {
            "summary": NOT_AVAILABLE,
            "available": False,
            "reason": (
                "sandbox reproduction arrives with milestone M5; this build registers the "
                "tool so clients can discover it, but runs no proof of concept anywhere"
            ),
        }


# -- the server ----------------------------------------------------------------------------


def _load_mcp() -> tuple[type[MCPServer], type[Exception]]:
    """Import the SDK lazily; a minimal install gets an actionable error, not a traceback."""
    try:
        server_module = importlib.import_module("mcp.server")
        exceptions = importlib.import_module("mcp.server.mcpserver.exceptions")
    except ImportError as exc:
        raise NikashaError(MISSING_EXTRA) from exc
    server_cls: type[MCPServer] = server_module.MCPServer
    tool_error: type[Exception] = exceptions.ToolError
    return server_cls, tool_error


def build_server(
    *,
    online: bool = False,
    allow_repro: bool | None = None,
    backend: NikashaTools | None = None,
) -> MCPServer:
    """Assemble the ``MCPServer`` with the four tools (five with ``NIKASHA_MCP_ALLOW_REPRO=1``).

    ``allow_repro`` overrides the environment variable (tests); ``backend`` supplies the
    tool functions and result store, so a caller can share a store between servers.
    """
    server_cls, tool_error = _load_mcp()
    tools = backend if backend is not None else NikashaTools(online=online)
    server = server_cls("nikasha", instructions=INSTRUCTIONS, version=__version__)

    def guarded(fn: Callable[..., dict[str, Any]], **kwargs: object) -> dict[str, Any]:
        """Expected failures become tool errors the client model can read and act on."""
        try:
            return fn(**kwargs)
        except NikashaError as exc:
            raise tool_error(str(exc)) from exc

    # Registered with add_tool rather than the @server.tool decorator: without the extra
    # installed the SDK's types are unknown to mypy, and an untyped decorator would fail
    # --strict, while a plain call type-checks in both environments.
    def check_report(
        report_text: str, repo: str, version: str | None = None, online: bool = False
    ) -> dict[str, Any]:
        """Check the factual claims of a vulnerability report against the source code at
        the version it names. report_text is the report (Markdown, plain text or HTML);
        repo is a local path or an https:// URL; version (optional) overrides the version
        the report names, e.g. "8.5.0" or a tag. Returns a verdict (REPRODUCED, GROUNDED,
        MIXED, UNGROUNDED or INSUFFICIENT) with a score, the claims found, one line per
        evidence item, questions for the reporter and a result_id for explain. The check
        is offline; online=true is honoured only when the server was started with
        --online."""
        return guarded(
            tools.check_report, report_text=report_text, repo=repo, version=version, online=online
        )

    def check_trace(trace_text: str, repo: str, version: str) -> dict[str, Any]:
        """Check a stack trace (ASan, UBSan, Valgrind, gdb, Python, Go, Rust, Java, Node)
        against the code at a version: for every application frame whether the file exists,
        the line is inside the file and inside the named function, and for every consecutive
        pair of frames whether the call edge exists in the call graph. trace_text is the raw
        trace; repo is a local path or an https:// URL; version is a release such as "1.2.0"
        or a tag. Frames in generated files are reported but never judged."""
        return guarded(tools.check_trace, trace_text=trace_text, repo=repo, version=version)

    def symbol_timeline(repo: str, symbol: str) -> dict[str, Any]:
        """In which releases of a repository is a function, macro or type defined? repo is a
        local path or an https:// URL; symbol is one identifier. Returns the defined ranges,
        release-by-release presence, whether the name ever appeared in git history, and
        "did you mean" names when no release defines it. An incomplete history search or a
        file that did not parse cleanly is reported as uncertainty, never as absence."""
        return guarded(tools.symbol_timeline, repo=repo, symbol=symbol)

    def explain(result_id: str) -> dict[str, Any]:
        """Everything behind a check_report result: the log-odds ledger (every strength,
        weight and contribution), every claim, and every evidence item with its code
        locations and the commands that produced it. result_id is the ID check_report
        returned in this server session."""
        return guarded(tools.explain, result_id=result_id)

    def reproduce(repo: str, version: str, poc_text: str = "") -> dict[str, Any]:
        """Reproduce a crash in the hardened sandbox. repo is a local path or an https://
        URL, version a release or tag, poc_text the proof of concept. Registered only when
        the server was started with NIKASHA_MCP_ALLOW_REPRO=1; this build reports that
        reproduction is not available and runs nothing."""
        return guarded(tools.reproduce, repo=repo, version=version, poc_text=poc_text)

    for fn in (check_report, check_trace, symbol_timeline, explain):
        server.add_tool(fn, name=fn.__name__, description=_describe(fn))
    if allow_repro if allow_repro is not None else repro_allowed():
        server.add_tool(reproduce, name="reproduce", description=_describe(reproduce))
    return server


def _describe(fn: Callable[..., object]) -> str:
    """A tool description is the function's docstring on one line: the SDK would otherwise
    hand the client the raw indentation of the source."""
    return " ".join((fn.__doc__ or "").split())


# -- the CLI command -------------------------------------------------------------------------


def mcp_command(
    online: Annotated[
        bool,
        typer.Option(
            "--online",
            help="Allow network access (clone or refresh repositories) for this server.",
        ),
    ] = False,
) -> None:
    """Serve Nikasha's checks to an MCP client over stdio (SPEC §16.3).

    Tools: check_report, check_trace, symbol_timeline and explain. Offline unless --online.
    A reproduce tool is registered only with NIKASHA_MCP_ALLOW_REPRO=1, and reports itself
    as not available in this build. Needs the mcp extra (uv sync --extra mcp). Setup for
    Claude Code and Claude Desktop is in docs/mcp.md.

    Example:
        claude mcp add nikasha -- uv run nikasha mcp
    """
    try:
        server = build_server(online=online)
    except NikashaError as exc:
        Console(stderr=True).print(f"[red]error:[/] {escape(str(exc))}", highlight=False)
        raise typer.Exit(code=1) from exc
    server.run()


def register(app: typer.Typer) -> None:
    """Add the ``mcp`` command to the CLI (wired by :mod:`nikasha.cli`)."""
    app.command("mcp")(mcp_command)


__all__ = [
    "ALLOW_REPRO_ENV",
    "INSTRUCTIONS",
    "MAX_REPO_CHARS",
    "MAX_STORED_RESULTS",
    "MISSING_EXTRA",
    "NOT_AVAILABLE",
    "NikashaTools",
    "ResultStore",
    "build_server",
    "explain_payload",
    "mcp_command",
    "register",
    "report_payload",
    "repro_allowed",
    "timeline_payload",
    "trace_payload",
    "validate_repo",
    "validate_result_id",
    "validate_rev",
    "validate_symbol",
    "validate_text",
]
