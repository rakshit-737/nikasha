# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The ``nikasha check`` terminal view (SPEC §15.1).

The layout puts the verdict and the resolved target first, then one row per claim with the
single most decisive piece of evidence about it. That ordering is the product: a maintainer
triaging a queue should be able to stop reading after the first two lines.

Report text and repository code are always rendered as :class:`rich.text.Text`, never as
Rich markup, so a report containing ``[bold]`` or an escape sequence cannot style or
corrupt the terminal (P7).

**Wording (P1):** every string here describes a claim or a file. Nothing in this module
describes the person who wrote the report.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence

from rich import box
from rich.console import Console, Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from nikasha.model.claims import ClaimBase
from nikasha.model.evidence import Evidence
from nikasha.model.result import Result
from nikasha.model.verdict import Verdict

#: Exit codes (SPEC §15.1). CI uses them directly, so they are part of the public contract.
EXIT_CODES: dict[str, int] = {
    "GROUNDED": 0,
    "REPRODUCED": 0,
    "MIXED": 10,
    "UNGROUNDED": 20,
    "INSUFFICIENT": 30,
}

VERDICT_STYLES: dict[str, str] = {
    "REPRODUCED": "bold green",
    "GROUNDED": "bold green",
    "MIXED": "bold yellow",
    "UNGROUNDED": "bold red",
    "INSUFFICIENT": "bold bright_black",
    "ERROR": "bold red",
}

_OUTCOME_KEY = {"SUPPORTS": "ok", "REFUTES": "fail", "NEUTRAL": "warn", "ERROR": "unknown"}
_OUTCOME_STYLE = {
    "SUPPORTS": "green",
    "REFUTES": "red",
    "NEUTRAL": "yellow",
    "ERROR": "bright_black",
}
_UNICODE = {"ok": "✓", "fail": "✗", "warn": "~", "unknown": "?"}
_ASCII = {"ok": "+", "fail": "x", "warn": "~", "unknown": "?"}

_MAX_SUMMARY = 78
_MAX_CLAIM = 42


def _box(ascii_only: bool) -> box.Box:
    """Panel borders the stream can encode; ``--ascii`` must not emit box-drawing runes."""
    return box.ASCII if ascii_only else box.ROUNDED


def exit_code(label: str) -> int:
    """The process exit code for a verdict label; anything unknown is an error (1)."""
    return EXIT_CODES.get(label, 1)


def symbols(*, ascii_only: bool = False, encoding: str | None = None) -> dict[str, str]:
    """Symbols the output stream can actually encode (SPEC §15.1 ``--ascii`` fallback).

    A legacy console (cp1252 on Windows is the common one) cannot encode the check and
    cross marks, and printing them raises rather than degrading. Probe the encoding and
    fall back before anything is written.
    """
    if ascii_only:
        return dict(_ASCII)
    try:
        "".join(_UNICODE.values()).encode(encoding or "utf-8")
    except (UnicodeEncodeError, LookupError):
        return dict(_ASCII)
    return dict(_UNICODE)


def _clip(text: str, limit: int) -> str:
    """One line, at most ``limit`` characters, with control characters removed."""
    flat = " ".join(text.split())
    safe = "".join(ch for ch in flat if ch.isprintable())
    if len(safe) <= limit:
        return safe
    return safe[: limit - 3] + "..."


def decisive(evidence: Sequence[Evidence], claim_id: str) -> Evidence | None:
    """The evidence that most moved the needle for one claim.

    Strongest absolute strength wins; a refutation outranks support at equal strength, so a
    claim that is both confirmed and contradicted shows the contradiction. Ties break on
    evidence ID, keeping the view deterministic.
    """
    about = [item for item in evidence if claim_id in item.claim_ids]
    if not about:
        return None
    return min(
        about,
        key=lambda e: (-abs(e.strength), e.outcome != "REFUTES", e.id),
    )


def _count(data: dict[str, object], key: str) -> int:
    """How many items a tuple-valued claim field holds (0 when absent)."""
    value = data.get(key)
    return len(value) if isinstance(value, (list, tuple)) else 0


def _line_label(data: dict[str, object]) -> str:
    path, line = data.get("path"), data.get("line")
    return f"{path}:{line}" if path else f"line {line}"


#: How each claim kind describes itself in the first column.
_LABELS: dict[str, Callable[[dict[str, object]], str]] = {
    "symbol": lambda d: f"fn {d.get('name')}()",
    "file": lambda d: f"file {d.get('path')}",
    "line": _line_label,
    "version": lambda d: f'version "{d.get("raw")}"',
    "trace": lambda d: f"trace ({d.get('format')}, {_count(d, 'frames')} frames)",
    "snippet": lambda d: f"snippet ({d.get('n_lines')} lines)",
    "patch": lambda d: f"patch ({_count(d, 'hunks')} hunks)",
    "poc": lambda d: f"PoC ({d.get('poc_kind')})",
    "option": lambda d: f"option {d.get('token')}",
    "impact": lambda d: f"CVSS {d.get('cvss_score')}",
    "reference": lambda d: f"{d.get('ref_kind')} {d.get('value')}",
    "behavior": lambda d: f"{d.get('subject_symbol')} {d.get('predicate')}",
}


def claim_label(claim: ClaimBase) -> str:
    """A short, human description of a claim for the first column."""
    data = claim.model_dump()
    kind = str(data.get("kind", "claim"))
    prefix = "core " if claim.role == "core" else ""
    render = _LABELS.get(kind)
    return prefix + (render(data) if render is not None else kind)


def verdict_line(verdict: Verdict, marks: dict[str, str]) -> Text:
    """``✗ UNGROUNDED     grounding 4/100     confidence: high``"""
    mark = {
        "GROUNDED": marks["ok"],
        "REPRODUCED": marks["ok"],
        "MIXED": marks["warn"],
        "UNGROUNDED": marks["fail"],
    }.get(verdict.label, marks["unknown"])
    line = Text()
    line.append(f"{mark} {verdict.label}", style=VERDICT_STYLES.get(verdict.label, "bold"))
    line.append(f"     grounding {verdict.score}/100")
    line.append(f"     confidence: {verdict.confidence}")
    return line


def _header(result: Result, marks: dict[str, str], source: str, *, ascii_only: bool) -> Panel:
    target = result.target
    sep = " - " if ascii_only else " · "
    rows = Table.grid(padding=(0, 2))
    rows.add_column(style="bright_black", no_wrap=True)
    rows.add_column(overflow="fold")
    rows.add_row("Report", Text(_clip(source, 90)))
    if target is not None:
        # Every one of these is report-derived: `method` quotes the text it resolved from,
        # and `repo_url`/`ref_name` can come from a permalink the reporter pasted. Rich's
        # Text does not strip ESC, so an unclipped field would put raw escape sequences on
        # the terminal (P7). _clip drops every non-printable character.
        where = Text(_clip(target.repo_url, 120))
        if target.ref_name:
            where.append(" @ " + _clip(target.ref_name, 60))
        if target.commit:
            where.append(f" ({_clip(target.commit, 40)[:7]})")
        where.append(f"{sep}resolved from {_clip(target.method, 80)}", style="bright_black")
        rows.add_row("Target", where)
    if result.verdict is not None:
        rows.add_row("Verdict", verdict_line(result.verdict, marks))
    title = "nikasha - proof, not prose" if ascii_only else "nikasha · proof, not prose"
    return Panel(rows, title=title, title_align="left", box=_box(ascii_only))


def _claims_table(result: Result, marks: dict[str, str]) -> Table:
    table = Table(box=None, pad_edge=False, show_edge=False)
    table.add_column("Claim", overflow="fold", max_width=_MAX_CLAIM)
    table.add_column("Result", justify="center", no_wrap=True)
    table.add_column("Evidence", overflow="fold")
    ordered = sorted(
        result.claims,
        key=lambda c: ({"core": 0, "supporting": 1, "peripheral": 2}.get(c.role, 3), c.id),
    )
    shown = 0
    for claim in ordered:
        item = decisive(result.evidence, claim.id)
        if item is None:
            continue
        key = _OUTCOME_KEY.get(item.outcome, "unknown")
        table.add_row(
            Text(_clip(claim_label(claim), _MAX_CLAIM)),
            Text(marks[key], style=_OUTCOME_STYLE.get(item.outcome, "")),
            Text(_clip(item.summary, _MAX_SUMMARY)),
        )
        shown += 1
    if shown == 0:
        dash = "-" if marks is _ASCII or marks["ok"] == "+" else "—"
        table.add_row(Text(dash), Text(marks["unknown"]), Text("no claim could be checked"))
    return table


def render_check(
    console: Console,
    result: Result,
    *,
    ascii_only: bool = False,
    quiet: bool = False,
    source: str = "",
) -> None:
    """Render one checked report. ``quiet`` prints only the verdict line (SPEC §15.1)."""
    marks = symbols(ascii_only=ascii_only, encoding=console.encoding)
    if result.verdict is None:
        console.print(Text("no verdict was produced", style="bold red"))
        return
    if quiet:
        console.print(verdict_line(result.verdict, marks))
        return

    parts: list[RenderableType] = [
        _header(result, marks, source or result.report.id, ascii_only=ascii_only),
        "",
    ]
    parts.append(_claims_table(result, marks))

    questions = result.verdict.questions
    if questions:
        parts.append("")
        asked = Table.grid(padding=(0, 1))
        asked.add_column(style="bright_black", no_wrap=True)
        asked.add_column(overflow="fold")
        for i, question in enumerate(questions, start=1):
            asked.add_row(f"{i}.", Text(_clip(question.text, 200)))
        parts.append(
            Panel(
                asked,
                title=f"Questions for the reporter ({len(questions)})",
                title_align="left",
                box=_box(ascii_only),
            )
        )
    parts.append(
        Text(
            "Full report: nikasha check ... --format html -o report.html",
            style="bright_black",
        )
    )
    console.print(Group(*parts))


__all__ = [
    "EXIT_CODES",
    "VERDICT_STYLES",
    "claim_label",
    "decisive",
    "exit_code",
    "render_check",
    "symbols",
    "verdict_line",
]
