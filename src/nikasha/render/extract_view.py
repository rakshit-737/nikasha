# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The ``nikasha extract`` debug view (SPEC §9.10): the report with every claim highlighted
by kind, followed by a table of claims. Report text is always rendered as plain text, never
as Rich markup, so hostile input cannot inject styling or escape sequences."""

from __future__ import annotations

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from nikasha.model.claims import ClaimBase
from nikasha.model.report import Report

KIND_STYLES: dict[str, str] = {
    "symbol": "bold cyan",
    "file": "blue",
    "line": "bold blue",
    "version": "magenta",
    "trace": "red",
    "snippet": "yellow",
    "patch": "green",
    "poc": "bright_red",
    "reference": "bright_blue",
    "option": "bright_magenta",
    "impact": "dark_orange",
    "behavior": "bright_cyan",
}
_DETAIL_FIELDS = (
    "name", "path", "line", "end_line", "token", "raw", "relation", "ref_kind", "value",
    "cvss_vector", "cvss_score", "severity_word", "cwe", "poc_kind", "files", "attributed_path",
    "attributed_function", "subject_symbol", "predicate", "object", "format", "bug_type",
    "symbol_kind_hint", "context_path", "function_hint",
)  # fmt: skip
_MAX_CELL = 60


def claim_detail(claim: ClaimBase) -> str:
    """A compact ``key=value`` summary of a claim's content fields."""
    data = claim.model_dump()
    parts: list[str] = []
    for key in _DETAIL_FIELDS:
        value = data.get(key)
        if value in (None, (), [], "", False):
            continue
        if isinstance(value, (list, tuple)):
            value = ",".join(map(str, value))
        parts.append(f"{key}={value}")
    if data.get("kind") == "trace":
        parts.append(f"frames={len(data.get('frames') or ())}")
    return " ".join(parts)


def _shorten(text: str, limit: int = _MAX_CELL) -> str:
    one_line = " ".join(text.split())
    return one_line if len(one_line) <= limit else one_line[: limit - 1] + "…"


def highlighted_body(report: Report, claims: tuple[ClaimBase, ...]) -> Text:
    text = Text(report.body, no_wrap=False)
    # Containers (traces, patches) first so finer claims paint over them.
    ordered = sorted(claims, key=lambda c: -(c.spans[0].end - c.spans[0].start))
    for claim in ordered:
        style = KIND_STYLES.get(str(getattr(claim, "kind", "")), "")
        if claim.negated:
            style += " strike dim"
        for span in claim.spans:
            text.stylize(style, span.start, span.end)
    return text


def claims_table(claims: tuple[ClaimBase, ...]) -> Table:
    table = Table(title=f"{len(claims)} claims", title_justify="left", expand=True)
    table.add_column("#", justify="right", no_wrap=True)
    table.add_column("Kind", no_wrap=True)
    table.add_column("Role", no_wrap=True)
    table.add_column("Scope", no_wrap=True)
    table.add_column("Text")
    table.add_column("Details", overflow="fold")
    for i, claim in enumerate(claims, 1):
        kind = str(getattr(claim, "kind", ""))
        scope = claim.provenance.replace("_", " ") + (" · negated" if claim.negated else "")
        table.add_row(
            str(i),
            Text(kind, style=KIND_STYLES.get(kind, "")),
            claim.role,
            scope,
            Text(_shorten(claim.spans[0].text)),
            Text(claim_detail(claim)),
        )
    return table


def render_extract(
    console: Console, report: Report, claims: tuple[ClaimBase, ...], warnings: tuple[str, ...]
) -> None:
    title = Text(report.title or report.source.uri or "report")
    legend = Text("  ").join(Text(k, style=s) for k, s in KIND_STYLES.items())
    console.print(Panel(Group(highlighted_body(report, claims)), title=title, subtitle=legend))
    console.print(claims_table(claims))
    for warning in (*report.warnings, *warnings):
        console.print(Text(f"warning: {warning}", style="yellow"))
