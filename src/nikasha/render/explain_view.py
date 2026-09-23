# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The ``nikasha explain`` view (SPEC §14.5): the log-odds ledger behind a verdict.

Every score this tool prints must be reconstructible by hand from this table: each piece of
evidence with its strength, its damping weight and its contribution, the running total, and
the rule that fired. A verdict nobody can audit is not evidence (P6).
"""

from __future__ import annotations

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from nikasha.fuse.scoring import Ledger
from nikasha.model.evidence import Evidence
from nikasha.model.verdict import Verdict
from nikasha.render.terminal import VERDICT_STYLES

_MAX_SUMMARY = 56


def _clip(text: str, limit: int = _MAX_SUMMARY) -> str:
    flat = " ".join(text.split())
    safe = "".join(ch for ch in flat if ch.isprintable())
    return safe if len(safe) <= limit else safe[: limit - 1] + "…"


def ledger_table(ledger: Ledger, evidence: dict[str, Evidence] | None = None) -> Table:
    """One row per contribution, in the order it was applied."""
    by_id = evidence or {}
    table = Table(title="Evidence ledger", title_justify="left", box=None, pad_edge=False)
    table.add_column("Check", no_wrap=True)
    table.add_column("Group", no_wrap=True, style="bright_black")
    table.add_column("Finding", overflow="fold")
    table.add_column("Strength", justify="right", no_wrap=True)
    table.add_column("Weight", justify="right", no_wrap=True)
    table.add_column("Contribution", justify="right", no_wrap=True)
    table.add_column("Running λ", justify="right", no_wrap=True)

    for contribution, running in ledger.running():
        item = by_id.get(contribution.evidence_id)
        style = "red" if contribution.strength < 0 else "green"
        table.add_row(
            contribution.check_id,
            contribution.group,
            Text(_clip(item.summary) if item else contribution.evidence_id),
            Text(f"{contribution.strength:+.2f}", style=style),
            f"{contribution.weight:.3f}",
            Text(f"{contribution.contribution:+.3f}", style=style),
            f"{running:+.3f}",
        )
    if not ledger.contributions:
        table.add_row("—", "—", Text("no evidence moved the score"), "0.00", "0.000", "+0.000",
                      f"{ledger.prior:+.3f}")  # fmt: skip
    return table


def render_explain(
    console: Console,
    ledger: Ledger,
    verdict: Verdict,
    evidence: dict[str, Evidence] | None = None,
) -> None:
    """Print the ledger, the totals and the rule that decided the verdict."""
    totals = Table.grid(padding=(0, 2))
    totals.add_column(style="bright_black", no_wrap=True)
    totals.add_column(overflow="fold")
    totals.add_row("Prior λ0", f"{ledger.prior:+.3f}")
    totals.add_row("Total λ", f"{ledger.log_odds:+.3f}")
    totals.add_row("Score", f"{ledger.score}/100   (100 · sigmoid(lambda))")
    totals.add_row("Groups", ", ".join(ledger.groups) or "—")
    totals.add_row("Σ|strength|", f"{ledger.total_absolute:.2f}")
    totals.add_row("Calibration", ledger.calibration)
    totals.add_row(
        "Verdict",
        Text(
            f"{verdict.label}  (confidence: {verdict.confidence})",
            style=VERDICT_STYLES.get(verdict.label, "bold"),
        ),
    )
    totals.add_row("Rule", Text(verdict.rule or "—"))
    console.print(
        Group(
            ledger_table(ledger, evidence),
            "",
            Panel(totals, title="How the verdict was reached", title_align="left"),
        )
    )


__all__ = ["ledger_table", "render_explain"]
