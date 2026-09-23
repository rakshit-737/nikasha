# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The evidence ledger: the arithmetic behind the score, collapsed (SPEC §14.5, §15.2).

This is ``nikasha explain`` on the page. Every number the report shows must be
reconstructible by hand from this one table — prior, then each finding with its strength,
its damping weight and its contribution, a running total that lands exactly on the score,
and the rule that fired. A verdict nobody can audit is not evidence (P6).

**The damping weight column is the point of the whole table.** Evidence inside one group is
correlated: ten findings about one missing symbol are ten views of a single fact, and
summing them would let one mistake manufacture certainty. So within each group the
strongest finding counts in full, the next counts half, the next a quarter
(:mod:`nikasha.fuse.scoring`). The weight column is that multiplier, written down, which is
the difference between a fused score and a checklist that adds up ticks.

It ships collapsed in a ``<details>``: a maintainer triaging a queue wants the verdict, and
the reader who does not trust the verdict wants all of this. ``<details>`` gives both
without a line of JavaScript, and it is keyboard reachable and expandable natively.
"""

from __future__ import annotations

from nikasha.fuse.scoring import Contribution, Ledger
from nikasha.render.html.context import Fragment, HtmlContext
from nikasha.render.html.escaping import attr, css_ident
from nikasha.render.html.escaping import text as esc

ORDER = 90

#: One sentence, above the table, saying what the weight column means. Without it the
#: column is just a number nobody can interpret.
DAMPING_NOTE = (
    "Findings in the same group are different views of the same fact, so within each group "
    "only the strongest one counts in full and every one after it is halved — that "
    "multiplier is the damping weight, and it is why ten findings of one kind cannot add "
    "up to ten times the certainty."
)

#: Past this rank the exact fraction (1/8192 and smaller) tells a reader nothing useful.
MAX_FRACTION_RANK = 12

#: Summaries are one line here; the full text is on the evidence card this row links to.
MAX_SUMMARY = 160

CSS = """
.lg { margin: 28px 0; }
.lg > details > summary {
  cursor: pointer; font-weight: 600; padding: 2px 0;
}
.lg > details > summary:focus-visible { outline: 2px solid var(--link); outline-offset: 2px; }
.lg-sub { font-weight: 400; font-size: 13px; }
.lg-note { max-width: 78ch; margin: 12px 0 14px; }
.lg-scroll { overflow-x: auto; }
.lg table { width: 100%; border-collapse: collapse; font-size: 13px; }
.lg th, .lg td {
  text-align: left; vertical-align: top;
  padding: 6px 10px; border-bottom: 1px solid var(--border);
}
.lg thead th {
  font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em;
  color: var(--muted); font-weight: 600; white-space: nowrap;
}
.lg thead th.lg-key { color: var(--fg); }
.lg tbody th { font-weight: 600; white-space: nowrap; }
.lg .lg-num { text-align: right; white-space: nowrap; font-family: var(--mono); }
.lg .lg-weight { text-align: right; white-space: nowrap; }
.lg-frac { display: block; font-size: 11px; font-family: var(--sans); }
.lg-group { white-space: nowrap; }
.lg-finding { overflow-wrap: anywhere; min-width: 22ch; }
.lg tfoot th { text-align: right; font-weight: 600; }
.lg tfoot td { font-family: var(--mono); text-align: right; white-space: nowrap; }
.lg-rule { margin: 14px 0 0; max-width: 78ch; }
.lg-meta {
  display: grid; grid-template-columns: auto minmax(0, 1fr);
  gap: 2px 12px; margin: 12px 0 0; font-size: 13px;
}
.lg-meta dt { color: var(--muted); }
.lg-meta dd { margin: 0; overflow-wrap: anywhere; }
@media (max-width: 700px) { .lg th, .lg td { padding: 6px 5px; } }
"""


def _one_line(value: str, limit: int = MAX_SUMMARY) -> str:
    flat = " ".join(value.split())
    return flat if len(flat) <= limit else flat[: limit - 1] + "…"


def _sign_class(value: float) -> str:
    """Red for evidence against the report, green for evidence in favour of it."""
    if value < 0:
        return "bad"
    if value > 0:
        return "ok"
    return "muted"


def _fraction(rank: int) -> str:
    """The damping weight in words: what this finding's position inside its group cost it."""
    if rank <= 0:
        return "counted in full"
    if rank > MAX_FRACTION_RANK:
        return "the weakest of many here"
    return f"1/{2**rank} of full"


def _finding_cell(ctx: HtmlContext, contribution: Contribution) -> str:
    """The evidence summary, linked to its card; the bare ID when it is not in the result."""
    item = ctx.by_id.get(contribution.evidence_id)
    if item is None:
        return f'<td class="lg-finding mono">{esc(contribution.evidence_id)}</td>'
    # `css_ident` keeps only [A-Za-z0-9_-], so nothing can escape the attribute here.
    anchor = css_ident(item.id)
    return f'<td class="lg-finding"><a href="#ev-{anchor}">{esc(_one_line(item.summary))}</a></td>'


def _prior_row(ledger: Ledger) -> str:
    """The starting point, so the running column can be followed from the top."""
    return (
        '<tr><th scope="row">—</th><td class="lg-group muted">—</td>'
        '<td class="lg-finding muted">Prior, before any evidence</td>'
        '<td class="lg-num muted">—</td><td class="lg-weight muted">—</td>'
        '<td class="lg-num muted">—</td>'
        f'<td class="lg-num">{ledger.prior:+.3f}</td></tr>'
    )


def _row(ctx: HtmlContext, contribution: Contribution, running: float) -> str:
    klass = _sign_class(contribution.strength)
    return (
        f'<tr><th scope="row" class="mono">{esc(contribution.check_id)}</th>'
        f'<td class="lg-group muted">{esc(ctx.group_label(contribution.group))}</td>'
        f"{_finding_cell(ctx, contribution)}"
        f'<td class="lg-num {attr(klass)}">{contribution.strength:+.2f}</td>'
        f'<td class="lg-weight"><span class="mono">{contribution.weight:.3f}</span>'
        f'<span class="lg-frac muted">{esc(_fraction(contribution.rank))}</span></td>'
        f'<td class="lg-num {attr(klass)}">{contribution.contribution:+.3f}</td>'
        f'<td class="lg-num">{running:+.3f}</td></tr>'
    )


def _empty_row() -> str:
    return (
        '<tr><td class="muted" colspan="7">'
        "No evidence moved the score: every finding was neutral or informational."
        "</td></tr>"
    )


def _meta(ctx: HtmlContext, ledger: Ledger) -> str:
    """Everything that is not a row of arithmetic but is still needed to redo it."""
    rows = [
        f"<dt>Groups</dt><dd>{esc(', '.join(ledger.groups) or '—')}</dd>",
        f"<dt>Σ|strength|</dt><dd>{ledger.total_absolute:.2f}</dd>",
        f"<dt>Calibration</dt><dd>{esc(ledger.calibration)}</dd>",
    ]
    verdict = ctx.verdict
    if verdict is not None:
        rows.append(f"<dt>Confidence</dt><dd>{esc(verdict.confidence)}</dd>")
    return f'<dl class="lg-meta">{"".join(rows)}</dl>'


def _rule(ctx: HtmlContext) -> str:
    """The rule that turned the score into a label (SPEC §14.3)."""
    verdict = ctx.verdict
    if verdict is None or not verdict.rule:
        return ""
    return (
        f'<p class="lg-rule">The verdict <strong>{esc(verdict.label)}</strong> came from '
        f"rule {esc(verdict.rule)}.</p>"
    )


def render(ctx: HtmlContext) -> Fragment | None:
    ledger = ctx.ledger
    if ledger is None:
        # A report rendered from a saved RESULT.json carries no ledger. Showing an empty
        # table would be worse than showing nothing: it would read as "no evidence scored".
        return None
    body = [_prior_row(ledger)]
    body += [_row(ctx, contribution, running) for contribution, running in ledger.running()]
    if not ledger.contributions:
        body.append(_empty_row())
    findings = len(ledger.contributions)
    groups = len(ledger.groups)
    subtitle = (
        f"score {ledger.score}/100 · {findings} scoring finding{'' if findings == 1 else 's'}"
        f" · {groups} group{'' if groups == 1 else 's'}"
    )
    html = f"""
<section id="ledger" class="lg" aria-labelledby="ledger-heading">
  <details>
    <summary id="ledger-heading">How this score was computed
      <span class="lg-sub muted">({esc(subtitle)})</span>
    </summary>
    <p class="lg-note">{esc(DAMPING_NOTE)}</p>
    <div class="lg-scroll">
      <table>
        <thead>
          <tr>
            <th scope="col">Check</th>
            <th scope="col">Group</th>
            <th scope="col">Finding</th>
            <th scope="col">Strength</th>
            <th scope="col" class="lg-key">Damping weight</th>
            <th scope="col">Contribution</th>
            <th scope="col">Running &lambda;</th>
          </tr>
        </thead>
        <tbody>{"".join(body)}</tbody>
        <tfoot>
          <tr>
            <th scope="row" colspan="6">Total &lambda;</th>
            <td>{ledger.log_odds:+.3f}</td>
          </tr>
          <tr>
            <th scope="row" colspan="6">Grounding score, 100 &times; sigmoid(&lambda;)</th>
            <td>{esc(ledger.score)}/100</td>
          </tr>
        </tfoot>
      </table>
    </div>
    {_rule(ctx)}
    {_meta(ctx, ledger)}
  </details>
</section>
"""
    return Fragment(html=html, css=CSS)
