# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The claims table: one row per claim, with the evidence that decided it (SPEC §15.2).

This is the at-a-glance view, and it is deliberately the *same* table ``nikasha check``
prints in the terminal (SPEC §15.1): a maintainer who read the terminal output and then
opened the HTML report must not be shown a different set of rows in a different order.
That is why the label and the choice of decisive evidence come from
:mod:`nikasha.render.terminal` rather than being written again here — two copies of that
logic would drift, and a report whose two views disagree is not evidence (P6).

Two things this view does that the terminal cannot:

1. **Every claim gets a row**, including one no check could say anything about. The
   terminal skips those to keep the output short; here the row is the anchor
   (``id="claim-<claim id>"``) the report pane links to when the reader clicks an
   underlined claim, so a missing row is a dead link.
2. **The evidence summary is a link** to that evidence's card (``#ev-<evidence id>``), so
   the table is the index into the rest of the page.

**Accessibility:** the outcome is a coloured pill *and* a word ("contradicted",
"supported"), because colour alone carries no information to a reader who cannot see it
(WCAG 1.4.1). The glyph is ``aria-hidden`` so a screen reader says "contradicted" once
rather than "cross contradicted".

**Wording (P1):** every string describes a claim. Nothing here describes the person who
wrote the report.
"""

from __future__ import annotations

from nikasha.model.claims import Claim
from nikasha.model.evidence import Evidence
from nikasha.render.html.context import OUTCOME_CLASS, Fragment, HtmlContext
from nikasha.render.html.escaping import attr, css_ident
from nikasha.render.html.escaping import text as esc
from nikasha.render.terminal import claim_label, decisive

ORDER = 15

#: How each outcome reads in words. The word, not the colour, is the message.
OUTCOME_WORD = {
    "SUPPORTS": "supported",
    "REFUTES": "contradicted",
    "NEUTRAL": "unclear",
    "ERROR": "not checked",
}

#: Shown when no check produced any evidence about a claim at all.
NO_EVIDENCE_WORD = "no evidence"

#: The glyph beside the word, keyed by the outcome *class* so it always agrees with the
#: colour. Same marks as the terminal view.
MARKS = {"ok": "✓", "bad": "✗", "warn": "~", "unknown": "?"}

#: Core claims first: the verdict turns on them, so they are what a triager reads first.
ROLE_ORDER = {"core": 0, "supporting": 1, "peripheral": 2}

#: The order the count line lists outcomes in, worst first.
COUNT_ORDER = ("contradicted", "supported", "unclear", "not checked", NO_EVIDENCE_WORD)

#: Caps on the two free-text cells. Both are one line here; the full text lives on the
#: evidence card this row links to, so nothing is lost by clipping a pathological string.
MAX_LABEL = 120
MAX_SUMMARY = 240

CSS = """
.ct { margin: 28px 0; }
.ct h2 { font-size: 18px; margin: 0 0 2px; letter-spacing: -0.01em; }
.ct-counts { margin: 0 0 12px; font-size: 13px; }
.ct-scroll { overflow-x: auto; }
.ct table { width: 100%; border-collapse: collapse; }
.ct th, .ct td {
  text-align: left; vertical-align: top;
  padding: 8px 10px; border-bottom: 1px solid var(--border);
}
.ct thead th {
  font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em;
  color: var(--muted); font-weight: 600; white-space: nowrap;
}
.ct tbody th { font-weight: 600; }
.ct-claim { width: 26%; min-width: 14ch; overflow-wrap: anywhere; }
.ct-outcome { width: 1%; white-space: nowrap; }
.ct-mark { font-family: var(--mono); }
.ct-ev { overflow-wrap: anywhere; }
.ct-ev a { text-decoration-thickness: 1px; text-underline-offset: 2px; }
.ct-check { font-size: 11px; margin-left: 6px; white-space: nowrap; }
.ct tbody tr:target { background: var(--panel); }
.ct tbody tr:target th { box-shadow: inset 3px 0 0 var(--link); }
@media (max-width: 700px) {
  .ct-claim { width: auto; }
  .ct th, .ct td { padding: 7px 6px; }
}
"""


def _one_line(value: str, limit: int) -> str:
    """One line, at most ``limit`` characters. Collapses the newlines a summary may hold."""
    flat = " ".join(value.split())
    return flat if len(flat) <= limit else flat[: limit - 1] + "…"


def _outcome(item: Evidence | None) -> tuple[str, str]:
    """The ``(class, word)`` for a claim whose decisive evidence is ``item``."""
    if item is None:
        return "unknown", NO_EVIDENCE_WORD
    klass = OUTCOME_CLASS.get(item.outcome, "unknown")
    return klass, OUTCOME_WORD.get(item.outcome, "not checked")


def _evidence_cell(item: Evidence | None) -> str:
    """The summary of the decisive evidence, linked to its card."""
    if item is None:
        return '<td class="ct-ev muted">no check produced evidence about this claim</td>'
    # `css_ident` leaves only [A-Za-z0-9_-], so the fragment cannot carry a quote or an
    # angle bracket out of the attribute even if an ID ever stopped being a content hash.
    anchor = css_ident(item.id)
    return (
        f'<td class="ct-ev"><a href="#ev-{anchor}">'
        f"{esc(_one_line(item.summary, MAX_SUMMARY))}</a>"
        f'<span class="ct-check mono muted">{esc(item.check_id)}</span></td>'
    )


def _row(claim: Claim, item: Evidence | None) -> str:
    klass, word = _outcome(item)
    return (
        f'<tr id="claim-{css_ident(claim.id)}">'
        f'<th scope="row" class="ct-claim">{esc(_one_line(claim_label(claim), MAX_LABEL))}</th>'
        f'<td class="ct-outcome"><span class="pill {attr(klass)}">'
        f'<span class="ct-mark" aria-hidden="true">{esc(MARKS[klass])}</span> {esc(word)}'
        "</span></td>"
        f"{_evidence_cell(item)}"
        "</tr>"
    )


def _counts(pairs: list[tuple[Claim, Evidence | None]]) -> str:
    """``5 claims · 2 contradicted · 2 supported · 1 with no evidence``."""
    tally: dict[str, int] = {}
    for _claim, item in pairs:
        word = _outcome(item)[1]
        tally[word] = tally.get(word, 0) + 1
    plural = "" if len(pairs) == 1 else "s"
    parts = [f"{len(pairs)} claim{plural}"]
    parts += [
        f"{tally[word]} with {word}" if word == NO_EVIDENCE_WORD else f"{tally[word]} {word}"
        for word in COUNT_ORDER
        if tally.get(word)
    ]
    return " · ".join(parts)


def render(ctx: HtmlContext) -> Fragment | None:
    claims = sorted(ctx.claims, key=lambda c: (ROLE_ORDER.get(c.role, len(ROLE_ORDER)), c.id))
    if not claims:
        return None
    # `decisive` is the terminal view's rule: strongest wins, and a refutation outranks
    # support at equal strength, so a claim that is both confirmed and contradicted shows
    # the contradiction rather than hiding it behind a tie-break.
    pairs = [(claim, decisive(ctx.evidence, claim.id)) for claim in claims]
    rows = "".join(_row(claim, item) for claim, item in pairs)
    html = f"""
<section id="claims-summary" class="ct" aria-labelledby="claims-heading">
  <h2 id="claims-heading">Claims</h2>
  <p class="ct-counts muted">{esc(_counts(pairs))}</p>
  <div class="ct-scroll">
    <table>
      <thead>
        <tr>
          <th scope="col">Claim</th>
          <th scope="col">Result</th>
          <th scope="col">Most decisive evidence</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
</section>
"""
    return Fragment(html=html, css=CSS)
