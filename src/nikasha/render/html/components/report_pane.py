# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The "Report" pane: the reporter's own words, every claim underlined (SPEC §15.2).

This is the left column of the report page, and the single most dangerous view in it:
every character it renders was written by a stranger. So the rule here is absolute —
**the body reaches the page only through** :func:`nikasha.render.html.escaping.text`, one
segment at a time, and the segments concatenate back to exactly the body. There is no
path through this module by which a character of input becomes markup.

The hard part is that **claim spans overlap and nest**. A trace claim covers twenty lines;
a symbol claim covers eight characters inside it; a line claim overlaps the end of one
sentence and the start of the next. Wrapping each span in turn produces crossed tags
(``<a>…<b>…</a>…</b>``), which browsers silently reparent into something that underlines
the wrong text — and, with ``<a>`` inside ``<a>``, into a link that leads somewhere the
markup never said. :func:`_segments` cuts the text at every span boundary instead, so the
output is a *flat* sequence of non-overlapping pieces: nesting becomes adjacency, and the
markup is well-formed by construction.

**Ids are an API between components.** This pane only ever *links out*, to
``#ev-<evidence id>`` in the evidence cards. The matching ``id="claim-<claim id>"`` anchor
belongs to the claims table (``claims_table``, ``ORDER = 25``), which guarantees one row
per claim; emitting it here as well would put two elements with the same id in one
document, and the browser would resolve every back-link to whichever came first.

Links are plain ``<a href="#ev-…">``: the card is on the same page, so scrolling to it
needs no JavaScript, and this component ships none. The hover summary is likewise a
``title``/``aria-label`` pair rather than a scripted tooltip.
"""

from __future__ import annotations

import itertools
from collections.abc import Iterator, Sequence
from dataclasses import dataclass

from nikasha.render.html.context import Fragment, HtmlContext
from nikasha.render.html.escaping import attr, css_ident
from nikasha.render.html.escaping import text as esc

ORDER = 20
#: SPEC 15.2 puts the report text on the left, beside its evidence.
COLUMN = "left"

#: How much report text is rendered. Ingestion allows a 2 MB body, and escaping only grows
#: it, so an unbounded pane would blow the 1.5 MB page budget on its own (SPEC §15.2).
#: The claims table still lists every claim, so nothing is lost from the page.
MAX_BODY_CHARS = 200_000

#: Longest hover summary put in an attribute, so one pathological summary cannot be
#: repeated into a megabyte of ``title=``.
MAX_SUMMARY_CHARS = 240

#: The legend, in a fixed order (P2: never an iteration over a set or a dict of counts).
#: The wording describes the evidence about a claim, never the person who wrote it (P1).
OUTCOME_LEGEND = (
    ("ok", "supported"),
    ("bad", "refuted"),
    ("warn", "noted"),
    ("unknown", "not checked"),
)

#: Shown when no check had anything to say about a claim. Absence of evidence is not
#: evidence of absence (P4), so this says only that nothing was produced.
NO_EVIDENCE_SUMMARY = "No check produced evidence about this claim."

CSS = """
.rp { margin: 24px 0; min-width: 0; }
.rp-head { display: flex; flex-wrap: wrap; gap: 6px 16px;
           align-items: baseline; justify-content: space-between; }
.rp h2 { margin: 0; font-size: 18px; letter-spacing: -0.01em; }
.rp-note { margin: 4px 0 10px; font-size: 13px; }
.rp-legend { display: flex; flex-wrap: wrap; gap: 4px 14px; margin: 0; padding: 0;
             list-style: none; font-size: 12px; }
.rp-legend li { display: flex; align-items: center; gap: 6px; }
.rp-swatch { display: inline-block; width: 16px; height: 3px; border-radius: 2px;
             background: var(--rp-line, var(--border)); }
.rp-text {
  max-height: 68vh; overflow: auto; overscroll-behavior: contain;
  white-space: pre-wrap; overflow-wrap: anywhere; tab-size: 4;
  font-family: var(--mono); font-size: 13px; line-height: 1.65;
}
.rp-ok { --rp-line: var(--ok); --rp-tint: var(--ok-bg); }
.rp-bad { --rp-line: var(--bad); --rp-tint: var(--bad-bg); }
.rp-warn { --rp-line: var(--warn); --rp-tint: var(--warn-bg); }
.rp-unknown { --rp-line: var(--unknown); --rp-tint: var(--unknown-bg); }
.rp-c {
  color: inherit; border-radius: 2px;
  text-decoration-line: underline; text-decoration-color: var(--rp-line);
  text-decoration-thickness: 2px; text-underline-offset: 3px;
  text-decoration-skip-ink: none;
}
.rp-c.rp-multi { text-decoration-style: double; }
.rp-c:hover, .rp-c:focus-visible { background: var(--rp-tint); }
.rp-cut { margin: 10px 0 0; font-size: 12px; }
@media print {
  .rp-text { max-height: none; overflow: visible; }
}
"""


@dataclass(frozen=True, slots=True)
class _Piece:
    """One claim span, clipped to the text actually rendered, with what it links to."""

    start: int
    end: int
    claim_id: str
    outcome: str
    href: str  # "" when no evidence mentions the claim, so there is no card to link to
    summary: str


def _one_line(value: str) -> str:
    """Collapse to a single bounded line: attributes are not the place for a paragraph."""
    out = " ".join(value.split())
    return out if len(out) <= MAX_SUMMARY_CHARS else out[: MAX_SUMMARY_CHARS - 1] + "…"


def _pieces(ctx: HtmlContext, limit: int) -> list[_Piece]:
    """Every claim span that falls inside ``[0, limit)``, clipped to it.

    A span that is empty, reversed or out of range is *skipped*: a hand-built or
    round-tripped ``Result`` can carry one, and a report that fails to render teaches a
    maintainer nothing at all.
    """
    found: list[_Piece] = []
    seen: set[str] = set()
    for claim in ctx.claims:
        if claim.id in seen:  # one claim id, one set of underlines
            continue
        seen.add(claim.id)
        items = ctx.by_claim.get(claim.id) or []
        strongest = items[0] if items else None  # `by_claim` is sorted strongest first
        outcome = css_ident(ctx.outcome_of(claim.id), fallback="unknown")
        href = f"#ev-{css_ident(strongest.id)}" if strongest is not None else ""
        summary = _one_line(strongest.summary if strongest is not None else NO_EVIDENCE_SUMMARY)
        for span in claim.spans:
            if span.start < 0 or span.end <= span.start or span.start >= limit:
                continue
            found.append(_Piece(span.start, min(span.end, limit), claim.id, outcome, href, summary))
    return found


def _segments(
    pieces: Sequence[_Piece], length: int
) -> Iterator[tuple[int, int, tuple[_Piece, ...]]]:
    """Cut ``[0, length)`` at every span boundary; yield each cut with its covering claims.

    The result is a partition: the cuts are contiguous, disjoint and cover the whole text,
    so joining the rendered pieces reproduces the body exactly. Covering claims come out
    shortest-first, so the innermost claim wins the cut — an eight-character symbol paints
    over the twenty-line trace it sits in, as ``nikasha extract`` does in the terminal.

    Cost is ``O(cuts x depth)``; depth is how many claims cover one character, which is
    one or two in every real report.
    """
    cuts = sorted({0, length} | {p.start for p in pieces} | {p.end for p in pieces})
    opening = sorted(pieces, key=lambda p: (p.start, p.end, p.claim_id))
    active: list[_Piece] = []
    index = 0
    for start, end in itertools.pairwise(cuts):
        while index < len(opening) and opening[index].start <= start:
            active.append(opening[index])
            index += 1
        active = [p for p in active if p.end > start]
        yield start, end, tuple(sorted(active, key=lambda p: (p.end - p.start, p.claim_id)))


def _body_html(body: str, pieces: Sequence[_Piece], limit: int) -> str:
    """The body with each claim underlined. Every character goes through ``esc``."""
    parts: list[str] = []
    for start, end, active in _segments(pieces, limit):
        chunk = esc(body[start:end])
        if not active:
            parts.append(chunk)
            continue
        primary = active[0]
        klass = f"rp-c rp-{primary.outcome}" + (" rp-multi" if len(active) > 1 else "")
        # `title` is the mouse affordance; `aria-label` carries the same sentence to a
        # screen reader and to a keyboard user tabbing through the underlined claims.
        common = (
            f'class="{attr(klass)}" title="{attr(primary.summary)}" '
            f'aria-label="{attr(primary.summary)}"'
        )
        if primary.href:
            # The href is "#" + a sanitized id, so it can hold no scheme and needs no
            # `url()` check — which would reject a fragment anyway.
            parts.append(f'<a {common} href="{attr(primary.href)}">{chunk}</a>')
        else:
            parts.append(f"<span {common}>{chunk}</span>")
    return "".join(parts)


def _legend(pieces: Sequence[_Piece]) -> tuple[str, int]:
    """The colour key and how many distinct claims it accounts for."""
    counts: dict[str, int] = {}
    for _claim_id, outcome in sorted({(p.claim_id, p.outcome) for p in pieces}):
        counts[outcome] = counts.get(outcome, 0) + 1
    items = [
        f'<li class="rp-{attr(klass)}"><span class="rp-swatch"></span>'
        f'<span class="muted">{esc(counts[klass])} {esc(label)}</span></li>'
        for klass, label in OUTCOME_LEGEND
        if counts.get(klass)
    ]
    return (f'<ul class="rp-legend">{"".join(items)}</ul>' if items else ""), sum(counts.values())


def render(ctx: HtmlContext) -> Fragment | None:
    body = ctx.result.report.body
    if not body.strip():
        return None
    limit = min(len(body), MAX_BODY_CHARS)
    pieces = _pieces(ctx, limit)
    legend, shown = _legend(pieces)
    if shown:
        note = (
            f"{shown} of {len(ctx.claims)} claims are underlined in the colour of what the "
            "evidence says. Select one to jump to its evidence card; the claims table "
            "below lists them all."
        )
    elif not ctx.claims:
        note = "No checkable claim was extracted from this report."
    else:
        note = "No claim in this report could be tied to a span of its text."
    cut = ""
    if len(body) > limit:
        cut = (
            f'<p class="rp-cut muted">Showing the first {esc(limit)} of {esc(len(body))} '
            "characters. The full text is in the JSON output.</p>"
        )
    # The text container is built without surrounding whitespace on purpose: it is
    # `white-space: pre-wrap`, so a newline of source indentation would be a newline on
    # the page.
    text_html = (
        '<div class="rp-text panel" tabindex="0" role="region" aria-labelledby="rp-heading">'
        f"{_body_html(body, pieces, limit)}</div>"
    )
    html = f"""
<section class="rp" id="report" aria-labelledby="rp-heading">
  <div class="rp-head">
    <h2 id="rp-heading">Report</h2>
    {legend}
  </div>
  <p class="rp-note muted">{esc(note)}</p>
  {text_html}{cut}
</section>
"""
    return Fragment(html=html, css=CSS)
