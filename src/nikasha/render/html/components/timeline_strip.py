# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Symbol timeline strip: in which releases does this symbol exist? (SPEC §15.2)

This is the view that makes *"this function never existed"* legible in one glance, so
most of its design is about not overstating that. It reads the evidence C03
SYMBOL_EXISTS recorded (:mod:`nikasha.checks.c03_symbol_exists`) and draws one cell per
sampled release, filled where the symbol is defined.

Four cell states, because the evidence distinguishes four situations and collapsing them
would turn a measurement into an accusation (P4):

* **present** — a release in ``details['defined_in']``: solid.
* **absent** — the release does not define the symbol, and the evidence establishes that:
  an empty box.
* **uncertain** — a release in ``details['uncertain_releases']``: the name *is* there, in
  files tree-sitter could not read through, so absence is not established. Hatched, never
  empty: a reader who sees a gap reads it as a fact, and this gap is not one.
* **unknown** — C03's ``uncertain`` branch reports which releases are uncertain but not
  which ones define the symbol, so the rest of that timeline is genuinely undetermined.
  Dashed, and the legend says so. Calling those releases "absent" would be the exact
  false statement P4 exists to prevent.

Everything else follows the page rules: inline SVG (no chart library, no image, no
network), ``role="img"`` with the whole run spelled out in the ``aria-label`` because the
shapes say nothing to a screen reader, and the same sentence repeated in visible text.
Release names come from the report, so they are escaped, whitespace-collapsed, truncated,
and — when a name is still wide — clamped with ``textLength`` so one hostile tag cannot
push anything outside the ``viewBox``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from nikasha.model.evidence import Evidence
from nikasha.render.html.context import Fragment, HtmlContext
from nikasha.render.html.escaping import attr, css_ident
from nikasha.render.html.escaping import text as esc

ORDER = 40

#: The check whose evidence this view draws.
CHECK_ID = "C03"

State = Literal["present", "absent", "uncertain", "unknown"]

#: Draw order for the legend; also the order states are introduced to the reader.
STATE_ORDER: tuple[State, ...] = ("present", "absent", "uncertain", "unknown")

STATE_CLASS: dict[State, str] = {
    "present": "tl-present",
    "absent": "tl-absent",
    "uncertain": "tl-uncertain",
    "unknown": "tl-unknown",
}

#: How a run of cells reads in the spoken sentence.
STATE_WORD: dict[State, str] = {
    "present": "defined",
    "absent": "absent",
    "uncertain": "not established",
    "unknown": "not determined",
}

#: The same, said about the one release the report names, where the reason matters.
CLAIMED_WORD: dict[State, str] = {
    "present": "defined",
    "absent": "absent",
    "uncertain": "not established, because the files mentioning it there did not parse cleanly",
    "unknown": "not determined by this evidence",
}

#: The page's own colour classes (they set ``color``; the SVG paints ``currentColor``).
CLAIMED_TONE: dict[State, str] = {
    "present": "ok",
    "absent": "bad",
    "uncertain": "warn",
    "unknown": "unknown",
}

STATE_LEGEND: dict[State, str] = {
    "present": "defined in this release",
    "absent": "not defined in this release",
    "uncertain": "hatched: mentioned in files that did not parse cleanly, so absence is"
    " not established",
    "unknown": "dashed: this evidence does not say",
}

# --- geometry -------------------------------------------------------------------------
#
# The strip is laid out in user units that are CSS pixels: the SVG keeps its intrinsic
# width and the container scrolls, because scaling a 40-release strip down to fit a phone
# would shrink 11px labels to something nobody can read.

#: Cell height, and the bands above (claimed-release marker) and below (labels).
CELL_H = 26
MARK_H = 14
LABEL_H = 20
#: Padding so the 2px ring around the claimed cell cannot fall outside the viewBox.
PAD = 5

WIDE_CELL, WIDE_GAP = 78, 6
COMPACT_CELL, COMPACT_GAP = 16, 3
#: Above this many releases there is no room to label every cell.
COMPACT_ABOVE = 12
#: Cells beyond this are windowed away around the interesting ones, and the note says so.
MAX_RELEASES = 48
#: A report naming forty symbols must not turn the page into forty strips.
MAX_STRIPS = 8

#: Truncation limits: inside a cell label, and in prose (sentence, heading, tooltip).
LABEL_CHARS = 14
PROSE_CHARS = 40
#: Past this many characters a label is squeezed to the cell width rather than trusted.
CLAMP_CHARS = 12
#: In compact mode, how many cells a label needs on each side before it may be drawn.
LABEL_CLEARANCE = 5
#: …and how wide it may then be: four of those cells, which the clearance guarantees.
COMPACT_LABEL_ROOM = COMPACT_CELL * 4 + COMPACT_GAP * 3

#: One hatch pattern serves every strip: this component contributes a single fragment, so
#: the id is unique in the document and ``url(#…)`` resolves across the inline SVGs.
HATCH_ID = "nk-tl-hatch"

CSS = """
.tl-section { margin: 24px 0; }
.tl-section > h2 { font-size: 18px; margin: 0 0 4px; letter-spacing: -0.01em; }
.tl-section > .tl-lede { margin: 0 0 12px; font-size: 13px; }
.tl-strip { margin: 0 0 16px; }
.tl-strip h3 { margin: 0 0 10px; font-size: 14px; font-weight: 600; }
.tl-scroll { overflow-x: auto; padding: 2px 0; }
.tl-scroll svg { display: block; }
.tl-cell { pointer-events: all; }
.tl-present { fill: var(--ok); stroke: var(--ok); stroke-width: 1; }
.tl-absent { fill: none; stroke: var(--border); stroke-width: 1; }
.tl-uncertain { stroke: var(--warn); stroke-width: 1.5; }
.tl-unknown { fill: none; stroke: var(--muted); stroke-width: 1; stroke-dasharray: 3 3; }
.tl-hatch-line { stroke: var(--warn); stroke-width: 3; }
.tl-label { font-family: var(--sans); font-size: 11px; fill: var(--muted); }
.tl-label.tl-named { fill: currentColor; font-weight: 700; }
.tl-claimed rect { fill: none; stroke: currentColor; stroke-width: 2; }
.tl-claimed path { fill: currentColor; stroke: none; }
.tl-defs { position: absolute; width: 0; height: 0; overflow: hidden; }
.tl-says { margin: 10px 0 0; max-width: 78ch; }
.tl-note { margin: 6px 0 0; font-size: 13px; max-width: 78ch; }
.tl-legend { display: flex; flex-wrap: wrap; gap: 6px 18px; list-style: none;
             margin: 12px 0 0; padding: 0; font-size: 12px; color: var(--muted); }
.tl-legend li { display: flex; align-items: center; gap: 6px; }
.tl-swatch { flex: none; }
@media print { .tl-scroll { overflow: visible; } }
"""

#: The hatch, defined once and referenced by every uncertain cell. The stripe is a class,
#: not a hard-coded colour, so it follows the theme like everything else.
DEFS = (
    '<svg class="tl-defs" width="0" height="0" aria-hidden="true">'
    f'<defs><pattern id="{HATCH_ID}" width="7" height="7" patternUnits="userSpaceOnUse"'
    ' patternTransform="rotate(45)">'
    '<line class="tl-hatch-line" x1="0" y1="0" x2="0" y2="7"/>'
    "</pattern></defs></svg>"
)


@dataclass(frozen=True)
class _Strip:
    """One symbol's timeline, already windowed and already resolved to cell states."""

    uid: str
    symbol: str
    releases: list[str]
    states: list[State]
    claimed_index: int | None
    claimed_raw: str | None
    never_in_history: bool
    notes: list[str]


# --- reading the evidence ---------------------------------------------------------------


def _strings(value: object) -> list[str]:
    """The string members of a JSON list, in order. Anything else is not release data."""
    if not isinstance(value, (list, tuple)):
        return []
    return [item for item in value if isinstance(item, str)]


def _symbol_name(ctx: HtmlContext, item: Evidence) -> str:
    """The symbol this evidence is about: the check records it, the claim is the fallback."""
    recorded = item.details.get("symbol")
    if isinstance(recorded, str) and recorded.strip():
        return recorded
    for claim_id in item.claim_ids:
        name = getattr(ctx.claim_by_id.get(claim_id), "name", None)
        if isinstance(name, str) and name.strip():
            return name
    return ""


def _states(details: dict[str, Any], releases: list[str]) -> list[State]:
    """One state per release, refusing to call a release absent unless C03 established it.

    ``defined_in`` is present only on the ``absent_here_present_elsewhere`` outcome. The
    outcomes that reach a *complete* absence (``never_in_history*``, ``history_incomplete``,
    ``absent_in_sampled_core``) carry no ``defined_in`` because no release defines the
    symbol at all — that is how they were reached. The ``uncertain`` outcome is the odd one
    out: it names the uncertain releases but drops the presence data, so the remaining
    releases are *unknown* rather than absent.
    """
    defined = set(_strings(details.get("defined_in")))
    uncertain = set(_strings(details.get("uncertain_releases")))
    absence_known = "defined_in" in details or not uncertain
    out: list[State] = []
    for release in releases:
        if release in defined:
            out.append("present")
        elif release in uncertain:
            out.append("uncertain")
        else:
            out.append("absent" if absence_known else "unknown")
    return out


def _window(states: list[State], claimed: int | None, total: int) -> tuple[int, int]:
    """``(start, stop)`` of the slice to draw: everything interesting, at most the cap."""
    if total <= MAX_RELEASES:
        return 0, total
    anchors = [i for i, state in enumerate(states) if state != "absent"]
    if claimed is not None:
        anchors.append(claimed)
    if not anchors:
        anchors = [total - 1]
    low, high = min(anchors), max(anchors)
    spare = MAX_RELEASES - (high - low + 1)
    # Centre the window on the interesting range when there is room, then clamp it inside.
    start = low if spare <= 0 else low - spare // 2
    if claimed is not None:
        # The release the report names is the one cell that must never be cut: without it
        # the caption would say that release "is not among the sampled releases" (P6).
        start = max(min(start, claimed), claimed - MAX_RELEASES + 1)
    start = max(0, min(start, total - MAX_RELEASES))
    return start, start + MAX_RELEASES


def _notes(details: dict[str, Any], symbol: str, dropped: tuple[int, int]) -> list[str]:
    """The caveats that belong under the strip rather than inside the sentence."""
    out: list[str] = []
    if details.get("history_complete") is False:
        gap = details.get("history_gap")
        reason = _short(gap, PROSE_CHARS) if isinstance(gap, str) else "the search did not finish"
        out.append(
            f"History could not be searched exhaustively ({reason}), so this is not"
            f" evidence that {_short(symbol, PROSE_CHARS)} never existed."
        )
    before, after = dropped
    if before or after:
        parts = []
        if before:
            parts.append(f"{before} earlier")
        if after:
            parts.append(f"{after} later")
        out.append(f"{' and '.join(parts)} release{'s' if before + after > 1 else ''} not shown.")
    suggestions = [_short(name, PROSE_CHARS) for name in _strings(details.get("suggestions"))][:5]
    if suggestions:
        out.append(f"Similar names in the code: {', '.join(suggestions)}.")
    return out


def _collect(ctx: HtmlContext) -> tuple[list[_Strip], int]:
    """Every symbol with timeline evidence, strongest first, capped. Plus the overflow count."""
    candidates = [
        item
        for item in ctx.evidence
        if item.check_id == CHECK_ID and _strings(item.details.get("releases_searched"))
    ]
    # Refutations first, then by strength, then by name and id so two runs agree (P2).
    candidates.sort(
        key=lambda item: (
            item.outcome != "REFUTES",
            -abs(item.strength),
            _symbol_name(ctx, item),
            item.id,
        )
    )
    claimed_ref = ctx.result.target.ref_name if ctx.result.target is not None else None
    strips: list[_Strip] = []
    seen: set[str] = set()
    for item in candidates:
        symbol = _symbol_name(ctx, item)
        if not symbol or symbol in seen:
            continue
        seen.add(symbol)
        releases = _strings(item.details["releases_searched"])
        states = _states(item.details, releases)
        claimed = releases.index(claimed_ref) if claimed_ref in releases else None
        start, stop = _window(states, claimed, len(releases))
        shown_claimed = claimed - start if claimed is not None and start <= claimed < stop else None
        strips.append(
            _Strip(
                uid=f"tl-{len(strips)}-{css_ident(item.id)}",
                symbol=symbol,
                releases=releases[start:stop],
                states=states[start:stop],
                claimed_index=shown_claimed,
                claimed_raw=claimed_ref,
                never_in_history=item.details.get("never_in_history") is True,
                notes=_notes(item.details, symbol, (start, len(releases) - stop)),
            )
        )
    return strips[:MAX_STRIPS], max(0, len(strips) - MAX_STRIPS)


# --- saying it in words -----------------------------------------------------------------


def _short(value: object, limit: int) -> str:
    """A release or symbol name, whitespace collapsed and bounded. Not yet escaped."""
    collapsed = " ".join(str(value).split())
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[: max(1, limit - 1)] + "…"


def _runs(labels: list[str], states: list[State]) -> list[tuple[State, str, str]]:
    """Adjacent cells in the same state, as ``(state, first label, last label)``."""
    out: list[tuple[State, str, str]] = []
    for label, state in zip(labels, states, strict=True):
        if out and out[-1][0] == state:
            out[-1] = (state, out[-1][1], label)
        else:
            out.append((state, label, label))
    return out


def _phrase(run: tuple[State, str, str]) -> str:
    state, first, last = run
    where = first if first == last else f"{first} through {last}"
    return f"{STATE_WORD[state]} in {where}"


def _sentence(strip: _Strip) -> str:
    """The whole strip in one sentence: the ``aria-label`` and the visible caption.

    A screen reader gets nothing at all from the rectangles, so this has to carry the run
    itself — "defined in v1.0.0 through v1.2.1, absent in v1.3.0" — and not a summary of it.
    """
    symbol = _short(strip.symbol, PROSE_CHARS)
    labels = [_short(release, PROSE_CHARS) for release in strip.releases]
    runs = _runs(labels, strip.states)
    count = len(labels)
    if len(runs) == 1 and count > 1 and runs[0][0] in ("present", "absent"):
        span = f"{labels[0]} through {labels[-1]}"
        every = "all" if runs[0][0] == "present" else "none of"
        body = f"is defined in {every} the {count} sampled releases, {span}"
    else:
        body = "is " + ", ".join(_phrase(run) for run in runs)
    parts = [f"{symbol} {body}."]
    if strip.claimed_index is not None:
        state = strip.states[strip.claimed_index]
        parts.append(
            f"The report names {labels[strip.claimed_index]}, where it is {CLAIMED_WORD[state]}."
        )
    elif strip.claimed_raw:
        parts.append(
            f"The report names {_short(strip.claimed_raw, PROSE_CHARS)}, which is not among"
            " the sampled releases."
        )
    if strip.never_in_history:
        parts.append("It never appears anywhere in this repository's history.")
    return " ".join(parts)


# --- drawing it -------------------------------------------------------------------------


def _cell(x: float, width: float, state: State, release: str) -> str:
    """One release cell. The ``<title>`` is a mouse affordance; the sentence is the label."""
    fill = f' fill="url(#{HATCH_ID})"' if state == "uncertain" else ""
    title = f"{_short(release, PROSE_CHARS)}: {STATE_WORD[state]}"
    return (
        f'<rect class="tl-cell {STATE_CLASS[state]}" x="{x:g}" y="{MARK_H}"'
        f' width="{width:g}" height="{CELL_H}" rx="3"{fill}>'
        f"<title>{esc(title)}</title></rect>"
    )


def _claimed_marker(x: float, width: float, state: State) -> str:
    """A caret above the named release and a ring around it, in the outcome's colour."""
    centre = x + width / 2
    return (
        f'<g class="tl-claimed {attr(CLAIMED_TONE[state])}">'
        f'<path d="M{centre - 5:g} 2 L{centre + 5:g} 2 L{centre:g} 10 Z"/>'
        f'<rect x="{x - 2.5:g}" y="{MARK_H - 2.5}" width="{width + 5:g}"'
        f' height="{CELL_H + 5}" rx="5"/>'
        "</g>"
    )


def _label(
    x: float, width: float, text_value: str, *, anchor: str, named: bool, tone: str, room: float
) -> str:
    """A release label that cannot escape its space, however long the tag name is.

    ``room`` is the width the label may occupy: its own cell when every cell is labelled,
    and the gap to the next label in compact mode, where only the edges and the claimed
    release are named and there is more room than one 16px cell.
    """
    label = _short(text_value, LABEL_CHARS)
    at = {"start": x, "middle": x + width / 2, "end": x + width}[anchor]
    clamp = (
        f' textLength="{room:g}" lengthAdjust="spacingAndGlyphs"'
        if len(label) > CLAMP_CHARS
        else ""
    )
    klass = f"tl-label tl-named {tone}" if named else "tl-label"
    return (
        f'<text class="{attr(klass)}" x="{at:g}" y="{MARK_H + CELL_H + 14}"'
        f' text-anchor="{anchor}"{clamp}>{esc(label)}</text>'
    )


def _label_indices(count: int, claimed: int | None, compact: bool) -> list[int]:
    """Which cells get a label: all of them, or first/last/claimed when they are thin."""
    if not compact:
        return list(range(count))
    chosen = {0, count - 1}
    if claimed is not None and min(claimed, count - 1 - claimed) >= LABEL_CLEARANCE:
        chosen.add(claimed)
    return sorted(chosen)


def _svg(strip: _Strip) -> str:
    count = len(strip.releases)
    compact = count > COMPACT_ABOVE
    width = float(COMPACT_CELL if compact else WIDE_CELL)
    gap = COMPACT_GAP if compact else WIDE_GAP
    total_w = PAD * 2 + count * width + max(0, count - 1) * gap
    total_h = MARK_H + CELL_H + LABEL_H

    def left(index: int) -> float:
        return PAD + index * (width + gap)

    cells = "".join(
        _cell(left(i), width, state, release)
        for i, (release, state) in enumerate(zip(strip.releases, strip.states, strict=True))
    )
    marker = ""
    if strip.claimed_index is not None:
        marker = _claimed_marker(
            left(strip.claimed_index), width, strip.states[strip.claimed_index]
        )
    labels = "".join(
        _label(
            left(i),
            width,
            strip.releases[i],
            anchor=(
                "start" if compact and i == 0 else "end" if compact and i == count - 1 else "middle"
            ),
            named=i == strip.claimed_index,
            tone=CLAIMED_TONE[strip.states[i]],
            room=COMPACT_LABEL_ROOM if compact else width,
        )
        for i in _label_indices(count, strip.claimed_index, compact)
    )
    return (
        f'<svg class="tl-svg" width="{total_w:g}" height="{total_h}"'
        f' viewBox="0 0 {total_w:g} {total_h}" role="img"'
        f' aria-label="{attr(_sentence(strip))}">'
        f"{cells}{marker}{labels}</svg>"
    )


def _swatch(state: State) -> str:
    fill = f' fill="url(#{HATCH_ID})"' if state == "uncertain" else ""
    return (
        '<svg class="tl-swatch" width="18" height="14" viewBox="0 0 18 14" aria-hidden="true">'
        f'<rect class="tl-cell {STATE_CLASS[state]}" x="1" y="1" width="16" height="12"'
        f' rx="3"{fill}/></svg>'
    )


#: The caret and ring, shown at legend size so the marker is explained, not just used.
CLAIMED_SWATCH = (
    '<svg class="tl-swatch" width="18" height="18" viewBox="0 0 18 18" aria-hidden="true">'
    '<g class="tl-claimed muted"><path d="M4 1 L14 1 L9 8 Z"/>'
    '<rect x="2" y="9" width="14" height="7" rx="3"/></g></svg>'
)


def _legend(strip: _Strip) -> str:
    """Only the states this strip actually uses, in a fixed order (P2)."""
    used = [state for state in STATE_ORDER if state in strip.states]
    items = [f"<li>{_swatch(state)}<span>{esc(STATE_LEGEND[state])}</span></li>" for state in used]
    if strip.claimed_index is not None:
        items.append(f"<li>{CLAIMED_SWATCH}<span>the release the report names</span></li>")
    return f'<ul class="tl-legend">{"".join(items)}</ul>'


def _section(strip: _Strip) -> str:
    name = _short(strip.symbol, PROSE_CHARS)
    notes = "".join(f'<p class="tl-note muted">{esc(note)}</p>' for note in strip.notes)
    return (
        f'<section class="tl-strip panel" aria-labelledby="{attr(strip.uid)}-h">'
        f'<h3 id="{attr(strip.uid)}-h">Where <span class="mono">{esc(name)}</span> exists</h3>'
        f'<div class="tl-scroll" role="group" tabindex="0"'
        f' aria-label="{attr(name)} release timeline">{_svg(strip)}</div>'
        f'<p class="tl-says">{esc(_sentence(strip))}</p>'
        f"{notes}{_legend(strip)}</section>"
    )


def render(ctx: HtmlContext) -> Fragment | None:
    strips, extra = _collect(ctx)
    if not strips:
        return None
    overflow = f"{extra} more symbol timeline{'s' if extra > 1 else ''} are in the evidence column."
    more = f'<p class="tl-note muted">{esc(overflow)}</p>' if extra else ""
    html = (
        f'{DEFS}<section class="tl-section" id="symbol-timeline" aria-labelledby="tl-title">'
        '<h2 id="tl-title">Where these symbols exist</h2>'
        '<p class="tl-lede muted">One cell per sampled release, oldest first.</p>'
        f"{''.join(_section(strip) for strip in strips)}{more}</section>"
    )
    return Fragment(html=html, css=CSS)
