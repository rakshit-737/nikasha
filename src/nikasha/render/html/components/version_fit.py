# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The version fit chart: which release does this trace actually come from? (SPEC §15.2)

A stack trace fingerprints one build. C10 TRACE_VERSION_FIT scores, release by release,
how many of the trace's frames land in the function they name, and this view draws that
score. It exists to answer the one question a maintainer has about a report that looks
wrong: *was this a real bug reported against the wrong version?*

That framing decides the wording. A trace that matches a neighbouring release exactly is
almost always a genuine report with a stale version header, so this view says that in
words rather than leaving a maintainer to read it out of a bar chart.

Three things the drawing has to get right:

1. **An incomplete scan must look incomplete.** C10 stops when its time budget runs out
   (``scan_complete: False``), and a chart that quietly showed a short release range would
   let a truncated scan read as "no other release fits" — the one conclusion a truncated
   scan cannot support (P4). So the count of releases scored is always on the page, and a
   truncated scan gets a pill of its own.
2. **A bar chart is invisible to a screen reader.** The SVG is one ``role="img"`` whose
   ``aria-label`` states the conclusion in words, and the numbers live again in a real
   ``<table>`` inside a ``<details>``.
3. **Release names are report-derived** — they come from the tags of a repository a
   stranger named — so they are escaped like everything else, truncated for the axis, and
   capped in number: a project with hundreds of releases still has to produce a chart that
   fits on a page.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from math import isfinite
from typing import Any

from nikasha.model.evidence import Evidence
from nikasha.render.html.context import Fragment, HtmlContext
from nikasha.render.html.escaping import attr
from nikasha.render.html.escaping import text as esc

ORDER = 60

#: The check this view draws. Its details keys are the contract between the two.
CHECK_ID = "C10"

#: Mirrors of C10's thresholds. They are copied rather than imported: this package renders
#: a :class:`~nikasha.model.result.Result`, which may have been loaded from a JSON file,
#: and must not drag the check machinery (and tree-sitter with it) into the page renderer.
USABLE_FIT = 0.5
PERFECT_FIT = 1.0

#: At most this many marks are drawn, as a contiguous run centred on the claimed release.
#: Dropping releases would misrepresent the scan, so whenever this bites, the page says so.
MAX_MARKS = 200
#: Up to this many marks, every release gets an axis label; above it, only the two ends do.
LABEL_EVERY = 8
#: Axis labels are truncated to this many characters; the table keeps the full name.
MAX_LABEL = 16
#: How many other exactly-fitting releases the prose names before it counts the rest.
MAX_NAMED = 5

# The chart geometry, in viewBox units. The SVG is width:100% with a fixed viewBox, so
# these are proportions rather than pixels.
_VIEW_W = 1000.0
_VIEW_H = 230.0
_PAD_L = 40.0
_PAD_R = 10.0
_PAD_T = 12.0
_PAD_B = 44.0
_PLOT_W = _VIEW_W - _PAD_L - _PAD_R
_PLOT_H = _VIEW_H - _PAD_T - _PAD_B
_BASE_Y = _PAD_T + _PLOT_H

CSS = """
.vf { margin: 28px 0; }
.vf h2 { font-size: 18px; margin: 0 0 4px; letter-spacing: -0.01em; }
.vf .vf-intro { margin: 0 0 14px; max-width: 74ch; }
.vf-fig { margin: 0; padding: 14px 16px; background: var(--panel);
          border: 1px solid var(--border); border-radius: var(--radius); }
.vf-fig + .vf-fig { margin-top: 14px; }
.vf-lead { margin: 0 0 12px; max-width: 80ch; }
.vf-chart { display: block; width: 100%; height: auto; }
.vf-bar { fill: var(--unknown); }
.vf-bar.vf-claimed { fill: var(--warn); stroke: var(--fg); stroke-width: 0.8;
                     stroke-dasharray: 2.5 2; }
.vf-bar.vf-best { fill: var(--ok); }
.vf-mark-claimed { fill: var(--warn); stroke: var(--fg); stroke-width: 0.6; }
.vf-mark-best { fill: var(--ok); stroke: var(--fg); stroke-width: 0.6; }
.vf-axis { stroke: var(--border); stroke-width: 1.2; }
.vf-grid { stroke: var(--border); stroke-width: 1; stroke-dasharray: 4 4; }
.vf-tick { fill: var(--muted); font-family: var(--sans); font-size: 11px; }
.vf-name { fill: var(--muted); font-family: var(--sans); font-size: 12px; }
.vf-legend, .vf-scope { margin: 8px 0 0; font-size: 13px; }
.vf-scope .pill { margin-right: 6px; }
.vf-data { margin: 10px 0 0; }
.vf-data summary { cursor: pointer; font-size: 13px; }
.vf-table { border-collapse: collapse; width: 100%; margin: 10px 0 0; font-size: 13px; }
.vf-table caption { text-align: left; color: var(--muted); padding: 0 0 6px; }
.vf-table th, .vf-table td { border-bottom: 1px solid var(--border);
                             padding: 4px 10px 4px 0; text-align: left;
                             vertical-align: top; }
.vf-table th[scope="row"] { font-weight: 400; overflow-wrap: anywhere; }
.vf-table td.vf-num { text-align: right; font-family: var(--mono); white-space: nowrap; }
.vf-row-claimed th, .vf-row-claimed td { background: var(--warn-bg); }
.vf-row-best th, .vf-row-best td { background: var(--ok-bg); }
"""


@dataclass(frozen=True, slots=True)
class _Chart:
    """One C10 finding reduced to what the chart draws.

    ``shown`` is the contiguous run of ``(release, r)`` actually drawn, in the order C10
    recorded them (release order); ``total`` is how many it had before :data:`MAX_MARKS`
    trimmed it, so the page can admit to the trim.
    """

    shown: tuple[tuple[str, float], ...]
    total: int
    claimed: str | None
    claimed_ratio: float | None
    best: str | None
    best_ratio: float | None
    perfect: tuple[str, ...]
    scored: int
    radius: int | None
    complete: bool

    @property
    def claimed_shown(self) -> bool:
        return any(name == self.claimed for name, _ in self.shown)

    @property
    def best_shown(self) -> bool:
        return any(name == self.best for name, _ in self.shown)


# --- reading the evidence ---------------------------------------------------------------


def _str_or_none(value: object) -> str | None:
    if isinstance(value, str):
        return value
    return None


def _number(value: object) -> float | None:
    """A finite float, or ``None``. ``bool`` is an ``int`` in Python and is not a ratio."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    out = float(value)
    return out if isfinite(out) else None


def _count(value: object) -> int | None:
    """A non-boolean integer, or ``None``: a crafted JSON can put anything in these keys."""
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


_PAIR = 2  # one ``[release, ratio]`` entry of ``ratios_in_release_order``


def _ratios(details: dict[str, Any]) -> list[tuple[str, float]]:
    """C10's per-release ratios in release order (``ratios_in_release_order``, else ``ratios``).

    Anything that is not a name mapped to a finite number is dropped rather than trusted:
    a ``Result`` may have been loaded from a JSON file this process did not write.
    """
    ordered = details.get("ratios_in_release_order")
    items: list[tuple[object, object]] = []
    if isinstance(ordered, list):
        # Preferred: JSON keeps list order, while ``Result.to_json`` sorts ``ratios`` keys.
        items = [(p[0], p[1]) for p in ordered if isinstance(p, list | tuple) and len(p) == _PAIR]
    else:
        raw = details.get("ratios")
        if not isinstance(raw, dict):
            return []
        items = list(raw.items())
    out: list[tuple[str, float]] = []
    for name, value in items:
        ratio = _number(value)
        if isinstance(name, str) and ratio is not None:
            out.append((name, ratio))
    return out


def _window(
    pairs: Sequence[tuple[str, float]], claimed: str | None, best: str | None
) -> tuple[tuple[str, float], ...]:
    """At most :data:`MAX_MARKS` releases, centred on the claimed one (then the best fit).

    The run stays contiguous: a chart that silently skipped releases would be a worse lie
    than one that shows a shorter range and says so.
    """
    if len(pairs) <= MAX_MARKS:
        return tuple(pairs)
    names = [name for name, _ in pairs]
    centre = len(pairs) // 2
    for anchor in (claimed, best):
        if anchor is not None and anchor in names:
            centre = names.index(anchor)
            break
    start = max(0, min(len(pairs) - MAX_MARKS, centre - MAX_MARKS // 2))
    return tuple(pairs[start : start + MAX_MARKS])


def _chart(item: Evidence) -> _Chart | None:
    """The chart for one C10 finding, or ``None`` when it has no scored release."""
    details = item.details
    pairs = _ratios(details)
    if not pairs:
        return None
    claimed = _str_or_none(details.get("claimed_release"))
    best = _str_or_none(details.get("best_release"))
    perfect = details.get("perfect_releases")
    scored = _count(details.get("releases_scored"))
    return _Chart(
        shown=_window(pairs, claimed, best),
        total=len(pairs),
        claimed=claimed,
        claimed_ratio=_number(details.get("claimed_ratio")),
        best=best,
        best_ratio=_number(details.get("best_ratio")),
        perfect=tuple(n for n in perfect if isinstance(n, str))
        if isinstance(perfect, list)
        else (),
        scored=len(pairs) if scored is None else scored,
        radius=_count(details.get("window_radius")),
        # Absent means "not recorded", and an unrecorded scan is not a complete one (P4).
        complete=details.get("scan_complete") is True,
    )


# --- wording ----------------------------------------------------------------------------


def _pct(ratio: float | None) -> str:
    return "not scored" if ratio is None else f"{ratio:.0%}"


def _n_releases(count: int) -> str:
    return f"{count} release" if count == 1 else f"{count} releases"


def _headline(chart: _Chart) -> str:
    """The conclusion in one plain sentence, used for the caption *and* the aria-label.

    It is plain text on purpose: the same string is escaped for character data and for an
    attribute, so there is one wording to review rather than two that can drift apart.
    """
    best, claimed = chart.best, chart.claimed
    ratio = chart.best_ratio
    if best is None or ratio is None:
        return f"The trace was scored against {_n_releases(chart.scored)}."
    where = f"{_pct(ratio)} of its frames land in the function they name"
    same = claimed is not None and best == claimed
    # The against-clause is what makes the comparison legible, and it is noise when the
    # claimed release *is* the best fit.
    against = (
        ""
        if same or claimed is None
        else f", against {_pct(chart.claimed_ratio)} for {claimed}, the release the report names"
    )
    if ratio >= PERFECT_FIT and same:
        return (
            f"The trace fits {best}, the release the report names, exactly: every checked"
            f" frame lands in the function it names, and no other scored release fits better."
        )
    if ratio >= PERFECT_FIT:
        return (
            f"The trace fits {best} exactly{against}. A trace that matches a neighbouring"
            f" release usually means the report names a different version from the build"
            f" it came from, rather than that the bug is not real."
        )
    # Below the usable mark the finding is about *every* release, so it is said before the
    # claimed-release wording: "the version you named is the best of a bad set" is the
    # weaker half of the sentence, and the stronger half must not be dropped.
    if ratio < USABLE_FIT:
        return (
            f"No scored release fits this trace well: the best is {best}, where {where}{against}."
        )
    if same:
        return (
            f"{best}, the release the report names, is also the best fit: {where}."
            f" No scored release fits every frame."
        )
    return (
        f"The trace fits {best} best, where {where}{against}. No scored release fits every frame."
    )


def _aria(chart: _Chart) -> str:
    """The chart's label: the conclusion, then how far the scan reached."""
    parts = [f"Version fit chart. {_headline(chart)}", f"{_n_releases(chart.scored)} scored."]
    if not chart.complete:
        parts.append("The scan did not finish, so the releases beyond that were never compared.")
    parts.append("Every release and its score is in the table below the chart.")
    return " ".join(parts)


def _scope(chart: _Chart) -> str:
    """How far the scan reached — the part a truncated chart must not hide (P4)."""
    sentences: list[str] = []
    if chart.complete:
        window = (
            f" in the window it searched (the claimed release plus or minus"
            f" {chart.radius} final releases)"
            if chart.radius is not None
            else ""
        )
        sentences.append(f"{_n_releases(chart.scored)} scored{window}.")
    else:
        sentences.append(
            f"The scan stopped at its time budget after {_n_releases(chart.scored)},"
            f" so the releases beyond that range were never compared, and this chart"
            f" cannot say that none of them fits."
        )
    if len(chart.shown) < chart.total:
        sentences.append(
            f"The chart draws {len(chart.shown)} of them, the run nearest the claimed"
            f" release; the rest are in the result JSON."
        )
    elif chart.total != chart.scored:
        sentences.append(f"{_n_releases(chart.total)} carried a score and are drawn here.")
    if chart.claimed is not None and not chart.claimed_shown:
        sentences.append(f"{chart.claimed}, the release the report names, is not among them.")
    others = [name for name in chart.perfect if name != chart.best]
    if others:
        shown = ", ".join(others[:MAX_NAMED])
        more = f" and {len(others) - MAX_NAMED} more" if len(others) > MAX_NAMED else ""
        sentences.append(f"Other releases fit exactly too: {shown}{more}.")
    body = esc(" ".join(sentences))
    if chart.complete:
        return f'<p class="vf-scope muted">{body}</p>'
    return f'<p class="vf-scope warn"><span class="pill warn">partial scan</span>{body}</p>'


# --- drawing ----------------------------------------------------------------------------


def _short(name: str) -> str:
    """An axis label short enough to sit under a mark. SVG text does not wrap."""
    return name if len(name) <= MAX_LABEL else name[: MAX_LABEL - 1] + "…"


def _gridline(ratio: float, label: str) -> str:
    y = _BASE_Y - ratio * _PLOT_H
    klass = "vf-axis" if ratio == 0 else "vf-grid"
    return (
        f'<line class="{klass}" x1="{_PAD_L:.2f}" y1="{y:.2f}"'
        f' x2="{_VIEW_W - _PAD_R:.2f}" y2="{y:.2f}"/>'
        f'<text class="vf-tick" x="{_PAD_L - 6:.2f}" y="{y + 3.5:.2f}"'
        f' text-anchor="end">{esc(label)}</text>'
    )


def _bar(chart: _Chart, name: str, ratio: float, cx: float, width: float) -> tuple[str, float]:
    """One mark, plus the y of its top so the best-fit diamond can sit above it."""
    clamped = min(1.0, max(0.0, ratio))
    # A zero-height rect is invisible against the axis, so an unfitting release still gets
    # a stub: "scored, and nothing fitted" must not look like "never scored".
    height = max(1.2, clamped * _PLOT_H)
    top = _BASE_Y - height
    classes = "vf-bar"
    if name == chart.claimed:
        classes += " vf-claimed"
    if name == chart.best:
        classes += " vf-best"
    rect = (
        f'<rect class="{classes}" x="{cx - width / 2:.2f}" y="{top:.2f}"'
        f' width="{width:.2f}" height="{height:.2f}" rx="{min(1.5, width / 3):.2f}">'
        f"<title>{esc(name)} — {esc(_pct(ratio))}</title></rect>"
    )
    return rect, top


def _svg(chart: _Chart) -> str:
    marks = chart.shown
    step = _PLOT_W / len(marks)
    width = min(44.0, max(1.5, step * 0.62))
    parts: list[str] = [
        f'<svg class="vf-chart" viewBox="0 0 {_VIEW_W:.0f} {_VIEW_H:.0f}"'
        f' preserveAspectRatio="xMidYMid meet" role="img"'
        f' aria-label="{attr(_aria(chart))}">',
        _gridline(1.0, "100%"),
        _gridline(USABLE_FIT, f"{USABLE_FIT:.0%}"),
        _gridline(0.0, "0"),
    ]
    labels: list[str] = []
    for index, (name, ratio) in enumerate(marks):
        cx = _PAD_L + step * (index + 0.5)
        rect, top = _bar(chart, name, ratio, cx, width)
        parts.append(rect)
        if name == chart.claimed:
            parts.append(
                f'<polygon class="vf-mark-claimed" points="{cx - 4.5:.2f},{_BASE_Y + 10:.2f}'
                f' {cx + 4.5:.2f},{_BASE_Y + 10:.2f} {cx:.2f},{_BASE_Y + 2:.2f}"/>'
            )
        if name == chart.best:
            parts.append(
                f'<polygon class="vf-mark-best" points="{cx:.2f},{top - 9:.2f}'
                f" {cx + 4.5:.2f},{top - 4.5:.2f} {cx:.2f},{top:.2f}"
                f' {cx - 4.5:.2f},{top - 4.5:.2f}"/>'
            )
        if len(marks) <= LABEL_EVERY:
            labels.append(
                f'<text class="vf-name" x="{cx:.2f}" y="{_BASE_Y + 26:.2f}"'
                f' text-anchor="middle">{esc(_short(name))}</text>'
            )
    if len(marks) > LABEL_EVERY:
        # Too many names to fit: show the ends, so the axis still says what range it covers.
        labels = [
            f'<text class="vf-name" x="{_PAD_L:.2f}" y="{_BASE_Y + 26:.2f}"'
            f' text-anchor="start">{esc(_short(marks[0][0]))}</text>',
            f'<text class="vf-name" x="{_VIEW_W - _PAD_R:.2f}" y="{_BASE_Y + 26:.2f}"'
            f' text-anchor="end">{esc(_short(marks[-1][0]))}</text>',
        ]
    parts.extend(labels)
    parts.append("</svg>")
    return "".join(parts)


def _legend(chart: _Chart) -> str:
    keys: list[str] = []
    if chart.claimed is not None and chart.claimed_shown:
        keys.append(f"▲ {esc(chart.claimed)}, the release the report names")
    if chart.best is not None and chart.best_shown:
        keys.append(f"◆ {esc(chart.best)}, the best fit")
    keys.append(
        f"dashed line: the {USABLE_FIT:.0%} mark, below which a release is not a usable fit"
    )
    return f'<p class="vf-legend muted">{" &middot; ".join(keys)}</p>'


def _row(chart: _Chart, name: str, ratio: float) -> str:
    notes: list[str] = []
    classes: list[str] = []
    if name == chart.claimed:
        notes.append("named by the report")
        classes.append("vf-row-claimed")
    if name == chart.best:
        notes.append("best fit")
        classes.append("vf-row-best")
    if name in chart.perfect or ratio >= PERFECT_FIT:
        notes.append("every checked frame fits")
    klass = f' class="{" ".join(classes)}"' if classes else ""
    return (
        f'<tr{klass}><th scope="row">{esc(name)}</th>'
        f'<td class="vf-num">{esc(_pct(ratio))}</td>'
        f"<td>{esc(', '.join(notes))}</td></tr>"
    )


def _table(chart: _Chart) -> str:
    """The chart again, as data. A bar chart alone is unreadable to a screen reader."""
    rows = "".join(_row(chart, name, ratio) for name, ratio in chart.shown)
    caption = (
        "Frames landing in the function they name, per release, in release order."
        f" {_n_releases(len(chart.shown))} shown."
    )
    return (
        '<details class="vf-data"><summary>Fit for each release'
        f" ({esc(len(chart.shown))})</summary>"
        f'<table class="vf-table"><caption>{esc(caption)}</caption>'
        '<thead><tr><th scope="col">Release</th><th scope="col">Fit</th>'
        '<th scope="col">Notes</th></tr></thead>'
        f"<tbody>{rows}</tbody></table></details>"
    )


def _figure(chart: _Chart) -> str:
    return (
        '<figure class="vf-fig">'
        f'<figcaption class="vf-lead">{esc(_headline(chart))}</figcaption>'
        f"{_svg(chart)}{_legend(chart)}{_scope(chart)}{_table(chart)}"
        "</figure>"
    )


def render(ctx: HtmlContext) -> Fragment | None:
    """The version fit chart for every C10 finding, or ``None`` when there is none.

    Most reports carry no stack trace at all, and a trace under three frames cannot tell
    releases apart, so C10 stays silent far more often than it speaks.
    """
    items = sorted(
        (item for item in ctx.evidence if item.check_id == CHECK_ID),
        key=lambda item: (-abs(item.strength), item.id),
    )
    charts = [chart for chart in (_chart(item) for item in items) if chart is not None]
    if not charts:
        return None
    figures = "".join(_figure(chart) for chart in charts)
    html = (
        '<section class="vf" aria-labelledby="vf-heading">'
        '<h2 id="vf-heading">Version fit</h2>'
        '<p class="vf-intro muted">A stack trace fingerprints one build. Each mark is one'
        " release, scored by how many of the trace's frames land in the function they"
        " name at that release.</p>"
        f"{figures}</section>"
    )
    return Fragment(html=html, css=CSS)
