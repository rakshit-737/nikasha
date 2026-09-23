# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The hero: verdict badge, score ring, confidence, resolved target (SPEC §15.2).

This is the reference component — copy its shape. Three things it does that every other
component must also do:

1. **Every interpolated value goes through** :mod:`nikasha.render.html.escaping`. The
   repository URL, the ref name and the resolution method are all report-derived.
2. **No ``<script>`` tag and no ``onclick``.** Behaviour is returned in ``Fragment.js`` and
   attached with ``addEventListener``, because the CSP pins one script by hash.
3. **The score ring is inline SVG**, not an image and not a chart library: the page makes
   no network request at all.
"""

from __future__ import annotations

from nikasha.render.html.context import Fragment, HtmlContext
from nikasha.render.html.escaping import attr, url
from nikasha.render.html.escaping import text as esc

ORDER = 10

VERDICT_CLASS = {
    "REPRODUCED": "bad",
    "UNGROUNDED": "bad",
    "GROUNDED": "ok",
    "MIXED": "warn",
    "INSUFFICIENT": "unknown",
    "ERROR": "unknown",
}

#: What each verdict means, in one sentence a maintainer can act on.
VERDICT_BLURB = {
    "REPRODUCED": "The proof-of-concept reproduced the reported crash in the sandbox.",
    "GROUNDED": "Every claim that could be checked matches the code at the named version.",
    "MIXED": "Some claims check out and others do not. The questions below are the fastest"
    " way to resolve the difference.",
    "UNGROUNDED": "The central claims could not be found in the code at any released"
    " version. The questions below ask for the evidence that would settle it.",
    "INSUFFICIENT": "There was not enough in the report to check against the code.",
    "ERROR": "The check could not be completed.",
}

CSS = """
.hero { display: grid; grid-template-columns: auto minmax(0, 1fr); gap: 24px;
        align-items: center; margin: 24px 0; }
@media (max-width: 700px) { .hero { grid-template-columns: minmax(0, 1fr); } }
.hero h1 { margin: 0 0 4px; font-size: 26px; letter-spacing: -0.01em; }
.hero .blurb { margin: 8px 0 0; max-width: 62ch; }
.hero dl { display: grid; grid-template-columns: auto minmax(0, 1fr);
           gap: 2px 12px; margin: 14px 0 0; font-size: 13px; }
.hero dt { color: var(--muted); }
.hero dd { margin: 0; overflow-wrap: anywhere; }
.ring { display: block; }
.ring text { font-family: var(--sans); fill: var(--fg); }
.ring .score { font-size: 30px; font-weight: 700; }
.ring .of { font-size: 11px; fill: var(--muted); }
.ring .track { stroke: var(--border); }
.topbar { display: flex; justify-content: space-between; align-items: center;
          gap: 12px; padding: 12px 0; border-bottom: 1px solid var(--border); }
.topbar .name { font-weight: 700; letter-spacing: -0.01em; }
.topbar .tag { color: var(--muted); font-size: 13px; }
"""

_RADIUS = 46.0
_CIRCUMFERENCE = 2 * 3.141592653589793 * _RADIUS


def _ring(score: int, klass: str) -> str:
    """A score ring. ``stroke-dasharray`` draws the filled arc; no JS, no images."""
    filled = _CIRCUMFERENCE * max(0, min(100, score)) / 100
    return (
        '<svg class="ring" width="128" height="128" viewBox="0 0 110 110" role="img" '
        f'aria-label="Grounding score {esc(score)} out of 100">'
        f'<circle class="track" cx="55" cy="55" r="{_RADIUS}" fill="none" stroke-width="9"/>'
        f'<circle cx="55" cy="55" r="{_RADIUS}" fill="none" stroke-width="9" '
        f'stroke="currentColor" stroke-linecap="round" '
        f'stroke-dasharray="{filled:.2f} {_CIRCUMFERENCE - filled:.2f}" '
        'transform="rotate(-90 55 55)"/>'
        f'<text class="score" x="55" y="57" text-anchor="middle">{esc(score)}</text>'
        '<text class="of" x="55" y="74" text-anchor="middle">of 100</text>'
        f"</svg>"
    ).replace('class="ring"', f'class="ring {attr(klass)}"', 1)


def _target_rows(ctx: HtmlContext) -> str:
    rows: list[str] = []
    if ctx.source:
        rows.append(f"<dt>Report</dt><dd>{esc(ctx.source)}</dd>")
    target = ctx.result.target
    if target is not None:
        where = esc(target.repo_url)
        if target.ref_name:
            where += f" @ {esc(target.ref_name)}"
        rows.append(f"<dt>Target</dt><dd>{where}</dd>")
        if target.commit:
            link = url(f"{target.repo_url.removesuffix('.git')}/commit/{target.commit}")
            commit = esc(target.commit[:12])
            shown = f'<a href="{link}" rel="noreferrer noopener">{commit}</a>' if link else commit
            rows.append(f'<dt>Commit</dt><dd class="mono">{shown}</dd>')
        rows.append(f"<dt>Resolved by</dt><dd>{esc(target.method)}</dd>")
    verdict = ctx.verdict
    if verdict is not None and verdict.rule:
        rows.append(f"<dt>Rule</dt><dd>{esc(verdict.rule)}</dd>")
    mode = ctx.result.environment.mode
    rows.append(f"<dt>Mode</dt><dd>{esc(mode)}</dd>")
    return "".join(rows)


def render(ctx: HtmlContext) -> Fragment | None:
    verdict = ctx.verdict
    if verdict is None:
        return None
    klass = VERDICT_CLASS.get(verdict.label, "unknown")
    blurb = VERDICT_BLURB.get(verdict.label, "")
    counts = f"{len(ctx.claims)} claims checked, {len(ctx.evidence)} pieces of evidence"
    html = f"""
<header class="topbar">
  <span><span class="name">nikasha</span> <span class="tag">proof, not prose</span></span>
  <button id="theme-toggle" type="button" aria-pressed="false">Toggle theme</button>
</header>
<section class="hero" aria-labelledby="verdict-heading">
  <div class="{attr(klass)}">{_ring(verdict.score, klass)}</div>
  <div>
    <h1 id="verdict-heading">
      <span class="pill {attr(klass)}">{esc(verdict.label)}</span>
    </h1>
    <p class="muted" style="margin:6px 0 0">
      grounding {esc(verdict.score)}/100 &middot; confidence {esc(verdict.confidence)}
      &middot; {esc(counts)}
    </p>
    <p class="blurb">{esc(blurb)}</p>
    <dl>{_target_rows(ctx)}</dl>
  </div>
</section>
"""
    return Fragment(html=html, css=CSS)
