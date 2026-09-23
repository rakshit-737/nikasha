# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The JSON download and the page footer (SPEC §15.2).

The report is one file, so "download the JSON" cannot mean a second file sitting next to
it: the link carries the whole :class:`~nikasha.model.result.Result` in a ``data:`` URI
with a ``download`` attribute. Three things about that are easy to get wrong.

**Percent-encoding.** A raw ``#`` in a ``data:`` URI starts the fragment and silently
truncates the download at that byte; a raw ``%`` starts an escape and corrupts the next
two. Both appear in ordinary report text. :data:`_DATA_SAFE` is therefore a deliberately
small allow-list — the JSON punctuation that is unambiguously safe in a URL — and
everything else, including every space and newline, is percent-encoded. Whitespace is not
optional to encode: the URL parser strips tab, CR and LF out of a URL before anything else
sees it, which would quietly reflow the JSON.

**The CSP.** The page policy is ``default-src 'none'; img-src data:``. That governs
*fetches*, and a ``data:`` URI in the ``href`` of an ``<a download>`` is not one — no CSP
directive covers link downloads (there is no ``download-src``, and ``navigate-to`` was
never shipped). What browsers do block is a top-level *navigation* to ``data:``, which the
``download`` attribute turns into a save instead. See the module tests, which decode the
generated URI back to the exact JSON.

**Size.** The page budget is :data:`~nikasha.render.html.page.MAX_BYTES`, and this one
link is the largest single thing on the page. Above :data:`URI_BUDGET` the link is
replaced by the command that produces the same JSON on disk, because half a result is
worse than none.

The footer states the tool version, the command that reproduces the run, and whether
anything touched the network. It never renders ``result.timings``: that is the one field
allowed to differ between two runs of the same input, and the page must be byte-identical
(P2). For the same reason the embedded JSON is serialized with ``include_timings=False``.
"""

from __future__ import annotations

from urllib.parse import quote

from nikasha.render.html.context import Fragment, HtmlContext
from nikasha.render.html.escaping import attr, css_ident
from nikasha.render.html.escaping import text as esc
from nikasha.render.html.escaping import url as safe_url
from nikasha.render.html.page import MAX_BYTES
from nikasha.render.markdown import rerun_command

ORDER = 95

#: The encoded URI may claim this much of the page budget. The rest of the page — the
#: report body, the evidence cards and their excerpts — needs the remainder.
URI_BUDGET = MAX_BYTES * 2 // 5

#: Characters left unencoded in the ``data:`` URI. Everything else becomes ``%XX``.
#:
#: Excluded on purpose: ``#`` (starts the fragment) and ``%`` (starts an escape), which
#: are the two that corrupt a ``data:`` URI; all whitespace, which the URL parser strips;
#: and ``& " ' < > = `` `` ``, which :func:`~nikasha.render.html.escaping.attr` would turn
#: into character references, costing five bytes each to say what ``%XX`` says in three.
#: What is left is the punctuation JSON is actually made of.
_DATA_SAFE = "{}[],:!$()*+;/?@"

#: `application/json` has no registered charset parameter (RFC 8259 requires UTF-8), and
#: leaving it out keeps an `=` out of the URI — `attr()` would spend five bytes turning
#: each one into `&#x3d;`, on a string that is already the largest thing on the page.
_MIME = "data:application/json,"

#: Upper bound on the displayed command, which is built from the report-supplied repo URL.
MAX_COMMAND_CHARS = 400

#: Fetched URLs listed in the footer when a run was allowed online.
MAX_FETCHED = 6

_KIB = 1024
_MIB = 1024 * 1024

CSS = """
.dl { margin: 32px 0 0; padding-top: 18px; border-top: 1px solid var(--border);
      font-size: 13px; color: var(--muted); }
.dl-actions { display: flex; flex-wrap: wrap; align-items: center; gap: 10px; }
.dl-json { display: inline-flex; align-items: center; gap: 7px;
           font-size: 14px; text-decoration: none; color: var(--fg);
           background: var(--panel); border: 1px solid var(--border);
           border-radius: var(--radius); padding: 7px 13px; }
.dl-json:hover { border-color: var(--link); color: var(--link); }
.dl-json svg { width: 15px; height: 15px; flex: none; }
.dl-size { color: var(--muted); font-size: 12px; }
.dl-meta { display: grid; grid-template-columns: auto minmax(0, 1fr);
           gap: 2px 12px; margin: 16px 0 0; }
.dl-meta dt { color: var(--muted); }
.dl-meta dd { margin: 0; color: var(--fg); overflow-wrap: anywhere; }
.dl-note { margin: 12px 0 0; max-width: 78ch; }
.dl-cmd { display: block; margin: 6px 0 0; padding: 8px 10px;
          background: var(--panel); border: 1px solid var(--border);
          border-radius: var(--radius); overflow-x: auto; white-space: pre-wrap;
          overflow-wrap: anywhere; color: var(--fg); }
.dl-urls { margin: 6px 0 0; padding-left: 20px; }
@media print { .dl-json { display: none; } }
"""

#: A tray-with-arrow glyph, inline because the page makes no network request (P3).
_ICON = (
    '<svg viewBox="0 0 16 16" aria-hidden="true" focusable="false" fill="none" '
    'stroke="currentColor" stroke-width="1.5" stroke-linecap="round">'
    '<path d="M8 2v7.5"/><path d="M4.75 6.75 8 10l3.25-3.25"/>'
    '<path d="M2.5 11.5v1.25a1 1 0 0 0 1 1h9a1 1 0 0 0 1-1V11.5"/>'
    "</svg>"
)


def data_uri(json_text: str) -> str:
    """``json_text`` as a ``data:`` URI that decodes back to exactly those bytes."""
    return _MIME + quote(json_text, safe=_DATA_SAFE, encoding="utf-8")


def _human_bytes(count: int) -> str:
    """A stable size label. Integer arithmetic only: no float formatting, no locale."""
    if count < _KIB:
        return f"{count} bytes"
    if count < _MIB:
        return f"{(count + _KIB // 2) // _KIB} KB"
    tenths = (count * 10 + _MIB // 2) // _MIB
    return f"{tenths // 10}.{tenths % 10} MB"


def _command(ctx: HtmlContext, *, output_format: str) -> str:
    """The ``nikasha check …`` line that reproduces this run in a given format."""
    suffix = {"html": " --format html -o report.html", "json": " --format json -o result.json"}
    command = rerun_command(ctx.result) + suffix.get(output_format, "")
    return command if len(command) <= MAX_COMMAND_CHARS else command[:MAX_COMMAND_CHARS] + "…"


def _filename(ctx: HtmlContext) -> str:
    """A deterministic, inert download name. The report ID is content-derived."""
    stem = css_ident(ctx.result.report.id, fallback="result")[:40]
    return f"nikasha-{stem}.json"


def _download_html(ctx: HtmlContext) -> str:
    """The link, or the command that produces the same file when it will not fit."""
    # `include_timings=False`: timings are the one field allowed to differ between runs,
    # and a `data:` URI carrying them would make the page differ too (P2).
    payload = ctx.result.to_json(include_timings=False)
    uri = data_uri(payload)
    size = _human_bytes(len(payload.encode("utf-8")))
    if len(uri) > URI_BUDGET:
        return (
            f'<p class="dl-note">The result JSON is {esc(size)}, too large to embed in '
            "this page without breaking the size budget. Re-run to write it to disk:</p>"
            f'<code class="dl-cmd">{esc(_command(ctx, output_format="json"))}</code>'
        )
    return (
        '<div class="dl-actions">'
        f'<a class="dl-json" download="{attr(_filename(ctx))}" href="{attr(uri)}">'
        f'{_ICON}Download JSON<span class="dl-size">&nbsp;{esc(size)}</span></a>'
        '<span class="dl-size">every claim, every piece of evidence, machine-readable'
        " (timings omitted, so this page is byte-identical for one report)</span>"
        "</div>"
    )


def _environment_html(ctx: HtmlContext) -> str:
    """What touched the network, stated plainly. This is the P3 promise, in writing."""
    env = ctx.result.environment
    if env.mode == "offline":
        note = (
            "This report was produced offline: no network request was made while checking, "
            "and this page makes none when you open it."
        )
    else:
        note = (
            "This run was allowed network access with --online. The page itself still makes "
            "no network request when you open it."
        )
    parts = [f'<p class="dl-note">{esc(note)}</p>']
    if env.fetched_urls:
        rows = []
        for raw in env.fetched_urls[:MAX_FETCHED]:
            href = safe_url(raw)
            shown = esc(raw)
            rows.append(
                f'<li><a href="{href}" rel="noreferrer noopener">{shown}</a></li>'
                if href
                else f'<li class="mono">{shown}</li>'
            )
        extra = len(env.fetched_urls) - len(rows)
        if extra > 0:
            rows.append(f'<li class="muted">and {esc(extra)} more</li>')
        parts.append(f'<ul class="dl-urls">{"".join(rows)}</ul>')
    return "".join(parts)


def _meta_html(ctx: HtmlContext) -> str:
    env = ctx.result.environment
    version = ctx.tool_version or ctx.result.tool_version
    rows = [f"<dt>Tool</dt><dd>nikasha {esc(version)}</dd>"]
    rows.append(
        "<dt>Reproduce</dt><dd>"
        f'<code class="dl-cmd">{esc(_command(ctx, output_format="html"))}</code></dd>'
    )
    if env.sandbox_engine:
        rows.append(f"<dt>Sandbox</dt><dd>{esc(env.sandbox_engine)}</dd>")
    return f'<dl class="dl-meta">{"".join(rows)}</dl>'


def render(ctx: HtmlContext) -> Fragment | None:
    html = f"""
<footer class="dl" id="downloads" aria-label="Downloads and run details">
  {_download_html(ctx)}
  {_meta_html(ctx)}
  {_environment_html(ctx)}
</footer>
"""
    return Fragment(html=html, css=CSS)


__all__ = ["MAX_COMMAND_CHARS", "ORDER", "URI_BUDGET", "data_uri", "render"]
