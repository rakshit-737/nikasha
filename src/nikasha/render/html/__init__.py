# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The self-contained HTML fact-check report (SPEC §15.2).

A component is a module in :mod:`nikasha.render.html.components` exposing::

    ORDER: int                       # where it sits on the page, low first
    COLUMN: str                      # optional: "left" or "right" (see below)
    def render(ctx: HtmlContext) -> Fragment | None

Components are discovered, so adding one is adding a file — no shared registry to edit.
Returning ``None`` means "nothing to show for this report", which is normal: a report with
no patch has no patch view.

A component that raises is **skipped**, and the rest of the page is still written. A
maintainer who cannot open the report learns nothing at all; one whose version-fit chart
is missing still gets the verdict and the evidence.
"""

from __future__ import annotations

import importlib
import pkgutil
from collections.abc import Sequence

from nikasha.model.evidence import CodeLocation
from nikasha.render.html.context import ExcerptProvider, Fragment, HtmlContext
from nikasha.render.html.escaping import text as esc
from nikasha.render.html.page import MAX_BYTES, build_page

__all__ = [
    "MAX_BYTES",
    "CodeLocation",
    "ExcerptProvider",
    "Fragment",
    "HtmlContext",
    "component_modules",
    "render_html",
    "render_html_result",
]


def component_modules() -> list[tuple[int, str, object]]:
    """Every component module, as ``(ORDER, name, module)``, sorted for a stable page."""
    # Importing a submodule binds it as an attribute of this package, so a function named
    # `components` would be overwritten by the `components` subpackage on first call and
    # stop being callable on the second. Hence the name, and the import by string.
    package = importlib.import_module("nikasha.render.html.components")
    found: list[tuple[int, str, object]] = []
    for info in pkgutil.iter_modules(package.__path__):
        if info.name.startswith("_"):
            continue
        module = importlib.import_module(f"{package.__name__}.{info.name}")
        if not hasattr(module, "render"):
            continue
        found.append((int(getattr(module, "ORDER", 500)), info.name, module))
    return sorted(found, key=lambda item: (item[0], item[1]))


def render_html_result(
    result: object,
    *,
    ledger: object = None,
    excerpts: ExcerptProvider | None = None,
    source: str = "",
    tool_version: str = "",
) -> str:
    """Render a :class:`~nikasha.model.result.Result` (plus an optional ledger) to HTML."""
    from nikasha.fuse.scoring import Ledger  # noqa: PLC0415
    from nikasha.model.result import Result  # noqa: PLC0415

    if not isinstance(result, Result):
        raise TypeError(f"expected a Result, got {type(result).__name__}")
    ctx = HtmlContext(
        result=result,
        ledger=ledger if isinstance(ledger, Ledger) else None,
        excerpts=excerpts,
        source=source,
        tool_version=tool_version or result.tool_version,
    )
    fragments: list[Fragment] = []
    columns: dict[str, list[Fragment]] = {"left": [], "right": []}
    column_slot: int | None = None
    failed: list[str] = []
    for _order, name, module in component_modules():
        try:
            fragment = module.render(ctx)  # type: ignore[attr-defined]
        except Exception as exc:  # one broken view must not cost the whole report
            failed.append(f"{name}: {type(exc).__name__}: {exc}")
            continue
        if fragment is None:
            continue
        side = getattr(module, "COLUMN", None)
        if side in columns:
            if column_slot is None:
                column_slot = len(fragments)
                fragments.append(Fragment(html=""))  # reserved; filled in below
            columns[str(side)].append(fragment)
        else:
            fragments.append(fragment)
    if column_slot is not None:
        fragments[column_slot] = _columns(columns)
    if failed:
        # Say so on the page rather than quietly shipping a report with a hole in it.
        notes = "".join(f"<li>{esc(note)}</li>" for note in failed)
        fragments.append(
            Fragment(
                html='<section class="panel" role="status"><p><strong>Some views could '
                f"not be rendered.</strong></p><ul>{notes}</ul></section>"
            )
        )
    label = result.verdict.label if result.verdict is not None else "report"
    return build_page(
        title=f"Nikasha: {label}",
        description=(
            f"Evidence-backed check of a vulnerability report against the code at the "
            f"version it names. Verdict: {label}."
        ),
        fragments=fragments,
    )


def _columns(columns: dict[str, list[Fragment]]) -> Fragment:
    """Fold the ``COLUMN`` components into one side-by-side band.

    The CSS collapses to a single column under 1000px, so the markup order is also the
    reading order on a phone: the report first, then the evidence about it.
    """
    left = chr(10).join(f.html for f in columns["left"])
    right = chr(10).join(f.html for f in columns["right"])
    css = "".join(f.css for side in columns.values() for f in side if f.css)
    js = "".join(f.js for side in columns.values() for f in side if f.js)
    if not left or not right:
        # Only one side has anything to show; a grid with an empty half wastes the width.
        return Fragment(html=left + right, css=css, js=js)
    return Fragment(
        html=f'<div class="columns"><div>{left}</div><div>{right}</div></div>',
        css=css,
        js=js,
    )


def render_html(
    report: object,
    *,
    excerpts: ExcerptProvider | None = None,
    source: str = "",
) -> str:
    """Render a :class:`~nikasha.pipeline.CheckReport` to a single HTML file."""
    return render_html_result(
        report.result,  # type: ignore[attr-defined]
        ledger=report.ledger,  # type: ignore[attr-defined]
        excerpts=excerpts,
        source=source,
    )


def excerpt_lines(
    text_of: str, start: int, end: int, *, context: int = 4
) -> Sequence[tuple[int, str]]:
    """Numbered lines covering ``start``..``end`` with ``context`` lines either side."""
    lines = text_of.splitlines()
    first = max(1, start - context)
    last = min(len(lines), max(end, start) + context)
    return [(n, lines[n - 1]) for n in range(first, last + 1)]
