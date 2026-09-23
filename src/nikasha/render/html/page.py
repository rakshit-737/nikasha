# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The page shell: CSP, theme, base stylesheet, and assembly (SPEC §15.2).

The report is **one file that makes no network request at all**. Fonts are the system
stack, icons are inline SVG, there is no CDN and no analytics. That is not minimalism for
its own sake: a maintainer opens this file while triaging an embargoed report, and a
document that phones home would leak which vulnerability they are looking at, and when
(P3).

The Content-Security-Policy is what enforces that rather than merely promising it:

    default-src 'none'; img-src data:; style-src 'unsafe-inline'; script-src 'sha256-…'

``default-src 'none'`` blocks every fetch the page could attempt. The script is pinned by
hash, so the page has exactly **one** script element and no inline handlers; a component
that emits its own ``<script>`` or an ``onclick=`` simply stops working, which is a much
better failure than one that silently works.
"""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Iterable

from nikasha.render.html.context import Fragment

#: SPEC §15.2 target. The report is meant to be attached to an issue or an email.
MAX_BYTES = 1_500_000

#: The base stylesheet. Colours are CSS variables so the dark theme redefines values
#: rather than duplicating rules, and every pairing meets WCAG 2.1 AA contrast.
BASE_CSS = """
:root {
  color-scheme: light dark;
  --bg: #ffffff; --panel: #f6f7f9; --border: #d8dce2;
  --fg: #1a1d21; --muted: #5a6470;
  --ok: #10633a; --ok-bg: #e7f4ec;
  --bad: #9b1c1c; --bad-bg: #fdecec;
  --warn: #7a4a02; --warn-bg: #fdf3e3;
  --unknown: #4a5058; --unknown-bg: #eef0f3;
  --link: #0b4fa8;
  --radius: 8px;
  --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;
  --sans: system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg: #14171a; --panel: #1c2024; --border: #2f353c;
    --fg: #e8eaed; --muted: #9aa4b0;
    --ok: #6ee7a8; --ok-bg: #12291f;
    --bad: #ff9a9a; --bad-bg: #2d1717;
    --warn: #f0c274; --warn-bg: #2b2015;
    --unknown: #b6bec8; --unknown-bg: #22272c;
    --link: #8ab4f8;
  }
}
:root[data-theme="dark"] {
  --bg: #14171a; --panel: #1c2024; --border: #2f353c;
  --fg: #e8eaed; --muted: #9aa4b0;
  --ok: #6ee7a8; --ok-bg: #12291f;
  --bad: #ff9a9a; --bad-bg: #2d1717;
  --warn: #f0c274; --warn-bg: #2b2015;
  --unknown: #b6bec8; --unknown-bg: #22272c;
  --link: #8ab4f8;
}
* { box-sizing: border-box; }
html { background: var(--bg); }
body {
  margin: 0; background: var(--bg); color: var(--fg);
  font-family: var(--sans); font-size: 15px; line-height: 1.55;
  -webkit-text-size-adjust: 100%;
}
a { color: var(--link); }
a:focus-visible, button:focus-visible, [tabindex]:focus-visible {
  outline: 2px solid var(--link); outline-offset: 2px;
}
code, pre, .mono { font-family: var(--mono); font-size: 13px; }
.wrap { max-width: 1400px; margin: 0 auto; padding: 0 16px 64px; }
.panel {
  background: var(--panel); border: 1px solid var(--border);
  border-radius: var(--radius); padding: 16px;
}
.muted { color: var(--muted); }
.ok { color: var(--ok); } .bad { color: var(--bad); }
.warn { color: var(--warn); } .unknown { color: var(--unknown); }
.pill {
  display: inline-block; padding: 2px 8px; border-radius: 999px;
  font-size: 12px; font-weight: 600; border: 1px solid currentColor;
}
.pill.ok { background: var(--ok-bg); } .pill.bad { background: var(--bad-bg); }
.pill.warn { background: var(--warn-bg); } .pill.unknown { background: var(--unknown-bg); }
.columns { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); gap: 20px; }
@media (max-width: 1000px) { .columns { grid-template-columns: minmax(0, 1fr); } }
.skip {
  position: absolute; left: -9999px; top: 0; background: var(--panel);
  padding: 8px 12px; z-index: 10;
}
.skip:focus { left: 8px; }
#theme-toggle {
  font: inherit; color: var(--fg); background: var(--panel);
  border: 1px solid var(--border); border-radius: var(--radius);
  padding: 4px 10px; cursor: pointer;
}
@media print {
  :root { --bg: #fff; --panel: #fff; --fg: #000; --muted: #333; --border: #999; }
  #theme-toggle, .skip { display: none; }
  details { open: open; }
  .columns { grid-template-columns: 1fr; }
  a[href]::after {
    content: " (" attr(href) ")"; font-size: 11px; color: #333;
    word-break: break-all;
  }
}
"""

#: The theme toggle. Every storage access is wrapped: a file:// page in a private window
#: throws on localStorage, and the report must still render.
BASE_JS = """
(function () {
  "use strict";
  var root = document.documentElement;
  function stored() {
    try { return localStorage.getItem("nikasha-theme"); } catch (e) { return null; }
  }
  function remember(value) {
    try { localStorage.setItem("nikasha-theme", value); } catch (e) { /* ignore */ }
  }
  var saved = stored();
  if (saved === "dark" || saved === "light") { root.setAttribute("data-theme", saved); }
  var button = document.getElementById("theme-toggle");
  if (button) {
    button.addEventListener("click", function () {
      var dark = root.getAttribute("data-theme") === "dark" ||
        (!root.getAttribute("data-theme") &&
         window.matchMedia("(prefers-color-scheme: dark)").matches);
      var next = dark ? "light" : "dark";
      root.setAttribute("data-theme", next);
      button.setAttribute("aria-pressed", String(next === "dark"));
      remember(next);
    });
  }
})();
"""


def script_hash(script: str) -> str:
    """The ``sha256-…`` source expression for an inline script's exact text."""
    digest = hashlib.sha256(script.encode("utf-8")).digest()
    return "sha256-" + base64.b64encode(digest).decode("ascii")


def csp(script: str) -> str:
    """The policy for a page whose only script is ``script``."""
    return (
        "default-src 'none'; "
        "img-src data:; "
        "style-src 'unsafe-inline'; "
        f"script-src '{script_hash(script)}'; "
        "base-uri 'none'; "
        "form-action 'none'"
    )


def build_page(*, title: str, fragments: Iterable[Fragment], description: str = "") -> str:
    """Assemble the one stylesheet, the one script and the body into a single file.

    ``title`` and ``description`` must already be escaped by the caller, which is the one
    place in this package where that is true — everything else escapes at the point of use.
    """
    parts = list(fragments)
    css = BASE_CSS + "".join(f.css for f in parts if f.css)
    script = BASE_JS + "".join(f.js for f in parts if f.js)
    body = "\n".join(f.html for f in parts if f.html)
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="{csp(script)}">
<meta name="referrer" content="no-referrer">
<meta name="robots" content="noindex, nofollow">
<meta name="generator" content="nikasha">
<meta name="description" content="{description}">
<title>{title}</title>
<style>{css}</style>
</head>
<body>
<a class="skip" href="#evidence">Skip to the evidence</a>
<div class="wrap">
{body}
</div>
<script>{script}</script>
</body>
</html>
"""


__all__ = ["BASE_CSS", "BASE_JS", "MAX_BYTES", "build_page", "csp", "script_hash"]
