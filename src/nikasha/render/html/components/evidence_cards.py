# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Evidence cards: the right column of the report, and its whole point (SPEC §15.2).

Everything else on the page is a summary of this column. A card is one piece of evidence:
what the check concluded, in one sentence; the source lines **at the exact commit the
report named**, with the cited lines marked; a permalink so the reader can check upstream
without trusting this file; and, collapsed, the commands that produced it (P6).

Four things here are worth knowing before changing anything.

**The card ID is an API.** Each card is ``id="ev-<evidence id>"`` and the report pane links
straight to it, so the ID must stay derived from ``Evidence.id`` and nothing else. A card
is never dropped for being long — dropping one would break an anchor — only its code is,
and only when the page budget runs out.

**Pygments output is escaped, and we prove it.** ``HtmlFormatter`` escapes the source text
it wraps in ``<span>`` tags, but "the library escapes it" is exactly the assumption every
XSS in a code viewer was built on, so ``tests/unit/render/html/test_evidence_cards.py``
runs ``</script>`` and ``</style>`` through this path and asserts nothing executable comes
out. Two habits keep that true: lines go through
:func:`~nikasha.render.html.escaping.clean` *before* highlighting, since Pygments happily
passes a bidi override through, and the highlighted output is used only when it splits
into exactly as many lines as went in — anything else falls back to
:func:`~nikasha.render.html.escaping.text`.

**The token colours are ours, not Pygments'.** ``HtmlFormatter().get_style_defs()`` emits
fixed hex colours, and the default style's dark blue keywords on this page's near-black
dark panel are unreadable, while a style chosen to survive the dark theme is washed out on
the light one. So the *class names* come from Pygments
(:data:`~pygments.token.STANDARD_TYPES`, so every class Pygments can emit is covered)
while the colours are CSS variables that flip with the theme, and every pairing below
clears WCAG 2.1 AA against the panel, the page and the highlight background.

**No script.** Collapsing is ``<details>``, which is keyboard reachable and announces its
own expanded state, so this component contributes no JS at all.
"""

from __future__ import annotations

import shlex
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from pygments import highlight  # type: ignore[import-untyped]
from pygments.formatters import HtmlFormatter  # type: ignore[import-untyped]
from pygments.lexers import get_lexer_for_filename  # type: ignore[import-untyped]
from pygments.token import STANDARD_TYPES, Token  # type: ignore[import-untyped]
from pygments.util import ClassNotFound  # type: ignore[import-untyped]

from nikasha.model.evidence import CodeLocation, CommandRecord, Evidence
from nikasha.model.ids import canonical_json
from nikasha.render.html.context import OUTCOME_CLASS, Fragment, HtmlContext
from nikasha.render.html.escaping import attr, clean, css_ident, url
from nikasha.render.html.escaping import text as esc

ORDER = 30
#: SPEC 15.2 puts the evidence cards on the right, beside the report text.
COLUMN = "right"

#: Lines of source shown per location before the rest is summarised away.
MAX_EXCERPT_LINES = 40

#: A minified file is one line of a hundred thousand characters. Cut it well before that.
MAX_LINE_CHARS = 200

#: Locations shown per card; the rest are counted.
MAX_LOCATIONS = 4

#: Caps on the ``details`` mapping, which is check-defined and can hold anything.
MAX_DETAIL_KEYS = 24
MAX_DETAIL_CHARS = 400

#: Cap on one rendered command line.
MAX_ARGV_CHARS = 300

#: Total characters of code markup the column may spend. The page budget is 1.5 MB
#: (SPEC §15.2) and the rest of the report needs room, so code yields first — and it yields
#: *late*, after the cards that matter most, because ``HtmlContext.by_group`` puts the
#: strongest evidence first.
MAX_CODE_CHARS = 600_000

#: Pygments, told not to wrap its output: we supply the ``<pre>`` and the line markers.
_FORMATTER = HtmlFormatter(nowrap=True)

#: Token families, most specific first — ``Token.Keyword.Type in Token.Keyword`` is true,
#: so the order decides. Anything unmatched keeps the body text colour.
_TOKEN_FAMILIES: tuple[tuple[str, Any], ...] = (
    ("preproc", Token.Comment.Preproc),
    ("preproc", Token.Comment.PreprocFile),
    ("comment", Token.Comment),
    ("type", Token.Keyword.Type),
    ("keyword", Token.Keyword),
    ("keyword", Token.Operator.Word),
    ("string", Token.Literal.String),
    ("string", Token.Literal.Date),
    ("number", Token.Literal.Number),
    ("func", Token.Name.Function),
    ("func", Token.Name.Class),
    ("func", Token.Name.Decorator),
    ("func", Token.Name.Exception),
    ("builtin", Token.Name.Builtin),
    ("builtin", Token.Name.Constant),
    ("builtin", Token.Name.Tag),
    ("builtin", Token.Name.Attribute),
    ("builtin", Token.Name.Namespace),
    ("builtin", Token.Name.Label),
    ("builtin", Token.Name.Entity),
    ("removed", Token.Generic.Deleted),
    ("added", Token.Generic.Inserted),
    ("comment", Token.Generic.Heading),
    ("comment", Token.Generic.Subheading),
    ("comment", Token.Generic.Prompt),
    ("bad", Token.Generic.Error),
    ("bad", Token.Generic.Traceback),
    ("bad", Token.Error),
    ("punct", Token.Operator),
    ("punct", Token.Punctuation),
)

#: One declaration per family. Colours are variables so the theme toggle reaches them.
_FAMILY_STYLE = {
    "added": "color: var(--ok);",
    "bad": "color: var(--bad);",
    "builtin": "color: var(--ev-builtin);",
    "comment": "color: var(--ev-comment); font-style: italic;",
    "func": "color: var(--ev-func);",
    "keyword": "color: var(--ev-keyword); font-weight: 600;",
    "number": "color: var(--ev-number);",
    "preproc": "color: var(--ev-preproc);",
    "punct": "color: var(--ev-punct);",
    "removed": "color: var(--bad);",
    "string": "color: var(--ev-string);",
    "type": "color: var(--ev-type);",
}


def _family(token: object) -> str | None:
    """Which colour family a Pygments token belongs to, or ``None`` for body text."""
    for name, parent in _TOKEN_FAMILIES:
        if token in parent:
            return name
    return None


def _token_css() -> str:
    """One CSS rule per family, listing every Pygments class that lands in it.

    Built from Pygments' own table rather than a hand-written list, so a token class we
    have never seen still gets a colour that follows the theme. Sorted throughout: this
    string is part of the page, and the page must be byte-identical between runs (P2).
    """
    families: dict[str, set[str]] = {}
    for token, short in STANDARD_TYPES.items():
        name = _family(token)
        if name is not None and short:
            families.setdefault(name, set()).add(short)
    rules = []
    for name in sorted(families):
        selector = ", ".join(f".ev-code .{short}" for short in sorted(families[name]))
        rules.append(f"{selector} {{ {_FAMILY_STYLE[name]} }}")
    return "\n".join(rules)


#: Syntax colours, verified against ``--bg``, ``--panel`` and ``--ev-hit-bg`` in both
#: themes: the lowest pairing is 4.87:1, above the 4.5:1 AA threshold for body text.
_PALETTE_LIGHT = """
  --ev-comment: #626c78; --ev-preproc: #8a4a00; --ev-keyword: #8a1f8a;
  --ev-type: #0a5c70; --ev-string: #0e6a3a; --ev-number: #8a4a00;
  --ev-func: #0b4fa8; --ev-builtin: #5a3aa8; --ev-punct: #444c55;
  --ev-hit-bg: #fff4d5;
"""

_PALETTE_DARK = """
  --ev-comment: #93a0ad; --ev-preproc: #f0c274; --ev-keyword: #e5a8f0;
  --ev-type: #7fd6ea; --ev-string: #94dcae; --ev-number: #f0c274;
  --ev-func: #8ab4f8; --ev-builtin: #c4b0f5; --ev-punct: #c0c8d1;
  --ev-hit-bg: #2a3038;
"""

_LAYOUT_CSS = """
.ev { margin: 28px 0 0; }
.ev > h2 { font-size: 18px; margin: 0 0 4px; }
.ev-group { margin: 20px 0 0; }
.ev-group > h3 {
  font-size: 13px; text-transform: uppercase; letter-spacing: 0.06em;
  color: var(--muted); margin: 0 0 8px; font-weight: 700;
}
.ev-card { margin: 0 0 12px; padding: 14px 16px; scroll-margin-top: 16px; }
.ev-card:target { outline: 2px solid var(--link); outline-offset: 2px; }
.ev-head { display: flex; flex-wrap: wrap; align-items: baseline; gap: 8px; }
.ev-check { font-weight: 700; }
.ev-strength, .ev-by { font-size: 12px; color: var(--muted); }
.ev-summary { margin: 8px 0 0; overflow-wrap: anywhere; }
.ev-loc { margin: 12px 0 0; }
.ev-where {
  display: flex; flex-wrap: wrap; gap: 4px 10px; align-items: baseline;
  font-size: 12px; margin: 0 0 4px; overflow-wrap: anywhere;
}
.ev-where .ev-path { font-family: var(--mono); }
.ev-code {
  margin: 0; padding: 8px 0; background: var(--bg);
  border: 1px solid var(--border); border-radius: var(--radius);
  font-family: var(--mono); font-size: 12.5px; line-height: 1.5; color: var(--fg);
  overflow: hidden;
}
.ev-code .ev-l {
  display: block; position: relative; padding: 0 10px 0 4.6em;
  white-space: pre-wrap; overflow-wrap: anywhere; tab-size: 4;
}
.ev-code .ev-l::before {
  content: attr(data-ln); position: absolute; left: 0; top: 0; width: 3.8em;
  text-align: right; color: var(--muted); -webkit-user-select: none; user-select: none;
}
.ev-code .ev-hit { background: var(--ev-hit-bg); }
.ev-code.ev-ok .ev-hit { box-shadow: inset 3px 0 0 var(--ok); }
.ev-code.ev-bad .ev-hit { box-shadow: inset 3px 0 0 var(--bad); }
.ev-code.ev-warn .ev-hit { box-shadow: inset 3px 0 0 var(--warn); }
.ev-code.ev-unknown .ev-hit { box-shadow: inset 3px 0 0 var(--unknown); }
.ev-cut { color: var(--muted); }
.ev-note { font-size: 12px; color: var(--muted); margin: 4px 0 0; }
.ev-card details { margin: 10px 0 0; font-size: 13px; }
.ev-card summary { cursor: pointer; color: var(--muted); }
.ev-card summary:hover { color: var(--fg); }
.ev-dl {
  display: grid; grid-template-columns: auto minmax(0, 1fr);
  gap: 2px 12px; margin: 8px 0 0;
}
.ev-dl dt { color: var(--muted); }
.ev-dl dd { margin: 0; font-family: var(--mono); font-size: 12px; overflow-wrap: anywhere; }
.ev-cmds { margin: 8px 0 0; padding: 0 0 0 18px; }
.ev-cmds li { margin: 0 0 6px; }
.ev-argv { display: block; overflow-wrap: anywhere; }
@media print {
  /* A collapsed card prints as a card with nothing in it, so open them on paper. The
     sibling rule handles engines that hide the content with `display: none`, and
     `::details-content` the newer ones that use content-visibility; both are ignored
     where they are not understood, which is the worst case we can be in here. */
  .ev-card details > summary ~ * { display: block; }
  .ev-card details::details-content { content-visibility: visible; block-size: auto; }
  .ev-card summary { color: #000; }
  .ev-code { border-color: #999; }
}
"""

CSS = (
    f":root {{{_PALETTE_LIGHT}}}\n"
    f"@media (prefers-color-scheme: dark) {{\n"
    f'  :root:not([data-theme="light"]) {{{_PALETTE_DARK}}}\n'
    f"}}\n"
    f':root[data-theme="dark"] {{{_PALETTE_DARK}}}\n' + _LAYOUT_CSS + _token_css()
)


@dataclass
class _Budget:
    """How much code markup the column may still spend (see :data:`MAX_CODE_CHARS`)."""

    left: int = MAX_CODE_CHARS
    spent_out: bool = False

    def take(self, chunk: str) -> bool:
        """Charge ``chunk`` to the budget, or refuse it and remember that we had to."""
        if len(chunk) > self.left:
            self.spent_out = True
            return False
        self.left -= len(chunk)
        return True


#: Lexers are looked up by file name, which is report-derived, so the lookup is cached:
#: a report with forty findings in one file should not re-resolve the lexer forty times.
_LEXER_CACHE: dict[str, object] = {}


def _lexer_for(path: str) -> object:
    """A Pygments lexer for ``path``, or ``None`` when there is no sensible one."""
    name = path.rsplit("/", 1)[-1][:120] or "x"
    if name not in _LEXER_CACHE:
        lexer: object = None
        try:
            lexer = get_lexer_for_filename(name, stripnl=False, ensurenl=False)
        except ClassNotFound:
            lexer = None  # an extension nobody has a lexer for: plain text is correct
        except Exception:
            lexer = None  # a third-party lexer plugin misbehaving is not our problem
        _LEXER_CACHE[name] = lexer
    return _LEXER_CACHE[name]


def _highlight(path: str, lines: Sequence[str]) -> list[str]:
    """Token-marked HTML for each already-cleaned line, one string per input line.

    The result is escaped either way: Pygments escapes the text it marks up, and the
    fallback escapes it here. The line-count check is what makes that guarantee hold — if
    the formatter ever returned something we did not expect, we would otherwise be slicing
    markup at newlines and could hand a half-open tag to the page.
    """
    lexer = _lexer_for(path)
    if lexer is not None:
        marked: str | None
        try:
            marked = highlight("\n".join(lines), lexer, _FORMATTER)
        except Exception:
            marked = None  # a lexer dying on hostile input costs one excerpt, not the page
        if marked is not None:
            parts = marked.split("\n")
            if parts and parts[-1] == "":
                parts.pop()
            if len(parts) == len(lines):
                return parts
    return [esc(line) for line in lines]


def _line_range(location: CodeLocation) -> tuple[int, int]:
    """The cited range, ordered — a check may record it either way round."""
    low = min(location.start_line, location.end_line)
    high = max(location.start_line, location.end_line)
    return low, high


def _code_block(ctx: HtmlContext, location: CodeLocation, klass: str, budget: _Budget) -> str:
    """The ``<pre>`` for one location, or ``""`` when there is no code to show.

    ``ctx.excerpt`` returns ``None`` when no repository is available — a report rendered
    from a saved ``RESULT.json`` is offline by construction — and that is not an error:
    the card is simply shown without code.
    """
    lines = ctx.excerpt(location)
    if not lines:
        return ""
    low, high = _line_range(location)
    shown = list(lines)[:MAX_EXCERPT_LINES]
    dropped = len(lines) - len(shown)

    cleaned = [clean(raw) for _number, raw in shown]
    cut = [len(text) > MAX_LINE_CHARS for text in cleaned]
    marked = _highlight(location.path, [text[:MAX_LINE_CHARS] for text in cleaned])

    rows = []
    for (number, _raw), body, was_cut in zip(shown, marked, cut, strict=True):
        hit = " ev-hit" if low <= number <= high else ""
        tail = '<span class="ev-cut"> …</span>' if was_cut else ""
        rows.append(f'<span class="ev-l{hit}" data-ln="{attr(number)}">{body}{tail}</span>')

    where = f"{location.path} lines {low} to {high}"
    joined = "".join(rows)
    block = (
        f'<pre class="ev-code ev-{attr(klass)}" aria-label="{attr(where)}">'
        f"<code>{joined}</code></pre>"
    )
    if dropped > 0:
        block += f'<p class="ev-note">{esc(dropped)} more lines not shown.</p>'
    if any(cut):
        block += f'<p class="ev-note">Long lines are cut at {MAX_LINE_CHARS} characters.</p>'
    return block if budget.take(block) else ""


def _location(ctx: HtmlContext, location: CodeLocation, klass: str, budget: _Budget) -> str:
    """One location: where it is, where to verify it upstream, and the source lines."""
    low, high = _line_range(location)
    span = f"{location.path}:{low}" + (f"-{high}" if high != low else "")
    bits = [f'<span class="ev-path">{esc(span)}</span>']
    if location.ref:
        bits.append(f'<span class="muted">{esc(location.ref)}</span>')
    if location.commit:
        bits.append(f'<span class="muted mono">{esc(location.commit[:12])}</span>')
    # `permalink` is report-derived and may be absent, or `javascript:`. `url()` returns ""
    # for anything that is not plainly an http(s) link, and then there is simply no link.
    href = url(location.permalink)
    if href:
        bits.append(
            f'<a href="{href}" rel="noreferrer noopener">view upstream'
            f'<span aria-hidden="true"> ↗</span></a>'
        )
    where = "".join(bits)
    return (
        f'<div class="ev-loc"><div class="ev-where">{where}</div>'
        f"{_code_block(ctx, location, klass, budget)}</div>"
    )


def _detail_value(value: object) -> str:
    """One ``details`` value as a short string. Anything structured becomes canonical JSON."""
    raw = value if isinstance(value, str) else canonical_json(value)
    if len(raw) > MAX_DETAIL_CHARS:
        return f"{raw[:MAX_DETAIL_CHARS]} … (+{len(raw) - MAX_DETAIL_CHARS} characters)"
    return raw


def _details(item: Evidence) -> str:
    """The check's own record, collapsed. Keys are sorted; the mapping is check-defined."""
    if not item.details:
        return ""
    keys = sorted(item.details)[:MAX_DETAIL_KEYS]
    rows = "".join(
        f"<dt>{esc(key.replace('_', ' '))}</dt><dd>{esc(_detail_value(item.details[key]))}</dd>"
        for key in keys
    )
    extra = len(item.details) - len(keys)
    note = f'<p class="ev-note">{esc(extra)} more fields not shown.</p>' if extra > 0 else ""
    return (
        f"<details><summary>What the check found ({esc(len(item.details))} fields)</summary>"
        f'<dl class="ev-dl">{rows}</dl>{note}</details>'
    )


def _command(record: CommandRecord) -> str:
    """One command, as something a reader could paste, plus the hashes of its output."""
    try:
        argv = shlex.join(record.argv)
    except (TypeError, ValueError):
        argv = " ".join(record.argv)
    if len(argv) > MAX_ARGV_CHARS:
        argv = f"{argv[:MAX_ARGV_CHARS]} …"
    duration = "" if record.duration_ms is None else f"{record.duration_ms} ms · "
    facts = (
        f"exit {record.exit_code} · {duration}"
        f"stdout {record.stdout_sha256[:12]} · stderr {record.stderr_sha256[:12]}"
    )
    if record.truncated:
        facts += " · output truncated"
    return (
        f'<li><code class="ev-argv mono">{esc(argv)}</code>'
        f'<span class="ev-note">{esc(facts)}</span></li>'
    )


def _commands(item: Evidence) -> str:
    """The command record, collapsed. An empty tuple renders nothing at all."""
    if not item.commands:
        return ""
    rows = "".join(_command(record) for record in item.commands)
    return (
        f"<details><summary>Commands run ({esc(len(item.commands))})</summary>"
        f'<ol class="ev-cmds">{rows}</ol></details>'
    )


def _card(ctx: HtmlContext, item: Evidence, budget: _Budget) -> str:
    """One evidence card. The ``id`` is what the report pane links to — do not change it."""
    klass = OUTCOME_CLASS.get(item.outcome, "unknown")
    # -0.0 formats as "-0.00", which would differ from run to run only by how a check
    # happened to compute zero. Normalise it: identical results must render identically.
    strength = item.strength if item.strength != 0 else 0.0
    by = (
        '<span class="ev-by">model review, never decisive</span>'
        if item.produced_by == "llm"
        else ""
    )
    locations = item.locations[:MAX_LOCATIONS]
    shown = "".join(_location(ctx, location, klass, budget) for location in locations)
    more = len(item.locations) - len(locations)
    if more > 0:
        shown += f'<p class="ev-note">{esc(more)} more locations not shown.</p>'
    return f"""<article class="ev-card panel" id="ev-{css_ident(item.id)}">
  <div class="ev-head">
    <span class="pill {attr(klass)}">{esc(item.outcome)}</span>
    <span class="ev-check mono">{esc(item.check_id)}</span>
    <span class="ev-strength mono">strength {esc(f"{strength:+.2f}")}</span>
    {by}
  </div>
  <p class="ev-summary">{esc(item.summary)}</p>
  {shown}{_details(item)}{_commands(item)}
</article>"""


def render(ctx: HtmlContext) -> Fragment | None:
    """The evidence column: every piece of evidence, grouped, strongest first."""
    if not ctx.evidence:
        return None
    budget = _Budget(MAX_CODE_CHARS)
    sections = []
    for group, items in ctx.by_group:
        slug = css_ident(f"g-{group}")
        cards = "".join(_card(ctx, item, budget) for item in items)
        sections.append(
            f'<section class="ev-group" aria-labelledby="ev{slug}">'
            f'<h3 id="ev{slug}">{esc(ctx.group_label(group))}'
            f' <span class="muted">({esc(len(items))})</span></h3>{cards}</section>'
        )
    tail = (
        '<p class="ev-note">Some code excerpts were left out to keep this file small.</p>'
        if budget.spent_out
        else ""
    )
    html = (
        '<section class="ev" id="evidence" aria-labelledby="evidence-heading">'
        '<h2 id="evidence-heading">Evidence</h2>'
        '<p class="muted">Each card is one check, at the commit the report names.</p>'
        f"{''.join(sections)}{tail}</section>"
    )
    return Fragment(html=html, css=CSS)
