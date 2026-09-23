# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The questions block, with a "Copy as reply" button (SPEC §15.2).

This is the one part of the report a maintainer *sends onward*, so two things matter more
here than anywhere else on the page.

**Tone (P1).** The questions come from fusion already written to be neutral and
answerable. Nothing this module wraps around them may editorialise: the heading, the
introduction, the status messages and the plain-text preamble all talk about *the report's
claims and the code*, never about the person who wrote them. There is a test that scans
the rendered markup for the words that would betray that.

**The copy button has to actually work, or say why not.** The CSP pins one script by
hash, so the handler is returned in :attr:`Fragment.js` and attached with
``addEventListener`` — an ``onclick=`` would be silently dropped by the policy. The text
to copy lives in a readonly ``<textarea>`` rather than in JavaScript, which keeps it out
of the script entirely (no ``script_json`` round-trip to get wrong) and gives the fallback
something real to select. ``navigator.clipboard`` is undefined on ``file://`` in some
browsers and rejects in others, so the handler degrades twice — clipboard API,
``execCommand("copy")``, then "here is the text, selected, press Ctrl+C" — and every
branch ends by writing to an ``aria-live`` region. A button that does nothing visible is
the failure mode this is written to avoid.
"""

from __future__ import annotations

from collections.abc import Sequence

from nikasha.model.verdict import Question
from nikasha.render.html.context import Fragment, HtmlContext
from nikasha.render.html.escaping import attr, css_ident
from nikasha.render.html.escaping import text as esc

ORDER = 80

#: Questions are few by construction (fusion emits a handful), but the page budget is not
#: negotiable and the verdict is input-derived, so the block is bounded anyway.
MAX_QUESTIONS = 20

#: Per-field caps. A question is a sentence; anything longer is a reporting bug or an
#: attempt to bloat the document, and both are handled the same way.
MAX_QUESTION_CHARS = 400
MAX_RATIONALE_CHARS = 400
MAX_SUMMARY_CHARS = 110
MAX_CITED = 6

#: The preamble of the pasted reply. Deliberately true for every verdict: a GROUNDED
#: report can still have questions, so this may not assume anything went wrong.
INTRO = (
    "Thanks for the report. I checked the details in it against the source at the version "
    "it names. To finish the review I need a little more information:"
)

#: The sign-off. It names the tool and what it did, and makes no claim about the reporter.
SIGNOFF = (
    "Checked with Nikasha, which compares a report against the source at the version it "
    "names. Happy to share the full evidence report if that helps."
)

#: Shown above the list, in the page only.
LEAD = (
    "Each question links to the evidence that raised it. They are written to be "
    "answerable: a commit, a release or a command is usually enough."
)

CSS = """
.qb { margin: 24px 0; }
.qb-head { display: flex; flex-wrap: wrap; align-items: center; gap: 12px;
           justify-content: space-between; }
.qb-head h2 { margin: 0; font-size: 18px; letter-spacing: -0.01em; }
.qb-lead { margin: 6px 0 14px; font-size: 13px; max-width: 70ch; }
.qb-copy { font: inherit; color: var(--fg); background: var(--bg);
           border: 1px solid var(--border); border-radius: var(--radius);
           padding: 6px 12px; cursor: pointer;
           display: inline-flex; align-items: center; gap: 6px; }
.qb-copy:hover { border-color: var(--link); }
.qb-copy svg { width: 14px; height: 14px; flex: none; }
.qb-list { margin: 0; padding-left: 22px; }
.qb-list > li { margin: 0 0 14px; }
.qb-list > li:last-child { margin-bottom: 0; }
.qb-q { margin: 0; font-weight: 600; overflow-wrap: anywhere; }
.qb-why, .qb-ev { margin: 3px 0 0; font-size: 13px; overflow-wrap: anywhere; }
.qb-label { color: var(--muted); }
.qb-sep { color: var(--muted); padding: 0 2px; }
.qb-status { margin: 14px 0 0; font-size: 13px; min-height: 1.3em; }
.qb-status[data-state="ok"] { color: var(--ok); }
.qb-status[data-state="warn"] { color: var(--warn); }
.qb-reveal { margin-top: 10px; font-size: 13px; }
.qb-reveal summary { cursor: pointer; color: var(--muted); }
.qb-text { width: 100%; margin-top: 8px; padding: 8px;
           font-family: var(--mono); font-size: 12px;
           color: var(--fg); background: var(--bg);
           border: 1px solid var(--border); border-radius: var(--radius);
           resize: vertical; }
.qb-more { margin: 12px 0 0; font-size: 13px; }
@media print { .qb-copy, .qb-status, .qb-reveal { display: none; } }
"""

#: No `<` appears anywhere in this script: the HTML tokenizer ends a `<script>` element at
#: the first `</script` even inside a string literal, and the safest way to never write
#: that sequence is to never write the character.
JS = """
(function () {
  "use strict";
  var button = document.getElementById("qb-copy");
  var source = document.getElementById("qb-source");
  var status = document.getElementById("qb-status");
  var reveal = document.getElementById("qb-reveal");
  if (!button || !source || !status) { return; }
  var DONE = "Copied. Paste it into your reply.";
  function say(message, state) {
    status.textContent = message;
    status.setAttribute("data-state", state);
  }
  function selectAll() {
    if (reveal) { reveal.open = true; }
    try {
      source.focus({ preventScroll: true });
      source.select();
      source.setSelectionRange(0, source.value.length);
      return true;
    } catch (e) {
      return false;
    }
  }
  function manual() {
    if (selectAll()) {
      say("This browser did not allow copying. The reply is selected below \\u2014 " +
          "press Ctrl+C, or Cmd+C on macOS.", "warn");
    } else {
      say("This browser did not allow copying. Open \\u201cThe reply as plain text\\u201d " +
          "below and copy it by hand.", "warn");
    }
  }
  function legacy() {
    if (!selectAll()) { manual(); return; }
    var copied = false;
    try { copied = document.execCommand("copy"); } catch (e) { copied = false; }
    if (copied) { say(DONE, "ok"); } else { manual(); }
  }
  button.addEventListener("click", function () {
    var api = navigator.clipboard;
    if (api && typeof api.writeText === "function") {
      try {
        api.writeText(source.value).then(function () { say(DONE, "ok"); }, legacy);
        return;
      } catch (e) {
        /* a throwing clipboard API is a non-secure context; fall through */
      }
    }
    legacy();
  });
})();
"""

#: A clipboard glyph, inline because the page makes no network request (P3).
_ICON = (
    '<svg viewBox="0 0 16 16" aria-hidden="true" focusable="false" fill="none" '
    'stroke="currentColor" stroke-width="1.5">'
    '<rect x="5.25" y="2.25" width="8.5" height="10.5" rx="1.5"/>'
    '<path d="M10.75 13.75H3.75a1.5 1.5 0 0 1-1.5-1.5V4.25"/>'
    "</svg>"
)


def _cap(value: object, limit: int) -> str:
    """Bound a report-derived string. The ellipsis says the text was cut, not dropped."""
    out = str(value).strip()
    return out if len(out) <= limit else out[: limit - 1].rstrip() + "…"


def _cited(ctx: HtmlContext, question: Question) -> list[tuple[str | None, str]]:
    """``(anchor, label)`` for each evidence item a question cites, in the cited order.

    ``anchor`` is ``None`` when the report carries no such evidence item — a citation with
    nowhere to land is rendered as inert text rather than as a link that goes nowhere.
    """
    out: list[tuple[str | None, str]] = []
    for evidence_id in question.evidence_ids[:MAX_CITED]:
        item = ctx.by_id.get(evidence_id)
        if item is None:
            out.append((None, _cap(evidence_id, 40)))
            continue
        # `css_ident` keeps the fragment to [A-Za-z0-9_-]; evidence IDs are already hex,
        # so this is a no-op in practice and a hard stop if one ever is not.
        out.append((css_ident(item.id), _cap(item.summary or item.check_id, MAX_SUMMARY_CHARS)))
    return out


def _question_html(ctx: HtmlContext, question: Question) -> str:
    parts = [f'<p class="qb-q">{esc(_cap(question.text, MAX_QUESTION_CHARS))}</p>']
    if question.rationale:
        parts.append(
            '<p class="qb-why muted"><span class="qb-label">Why this is asked:</span> '
            f"{esc(_cap(question.rationale, MAX_RATIONALE_CHARS))}</p>"
        )
    cited = _cited(ctx, question)
    if cited:
        links = [
            f'<a href="#ev-{attr(anchor)}">{esc(label)}</a>'
            if anchor
            else f'<span class="mono">{esc(label)}</span>'
            for anchor, label in cited
        ]
        joined = '<span class="qb-sep">&middot;</span>'.join(links)
        parts.append(f'<p class="qb-ev"><span class="qb-label">Evidence:</span> {joined}</p>')
    return f"<li>{''.join(parts)}</li>"


def reply_text(ctx: HtmlContext, questions: Sequence[Question]) -> str:
    """The questions as the plain text a maintainer pastes into a comment.

    Kept free of markup on purpose: it goes into a GitHub or HackerOne box, where the
    numbers and the indentation are the whole formatting budget.
    """
    lines = [INTRO, ""]
    for number, question in enumerate(questions, 1):
        lines.append(f"{number}. {_cap(question.text, MAX_QUESTION_CHARS)}")
        if question.rationale:
            lines.append(f"   Why this is asked: {_cap(question.rationale, MAX_RATIONALE_CHARS)}")
        for _anchor, label in _cited(ctx, question):
            lines.append(f"   Evidence: {label}")
        lines.append("")
    lines.append(SIGNOFF)
    return "\n".join(lines)


def render(ctx: HtmlContext) -> Fragment | None:
    verdict = ctx.verdict
    if verdict is None or not verdict.questions:
        return None
    shown = verdict.questions[:MAX_QUESTIONS]
    items = "".join(_question_html(ctx, question) for question in shown)
    more = ""
    if len(shown) < len(verdict.questions):
        more = (
            f'<p class="qb-more muted">Showing {esc(len(shown))} of '
            f"{esc(len(verdict.questions))} questions; the JSON below has them all.</p>"
        )
    # `esc` is the correct escape for a textarea: its content is RCDATA, so the element
    # ends at the first `</textarea` and character references are decoded. Escaping `<`
    # closes both, and the value JavaScript reads back is the original text.
    body = esc(reply_text(ctx, shown))
    rows = min(20, max(6, body.count("\n") + 2))
    html = f"""
<section class="qb panel" id="questions" aria-labelledby="qb-heading">
  <div class="qb-head">
    <h2 id="qb-heading">Questions for the reporter ({esc(len(shown))})</h2>
    <button class="qb-copy" id="qb-copy" type="button" aria-describedby="qb-status">
      {_ICON}Copy as reply</button>
  </div>
  <p class="qb-lead muted">{esc(LEAD)}</p>
  <ol class="qb-list">{items}</ol>
  {more}
  <p class="qb-status" id="qb-status" role="status" aria-live="polite"></p>
  <details class="qb-reveal" id="qb-reveal">
    <summary>The reply as plain text</summary>
    <textarea class="qb-text" id="qb-source" readonly rows="{attr(rows)}"
      aria-label="The questions as plain text, ready to paste into a reply"
      >{body}</textarea>
  </details>
</section>
"""
    return Fragment(html=html, css=CSS, js=JS)


__all__ = ["INTRO", "LEAD", "MAX_QUESTIONS", "ORDER", "SIGNOFF", "render", "reply_text"]
