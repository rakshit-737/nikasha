# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The patch view: every hunk, and which of its lines are really in the tree (SPEC §15.2).

A suggested patch is the most testable thing a report can carry, and C12 PATCH_APPLIES
applies it in memory, hunk by hunk. This view shows that answer line by line: the diff as
the reporter wrote it, with a mark against every line saying whether it was actually found
in the file at the version the report names.

Three decisions shape it.

**The marks are the point.** "This patch does not apply" and "this patch was written
against something else entirely" read identically in a one-line summary and look nothing
alike here: a hunk whose context matched at the wrong offset is a rebase, a hunk whose
context is nowhere is a different tree, and a hunk that needed fuzz is a patch against a
neighbouring release. The marks are derived from the status C12 recorded plus the fuzz it
needed — exactly what its matcher checked. This view never matches anything itself, so it
cannot claim more than the check did.

**"Already applied" is not a failure.** C12 detects it by the *reverse* patch applying,
and that nearly always means the reporter described a real problem that is already fixed at
the named version; SPEC §14.3 rule 4 caps the verdict at MIXED for precisely this reason.
Drawing it as a red "does not apply" would be actively misleading, so it gets plain
wording, a neutral colour, and a sentence naming the question actually worth asking. The
same goes for ``other_release_only``: a version mismatch is a question, not a refutation.

**A diff is hostile input (P7).** It comes from a stranger, it can carry thousands of hunks
and lines megabytes long, and it is the one place in the report where ``<`` and ``&`` are
completely normal characters. Every byte goes through :mod:`~nikasha.render.html.escaping`,
the hunks, lines and line lengths are all capped, and the code column wraps rather than
scrolls. Whatever was cut is stated on the page: a view that quietly drops evidence is
worse than no view at all.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from nikasha.model.claims import PatchClaim, PatchHunk, PatchLine
from nikasha.model.evidence import Evidence
from nikasha.render.html.context import Fragment, HtmlContext
from nikasha.render.html.escaping import attr
from nikasha.render.html.escaping import text as esc

ORDER = 70

#: The check whose per-hunk detail this view draws.
CHECK_ID = "C12"

#: Patches shown. A report carrying more than two suggested fixes is either a rollup or an
#: attempt to make the page enormous; both are served by a count and a cap.
MAX_CLAIMS = 2
#: Hunks shown per patch. C12 itself checks at most 100.
MAX_HUNKS = 10
#: Lines shown per hunk.
MAX_HUNK_LINES = 50
#: Characters shown per line. The column wraps, so this is about page size, not layout.
MAX_LINE_CHARS = 300
#: Names listed before "and N more" in a file or release list.
MAX_NAMES = 6

#: Which side of a hunk C12 managed to locate, which is what the per-line marks mean:
#: ``forward`` the pre-patch text, ``reverse`` the post-patch text, ``none`` neither, and
#: ``unchecked`` "the question was never put to the tree".
_Mode = Literal["forward", "reverse", "none", "unchecked"]


@dataclass(frozen=True, slots=True)
class _Style:
    """How one C12 hunk status is drawn and explained."""

    label: str
    klass: str
    mode: _Mode
    blurb: str


_UNCHECKED_BLURB = "This hunk was not compared against the file, so nothing here is a finding."

#: One entry per ``_Status`` in :mod:`nikasha.checks.c12_patch_applies`. Only
#: ``context_not_found`` is drawn as a failure: every other unhappy status is a question
#: about versions or about what could be read, and SPEC §14.3 rule 4 treats it as one.
_STATUS: dict[str, _Style] = {
    "applies_clean": _Style(
        label="applies cleanly",
        klass="ok",
        mode="forward",
        blurb="Every line this hunk expects is in the file, at the line the diff cites.",
    ),
    "applies_with_fuzz": _Style(
        label="applies with fuzz",
        klass="ok",
        mode="forward",
        blurb="The hunk was found near the cited line. Lines marked as skipped were ignored"
        " to make it fit, exactly as patch(1) would have.",
    ),
    "already_applied": _Style(
        label="already applied",
        klass="warn",
        mode="reverse",
        blurb="The file already reads the way this patch would leave it: the reverse patch"
        " matches. The change appears to be in place at this version.",
    ),
    "context_elsewhere_in_file": _Style(
        label="context found elsewhere",
        klass="warn",
        mode="forward",
        blurb="These lines are in the file, but far from the position the diff cites.",
    ),
    "generated": _Style(
        label="generated file",
        klass="unknown",
        mode="unchecked",
        blurb="This file is generated or ships only in releases, so the patch is not judged"
        " against the tree.",
    ),
    "file_missing": _Style(
        label="file not read",
        klass="warn",
        mode="unchecked",
        blurb="The file this hunk names could not be read at this version, so its lines were"
        " never looked for.",
    ),
    "search_incomplete": _Style(
        label="search incomplete",
        klass="unknown",
        mode="unchecked",
        blurb="The search of the other releases ran out of time, so the context may still"
        " exist in one of them.",
    ),
    "other_release_only": _Style(
        label="fits another release",
        klass="warn",
        mode="none",
        blurb="These lines are not in the file at this version, but they are in another"
        " release. That is a question about which version was tested.",
    ),
    "context_not_found": _Style(
        label="context not found",
        klass="bad",
        mode="none",
        blurb="None of the lines this hunk expects are in the file at this version, nor in"
        " the releases searched.",
    ),
}

#: ``(glyph, words, class)`` per line mark. The glyph and the words both carry the meaning,
#: so the distinction never rests on colour alone (WCAG 1.4.1). HTML entities rather than
#: literal characters: this file travels through whatever encoding a consumer chooses.
_MARKS: dict[str, tuple[str, str, str]] = {
    "found": ("&#10003;", "found in the file", "pv-yes"),
    "skipped": ("&#126;", "skipped to make the hunk fit", "pv-skip"),
    "missing": ("&#10007;", "not found in the file", "pv-no"),
    "gone": ("&#183;", "already gone from the file", "pv-na"),
    "not_sought": ("&#183;", "added by the patch, not looked for", "pv-na"),
    "unchecked": ("&#63;", "not checked", "pv-unk"),
}

#: ``(glyph, word, row class, wrapping element)`` per diff operation.
_OPS: dict[str, tuple[str, str, str, str]] = {
    " ": ("&#160;", "context", "pv-r-ctx", ""),
    "+": ("+", "added", "pv-r-add", "ins"),
    "-": ("-", "removed", "pv-r-del", "del"),
}

CSS = """
.pv { margin: 24px 0; }
.pv h2 { margin: 0 0 4px; font-size: 18px; letter-spacing: -0.01em; }
.pv h3 { margin: 18px 0 2px; font-size: 15px; }
.pv h4 { margin: 14px 0 2px; font-size: 13px; font-family: var(--mono); font-weight: 600;
         overflow-wrap: anywhere; }
.pv p { margin: 4px 0; }
.pv .meta { font-size: 13px; overflow-wrap: anywhere; }
.pv-note { margin: 10px 0 14px; padding: 10px 12px; border-radius: var(--radius);
           border: 1px solid currentColor; }
.pv-note.warn { background: var(--warn-bg); color: var(--warn); }
.pv-note.ok { background: var(--ok-bg); color: var(--ok); }
.pv-note.bad { background: var(--bad-bg); color: var(--bad); }
.pv-note.unknown { background: var(--unknown-bg); color: var(--unknown); }
.pv-legend { display: flex; flex-wrap: wrap; gap: 4px 16px; margin: 8px 0 0; padding: 0;
             list-style: none; font-size: 12px; color: var(--muted); }
.pv-legend b { font-family: var(--mono); font-weight: 700; }
.pv-hunk { margin: 0 0 6px; }
.pv-table { width: 100%; border-collapse: collapse; table-layout: fixed;
            font-family: var(--mono); font-size: 12.5px; line-height: 1.45;
            border: 1px solid var(--border); border-radius: var(--radius); }
.pv-table td { padding: 0 6px; vertical-align: top; }
.pv-c-ln { width: 5ch; }
.pv-c-op { width: 2ch; }
.pv-c-mark { width: 3ch; }
.pv-ln { text-align: right; color: var(--muted); -webkit-user-select: none;
         user-select: none; }
.pv-op { text-align: center; color: var(--muted); -webkit-user-select: none;
         user-select: none; }
.pv-code { white-space: pre-wrap; overflow-wrap: anywhere; }
.pv-code ins, .pv-code del { text-decoration: none; background: none; color: inherit; }
.pv-mark { text-align: center; -webkit-user-select: none; user-select: none; }
.pv-r-add { background: var(--ok-bg); }
.pv-r-del { background: var(--bad-bg); }
.pv-yes { color: var(--ok); }
.pv-no { color: var(--bad); }
.pv-skip { color: var(--warn); }
.pv-na, .pv-unk { color: var(--muted); }
.pv-cut { color: var(--muted); }
.pv-sr { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px;
         overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; border: 0; }
@media print { .pv-hunk { break-inside: avoid; } }
"""


# --- reading C12's details ----------------------------------------------------------------
#
# ``Evidence.details`` is free-form JSON and may have been loaded from a file this process
# did not write, so every read is defensive: a wrong type degrades the view, it never
# raises. A component that raises is skipped entirely, which costs the maintainer the whole
# patch view over one bad key.


def _text_of(data: Mapping[str, object] | None, key: str) -> str:
    value = data.get(key) if data is not None else None
    return value if isinstance(value, str) else ""


def _int_of(data: Mapping[str, object] | None, key: str) -> int | None:
    value = data.get(key) if data is not None else None
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _names_of(data: Mapping[str, object] | None, key: str) -> list[str]:
    value = data.get(key) if data is not None else None
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _hunk_details(evidence: Evidence | None) -> list[Mapping[str, object]]:
    if evidence is None:
        return []
    raw = evidence.details.get("hunks")
    if not isinstance(raw, list):
        return []
    return [item for item in raw if isinstance(item, dict)]


def _style_for(status: str) -> _Style:
    """The drawing style for a status, tolerating one this version does not know."""
    known = _STATUS.get(status)
    if known is not None:
        return known
    label = status.replace("_", " ") if status else "not checked"
    return _Style(label=label, klass="unknown", mode="unchecked", blurb=_UNCHECKED_BLURB)


# --- the marks ------------------------------------------------------------------------------


def _fuzz_drops(hunk: PatchHunk, fuzz: int) -> tuple[int, int]:
    """How many leading and trailing context lines the match was allowed to ignore.

    Mirrors ``c12_patch_applies._sides``: fuzz drops whole context lines from each end of
    the hunk, never more than there are, so the count is the same for both directions.
    """
    ops = [line.op for line in hunk.lines]
    changed = [index for index, op in enumerate(ops) if op != " "]
    if not changed or fuzz <= 0:
        return 0, 0
    lead, trail = changed[0], len(ops) - 1 - changed[-1]
    return min(fuzz, lead), min(fuzz, trail)


def _marks_for(hunk: PatchHunk, mode: _Mode, fuzz: int) -> list[str]:
    """One mark per line of the hunk, answering "was this line in the file at the ref?".

    A forward match located the pre-patch text, so its context and removed lines are the
    ones that were found; a reverse match located the post-patch text, so its context and
    *added* lines were found and the removed lines are already gone. That difference is the
    whole distinction between "does not apply" and "already applied".
    """
    drop_lead, drop_trail = _fuzz_drops(hunk, fuzz)
    total = len(hunk.lines)
    marks: list[str] = []
    for index, line in enumerate(hunk.lines):
        dropped = index < drop_lead or index >= total - drop_trail
        if mode == "unchecked":
            marks.append("unchecked")
        elif mode == "none":
            marks.append("not_sought" if line.op == "+" else "missing")
        elif mode == "reverse":
            if line.op == "-":
                marks.append("gone")
            else:
                marks.append("skipped" if dropped else "found")
        elif line.op == "+":
            marks.append("not_sought")
        else:
            marks.append("skipped" if dropped else "found")
    return marks


def _counts_phrase(marks: Sequence[str], mode: _Mode) -> str:
    """ "6 of 6 lines … are in the file", or nothing when nothing was looked for."""
    found = marks.count("found")
    expected = found + marks.count("missing") + marks.count("skipped")
    if not expected:
        return ""
    subject = (
        "lines of the patched text are already in the file"
        if mode == "reverse"
        else "lines this hunk expects are in the file"
    )
    return f"{found} of {expected} {subject}"


# --- rendering one hunk ---------------------------------------------------------------------


def _shorten(value: str) -> tuple[str, bool]:
    if len(value) <= MAX_LINE_CHARS:
        return value, False
    return value[:MAX_LINE_CHARS], True


def _row(line: PatchLine, mark: str, old: int | None, new: int | None) -> str:
    """One diff line: old and new numbers, the operation, the code, and the mark."""
    glyph, words, mark_class = _MARKS.get(mark, _MARKS["unchecked"])
    op_glyph, op_word, row_class, tag = _OPS.get(line.op, _OPS[" "])
    shown, cut = _shorten(line.text)
    # A blank line still needs a line box under `white-space: pre-wrap`, hence the space.
    code = esc(shown) if shown else " "
    if tag:
        code = f"<{tag}>{code}</{tag}>"
    if cut:
        code += '<span class="pv-cut" aria-hidden="true">&#8230;</span>'
        code += '<span class="pv-sr"> (line truncated)</span>'
    return (
        f'<tr class="{attr(row_class)}">'
        f'<td class="pv-ln">{esc(old) if old is not None else ""}</td>'
        f'<td class="pv-ln">{esc(new) if new is not None else ""}</td>'
        f'<td class="pv-op"><span aria-hidden="true">{op_glyph}</span>'
        f'<span class="pv-sr">{esc(op_word)}</span></td>'
        f'<td class="pv-code">{code}</td>'
        f'<td class="pv-mark {attr(mark_class)}"><span aria-hidden="true">{glyph}</span>'
        f'<span class="pv-sr">{esc(words)}</span></td>'
        "</tr>"
    )


def _rows(hunk: PatchHunk, marks: Sequence[str]) -> tuple[str, int]:
    """The hunk's rows, and how many lines were left out of them."""
    old, new = hunk.source_start, hunk.target_start
    out: list[str] = []
    for index, line in enumerate(hunk.lines[:MAX_HUNK_LINES]):
        mark = marks[index] if index < len(marks) else "unchecked"
        out.append(
            _row(
                line,
                mark,
                old if line.op != "+" else None,
                new if line.op != "-" else None,
            )
        )
        old += 1 if line.op != "+" else 0
        new += 1 if line.op != "-" else 0
    return "".join(out), max(0, len(hunk.lines) - MAX_HUNK_LINES)


def _hunk_header(hunk: PatchHunk) -> str:
    head = (
        f"@@ -{hunk.source_start},{hunk.source_length} +{hunk.target_start},{hunk.target_length} @@"
    )
    if hunk.section_header:
        head = f"{head} {hunk.section_header}"
    return head


def _match_phrase(detail: Mapping[str, object] | None, mode: _Mode) -> str:
    """Where C12 found the hunk, in the wording of the side it matched."""
    line = _int_of(detail, "line")
    if line is None:
        return ""
    offset = _int_of(detail, "offset") or 0
    fuzz = _int_of(detail, "fuzz") or 0
    phrase = f"the patched text is at line {line}" if mode == "reverse" else f"found at line {line}"
    if offset:
        phrase = f"{phrase}, {offset:+d} lines from the cited position"
    if fuzz:
        plural = "" if fuzz == 1 else "s"
        phrase = f"{phrase}, {fuzz} context line{plural} skipped at each end"
    return phrase


def _join(names: Sequence[str]) -> str:
    shown = list(names[:MAX_NAMES])
    extra = len(names) - len(shown)
    text = ", ".join(shown)
    return f"{text} and {extra} more" if extra else text


#: The table's fixed geometry and its screen-reader header row. ``table-layout: fixed``
#: takes its widths from the first row, so they come from a ``colgroup`` rather than from
#: the visually hidden ``thead``, whose cells are out of flow.
_TABLE_HEAD = (
    '<colgroup><col class="pv-c-ln"><col class="pv-c-ln"><col class="pv-c-op">'
    '<col class="pv-c-code"><col class="pv-c-mark"></colgroup>'
    '<thead class="pv-sr"><tr><th scope="col">Line before</th>'
    '<th scope="col">Line after</th><th scope="col">Change</th>'
    '<th scope="col">Code</th><th scope="col">In the file at this version</th></tr></thead>'
)


def _meta_line(
    hunk: PatchHunk,
    detail: Mapping[str, object] | None,
    style: _Style,
    marks: Sequence[str],
    dropped: int,
) -> str:
    parts = [_match_phrase(detail, style.mode), _counts_phrase(marks, style.mode)]
    releases = _names_of(detail, "releases")
    if releases:
        parts.append(f"applies at {_join(releases)}")
    reason = _text_of(detail, "reason")
    if reason:
        parts.append(f"{hunk.path} is {reason}")
    if dropped:
        parts.append(f"{dropped} further lines of this hunk are not shown")
    return " &middot; ".join(esc(part) for part in parts if part)


def _hunk_block(
    number: int, hunk: PatchHunk, detail: Mapping[str, object] | None, ref: str
) -> tuple[str, list[str]]:
    """One hunk as a heading, a meta line and a table. Also returns the marks it used."""
    style = _style_for(_text_of(detail, "status"))
    marks = _marks_for(hunk, style.mode, _int_of(detail, "fuzz") or 0)
    rows, dropped = _rows(hunk, marks)
    path = _text_of(detail, "path") or hunk.path
    naming = ""
    if path != hunk.path:
        naming = f' <span class="muted">(the diff names {esc(hunk.path)})</span>'
    line = _meta_line(hunk, detail, style, marks, dropped)
    caption = f"Hunk {esc(number)} of {esc(path)} at {esc(ref)}: {esc(style.label)}"
    parts = [
        '<article class="pv-hunk">',
        f'<h4>{esc(path)} <span class="pill {attr(style.klass)}">{esc(style.label)}</span>',
        f"{naming}</h4>",
        f'<p class="meta muted">{esc(_hunk_header(hunk))}</p>',
        f'<p class="meta">{esc(style.blurb)}</p>',
        f'<p class="meta muted">{line}</p>' if line else "",
        '<table class="pv-table">',
        f'<caption class="pv-sr">{caption}</caption>',
        _TABLE_HEAD,
        f"<tbody>{rows}</tbody></table></article>",
    ]
    return "".join(parts), marks


# --- rendering one patch claim ----------------------------------------------------------------


def _legend(used: Sequence[str]) -> str:
    """Only the marks this page actually used, in a fixed order."""
    items = [
        f'<li><b aria-hidden="true">{glyph}</b> {esc(words)}</li>'
        for key, (glyph, words, _klass) in _MARKS.items()
        if key in used
    ]
    return f'<ul class="pv-legend">{"".join(items)}</ul>' if items else ""


def _callout(style: _Style, ref: str) -> str:
    """The plain-wording box for the statuses that are a question, not a failure."""
    if style.mode == "reverse":
        body = (
            f"<strong>This patch is already applied at {esc(ref)}.</strong> The reverse patch"
            " matches the file, so the change it proposes appears to be in place already."
            " That usually means the report describes a real problem that has since been"
            " fixed, and the useful question is which version was tested &mdash; not whether"
            " the patch applies."
        )
        return f'<p class="pv-note warn">{body}</p>'
    return ""


def _search_line(details: Mapping[str, object]) -> str:
    searched = _names_of(details, "searched_releases")
    if not searched:
        return ""
    complete = details.get("search_complete")
    tail = "" if complete is not False else " The search did not finish."
    return f'<p class="meta muted">Also searched: {esc(_join(searched))}.{esc(tail)}</p>'


def _claim_block(claim: PatchClaim, evidence: Evidence | None, ref: str) -> tuple[str, list[str]]:
    """One patch claim: its overall status, then its hunks."""
    details: Mapping[str, object] = evidence.details if evidence is not None else {}
    style = _style_for(_text_of(details, "status"))
    files = _names_of(details, "files") or list(claim.files)
    hunks = list(claim.hunks[:MAX_HUNKS])
    detail_list = _hunk_details(evidence)

    blocks: list[str] = []
    used: list[str] = []
    for number, hunk in enumerate(hunks, start=1):
        detail = detail_list[number - 1] if number - 1 < len(detail_list) else None
        block, marks = _hunk_block(number, hunk, detail, ref)
        blocks.append(block)
        used.extend(marks)

    total = _int_of(details, "hunks_total") or len(claim.hunks)
    head = f"{total} hunk" if total == 1 else f"{total} hunks"
    where = f"{head} touching {_join(files)}" if files else head
    summary = evidence.summary if evidence is not None else ""
    unapplied = '<p class="meta muted">This patch was not applied, so its lines are unmarked.</p>'
    left = len(claim.hunks) - len(hunks)
    parts = [
        f'<h3>{esc(where)} <span class="pill {attr(style.klass)}">{esc(style.label)}</span></h3>',
        f'<p class="meta">{esc(summary)}</p>' if summary else "",
        "" if evidence is not None else unapplied,
        _callout(style, ref),
        _search_line(details),
        *blocks,
        f'<p class="meta muted">{esc(left)} further hunks are not shown.</p>' if left else "",
    ]
    return "".join(parts), used


def _ref_label(ctx: HtmlContext) -> str:
    target = ctx.result.target
    if target is not None:
        if target.ref_name:
            return target.ref_name
        if target.commit:
            return target.commit[:12]
    return "the named version"


def render(ctx: HtmlContext) -> Fragment | None:
    patches = [claim for claim in ctx.claims if isinstance(claim, PatchClaim)]
    if not patches:
        return None
    ref = _ref_label(ctx)
    usable = [claim for claim in patches if claim.hunks]
    if not usable:
        # A diff that no parser could split into hunks is a hygiene finding (C21), not a
        # refutation, and saying so beats an empty page where a patch obviously exists.
        body = (
            '<p class="meta">The report contains a diff that could not be read as hunks, so'
            " it was not applied to the tree.</p>"
        )
        return Fragment(html=_shell(body), css=CSS)

    shown = usable[:MAX_CLAIMS]
    blocks: list[str] = []
    used: list[str] = []
    for claim in shown:
        block, marks = _claim_block(claim, _evidence_for(ctx, claim), ref)
        blocks.append(block)
        used.extend(marks)
    left = len(usable) - len(shown)
    if left:
        blocks.append(f'<p class="meta muted">{esc(left)} further patches are not shown.</p>')
    intro = (
        '<p class="meta muted">Each hunk is shown as the report wrote it, with every line'
        f" marked against the file at {esc(ref)}.</p>"
    )
    return Fragment(html=_shell(intro + _legend(used) + "".join(blocks)), css=CSS)


def _evidence_for(ctx: HtmlContext, claim: PatchClaim) -> Evidence | None:
    """C12's evidence about this claim, or ``None`` when the check did not run."""
    items = [item for item in ctx.by_claim.get(claim.id, []) if item.check_id == CHECK_ID]
    return items[0] if items else None


def _shell(body: str) -> str:
    return (
        '<section class="pv panel" id="patch-view" aria-labelledby="patch-view-heading">'
        '<h2 id="patch-view-heading">Proposed patch</h2>'
        f"{body}</section>"
    )
