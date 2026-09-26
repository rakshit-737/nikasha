# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The trace alignment table: each claimed frame beside its real location (SPEC §15.2).

A pasted stack trace is a stack of assertions about the code — *this function, in this
file, at this line, called by the one below it* — and this view lays them out so a
maintainer can see in one pass which of them the repository agrees with. It reads two
checks and invents nothing of its own:

* **C08 TRACE_FRAMES** fills the rows: one per application frame, with the claimed path
  and line, the path that resolved in the tree, and what did and did not match.
* **C09 TRACE_CALL_EDGES** fills the arrows between the rows: caller → callee, and whether
  a call like that exists at the checked commit at all.

Three things this view does deliberately:

1. **Every mark column has three states, not two.** A frame C08 kept out of its ratio — a
   libc or third-party frame, a generated file, a file whose parse was cut short — is
   drawn "not checked", never crossed. Rendering an unparsed file as a failed frame is exactly
   the false contradiction ADR 0003 exists to prevent, and the most visible place in the
   report to make it (P4). The same holds for a call edge that left the repository.
2. **Every glyph carries text.** The marks are the whole content of their cells, and a bare
   glyph is silence to a screen reader, so each one is paired with visually hidden words.
3. **Every frame string is bounded and escaped.** Function names and paths come straight
   out of a trace the reporter wrote; a 4000-character function name may not decide the
   width of the page, and nothing reaches the markup except through
   :mod:`nikasha.render.html.escaping` (P7).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from nikasha.model.evidence import Evidence
from nikasha.render.html.context import Fragment, HtmlContext
from nikasha.render.html.escaping import attr, css_ident
from nikasha.render.html.escaping import text as esc

ORDER = 50

#: The two checks this view reads. Named rather than imported: pulling in a check module
#: would drag the whole registry (and tree-sitter) into the renderer.
FRAMES_CHECK = "C08"
EDGES_CHECK = "C09"

#: state -> (glyph, palette class, the words a screen reader hears).
MARKS: dict[str, tuple[str, str, str]] = {
    "yes": ("✓", "ok", "matches"),
    "no": ("✗", "bad", "does not match"),
    "unknown": ("?", "unknown", "not checked"),
}

#: The three questions C08 asks of a frame, in column order, with their headers.
FIELDS: tuple[tuple[str, str], ...] = (
    ("file", "File"),
    ("function", "Function"),
    ("line", "Line"),
)

#: Frame number, function, claimed location, actual location, then one column per field.
COLUMNS = 4 + len(FIELDS)

#: C09's edge kinds -> (what the edge means in one phrase, palette class). ``direct``,
#: ``macro`` and ``inlined_2hop`` are C09's REAL_KINDS; ``indirect_possible`` is its
#: neutral outcome and ``none`` its only refutation.
EDGE_KINDS: dict[str, tuple[str, str]] = {
    "direct": ("a direct call", "ok"),
    "macro": ("a call through a macro", "ok"),
    "inlined_2hop": ("a call through an inlined function", "ok"),
    "indirect_possible": ("possible only indirectly", "warn"),
    "none": ("no such call at this version", "bad"),
}

#: An edge C09 recorded under ``skipped`` or ``unknown``: it left the repository, or an
#: endpoint was generated, unparsed or undefined. Never a failure (P4).
UNCHECKED_EDGE = ("not checked", "unknown")

NOT_CHECKED = "not checked"

#: Why the third state is not a failure, said once, on the page itself.
UNCHECKED_BLURB = (
    "not checked: a frame outside the repository, a generated file or a file that did not"
    " parse cleanly is never counted against a report"
)

ARROW_UP = "↑"
ARROW_RIGHT = "→"
DOT = "·"

#: Rendered width and count caps. Everything here is reporter-controlled, so a trace with
#: eight hundred frames and a 4000-character function name still produces a readable page
#: well inside SPEC §15.2's 1.5 MB budget.
MAX_FUNCTION = 100
MAX_PATH = 160
MAX_NOTE = 240
MAX_FRAMES = 150
MAX_TABLES = 20
MAX_CALLS = 12
MAX_NOTES = 6
MAX_SITES = 3
MAX_FORMAT = 24

CSS = """
.tt-wrap { margin: 24px 0; }
.tt-wrap h2 { margin: 0 0 4px; font-size: 18px; letter-spacing: -0.01em; }
.tt-legend { margin: 0 0 12px; font-size: 12px; color: var(--muted); }
.tt-scroll { overflow-x: auto; margin: 0 0 18px; }
.tt-scroll:last-child { margin-bottom: 0; }
.tt-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.tt-table caption { text-align: left; padding: 0 0 6px; font-weight: 600; }
.tt-table .tt-sub { display: block; font-weight: 400; font-size: 12px; }
.tt-table th, .tt-table td {
  padding: 6px 8px; text-align: left; vertical-align: top;
  border-bottom: 1px solid var(--border);
}
.tt-table thead th {
  font-size: 12px; font-weight: 600; color: var(--muted); white-space: nowrap;
}
.tt-num { width: 1%; text-align: right; color: var(--muted); font-family: var(--mono); }
.tt-fn, .tt-loc { font-family: var(--mono); font-size: 12px; overflow-wrap: anywhere; }
.tt-loc { max-width: 34ch; }
.tt-fn { max-width: 28ch; display: inline-block; vertical-align: top; }
.tt-mark { width: 1%; text-align: center; white-space: nowrap; font-size: 15px; }
.tt-table thead th.tt-mark { text-align: center; }
.tt-notes { margin: 4px 0 0; padding-left: 16px; color: var(--muted); font-size: 12px; }
.tt-notes li { overflow-wrap: anywhere; }
.tt-edge td {
  border-bottom: none; padding: 3px 8px 3px 26px; font-size: 12px; color: var(--muted);
}
.tt-edge .tt-fn { max-width: 24ch; }
.tt-arrow { display: inline-block; width: 16px; margin-left: -18px; }
.tt-more td { color: var(--muted); font-size: 12px; border-bottom: none; }
.tt-sr {
  position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px;
  overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; border: 0;
}
@media (max-width: 700px) {
  .tt-loc, .tt-fn { max-width: none; }
  .tt-table th, .tt-table td { padding: 5px 6px; }
}
"""


# --- small, defensive readers ------------------------------------------------------------
#
# ``Evidence.details`` is free-form JSON and a Result can be loaded from a file, so nothing
# below assumes a shape: a detail that is not what it should be renders as absent.


def _short(value: object, limit: int) -> str:
    """``value`` as a string, cut to ``limit`` rendered characters with an ellipsis."""
    raw = str(value)
    return raw if len(raw) <= limit else raw[: limit - 1] + "…"


def _strings(value: object, limit: int) -> list[str]:
    """The string items of a details list, bounded."""
    if isinstance(value, str) or not isinstance(value, Sequence):
        return []
    return [item for item in value if isinstance(item, str)][:limit]


def _records(value: object) -> list[Mapping[str, Any]]:
    """The mapping items of a details list."""
    if isinstance(value, str) or not isinstance(value, Sequence):
        return []
    return [item for item in value if isinstance(item, Mapping)]


# --- deriving the three marks from C08 ----------------------------------------------------


def _matched_kind(note: str, detail: Mapping[str, Any]) -> str | None:
    """Which of C08's three questions a ``matched`` sentence answered, if any."""
    line = detail.get("line")
    function = detail.get("function")
    if note == f"{detail.get('resolved_path')} exists at this commit":
        return "file"
    if line is not None and note.startswith(f"line {line} is inside the file ("):
        return "line"
    if function and line is not None and note == f"line {line} is inside {function}":
        return "function"
    return None


def _mismatched_kind(note: str, detail: Mapping[str, Any]) -> str | None:
    """Which question a ``mismatched`` sentence answered, if any.

    The three function-mismatch wordings are C08's ``_function_mismatch`` branches: the
    function is defined elsewhere, the line belongs to another function, or the function is
    not in that file at all.
    """
    line = detail.get("line")
    resolved = detail.get("resolved_path")
    function = detail.get("function")
    if note == f"no file matching {detail.get('claimed_path')} exists at this commit":
        return "file"
    if resolved and note.startswith(f"{resolved} has ") and note.endswith(" lines"):
        return "line"
    if function:
        if note.startswith(f"{function} is defined at ") and "; line " in note:
            return "function"
        if note.startswith(f"line {line} is inside ") and note.endswith(f", not {function}"):
            return "function"
        if note == f"{function} is not defined in {resolved}":
            return "function"
    return None


def _state(yes: bool, no: bool) -> str:
    """One mark's state. A question answered both ways, or not at all, is not checked."""
    if yes and not no:
        return "yes"
    if no and not yes:
        return "no"
    return "unknown"


def _marks(detail: Mapping[str, Any]) -> dict[str, str]:
    """A tick, a cross or a question mark per question for one frame.

    C08 records its answers as booleans under ``checks``; those are read directly. Results
    written before that field existed carry only prose, so their sentences are classified
    back against the exact templates C08 writes (the tests pin every one of them).
    Wording that is not recognised is *not checked* rather than a guess — the safe direction,
    because the alternative is drawing a ✗ nobody computed.

    A frame C08 left out of its ratio, ``skipped`` or ``uncertain``, is not checked in all
    three columns. That exclusion is the whole point of C08's third-party and unparsed-file
    rules (ADR 0003), and it must survive into the picture a maintainer actually looks at.
    """
    if detail.get("status") not in ("consistent", "inconsistent"):
        return {field: "unknown" for field, _ in FIELDS}
    checks = detail.get("checks")
    if isinstance(checks, Mapping):
        # C08's structured answers. Anything but a real boolean is not checked (P4).
        return {
            field: _state(checks.get(field) is True, checks.get(field) is False)
            for field, _ in FIELDS
        }
    yes = {_matched_kind(note, detail) for note in _strings(detail.get("matched"), MAX_NOTES)}
    no = {_mismatched_kind(note, detail) for note in _strings(detail.get("mismatched"), MAX_NOTES)}
    return {field: _state(field in yes, field in no) for field, _ in FIELDS}


# --- cells and rows -----------------------------------------------------------------------


def _mark_cell(label: str, state: str) -> str:
    """One mark, with the glyph hidden from assistive technology and words behind it."""
    glyph, klass, words = MARKS[state]
    return (
        f'<td class="tt-mark {attr(klass)}">'
        f'<span aria-hidden="true">{esc(glyph)}</span>'
        f'<span class="tt-sr">{esc(label)}: {esc(words)}</span>'
        "</td>"
    )


def _claimed(detail: Mapping[str, Any]) -> str:
    """What the trace said: the path as written, with the line it named."""
    path = detail.get("claimed_path")
    line = detail.get("line")
    if not isinstance(path, str) or not path:
        return '<span class="muted">no file name in the frame</span>'
    shown = esc(_short(path, MAX_PATH))
    if isinstance(line, int):
        shown += f":{esc(line)}"
    return shown


def _actual(detail: Mapping[str, Any]) -> str:
    """What the repository says: the resolved path, plus every note C08 recorded."""
    resolved = detail.get("resolved_path")
    parts: list[str] = []
    if isinstance(resolved, str) and resolved:
        parts.append(f'<span class="tt-loc">{esc(_short(resolved, MAX_PATH))}</span>')
    else:
        parts.append('<span class="muted">no such file at this version</span>')
    if detail.get("status") not in ("consistent", "inconsistent"):
        parts.append(f' <span class="pill unknown">{esc(NOT_CHECKED)}</span>')
    notes: list[str] = []
    reason = detail.get("reason")
    if isinstance(reason, str) and reason:
        notes.append(reason)
    notes.extend(_strings(detail.get("mismatched"), MAX_NOTES))
    if notes:
        items = "".join(f"<li>{esc(_short(note, MAX_NOTE))}</li>" for note in notes)
        parts.append(f'<ul class="tt-notes">{items}</ul>')
    return "".join(parts)


def _frame_row(detail: Mapping[str, Any]) -> str:
    """One application frame: claimed against actual, with the three marks."""
    marks = _marks(detail)
    index = detail.get("index")
    function = detail.get("function")
    named = (
        f'<span class="tt-fn">{esc(_short(function, MAX_FUNCTION))}</span>'
        if isinstance(function, str) and function
        else '<span class="muted">unnamed</span>'
    )
    cells = "".join(_mark_cell(label, marks[field]) for field, label in FIELDS)
    return (
        '<tr class="tt-frame">'
        f'<td class="tt-num">{esc(index) if isinstance(index, int) else ""}</td>'
        f"<td>{named}</td>"
        f'<td class="tt-loc">{_claimed(detail)}</td>'
        f"<td>{_actual(detail)}</td>"
        f"{cells}</tr>"
    )


def _edge_extra(record: Mapping[str, Any], kind: str) -> str:
    """The useful half of an edge: what the caller really calls, or why it is not judged."""
    if kind == "none":
        calls = _strings(record.get("caller_calls"), MAX_CALLS)
        if calls:
            caller = _short(record.get("caller") or "the caller", MAX_FUNCTION)
            joined = ", ".join(_short(call, MAX_FUNCTION) for call in calls)
            return f"{caller} calls: {joined}"
        return ""
    sites = _strings(record.get("sites"), MAX_SITES)
    return ", ".join(sites) if sites else ", ".join(_strings(record.get("reasons"), MAX_NOTES))


def _edge_row(record: Mapping[str, Any] | None) -> str:
    """The arrow between two frames, and what the call graph says about it.

    With no C09 record — fewer than two application frames, or C09 never ran — the arrow is
    drawn but makes no claim: the trace still asserts the call, nothing checked it.
    """
    arrow = f'<span class="tt-arrow" aria-hidden="true">{esc(ARROW_UP)}</span>'
    if record is None:
        inner = f'{arrow}<span class="tt-sr">called by the frame below</span>'
        return f'<tr class="tt-edge"><td colspan="{COLUMNS}">{inner}</td></tr>'
    kind = record.get("kind")
    kind = kind if isinstance(kind, str) else ""
    label, klass = EDGE_KINDS.get(kind, UNCHECKED_EDGE)
    extra = _edge_extra(record, kind)
    tail = f' <span class="muted">{esc(_short(extra, MAX_NOTE))}</span>' if extra else ""
    return (
        f'<tr class="tt-edge"><td colspan="{COLUMNS}">{arrow}'
        f'<span class="tt-fn">{esc(_short(record.get("caller") or "", MAX_FUNCTION))}</span>'
        '<span class="tt-sr"> calls </span>'
        f'<span aria-hidden="true"> {esc(ARROW_RIGHT)} </span>'
        f'<span class="tt-fn">{esc(_short(record.get("callee") or "", MAX_FUNCTION))}</span>'
        f' <span class="pill {attr(klass)}">{esc(label)}</span>{tail}'
        "</td></tr>"
    )


# --- one table per trace ------------------------------------------------------------------


def _edge_index(items: Sequence[Evidence]) -> dict[tuple[int, int], Mapping[str, Any]]:
    """Every C09 record for one trace, keyed by ``(caller frame, callee frame)``.

    Checked edges are indexed first so a pair that C09 both classified and (impossibly)
    also skipped shows the classification.
    """
    index: dict[tuple[int, int], Mapping[str, Any]] = {}
    for key in ("edges", "skipped", "unknown"):
        for item in items:
            for record in _records(item.details.get(key)):
                caller = record.get("caller_frame")
                callee = record.get("callee_frame")
                if isinstance(caller, int) and isinstance(callee, int):
                    index.setdefault((caller, callee), record)
    return index


def _edge_between(
    edges: Mapping[tuple[int, int], Mapping[str, Any]],
    caller: Mapping[str, Any],
    callee: Mapping[str, Any],
) -> Mapping[str, Any] | None:
    """Stacks are innermost-first, so the caller is the *later* row."""
    above, below = callee.get("index"), caller.get("index")
    if isinstance(above, int) and isinstance(below, int):
        return edges.get((below, above))
    return None


def _head() -> str:
    marks = "".join(
        f'<th scope="col" class="tt-mark">{esc(label)}</th>' for _field, label in FIELDS
    )
    return (
        "<thead><tr>"
        f'<th scope="col" class="tt-num">#</th>'
        f'<th scope="col">Frame</th>'
        f'<th scope="col">Claimed location</th>'
        f'<th scope="col">Actual location</th>'
        f"{marks}</tr></thead>"
    )


def _caption(item: Evidence) -> str:
    fmt = item.details.get("trace_format")
    title = "Stack trace alignment"
    if isinstance(fmt, str) and fmt:
        title += f" ({_short(fmt, MAX_FORMAT)})"
    return (
        f"<caption>{esc(title)}"
        f'<span class="tt-sub muted">{esc(_short(item.summary, MAX_NOTE))}</span>'
        "</caption>"
    )


def _table(item: Evidence, edges: Mapping[tuple[int, int], Mapping[str, Any]]) -> str:
    frames = _records(item.details.get("frames"))
    shown = frames[:MAX_FRAMES]
    rows: list[str] = []
    for position, detail in enumerate(shown):
        if position:
            rows.append(_edge_row(_edge_between(edges, detail, shown[position - 1])))
        rows.append(_frame_row(detail))
    if len(frames) > len(shown):
        extra = f"{len(frames) - len(shown)} further frames are not shown here."
        rows.append(f'<tr class="tt-more"><td colspan="{COLUMNS}">{esc(extra)}</td></tr>')
    table_id = attr("tt-" + css_ident(item.id))
    return (
        f'<div class="tt-scroll"><table class="tt-table" id="{table_id}">'
        f"{_caption(item)}{_head()}<tbody>{''.join(rows)}</tbody></table></div>"
    )


def _legend() -> str:
    rows = (
        ("yes", "the code at this version agrees"),
        ("no", "it does not"),
        ("unknown", UNCHECKED_BLURB),
    )
    parts = [
        f'<span class="{attr(MARKS[state][1])}" aria-hidden="true">{esc(MARKS[state][0])}</span>'
        f" {esc(meaning)}"
        for state, meaning in rows
    ]
    return f" {esc(DOT)} ".join(parts)


def _tables(ctx: HtmlContext) -> list[str]:
    """One table per trace, in the order the traces appear in the report."""
    position_of = {claim.id: position for position, claim in enumerate(ctx.claims)}
    last = len(position_of)
    edges_by_claim: dict[str, dict[str, Evidence]] = {}
    for item in ctx.evidence:
        if item.check_id != EDGES_CHECK:
            continue
        for claim_id in item.claim_ids:
            edges_by_claim.setdefault(claim_id, {})[item.id] = item

    items = [
        item
        for item in ctx.evidence
        if item.check_id == FRAMES_CHECK and _records(item.details.get("frames"))
    ]
    items.sort(
        key=lambda item: (
            min((position_of.get(cid, last) for cid in item.claim_ids), default=last),
            item.id,
        )
    )
    out: list[str] = []
    for item in items[:MAX_TABLES]:
        found: dict[str, Evidence] = {}
        for claim_id in item.claim_ids:
            found.update(edges_by_claim.get(claim_id, {}))
        related = [found[key] for key in sorted(found)]
        out.append(_table(item, _edge_index(related)))
    return out


def render(ctx: HtmlContext) -> Fragment | None:
    tables = _tables(ctx)
    if not tables:
        return None
    html = (
        '<section class="panel tt-wrap" aria-labelledby="tt-heading">'
        '<h2 id="tt-heading">Trace alignment</h2>'
        f'<p class="tt-legend">{_legend()}</p>'
        f"{''.join(tables)}"
        "</section>"
    )
    return Fragment(html=html, css=CSS)
