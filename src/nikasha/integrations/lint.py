# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""``nikasha lint``: the reporter's pre-submit check (SPEC §16.1, P8).

Someone about to file a report has the same question a maintainer has after receiving it:
does every detail in this text match the code at the version it names? ``lint`` runs the
identical engine as ``nikasha check`` (:func:`nikasha.pipeline.check_report`, then the
questions from :mod:`nikasha.fuse.questions`) and differs only in who it talks to:

* **Second person, friendly.** "We couldn't find ``foo()`` at v1.2.0 - did you mean
  ``bar()``?" The reader is the person editing the draft, so every line says what to fix
  or what to add.
* **No verdict label.** GROUNDED, UNGROUNDED and the rest are the maintainer's words, said
  about a submitted report. A draft gets findings and questions, never a label. (The
  ``--json`` output is the full :class:`~nikasha.model.result.Result`, verdict included,
  because it is the same document a maintainer's run would produce.)
* **Exit code.** :data:`EXIT_OK` unless at least one finding contradicts the code (an
  evidence item with outcome ``REFUTES`` and a negative strength), then
  :data:`EXIT_REFUTED`; ``1`` on an error. A refutation withheld by the ADR 0003 gate is
  ``NEUTRAL`` and never fails the lint, and neither does anything that merely could not be
  checked (P4).

The wording rules of :mod:`nikasha.fuse.questions` apply here too (P1): every sentence
describes a claim, a file, a line or a release. Nothing describes the person who wrote
the draft, and nothing guesses how it was written. Everything printed is report-derived
and goes through :class:`rich.text.Text` and the terminal view's clipping, never through
Rich markup (P7).

The heavy imports (pipeline, checks, tree-sitter) are deferred to the functions that need
them, so registering the command keeps ``nikasha version`` fast.
"""

from __future__ import annotations

import shlex
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any

import typer
from rich import box
from rich.console import Console, Group, RenderableType
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from nikasha.errors import NikashaError

if TYPE_CHECKING:
    from nikasha.ingest import InputFormat
    from nikasha.model.claims import Claim
    from nikasha.model.evidence import Evidence
    from nikasha.model.result import Result
    from nikasha.model.verdict import Question

#: Exit codes. ``1`` stays reserved for errors, as in every other command. A refuted draft
#: exits with the same number ``nikasha check`` uses for its refuted tier, so a CI script
#: that already reacts to 20 reacts the same way here.
EXIT_OK = 0
EXIT_REFUTED = 20

#: Clipping limits. Findings and questions are the product here, so they get room to be a
#: whole paragraph (the panels fold them); only a runaway string is cut.
_MAX_LABEL = 42
_MAX_FOUND = 400
_MAX_QUESTION = 600
_MAX_SOURCE = 90
_MAX_RERUN = 400

_OUTCOME_KEY = {"SUPPORTS": "ok", "REFUTES": "fail", "NEUTRAL": "warn", "ERROR": "unknown"}
_OUTCOME_STYLE = {
    "SUPPORTS": "green",
    "REFUTES": "red",
    "NEUTRAL": "yellow",
    "ERROR": "bright_black",
}
#: Problems first: a reporter fixing a draft reads the top of the table, not the bottom.
_OUTCOME_RANK = {"REFUTES": 0, "NEUTRAL": 1, "ERROR": 2, "SUPPORTS": 3}
_ROLE_RANK = {"core": 0, "supporting": 1, "peripheral": 2}

#: The typographic characters this module emits, spelled out so no literal can be confused
#: with its ASCII look-alike (the same choice :mod:`nikasha.fuse.questions` makes).
_EN_DASH = chr(0x2013)
_EM_DASH = chr(0x2014)
_MIDDLE_DOT = chr(0xB7)

#: Typographic punctuation this module (and the question templates) may emit, mapped to
#: what an ``--ascii`` stream can carry. Report content is left alone: it is the draft's.
_ASCII_PUNCTUATION = str.maketrans(
    {
        _EN_DASH: "-",
        _EM_DASH: "-",
        _MIDDLE_DOT: "-",
        chr(0x2026): "...",  # horizontal ellipsis
        chr(0x2018): "'",  # left single quotation mark
        chr(0x2019): "'",  # right single quotation mark
        chr(0x201C): '"',  # left double quotation mark
        chr(0x201D): '"',  # right double quotation mark
        chr(0x2192): "->",  # rightwards arrow
    }
)

#: ``function_span`` is a ``[start, end]`` pair.
_PAIR = 2

#: Why a refutation was withheld (``details['gated']``, ADR 0003), said to the reporter.
_GATE_REASONS = {
    "third_party": "the draft places it outside this repository",
    "reporter_artifact": "the draft presents it as part of your own harness or setup",
    "negated": "the draft says it is absent",
    "unscoped": "the draft does not tie it to this repository",
}

#: What C21 says is missing, as the reporter would name it.
_HYGIENE_ITEMS = {
    "poc": "a proof of concept with the exact command",
    "version": "the exact version or commit you tested",
    "trace": "the unmodified crash or sanitizer output",
    "location": "a file, line or function to look at",
}


# --- the library entry point ------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class LintReport:
    """Everything one ``nikasha lint`` run produced."""

    result: Result
    questions: tuple[Question, ...]
    refuted: tuple[Evidence, ...]

    @property
    def clean(self) -> bool:
        """True when no finding contradicts the code."""
        return not self.refuted

    @property
    def exit_code(self) -> int:
        return EXIT_OK if self.clean else EXIT_REFUTED

    @property
    def where(self) -> str:
        return where_of(self.result)


def is_refuting(item: Evidence) -> bool:
    """A finding that counts against the draft, in the same terms as the verdict ladder."""
    return item.outcome == "REFUTES" and item.strength < 0.0


def refutations(evidence: Sequence[Evidence]) -> tuple[Evidence, ...]:
    """Every refuting item, strongest first; ties break on the content-derived ID (P2)."""
    return tuple(sorted((e for e in evidence if is_refuting(e)), key=lambda e: (e.strength, e.id)))


def exit_code_for(evidence: Sequence[Evidence]) -> int:
    """``EXIT_REFUTED`` when anything is refuted, else ``EXIT_OK``."""
    return EXIT_REFUTED if any(is_refuting(e) for e in evidence) else EXIT_OK


def where_of(result: Result) -> str:
    """The version under test, as a sentence names it: "v1.2.0", "commit 3f2a9c1b2d4e"."""
    target = result.target
    if target is None:
        return "the version the draft names"
    if target.ref_name:
        return target.ref_name
    if target.commit:
        return f"commit {target.commit[:12]}"
    return "the version the draft names"


def lint_report(
    report_path: str | Path,
    *,
    repo: str | None = None,
    ref: str | None = None,
    version: str | None = None,
    product: str | None = None,
    input_format: InputFormat = "auto",
    online: bool = False,
    index_path: Path | None = None,
) -> LintReport:
    """Run the ``check`` pipeline over a draft and keep what a reporter needs from it.

    The questions are rendered by :func:`nikasha.fuse.questions.questions_for` from the
    same decision the maintainer's run would take, so the two commands can never disagree
    about what to ask.
    """
    from nikasha.fuse.questions import questions_for  # noqa: PLC0415 (keeps import light)
    from nikasha.pipeline import check_report  # noqa: PLC0415

    checked = check_report(
        report_path,
        repo=repo,
        ref=ref,
        version=version,
        product=product,
        input_format=input_format,
        online=online,
        index_path=index_path,
    )
    questions = questions_for(checked.decision, checked.evidence, checked.claims)
    return LintReport(
        result=checked.result,
        questions=questions,
        refuted=refutations(checked.evidence),
    )


# --- friendly wording ---------------------------------------------------------------------------

Details = dict[str, Any]
Friendly = Callable[[Details, str], str | None]


def _str(details: Details, key: str) -> str | None:
    """A scalar detail as display text, or ``None`` when absent or not a scalar."""
    value = details.get(key)
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (str, int, float)):
        text = str(value).strip()
        return text or None
    return None


def _int(details: Details, key: str) -> int | None:
    value = details.get(key)
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _names(value: object) -> list[str]:
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value if isinstance(item, (str, int, float)) and item != ""]
    return [value] if isinstance(value, str) and value else []


def _listed(value: object) -> str:
    from nikasha.fuse.questions import listed  # noqa: PLC0415

    return listed(_names(value))


def _ranged(value: object) -> str:
    from nikasha.fuse.questions import ranged  # noqa: PLC0415

    return ranged(_names(value))


def _did_you_mean(lead: str, details: Details, hint: str) -> str:
    """Finish a "couldn't find" sentence with the nearest names, or with what to do."""
    names = _listed([f"{name}()" for name in _names(details.get("suggestions"))])
    if names:
        return f"{lead} {_EM_DASH} did you mean {names}?"
    return f"{lead}. {hint}"


def _symbol_never(d: Details, where: str) -> str | None:
    symbol = _str(d, "symbol")
    if symbol is None:
        return None
    span = _ranged(d.get("releases_searched"))
    searched = f" ({span})" if span else ""
    lead = (
        f"We couldn't find {symbol}() at {where}, in any release we searched{searched},"
        " or anywhere in the git history"
    )
    return _did_you_mean(lead, d, "Check the spelling, or link to where it is defined.")


def _symbol_sampled(d: Details, where: str) -> str | None:
    symbol = _str(d, "symbol")
    if symbol is None:
        return None
    sampled = _names(d.get("releases_searched"))
    which = f"the {len(sampled)} releases we sampled" if sampled else "the releases we sampled"
    lead = f"We couldn't find {symbol}() at {where} or in {which}"
    return _did_you_mean(lead, d, "Check the spelling, or link to where it is defined.")


def _symbol_elsewhere(d: Details, where: str) -> str | None:
    # Listed, not ranged: the releases that define the symbol can sit on both sides of the
    # target, and "v1.0.0-v1.3.0" would then include the very version where it is absent.
    symbol, defined_in = _str(d, "symbol"), _listed(d.get("defined_in"))
    if symbol is None or not defined_in:
        return None
    return (
        f"We couldn't find {symbol}() at {where}; it is defined in {defined_in}."
        " Were you testing one of those versions?"
    )


def _file_never(d: Details, where: str) -> str | None:
    path = _str(d, "path")
    if path is None:
        return None
    return (
        f"We couldn't find {path} at {where} or anywhere in the git history."
        " Check the path against the tree you tested."
    )


def _file_elsewhere(d: Details, where: str) -> str | None:
    path, present_in = _str(d, "path"), _listed(d.get("present_in"))
    if path is None or not present_in:
        return None
    return (
        f"{path} isn't in the tree at {where}; it is in {present_in}."
        " Were you testing one of those versions?"
    )


def _line_past_end(d: Details, where: str) -> str | None:
    path, line, n_lines = _str(d, "path"), _int(d, "line"), _int(d, "n_lines")
    if path is None or line is None or n_lines is None:
        return None
    return (
        f"{path} has {n_lines} lines at {where}, so line {line} doesn't exist there."
        " Re-check the line number against the version you tested."
    )


def _line_outside_function(d: Details, where: str) -> str | None:
    path, line, function = _str(d, "path"), _int(d, "line"), _str(d, "function")
    if path is None or line is None or function is None:
        return None
    text = f"{path}:{line} isn't inside {function}() at {where}"
    actual = _str(d, "actual_function")
    if actual is not None:
        text += f"; it is inside {actual}()"
    span = d.get("function_span")
    if isinstance(span, (list, tuple)) and len(span) == _PAIR and all(_is_int(v) for v in span):
        text += f" ({function}() spans lines {span[0]}-{span[1]})"
    return f"{text}. Re-check the line against the version you tested."


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _line_fits_nearby(d: Details, where: str) -> str | None:
    path, line, function = _str(d, "path"), _int(d, "line"), _str(d, "function")
    hint = d.get("version_fit_hint")
    release = _str(hint, "release") if isinstance(hint, dict) else None
    if path is None or line is None or function is None or release is None:
        return None
    return (
        f"{path}:{line} is inside {function}() in {release}, but not at {where}."
        f" Were you testing {release}?"
    )


def _function_not_defined(d: Details, where: str) -> str | None:
    path, function = _str(d, "path"), _str(d, "function")
    if path is None or function is None:
        return None
    return f"{function}() isn't defined in {path} at {where}. Check the function name and the file."


def _quote_nowhere(d: Details, where: str) -> str | None:
    path = _str(d, "path")
    place = f"in {path} at {where}" if path else f"at {where}"
    return (
        f"The quoted line isn't {place}, in any other release, or anywhere in the git"
        " history. Paste it straight from the tree you tested."
    )


def _quote_elsewhere(d: Details, where: str) -> str | None:
    found = _listed(d.get("found_in_releases"))
    if not found:
        return None
    return (
        f"The quoted line isn't at {where}, but it is in {found}."
        " Were you testing one of those versions?"
    )


def _snippet_absent(_: Details, where: str) -> str | None:
    return (
        f"We couldn't match the quoted code against any file at {where}, in the releases we"
        " sampled, or in the git history. Paste it straight from the tree you tested, and"
        " name the commit."
    )


def _frames(d: Details, where: str) -> str | None:
    fitting, checked = _int(d, "consistent_frames"), _int(d, "checked_frames")
    if fitting is None or checked is None:
        return None
    return (
        f"{fitting} of {checked} application frames in the stack trace fit the code at"
        f" {where}. Paste the unmodified sanitizer output from the build you ran."
    )


def _missing_edges(d: Details, where: str) -> str | None:
    edges = d.get("edges")
    if not isinstance(edges, (list, tuple)):
        return None
    pairs = [
        f"{edge['caller']} -> {edge['callee']}"
        for edge in edges
        if isinstance(edge, dict)
        and edge.get("kind") == "none"
        and isinstance(edge.get("caller"), str)
        and isinstance(edge.get("callee"), str)
    ]
    if not pairs:
        return None
    return (
        f"We couldn't find these calls at {where}: {', '.join(pairs)}."
        " If they go through a function pointer or a macro, say so in the draft."
    )


def _no_release_fits(d: Details, where: str) -> str | None:
    best = _str(d, "best_release")
    if best is None:
        return None
    fitting, checked = _int(d, "best_frames_fitting"), _int(d, "best_frames_checked")
    closest = f"the closest is {best}"
    if fitting is not None and checked is not None:
        closest += f" ({fitting} of {checked} frames)"
    return (
        f"The stack trace doesn't fit {where} or any other release we scored; {closest}."
        " Paste the unmodified trace from the build you ran, and name its commit."
    )


def _other_release_fits(d: Details, where: str) -> str | None:
    best = _str(d, "best_release")
    if best is None:
        return None
    return (
        f"The stack trace fits {best} exactly, but the draft names {where}."
        f" Were you testing {best}?"
    )


def _sanitizer(d: Details, _: str) -> str | None:
    violations = d.get("violations")
    names: list[str] = []
    if isinstance(violations, (list, tuple)):
        names = [
            v["name"] for v in violations if isinstance(v, dict) and isinstance(v.get("name"), str)
        ]
    detail = f" ({_listed(names)})" if names else ""
    return (
        f"The sanitizer output contradicts itself{detail}."
        " Paste it unmodified rather than retyping it."
    )


def _patch_context(_: Details, where: str) -> str | None:
    return (
        f"We couldn't find the patch's context lines at {where}."
        " Send it as `git diff` output against a commit you can name."
    )


def _patch_applied(_: Details, where: str) -> str | None:
    return (
        f"The change the patch proposes already seems to be in {where}."
        " Check whether the issue still reproduces there, and name the commit you tested."
    )


def _option_never(d: Details, where: str) -> str | None:
    token = _str(d, "token")
    if token is None:
        return None
    return (
        f"{token} doesn't appear at {where} or anywhere in the git history. Check the option name."
    )


def _cvss(d: Details, _: str) -> str | None:
    computed, claimed = _str(d, "computed_score"), _str(d, "claimed_score")
    if computed is None or claimed is None:
        return None
    severity = _str(d, "computed_severity")
    band = f" ({severity})" if severity else ""
    return (
        f"The CVSS vector works out to {computed}{band}, not {claimed}."
        " Fix the score or the vector so they agree."
    )


def _hygiene(d: Details, _: str) -> str | None:
    missing = [_HYGIENE_ITEMS[key] for key in _names(d.get("missing")) if key in _HYGIENE_ITEMS]
    if not missing:
        return (
            "The draft names a version, gives a proof of concept and a crash trace, and points"
            " at the code: everything a maintainer needs to start."
        )
    return (
        f"The draft doesn't include {_listed(missing)}. Adding it makes verification much faster."
    )


#: Findings a reporter can act on, said in the second person. Keyed by check ID and the
#: strengths-table outcome key the check recorded; anything else falls back to the check's
#: own summary, which is already neutral (P1).
_FRIENDLY: dict[tuple[str, str], Friendly] = {
    ("C02", "never_in_history"): _file_never,
    ("C02", "missing_here_present_elsewhere"): _file_elsewhere,
    ("C03", "never_in_history_core"): _symbol_never,
    ("C03", "never_in_history_supporting"): _symbol_never,
    ("C03", "absent_here_present_elsewhere"): _symbol_elsewhere,
    ("C03", "absent_in_sampled_core"): _symbol_sampled,
    ("C04", "past_end"): _line_past_end,
    ("C05", "outside_function"): _line_outside_function,
    ("C05", "fits_nearby_release"): _line_fits_nearby,
    ("C05", "function_not_defined"): _function_not_defined,
    ("C06", "nowhere_in_history"): _quote_nowhere,
    ("C06", "other_release_only"): _quote_elsewhere,
    ("C07", "absent_everywhere"): _snippet_absent,
    ("C08", "inconsistent"): _frames,
    ("C08", "mixed"): _frames,
    ("C09", "missing_edge"): _missing_edges,
    ("C10", "no_release_fits"): _no_release_fits,
    ("C10", "other_release_fits"): _other_release_fits,
    ("C11", "violation"): _sanitizer,
    ("C12", "context_not_found"): _patch_context,
    ("C12", "already_applied"): _patch_applied,
    ("C14", "never_in_history"): _option_never,
    ("C17", "score_mismatch"): _cvss,
    ("C21", "hygiene"): _hygiene,
}


def _gate_note(details: Details) -> str:
    reasons = [_GATE_REASONS.get(key, key) for key in _names(details.get("gated"))]
    if not reasons:
        return ""
    return f" Not counted against the draft: {_listed(reasons)}."


def describe(item: Evidence, where: str) -> str:
    """One sentence about a finding, addressed to the person editing the draft.

    Refuting and neutral findings with a friendly template get it; anything else, and any
    template whose details are missing, gets the check's own summary. The wording is a
    pure function of the evidence item (P2).
    """
    from nikasha.fuse.verdict import outcome_key  # noqa: PLC0415

    if item.outcome in ("REFUTES", "NEUTRAL"):
        friendly = _FRIENDLY.get((item.check_id, outcome_key(item) or ""))
        text = friendly(dict(item.details), where) if friendly is not None else None
        if text:
            return text + _gate_note(item.details) if item.outcome == "NEUTRAL" else text
    if item.outcome == "REFUTES":
        return f"This doesn't match the code at {where}: {item.summary}"
    if item.outcome == "ERROR":
        return f"This check couldn't run: {item.summary}"
    return item.summary


def plain(text: str, *, ascii_only: bool) -> str:
    """``--ascii``: swap the typographic punctuation this module and the templates emit."""
    return text.translate(_ASCII_PUNCTUATION) if ascii_only else text


def question_text(question: Question) -> str:
    """A question as the draft's own author should read it: without the maintainer's
    closing thanks, which is written for the person who *sent* a report."""
    from nikasha.fuse.questions import CLOSING  # noqa: PLC0415

    text = question.text
    if text.endswith(CLOSING):
        text = text[: -len(CLOSING)].rstrip()
    return text


# --- the rows -----------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Row:
    label: str
    item: Evidence
    role_rank: int

    @property
    def key(self) -> tuple[int, int, str]:
        return (_OUTCOME_RANK.get(self.item.outcome, 9), self.role_rank, self.item.id)


def row_item(evidence: Sequence[Evidence], claim_id: str) -> Evidence | None:
    """The finding to show for one claim: the strongest refutation when there is one.

    :func:`nikasha.render.terminal.decisive` lets a stronger support outrank a weaker
    refutation, which is right for a verdict. For a draft, the refutation is the thing to
    fix, so it wins whenever it exists. Ties break on the evidence ID (P2).
    """
    from nikasha.render.terminal import decisive  # noqa: PLC0415

    refuting = [e for e in evidence if claim_id in e.claim_ids and is_refuting(e)]
    if refuting:
        return min(refuting, key=lambda e: (e.strength, e.id))
    return decisive(evidence, claim_id)


def _rows(result: Result) -> tuple[list[_Row], int]:
    """One row per claim with a finding, plus one per claim-less finding; and the count of
    claims nothing could check."""
    from nikasha.render.terminal import claim_label  # noqa: PLC0415

    rows: list[_Row] = []
    unchecked = 0
    claims: Sequence[Claim] = result.claims
    for claim in claims:
        item = row_item(result.evidence, claim.id)
        if item is None:
            unchecked += 1
            continue
        rows.append(_Row(claim_label(claim), item, _ROLE_RANK.get(claim.role, 3)))
    for item in result.evidence:
        if not item.claim_ids:
            rows.append(_Row("the draft", item, 3))
    rows.sort(key=lambda row: row.key)
    return rows, unchecked


def _count(n: int, singular: str, plural: str) -> str:
    return f"{n} {singular if n == 1 else plural}"


def _tally(rows: Sequence[_Row], unchecked: int, *, ascii_only: bool) -> Text:
    """``2 details don't match the code - 3 couldn't be confirmed - 7 check out``."""
    counts = {"REFUTES": 0, "NEUTRAL": 0, "ERROR": 0, "SUPPORTS": 0}
    for row in rows:
        counts[row.item.outcome] = counts.get(row.item.outcome, 0) + 1
    parts: list[tuple[str, str]] = []
    if counts["REFUTES"]:
        n = counts["REFUTES"]
        verb = "doesn't" if n == 1 else "don't"
        parts.append((f"{_count(n, 'detail', 'details')} {verb} match the code", "red"))
    if counts["NEUTRAL"] + counts["ERROR"]:
        n = counts["NEUTRAL"] + counts["ERROR"]
        parts.append((f"{n} couldn't be confirmed", "yellow"))
    if counts["SUPPORTS"]:
        n = counts["SUPPORTS"]
        parts.append((f"{n} {'checks' if n == 1 else 'check'} out", "green"))
    if unchecked:
        parts.append((f"{unchecked} not checked", "bright_black"))
    if not parts:
        return Text("nothing in the draft could be checked against the code", style="yellow")
    sep = " - " if ascii_only else f" {_MIDDLE_DOT} "
    line = Text()
    for i, (words, style) in enumerate(parts):
        if i:
            line.append(sep, style="bright_black")
        line.append(words, style=style)
    return line


# --- rendering ----------------------------------------------------------------------------------


def _box(ascii_only: bool) -> box.Box:
    return box.ASCII if ascii_only else box.ROUNDED


def _clip(text: str, limit: int) -> str:
    """The terminal view's clipping: one printable line, at most ``limit`` characters (P7)."""
    from nikasha.render.terminal import _clip as clip  # noqa: PLC0415

    return clip(text, limit)


def _header(
    result: Result, rows: Sequence[_Row], unchecked: int, source: str, *, ascii_only: bool
) -> Panel:
    target = result.target
    sep = " - " if ascii_only else f" {_MIDDLE_DOT} "
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bright_black", no_wrap=True)
    grid.add_column(overflow="fold")
    grid.add_row("Draft", Text(_clip(source, _MAX_SOURCE)))
    if target is None or target.commit is None:
        note = Text("no version in the draft resolves to a release", style="yellow")
        if target is not None:
            note.append(f"{sep}{_clip(target.method, 80)}", style="bright_black")
        grid.add_row("Checked", note)
    else:
        # Every field here is report-derived (a permalink the draft pasted can set the repo
        # and ref), so it is clipped and rendered as inert Text (P7).
        where = Text(_clip(target.repo_url, 120))
        if target.ref_name:
            where.append(" @ " + _clip(target.ref_name, 60))
        where.append(f" ({_clip(target.commit, 40)[:7]})")
        where.append(f"{sep}resolved from {_clip(target.method, 80)}", style="bright_black")
        grid.add_row("Checked", where)
    grid.add_row("Summary", _tally(rows, unchecked, ascii_only=ascii_only))
    joiner = "-" if ascii_only else _MIDDLE_DOT
    title = f"nikasha lint {joiner} before you submit"
    return Panel(grid, title=title, title_align="left", box=_box(ascii_only))


def _table(rows: Sequence[_Row], marks: dict[str, str], where: str, *, ascii_only: bool) -> Table:
    table = Table(box=None, pad_edge=False, show_edge=False)
    table.add_column("Claim", overflow="fold", max_width=_MAX_LABEL)
    table.add_column("", justify="center", no_wrap=True)
    table.add_column("What we found", overflow="fold")
    for row in rows:
        key = _OUTCOME_KEY.get(row.item.outcome, "unknown")
        found = plain(describe(row.item, where), ascii_only=ascii_only)
        table.add_row(
            Text(_clip(row.label, _MAX_LABEL)),
            Text(marks[key], style=_OUTCOME_STYLE.get(row.item.outcome, "")),
            Text(_clip(found, _MAX_FOUND)),
        )
    if not rows:
        dash = "-" if ascii_only or marks["ok"] == "+" else _EM_DASH
        table.add_row(Text(dash), Text(marks["unknown"]), Text("nothing here could be checked"))
    return table


def _legend(marks: dict[str, str]) -> Text:
    return Text(
        f"{marks['ok']} checks out   {marks['fail']} doesn't match the code   "
        f"{marks['warn']} couldn't be confirmed   {marks['unknown']} check didn't run",
        style="bright_black",
    )


def _questions(questions: Sequence[Question], *, ascii_only: bool) -> Panel:
    grid = Table.grid(padding=(0, 1))
    grid.add_column(style="bright_black", no_wrap=True)
    grid.add_column(overflow="fold")
    for i, question in enumerate(questions, start=1):
        text = plain(question_text(question), ascii_only=ascii_only)
        grid.add_row(f"{i}.", Text(_clip(text, _MAX_QUESTION)))
    return Panel(
        grid,
        title=f"What a maintainer would ask ({len(questions)})",
        title_align="left",
        box=_box(ascii_only),
    )


def _footer(result: Result, refuted: int, where: str, rerun: str, *, ascii_only: bool) -> Group:
    lines: list[RenderableType] = []
    target = result.target
    if target is None or target.commit is None:
        lines.append(
            Text(
                "Add the exact version or commit you tested (or pass --version) so the draft"
                " can be checked against the code.",
                style="bold yellow",
            )
        )
    elif refuted:
        # The same per-claim count as the Summary line, so the two never disagree.
        dash = "-" if ascii_only else _EM_DASH
        verb, them = ("doesn't", "it") if refuted == 1 else ("don't", "them")
        lines.append(
            Text(
                f"{_count(refuted, 'detail', 'details')} {verb} match the code at {where} {dash}"
                f" fix {them}, or name the version you tested, then re-run.",
                style="bold red",
            )
        )
    else:
        lines.append(
            Text(
                f"Nothing in the draft is contradicted by the code at {where}.", style="bold green"
            )
        )
    if rerun:
        lines.append(
            Text(f"Re-run after editing: {_clip(rerun, _MAX_RERUN)}", style="bright_black")
        )
    lines.append(
        Text(
            "This is a pre-submit check, not a verdict: maintainers run their own nikasha check.",
            style="bright_black",
        )
    )
    return Group(*lines)


def render_lint(
    console: Console,
    result: Result,
    questions: Sequence[Question] = (),
    *,
    ascii_only: bool = False,
    source: str = "",
    rerun: str = "",
) -> None:
    """Render one linted draft: header, findings (problems first), questions, next step."""
    from nikasha.render.terminal import symbols  # noqa: PLC0415

    marks = symbols(ascii_only=ascii_only, encoding=console.encoding)
    where = where_of(result)
    rows, unchecked = _rows(result)
    refuted = sum(1 for row in rows if row.item.outcome == "REFUTES")
    parts: list[RenderableType] = [
        _header(result, rows, unchecked, source or result.report.id, ascii_only=ascii_only),
        "",
        _table(rows, marks, where, ascii_only=ascii_only),
        _legend(marks),
    ]
    if questions:
        parts += ["", _questions(questions, ascii_only=ascii_only)]
    parts += ["", _footer(result, refuted, where, rerun, ascii_only=ascii_only)]
    console.print(Group(*parts))


# --- the command --------------------------------------------------------------------------------


def _emit_utf8(text: str) -> None:
    """Write machine output as UTF-8 bytes whatever the console encoding (e.g. cp1252)."""
    stream = sys.stdout
    buffer = getattr(stream, "buffer", None)
    if buffer is None:
        stream.write(text)
    else:
        stream.flush()
        buffer.write(text.encode("utf-8"))
        buffer.flush()


def _rerun_hint(
    draft: str, repo: str | None, ref: str | None, version: str | None, product: str | None
) -> str:
    """The command to run again, quoted so it stays one runnable line whatever the values hold.

    The draft path and every option value came from the user's own command line, but a
    space or a shell metacharacter in one of them would otherwise print as a hint that
    does something else when pasted (``--repo 'https://x/y; rm -rf /'`` is inert, the
    unquoted form is not). :func:`shlex.join` quotes each word only when it has to.
    """
    words = ["nikasha", "lint", draft]
    for flag, value in (
        ("--repo", repo),
        ("--ref", ref),
        ("--version", version),
        ("--product", product),
    ):
        if value:
            words += [flag, value]
    return shlex.join(words)


def lint(  # noqa: PLR0917 - a CLI command's options are its signature
    draft: Annotated[
        str, typer.Argument(help="Draft report (Markdown, text or HTML), or - for stdin.")
    ],
    repo: Annotated[
        str | None, typer.Option("--repo", help="Repository URL (https) or local path.")
    ] = None,
    ref: Annotated[
        str | None, typer.Option("--ref", help="Exact git ref to check against.")
    ] = None,
    version: Annotated[
        str | None, typer.Option("--version", help="Release the draft is about, e.g. 8.5.0.")
    ] = None,
    product: Annotated[
        str | None, typer.Option("--product", help="Product name, e.g. curl or libhdr.")
    ] = None,
    input_format: Annotated[
        str, typer.Option("--input-format", help="auto, markdown, text or html.")
    ] = "auto",
    online: Annotated[
        bool,
        typer.Option("--online", help="Allow network access (clone or refresh the repository)."),
    ] = False,
    as_json: Annotated[
        bool, typer.Option("--json", help="Emit the full Result as JSON instead of the view.")
    ] = False,
    ascii_only: Annotated[bool, typer.Option("--ascii", help="ASCII symbols only.")] = False,
) -> None:
    """Check a draft report before you submit it: same checks as `check`, no verdict.

    Every finding is worded for the person editing the draft, and the questions are the
    ones a maintainer would send back. Exit codes: 0 when nothing is contradicted by the
    code, 20 when at least one detail is, 1 on error.

    Example:
        nikasha lint DRAFT.md --repo https://github.com/curl/curl --version 8.5.0
        nikasha lint DRAFT.md --repo ./libhdr.git --version 1.2.0 --json > result.json
    """
    if input_format not in ("auto", "markdown", "text", "html"):
        raise typer.BadParameter(
            "must be auto, markdown, text or html", param_hint="--input-format"
        )
    fmt: InputFormat = input_format  # type: ignore[assignment]
    try:
        linted = lint_report(
            draft,
            repo=repo,
            ref=ref,
            version=version,
            product=product,
            input_format=fmt,
            online=online,
        )
    except NikashaError as exc:
        # The message carries the draft path and option values, so it is escaped: a path
        # such as "[/b].md" must print as text, not raise MarkupError inside the handler.
        Console(stderr=True).print(
            f"[red]error:[/] {escape(str(exc))}", markup=True, highlight=False
        )
        raise typer.Exit(code=1) from exc

    if as_json:
        _emit_utf8(linted.result.to_json())
    else:
        render_lint(
            Console(),
            linted.result,
            linted.questions,
            ascii_only=ascii_only,
            source=draft,
            rerun=_rerun_hint(draft, repo, ref, version, product),
        )
    raise typer.Exit(code=linted.exit_code)


def register(app: typer.Typer) -> None:
    """Add ``nikasha lint`` to the CLI. :mod:`nikasha.cli` calls this when it is wired."""
    app.command(name="lint")(lint)


__all__ = [
    "EXIT_OK",
    "EXIT_REFUTED",
    "LintReport",
    "describe",
    "exit_code_for",
    "is_refuting",
    "lint",
    "lint_report",
    "plain",
    "question_text",
    "refutations",
    "register",
    "render_lint",
    "row_item",
    "where_of",
]
