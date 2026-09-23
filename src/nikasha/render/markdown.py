# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Markdown output (SPEC §15.3): what a maintainer pastes into a GitHub issue, a
HackerOne comment or an email reply.

Three properties matter more than looks here.

**It fits.** GitHub caps a comment at 65,536 characters, so the document must stay under
:data:`MAX_CHARS`. When it does not fit, sections are dropped in a fixed order — evidence
details first, then the score arithmetic, excerpts, context, and only last the claim and
evidence lists — and the questions for the reporter are never cut below the top three
(they are the part a maintainer actually acts on). Any reduction is stated in the footer.

**It is escaped.** Every string that came from the report or from repository code is
hostile input (P7): a title of ``</details><script>alert(1)</script>``, a claim holding
pipes, backticks or newlines, a 1 MB single line. :func:`escape_inline` collapses the
value to one line, drops control and format characters (including the bidirectional
overrides behind "Trojan Source"), entity-escapes ``& < >`` and backslash-escapes the
Markdown punctuation that could otherwise break out of a table cell or a code span.
:func:`code_span` and :func:`fence` pick a backtick run longer than anything inside the
value, so no excerpt can close its own fence. Nothing is ever marked safe.

Repository code keeps its ``<`` and ``>`` — otherwise a C excerpt would read
``#include &lt;stdio.h&gt;`` — but only ever inside a code span or a fenced block, where
the Markdown renderer escapes it. The invariant is therefore: **outside a code span or a
fence, the only ``<`` in the document is the ``<details>``/``<summary>`` scaffolding this
module writes itself**, and ``tests/unit/render/test_markdown.py`` checks it on every
hostile payload. The blank line after each ``<summary>`` closes the HTML block
(CommonMark's rule 6), so everything below it is Markdown, not raw HTML.

**It is deterministic (P2).** Same :class:`~nikasha.model.result.Result`, byte-identical
Markdown. No clock, no randomness; ``Result.timings`` is never rendered.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any

from nikasha.code.languages import detect_language
from nikasha.model.evidence import CodeLocation, Evidence
from nikasha.model.result import Environment, ResolvedTarget, Result
from nikasha.model.verdict import Question, Verdict
from nikasha.version import __version__

if TYPE_CHECKING:  # pragma: no cover - imports used only for annotations
    from nikasha.fuse.scoring import Ledger
    from nikasha.pipeline import CheckReport

#: GitHub's comment limit is 65,536 characters; leave headroom for a quoting maintainer.
MAX_CHARS = 60_000

#: Questions are the actionable part of the document and are never cut below this many.
MIN_QUESTIONS = 3

_MAX_TITLE = 120
_MAX_CELL = 72
_MAX_SUMMARY = 220
_MAX_QUESTION = 400
_MAX_VALUE = 120
_MAX_URL = 500
_MAX_EXCERPT_LINES = 12
_MAX_EXCERPT_COLS = 120
_MAX_NOTES = 6

#: Characters that never survive into the output: C0/C1 controls, format characters
#: (bidi overrides, zero-width joiners), surrogates, private use, unassigned, and the
#: line/paragraph separators. They are display attacks, not content.
_DROPPED_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})

#: Markdown punctuation that can change the structure of the document from inside a value.
#: ``&``, ``<`` and ``>`` are entity-escaped instead, and ``|`` is escaped so a value can
#: never add a column to a table.
_MD_PUNCT = frozenset("\\`*_[]()#!|~")

#: A link destination is only emitted when the whole URL matches: https only, and no
#: whitespace, parentheses or angle brackets that could close the destination early. The
#: bound keeps the match linear on hostile input.
_SAFE_URL = re.compile(r"\Ahttps://[A-Za-z0-9._~:/?#\[\]@!$&'*+,;=%-]{1,500}\Z")

#: Info strings are attacker-influenced, so only a plain language token is kept.
_SAFE_LANG = re.compile(r"\A[a-z0-9+#-]{1,20}\Z")

_VERDICT_MARK: dict[str, str] = {
    "REPRODUCED": "✓",
    "GROUNDED": "✓",
    "MIXED": "~",
    "UNGROUNDED": "✗",
    "INSUFFICIENT": "?",
    "ERROR": "!",
}
_OUTCOME_MARK: dict[str, str] = {
    "SUPPORTS": "✓",
    "REFUTES": "✗",
    "NEUTRAL": "~",
    "ERROR": "!",
}
_OUTCOME_LABEL: dict[str, str] = {
    "SUPPORTS": "✓ supported",
    "REFUTES": "✗ refuted",
    "NEUTRAL": "~ noted",
    "ERROR": "! error",
}
#: Worst-first: one refutation decides a claim's row even when other checks agreed.
_OUTCOME_ORDER = ("REFUTES", "SUPPORTS", "NEUTRAL", "ERROR")
_UNCHECKED = "? unchecked"

_TRUNCATION_NOTE = (
    "Some sections were shortened to fit the comment size limit. "
    "The complete evidence is in the JSON output (`--format json`)."
)


# --- escaping ---------------------------------------------------------------------------


def _strip_controls(text: str) -> str:
    """Replace control, format and separator characters with a space."""
    return "".join(" " if unicodedata.category(ch) in _DROPPED_CATEGORIES else ch for ch in text)


def _cut(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: max(0, limit - 1)].rstrip() + "…"


def escape_inline(text: str, limit: int = _MAX_SUMMARY) -> str:
    """One line of Markdown-safe text from an untrusted value.

    Newlines become spaces (so a value cannot add a table row), ``& < >`` become entities
    (so it cannot open an HTML element or close a ``<details>``) and Markdown punctuation
    is backslash-escaped (so it cannot emphasise, link, or add a table column).
    """
    flat = " ".join(_strip_controls(text).split())
    parts: list[str] = []
    for ch in _cut(flat, limit):
        if ch == "&":
            parts.append("&amp;")
        elif ch == "<":
            parts.append("&lt;")
        elif ch == ">":
            parts.append("&gt;")
        elif ch in _MD_PUNCT:
            parts.append("\\" + ch)
        else:
            parts.append(ch)
    return "".join(parts)


def _backtick_run(text: str) -> int:
    longest = run = 0
    for ch in text:
        run = run + 1 if ch == "`" else 0
        longest = max(longest, run)
    return longest


def code_span(text: str, limit: int = _MAX_CELL, *, in_table: bool = False) -> str:
    """An untrusted value as a code span that it cannot escape from.

    The delimiter is always longer than the longest backtick run inside the value. Inside
    a table, ``|`` is backslash-escaped as well: GFM splits cells before inline parsing,
    so a pipe breaks the row even from inside a code span.
    """
    inner = _cut(" ".join(_strip_controls(text).split()), limit)
    if not inner:
        return ""
    if in_table:
        inner = inner.replace("|", "\\|")
    ticks = "`" * (_backtick_run(inner) + 1)
    pad = " " if inner.startswith("`") or inner.endswith("`") else ""
    return f"{ticks}{pad}{inner}{pad}{ticks}"


def fence(text: str, lang: str = "") -> list[str]:
    """Untrusted code as a fenced block that it cannot close early.

    The block is capped in both directions, and the fence is longer than the longest
    backtick run in the content, so neither a stray ``` ``` ``` nor a ``</details>`` line
    can break out of it.
    """
    body = [
        _cut(_strip_controls(line.replace("\t", "    ")).rstrip(), _MAX_EXCERPT_COLS)
        for line in text.splitlines()[:_MAX_EXCERPT_LINES]
    ]
    marker = "`" * max(3, max((_backtick_run(line) for line in body), default=0) + 1)
    info = lang if _SAFE_LANG.match(lang) else ""
    return [marker + info, *body, marker]


def link(label: str, url: str | None) -> str:
    """``label`` as a Markdown link when ``url`` is a plain https URL, else plain."""
    if url is None or not _SAFE_URL.match(url):
        return label
    return f"[{label}]({_cut(url, _MAX_URL)})"


# --- shaping ----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Limits:
    """How much of the document is rendered. Reduced until the output fits."""

    claims: int = 60
    evidence: int = 12
    questions: int = 6
    excerpts: bool = True
    details: bool = True
    ledger: bool = True
    context: bool = True


#: Applied in order until the document fits. Least important first (SPEC §15.3): the long
#: ``<details>`` bodies go before the lists, and questions are touched last and only down
#: to :data:`MIN_QUESTIONS`.
_REDUCTIONS: tuple[Callable[[_Limits], _Limits], ...] = (
    lambda limits: replace(limits, details=False),
    lambda limits: replace(limits, ledger=False),
    lambda limits: replace(limits, excerpts=False),
    lambda limits: replace(limits, context=False),
    lambda limits: replace(limits, evidence=6),
    lambda limits: replace(limits, claims=30),
    lambda limits: replace(limits, evidence=3),
    lambda limits: replace(limits, claims=15),
    lambda limits: replace(limits, questions=MIN_QUESTIONS),
)


def evidence_by_claim(evidence: Sequence[Evidence]) -> dict[str, tuple[Evidence, ...]]:
    """Evidence per claim id, strongest first, ties broken by id (P2)."""
    grouped: dict[str, list[Evidence]] = {}
    for item in evidence:
        for claim_id in item.claim_ids:
            grouped.setdefault(claim_id, []).append(item)
    return {
        claim_id: tuple(sorted(items, key=lambda e: (-abs(e.strength), e.id)))
        for claim_id, items in grouped.items()
    }


def claim_outcome(items: Sequence[Evidence]) -> tuple[str, Evidence | None]:
    """The row label for a claim and the evidence item that earned it."""
    for outcome in _OUTCOME_ORDER:
        for item in items:
            if item.outcome == outcome:
                return _OUTCOME_LABEL[outcome], item
    return _UNCHECKED, None


def top_evidence(result: Result, limit: int) -> tuple[Evidence, ...]:
    """Key evidence first, in the verdict's order, then the rest by strength then id."""
    by_id = {item.id: item for item in result.evidence}
    keyed = result.verdict.key_evidence if result.verdict is not None else ()
    seen: set[str] = set()
    ordered: list[Evidence] = []
    for eid in keyed:
        if eid in by_id and eid not in seen:
            seen.add(eid)
            ordered.append(by_id[eid])
    ordered += sorted(
        (item for item in result.evidence if item.id not in seen),
        key=lambda e: (-abs(e.strength), e.id),
    )
    return tuple(ordered[: max(0, limit)])


def _location_label(location: CodeLocation) -> str:
    lines = (
        f"line {location.start_line}"
        if location.end_line <= location.start_line
        else f"lines {location.start_line}-{location.end_line}"
    )
    return f"{code_span(location.path)} {lines}"


def _excerpt_lang(path: str) -> str:
    """The fence info string for a repository path, from the shared extension table.

    The value comes from :class:`~nikasha.code.languages.Lang`, never from the path
    itself, so an attacker-chosen extension cannot reach the info string.
    """
    lang = detect_language(path[:_MAX_CELL])
    return str(lang) if lang is not None else ""


def _plural(count: int, word: str) -> str:
    return f"{count} {word}" if count == 1 else f"{count} {word}s"


# --- sections ---------------------------------------------------------------------------


def _verdict_line(verdict: Verdict | None) -> str:
    if verdict is None:
        return "## Nikasha: ? no verdict"
    mark = _VERDICT_MARK.get(verdict.label, "?")
    return (
        f"## Nikasha: {mark} {verdict.label} — grounding {verdict.score}/100, "
        f"confidence {verdict.confidence}"
    )


def _target_line(target: ResolvedTarget | None) -> str:
    if target is None:
        return "- **Target:** not resolved"
    parts = [code_span(target.repo_url, _MAX_URL)]
    if target.ref_name:
        parts.append(f"at {code_span(target.ref_name)}")
    if target.commit:
        parts.append(f"({code_span(target.commit[:12])})")
    how = escape_inline(target.method, _MAX_CELL)
    return f"- **Target:** {' '.join(parts)} — resolved by {how} ({target.confidence} confidence)"


def _header(result: Result, env: Environment) -> list[str]:
    report = result.report
    title = report.title or report.source.uri or report.id
    lines = [
        _verdict_line(result.verdict),
        "",
        f"- **Report:** {escape_inline(title, _MAX_TITLE)}",
        _target_line(result.target),
        (
            f"- **Checked:** {_plural(len(result.claims), 'claim')} · "
            f"{_plural(len(result.evidence), 'evidence item')} · {env.mode}"
        ),
    ]
    verdict = result.verdict
    if verdict is not None and verdict.rule:
        lines.append(f"- **Rule:** {code_span(verdict.rule)}")
    for note in verdict.notes[:_MAX_NOTES] if verdict is not None else ():
        lines.append(f"- {escape_inline(note)}")
    lines.append("")
    return lines


def _claims_table(result: Result, limit: int) -> list[str]:
    if not result.claims:
        return []
    grouped = evidence_by_claim(result.evidence)
    lines = [
        "### Claims",
        "",
        "| # | Claim | Kind | Result | Evidence |",
        "| ---: | --- | --- | --- | --- |",
    ]
    shown = result.claims[: max(0, limit)]
    for number, claim in enumerate(shown, 1):
        label, item = claim_outcome(grouped.get(claim.id, ()))
        kind = escape_inline(str(getattr(claim, "kind", "")), 20)
        text = escape_inline(claim.spans[0].text, _MAX_CELL)
        if item is None:
            note = "no check covered this claim"
        else:
            note = (
                f"{code_span(item.check_id, 12, in_table=True)} "
                f"{escape_inline(item.summary, _MAX_CELL * 2)}"
            )
        lines.append(f"| {number} | {text} | {kind} | {label} | {note} |")
    if len(shown) < len(result.claims):
        lines += ["", f"_Showing {len(shown)} of {len(result.claims)} claims._"]
    lines.append("")
    return lines


def _evidence_section(result: Result, limit: int, *, excerpts: bool) -> list[str]:
    items = top_evidence(result, limit)
    if not items:
        return []
    lines = ["### Evidence", ""]
    for number, item in enumerate(items, 1):
        mark = _OUTCOME_MARK.get(item.outcome, "?")
        head = (
            f"**{number}. {mark} {code_span(item.check_id, 12)}** "
            f"({escape_inline(item.group, 40)}) — {escape_inline(item.summary)}"
        )
        located = [loc for loc in item.locations if loc.permalink or loc.path][:2]
        if located:
            head += " — " + ", ".join(link(_location_label(loc), loc.permalink) for loc in located)
        lines += [head, ""]
        if excerpts:
            for loc in located:
                if loc.excerpt:
                    lines += fence(loc.excerpt, _excerpt_lang(loc.path))
                    lines.append("")
    if len(items) < len(result.evidence):
        lines += [f"_Showing {len(items)} of {len(result.evidence)} evidence items._", ""]
    return lines


def _questions_section(questions: Sequence[Question], limit: int) -> list[str]:
    shown = questions[: max(0, limit)]
    if not shown:
        return []
    lines = [f"### Questions for the reporter ({len(shown)})", ""]
    for number, question in enumerate(shown, 1):
        lines.append(f"{number}. {escape_inline(question.text, _MAX_QUESTION)}")
        if question.rationale:
            lines.append(f"   - Why: {escape_inline(question.rationale, _MAX_QUESTION)}")
        if question.evidence_ids:
            cited = ", ".join(code_span(eid, 24) for eid in question.evidence_ids[:6])
            lines.append(f"   - Evidence: {cited}")
    if len(shown) < len(questions):
        lines.append("")
        lines.append(f"_Showing {len(shown)} of {len(questions)} questions._")
    lines.append("")
    return lines


def _details(summary: str, body: Iterable[str]) -> list[str]:
    rows = list(body)
    if not rows:
        return []
    return ["<details>", f"<summary>{summary}</summary>", "", *rows, "", "</details>", ""]


def _value(value: Any) -> str:  # noqa: ANN401 - evidence details are free-form JSON
    if isinstance(value, (list, tuple)):
        return code_span(", ".join(str(part) for part in value), _MAX_VALUE)
    return code_span(str(value), _MAX_VALUE)


def _evidence_details(result: Result) -> list[str]:
    rows: list[str] = []
    # Sorted by id, so the section never depends on the order the checks happened to run in.
    for item in sorted(result.evidence, key=lambda e: e.id):
        rows.append(
            f"- {code_span(item.id, 24)} {code_span(item.check_id, 12)} "
            f"{item.outcome} strength {item.strength:+.2f} "
            f"({escape_inline(item.group, 40)}, {item.produced_by})"
        )
        rows.append(f"  - {escape_inline(item.summary)}")
        for key in sorted(item.details):
            rows.append(f"  - {escape_inline(key, 40)}: {_value(item.details[key])}")
        for command in item.commands:
            rows.append(
                f"  - ran {code_span(' '.join(command.argv), _MAX_VALUE)} "
                f"→ exit {command.exit_code}, stdout sha256 "
                f"{code_span(command.stdout_sha256[:16], 20)}"
            )
    return _details(f"Evidence details ({len(result.evidence)})", rows)


def _ledger_details(ledger: Ledger | None) -> list[str]:
    if ledger is None or not ledger.contributions:
        return []
    rows = [
        "| Evidence | Check | Group | Strength | Weight | Contribution |",
        "| --- | --- | --- | ---: | ---: | ---: |",
    ]
    for contribution in ledger.contributions:
        rows.append(
            f"| {code_span(contribution.evidence_id, 24, in_table=True)} "
            f"| {code_span(contribution.check_id, 12, in_table=True)} "
            f"| {escape_inline(contribution.group, 40)} "
            f"| {contribution.strength:+.2f} | {contribution.weight:.3f} "
            f"| {contribution.contribution:+.3f} |"
        )
    rows += [
        "",
        f"Prior {ledger.prior:+.2f}, total log-odds {ledger.log_odds:+.3f}, "
        f"score {ledger.score}/100, calibration {code_span(ledger.calibration, 40)}.",
    ]
    return _details("How the score was computed", rows)


def _context_details(result: Result, env: Environment) -> list[str]:
    rows = [
        f"- Report id: {code_span(result.report.id, 40)}",
        f"- Source: {escape_inline(result.report.source.kind, 20)}"
        + (f" {code_span(result.report.source.uri, _MAX_URL)}" if result.report.source.uri else ""),
        f"- Mode: {escape_inline(env.mode, 20)}",
    ]
    if env.sandbox_engine:
        rows.append(f"- Sandbox: {code_span(env.sandbox_engine, 40)}")
    if env.llm:
        rows.append(f"- LLM: {code_span(env.llm, 60)}")
    for url in env.fetched_urls[:_MAX_NOTES]:
        rows.append(f"- Fetched: {code_span(url, _MAX_URL)}")
    target = result.target
    if target is not None:
        for alternative in target.alternatives[:_MAX_NOTES]:
            rows.append(f"- Other candidate: {code_span(alternative, _MAX_URL)}")
        for warning in target.warnings[:_MAX_NOTES]:
            rows.append(f"- Target warning: {escape_inline(warning)}")
    for warning in result.report.warnings[:_MAX_NOTES]:
        rows.append(f"- Intake warning: {escape_inline(warning)}")
    return _details("Run context", rows)


def rerun_command(result: Result) -> str:
    """The `nikasha check` invocation that reproduces this result."""
    parts = ["nikasha check", result.report.source.uri or "REPORT"]
    target = result.target
    if target is not None:
        parts += ["--repo", target.repo_url]
        if target.ref_name:
            parts += ["--ref", target.ref_name]
    return " ".join(parts)


def _footer(result: Result, *, truncated: bool) -> list[str]:
    lines = ["---", ""]
    if truncated:
        lines += [f"_{_TRUNCATION_NOTE}_", ""]
    lines.append(
        f"Generated by Nikasha v{__version__} (deterministic checks). "
        f"Re-run: {code_span(rerun_command(result), 300)}"
    )
    return lines


# --- assembly ---------------------------------------------------------------------------


def _body(result: Result, ledger: Ledger | None, limits: _Limits) -> list[str]:
    env = result.environment
    verdict = result.verdict
    lines = _header(result, env)
    lines += _claims_table(result, limits.claims)
    lines += _evidence_section(result, limits.evidence, excerpts=limits.excerpts)
    lines += _questions_section(verdict.questions if verdict else (), limits.questions)
    if limits.details:
        lines += _evidence_details(result)
    if limits.ledger:
        lines += _ledger_details(ledger)
    if limits.context:
        lines += _context_details(result, env)
    return lines


def _join(body: Sequence[str], footer: Sequence[str]) -> str:
    return "\n".join([*body, *footer]) + "\n"


def _close_open_blocks(body: list[str]) -> list[str]:
    """Close any fence or ``<details>`` a hard cut left open, and end on a blank line.

    Cutting trailing lines can stop inside a fenced excerpt or a ``<details>`` body; the
    footer that follows must not end up inside either, nor be glued to a table row.
    """
    open_fence: str | None = None
    depth = 0
    for line in body:
        if open_fence is not None:
            if line == open_fence:
                open_fence = None
            continue
        if line.startswith("```"):
            open_fence = line[: len(line) - len(line.lstrip("`"))]
        elif line == "<details>":
            depth += 1
        elif line == "</details>":
            depth = max(0, depth - 1)
    closed = list(body)
    if open_fence is not None:
        closed.append(open_fence)
    closed += ["</details>"] * depth
    if closed and closed[-1] != "":
        closed.append("")
    return closed


def render_markdown_result(
    result: Result,
    *,
    ledger: Ledger | None = None,
    max_chars: int = MAX_CHARS,
) -> str:
    """Render one :class:`~nikasha.model.result.Result` as Markdown (SPEC §15.3).

    Pure: no printing, no files, no clock. The output is byte-identical for equal input
    and never exceeds ``max_chars`` characters.
    """
    limits = _Limits()
    footer = _footer(result, truncated=False)
    body = _body(result, ledger, limits)
    if len(_join(body, footer)) <= max_chars:
        return _join(body, footer)

    footer = _footer(result, truncated=True)
    for reduce_once in _REDUCTIONS:
        limits = reduce_once(limits)
        body = _body(result, ledger, limits)
        if len(_join(body, footer)) <= max_chars:
            return _join(body, footer)

    while body and len(_join(_close_open_blocks(body), footer)) > max_chars:
        body.pop()
    text = _join(_close_open_blocks(body), footer)
    return text if len(text) <= max_chars else text[:max_chars]


def render_markdown(report: CheckReport, *, max_chars: int = MAX_CHARS) -> str:
    """Render a finished ``nikasha check`` run as Markdown (SPEC §15.3)."""
    return render_markdown_result(report.result, ledger=report.ledger, max_chars=max_chars)


__all__ = [
    "MAX_CHARS",
    "MIN_QUESTIONS",
    "claim_outcome",
    "code_span",
    "escape_inline",
    "evidence_by_claim",
    "fence",
    "link",
    "render_markdown",
    "render_markdown_result",
    "rerun_command",
    "top_evidence",
]
