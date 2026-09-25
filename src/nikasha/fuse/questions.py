# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Questions for the reporter (SPEC §14.4, Appendix D).

A verdict on its own is an accusation. A verdict with the two questions that would settle
it is triage. This module turns evidence into those questions, and it is the one place in
Nikasha whose output is read by the *reporter* rather than by the maintainer, so the tone
rules are part of the contract, not a style preference (P1):

* **Neutral and specific.** Every question names a file, a symbol, a line or a release,
  and asks about *that*, never about the report or the person who wrote it.
* **No accusations.** "We couldn't find X at this version" is a measurement.
  "X doesn't exist" is a verdict, and the verdict has its own field.
* **Nothing about how the report was written.** Nikasha checks claims against code; it has
  no evidence about authorship and must never imply that it does. ``tests/unit/fuse``
  scans both the templates and the rendered text for the words that would break this.
* **Always end with the cheapest way to verify** — a permalink, a commit hash, the exact
  command — followed by :data:`CLOSING`, which is appended here so no template can forget
  it.

Templates live in ``fuse/questions/*.j2``, named ``<check>.<outcome>.j2``, so adding a
question to a check is adding one file and no code. Rendering uses
:class:`~jinja2.StrictUndefined`: a template that asks for a variable the check did not
record fails instead of quietly writing "None" into a question sent to a human. In a real
run that failure is swallowed and the question is dropped (a missing question is a small
loss; a crashed run is a big one), which is exactly why the tests render every template
directly, where the failure is loud.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined, TemplateError

from nikasha.fuse.verdict import Decision, outcome_key
from nikasha.model.claims import Claim, VersionClaim
from nikasha.model.evidence import Evidence
from nikasha.model.verdict import Question

#: Where the templates live, one file per (check, outcome).
TEMPLATE_DIR = Path(__file__).with_name("questions")

TEMPLATE_SUFFIX = ".j2"

#: SPEC §14.4: never more than six, however much there is to ask about. A reporter who is
#: sent twenty questions answers none of them.
MAX_QUESTIONS = 6

#: Appended to every question (SPEC Appendix D).
CLOSING = "Thanks for the report. These details will let us verify it quickly."

#: Releases quoted in a list before it collapses into "and N others".
MAX_LISTED = 3

#: Template names are built from check IDs and outcome keys. Both come from our own
#: tables, but they arrive via ``Evidence.details``, so they are validated before they
#: reach the loader rather than trusted (P7).
_NAME_PART = re.compile(r"\A[A-Za-z0-9_]{1,64}\Z")

#: SPEC Appendix D writes release ranges as "{first} to {last}" with an en dash.
_EN_DASH = chr(0x2013)

#: Templates are written as blocks so the conditionals stay readable, which leaves a space
#: in front of punctuation that follows an ``{% endif %}``. Closing it up here means no
#: template has to be written as one unreadable line to produce one readable sentence.
_SPACE_BEFORE_PUNCTUATION = re.compile(r"\s+(?=[,.;:?!])")


@dataclass(frozen=True, slots=True)
class _Subject:
    """What the report says it is about, as far as the evidence and claims reveal it.

    Composed once per run so that every question names the same target in the same words.
    """

    project: str | None
    version: str | None
    commit: str | None

    @property
    def target(self) -> str:
        """The target as a question would name it: "curl 8.5.0 (commit 3f2a9c1b2d4e)"."""
        phrase = self.project or "this project"
        if self.version:
            phrase = f"{phrase} {self.version}"
        if self.commit:
            phrase = f"{phrase} (commit {self.commit[:12]})"
        return phrase

    @property
    def where(self) -> str:
        """The shortest unambiguous name for the version under test."""
        if self.version:
            return self.version
        if self.commit:
            return f"commit {self.commit[:12]}"
        return "the version the report names"


# --- template filters ----------------------------------------------------------------------


def _text(value: object) -> str:
    """One display string for a scalar out of a check's ``details``."""
    if isinstance(value, bool):
        return "yes" if value else "no"
    return str(value)


def _items(value: object) -> list[str]:
    """Coerce a details value to a list of display strings, whatever the check put there."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [_text(item) for item in value if item is not None and item != ""]
    return [_text(value)]


def ranged(value: object) -> str:
    """``["1.0", "1.2", "1.4"]`` -> ``"1.0-1.4"``; Appendix D's "{first}-{last}"."""
    values = _items(value)
    if not values:
        return ""
    if len(values) == 1:
        return values[0]
    return f"{values[0]}{_EN_DASH}{values[-1]}"


def listed(value: object, limit: int = MAX_LISTED) -> str:
    """``["a", "b", "c"]`` -> ``"a, b and c"``, capped so a question stays readable."""
    values = _items(value)
    if not values:
        return ""
    if len(values) > limit:
        head = ", ".join(values[:limit])
        rest = len(values) - limit
        return f"{head} and {rest} {'other' if rest == 1 else 'others'}"
    if len(values) == 1:
        return values[0]
    return f"{', '.join(values[:-1])} and {values[-1]}"


def short(value: object) -> str:
    """A commit as a human quotes it."""
    return _text(value)[:12]


@lru_cache(maxsize=1)
def environment() -> Environment:
    """The template environment, built once.

    ``autoescape`` is off on purpose: questions are plain text, pasted into a review
    comment or an email. The renderers that put them into HTML or Markdown escape them
    there (SPEC §15.2); escaping here would turn ``&`` in a symbol name into ``&amp;`` in
    a terminal.
    """
    env = Environment(
        loader=FileSystemLoader(TEMPLATE_DIR, encoding="utf-8"),
        undefined=StrictUndefined,
        autoescape=False,  # noqa: S701 - plain text out; the HTML and Markdown renderers escape.
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=False,
    )
    env.filters["ranged"] = ranged
    env.filters["listed"] = listed
    env.filters["short"] = short
    return env


def template_name(check_id: str, outcome: str) -> str | None:
    """``("C03", "never_in_history_core")`` -> ``"C03.never_in_history_core.j2"``."""
    if not _NAME_PART.match(check_id) or not _NAME_PART.match(outcome):
        return None
    return f"{check_id}.{outcome}{TEMPLATE_SUFFIX}"


def known_templates() -> tuple[str, ...]:
    """Every template file that exists, sorted. Used by the tone tests and by docs."""
    return tuple(sorted(environment().list_templates(extensions=["j2"])))


# --- the render context ----------------------------------------------------------------------


def _subject_of(evidence: Sequence[Evidence], claims: Sequence[Claim]) -> _Subject:
    """Name the target once, from the evidence locations first and the claims second."""
    ordered = sorted(evidence, key=lambda item: item.id)
    locations = [location for item in ordered for location in item.locations]
    repo = next((location.repo for location in locations if location.repo), None)
    ref = next((location.ref for location in locations if location.ref), None)
    commit = next((location.commit for location in locations if location.commit), None)

    versions = [claim for claim in claims if isinstance(claim, VersionClaim)]
    product = next((claim.product for claim in versions if claim.product), None)
    tested = next(
        (claim.raw for claim in versions if claim.relation == "tested_on" and claim.raw), None
    )
    spoken = next((claim.raw for claim in versions if claim.raw), None)
    return _Subject(
        project=product or _project_of(repo),
        version=ref or tested or spoken,
        commit=commit,
    )


def _project_of(repo: str | None) -> str | None:
    """The project name inside a clone URL, for sentences like "in curl 8.5.0"."""
    if not repo:
        return None
    name = repo.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")
    return name or None


def _context(item: Evidence, outcome: str, decision: Decision, subject: _Subject) -> dict[str, Any]:
    """Everything a template may reference, with ``None`` omitted rather than passed on.

    Dropping ``None`` is what makes :class:`~jinja2.StrictUndefined` useful: a check that
    recorded ``actual_function=None`` leaves the variable *undefined*, so a template either
    guards it with ``| default(...)`` or is skipped — neither path can print "None" to a
    reporter.
    """
    context: dict[str, Any] = {
        "check_id": item.check_id,
        "outcome": outcome,
        "group": item.group,
        "strength": item.strength,
        "verdict": decision.label,
        "score": decision.score,
        "target": subject.target,
        "where": subject.where,
        "details": dict(item.details),
        "locations": [location.model_dump(mode="json") for location in item.locations],
    }
    optional: dict[str, Any] = {
        "project": subject.project,
        "version": subject.version,
        "commit": subject.commit,
        "short_sha": subject.commit[:12] if subject.commit else None,
    }
    if item.locations:
        first = item.locations[0]
        optional |= {
            "repo": first.repo,
            "path": first.path,
            "line": first.start_line,
            "permalink": first.permalink,
        }
    # The check measured it, so the check's own words win over anything inferred above.
    optional |= dict(item.details)
    context |= {key: value for key, value in optional.items() if value is not None}
    return context


def _rationale(item: Evidence, outcome: str, decision: Decision) -> str:
    """Why this question is being asked, in ledger terms (P6).

    Deliberately built from the check ID, group, strength and verdict alone: it is a
    citation for the maintainer, not a second opinion about the report.
    """
    return (
        f"{item.check_id} ({item.group}/{outcome}) contributed {item.strength:+.2f} "
        f"to a {decision.label} verdict scored {decision.score}/100."
    )


# --- rendering ---------------------------------------------------------------------------------


def render_question(check_id: str, outcome: str, context: dict[str, Any]) -> str:
    """Render one template and normalize it to a single paragraph.

    Raises :class:`~jinja2.TemplateError` when the template is missing or the context does
    not carry a variable it needs. Callers inside a run use :func:`questions_for`, which
    swallows both; tests call this, where a broken template must be loud.
    """
    name = template_name(check_id, outcome)
    if name is None:
        raise TemplateError(f"unsafe template key {check_id!r}/{outcome!r}")
    rendered = environment().get_template(name).render(context)
    text = _SPACE_BEFORE_PUNCTUATION.sub("", " ".join(rendered.split()))
    if not text:
        raise TemplateError(f"{name} rendered nothing")
    return text if text.endswith(CLOSING) else f"{text} {CLOSING}"


def _try_render(item: Evidence, outcome: str, decision: Decision, subject: _Subject) -> str | None:
    """Render, or give up quietly.

    Most (check, outcome) pairs have no template, and that is the normal case, not an
    error: only findings a reporter can act on are worth a question. A template that does
    exist but cannot render is also swallowed here, because dropping one question is
    always better than failing a run that has already done all its work (P4).
    """
    try:
        return render_question(item.check_id, outcome, _context(item, outcome, decision, subject))
    except TemplateError:
        return None


# --- ordering ------------------------------------------------------------------------------------


def _rank(item: Evidence, decisive: frozenset[str]) -> tuple[int, float, float, str]:
    """Sort key: how much an answer would move the verdict (SPEC §14.4).

    1. Evidence the verdict rule actually fired on comes first. SPEC §14.3 rule 4 requires
       the version-mismatch question to be asked whenever the cap applies, and this is what
       guarantees it survives the cut at six.
    2. Then the absolute strength: the strongest evidence is the evidence whose correction
       would change the score most.
    3. Then the strength a gated finding *would* have carried (ADR 0003), which ranks the
       near-misses above the genuinely weightless ones without ever letting one outrank a
       finding that counted.
    4. Then the evidence ID, so the order never depends on how the checks were scheduled.
    """
    withheld = item.details.get("withheld_strength")
    numeric = isinstance(withheld, (int, float)) and not isinstance(withheld, bool)
    backup = abs(float(withheld)) if numeric else 0.0  # type: ignore[arg-type]
    return (0 if item.id in decisive else 1, -abs(item.strength), -backup, item.id)


def questions_for(
    decision: Decision,
    evidence: Sequence[Evidence],
    claims: Sequence[Claim],
) -> tuple[Question, ...]:
    """The questions to send back to the reporter, strongest first (SPEC §14.4).

    Deterministic for a given set of evidence: the order comes from :func:`_rank` and ties
    break on content-derived IDs, so two runs on the same report produce the same six
    questions in the same order (P2). Two findings that would ask the same thing are merged
    into one question citing both, because a reporter should never be asked twice.
    """
    subject = _subject_of(evidence, claims)
    decisive = frozenset(decision.key_evidence)
    order: list[str] = []
    cited: dict[str, list[str]] = {}
    rationales: dict[str, str] = {}

    for item in sorted(evidence, key=lambda e: _rank(e, decisive)):
        if item.outcome == "ERROR":
            continue
        outcome = outcome_key(item)
        if outcome is None:
            continue
        text = _try_render(item, outcome, decision, subject)
        if text is None:
            continue
        if text not in cited:
            if len(order) >= MAX_QUESTIONS:
                continue  # full, but keep going: a later item may belong to a question above
            order.append(text)
            cited[text] = []
            rationales[text] = _rationale(item, outcome, decision)
        cited[text].append(item.id)

    return tuple(
        Question(
            text=text,
            rationale=rationales[text],
            evidence_ids=tuple(sorted(set(cited[text]))),
        )
        for text in order
    )


__all__ = [
    "CLOSING",
    "MAX_QUESTIONS",
    "TEMPLATE_DIR",
    "environment",
    "known_templates",
    "questions_for",
    "render_question",
    "template_name",
]
