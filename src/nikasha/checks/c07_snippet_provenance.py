# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""C07 SNIPPET_PROVENANCE: does this quoted snippet come from the code? (SPEC §12)

C06 asks whether one quoted *line* sits at the line the report cites. This check asks the
larger question: a report pastes fifteen lines of C under "Vulnerable code" — are those
lines in the tree at the version it names, and where?

The answer is winnowing fingerprints (:mod:`nikasha.code.fingerprint`, SPEC §11.4), which
survive reformatting, re-commenting and changed literals but not renamed identifiers. That
is the right sensitivity: a genuine reporter's paste differs from the file by indentation
and elisions, a fabricated one differs by having no source at all.

Fingerprinting the whole tree per snippet would cost seconds per report, so the commit is
first narrowed with a capped ``git grep -F`` (:mod:`nikasha.code.literal`) on the snippet's
most distinctive line and its rarest identifiers. Only those candidates are fingerprinted,
ranked by :func:`~nikasha.code.fingerprint.containment`, and the best few aligned with
:func:`~nikasha.code.fingerprint.align` — which measures containment exactly and yields the
file line range the evidence points at.

Two conservative rules shape everything below (P4):

* **"Nowhere" must be earned.** ``absent_everywhere`` (-2.5) is the strongest thing this
  check can say, so it is emitted only once the ref, the sampled releases *and* ``log -S``
  on the rarest identifier have all come back empty, and only when every one of those
  searches finished. A spent budget or a pickaxe timeout downgrades it to NEUTRAL with the
  reason named.
* **Generated files are not judged.** A snippet attributed to, or found in, a SPEC §11.5
  generated or release-only file is NEUTRAL with a note.
"""

from __future__ import annotations

import shlex
from collections.abc import Sequence
from dataclasses import dataclass, field

from nikasha.checks.base import BaseCheck, CheckContext, make_evidence, register
from nikasha.checks.strengths import Strengths, default_strengths
from nikasha.code.fingerprint import (
    DEFAULT_K,
    DEFAULT_W,
    NUM,
    STR,
    Fingerprint,
    Token,
    align,
    containment,
    fingerprint_tokens,
    tokenize,
)
from nikasha.code.gitio import HistoryTimeoutError
from nikasha.code.languages import detect_language
from nikasha.code.literal import literal_search, searchable
from nikasha.model.claims import Claim, ClaimKind, SnippetClaim
from nikasha.model.evidence import CodeLocation, CommandRecord, Evidence, Outcome
from nikasha.resolve.refs import Release

CHECK_ID = "C07"
GROUP = "code_quotes"

#: SPEC §12: at or above this containment the snippet *is* that piece of the file.
CONTAINED_AT = 0.85
#: Between this and :data:`CONTAINED_AT` the snippet is modified, elided or partial.
PARTIAL_AT = 0.5
#: Below this everywhere searched, the snippet is absent — subject to the P4 rule above.
ABSENT_BELOW = 0.3
#: SPEC §12: a snippet this big carries full weight; a smaller one is multiplied by 0.3.
FULL_WEIGHT_LINES = 3
FULL_WEIGHT_TOKENS = 25
#: Below this many tokens winnowing selects nothing, so alignment is the only tool left.
MIN_FINGERPRINT_TOKENS = DEFAULT_W + DEFAULT_K - 1

#: Search bounds. These cap the work per snippet; ``ctx.expired()`` caps it per report.
MAX_CANDIDATES = 12
MAX_ALIGNED = 3
MAX_LITERAL_HITS = 40
MAX_IDENT_PROBES = 2
MAX_RELEASES = 8
RELEASE_RADIUS = 4
#: A line shorter than this is not distinctive enough to be worth a grep.
MIN_LINE_CHARS = 10
MIN_IDENT_CHARS = 4
#: The hard ceiling on the file tokens one alignment sees, for the pathological case where
#: shared fingerprints are scattered through a multi-megabyte file (``difflib`` is quadratic).
ALIGN_WINDOW_TOKENS = 20_000
_HEAD_BYTES = 4096

#: Keywords make terrible probes: they are in every file, so they narrow nothing. This is a
#: cross-language stoplist, not a grammar — a name missing from it only costs one grep.
_KEYWORDS = frozenset(
    """
    async await bool break case catch char class const constexpr continue default defer
    delete double elif else enum export extern false final finally float from func function
    global goto impl import inline instanceof interface lambda let long match module
    mutable namespace native none null nullptr operator package pass private protected
    public raise register return self short signed sizeof static struct super switch
    template then this throw throws trait true type typedef typeof union unsigned using
    var virtual void volatile where while with yield
    """.split()
)


# --- the snippet, prepared once ----------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Snippet:
    """A quoted snippet reduced to what searching and scoring need."""

    tokens: tuple[Token, ...]
    fingerprints: tuple[Fingerprint, ...]
    hashes: frozenset[int]
    #: Lines carrying at least one token: blank and comment-only lines are not code.
    code_lines: int
    #: Literals to grep for, most distinctive first.
    probes: tuple[str, ...]
    identifiers: tuple[str, ...]

    @property
    def small(self) -> bool:
        """Below the SPEC §12 size at which a snippet carries its full weight."""
        return self.code_lines < FULL_WEIGHT_LINES and len(self.tokens) < FULL_WEIGHT_TOKENS

    @property
    def fingerprinted(self) -> bool:
        return bool(self.fingerprints)


@dataclass(frozen=True, slots=True)
class _Match:
    """Where a snippet was found at one revision, and how much of it was there."""

    ref: str
    path: str
    containment: float
    start_line: int | None
    end_line: int | None

    def key(self) -> tuple[float, str]:
        """The sort key that makes "the best match" deterministic when containments tie."""
        return (-self.containment, self.path)

    def as_details(self) -> dict[str, object]:
        return {
            "ref": self.ref,
            "path": self.path,
            "containment": round(self.containment, 3),
            "lines": [self.start_line, self.end_line],
        }


def _lang(claim: SnippetClaim) -> str | None:
    """The language to lex the snippet as: the fence's hint, else the attributed file's."""
    if claim.lang_hint:
        return claim.lang_hint
    if claim.attributed_path:
        found = detect_language(claim.attributed_path)
        if found is not None:
            return str(found)
    return None


def _identifiers(tokens: Sequence[Token]) -> tuple[str, ...]:
    """Identifiers worth grepping for, longest first.

    Length is the cheapest proxy for rarity; :meth:`_Scan.rarest` refines it afterwards
    with the hit counts the greps actually measured.
    """
    names = {
        token.text
        for token in tokens
        if len(token.text) >= MIN_IDENT_CHARS
        and token.text not in (STR, NUM)
        and token.text not in _KEYWORDS
        and (token.text[0].isalpha() or token.text[0] == "_")
        and token.text.isidentifier()
    }
    return tuple(sorted(names, key=lambda name: (-len(name), name)))


def _distinctive_line(code: str, tokens: Sequence[Token]) -> str | None:
    """The snippet line carrying the most tokens (ties: the longest, then the earliest).

    Counting *tokens* rather than characters keeps a long comment or a row of dashes from
    being chosen: the lexer has already dropped comments, so those lines score zero.
    """
    counts: dict[int, int] = {}
    for token in tokens:
        counts[token.line] = counts.get(token.line, 0) + 1
    lines = code.splitlines()
    best: tuple[int, int, int] | None = None
    for line_no, count in counts.items():
        text = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else ""
        if len(text) < MIN_LINE_CHARS or searchable(text) is None:
            continue
        key = (-count, -len(text), line_no)
        if best is None or key < best:
            best = key
    return lines[best[2] - 1].strip() if best is not None else None


def _prepare(claim: SnippetClaim) -> _Snippet | None:
    """Tokenize, fingerprint and pick search probes; ``None`` when there is nothing to find."""
    tokens = tuple(tokenize(claim.code, _lang(claim)))
    if not tokens:
        return None
    identifiers = _identifiers(tokens)
    probes: list[str] = []
    for candidate in (_distinctive_line(claim.code, tokens), *identifiers[:MAX_IDENT_PROBES]):
        text = searchable(candidate) if candidate else None
        if text is not None and text not in probes:
            probes.append(text)
    fingerprints = tuple(fingerprint_tokens(tokens))
    return _Snippet(
        tokens=tokens,
        fingerprints=fingerprints,
        hashes=frozenset(fp.hash for fp in fingerprints),
        code_lines=len({token.line for token in tokens}),
        probes=tuple(probes),
        identifiers=identifiers,
    )


# --- searching -----------------------------------------------------------------------------


@dataclass
class _Scan:
    """Per-report search state: tokenized files, probe hit counts and the commands run.

    One report can quote the same file a dozen times; tokenizing and fingerprinting it once
    per snippet instead of once per quote is the difference between a check that fits its
    budget and one that does not.
    """

    ctx: CheckContext
    _files: dict[tuple[str, str], tuple[tuple[Token, ...], tuple[Fingerprint, ...]]] = field(
        default_factory=dict, repr=False
    )
    _hits: dict[tuple[str, str], int] = field(default_factory=dict, repr=False)
    #: The greps and pickaxes run for the *current* snippet, so each evidence item records
    #: only the commands behind it (P6). File tokens stay cached across snippets.
    #: ``commands`` holds the re-runnable command *strings* (``literal_search`` surfaces
    #: nothing else); ``records`` holds the full :class:`CommandRecord` for the
    #: invocations made through :class:`~nikasha.code.gitio.GitRepo` itself.
    commands: list[str] = field(default_factory=list)
    records: list[CommandRecord] = field(default_factory=list)

    def file(self, commit: str, path: str) -> tuple[tuple[Token, ...], tuple[Fingerprint, ...]]:
        """The tokens and fingerprints of ``path`` at ``commit`` (empty when unreadable)."""
        cached = self._files.get((commit, path))
        if cached is not None:
            return cached
        entry = self.ctx.index.file_at(commit, path)
        blob = self.ctx.resolution.repo.read_blob(entry.blob) if entry is not None else None
        tokens: tuple[Token, ...] = ()
        if blob is not None:
            lang = detect_language(path, blob[:_HEAD_BYTES])
            tokens = tuple(tokenize(blob.decode("utf-8", "replace"), lang))
        result = (tokens, tuple(fingerprint_tokens(tokens)) if tokens else ())
        self._files[(commit, path)] = result
        return result

    def candidates(self, commit: str, snippet: _Snippet) -> list[tuple[str, int]]:
        """Paths at ``commit`` holding one of the snippet's probes, with the probe's rank.

        The rank matters: a file holding the snippet's most distinctive *line* is a better
        candidate than one that merely mentions an identifier from it, and only the best few
        candidates are aligned.
        """
        found_at: dict[str, int] = {}
        for rank, probe in enumerate(snippet.probes):
            if self.ctx.expired() or len(found_at) >= MAX_CANDIDATES:
                break
            result = literal_search(
                self.ctx.resolution.repo, probe, commit, max_hits=MAX_LITERAL_HITS
            )
            if result is None:
                continue
            if result.command not in self.commands:
                self.commands.append(result.command)
            self._hits[(commit, probe)] = len(result.hits)
            for path in result.paths:
                found_at.setdefault(path, rank)
        return list(found_at.items())[:MAX_CANDIDATES]

    def best_at(self, commit: str, ref: str, snippet: _Snippet) -> _Match | None:
        """The best-containing file for ``snippet`` at ``commit``, aligned for line numbers.

        Fingerprint containment ranks the candidates cheaply; alignment then measures the
        top few exactly, because a file can share fingerprints with a snippet without
        containing it as a run.
        """
        ranked: list[tuple[float, int, str]] = []
        for path, rank in self.candidates(commit, snippet):
            tokens, fingerprints = self.file(commit, path)
            if tokens:
                ranked.append((containment(snippet.fingerprints, fingerprints), rank, path))
        ranked.sort(key=lambda item: (-item[0], item[1], item[2]))
        best: _Match | None = None
        for _, _, path in ranked[:MAX_ALIGNED]:
            if self.ctx.expired():
                break
            tokens, fingerprints = self.file(commit, path)
            aligned = align(snippet.tokens, _narrow(tokens, fingerprints, snippet))
            found = _Match(ref, path, aligned.containment, aligned.start_line, aligned.end_line)
            if best is None or found.key() < best.key():
                best = found
        return best

    def elsewhere(self, snippet: _Snippet) -> tuple[_Match | None, list[str], bool]:
        """The best match across the sampled releases, their names, and whether all ran."""
        best: _Match | None = None
        scanned: list[str] = []
        for release in _sampled(self.ctx):
            if self.ctx.expired():
                return best, scanned, False
            scanned.append(release.name)
            found = self.best_at(release.commit, release.name, snippet)
            if found is not None and (best is None or found.key() < best.key()):
                best = found
        return best, scanned, True

    def rarest(self, snippet: _Snippet) -> str | None:
        """The snippet identifier with the fewest matches at the ref, else the longest one.

        SPEC §12 pickaxes "the rarest identifier". The greps already run give real counts
        for the probed ones, and everything else falls back to the length ordering.
        """
        if not snippet.identifiers:
            return None
        return min(
            snippet.identifiers,
            key=lambda name: (
                self._hits.get((self.ctx.commit, name), MAX_LITERAL_HITS + 1),
                -len(name),
                name,
            ),
        )

    def never_in_history(self, term: str) -> bool | None:
        """Whether ``git log --all -S<term>`` finds nothing; ``None`` when it could not run.

        A pickaxe that timed out leaves no record behind: there is no exit code and no
        output to hash, and a fabricated one would be worse than none (P6).
        """
        try:
            first = self.ctx.resolution.repo.pickaxe_first(term, record=self.records)
        except HistoryTimeoutError:
            return None
        command = shlex.join(["git", "log", "--all", "-1", "--format=%H", f"-S{term}"])
        if command not in self.commands:
            self.commands.append(command)
        return first is None


def _narrow(
    tokens: tuple[Token, ...], fingerprints: tuple[Fingerprint, ...], snippet: _Snippet
) -> Sequence[Token]:
    """The region of a file whose fingerprints ``snippet`` shares, padded by its length.

    Alignment is quadratic, and it is *global*: run against a whole file, an eleven-line
    snippet happily reports "hdr.c:14-156" by stitching together runs from three different
    functions. Aligning inside the densest region of shared fingerprints keeps both the cost
    and the reported line range proportional to the snippet, and the winnowing guarantee
    says a genuine match cannot hide outside that region. Line numbers travel with the
    tokens, so the range stays correct.

    A snippet with no fingerprints (or none in common) is aligned against the whole file:
    that is the documented fallback for snippets shorter than one window.
    """
    span = max(len(snippet.tokens), MIN_FINGERPRINT_TOKENS)
    positions = sorted(fp.position for fp in fingerprints if fp.hash in snippet.hashes)
    if not positions:
        return tokens[:ALIGN_WINDOW_TOKENS]
    first, last = _cluster(positions, 2 * span)
    low = max(0, first - span)
    high = min(len(tokens), last + span + DEFAULT_K, low + ALIGN_WINDOW_TOKENS)
    return tokens[low:high]


def _cluster(positions: Sequence[int], gap: int) -> tuple[int, int]:
    """The largest run of sorted ``positions`` with no neighbours more than ``gap`` apart.

    The gap is generous (twice the snippet) because a reporter's quote may elide lines the
    file has, which stretches the region without meaning it is a different region. Ties keep
    the earliest run, so the choice does not depend on iteration order.
    """
    best = (0, positions[0], positions[0])
    start = 0
    for i in range(1, len(positions) + 1):
        if i == len(positions) or positions[i] - positions[i - 1] > gap:
            if i - start > best[0]:
                best = (i - start, positions[start], positions[i - 1])
            start = i
    return best[1], best[2]


def _sampled(ctx: CheckContext) -> list[Release]:
    """The releases searched besides the ref: a window around the target, else the finals."""
    releases = ctx.resolution.releases
    target = ctx.resolution.release
    pool = releases.window(target, RELEASE_RADIUS) if target is not None else []
    if not pool:
        pool = releases.finals()
    return [release for release in pool if release.commit != ctx.commit][:MAX_RELEASES]


# --- the check -------------------------------------------------------------------------------


@register
class SnippetProvenance(BaseCheck):
    id = CHECK_ID
    name = "SNIPPET_PROVENANCE"
    group = GROUP
    applies_to: frozenset[ClaimKind] = frozenset({"snippet"})
    description = "Locates a quoted code snippet in the tree with winnowing fingerprints."

    def __init__(self, strengths: Strengths | None = None) -> None:
        self.strengths = strengths or default_strengths()

    def run(self, ctx: CheckContext, claims: Sequence[Claim]) -> list[Evidence]:
        scan = _Scan(ctx)
        out: list[Evidence] = []
        for claim in claims:
            if not isinstance(claim, SnippetClaim):
                continue
            evidence = self._one(scan, claim)
            if evidence is not None:
                out.append(evidence)
        return out

    # -- one snippet ----------------------------------------------------------------------

    def _one(self, scan: _Scan, claim: SnippetClaim) -> Evidence | None:
        ctx = scan.ctx
        scan.commands.clear()
        scan.records.clear()
        snippet = _prepare(claim)
        if snippet is None:
            return None  # comments and prose only: there is nothing to look for
        if claim.attributed_path is not None:
            generated = ctx.generated(claim.attributed_path)
            if generated is not None:
                return self._neutral(
                    claim,
                    snippet,
                    scan,
                    f"the snippet is attributed to {claim.attributed_path}, which is"
                    f" {generated.kind}, so its contents are not judged",
                    {"attributed_path": claim.attributed_path, "generated": generated.reason},
                    label="generated",
                )
        ref = ctx.ref_name or ctx.commit[:12]
        here = scan.best_at(ctx.commit, ref, snippet)
        if here is not None:
            generated = ctx.generated(here.path)
            if generated is not None:
                return self._neutral(
                    claim,
                    snippet,
                    scan,
                    f"the snippet matches {here.path}, which is {generated.kind},"
                    " so it is not judged",
                    {"here": here.as_details(), "generated": generated.reason},
                    label="generated",
                )
            if here.containment >= CONTAINED_AT:
                return self._located(claim, snippet, scan, here, "contained")
            if here.containment >= PARTIAL_AT:
                return self._located(claim, snippet, scan, here, "partial")
        return self._not_here(scan, claim, snippet, here)

    def _not_here(
        self, scan: _Scan, claim: SnippetClaim, snippet: _Snippet, here: _Match | None
    ) -> Evidence:
        """Below :data:`PARTIAL_AT` at the ref: look at the other releases, then at history."""
        ctx = scan.ctx
        ref = ctx.ref_name or ctx.commit[:12]
        found = here.containment if here is not None else 0.0
        other, scanned, complete = scan.elsewhere(snippet)
        base: dict[str, object] = {
            "here": here.as_details() if here is not None else None,
            "containment": round(found, 3),
            "sampled_releases": scanned,
            "elsewhere": other.as_details() if other is not None else None,
        }
        if other is not None and other.containment >= CONTAINED_AT:
            return self._emit(
                claim,
                snippet,
                scan,
                outcome="REFUTES",
                key="other_release_only",
                summary=f"the snippet matches {other.path} in {other.ref}"
                f" (containment {other.containment:.2f}) but not at {ref}"
                f" (containment {found:.2f})",
                details=base,
            )
        best_other = other.containment if other is not None else 0.0
        if max(found, best_other) >= ABSENT_BELOW:
            return self._neutral(
                claim,
                snippet,
                scan,
                f"parts of the snippet are in the tree at {ref} (containment {found:.2f}),"
                " but not enough of it to say where it came from",
                base,
                label="insufficient_containment",
            )
        term = scan.rarest(snippet)
        never = scan.never_in_history(term) if complete and term is not None else None
        details = {**base, "history_term": term, "history_complete": never is not None}
        if never is None:
            return self._neutral(
                claim,
                snippet,
                scan,
                self._incomplete(ref, complete, term),
                details,
                label="search_incomplete",
            )
        if not never:
            return self._neutral(
                claim,
                snippet,
                scan,
                f"the snippet is not in the tree at {ref} or in {len(scanned)} sampled"
                f" releases, but history still contains {term!r}, so it is not called absent",
                details,
                label="found_in_history",
            )
        return self._emit(
            claim,
            snippet,
            scan,
            outcome="REFUTES",
            key="absent_everywhere",
            summary=f"the snippet is not at {ref}, in {len(scanned)} sampled releases, or"
            f" anywhere in history: best containment {max(found, best_other):.2f}, and no"
            f" commit ever added or removed {term!r}",
            details=details,
        )

    @staticmethod
    def _incomplete(ref: str, complete: bool, term: str | None) -> str:
        """Why absence was not claimed although nothing was found (P4)."""
        if not complete:
            reason = "the release search did not finish"
        elif term is None:
            reason = "the snippet has no identifier distinctive enough to search history for"
        else:
            reason = f"the history search for {term!r} did not finish"
        return f"the snippet is not in the tree at {ref}, but {reason}, so it is not called absent"

    # -- evidence -------------------------------------------------------------------------

    def _located(
        self, claim: SnippetClaim, snippet: _Snippet, scan: _Scan, match: _Match, key: str
    ) -> Evidence:
        lines = f"{match.start_line}-{match.end_line}" if match.start_line else "an unknown range"
        modified = "" if key == "contained" else "; it has been modified, elided or reformatted"
        return self._emit(
            claim,
            snippet,
            scan,
            outcome="SUPPORTS",
            key=key,
            summary=f"the snippet matches {match.path}:{lines} at {match.ref}"
            f" (containment {match.containment:.2f}){modified}",
            details={"here": match.as_details(), "containment": round(match.containment, 3)},
            location=_location(scan.ctx, match),
        )

    def _neutral(
        self,
        claim: SnippetClaim,
        snippet: _Snippet,
        scan: _Scan,
        summary: str,
        details: dict[str, object],
        *,
        label: str,
    ) -> Evidence:
        return self._emit(
            claim,
            snippet,
            scan,
            outcome="NEUTRAL",
            key=None,
            label=label,
            summary=summary,
            details=details,
        )

    def _emit(
        self,
        claim: SnippetClaim,
        snippet: _Snippet,
        scan: _Scan,
        *,
        outcome: Outcome,
        key: str | None,
        label: str | None = None,
        summary: str,
        details: dict[str, object],
        location: CodeLocation | None = None,
    ) -> Evidence:
        """Score, record how the snippet was measured, and build the evidence.

        ``key`` names the row in the LR table; ``label`` names the outcome of a finding that
        has no row, so ``details['outcome']`` always says what was concluded rather than
        leaving the fuser to read it off a strength of zero (SPEC §14.3).
        """
        strength = 0.0
        if key is not None:
            strength = self.strengths.get(CHECK_ID, key)
            if snippet.small:
                strength *= self.strengths.get(CHECK_ID, "small_snippet_multiplier")
        note = " (a small snippet, so its weight is reduced)" if snippet.small else ""
        if not snippet.fingerprinted:
            note += (
                f" (fewer than {MIN_FINGERPRINT_TOKENS} tokens, so it has no fingerprints"
                " and was matched by alignment alone)"
            )
        payload: dict[str, object] = {
            **details,
            "outcome": key if key is not None else label,
            "outcome_key": key,
            "tokens": len(snippet.tokens),
            "code_lines": snippet.code_lines,
            "small_snippet": snippet.small,
            "method": "fingerprint" if snippet.fingerprinted else "align",
            "searched": list(scan.commands),
        }
        return make_evidence(
            check_id=CHECK_ID,
            group=GROUP,
            claims=[claim],
            outcome=outcome,
            strength=strength,
            summary=summary + note,
            details=payload,
            locations=[location] if location is not None else [],
            commands=tuple(scan.records),
        )


def _location(ctx: CheckContext, match: _Match) -> CodeLocation | None:
    """The evidence location for a match, when alignment produced a line range."""
    if match.start_line is None or match.end_line is None:
        return None
    return ctx.location(match.path, match.start_line, match.end_line)
