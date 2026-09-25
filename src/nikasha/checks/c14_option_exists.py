# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""C14 OPTION_EXISTS: does this flag, constant or config key exist at the claimed version?

"``--proxy-unsafe-fold`` is not a curl option in any release" is the kind of fact a literal
search settles outright, and the kind an invented report gets wrong: a plausible flag costs
nothing to write and a lot of a maintainer's time to disprove by hand.

The search covers the **whole tree** — man pages and ``docs/`` as much as source — because
an option is documented as well as implemented, and a flag that appears only in a man page
is still a real flag. It is a fixed-string ``git grep -w -F`` through
:mod:`nikasha.code.literal`, so the token (report text, therefore attacker-controlled) is
only ever a pattern after ``-e``, never an option position (SPEC §19.3). ``-w`` matters:
without it ``hdr_find`` would "exist" because ``hdr_find_line`` does.

P4 governs every negative answer. "Never in history" is said only after a *completed*
pickaxe over all refs; a shallow clone, a timed-out search or a spent budget mean the
search was incomplete, and an incomplete search is not evidence of absence. A constant or
config key seen only in generated files is not judged at all: the file that defines it may
simply not be checked in at this release (SPEC §11.5).
"""

from __future__ import annotations

import shlex
from collections.abc import Sequence
from pathlib import PurePosixPath
from typing import Any

from nikasha.checks.base import BaseCheck, CheckContext, make_evidence, register
from nikasha.checks.strengths import Strengths, default_strengths
from nikasha.code.gitio import GitRepo, HistoryTimeoutError, HistoryUnavailableError
from nikasha.code.literal import LiteralResult, literal_search
from nikasha.errors import ExternalToolError
from nikasha.model.claims import Claim, ClaimKind, OptionClaim
from nikasha.model.evidence import CommandRecord, Evidence
from nikasha.resolve.refs import Release

CHECK_ID = "C14"
GROUP = "locus"

#: Hits kept from the tree at the ref: enough to prove the option is there, never a whole
#: generated help file.
MAX_HITS = 50
#: Files the release sweep will look at before it stops caring how many more there are.
MAX_SWEEP_FILES = 500
#: Paths, release names and locations carried in the evidence.
MAX_PATHS = 10
MAX_LOCATIONS = 3

#: Option kinds whose absence can be an artefact of a file that is generated at build time,
#: and which therefore may not be refuted on generated-only evidence (SPEC §11.5).
GENERATED_SENSITIVE: frozenset[str] = frozenset({"constant", "config_key"})

_DOC_DIRS = frozenset({"doc", "docs", "documentation", "man", "manpages"})
_DOC_SUFFIXES = frozenset({".1", ".3", ".8", ".adoc", ".html", ".md", ".pod", ".rst", ".txt"})
_DOC_STEMS = frozenset({"changelog", "changes", "news", "readme"})


def is_doc(path: str) -> bool:
    """Whether ``path`` is documentation rather than code (a man page, ``docs/``, a README).

    Only used to describe *where* the option was found; the search itself never excludes
    anything, because for an option the documentation is as authoritative as the source.
    """
    parts = PurePosixPath(path)
    return (
        any(part.lower() in _DOC_DIRS for part in parts.parts[:-1])
        or parts.suffix.lower() in _DOC_SUFFIXES
        or parts.stem.lower() in _DOC_STEMS
    )


def generated_reasons(ctx: CheckContext, paths: Sequence[str]) -> list[str]:
    """Why each of ``paths`` is generated, or ``[]`` as soon as one of them is real code.

    The caller refutes only when this is empty: a constant that lives solely in
    ``config.h`` says nothing about the release that does not check ``config.h`` in.
    """
    reasons: list[str] = []
    for path in paths:
        match = ctx.generated(path)
        if match is None:
            return []
        reasons.append(f"{path}: {match.reason}")
    return reasons


def _listed(items: Sequence[str], limit: int = MAX_PATHS) -> str:
    return ", ".join(items[:limit]) + (", ..." if len(items) > limit else "")


def _sweep_command(token: str, names: Sequence[str]) -> str:
    argv = ["git", "grep", "-l", "-I", "-F", "-w", "-e", token, *names[:MAX_PATHS]]
    return shlex.join(argv) + (" ..." if len(names) > MAX_PATHS else "")


@register
class OptionExists(BaseCheck):
    id = CHECK_ID
    name = "OPTION_EXISTS"
    group = GROUP
    applies_to: frozenset[ClaimKind] = frozenset({"option"})
    description = "Checks that a cited flag, constant or config key exists in the source or docs."

    def __init__(self, strengths: Strengths | None = None) -> None:
        self.strengths = strengths or default_strengths()

    def run(self, ctx: CheckContext, claims: Sequence[Claim]) -> list[Evidence]:
        out: list[Evidence] = []
        for claim in claims:
            if not isinstance(claim, OptionClaim):
                continue
            evidence = self._one(ctx, claim)
            if evidence is not None:
                out.append(evidence)
        return out

    def _one(self, ctx: CheckContext, claim: OptionClaim) -> Evidence | None:
        at_ref = literal_search(
            ctx.resolution.repo, claim.token, ctx.commit, word=True, max_hits=MAX_HITS
        )
        if at_ref is None:
            # Empty, multi-line or absurdly long: nothing a literal search can settle.
            return None
        if at_ref.hits:
            return self._present(ctx, claim, at_ref)
        return self._absent(ctx, claim, at_ref)

    # --- the option is there ------------------------------------------------------------

    def _present(self, ctx: CheckContext, claim: OptionClaim, at_ref: LiteralResult) -> Evidence:
        hits = sorted(at_ref.hits, key=lambda hit: (hit.path, hit.line))
        paths = sorted(at_ref.paths)
        docs_only = all(is_doc(path) for path in paths)
        details = self._common(claim, at_ref, [at_ref.command])
        details |= {
            "outcome": "present",
            "paths": paths[:MAX_PATHS],
            "n_paths": len(paths),
            "documented": any(is_doc(path) for path in paths),
            "truncated": at_ref.truncated,
        }
        return make_evidence(
            check_id=CHECK_ID,
            group=GROUP,
            claims=[claim],
            outcome="SUPPORTS",
            strength=self.strengths.get(CHECK_ID, "present"),
            summary=f"{at_ref.literal} appears at {_where(ctx)} in {_listed(paths)}"
            + (" (documentation only)" if docs_only else ""),
            details=details,
            locations=[
                ctx.location(hit.path, hit.line, excerpt=hit.text.strip())
                for hit in hits[:MAX_LOCATIONS]
            ],
        )

    # --- the option is not there ---------------------------------------------------------

    def _absent(self, ctx: CheckContext, claim: OptionClaim, at_ref: LiteralResult) -> Evidence:
        # ``literal_search`` surfaces only a command *string*, so the search at the ref
        # stays in ``details['commands']``; the release sweep and the pickaxe below run
        # through ``GitRepo``, which hands back real records (P6).
        records: list[CommandRecord] = []
        named, name_commands = self._named_only(ctx, claim, at_ref)
        if named is not None:
            return named
        others = [r for r in ctx.resolution.releases.finals() if r.commit != ctx.commit]
        if ctx.expired():
            # Nothing was searched beyond the ref, so there is no refutation to withhold.
            return self._incomplete(
                ctx,
                claim,
                at_ref,
                [at_ref.command],
                "the check's time budget ran out before the other releases",
                withheld=0.0,
                records=records,
            )
        found, command = self._sweep(ctx, at_ref.literal, others, records)
        commands = [at_ref.command, *name_commands, command]
        if found:
            return self._other_release_only(ctx, claim, at_ref, found, commands, records=records)
        return self._never(ctx, claim, at_ref, others, commands, records=records)

    def _named_only(
        self, ctx: CheckContext, claim: OptionClaim, at_ref: LiteralResult
    ) -> tuple[Evidence | None, list[str]]:
        """NEUTRAL when the option's *name* is in the tree at the ref though its spelling is not.

        Many real options never appear spelled the way a user types them: a getopt table or
        Go's ``flag`` package holds ``"fold"`` for ``--fold``, clap derives ``--max-lines``
        from a ``max_lines`` field, a man page writes ``\\-\\-fold``, and an INI file keeps
        ``key`` under ``[section]`` rather than ``section.key``. When every part of the name
        is there, a missing literal is not evidence the option was invented (P4).

        Also returns the searches that ran, so a later refutation can show them (P6).
        """
        commands: list[str] = []
        found: dict[str, list[str]] = {}
        forms = _name_forms(claim.option_kind, at_ref.literal)
        for form in forms:
            if ctx.expired():
                break
            result = literal_search(
                ctx.resolution.repo, form, ctx.commit, word=True, max_hits=MAX_LOCATIONS
            )
            if result is None:
                continue
            commands.append(result.command)
            if result.hits:
                found[form] = sorted(result.paths)
        needed = forms if claim.option_kind == "config_key" else list(found)
        if not found or any(form not in found for form in needed):
            return None, commands
        names = sorted(found)
        paths = sorted({path for form_paths in found.values() for path in form_paths})
        details = self._common(claim, at_ref, [at_ref.command, *commands])
        details |= {"outcome": "name_only", "names": names, "paths": paths[:MAX_PATHS]}
        return make_evidence(
            check_id=CHECK_ID,
            group=GROUP,
            claims=[claim],
            outcome="NEUTRAL",
            strength=0.0,
            summary=f"{at_ref.literal} is not spelled out at {_where(ctx)}, but its name"
            f" ({_listed(names)}) is, in {_listed(paths)}; the option may be declared by name,"
            " so its absence is not evidence",
            details=details,
        ), commands

    def _sweep(
        self,
        ctx: CheckContext,
        token: str,
        others: Sequence[Release],
        records: list[CommandRecord],
    ) -> tuple[list[tuple[str, tuple[str, ...]]], str]:
        """Which of ``others`` contain ``token``, and the git command that asked.

        One batched grep over every other release tree, rather than one process per
        release: a project with 250 tags must not cost 250 git invocations. The hit cap can
        shorten the list of releases reported, never turn a hit into a miss, so it cannot
        manufacture a "never in history" (P4).
        """
        if not others:
            return [], ""
        hits = ctx.resolution.repo.grep(
            token,
            [release.commit for release in others],
            word=True,
            files_only=True,
            max_hits=MAX_SWEEP_FILES,
            record=records,
        )
        by_commit: dict[str, set[str]] = {}
        for hit in hits:
            by_commit.setdefault(hit.rev, set()).add(hit.path)
        found = [
            (release.name, tuple(sorted(by_commit[release.commit])))
            for release in others
            if release.commit in by_commit
        ]
        return found, _sweep_command(token, [release.name for release in others])

    def _other_release_only(
        self,
        ctx: CheckContext,
        claim: OptionClaim,
        at_ref: LiteralResult,
        found: Sequence[tuple[str, tuple[str, ...]]],
        commands: Sequence[str],
        *,
        records: Sequence[CommandRecord] = (),
    ) -> Evidence:
        names = [name for name, _ in found]
        paths = sorted({path for _, release_paths in found for path in release_paths})
        details = self._common(claim, at_ref, commands)
        details |= {"releases": names[:MAX_PATHS], "n_releases": len(names), "paths": paths}
        generated = (
            generated_reasons(ctx, paths) if claim.option_kind in GENERATED_SENSITIVE else []
        )
        if generated:
            # P4: the file it lives in is built, not committed, so this release proves nothing.
            details["generated"] = generated
            details["outcome"] = "generated"
            return make_evidence(
                check_id=CHECK_ID,
                group=GROUP,
                claims=[claim],
                outcome="NEUTRAL",
                strength=0.0,
                summary=f"{at_ref.literal} is absent at {_where(ctx)} and appears in"
                f" {_listed(names)} only in generated files, which are not judged",
                details=details,
                commands=records,
            )
        return make_evidence(
            check_id=CHECK_ID,
            group=GROUP,
            claims=[claim],
            outcome="REFUTES",
            strength=self.strengths.get(CHECK_ID, "other_release_only"),
            summary=f"{at_ref.literal} does not appear at {_where(ctx)};"
            f" it appears in {_listed(names)} ({_listed(paths)})",
            details=details | {"outcome": "other_release_only"},
            commands=records,
        )

    def _never(
        self,
        ctx: CheckContext,
        claim: OptionClaim,
        at_ref: LiteralResult,
        others: Sequence[Release],
        commands: Sequence[str],
        *,
        records: list[CommandRecord],
    ) -> Evidence:
        """Nothing in any release: only a completed history search may call that fabricated."""
        repo = ctx.resolution.repo
        searched = len(others) + 1
        never = self.strengths.get(CHECK_ID, "never_in_history")
        blocked = self._history_blocked(ctx, at_ref.literal)
        if blocked is not None:
            return self._incomplete(
                ctx, claim, at_ref, commands, blocked, withheld=never, records=records
            )
        try:
            first = repo.pickaxe_first(at_ref.literal, timeout=ctx.history_timeout, record=records)
        except HistoryTimeoutError as exc:
            reason = f"the history search did not finish ({exc})"
            return self._incomplete(
                ctx, claim, at_ref, commands, reason, withheld=never, records=records
            )
        pickaxe = shlex.join(["git", "log", "--all", "-1", f"-S{at_ref.literal}"])
        details = self._common(claim, at_ref, [*commands, pickaxe])
        details |= {"releases_searched": searched, "history_complete": True}
        if first is not None:
            # In some commit, in no release: true, but not the claim's own refutation.
            details["first_commit_with_text"] = first
            details["outcome"] = "history_only"
            return make_evidence(
                check_id=CHECK_ID,
                group=GROUP,
                claims=[claim],
                outcome="NEUTRAL",
                strength=0.0,
                summary=f"{at_ref.literal} is in no release of the {searched} searched,"
                f" though commit {first[:12]} contains it",
                details=details,
                commands=records,
            )
        try:
            variant = _pickaxe_any_case(repo, at_ref.literal, ctx.history_timeout, records)
        except ExternalToolError as exc:
            reason = f"the case-insensitive history search did not finish ({exc})"
            return self._incomplete(
                ctx, claim, at_ref, commands, reason, withheld=never, records=records
            )
        details["commands"] = [*details["commands"], _any_case_command(at_ref.literal)]
        if variant is not None:
            # P4: "--FOLD" for "--fold" is a transcription slip, not an invented option.
            details["first_commit_with_text"] = variant
            details["outcome"] = "case_variant_only"
            return make_evidence(
                check_id=CHECK_ID,
                group=GROUP,
                claims=[claim],
                outcome="NEUTRAL",
                strength=0.0,
                summary=f"{at_ref.literal} appears exactly in none of the {searched} releases"
                f" searched, though commit {variant[:12]} contains it in different letter case",
                details=details,
                commands=records,
            )
        return make_evidence(
            check_id=CHECK_ID,
            group=GROUP,
            claims=[claim],
            outcome="REFUTES",
            strength=never,
            summary=f"{at_ref.literal} appears in none of the {searched} releases searched"
            " and in no commit in the repository's history, in any letter case",
            details=details | {"outcome": "never_in_history"},
            commands=records,
        )

    def _history_blocked(self, ctx: CheckContext, token: str) -> str | None:
        """Why a history search cannot be trusted here, or ``None`` if it can be run."""
        if ctx.resolution.repo.is_shallow():
            return "the repository is a shallow clone, so its history is incomplete"
        if not token.isprintable():
            return "the token contains characters a history search cannot carry"
        if ctx.expired():
            return "the check's time budget ran out before the history search"
        return None

    def _incomplete(
        self,
        ctx: CheckContext,
        claim: OptionClaim,
        at_ref: LiteralResult,
        commands: Sequence[str],
        reason: str,
        *,
        withheld: float,
        records: Sequence[CommandRecord] = (),
    ) -> Evidence:
        """P4: an unfinished search is not absence. Record the refutation we did not make.

        ``make_evidence`` zeroes a NEUTRAL strength and keeps it as ``withheld_strength``,
        so the ledger shows exactly what the incomplete search cost.
        """
        details = self._common(claim, at_ref, commands)
        details |= {"outcome": "search_incomplete", "incomplete": reason, "history_complete": False}
        return make_evidence(
            check_id=CHECK_ID,
            group=GROUP,
            claims=[claim],
            outcome="NEUTRAL",
            strength=withheld,
            summary=f"{at_ref.literal} is not in the tree at {_where(ctx)}, but {reason},"
            " so its absence is not evidence",
            details=details,
            commands=records,
        )

    def _common(
        self, claim: OptionClaim, at_ref: LiteralResult, commands: Sequence[str]
    ) -> dict[str, Any]:
        return {
            "token": at_ref.literal,
            "option_kind": claim.option_kind,
            "commands": [command for command in commands if command],
        }


def _where(ctx: CheckContext) -> str:
    return ctx.ref_name or ctx.commit[:12]


def _name_forms(option_kind: str, token: str) -> list[str]:
    """The spellings a real option's name can take in code that declares it by name.

    ``--max-lines`` → ``max-lines`` and ``max_lines``; ``server.port`` → ``server`` and
    ``port`` (all of which must be present). Constants are declared as spelled: none.
    """
    if option_kind == "cli_flag":
        bare = token.lstrip("-")
        forms = [bare, bare.replace("-", "_")]
    elif option_kind == "config_key":
        forms = token.split(".")
    else:
        return []
    return sorted({form for form in forms if form and form != token})


def _any_case_command(token: str) -> str:
    return shlex.join(["git", "log", "--all", "-1", "-i", f"-S{token}"])


def _pickaxe_any_case(
    repo: GitRepo, token: str, timeout: float, records: list[CommandRecord]
) -> str | None:
    """A commit whose diff adds or removes ``token`` in any letter case, or ``None``.

    The token rides attached to ``-S`` (a data position, never an option); the caller has
    already refused tokens that are not printable. Raises ``ExternalToolError`` on timeout.
    """
    result = repo.run(
        ["log", "--all", "-1", "--format=%H", "-i", f"-S{token}"], timeout=timeout, record=records
    )
    if result.returncode != 0:
        # An empty stdout from a failed log is not "never in history" (P4).
        raise HistoryUnavailableError(f"git log -i -S failed with exit code {result.returncode}")
    sha = result.stdout.decode("ascii", "replace").strip()
    return sha or None
