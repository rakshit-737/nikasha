# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Option claims (SPEC §9.7): long CLI flags, project-prefixed constants (``CURLOPT_…``) and
``section.key=`` configuration keys.

Provenance is decided here because it depends on the *program* a flag is passed to: a flag
of a known external tool (``gcc --version``) is third-party; a flag inside a PoC block is a
reporter artifact unless the command runs one of the project's own programs.
"""

from __future__ import annotations

import bisect
import re

from nikasha.extract.commands import EXTERNAL_TOOLS, Command, block_commands, inline_commands
from nikasha.extract.registry import ExtractContext, make_claim, register
from nikasha.extract.spans import IntervalIndex, Region, contains, finditer_in
from nikasha.model.claims import OptionClaim, Provenance

NAME = "options"

_FLAG_RE = re.compile(r"(?<![\w-])--[a-z0-9][a-z0-9-]{0,60}+(?![\w-])", re.IGNORECASE)
_CONFIG_KEY_RE = re.compile(r"(?<![\w.-])[a-z][\w-]{1,40}\.[a-z][\w.-]{1,60}+(?==)", re.IGNORECASE)


def _constant_re(ctx: ExtractContext) -> re.Pattern[str] | None:
    prefixes = sorted({p for prod in ctx.products for p in prod.constant_prefixes})
    if not prefixes:
        return None
    alternation = "|".join(re.escape(p) for p in prefixes)
    return re.compile(rf"(?<![\w])(?:{alternation})[A-Z0-9_]{{2,60}}+(?![\w])")


def _provenance(
    region: Region,
    commands: list[Command],
    command_starts: list[int],
    in_block: bool,
    programs: set[str],
) -> Provenance:
    """Who owns an option depends on the command it is passed to (``O(log n)`` lookup)."""
    i = bisect.bisect_right(command_starts, region[0]) - 1
    if i >= 0 and contains((commands[i].span.start, commands[i].span.end), region):
        program = commands[i].program
        if program in programs:
            return "project_attributed"
        if program in EXTERNAL_TOOLS:
            return "third_party"
    return "reporter_artifact" if in_block else "project_attributed"


@register(NAME)
def extract_options(ctx: ExtractContext) -> list[OptionClaim]:
    report, body = ctx.report, ctx.report.body
    programs = {prog for p in ctx.products for prog in p.programs}
    poc_blocks = [b for b in report.code_blocks if b.role_guess in ("poc", "log")]
    commands = sorted(
        inline_commands(ctx) + [c for b in poc_blocks for c in block_commands(ctx, b)],
        key=lambda c: c.span.start,
    )
    command_starts = [c.span.start for c in commands]
    block_regions = [(b.span.start, b.span.end) for b in poc_blocks]
    block_index = IntervalIndex(block_regions)
    regions = sorted(ctx.prose + block_regions)
    claims: list[OptionClaim] = []

    def add(start: int, end: int, token: str, kind: str) -> None:
        region = (start, end)
        if ctx.url_index.overlaps(region):
            return
        in_block = block_index.overlaps(region)
        claims.append(
            make_claim(
                OptionClaim,
                spans=[report.span(start, end)],
                extractor=NAME,
                confidence=0.85,
                token=token,
                option_kind=kind,
                provenance=_provenance(region, commands, command_starts, in_block, programs),
            )
        )

    for m in finditer_in(_FLAG_RE, body, regions):
        add(m.start(), m.end(), m.group(0), "cli_flag")
    constant_re = _constant_re(ctx)
    if constant_re is not None:
        for m in finditer_in(constant_re, body, regions):
            add(m.start(), m.end(), m.group(0), "constant")
    for m in finditer_in(_CONFIG_KEY_RE, body, regions):
        add(m.start(), m.end(), m.group(0), "config_key")
    return claims
