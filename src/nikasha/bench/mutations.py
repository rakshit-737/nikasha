# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""S5: deterministic, seeded mutations of genuine reports (SPEC §17.2).

Each mutation takes the text of a vulnlab fixture and plants exactly one kind of
fabricated detail. The text only ever exists in memory (and in a temporary file for the
duration of one check): mutated reports are never committed.

Randomness is a :class:`random.Random` seeded from ``"<base>:<mutation>:<seed>"``, which
Python hashes with SHA-512, so the same triple yields the same text on every machine.
"""

from __future__ import annotations

import random
import re
from collections.abc import Callable
from dataclasses import dataclass

from nikasha.errors import NikashaError

_CORE = "util_copy_value"
_VERSION = re.compile(r"(?<![\d.])1\.[0-3]\.0(?!\.?\d)")
_REGION = re.compile(r"is located (\d{1,6}) bytes after (\d{1,6})-byte region")
_UTIL_FRAME = re.compile(r"src/util\.c:(\d{1,6}):(\d{1,4})")
_UTIL_PROSE = re.compile(r"src/util\.c line (\d{1,6})")
_RUN = re.compile(r"\./build/hdrcat poc\.txt")
_POC_HEADING = "## Proof of concept"


class MutationError(NikashaError):
    """A mutation could not be applied because its anchor is missing from the base text."""


@dataclass(frozen=True, slots=True)
class Mutation:
    """One row of the SPEC §17.1 table."""

    id: str
    description: str
    expected: str
    label: str
    apply: Callable[[str, random.Random], str]


def _require(text: str, needle: str, mutation: str) -> None:
    if needle not in text:
        raise MutationError(f"{mutation}: the base report has no {needle!r} to mutate")


def _m1_rename_symbol(text: str, rng: random.Random) -> str:
    _require(text, _CORE, "M1")
    fake = rng.choice(
        ("util_copy_hdr_value", "util_dup_value", "util_value_copy", "hdr_copy_value")
    )
    return text.replace(_CORE, fake)


#: util.c layout per vulnlab release: (lines in the file, util_copy_value span, and a
#: window of start lines that keeps two moved lines 4 apart inside util_strip()).
#: Taken from examples/vulnlab/src/v<version>/src/util.c; a test re-derives it.
UTIL_LAYOUT: dict[str, tuple[int, tuple[int, int], tuple[int, int]]] = {
    "1.1.0": (39, (26, 39), (14, 17)),
    "1.2.0": (36, (8, 19), (26, 28)),
}
_WINDOW_LINES = 2  # the in-function windows fit this many distinct moved lines
_MAX_EOF = 60  # the longest util.c of any release (v1.3.0)


def _m2_move_trace_lines(text: str, rng: random.Random) -> str:
    if not _UTIL_FRAME.search(text):
        raise MutationError("M2: the base report has no src/util.c trace frame")
    old_lines = {m.group(1) for m in _UTIL_FRAME.finditer(text)}
    old_lines |= {m.group(1) for m in _UTIL_PROSE.finditer(text)}
    named = {m.group(0) for m in _VERSION.finditer(text)}
    layout = None
    if len(named) == 1 and named <= UTIL_LAYOUT.keys():
        layout = UTIL_LAYOUT[next(iter(named))]
    # Past the end of util.c in every release, or (only when the named version's layout is
    # known and the lines fit) inside util_strip() instead of util_copy_value().
    windows = [(_MAX_EOF + 60, 480)]
    if layout is not None and len(old_lines) <= _WINDOW_LINES:
        windows.append(layout[2])
    low, high = rng.choice(windows)
    base = rng.randint(low, high)
    lines: dict[str, int] = {}

    def moved(old: str) -> int:
        return lines.setdefault(old, base + len(lines) * 4)

    text = _UTIL_FRAME.sub(lambda m: f"src/util.c:{moved(m.group(1))}:{m.group(2)}", text)
    return _UTIL_PROSE.sub(lambda m: f"src/util.c line {moved(m.group(1))}", text)


#: Real vulnlab functions that never call util_copy_value, and a line inside each.
_NON_CALLERS = (("hdr_list_free", 76), ("hdr_list_init", 66), ("hdr_casecmp", 28))


def _m4_impossible_edge(text: str, rng: random.Random) -> str:
    _require(text, "hdr_parse_line", "M4")
    caller, line = rng.choice(_NON_CALLERS)
    text = text.replace("src/hdr.c:104:13", f"src/hdr.c:{line}:5")
    return text.replace("hdr_parse_line", caller)


_PATCH_HEAD = (
    "\n\n## Suggested patch\n\n```diff\n--- a/src/util.c\n+++ b/src/util.c\n"
    "@@ -13,4 +13,6 @@ char *util_copy_value(const char *value)\n"
)
_ADDED = ("+    if (len >= HDR_VALUE_MAX)", "+        len = HDR_VALUE_MAX - 1;")
_REAL_CONTEXT = (
    "     if (dst == NULL)",
    "         return NULL;",
    "     memcpy(dst, value, len);",
    "     dst[len] = '\\0';",
)
_FAKE_CONTEXT = (
    "     if (!dst || !value)",
    "         goto fail;",
    "     memcpy(dst, value, value_len);",
    "     dst[value_len] = 0;",
)


def _m5_corrupt_patch(text: str, rng: random.Random) -> str:
    _require(text, _CORE, "M5")
    context = list(_REAL_CONTEXT)
    # Corrupt two to four of the four context lines, chosen by the seed.
    for index in rng.sample(range(4), rng.randint(2, 4)):
        context[index] = _FAKE_CONTEXT[index]
    body = [context[0], context[1], *_ADDED, context[2], context[3]]
    return text.rstrip("\n") + _PATCH_HEAD + "\n".join(body) + "\n```\n"


def _m6_invent_option(text: str, rng: random.Random) -> str:
    if not _RUN.search(text):
        raise MutationError("M6: the base report has no hdrcat command line")
    option = rng.choice(("--unfold-values", "--raw-headers", "--no-limit", "--strict-values"))
    text = _RUN.sub(f"./build/hdrcat {option} poc.txt", text)
    sentence = f"The overflow is only reachable with the `{option}` option of `hdrcat`.\n\n"
    if _POC_HEADING in text:
        return text.replace(_POC_HEADING, sentence + _POC_HEADING, 1)
    return text + "\n" + sentence


def _m7_break_region(text: str, rng: random.Random) -> str:
    match = _REGION.search(text)
    if match is None:
        raise MutationError("M7: the base report has no ASan region line")
    offset, size = int(match.group(1)), int(match.group(2))
    if rng.choice((True, False)):
        size = rng.choice([s for s in (16, 32, 48, 96, 128) if s != size])
    else:
        offset = rng.choice([o for o in (8, 16, 24, 40) if o != offset])
    return _REGION.sub(f"is located {offset} bytes after {size}-byte region", text)


def _m3_swap_version(text: str, rng: random.Random) -> str:
    versions = {m.group(0) for m in _VERSION.finditer(text)}
    if not versions:
        raise MutationError("M3: the base report names no version")
    # 1.0.0 predates util_copy_value; 1.3.0 carries the fix. Either way the locus differs.
    target = rng.choice([v for v in ("1.0.0", "1.3.0") if v not in versions])
    return _VERSION.sub(target, text)


_FAB = "fabricated"

MUTATIONS: dict[str, Mutation] = {
    m.id: m
    for m in (
        Mutation(
            "M1",
            "rename the core symbol to a plausible name that does not exist",
            "UNGROUNDED",
            _FAB,
            _m1_rename_symbol,
        ),
        Mutation(
            "M2",
            "move trace lines past EOF or into the wrong function",
            "UNGROUNDED",
            _FAB,
            _m2_move_trace_lines,
        ),
        Mutation(
            "M3",
            "change the version to one where the locus differs",
            "MIXED",
            "genuine",
            _m3_swap_version,
        ),
        Mutation("M4", "inject an impossible call edge", "UNGROUNDED", _FAB, _m4_impossible_edge),
        Mutation("M5", "corrupt the patch context", "UNGROUNDED", _FAB, _m5_corrupt_patch),
        Mutation("M6", "invent a CLI option", "UNGROUNDED", _FAB, _m6_invent_option),
        Mutation("M7", "break the ASan region arithmetic", "UNGROUNDED", _FAB, _m7_break_region),
    )
}


def mutate(text: str, mutation: str, *, base: str, seed: int) -> str:
    """Apply ``mutation`` to ``text`` deterministically for ``(base, seed)``."""
    try:
        spec = MUTATIONS[mutation]
    except KeyError:
        raise MutationError(f"unknown mutation {mutation!r}") from None
    rng = random.Random(f"{base}:{mutation}:{seed}")  # noqa: S311 - reproducible, not secret
    mutated = spec.apply(text, rng)
    if mutated == text:
        raise MutationError(f"{mutation} left {base} unchanged")
    return mutated


@dataclass(frozen=True, slots=True)
class SyntheticCase:
    """One generated report, held in memory only."""

    id: str
    base: str
    mutation: str
    seed: int
    label: str
    expected: str
    text: str


def generate(
    bases: dict[str, str], mutations: tuple[str, ...], seeds: tuple[int, ...]
) -> tuple[SyntheticCase, ...]:
    """Every (base, mutation, seed) combination, in a stable order."""
    cases: list[SyntheticCase] = []
    for base in sorted(bases):
        for mutation in sorted(mutations):
            spec = MUTATIONS[mutation]
            for seed in sorted(seeds):
                cases.append(
                    SyntheticCase(
                        id=f"s5-{base}-{mutation.lower()}-{seed}",
                        base=base,
                        mutation=mutation,
                        seed=seed,
                        label=spec.label,
                        expected=spec.expected,
                        text=mutate(bases[base], mutation, base=base, seed=seed),
                    )
                )
    return tuple(cases)
