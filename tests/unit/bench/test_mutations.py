# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""S5 mutations are deterministic, plant exactly the fabricated detail they name, and
carry the SPEC §17.1 expected verdicts."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from nikasha.bench.mutations import MUTATIONS, UTIL_LAYOUT, MutationError, generate, mutate

REPORTS = Path(__file__).resolve().parents[3] / "examples" / "reports"
GENUINE = (REPORTS / "genuine_hdr_overflow.md").read_text(encoding="utf-8")
MIXED = (REPORTS / "mixed_wrong_version.md").read_text(encoding="utf-8")
BASES = {"genuine": GENUINE, "mixed": MIXED}


def test_the_table_matches_the_spec() -> None:
    assert {m: (s.expected, s.label) for m, s in MUTATIONS.items()} == {
        "M1": ("UNGROUNDED", "fabricated"),
        "M2": ("UNGROUNDED", "fabricated"),
        "M3": ("MIXED", "genuine"),
        "M4": ("UNGROUNDED", "fabricated"),
        "M5": ("UNGROUNDED", "fabricated"),
        "M6": ("UNGROUNDED", "fabricated"),
        "M7": ("UNGROUNDED", "fabricated"),
    }


@pytest.mark.parametrize("mutation", sorted(MUTATIONS))
@pytest.mark.parametrize("base", sorted(BASES))
def test_every_mutation_is_deterministic_and_changes_the_text(mutation: str, base: str) -> None:
    for seed in range(5):
        first = mutate(BASES[base], mutation, base=base, seed=seed)
        again = mutate(BASES[base], mutation, base=base, seed=seed)
        assert first == again
        assert first != BASES[base]


def test_seeds_vary_the_output() -> None:
    outputs = {mutate(GENUINE, "M1", base="g", seed=s) for s in range(20)}
    assert len(outputs) > 1


def test_m1_removes_the_real_core_symbol() -> None:
    out = mutate(GENUINE, "M1", base="g", seed=0)
    assert "util_copy_value" not in out


VULNLAB = REPORTS.parent / "vulnlab" / "src"


def _function_spans(version: str) -> dict[str, tuple[int, int]]:
    """Top-level function spans in util.c at ``version``, from the vulnlab sources."""
    lines = (VULNLAB / f"v{version}" / "src" / "util.c").read_text("utf-8").splitlines()
    starts = [
        (i + 1, m.group(1))
        for i, t in enumerate(lines)
        if (m := re.match(r"^[a-z][^(]*?\b(\w+)\(", t))
    ]
    spans: dict[str, tuple[int, int]] = {}
    for n, (start, name) in enumerate(starts):
        end = starts[n + 1][0] - 1 if n + 1 < len(starts) else len(lines)
        spans[name] = (start, end)
    return spans


def test_util_layout_table_matches_the_sources() -> None:
    for version, (eof, core, window) in UTIL_LAYOUT.items():
        spans = _function_spans(version)
        lines = (VULNLAB / f"v{version}" / "src" / "util.c").read_text("utf-8").splitlines()
        assert eof == len(lines)
        assert core == spans["util_copy_value"]
        strip = spans["util_strip"]
        assert strip[0] < window[0] and window[1] + 4 <= strip[1], version


@pytest.mark.parametrize(
    ("text", "version"), [(GENUINE, "1.2.0"), (MIXED, "1.1.0")], ids=["genuine", "mixed"]
)
def test_m2_never_lands_inside_util_copy_value_at_the_named_version(
    text: str, version: str
) -> None:
    spans = _function_spans(version)
    core = spans["util_copy_value"]
    eof = len((VULNLAB / f"v{version}" / "src" / "util.c").read_text("utf-8").splitlines())
    for base in ("vulnlab-genuine", "vulnlab-mixed-wrong-version"):
        for seed in range(200):
            out = mutate(text, "M2", base=base, seed=seed)
            lines = {int(n) for n in re.findall(r"src/util\.c:(\d+):", out)}
            lines |= {int(n) for n in re.findall(r"src/util\.c line (\d+)", out)}
            assert lines, seed
            for n in lines:
                assert not core[0] <= n <= core[1], (base, seed, n)
                assert n > eof or any(
                    a <= n <= b for name, (a, b) in spans.items() if name != "util_copy_value"
                ), (base, seed, n)


def test_m3_names_a_version_where_the_locus_differs() -> None:
    for seed in range(6):
        out = mutate(GENUINE, "M3", base="g", seed=seed)
        assert "1.2.0" not in out
        assert "1.0.0" in out or "1.3.0" in out


def test_m4_replaces_the_caller_with_a_non_caller() -> None:
    out = mutate(GENUINE, "M4", base="g", seed=0)
    assert "hdr_parse_line" not in out
    assert re.search(r"in (hdr_list_free|hdr_list_init|hdr_casecmp) /work", out)


def test_m5_appends_a_patch_with_wrong_context() -> None:
    out = mutate(GENUINE, "M5", base="g", seed=0)
    patch = out.split("```diff", 1)[1]
    assert "+++ b/src/util.c" in patch
    wrong = ["value_len", "goto fail", "!dst || !value"]
    assert sum(w in patch for w in wrong) >= 2


def test_m6_invents_an_option_hdrcat_does_not_have() -> None:
    out = mutate(GENUINE, "M6", base="g", seed=0)
    option = re.search(r"hdrcat (--[a-z-]+) poc\.txt", out)
    assert option is not None
    assert option.group(1) not in ("--fold", "--max-lines")


def test_m7_breaks_the_region_arithmetic() -> None:
    for seed in range(8):
        out = mutate(GENUINE, "M7", base="g", seed=seed)
        m = re.search(
            r"located (\d+) bytes after (\d+)-byte region \[0x([0-9a-f]+),0x([0-9a-f]+)\)", out
        )
        assert m is not None
        offset, size = int(m.group(1)), int(m.group(2))
        start, end = int(m.group(3), 16), int(m.group(4), 16)
        assert (size, offset) != (end - start, 0), seed


def test_missing_anchors_and_unknown_mutations_raise() -> None:
    with pytest.raises(MutationError):
        mutate("nothing to see", "M7", base="x", seed=0)
    with pytest.raises(MutationError):
        mutate(GENUINE, "M9", base="x", seed=0)


def test_generate_is_stable_and_complete() -> None:
    cases = generate(BASES, ("M3", "M1"), (1, 0))
    assert [c.id for c in cases] == [
        "s5-genuine-m1-0",
        "s5-genuine-m1-1",
        "s5-genuine-m3-0",
        "s5-genuine-m3-1",
        "s5-mixed-m1-0",
        "s5-mixed-m1-1",
        "s5-mixed-m3-0",
        "s5-mixed-m3-1",
    ]
    assert generate(BASES, ("M3", "M1"), (1, 0)) == cases
    assert {c.expected for c in cases if c.mutation == "M3"} == {"MIXED"}
