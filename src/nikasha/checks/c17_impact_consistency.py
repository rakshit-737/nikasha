# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""C17 IMPACT_CONSISTENCY: does the CVSS vector compute to the score the report states?

This check is **weak by design** (SPEC §12). A vector that does not add up to the number
printed next to it is sloppiness far more often than invention: people copy a vector from
one advisory and a score from another, or round by hand. So the whole check is worth less
than one missing line of code, and its wording stays descriptive — it reports the
arithmetic and lets fusion decide how little that matters.

The base score is computed here rather than taken from a library: the formula is thirty
lines, a dependency for it would be out of proportion, and having it in-tree means the
number in a verdict can be re-derived by reading this file (P6). The implementation follows
the *CVSS v3.1 Specification Document* (revision 1), §7.1 "Base" and Appendix A "Floating
Point Rounding". CVSS v3.0 shares that formula exactly, so both versions are scored.

A version whose formula is *not* implemented here — v2.0, v4.0 — never counts as
``vector_unparseable``: not knowing how to score a vector says nothing about the report
(P4). Its severity word is still checked, against the band table that version publishes.

The CWE on an impact claim belongs to C15, which owns the reference checks and the bug-type
compatibility table. Judging it here as well would count one mistake twice (SPEC §14.1).
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from nikasha.checks.base import BaseCheck, CheckContext, make_evidence, register
from nikasha.checks.strengths import Strengths, default_strengths
from nikasha.model.claims import Claim, ClaimKind, ImpactClaim
from nikasha.model.evidence import Evidence

CHECK_ID = "C17"
GROUP = "meta"

# --- CVSS v3.1 base metrics and weights (Specification Document v3.1 r1, §7.1, table 15) ---

_CIA_WEIGHTS = {"H": 0.56, "L": 0.22, "N": 0.0}
#: Every base weight except Privileges Required, which depends on Scope.
_WEIGHTS: dict[str, dict[str, float]] = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": _CIA_WEIGHTS,
    "I": _CIA_WEIGHTS,
    "A": _CIA_WEIGHTS,
}
#: Privileges Required is worth more when the Scope changed, so it is keyed by Scope.
_PR_WEIGHTS: dict[str, dict[str, float]] = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "C": {"N": 0.85, "L": 0.68, "H": 0.50},
}
#: The eight mandatory base metrics, in the order the spec prints them.
_BASE_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")

#: The temporal and environmental metric keys each version defines (v3.0/v3.1 §3-4, v2.0
#: §2.2-2.3). Only these can give a vector a score besides its base score; any other key
#: is noise and never counts as a modifier.
_V3_MODIFIER_METRICS = frozenset(
    {"E", "RL", "RC", "CR", "IR", "AR", "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA"}
)
_V2_MODIFIER_METRICS = frozenset({"E", "RL", "RC", "CDP", "TD", "CR", "IR", "AR"})

_EXPLOITABILITY_COEFFICIENT = 8.22
_IMPACT_UNCHANGED = 6.42
_IMPACT_CHANGED_LINEAR = 7.52
_IMPACT_CHANGED_POWER = 3.25
_SCOPE_COEFFICIENT = 1.08
_MAX_SCORE = 10.0

#: The versions whose base formula is implemented above. v3.0 and v3.1 differ only in how
#: they *describe* rounding, and Appendix A's procedure is the correct one for both.
SCORED_VERSIONS = frozenset({"3.0", "3.1"})

#: One metric of a vector string, e.g. ``AV:N`` or ``MAV:X``. Both quantifiers are bounded
#: and the pattern is anchored, so it stays linear on hostile input (SPEC §19.2).
_METRIC_RE = re.compile(r"\A[A-Za-z]{1,3}:[A-Za-z]{1,2}\Z")
#: A full v3.1 vector carries at most 20 metrics plus the prefix; past that it is not one.
_MAX_METRICS = 24
#: Reporter text echoed into a summary is flattened and cut to this many characters.
_MAX_ECHO = 60

#: SPEC §12 flags a difference of "more than 0.1". The slack absorbs binary floating-point
#: noise (``4.2 - 4.1`` is 0.10000000000000053), so an exact 0.1 gap never counts.
_SCORE_TOLERANCE = 0.1 + 1e-9

#: Qualitative bands as ``(exclusive upper bound, label)``. v3.x is the ratings table in
#: §5 of the v3.1 spec; v2.0 has no table of its own, so NVD's Low/Medium/High is used.
_V3_BANDS = ((0.1, "None"), (4.0, "Low"), (7.0, "Medium"), (9.0, "High"))
_V3_TOP = "Critical"
_V2_BANDS = ((4.0, "Low"), (7.0, "Medium"))
_V2_TOP = "High"

#: GitHub and Red Hat print "Moderate" where the CVSS table says "Medium".
_SEVERITY_SYNONYMS = {"moderate": "medium"}


def roundup(value: float) -> float:
    """Round ``value`` *up* to one decimal, exactly as CVSS v3.1 Appendix A defines it.

    Not ``math.ceil(value * 10) / 10``: an exploitability sum of 6.000000000000001 — which
    binary floating point produces routinely — becomes 6.1 that way, and did, in real
    scoring tools, until v3.1 replaced the prose definition with this integer procedure.
    """
    scaled = math.floor(value * 100_000 + 0.5)
    if scaled % 10_000 == 0:
        return scaled / 100_000
    return (scaled // 10_000 + 1) / 10


def base_score(metrics: Mapping[str, str]) -> float:
    """The CVSS v3.x base score for already-validated base ``metrics`` (spec §7.1)."""
    scope_changed = metrics["S"] == "C"
    iss = 1 - (
        (1 - _CIA_WEIGHTS[metrics["C"]])
        * (1 - _CIA_WEIGHTS[metrics["I"]])
        * (1 - _CIA_WEIGHTS[metrics["A"]])
    )
    if scope_changed:
        impact = _IMPACT_CHANGED_LINEAR * (iss - 0.029) - _IMPACT_CHANGED_POWER * (iss - 0.02) ** 15
    else:
        impact = _IMPACT_UNCHANGED * iss
    if impact <= 0:
        return 0.0
    exploitability = (
        _EXPLOITABILITY_COEFFICIENT
        * _WEIGHTS["AV"][metrics["AV"]]
        * _WEIGHTS["AC"][metrics["AC"]]
        * _PR_WEIGHTS[metrics["S"]][metrics["PR"]]
        * _WEIGHTS["UI"][metrics["UI"]]
    )
    total = impact + exploitability
    if scope_changed:
        total *= _SCOPE_COEFFICIENT
    return roundup(min(total, _MAX_SCORE))


def vector_version(vector: str) -> str | None:
    """The version a vector states in its own ``CVSS:x.y/`` prefix, if it has one."""
    head = vector.strip().strip("()").split("/", 1)[0]
    return head[5:] if head[:5].upper() == "CVSS:" else None


def _base_metric_error(metrics: Mapping[str, str]) -> str:
    """Why ``metrics`` is not a complete set of CVSS v3 base metrics, or ``""`` if it is."""
    missing = [key for key in _BASE_METRICS if key not in metrics]
    if missing:
        return f"it has no {', '.join(missing)} metric"
    if metrics["S"] not in _PR_WEIGHTS:
        return f"S:{metrics['S']} is not a Scope value"
    for key in _BASE_METRICS:
        table = _PR_WEIGHTS[metrics["S"]] if key == "PR" else _WEIGHTS.get(key, {})
        if table and metrics[key] not in table:
            return f"{key}:{metrics[key]} is not a CVSS v3 value"
    return ""


def parse_vector(vector: str) -> tuple[dict[str, str] | None, str]:
    """The base metrics of a CVSS v3.x vector, or ``(None, reason)`` if it does not parse.

    Temporal and environmental metrics are accepted and ignored: a vector carrying them is
    still a well-formed vector with a base score.
    """
    parts = vector.strip().strip("()").split("/")
    if len(parts) > _MAX_METRICS:
        return None, f"it has more than {_MAX_METRICS} metrics"
    if parts and parts[0][:5].upper() == "CVSS:":
        parts = parts[1:]
    # A stray leading or trailing slash is a formatting slip, not a malformed metric (P4).
    parts = [part for part in parts if part]
    metrics: dict[str, str] = {}
    for part in parts:
        if not _METRIC_RE.match(part):
            return None, f"{echo(part)!r} is not a metric"
        key, _, value = part.partition(":")
        if key.upper() in metrics:
            return None, f"the {key.upper()} metric appears twice"
        metrics[key.upper()] = value.upper()
    reason = _base_metric_error(metrics)
    return (None, reason) if reason else (metrics, "")


def modifying_metrics(vector: str, version: str | None = None) -> list[str]:
    """The temporal or environmental metrics of a vector that are set to something but ``X``.

    Such a vector has a temporal or environmental score besides its base score, and a report
    may print either one next to it. ``X`` ("Not Defined") changes nothing, so it is ignored,
    and so is a key that ``version`` (v3.x unless it says ``2.0``) does not define.
    """
    known = _V2_MODIFIER_METRICS if version == "2.0" else _V3_MODIFIER_METRICS
    parts = vector.strip().strip("()").split("/")[:_MAX_METRICS]
    out: set[str] = set()
    for part in parts:
        if not _METRIC_RE.match(part) or part[:5].upper() == "CVSS:":
            continue
        key, _, value = part.partition(":")
        if key.upper() in known and value.upper() != "X":
            out.add(key.upper())
    return sorted(out)


def severity_band(score: float, version: str | None = None) -> str:
    """The qualitative band ``score`` falls in, using the table that ``version`` publishes."""
    bands, top = (_V2_BANDS, _V2_TOP) if version == "2.0" else (_V3_BANDS, _V3_TOP)
    for upper, label in bands:
        if score < upper:
            return label
    return top


def word_matches(word: str, band: str) -> bool:
    """Whether a severity word names ``band``, allowing the usual vendor synonyms."""
    normalised = word.strip().lower()
    return _SEVERITY_SYNONYMS.get(normalised, normalised) == band.lower()


def echo(text: str) -> str:
    """A flattened, length-capped echo of reporter text, safe to put in a one-line summary."""
    # Control characters (ANSI escapes, NUL, bidi overrides) never reach a summary (P7).
    printable = "".join(ch if ch.isprintable() else " " for ch in text)
    flat = " ".join(printable.split())
    return flat if len(flat) <= _MAX_ECHO else flat[: _MAX_ECHO - 3] + "..."


@dataclass(frozen=True, slots=True)
class Assessment:
    """What the arithmetic says about one impact claim, before it becomes evidence."""

    version: str | None
    claimed: float | None
    word: str | None
    computed: float | None
    #: Why a vector that should have been scored did not parse.
    parse_error: str | None
    #: Why a well-formed vector was not scored at all (an unimplemented CVSS version).
    unscored: str | None
    #: The score the severity word has to describe: the report's own, else the computed one.
    reference: float | None


def assess(claim: ImpactClaim) -> Assessment:
    """Score the claim's vector and work out which band its severity word should name."""
    vector = claim.cvss_vector
    stated = vector_version(vector) if vector is not None else None
    version = stated or claim.cvss_version
    # A NaN or infinite score is not a number the report printed; it has no band (P4).
    claimed = claim.cvss_score
    if claimed is not None and not math.isfinite(claimed):
        claimed = None
    computed: float | None = None
    parse_error: str | None = None
    unscored: str | None = None
    if vector is not None:
        if version in SCORED_VERSIONS:
            metrics, reason = parse_vector(vector)
            if metrics is None:
                parse_error = reason
            else:
                computed = round(base_score(metrics), 1)
        elif version is None:
            unscored = f"the vector {echo(vector)!r} does not say which CVSS version it uses"
        else:
            unscored = f"CVSS v{version} vectors are not scored by this check"
    return Assessment(
        version=version,
        claimed=claimed,
        word=claim.severity_word,
        computed=computed,
        parse_error=parse_error,
        unscored=unscored,
        # The severity word describes the number the report itself prints, when it prints one.
        reference=claimed if claimed is not None else computed,
    )


@register
class ImpactConsistency(BaseCheck):
    id = CHECK_ID
    name = "IMPACT_CONSISTENCY"
    group = GROUP
    applies_to: frozenset[ClaimKind] = frozenset({"impact"})
    description = "Recomputes the CVSS base score and compares it with the stated score and word."

    def __init__(self, strengths: Strengths | None = None) -> None:
        self.strengths = strengths or default_strengths()

    def run(self, ctx: CheckContext, claims: Sequence[Claim]) -> list[Evidence]:
        out: list[Evidence] = []
        for claim in claims:
            if not isinstance(claim, ImpactClaim):
                continue
            evidence = self._one(claim)
            if evidence is not None:
                out.append(evidence)
        return out

    def _one(self, claim: ImpactClaim) -> Evidence | None:
        found = assess(claim)
        reference, computed, claimed = found.reference, found.computed, found.claimed
        band = severity_band(reference, found.version) if reference is not None else None
        details: dict[str, object] = {"cvss_version": found.version}
        if claim.cvss_vector is not None:
            details["vector"] = echo(claim.cvss_vector)
        if claimed is not None:
            details["claimed_score"] = claimed
        if computed is not None:
            details["computed_score"] = computed
        if band is not None:
            details["band"] = band
        if found.word is not None:
            details["severity_word"] = found.word

        if found.parse_error is not None:
            vector = echo(claim.cvss_vector or "")
            return self._refutes(
                claim,
                "vector_unparseable",
                f"the CVSS v{found.version} vector {vector!r} does not parse: {found.parse_error}",
                {**details, "reason": found.parse_error},
            )

        if (
            computed is not None
            and claimed is not None
            and abs(computed - claimed) > _SCORE_TOLERANCE
        ):
            computed_band = severity_band(computed, found.version)
            modifiers = modifying_metrics(claim.cvss_vector or "", found.version)
            if modifiers:
                # A temporal or environmental score legitimately differs from the base
                # score; the stated number may be one of those, so nothing is refuted (P4).
                return make_evidence(
                    check_id=CHECK_ID,
                    group=GROUP,
                    claims=[claim],
                    outcome="NEUTRAL",
                    strength=0.0,
                    summary=f"the vector's base score computes to {computed:.1f}"
                    f" ({computed_band}) under CVSS v{found.version}; the report states"
                    f" {claimed:.1f}, which may be the temporal or environmental score"
                    f" its {', '.join(modifiers)} metrics define",
                    details={
                        **details,
                        "computed_severity": computed_band,
                        "modifying_metrics": modifiers,
                        "outcome": "non_base_score",
                    },
                )
            return self._refutes(
                claim,
                "score_mismatch",
                f"the vector computes to {computed:.1f} ({computed_band}) under CVSS"
                f" v{found.version}; the report states {claimed:.1f}",
                {**details, "computed_severity": computed_band},
            )

        if (
            found.word is not None
            and band is not None
            and reference is not None
            and not word_matches(found.word, band)
        ):
            return self._refutes(
                claim,
                "severity_mismatch",
                f"CVSS {reference:.1f} is in the {band} band;"
                f" the report calls it {echo(found.word)}",
                details,
            )

        return self._note(claim, found, band, details)

    def _note(
        self,
        claim: ImpactClaim,
        found: Assessment,
        band: str | None,
        details: dict[str, object],
    ) -> Evidence | None:
        """A strength-0 record of what was verified, or nothing when nothing was."""
        if found.computed is not None:
            label = "scored"
            computed_band = severity_band(found.computed, found.version)
            summary = (
                f"the CVSS v{found.version} vector computes to"
                f" {found.computed:.1f} ({computed_band})"
            )
            # Only claim agreement when the two numbers really are the same one: a score
            # within the tolerance but not equal to it is not "the score the report states".
            if found.claimed == found.computed:
                summary += ", the score the report states"
        elif found.unscored is not None:
            label = "unscored"
            summary = found.unscored
        elif found.word is not None and band is not None and found.reference is not None:
            label = "band_matches"
            summary = f"CVSS {found.reference:.1f} is in the {band} band, as the report says"
        else:
            return None
        return make_evidence(
            check_id=CHECK_ID,
            group=GROUP,
            claims=[claim],
            outcome="NEUTRAL",
            strength=0.0,
            summary=summary,
            details={**details, "outcome": label},
        )

    def _refutes(
        self,
        claim: ImpactClaim,
        outcome_key: str,
        summary: str,
        details: dict[str, object],
    ) -> Evidence:
        return make_evidence(
            check_id=CHECK_ID,
            group=GROUP,
            claims=[claim],
            outcome="REFUTES",
            strength=self.strengths.get(CHECK_ID, outcome_key),
            summary=summary,
            details={**details, "outcome": outcome_key, "finding": outcome_key},
        )
