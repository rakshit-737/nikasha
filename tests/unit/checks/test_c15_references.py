# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""C15 REFERENCES, against the real vulnlab history (SPEC §12).

The CVE outcomes are driven through an injected fetcher: the default suite has no network
(P3), and one test proves an offline run never reaches ``urlopen`` at all.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from conftest import MakeContext, claim
from nikasha.checks.base import CheckError, run_checks
from nikasha.checks.c15_references import (
    MAX_CVE_BYTES,
    CveLookup,
    CweCompat,
    References,
    _read_cve,
    cve_products,
    cve_state,
    cve_url,
    cwe_compat,
    cwe_id,
    fetch_cve,
    load_cwe_compat,
    normalize_repo,
)
from nikasha.model.claims import FileClaim, ImpactClaim, ReferenceClaim, TraceClaim
from nikasha.model.evidence import Evidence

CVE = "CVE-2026-12345"


def _never_fetch(cve_id: str) -> CveLookup:
    raise AssertionError(f"an offline run must not fetch {cve_id}")


def _canned(**fields: Any) -> Any:
    """A fetcher that answers with one prepared record."""

    def fetch(cve_id: str) -> CveLookup:
        defaults: dict[str, Any] = {"url": "https://example.invalid/cve.json", "status": 200}
        return CveLookup(cve_id=cve_id, **{**defaults, **fields})

    return fetch


def _run(
    make_ctx: MakeContext,
    claims: list[Any],
    *,
    tag: str = "v1.2.0",
    online: bool = False,
    fetch: Any = None,
) -> list[Evidence]:
    ctx = make_ctx(claims=claims, tag=tag, online=online)
    check = References(fetch=fetch)
    return check.run(ctx, check.select(list(ctx.claims)))


def _reference(**fields: Any) -> ReferenceClaim:
    return claim(ReferenceClaim, **fields)


# --- commits --------------------------------------------------------------------------------


def test_a_cited_commit_that_exists_supports(
    make_ctx: MakeContext, commits: dict[str, str]
) -> None:
    sha = commits["v1.2.0"]
    (evidence,) = _run(make_ctx, [_reference(ref_kind="commit", value=sha)])
    assert evidence.outcome == "SUPPORTS"
    assert evidence.strength == 0.3
    assert evidence.check_id == "C15"
    assert evidence.group == "refs"
    assert evidence.details["outcome"] == "commit_exists"
    assert evidence.details["commit"] == sha
    assert evidence.details["touches"] == ["src/util.c"]


def test_a_commit_that_touches_the_claimed_file_scores_higher(
    make_ctx: MakeContext, commits: dict[str, str]
) -> None:
    sha = commits["v1.2.0"]
    claims = [_reference(ref_kind="commit", value=sha), claim(FileClaim, path="src/util.c")]
    (evidence,) = _run(make_ctx, claims)
    assert evidence.outcome == "SUPPORTS"
    assert evidence.strength == 0.5
    assert evidence.details["outcome"] == "commit_touches_file"
    assert evidence.details["claimed_paths_touched"] == ["src/util.c"]
    (location,) = evidence.locations
    assert location.path == "src/util.c"
    assert location.permalink is not None


def test_a_partial_claimed_path_still_counts_as_touched(
    make_ctx: MakeContext, commits: dict[str, str]
) -> None:
    claims = [
        _reference(ref_kind="commit", value=commits["v1.2.0"]),
        claim(FileClaim, path="util.c"),
    ]
    (evidence,) = _run(make_ctx, claims)
    assert evidence.details["outcome"] == "commit_touches_file"


def test_a_commit_touching_another_file_only_says_it_exists(
    make_ctx: MakeContext, commits: dict[str, str]
) -> None:
    # v1.2.0 changes src/util.c only, so a report about src/hdr.c gets the weaker item.
    claims = [
        _reference(ref_kind="commit", value=commits["v1.2.0"]),
        claim(FileClaim, path="src/hdr.c"),
    ]
    (evidence,) = _run(make_ctx, claims)
    assert evidence.details["outcome"] == "commit_exists"
    assert evidence.strength == 0.3
    assert evidence.locations == ()


def test_an_abbreviated_sha_resolves_to_the_full_commit(
    make_ctx: MakeContext, commits: dict[str, str]
) -> None:
    sha = commits["v1.3.0"]
    (evidence,) = _run(make_ctx, [_reference(ref_kind="commit", value=sha[:8])])
    assert evidence.outcome == "SUPPORTS"
    assert evidence.details["commit"] == sha
    assert evidence.details["cited"] == sha[:8]


def test_a_missing_commit_is_neutral_and_asks_about_a_fork(make_ctx: MakeContext) -> None:
    c = _reference(ref_kind="commit", value="deadbeefdeadbeef")
    (evidence,) = _run(make_ctx, [c])
    assert evidence.outcome == "NEUTRAL"
    assert evidence.strength == 0.0
    assert evidence.details["outcome"] == "commit_missing"
    assert "fork" in evidence.details["question"]
    assert "deadbeefdeadbeef" in evidence.details["question"]
    assert "gated" not in evidence.details  # a missing SHA is never a withheld refutation


def test_a_value_that_is_not_a_sha_is_ignored(make_ctx: MakeContext) -> None:
    assert _run(make_ctx, [_reference(ref_kind="commit", value="HEAD~3")]) == []
    assert _run(make_ctx, [_reference(ref_kind="commit", value="abc")]) == []


def test_the_same_sha_cited_twice_is_one_evidence_item(
    make_ctx: MakeContext, commits: dict[str, str]
) -> None:
    sha = commits["v1.2.0"]
    first = _reference(ref_kind="commit", value=sha, text="one")
    second = _reference(ref_kind="commit", value=sha.upper(), text="two")
    (evidence,) = _run(make_ctx, [first, second])
    assert evidence.claim_ids == tuple(sorted({first.id, second.id}))


def test_a_commit_cited_from_another_repository_is_not_reported_missing(
    make_ctx: MakeContext,
) -> None:
    c = _reference(
        ref_kind="commit",
        value="deadbeefdeadbeef",
        repo_url="https://github.com/someone/fork",
    )
    outcomes = {e.details.get("outcome") for e in _run(make_ctx, [c])}
    assert outcomes == {"foreign_repo"}


# --- repository links -----------------------------------------------------------------------


def test_a_link_to_a_different_repository_refutes(make_ctx: MakeContext) -> None:
    c = _reference(
        ref_kind="pr",
        value="https://github.com/other/thing/pull/7",
        repo_url="https://github.com/other/thing",
    )
    (evidence,) = _run(make_ctx, [c])
    assert evidence.outcome == "REFUTES"
    assert evidence.strength == -0.3
    assert evidence.details["repo"] == "github.com/other/thing"
    assert evidence.details["expected"] == ["github.com/nikasha-demo/libhdr"]


def test_a_link_to_the_target_repository_is_not_foreign(make_ctx: MakeContext) -> None:
    c = _reference(
        ref_kind="issue",
        value="https://github.com/nikasha-demo/libhdr/issues/3",
        repo_url="https://github.com/nikasha-demo/libhdr.git",
    )
    assert _run(make_ctx, [c]) == []


def test_a_mirror_under_the_project_name_is_not_foreign(make_ctx: MakeContext) -> None:
    c = _reference(
        ref_kind="url",
        value="https://gitlab.com/mirrors/libhdr",
        repo_url="https://gitlab.com/mirrors/libhdr",
    )
    assert _run(make_ctx, [c]) == []


def test_normalize_repo_ignores_local_paths_and_keeps_forge_identity() -> None:
    assert normalize_repo("https://GitHub.com/Owner/Repo.git/") == "github.com/owner/repo"
    assert normalize_repo("https://www.github.com/o/r") == "github.com/o/r"
    assert normalize_repo("/srv/mirrors/libhdr.git") == ""
    assert normalize_repo("file:///srv/libhdr.git") == ""
    assert normalize_repo(None) == ""


# --- CVE records ----------------------------------------------------------------------------


def test_a_cve_is_not_fetched_offline(make_ctx: MakeContext, monkeypatch: Any) -> None:
    def boom(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("an offline run must make no network call (P3)")

    monkeypatch.setattr("urllib.request.urlopen", boom)
    # No injected fetcher: this exercises the real code path with the network booby-trapped.
    (evidence,) = _run(make_ctx, [_reference(ref_kind="cve", value=CVE)])
    assert evidence.outcome == "NEUTRAL"
    assert evidence.strength == 0.0
    assert evidence.details["outcome"] == "offline"
    assert "--online" in evidence.summary


def test_an_injected_fetcher_is_never_called_offline(make_ctx: MakeContext) -> None:
    (evidence,) = _run(make_ctx, [_reference(ref_kind="cve", value=CVE)], fetch=_never_fetch)
    assert evidence.details["outcome"] == "offline"


def test_a_cve_for_this_product_supports(make_ctx: MakeContext) -> None:
    fetch = _canned(state="PUBLISHED", products=("libhdr",), body_sha256="ab" * 32)
    (evidence,) = _run(make_ctx, [_reference(ref_kind="cve", value=CVE)], online=True, fetch=fetch)
    assert evidence.outcome == "SUPPORTS"
    assert evidence.strength == 0.3
    assert evidence.details["outcome"] == "cve_matches_product"
    assert evidence.details["matched"] == ["libhdr"]
    assert evidence.details["response_sha256"] == "ab" * 32


def test_a_cve_for_another_product_refutes(make_ctx: MakeContext) -> None:
    fetch = _canned(state="PUBLISHED", products=("OpenSSL", "openssl"))
    (evidence,) = _run(make_ctx, [_reference(ref_kind="cve", value=CVE)], online=True, fetch=fetch)
    assert evidence.outcome == "REFUTES"
    assert evidence.strength == -1.0
    assert evidence.details["outcome"] == "cve_other_product"
    assert evidence.details["products"] == ["OpenSSL", "openssl"]


def test_a_rejected_cve_refutes(make_ctx: MakeContext) -> None:
    fetch = _canned(state="REJECTED", products=("libhdr",))
    (evidence,) = _run(make_ctx, [_reference(ref_kind="cve", value=CVE)], online=True, fetch=fetch)
    assert evidence.outcome == "REFUTES"
    assert evidence.strength == -0.5
    assert evidence.details["outcome"] == "cve_rejected"


def test_a_cve_with_no_record_refutes(make_ctx: MakeContext) -> None:
    (evidence,) = _run(
        make_ctx, [_reference(ref_kind="cve", value=CVE)], online=True, fetch=_canned(status=404)
    )
    assert evidence.outcome == "REFUTES"
    assert evidence.strength == -0.3
    assert evidence.details["outcome"] == "cve_not_found"


def test_a_failed_fetch_is_neutral_not_a_refutation(make_ctx: MakeContext) -> None:
    fetch = _canned(status=0, error="URLError: [Errno -3] no route")
    (evidence,) = _run(make_ctx, [_reference(ref_kind="cve", value=CVE)], online=True, fetch=fetch)
    assert evidence.outcome == "NEUTRAL"
    assert evidence.strength == 0.0
    assert evidence.details["outcome"] == "fetch_failed"


def test_a_server_error_is_neutral(make_ctx: MakeContext) -> None:
    (evidence,) = _run(
        make_ctx, [_reference(ref_kind="cve", value=CVE)], online=True, fetch=_canned(status=503)
    )
    assert evidence.outcome == "NEUTRAL"
    assert evidence.details["outcome"] == "unexpected_status"


def test_a_record_naming_no_product_is_neutral(make_ctx: MakeContext) -> None:
    (evidence,) = _run(
        make_ctx,
        [_reference(ref_kind="cve", value=CVE)],
        online=True,
        fetch=_canned(state="PUBLISHED"),
    )
    assert evidence.outcome == "NEUTRAL"
    assert evidence.details["outcome"] == "no_product"


def test_cve_urls_follow_the_cvelist_layout() -> None:
    assert cve_url("2024", "1234").endswith("cves/2024/1xxx/CVE-2024-1234.json")
    assert cve_url("2021", "0001").endswith("cves/2021/0xxx/CVE-2021-0001.json")
    assert cve_url("2025", "45678").endswith("cves/2025/45xxx/CVE-2025-45678.json")
    assert cve_url("2024", "1234").startswith("https://")


def test_a_malformed_cve_id_is_reported_without_a_request() -> None:
    lookup = fetch_cve("not-a-cve")
    assert lookup.error == "not a CVE ID"
    assert lookup.url == ""


def test_cve_json_parsing_keeps_real_products_and_drops_placeholders() -> None:
    record: dict[str, Any] = {
        "cveMetadata": {"state": "published"},
        "containers": {
            "cna": {  # codespell:ignore cna
                "affected": [
                    {"vendor": "n/a", "product": "libhdr"},
                    {"vendor": "Example", "product": "unspecified", "packageName": "libhdr-dev"},
                ]
            },
            "adp": [{"affected": [{"vendor": "Debian", "product": "libhdr"}]}],
        },
    }
    assert cve_state(record) == "PUBLISHED"
    assert cve_products(record) == ("Debian", "Example", "libhdr", "libhdr-dev")
    assert cve_products({}) == ()
    assert cve_state({}) is None


def test_a_fetched_body_becomes_a_lookup_with_its_hash() -> None:
    body = json.dumps(
        {
            "cveMetadata": {"state": "REJECTED"},
            "containers": {"cna": {"affected": []}},  # codespell:ignore cna
        }
    ).encode()
    lookup = _read_cve(CVE, "https://example.invalid/cve.json", 200, body)
    assert lookup.state == "REJECTED"
    assert lookup.products == ()
    assert lookup.body_sha256 == hashlib.sha256(body).hexdigest()
    assert lookup.error is None


def test_an_unreadable_or_oversized_body_is_an_error_not_a_verdict() -> None:
    broken = _read_cve(CVE, "https://example.invalid/cve.json", 200, b"{not json")
    assert broken.error is not None
    assert broken.state is None
    huge = _read_cve(CVE, "https://example.invalid/cve.json", 200, b"x" * (MAX_CVE_BYTES + 1))
    assert huge.error == "record exceeds the size cap"
    listed = _read_cve(CVE, "https://example.invalid/cve.json", 200, b"[1, 2]")
    assert listed.error == "not a JSON object"


# --- CWE IDs --------------------------------------------------------------------------------


def _trace(bug_type: str) -> TraceClaim:
    return claim(TraceClaim, format="asan", bug_type=bug_type)


def test_a_cwe_incompatible_with_the_trace_refutes(make_ctx: MakeContext) -> None:
    claims = [_trace("heap-buffer-overflow"), _reference(ref_kind="cwe", value="CWE-79")]
    (evidence,) = _run(make_ctx, claims)
    assert evidence.outcome == "REFUTES"
    assert evidence.strength == -0.4
    assert evidence.details["outcome"] == "cwe_incompatible"
    assert evidence.details["bug_types"] == ["heap-buffer-overflow"]
    assert "CWE-122" in evidence.details["compatible"]


def test_a_compatible_cwe_is_neutral(make_ctx: MakeContext) -> None:
    claims = [_trace("heap-buffer-overflow"), _reference(ref_kind="cwe", value="CWE-122")]
    (evidence,) = _run(make_ctx, claims)
    assert evidence.outcome == "NEUTRAL"
    assert evidence.strength == 0.0
    assert evidence.details["outcome"] == "compatible"


def test_an_unknown_cwe_is_never_called_incompatible(make_ctx: MakeContext) -> None:
    claims = [_trace("heap-buffer-overflow"), _reference(ref_kind="cwe", value="CWE-99999")]
    (evidence,) = _run(make_ctx, claims)
    assert evidence.outcome == "NEUTRAL"
    assert evidence.details["outcome"] == "unknown_cwe"


def test_an_unknown_bug_type_leaves_the_cwe_unjudged(make_ctx: MakeContext) -> None:
    claims = [_trace("wibble-fault"), _reference(ref_kind="cwe", value="CWE-79")]
    (evidence,) = _run(make_ctx, claims)
    assert evidence.outcome == "NEUTRAL"
    assert evidence.details["outcome"] == "no_bug_type"


def test_without_a_trace_no_cwe_is_judged(make_ctx: MakeContext) -> None:
    (evidence,) = _run(make_ctx, [_reference(ref_kind="cwe", value="CWE-79")])
    assert evidence.outcome == "NEUTRAL"
    assert evidence.details["outcome"] == "no_bug_type"


def test_a_cwe_on_an_impact_claim_is_checked_too(make_ctx: MakeContext) -> None:
    claims = [_trace("heap-buffer-overflow"), claim(ImpactClaim, cwe="CWE-89")]
    (evidence,) = _run(make_ctx, claims)
    assert evidence.outcome == "REFUTES"
    assert evidence.details["cwe"] == "CWE-89"


def test_the_same_cwe_from_two_claims_is_one_item(make_ctx: MakeContext) -> None:
    reference = _reference(ref_kind="cwe", value="CWE-79")
    impact = claim(ImpactClaim, cwe="79")
    claims = [_trace("heap-buffer-overflow"), reference, impact]
    (evidence,) = _run(make_ctx, claims)
    assert evidence.claim_ids == tuple(sorted({reference.id, impact.id}))


def test_an_impact_claim_without_a_cwe_produces_nothing(make_ctx: MakeContext) -> None:
    assert _run(make_ctx, [_trace("heap-buffer-overflow"), claim(ImpactClaim)]) == []


def test_a_valgrind_bug_type_spelling_is_recognised(make_ctx: MakeContext) -> None:
    claims = [_trace("invalid-write"), _reference(ref_kind="cwe", value="CWE-787")]
    (evidence,) = _run(make_ctx, claims)
    assert evidence.details["outcome"] == "compatible"


# --- the bundled table ------------------------------------------------------------------------


def test_the_bundled_table_is_self_consistent() -> None:
    table = cwe_compat()
    assert table.version == "1"
    assert table.knows(79) and table.knows(122)
    assert not table.knows(99999)
    assert table.family("Heap Buffer Overflow") == "heap-buffer-overflow"
    assert table.family("heap_buffer_overflow") == "heap-buffer-overflow"
    assert table.family("nothing-like-this") is None
    for family, ids in table.families.items():
        assert ids, family
        assert ids <= table.titles.keys(), family


def test_cwe_ids_are_parsed_from_every_spelling() -> None:
    assert cwe_id("CWE-79") == 79
    assert cwe_id("cwe_79") == 79
    assert cwe_id(" 79 ") == 79
    assert cwe_id("CWE-") is None
    assert cwe_id("CVE-2026-1") is None


def test_a_table_citing_an_unlisted_cwe_is_rejected(tmp_path: Path) -> None:
    bad = tmp_path / "cwe_compat.yaml"
    bad.write_text(
        "version: 1\ncwes:\n  79: XSS\n"
        "bug_types:\n  x:\n    aliases: [x]\n    compatible: [1234]\n",
        encoding="utf-8",
    )
    with pytest.raises(CheckError, match="absent from 'cwes'"):
        load_cwe_compat(bad)


def test_a_table_without_bug_types_is_rejected(tmp_path: Path) -> None:
    bad = tmp_path / "cwe_compat.yaml"
    bad.write_text("version: 1\ncwes:\n  79: XSS\n", encoding="utf-8")
    with pytest.raises(CheckError, match="bug_types"):
        load_cwe_compat(bad)


def test_the_table_dataclass_reports_unknown_families() -> None:
    empty = CweCompat(version="0", titles={}, families={}, aliases={})
    assert empty.expected("nothing") == ()
    assert not empty.compatible("nothing", 79)


# --- the refutation gate, P4 and determinism --------------------------------------------------


class TestRefutationGate:
    """ADR 0003: only project-attributed, non-negated claims may be refuted."""

    def test_a_reporter_artifact_cwe_is_not_refuted(self, make_ctx: MakeContext) -> None:
        c = _reference(ref_kind="cwe", value="CWE-79", provenance="reporter_artifact")
        (evidence,) = _run(make_ctx, [_trace("heap-buffer-overflow"), c])
        assert evidence.outcome == "NEUTRAL"
        assert evidence.strength == 0.0
        assert evidence.details["gated"] == ["reporter_artifact"]
        assert evidence.details["withheld_strength"] == -0.4

    def test_a_negated_foreign_repo_claim_is_not_refuted(self, make_ctx: MakeContext) -> None:
        c = _reference(
            ref_kind="url",
            value="https://github.com/other/thing",
            repo_url="https://github.com/other/thing",
            negated=True,
        )
        (evidence,) = _run(make_ctx, [c])
        assert evidence.outcome == "NEUTRAL"
        assert evidence.details["gated"] == ["negated"]

    def test_support_is_never_gated(self, make_ctx: MakeContext, commits: dict[str, str]) -> None:
        c = _reference(ref_kind="commit", value=commits["v1.2.0"], provenance="third_party")
        (evidence,) = _run(make_ctx, [c])
        assert evidence.outcome == "SUPPORTS"


def test_identical_input_gives_identical_evidence(
    make_ctx: MakeContext, commits: dict[str, str]
) -> None:
    claims = [
        _reference(ref_kind="commit", value=commits["v1.2.0"]),
        _reference(ref_kind="cwe", value="CWE-79"),
        _trace("heap-buffer-overflow"),
        claim(FileClaim, path="src/util.c"),
    ]
    first = _run(make_ctx, claims)
    second = _run(make_ctx, claims)
    assert [e.id for e in first] == [e.id for e in second]
    assert [e.model_dump() for e in first] == [e.model_dump() for e in second]


def test_registered_and_runnable_through_the_runner(
    make_ctx: MakeContext, commits: dict[str, str]
) -> None:
    ctx = make_ctx(
        claims=[
            _reference(ref_kind="commit", value=commits["v1.2.0"]),
            _reference(
                ref_kind="url",
                value="https://github.com/other/thing",
                repo_url="https://github.com/other/thing",
            ),
        ]
    )
    (run,) = run_checks(ctx, checks=[References()])
    assert run.check_id == "C15"
    assert run.error is None
    assert sorted(e.outcome for e in run.evidence) == ["REFUTES", "SUPPORTS"]


def test_the_check_only_takes_reference_and_impact_claims() -> None:
    check = References()
    assert check.applies_to == frozenset({"reference", "impact"})
    assert check.name == "REFERENCES"
    assert check.group == "refs"
