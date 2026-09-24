# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""``nikasha cve`` (SPEC §8, §16.1): a CVE JSON 5.x record as a report.

Four contracts are pinned here. A bare CVE ID is refused offline *before* any network code
runs, and the online path is proven to use the cvelistV5 URL over HTTPS with a timeout and
a size cap (P3), against a booby-trapped ``urlopen``. A record is hostile input: wrong
types, placeholders, oversized lists, control characters and Markdown in names are all
tolerated, capped and never able to hide a section (P7). The conversion is deterministic
and produces a body the ordinary extractors read (P2). And end to end, against the real
vulnlab history, the record whose details are all in the code is never UNGROUNDED while the
one whose details are not is refuted across groups (P4).

The fixtures are fictional records about the demo library ``libhdr`` (``examples/vulnlab``),
never about real software. The two pipeline runs are shared by the module; the CLI's
output formats and exit codes reuse them through a stubbed ``check_cve`` so the file stays
in the fast suite.
"""

from __future__ import annotations

import json
import re
import shutil
import time
import urllib.error
import urllib.request
from email.message import Message
from http.client import HTTPMessage
from pathlib import Path
from typing import Any

import pytest
import typer
from typer.testing import CliRunner

from nikasha.checks.c15_references import MAX_CVE_BYTES, cve_url
from nikasha.errors import NikashaError
from nikasha.extract import extract_claims
from nikasha.integrations import cve as cve_module
from nikasha.integrations.cve import (
    MAX_AFFECTED,
    MAX_DESCRIPTION_CHARS,
    MAX_REFERENCES,
    MAX_VERSIONS,
    AffectedProduct,
    AffectedVersion,
    CveRecord,
    Metric,
    ProblemType,
    Reference,
    check_converted,
    check_cve,
    declared_target,
    exit_code_for,
    fetch_record,
    format_report,
    load_source,
    parse_record,
    read_record,
    register,
    render_body,
    to_report,
    version_text,
)
from nikasha.model.claims import ReferenceClaim, VersionClaim

ROOT = Path(__file__).resolve().parents[3]
FIXTURES = ROOT / "tests" / "fixtures" / "cve"
GENUINE = FIXTURES / "CVE-2026-00001.json"
CONTRADICTED = FIXTURES / "CVE-2026-00002.json"
REJECTED = FIXTURES / "CVE-2026-00003.json"
HOSTILE = FIXTURES / "hostile-shapes.json"

runner = CliRunner()

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")


# --- builders -------------------------------------------------------------------------------


def record_of(path: Path) -> CveRecord:
    return read_record(path.read_bytes())


def report_of(path: Path) -> Any:
    return to_report(record_of(path), uri=str(path))


def make_record(**fields: Any) -> CveRecord:
    """A record with every field empty unless a test says otherwise."""
    defaults: dict[str, Any] = {
        "cve_id": "CVE-2026-00009",
        "state": "PUBLISHED",
        "title": None,
        "descriptions": (),
        "rejected_reasons": (),
        "affected": (),
        "references": (),
        "problem_types": (),
        "metrics": (),
        "date_published": None,
        "body_sha256": "",
    }
    return CveRecord(**{**defaults, **fields})


def minimal_json(**authority: Any) -> bytes:
    document = {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.1",
        "cveMetadata": {"cveId": "CVE-2026-00009", "state": "PUBLISHED"},
        "containers": {"cna": authority},  # codespell:ignore cna
    }
    return json.dumps(document).encode()


def make_app() -> typer.Typer:
    app = typer.Typer(no_args_is_help=True, pretty_exceptions_enable=False)
    register(app)

    @app.command()
    def other() -> None:
        """A second command, so ``cve`` stays a subcommand as it is in the real CLI."""

    return app


class _Response:
    """What ``urlopen`` returns, reduced to what the fetcher reads."""

    def __init__(self, body: bytes, url: str, status: int = 200) -> None:
        self._body = body
        self.url = url
        self.status = status

    def read(self, n: int = -1) -> bytes:
        return self._body if n < 0 else self._body[:n]

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *args: object) -> None:
        return None


def serve(
    monkeypatch: pytest.MonkeyPatch,
    body: bytes,
    *,
    status: int = 200,
    final_url: str | None = None,
    raising: Exception | None = None,
) -> list[tuple[Any, Any]]:
    """Replace the fetcher's opener and record every call it receives."""
    calls: list[tuple[Any, Any]] = []

    def urlopen(request: Any, timeout: Any = None) -> _Response:
        calls.append((request, timeout))
        if raising is not None:
            raise raising
        return _Response(body, final_url or request.full_url, status)

    monkeypatch.setattr(cve_module, "_open", urlopen)
    return calls


def boobytrap(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    """Every way to the network, booby-trapped; the list records any attempt."""
    attempts: list[Any] = []

    def boom(*args: Any, **kwargs: Any) -> None:
        attempts.append(args)
        raise AssertionError("an offline run must make no network call (P3)")

    monkeypatch.setattr("urllib.request.urlopen", boom)
    monkeypatch.setattr("urllib.request.OpenerDirector.open", boom)
    monkeypatch.setattr(cve_module, "_open", boom)
    return attempts


# --- reading a record -------------------------------------------------------------------------


def test_the_genuine_record_parses_every_block() -> None:
    record = record_of(GENUINE)
    assert record.cve_id == "CVE-2026-00001"
    assert record.state == "PUBLISHED"
    assert record.title is not None and record.title.startswith("libhdr: heap buffer overflow")
    assert len(record.descriptions) == 1  # English preferred; the German text is dropped
    assert "util_copy_value()" in record.descriptions[0]
    assert record.rejected_reasons == ()
    (product,) = record.affected
    assert (product.vendor, product.product, product.default_status) == (
        "vulnlab",
        "libhdr",
        "unaffected",
    )
    assert product.versions == (
        AffectedVersion("1.2.0", "affected", version_type="semver"),
        AffectedVersion("1.3.0", "unaffected", less_than="*", version_type="semver"),
    )
    assert [r.url for r in record.references] == [
        "https://vulnlab.example.invalid/advisories/2026-001",
        "https://vulnlab.example.invalid/issues/3",
    ]
    assert record.references[0].tags == ("vendor-advisory",)
    assert record.problem_types == (ProblemType("CWE-122", "Heap-based Buffer Overflow"),)
    assert record.metrics == (
        Metric("3.1", "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H", 5.5, "Medium"),
    )
    assert record.date_published is not None
    assert record.date_published.isoformat() == "2026-04-30"
    assert len(record.body_sha256) == 64
    assert record.warnings == ()


def test_hostile_shapes_are_tolerated_capped_and_reported() -> None:
    record = record_of(HOSTILE)
    assert record.cve_id == "CVE-2026-00004"  # lower-case input, normalized
    assert record.state == "PUBLISHED"  # the control character is dropped, not the state
    assert record.date_published is None
    assert record.title == "<!-- hidden --> libhdr title with code and tabs"
    assert record.descriptions == ()
    # Of five affected entries, two are not objects and one is all placeholders.
    libhdr, libfoo = record.affected
    assert libhdr.product == "<!-- libhdr"
    assert libhdr.vendor is None  # a name that was only fence characters is no name
    assert libhdr.package_name == "libhdr-dev"
    assert libhdr.repo is None  # http:// is not https://
    assert libhdr.default_status is None
    assert libhdr.versions == (
        AffectedVersion("1.2.0", "affected"),  # "not a version!" as lessThan is dropped
        AffectedVersion("1.1.0", "unknown"),
    )
    assert libfoo == AffectedProduct(product="libfoo")
    assert record.references == (
        Reference("https://ok.example.invalid/a", ("patch", "x_refsource_MISC")),
    )
    assert record.problem_types == (
        ProblemType("CWE-122", "Heap-based Buffer Overflow"),
        ProblemType(None, "Free text only"),
    )
    assert record.metrics == (
        Metric("3.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
        Metric(
            "4.0", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", None, "High"
        ),
        Metric("2.0", "AV:N/AC:L/Au:N/C:P/I:P/A:P", 7.5),
    )
    blob = "\n".join(record.warnings)
    assert "dataType is 'SOMETHING_ELSE'" in blob
    assert "dataVersion is '5'" in blob
    assert "descriptions is not a list" in blob
    assert "3 version entries were skipped" in blob
    assert "3 affected entries were skipped" in blob
    assert "4 reference entries were skipped" in blob
    assert "1 problem type entry was skipped" in blob
    assert "1 CVSS metric entry was skipped" in blob


@pytest.mark.parametrize(
    ("body", "message"),
    [
        (b"{not json", "not a CVE JSON record"),
        (b"[1, 2, 3]", "top level is not a JSON object"),
        (b'{"containers": {}}', "cveMetadata is missing"),
        (b'{"cveMetadata": {"cveId": "nope"}}', "cveId is missing or malformed"),
        (b"[" * 100_000 + b"]" * 100_000, "not a CVE JSON record"),
        (b"x" * (MAX_CVE_BYTES + 1), "exceeds"),
    ],
    ids=["not-json", "list", "no-metadata", "bad-id", "deeply-nested", "oversized"],
)
def test_unreadable_records_are_clear_errors_never_verdicts(body: bytes, message: str) -> None:
    with pytest.raises(NikashaError, match=message):
        read_record(body)


def test_a_bom_and_a_missing_authority_container_are_survivable() -> None:
    record = read_record(b"\xef\xbb\xbf" + b'{"cveMetadata": {"cveId": "CVE-2026-00009"}}')
    assert record.cve_id == "CVE-2026-00009"
    assert "no numbering-authority container" in "\n".join(record.warnings)
    assert render_body(record).startswith("# CVE record\n")


def test_the_requested_id_stands_in_and_mismatches_are_noted() -> None:
    fallback = parse_record({"cveMetadata": {"state": "PUBLISHED"}}, expected_id="CVE-2026-00009")
    assert fallback.cve_id == "CVE-2026-00009"
    assert any("using CVE-2026-00009" in w for w in fallback.warnings)
    other = parse_record({"cveMetadata": {"cveId": "CVE-2026-00001"}}, expected_id="CVE-2026-00009")
    assert other.cve_id == "CVE-2026-00001"
    assert any("not the requested CVE-2026-00009" in w for w in other.warnings)


def test_every_list_is_capped_with_a_warning() -> None:
    body = minimal_json(
        descriptions=[{"lang": "en", "value": "x" * (MAX_DESCRIPTION_CHARS * 5)}],
        affected=[{"product": f"p{i}"} for i in range(MAX_AFFECTED + 40)]
        + [{"product": "q", "versions": [{"version": f"1.{i}"} for i in range(MAX_VERSIONS + 5)]}],
        references=[{"url": f"https://r.example.invalid/{i}"} for i in range(MAX_REFERENCES + 436)],
    )
    record = read_record(body)
    assert len(record.descriptions[0]) == MAX_DESCRIPTION_CHARS
    assert len(record.affected) == MAX_AFFECTED
    assert len(record.references) == MAX_REFERENCES
    blob = "\n".join(record.warnings)
    assert f"the first {MAX_AFFECTED} were kept" in blob
    assert f"the first {MAX_REFERENCES} were kept" in blob
    assert f"the first {MAX_VERSIONS} were kept" in blob


# --- the record as a report -------------------------------------------------------------------


def test_the_converted_report_is_a_cve_json_report_with_its_target_declared() -> None:
    report = report_of(GENUINE)
    assert report.source.kind == "cve_json"
    assert report.source.uri == str(GENUINE)
    assert report.title == (
        "CVE-2026-00001: libhdr: heap buffer overflow in util_copy_value() with long header values"
    )
    assert report.reported_at is not None and report.reported_at.isoformat() == "2026-04-30"
    assert report.declared_target is not None
    assert report.declared_target.product == "libhdr"
    assert report.declared_target.repo_url is None
    assert report.declared_target.versions == ("1.2.0",)
    assert report.code_blocks == ()
    assert report.warnings == ()
    body = report.body
    assert "## Affected\n\n- libhdr by vulnlab: version 1.2.0 (affected); " in body
    assert "unaffected: 1.3.0 onwards; default status: unaffected" in body
    assert "- CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H 5.5 (Medium) · CWE-122" in body
    assert "- CWE-122: Heap-based Buffer Overflow" in body
    assert "- https://vulnlab.example.invalid/advisories/2026-001 (vendor-advisory)" in body
    assert body.index("## References") < body.index("## Description")
    assert body.rstrip().endswith("parses a crafted file.")


def test_the_body_never_repeats_the_records_own_id() -> None:
    """C15 must not be able to fetch the record and count it as support for itself."""
    for path in (GENUINE, CONTRADICTED, REJECTED):
        report = report_of(path)
        assert report.title.startswith(record_of(path).cve_id)
        assert "CVE-2026-0000" not in report.body


def test_a_description_naming_its_own_id_does_not_become_a_reference() -> None:
    """The prose may name the record itself; that mention must not reach C15."""
    body = minimal_json(
        descriptions=[
            {"lang": "en", "value": "Overflow in parse(). See cve-2026-00009 and CVE-2025-1234."}
        ],
        rejectedReasons=[{"lang": "en", "value": "CVE-2026-00009 duplicates CVE-2025-1234."}],
    )
    report = to_report(read_record(body))
    assert "2026-00009" not in report.body
    assert "See this record and CVE-2025-1234." in report.body
    values = [c.value for c in extract_claims(report).claims if isinstance(c, ReferenceClaim)]
    assert not any("2026-00009" in v for v in values), values
    assert any("CVE-2025-1234" in v for v in values), values


def test_conversion_is_deterministic() -> None:
    first = report_of(GENUINE)
    second = report_of(GENUINE)
    assert first.model_dump() == second.model_dump()
    assert first.id == second.id
    assert first.id != report_of(CONTRADICTED).id


def test_the_ordinary_extractors_read_the_converted_body() -> None:
    report = report_of(GENUINE)
    claims = extract_claims(report, product="libhdr").claims
    by_kind: dict[str, list[Any]] = {}
    for claim in claims:
        by_kind.setdefault(claim.kind, []).append(claim)
    versions = [c for c in by_kind["version"] if c.relation == "tested_on"]
    assert versions and all(c.parsed.raw == "1.2.0" for c in versions)
    assert all(c.product == "libhdr" for c in versions)
    assert {c.name for c in by_kind["symbol"]} >= {"util_copy_value"}
    assert {c.path for c in by_kind["file"]} == {"src/util.c"}
    assert {c.token for c in by_kind["option"]} == {"HDR_VALUE_MAX"}
    (impact,) = by_kind["impact"]
    assert (impact.cvss_score, impact.severity_word, impact.cwe) == (5.5, "Medium", "CWE-122")
    refs = {(c.ref_kind, c.value) for c in by_kind["reference"]}
    assert ("cwe", "CWE-122") in refs
    assert ("url", "https://vulnlab.example.invalid/advisories/2026-001") in refs
    # The unaffected range is information for the reader, never a version claim (P4).
    assert not any("1.3.0" in c.raw for c in by_kind["version"])


@pytest.mark.parametrize(
    ("entry", "text"),
    [
        (AffectedVersion("1.2.0", "affected"), "version 1.2.0 (affected)"),
        (AffectedVersion("1.0.0", "affected", less_than="1.3.0"), ">= 1.0.0, < 1.3.0 (affected)"),
        (
            AffectedVersion("1.0.0", "affected", less_than_or_equal="1.2.1"),
            ">= 1.0.0, <= 1.2.1 (affected)",
        ),
        (AffectedVersion("0", "affected", less_than="1.3.0"), "before 1.3.0 (affected)"),
        (AffectedVersion("0", "affected", less_than_or_equal="1.2.0"), "up to 1.2.0 (affected)"),
        (AffectedVersion("1.0.0", "affected", less_than="*"), "since 1.0.0 (affected)"),
        (AffectedVersion("*", "affected"), "all versions (affected)"),
        (AffectedVersion("1.3.0", "unaffected"), "unaffected: 1.3.0"),
        (AffectedVersion("1.3.0", "unaffected", less_than="*"), "unaffected: 1.3.0 onwards"),
        (
            AffectedVersion("1.3.0", "unaffected", less_than="1.4.0"),
            "unaffected: 1.3.0 to 1.4.0 (exclusive)",
        ),
        (AffectedVersion("0", "unknown", less_than="1.0.0"), "unknown: below 1.0.0"),
        (AffectedVersion("0", "unknown", less_than_or_equal="1.0.0"), "unknown: 1.0.0 or lower"),
    ],
)
def test_version_entries_are_written_in_the_forms_the_extractor_reads(
    entry: AffectedVersion, text: str
) -> None:
    assert version_text(entry) == text


def _version_claims(*entries: AffectedVersion) -> list[VersionClaim]:
    record = make_record(affected=(AffectedProduct(product="libhdr", versions=entries),))
    claims = extract_claims(to_report(record), product="libhdr").claims
    return [c for c in claims if isinstance(c, VersionClaim)]


def test_affected_ranges_become_range_claims_with_the_right_bounds() -> None:
    (ranged,) = _version_claims(AffectedVersion("1.0.0", "affected", less_than="1.3.0"))
    assert ranged.relation == "affected_range"
    assert (ranged.lower.raw, ranged.upper.raw, ranged.upper_inclusive) == ("1.0.0", "1.3.0", False)
    (capped,) = _version_claims(AffectedVersion("0", "affected", less_than_or_equal="1.2.0"))
    assert (capped.relation, capped.upper.raw, capped.upper_inclusive) == (
        "affected_range",
        "1.2.0",
        True,
    )
    (open_ended,) = _version_claims(AffectedVersion("0", "affected", less_than="1.3.0"))
    assert (open_ended.upper.raw, open_ended.upper_inclusive) == ("1.3.0", False)


def test_unaffected_and_unknown_versions_make_no_claim() -> None:
    assert (
        _version_claims(
            AffectedVersion("1.3.0", "unaffected", less_than="*"),
            AffectedVersion("1.3.0", "unaffected", less_than="1.4.0"),
            AffectedVersion("0", "unknown", less_than_or_equal="1.0.0"),
        )
        == []
    )


def test_names_cannot_open_a_code_block_or_hide_the_sections_after_them() -> None:
    report = report_of(HOSTILE)
    assert report.code_blocks == ()
    assert "```" not in report.body and "~" not in report.body
    urls = {c.value for c in extract_claims(report).claims if isinstance(c, ReferenceClaim)}
    assert "https://ok.example.invalid/a" in urls
    assert "\x00" not in report.body and "\u202e" not in report.title


def test_a_description_is_prose_with_its_line_breaks_and_without_controls() -> None:
    body = minimal_json(
        descriptions=[{"lang": "en", "value": "line one\r\nline two\x07\u200b\ttabbed\u00a0nbsp"}]
    )
    (text,) = read_record(body).descriptions
    assert text == "line one\nline two\ttabbed nbsp"


def test_a_rejected_record_is_converted_with_its_notice_and_a_warning() -> None:
    record = record_of(REJECTED)
    assert record.state == "REJECTED"
    assert record.descriptions == ()
    assert len(record.rejected_reasons) == 1
    report = to_report(record)
    assert report.title == "CVE-2026-00003"
    assert report.declared_target is None
    assert "## Rejected\n\nThis CVE ID was withdrawn" in report.body
    assert any(w.startswith("CVE-2026-00003 is REJECTED") for w in report.warnings)


def test_the_declared_target_carries_product_repo_and_every_affected_range() -> None:
    record = make_record(
        affected=(
            AffectedProduct(vendor="n/a"),
            AffectedProduct(
                product="libhdr",
                repo="https://github.com/example/libhdr",
                versions=(
                    AffectedVersion("1.2.0", "affected"),
                    AffectedVersion("1.0.0", "affected", less_than="1.3.0"),
                    AffectedVersion("0", "affected", less_than_or_equal="0.9.0"),
                    AffectedVersion("2.0.0", "affected", less_than="*"),
                    AffectedVersion("1.2.0", "affected"),
                    AffectedVersion("1.3.0", "unaffected"),
                ),
            ),
        )
    )
    target = declared_target(record)
    assert target is not None
    assert target.product == "libhdr"
    assert target.repo_url == "https://github.com/example/libhdr"
    assert target.versions == ("1.2.0", ">=1.0.0 <1.3.0", "<=0.9.0", ">=2.0.0")
    assert declared_target(make_record()) is None
    assert report_of(CONTRADICTED).declared_target.versions == ("<=1.2.0",)
    assert "- libhdr, repository https://github.com/example/libhdr: " in render_body(record)


# --- offline and online ---------------------------------------------------------------------


def test_a_bare_id_is_refused_offline_before_any_network_code_runs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts = boobytrap(monkeypatch)
    with pytest.raises(NikashaError, match="needs --online") as info:
        load_source("CVE-2026-00001")
    assert "no network request" in str(info.value)
    with pytest.raises(NikashaError, match="needs --online"):
        check_cve("cve-2026-00001", repo="unused")
    result = runner.invoke(make_app(), ["cve", "CVE-2026-00001"])
    assert result.exit_code == 1, result.output
    assert "--online" in result.output
    assert "Traceback" not in result.output
    assert attempts == []


def test_an_id_is_fetched_from_cvelist_over_https_with_a_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = serve(monkeypatch, GENUINE.read_bytes())
    record, uri, fetched = load_source("CVE-2026-00001", online=True)
    ((request, timeout),) = calls
    expected = cve_url("2026", "00001")
    assert request.full_url == expected
    assert expected.startswith("https://raw.githubusercontent.com/CVEProject/cvelistV5/")
    assert expected.endswith("/cves/2026/0xxx/CVE-2026-00001.json")
    assert timeout == 10.0
    assert request.get_header("User-agent", "").startswith("nikasha/")
    assert record.cve_id == "CVE-2026-00001"
    assert record.warnings == ()
    assert uri == fetched == expected


def test_a_fetched_record_for_another_id_is_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    serve(monkeypatch, GENUINE.read_bytes())
    record, _ = fetch_record("CVE-2026-00009")
    assert record.cve_id == "CVE-2026-00001"
    assert any("not the requested CVE-2026-00009" in w for w in record.warnings)


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"body": b"x" * (MAX_CVE_BYTES + 1)}, "exceeds"),
        ({"body": b"{}", "status": 204}, "HTTP 204"),
        ({"body": b"{}", "final_url": "http://raw.githubusercontent.com/x"}, "off HTTPS"),
        (
            {
                "body": b"",
                "raising": urllib.error.HTTPError("https://x", 404, "Not Found", Message(), None),
            },
            "HTTP 404",
        ),
        (
            {
                "body": b"",
                "raising": urllib.error.HTTPError("https://x", 503, "Busy", Message(), None),
            },
            "HTTP 503",
        ),
        ({"body": b"", "raising": urllib.error.URLError("no route to host")}, "could not fetch"),
        ({"body": b"", "raising": TimeoutError("timed out")}, "could not fetch"),
        ({"body": b"not json"}, "not a CVE JSON record"),
    ],
    ids=[
        "oversized",
        "odd-status",
        "redirect-off-https",
        "404",
        "503",
        "urlerror",
        "timeout",
        "body",
    ],
)
def test_online_failures_are_clear_errors(
    monkeypatch: pytest.MonkeyPatch, kwargs: dict[str, Any], message: str
) -> None:
    serve(monkeypatch, **kwargs)
    with pytest.raises(NikashaError, match=message):
        fetch_record("CVE-2026-00001")


def test_fetch_record_refuses_a_malformed_id_without_a_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts = boobytrap(monkeypatch)
    with pytest.raises(NikashaError, match="not a CVE ID"):
        fetch_record("CVE-1")
    assert attempts == []


def test_a_file_named_like_an_id_is_read_offline(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    attempts = boobytrap(monkeypatch)
    (tmp_path / "CVE-2026-00001").write_bytes(GENUINE.read_bytes())
    monkeypatch.chdir(tmp_path)
    record, uri, fetched = load_source("CVE-2026-00001")
    assert record.cve_id == "CVE-2026-00001"
    assert uri == "CVE-2026-00001"
    assert fetched is None
    assert attempts == []


@pytest.mark.parametrize("target", ["http://example.invalid/x", "ftp://example.invalid/x"])
def test_a_redirect_off_https_is_refused_before_it_is_followed(target: str) -> None:
    handler = cve_module._HttpsOnlyRedirect()
    request = urllib.request.Request("https://raw.githubusercontent.com/x")
    with pytest.raises(urllib.error.URLError, match="off HTTPS"):
        handler.redirect_request(request, None, 302, "Found", HTTPMessage(), target)
    followed = handler.redirect_request(
        request, None, 302, "Found", HTTPMessage(), "https://example.invalid/y"
    )
    assert followed is not None
    assert followed.full_url == "https://example.invalid/y"


def test_the_fetch_goes_through_the_https_only_opener(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[list[type]] = []

    def open_(self: urllib.request.OpenerDirector, request: Any, *a: Any, **k: Any) -> Any:
        seen.append([type(h) for h in self.handlers])
        return _Response(GENUINE.read_bytes(), request.full_url)

    monkeypatch.setattr("urllib.request.OpenerDirector.open", open_)
    record, _ = fetch_record("CVE-2026-00001")
    assert record.cve_id == "CVE-2026-00001"
    (handlers,) = seen
    assert cve_module._HttpsOnlyRedirect in handlers
    assert urllib.request.HTTPRedirectHandler not in handlers


def test_report_only_refuses_html() -> None:
    result = runner.invoke(make_app(), ["cve", str(GENUINE), "--report-only", "--format", "html"])
    assert result.exit_code == 2, result.output
    assert "report-only" in result.output


def test_an_online_id_through_the_cli_records_where_it_came_from(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    serve(monkeypatch, GENUINE.read_bytes())
    expected = cve_url("2026", "00001")
    result = runner.invoke(
        make_app(), ["cve", "CVE-2026-00001", "--online", "--report-only", "--format", "json"]
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["report"]["source"]["uri"] == expected

    captured: dict[str, Any] = {}

    def fake_check(report: Any, **kwargs: Any) -> Any:
        captured.update(kwargs, uri=report.source.uri)
        raise NikashaError("stop here")

    monkeypatch.setattr(cve_module, "check_converted", fake_check)
    result = runner.invoke(make_app(), ["cve", "CVE-2026-00001", "--online"])
    assert result.exit_code == 1, result.output
    assert captured["fetched_urls"] == (expected,)
    assert captured["uri"] == expected
    assert captured["online"] is True


def test_the_cli_passes_nikasha_toml_to_the_check(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = tmp_path / "nikasha.toml"
    config.write_text("[thresholds]\ngrounded_score = 97\n\n[scoring]\nprior = -0.5\n")
    captured: dict[str, Any] = {}

    def fake_check(source: str, **kwargs: Any) -> Any:
        captured.update(kwargs)
        raise NikashaError("stop here")

    monkeypatch.setattr(cve_module, "check_cve", fake_check)
    result = runner.invoke(make_app(), ["cve", str(GENUINE), "--config", str(config)])
    assert result.exit_code == 1, result.output
    assert captured["thresholds"].grounded_score == 97
    assert captured["prior"] == -0.5
    assert captured["llm"] is None


def _default_affected(*unaffected: str) -> bytes:
    return minimal_json(
        affected=[
            {
                "product": "libhdr",
                "defaultStatus": "affected",
                "versions": [
                    {"version": v, "lessThan": "*", "status": "unaffected"} for v in unaffected
                ],
            }
        ]
    )


def test_default_status_affected_with_one_open_unaffected_range_bounds_the_versions() -> None:
    record = read_record(_default_affected("1.3.0"))
    target = declared_target(record)
    assert target is not None
    assert target.versions == ("<1.3.0",)
    assert any("derived from defaultStatus" in w for w in record.warnings)
    assert "before 1.3.0 (affected)" in render_body(record)


def test_default_status_is_not_read_when_the_shape_is_ambiguous() -> None:
    target = declared_target(read_record(_default_affected("1.3.0", "1.2.5")))
    assert target is not None
    assert target.versions == ()


def test_a_missing_file_is_a_clear_error(tmp_path: Path) -> None:
    with pytest.raises(NikashaError, match="cannot read"):
        load_source(str(tmp_path / "nope.json"))
    with pytest.raises(NikashaError, match="cannot read"):
        load_source(str(tmp_path))


# --- end to end against the vulnlab history --------------------------------------------------


@pytest.fixture(scope="module")
def checked(vulnlab_repo: Path, tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    index_dir = tmp_path_factory.mktemp("cve-index")
    return {
        path.stem: check_cve(str(path), repo=str(vulnlab_repo), index_path=index_dir / path.stem)
        for path in (GENUINE, CONTRADICTED)
    }


@needs_git
def test_the_record_whose_details_are_in_the_code_is_never_ungrounded(checked) -> None:
    report = checked[GENUINE.stem]
    assert report.verdict.label != "UNGROUNDED", report.verdict
    assert report.verdict.label in {"GROUNDED", "MIXED"}, report.verdict
    assert report.result.report.source.kind == "cve_json"
    assert report.result.target is not None and report.result.target.ref_name == "v1.2.0"
    assert report.result.environment.mode == "offline"
    assert report.result.environment.fetched_urls == ()
    outcomes = {(e.check_id, e.details.get("outcome")): e.outcome for e in report.evidence}
    assert outcomes[("C02", "exists")] == "SUPPORTS"
    assert outcomes[("C03", "defined_core")] == "SUPPORTS"
    assert outcomes[("C14", "present")] == "SUPPORTS"
    assert not [e for e in report.evidence if e.outcome == "REFUTES"]


@needs_git
def test_the_record_whose_details_are_not_in_the_code_is_refuted_across_groups(checked) -> None:
    report = checked[CONTRADICTED.stem]
    assert report.verdict.label in {"UNGROUNDED", "MIXED"}, report.verdict
    assert report.result.target is not None and report.result.target.ref_name == "v1.2.0"
    assert "affected-range upper bound" in report.result.target.method
    refutations = [e for e in report.evidence if e.outcome == "REFUTES"]
    assert len({e.group for e in refutations}) >= 2, refutations
    assert {e.check_id for e in refutations} >= {"C03", "C14"}


@needs_git
def test_every_run_is_deterministic(vulnlab_repo: Path, tmp_path: Path, checked) -> None:
    again = check_cve(str(GENUINE), repo=str(vulnlab_repo), index_path=tmp_path / "again.sqlite")
    first = checked[GENUINE.stem].result.to_json(include_timings=False)
    assert again.result.to_json(include_timings=False) == first


@needs_git
def test_no_output_describes_a_person(checked) -> None:
    """P1: the wording targets the record's claims, never whoever wrote them."""
    banned = ("ai-generated", "slop", "fabricated by", "fake", "hallucinat")
    for name, report in checked.items():
        blob = report.result.to_json(include_timings=False).lower()
        for word in banned:
            assert word not in blob, f"{name} mentions {word!r}"


@needs_git
def test_a_record_without_a_resolvable_version_is_insufficient(vulnlab_repo: Path) -> None:
    record = make_record(
        descriptions=("util_copy_value() in src/util.c copies without a bound.",),
        affected=(AffectedProduct(product="libhdr"),),
    )
    report = check_converted(to_report(record), repo=str(vulnlab_repo))
    assert report.verdict.label == "INSUFFICIENT"
    assert report.verdict.rule is not None and report.verdict.rule.startswith("2: the report")
    assert report.evidence == ()


@needs_git
def test_explicit_flags_override_the_record(vulnlab_repo: Path, tmp_path: Path) -> None:
    report = check_cve(
        str(GENUINE), repo=str(vulnlab_repo), version="1.3.0", index_path=tmp_path / "i.sqlite"
    )
    assert report.result.target is not None and report.result.target.ref_name == "v1.3.0"


# --- the command ----------------------------------------------------------------------------


def test_register_adds_the_cve_command() -> None:
    app = make_app()
    assert "cve" in {c.name for c in app.registered_commands}
    result = runner.invoke(app, ["cve", "--help"])
    assert result.exit_code == 0, result.output
    assert "--online" in result.output and "--report-only" in result.output


def test_the_real_cli_lists_cve() -> None:
    from nikasha.cli import app  # noqa: PLC0415

    assert "cve" in runner.invoke(app, ["--help"]).output


def test_report_only_prints_the_converted_markdown_and_stops(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    attempts = boobytrap(monkeypatch)
    result = runner.invoke(make_app(), ["cve", str(GENUINE), "--report-only"])
    assert result.exit_code == 0, result.output
    assert "## Affected" in result.stdout and "version 1.2.0 (affected)" in result.stdout
    out = tmp_path / "report.json"
    result = runner.invoke(
        make_app(), ["cve", str(REJECTED), "--report-only", "--format", "json", "-o", str(out)]
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["report"]["source"]["kind"] == "cve_json"
    assert payload["verdict"] is None
    assert "REJECTED" in result.output  # the warning is repeated on stderr
    assert attempts == []


def test_report_only_reads_stdin() -> None:
    result = runner.invoke(
        make_app(), ["cve", "-", "--report-only"], input=GENUINE.read_text(encoding="utf-8")
    )
    assert result.exit_code == 0, result.output
    assert "util_copy_value()" in result.stdout


@pytest.mark.parametrize(
    ("args", "code"),
    [
        (["cve", "missing.json"], 1),
        (["cve", "x.json", "--format", "pdf"], 2),
        (["cve", "x.json", "--fail-on", "SOMETIMES"], 2),
    ],
)
def test_bad_input_and_options_fail_cleanly(args: list[str], code: int) -> None:
    result = runner.invoke(make_app(), args)
    assert result.exit_code == code, result.output
    assert "Traceback" not in result.output


@pytest.mark.parametrize(
    ("label", "fail_on", "code"),
    [
        ("GROUNDED", None, 0),
        ("MIXED", None, 10),
        ("UNGROUNDED", None, 20),
        ("INSUFFICIENT", None, 30),
        ("ERROR", None, 1),
        ("GROUNDED", "mixed", 0),
        ("MIXED", "MIXED", 1),
        ("UNGROUNDED", "MIXED", 1),
        ("ERROR", "MIXED", 1),
    ],
)
def test_exit_codes_follow_the_verdict_and_fail_on(
    label: str, fail_on: str | None, code: int
) -> None:
    assert exit_code_for(label, fail_on) == code


@needs_git
class TestOutputs:
    """Formats and exit codes, on the shared run through a stubbed ``check_cve``."""

    @pytest.fixture(autouse=True)
    def _stub(self, monkeypatch: pytest.MonkeyPatch, checked: dict[str, Any]) -> None:
        self.genuine = checked[GENUINE.stem]

        def fake(source: str, **kwargs: Any) -> Any:
            return self.genuine

        monkeypatch.setattr(cve_module, "check_cve", fake)

    def test_terminal_output_and_exit_code(self) -> None:
        result = runner.invoke(make_app(), ["cve", str(GENUINE), "--repo", "unused", "--ascii"])
        assert result.exit_code == exit_code_for(self.genuine.verdict.label, None), result.output
        assert self.genuine.verdict.label in result.output
        assert str(GENUINE) in result.output
        quiet = runner.invoke(make_app(), ["cve", str(GENUINE), "--quiet", "--explain"])
        assert quiet.exit_code == result.exit_code

    def test_json_markdown_and_html_use_the_shared_renderers(self, tmp_path: Path) -> None:
        for fmt in ("json", "markdown", "html"):
            out = tmp_path / f"out.{fmt}"
            result = runner.invoke(
                make_app(), ["cve", str(GENUINE), "--format", fmt, "-o", str(out)]
            )
            assert result.exit_code == exit_code_for(self.genuine.verdict.label, None), (
                result.output
            )
            assert out.read_text(encoding="utf-8") == format_report(self.genuine, fmt, str(GENUINE))
        payload = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))
        assert payload["report"]["source"]["kind"] == "cve_json"
        assert payload["verdict"]["label"] == self.genuine.verdict.label
        assert (tmp_path / "out.html").read_text(encoding="utf-8").lstrip().startswith("<!")

    def test_fail_on_turns_a_verdict_into_exit_1(self) -> None:
        label = self.genuine.verdict.label
        result = runner.invoke(make_app(), ["cve", str(GENUINE), "--fail-on", label, "--quiet"])
        assert result.exit_code == 1


# --- every regex is linear ------------------------------------------------------------------

_PATTERNS = sorted(
    (name, value) for name, value in vars(cve_module).items() if isinstance(value, re.Pattern)
)
_HOSTILE_TEXTS = {
    "letters": "a" * 40_000,
    "dotted": "1." * 20_000,
    "slashes": "https://" + "a/" * 20_000,
    "cvss": "CVSS:3.1" + "/AV:N" * 8_000,
    "dashes": "CVE-2026-" + "0" * 40_000,
    "colons": "AV:N/" * 8_000,
}


def test_patterns_were_collected() -> None:
    assert len(_PATTERNS) >= 8


@pytest.mark.parametrize(("name", "pattern"), _PATTERNS, ids=[n for n, _ in _PATTERNS])
@pytest.mark.parametrize("text", list(_HOSTILE_TEXTS.values()), ids=list(_HOSTILE_TEXTS))
def test_regexes_are_linear_on_hostile_input(
    name: str, pattern: re.Pattern[str], text: str
) -> None:
    started = time.perf_counter()
    for _ in pattern.finditer(text):
        pass
    pattern.match(text)
    elapsed = time.perf_counter() - started
    assert elapsed < 0.5, f"{name} took {elapsed:.3f}s"


@needs_git
def test_a_derived_affected_range_resolves_against_the_history(
    vulnlab_repo: Path, tmp_path: Path
) -> None:
    report = check_converted(
        to_report(read_record(_default_affected("1.3.0"))),
        repo=str(vulnlab_repo),
        index_path=tmp_path / "i.sqlite",
    )
    assert report.result.target is not None
    assert report.result.target.ref_name == "v1.2.1"  # the newest release below the fix, 1.3.0


@needs_git
def test_tightened_thresholds_move_the_cve_verdict_as_they_move_check(
    vulnlab_repo: Path, tmp_path: Path
) -> None:
    from nikasha.fuse.verdict import Thresholds  # noqa: PLC0415

    config = tmp_path / "nikasha.toml"
    config.write_text("[thresholds]\ngrounded_score = 100\n")
    args = ["cve", str(GENUINE), "--repo", str(vulnlab_repo), "--format", "json"]
    result = runner.invoke(make_app(), [*args, "--config", str(config)])
    assert result.exit_code != 1, result.output
    label = json.loads(result.stdout)["verdict"]["label"]
    direct = check_converted(
        report_of(GENUINE),
        repo=str(vulnlab_repo),
        thresholds=Thresholds(grounded_score=100),
        index_path=tmp_path / "direct.sqlite",
    )
    assert label == direct.verdict.label
    assert label != "GROUNDED"
