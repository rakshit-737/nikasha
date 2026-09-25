# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The release, screenshots and docs workflows follow the workflow rules (SPEC §21.2).

Every action is pinned by a full commit SHA with a version comment, permissions default to
none and are granted per job, checkout never persists credentials, no ``run:`` script
interpolates ``github.event`` text, and ``pull_request_target`` is never used. Also covers
the pure helpers of ``scripts/release_check.py``.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ("release.yml", "screenshots.yml", "docs.yml")
_SHA_PIN = re.compile(r"^[\w.-]{1,100}/[\w./-]{1,200}@[0-9a-f]{40}$")
_USES_LINE = re.compile(r"^\s{0,40}(?:- )?uses: (\S{1,300})(?: # (v\S{1,40}))?")
_EVENT_EXPR = re.compile(r"\$\{\{[^}]{0,200}github\.event\b")
_ANY_EXPR = re.compile(r"\$\{\{")


def _load(name: str) -> dict[Any, Any]:
    data = yaml.safe_load((ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def _triggers(wf: dict[Any, Any]) -> dict[str, Any]:
    # PyYAML (YAML 1.1) reads the bare key `on` as the boolean True.
    on = wf.get("on", wf.get(True))
    assert isinstance(on, dict)
    return on


def _steps(wf: dict[Any, Any]) -> list[tuple[str, dict[str, Any]]]:
    return [(job_id, step) for job_id, job in wf["jobs"].items() for step in job["steps"]]


@pytest.mark.parametrize("name", WORKFLOWS)
def test_actions_pinned_by_full_sha_with_version_comment(name: str) -> None:
    text = (ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")
    uses = [m for m in map(_USES_LINE.match, text.splitlines()) if m]
    assert uses
    for match in uses:
        assert _SHA_PIN.match(match.group(1)), match.group(0)
        assert match.group(2), f"missing version comment: {match.group(0)}"


@pytest.mark.parametrize("name", WORKFLOWS)
def test_permissions_default_to_none_and_are_granted_per_job(name: str) -> None:
    wf = _load(name)
    assert wf["permissions"] == {}
    for job_id, job in wf["jobs"].items():
        perms = job.get("permissions")
        assert isinstance(perms, dict) and perms, f"{job_id} has no explicit permissions"
        assert "write-all" not in str(perms)


@pytest.mark.parametrize("name", WORKFLOWS)
def test_checkout_never_persists_credentials(name: str) -> None:
    for job_id, step in _steps(_load(name)):
        if str(step.get("uses", "")).startswith("actions/checkout@"):
            assert step.get("with", {}).get("persist-credentials") is False, job_id


@pytest.mark.parametrize("name", WORKFLOWS)
def test_no_expression_is_interpolated_into_run(name: str) -> None:
    for job_id, step in _steps(_load(name)):
        run = step.get("run")
        if run is not None:
            assert not _EVENT_EXPR.search(run), f"{job_id}: github.event text in run:"
            assert not _ANY_EXPR.search(run), f"{job_id}: pass expressions through env:"


@pytest.mark.parametrize("name", WORKFLOWS)
def test_no_pull_request_target(name: str) -> None:
    assert "pull_request_target" not in _triggers(_load(name))


def test_release_runs_only_on_version_tags() -> None:
    on = _triggers(_load("release.yml"))
    assert set(on) == {"push"}
    assert on["push"] == {"tags": ["v*"]}


def test_release_has_the_spec_jobs_and_least_privilege() -> None:
    jobs = _load("release.yml")["jobs"]
    assert {"build", "sbom", "attest", "pypi", "ghcr"} <= set(jobs)
    assert jobs["pypi"]["permissions"] == {"id-token": "write"}
    assert jobs["pypi"]["environment"]["name"] == "pypi"
    assert jobs["build"]["permissions"] == {"contents": "read"}
    uses = [str(s.get("uses", "")) for _, s in _steps({"jobs": jobs})]
    assert any(u.startswith("pypa/gh-action-pypi-publish@") for u in uses)
    assert any(u.startswith("actions/attest@") for u in uses)
    assert not any("attest-build-provenance" in u for u in uses)
    for job in ("attest", "ghcr"):
        assert jobs[job]["permissions"].get("attestations") == "write"
        assert jobs[job]["permissions"].get("id-token") == "write"


def test_release_never_uses_secrets_other_than_the_github_token() -> None:
    text = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    assert set(re.findall(r"secrets\.(\w{1,60})", text)) <= {"GITHUB_TOKEN"}


def test_screenshots_installs_chromium_runs_make_and_opens_a_pr() -> None:
    wf = _load("screenshots.yml")
    assert set(_triggers(wf)) == {"workflow_dispatch"}
    steps = _steps(wf)
    runs = "\n".join(str(s.get("run", "")) for _, s in steps)
    assert "playwright install --with-deps chromium" in runs
    assert "make screenshots" in runs
    pr = [s for _, s in steps if str(s.get("uses", "")).startswith("peter-evans/")]
    assert pr and pr[0]["with"]["signoff"] is True


def test_docs_builds_with_zensical_and_deploys_only_from_main() -> None:
    wf = _load("docs.yml")
    jobs = wf["jobs"]
    assert "zensical" in "\n".join(str(s.get("run", "")) for _, s in _steps(wf))
    assert jobs["deploy"]["if"] == (
        "github.ref == 'refs/heads/main' && vars.PAGES_ENABLED == 'true'"
    )
    assert jobs["deploy"]["permissions"] == {"pages": "write", "id-token": "write"}
    assert jobs["build"]["permissions"] == {"contents": "read"}


# --- scripts/release_check.py helpers -------------------------------------------------


def _release_check() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "release_check", ROOT / "scripts" / "release_check.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _complete_wheel() -> list[str]:
    return [
        "nikasha/__init__.py",
        "nikasha/py.typed",
        "nikasha/data/known_projects.yaml",
        "nikasha/checks/lr_defaults.yaml",
        "nikasha/checks/cwe_compat.yaml",
        "nikasha/fuse/questions/C02.x.j2",
        "nikasha/render/html/page.py",
        "nikasha/code/queries/c.scm",
        "nikasha/integrations/web/templates/base.html",
    ]


def test_release_check_accepts_a_complete_wheel() -> None:
    assert _release_check().check_wheel_members(_complete_wheel()) == []


def test_release_check_reports_missing_data_and_forbidden_members() -> None:
    names = [n for n in _complete_wheel() if not n.endswith(".j2")]
    names += ["tests/unit/test_x.py", "nikasha/__pycache__/x.cpython-312.pyc"]
    failures = _release_check().check_wheel_members(names)
    assert any("fuse/questions" in f for f in failures)
    assert any("tests/" in f for f in failures)
    assert any("pyc" in f for f in failures)


def test_release_check_metadata() -> None:
    rc = _release_check()
    good = (
        "Metadata-Version: 2.4\nName: nikasha\nVersion: 1.2.3\nSummary: s\n"
        "License-Expression: Apache-2.0\nRequires-Python: >=3.11\n"
    )
    assert rc.check_metadata(good, "1.2.3") == []
    bad = rc.check_metadata("Name: other\nVersion: 9\n", "1.2.3")
    assert len(bad) == 5


def test_release_publishes_exactly_the_checked_dist() -> None:
    runs = [str(s.get("run", "")) for _, s in _steps(_load("release.yml"))]
    assert any("scripts/release_check.py --dist dist" in r for r in runs)
    assert not any("uv build" in r for r in runs)


def test_pypi_publish_pin_is_the_peeled_commit() -> None:
    # a892a5a6... is the annotated tag object for v1.14.2; its commit is dc37677b...
    uses = [str(s.get("uses", "")) for _, s in _steps(_load("release.yml"))]
    assert "pypa/gh-action-pypi-publish@dc37677b2e1c63e2034f94d8a5b11f265b73ba33" in uses


def test_pypi_and_ghcr_run_in_protected_environments() -> None:
    jobs = _load("release.yml")["jobs"]
    assert jobs["pypi"]["environment"]["name"] == "pypi"
    assert jobs["ghcr"]["environment"]["name"] == "ghcr"


def test_prereleases_are_never_tagged_latest() -> None:
    steps = _load("release.yml")["jobs"]["ghcr"]["steps"]
    kind = next(s for s in steps if s.get("id") == "kind")
    assert r"^v[0-9]+\.[0-9]+\.[0-9]+$" in kind["run"]
    assert "${{" not in kind["run"]
    meta = next(s for s in steps if s.get("id") == "meta")
    latest = [t for t in meta["with"]["tags"].splitlines() if "value=latest" in t]
    assert latest == ["type=raw,value=latest,enable=${{ steps.kind.outputs.final == 'true' }}"]
    pattern = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+$")
    for tag in ("v0.1.0.dev0", "v1.0.0rc1", "v1.0.0a1", "v1.0.0b2"):
        assert not pattern.match(tag)
    assert pattern.match("v1.2.3")


def test_ci_actions_are_pinned_by_full_sha_too() -> None:
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    uses = [m for m in map(_USES_LINE.match, text.splitlines()) if m]
    assert uses
    for match in uses:
        assert _SHA_PIN.match(match.group(1)), match.group(0)
        assert match.group(2), f"missing version comment: {match.group(0)}"


def test_docs_build_is_strict() -> None:
    runs = [str(s.get("run", "")) for _, s in _steps(_load("docs.yml"))]
    assert any("zensical" in r and r.rstrip().endswith("build --strict") for r in runs)


def test_docs_never_link_outside_the_docs_dir() -> None:
    # A relative Markdown link that climbs out of docs/ aborts `zensical build --strict`.
    escape = re.compile(r"\]\((?:\.\./){1,20}[^)\s]{0,300}?\.md[)#]")
    for page in (ROOT / "docs").rglob("*.md"):
        depth = len(page.relative_to(ROOT / "docs").parts) - 1
        for m in escape.finditer(page.read_text(encoding="utf-8")):
            ups = m.group(0).count("../")
            assert ups <= depth, f"{page}: link leaves docs/"


def test_nav_lists_sandbox_and_every_adr_and_concepts_links_sandbox() -> None:
    nav = (ROOT / "zensical.toml").read_text(encoding="utf-8")
    assert '"sandbox.md"' in nav
    for adr in sorted((ROOT / "docs" / "adr").glob("*.md")):
        assert f'"adr/{adr.name}"' in nav, adr.name
    concepts = (ROOT / "docs" / "concepts.md").read_text(encoding="utf-8")
    assert "](sandbox.md)" in concepts


def test_threat_model_names_every_online_egress() -> None:
    text = (ROOT / "docs" / "THREAT_MODEL.md").read_text(encoding="utf-8")
    # The whole sentence, not a bare host name: this checks the docs, it validates no URL.
    assert "CVE Program's `cvelistV5` on `raw.githubusercontent.com`" in text
    assert "CVE IDs a report cites are disclosed" in text


def test_release_documents_required_reviewers_and_screenshots_pr_caveats() -> None:
    release = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    assert "required reviewers" in release
    shots = (ROOT / ".github" / "workflows" / "screenshots.yml").read_text(encoding="utf-8")
    assert "Allow GitHub" in shots and "does not" in shots


def test_release_check_requires_the_schema_in_the_sdist_not_the_wheel() -> None:
    rc = _release_check()
    assert not any("schema" in p for p in rc.REQUIRED_IN_WHEEL)
    good = ["nikasha-1.2.3/PKG-INFO", "nikasha-1.2.3/schema/result-v1.json"]
    assert rc.check_sdist_members(good, "1.2.3") == []
    assert rc.check_sdist_members(good[:1], "1.2.3") == ["sdist is missing schema/result-v1.json"]


# --- nightly.yml -----------------------------------------------------------------------


def test_nightly_is_scheduled_and_dispatchable_with_minimal_permissions() -> None:
    wf = _load("nightly.yml")
    assert set(_triggers(wf)) == {"schedule", "workflow_dispatch"}
    assert wf["permissions"] == {"contents": "read"}
    for job_id, job in wf["jobs"].items():
        assert job.get("permissions", {"contents": "read"}) == {"contents": "read"}, job_id
        assert job["runs-on"] == "ubuntu-latest"


def test_nightly_pins_every_action_by_full_sha() -> None:
    text = (ROOT / ".github" / "workflows" / "nightly.yml").read_text(encoding="utf-8")
    uses = [m for m in map(_USES_LINE.match, text.splitlines()) if m]
    assert uses
    for match in uses:
        assert _SHA_PIN.match(match.group(1)), match.group(0)
        assert re.search(r"@[0-9a-f]{40}$", match.group(1))
        assert match.group(2), f"missing version comment: {match.group(0)}"


def test_nightly_checkout_and_run_hygiene() -> None:
    wf = _load("nightly.yml")
    for job_id, step in _steps(wf):
        if str(step.get("uses", "")).startswith("actions/checkout@"):
            assert step.get("with", {}).get("persist-credentials") is False, job_id
        run = step.get("run")
        if run is not None:
            assert not _EVENT_EXPR.search(run), job_id
            assert not _ANY_EXPR.search(run), job_id


def test_nightly_builds_both_images_and_runs_the_network_markers() -> None:
    runs = "\n".join(str(s.get("run", "")) for _, s in _steps(_load("nightly.yml")))
    assert "docker build -f docker/capture/Containerfile" in runs
    assert "docker build -f docker/recipes/c-toolchain.Dockerfile" in runs
    assert 'pytest -m "network and not sandbox"' in runs
    assert 'pytest -m "sandbox and network"' in runs
