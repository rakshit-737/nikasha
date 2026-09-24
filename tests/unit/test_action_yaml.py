# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The GitHub Action and its example workflow are injection-safe and least-privilege.

SPEC §16.2 defines the action; §19.2 requires that no event text (the issue body above
all) is ever interpolated into a ``run:`` script, that actions are pinned by commit SHA and
that permissions stay minimal. This module lints both YAML files so a later edit cannot
quietly reopen the PromptPwnd/Clinejection class of bug.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
ACTION = ROOT / "action.yml"
WORKFLOW = ROOT / "examples" / "workflows" / "nikasha-issues.yml"
DOCS = ROOT / "docs" / "action.md"

REQUIRED_INPUTS = {
    "mode": "issue",
    "report-path": "",
    "repo-path": ".",
    "version": "",
    "fail-on": "none",
    "comment": "summary",
    "labels": "false",
    "nikasha-version": "",
    "comment-author": "github-actions[bot]",
}

#: ``owner/repo[/path]@<40-hex commit>``: a tag or branch is not a pin.
_SHA_PIN = re.compile(
    r"\A[A-Za-z0-9_.-]{1,64}/[A-Za-z0-9_.-]{1,64}(?:/[A-Za-z0-9_./-]{1,128})?@[0-9a-f]{40}\Z"
)
#: The tag the SHA was resolved from must follow in a comment, for humans and Dependabot.
_PINNED_LINE = re.compile(r"uses: [^@\s]{1,200}@[0-9a-f]{40} # v[0-9]")
#: ``inputs.<name>`` inside ``${{ }}`` or bare in an ``if:`` expression.
_INPUT_REF = re.compile(r"(?<![A-Za-z0-9_.])inputs\.([A-Za-z0-9_-]{1,64})")
#: The single-quoted program after ``--jq``; it may span lines.
_JQ_PROGRAM = re.compile(r"--jq '([^']{1,400})'")


@pytest.fixture(scope="module")
def action() -> dict[str, Any]:
    loaded = yaml.safe_load(ACTION.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


@pytest.fixture(scope="module")
def workflow() -> dict[str, Any]:
    loaded = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def _steps(document: dict[str, Any]) -> list[dict[str, Any]]:
    """Every step of a composite action or of every job of a workflow."""
    if "runs" in document:
        steps = document["runs"]["steps"]
        assert isinstance(steps, list)
        return list(steps)
    steps = []
    for job in document["jobs"].values():
        steps += job["steps"]
    return steps


def _triggers(document: dict[str, Any]) -> dict[str, Any]:
    # YAML 1.1 reads the bare key ``on`` as the boolean True; PyYAML follows it.
    loose: dict[Any, Any] = document
    triggers = loose.get("on", loose.get(True))
    assert isinstance(triggers, dict)
    return triggers


def _nikasha_steps(job: dict[str, Any]) -> list[dict[str, Any]]:
    return [s for s in job["steps"] if str(s.get("uses", "")).startswith("rakshit-737/nikasha@")]


# --- both files ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", [ACTION, WORKFLOW], ids=["action", "workflow"])
def test_files_carry_spdx_headers(path: Path) -> None:
    head = path.read_text(encoding="utf-8").splitlines()[:2]
    # REUSE-IgnoreStart: the expected header lines are data here, not this file's licence.
    assert head[0] == "# SPDX-FileCopyrightText: 2026 The Nikasha Authors"
    assert head[1] == "# SPDX-License-Identifier: Apache-2.0"
    # REUSE-IgnoreEnd


@pytest.mark.parametrize("name", ["action", "workflow"])
def test_no_expression_is_interpolated_into_a_run_script(
    name: str, request: pytest.FixtureRequest
) -> None:
    """SPEC §19.2: event text, and inputs too, travel through ``env:``, never ``run:``."""
    document = request.getfixturevalue(name)
    scripts = [str(step["run"]) for step in _steps(document) if "run" in step]
    assert scripts or name == "workflow"
    for script in scripts:
        assert "${{ github.event" not in script
        assert "${{" not in script, script


@pytest.mark.parametrize("name", ["action", "workflow"])
def test_every_uses_is_pinned_by_full_commit_sha(name: str, request: pytest.FixtureRequest) -> None:
    document = request.getfixturevalue(name)
    uses = [str(step["uses"]) for step in _steps(document) if "uses" in step]
    assert uses
    for ref in uses:
        assert _SHA_PIN.match(ref), f"not pinned by a 40-hex commit SHA: {ref}"


@pytest.mark.parametrize("path", [ACTION, WORKFLOW], ids=["action", "workflow"])
def test_every_pin_names_its_tag_in_a_comment(path: Path) -> None:
    lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines()]
    uses = [line for line in lines if line.startswith(("uses: ", "- uses: "))]
    assert uses
    for line in uses:
        assert _PINNED_LINE.search(line), f"pin without its tag comment: {line}"


@pytest.mark.parametrize("name", ["action", "workflow"])
def test_every_run_step_uses_bash(name: str, request: pytest.FixtureRequest) -> None:
    document = request.getfixturevalue(name)
    for step in _steps(document):
        if "run" in step:
            assert step.get("shell", "bash" if name == "workflow" else None) == "bash", step


# --- action.yml ---------------------------------------------------------------------------


def test_action_is_composite(action: dict[str, Any]) -> None:
    assert action["runs"]["using"] == "composite"
    assert action["name"] == "Nikasha"
    assert "public" in action["description"].lower()


def test_required_inputs_and_their_defaults(action: dict[str, Any]) -> None:
    inputs = action["inputs"]
    for name, default in REQUIRED_INPUTS.items():
        assert name in inputs, f"missing input {name}"
        assert str(inputs[name].get("default", "")) == default, name
        assert inputs[name]["description"]
    assert inputs["token"]["default"] == "${{ github.token }}"


def test_every_input_reference_names_a_declared_input(action: dict[str, Any]) -> None:
    declared = set(action["inputs"])
    referenced = set(_INPUT_REF.findall(ACTION.read_text(encoding="utf-8")))
    assert referenced <= declared, referenced - declared
    # Every declared input is actually used somewhere.
    assert declared <= referenced, declared - referenced


def test_issue_body_reaches_the_shell_only_through_env(action: dict[str, Any]) -> None:
    writers = [
        step
        for step in _steps(action)
        if step.get("env", {}).get("ISSUE_BODY") == "${{ github.event.issue.body }}"
    ]
    assert len(writers) == 1
    script = str(writers[0]["run"])
    assert "printf '%s\\n' \"$ISSUE_BODY\"" in script
    assert "$ISSUE_BODY" not in script.replace('"$ISSUE_BODY"', "")
    # Event text appears in the action only as an ``env:`` value.
    for step in _steps(action):
        for key, value in step.items():
            if key == "env":
                continue
            assert "github.event" not in yaml.safe_dump(value), (step.get("name"), key)


def test_action_installs_from_its_own_checkout(action: dict[str, Any]) -> None:
    scripts = "\n".join(str(step["run"]) for step in _steps(action) if "run" in step)
    assert 'pip install --disable-pip-version-check --quiet "$GITHUB_ACTION_PATH"' in scripts
    assert 'pip install --disable-pip-version-check --quiet "nikasha==$NIKASHA_VERSION"' in scripts


def test_action_produces_json_and_markdown_and_passes_fail_on_through(
    action: dict[str, Any],
) -> None:
    check = next(step for step in _steps(action) if step.get("id") == "check")
    script = str(check["run"])
    assert '--format json --out "$work/result.json"' in script
    assert '--format markdown --out "$work/result.md"' in script
    assert '--fail-on "$FAIL_ON"' in script
    assert "--online" not in script
    last = _steps(action)[-1]
    assert last["name"] == "Apply fail-on"
    assert 'exit "$EXIT_CODE"' in str(last["run"])
    for output in ("verdict", "score", "confidence", "json", "markdown"):
        assert action["outputs"][output]["value"] == f"${{{{ steps.check.outputs.{output} }}}}"


def test_summary_artifact_comment_and_labels_steps(action: dict[str, Any]) -> None:
    steps = {str(step.get("name")): step for step in _steps(action)}
    summary = str(steps["Write the job summary"]["run"])
    assert '>> "$GITHUB_STEP_SUMMARY"' in summary
    assert 'if [ ! -f "$result" ]' in summary
    upload = steps["Upload the results"]
    assert upload["uses"].startswith("actions/upload-artifact@")
    assert upload["with"]["if-no-files-found"] == "error"
    comment = steps["Comment on the issue"]
    assert comment["if"] == "inputs.mode == 'issue' && inputs.comment != 'none'"
    assert comment["env"]["GH_TOKEN"] == "${{ inputs.token }}"
    assert "gh api" in str(comment["run"])
    labels = steps["Label the issue with the verdict"]
    assert labels["if"] == "inputs.mode == 'issue' && inputs.labels == 'true'"
    assert labels["env"]["GH_TOKEN"] == "${{ inputs.token }}"
    assert 'label="nikasha:$(printf' in str(labels["run"])


def test_comment_update_requires_marker_and_author(action: dict[str, Any]) -> None:
    """A marker alone is no control: anyone can post it and the token can edit anything.

    The comment to update must also be authored by ``comment-author`` (the token's own
    login), the comparison happens in the shell and never inside the jq program, and the
    id is digits-only before it is spliced into the PATCH URL.
    """
    step = next(s for s in _steps(action) if s.get("name") == "Comment on the issue")
    assert step["env"]["COMMENT_AUTHOR"] == "${{ inputs.comment-author }}"
    assert action["inputs"]["comment-author"]["default"] == "github-actions[bot]"
    script = str(step["run"])
    programs = _JQ_PROGRAM.findall(script)
    assert len(programs) == 1, programs
    program = programs[0]
    assert 'startswith("<!-- nikasha:comment -->")' in program
    assert ".user.login" in program
    assert "$COMMENT_AUTHOR" not in program
    assert '[ "$login" = "$COMMENT_AUTHOR" ]' in script
    assert '*[!0-9]*) existing="" ;;' in script
    assert 'if [ -z "$COMMENT_AUTHOR" ]' in script
    assert "issues/comments/$existing" in script


def test_comment_wording_describes_claims_not_people(action: dict[str, Any]) -> None:
    """P1: the label descriptions and messages target claims, never the reporter."""
    text = ACTION.read_text(encoding="utf-8").lower()
    for word in ("fabricat", "slop", "fake", "ai-generated", "hallucinat", "liar"):
        assert word not in text, word


# --- example workflow ---------------------------------------------------------------------


def test_workflow_triggers_on_labelled_issue_events(workflow: dict[str, Any]) -> None:
    triggers = _triggers(workflow)
    assert list(triggers) == ["issues"]
    assert triggers["issues"]["types"] == ["opened", "edited", "labeled"]
    for job in workflow["jobs"].values():
        condition = str(job["if"])
        assert "security-report" in condition
        assert "github.event.label.name" in condition
        assert "contains(github.event.issue.labels.*.name" in condition


def test_workflow_permissions_are_minimal(workflow: dict[str, Any]) -> None:
    assert workflow["permissions"] == {"contents": "read"}
    for name, job in workflow["jobs"].items():
        permissions = job["permissions"]
        assert set(permissions) <= {"contents", "issues"}, name
        assert permissions["contents"] == "read", name
        comments = any(
            str(step["with"].get("comment", "summary")) != "none"
            or str(step["with"].get("labels", "false")) == "true"
            for step in _nikasha_steps(job)
        )
        if comments:
            assert permissions.get("issues") == "write", name
        else:
            assert "issues" not in permissions, name


def test_workflow_jobs_have_a_hard_timeout(workflow: dict[str, Any]) -> None:
    """P7: a hostile or huge report must not hold a runner for the 360-minute default."""
    for name, job in workflow["jobs"].items():
        timeout = job["timeout-minutes"]
        assert isinstance(timeout, int), name
        assert 0 < timeout <= 60, name


def test_workflow_checkout_is_full_and_keeps_no_credentials(workflow: dict[str, Any]) -> None:
    checkouts = [
        step
        for step in _steps(workflow)
        if str(step.get("uses", "")).startswith("actions/checkout@")
    ]
    assert checkouts
    for step in checkouts:
        assert step["with"]["fetch-depth"] == 0
        assert step["with"]["persist-credentials"] is False


def test_workflow_runs_the_action_in_issue_mode(workflow: dict[str, Any]) -> None:
    steps = [step for job in workflow["jobs"].values() for step in _nikasha_steps(job)]
    assert len(steps) == 1
    with_ = steps[0]["with"]
    assert with_["mode"] == "issue"
    assert with_["fail-on"] == "none"
    assert "--online" not in yaml.safe_dump(with_)


def test_workflow_carries_the_public_only_warning() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "PUBLIC ISSUES ONLY" in text


def test_workflow_placeholder_pin_is_marked_on_its_line() -> None:
    """Until the release commit exists, the nikasha pin says it is a placeholder."""
    lines = WORKFLOW.read_text(encoding="utf-8").splitlines()
    pins = [line for line in lines if "uses: rakshit-737/nikasha@" in line]
    assert len(pins) == 1
    assert "placeholder" in pins[0] and "docs/action.md" in pins[0]


# --- docs ---------------------------------------------------------------------------------


def test_docs_warn_and_describe_every_input(action: dict[str, Any]) -> None:
    text = DOCS.read_text(encoding="utf-8")
    assert "Warning: public issues only" in text
    assert "public" in text.split("## What one run does")[0].lower()
    for name in action["inputs"]:
        assert f"| `{name}` |" in text, f"input {name} is missing from the docs table"
    for name in action["outputs"]:
        assert f"| `{name}` |" in text, f"output {name} is missing from the docs table"
    assert "re-verified with `gh api`" in text
    assert "github-actions[bot]" in text
    assert "`type: commit`" in text
    assert "unverified" not in text
    for step in _steps(action):
        if "uses" in step:
            assert step["uses"].split("@")[1] in text
