# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The MCP server (SPEC §16.3): tool functions, argument hardening and the SDK wiring.

The tool functions run directly against the real vulnlab history and need no ``mcp``
package, so the logic is covered on a minimal install. The SDK wiring (schemas, error
mapping, the reproduce gate) is checked only where ``mcp`` imports
(``pytest.importorskip``). Every argument an MCP client sends is hostile (P7), so the
hardening tests are the ones that must never be weakened.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import re
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import pytest
import typer
from typer.testing import CliRunner

from nikasha.code.gitio import MAX_REV_LEN
from nikasha.errors import NikashaError
from nikasha.ingest import MAX_INPUT_BYTES
from nikasha.integrations import mcp_server
from nikasha.integrations.mcp_server import (
    ALLOW_REPRO_ENV,
    INSTRUCTIONS,
    NOT_AVAILABLE,
    NikashaTools,
    ResultStore,
    build_server,
    register,
    repro_allowed,
    validate_repo,
    validate_result_id,
    validate_rev,
    validate_symbol,
    validate_text,
)

ROOT = Path(__file__).resolve().parents[3]
GENUINE = ROOT / "examples" / "reports" / "genuine_hdr_overflow.md"
ASAN_TRACE = ROOT / "tests" / "fixtures" / "traces" / "asan" / "01-vulnlab-heap-overflow-v1.2.0.txt"
#: P1: wording is about claims, never about people, anywhere a client can see it.
BANNED_WORDS = ("ai-generated", "slop", "fake", "fabricated by", "hallucinat")
RESULT_ID = re.compile(r"[0-9a-f]{12}")

if TYPE_CHECKING:
    from mcp.server import MCPServer
    from mcp.types import CallToolResult, TextContent


# -- argument hardening (no repository needed) --------------------------------------------


def test_validate_repo_canonicalizes_https_urls() -> None:
    assert validate_repo(" https://github.com/curl/curl.git/tree/master ") == (
        "https://github.com/curl/curl"
    )


@pytest.mark.parametrize(
    "repo",
    [
        "http://github.com/curl/curl",
        "ssh://git@github.com/curl/curl",
        "file:///etc",
        "git@github.com:curl/curl",
        "ext::sh -c touch%20/tmp/x",
        "https://github.com/../../etc",
    ],
)
def test_validate_repo_refuses_everything_but_https_and_paths(repo: str) -> None:
    with pytest.raises(NikashaError):
        validate_repo(repo)


@pytest.mark.parametrize("repo", ["", "   ", "-", "--git-dir=/x", "a\nb", "x\x00y", "p" * 5000])
def test_validate_repo_refuses_empty_option_like_and_control_input(repo: str) -> None:
    with pytest.raises(NikashaError):
        validate_repo(repo)


def test_validate_repo_keeps_a_local_path_as_given(tmp_path: Path) -> None:
    assert validate_repo(str(tmp_path)) == str(tmp_path)


@pytest.mark.parametrize("value", ["1.2.0", "v1.2.0", "curl-8_5_0", " main ", "a" * MAX_REV_LEN])
def test_validate_rev_accepts_ordinary_revisions(value: str) -> None:
    assert validate_rev(value) == value.strip()


@pytest.mark.parametrize(
    "value", ["", "--upload-pack=touch /tmp/x", "-v", "a\nb", "x\x7f", "a" * (MAX_REV_LEN + 1)]
)
def test_validate_rev_reuses_the_gitio_rules(value: str) -> None:
    with pytest.raises(NikashaError, match="version"):
        validate_rev(value, "version")


def test_validate_symbol_wants_one_identifier() -> None:
    assert validate_symbol(" util_copy_value ") == "util_copy_value"
    with pytest.raises(NikashaError, match="whitespace"):
        validate_symbol("util copy_value")
    with pytest.raises(NikashaError, match="symbol"):
        validate_symbol("--all")


def test_validate_text_applies_the_cli_input_cap() -> None:
    assert validate_text("a report", "report_text") == "a report"
    with pytest.raises(NikashaError, match="empty"):
        validate_text(" \n\t", "report_text")
    with pytest.raises(NikashaError, match="input limit"):
        validate_text("a" * (MAX_INPUT_BYTES + 1), "report_text")
    # Bytes, not characters: a multi-byte text can be over the cap with fewer characters.
    with pytest.raises(NikashaError, match="input limit"):
        validate_text("€" * (MAX_INPUT_BYTES // 3 + 1), "trace_text")


@pytest.mark.parametrize("value", ["", "nope", "0123456789abc", "0123456789ag", "../../etc"])
def test_validate_result_id_accepts_only_content_ids(value: str) -> None:
    with pytest.raises(NikashaError, match="12-character"):
        validate_result_id(value)
    assert validate_result_id(" 0123456789AB ") == "0123456789ab"


def test_repro_gate_reads_the_environment_variable(monkeypatch: pytest.MonkeyPatch) -> None:
    assert repro_allowed({}) is False
    assert repro_allowed({ALLOW_REPRO_ENV: "1"}) is True
    assert repro_allowed({ALLOW_REPRO_ENV: "true"}) is False
    monkeypatch.setenv(ALLOW_REPRO_ENV, " 1 ")
    assert repro_allowed() is True
    monkeypatch.delenv(ALLOW_REPRO_ENV)
    assert repro_allowed() is False


# -- the tool functions against the real vulnlab history -----------------------------------


@pytest.fixture(scope="module")
def tools(vulnlab_repo: Path, tmp_path_factory: pytest.TempPathFactory) -> Iterator[NikashaTools]:
    """An offline server backend whose index cache lives in a temporary directory."""
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("NIKASHA_CACHE_DIR", str(tmp_path_factory.mktemp("mcp-cache")))
        yield NikashaTools(online=False)


@pytest.fixture(scope="module")
def repo(vulnlab_repo: Path) -> str:
    return str(vulnlab_repo)


@pytest.fixture(scope="module")
def checked(tools: NikashaTools, repo: str) -> dict[str, Any]:
    """One ``check_report`` run over the genuine fixture; the whole module reads it."""
    return tools.check_report(GENUINE.read_text(encoding="utf-8"), repo)


def test_check_report_answers_with_a_summary_and_a_result_id(
    tools: NikashaTools, checked: dict[str, Any]
) -> None:
    verdict = checked["verdict"]
    assert checked["summary"].startswith(f"{verdict['label']} ({verdict['score']}/100")
    assert verdict["label"] == "GROUNDED", "the golden fixture (tests/integration) is GROUNDED"
    assert RESULT_ID.fullmatch(checked["result_id"])
    assert checked["target"]["ref_name"] == "v1.2.0"
    assert checked["claims"]["total"] == len(checked["claims"]["items"]) > 0
    assert checked["claims"]["core"] >= 1
    assert checked["evidence"]
    for item in checked["evidence"]:
        assert {"id", "check_id", "outcome", "group", "strength", "summary", "claim_ids"} <= set(
            item
        )
    assert checked["mode"] == "offline"
    stored = tools.store.get(checked["result_id"])
    assert stored is not None
    assert len(stored.evidence) == len(checked["evidence"])


def test_check_report_forgets_the_temporary_file(
    tools: NikashaTools, checked: dict[str, Any]
) -> None:
    """The result must not name a directory on this machine (P3), and a second server
    checking the same text must produce the same bytes (P2)."""
    stored = tools.store.get(checked["result_id"])
    assert stored is not None
    assert stored.result.report.source.uri is None
    assert "nikasha-mcp-" not in stored.result.to_json()
    assert "nikasha-mcp-" not in json.dumps(checked)


def test_check_report_is_deterministic(
    tools: NikashaTools, repo: str, checked: dict[str, Any]
) -> None:
    again = tools.check_report(GENUINE.read_text(encoding="utf-8"), repo)
    assert again["result_id"] == checked["result_id"]
    assert json.dumps(again, sort_keys=True) == json.dumps(checked, sort_keys=True)
    assert len(tools.store) >= 1


def test_check_report_version_argument_overrides_the_report(
    tools: NikashaTools, repo: str, checked: dict[str, Any]
) -> None:
    other = tools.check_report(GENUINE.read_text(encoding="utf-8"), repo, version="v1.3.0")
    assert other["target"]["ref_name"] == "v1.3.0"
    assert other["result_id"] != checked["result_id"]
    assert other["verdict"]["label"] != "UNGROUNDED", "P4: a genuine report is never UNGROUNDED"


def test_check_report_refuses_network_on_an_offline_server(tools: NikashaTools, repo: str) -> None:
    with pytest.raises(NikashaError, match="--online"):
        tools.check_report("# report\n\nlibhdr 1.2.0", repo, online=True)


def test_check_report_validates_before_it_touches_anything(tools: NikashaTools) -> None:
    with pytest.raises(NikashaError, match="https"):
        tools.check_report("# report", "http://example.com/a/b")
    with pytest.raises(NikashaError, match="empty"):
        tools.check_report("   ", "https://example.com/a/b")
    with pytest.raises(NikashaError, match="version"):
        tools.check_report("# report", "https://example.com/a/b", version="--upload-pack=x")


def test_explain_returns_the_ledger_behind_the_verdict(
    tools: NikashaTools, checked: dict[str, Any]
) -> None:
    payload = tools.explain(checked["result_id"])
    ledger = payload["ledger"]
    assert payload["result_id"] == checked["result_id"]
    assert ledger["score"] == checked["verdict"]["score"]
    assert 0 < len(ledger["contributions"]) <= len(payload["evidence"]) == len(checked["evidence"])
    running = [c["running"] for c in ledger["contributions"]]
    assert running[-1] == pytest.approx(ledger["log_odds"], abs=1e-3)
    assert set(ledger["groups"]) == {c["group"] for c in ledger["contributions"]}
    for item in payload["evidence"]:
        assert "locations" in item
        assert "commands" in item
    assert "body" not in payload["report"], "the client already has the report text"
    assert "timings" not in payload, "wall-clock timings never travel with a verdict"
    assert payload["summary"].startswith(checked["verdict"]["label"])


def test_explain_accepts_the_id_in_any_case_and_refuses_the_rest(
    tools: NikashaTools, checked: dict[str, Any]
) -> None:
    assert tools.explain(checked["result_id"].upper())["result_id"] == checked["result_id"]
    with pytest.raises(NikashaError, match="12-character"):
        tools.explain("nope")
    with pytest.raises(NikashaError, match="no result"):
        tools.explain("0123456789ab")


def test_store_is_bounded_and_keyed_by_content(
    tools: NikashaTools, checked: dict[str, Any]
) -> None:
    original = tools.store.get(checked["result_id"])
    assert original is not None
    store = ResultStore(capacity=2)
    variants = [
        dataclasses.replace(
            original, result=original.result.model_copy(update={"tool_version": f"t{i}"})
        )
        for i in range(3)
    ]
    ids = [store.put(v) for v in variants]
    assert len(set(ids)) == 3
    assert len(store) == 2
    assert store.get(ids[0]) is None, "the oldest result is evicted first"
    assert store.ids == (ids[1], ids[2])
    assert store.put(variants[2]) == ids[2], "the ID is a function of the content"
    assert len(store) == 2
    with pytest.raises(ValueError, match="capacity"):
        ResultStore(capacity=0)


def test_check_trace_fits_the_version_it_was_captured_at(tools: NikashaTools, repo: str) -> None:
    payload = tools.check_trace(ASAN_TRACE.read_text(encoding="utf-8"), repo, "1.2.0")
    assert payload["target"]["ref_name"] == "v1.2.0"
    (trace,) = payload["traces"]
    assert trace["format"] == "asan"
    assert trace["ratio"] == 1.0
    assert len(trace["frames"]) == 4
    assert all(f["consistent"] for f in trace["frames"])
    assert [e["kind"] for e in trace["edges"]] == ["direct", "direct", "direct"]
    assert payload["summary"].startswith("1 trace at v1.2.0")
    assert "4 of 4 checkable frames consistent; 3 of 3 call edges" in payload["summary"]


def test_check_trace_does_not_fit_a_release_before_the_function_existed(
    tools: NikashaTools, repo: str
) -> None:
    payload = tools.check_trace(ASAN_TRACE.read_text(encoding="utf-8"), repo, "v1.0.0")
    (trace,) = payload["traces"]
    assert trace["ratio"] is not None
    assert trace["ratio"] < 1.0
    assert any(e["kind"] == "none" for e in trace["edges"])
    assert any(f["function_matches"] is False for f in trace["frames"])


def test_check_trace_needs_a_trace_and_a_real_version(tools: NikashaTools, repo: str) -> None:
    with pytest.raises(NikashaError, match="no stack trace"):
        tools.check_trace("nothing to see here", repo, "1.2.0")
    with pytest.raises(NikashaError, match=r"9\.9\.9"):
        tools.check_trace(ASAN_TRACE.read_text(encoding="utf-8"), repo, "9.9.9")


def test_symbol_timeline_reports_the_defined_releases(tools: NikashaTools, repo: str) -> None:
    payload = tools.symbol_timeline(repo, "util_copy_value")
    assert payload["runs"] == [["v1.1.0", "v1.3.0"]]
    assert payload["releases"] == len(payload["presence"]) == 5
    assert [p["release"] for p in payload["presence"]] == [
        "v1.0.0",
        "v1.1.0",
        "v1.2.0",
        "v1.2.1",
        "v1.3.0",
    ]
    assert payload["presence"][0]["defined"] is False
    assert payload["presence"][1]["paths"] == ["src/util.c"]
    assert payload["summary"] == "util_copy_value is defined in v1.1.0 to v1.3.0 (4 of 5 releases)."
    assert payload["suggestions"] == []
    assert "seconds" not in payload, "wall-clock time never enters a payload"


def test_symbol_timeline_is_conservative_about_absence(tools: NikashaTools, repo: str) -> None:
    payload = tools.symbol_timeline(repo, "hdr_frobnicate")
    assert payload["runs"] == []
    assert payload["history_complete"] is True
    assert payload["never_in_history"] is True
    assert payload["summary"].startswith("No release defines hdr_frobnicate")
    assert "never appears anywhere in the git history" in payload["summary"]
    assert isinstance(payload["suggestions"], list)


def test_symbol_timeline_suggests_a_near_miss(tools: NikashaTools, repo: str) -> None:
    payload = tools.symbol_timeline(repo, "util_copy_valu")
    assert "util_copy_value" in payload["suggestions"]
    assert "did you mean: util_copy_value" in payload["summary"]


def test_symbol_timeline_validates_the_symbol(tools: NikashaTools, repo: str) -> None:
    with pytest.raises(NikashaError, match="symbol"):
        tools.symbol_timeline(repo, "--all")
    with pytest.raises(NikashaError, match="whitespace"):
        tools.symbol_timeline(repo, "util copy")


def test_reproduce_reports_not_available(tools: NikashaTools, repo: str) -> None:
    payload = tools.reproduce(repo, "1.2.0", poc_text="AAAA")
    assert payload["summary"] == NOT_AVAILABLE
    assert payload["available"] is False
    with pytest.raises(NikashaError, match="version"):
        tools.reproduce(repo, "-x")


def test_payloads_are_plain_json_and_describe_claims_not_people(
    tools: NikashaTools, repo: str, checked: dict[str, Any]
) -> None:
    payloads = [
        checked,
        tools.explain(checked["result_id"]),
        tools.check_trace(ASAN_TRACE.read_text(encoding="utf-8"), repo, "1.2.0"),
        tools.symbol_timeline(repo, "hdr_parse_line"),
        tools.reproduce(repo, "1.2.0"),
    ]
    for payload in payloads:
        assert next(iter(payload)) == "summary", "the summary is always the first field"
        blob = json.dumps(payload, sort_keys=True).lower()
        for word in BANNED_WORDS:
            assert word not in blob, word


# -- the SDK wiring (needs the [mcp] extra) -------------------------------------------------


def _tool_names(server: MCPServer) -> list[str]:
    return [tool.name for tool in asyncio.run(server.list_tools())]


class TestServer:
    @pytest.fixture(autouse=True)
    def _needs_mcp(self) -> None:
        pytest.importorskip("mcp")

    def test_registers_exactly_the_spec_tools(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(ALLOW_REPRO_ENV, raising=False)
        server = build_server()
        assert _tool_names(server) == ["check_report", "check_trace", "symbol_timeline", "explain"]
        assert server.name == "nikasha"
        assert server.instructions == INSTRUCTIONS

    def test_reproduce_is_registered_only_behind_the_gate(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(ALLOW_REPRO_ENV, "1")
        assert "reproduce" in _tool_names(build_server())
        monkeypatch.setenv(ALLOW_REPRO_ENV, "0")
        assert "reproduce" not in _tool_names(build_server())
        assert "reproduce" in _tool_names(build_server(allow_repro=True))
        monkeypatch.setenv(ALLOW_REPRO_ENV, "1")
        assert "reproduce" not in _tool_names(build_server(allow_repro=False))

    def test_input_schemas_follow_the_spec(self) -> None:
        listed = asyncio.run(build_server(allow_repro=True).list_tools())
        schemas = {tool.name: tool.input_schema for tool in listed}
        assert schemas["check_report"]["required"] == ["report_text", "repo"]
        assert set(schemas["check_report"]["properties"]) == {
            "report_text",
            "repo",
            "version",
            "online",
        }
        assert schemas["check_report"]["properties"]["online"]["default"] is False
        assert schemas["check_trace"]["required"] == ["trace_text", "repo", "version"]
        assert schemas["symbol_timeline"]["required"] == ["repo", "symbol"]
        assert schemas["explain"]["required"] == ["result_id"]
        assert schemas["reproduce"]["required"] == ["repo", "version"]
        for tool in listed:
            assert tool.description, tool.name
            assert "\n" not in tool.description, "descriptions are one line, not source layout"
            if "repo" in tool.input_schema["properties"]:
                assert "repo is a local path or an https:// URL" in tool.description, tool.name

    def test_expected_failures_become_tool_errors(self) -> None:
        ToolError = pytest.importorskip("mcp.server.mcpserver.exceptions").ToolError  # noqa: N806
        server = build_server()
        with pytest.raises(ToolError, match="https"):
            asyncio.run(
                server.call_tool(
                    "check_report", {"report_text": "x", "repo": "http://example.com/a/b"}
                )
            )
        with pytest.raises(ToolError, match="12-character"):
            asyncio.run(server.call_tool("explain", {"result_id": "zzz"}))
        with pytest.raises(ToolError, match="--online"):
            asyncio.run(
                server.call_tool(
                    "check_report",
                    {"report_text": "x", "repo": "https://example.com/a/b", "online": True},
                )
            )

    def test_a_call_through_the_server_returns_text_and_structured_content(
        self, tools: NikashaTools, repo: str, checked: dict[str, Any]
    ) -> None:
        server = build_server(backend=tools)
        result = cast(
            "CallToolResult",
            asyncio.run(server.call_tool("explain", {"result_id": checked["result_id"]})),
        )
        assert result.is_error is False
        assert result.structured_content["result_id"] == checked["result_id"]
        text = cast("TextContent", result.content[0]).text
        assert json.loads(text)["summary"] == result.structured_content["summary"]
        timeline = cast(
            "CallToolResult",
            asyncio.run(
                server.call_tool("symbol_timeline", {"repo": repo, "symbol": "util_copy_value"})
            ),
        )
        assert timeline.structured_content["runs"] == [["v1.1.0", "v1.3.0"]]

    def test_instructions_describe_claims_not_people(self) -> None:
        low = INSTRUCTIONS.lower()
        for word in BANNED_WORDS:
            assert word not in low, word


# -- without the extra, and the CLI command -------------------------------------------------


def _without_mcp(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("mcp", "mcp.server", "mcp.server.mcpserver.exceptions"):
        monkeypatch.setitem(sys.modules, name, None)


def test_build_server_without_the_extra_explains_the_install(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _without_mcp(monkeypatch)
    with pytest.raises(NikashaError, match=r"nikasha\[mcp\]"):
        build_server()


def _app() -> typer.Typer:
    app = typer.Typer(add_completion=False)

    @app.command()
    def noop() -> None:
        """A second command, so ``mcp`` stays a subcommand."""

    register(app)
    return app


def test_register_adds_the_mcp_command() -> None:
    result = CliRunner().invoke(_app(), ["mcp", "--help"])
    assert result.exit_code == 0
    assert "--online" in result.output
    assert "stdio" in result.output


def test_mcp_command_fails_cleanly_without_the_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    _without_mcp(monkeypatch)
    result = CliRunner().invoke(_app(), ["mcp"])
    assert result.exit_code == 1
    assert "nikasha[mcp]" in result.output + getattr(result, "stderr", "")


def test_mcp_command_starts_the_stdio_server(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: dict[str, object] = {}

    class FakeServer:
        def run(self) -> None:
            calls["ran"] = True

    def fake_build(**kwargs: object) -> FakeServer:
        calls.update(kwargs)
        return FakeServer()

    monkeypatch.setattr(mcp_server, "build_server", fake_build)
    result = CliRunner().invoke(_app(), ["mcp", "--online"])
    assert result.exit_code == 0, result.output
    assert calls == {"online": True, "ran": True}
