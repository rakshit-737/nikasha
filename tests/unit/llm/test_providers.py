# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Provider specs, the cloud gate, the warning and the three providers (SPEC §16.6).

No test here opens a socket: the Ollama provider gets a fake opener, the cloud providers
get fake SDK clients, and the one test that imports a real SDK skips when it is absent.
"""

from __future__ import annotations

import io
import json
import sys
import urllib.error
import urllib.request
from types import SimpleNamespace
from typing import Any

import pytest

from nikasha.llm.anthropic_provider import AnthropicProvider
from nikasha.llm.ollama import (
    CHAT_PATH,
    DEFAULT_BASE_URL,
    OllamaProvider,
    local_opener,
    loopback_base_url,
)
from nikasha.llm.openai_provider import SCHEMA_NAME, OpenAIProvider
from nikasha.llm.provider import (
    CLOUD_WARNING,
    MAX_RESPONSE_BYTES,
    CloudRefusedError,
    LLMError,
    LLMProvider,
    LLMUnavailableError,
    ProviderSpec,
    ProviderSpecError,
    parse_json_object,
    parse_spec,
    provider_for,
)

SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"verdict": {"type": "string"}},
    "required": ["verdict"],
    "additionalProperties": False,
}
ANSWER = {"verdict": "unclear"}


def _noop(_message: str) -> None:
    return None


# --- specs ----------------------------------------------------------------------------------------


def test_specs_parse_kind_and_model_and_keep_colons_in_the_model() -> None:
    spec = parse_spec("ollama:llama3.1:8b")
    assert spec == ProviderSpec(kind="ollama", model="llama3.1:8b")
    assert spec is not None
    assert spec.cloud is False
    assert spec.name == "ollama:llama3.1:8b"
    cloud = parse_spec("Anthropic:MODEL-NAME")
    assert cloud == ProviderSpec(kind="anthropic", model="MODEL-NAME")
    assert cloud is not None
    assert cloud.cloud is True
    openai = parse_spec("openai:org/model@2026")
    assert openai is not None
    assert openai.cloud is True


@pytest.mark.parametrize("spec", ["none", "", "  ", "off", "NONE"])
def test_none_means_no_provider(spec: str) -> None:
    assert parse_spec(spec) is None
    assert provider_for(spec) is None


@pytest.mark.parametrize(
    "spec",
    ["ollama", "ollama:", "gemini:x", "anthropic:with space", "openai:-x", "ollama:a" * 200],
)
def test_malformed_specs_are_refused(spec: str) -> None:
    with pytest.raises(ProviderSpecError):
        parse_spec(spec)
    with pytest.raises(ProviderSpecError):
        provider_for(spec, allow_cloud=True)


def test_a_local_spec_builds_a_local_provider_silently(capsys: pytest.CaptureFixture[str]) -> None:
    provider = provider_for("ollama:MODEL")
    assert isinstance(provider, OllamaProvider)
    assert isinstance(provider, LLMProvider)
    assert provider.name == "ollama:MODEL"
    assert provider.model == "MODEL"
    assert capsys.readouterr().err == ""


# --- the cloud gate (P3) ------------------------------------------------------------------------


@pytest.mark.parametrize("spec", ["anthropic:MODEL", "openai:MODEL"])
def test_cloud_specs_are_refused_without_consent(spec: str) -> None:
    with pytest.raises(CloudRefusedError, match="leave this machine"):
        provider_for(spec)


@pytest.mark.parametrize("spec", ["anthropic:MODEL", "openai:MODEL"])
def test_environment_variables_never_enable_a_cloud_provider(
    spec: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("NIKASHA_LLM", spec)
    monkeypatch.setenv("NIKASHA_LLM_ALLOW_CLOUD", "1")
    monkeypatch.setenv("NIKASHA_ALLOW_CLOUD", "true")
    with pytest.raises(CloudRefusedError):
        provider_for(spec)
    with pytest.raises(CloudRefusedError):
        provider_for(spec, allow_cloud=False)
    assert provider_for("none") is None


def test_direct_construction_is_gated_too() -> None:
    with pytest.raises(CloudRefusedError):
        AnthropicProvider("MODEL", client=object())
    with pytest.raises(CloudRefusedError):
        OpenAIProvider("MODEL", client=object())


def test_consent_builds_the_cloud_provider_and_warns_through_the_sink() -> None:
    seen: list[str] = []
    provider = provider_for("anthropic:MODEL", allow_cloud=True, warn=seen.append)
    assert isinstance(provider, AnthropicProvider)
    assert provider.name == "anthropic:MODEL"
    assert seen == [CLOUD_WARNING.format(vendor="Anthropic", model="MODEL")]
    assert "leave this machine" in seen[0]
    assert "never decisive" in seen[0]
    seen.clear()
    provider = provider_for("openai:MODEL", allow_cloud=True, warn=seen.append)
    assert isinstance(provider, OpenAIProvider)
    assert seen == [CLOUD_WARNING.format(vendor="OpenAI", model="MODEL")]


def test_the_warning_goes_to_stderr_by_default(capsys: pytest.CaptureFixture[str]) -> None:
    provider_for("anthropic:MODEL", allow_cloud=True)
    provider_for("openai:MODEL", allow_cloud=True)
    captured = capsys.readouterr()
    assert captured.out == ""
    lines = captured.err.strip().splitlines()
    assert len(lines) == 2
    assert all(line.startswith("warning: ") for line in lines)
    assert "Anthropic (MODEL)" in lines[0]
    assert "OpenAI (MODEL)" in lines[1]


def test_every_instance_warns(capsys: pytest.CaptureFixture[str]) -> None:
    AnthropicProvider("MODEL", allow_cloud=True, client=object())
    AnthropicProvider("MODEL", allow_cloud=True, client=object())
    assert capsys.readouterr().err.count("warning: ") == 2


# --- missing SDKs ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("cls", "module"),
    [(AnthropicProvider, "anthropic"), (OpenAIProvider, "openai")],
)
def test_a_missing_sdk_names_the_extra(
    cls: type[AnthropicProvider] | type[OpenAIProvider],
    module: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(sys.modules, module, None)  # makes import_module raise ImportError
    provider = cls("MODEL", allow_cloud=True, warn=_noop)
    with pytest.raises(LLMUnavailableError, match=r"nikasha\[llm\]"):
        provider.complete_json("s", "u", SCHEMA, max_tokens=10, timeout=1.0)


def test_the_real_anthropic_sdk_builds_a_client(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-not-a-real-key")
    provider = AnthropicProvider("MODEL", allow_cloud=True, warn=_noop)
    assert hasattr(provider._client_or_import(), "messages")


def test_the_real_openai_sdk_builds_a_client(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("openai")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-not-a-real-key")
    provider = OpenAIProvider("MODEL", allow_cloud=True, warn=_noop)
    assert hasattr(provider._client_or_import(), "chat")


# --- the Anthropic provider through a fake client -------------------------------------------------


class FakeAnthropic:
    """The slice of the SDK the provider touches: ``with_options().messages.create()``."""

    def __init__(self, response: object) -> None:
        self.response = response
        self.options: dict[str, Any] = {}
        self.kwargs: dict[str, Any] = {}
        self.messages = self

    def with_options(self, **options: Any) -> FakeAnthropic:
        self.options = options
        return self

    def create(self, **kwargs: Any) -> object:
        self.kwargs = kwargs
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def _message(text: str | None, stop_reason: str = "end_turn") -> SimpleNamespace:
    blocks = [SimpleNamespace(type="text", text=text)] if text is not None else []
    return SimpleNamespace(content=blocks, stop_reason=stop_reason)


def test_anthropic_sends_a_structured_request_and_parses_the_answer() -> None:
    client = FakeAnthropic(_message(json.dumps(ANSWER)))
    provider = AnthropicProvider("MODEL", allow_cloud=True, client=client, warn=_noop)
    out = provider.complete_json("SYS", "USER", SCHEMA, max_tokens=77, timeout=3.5)
    assert out == ANSWER
    assert client.options == {"timeout": 3.5}
    assert client.kwargs["model"] == "MODEL"
    assert client.kwargs["max_tokens"] == 77
    assert client.kwargs["system"] == "SYS"
    assert client.kwargs["messages"] == [{"role": "user", "content": "USER"}]
    assert client.kwargs["output_config"] == {"format": {"type": "json_schema", "schema": SCHEMA}}
    assert "tools" not in client.kwargs
    assert "stream" not in client.kwargs


@pytest.mark.parametrize(
    ("response", "match"),
    [
        (_message(None), "no text block"),
        (_message("not json"), "not valid JSON"),
        (_message("[1, 2]"), "not a JSON object"),
        (_message("{}", stop_reason="refusal"), "declined"),
        (_message("{}", stop_reason="max_tokens"), "cut off"),
        (RuntimeError("boom"), "RuntimeError: boom"),
    ],
    ids=["no-text", "prose", "array", "refusal", "truncated", "sdk-error"],
)
def test_anthropic_failures_become_llm_errors(response: object, match: str) -> None:
    client = FakeAnthropic(response)
    provider = AnthropicProvider("MODEL", allow_cloud=True, client=client, warn=_noop)
    with pytest.raises(LLMError, match=match):
        provider.complete_json("s", "u", SCHEMA, max_tokens=10, timeout=1.0)


# --- the OpenAI provider through a fake client ----------------------------------------------------


class FakeOpenAI:
    """``with_options().chat.completions.create()``."""

    def __init__(self, response: object) -> None:
        self.response = response
        self.options: dict[str, Any] = {}
        self.kwargs: dict[str, Any] = {}
        self.chat = self
        self.completions = self

    def with_options(self, **options: Any) -> FakeOpenAI:
        self.options = options
        return self

    def create(self, **kwargs: Any) -> object:
        self.kwargs = kwargs
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def _completion(
    content: str | None, finish_reason: str = "stop", refusal: str | None = None
) -> SimpleNamespace:
    message = SimpleNamespace(content=content, refusal=refusal)
    return SimpleNamespace(choices=[SimpleNamespace(message=message, finish_reason=finish_reason)])


def test_openai_sends_a_strict_schema_request_and_parses_the_answer() -> None:
    client = FakeOpenAI(_completion(json.dumps(ANSWER)))
    provider = OpenAIProvider("MODEL", allow_cloud=True, client=client, warn=_noop)
    out = provider.complete_json("SYS", "USER", SCHEMA, max_tokens=55, timeout=2.0)
    assert out == ANSWER
    assert client.options == {"timeout": 2.0}
    assert client.kwargs["model"] == "MODEL"
    assert client.kwargs["max_completion_tokens"] == 55
    assert client.kwargs["messages"] == [
        {"role": "system", "content": "SYS"},
        {"role": "user", "content": "USER"},
    ]
    assert client.kwargs["response_format"] == {
        "type": "json_schema",
        "json_schema": {"name": SCHEMA_NAME, "schema": SCHEMA, "strict": True},
    }
    assert "tools" not in client.kwargs


@pytest.mark.parametrize(
    ("response", "match"),
    [
        (SimpleNamespace(choices=[]), "no choices"),
        (_completion(None), "no message content"),
        (_completion("  "), "no message content"),
        (_completion("nope"), "not valid JSON"),
        (_completion("[]"), "not a JSON object"),
        (_completion("{}", finish_reason="length"), "cut off"),
        (_completion(None, refusal="no"), "declined"),
        (RuntimeError("boom"), "RuntimeError: boom"),
    ],
    ids=["no-choices", "null", "blank", "prose", "array", "truncated", "refusal", "sdk-error"],
)
def test_openai_failures_become_llm_errors(response: object, match: str) -> None:
    client = FakeOpenAI(response)
    provider = OpenAIProvider("MODEL", allow_cloud=True, client=client, warn=_noop)
    with pytest.raises(LLMError, match=match):
        provider.complete_json("s", "u", SCHEMA, max_tokens=10, timeout=1.0)


# --- the Ollama provider through a fake opener ----------------------------------------------------


class FakeResponse:
    def __init__(self, body: bytes) -> None:
        self._body = io.BytesIO(body)

    def read(self, n: int = -1) -> bytes:
        return self._body.read(n)

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None


class FakeOpener:
    def __init__(self, body: bytes | Exception) -> None:
        self.body = body
        self.requests: list[Any] = []
        self.timeouts: list[float] = []

    def __call__(self, request: Any, *, timeout: float) -> FakeResponse:
        self.requests.append(request)
        self.timeouts.append(timeout)
        if isinstance(self.body, Exception):
            raise self.body
        return FakeResponse(self.body)


def _envelope(content: str) -> bytes:
    return json.dumps(
        {"model": "MODEL", "message": {"role": "assistant", "content": content}}
    ).encode()


def test_ollama_posts_a_structured_chat_request_to_loopback() -> None:
    opener = FakeOpener(_envelope(json.dumps(ANSWER)))
    provider = OllamaProvider("MODEL", opener=opener)
    out = provider.complete_json("SYS", "USER", SCHEMA, max_tokens=42, timeout=9.0)
    assert out == ANSWER
    (request,) = opener.requests
    assert request.full_url == DEFAULT_BASE_URL + CHAT_PATH
    assert request.get_method() == "POST"
    assert request.get_header("Content-type") == "application/json"
    assert opener.timeouts == [9.0]
    body = json.loads(request.data.decode())
    assert body["model"] == "MODEL"
    assert body["stream"] is False
    assert body["format"] == SCHEMA
    assert body["messages"] == [
        {"role": "system", "content": "SYS"},
        {"role": "user", "content": "USER"},
    ]
    assert body["options"] == {"temperature": 0, "num_predict": 42}


@pytest.mark.parametrize(
    ("body", "match"),
    [
        (b"not json", "not valid JSON"),
        (b"[]", "not a JSON object"),
        (b"{}", "no message content"),
        (json.dumps({"message": {"content": ""}}).encode(), "no message content"),
        (_envelope("prose"), "not valid JSON"),
        (_envelope("[1]"), "not a JSON object"),
        (b"x" * (MAX_RESPONSE_BYTES + 1), "size cap"),
        (urllib.error.HTTPError("u", 404, "not found", {}, None), "HTTP 404"),  # type: ignore[arg-type]
        (urllib.error.URLError("connection refused"), "cannot reach ollama"),
        (TimeoutError("timed out"), "cannot reach ollama"),
    ],
    ids=[
        "prose",
        "array",
        "no-message",
        "empty-content",
        "content-prose",
        "content-array",
        "oversize",
        "http-404",
        "unreachable",
        "timeout",
    ],
)
def test_ollama_failures_become_llm_errors(body: bytes | Exception, match: str) -> None:
    provider = OllamaProvider("MODEL", opener=FakeOpener(body))
    with pytest.raises(LLMError, match=match):
        provider.complete_json("s", "u", SCHEMA, max_tokens=10, timeout=1.0)


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:11434",
        "http://localhost:11434/",
        "http://127.0.0.1:8080",
        "http://[::1]:11434",
        "HTTP://LOCALHOST:11434",
    ],
)
def test_loopback_base_urls_are_accepted(url: str) -> None:
    assert loopback_base_url(url).startswith("http://")
    assert OllamaProvider("MODEL", base_url=url, opener=FakeOpener(b"{}")).base_url.endswith(
        url.lower().removeprefix("http://").rstrip("/")
    )


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com:11434",
        "https://localhost:11434",
        "http://localhost:11434/api",
        "http://localhost:11434/?x=1",
        "http://user@localhost:11434",
        "http://localhost.evil.test:11434",
        "http://10.0.0.5:11434",
        "ftp://localhost:11434",
        "localhost:11434",
        "",
    ],
)
def test_non_loopback_base_urls_are_refused(url: str) -> None:
    with pytest.raises(LLMError, match="refusing Ollama base URL"):
        OllamaProvider("MODEL", base_url=url, opener=FakeOpener(b"{}"))


def test_the_default_opener_is_urllib_and_never_reaches_a_socket_in_tests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(*_args: object, **_kwargs: object) -> object:
        raise urllib.error.URLError("no network in tests")

    monkeypatch.setattr("urllib.request.OpenerDirector.open", boom)
    provider = OllamaProvider("MODEL")  # constructed after the patch, so it binds `boom`
    with pytest.raises(LLMError, match="cannot reach ollama"):
        provider.complete_json("s", "u", SCHEMA, max_tokens=10, timeout=1.0)


# --- the shared JSON parser -----------------------------------------------------------------------


def test_parse_json_object_accepts_bytes_and_str_objects_only() -> None:
    assert parse_json_object(b'{"a": 1}', where="x") == {"a": 1}
    assert parse_json_object('{"a": 1}', where="x") == {"a": 1}
    with pytest.raises(LLMError, match="x is not valid JSON"):
        parse_json_object(b"\xff", where="x")
    with pytest.raises(LLMError, match="size cap"):
        parse_json_object("1" * (MAX_RESPONSE_BYTES + 1), where="x")


def test_the_default_ollama_opener_ignores_proxy_env_and_refuses_redirects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """HTTP_PROXY must not route a local prompt through a proxy, nor may a 3xx move it."""
    monkeypatch.setenv("HTTP_PROXY", "http://10.9.9.9:3128")
    monkeypatch.setenv("http_proxy", "http://10.9.9.9:3128")
    opener = local_opener()
    director = opener.__self__  # type: ignore[attr-defined]
    proxies = [h for h in director.handlers if isinstance(h, urllib.request.ProxyHandler)]
    assert all(not getattr(h, "proxies", {}) for h in proxies)
    redirects = [h for h in director.handlers if isinstance(h, urllib.request.HTTPRedirectHandler)]
    assert redirects
    request = urllib.request.Request("http://localhost:11434/api/chat", data=b"{}")
    for handler in redirects:
        assert handler.redirect_request(request, None, 307, "x", {}, "http://evil.example/") is None
