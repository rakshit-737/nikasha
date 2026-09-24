# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The Anthropic provider: the official SDK, imported only when a request is made.

A cloud provider. Its constructor refuses to exist without ``allow_cloud`` and prints the
confidentiality warning otherwise (SPEC §16.6), so the gate holds even for callers that
bypass :func:`nikasha.llm.provider.provider_for`. The SDK reads its own credentials from
the environment when the client is built; that happens only after the user opted in
through configuration, which is the order P3 requires.

The request asks for structured output (``output_config.format`` with the guard's JSON
schema), no tools, no streaming, and reads the first text block back as JSON.
"""

from __future__ import annotations

import importlib
from typing import Any

from nikasha.llm.provider import (
    LLMError,
    LLMUnavailableError,
    ProviderSpec,
    WarnSink,
    cloud_consent,
    parse_json_object,
)

INSTALL_HINT = 'the anthropic SDK is not installed: pip install "nikasha[llm]"'


class AnthropicProvider:
    """``anthropic:MODEL``: one structured completion through the official SDK."""

    kind = "anthropic"

    def __init__(
        self,
        model: str,
        *,
        allow_cloud: bool = False,
        client: object | None = None,
        warn: WarnSink | None = None,
    ) -> None:
        cloud_consent(
            ProviderSpec(kind="anthropic", model=model), allow_cloud=allow_cloud, warn=warn
        )
        self.model = model
        self.name = f"anthropic:{model}"
        # The SDK client, or a stand-in injected by tests. Its type is the SDK's own.
        self._client: Any = client

    def _client_or_import(self) -> Any:  # noqa: ANN401 - the SDK client is an opaque object
        if self._client is None:
            try:
                module = importlib.import_module("anthropic")
            except ImportError as exc:
                raise LLMUnavailableError(INSTALL_HINT) from exc
            self._client = module.Anthropic()
        return self._client

    def complete_json(
        self,
        system: str,
        user: str,
        json_schema: dict[str, Any],
        *,
        max_tokens: int,
        timeout: float,
    ) -> dict[str, Any]:
        client = self._client_or_import()
        try:
            response = client.with_options(timeout=timeout).messages.create(
                model=self.model,
                max_tokens=max_tokens,
                system=system,
                messages=[{"role": "user", "content": user}],
                output_config={"format": {"type": "json_schema", "schema": json_schema}},
            )
        except Exception as exc:
            raise LLMError(f"anthropic request failed: {type(exc).__name__}: {exc}") from exc
        stop_reason = getattr(response, "stop_reason", None)
        if stop_reason == "refusal":
            raise LLMError("the model declined this request")
        if stop_reason == "max_tokens":
            raise LLMError(f"the response was cut off at {max_tokens} tokens")
        return parse_json_object(first_text(response), where="anthropic response")


def first_text(response: object) -> str:
    """The first text block of a Messages API response."""
    for block in getattr(response, "content", None) or ():
        if getattr(block, "type", None) == "text":
            text = getattr(block, "text", None)
            if isinstance(text, str):
                return text
    raise LLMError("anthropic returned no text block")


__all__ = ["INSTALL_HINT", "AnthropicProvider", "first_text"]
