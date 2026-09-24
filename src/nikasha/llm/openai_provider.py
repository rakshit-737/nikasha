# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The OpenAI provider: the official SDK, imported only when a request is made.

A cloud provider, gated exactly like :mod:`nikasha.llm.anthropic_provider`: no instance
without ``allow_cloud``, a warning on stderr for every instance, credentials read by the
SDK only after that consent.

The request uses Chat Completions with a strict JSON-schema ``response_format``, no tools
and no streaming, and parses ``choices[0].message.content`` as JSON.
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

INSTALL_HINT = 'the openai SDK is not installed: pip install "nikasha[llm]"'
SCHEMA_NAME = "nikasha_review"


class OpenAIProvider:
    """``openai:MODEL``: one structured chat completion through the official SDK."""

    kind = "openai"

    def __init__(
        self,
        model: str,
        *,
        allow_cloud: bool = False,
        client: object | None = None,
        warn: WarnSink | None = None,
    ) -> None:
        cloud_consent(ProviderSpec(kind="openai", model=model), allow_cloud=allow_cloud, warn=warn)
        self.model = model
        self.name = f"openai:{model}"
        # The SDK client, or a stand-in injected by tests. Its type is the SDK's own.
        self._client: Any = client

    def _client_or_import(self) -> Any:  # noqa: ANN401 - the SDK client is an opaque object
        if self._client is None:
            try:
                module = importlib.import_module("openai")
            except ImportError as exc:
                raise LLMUnavailableError(INSTALL_HINT) from exc
            self._client = module.OpenAI()
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
            response = client.with_options(timeout=timeout).chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                max_completion_tokens=max_tokens,
                response_format={
                    "type": "json_schema",
                    "json_schema": {"name": SCHEMA_NAME, "schema": json_schema, "strict": True},
                },
            )
        except Exception as exc:
            raise LLMError(f"openai request failed: {type(exc).__name__}: {exc}") from exc
        return parse_json_object(first_content(response, max_tokens), where="openai response")


def first_content(response: object, max_tokens: int) -> str:
    """The content of the first choice, or the reason there is none."""
    choices = getattr(response, "choices", None) or ()
    if not choices:
        raise LLMError("openai returned no choices")
    choice = choices[0]
    if getattr(choice, "finish_reason", None) == "length":
        raise LLMError(f"the response was cut off at {max_tokens} tokens")
    message = getattr(choice, "message", None)
    if getattr(message, "refusal", None):
        raise LLMError("the model declined this request")
    content = getattr(message, "content", None)
    if not isinstance(content, str) or not content.strip():
        raise LLMError("openai returned no message content")
    return content


__all__ = ["INSTALL_HINT", "SCHEMA_NAME", "OpenAIProvider", "first_content"]
