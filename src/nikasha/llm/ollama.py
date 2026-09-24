# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The Ollama provider: plain HTTP to a loopback address, with stdlib ``urllib`` only.

This is the provider a confidential report should use: the prompt goes to a model running
on this machine and nowhere else. The base URL is checked to be ``http://`` on a loopback
host, so a mistyped or hostile configuration cannot turn "local" into a network call
(P3; ADR 0002: no httpx).

Ollama's ``/api/chat`` accepts a JSON schema in ``format`` and returns the model's answer
as a JSON string in ``message.content``; that string is parsed here into the object the
guard validates.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

from nikasha.llm.provider import MAX_RESPONSE_BYTES, LLMError, parse_json_object

DEFAULT_BASE_URL = "http://localhost:11434"
CHAT_PATH = "/api/chat"
LOOPBACK_HOSTS: frozenset[str] = frozenset({"localhost", "127.0.0.1", "::1"})

#: ``urllib.request.urlopen``'s shape: ``(request, timeout=...)`` giving a readable context.
Opener = Callable[..., Any]


class _RefuseRedirects(urllib.request.HTTPRedirectHandler):
    """A 3xx from the "local" server is an error, never a hop to another host (P3)."""

    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:  # noqa: ANN401
        return None


def local_opener() -> Opener:
    """``urlopen`` for loopback only: no proxy and no redirects.

    Plain ``urllib.request.urlopen`` honours ``HTTP_PROXY`` from the environment, which
    would hand the whole prompt (report text and code) to a proxy, and it follows
    redirects to any host. Neither is acceptable for the provider that promises to keep
    everything on this machine.
    """
    director = urllib.request.build_opener(urllib.request.ProxyHandler({}), _RefuseRedirects())
    return director.open


def loopback_base_url(base_url: str) -> str:
    """Validate that ``base_url`` is ``http://`` on a loopback host, returning it normalized."""
    parts = urlsplit(base_url.strip())
    host = parts.hostname or ""
    if (
        parts.scheme != "http"
        or host not in LOOPBACK_HOSTS
        or parts.username is not None
        or parts.query
        or parts.fragment
        or parts.path not in ("", "/")
    ):
        raise LLMError(
            f"refusing Ollama base URL {base_url!r}: only http://localhost:PORT,"
            " http://127.0.0.1:PORT or http://[::1]:PORT are allowed"
        )
    return f"{parts.scheme}://{parts.netloc.lower()}"


class OllamaProvider:
    """``ollama:MODEL``: structured chat completion against a local Ollama server."""

    kind = "ollama"

    def __init__(
        self,
        model: str,
        *,
        base_url: str = DEFAULT_BASE_URL,
        opener: Opener | None = None,
    ) -> None:
        self.model = model
        self.name = f"ollama:{model}"
        self.base_url = loopback_base_url(base_url)
        self._open: Opener = opener or local_opener()

    def complete_json(
        self,
        system: str,
        user: str,
        json_schema: dict[str, Any],
        *,
        max_tokens: int,
        timeout: float,
    ) -> dict[str, Any]:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
            "format": json_schema,
            "options": {"temperature": 0, "num_predict": max_tokens},
        }
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        request = urllib.request.Request(  # noqa: S310 - loopback http only, checked in __init__
            self.base_url + CHAT_PATH,
            data=body,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            with self._open(request, timeout=timeout) as response:
                raw: bytes = response.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            raise LLMError(f"ollama returned HTTP {exc.code} for {self.model}") from exc
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise LLMError(f"cannot reach ollama at {self.base_url}: {exc}") from exc
        envelope = parse_json_object(raw, where="ollama response")
        message = envelope.get("message")
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, str) or not content.strip():
            raise LLMError("ollama returned no message content")
        return parse_json_object(content, where="ollama message")


__all__ = [
    "CHAT_PATH",
    "DEFAULT_BASE_URL",
    "LOOPBACK_HOSTS",
    "OllamaProvider",
    "local_opener",
    "loopback_base_url",
]
