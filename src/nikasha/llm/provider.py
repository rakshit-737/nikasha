# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The optional model provider interface and the gate in front of it (SPEC §16.6).

Three principles shape this module, and every provider behind it:

* **Off by default, never decisive (P2).** Nothing here runs unless a ``--llm`` spec or a
  config entry names a provider, and what a model says reaches the verdict only through
  :mod:`nikasha.llm.guard`, which caps it at |0.5|.
* **Confidential by default (P3).** ``ollama:MODEL`` talks to this machine only. The cloud
  providers (``anthropic:MODEL``, ``openai:MODEL``) are refused unless the caller passes
  ``allow_cloud=True``, which the CLI derives from ``llm.allow_cloud = true`` in the
  project's ``nikasha.toml``. **Environment variables never enable a provider**: an API key
  in the environment is a credential, not consent, and this module never reads one.
* **No hard-coded model IDs.** Users name the model in the spec; docs use placeholders.

The provider interface is one method, :meth:`LLMProvider.complete_json`: a system prompt,
a user prompt and a JSON schema in, one JSON object out. Providers do not get tools, do not
stream and do not keep conversations; there is nothing for injected text to steer.
"""

from __future__ import annotations

import json
import re
import sys
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal, Protocol, cast, runtime_checkable

from nikasha.errors import NikashaError

ProviderKind = Literal["ollama", "anthropic", "openai"]

#: Providers that run on this machine: report text never leaves it.
LOCAL_KINDS: frozenset[str] = frozenset({"ollama"})
#: Providers that send the prompt to a third party. Refused without ``allow_cloud``.
CLOUD_KINDS: frozenset[str] = frozenset({"anthropic", "openai"})
KINDS: frozenset[str] = LOCAL_KINDS | CLOUD_KINDS

#: Spec values meaning "no model at all", which is the default.
NONE_SPECS: frozenset[str] = frozenset({"", "none", "off"})

#: Who receives the prompt, for the warning.
VENDORS: dict[str, str] = {"anthropic": "Anthropic", "openai": "OpenAI"}

#: Model identifiers as the three providers spell them (``llama3.1:8b``, ``org/model``,
#: ``name-YYYYMMDD``): one bounded character class, so a spec from a flag or a config
#: file can never carry prompt text or shell text into a request.
MAX_MODEL_CHARS = 128
MODEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}")

#: Printed to stderr by every cloud provider, every time one is constructed (SPEC §16.6).
CLOUD_WARNING = (
    "cloud model review is enabled: the claim text and the code excerpts of this run are"
    " sent to {vendor} ({model}) and leave this machine. The answer is advisory and never"
    " decisive. Use ollama:MODEL, or unset llm.allow_cloud, to keep every report local."
)

#: Largest response body any provider will read, in bytes.
MAX_RESPONSE_BYTES = 1 << 20

WarnSink = Callable[[str], None]


class LLMError(NikashaError):
    """The provider could not produce a usable answer (network, SDK or malformed output)."""


class LLMUnavailableError(LLMError):
    """The optional SDK is not installed (``pip install "nikasha[llm]"``)."""


class CloudRefusedError(LLMError):
    """A cloud provider was named without ``allow_cloud`` (P3)."""


class ProviderSpecError(LLMError):
    """The spec is not ``ollama:MODEL``, ``anthropic:MODEL`` or ``openai:MODEL``."""


@runtime_checkable
class LLMProvider(Protocol):
    """What a check may ask of a model (SPEC §16.6).

    ``name`` is the spec that built the provider (``kind:model``) and is what the evidence
    records; ``model`` is the model part alone.
    """

    name: str
    model: str

    def complete_json(
        self,
        system: str,
        user: str,
        json_schema: dict[str, Any],
        *,
        max_tokens: int,
        timeout: float,
    ) -> dict[str, Any]:
        """One structured completion: the model's JSON object, already parsed.

        Raises :class:`LLMError` for anything short of a JSON object that came back within
        ``timeout`` seconds. Providers never retry on their own: the check's budget is the
        only clock.
        """
        ...


@dataclass(frozen=True, slots=True)
class ProviderSpec:
    """A parsed ``kind:model`` spec."""

    kind: ProviderKind
    model: str

    @property
    def cloud(self) -> bool:
        return self.kind in CLOUD_KINDS

    @property
    def name(self) -> str:
        return f"{self.kind}:{self.model}"


def parse_spec(spec: str) -> ProviderSpec | None:
    """Parse ``ollama:MODEL`` / ``anthropic:MODEL`` / ``openai:MODEL``; ``none`` is ``None``.

    The model part may itself contain colons (``llama3.1:8b``): only the first colon
    separates the kind.
    """
    text = spec.strip()
    if text.lower() in NONE_SPECS:
        return None
    kind, separator, model = text.partition(":")
    kind = kind.strip().lower()
    model = model.strip()
    if not separator or kind not in KINDS:
        raise ProviderSpecError(
            f"unknown LLM provider spec {spec!r}: use none, ollama:MODEL, anthropic:MODEL"
            " or openai:MODEL"
        )
    if not model or len(model) > MAX_MODEL_CHARS or MODEL_RE.fullmatch(model) is None:
        raise ProviderSpecError(
            f"invalid model name in {spec!r}: letters, digits and . _ : / @ - only,"
            f" at most {MAX_MODEL_CHARS} characters"
        )
    return ProviderSpec(kind=cast("ProviderKind", kind), model=model)


def warn_to_stderr(message: str) -> None:
    """The default warning sink: one line on stderr, never on stdout (stdout is the result)."""
    sys.stderr.write(f"warning: {message}\n")
    sys.stderr.flush()


def require_cloud_consent(spec: ProviderSpec, *, allow_cloud: bool) -> None:
    """Refuse a cloud spec unless the user opted in through configuration (P3)."""
    if spec.cloud and not allow_cloud:
        raise CloudRefusedError(
            f"{spec.name} is a cloud provider and report text would leave this machine;"
            " set llm.allow_cloud = true in nikasha.toml to permit it. Environment"
            " variables never enable it."
        )


def cloud_consent(spec: ProviderSpec, *, allow_cloud: bool, warn: WarnSink | None) -> None:
    """The gate every cloud provider passes in its constructor: refuse, or warn out loud.

    Living in the constructor rather than only in :func:`provider_for` means no code path,
    however it builds the provider, gets a silent cloud call.
    """
    require_cloud_consent(spec, allow_cloud=allow_cloud)
    sink = warn or warn_to_stderr
    sink(CLOUD_WARNING.format(vendor=VENDORS.get(spec.kind, spec.kind), model=spec.model))


def provider_for(
    spec: str,
    *,
    allow_cloud: bool = False,
    warn: WarnSink | None = None,
) -> LLMProvider | None:
    """Build the provider a spec names, or ``None`` for ``none``.

    Cloud specs are refused with :class:`CloudRefusedError` unless ``allow_cloud`` is
    ``True``; the caller passes that from configuration, never from the environment.
    The SDK behind a cloud provider is imported lazily, on the first request, so naming a
    provider whose extra is missing fails with :class:`LLMUnavailableError` then.
    """
    parsed = parse_spec(spec)
    if parsed is None:
        return None
    require_cloud_consent(parsed, allow_cloud=allow_cloud)
    if parsed.kind == "ollama":
        from nikasha.llm.ollama import OllamaProvider  # noqa: PLC0415 - avoids an import cycle

        return OllamaProvider(parsed.model)
    if parsed.kind == "anthropic":
        from nikasha.llm.anthropic_provider import AnthropicProvider  # noqa: PLC0415

        return AnthropicProvider(parsed.model, allow_cloud=allow_cloud, warn=warn)
    from nikasha.llm.openai_provider import OpenAIProvider  # noqa: PLC0415

    return OpenAIProvider(parsed.model, allow_cloud=allow_cloud, warn=warn)


def parse_json_object(text: str | bytes, *, where: str) -> dict[str, Any]:
    """Parse a provider's text as one JSON object, or raise :class:`LLMError`.

    Providers are asked for a JSON object and nothing else. Anything else — prose around
    the JSON, an array, a bare string, invalid UTF-8 — is an error here, and the guard
    turns an error into a NEUTRAL finding rather than guessing at what was meant.
    """
    if len(text) > MAX_RESPONSE_BYTES:
        raise LLMError(f"{where} exceeds the {MAX_RESPONSE_BYTES}-byte size cap")
    try:
        raw = text.decode("utf-8") if isinstance(text, bytes) else text
        parsed = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LLMError(f"{where} is not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise LLMError(f"{where} is not a JSON object")
    return cast("dict[str, Any]", parsed)


__all__ = [
    "CLOUD_KINDS",
    "CLOUD_WARNING",
    "LOCAL_KINDS",
    "MAX_RESPONSE_BYTES",
    "CloudRefusedError",
    "LLMError",
    "LLMProvider",
    "LLMUnavailableError",
    "ProviderKind",
    "ProviderSpec",
    "ProviderSpecError",
    "WarnSink",
    "cloud_consent",
    "parse_json_object",
    "parse_spec",
    "provider_for",
    "require_cloud_consent",
    "warn_to_stderr",
]
