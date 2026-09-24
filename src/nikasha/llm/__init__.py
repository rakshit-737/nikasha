# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Optional model providers and the guard in front of them (SPEC §16.6; ``[llm]`` extra).

Off by default, never decisive (P2), cloud only with explicit consent (P3), and every
prompt built by :mod:`nikasha.llm.guard` so injected text is data, not instructions (P7).
The package imports no SDK: ``anthropic`` and ``openai`` are loaded on the first request
a cloud provider makes, and Ollama uses stdlib ``urllib`` against a loopback address.
"""

from __future__ import annotations

from nikasha.llm.guard import (
    MAX_LLM_STRENGTH,
    REVIEW_SCHEMA,
    Excerpt,
    GuardedReview,
    ReviewRequest,
    build_prompt,
    cap_strength,
    review,
    wrap_untrusted,
)
from nikasha.llm.provider import (
    CLOUD_WARNING,
    CloudRefusedError,
    LLMError,
    LLMProvider,
    LLMUnavailableError,
    ProviderSpec,
    ProviderSpecError,
    parse_spec,
    provider_for,
)

__all__ = [
    "CLOUD_WARNING",
    "MAX_LLM_STRENGTH",
    "REVIEW_SCHEMA",
    "CloudRefusedError",
    "Excerpt",
    "GuardedReview",
    "LLMError",
    "LLMProvider",
    "LLMUnavailableError",
    "ProviderSpec",
    "ProviderSpecError",
    "ReviewRequest",
    "build_prompt",
    "cap_strength",
    "parse_spec",
    "provider_for",
    "review",
    "wrap_untrusted",
]
