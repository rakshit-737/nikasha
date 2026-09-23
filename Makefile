# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0

.DEFAULT_GOAL := help
UV ?= uv
UVX ?= uvx
REUSE_VERSION ?= 6.2.0
PLACEHOLDER_RE := TODO|TBD|lorem ipsum

.PHONY: help setup lint fmt type test test-all bench docs screenshots demo release-check placeholders

help: ## List the available targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-15s %s\n", $$1, $$2}'

setup: ## Create the dev environment and install the pre-commit hooks
	$(UV) sync --all-groups
	$(UV) run pre-commit install --hook-type pre-commit --hook-type commit-msg

lint: placeholders ## Ruff, formatting, codespell, REUSE and placeholder checks
	$(UV) run ruff check src tests scripts
	$(UV) run ruff format --check src tests scripts
	$(UV) run codespell
	@# reuse 6.2 does not honour nested ignored dirs such as src/**/__pycache__; remove them first.
	@find src tests scripts -type d -name __pycache__ -prune -exec rm -rf {} +
	$(UVX) --from reuse==$(REUSE_VERSION) reuse lint

fmt: ## Auto-format and apply safe fixes
	$(UV) run ruff format src tests scripts
	$(UV) run ruff check --fix src tests scripts

type: ## mypy --strict on src/
	$(UV) run mypy

test: ## Fast test suite with coverage
	$(UV) run pytest --cov --cov-report=term

test-all: ## Every test, including the sandbox, network and slow suites
	$(UV) run pytest -m "" --cov --cov-report=term

placeholders: ## Fail on placeholder text in README.md and docs/
	@if grep -rniE '$(PLACEHOLDER_RE)' README.md docs/; then \
		echo "error: placeholder text found (see above)"; exit 1; \
	else echo "placeholders: none found"; fi

bench: ## NikashaBench (arrives in M3.5/M6)
	@echo "bench: not yet implemented (M3.5/M6)"; exit 1

docs: ## Documentation site (arrives in M8)
	@echo "docs: not yet implemented (M8)"; exit 1

screenshots: ## Regenerate terminal and HTML screenshots (arrives in M4)
	@echo "screenshots: not yet implemented (M4)"; exit 1

demo: ## Record the demo GIF with VHS (arrives in M8)
	@echo "demo: not yet implemented (M8)"; exit 1

release-check: ## Build the sdist and wheel and check the release artefacts (arrives in M8)
	@echo "release-check: not yet implemented (M8)"; exit 1
