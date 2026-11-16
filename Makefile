.PHONY: install lint type test check run bench

install:
	uv sync

lint:
	uv run ruff check .
	uv run ruff format --check .

type:
	uv run mypy

test:
	uv run pytest

check: lint type test

run:
	uv run apiguard-mcp

bench:
	@echo "bench: placeholder - per-rule precision and recall benchmarks arrive in Phase 1d"
