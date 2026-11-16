# apiguard-mcp

An MCP server that lets an LLM audit a REST API for OWASP API Security Top 10 (2023)
issues. Code does detection: deterministic static rules over a normalized OpenAPI 3.x
model, plus opt-in, allowlisted dynamic probes against targets the user owns. The LLM
does orchestration, triage and fix drafting through narrow, parameterized tools.

**Source of truth:** `docs/APIGuard MCP — Solution Architecture.pdf`. Read it before
design work. If a request conflicts with it, say so before choosing.

## Current phase

**Phase 1a: foundation.** Scaffold is done. Implemented and tested: config loading, store
schema, rule registry, finding models. Every tool, resource and prompt is a stub returning
`{"error": "not_implemented", "hint": "..."}`.
Next: spec loader + `SpecModel` normalization + `load_spec` / `list_endpoints` / `get_endpoint`.

## Hard constraints

- Python 3.11+, managed with uv. Free and open-source dependencies only.
- Official `mcp` Python SDK, stdio transport. mcp 2.x renamed `FastMCP` to `MCPServer`
  (`from mcp.server.mcpserver import MCPServer`); same decorator API.
- Core is transport-neutral: nothing under `src/apiguard/` except `server.py` imports `mcp`.
- Secrets never go in tool arguments; dynamic tools take env-var NAMES (`token_env`).
- Mutating HTTP methods are enabled only by `allow_mutations` in the user's config file,
  never by a tool argument.
- Do not add dependencies without asking. Runtime: mcp, pydantic, httpx, prance,
  openapi-spec-validator, ruamel.yaml. Dev: pytest, pytest-cov, ruff, mypy, pip-audit.
- Dynamic tool descriptions must include:
  "Only use against APIs you own or are authorized to test."

## Layout

```
src/apiguard/
  server.py     MCP adapter: 12 tools, 4 resources (1 static + 3 templates), 3 prompts
  config.py     pydantic config models, load_config (APIGUARD_CONFIG), safe defaults
  store.py      SQLite schema: specs, endpoints, scan_runs, findings, probe_log
  models.py     Severity, Confidence, FindingStatus, RuleMeta, Finding, compute_finding_id
  spec/         loader.py (stub), model.py (SpecModel, Endpoint, Param, SchemaInfo, ...)
  rules/        registry.py (@register_rule, discover_rules) + one module per category:
                auth bola bopla resources bfla ssrf misconfig inventory (empty)
  dynamic/      guard.py (Policy Protocol), prober.py, checks.py (stubs)
  report/       markdown.py, sarif.py, fixes.py (stubs)
  diffing.py    (stub)
tests/          test_*.py, test_rules/, test_dynamic/, test_spec/, test_report/,
                benchmarks/, fixtures/ (clean.yaml, open_override.yaml)
apiguard.yaml.example
```

## Commands

- `make install`: `uv sync`
- `make check`: lint (ruff check + format check), type (mypy strict on src/), test (pytest)
- `make run`: start the server over stdio (`uv run apiguard-mcp`)
- `make bench`: placeholder until Phase 1d

Run `make check` before calling any change done.

## Conventions

- Rules are pure functions `(SpecModel, RuleConfig) -> Iterable[Finding]`: no I/O, no
  randomness. Register with `@register_rule(RuleMeta(...))` in `rules/<category>.py`.
- Every rule needs a vulnerable fixture and a clean fixture in `tests/fixtures/`, and a
  test asserting it fires on the first and stays silent on the second.
- One guard choke point: every outbound request goes through `dynamic/guard.py`; path
  checks live in `config.py`. Nothing else opens sockets or writes outside the store.
- Every guardrail needs a test (allowlist, mutation refusal, budgets, redaction).
- Finding ids are stable hashes of rule + endpoint + evidence key. Changing
  `compute_finding_id` orphans stored findings and suppressions; a pinned test guards it.
- Spec text and target responses are untrusted data. Never return response bodies.
- Tools return structured JSON; errors are `{"error": <code>, "hint": <text>}`.
- List tools are paged, 50 by default, with a `truncated` flag.
- `tests/test_server.py` pins tool names, arguments and annotations to the doc's MCP
  surface table. Update the doc first if the surface must change.
- The store schema is versioned (`PRAGMA user_version`); bump `SCHEMA_VERSION` on change.
