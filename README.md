# apiguard-mcp

An MCP server that lets an LLM audit a REST API for OWASP API Security Top 10 (2023)
weaknesses: deterministic static rules over an OpenAPI 3.x spec, plus opt-in, allowlisted
dynamic probes.

**Status:** Phase 1a scaffold. Every tool, resource and prompt is registered but returns
`{"error": "not_implemented", "hint": "..."}`.

> **Authorization notice.** The dynamic tools (`probe_target`, `test_bola`) send real HTTP
> requests. Only use them against APIs you own or are authorized to test.

## Quick start

```sh
make install   # uv sync
make check     # ruff, mypy, pytest
make run       # start the server over stdio
```

Copy `apiguard.yaml.example` to `apiguard.yaml` and point `APIGUARD_CONFIG` at it.

Design: [docs/APIGuard MCP — Solution Architecture.pdf](docs/APIGuard%20MCP%20—%20Solution%20Architecture.pdf)
