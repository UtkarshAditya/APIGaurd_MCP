"""MCP surface: names, arguments, annotations and stub behaviour."""

from __future__ import annotations

import asyncio
import json
import sys
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar

import pytest
from mcp import Client, StdioServerParameters

from apiguard import server

T = TypeVar("T")

AUTH_NOTICE = "Only use against APIs you own or are authorized to test."

# Tool name -> (required arguments, optional arguments), from the MCP surface table.
TOOLS: dict[str, tuple[set[str], set[str]]] = {
    "load_spec": ({"source"}, {"name"}),
    "list_endpoints": ({"spec_id"}, {"method", "tag", "path_contains", "limit", "cursor"}),
    "get_endpoint": ({"spec_id", "endpoint_id"}, set()),
    "run_static_scan": ({"spec_id"}, {"categories", "min_severity"}),
    "list_findings": ({"run_id"}, {"severity", "category", "status", "limit", "cursor"}),
    "explain_finding": ({"finding_id"}, {"run_id"}),
    "suggest_fix": ({"finding_id", "target"}, set()),
    "update_finding_status": ({"finding_id", "status"}, {"note"}),
    "diff_specs": ({"old_spec_id", "new_spec_id"}, set()),
    "probe_target": ({"spec_id", "base_url", "checks"}, {"token_env"}),
    "test_bola": (
        {"spec_id", "endpoint_id", "base_url", "token_a_env", "token_b_env", "object_id"},
        set(),
    ),
    "generate_report": ({"run_id", "format"}, set()),
}
DYNAMIC_TOOLS = {"probe_target", "test_bola"}
# Tools that may reach the network: the dynamic tools, plus load_spec for URL sources.
OPEN_WORLD_TOOLS = DYNAMIC_TOOLS | {"load_spec"}
READ_ONLY_TOOLS = {
    "list_endpoints",
    "get_endpoint",
    "list_findings",
    "explain_finding",
    "suggest_fix",
    "diff_specs",
}
RESOURCE_URIS = {
    "owasp://api-top10-2023/{id}",
    "rules://catalog",
    "spec://{spec_id}/summary",
    "finding://{finding_id}{?run_id}",
}
PROMPTS = {
    "security_review": ["spec_id"],
    "triage_findings": ["run_id"],
    "pr_review": ["old_spec_id", "new_spec_id"],
}

# Valid sample arguments for calling each stub.
SAMPLE_ARGS: dict[str, dict[str, Any]] = {
    "load_spec": {"source": "spec.yaml"},
    "list_endpoints": {"spec_id": "s"},
    "get_endpoint": {"spec_id": "s", "endpoint_id": "GET /x"},
    "run_static_scan": {"spec_id": "s"},
    "list_findings": {"run_id": "r"},
    "explain_finding": {"finding_id": "F-000000000000"},
    "suggest_fix": {"finding_id": "F-000000000000", "target": "openapi"},
    "update_finding_status": {"finding_id": "F-000000000000", "status": "accepted_risk"},
    "diff_specs": {"old_spec_id": "a", "new_spec_id": "b"},
    "probe_target": {"spec_id": "s", "base_url": "http://localhost:8000", "checks": ["cors"]},
    "test_bola": {
        "spec_id": "s",
        "endpoint_id": "GET /x/{id}",
        "base_url": "http://localhost:8000",
        "token_a_env": "APIGUARD_TOKEN_A",
        "token_b_env": "APIGUARD_TOKEN_B",
        "object_id": "42",
    },
    "generate_report": {"run_id": "r", "format": "sarif"},
}


def with_client(fn: Callable[[Client], Awaitable[T]]) -> T:
    """Run ``fn`` against the server through an in-process MCP client."""

    async def run() -> T:
        async with Client(server.mcp) as client:
            return await fn(client)

    return asyncio.run(run())


def assert_not_implemented(payload: Any) -> None:
    assert set(payload) == {"error", "hint"}
    assert payload["error"] == "not_implemented"
    assert isinstance(payload["hint"], str) and payload["hint"]


@pytest.fixture(scope="module")
def tools() -> dict[str, Any]:
    result = with_client(lambda c: c.list_tools())
    return {tool.name: tool for tool in result.tools}


def test_exactly_the_twelve_documented_tools(tools: dict[str, Any]) -> None:
    assert set(tools) == set(TOOLS)
    assert len(tools) == 12


@pytest.mark.parametrize("name", sorted(TOOLS))
def test_tool_arguments_match_the_surface_table(tools: dict[str, Any], name: str) -> None:
    required, optional = TOOLS[name]
    schema = tools[name].input_schema
    assert set(schema["properties"]) == required | optional
    assert set(schema.get("required", [])) == required


@pytest.mark.parametrize("name", sorted(TOOLS))
def test_every_tool_has_a_description(tools: dict[str, Any], name: str) -> None:
    assert len(tools[name].description) > 40


def test_list_tools_page_fifty_items_by_default(tools: dict[str, Any]) -> None:
    for name in ("list_endpoints", "list_findings"):
        assert tools[name].input_schema["properties"]["limit"]["default"] == 50


def test_dynamic_tools_carry_the_authorization_notice(tools: dict[str, Any]) -> None:
    for name in DYNAMIC_TOOLS:
        assert AUTH_NOTICE in tools[name].description


def test_secrets_are_passed_by_env_var_name_only(tools: dict[str, Any]) -> None:
    forbidden = {"token", "token_a", "token_b", "password", "secret", "api_key", "authorization"}
    for name, tool in tools.items():
        assert not forbidden & set(tool.input_schema["properties"]), name


def test_no_tool_argument_can_enable_mutations(tools: dict[str, Any]) -> None:
    for name, tool in tools.items():
        for argument in tool.input_schema["properties"]:
            assert "mutat" not in argument.lower(), name
            assert "method" not in argument.lower() or name == "list_endpoints", name


def test_tool_annotations_are_honest(tools: dict[str, Any]) -> None:
    for name, tool in tools.items():
        annotations = tool.annotations
        assert annotations.destructive_hint is False, name
        assert annotations.read_only_hint is (name in READ_ONLY_TOOLS), name
        assert annotations.open_world_hint is (name in OPEN_WORLD_TOOLS), name


def test_enumerated_arguments_are_constrained_in_the_schema(tools: dict[str, Any]) -> None:
    def enum_of(tool: str, argument: str) -> list[str]:
        text = json.dumps(tools[tool].input_schema)
        schema = json.loads(text)
        prop = schema["properties"][argument]
        defs = schema.get("$defs", {})
        found: list[str] = []

        def walk(node: Any) -> None:
            if isinstance(node, dict):
                if "enum" in node:
                    found.extend(node["enum"])
                if "$ref" in node:
                    walk(defs[node["$ref"].rsplit("/", 1)[-1]])
                for value in node.values():
                    walk(value)
            elif isinstance(node, list):
                for value in node:
                    walk(value)

        walk(prop)
        return found

    assert enum_of("suggest_fix", "target") == ["openapi", "fastapi"]
    assert enum_of("generate_report", "format") == ["markdown", "sarif"]
    assert enum_of("update_finding_status", "status") == [
        "open",
        "confirmed",
        "false_positive",
        "accepted_risk",
    ]
    assert enum_of("probe_target", "checks") == [
        "unauth-access",
        "bola",
        "security-headers",
        "cors",
        "error-leak",
        "rate-limit",
    ]


@pytest.mark.parametrize("name", sorted(TOOLS))
def test_every_tool_stub_returns_a_structured_not_implemented_error(name: str) -> None:
    result = with_client(lambda c: c.call_tool(name, SAMPLE_ARGS[name]))
    assert_not_implemented(result.structured_content)
    assert_not_implemented(json.loads(result.content[0].text))


def test_invalid_enum_argument_is_rejected_before_the_handler() -> None:
    async def call(client: Client) -> Any:
        return await client.call_tool("suggest_fix", {"finding_id": "F-1", "target": "rust"})

    result = with_client(call)
    assert result.is_error is True
    assert "target" in result.content[0].text


def test_four_resources_one_static_and_three_templates() -> None:
    async def listing(client: Client) -> tuple[set[str], set[str]]:
        static = await client.list_resources()
        templates = await client.list_resource_templates()
        return (
            {str(r.uri) for r in static.resources},
            {t.uri_template for t in templates.resource_templates},
        )

    static, templates = with_client(listing)
    assert static == {"rules://catalog"}
    assert static | templates == RESOURCE_URIS


@pytest.mark.parametrize(
    "uri",
    [
        "owasp://api-top10-2023/API1",
        "rules://catalog",
        "spec://abc/summary",
        "finding://F-000000000000",
        "finding://F-000000000000?run_id=r1",
    ],
)
def test_every_resource_stub_returns_not_implemented(uri: str) -> None:
    result = with_client(lambda c: c.read_resource(uri))
    assert_not_implemented(json.loads(result.contents[0].text))


def test_three_prompts_with_documented_arguments() -> None:
    result = with_client(lambda c: c.list_prompts())
    found = {p.name: [a.name for a in (p.arguments or [])] for p in result.prompts}
    assert found == PROMPTS
    for prompt in result.prompts:
        assert prompt.description
        assert all(a.required for a in (prompt.arguments or []))


@pytest.mark.parametrize("name", sorted(PROMPTS))
def test_every_prompt_stub_returns_not_implemented(name: str) -> None:
    arguments = dict.fromkeys(PROMPTS[name], "x")
    result = with_client(lambda c: c.get_prompt(name, arguments))
    assert_not_implemented(json.loads(result.messages[0].content.text))


def test_server_starts_over_stdio_and_lists_its_surface() -> None:
    """Spawn the real entry module as a subprocess and talk to it over stdio."""
    params = StdioServerParameters(command=sys.executable, args=["-m", "apiguard.server"])

    async def run() -> tuple[int, int, int, Any]:
        async with Client(params) as client:
            tool_list = await client.list_tools()
            static = await client.list_resources()
            templates = await client.list_resource_templates()
            prompts = await client.list_prompts()
            called = await client.call_tool("load_spec", {"source": "spec.yaml"})
            return (
                len(tool_list.tools),
                len(static.resources) + len(templates.resource_templates),
                len(prompts.prompts),
                called.structured_content,
            )

    tool_count, resource_count, prompt_count, payload = asyncio.run(run())
    assert (tool_count, resource_count, prompt_count) == (12, 4, 3)
    assert_not_implemented(payload)
