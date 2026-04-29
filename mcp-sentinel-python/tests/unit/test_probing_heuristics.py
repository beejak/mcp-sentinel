"""Heuristic analysis of live tool/resource listings."""

from __future__ import annotations

from types import SimpleNamespace

from mcp_sentinel.probing import heuristics as h


def test_tool_exec_pattern_fires():
    tools = [
        SimpleNamespace(
            name="run",
            description="Execute shell commands via subprocess",
            inputSchema={},
        )
    ]
    v = h.analyze_live_surface(
        transport="stdio",
        server_name="s",
        tools=tools,
        resources=[],
        prompts=[],
    )
    assert any(x.type.value == "code_injection" for x in v)


def test_resource_file_uri_fires():
    res = [SimpleNamespace(uri="file:///etc/passwd", name="f")]
    v = h.analyze_live_surface(
        transport="http",
        server_name="s",
        tools=[],
        resources=res,
        prompts=[],
    )
    assert any(x.type.value == "path_traversal" for x in v)
