"""Probe target descriptors (from repo MCP JSON)."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class ProbeTarget(BaseModel):
    """One MCP server entry suitable for a live handshake."""

    server_name: str
    source_file: str
    transport: Literal["stdio", "http"]
    command: str | None = None
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] | None = None
    url: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)


class ProbeRunRecord(BaseModel):
    """Per-target outcome for reporting."""

    server_name: str
    transport: str
    source_file: str
    ok: bool
    error: str | None = None
    tools_count: int = 0
    resources_count: int = 0
    prompts_count: int = 0
    server_info: dict[str, Any] = Field(default_factory=dict)
