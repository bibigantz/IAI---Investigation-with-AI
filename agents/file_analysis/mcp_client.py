"""
Shared Model Context Protocol automation layer for the File / Malware
Analysis Father Agent's three sub-modules -- Ghidra MCP, CAPA MCP, and
Cuckoo v3 MCP (or a generic Sandbox MCP). Every sub-module calls the
module-level call_tool(server, tool_name, arguments) and gets back parsed
data or {}; this is the only place that talks the actual MCP wire protocol
(via the official `mcp` Python SDK), mirroring how
agents/memory_analysis/volatility_runner.py is the only place that shells
out to Volatility3.
"""
import asyncio
import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class MCPServerSpec:
    """Connection info for one MCP server, resolved from env vars so each
    deployment can point at wherever its Ghidra/CAPA/Cuckoo MCP server
    actually runs without any code change -- the same philosophy this
    project already uses for GEMINI_API_KEY / LLM_MODEL."""
    name: str
    transport: str  # "stdio" or "sse"
    command: Optional[str] = None
    args: List[str] = field(default_factory=list)
    env: Dict[str, str] = field(default_factory=dict)
    url: Optional[str] = None
    timeout: float = 120.0

    @classmethod
    def from_env(
        cls, name: str, env_prefix: str,
        default_command: str, default_args: Optional[List[str]] = None,
        default_transport: str = "stdio",
    ) -> "MCPServerSpec":
        url = os.getenv(f"{env_prefix}_URL")
        transport = os.getenv(f"{env_prefix}_TRANSPORT", "sse" if url else default_transport).lower()
        command = os.getenv(f"{env_prefix}_COMMAND", default_command)
        args_env = os.getenv(f"{env_prefix}_ARGS")
        args = args_env.split() if args_env else list(default_args or [])
        timeout = float(os.getenv(f"{env_prefix}_TIMEOUT", "120"))
        return cls(name=name, transport=transport, command=command, args=args, url=url, timeout=timeout)


# One spec per server, resolved once at import time. Override at runtime via
# GHIDRA_MCP_URL / GHIDRA_MCP_COMMAND / GHIDRA_MCP_ARGS / GHIDRA_MCP_TRANSPORT
# / GHIDRA_MCP_TIMEOUT (and the CAPA_MCP_ / CUCKOO_MCP_ equivalents).
GHIDRA_MCP = MCPServerSpec.from_env("Ghidra", "GHIDRA_MCP", default_command="ghidra-mcp")
CAPA_MCP = MCPServerSpec.from_env("CAPA", "CAPA_MCP", default_command="capa-mcp")
# Sandboxes are far more commonly deployed as a network service than spawned
# per-call, so Cuckoo defaults to SSE unless a command/stdio setup is given.
CUCKOO_MCP = MCPServerSpec.from_env(
    "Cuckoo", "CUCKOO_MCP", default_command="cuckoo-mcp", default_transport="sse"
)


class MCPError(RuntimeError):
    """An MCP tool call failed outright -- server unreachable/not installed,
    tool returned isError, timeout, or a malformed response. Callers of the
    module-level call_tool() never see this; see its own docstring."""


class MCPBackend:
    """Interface every backend implements: call one tool, get back parsed data."""

    async def call_tool(self, server: MCPServerSpec, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError


def _extract_text(result) -> str:
    parts = []
    for block in (result.content or []):
        text = getattr(block, "text", None)
        if text:
            parts.append(text)
    return "\n".join(parts)


class SDKMCPBackend(MCPBackend):
    """Talks real MCP over stdio (spawns `server.command`) or SSE (`server.url`)
    using the official `mcp` Python SDK. Every SDK symbol is imported lazily
    inside this method, so a deployment without `pip install mcp` still
    imports every sub-module fine -- it just gets {} back from every call
    (see the module-level call_tool()'s degrade-gracefully contract)."""

    async def call_tool(self, server: MCPServerSpec, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        from mcp import ClientSession, StdioServerParameters

        if server.transport == "sse":
            if not server.url:
                raise MCPError(f"{server.name} MCP is configured for SSE transport but no *_URL is set")
            from mcp.client.sse import sse_client
            client_ctx = sse_client(server.url)
        else:
            if not server.command:
                raise MCPError(f"{server.name} MCP is configured for stdio transport but no *_COMMAND is set")
            params = StdioServerParameters(command=server.command, args=server.args, env=server.env or None)
            from mcp.client.stdio import stdio_client
            client_ctx = stdio_client(params)

        async with client_ctx as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await asyncio.wait_for(
                    session.call_tool(tool_name, arguments=arguments),
                    timeout=server.timeout,
                )

        if result.isError:
            raise MCPError(f"{server.name} MCP tool '{tool_name}' returned an error: {_extract_text(result)}")

        # Prefer the SDK's structured result field when the server sets it --
        # most MCP tool servers designed for automation (rather than pure
        # chat-tool use) return their real payload here, not as text.
        if result.structuredContent is not None:
            return result.structuredContent

        text = _extract_text(result)
        if not text:
            return {}
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {"raw_text": text}


_backend: MCPBackend = SDKMCPBackend()


def set_backend(backend: MCPBackend) -> None:
    """Swap the module-level backend -- e.g. a canned-response test double,
    or a different transport implementation."""
    global _backend
    _backend = backend


async def call_tool(
    server: MCPServerSpec, tool_name: str, arguments: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Every sub-module's one entry point into an MCP server. Never raises
    for an ordinary failure (server not running/installed, tool error,
    timeout, malformed response) -- logs a warning through the bridge if one
    is running, and returns {} so the calling agent can submit a partial/
    degraded report instead of taking the whole investigation down."""
    try:
        return await _backend.call_tool(server, tool_name, arguments or {})
    except Exception as e:
        message = f"{server.name} MCP call '{tool_name}' failed: {e}"
        try:
            from bridge.hitl_bridge import bridge
            bridge.log_event(f"{server.name}_MCP", message, level="WARN")
        except Exception:
            print(f"[MCP][WARN] {message}")
        return {}
