"""
AgentGuard MCP (Model Context Protocol) Security Proxy Adapter.

Provides drop-in compatibility for stdio proxying while delegating
to the enterprise MCPGateway for bidirectional inspection, secret redaction,
and contextual taint propagation.
"""

from __future__ import annotations

import asyncio
import sys
from typing import List

from agentguard.interceptors.mcp_gateway import (
    DEFAULT_SOCK_PATH,
    MCPGateway,
    notify_daemon_taint,
)


def process_mcp_response(raw_line: str, session_id: str, sock_path: str = DEFAULT_SOCK_PATH) -> str:
    """
    Parses and sanitizes a JSON-RPC 2.0 response from an MCP server.
    Strips prompt injections from tool call outputs and propagates taint.
    """
    gateway = MCPGateway(session_id=session_id, socket_path=sock_path)
    return gateway.process_server_message(raw_line)


async def run_mcp_proxy(target_command: List[str]) -> int:
    """
    Executes target MCP server process, bidirectionally relaying stdio
    with JSON-RPC inspection and sanitization via MCPGateway.
    """
    gateway = MCPGateway()
    return await gateway.run_stdio(target_command)


def main():
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: ag mcp-proxy <command> [args...]\n")
        sys.exit(1)

    cmd = sys.argv[1:]
    try:
        code = asyncio.run(run_mcp_proxy(cmd))
        sys.exit(code)
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
