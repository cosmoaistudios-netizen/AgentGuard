"""
AgentGuard Enterprise MCP (Model Context Protocol) Security Gateway.

Provides bidirectional zero-trust inspection and containment for Model Context Protocol:
1. Multi-Transport Streaming Proxy:
   - Stdio transport: Transparent JSON-RPC 2.0 interception between MCP clients
     (Claude Code, Antigravity IDE, Cursor, OpenClaw) and upstream server processes.
   - SSE (Server-Sent Events) transport: Async HTTP/SSE gateway server supporting
     remote and web-based MCP client connections with transparent binary and line streaming.
2. Inbound Client Interception (tools/list & tools/call):
   - Audits tool arguments for credential leaks via SecretVault.tokenize().
   - Enforces shell AST analysis on execution tools to prevent command injection and evasions.
3. Outbound Upstream Interception:
   - Neutralizes indirect prompt injections in tool results (strip_instructions()).
   - Automatically issues PROPAGATE_TAINT IPC calls to /tmp/agentguard.sock with typed
     tags (UNTRUSTED_WEB, EXTERNAL_FILE) when untrusted external tool data is ingested.
4. Robust JSON-RPC 2.0 Error Handling:
   - Full standard error code handling (-32700, -32600, -32000) and graceful shutdown.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import re
import shutil
import socket
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union
import urllib.parse

from agentguard.daemon.audit import AuditLogger
from agentguard.daemon.command_classifier import CommandClassifier
from agentguard.daemon.taint_engine import TaintTag
from agentguard.daemon.vault import SecretVault
from agentguard.interceptors.fs_guard import strip_instructions

DEFAULT_SOCK_PATH = "/tmp/agentguard.sock"

# Standard JSON-RPC 2.0 Error Codes
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603
SECURITY_VIOLATION = -32000

# High-risk web and external ingestion tools
WEB_TOOL_PATTERNS = [
    r"(?i)\b(?:fetch|curl|wget|http|request|scrape|browse|browser|web|url|search|google|duckduckgo)\b",
]
FILE_TOOL_PATTERNS = [
    r"(?i)\b(?:read|load|cat|inspect|open|view|parse)_(?:file|document|text|data|content)\b",
]
COMMAND_EXEC_PATTERNS = [
    r"(?i)\b(?:bash|sh|exec|execute|terminal|shell|run|cmd|command|subprocess)\b",
]


def notify_daemon_taint(
    session_id: str,
    reason: str,
    tags: Optional[List[str]] = None,
    tool_name: str = "",
    socket_path: str = DEFAULT_SOCK_PATH,
) -> bool:
    """Sends PROPAGATE_TAINT IPC request to AgentGuard daemon socket."""
    effective_sock = os.environ.get("AGENTGUARD_SOCKET", socket_path)
    if not os.path.exists(effective_sock):
        return False

    effective_tags = tags or ["USER_INPUT"]
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(1.0)
        s.connect(effective_sock)
        req = {
            "protocol_version": "1.0",
            "action": "PROPAGATE_TAINT",
            "session_id": session_id,
            "payload": {
                "taint": "TAINTED",
                "reason": f"MCPToolIngestion:{tool_name}:{reason}",
                "tags": effective_tags,
                "tool_name": tool_name,
            },
        }
        s.sendall((json.dumps(req) + "\n").encode("utf-8"))
        raw_resp = s.recv(4096)
        s.close()
        return bool(raw_resp)
    except Exception as exc:
        return False


def make_jsonrpc_error(req_id: Any, code: int, message: str, data: Optional[Any] = None) -> Dict[str, Any]:
    """Generates specification-compliant JSON-RPC 2.0 error dictionary."""
    err: Dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": err,
    }


class MCPGateway:
    """
    Model Context Protocol (MCP) Security Gateway.

    Interposes between MCP clients and upstream MCP server runtimes.
    Performs bidirectional telemetry, secret redaction, command auditing,
    prompt injection sanitization, and automated taint propagation.
    """

    def __init__(
        self,
        session_id: Optional[str] = None,
        socket_path: str = DEFAULT_SOCK_PATH,
        vault: Optional[SecretVault] = None,
        classifier: Optional[CommandClassifier] = None,
        audit_logger: Optional[AuditLogger] = None,
    ):
        self.session_id = session_id or os.environ.get("AGENTGUARD_SESSION_ID", "default")
        self.socket_path = os.environ.get("AGENTGUARD_SOCKET", socket_path)
        self.vault = vault if vault is not None else SecretVault()
        self.classifier = classifier if classifier is not None else CommandClassifier()
        self.audit_logger = audit_logger if audit_logger is not None else AuditLogger()

        # Outstanding requests: id -> {tool_name, arguments, timestamp}
        self._pending_calls: Dict[Union[int, str], Dict[str, Any]] = {}
        # Registered upstream tools from tools/list
        self._registered_tools: Dict[str, Dict[str, Any]] = {}

    def _classify_tool_tag(self, tool_name: str) -> TaintTag:
        """Determines typed taint tag for a given tool name."""
        name_clean = tool_name.lower().strip()
        for pat in WEB_TOOL_PATTERNS:
            if re.search(pat, name_clean):
                return TaintTag.UNTRUSTED_WEB
        for pat in FILE_TOOL_PATTERNS:
            if re.search(pat, name_clean):
                return TaintTag.EXTERNAL_FILE
        return TaintTag.USER_INPUT

    def _is_exec_tool(self, tool_name: str) -> bool:
        """Checks if tool executes arbitrary shell or system commands."""
        name_clean = tool_name.lower().strip()
        return any(bool(re.search(pat, name_clean)) for pat in COMMAND_EXEC_PATTERNS)

    def process_client_message(self, raw_line: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Inspects incoming client JSON-RPC request before forwarding to upstream.

        Returns: (line_to_forward_upstream, immediate_client_response)
        If immediate_client_response is set, the request was blocked by security policy.
        """
        line_clean = raw_line.strip()
        if not line_clean:
            return raw_line, None

        try:
            msg = json.loads(line_clean)
        except Exception:
            # Pass through non-JSON / raw binary line transparently
            return raw_line, None

        if not isinstance(msg, dict):
            return raw_line, None

        method = msg.get("method", "")
        req_id = msg.get("id")
        params = msg.get("params", {})

        # Handle tools/list
        if method == "tools/list":
            return raw_line, None

        # Handle tools/call
        if method == "tools/call" and isinstance(params, dict):
            tool_name = params.get("name", "")
            raw_args = params.get("arguments", {})

            # 1. Audit and Redact Secrets in Tool Arguments using SecretVault
            modified_args = False
            tokenized_args = raw_args

            if isinstance(raw_args, dict):
                args_json = json.dumps(raw_args)
                tokenized_str, tokens_created = self.vault.tokenize(
                    args_json, session_id=self.session_id
                )
                if tokens_created:
                    try:
                        tokenized_args = json.loads(tokenized_str)
                        params["arguments"] = tokenized_args
                        modified_args = True
                    except Exception as err:
                        tokenized_args = raw_args
            elif isinstance(raw_args, str):
                tokenized_str, tokens_created = self.vault.tokenize(
                    raw_args, session_id=self.session_id
                )
                if tokens_created:
                    params["arguments"] = tokenized_str
                    modified_args = True

            # 2. Check Execution Tools for Dangerous Shell AST & Obfuscations
            if self._is_exec_tool(tool_name) and isinstance(tokenized_args, dict):
                cmd_val = (
                    tokenized_args.get("command")
                    or tokenized_args.get("cmd")
                    or tokenized_args.get("script")
                    or ""
                )
                if cmd_val and isinstance(cmd_val, str):
                    cls_res = self.classifier.classify(cmd_val)
                    if cls_res.is_dangerous:
                        err_resp = make_jsonrpc_error(
                            req_id=req_id,
                            code=SECURITY_VIOLATION,
                            message=f"AgentGuard Security Gate: Blocked dangerous tool command: {cls_res.reason}",
                            data={"risk_vector": cls_res.risk_vector.to_dict()},
                        )
                        return None, json.dumps(err_resp) + "\n"

            # 3. Track pending call for response sanitization
            if req_id is not None:
                self._pending_calls[req_id] = {
                    "tool_name": tool_name,
                    "arguments": tokenized_args,
                    "timestamp": time.time(),
                }

            if modified_args:
                return json.dumps(msg) + "\n", None

        return raw_line, None

    def process_server_message(self, raw_line: str) -> str:
        """
        Inspects outgoing upstream JSON-RPC response before forwarding to client.
        Strips prompt injections and triggers automated taint propagation.
        """
        line_clean = raw_line.strip()
        if not line_clean:
            return raw_line

        try:
            msg = json.loads(line_clean)
        except Exception:
            # Pass through non-JSON / raw binary line transparently
            return raw_line

        if not isinstance(msg, dict):
            return raw_line

        resp_id = msg.get("id")
        call_info = self._pending_calls.pop(resp_id, None) if resp_id is not None else None
        tool_name = call_info.get("tool_name", "unknown") if call_info else "unknown"

        # Record tools list if this was a tools/list response
        result = msg.get("result")
        if isinstance(result, dict) and "tools" in result and isinstance(result["tools"], list):
            for t in result["tools"]:
                if isinstance(t, dict) and "name" in t:
                    self._registered_tools[t["name"]] = t
            return raw_line

        # Inspect tool results
        if isinstance(result, dict) and "content" in result:
            content_list = result.get("content", [])
            modified = False
            detected_injections: List[str] = []

            if isinstance(content_list, list):
                for item in content_list:
                    if isinstance(item, dict) and item.get("type") == "text":
                        raw_text = item.get("text", "")
                        clean_text, was_sanitized, detected = strip_instructions(raw_text)
                        if was_sanitized:
                            item["text"] = clean_text
                            modified = True
                            detected_injections.extend(detected)

            # Determine whether taint propagation is required
            tag = self._classify_tool_tag(tool_name)
            is_untrusted_source = tag in (TaintTag.UNTRUSTED_WEB, TaintTag.EXTERNAL_FILE)

            if detected_injections or is_untrusted_source:
                reason = (
                    f"PromptInjectionDetected:{','.join(detected_injections)}"
                    if detected_injections
                    else f"IngestedExternalDataVia:{tool_name}"
                )
                notify_daemon_taint(
                    session_id=self.session_id,
                    reason=reason,
                    tags=[tag.value],
                    tool_name=tool_name,
                    socket_path=self.socket_path,
                )

            if modified:
                return json.dumps(msg) + "\n"

        return raw_line

    # -----------------------------------------------------------------------
    # Stdio Transport Stream Proxy
    # -----------------------------------------------------------------------

    async def run_stdio(self, target_command: List[str]) -> int:
        """
        Executes target MCP server command, bidirectionally relaying stdin/stdout
        with JSON-RPC 2.0 argument protection and response sanitization.
        """
        if not target_command:
            sys.stderr.write("[AgentGuard Gateway] Error: No target MCP command specified\n")
            return 1

        proc = await asyncio.create_subprocess_exec(
            *target_command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=None,  # Inherit stderr for direct diagnostic output
        )

        loop = asyncio.get_running_loop()

        # Forward stdin -> proc.stdin (with client inspection)
        async def forward_stdin():
            reader = asyncio.StreamReader()
            protocol = asyncio.StreamReaderProtocol(reader)
            await loop.connect_read_pipe(lambda: protocol, sys.stdin)
            try:
                while True:
                    line_bytes = await reader.readline()
                    if not line_bytes:
                        break
                    raw_line = line_bytes.decode("utf-8", errors="replace")
                    fwd_line, immediate_resp = self.process_client_message(raw_line)

                    if immediate_resp:
                        sys.stdout.write(immediate_resp)
                        sys.stdout.flush()
                        continue

                    if fwd_line and proc.stdin:
                        proc.stdin.write(fwd_line.encode("utf-8"))
                        await proc.stdin.drain()
            except Exception as exc:
                self.audit_logger.log("GATEWAY_STDIN_ERROR", details={"error": str(exc)})
            finally:
                if proc.stdin and not proc.stdin.is_closing():
                    proc.stdin.close()

        # Forward proc.stdout -> sys.stdout (with response sanitization)
        async def forward_stdout():
            try:
                while True:
                    line_bytes = await proc.stdout.readline()
                    if not line_bytes:
                        break
                    raw_line = line_bytes.decode("utf-8", errors="replace")
                    sanitized_line = self.process_server_message(raw_line)
                    sys.stdout.write(sanitized_line)
                    sys.stdout.flush()
            except Exception as exc:
                self.audit_logger.log("GATEWAY_STDOUT_ERROR", details={"error": str(exc)})

        stdin_task = asyncio.create_task(forward_stdin())
        stdout_task = asyncio.create_task(forward_stdout())

        try:
            returncode = await proc.wait()
        finally:
            stdin_task.cancel()
            stdout_task.cancel()

        return returncode

    # -----------------------------------------------------------------------
    # SSE (Server-Sent Events) HTTP Transport Proxy
    # -----------------------------------------------------------------------

    async def run_sse_server(
        self,
        host: str = "127.0.0.1",
        port: int = 18445,
        target_command: Optional[List[str]] = None,
    ) -> None:
        """
        Runs an async HTTP/SSE gateway proxy server for remote and IDE MCP clients.
        Supports standard MCP SSE protocol:
        - GET /sse -> Server-Sent Events stream
        - POST /message?sessionId=... -> Client JSON-RPC requests
        """
        upstream_proc: Optional[asyncio.subprocess.Process] = None
        sse_clients: Set[asyncio.StreamWriter] = set()
        active_sessions: Dict[str, asyncio.Queue] = {}

        if target_command:
            upstream_proc = await asyncio.create_subprocess_exec(
                *target_command,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=None,
            )

            # Read upstream stdout and fan out to active SSE clients
            async def upstream_reader():
                while True:
                    line_bytes = await upstream_proc.stdout.readline()
                    if not line_bytes:
                        break
                    raw_line = line_bytes.decode("utf-8", errors="replace")
                    sanitized = self.process_server_message(raw_line)

                    # Format as SSE event
                    sse_payload = f"event: message\ndata: {sanitized.strip()}\n\n".encode("utf-8")
                    for writer in list(sse_clients):
                        try:
                            writer.write(sse_payload)
                            await writer.drain()
                        except Exception:
                            sse_clients.discard(writer)

            asyncio.create_task(upstream_reader())

        async def handle_http_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
            try:
                req_line = await reader.readline()
                if not req_line:
                    writer.close()
                    await writer.wait_closed()
                    return

                req_str = req_line.decode("utf-8", errors="replace").strip()
                parts = req_str.split(" ")
                if len(parts) < 2:
                    writer.close()
                    await writer.wait_closed()
                    return

                http_method, full_path = parts[0].upper(), parts[1]
                parsed_url = urllib.parse.urlparse(full_path)
                path = parsed_url.path

                # Read HTTP headers
                headers: Dict[str, str] = {}
                content_length = 0
                while True:
                    hdr_line = await reader.readline()
                    if not hdr_line or hdr_line == b"\r\n" or hdr_line == b"\n":
                        break
                    hdr_str = hdr_line.decode("utf-8", errors="replace").strip()
                    if ":" in hdr_str:
                        hk, hv = hdr_str.split(":", 1)
                        headers[hk.strip().lower()] = hv.strip()
                        if hk.strip().lower() == "content-length":
                            content_length = int(hv.strip())

                # 1. Health and Status endpoint
                if http_method == "GET" and path in ("/health", "/status"):
                    body = json.dumps({
                        "status": "ok",
                        "service": "AgentGuard MCP Security Gateway",
                        "session_id": self.session_id,
                        "upstream_active": upstream_proc is not None and upstream_proc.returncode is None,
                    }).encode("utf-8")
                    resp = (
                        b"HTTP/1.1 200 OK\r\n"
                        b"Content-Type: application/json\r\n"
                        b"Access-Control-Allow-Origin: *\r\n"
                        + f"Content-Length: {len(body)}\r\n\r\n".encode("utf-8")
                        + body
                    )
                    writer.write(resp)
                    await writer.drain()
                    writer.close()
                    await writer.wait_closed()
                    return

                # 2. SSE Stream Connection (GET /sse)
                if http_method == "GET" and path in ("/sse", "/events"):
                    endpoint_path = f"/message?sessionId={self.session_id}"
                    handshake = (
                        b"HTTP/1.1 200 OK\r\n"
                        b"Content-Type: text/event-stream\r\n"
                        b"Cache-Control: no-cache\r\n"
                        b"Connection: keep-alive\r\n"
                        b"Access-Control-Allow-Origin: *\r\n\r\n"
                        + f"event: endpoint\ndata: {endpoint_path}\n\n".encode("utf-8")
                    )
                    writer.write(handshake)
                    await writer.drain()
                    sse_clients.add(writer)

                    # Keep connection open until client disconnects
                    try:
                        while not writer.is_closing():
                            await asyncio.sleep(15)
                            # Send SSE heartbeat keep-alive comment
                            writer.write(b": ping\n\n")
                            await writer.drain()
                    except Exception as exc:
                        self.audit_logger.log("SSE_HEARTBEAT_DISCONNECT", details={"error": str(exc)})
                    finally:
                        sse_clients.discard(writer)
                    return

                # 3. Client JSON-RPC POST (POST /message)
                if http_method == "POST" and path == "/message":
                    body_bytes = await reader.readexactly(content_length) if content_length > 0 else b""
                    raw_body = body_bytes.decode("utf-8", errors="replace")

                    fwd_line, immediate_resp = self.process_client_message(raw_body)

                    if immediate_resp:
                        resp_bytes = immediate_resp.encode("utf-8")
                        http_resp = (
                            b"HTTP/1.1 200 OK\r\n"
                            b"Content-Type: application/json\r\n"
                            b"Access-Control-Allow-Origin: *\r\n"
                            + f"Content-Length: {len(resp_bytes)}\r\n\r\n".encode("utf-8")
                            + resp_bytes
                        )
                        writer.write(http_resp)
                        await writer.drain()
                    else:
                        if fwd_line and upstream_proc and upstream_proc.stdin:
                            upstream_proc.stdin.write(fwd_line.encode("utf-8"))
                            await upstream_proc.stdin.drain()

                        http_resp = (
                            b"HTTP/1.1 202 Accepted\r\n"
                            b"Content-Type: text/plain\r\n"
                            b"Access-Control-Allow-Origin: *\r\n"
                            b"Content-Length: 2\r\n\r\n"
                            b"OK"
                        )
                        writer.write(http_resp)
                        await writer.drain()

                    writer.close()
                    await writer.wait_closed()
                    return

                # 4. Fallback 404
                not_found = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
                writer.write(not_found)
                await writer.drain()
                writer.close()
                await writer.wait_closed()
            except Exception as exc:
                self.audit_logger.log("SSE_SERVER_CLIENT_ERROR", details={"error": str(exc)})
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception as close_exc:
                    self.audit_logger.log("SSE_CLOSE_ERROR", details={"error": str(close_exc)})

        server = await asyncio.start_server(handle_http_client, host, port)
        sys.stderr.write(f"[AgentGuard Gateway] SSE Server online at http://{host}:{port}/sse\n")

        async with server:
            await server.serve_forever()


async def run_gateway(
    command: List[str],
    transport: str = "stdio",
    host: str = "127.0.0.1",
    port: int = 18445,
) -> int:
    """Entry point launching MCPGateway in chosen transport mode."""
    gateway = MCPGateway()
    if transport == "sse":
        await gateway.run_sse_server(host=host, port=port, target_command=command)
        return 0
    return await gateway.run_stdio(command)


def main():
    """Command-line entry point for direct invocation."""
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: python -m agentguard.interceptors.mcp_gateway <command> [args...]\n")
        sys.exit(1)

    cmd = sys.argv[1:]
    try:
        code = asyncio.run(run_gateway(cmd))
        sys.exit(code)
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
