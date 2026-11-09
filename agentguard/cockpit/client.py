"""AgentGuard Cockpit Client.

Provides unified IPC communication with the AgentGuard security daemon via
Unix Domain Socket (UDS) JSON-RPC and HTTP Server-Sent Events (SSE).
"""

from __future__ import annotations

import json
import os
import socket
import threading
import time
import urllib.error
import urllib.request
import uuid
from typing import Any, Callable, Dict, List, Optional, Union

DEFAULT_SOCKET_PATH = os.environ.get(
    "AGENTGUARD_SOCKET", "/tmp/agentguard.sock"
)
DEFAULT_HTTP_URL = os.environ.get(
    "AGENTGUARD_HTTP_URL", "http://127.0.0.1:18443"
)


class CockpitClient:
    """Client for querying daemon telemetry and issuing process control actions."""

    def __init__(
        self,
        socket_path: str = DEFAULT_SOCKET_PATH,
        http_url: str = DEFAULT_HTTP_URL,
        timeout: float = 2.0,
    ):
        self.socket_path = socket_path
        self.http_url = http_url.rstrip("/")
        self.timeout = timeout
        self._sse_thread: Optional[threading.Thread] = None
        self._sse_running = False
        self._sse_stop_event = threading.Event()
        self._last_event_ids: set[str] = set()

    def is_running(self) -> bool:
        """Check if daemon is reachable and responding to status queries."""
        if not os.path.exists(self.socket_path):
            return False
        try:
            res = self.send("GET_STATUS", timeout=0.8)
            return res.get("status") in ("ALLOWED", "OK", "HEALTHY") or "data" in res
        except (
            FileNotFoundError,
            ConnectionRefusedError,
            socket.timeout,
            ConnectionError,
            OSError,
        ):
            return False

    def send(
        self,
        action: str,
        payload: Optional[Dict[str, Any]] = None,
        session_id: str = "",
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Send a newline-delimited JSON-RPC request over UDS and return parsed response."""
        sock_timeout = timeout if timeout is not None else self.timeout
        if not os.path.exists(self.socket_path):
            raise FileNotFoundError(
                f"Daemon socket '{self.socket_path}' does not exist."
            )

        req = {
            "protocol_version": "1.0",
            "request_id": str(uuid.uuid4()),
            "session_id": session_id,
            "pid": os.getpid(),
            "action": action,
            "payload": payload or {},
        }
        data = (json.dumps(req) + "\n").encode("utf-8")

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(sock_timeout)
        try:
            sock.connect(self.socket_path)
            sock.sendall(data)

            buf = b""
            while b"\n" not in buf:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk

            if not buf:
                raise ConnectionError("Daemon closed connection without response.")

            line = buf.decode("utf-8").strip().split("\n")[0]
            return json.loads(line)
        finally:
            sock.close()

    def get_status(self) -> Dict[str, Any]:
        """Query daemon status containing active sessions, metrics, and health."""
        try:
            res = self.send("GET_STATUS")
            return res.get("data", {})
        except Exception:
            return {}

    def get_audit(
        self, limit: int = 50, event_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Fetch recent audit events from daemon in-memory ring buffer."""
        payload: Dict[str, Any] = {"limit": limit}
        if event_type:
            payload["event_type"] = event_type
        try:
            res = self.send("GET_AUDIT", payload=payload)
            data = res.get("data", {})
            if isinstance(data, dict):
                return data.get("events", [])
            elif isinstance(data, list):
                return data
            return []
        except Exception:
            return []

    def pause_agent(self, target: Union[int, str]) -> Dict[str, Any]:
        """Recursively pause an agent's process tree via SIGSTOP."""
        payload = (
            {"pid": int(target)}
            if (isinstance(target, int) or (isinstance(target, str) and target.isdigit()))
            else {"session_id": str(target)}
        )
        return self.send("PAUSE_AGENT", payload=payload)

    def resume_agent(self, target: Union[int, str]) -> Dict[str, Any]:
        """Recursively resume an agent's process tree via SIGCONT."""
        payload = (
            {"pid": int(target)}
            if (isinstance(target, int) or (isinstance(target, str) and target.isdigit()))
            else {"session_id": str(target)}
        )
        return self.send("RESUME_AGENT", payload=payload)

    def terminate_agent(
        self, target: Union[int, str], timeout: float = 2.0
    ) -> Dict[str, Any]:
        """Recursively terminate an agent's process tree cleanly escalating to SIGKILL."""
        payload: Dict[str, Any] = {"timeout": timeout}
        if isinstance(target, int) or (isinstance(target, str) and target.isdigit()):
            payload["pid"] = int(target)
        else:
            payload["session_id"] = str(target)
        return self.send("TERMINATE_AGENT", payload=payload)

    def inspect_agent(self, target: Union[int, str]) -> Dict[str, Any]:
        """Inspect agent metrics, process tree info, and taint provenance chain."""
        payload = (
            {"pid": int(target)}
            if (isinstance(target, int) or (isinstance(target, str) and target.isdigit()))
            else {"session_id": str(target)}
        )
        res = self.send("INSPECT_AGENT", payload=payload)
        return res.get("data", {})

    def list_pending_hitl(self) -> List[Dict[str, Any]]:
        """List active Human-In-The-Loop requests awaiting operator decision."""
        try:
            res = self.send("LIST_PENDING_HITL")
            return res.get("data", {}).get("pending", [])
        except Exception:
            return []

    def hitl_decision(self, request_id: str, decision: str) -> Dict[str, Any]:
        """Submit ALLOW or DENY decision for a pending HITL request."""
        return self.send(
            "HITL_DECISION",
            payload={"request_id": request_id, "decision": decision.upper()},
        )

    def start_sse_listener(
        self,
        callback: Callable[[Dict[str, Any]], None],
        fallback_poll_interval: float = 1.0,
    ) -> None:
        """Start background thread listening to HTTP SSE stream with UDS polling fallback."""
        if self._sse_running:
            return
        self._sse_running = True
        self._sse_stop_event.clear()

        def _worker():
            events_url = f"{self.http_url}/events"
            connected_http = False

            while self._sse_running and not self._sse_stop_event.is_set():
                # Attempt HTTP SSE stream connection first
                try:
                    req = urllib.request.Request(
                        events_url, headers={"Accept": "text/event-stream"}
                    )
                    with urllib.request.urlopen(req, timeout=10.0) as resp:
                        connected_http = True
                        for raw_line in resp:
                            if not self._sse_running or self._sse_stop_event.is_set():
                                break
                            line = raw_line.decode("utf-8", errors="replace").strip()
                            if line.startswith("data:"):
                                payload_str = line[5:].strip()
                                try:
                                    ev = json.loads(payload_str)
                                    ev_id = ev.get("event_id")
                                    if ev_id:
                                        self._last_event_ids.add(ev_id)
                                    callback(ev)
                                except Exception:
                                    pass
                except Exception:
                    connected_http = False

                # Fallback: Poll via UDS get_audit if HTTP SSE is disconnected
                if not connected_http and self._sse_running:
                    try:
                        events = self.get_audit(limit=25)
                        for ev in reversed(events):
                            ev_id = ev.get("event_id") or str(ev)
                            if ev_id not in self._last_event_ids:
                                self._last_event_ids.add(ev_id)
                                if len(self._last_event_ids) > 1000:
                                    self._last_event_ids = set(
                                        list(self._last_event_ids)[-500:]
                                    )
                                callback(ev)
                    except Exception:
                        pass

                # Sleep brief interval before reconnection/poll
                self._sse_stop_event.wait(timeout=fallback_poll_interval)

        self._sse_thread = threading.Thread(
            target=_worker, name="CockpitSSEListener", daemon=True
        )
        self._sse_thread.start()

    def stop(self) -> None:
        """Stop background listeners and clean up resources."""
        self._sse_running = False
        self._sse_stop_event.set()
        if self._sse_thread and self._sse_thread.is_alive():
            self._sse_thread.join(timeout=0.5)
