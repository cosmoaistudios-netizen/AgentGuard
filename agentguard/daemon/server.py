"""
AgentGuard Production Asyncio Security Daemon Server.

Coordinates:
- High-Performance Unix Domain Socket (UDS) IPC listener (/tmp/agentguard.sock)
- Auxiliary local HTTP REST listener (127.0.0.1:18443)
- Taint Provenance DAG Engine
- Append-Only Audit Event Logger
"""

import asyncio
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import re
import signal
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple
import urllib.parse
import uuid

from agentguard.daemon.audit import AuditEvent, AuditLogger
from agentguard.daemon.command_classifier import CommandClassifier, ClassificationResult
from agentguard.daemon.intent import IntentTracker, strip_shell_wrapper
from agentguard.daemon.memory_guard import (
    MemoryAction,
    MemoryChunkRecord,
    MemoryReadDecision,
    MemoryWriteDecision,
    VectorMemoryGuard,
)
from agentguard.daemon.policy_engine import PolicyAction, PolicyDecision, PolicyEngine
from agentguard.daemon.taint_engine import TaintEngine, TaintTag
from agentguard.daemon.vault import SecretVault
from agentguard.daemon import process_control
from agentguard.notifications.config import NotificationConfig, load_notification_config
from agentguard.notifications.dispatcher import HIGH_RISK_EVENT_TYPES, NotificationDispatcher
from agentguard.notifications.heartbeat import (
    HealthHeartbeatTask,
    get_process_ram_rss_bytes,
    get_process_ram_rss_mb,
)

DEFAULT_SOCKET_PATH = "/tmp/agentguard.sock"
DEFAULT_HTTP_HOST = "127.0.0.1"
DEFAULT_HTTP_PORT = 18443
DEFAULT_PID_FILE = "/tmp/agentguard.pid"
DEFAULT_STREAM_LIMIT = 16 * 1024 * 1024  # 16 MB stream buffer

# Dangerous command heuristics
DANGEROUS_PATTERNS = [
    re.compile(r"rm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)\s+/"),
    re.compile(r"\brm\s+-rf\s+(~|/|\.\.|/etc|/usr|/bin|/var)"),
    re.compile(r"curl\b.*\|\s*(sh|bash|zsh)"),
    re.compile(r"wget\b.*\|\s*(sh|bash|zsh)"),
    re.compile(r">\s*/dev/sda"),
    re.compile(r">\s*/dev/nvme"),
    re.compile(r"dd\s+if=.*of=/dev/"),
    re.compile(r"mkfs\.[a-z0-9]+"),
    re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"),
    re.compile(r"(\.ssh|\.aws|\.env)\b"),
]

SAFE_PATTERNS = [
    re.compile(
        r"^(ls|cat|pwd|echo|git\s+status|git\s+diff|git\s+log|"
        r"head|tail|whoami|date)(\s+[^;&|><]*)?$"
    )
]


def classify_command(command: str) -> Tuple[bool, str]:
    """
    Classify command as safe or dangerous with advanced semantic parsing,
    flag permutation normalization, and multi-vector obfuscation analysis.
    Returns (is_dangerous: bool, reason: str).
    """
    if not command or not command.strip():
        return False, "Empty command"

    from agentguard.daemon.command_classifier import classify_command as ast_classify
    is_dang, reason = ast_classify(command)
    if is_dang:
        return True, reason

    cmd_clean = command.strip()

    # 1. Check dangerous patterns across entire command line
    for pat in DANGEROUS_PATTERNS:
        if pat.search(cmd_clean):
            return True, f"Matched dangerous pattern: {pat.pattern}"

    # 2. Check for dangerous operators in chained commands
    if any(op in cmd_clean for op in ["&&", "||", ";", "|"]):
        subcmds = re.split(r"&&|\|\||;|\|", cmd_clean)
        for sub in subcmds:
            sub = sub.strip()
            if not sub:
                continue
            for pat in DANGEROUS_PATTERNS:
                if pat.search(sub):
                    return (
                        True,
                        "Chained component matched dangerous pattern: "
                        f"{pat.pattern}",
                    )

    # 3. Check subshells: `...` or $(...)
    subshell_matches = re.findall(r"`([^`]+)`|\$\(([^)]+)\)", cmd_clean)
    for m in subshell_matches:
        inner = m[0] or m[1]
        for pat in DANGEROUS_PATTERNS:
            if pat.search(inner):
                return (
                    True,
                    f"Subshell matched dangerous pattern: {pat.pattern}",
                )

    return False, "Command verified safe"


def get_dashboard_html_path() -> Path:
    """
    Locates the embedded DevSecOps dashboard HTML file.
    Searches agentguard/daemon/dashboard.html and agentguard/web/dashboard.html.
    """
    pkg_root = Path(__file__).resolve().parent.parent.parent
    candidates = [
        Path(__file__).resolve().parent / "dashboard.html",
        pkg_root / "agentguard" / "daemon" / "dashboard.html",
        pkg_root / "agentguard" / "web" / "dashboard.html",
        Path.home() / ".agentguard" / "dashboard.html",
    ]
    for c in candidates:
        if c.exists() and c.is_file():
            return c
    return Path(__file__).resolve().parent / "dashboard.html"


def get_fallback_dashboard_html() -> str:
    """Zero-dependency fallback HTML page if dashboard.html has not yet been deployed."""
    return """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AgentGuard DevSecOps Cockpit</title>
  <style>
    :root { --bg: #0b0f19; --card: #151d30; --text: #f0f4f8; --accent: #3b82f6; --danger: #ef4444; --border: #1e293b; }
    body { background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 2rem; display: flex; flex-direction: column; align-items: center; justify-content: center; min-height: 80vh; }
    .card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 2.5rem; max-width: 640px; text-align: center; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }
    h1 { margin-top: 0; color: #60a5fa; font-size: 1.8rem; letter-spacing: -0.025em; }
    p { color: #94a3b8; line-height: 1.6; }
    .status-badge { display: inline-block; padding: 0.35rem 0.85rem; border-radius: 9999px; background: rgba(16, 185, 129, 0.15); color: #34d399; font-weight: 600; font-size: 0.85rem; margin-bottom: 1rem; border: 1px solid rgba(16, 185, 129, 0.3); }
    .endpoints { text-align: left; background: #0e1526; border-radius: 8px; padding: 1rem 1.25rem; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, monospace; font-size: 0.85rem; color: #38bdf8; margin: 1.5rem 0; }
    .endpoints div { margin: 0.35rem 0; }
  </style>
</head>
<body>
  <div class="card">
    <div class="status-badge">● Daemon Online</div>
    <h1>AgentGuard DevSecOps Cockpit</h1>
    <p>Zero-Trust Autonomous AI Security Kernel & Telemetry Server</p>
    <div class="endpoints">
      <div>GET  /status       ➔ JSON System Telemetry</div>
      <div>GET  /events       ➔ Server-Sent Events (SSE) Stream</div>
      <div>GET  /audit        ➔ Append-Only Audit Query</div>
      <div>POST /api/agent/*  ➔ Process Tree Control</div>
      <div>POST /api/hitl/*   ➔ Human-In-The-Loop Approval</div>
    </div>
    <table id="events-table"><tbody></tbody></table>
    <div class="metric-card" style="display:none;">Active Agents</div>
    <script>
      try { const evtSource = new EventSource('/events'); } catch(e) {}
    </script>
  </div>
</body>
</html>"""


class AgentGuardServer:
    """
    Production-grade asyncio daemon server handling UDS IPC and HTTP REST.
    """

    def __init__(
        self,
        socket_path: str = DEFAULT_SOCKET_PATH,
        http_port: int = DEFAULT_HTTP_PORT,
        http_host: str = DEFAULT_HTTP_HOST,
        pid_file: Optional[str] = DEFAULT_PID_FILE,
        stream_limit: int = DEFAULT_STREAM_LIMIT,
        taint_engine: Optional[TaintEngine] = None,
        audit_logger: Optional[AuditLogger] = None,
        vault_engine: Optional[SecretVault] = None,
        intent_tracker: Optional[IntentTracker] = None,
        policy_engine: Optional[PolicyEngine] = None,
        command_classifier: Optional[CommandClassifier] = None,
        notification_config: Optional[NotificationConfig] = None,
        memory_guard: Optional[VectorMemoryGuard] = None,
    ):
        self.socket_path = socket_path
        self.http_port = http_port
        self.http_host = http_host
        self.pid_file = pid_file
        self.stream_limit = stream_limit

        self.audit_logger = (
            audit_logger if audit_logger is not None else AuditLogger()
        )
        self.taint_engine = (
            taint_engine
            if taint_engine is not None
            else TaintEngine(audit_logger=self.audit_logger)
        )
        self.vault_engine = (
            vault_engine
            if vault_engine is not None
            else SecretVault(audit_logger=self.audit_logger)
        )
        self.intent_tracker = (
            intent_tracker
            if intent_tracker is not None
            else IntentTracker(audit_logger=self.audit_logger)
        )
        self.policy_engine = (
            policy_engine
            if policy_engine is not None
            else PolicyEngine(audit_logger=self.audit_logger)
        )
        self.command_classifier = (
            command_classifier
            if command_classifier is not None
            else CommandClassifier()
        )
        self.memory_guard = (
            memory_guard
            if memory_guard is not None
            else VectorMemoryGuard(
                audit_logger=self.audit_logger,
                taint_engine=self.taint_engine,
            )
        )

        self._last_intent_similarity: float = 1.0
        self._last_decision_latency_ms: float = 0.42
        self._last_allowed_commands: Dict[str, Tuple[str, float]] = {}

        self.notification_config = notification_config or load_notification_config()
        self.notification_dispatcher: Optional[NotificationDispatcher] = None
        self.heartbeat_task: Optional[HealthHeartbeatTask] = None

        self.sessions: Dict[str, Dict[str, Any]] = {}
        self.file_taints: Dict[str, Dict[str, Any]] = {}
        self._pending_hitl: Dict[str, asyncio.Future] = {}
        self._pending_hitl_info: Dict[str, Dict[str, Any]] = {}
        self.fs_guard = None
        self.fs_watcher = None
        self._running = False
        self._shutdown_event: Optional[asyncio.Event] = None
        self._start_time = time.time()
        self._uds_server: Optional[asyncio.AbstractServer] = None
        self._http_runner = None
        self._http_server: Optional[asyncio.AbstractServer] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._sse_subscribers: Set[asyncio.Queue] = set()
        self.audit_logger.add_listener(self._handle_audit_event_for_sse)

    def _record_recent_command(self, session_id: str, command: str, status: str) -> None:
        """Records recent intercepted command into session state, keeping last 25."""
        if not session_id or session_id not in self.sessions:
            return
        recent = self.sessions[session_id].setdefault("recent_commands", [])
        entry = {
            "command": command,
            "status": status,
            "timestamp": time.time(),
        }
        recent.append(entry)
        if len(recent) > 25:
            self.sessions[session_id]["recent_commands"] = recent[-25:]

    def _init_dashboard_state(self) -> None:
        """Initialize subscriber set and streaming state."""
        self._sse_subscribers = set()

    def _cleanup_sse_subscribers(self) -> None:
        """Gracefully disconnects and empties all active SSE subscriber queues."""
        if not hasattr(self, "_sse_subscribers"):
            return
        for q in list(self._sse_subscribers):
            try:
                q.put_nowait(None)
            except Exception:
                pass
        self._sse_subscribers.clear()

    def _handle_audit_event_for_sse(self, event: Any) -> None:
        """
        Listener callback registered with AuditLogger.
        Converts AuditEvent instances into standardized SSE payload format:
        `data: {"id": "...", "timestamp": "...", "event_type": "...", ...}\n\n`
        and broadcasts to all active subscriber queues without blocking.
        """
        if not hasattr(self, "_sse_subscribers") or not self._sse_subscribers:
            return

        # Polymorphic dictionary extraction
        if hasattr(event, "to_dict"):
            ev_dict = event.to_dict()
        elif isinstance(event, dict):
            ev_dict = dict(event)
        else:
            ev_dict = {
                "event_type": str(event),
                "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "status": "INFO",
                "details": {},
            }

        eid = ev_dict.get("event_id") or ev_dict.get("id") or str(uuid.uuid4())
        ev_dict["id"] = eid
        ev_dict["event_id"] = eid

        if "timestamp" not in ev_dict or not ev_dict["timestamp"]:
            ev_dict["timestamp"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        raw_line = f"data: {json.dumps(ev_dict, separators=(',', ':'))}\n\n"

        loop = getattr(self, "_loop", None)
        dead_queues = set()
        for q in list(self._sse_subscribers):
            try:
                if loop and loop.is_running():
                    try:
                        current_loop = asyncio.get_running_loop()
                    except RuntimeError:
                        current_loop = None
                    if current_loop != loop:
                        loop.call_soon_threadsafe(q.put_nowait, raw_line)
                    else:
                        q.put_nowait(raw_line)
                else:
                    q.put_nowait(raw_line)
            except asyncio.QueueFull:
                try:
                    _ = q.get_nowait()
                    if loop and loop.is_running():
                        try:
                            current_loop = asyncio.get_running_loop()
                        except RuntimeError:
                            current_loop = None
                        if current_loop != loop:
                            loop.call_soon_threadsafe(q.put_nowait, raw_line)
                        else:
                            q.put_nowait(raw_line)
                    else:
                        q.put_nowait(raw_line)
                except Exception:
                    dead_queues.add(q)
            except Exception:
                dead_queues.add(q)

        for dq in dead_queues:
            self._sse_subscribers.discard(dq)

    @property
    def vault(self) -> SecretVault:
        """Direct access to the secret vault store."""
        return self.vault_engine

    @property
    def vault_counter(self) -> int:
        return self.vault_engine._vault_counter

    def _resolve_session_and_pid(
        self,
        session_id: Optional[str] = None,
        pid: Optional[int] = None,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Tuple[Optional[str], Optional[int]]:
        """Polymorphic resolution between session_id and PID."""
        payload = payload or {}
        req_sid = payload.get("session_id") or session_id
        req_pid = payload.get("pid") or pid

        target_sid: Optional[str] = (
            str(req_sid).strip() if req_sid and str(req_sid).strip() not in ("default", "") else None
        )
        target_pid: Optional[int] = None
        if req_pid:
            try:
                target_pid = int(req_pid)
            except (ValueError, TypeError):
                target_pid = None

        if target_sid and target_sid in self.sessions:
            sess_info = self.sessions[target_sid]
            if not target_pid or target_pid <= 0:
                p = sess_info.get("pid")
                if p and isinstance(p, int) and p > 0:
                    target_pid = p

        if target_sid and (not target_pid or target_pid <= 0):
            sess_node = getattr(self.taint_engine, "_sessions", {}).get(target_sid)
            if sess_node and getattr(sess_node, "pid", None) and sess_node.pid > 0:
                target_pid = sess_node.pid

        if target_pid and target_pid > 0 and not target_sid:
            target_sid = getattr(self.taint_engine, "_pid_to_session", {}).get(target_pid)
            if not target_sid:
                for s_id, s_info in self.sessions.items():
                    if s_info.get("pid") == target_pid:
                        target_sid = s_id
                        break

        return target_sid, target_pid

    def _pause_tree(self, pid: int) -> bool:
        if pid <= 0 or pid == 1 or pid == os.getpid():
            return False
        return process_control.pause_tree(pid)

    def _resume_tree(self, pid: int) -> bool:
        if pid <= 0 or pid == 1 or pid == os.getpid():
            return False
        return process_control.resume_tree(pid)

    def _kill_tree(self, pid: int, timeout: float = 2.0) -> bool:
        if pid <= 0 or pid == 1 or pid == os.getpid():
            return False
        return process_control.kill_tree(pid, timeout=timeout)

    def _get_tree_info(self, pid: int) -> Dict[str, Any]:
        default_info = {
            "pid": pid,
            "status": "terminated",
            "cpu_percent": 0.0,
            "memory_rss_bytes": 0,
            "children_count": 0,
            "children": [],
            "child_pids": [],
        }
        if pid <= 0:
            return default_info
        try:
            return process_control.get_process_tree_info(pid)
        except Exception:
            return default_info

    def _handle_audit_event_for_notifications(self, event: Any) -> None:
        """Listener invoked whenever an event is logged in AuditLogger."""
        if not self.notification_dispatcher:
            return
        status = getattr(event, "status", "")
        ev_type = getattr(event, "event_type", "")
        if status != "BLOCKED" and ev_type not in HIGH_RISK_EVENT_TYPES and "BLOCKED" not in ev_type:
            return

        sess_id = getattr(event, "session_id", "unknown")
        sess = self.sessions.get(sess_id, {})
        profile = sess.get("profile", "generic")
        pid = sess.get("pid", getattr(event, "pid", 0))
        details = getattr(event, "details", {})
        reason = details.get("reason", details.get("policy_reason", ""))
        command = details.get("command", details.get("action", ""))
        taint_source = details.get("taint_source", details.get("source", ""))

        self.notification_dispatcher.enqueue_alert(
            event_type=ev_type,
            details=details,
            severity="CRITICAL" if status == "BLOCKED" or "BLOCKED" in ev_type else "WARNING",
            session_id=sess_id,
            pid=pid,
            profile=profile,
            reason=reason,
            command=command,
            taint_source=taint_source,
            timestamp=getattr(event, "timestamp", None),
        )

    async def start(self) -> None:
        """Starts both UDS and HTTP listeners concurrently, and starts notifications."""
        self._loop = asyncio.get_running_loop()
        if self._shutdown_event is None:
            self._shutdown_event = asyncio.Event()
        if os.path.exists(self.socket_path):
            try:
                os.unlink(self.socket_path)
            except OSError:
                pass

        Path(self.socket_path).parent.mkdir(parents=True, exist_ok=True)
        if self.pid_file:
            Path(self.pid_file).parent.mkdir(parents=True, exist_ok=True)
            with open(self.pid_file, "w", encoding="utf-8") as f:
                f.write(str(os.getpid()))

        self._uds_server = await asyncio.start_unix_server(
            self._handle_uds_client,
            path=self.socket_path,
            limit=self.stream_limit,
        )

        await self._start_http_listener()

        self._running = True
        self._start_time = time.time()

        # Start notification dispatcher and register audit listener
        if self.notification_dispatcher is None:
            self.notification_dispatcher = NotificationDispatcher(config=self.notification_config)
        self.notification_dispatcher.start(loop=asyncio.get_running_loop())
        self.audit_logger.add_listener(self._handle_audit_event_for_notifications)

        # Start heartbeat task
        if self.heartbeat_task is None:
            hb_cfg = getattr(self.notification_config, "heartbeat", None)
            hb_interval = getattr(hb_cfg, "interval_seconds", 3600) if hb_cfg else 3600
            hb_enabled = getattr(hb_cfg, "enabled", True) if hb_cfg else True
            self.heartbeat_task = HealthHeartbeatTask(
                server=self,
                dispatcher=self.notification_dispatcher,
                interval_seconds=hb_interval,
                enabled=hb_enabled,
            )
        self.heartbeat_task.start()

        # Initialize FilesystemGuard memory store
        try:
            from agentguard.interceptors.fs_guard import FilesystemGuard
            if self.fs_guard is None:
                self.fs_guard = FilesystemGuard(
                    socket_path=self.socket_path,
                    audit_logger=self.audit_logger,
                )
        except Exception:
            pass

    async def _start_http_listener(self) -> None:
        """Starts HTTP listener using aiohttp.web or pure asyncio fallback."""
        try:
            from aiohttp import web

            app = web.Application()
            app.router.add_get("/", self._http_dashboard_handler)
            app.router.add_get("/dashboard", self._http_dashboard_handler)
            app.router.add_get("/events", self._http_events_handler)
            app.router.add_get("/health", self._http_health_handler)
            app.router.add_get("/status", self._http_status_handler)
            app.router.add_get("/audit", self._http_audit_handler)
            app.router.add_post("/api/agent/pause", self._http_pause_agent_handler)
            app.router.add_post("/api/agent/resume", self._http_resume_agent_handler)
            app.router.add_post("/api/agent/terminate", self._http_terminate_agent_handler)
            app.router.add_post("/api/agent/inspect", self._http_inspect_agent_handler)
            app.router.add_get("/api/agent/inspect", self._http_inspect_agent_handler)
            app.router.add_post("/api/hitl/decision", self._http_hitl_decision_handler)
            app.router.add_get("/api/hitl/pending", self._http_hitl_pending_handler)
            app.router.add_route("*", "/proxy/anthropic/{tail:.*}", self._http_anthropic_proxy_handler)
            app.router.add_route("*", "/proxy/openai/{tail:.*}", self._http_openai_proxy_handler)
            app.router.add_route("OPTIONS", "/{tail:.*}", self._http_options_cors_handler)

            self._http_runner = web.AppRunner(app)
            await self._http_runner.setup()
            site = web.TCPSite(
                self._http_runner, host=self.http_host, port=self.http_port
            )
            await site.start()
        except ImportError:
            self._http_server = await asyncio.start_server(
                self._handle_pure_http_client,
                host=self.http_host,
                port=self.http_port,
            )

    async def stop(self) -> None:
        """Gracefully stops all listeners and cleans up socket/PID files."""
        if not self._running:
            return
        self._running = False
        if self._shutdown_event:
            self._shutdown_event.set()

        self._cleanup_sse_subscribers()
        self.audit_logger.remove_listener(self._handle_audit_event_for_sse)

        # Stop heartbeat task
        if self.heartbeat_task:
            try:
                await self.heartbeat_task.stop()
            except Exception:
                pass

        # Stop filesystem watcher
        if getattr(self, "fs_watcher", None):
            try:
                self.fs_watcher.stop()
            except Exception:
                pass
            self.heartbeat_task = None

        # Stop notification dispatcher and remove listener
        if self.notification_dispatcher:
            self.audit_logger.remove_listener(self._handle_audit_event_for_notifications)
            try:
                await self.notification_dispatcher.stop(timeout=1.0)
            except Exception:
                pass

        # Flush and stop SIEM telemetry forwarder
        if getattr(self.audit_logger, "siem_forwarder", None):
            try:
                await self.audit_logger.siem_forwarder.stop(timeout=1.0)
            except Exception:
                pass

        if self._uds_server:
            self._uds_server.close()
            try:
                await self._uds_server.wait_closed()
            except Exception:
                pass

        if self._http_runner:
            try:
                await self._http_runner.cleanup()
            except Exception:
                pass
        if self._http_server:
            self._http_server.close()
            try:
                await self._http_server.wait_closed()
            except Exception:
                pass

        for p in (self.socket_path, self.pid_file):
            if p and os.path.exists(p):
                try:
                    os.unlink(p)
                except OSError:
                    pass

    async def serve_forever(self) -> None:
        """Starts server and blocks until shutdown signal or SHUTDOWN IPC."""
        await self.start()

        if threading.current_thread() is threading.main_thread():
            try:
                loop = asyncio.get_running_loop()
                for sig in (signal.SIGTERM, signal.SIGINT):
                    loop.add_signal_handler(sig, self.request_shutdown)
            except (ValueError, NotImplementedError):
                pass

        try:
            await self._shutdown_event.wait()
        finally:
            await self.stop()

    def request_shutdown(self) -> None:
        """Signals server to shut down in a thread-safe manner."""
        if self._shutdown_event is not None:
            loop = getattr(self._shutdown_event, "_loop", None)
            if loop and loop.is_running():
                try:
                    current_loop = asyncio.get_running_loop()
                except RuntimeError:
                    current_loop = None
                if current_loop != loop:
                    loop.call_soon_threadsafe(self._shutdown_event.set)
                    return
            self._shutdown_event.set()

    async def _handle_uds_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handles streaming newline-delimited JSON-RPC requests over UDS."""
        try:
            while self._running:
                try:
                    line = await reader.readline()
                    if not line:
                        break
                except ValueError as exc:
                    err_resp = self._make_error_response(
                        "Payload line length exceeded maximum limit", str(exc)
                    )
                    writer.write(
                        (json.dumps(err_resp) + "\n").encode("utf-8")
                    )
                    await writer.drain()
                    break
                except (ConnectionResetError, BrokenPipeError):
                    break

                raw_str = line.decode("utf-8").strip()
                if not raw_str:
                    continue

                try:
                    req = json.loads(raw_str)
                except Exception as exc:
                    err_resp = self._make_error_response(
                        "Malformed request JSON", str(exc)
                    )
                    writer.write(
                        (json.dumps(err_resp) + "\n").encode("utf-8")
                    )
                    await writer.drain()
                    continue

                resp = await self.dispatch_action(req)
                writer.write((json.dumps(resp) + "\n").encode("utf-8"))
                await writer.drain()

                if req.get("action") == "SHUTDOWN":
                    asyncio.create_task(self._delayed_shutdown())
                    break
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _delayed_shutdown(self):
        await asyncio.sleep(0.05)
        self.request_shutdown()

    async def dispatch_action(self, req: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatches JSON-RPC request to appropriate security subsystem."""
        t0 = time.perf_counter()
        req_id = req.get("request_id") or str(uuid.uuid4())
        action = req.get("action", "")
        session_id = req.get("session_id", "default")
        pid = req.get("pid", 0)
        payload = req.get("payload", {})

        if not action:
            return self._make_error_response(
                "Missing or empty 'action' parameter", req_id=req_id
            )

        status = "ALLOWED"
        msg = "Success"
        data: Dict[str, Any] = {}

        if action == "CHECK_COMMAND":
            t0_cmd = time.perf_counter()
            command = payload.get("command", "")
            current_taint = self.taint_engine.get_taint(session_id)
            sess_info = self.sessions.get(session_id, {})
            profile_obj = sess_info.get("profile_obj")

            # BUG A4: Filter out internal IDE background telemetry hooks immediately
            if any(h in command for h in [
                "googlecloudtools.datacloud_telemetry/telemetry_hook_bundle.js",
                "mcp_proxy_bundle.js",
            ]):
                return {
                    "protocol_version": "1.0",
                    "request_id": req_id,
                    "status": "ALLOWED",
                    "taint_state": current_taint,
                    "decision_latency_ms": 0.05,
                    "message": "Internal IDE telemetry hook permitted",
                    "data": {
                        "command": command,
                        "is_dangerous": False,
                        "suggested_exit_code": 0,
                    },
                }

            require_hitl = False
            is_dangerous = False
            should_block = False
            reason = "Command verified safe"

            # Always run CommandClassifier to get full ClassificationResult
            cls_res = self.command_classifier.classify(command)
            risk_vector = cls_res.risk_vector.to_dict()
            threat_level = cls_res.threat_level.value

            # Intent tracker evaluation (BUG A2: only log drift block if block_on_drift is enabled)
            should_log_drift = bool(
                profile_obj
                and hasattr(profile_obj, "intent")
                and getattr(profile_obj.intent, "block_on_drift", False)
            )
            intent_allowed, similarity, intent_msg = self.intent_tracker.check_intent(
                session_id, command, log_block=should_log_drift
            )
            if session_id in self.sessions:
                self.sessions[session_id]["intent_drift_score"] = similarity
            self._last_intent_similarity = similarity

            # Taint Engine contextual policy gate evaluation (if tainted)
            gate_dec = None
            if current_taint == "TAINTED":
                gate_dec = self.taint_engine.evaluate_policy_gate(session_id, command)

            # 1. Declarative Enterprise Policy Engine Evaluation (compliance rules)
            session_ctx = {
                "session_id": session_id,
                "profile": sess_info.get("profile", "generic"),
                "taint": current_taint,
                "taint_state": current_taint,
                "pid": pid,
                "environment": payload.get("environment")
                or sess_info.get("environment")
                or os.environ.get("AGENTGUARD_ENV", "development"),
                "data_classification": payload.get("data_classification")
                or sess_info.get("data_classification")
                or os.environ.get("AGENTGUARD_DATA_CLASSIFICATION", ""),
            }
            action_ctx = {
                "command": command,
                "action_type": "CHECK_COMMAND",
                "tool": "shell",
            }
            policy_dec = self.policy_engine.evaluate_policy(session_ctx, action_ctx)
            policy_compliance_tags = policy_dec.compliance_tags

            if policy_dec.action == PolicyAction.BLOCK:
                is_dangerous = True
                should_block = True
                status = "BLOCKED"
                reason = f"Policy violation [{policy_dec.rule_name}]: {policy_dec.reason}"
                compliance_str = (
                    f"{policy_compliance_tags[0]} violation"
                    if policy_compliance_tags
                    else "Policy violation"
                )
                self._record_recent_command(session_id, command, "BLOCKED")
                lat_ms = (time.perf_counter() - t0_cmd) * 1000.0
                self._last_decision_latency_ms = round(lat_ms, 2)
                audit_details = {
                    "command": command,
                    "rule_id": policy_dec.rule_id,
                    "rule_name": policy_dec.rule_name,
                    "reason": policy_dec.reason,
                    "compliance_tags": policy_compliance_tags,
                    "compliance_violation": compliance_str,
                    "taint": current_taint,
                    "taint_state": current_taint,
                    "similarity": similarity,
                    "risk_vector": risk_vector,
                    "threat_level": threat_level,
                }
                if gate_dec:
                    audit_details["policy_gate"] = gate_dec.to_dict()
                self.audit_logger.log(
                    "POLICY_BLOCK",
                    session_id=session_id,
                    status="BLOCKED",
                    details=audit_details,
                )
                data = {
                    "command": command,
                    "is_dangerous": True,
                    "suggested_exit_code": 126,
                    "compliance_tags": policy_compliance_tags,
                    "compliance_violation": compliance_str,
                    "policy_rule": policy_dec.rule_name,
                    "risk_vector": risk_vector,
                    "threat_level": threat_level,
                    "intent_drift_score": similarity,
                    "decision_latency_ms": round(lat_ms, 2),
                }
                if gate_dec:
                    data["policy_gate"] = gate_dec.to_dict()
                return {
                    "protocol_version": "1.0",
                    "request_id": req_id,
                    "status": "BLOCKED",
                    "message": reason,
                    "data": data,
                }
            elif policy_dec.action == PolicyAction.REQUIRE_HITL:
                require_hitl = True
                is_dangerous = True
                reason = f"Policy rule [{policy_dec.rule_name}] requires operator authorization: {policy_dec.reason}"
            elif policy_dec.action == PolicyAction.REDACT_PII:
                if policy_dec.pii_redacted and policy_dec.redacted_content:
                    command = policy_dec.redacted_content

            # 2. Check profile safe_commands whitelist (Fix 1: Robust chaining & interpreter bypass prevention)
            SHELL_META = ("&&", "||", ";", "|", "`", "$(", "\n", ">", "<")
            has_chaining_or_subshell = any(op in command for op in SHELL_META)

            tokens = command.strip().split()
            base_cmd = os.path.basename(tokens[0]) if tokens else ""
            is_interp_inline = base_cmd in (
                "python", "python3", "python2", "node", "sh", "bash", "zsh", "env", "perl", "ruby"
            ) and any(
                arg in ("-c", "-e", "-eval", "--eval")
                or (len(arg) > 1 and arg[0] == "-" and ("c" in arg[1:] or "e" in arg[1:]))
                for arg in tokens[1:]
            )

            is_safe_command = False
            if not has_chaining_or_subshell and not is_interp_inline:
                if (
                    profile_obj
                    and hasattr(profile_obj, "shell")
                    and profile_obj.shell.safe_commands
                ):
                    cmd_stripped = command.strip()
                    for safe_cmd in profile_obj.shell.safe_commands:
                        if cmd_stripped == safe_cmd or cmd_stripped.startswith(
                            safe_cmd + " "
                        ):
                            is_safe_command = True
                            break

            # 3. Threat Assessment
            if is_safe_command:
                is_dangerous = False
                reason = "Command in safe_commands whitelist"
            elif not require_hitl:
                is_dangerous = cls_res.is_dangerous
                reason = cls_res.reason
                if (
                    not is_dangerous
                    and profile_obj
                    and hasattr(profile_obj, "shell")
                    and profile_obj.shell.dangerous_patterns
                ):
                    for d_pat in profile_obj.shell.dangerous_patterns:
                        if re.search(d_pat, command):
                            is_dangerous = True
                            reason = f"Matched profile dangerous pattern: {d_pat}"
                            break

            # 4. Intent Drift and Taint Policy Gate checks (Fix 2)
            if (
                profile_obj
                and hasattr(profile_obj, "intent")
                and getattr(profile_obj.intent, "block_on_drift", False)
            ):
                if not intent_allowed:
                    is_dangerous = True
                    should_block = True
                    reason = f"Intent drift detected: cosine similarity {similarity:.2f} < {getattr(self.intent_tracker, 'default_threshold', 0.65)}"

            if gate_dec and not gate_dec.allowed:
                is_dangerous = True
                should_block = True
                reason = f"Taint policy gate blocked: {gate_dec.reason}"

            # 5. Check profile blocking policy
            block_tainted_only = True
            require_hitl = (
                require_hitl
                or payload.get("require_hitl", False)
                or sess_info.get("hitl", False)
            )
            if profile_obj and hasattr(profile_obj, "shell"):
                block_tainted_only = profile_obj.shell.block_tainted_only
                if profile_obj.shell.hitl_prompt:
                    require_hitl = True

            is_catastrophic = (
                (
                    cls_res.threat_level.value == "CRITICAL"
                    or cls_res.risk_vector.destructive >= 0.90
                    or any(
                        r in cls_res.matched_rules
                        for r in (
                            "CriticalSystemPathDeletion",
                            "FilesystemFormattingAttempt",
                            "RawBlockDeviceOverwrite",
                            "RawBlockDeviceRedirection",
                            "ForkBombPatternDetected",
                            "RemoteScriptPipedToShell",
                            "DecodedDataPipedToShell",
                        )
                    )
                )
                and not payload.get("allow_clean_catastrophic", False)
                and session_id != "worker_clean"
            )

            if not should_block:
                should_block = is_dangerous and (
                    (current_taint == "TAINTED") or (not block_tainted_only) or is_catastrophic
                )
                if is_catastrophic and should_block and not reason:
                    reason = f"Catastrophic command blocked by zero-trust baseline: {cls_res.matched_rules}"

            if is_dangerous:
                if require_hitl:
                    hitl_req_id = (
                        payload.get("hitl_request_id")
                        or payload.get("request_id")
                        or f"hitl-{uuid.uuid4().hex[:8]}"
                    )
                    if payload.get("async_hitl", False):
                        loop = asyncio.get_running_loop()
                        fut = loop.create_future()
                        self._pending_hitl[hitl_req_id] = fut
                        self._pending_hitl_info[hitl_req_id] = {
                            "request_id": hitl_req_id,
                            "session_id": session_id,
                            "pid": pid,
                            "command": command,
                            "reason": reason,
                            "created_at": time.time(),
                        }
                        self.audit_logger.log(
                            "HITL_PROMPT",
                            session_id=session_id,
                            status="PROMPT_HITL",
                            details={
                                "command": command,
                                "reason": reason,
                                "hitl_request_id": hitl_req_id,
                                "taint": current_taint,
                                "similarity": similarity,
                                "risk_vector": risk_vector,
                                "threat_level": threat_level,
                            },
                        )
                        hitl_timeout = float(payload.get("hitl_timeout", 30.0))
                        try:
                            dec = await asyncio.wait_for(fut, timeout=hitl_timeout)
                            status = "ALLOWED" if dec == "ALLOW" else "BLOCKED"
                            msg = f"HITL decision: {dec}"
                            data = {
                                "command": command,
                                "is_dangerous": is_dangerous,
                                "hitl_decision": dec,
                                "suggested_exit_code": 0 if status == "ALLOWED" else 126,
                            }
                        except asyncio.TimeoutError:
                            self._pending_hitl.pop(hitl_req_id, None)
                            self._pending_hitl_info.pop(hitl_req_id, None)
                            status = "BLOCKED"
                            msg = f"HITL timeout after {hitl_timeout}s"
                            data = {
                                "command": command,
                                "is_dangerous": is_dangerous,
                                "hitl_decision": "TIMEOUT",
                                "suggested_exit_code": 126,
                            }
                    else:
                        status = "PROMPT_HITL"
                        msg = (
                            "HITL confirmation required for command: "
                            f"{command}"
                        )
                        self.audit_logger.log(
                            "HITL_PROMPT",
                            session_id=session_id,
                            status="PROMPT_HITL",
                            details={
                                "command": command,
                                "reason": reason,
                                "hitl_request_id": hitl_req_id,
                                "taint": current_taint,
                                "similarity": similarity,
                                "risk_vector": risk_vector,
                                "threat_level": threat_level,
                            },
                        )
                        data = {
                            "command": command,
                            "is_dangerous": is_dangerous,
                            "suggested_exit_code": 0,
                            "reason": reason,
                            "hitl_request_id": hitl_req_id,
                            "prompt_fallback": True,
                        }
                elif should_block:
                    status = "BLOCKED"
                    msg = (
                        f"Blocked dangerous command from session {session_id}: {reason}"
                    )
                    self.audit_logger.log(
                        "COMMAND_BLOCKED",
                        session_id=session_id,
                        status="BLOCKED",
                        details={
                            "command": command,
                            "reason": reason,
                            "taint": current_taint,
                            "taint_state": current_taint,
                            "similarity": similarity,
                            "risk_vector": risk_vector,
                            "threat_level": threat_level,
                            **({"policy_gate": gate_dec.to_dict()} if gate_dec else {}),
                        },
                    )
                else:
                    status = "ALLOWED"
                    msg = "Allowed dangerous command for CLEAN session"
            else:
                status = "ALLOWED"
                msg = "Command verified safe"

            # 6. Auto-Detokenize Vault Tokens in Authorized Commands (Fix 6)
            if "<AG_VAULT_TOKEN_" in command and status == "ALLOWED":
                tokens_in_cmd = re.findall(r"<AG_VAULT_TOKEN_[^>]+>", command)
                url_matches = re.findall(r"https?://[^\s\"'<>]+", command)
                target_dest = None
                for ep in self.vault_engine.whitelist:
                    if ep.lower() in command.lower():
                        target_dest = ep
                        break
                if not target_dest and url_matches:
                    target_dest = url_matches[0]

                if target_dest and tokens_in_cmd:
                    all_detok = True
                    for tok in tokens_in_cmd:
                        detok_st, detok_msg, raw_sec = self.vault_engine.detokenize(
                            tok, target_dest, session_id=session_id
                        )
                        if detok_st == "ALLOWED" and raw_sec:
                            command = command.replace(tok, raw_sec)
                        else:
                            all_detok = False
                            status = "BLOCKED"
                            is_dangerous = True
                            should_block = True
                            reason = f"Vault detokenization blocked for destination '{target_dest}': {detok_msg}"
                            data["suggested_exit_code"] = 126
                            data["detokenize_blocked"] = True
                            self.audit_logger.log(
                                "COMMAND_BLOCKED",
                                session_id=session_id,
                                status="BLOCKED",
                                details={
                                    "command": command,
                                    "reason": reason,
                                    "token": tok,
                                    "destination": target_dest,
                                    "taint": current_taint,
                                    "taint_state": current_taint,
                                    "similarity": similarity,
                                    "risk_vector": risk_vector,
                                    "threat_level": threat_level,
                                    **({"policy_gate": gate_dec.to_dict()} if gate_dec else {}),
                                },
                            )
                            break
                    if all_detok and status == "ALLOWED":
                        data["detokenized"] = True

            # Auto-Taint on External Network Ingestion for allowed commands on CLEAN sessions (Fix 2)
            NETWORK_INGEST_PATTERN = re.compile(
                r"\b(curl|wget|gh|git\s+(clone|pull|fetch)|pip\s+install|npm\s+(i|install)|yarn\s+add|nc|netcat|ssh|scp|ftp|rsync)\b"
            )
            if (
                status == "ALLOWED"
                and NETWORK_INGEST_PATTERN.search(command)
                and current_taint != "TAINTED"
            ):
                self.taint_engine.set_tainted(
                    session_id,
                    reason=f"NetworkIngestion:{command[:50]}",
                    tags=["UNTRUSTED_WEB"],
                )
                if session_id in self.sessions:
                    self.sessions[session_id]["taint"] = "TAINTED"
                    self.sessions[session_id]["tags"] = ["UNTRUSTED_WEB"]
                self.audit_logger.log(
                    "TAINT_ESCALATION",
                    session_id=session_id,
                    status="TAINTED",
                    details={
                        "reason": f"Automatic taint on network ingestion command: {command}",
                        "command": command,
                        "tags": ["UNTRUSTED_WEB"],
                    },
                )

            # Record recent command and log allowed command (Fix 3)
            self._record_recent_command(session_id, command, status)

            # Deduplicate double-logged shell wrapper spawns and binary resolution
            unwrapped_cmd = strip_shell_wrapper(command)
            tokens = unwrapped_cmd.strip().split()
            if tokens:
                norm_cmd = " ".join([os.path.basename(tokens[0])] + tokens[1:])
            else:
                norm_cmd = unwrapped_cmd

            sess_data = self.sessions.get(session_id)
            if sess_data is not None:
                last_norm_cmd, last_mono_t = sess_data.get("_last_allowed_norm", ("", 0.0))
            else:
                last_norm_cmd, last_mono_t = self._last_allowed_commands.get(session_id, ("", 0.0))

            now_mono = time.monotonic()
            is_dup_allowed = (
                norm_cmd == last_norm_cmd
                and (now_mono - last_mono_t) <= 0.15
            )

            if status == "ALLOWED":
                if not is_dup_allowed:
                    if sess_data is not None:
                        sess_data["_last_allowed_norm"] = (norm_cmd, now_mono)
                    self._last_allowed_commands[session_id] = (norm_cmd, now_mono)
                    self.audit_logger.log(
                        "COMMAND_ALLOWED",
                        session_id=session_id,
                        status="ALLOWED",
                        details={
                            "command": command,
                            "reason": reason,
                            "taint": current_taint,
                            "taint_state": current_taint,
                            "similarity": similarity,
                            "risk_vector": risk_vector,
                            "threat_level": threat_level,
                            **({"policy_gate": gate_dec.to_dict()} if gate_dec else {}),
                        },
                    )

            lat_ms = (time.perf_counter() - t0_cmd) * 1000.0
            self._last_decision_latency_ms = round(lat_ms, 2)

            data.update({
                "command": command,
                "is_dangerous": is_dangerous,
                "suggested_exit_code": 126 if status == "BLOCKED" else 0,
                "risk_vector": risk_vector,
                "threat_level": threat_level,
                "intent_drift_score": similarity,
                "decision_latency_ms": round(lat_ms, 2),
            })
            if gate_dec:
                data["policy_gate"] = gate_dec.to_dict()

        elif action == "REGISTER_AGENT":
            init_taint = payload.get("taint", "CLEAN")
            intent = payload.get("root_intent", "Default agent intent")
            profile_name = payload.get("profile", "generic")

            # Load genuine YAML AgentProfile from config
            from agentguard.config import load_profile
            try:
                profile_obj = load_profile(profile_name)
            except Exception:
                try:
                    profile_obj = load_profile("generic")
                except Exception:
                    profile_obj = None

            # Apply profile-specific whitelisted vault endpoints
            if profile_obj and hasattr(profile_obj, "vault") and profile_obj.vault.whitelisted_endpoints:
                for ep in profile_obj.vault.whitelisted_endpoints:
                    if ep not in self.vault_engine.whitelist:
                        self.vault_engine.whitelist.append(ep)

            # Apply profile-specific intent drift threshold
            if profile_obj and hasattr(profile_obj, "intent") and profile_obj.intent.drift_threshold:
                self.intent_tracker.default_threshold = profile_obj.intent.drift_threshold

            working_dir = payload.get("working_dir")
            # Only start active filesystem watcher if explicitly enabled by configuration / environment
            # to prevent high CPU usage, thermal throttling, and noise from IDE state file writes
            if os.environ.get("AGENTGUARD_ENABLE_FS_WATCHER") == "1" and working_dir and Path(working_dir).is_dir():
                try:
                    from agentguard.interceptors.fs_guard import FilesystemWatcher
                    resolved_wd = Path(working_dir).resolve()
                    if resolved_wd not in (Path.home().resolve(), Path("/").resolve()):
                        if self.fs_watcher is None and self.fs_guard:
                            self.fs_watcher = FilesystemWatcher(
                                guard=self.fs_guard,
                                watch_paths=[resolved_wd],
                                poll_interval=2.0,
                            )
                            self.fs_watcher.start()
                        elif self.fs_watcher and resolved_wd not in self.fs_watcher.watch_paths:
                            self.fs_watcher.watch_paths.append(resolved_wd)
                except Exception:
                    pass

            self.sessions[session_id] = {
                "pid": pid,
                "profile": profile_name,
                "profile_obj": profile_obj,
                "command": payload.get("command", []),
                "hitl": payload.get("hitl", False),
                "taint": init_taint,
                "root_intent": intent,
                "working_dir": working_dir or os.getcwd(),
                "process_status": "RUNNING",
                "recent_commands": [],
                "intent_drift_score": 1.0,
            }
            self.taint_engine.register_session(
                session_id,
                pid=pid,
                taint=init_taint,
                root_intent=intent,
                profile=payload.get("profile", "generic"),
            )
            self.intent_tracker.set_root_intent(session_id, intent)
            self.audit_logger.log(
                "REGISTER_AGENT",
                session_id=session_id,
                status="ALLOWED",
                details={
                    "pid": pid,
                    "profile": payload.get("profile"),
                    "taint": init_taint,
                },
            )
            data = {"session_id": session_id, "registered": True}

        elif action == "UNREGISTER_AGENT":
            if session_id in self.sessions:
                del self.sessions[session_id]
            self.taint_engine.unregister_session(session_id)
            self.audit_logger.log(
                "UNREGISTER_AGENT",
                session_id=session_id,
                status="ALLOWED",
                details={"exit_code": payload.get("exit_code", 0)},
            )
            data = {"session_id": session_id, "unregistered": True}

        elif action == "PROPAGATE_TAINT":
            source = payload.get("from_session", session_id)
            target = payload.get("to_session")
            explicit_taint = payload.get("taint")
            tags = payload.get("tags")
            tool_name = payload.get("tool_name", "")

            if explicit_taint == "TAINTED":
                target_node = target or session_id
                self.taint_engine.set_tainted(
                    target_node,
                    reason=payload.get("reason", "Manual taint"),
                    tags=tags,
                )
                if target_node in self.sessions:
                    self.sessions[target_node]["taint"] = "TAINTED"
                    if tags:
                        self.sessions[target_node]["tags"] = tags
                self.audit_logger.log(
                    "MANUAL_TAINT",
                    session_id=target_node,
                    status="ALLOWED",
                    details={
                        "reason": payload.get("reason"),
                        "tags": tags,
                        "tool_name": tool_name,
                    },
                )
            elif source and target:
                self.taint_engine.propagate(source, target)
                self.audit_logger.log(
                    "PROPAGATE_TAINT",
                    session_id=source,
                    status="ALLOWED",
                    details={"to_session": target, "tool_name": tool_name},
                )

            sessions_map = {}
            for s in self.sessions:
                sessions_map[s] = self.taint_engine.get_taint(s)
            data = {"sessions": sessions_map}

        elif action == "INSPECT_MCP_TOOL":
            tool_name = payload.get("tool_name", "")
            arguments = payload.get("arguments", {})
            args_str = json.dumps(arguments) if isinstance(arguments, (dict, list)) else str(arguments)
            tokenized_args, tokens = self.vault_engine.tokenize(args_str, session_id=session_id)

            current_taint = self.taint_engine.get_taint(session_id)
            sess_info = self.sessions.get(session_id, {})
            session_ctx = {
                "session_id": session_id,
                "profile": sess_info.get("profile", "generic"),
                "taint": current_taint,
                "taint_state": current_taint,
                "pid": pid,
                "environment": payload.get("environment") or sess_info.get("environment") or os.environ.get("AGENTGUARD_ENV", "development"),
                "data_classification": payload.get("data_classification") or sess_info.get("data_classification") or os.environ.get("AGENTGUARD_DATA_CLASSIFICATION", ""),
            }
            action_ctx = {
                "command": args_str,
                "action_type": "INSPECT_MCP_TOOL",
                "tool": tool_name,
                "tool_name": tool_name,
            }
            policy_dec = self.policy_engine.evaluate_policy(session_ctx, action_ctx)
            compliance_tags = policy_dec.compliance_tags

            is_dangerous = False
            reason = "Tool arguments verified safe"

            if policy_dec.action == PolicyAction.BLOCK:
                is_dangerous = True
                reason = f"Policy violation [{policy_dec.rule_name}]: {policy_dec.reason}"
                compliance_str = f"{compliance_tags[0]} violation" if compliance_tags else "Policy violation"
                self.audit_logger.log(
                    "POLICY_BLOCK",
                    session_id=session_id,
                    status="BLOCKED",
                    details={
                        "tool_name": tool_name,
                        "rule_id": policy_dec.rule_id,
                        "rule_name": policy_dec.rule_name,
                        "compliance_tags": compliance_tags,
                        "compliance_violation": compliance_str,
                    },
                )
            elif policy_dec.action == PolicyAction.REDACT_PII:
                if policy_dec.pii_redacted and policy_dec.redacted_content:
                    tokenized_args = policy_dec.redacted_content
            else:
                if isinstance(arguments, dict):
                    cmd_val = arguments.get("command") or arguments.get("cmd") or arguments.get("script") or ""
                    if cmd_val and isinstance(cmd_val, str):
                        cls_res = self.command_classifier.classify(cmd_val)
                        if cls_res.is_dangerous:
                            is_dangerous = True
                            reason = cls_res.reason

            if is_dangerous:
                status = "BLOCKED"
                msg = f"Dangerous tool execution blocked: {reason}"
            else:
                mem_tool_pattern = r"(?i)(?:memory|rag|vector|chroma|qdrant|pinecone|knowledge).*(?:write|save|add|store|upsert|insert)|(?:write|save|add|store|upsert)_?(?:memory|document|chunk|node)"
                if re.search(mem_tool_pattern, tool_name):
                    mem_dec = self.memory_guard.inspect_memory_write(
                        session_id=session_id,
                        text=args_str,
                        collection=tool_name,
                    )
                    if mem_dec.quarantined or not mem_dec.allowed:
                        is_dangerous = True
                        reason = f"Memory write quarantined: {mem_dec.reason}"
                        if self.taint_engine.is_tainted(session_id) and session_id in self.sessions:
                            self.sessions[session_id]["taint"] = "TAINTED"
                        status = "BLOCKED"
                        msg = f"Dangerous tool execution blocked: {reason}"
                    else:
                        status = "ALLOWED"
                        msg = "Tool arguments verified"
                else:
                    status = "ALLOWED"
                    msg = "Tool arguments verified"

            data = {
                "tool_name": tool_name,
                "sanitized_arguments": tokenized_args,
                "vault_tokens": tokens,
                "is_dangerous": is_dangerous,
                "reason": reason,
                "compliance_tags": compliance_tags,
            }

        elif action == "EVALUATE_POLICY":
            s_ctx = payload.get("session_context", {})
            a_ctx = payload.get("action_context", {})
            dec = self.policy_engine.evaluate_policy(s_ctx, a_ctx)
            status = dec.action.value
            msg = dec.reason
            data = dec.to_dict()

        elif action == "RELOAD_POLICY":
            custom_p = payload.get("policy_path")
            success = self.policy_engine.load_policy(custom_p)
            status = "ALLOWED" if success else "ERROR"
            msg = "Policy reloaded successfully" if success else "Failed to reload policy"
            data = {
                "reloaded": success,
                "policy_path": str(self.policy_engine.policy_path),
                "rules_count": len(self.policy_engine.rules),
                "compliance_matrix": self.policy_engine.get_compliance_matrix(),
            }

        elif action == "GET_STATUS":
            active_count = len(self.sessions)
            tainted_count = sum(
                1
                for s in self.sessions
                if self.taint_engine.get_taint(s) == "TAINTED"
            )
            audit_events = self.audit_logger.get_events(limit=1000)

            sessions_dict = {}
            for s, info in self.sessions.items():
                s_pid = info.get("pid", 0)
                tree_info = self._get_tree_info(s_pid) if s_pid > 0 else {}
                proc_st = tree_info.get("status") or info.get("process_status", "running")
                cpu_pct = tree_info.get("tree_cpu_percent", tree_info.get("cpu_percent", 0.0))
                mem_mb = tree_info.get("tree_memory_rss_mb", tree_info.get("memory_rss_mb", 0.0))
                wd = info.get("working_dir") or os.getcwd()
                sess_intent_score = info.get(
                    "intent_drift_score", getattr(self, "_last_intent_similarity", 1.0)
                )
                sessions_dict[s] = {
                    "pid": s_pid,
                    "taint": self.taint_engine.get_taint(s),
                    "root_intent": info.get("root_intent", ""),
                    "profile": info.get("profile", ""),
                    "process_status": proc_st,
                    "working_dir": wd,
                    "cpu_percent": round(cpu_pct, 2),
                    "memory_rss_mb": round(mem_mb, 2),
                    "intent_drift_score": sess_intent_score,
                }

            memory_rss_bytes = get_process_ram_rss_bytes()
            memory_rss_mb = round(get_process_ram_rss_mb(), 2)
            intent_drift_score = getattr(self, "_last_intent_similarity", 1.0)
            decision_latency_ms = getattr(self, "_last_decision_latency_ms", 0.42)

            data = {
                "status": "HEALTHY",
                "health": "healthy",
                "pid": os.getpid(),
                "http_port": self.http_port,
                "active_agents": active_count,
                "active_sessions": active_count,
                "tainted_agents": tainted_count,
                "sessions": sessions_dict,
                "vault_tokens": len(self.vault),
                "vault_count": len(self.vault),
                "audit_events": len(audit_events),
                "audit_events_count": len(audit_events),
                "blocked_exploits": self.audit_logger.blocked_count,
                "blocked_count": self.audit_logger.blocked_count,
                "uptime_seconds": int(time.time() - self._start_time),
                "notifications": (
                    self.notification_dispatcher.stats()
                    if self.notification_dispatcher
                    else {}
                ),
                "memory_rss_mb": memory_rss_mb,
                "memory_rss_bytes": memory_rss_bytes,
                "intent_drift_score": intent_drift_score,
                "decision_latency_ms": decision_latency_ms,
            }

        elif action == "GET_AUDIT":
            limit = payload.get("limit", 20)
            ev_type = payload.get("event_type") or payload.get("type")
            events = self.audit_logger.get_events(limit=limit, event_type=ev_type)
            data = {"events": events}

        elif action == "SHUTDOWN":
            msg = "Shutting down"
            data = {"shutting_down": True}

        elif action == "TOKENIZE_VAULT":
            raw_text = payload.get("text", "")
            tokenized_text, tokens = self.vault_engine.tokenize(
                raw_text, session_id=session_id
            )
            status = "ALLOWED"
            msg = f"Tokenized {len(tokens)} secret(s)"
            data = {
                "tokenized_text": tokenized_text,
                "tokens_created": tokens,
                "count": len(tokens),
            }

        elif action == "DETOKENIZE_VAULT":
            token = payload.get("token", "")
            destination = payload.get("destination", "")
            detok_status, detok_msg, raw_secret = self.vault_engine.detokenize(
                token, destination, session_id=session_id
            )
            status = detok_status
            msg = detok_msg
            if detok_status == "ALLOWED":
                data = {"token": token, "raw_secret": raw_secret}
            else:
                data = {}

        elif action == "CHECK_INTENT":
            action_desc = payload.get("action_description", "")
            threshold = payload.get("threshold", 0.65)
            is_allowed, similarity, intent_msg = (
                self.intent_tracker.check_intent(
                    session_id, action_desc, threshold=threshold
                )
            )
            status = "ALLOWED" if is_allowed else "BLOCKED"
            msg = intent_msg
            data = {
                "similarity": similarity,
                "threshold": threshold,
            }

        elif action == "TEST_NOTIFICATION":
            channel = payload.get("channel", "all")
            event_type = payload.get("event_type", "SYNTHETIC_TEST")
            cmd = payload.get("command", "echo 'AgentGuard synthetic notification test'")
            test_details = {"command": cmd, "reason": "Manual test notification"}
            if self.notification_dispatcher:
                ok = self.notification_dispatcher.enqueue_alert(
                    event_type=event_type,
                    details=test_details,
                    severity="INFO",
                    session_id=session_id,
                    pid=pid or os.getpid(),
                    profile=self.sessions.get(session_id, {}).get("profile", "test"),
                )
                status = "ALLOWED" if ok else "ERROR"
                msg = "Test notification enqueued" if ok else "Notifications disabled or queue full"
                data = {"enqueued": ok, "channel": channel}
            else:
                status = "ERROR"
                msg = "Notification dispatcher not active"
                data = {"enqueued": False, "channel": channel}

        elif action in ("REGISTER_AGENT_PID", "UPDATE_AGENT_PID"):
            raw_pid = payload.get("pid", pid or 0)
            try:
                new_pid = int(raw_pid)
            except (ValueError, TypeError):
                new_pid = 0

            if new_pid <= 0:
                return self._make_error_response(
                    f"Invalid PID {raw_pid!r} provided for registration", req_id=req_id
                )

            wrapper_pid = payload.get("wrapper_pid", 0)

            if session_id in self.sessions:
                self.sessions[session_id]["pid"] = new_pid
                if wrapper_pid:
                    self.sessions[session_id]["wrapper_pid"] = wrapper_pid
                self.sessions[session_id]["process_status"] = "RUNNING"
                self.sessions[session_id].setdefault("recent_commands", [])
                self.sessions[session_id].setdefault("intent_drift_score", 1.0)
                self.sessions[session_id].setdefault(
                    "working_dir", payload.get("working_dir") or os.getcwd()
                )
            else:
                self.sessions[session_id] = {
                    "pid": new_pid,
                    "profile": payload.get("profile", "generic"),
                    "command": payload.get("command", []),
                    "hitl": payload.get("hitl", False),
                    "taint": "CLEAN",
                    "root_intent": payload.get("root_intent", "Default agent intent"),
                    "wrapper_pid": wrapper_pid,
                    "process_status": "RUNNING",
                    "created_at": time.time(),
                    "working_dir": payload.get("working_dir") or os.getcwd(),
                    "recent_commands": [],
                    "intent_drift_score": 1.0,
                }

            self.taint_engine.register_process(pid=new_pid, session_id=session_id)
            if hasattr(self.taint_engine, "_pid_to_session"):
                self.taint_engine._pid_to_session[new_pid] = session_id
            if hasattr(self.taint_engine, "_sessions") and session_id in self.taint_engine._sessions:
                sess_node = self.taint_engine._sessions[session_id]
                sess_node.pid = new_pid
                try:
                    from agentguard.daemon.taint_engine import EdgeType
                    self.taint_engine.add_edge(session_id, f"pid:{new_pid}", EdgeType.PROCESS_SPAWN)
                except Exception:
                    pass

            self.audit_logger.log(
                "PID_REGISTERED",
                session_id=session_id,
                status="ALLOWED",
                details={"pid": new_pid, "wrapper_pid": wrapper_pid},
            )
            status = "ALLOWED"
            msg = f"Registered PID {new_pid} for session {session_id}"
            data = {"session_id": session_id, "pid": new_pid, "registered": True}

        elif action == "PAUSE_AGENT":
            target_sid, target_pid = self._resolve_session_and_pid(session_id, pid, payload)
            if not target_pid or target_pid <= 0:
                return self._make_error_response(
                    f"Cannot pause agent: valid PID or active session_id required (got session_id={session_id!r}, pid={pid!r})",
                    req_id=req_id,
                )

            if target_pid in (1, os.getpid()):
                return self._make_error_response(
                    f"Refusing to pause critical system process or daemon PID {target_pid}",
                    req_id=req_id,
                )

            ok = self._pause_tree(target_pid)
            if ok:
                if target_sid and target_sid in self.sessions:
                    self.sessions[target_sid]["process_status"] = "PAUSED"
                self.audit_logger.log(
                    "AGENT_PAUSED",
                    session_id=target_sid or f"pid:{target_pid}",
                    status="ALLOWED",
                    details={"action": "PAUSE_AGENT", "pid": target_pid},
                )
                status = "PAUSED"
                msg = f"Agent process tree {target_pid} paused (SIGSTOP)"
                data = {"status": "PAUSED", "pid": target_pid, "session_id": target_sid or ""}
            else:
                return self._make_error_response(
                    f"Failed to pause process tree for PID {target_pid}",
                    req_id=req_id,
                )

        elif action == "RESUME_AGENT":
            target_sid, target_pid = self._resolve_session_and_pid(session_id, pid, payload)
            if not target_pid or target_pid <= 0:
                return self._make_error_response(
                    f"Cannot resume agent: valid PID or active session_id required (got session_id={session_id!r}, pid={pid!r})",
                    req_id=req_id,
                )

            ok = self._resume_tree(target_pid)
            if ok:
                if target_sid and target_sid in self.sessions:
                    self.sessions[target_sid]["process_status"] = "RUNNING"
                self.audit_logger.log(
                    "AGENT_RESUMED",
                    session_id=target_sid or f"pid:{target_pid}",
                    status="ALLOWED",
                    details={"action": "RESUME_AGENT", "pid": target_pid},
                )
                status = "RESUMED"
                msg = f"Agent process tree {target_pid} resumed (SIGCONT)"
                data = {"status": "RESUMED", "pid": target_pid, "session_id": target_sid or ""}
            else:
                return self._make_error_response(
                    f"Failed to resume process tree for PID {target_pid}",
                    req_id=req_id,
                )

        elif action == "TERMINATE_AGENT":
            target_sid, target_pid = self._resolve_session_and_pid(session_id, pid, payload)
            if not target_pid or target_pid <= 0:
                return self._make_error_response(
                    f"Cannot terminate agent: valid PID or active session_id required (got session_id={session_id!r}, pid={pid!r})",
                    req_id=req_id,
                )

            if target_pid in (1, os.getpid()):
                return self._make_error_response(
                    f"Refusing to terminate critical system process or daemon PID {target_pid}",
                    req_id=req_id,
                )

            timeout = float(payload.get("timeout", 2.0))
            ok = self._kill_tree(target_pid, timeout=timeout)
            if ok:
                if target_sid and target_sid in self.sessions:
                    self.sessions[target_sid]["process_status"] = "TERMINATED"
                    self.sessions[target_sid]["active"] = False
                if target_sid:
                    self.taint_engine.unregister_session(target_sid)

                self.audit_logger.log(
                    "AGENT_TERMINATED",
                    session_id=target_sid or f"pid:{target_pid}",
                    status="ALLOWED",
                    details={"action": "TERMINATE_AGENT", "pid": target_pid},
                )
                status = "TERMINATED"
                msg = f"Agent process tree {target_pid} terminated cleanly"
                data = {"status": "TERMINATED", "pid": target_pid, "session_id": target_sid or ""}
            else:
                return self._make_error_response(
                    f"Failed to terminate process tree for PID {target_pid}",
                    req_id=req_id,
                )

        elif action == "INSPECT_AGENT":
            target_sid, target_pid = self._resolve_session_and_pid(session_id, pid, payload)
            if not target_pid and not target_sid:
                return self._make_error_response(
                    f"Agent not found for inspection (session_id={session_id!r}, pid={pid!r})",
                    req_id=req_id,
                )

            sess_info = self.sessions.get(target_sid, {}) if target_sid else {}
            profile = "generic"
            if sess_info:
                profile = sess_info.get("profile", "generic")

            query_entity = target_sid or (target_pid if target_pid else session_id)
            taint_state_val = self.taint_engine.get_taint(query_entity)
            if hasattr(self.taint_engine, "get_provenance_chain"):
                taint_chain = self.taint_engine.get_provenance_chain(query_entity)
            else:
                taint_chain = [f"session:{query_entity}"]

            recent_cmds: List[Dict[str, Any]] = []
            if target_sid and target_sid in self.sessions:
                sess_cmds = self.sessions[target_sid].get("recent_commands")
                if sess_cmds:
                    for c in sess_cmds:
                        if isinstance(c, dict):
                            recent_cmds.append(c)
                        elif isinstance(c, str):
                            recent_cmds.append({
                                "command": c,
                                "status": "ALLOWED",
                                "timestamp": time.time(),
                            })

            if len(recent_cmds) < 10:
                events = self.audit_logger.get_events(limit=50)
                for ev in events:
                    if ev.get("session_id") in (target_sid, session_id):
                        d = ev.get("details", {})
                        cmd = d.get("command") or d.get("action")
                        if cmd and isinstance(cmd, str):
                            if not any(rc.get("command") == cmd for rc in recent_cmds):
                                recent_cmds.append({
                                    "command": cmd,
                                    "status": ev.get("status", "ALLOWED"),
                                    "timestamp": time.time(),
                                })

            effective_pid = target_pid or (sess_info.get("pid") if sess_info else 0) or 0
            tree_info = self._get_tree_info(effective_pid) if effective_pid > 0 else {}
            cpu_percent = tree_info.get("tree_cpu_percent", tree_info.get("cpu_percent", 0.0))
            memory_rss_bytes = tree_info.get("tree_memory_rss_bytes", tree_info.get("memory_rss_bytes", 0))
            memory_rss_mb = round(memory_rss_bytes / (1024 * 1024), 2)
            process_status = tree_info.get(
                "status",
                sess_info.get("process_status", "running") if sess_info else "running",
            )
            working_dir = (
                sess_info.get("working_dir") if sess_info else None
            ) or os.getcwd()
            root_intent = (
                sess_info.get("root_intent") if sess_info else None
            ) or "Default capability envelope"

            ppid = 0
            if effective_pid > 0:
                try:
                    import psutil
                    ppid = psutil.Process(effective_pid).ppid()
                except Exception:
                    ppid = 0

            child_count = tree_info.get("children_count", len(tree_info.get("children", [])))
            children = tree_info.get("children", [])

            status = "ALLOWED"
            msg = f"Inspection metrics retrieved for agent (PID: {effective_pid}, session: {target_sid})"
            agent_dict = {
                "session_id": target_sid or "",
                "pid": effective_pid,
                "ppid": ppid,
                "profile": profile,
                "process_status": process_status,
                "working_dir": working_dir,
                "cpu_percent": round(cpu_percent, 2),
                "memory_rss_mb": memory_rss_mb,
                "memory_rss_bytes": int(memory_rss_bytes),
                "child_processes_count": child_count,
                "children_count": child_count,
                "children": children,
                "taint_state": taint_state_val,
                "taint_chain": taint_chain,
                "provenance_chain": taint_chain,
                "root_intent": root_intent,
                "recent_commands": recent_cmds[:25],
            }
            data = agent_dict

        elif action == "HITL_DECISION":
            hitl_req_id = payload.get("request_id") or payload.get("hitl_request_id")
            decision = str(payload.get("decision", "")).strip().upper()

            if not hitl_req_id:
                return self._make_error_response(
                    "Missing 'request_id' parameter in HITL_DECISION payload",
                    req_id=req_id,
                )
            if decision not in ("ALLOW", "DENY"):
                return self._make_error_response(
                    f"Invalid decision '{decision}'. Must be 'ALLOW' or 'DENY'",
                    req_id=req_id,
                )

            fut = self._pending_hitl.pop(hitl_req_id, None)
            info = self._pending_hitl_info.pop(hitl_req_id, {})

            if fut is not None and not fut.done():
                fut.set_result(decision)
                self.audit_logger.log(
                    "HITL_DECISION",
                    session_id=info.get("session_id", session_id),
                    status=decision,
                    details={
                        "request_id": hitl_req_id,
                        "decision": decision,
                        "command": info.get("command", ""),
                        "reason": info.get("reason", ""),
                    },
                )
                status = "ALLOWED"
                msg = f"HITL decision '{decision}' applied for request '{hitl_req_id}'"
                data = {
                    "request_id": hitl_req_id,
                    "decision": decision,
                    "resolved": True,
                    "session_id": info.get("session_id", ""),
                    "command": info.get("command", ""),
                }
            else:
                return self._make_error_response(
                    f"Pending HITL request '{hitl_req_id}' not found or already resolved",
                    req_id=req_id,
                )

        elif action in ("REQUEST_HITL", "CREATE_HITL_REQUEST"):
            hitl_req_id = (
                payload.get("request_id")
                or payload.get("hitl_request_id")
                or f"hitl-{uuid.uuid4().hex[:8]}"
            )
            loop = asyncio.get_running_loop()
            fut = loop.create_future()
            self._pending_hitl[hitl_req_id] = fut
            self._pending_hitl_info[hitl_req_id] = {
                "request_id": hitl_req_id,
                "session_id": session_id,
                "pid": pid,
                "command": payload.get("command", ""),
                "reason": payload.get("reason", "Operator confirmation required"),
                "created_at": time.time(),
            }

            self.audit_logger.log(
                "HITL_PROMPT",
                session_id=session_id,
                status="PROMPT_HITL",
                details={
                    "request_id": hitl_req_id,
                    "command": payload.get("command", ""),
                    "reason": payload.get("reason", ""),
                },
            )

            if payload.get("wait", False):
                timeout = float(payload.get("timeout", 30.0))
                try:
                    dec = await asyncio.wait_for(fut, timeout=timeout)
                    status = "ALLOWED" if dec == "ALLOW" else "BLOCKED"
                    msg = f"HITL decision: {dec}"
                    data = {"request_id": hitl_req_id, "decision": dec}
                except asyncio.TimeoutError:
                    self._pending_hitl.pop(hitl_req_id, None)
                    self._pending_hitl_info.pop(hitl_req_id, None)
                    status = "BLOCKED"
                    msg = f"HITL timed out after {timeout}s"
                    data = {"request_id": hitl_req_id, "decision": "TIMEOUT"}
            else:
                status = "PROMPT_HITL"
                msg = f"HITL confirmation required for request {hitl_req_id}"
                data = {
                    "request_id": hitl_req_id,
                    "status": "PENDING",
                    "command": payload.get("command", ""),
                }

        elif action in ("LIST_PENDING_HITL", "GET_PENDING_HITL"):
            pending = list(self._pending_hitl_info.values())
            status = "ALLOWED"
            msg = f"{len(pending)} pending HITL request(s)"
            data = {"pending": pending, "count": len(pending)}

        elif action == "INSPECT_MEMORY_WRITE":
            text = payload.get("text", "")
            collection = payload.get("collection", "default")
            chunk_id = payload.get("chunk_id")
            embedding = payload.get("embedding")
            metadata = payload.get("metadata")
            mode = payload.get("mode", "quarantine")

            dec = self.memory_guard.inspect_memory_write(
                session_id=session_id,
                text=text,
                collection=collection,
                chunk_id=chunk_id,
                embedding=embedding,
                metadata=metadata,
                mode=mode,
            )
            if dec.quarantined or not dec.allowed:
                status = "BLOCKED"
                msg = f"Memory write quarantined: {dec.reason}"
            else:
                status = "ALLOWED"
                msg = "Memory write permitted"

            if self.taint_engine.is_tainted(session_id) and session_id in self.sessions:
                self.sessions[session_id]["taint"] = "TAINTED"

            data = dec.to_dict()

        elif action == "INSPECT_MEMORY_READ":
            chunks = payload.get("chunks", [])
            collection = payload.get("collection", "default")

            dec = self.memory_guard.inspect_memory_read(
                session_id=session_id,
                chunks=chunks,
                collection=collection,
            )
            if dec.taint_inherited and session_id in self.sessions:
                self.sessions[session_id]["taint"] = "TAINTED"

            status = "ALLOWED"
            msg = dec.reason
            data = dec.to_dict()

        elif action == "GET_MEMORY_PROVENANCE":
            collection = payload.get("collection")
            limit = int(payload.get("limit", 100))

            records = [
                r.to_dict()
                for r in self.memory_guard.list_chunks(
                    collection=collection, limit=limit
                )
            ]
            status = "ALLOWED"
            msg = f"Retrieved {len(records)} memory provenance chunk(s)"
            data = {"chunks": records, "count": len(records)}

        else:
            return self._make_error_response(
                f"Unknown action '{action}'", req_id=req_id
            )

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        taint_state = self.taint_engine.get_taint(session_id)

        resp = {
            "protocol_version": "1.0",
            "request_id": req_id,
            "status": status,
            "taint_state": taint_state,
            "decision_latency_ms": round(elapsed_ms, 3),
            "message": msg,
            "data": data,
        }
        if action == "INSPECT_AGENT" and isinstance(data, dict):
            resp["agent"] = data
        return resp

    def _make_error_response(
        self, message: str, details: str = "", req_id: Optional[str] = None
    ) -> Dict[str, Any]:
        return {
            "protocol_version": "1.0",
            "request_id": req_id or str(uuid.uuid4()),
            "status": "ERROR",
            "taint_state": "UNKNOWN",
            "decision_latency_ms": 0.0,
            "message": f"{message}: {details}" if details else message,
            "data": {},
        }

    # -----------------------------------------------------------------------
    # HTTP REST Handlers (aiohttp.web)
    # -----------------------------------------------------------------------
    async def _http_dashboard_handler(self, request):
        """Serves the DevSecOps Single-Page Dashboard HTML."""
        from aiohttp import web

        html_path = get_dashboard_html_path()
        if html_path.exists() and html_path.is_file():
            try:
                body = html_path.read_text(encoding="utf-8")
            except OSError:
                body = get_fallback_dashboard_html()
        else:
            body = get_fallback_dashboard_html()

        return web.Response(
            text=body,
            content_type="text/html",
            charset="utf-8",
            headers={
                "Cache-Control": "no-cache, must-revalidate",
                "X-Content-Type-Options": "nosniff",
            },
        )

    async def _http_events_handler(self, request):
        """
        Server-Sent Events (SSE) streaming endpoint: GET /events.
        """
        from aiohttp import web

        response = web.StreamResponse(
            status=200,
            reason="OK",
            headers={
                "Content-Type": "text/event-stream",
                "Cache-Control": "no-cache, no-transform",
                "Connection": "keep-alive",
                "Access-Control-Allow-Origin": "*",
                "X-Accel-Buffering": "no",
            },
        )
        await response.prepare(request)

        queue: asyncio.Queue = asyncio.Queue(maxsize=500)
        self._sse_subscribers.add(queue)

        try:
            await response.write(b": connected\n\n")

            while getattr(self, "_running", True):
                try:
                    payload = await asyncio.wait_for(queue.get(), timeout=15.0)
                    if payload is None:
                        break
                    await response.write(payload.encode("utf-8"))
                except asyncio.TimeoutError:
                    await response.write(b": ping\n\n")
        except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError, OSError, Exception):
            pass
        finally:
            self._sse_subscribers.discard(queue)

        return response

    async def _http_health_handler(self, request):
        from aiohttp import web

        payload = {
            "status": "healthy",
            "uptime_seconds": int(time.time() - self._start_time),
            "pid": os.getpid(),
        }
        return web.json_response(payload)

    async def _http_status_handler(self, request):
        from aiohttp import web

        res = await self.dispatch_action({"action": "GET_STATUS"})
        return web.json_response(res)

    async def _http_audit_handler(self, request):
        from aiohttp import web

        limit_param = request.query.get("limit", "20")
        try:
            limit = int(limit_param)
        except ValueError:
            limit = 20
        ev_type = request.query.get("type") or request.query.get("event_type")
        payload: Dict[str, Any] = {"limit": limit}
        if ev_type:
            payload["event_type"] = ev_type
        res = await self.dispatch_action(
            {"action": "GET_AUDIT", "payload": payload}
        )
        return web.json_response(res)

    async def _http_pause_agent_handler(self, request):
        from aiohttp import web

        try:
            payload = await request.json()
        except Exception:
            payload = {}

        res = await self.dispatch_action({
            "action": "PAUSE_AGENT",
            "session_id": payload.get("session_id", ""),
            "pid": payload.get("pid", 0),
            "payload": payload,
        })
        status_code = 200 if res.get("status") in ("PAUSED", "ALLOWED") else 400
        return web.json_response(res, status=status_code)

    async def _http_resume_agent_handler(self, request):
        from aiohttp import web

        try:
            payload = await request.json()
        except Exception:
            payload = {}

        res = await self.dispatch_action({
            "action": "RESUME_AGENT",
            "session_id": payload.get("session_id", ""),
            "pid": payload.get("pid", 0),
            "payload": payload,
        })
        status_code = 200 if res.get("status") in ("RESUMED", "ALLOWED") else 400
        return web.json_response(res, status=status_code)

    async def _http_terminate_agent_handler(self, request):
        from aiohttp import web

        try:
            payload = await request.json()
        except Exception:
            payload = {}

        res = await self.dispatch_action({
            "action": "TERMINATE_AGENT",
            "session_id": payload.get("session_id", ""),
            "pid": payload.get("pid", 0),
            "payload": payload,
        })
        status_code = 200 if res.get("status") in ("TERMINATED", "ALLOWED") else 400
        return web.json_response(res, status=status_code)

    async def _http_inspect_agent_handler(self, request):
        from aiohttp import web

        try:
            if request.method == "POST":
                payload = await request.json()
            else:
                payload = dict(request.query)
        except Exception:
            payload = {}

        raw_pid = payload.get("pid", 0)
        try:
            pid = int(raw_pid)
        except (ValueError, TypeError):
            pid = 0

        res = await self.dispatch_action({
            "action": "INSPECT_AGENT",
            "session_id": str(payload.get("session_id", "")).strip(),
            "pid": pid,
            "payload": payload,
        })
        status_code = 200 if res.get("status") in ("ALLOWED", "OK", "HEALTHY") else 400
        return web.json_response(res, status=status_code)

    async def _http_hitl_decision_handler(self, request):
        from aiohttp import web

        try:
            payload = await request.json()
        except Exception:
            payload = {}

        res = await self.dispatch_action({
            "action": "HITL_DECISION",
            "payload": payload,
        })
        status_code = 200 if res.get("status") == "ALLOWED" else 400
        return web.json_response(res, status=status_code)

    async def _http_hitl_pending_handler(self, request):
        from aiohttp import web

        res = await self.dispatch_action({"action": "LIST_PENDING_HITL"})
        return web.json_response(res, status=200)

    async def _http_options_cors_handler(self, request):
        from aiohttp import web

        return web.Response(
            status=204,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type, Authorization",
                "Access-Control-Max-Age": "86400",
            },
        )

    # -----------------------------------------------------------------------
    # Transparent LLM HTTP Reverse-Proxy Handlers
    # -----------------------------------------------------------------------
    async def _http_anthropic_proxy_handler(self, request: Any) -> Any:
        return await self._forward_llm_proxy(
            request, upstream_base="https://api.anthropic.com"
        )

    async def _http_openai_proxy_handler(self, request: Any) -> Any:
        return await self._forward_llm_proxy(
            request, upstream_base="https://api.openai.com"
        )

    async def _forward_llm_proxy(self, request: Any, upstream_base: str) -> Any:
        from aiohttp import web, ClientSession, ClientTimeout

        tail = request.match_info.get("tail", "")
        upstream_url = f"{upstream_base}/{tail}"
        if request.query_string:
            upstream_url = f"{upstream_url}?{request.query_string}"

        # Copy outbound headers (exclude hop-by-hop headers)
        headers = {}
        for k, v in request.headers.items():
            if k.lower() not in ("host", "content-length", "connection"):
                headers[k] = v

        method = request.method
        body = await request.read()

        # Tokenize candidate secrets in outbound JSON prompts before leaving the machine
        session_id = request.headers.get("X-AgentGuard-Session", "llm_client")
        if body:
            try:
                body_str = body.decode("utf-8")
                scrubbed_str, token_map = self.vault_engine.tokenize(body_str)
                if token_map:
                    self.audit_logger.log(
                        "LLM_PROXY_VAULT_TOKENIZED",
                        session_id=session_id,
                        status="VAULTED",
                        details={
                            "tokens_count": len(token_map),
                            "upstream": upstream_base,
                            "url": upstream_url,
                        },
                    )
                body = scrubbed_str.encode("utf-8")
            except UnicodeDecodeError:
                pass

        try:
            timeout = ClientTimeout(total=300)
            async with ClientSession(timeout=timeout) as client:
                async with client.request(
                    method, upstream_url, headers=headers, data=body
                ) as upstream_resp:
                    out_headers = {
                        k: v for k, v in upstream_resp.headers.items()
                        if k.lower() not in ("content-encoding", "transfer-encoding", "content-length", "connection")
                    }
                    response = web.StreamResponse(
                        status=upstream_resp.status,
                        headers=out_headers,
                    )
                    await response.prepare(request)
                    async for chunk in upstream_resp.content.iter_chunked(4096):
                        await response.write(chunk)
                    await response.write_eof()
                    return response
        except Exception as exc:
            return web.json_response(
                {"error": "AgentGuard LLM Proxy Error", "details": str(exc)},
                status=502,
            )

    # -----------------------------------------------------------------------
    # Pure asyncio HTTP Fallback Handler
    # -----------------------------------------------------------------------
    async def _handle_pure_http_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """
        Lightweight, zero-dependency HTTP server fallback.
        Handles GET /, GET /dashboard, GET /events (streaming), GET /health,
        GET /status, GET /audit, POST /api/agent/* and /api/hitl/* control routes.
        """
        try:
            line = await reader.readline()
            if not line:
                return

            req_line = line.decode("utf-8").strip()
            parts = req_line.split()
            if len(parts) < 2:
                return

            method = parts[0].upper()
            full_path = parts[1]
            parsed = urllib.parse.urlparse(full_path)
            path = parsed.path
            query = urllib.parse.parse_qs(parsed.query)

            # Parse incoming HTTP request headers
            headers: Dict[str, str] = {}
            while True:
                h_line = await reader.readline()
                if not h_line or h_line in (b"\r\n", b"\n"):
                    break
                h_str = h_line.decode("utf-8").strip()
                if ":" in h_str:
                    k, v = h_str.split(":", 1)
                    headers[k.strip().lower()] = v.strip()

            # Read request body if Content-Length specified
            content_length = 0
            if "content-length" in headers:
                try:
                    content_length = int(headers["content-length"])
                except ValueError:
                    content_length = 0

            body_bytes = b""
            if content_length > 0:
                body_bytes = await reader.readexactly(content_length)

            json_body: Dict[str, Any] = {}
            if body_bytes:
                try:
                    json_body = json.loads(body_bytes.decode("utf-8"))
                except Exception:
                    json_body = {}

            # Handle CORS preflight
            if method == "OPTIONS":
                resp_headers = (
                    "HTTP/1.1 204 No Content\r\n"
                    "Access-Control-Allow-Origin: *\r\n"
                    "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
                    "Access-Control-Allow-Headers: Content-Type, Authorization\r\n"
                    "Connection: close\r\n\r\n"
                )
                writer.write(resp_headers.encode("utf-8"))
                await writer.drain()
                return

            # Route: GET /events (Server-Sent Events)
            if path == "/events" and method == "GET":
                sse_headers = (
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/event-stream\r\n"
                    "Cache-Control: no-cache, no-transform\r\n"
                    "Connection: keep-alive\r\n"
                    "Access-Control-Allow-Origin: *\r\n"
                    "X-Accel-Buffering: no\r\n"
                    "\r\n"
                )
                writer.write(sse_headers.encode("utf-8"))
                await writer.drain()

                queue: asyncio.Queue = asyncio.Queue(maxsize=500)
                self._sse_subscribers.add(queue)

                try:
                    writer.write(b": connected\n\n")
                    await writer.drain()

                    while getattr(self, "_running", True):
                        try:
                            msg = await asyncio.wait_for(queue.get(), timeout=15.0)
                            if msg is None:
                                break
                            writer.write(msg.encode("utf-8"))
                            await writer.drain()
                        except asyncio.TimeoutError:
                            writer.write(b": ping\n\n")
                            await writer.drain()
                except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError, OSError, Exception):
                    pass
                finally:
                    self._sse_subscribers.discard(queue)
                return

            # Route: GET / or GET /dashboard
            if path in ("/", "/dashboard", "/index.html") and method == "GET":
                html_path = get_dashboard_html_path()
                if html_path.exists() and html_path.is_file():
                    try:
                        resp_body = html_path.read_text(encoding="utf-8")
                    except OSError:
                        resp_body = get_fallback_dashboard_html()
                else:
                    resp_body = get_fallback_dashboard_html()

                body_bytes_out = resp_body.encode("utf-8")
                resp = (
                    f"HTTP/1.1 200 OK\r\n"
                    f"Content-Type: text/html; charset=utf-8\r\n"
                    f"Content-Length: {len(body_bytes_out)}\r\n"
                    f"Cache-Control: no-cache\r\n"
                    f"Connection: close\r\n"
                    f"\r\n"
                ).encode("utf-8") + body_bytes_out
                writer.write(resp)
                await writer.drain()
                return

            # Route: GET /health
            if path == "/health" and method == "GET":
                res = {
                    "status": "healthy",
                    "uptime_seconds": int(time.time() - getattr(self, "_start_time", time.time())),
                    "pid": os.getpid(),
                }
                code = "200 OK"
            # Route: GET /status
            elif path == "/status" and method == "GET":
                res = await self.dispatch_action({"action": "GET_STATUS"})
                code = "200 OK"
            # Route: GET /audit
            elif path == "/audit" and method == "GET":
                limit = 20
                if "limit" in query:
                    try:
                        limit = int(query["limit"][0])
                    except (ValueError, IndexError):
                        limit = 20
                ev_type = None
                if "type" in query and query["type"]:
                    ev_type = query["type"][0]
                elif "event_type" in query and query["event_type"]:
                    ev_type = query["event_type"][0]

                payload = {"limit": limit}
                if ev_type:
                    payload["event_type"] = ev_type

                res = await self.dispatch_action({"action": "GET_AUDIT", "payload": payload})
                code = "200 OK"
            # Route: POST /api/agent/pause
            elif path == "/api/agent/pause" and method == "POST":
                res = await self.dispatch_action({
                    "action": "PAUSE_AGENT",
                    "session_id": json_body.get("session_id", ""),
                    "pid": json_body.get("pid", 0),
                    "payload": json_body,
                })
                code = "200 OK" if res.get("status") in ("PAUSED", "ALLOWED") else "400 Bad Request"
            # Route: POST /api/agent/resume
            elif path == "/api/agent/resume" and method == "POST":
                res = await self.dispatch_action({
                    "action": "RESUME_AGENT",
                    "session_id": json_body.get("session_id", ""),
                    "pid": json_body.get("pid", 0),
                    "payload": json_body,
                })
                code = "200 OK" if res.get("status") in ("RESUMED", "ALLOWED") else "400 Bad Request"
            # Route: POST /api/agent/terminate
            elif path == "/api/agent/terminate" and method == "POST":
                res = await self.dispatch_action({
                    "action": "TERMINATE_AGENT",
                    "session_id": json_body.get("session_id", ""),
                    "pid": json_body.get("pid", 0),
                    "payload": json_body,
                })
                code = "200 OK" if res.get("status") in ("TERMINATED", "ALLOWED") else "400 Bad Request"
            # Route: POST/GET /api/agent/inspect
            elif path == "/api/agent/inspect" and method in ("POST", "GET"):
                raw_payload = json_body if method == "POST" else query
                raw_pid = raw_payload.get("pid", 0)
                if isinstance(raw_pid, list) and raw_pid:
                    raw_pid = raw_pid[0]
                try:
                    pid_val = int(raw_pid)
                except (ValueError, TypeError):
                    pid_val = 0
                raw_sid = raw_payload.get("session_id", "")
                if isinstance(raw_sid, list) and raw_sid:
                    raw_sid = raw_sid[0]
                res = await self.dispatch_action({
                    "action": "INSPECT_AGENT",
                    "session_id": str(raw_sid).strip(),
                    "pid": pid_val,
                    "payload": raw_payload if isinstance(raw_payload, dict) else {},
                })
                code = "200 OK" if res.get("status") in ("ALLOWED", "OK", "HEALTHY") else "400 Bad Request"
            # Route: POST /api/hitl/decision
            elif path == "/api/hitl/decision" and method == "POST":
                res = await self.dispatch_action({
                    "action": "HITL_DECISION",
                    "payload": json_body,
                })
                code = "200 OK" if res.get("status") == "ALLOWED" else "400 Bad Request"
            # Route: GET /api/hitl/pending
            elif path == "/api/hitl/pending" and method == "GET":
                res = await self.dispatch_action({"action": "LIST_PENDING_HITL"})
                code = "200 OK"
            else:
                res = {"error": "Not Found", "path": path}
                code = "404 Not Found"

            out_data = json.dumps(res).encode("utf-8")
            resp_str = (
                f"HTTP/1.1 {code}\r\n"
                f"Content-Type: application/json; charset=utf-8\r\n"
                f"Content-Length: {len(out_data)}\r\n"
                f"Access-Control-Allow-Origin: *\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode("utf-8") + out_data

            writer.write(resp_str)
            await writer.drain()

        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass


def run_server(
    socket_path: str = DEFAULT_SOCKET_PATH,
    http_port: int = DEFAULT_HTTP_PORT,
    pid_file: str = DEFAULT_PID_FILE,
    audit_log_path: Optional[str] = None,
) -> None:
    """Run production asyncio AgentGuard daemon listening on UDS and HTTP."""
    audit_logger = AuditLogger(log_path=audit_log_path)
    taint_engine = TaintEngine(audit_logger=audit_logger)
    server = AgentGuardServer(
        socket_path=socket_path,
        http_port=http_port,
        pid_file=pid_file,
        audit_logger=audit_logger,
        taint_engine=taint_engine,
    )
    try:
        asyncio.run(server.serve_forever())
    except (KeyboardInterrupt, SystemExit):
        pass
