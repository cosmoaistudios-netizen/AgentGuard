"""
Challenger stress and adversarial tests for Milestone 2:
Core Security Daemon Server, Taint Engine DAG, and Audit Logger.
"""

import asyncio
import concurrent.futures
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest

from agentguard.daemon.audit import AuditLogger
from agentguard.daemon.server import AgentGuardServer
from agentguard.daemon.taint_engine import TaintEngine


class TestTaintGraphStressAndAdversarial(unittest.TestCase):
    """Adversarial stress testing on Taint Provenance DAG."""

    def setUp(self):
        self.engine = TaintEngine()

    def test_diamond_topology_transitive_taint(self):
        r"""
        Diamond topology:
               A
             /   \
            B     C
             \   /
               D
        """
        self.engine.register_session("A", taint="CLEAN")
        self.engine.register_session("B", taint="CLEAN")
        self.engine.register_session("C", taint="CLEAN")
        self.engine.register_session("D", taint="CLEAN")

        self.engine.data_handoff("A", "B")
        self.engine.data_handoff("A", "C")
        self.engine.data_handoff("B", "D")
        self.engine.data_handoff("C", "D")

        self.assertFalse(self.engine.is_tainted("D"))

        # Taint A
        self.engine.mark_tainted("A", reason="AdversarialPR")
        self.assertTrue(self.engine.is_tainted("A"))
        self.assertTrue(self.engine.is_tainted("B"))
        self.assertTrue(self.engine.is_tainted("C"))
        self.assertTrue(self.engine.is_tainted("D"))

    def test_dense_multipath_mesh(self):
        """10 nodes fully connected in forward cascade."""
        for i in range(10):
            self.engine.register_session(f"mesh_{i}", taint="CLEAN")
            for j in range(i):
                self.engine.data_handoff(f"mesh_{j}", f"mesh_{i}")

        self.assertFalse(self.engine.is_tainted("mesh_9"))
        self.engine.mark_tainted("mesh_0")

        for i in range(10):
            self.assertTrue(
                self.engine.is_tainted(f"mesh_{i}"),
                f"mesh_{i} should be tainted",
            )

    def test_polymorphic_id_resolution(self):
        """Verify polymorphic ID resolution across types."""
        self.assertEqual(self.engine._canonical_id(12345), "pid:12345")
        self.assertEqual(self.engine._canonical_id("sess_abc"), "sess_abc")
        self.assertTrue(
            self.engine._canonical_id("./local_file.txt").startswith("file:/")
        )
        self.assertTrue(
            self.engine._canonical_id("/etc/hosts").startswith("file:/")
        )

    def test_unregistered_node_auto_registration_on_edge(self):
        """Adding edge with unregistered IDs auto-creates session nodes."""
        self.engine.data_handoff("phantom_1", "phantom_2")
        self.assertIn("phantom_1", self.engine._nodes)
        self.assertIn("phantom_2", self.engine._nodes)
        self.assertFalse(self.engine.is_tainted("phantom_2"))

        self.engine.mark_tainted("phantom_1")
        self.assertTrue(self.engine.is_tainted("phantom_2"))


class TestDaemonSocketAdversarialStress(unittest.TestCase):
    """Stress tests on Unix Domain Socket server under adversarial inputs."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.sock_path = os.path.join(self.temp_dir.name, "ag_stress.sock")
        self.pid_path = os.path.join(self.temp_dir.name, "ag_stress.pid")
        self.audit_path = os.path.join(self.temp_dir.name, "audit.jsonl")
        self.http_port = 19445

        self.audit_logger = AuditLogger(log_path=self.audit_path)
        self.taint_engine = TaintEngine(audit_logger=self.audit_logger)
        self.server = AgentGuardServer(
            socket_path=self.sock_path,
            http_port=self.http_port,
            pid_file=self.pid_path,
            audit_logger=self.audit_logger,
            taint_engine=self.taint_engine,
        )

        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self._run_server, daemon=True)
        self.thread.start()

        deadline = time.time() + 3.0
        while time.time() < deadline:
            if os.path.exists(self.sock_path):
                break
            time.sleep(0.05)
        self.assertTrue(os.path.exists(self.sock_path))

    def _run_server(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self.server.serve_forever())

    def tearDown(self):
        self.server.request_shutdown()
        self.thread.join(timeout=2.0)
        self.temp_dir.cleanup()

    def _send_raw_socket(self, data: bytes) -> bytes:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(self.sock_path)
        s.sendall(data)
        res = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            res += chunk
            if b"\n" in res:
                break
        s.close()
        return res

    def test_malformed_json_returns_error_without_crash(self):
        raw_res = self._send_raw_socket(b"INVALID_NON_JSON_DATA\n")
        resp = json.loads(raw_res.decode("utf-8").strip())
        self.assertEqual(resp["status"], "ERROR")
        self.assertIn("Malformed request JSON", resp["message"])

    def test_missing_action_returns_error(self):
        raw_res = self._send_raw_socket(b'{"session_id": "test"}\n')
        resp = json.loads(raw_res.decode("utf-8").strip())
        self.assertEqual(resp["status"], "ERROR")
        self.assertIn("Missing or empty 'action'", resp["message"])

    def test_unknown_action_returns_error(self):
        raw_res = self._send_raw_socket(b'{"action": "NONEXISTENT_ACTION"}\n')
        resp = json.loads(raw_res.decode("utf-8").strip())
        self.assertEqual(resp["status"], "ERROR")
        self.assertIn("Unknown action", resp["message"])

    def test_rapid_concurrent_connections_burst(self):
        """Simulate 30 concurrent clients hitting UDS simultaneously."""
        def ping(idx: int):
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(self.sock_path)
            req = {
                "action": "GET_STATUS",
                "request_id": f"burst_{idx}",
            }
            s.sendall((json.dumps(req) + "\n").encode("utf-8"))
            buf = b""
            while b"\n" not in buf:
                chunk = s.recv(2048)
                if not chunk:
                    break
                buf += chunk
            s.close()
            return json.loads(buf.decode("utf-8").strip())

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
            futures = [ex.submit(ping, i) for i in range(30)]
            results = [
                f.result() for f in concurrent.futures.as_completed(futures)
            ]

        self.assertEqual(len(results), 30)
        for r in results:
            self.assertEqual(r["status"], "ALLOWED")
            self.assertEqual(r["data"]["health"], "healthy")


class TestAudioDirectiveCompliance(unittest.TestCase):
    """Enforce strict zero audio narration directives across codebase."""

    def test_no_say_or_afplay_in_source_or_tests(self):
        root = Path(__file__).resolve().parent.parent.parent
        prohibited = [
            b"say ",
            b"'say'",
            b'"say"',
            b"afplay",
        ]
        scanned = 0
        for p in root.rglob("*.py"):
            if any(skip in str(p) for skip in [".venv", ".git", ".agents", "__pycache__"]):
                continue
            scanned += 1
            if p.name.startswith("test_challenger_"):
                continue
            content = p.read_bytes()
            for pattern in prohibited:
                err_msg = (
                    f"Forbidden audio command found in {p}: "
                    f"{pattern.decode()}"
                )
                self.assertNotIn(pattern, content, err_msg)
        self.assertGreater(
            scanned, 10, "Should scan more than 10 source files"
        )


if __name__ == "__main__":
    unittest.main()
