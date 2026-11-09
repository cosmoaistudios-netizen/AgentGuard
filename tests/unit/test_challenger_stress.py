"""Adversarial challenge and stress tests for AgentGuard Milestone 1.

Authored by challenger_m1_1.
Tests extreme argument handling in ag wrap, daemon lifecycle resilience,
stale socket/PID handling, and offline fallback error paths.
"""

from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from click.testing import CliRunner

from agentguard.cli import (
    DaemonClient,
    cli,
    get_running_daemon_pid,
)


class TestWrapExtremeArguments(unittest.TestCase):
    """Stress tests for 'ag wrap' argument parsing and child execution."""

    def setUp(self):
        self.runner = CliRunner()

    def test_wrap_chained_flags(self):
        """Verify complex chained flags are forwarded to child process."""
        result = self.runner.invoke(
            cli,
            [
                "wrap",
                "--profile",
                "generic",
                "--",
                sys.executable,
                "-c",
                "import sys; print(' '.join(sys.argv[1:]))",
                "-a",
                "-b",
                "-c",
                "--foo=bar",
                "--baz",
                "qux",
                "-v",
                "--debug",
            ],
        )
        self.assertEqual(result.exit_code, 0)
        self.assertIn("-a -b -c --foo=bar --baz qux -v --debug", result.output)

    def test_wrap_unknown_options_forwarded_intact(self):
        """Verify arbitrary unknown flags for child agent pass through."""
        result = self.runner.invoke(
            cli,
            [
                "wrap",
                "--profile",
                "generic",
                "--",
                sys.executable,
                "-c",
                "import sys; print(sys.argv[1:])",
                "--agent-custom-opt=123",
                "-XYZ",
                "--deeply-nested-flag",
            ],
        )
        self.assertEqual(result.exit_code, 0)
        self.assertIn("--agent-custom-opt=123", result.output)
        self.assertIn("-XYZ", result.output)
        self.assertIn("--deeply-nested-flag", result.output)

    def test_wrap_quotes_and_nested_whitespace(self):
        """Verify arguments with spaces, nested quotes, and multiline chars."""
        args_to_test = [
            "argument with spaces",
            'quote"within"quote',
            "single'quote'within",
            "line1\nline2",
            "\t\ttabbed\t\t",
        ]
        result = self.runner.invoke(
            cli,
            [
                "wrap",
                "--profile",
                "generic",
                "--",
                sys.executable,
                "-c",
                "import sys, json; print(json.dumps(sys.argv[1:]))",
            ]
            + args_to_test,
        )
        self.assertEqual(result.exit_code, 0)
        output_lines = [
            ln for ln in result.output.strip().split("\n")
            if ln.startswith("[")
        ]
        self.assertTrue(output_lines, f"No JSON list found in {result.output}")
        parsed = json.loads(output_lines[0])
        self.assertEqual(parsed, args_to_test)

    def test_wrap_empty_string_arguments(self):
        """Verify empty string arguments are preserved in argv positions."""
        result = self.runner.invoke(
            cli,
            [
                "wrap",
                "--profile",
                "generic",
                "--",
                sys.executable,
                "-c",
                "import sys; print(len(sys.argv[1:]), list(sys.argv[1:]))",
                "first",
                "",
                "third",
                "",
                "fifth",
            ],
        )
        self.assertEqual(result.exit_code, 0)
        self.assertIn("5 ['first', '', 'third', '', 'fifth']", result.output)

    def test_wrap_subshell_and_pipes(self):
        """Verify shell scripts with subshells and pipes execute under wrap."""
        result = self.runner.invoke(
            cli,
            [
                "wrap",
                "--profile",
                "generic",
                "--",
                "sh",
                "-c",
                "echo $(echo subshell_result) | tr '[:lower:]' '[:upper:]'",
            ],
        )
        self.assertEqual(result.exit_code, 0)
        self.assertIn("SUBSHELL_RESULT", result.output)

    def test_wrap_empty_command_handled_without_crash(self):
        """Verify executing an empty binary string fails gracefully."""
        result = self.runner.invoke(
            cli,
            ["wrap", "--profile", "generic", "--", ""],
        )
        self.assertIn(result.exit_code, (126, 127))
        self.assertTrue(
            "Error:" in result.output or "denied" in result.output
        )

    def test_wrap_missing_command_click_error(self):
        """Verify wrap without command yields UsageError code 2."""
        result = self.runner.invoke(
            cli,
            ["wrap", "--profile", "generic"],
        )
        self.assertEqual(result.exit_code, 2)
        self.assertIn("Missing argument", result.output)

    def test_wrap_exit_code_propagation(self):
        """Verify non-zero exit codes from child process are forwarded."""
        for code in (42, 127, 3):
            result = self.runner.invoke(
                cli,
                [
                    "wrap",
                    "--profile",
                    "generic",
                    "--",
                    sys.executable,
                    "-c",
                    f"import sys; sys.exit({code})",
                ],
            )
            self.assertEqual(result.exit_code, code)

    def test_wrap_nonexistent_profile_handled_cleanly(self):
        """Verify invalid profile name prints error without traceback."""
        result = self.runner.invoke(
            cli,
            [
                "wrap",
                "--profile",
                "nonexistent_profile_adversarial_123",
                "--",
                "echo",
                "test",
            ],
        )
        self.assertEqual(result.exit_code, 1)
        self.assertIn(
            "Error: Profile 'nonexistent_profile_adversarial_123' not found.",
            result.output,
        )


class TestDaemonRobustnessAndLifecycle(unittest.TestCase):
    """Stress tests for daemon lifecycle, socket handling, and collisions."""

    def setUp(self):
        self.runner = CliRunner()
        ns = time.time_ns()
        self.test_socket = f"/tmp/ag_test_stress_{os.getpid()}_{ns}.sock"
        self.test_pid = f"/tmp/ag_test_stress_{os.getpid()}_{ns}.pid"

    def tearDown(self):
        client = DaemonClient(socket_path=self.test_socket)
        if client.is_running():
            try:
                client.send("SHUTDOWN")
            except Exception:
                pass
        pid = get_running_daemon_pid(self.test_pid)
        if pid:
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
        for p in (self.test_socket, self.test_pid):
            if os.path.exists(p):
                try:
                    os.unlink(p)
                except OSError:
                    pass

    def test_daemon_rapid_start_stop_cycles(self):
        """Perform 5 consecutive rapid start/stop cycles."""
        for cycle in range(5):
            res_start = self.runner.invoke(
                cli,
                [
                    "daemon",
                    "start",
                    "--socket",
                    self.test_socket,
                    "--pid-file",
                    self.test_pid,
                    "--http-port",
                    "19550",
                ],
            )
            self.assertEqual(
                res_start.exit_code,
                0,
                f"Failed start on cycle {cycle}: {res_start.output}",
            )
            self.assertIn("started successfully", res_start.output)

            res_stop = self.runner.invoke(
                cli,
                [
                    "daemon",
                    "stop",
                    "--socket",
                    self.test_socket,
                    "--pid-file",
                    self.test_pid,
                ],
            )
            self.assertEqual(
                res_stop.exit_code,
                0,
                f"Failed stop on cycle {cycle}: {res_stop.output}",
            )
            self.assertIn("stopped", res_stop.output)
            self.assertFalse(os.path.exists(self.test_socket))
            self.assertFalse(os.path.exists(self.test_pid))

    def test_daemon_stale_socket_cleanup(self):
        """Verify daemon start unlinks an abandoned stale socket file."""
        Path(self.test_socket).touch()
        self.assertTrue(os.path.exists(self.test_socket))

        res_start = self.runner.invoke(
            cli,
            [
                "daemon",
                "start",
                "--socket",
                self.test_socket,
                "--pid-file",
                self.test_pid,
                "--http-port",
                "19551",
            ],
        )
        self.assertEqual(res_start.exit_code, 0)
        self.assertIn("started successfully", res_start.output)

        client = DaemonClient(socket_path=self.test_socket)
        self.assertTrue(client.is_running())

        res_stop = self.runner.invoke(
            cli,
            [
                "daemon",
                "stop",
                "--socket",
                self.test_socket,
                "--pid-file",
                self.test_pid,
            ],
        )
        self.assertEqual(res_stop.exit_code, 0)

    def test_daemon_stale_pid_file_with_nonexistent_pid(self):
        """Verify daemon start cleans up a stale PID file with dead PID."""
        with open(self.test_pid, "w", encoding="utf-8") as f:
            f.write("99999999\n")

        res_start = self.runner.invoke(
            cli,
            [
                "daemon",
                "start",
                "--socket",
                self.test_socket,
                "--pid-file",
                self.test_pid,
                "--http-port",
                "19552",
            ],
        )
        self.assertEqual(res_start.exit_code, 0)
        self.assertIn("started successfully", res_start.output)

        res_stop = self.runner.invoke(
            cli,
            [
                "daemon",
                "stop",
                "--socket",
                self.test_socket,
                "--pid-file",
                self.test_pid,
            ],
        )
        self.assertEqual(res_stop.exit_code, 0)

    def test_daemon_pid_collision_behavior(self):
        """Active PID in pid_file makes daemon think it is alive."""
        # Spawn an unrelated background sleep process
        proc = subprocess.Popen(["sleep", "30"])
        try:
            with open(self.test_pid, "w", encoding="utf-8") as f:
                f.write(str(proc.pid))

            res_start = self.runner.invoke(
                cli,
                [
                    "daemon",
                    "start",
                    "--socket",
                    self.test_socket,
                    "--pid-file",
                    self.test_pid,
                ],
            )
            # Daemon refuses to start because PID exists
            self.assertEqual(res_start.exit_code, 0)
            self.assertIn("already running", res_start.output)
        finally:
            proc.terminate()
            proc.wait()


class TestOfflineErrorHandling(unittest.TestCase):
    """Stress tests for offline fallbacks and error degradation."""

    def setUp(self):
        self.runner = CliRunner()
        ns = time.time_ns()
        self.test_socket = f"/tmp/ag_test_offline_{os.getpid()}_{ns}.sock"

    def tearDown(self):
        if os.path.exists(self.test_socket):
            try:
                os.unlink(self.test_socket)
            except OSError:
                pass

    def test_status_when_daemon_stopped_text(self):
        """Verify ag status text mode cleanly reports STOPPED."""
        res = self.runner.invoke(cli, ["status", "--socket", self.test_socket])
        self.assertEqual(res.exit_code, 0)
        self.assertIn("Status: STOPPED", res.output)
        self.assertIn("not reachable", res.output)

    def test_status_when_daemon_stopped_json(self):
        """Verify ag status --json reports structured JSON when offline."""
        res = self.runner.invoke(
            cli, ["status", "--socket", self.test_socket, "--json"]
        )
        self.assertEqual(res.exit_code, 0)
        data = json.loads(res.output)
        self.assertEqual(data.get("status"), "STOPPED")
        self.assertEqual(data.get("error"), "daemon_not_running")
        self.assertEqual(data.get("active_agents"), 0)

    def test_status_unresponsive_socket_timeout_handled(self):
        """Verify ag status does not hang when socket does not reply."""
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(self.test_socket)
        srv.listen(1)
        srv.settimeout(0.5)

        try:
            start_t = time.time()
            res = self.runner.invoke(
                cli, ["status", "--socket", self.test_socket, "--json"]
            )
            duration = time.time() - start_t
            self.assertLess(duration, 4.0, "ag status hung beyond timeout")
            self.assertEqual(res.exit_code, 0)
            data = json.loads(res.output)
            self.assertEqual(data.get("status"), "STOPPED")
        finally:
            srv.close()

    def test_audit_offline_empty_log(self):
        """Verify ag audit with no socket and no log file reports empty."""
        with tempfile.NamedTemporaryFile() as tmp:
            tmp_path = tmp.name
        res_text = self.runner.invoke(
            cli,
            ["audit", "--socket", self.test_socket, "--file", tmp_path],
        )
        self.assertEqual(res_text.exit_code, 0)
        self.assertIn("No audit events recorded yet", res_text.output)

        res_json = self.runner.invoke(
            cli,
            [
                "audit",
                "--socket",
                self.test_socket,
                "--file",
                tmp_path,
                "--format",
                "json",
            ],
        )
        self.assertEqual(res_json.exit_code, 0)
        self.assertEqual(json.loads(res_json.output), [])

    def test_audit_corrupted_jsonl_gracefully_skipped(self):
        """Verify ag audit skips malformed JSON lines in local audit file."""
        ev1 = {
            "timestamp": "2026-10-27T08:00:00Z",
            "event_type": "TEST_EV1",
            "session_id": "s1",
            "status": "ALLOWED",
            "details": "ok",
        }
        ev2 = {
            "timestamp": "2026-10-27T08:01:00Z",
            "event_type": "TEST_EV2",
            "session_id": "s2",
            "status": "BLOCKED",
            "details": "bad",
        }
        with tempfile.NamedTemporaryFile(
            "w", delete=False, suffix=".jsonl"
        ) as tmp:
            tmp.write(json.dumps(ev1) + "\n")
            tmp.write("GARBAGE NOT JSON LINE {[[[\n")
            tmp.write(json.dumps(ev2) + "\n")
            tmp_path = tmp.name

        try:
            res_json = self.runner.invoke(
                cli,
                [
                    "audit",
                    "--socket",
                    self.test_socket,
                    "--file",
                    tmp_path,
                    "--format",
                    "json",
                ],
            )
            self.assertEqual(res_json.exit_code, 0)
            parsed = json.loads(res_json.output)
            self.assertEqual(len(parsed), 2)
            self.assertEqual(parsed[0]["event_type"], "TEST_EV1")
            self.assertEqual(parsed[1]["event_type"], "TEST_EV2")
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)


if __name__ == "__main__":
    unittest.main()
