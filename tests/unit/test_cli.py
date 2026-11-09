"""
tests/unit/test_cli.py - Unit test suite for AgentGuard Click CLI & Config.

Uses Click's CliRunner and unittest.TestCase for dual-runner execution
(pytest + unittest).
"""

import json
import os
import tempfile
import unittest

from click.testing import CliRunner

from agentguard.cli import cli
from agentguard.config import (
    AgentProfile,
    list_available_profiles,
    load_profile,
)


class TestCLIBasics(unittest.TestCase):
    """Validates top-level CLI entrypoints, flags, and command discovery."""

    def setUp(self):
        self.runner = CliRunner()

    def test_ag_help(self):
        result = self.runner.invoke(cli, ["--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("AgentGuard", result.output)
        self.assertIn("daemon", result.output)
        self.assertIn("wrap", result.output)
        self.assertIn("status", result.output)
        self.assertIn("audit", result.output)

    def test_version_flag(self):
        result = self.runner.invoke(cli, ["--version"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("0.1.0", result.output)


class TestDaemonCommands(unittest.TestCase):
    """Validates `ag daemon` subcommand hierarchy and options."""

    def setUp(self):
        self.runner = CliRunner()

    def test_daemon_help(self):
        result = self.runner.invoke(cli, ["daemon", "--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("start", result.output)
        self.assertIn("stop", result.output)

    def test_daemon_start_help(self):
        result = self.runner.invoke(cli, ["daemon", "start", "--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("--socket", result.output)
        self.assertIn("--http-port", result.output)
        self.assertIn("--foreground", result.output)

    def test_daemon_stop_help(self):
        result = self.runner.invoke(cli, ["daemon", "stop", "--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("--socket", result.output)

    def test_daemon_stop_when_not_running(self):
        sock = "/tmp/nonexistent_socket_test.sock"
        result = self.runner.invoke(cli, ["daemon", "stop", "--socket", sock])
        self.assertEqual(result.exit_code, 0)
        out = result.output.lower()
        self.assertTrue("not running" in out or "stopped" in out)


class TestStatusAndAuditCommands(unittest.TestCase):
    """Validates `ag status` and `ag audit` output and fallbacks."""

    def setUp(self):
        self.runner = CliRunner()

    def test_status_help(self):
        result = self.runner.invoke(cli, ["status", "--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("--json", result.output)

    def test_status_daemon_stopped_text(self):
        sock = "/tmp/nonexistent_socket_test.sock"
        result = self.runner.invoke(cli, ["status", "--socket", sock])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("STOPPED", result.output.upper())

    def test_status_daemon_stopped_json(self):
        sock = "/tmp/nonexistent_socket_test.sock"
        result = self.runner.invoke(
            cli, ["status", "--json", "--socket", sock]
        )
        self.assertEqual(result.exit_code, 0)
        data = json.loads(result.output)
        self.assertEqual(data["status"], "STOPPED")
        self.assertEqual(data["active_agents"], 0)

    def test_audit_help(self):
        result = self.runner.invoke(cli, ["audit", "--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("--limit", result.output)
        self.assertIn("--format", result.output)

    def test_audit_empty_text(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_log = os.path.join(tmpdir, "empty_audit.jsonl")
            result = self.runner.invoke(
                cli, ["audit", "--log-path", fake_log]
            )
            self.assertEqual(result.exit_code, 0)
            self.assertIn("No audit events", result.output)

    def test_audit_empty_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_log = os.path.join(tmpdir, "empty_audit.jsonl")
            result = self.runner.invoke(
                cli, ["audit", "--format", "json", "--log-path", fake_log]
            )
            self.assertEqual(result.exit_code, 0)
            data = json.loads(result.output)
            self.assertEqual(data, [])

    def test_audit_reads_mock_jsonl(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_log = os.path.join(tmpdir, "audit.jsonl")
            events = [
                {
                    "timestamp": "2026-10-27T08:00:00Z",
                    "event_type": "SESSION_REGISTERED",
                    "session_id": "s1",
                },
                {
                    "timestamp": "2026-10-27T08:01:00Z",
                    "event_type": "COMMAND_BLOCKED",
                    "session_id": "s1",
                    "command": "rm -rf /",
                },
            ]
            with open(fake_log, "w", encoding="utf-8") as f:
                for event in events:
                    f.write(json.dumps(event) + "\n")

            result = self.runner.invoke(
                cli,
                [
                    "audit",
                    "--limit",
                    "1",
                    "--format",
                    "json",
                    "--log-path",
                    fake_log,
                ],
            )
            self.assertEqual(result.exit_code, 0)
            parsed = json.loads(result.output)
            self.assertEqual(len(parsed), 1)
            self.assertEqual(parsed[0]["event_type"], "COMMAND_BLOCKED")


class TestWrapCommand(unittest.TestCase):
    """Validates `ag wrap` execution, argument handling, and env injection."""

    def setUp(self):
        self.runner = CliRunner()

    def test_wrap_help(self):
        result = self.runner.invoke(cli, ["wrap", "--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("--profile", result.output)
        self.assertIn("--hitl", result.output)

    def test_wrap_missing_profile(self):
        result = self.runner.invoke(
            cli,
            ["wrap", "--profile", "nonexistent_xyz", "--", "echo", "test"],
        )
        self.assertNotEqual(result.exit_code, 0)
        out = result.output.lower()
        self.assertTrue("not found" in out or "error" in out)

    def test_wrap_missing_command(self):
        result = self.runner.invoke(cli, ["wrap", "--profile", "generic"])
        self.assertNotEqual(result.exit_code, 0)
        self.assertTrue("missing" in result.output.lower())

    def test_wrap_passthrough_execution(self):
        result = self.runner.invoke(
            cli,
            ["wrap", "--profile", "generic", "--", "echo", "PASSTHROUGH_OK"],
        )
        self.assertEqual(result.exit_code, 0)
        self.assertIn("PASSTHROUGH_OK", result.output)

    def test_wrap_session_env_injection(self):
        py_cmd = (
            "import os; print('ENV_SESSION=' + "
            "os.environ.get('AGENTGUARD_SESSION_ID', 'MISSING'))"
        )
        cmd = [
            "wrap",
            "--profile",
            "generic",
            "--",
            "python3",
            "-c",
            py_cmd,
        ]
        result = self.runner.invoke(cli, cmd)
        self.assertEqual(result.exit_code, 0)
        self.assertIn("ENV_SESSION=", result.output)
        self.assertNotIn("MISSING", result.output)

    def test_wrap_hitl_flag_injection(self):
        py_cmd = (
            "import os; print('ENV_HITL=' + "
            "os.environ.get('AGENTGUARD_HITL', '0'))"
        )
        cmd = [
            "wrap",
            "--profile",
            "generic",
            "--hitl",
            "--",
            "python3",
            "-c",
            py_cmd,
        ]
        result = self.runner.invoke(cli, cmd)
        self.assertEqual(result.exit_code, 0)
        self.assertIn("ENV_HITL=1", result.output)


class TestConfigAndProfiles(unittest.TestCase):
    """Validates Pydantic schema validation, profile loading, and discovery."""

    def test_load_builtin_profiles(self):
        for profile_name in ["claude-code", "hermes", "generic"]:
            prof = load_profile(profile_name)
            self.assertIsInstance(prof, AgentProfile)
            self.assertEqual(prof.name, profile_name)
            self.assertTrue(len(prof.shell.safe_commands) > 0)
            self.assertTrue(len(prof.shell.dangerous_patterns) > 0)
            self.assertGreaterEqual(prof.vault.entropy_threshold, 4.0)

    def test_load_custom_yaml_path(self):
        with tempfile.NamedTemporaryFile(
            "w", suffix=".yaml", delete=False
        ) as f:
            f.write(
                "name: custom-unit-test\n"
                "description: Custom test profile\n"
                "shell:\n"
                "  safe_commands:\n"
                "    - uname\n"
                "vault:\n"
                "  entropy_threshold: 4.8\n"
            )
            custom_path = f.name

        try:
            prof = load_profile(custom_path)
            self.assertEqual(prof.name, "custom-unit-test")
            self.assertIn("uname", prof.shell.safe_commands)
            self.assertEqual(prof.vault.entropy_threshold, 4.8)
        finally:
            if os.path.exists(custom_path):
                os.remove(custom_path)

    def test_load_nonexistent_profile_raises(self):
        with self.assertRaises(FileNotFoundError):
            load_profile("definitely_non_existent_profile_99999")

    def test_list_available_profiles(self):
        profiles = list_available_profiles()
        self.assertIn("claude-code", profiles)
        self.assertIn("hermes", profiles)
        self.assertIn("generic", profiles)

    def test_pydantic_validation_error(self):
        with tempfile.NamedTemporaryFile(
            "w", suffix=".yaml", delete=False
        ) as f:
            f.write(
                "name: invalid-profile\n"
                "vault:\n"
                "  entropy_threshold: 'NOT_A_NUMBER'\n"
            )
            invalid_path = f.name

        try:
            with self.assertRaises(ValueError):
                load_profile(invalid_path)
        finally:
            if os.path.exists(invalid_path):
                os.remove(invalid_path)


class TestDaemonLifecycle(unittest.TestCase):
    """Validates daemon start, status, client IPC, and graceful stop."""

    def setUp(self):
        self.runner = CliRunner()
        self.tmpdir = tempfile.TemporaryDirectory()
        self.socket_path = os.path.join(
            self.tmpdir.name, "test_agentguard.sock"
        )
        self.pid_file = os.path.join(
            self.tmpdir.name, "test_agentguard.pid"
        )

    def tearDown(self):
        self.runner.invoke(
            cli,
            [
                "daemon",
                "stop",
                "--socket",
                self.socket_path,
                "--pid-file",
                self.pid_file,
            ],
        )
        self.tmpdir.cleanup()

    def test_daemon_lifecycle(self):
        # 1. Start daemon in detached mode
        start_res = self.runner.invoke(
            cli,
            [
                "daemon",
                "start",
                "--socket",
                self.socket_path,
                "--pid-file",
                self.pid_file,
                "--http-port",
                "18499",
            ],
        )
        self.assertEqual(start_res.exit_code, 0)
        self.assertIn("started successfully", start_res.output)

        # 2. Check status via CLI
        status_res = self.runner.invoke(
            cli,
            ["status", "--socket", self.socket_path],
        )
        self.assertEqual(status_res.exit_code, 0)
        self.assertIn("ACTIVE", status_res.output)

        # 3. Check status as JSON
        status_json_res = self.runner.invoke(
            cli,
            ["status", "--json", "--socket", self.socket_path],
        )
        self.assertEqual(status_json_res.exit_code, 0)
        status_data = json.loads(status_json_res.output)
        self.assertEqual(status_data["status"], "healthy")
        self.assertEqual(status_data["active_agents"], 0)

        # 4. Wrap a command with the active daemon
        wrap_res = self.runner.invoke(
            cli,
            [
                "wrap",
                "--profile",
                "generic",
                "--socket",
                self.socket_path,
                "--",
                "echo",
                "HELLO_FROM_WRAPPED",
            ],
        )
        self.assertEqual(wrap_res.exit_code, 0)
        self.assertIn("HELLO_FROM_WRAPPED", wrap_res.output)

        # 5. Check audit records the registration
        audit_res = self.runner.invoke(
            cli,
            ["audit", "--socket", self.socket_path, "--format", "json"],
        )
        self.assertEqual(audit_res.exit_code, 0)
        events = json.loads(audit_res.output)
        self.assertTrue(len(events) >= 1)
        self.assertEqual(events[0]["event_type"], "REGISTER_AGENT")

        # 6. Stop the daemon
        stop_res = self.runner.invoke(
            cli,
            [
                "daemon",
                "stop",
                "--socket",
                self.socket_path,
                "--pid-file",
                self.pid_file,
            ],
        )
        self.assertEqual(stop_res.exit_code, 0)
        self.assertIn("stopped", stop_res.output.lower())


if __name__ == "__main__":
    unittest.main()
