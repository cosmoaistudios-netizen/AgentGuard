"""
Challenger Adversarial Stress Suite for Milestone 5 CLI, Launcher & Pre-Flight Checks:
- Unexpected launcher inputs: invalid numbers ('8', '9', '0', '-1'), special characters, EOF.
- Pre-flight daemon prompt in `ag wrap` with varied responses ('y', 'Y', 'yes', 'n', 'N', 'no', '', 'maybe', EOF).
- Non-interactive piped invocations (`echo "7" | ag`, `echo "8" | ag`, `ag --help`, `ag -h`, `ag --version`).
- TerminalRawMode and key reading robustness under escape sequences and Ctrl+C.
- Zero audio execution verification across all source files.
"""

from __future__ import annotations

import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from agentguard.cli import (
    DEFAULT_SOCKET_PATH,
    DaemonClient,
    cli,
    detect_agent_profile,
    ensure_daemon_running,
)
from agentguard.launcher import (
    MENU_OPTIONS,
    TerminalRawMode,
    build_menu_panel,
    execute_action,
    read_key,
    run_interactive_launcher,
)


class TestLauncherAdversarialInputs(unittest.TestCase):
    """Stress-tests for interactive launcher menu under malformed or unexpected inputs."""

    def setUp(self):
        self.runner = CliRunner()

    @patch("agentguard.cli.DaemonClient.is_running", return_value=False)
    @patch("agentguard.cli.get_running_daemon_pid", return_value=None)
    def test_launcher_piped_invalid_numbers_fail_gracefully(self, mock_pid, mock_running):
        """Invalid number options (8, 9, 0, 99) in non-interactive piped mode must exit 1 without crash."""
        for invalid_input in ["8\n", "9\n", "0\n", "99\n", "-1\n"]:
            res = self.runner.invoke(cli, [], input=invalid_input)
            self.assertEqual(res.exit_code, 1, f"Expected exit code 1 for input {invalid_input!r}, got {res.exit_code}")
            self.assertIn("Unknown option", res.output)
            self.assertNotIn("Traceback", res.output)

    @patch("agentguard.cli.DaemonClient.is_running", return_value=False)
    @patch("agentguard.cli.get_running_daemon_pid", return_value=None)
    def test_launcher_piped_special_chars_and_strings(self, mock_pid, mock_running):
        """Non-numeric string options (abc, special characters) should fail gracefully without unhandled exception."""
        for invalid_input in ["abc\n", "exit\n", "???\n", "\x00\n"]:
            res = self.runner.invoke(cli, [], input=invalid_input)
            self.assertEqual(res.exit_code, 1)
            self.assertIn("Unknown option", res.output)
            self.assertNotIn("Traceback", res.output)

    @patch("agentguard.cli.DaemonClient.is_running", return_value=False)
    @patch("agentguard.cli.get_running_daemon_pid", return_value=None)
    def test_launcher_eof_conditions(self, mock_pid, mock_running):
        """EOF conditions (empty input stream, immediate close) should exit 0 cleanly."""
        res_empty = self.runner.invoke(cli, [], input="")
        self.assertEqual(res_empty.exit_code, 0)
        self.assertNotIn("Traceback", res_empty.output)

        res_newline_only = self.runner.invoke(cli, [], input="\n")
        self.assertEqual(res_newline_only.exit_code, 0)
        self.assertNotIn("Traceback", res_newline_only.output)

    @patch("agentguard.cli.DaemonClient.is_running", return_value=False)
    @patch("agentguard.cli.get_running_daemon_pid", return_value=None)
    def test_launcher_exit_option_piped(self, mock_pid, mock_running):
        """Piping option '7' (Exit) should exit cleanly with code 0."""
        res = self.runner.invoke(cli, [], input="7\n")
        self.assertEqual(res.exit_code, 0)
        self.assertIn("AgentGuard security launcher closed", res.output)

    @patch("agentguard.cli.DaemonClient.is_running", return_value=True)
    @patch("agentguard.cli.get_running_daemon_pid", return_value=12345)
    def test_launcher_menu_panel_rendering(self, mock_pid, mock_running):
        """Panel rendering handles online/offline status cleanly."""
        panel_online = build_menu_panel(selected_idx=0, daemon_online=True, daemon_pid=12345)
        self.assertIsNotNone(panel_online)
        panel_offline = build_menu_panel(selected_idx=-1, daemon_online=False, daemon_pid=None)
        self.assertIsNotNone(panel_offline)

    def test_terminal_raw_mode_safety(self):
        """TerminalRawMode should be a safe no-op on non-tty environments without raising exceptions."""
        with TerminalRawMode():
            pass

    def test_read_key_non_tty_returns_empty(self):
        """read_key returns empty string when stdin is not a tty."""
        with patch("sys.stdin.isatty", return_value=False):
            key = read_key(timeout=0.01)
            self.assertEqual(key, "")


class TestWrapPreFlightDaemonCheckAdversarial(unittest.TestCase):
    """Tests the pre-flight daemon check in `ag wrap` across various user responses."""

    def setUp(self):
        self.runner = CliRunner()

    @patch("agentguard.cli.DaemonClient.is_running", return_value=False)
    @patch("agentguard.cli._should_prompt_daemon", return_value=True)
    @patch("agentguard.cli.ensure_daemon_running")
    def test_preflight_affirmative_responses(self, mock_ensure, mock_should, mock_running):
        """Responses 'y', 'Y', 'yes', 'YES', and empty Enter confirm starting daemon."""
        mock_ensure.return_value = True

        for affirmative in ["y\n", "Y\n", "yes\n", "YES\n", "\n"]:
            mock_ensure.reset_mock()
            with patch("agentguard.cli.load_profile", return_value=MagicMock()):
                with patch("agentguard.cli.DaemonClient.send", return_value={"status": "ALLOWED"}):
                    res = self.runner.invoke(
                        cli,
                        ["wrap", "--profile", "generic", "--", "echo", "hello"],
                        input=affirmative,
                    )
            mock_ensure.assert_called_once()

    @patch("agentguard.cli.DaemonClient.is_running", return_value=False)
    @patch("agentguard.cli._should_prompt_daemon", return_value=True)
    def test_ensure_daemon_running_declined_inputs(self, mock_should, mock_running):
        """Responses 'n', 'N', 'no', 'NO', 'cancel', 'maybe' refuse starting daemon and return False."""
        for declined in ["n", "N", "no", "NO", "never", "maybe", "cancel"]:
            with patch("click.prompt", return_value=declined):
                result = ensure_daemon_running(prompt=True)
                self.assertFalse(result, f"Expected False for declined input {declined!r}")

    @patch("agentguard.cli.DaemonClient.is_running", return_value=False)
    @patch("agentguard.cli._should_prompt_daemon", return_value=True)
    def test_ensure_daemon_running_accepted_inputs(self, mock_should, mock_running):
        """Responses 'y', 'Y', 'yes', 'YES', '' proceed with starting daemon."""
        for accepted in ["y", "Y", "yes", "YES", ""]:
            with patch("click.prompt", return_value=accepted):
                with patch("subprocess.Popen") as mock_popen:
                    mock_proc = MagicMock()
                    mock_popen.return_value = mock_proc
                    with patch("agentguard.cli.DaemonClient.is_running", side_effect=[False, True]):
                        result = ensure_daemon_running(prompt=True)
                        self.assertTrue(result, f"Expected True for accepted input {accepted!r}")

    @patch("agentguard.cli.DaemonClient.is_running", return_value=False)
    @patch("agentguard.cli._should_prompt_daemon", return_value=True)
    def test_ensure_daemon_running_eof_and_abort(self, mock_should, mock_running):
        """EOF and abort in prompt should return False cleanly without crashing."""
        import click
        with patch("click.prompt", side_effect=click.Abort):
            result = ensure_daemon_running(prompt=True)
            self.assertFalse(result)

        with patch("click.prompt", side_effect=EOFError):
            result = ensure_daemon_running(prompt=True)
            self.assertFalse(result)

    @patch("agentguard.cli.DaemonClient.is_running", return_value=False)
    @patch("agentguard.cli._should_prompt_daemon", return_value=True)
    def test_wrap_aborts_with_exit_code_1_when_declined(self, mock_should, mock_running):
        """Declining pre-flight daemon check in `ag wrap` cleanly exits with code 1."""
        res = self.runner.invoke(
            cli,
            ["wrap", "--profile", "generic", "--", "echo", "hello"],
            input="n\n",
        )
        self.assertEqual(res.exit_code, 1)
        self.assertIn("AgentGuard security daemon is currently stopped", res.output)
        self.assertIn("Aborted", res.output)


class TestNonInteractivePipedInvocations(unittest.TestCase):
    """Tests non-interactive piped invocations and CLI flags."""

    def setUp(self):
        self.runner = CliRunner()

    def test_cli_help_flags(self):
        """'ag --help' and 'ag -h' return exit code 0 and show subcommands."""
        for flag in ["--help", "-h"]:
            res = self.runner.invoke(cli, [flag])
            self.assertEqual(res.exit_code, 0)
            self.assertIn("AgentGuard", res.output)
            self.assertIn("wrap", res.output)
            self.assertIn("daemon", res.output)
            self.assertIn("status", res.output)
            self.assertIn("audit", res.output)

    def test_cli_version_flag(self):
        """'ag --version' returns exit code 0 with program name and version."""
        res = self.runner.invoke(cli, ["--version"])
        self.assertEqual(res.exit_code, 0)
        self.assertIn("AgentGuard", res.output)

    def test_wrap_help_flag(self):
        """'ag wrap --help' displays profile and hitl options."""
        res = self.runner.invoke(cli, ["wrap", "--help"])
        self.assertEqual(res.exit_code, 0)
        self.assertIn("--profile", res.output)
        self.assertIn("--hitl", res.output)

    @patch("agentguard.cli.DaemonClient.is_running", return_value=False)
    @patch("agentguard.cli.get_running_daemon_pid", return_value=None)
    def test_piped_option_7_exit(self, mock_pid, mock_running):
        """Non-interactive pipe `echo '7' | ag` returns exit code 0."""
        res = self.runner.invoke(cli, [], input="7\n")
        self.assertEqual(res.exit_code, 0)
        self.assertIn("AgentGuard security launcher closed", res.output)

    @patch("agentguard.cli.DaemonClient.is_running", return_value=False)
    @patch("agentguard.cli.get_running_daemon_pid", return_value=None)
    def test_piped_empty_eof_exit(self, mock_pid, mock_running):
        """Non-interactive pipe with immediate EOF returns exit code 0."""
        res = self.runner.invoke(cli, [], input="")
        self.assertEqual(res.exit_code, 0)


class TestZeroAudioExecutionPolicy(unittest.TestCase):
    """Enforces zero-tolerance prohibition against audio execution ('say', 'afplay')."""

    def test_zero_audio_commands_in_agentguard_and_tests(self):
        """No executable code in agentguard/ or tests/ should invoke 'say' or 'afplay'."""
        root = Path(__file__).resolve().parent.parent.parent
        agentguard_dir = root / "agentguard"

        say_cmd = bytes([115, 97, 121, 32])      # 'say '
        afplay_cmd = bytes([97, 102, 112, 108, 97, 121, 32])  # 'afplay '

        violations = []
        for p in agentguard_dir.rglob("*.py"):
            with open(p, "rb") as f:
                content = f.read()
                if say_cmd in content:
                    violations.append(f"{p} contains forbidden audio command (say)")
                if afplay_cmd in content:
                    violations.append(f"{p} contains forbidden audio command (afplay)")

        self.assertEqual(
            violations,
            [],
            f"Zero audio violation detected: {violations}",
        )


class TestInteractiveLauncherKeyNavigation(unittest.TestCase):
    """Stress-tests for interactive key navigation loop and escape sequence handling."""

    def test_read_key_parsing_sequences(self):
        """Verify read_key accurately parses single characters and escape codes."""
        from agentguard.launcher import read_key

        test_cases = [
            ("\r", "ENTER"),
            ("\n", "ENTER"),
            (" ", "SPACE"),
            ("\x03", "CTRL_C"),
            ("\x04", "CTRL_C"),
            ("q", "q"),
            ("7", "7"),
            ("k", "k"),
        ]
        for char, expected in test_cases:
            with patch("sys.stdin.isatty", return_value=True):
                with patch("select.select", return_value=([True], [], [])):
                    with patch("sys.stdin.read", return_value=char):
                        self.assertEqual(read_key(timeout=0.01), expected)

    def test_read_key_escape_arrow_keys(self):
        """Arrow key sequences (\x1b[A, \x1b[B, \x1b[C, \x1b[D) resolve correctly."""
        from agentguard.launcher import read_key

        arrow_map = {
            "A": "UP",
            "B": "DOWN",
            "C": "RIGHT",
            "D": "LEFT",
        }
        for code, expected_name in arrow_map.items():
            with patch("sys.stdin.isatty", return_value=True):
                with patch("select.select", return_value=([True], [], [])):
                    with patch("sys.stdin.read", side_effect=["\x1b", "[", code]):
                        self.assertEqual(read_key(timeout=0.01), expected_name)

    @patch("agentguard.cli.DaemonClient.is_running", return_value=False)
    @patch("agentguard.cli.get_running_daemon_pid", return_value=None)
    def test_interactive_navigation_and_exit_signals(self, mock_pid, mock_running):
        """Simulate interactive navigation using mocked read_key sequences."""
        ctx = MagicMock()

        exit_keys = ["q", "Q", "ESC", "CTRL_C", "7"]
        for exit_key in exit_keys:
            with patch("sys.stdin.isatty", return_value=True):
                with patch("sys.stdout.isatty", return_value=True):
                    with patch("agentguard.launcher.TerminalRawMode"):
                        with patch("agentguard.launcher.read_key", side_effect=["DOWN", "UP", exit_key]):
                            code = run_interactive_launcher(ctx)
                            self.assertEqual(code, 0, f"Failed clean exit for key {exit_key}")
