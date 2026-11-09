"""Unit tests for AgentGuard Terminal Cockpit TUI (ag cockpit).

Verifies offline widget rendering, dynamic taint radiation meters, flight-path
intent drift gauges, live audited telemetry feeds, emergency kill-switch state
machine (SIGSTOP/SIGCONT/SIGKILL/Inspect), HITL decision hotkeys, CLI lifecycle
prompts, and zero-tolerance audio command compliance.
"""

from __future__ import annotations

import io
import os
import sys
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner
from rich.console import Console

from agentguard.cli import cli, ensure_daemon_running
from agentguard.cockpit.app import CockpitApp, TerminalRawMode
from agentguard.cockpit.client import CockpitClient
from agentguard.cockpit.drift_meter import (
    IntentDriftGaugeWidget,
    format_drift_gauge,
    render_intent_drift,
)
from agentguard.cockpit.kill_switch import (
    KillSwitchController,
    KillSwitchMode,
    render_hitl_prompt,
    render_inspect_modal,
    render_kill_switch_modal,
)
from agentguard.cockpit.radar import (
    SwarmRadarWidget,
    format_taint_meter,
    format_uptime,
    render_swarm_radar,
)
from agentguard.cockpit.telemetry_feed import (
    TelemetryFeedWidget,
    format_event_badge,
    format_event_summary,
    render_telemetry_feed,
)


def render_to_text(renderable: Any, width: int = 120, height: int = 35) -> str:
    """Render a Rich renderable object to plain text buffer without real TTY."""
    buf = io.StringIO()
    console = Console(file=buf, width=width, height=height, force_terminal=True, color_system=None)
    console.print(renderable)
    return buf.getvalue()


# ===========================================================================
# 1. Swarm Radar & Taint Radiation Meter Tests
# ===========================================================================


class TestRadarAndTaintRadiation:
    """Tests for SwarmRadarWidget and format_taint_meter."""

    def test_taint_meter_clean(self):
        """Clean state renders 0% with empty blocks and CLEAN label."""
        meter = format_taint_meter("CLEAN")
        text = meter.plain
        assert "0%" in text
        assert "░░░░░░░░░░" in text
        assert "CLEAN" in text

    def test_taint_meter_tainted(self):
        """Tainted state renders 100% with full blocks and TAINTED ☢ label."""
        meter = format_taint_meter("TAINTED")
        text = meter.plain
        assert "100%" in text
        assert "██████████" in text
        assert "TAINTED" in text
        assert "☢" in text

    def test_taint_meter_gradual_scores(self):
        """Progressive float scores render appropriate radiation levels."""
        # 20% elevated
        m_elevated = format_taint_meter("CLEAN", score=0.20)
        assert "20%" in m_elevated.plain
        assert "ELEVATED" in m_elevated.plain

        # 60% warning
        m_warn = format_taint_meter("CLEAN", score=0.60)
        assert "60%" in m_warn.plain
        assert "WARNING" in m_warn.plain

        # 90% radioactive
        m_rad = format_taint_meter("CLEAN", score=0.90)
        assert "90%" in m_rad.plain
        assert "TAINTED" in m_rad.plain

    def test_format_uptime(self):
        """Format uptime into human-readable strings."""
        assert format_uptime(25) == "25s"
        assert format_uptime(125) == "02m 05s"
        assert format_uptime(3665) == "01h 01m"
        assert format_uptime(None) == "--"

    def test_swarm_radar_empty(self):
        """Empty radar renders placeholder message."""
        panel = render_swarm_radar({})
        output = render_to_text(panel)
        assert "Swarm Radar" in output
        assert "No active agent sessions detected" in output

    def test_swarm_radar_with_active_sessions(self):
        """Active agent sessions render in table columns with status and meters."""
        sessions = {
            "ag-sess-001": {
                "pid": 12345,
                "profile": "claude-code",
                "process_status": "RUNNING",
                "uptime_seconds": 150,
                "current_tool": "read_file",
                "taint": "CLEAN",
                "taint_score": 0.0,
            },
            "ag-sess-002": {
                "pid": 23456,
                "profile": "hermes",
                "process_status": "PAUSED",
                "uptime_seconds": 300,
                "current_tool": "curl http://test",
                "taint": "TAINTED",
                "taint_score": 1.0,
            },
        }
        panel = render_swarm_radar(sessions)
        output = render_to_text(panel)

        assert "12345" in output
        assert "claude-code" in output
        assert "RUNNING" in output
        assert "read_file" in output
        assert "CLEAN" in output

        assert "23456" in output
        assert "hermes" in output
        assert "PAUSED" in output
        assert "curl http://test" in output
        assert "TAINTED" in output


# ===========================================================================
# 2. Flight-Path Intent Drift Meter Tests
# ===========================================================================


class TestIntentDriftMeter:
    """Tests for IntentDriftGaugeWidget and cosine similarity formatting."""

    def test_drift_gauge_safe(self):
        """Similarity >= 0.65 indicates SAFE flight path."""
        gauge = format_drift_gauge(0.85, threshold=0.65)
        text = gauge.plain
        assert "0.85" in text
        assert "SAFE" in text
        assert "Target ≥ 0.65" in text

    def test_drift_gauge_warning(self):
        """Similarity < 0.65 indicates DRIFT WARNING."""
        gauge = format_drift_gauge(0.35, threshold=0.65)
        text = gauge.plain
        assert "0.35" in text
        assert "DRIFT WARNING" in text
        assert "< 0.65" in text

    def test_drift_gauge_none(self):
        """None similarity displays awaiting state."""
        gauge = format_drift_gauge(None)
        text = gauge.plain
        assert "AWAITING SUB-ACTIONS" in text

    def test_intent_drift_panel_safe(self):
        """Safe panel displays nominal flight path message and metadata."""
        panel = render_intent_drift(
            similarity=0.88,
            pid=9999,
            profile="openclaw",
            root_intent="Analyze security logs",
            last_action="grep -i error /var/log/syslog",
        )
        output = render_to_text(panel)
        assert "Flight-Path Intent Drift Meter" in output
        assert "PID 9999" in output
        assert "openclaw" in output
        assert "Analyze security logs" in output
        assert "FLIGHT PATH NOMINAL" in output
        assert "0.88" in output

    def test_intent_drift_panel_warning(self):
        """Warning panel displays divergent tool action warning."""
        panel = render_intent_drift(
            similarity=0.22,
            pid=8888,
            profile="hermes",
            root_intent="Refactor code",
            last_action="cat /etc/passwd",
        )
        output = render_to_text(panel)
        assert "DRIFT WARNING" in output
        assert "UNEXPECTED TRAJECTORY" in output
        assert "cat /etc/passwd" in output


# ===========================================================================
# 3. Live Audited Telemetry Feed Tests
# ===========================================================================


class TestTelemetryFeed:
    """Tests for TelemetryFeedWidget and event badge formatting."""

    def test_event_badges(self):
        """Verify badges for PASS, BLOCKED, VAULTED, SANITIZED, TAINTED."""
        assert "[BLOCKED]" in format_event_badge("COMMAND_BLOCKED")
        assert "[PASS]" in format_event_badge("COMMAND_ALLOWED")
        assert "[VAULTED]" in format_event_badge("TOKENIZE_VAULT")
        assert "[SANITIZED]" in format_event_badge("FILE_SANITIZED")
        assert "[TAINTED]" in format_event_badge("PROPAGATE_TAINT")
        assert "[HITL]" in format_event_badge("HITL_PROMPT")
        assert "[PAUSED]" in format_event_badge("AGENT_PAUSED")
        assert "[RESUMED]" in format_event_badge("AGENT_RESUMED")
        assert "[KILLED]" in format_event_badge("AGENT_TERMINATED")

    def test_event_summary_formatting(self):
        """Summary extracts commands, files, tokens, and reasons."""
        assert "rm -rf /" in format_event_summary({"command": "rm -rf /", "reason": "Dangerous"})
        assert "file: /tmp/secret.md" in format_event_summary({"path": "/tmp/secret.md"})
        assert "3 secret(s) shielded" in format_event_summary({"count": 3})

    def test_telemetry_feed_empty(self):
        """Empty feed displays waiting placeholder."""
        panel = render_telemetry_feed([])
        output = render_to_text(panel)
        assert "Live Audited Telemetry Feed" in output
        assert "Waiting for telemetry events" in output

    def test_telemetry_feed_with_events(self):
        """Feed renders events with timestamps, badges, and session IDs."""
        events = [
            {
                "event_id": "ev-01",
                "timestamp": "2026-10-27T14:40:00Z",
                "event_type": "COMMAND_ALLOWED",
                "session_id": "sess-alpha",
                "details": {"command": "ls -la"},
            },
            {
                "event_id": "ev-02",
                "timestamp": "2026-10-27T14:40:05Z",
                "event_type": "COMMAND_BLOCKED",
                "session_id": "sess-beta",
                "details": {"command": "rm -rf /", "reason": "Root deletion blocked"},
            },
            {
                "event_id": "ev-03",
                "timestamp": "2026-10-27T14:40:10Z",
                "event_type": "TOKENIZE_VAULT",
                "session_id": "sess-gamma",
                "details": {"count": 2},
            },
        ]
        panel = render_telemetry_feed(events)
        output = render_to_text(panel)

        assert "[PASS]" in output
        assert "sess-alpha" in output
        assert "ls -la" in output

        assert "[BLOCKED]" in output
        assert "sess-beta" in output
        assert "rm -rf /" in output

        assert "[VAULTED]" in output
        assert "sess-gamma" in output
        assert "2 secret(s) shielded" in output

    def test_telemetry_feed_deduplication(self):
        """Deduplication prevents duplicate events from polluting feed."""
        feed = TelemetryFeedWidget(max_events=10)
        ev = {"event_id": "dup-1", "event_type": "COMMAND_ALLOWED", "details": {"command": "pwd"}}
        assert feed.add_event(ev) is True
        assert feed.add_event(ev) is False
        assert len(feed._events) == 1


# ===========================================================================
# 4. Emergency Kill-Switch & HITL Controller Tests
# ===========================================================================


class TestKillSwitchController:
    """Tests for KillSwitchController state machine and keybindings."""

    def test_kill_switch_k_single_session_pauses(self):
        """Pressing K with one active session immediately pauses process tree."""
        mock_client = MagicMock()
        controller = KillSwitchController(client=mock_client)

        sessions = {"sess-1": {"pid": 4321, "profile": "claude-code"}}
        controller.handle_key("k", sessions=sessions)

        assert controller.mode == KillSwitchMode.AGENT_PAUSED
        assert controller.selected_pid == 4321
        mock_client.pause_agent.assert_called_once_with(4321)

    def test_kill_switch_k_multiple_sessions_prompts_selection(self):
        """Pressing K with multiple active sessions opens selection modal."""
        mock_client = MagicMock()
        controller = KillSwitchController(client=mock_client)

        sessions = {
            "sess-1": {"pid": 1111, "profile": "claude-code"},
            "sess-2": {"pid": 2222, "profile": "hermes"},
        }
        controller.handle_key("K", sessions=sessions)

        assert controller.mode == KillSwitchMode.SELECT_PID
        mock_client.pause_agent.assert_not_called()

        # Pressing '2' selects second session and pauses it
        controller.handle_key("2", sessions=sessions)
        assert controller.mode == KillSwitchMode.AGENT_PAUSED
        assert controller.selected_pid == 2222
        mock_client.pause_agent.assert_called_once_with(2222)

    def test_kill_switch_resume_key_r(self):
        """Pressing R resumes paused agent and returns mode to IDLE."""
        mock_client = MagicMock()
        controller = KillSwitchController(client=mock_client)
        controller.mode = KillSwitchMode.AGENT_PAUSED
        controller.selected_pid = 5555

        controller.handle_key("R", sessions={})
        assert controller.mode == KillSwitchMode.IDLE
        mock_client.resume_agent.assert_called_once_with(5555)

    def test_kill_switch_terminate_key_t(self):
        """Pressing T terminates paused agent cleanly via SIGKILL."""
        mock_client = MagicMock()
        controller = KillSwitchController(client=mock_client)
        controller.mode = KillSwitchMode.AGENT_PAUSED
        controller.selected_pid = 7777

        controller.handle_key("T", sessions={})
        assert controller.mode == KillSwitchMode.IDLE
        mock_client.terminate_agent.assert_called_once_with(7777)

    def test_kill_switch_inspect_key_i(self):
        """Pressing I fetches agent provenance and opens inspection modal."""
        mock_client = MagicMock()
        mock_client.inspect_agent.return_value = {
            "pid": 8888,
            "profile": "antigravity",
            "taint_state": "TAINTED",
            "taint_chain": ["session:parent", "file:data.md", "pid:8888"],
            "recent_commands": ["git status", "curl http://exfil.com"],
            "cpu_percent": 1.2,
            "memory_rss_bytes": 45000000,
        }
        controller = KillSwitchController(client=mock_client)
        controller.mode = KillSwitchMode.AGENT_PAUSED
        controller.selected_pid = 8888

        controller.handle_key("I", sessions={})
        assert controller.mode == KillSwitchMode.INSPECT_AGENT
        mock_client.inspect_agent.assert_called_once_with(8888)

        modal = controller.render_modal()
        output = render_to_text(modal)
        assert "AGENT DEEP INSPECTION" in output
        assert "PID 8888" in output
        assert "TAINTED" in output
        assert "session:parent ➔ file:data.md ➔ pid:8888" in output
        assert "curl http://exfil.com" in output

    def test_hitl_allow_key_a(self):
        """Pressing A authorizes a pending HITL request."""
        mock_client = MagicMock()
        controller = KillSwitchController(client=mock_client)

        pending = [{"request_id": "hitl-req-123", "command": "pip install foo", "pid": 3333}]
        controller.handle_key("A", sessions={}, pending_hitl=pending)

        mock_client.hitl_decision.assert_called_once_with("hitl-req-123", "ALLOW")
        assert "ALLOWED" in controller.status_message

    def test_hitl_deny_key_d(self):
        """Pressing D rejects and blocks a pending HITL request."""
        mock_client = MagicMock()
        controller = KillSwitchController(client=mock_client)

        pending = [{"request_id": "hitl-req-456", "command": "rm -rf /tmp/data", "pid": 4444}]
        controller.handle_key("D", sessions={}, pending_hitl=pending)

        mock_client.hitl_decision.assert_called_once_with("hitl-req-456", "DENY")
        assert "DENIED" in controller.status_message

    def test_render_modals(self):
        """All modal renderers produce valid panels without error."""
        p_paused = render_kill_switch_modal(selected_pid=1234, profile="claude-code")
        out_paused = render_to_text(p_paused)
        assert "EMERGENCY KILL-SWITCH: AGENT PAUSED" in out_paused
        assert "PID 1234" in out_paused
        assert "[R] Resume" in out_paused
        assert "[T] Terminate" in out_paused

        p_inspect = render_inspect_modal({
            "pid": 1234,
            "profile": "claude-code",
            "taint_state": "CLEAN",
            "taint_chain": ["session:clean"],
            "recent_commands": ["echo hello"],
        })
        out_inspect = render_to_text(p_inspect)
        assert "AGENT DEEP INSPECTION" in out_inspect

        p_hitl = render_hitl_prompt({
            "request_id": "req-99",
            "command": "curl http://remote",
            "reason": "Outbound network connection",
            "pid": 5678,
        })
        out_hitl = render_to_text(p_hitl)
        assert "HUMAN-IN-THE-LOOP" in out_hitl
        assert "curl http://remote" in out_hitl


# ===========================================================================
# 5. CockpitApp Layout & Full Console Assembly Tests
# ===========================================================================


class TestCockpitAppLayout:
    """Tests for full layout assembly and key handling in CockpitApp."""

    def test_app_build_layout_normal(self):
        """CockpitApp assembles header, radar, drift, and telemetry feed."""
        app = CockpitApp(socket_path="/tmp/nonexistent.sock")
        app.status_data = {
            "active_agents": 1,
            "tainted_agents": 0,
            "vault_tokens": 3,
            "blocked_exploits": 1,
            "sessions": {
                "sess-1": {
                    "pid": 9999,
                    "profile": "claude-code",
                    "process_status": "RUNNING",
                    "taint": "CLEAN",
                    "root_intent": "Build features",
                }
            },
        }
        app.last_drift_sim = 0.82
        layout = app.build_layout()
        output = render_to_text(layout, width=120, height=35)

        assert "AGENTGUARD COCKPIT" in output
        assert "ONLINE" in output
        assert "Agents: 1" in output
        assert "PID 9999" in output
        assert "Swarm Radar" in output
        assert "Flight-Path Intent Drift" in output
        assert "Telemetry Feed" in output
        assert "[K] Kill-Switch" in output

    def test_app_build_layout_with_modal(self):
        """When modal is active, modal replaces lower panel."""
        app = CockpitApp(socket_path="/tmp/nonexistent.sock")
        app.kill_switch.mode = KillSwitchMode.AGENT_PAUSED
        app.kill_switch.selected_pid = 7777
        app.kill_switch.selected_profile = "hermes"

        layout = app.build_layout()
        output = render_to_text(layout, width=120, height=35)

        assert "EMERGENCY KILL-SWITCH: AGENT PAUSED" in output
        assert "PID 7777" in output
        assert "[R] Resume" in output

    def test_app_quit_keys(self):
        """Pressing q or Q sets is_running to False."""
        app = CockpitApp()
        app.is_running = True
        app.handle_key("q")
        assert app.is_running is False

        app.is_running = True
        app.handle_key("Q")
        assert app.is_running is False


# ===========================================================================
# 6. CockpitClient Unit Tests
# ===========================================================================


class TestCockpitClient:
    """Tests for CockpitClient IPC handling."""

    def test_client_is_running_false_on_missing_sock(self, tmp_path):
        """Client reports is_running() == False when socket file does not exist."""
        fake_sock = str(tmp_path / "missing.sock")
        client = CockpitClient(socket_path=fake_sock)
        assert client.is_running() is False

    def test_client_pause_resume_terminate_payloads(self):
        """Client properly dispatches PAUSE, RESUME, TERMINATE payloads."""
        client = CockpitClient(socket_path="/tmp/test.sock")
        with patch.object(client, "send") as mock_send:
            mock_send.return_value = {"status": "PAUSED", "data": {}}

            client.pause_agent(1234)
            mock_send.assert_called_with("PAUSE_AGENT", payload={"pid": 1234})

            client.resume_agent(1234)
            mock_send.assert_called_with("RESUME_AGENT", payload={"pid": 1234})

            client.terminate_agent(1234, timeout=3.0)
            mock_send.assert_called_with("TERMINATE_AGENT", payload={"timeout": 3.0, "pid": 1234})

            client.inspect_agent(1234)
            mock_send.assert_called_with("INSPECT_AGENT", payload={"pid": 1234})

            client.hitl_decision("req-1", "ALLOW")
            mock_send.assert_called_with("HITL_DECISION", payload={"request_id": "req-1", "decision": "ALLOW"})


# ===========================================================================
# 7. CLI Command & Daemon Pre-Flight Tests
# ===========================================================================


class TestCockpitCLI:
    """Tests for ag cockpit command and ensure_daemon_running prompt."""

    def test_cockpit_help(self):
        """ag cockpit --help displays command options."""
        runner = CliRunner()
        result = runner.invoke(cli, ["cockpit", "--help"])
        assert result.exit_code == 0
        assert "--socket" in result.output
        assert "--url" in result.output
        assert "--refresh-interval" in result.output

    def test_cockpit_daemon_stopped_declined_prompt(self, tmp_path):
        """When daemon is stopped and user declines prompt, cockpit aborts cleanly."""
        fake_sock = str(tmp_path / "fake.sock")
        runner = CliRunner()
        result = runner.invoke(cli, ["cockpit", "--socket", fake_sock], input="n\n")

        assert "AgentGuard security daemon is currently stopped." in result.output
        assert "Start daemon now? [Y/n]" in result.output
        assert "Aborted" in result.output
        assert result.exit_code != 0

    def test_ensure_daemon_running_already_active(self):
        """ensure_daemon_running returns True immediately if daemon is active."""
        with patch("agentguard.cli.DaemonClient.is_running", return_value=True):
            assert ensure_daemon_running(socket_path="/tmp/fake.sock", prompt=False) is True


# ===========================================================================
# 8. Strict Zero-Tolerance Audio Compliance Test
# ===========================================================================


class TestAudioDirectiveCompliance:
    """Verifies strict zero-tolerance prohibition against macOS audio commands."""

    def test_zero_audio_commands_in_cockpit(self):
        """Scans agentguard/cockpit/ to guarantee zero execution of audio commands."""
        cockpit_dir = Path(__file__).resolve().parent.parent.parent / "agentguard" / "cockpit"
        assert cockpit_dir.exists(), f"Cockpit directory {cockpit_dir} does not exist"

        forbidden_patterns = [
            bytes([115, 97, 121, 32]),
            bytes([97, 102, 112, 108, 97, 121, 32]),
        ]
        violations = []

        for py_file in cockpit_dir.rglob("*.py"):
            content = py_file.read_bytes()
            for pattern in forbidden_patterns:
                if pattern in content:
                    violations.append(f"{py_file.name} contains {pattern.decode()}")

        assert not violations, f"Forbidden audio commands found in cockpit: {violations}"


# ===========================================================================
# 9. Adversarial Stress & Robustness Hardening Tests
# ===========================================================================


class TestCockpitAdversarialHardening:
    """15 adversarial stress tests verifying resilience against malformed inputs and markup injections."""

    def test_adversarial_extreme_taint_scores(self):
        """Verify negative, overflow, and float edge cases in format_taint_meter."""
        m_neg = format_taint_meter("CLEAN", score=-100.0)
        assert "0%" in m_neg.plain
        assert "CLEAN" in m_neg.plain

        m_pos = format_taint_meter("CLEAN", score=999.0)
        assert "100%" in m_pos.plain
        assert "TAINTED" in m_pos.plain

        m_none_clean = format_taint_meter("clean", score=None)
        assert "0%" in m_none_clean.plain

        m_none_tainted = format_taint_meter("tAiNtEd", score=None)
        assert "100%" in m_none_tainted.plain

        m_zero_w = format_taint_meter("CLEAN", score=0.5, width=0)
        assert "50%" in m_zero_w.plain

    def test_adversarial_format_uptime_nan_and_inf(self):
        """Verify uptime formatting resilience against NaN, Inf, and non-numerics."""
        assert format_uptime(None) == "--"
        assert format_uptime(-1) == "--"
        assert format_uptime(0) == "00s"
        assert format_uptime(59.9) == "59s"
        assert format_uptime(3600) == "01h 00m"

        # Boundary: NaN and Inf must return '--' without raising ValueError or OverflowError
        assert format_uptime(float("nan")) == "--"
        assert format_uptime(float("inf")) == "--"
        assert format_uptime(float("-inf")) == "--"

    def test_adversarial_radar_table_string_pid(self):
        """Radar table should handle string or non-integer PIDs without crashing."""
        sessions = {
            "sess-str-pid": {
                "pid": "12345",
                "profile": "claude-code",
                "process_status": "RUNNING",
            }
        }
        panel = render_swarm_radar(sessions)
        out = render_to_text(panel)
        assert "12345" in out

    def test_adversarial_radar_table_markup_injection(self):
        """Untrusted commands with Rich markup closing tags should not crash radar rendering."""
        sessions = {
            "sess-markup": {
                "pid": 5432,
                "profile": "custom",
                "current_tool": "echo [/bold][/yellow][red]",
            }
        }
        panel = render_swarm_radar(sessions)
        out = render_to_text(panel)
        assert "5432" in out

    def test_adversarial_drift_gauge_extreme_values(self):
        """Test similarity bounds clipping for negative and overflow values."""
        g_neg = format_drift_gauge(-10.0)
        assert "0.00" in g_neg.plain
        assert "DRIFT WARNING" in g_neg.plain

        g_pos = format_drift_gauge(10.0)
        assert "1.00" in g_pos.plain
        assert "SAFE" in g_pos.plain

    def test_adversarial_intent_drift_markup_injection(self):
        """Rich markup tags in user intent or intercepted action must not crash drift panel."""
        malicious_action = "sed -i 's/[/bold]//g' /etc/hosts"
        malicious_intent = "Execute [/italic white] objective"
        panel = render_intent_drift(
            similarity=0.75,
            pid=9999,
            profile="generic",
            root_intent=malicious_intent,
            last_action=malicious_action,
        )
        out = render_to_text(panel)
        assert "Flight-Path" in out

    def test_adversarial_telemetry_epoch_timestamp(self):
        """Integer epoch timestamp should not crash telemetry feed rendering."""
        feed = TelemetryFeedWidget()
        feed.add_event({
            "event_id": "ev-epoch",
            "timestamp": 1730040000,
            "event_type": "COMMAND_ALLOWED",
            "details": {"command": "git pull"},
        })
        panel = feed.render()
        out = render_to_text(panel)
        assert "COMMAND_ALLOWED" in out

    def test_adversarial_telemetry_markup_injection(self):
        """Untrusted commands with Rich markup in details must not crash telemetry feed."""
        feed = TelemetryFeedWidget()
        feed.add_event({
            "event_id": "ev-injection",
            "timestamp": "2026-10-27T15:00:00Z",
            "event_type": "COMMAND_BLOCKED",
            "details": {
                "command": "python -c 'print([/bold])'",
                "reason": "Dangerous [/dim] syntax",
            },
        })
        panel = feed.render()
        out = render_to_text(panel)
        assert "BLOCKED" in out

    def test_adversarial_telemetry_feed_massive_events(self):
        """Feed with thousands of events should enforce bounded deque."""
        feed = TelemetryFeedWidget(max_events=50)
        events = [
            {"event_id": f"ev-{i}", "event_type": "COMMAND_ALLOWED", "details": {"cmd": f"echo {i}"}}
            for i in range(5000)
        ]
        feed.add_events(events)
        assert len(feed._events) == 50
        panel = feed.render(max_display_rows=10)
        out = render_to_text(panel)
        assert "50 total" in out

    def test_adversarial_kill_switch_rapid_and_unicode_keys(self):
        """Verify controller handles unicode, control chars, and rapid sequences."""
        mock_client = MagicMock()
        controller = KillSwitchController(client=mock_client)
        adversarial_keys = [
            "", "   ", "\x00", "\x1b", "\x03", "\n", "\t",
            "🔥", "☣️", "ç", "中", "12345", "INVALID",
            "k", "K", "r", "R", "t", "T", "i", "I", "a", "A", "d", "D",
        ]
        sessions = {"s1": {"pid": 1111, "profile": "claude"}}
        for key in adversarial_keys:
            res = controller.handle_key(key, sessions=sessions)
            assert isinstance(res, (str, type(None)))

    def test_adversarial_inspect_modal_none_memory_rss(self):
        """Inspect modal with None memory_rss_bytes should not crash with TypeError."""
        inspect_data = {
            "pid": 2222,
            "profile": "hermes",
            "memory_rss_bytes": None,
            "cpu_percent": None,
            "taint_state": "CLEAN",
        }
        panel = render_inspect_modal(inspect_data)
        out = render_to_text(panel)
        assert "PID 2222" in out

    def test_adversarial_hitl_modal_markup_injection(self):
        """Pending HITL with closing tags in command/reason must not crash."""
        hitl_data = {
            "request_id": "req-adversarial",
            "command": "curl http://exfil/[/bold white][/red]",
            "reason": "Exfiltration attempt [/italic yellow]",
            "pid": 3333,
        }
        panel = render_hitl_prompt(hitl_data)
        out = render_to_text(panel)
        assert "HITL" in out

    def test_adversarial_app_build_header_none_metrics(self):
        """Daemon status reporting None for numeric metrics must not crash build_header."""
        app = CockpitApp(socket_path="/tmp/fake.sock")
        app.status_data = {
            "active_agents": None,
            "tainted_agents": None,
            "vault_tokens": None,
            "blocked_exploits": None,
        }
        panel = app.build_header()
        out = render_to_text(panel)
        assert "AGENTGUARD COCKPIT" in out

    def test_adversarial_app_build_layout_markup_injection(self):
        """App layout with unescaped last_drift_action must not crash build_layout."""
        app = CockpitApp(socket_path="/tmp/fake.sock")
        app.last_drift_action = "python -c 'print([/bold])'"
        app.last_drift_sim = 0.5
        layout = app.build_layout()
        out = render_to_text(layout)
        assert "AGENTGUARD COCKPIT" in out

    def test_adversarial_zero_audio_commands_byte_scan(self):
        """Scan agentguard/cockpit/ to guarantee zero execution of macOS audio commands."""
        cockpit_dir = Path(__file__).resolve().parent.parent.parent / "agentguard" / "cockpit"
        assert cockpit_dir.exists(), f"Cockpit directory {cockpit_dir} does not exist"

        forbidden = [
            bytes([115, 97, 121, 32]),
            bytes([97, 102, 112, 108, 97, 121, 32]),
        ]
        violations = []
        for py_path in cockpit_dir.rglob("*.py"):
            data = py_path.read_bytes()
            for f in forbidden:
                if f in data:
                    violations.append(f"{py_path.name}: contains {f.decode()}")

        assert violations == [], f"Forbidden audio commands found: {violations}"

    def test_kill_switch_idle_inspect_key_i_single_session(self):
        """Pressing [I] in IDLE mode directly opens inspection modal for single agent."""
        mock_client = MagicMock()
        mock_client.inspect_agent.return_value = {
            "pid": 5555,
            "profile": "antigravity",
            "taint_state": "CLEAN",
            "taint_chain": ["session:s1"],
            "recent_commands": ["git status"],
        }
        controller = KillSwitchController(client=mock_client)
        sessions = {"s1": {"pid": 5555, "profile": "antigravity"}}
        msg = controller.handle_key("I", sessions=sessions)
        assert controller.mode == KillSwitchMode.INSPECT_AGENT
        assert controller.selected_pid == 5555
        assert "Inspecting agent PID 5555" in (msg or "")

        # ESC exits back to IDLE
        msg2 = controller.handle_key("\x1b", sessions=sessions)
        assert controller.mode == KillSwitchMode.IDLE

    def test_kill_switch_idle_inspect_commands_mode(self):
        """Pressing [C] or Enter in IDLE mode opens command inspector and allows drilling down."""
        controller = KillSwitchController()
        controller.recent_events = [
            {
                "event_id": "ev-1",
                "timestamp": 1700000000.0,
                "event_type": "COMMAND_BLOCKED",
                "status": "BLOCKED",
                "pid": 1234,
                "session_id": "sess-alpha",
                "details": {
                    "command": "rm -rf /tmp/agentguard_test_dir",
                    "reason": "Destructive deletion blocked by zero-trust baseline",
                },
            }
        ]
        controller.handle_key("C", sessions={})
        assert controller.mode == KillSwitchMode.INSPECT_COMMANDS

        panel = controller.render_modal()
        out = render_to_text(panel)
        assert "AUDITED COMMANDS & TELEMETRY INSPECTOR" in out
        assert "rm -rf" in out

        # Press [1] to view detail
        controller.handle_key("1", sessions={})
        panel_detail = controller.render_modal()
        out_detail = render_to_text(panel_detail)
        assert "COMMAND DETAIL #1" in out_detail
        assert "rm -rf /tmp/agentguard_test_dir" in out_detail
        assert "Destructive deletion blocked" in out_detail

        # ESC goes back to list then IDLE
        controller.handle_key("\x1b", sessions={})
        assert controller.selected_event_idx is None
        assert controller.mode == KillSwitchMode.INSPECT_COMMANDS
        controller.handle_key("\x1b", sessions={})
        assert controller.mode == KillSwitchMode.IDLE

    def test_kill_switch_help_modal(self):
        """Pressing [?] or [H] opens Help modal and ESC returns to IDLE."""
        controller = KillSwitchController()
        controller.handle_key("?", sessions={})
        assert controller.mode == KillSwitchMode.HELP
        panel = controller.render_modal()
        out = render_to_text(panel)
        assert "COCKPIT OPERATOR HELP" in out
        assert "Emergency Pause" in out
        assert "Deep Inspect Agent" in out

        controller.handle_key("\x1b", sessions={})
        assert controller.mode == KillSwitchMode.IDLE

