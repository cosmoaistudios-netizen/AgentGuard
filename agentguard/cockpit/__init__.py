"""AgentGuard Cockpit: Standalone Terminal Monitoring & Control Console.

Provides full-screen TUI monitoring of active agent swarms, dynamic taint radiation meters,
flight-path intent drift detection, live audited telemetry logs, and emergency kill-switch
process control (SIGSTOP/SIGCONT/SIGKILL) with Human-In-The-Loop confirmation.
"""

from __future__ import annotations

from agentguard.cockpit.app import CockpitApp, run_cockpit
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
    render_swarm_radar,
)
from agentguard.cockpit.telemetry_feed import (
    TelemetryFeedWidget,
    format_event_badge,
    render_telemetry_feed,
)

__all__ = [
    "CockpitApp",
    "run_cockpit",
    "CockpitClient",
    "SwarmRadarWidget",
    "format_taint_meter",
    "render_swarm_radar",
    "IntentDriftGaugeWidget",
    "format_drift_gauge",
    "render_intent_drift",
    "TelemetryFeedWidget",
    "format_event_badge",
    "render_telemetry_feed",
    "KillSwitchController",
    "KillSwitchMode",
    "render_kill_switch_modal",
    "render_inspect_modal",
    "render_hitl_prompt",
]
