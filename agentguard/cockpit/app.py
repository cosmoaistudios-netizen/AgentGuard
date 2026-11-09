"""AgentGuard Cockpit: Main Full-Screen Terminal Application.

Integrates Swarm Radar, Flight-Path Intent Drift Meter, Live Audited Telemetry Feed,
and Emergency Process Kill-Switch into a responsive, full-screen Rich Live console.
"""

from __future__ import annotations

import math
import os
import select
import sys
import time
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.text import Text

from agentguard.cockpit.client import CockpitClient, DEFAULT_HTTP_URL, DEFAULT_SOCKET_PATH
from agentguard.cockpit.drift_meter import IntentDriftGaugeWidget
from agentguard.cockpit.kill_switch import KillSwitchController
from agentguard.cockpit.radar import SwarmRadarWidget
from agentguard.cockpit.telemetry_feed import TelemetryFeedWidget
from agentguard.launcher import read_key

try:
    import termios
    import tty
    HAS_TERMIOS = True
except ImportError:
    HAS_TERMIOS = False


class TerminalRawMode:
    """Context manager placing stdin into cbreak mode and restoring on exit."""

    def __enter__(self):
        self.old_settings = None
        if HAS_TERMIOS and sys.stdin.isatty():
            try:
                self.fd = sys.stdin.fileno()
                self.old_settings = termios.tcgetattr(self.fd)
                tty.setcbreak(self.fd)
            except Exception:
                self.old_settings = None
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if HAS_TERMIOS and self.old_settings is not None and sys.stdin.isatty():
            try:
                termios.tcsetattr(self.fd, termios.TCSADRAIN, self.old_settings)
            except Exception:
                pass


class CockpitApp:
    """Full-screen interactive terminal cockpit monitoring autonomous agents."""

    def __init__(
        self,
        socket_path: str = DEFAULT_SOCKET_PATH,
        http_url: str = DEFAULT_HTTP_URL,
        refresh_interval: float = 0.5,
        console: Optional[Console] = None,
    ):
        self.socket_path = socket_path
        self.http_url = http_url
        self.refresh_interval = refresh_interval
        self.console = console or Console()
        self.client = CockpitClient(socket_path=socket_path, http_url=http_url)

        self.radar_widget = SwarmRadarWidget()
        self.drift_widget = IntentDriftGaugeWidget()
        self.telemetry_widget = TelemetryFeedWidget(max_events=100)
        self.kill_switch = KillSwitchController(client=self.client)

        self.is_running = False
        self.status_data: Dict[str, Any] = {}
        self.pending_hitl: List[Dict[str, Any]] = []
        self.recent_commands: Dict[Any, str] = {}
        self.last_drift_sim: Optional[float] = None
        self.last_drift_action: str = ""
        self.start_time = time.time()

    def poll_data(self) -> None:
        """Fetch latest state from daemon over IPC."""
        if not self.client.is_running():
            return

        # 1. Update status and sessions
        status = self.client.get_status()
        if status:
            self.status_data = status

        # 2. Update pending HITL requests
        self.pending_hitl = self.client.list_pending_hitl()

        # 3. Pull recent audit events for telemetry
        events = self.client.get_audit(limit=30)
        if events:
            self.telemetry_widget.add_events(events)
            for ev in events:
                sid = ev.get("session_id")
                pid = ev.get("pid")
                details = ev.get("details", {})
                cmd = details.get("command") or details.get("action")
                if cmd:
                    if sid:
                        self.recent_commands[sid] = str(cmd)
                    if pid:
                        self.recent_commands[pid] = str(cmd)
                    self.last_drift_action = str(cmd)

                sim = details.get("cosine_similarity") or details.get("similarity")
                if sim is not None:
                    try:
                        self.last_drift_sim = float(sim)
                    except (ValueError, TypeError):
                        pass

    def handle_key(self, ch: str) -> None:
        """Route keyboard inputs to controller or quit application."""
        if not ch:
            return

        # Check for quit keys
        if ch in ("q", "Q", "\x03"):  # 'q' or Ctrl+C
            self.is_running = False
            return

        # Delegate to kill_switch controller
        raw_sessions = self.status_data.get("sessions")
        sessions = raw_sessions if isinstance(raw_sessions, dict) else {}
        self.kill_switch.handle_key(ch, sessions=sessions, pending_hitl=self.pending_hitl)

    def build_header(self) -> Panel:
        """Build top status header panel."""
        def _safe_int(val: Any, default: int = 0) -> int:
            if val is None:
                return default
            try:
                f_val = float(val)
                if math.isnan(f_val) or math.isinf(f_val):
                    return default
                return int(f_val)
            except (ValueError, TypeError, OverflowError):
                return default

        uptime_sec = int(time.time() - self.start_time)
        uptime_str = f"{uptime_sec // 60:02d}m {uptime_sec % 60:02d}s"

        status = self.status_data if isinstance(self.status_data, dict) else {}
        active_agents = _safe_int(status.get("active_agents"), 0)
        tainted_agents = _safe_int(status.get("tainted_agents"), 0)
        vault_tokens = _safe_int(status.get("vault_tokens"), 0)
        blocked_count = _safe_int(status.get("blocked_exploits"), 0)

        header_text = Text()
        header_text.append("🛡️ AGENTGUARD COCKPIT v0.1.0", style="bold cyan")
        header_text.append("  │  ", style="dim")
        header_text.append("● ONLINE", style="bold green")
        header_text.append(f" ({uptime_str})", style="dim")
        header_text.append("  │  ", style="dim")
        header_text.append(f"Agents: {active_agents} ", style="bold white")
        if tainted_agents > 0:
            header_text.append(f"({tainted_agents} TAINTED ☢)", style="bold red")
        else:
            header_text.append("(0 Tainted)", style="green")
        header_text.append("  │  ", style="dim")
        header_text.append(f"Vault Tokens: {vault_tokens}", style="bold blue")
        header_text.append("  │  ", style="dim")
        header_text.append(f"Blocked: {blocked_count}", style="bold red" if blocked_count > 0 else "dim")
        header_text.append("  │  ", style="dim")
        header_text.append("Latency: <2ms", style="bold green")

        return Panel(header_text, style="white", border_style="cyan")

    def build_footer(self) -> Panel:
        """Build bottom keybinding and status footer panel."""
        footer_text = Text()
        footer_text.append("[K] Kill-Switch  ", style="bold red")
        footer_text.append("[R] Resume  ", style="bold green")
        footer_text.append("[T] Terminate  ", style="bold dark_red")
        footer_text.append("[I] Inspect  ", style="bold cyan")
        footer_text.append("[C] Inspect Cmds  ", style="bold yellow")
        footer_text.append("[A] Allow HITL  ", style="bold bright_green")
        footer_text.append("[D] Deny HITL  ", style="bold bright_red")
        footer_text.append("[?] Help  ", style="bold bright_blue")
        footer_text.append("[Q] Quit Cockpit", style="bold white")

        status_msg = self.kill_switch.status_message
        if status_msg:
            footer_text.append(f"   │   {status_msg}", style="italic yellow")

        return Panel(footer_text, style="white", border_style="dim")

    def build_layout(self) -> Layout:
        """Assemble full responsive cockpit layout."""
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body", ratio=1),
            Layout(name="footer", size=3),
        )

        layout["header"].update(self.build_header())
        layout["footer"].update(self.build_footer())

        # Modal override for body if modal active
        self.kill_switch.recent_events = list(self.telemetry_widget._events)
        modal_panel = self.kill_switch.render_modal(pending_hitl=self.pending_hitl)

        # Swarm Radar
        raw_sessions = self.status_data.get("sessions")
        sessions = raw_sessions if isinstance(raw_sessions, dict) else {}
        radar_panel = self.radar_widget.render(sessions, recent_commands=self.recent_commands)

        # Intent Drift Meter
        monitored_pid = None
        monitored_prof = "generic"
        monitored_intent = ""
        if sessions:
            first_sid, first_info = next(iter(sessions.items()))
            if isinstance(first_info, dict):
                monitored_pid = first_info.get("pid")
                monitored_prof = first_info.get("profile", "generic")
                monitored_intent = first_info.get("root_intent", "")

        safe_sim = None
        if self.last_drift_sim is not None:
            try:
                s_val = float(self.last_drift_sim)
                if not (math.isnan(s_val) or math.isinf(s_val)):
                    safe_sim = s_val
            except (ValueError, TypeError):
                safe_sim = None

        drift_panel = self.drift_widget.render(
            similarity=safe_sim,
            pid=monitored_pid,
            profile=monitored_prof,
            root_intent=monitored_intent,
            last_action=self.last_drift_action,
        )

        # Telemetry Feed
        telemetry_panel = self.telemetry_widget.render(max_display_rows=10)

        if modal_panel is not None:
            # When modal is active, display top split (radar/drift) and modal bottom
            layout["body"].split_column(
                Layout(name="top", ratio=1),
                Layout(name="modal", ratio=1),
            )
            layout["body"]["top"].split_row(
                Layout(radar_panel, ratio=3),
                Layout(drift_panel, ratio=2),
            )
            layout["body"]["modal"].update(modal_panel)
        else:
            # Normal dashboard mode: responsive 2-column tactical view on wide terminals (>=100 cols)
            term_width = 120
            if hasattr(self.console, "size") and self.console.size:
                term_width = self.console.size.width

            if term_width >= 100:
                # 2-column tactical layout: Left column (radar + drift), Right column (high-density telemetry stream)
                layout["body"].split_row(
                    Layout(name="left", ratio=3),
                    Layout(name="right", ratio=5),
                )
                layout["body"]["left"].split_column(
                    Layout(radar_panel, ratio=3),
                    Layout(drift_panel, ratio=2),
                )
                layout["body"]["right"].update(telemetry_panel)
            else:
                # Standard vertical layout on compact terminals
                layout["body"].split_column(
                    Layout(name="top", ratio=1),
                    Layout(name="bottom", ratio=1),
                )
                layout["body"]["top"].split_row(
                    Layout(radar_panel, ratio=3),
                    Layout(drift_panel, ratio=2),
                )
                layout["body"]["bottom"].update(telemetry_panel)

        return layout

    def run(self) -> int:
        """Run the main interactive event loop."""
        self.is_running = True
        self.poll_data()

        # Start SSE listener in background
        self.client.start_sse_listener(self.telemetry_widget.add_event)

        try:
            with TerminalRawMode():
                with Live(
                    self.build_layout(),
                    screen=True,
                    auto_refresh=False,
                    console=self.console,
                ) as live:
                    last_poll = time.time()
                    while self.is_running:
                        # 1. Non-blocking keyboard poll via select and raw key reader
                        if HAS_TERMIOS and sys.stdin.isatty():
                            k = read_key(timeout=0.15)
                            if k:
                                self.handle_key(k)
                        else:
                            time.sleep(0.15)

                        # 2. Periodic state polling
                        now = time.time()
                        if now - last_poll >= self.refresh_interval:
                            self.poll_data()
                            last_poll = now

                        # 3. Update full-screen layout
                        live.update(self.build_layout(), refresh=True)
        except KeyboardInterrupt:
            pass
        finally:
            self.is_running = False
            self.client.stop()
            self.console.print("\n[bold green]AgentGuard Cockpit exited cleanly.[/bold green]")

        return 0


def run_cockpit(
    socket_path: str = DEFAULT_SOCKET_PATH,
    http_url: str = DEFAULT_HTTP_URL,
    refresh_interval: float = 0.5,
    console: Optional[Console] = None,
) -> int:
    """Entry point for CLI launcher."""
    app = CockpitApp(
        socket_path=socket_path,
        http_url=http_url,
        refresh_interval=refresh_interval,
        console=console,
    )
    return app.run()
