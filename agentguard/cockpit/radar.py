"""AgentGuard Cockpit: Swarm Radar & Taint Radiation Meters.

Renders connected agent sessions, their PID, profile, uptime, process status,
current tool invocations, and real-time Taint Radiation meters.
"""

from __future__ import annotations

import math
import time
from typing import Any, Dict, Optional, Union

from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


def format_taint_meter(
    taint_state: str,
    score: Optional[float] = None,
    width: int = 10,
) -> Text:
    """Format a dynamic visual Taint Radiation meter.

    0% Clean: Green [░░░░░░░░░░] CLEAN
    100% Radioactive: Red [██████████] TAINTED ☢
    """
    normalized_state = (taint_state or "CLEAN").strip().upper()

    if score is None:
        eff_score = 1.0 if normalized_state == "TAINTED" else 0.0
    else:
        try:
            s_float = float(score)
            if math.isnan(s_float):
                eff_score = 1.0 if normalized_state == "TAINTED" else 0.0
            else:
                eff_score = max(0.0, min(1.0, s_float))
        except (ValueError, TypeError):
            eff_score = 1.0 if normalized_state == "TAINTED" else 0.0

    filled_count = int(round(eff_score * width))
    empty_count = width - filled_count
    bar_str = "█" * filled_count + "░" * empty_count
    pct = int(round(eff_score * 100))

    if eff_score <= 0.0 and normalized_state == "CLEAN":
        return Text.from_markup(f"[bold green]{pct:>3}% [{bar_str}] CLEAN[/bold green]")
    elif eff_score >= 0.85 or normalized_state == "TAINTED":
        return Text.from_markup(f"[bold red]{pct:>3}% [{bar_str}] TAINTED ☢[/bold red]")
    elif eff_score >= 0.50:
        return Text.from_markup(f"[bold dark_orange]{pct:>3}% [{bar_str}] WARNING[/bold dark_orange]")
    else:
        return Text.from_markup(f"[bold yellow]{pct:>3}% [{bar_str}] ELEVATED[/bold yellow]")


def format_uptime(seconds: Optional[Union[float, int, str]]) -> str:
    """Format seconds into human-readable MMm SSs or HHh MMm."""
    if seconds is None:
        return "--"
    try:
        sec_float = float(seconds)
    except (ValueError, TypeError):
        return "--"
    if math.isnan(sec_float) or math.isinf(sec_float) or sec_float < 0:
        return "--"
    try:
        sec = int(sec_float)
    except (ValueError, OverflowError):
        return "--"
    if sec < 60:
        return f"{sec:02d}s"
    minutes = sec // 60
    rem_sec = sec % 60
    if minutes < 60:
        return f"{minutes:02d}m {rem_sec:02d}s"
    hours = minutes // 60
    rem_min = minutes % 60
    return f"{hours:02d}h {rem_min:02d}m"


def format_status(status_str: Optional[str]) -> Text:
    """Format process status badge with appropriate styling."""
    st = (status_str or "RUNNING").strip().upper()
    if st in ("RUNNING", "HEALTHY", "ALIVE"):
        return Text.from_markup("[bold green]● RUNNING[/bold green]")
    elif st in ("PAUSED", "STOPPED", "FROZEN"):
        return Text.from_markup("[bold yellow]⏸ PAUSED[/bold yellow]")
    elif st in ("TERMINATED", "KILLED", "DEAD"):
        return Text.from_markup("[dim red]⏹ KILLED[/dim red]")
    return Text(st, style="cyan")


class SwarmRadarWidget:
    """Widget rendering Swarm Radar table showing active agents."""

    def __init__(self, title: str = "🛰️  Swarm Radar — Active Agents"):
        self.title = title

    def render(
        self,
        sessions: Dict[str, Any],
        recent_commands: Optional[Dict[Union[int, str], str]] = None,
    ) -> Panel:
        """Build and render the Swarm Radar panel."""
        table = Table(
            expand=True,
            show_header=True,
            header_style="bold cyan",
            box=None,
            pad_edge=False,
        )

        table.add_column("PID", justify="right", style="cyan", width=8, no_wrap=True)
        table.add_column("PROFILE", style="bold white", width=14, no_wrap=True)
        table.add_column("STATUS", justify="center", width=12, no_wrap=True)
        table.add_column("UPTIME", justify="right", style="dim", width=10, no_wrap=True)
        table.add_column("CURRENT TOOL / COMMAND", style="white", ratio=3, overflow="ellipsis", no_wrap=True)
        table.add_column("TAINT RADIATION", width=28, no_wrap=True)

        if not sessions:
            placeholder = (
                "[dim italic]No active agent sessions detected.\n"
                "Run 'ag wrap -- <command>' to attach an agent to the zero-trust kernel.[/dim italic]"
            )
            return Panel(
                Text.from_markup(placeholder),
                title=f"[bold cyan]{self.title}[/bold cyan]",
                border_style="cyan",
            )

        cmd_map = recent_commands or {}
        now = time.time()

        for sid, info in sessions.items():
            if not isinstance(info, dict):
                continue
            raw_pid = info.get("pid")
            int_pid = 0
            pid_str = "--"
            if raw_pid is not None:
                try:
                    val = int(raw_pid)
                    if val > 0:
                        int_pid = val
                        pid_str = str(val)
                except (ValueError, TypeError):
                    s = str(raw_pid).strip()
                    if s and s != "0":
                        pid_str = s

            profile = info.get("profile", "generic")
            status_text = format_status(info.get("process_status", "RUNNING"))

            # Calculate uptime safely
            created_at = info.get("created_at") or info.get("start_time")
            uptime_sec = None
            if created_at is not None:
                try:
                    c_val = float(created_at)
                    if not (math.isnan(c_val) or math.isinf(c_val)):
                        uptime_sec = now - c_val
                except (ValueError, TypeError):
                    uptime_sec = None
            if uptime_sec is None:
                uptime_sec = info.get("uptime_seconds")
            uptime_str = format_uptime(uptime_sec)

            # Determine current tool or command
            curr_cmd = (
                cmd_map.get(sid)
                or (cmd_map.get(int_pid) if int_pid > 0 else None)
                or (cmd_map.get(str(raw_pid)) if raw_pid is not None else None)
                or info.get("current_tool")
                or info.get("command")
                or info.get("root_intent")
                or "--"
            )

            taint_state = info.get("taint", "CLEAN")
            score = info.get("taint_score")
            radiation_meter = format_taint_meter(taint_state, score=score)

            table.add_row(
                pid_str,
                escape(str(profile)),
                status_text,
                uptime_str,
                Text(str(curr_cmd)),
                radiation_meter,
            )

        return Panel(
            table,
            title=f"[bold cyan]{escape(self.title)}[/bold cyan]",
            border_style="cyan",
        )


def render_swarm_radar(
    sessions: Dict[str, Any],
    recent_commands: Optional[Dict[Union[int, str], str]] = None,
) -> Panel:
    """Functional convenience wrapper to render the Swarm Radar panel."""
    return SwarmRadarWidget().render(sessions, recent_commands=recent_commands)
