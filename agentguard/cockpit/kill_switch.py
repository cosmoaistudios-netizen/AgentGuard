"""AgentGuard Cockpit: Emergency Process Kill-Switch & HITL Controller.

Provides interactive modal handling for pausing agent process trees via SIGSTOP,
resuming via SIGCONT, terminating via SIGKILL, inspecting provenance chains,
and resolving Human-in-the-Loop (HITL) authorization requests.
"""

from __future__ import annotations

import math
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


class KillSwitchMode(str, Enum):
    IDLE = "IDLE"
    SELECT_PID = "SELECT_PID"
    AGENT_PAUSED = "AGENT_PAUSED"
    INSPECT_AGENT = "INSPECT_AGENT"
    INSPECT_COMMANDS = "INSPECT_COMMANDS"
    HELP = "HELP"


class KillSwitchController:
    """Manages the state machine and modal rendering for emergency controls and HITL."""

    def __init__(self, client: Optional[Any] = None):
        self.client = client
        self.mode: KillSwitchMode = KillSwitchMode.IDLE
        self.selected_pid: Optional[int] = None
        self.selected_session: Optional[str] = None
        self.selected_profile: str = "generic"
        self.inspect_data: Dict[str, Any] = {}
        self.status_message: str = ""
        self._selectable_sessions: List[Dict[str, Any]] = []
        self._target_action: str = "pause"
        self._prior_mode: KillSwitchMode = KillSwitchMode.IDLE
        self.recent_events: List[Dict[str, Any]] = []
        self.selected_event_idx: Optional[int] = None

    def handle_key(
        self,
        ch: str,
        sessions: Dict[str, Any],
        pending_hitl: Optional[List[Dict[str, Any]]] = None,
    ) -> Optional[str]:
        """Handle a single keypress and advance the state machine."""
        key = ch.strip()
        upper_key = key.upper()

        # Handle pending HITL actions if [A] or [D] is pressed
        hitl_list = pending_hitl or []
        if hitl_list and upper_key in ("A", "D"):
            top_hitl = hitl_list[0]
            req_id = top_hitl.get("request_id") or top_hitl.get("hitl_request_id", "")
            decision = "ALLOW" if upper_key == "A" else "DENY"
            if self.client and req_id:
                try:
                    self.client.hitl_decision(req_id, decision)
                except Exception as e:
                    self.status_message = f"HITL decision error: {e}"
            verb = "ALLOWED" if decision == "ALLOW" else "DENIED"
            self.status_message = f"HITL request {req_id[:8]} -> {verb}"
            return self.status_message

        # State: IDLE
        if self.mode == KillSwitchMode.IDLE:
            if upper_key == "K":
                if not sessions:
                    self.status_message = "No active agent sessions to pause"
                    return self.status_message

                self._target_action = "pause"
                active_list: List[Dict[str, Any]] = []
                for sid, info in sessions.items():
                    if isinstance(info, dict):
                        rec = dict(info)
                        rec["session_id"] = sid
                        active_list.append(rec)

                if len(active_list) == 1:
                    target = active_list[0]
                    self.selected_pid = target.get("pid")
                    self.selected_session = target.get("session_id")
                    self.selected_profile = target.get("profile", "generic")
                    if self.client and self.selected_pid:
                        try:
                            self.client.pause_agent(self.selected_pid)
                        except Exception as e:
                            self.status_message = f"Pause error: {e}"
                            return self.status_message
                    self.mode = KillSwitchMode.AGENT_PAUSED
                    self.status_message = f"Agent PID {self.selected_pid} PAUSED (SIGSTOP)"
                else:
                    self._selectable_sessions = active_list
                    self.mode = KillSwitchMode.SELECT_PID
                    self.status_message = "Select target PID to pause"
                return self.status_message

            elif upper_key == "I":
                if not sessions:
                    self.status_message = "No active agent sessions to inspect"
                    return self.status_message

                self._target_action = "inspect"
                self._prior_mode = KillSwitchMode.IDLE
                active_list = []
                for sid, info in sessions.items():
                    if isinstance(info, dict):
                        rec = dict(info)
                        rec["session_id"] = sid
                        active_list.append(rec)

                if len(active_list) == 1:
                    target = active_list[0]
                    self.selected_pid = target.get("pid")
                    self.selected_session = target.get("session_id")
                    self.selected_profile = target.get("profile", "generic")
                    target_key = self.selected_pid or self.selected_session
                    if self.client and target_key:
                        try:
                            self.inspect_data = self.client.inspect_agent(target_key)
                        except Exception:
                            self.inspect_data = {}
                    if not self.inspect_data:
                        self.inspect_data = {
                            "pid": self.selected_pid,
                            "profile": self.selected_profile,
                            "taint_state": target.get("taint", "CLEAN"),
                            "taint_chain": [f"session:{self.selected_session or self.selected_pid}"],
                            "recent_commands": [],
                        }
                    self.mode = KillSwitchMode.INSPECT_AGENT
                    self.status_message = f"Inspecting agent PID {self.selected_pid}"
                else:
                    self._selectable_sessions = active_list
                    self.mode = KillSwitchMode.SELECT_PID
                    self.status_message = "Select target PID to inspect"
                return self.status_message

            elif upper_key == "R":
                if not sessions:
                    self.status_message = "No active agent sessions to resume"
                    return self.status_message

                active_list = []
                for sid, info in sessions.items():
                    if isinstance(info, dict):
                        rec = dict(info)
                        rec["session_id"] = sid
                        active_list.append(rec)

                paused_list = [s for s in active_list if s.get("process_status") in ("PAUSED", "STOPPED")]
                target_list = paused_list if paused_list else active_list
                if len(target_list) == 1:
                    target = target_list[0]
                    self.selected_pid = target.get("pid")
                    if self.client and self.selected_pid:
                        try:
                            self.client.resume_agent(self.selected_pid)
                        except Exception as e:
                            self.status_message = f"Resume error: {e}"
                            return self.status_message
                    self.status_message = f"Agent PID {self.selected_pid} RESUMED (SIGCONT)"
                else:
                    self._target_action = "resume"
                    self._selectable_sessions = target_list
                    self.mode = KillSwitchMode.SELECT_PID
                    self.status_message = "Select target PID to resume"
                return self.status_message

            elif upper_key == "T":
                if not sessions:
                    self.status_message = "No active agent sessions to terminate"
                    return self.status_message

                active_list = []
                for sid, info in sessions.items():
                    if isinstance(info, dict):
                        rec = dict(info)
                        rec["session_id"] = sid
                        active_list.append(rec)

                if len(active_list) == 1:
                    target = active_list[0]
                    self.selected_pid = target.get("pid")
                    if self.client and self.selected_pid:
                        try:
                            self.client.terminate_agent(self.selected_pid)
                        except Exception as e:
                            self.status_message = f"Terminate error: {e}"
                            return self.status_message
                    self.status_message = f"Agent PID {self.selected_pid} TERMINATED (SIGKILL)"
                else:
                    self._target_action = "terminate"
                    self._selectable_sessions = active_list
                    self.mode = KillSwitchMode.SELECT_PID
                    self.status_message = "Select target PID to terminate"
                return self.status_message

            elif upper_key in ("C", "E") or key in ("\r", "\n"):
                self.mode = KillSwitchMode.INSPECT_COMMANDS
                self.selected_event_idx = None
                self.status_message = "Inspect Commands: press [1-9] to inspect specific command, [ESC] to return"
                return self.status_message

            elif key in ("?", "h", "H"):
                self.mode = KillSwitchMode.HELP
                self.status_message = "Cockpit Help: press [ESC] to return"
                return self.status_message

        # State: SELECT_PID
        elif self.mode == KillSwitchMode.SELECT_PID:
            if key in ("\x1b", "q", "Q", "b", "B"):  # Esc or cancel
                self.mode = KillSwitchMode.IDLE
                self.status_message = "Selection cancelled"
                return self.status_message

            if key.isdigit():
                idx = int(key) - 1
                if 0 <= idx < len(self._selectable_sessions):
                    target = self._selectable_sessions[idx]
                    self.selected_pid = target.get("pid")
                    self.selected_session = target.get("session_id")
                    self.selected_profile = target.get("profile", "generic")

                    if self._target_action == "inspect":
                        self._prior_mode = KillSwitchMode.IDLE
                        if self.client and (self.selected_pid or self.selected_session):
                            try:
                                self.inspect_data = self.client.inspect_agent(self.selected_pid or self.selected_session)
                            except Exception:
                                self.inspect_data = {}
                        if not self.inspect_data:
                            self.inspect_data = {
                                "pid": self.selected_pid,
                                "profile": self.selected_profile,
                                "taint_state": target.get("taint", "CLEAN"),
                                "taint_chain": [f"session:{self.selected_session or self.selected_pid}"],
                                "recent_commands": [],
                            }
                        self.mode = KillSwitchMode.INSPECT_AGENT
                        self.status_message = f"Inspecting agent PID {self.selected_pid}"
                        return self.status_message
                    elif self._target_action == "resume":
                        if self.client and self.selected_pid:
                            try:
                                self.client.resume_agent(self.selected_pid)
                            except Exception as e:
                                self.status_message = f"Resume error: {e}"
                                return self.status_message
                        self.mode = KillSwitchMode.IDLE
                        self.status_message = f"Agent PID {self.selected_pid} RESUMED (SIGCONT)"
                        return self.status_message
                    elif self._target_action == "terminate":
                        if self.client and self.selected_pid:
                            try:
                                self.client.terminate_agent(self.selected_pid)
                            except Exception as e:
                                self.status_message = f"Terminate error: {e}"
                                return self.status_message
                        self.mode = KillSwitchMode.IDLE
                        self.status_message = f"Agent PID {self.selected_pid} TERMINATED (SIGKILL)"
                        return self.status_message
                    else:
                        # Default: pause
                        if self.client and self.selected_pid:
                            try:
                                self.client.pause_agent(self.selected_pid)
                            except Exception as e:
                                self.status_message = f"Pause error: {e}"
                                return self.status_message
                        self.mode = KillSwitchMode.AGENT_PAUSED
                        self.status_message = f"Agent PID {self.selected_pid} PAUSED (SIGSTOP)"
                        return self.status_message

        # State: AGENT_PAUSED
        elif self.mode == KillSwitchMode.AGENT_PAUSED:
            if upper_key == "R":
                if self.client and self.selected_pid:
                    try:
                        self.client.resume_agent(self.selected_pid)
                    except Exception as e:
                        self.status_message = f"Resume error: {e}"
                        return self.status_message
                self.mode = KillSwitchMode.IDLE
                self.status_message = f"Agent PID {self.selected_pid} RESUMED (SIGCONT)"
                return self.status_message

            elif upper_key == "T":
                if self.client and self.selected_pid:
                    try:
                        self.client.terminate_agent(self.selected_pid)
                    except Exception as e:
                        self.status_message = f"Terminate error: {e}"
                        return self.status_message
                self.mode = KillSwitchMode.IDLE
                self.status_message = f"Agent PID {self.selected_pid} TERMINATED (SIGKILL)"
                return self.status_message

            elif upper_key == "I":
                self._prior_mode = KillSwitchMode.AGENT_PAUSED
                if self.client and self.selected_pid:
                    try:
                        self.inspect_data = self.client.inspect_agent(self.selected_pid)
                    except Exception:
                        self.inspect_data = {
                            "pid": self.selected_pid,
                            "profile": self.selected_profile,
                            "taint_state": "UNKNOWN",
                            "taint_chain": [f"pid:{self.selected_pid}"],
                            "recent_commands": [],
                        }
                else:
                    self.inspect_data = {
                        "pid": self.selected_pid,
                        "profile": self.selected_profile,
                        "taint_state": "UNKNOWN",
                        "taint_chain": [f"pid:{self.selected_pid}"],
                        "recent_commands": [],
                    }
                self.mode = KillSwitchMode.INSPECT_AGENT
                self.status_message = f"Inspecting agent PID {self.selected_pid}"
                return self.status_message

            elif key in ("\x1b", "q", "Q"):  # Esc returns to Cockpit while keeping agent paused
                self.mode = KillSwitchMode.IDLE
                self.status_message = f"Agent PID {self.selected_pid} remains paused"
                return self.status_message

        # State: INSPECT_AGENT
        elif self.mode == KillSwitchMode.INSPECT_AGENT:
            if upper_key == "R":
                if self.client and self.selected_pid:
                    try:
                        self.client.resume_agent(self.selected_pid)
                    except Exception as e:
                        self.status_message = f"Resume error: {e}"
                        return self.status_message
                self.mode = KillSwitchMode.IDLE
                self.status_message = f"Agent PID {self.selected_pid} RESUMED (SIGCONT)"
                return self.status_message

            elif upper_key == "T":
                if self.client and self.selected_pid:
                    try:
                        self.client.terminate_agent(self.selected_pid)
                    except Exception as e:
                        self.status_message = f"Terminate error: {e}"
                        return self.status_message
                self.mode = KillSwitchMode.IDLE
                self.status_message = f"Agent PID {self.selected_pid} TERMINATED (SIGKILL)"
                return self.status_message

            elif key in ("\x1b", "b", "B", "q", "Q"):
                if getattr(self, "_prior_mode", None) == KillSwitchMode.AGENT_PAUSED:
                    self.mode = KillSwitchMode.AGENT_PAUSED
                    self.status_message = f"Back to pause menu for PID {self.selected_pid}"
                else:
                    self.mode = KillSwitchMode.IDLE
                    self.status_message = "Returned to cockpit live feed"
                return self.status_message

        # State: INSPECT_COMMANDS
        elif self.mode == KillSwitchMode.INSPECT_COMMANDS:
            if key in ("\x1b", "b", "B", "q", "Q"):
                if self.selected_event_idx is not None:
                    self.selected_event_idx = None
                    self.status_message = "Inspect Commands: press [1-9] to select, [ESC] to return"
                else:
                    self.mode = KillSwitchMode.IDLE
                    self.status_message = "Returned to cockpit live feed"
                return self.status_message

            if key in ("UP", "k", "K"):
                if self.selected_event_idx is not None and self.selected_event_idx > 0:
                    self.selected_event_idx -= 1
                    self.status_message = f"Viewing command #{self.selected_event_idx + 1} detail"
                    return self.status_message
            elif key in ("DOWN", "j", "J"):
                if self.selected_event_idx is not None and self.selected_event_idx < len(self.recent_events) - 1:
                    self.selected_event_idx += 1
                    self.status_message = f"Viewing command #{self.selected_event_idx + 1} detail"
                    return self.status_message

            if key.isdigit():
                idx = int(key) - 1
                if 0 <= idx < len(self.recent_events):
                    self.selected_event_idx = idx
                    self.status_message = f"Viewing command #{key} detail"
                    return self.status_message

        # State: HELP
        elif self.mode == KillSwitchMode.HELP:
            if key in ("\x1b", "b", "B", "q", "Q", " ", "\r", "\n"):
                self.mode = KillSwitchMode.IDLE
                self.status_message = "Returned to cockpit live feed"
                return self.status_message

        return None

    def render_modal(
        self, pending_hitl: Optional[List[Dict[str, Any]]] = None
    ) -> Optional[Panel]:
        """Render active modal panel based on current state machine mode."""
        hitl_list = pending_hitl or []

        # High-priority HITL modal if pending and mode is IDLE
        if hitl_list and self.mode == KillSwitchMode.IDLE:
            req = hitl_list[0]
            cmd = req.get("command", "--")
            reason = req.get("reason", "Potential unauthorized or dangerous action")
            pid = req.get("pid", "--")
            sid = req.get("session_id", "--")

            lines = [
                f"[bold red]TARGET AGENT:[/]  PID {escape(str(pid))} ({escape(str(sid))})",
                f"[bold red]COMMAND:[/]       [bold white]{escape(str(cmd))}[/bold white]",
                f"[bold red]REASON:[/]        [italic yellow]{escape(str(reason))}[/italic yellow]",
                "",
                "[bold white]DECISION HOTKEYS:[/] [bold black on green] [A] ALLOW ONCE [/bold black on green]   [bold white on red] [D] DENY & BLOCK [/bold white on red]",
            ]
            return Panel(
                Text.from_markup("\n".join(lines)),
                title="[bold yellow]⚠️  HUMAN-IN-THE-LOOP (HITL) CONFIRMATION REQUIRED[/bold yellow]",
                border_style="yellow",
            )

        if self.mode == KillSwitchMode.SELECT_PID:
            target_act = getattr(self, "_target_action", "pause").lower()
            if target_act == "inspect":
                panel_title = "[bold cyan]🔍 SELECT AGENT TO INSPECT[/bold cyan]"
                border_clr = "cyan"
                action_text = "inspect provenance & telemetry"
            elif target_act == "resume":
                panel_title = "[bold green]▶ SELECT AGENT TO RESUME[/bold green]"
                border_clr = "green"
                action_text = "resume via SIGCONT"
            elif target_act == "terminate":
                panel_title = "[bold dark_red]⏹ SELECT AGENT TO TERMINATE[/bold dark_red]"
                border_clr = "red"
                action_text = "terminate via SIGKILL"
            else:
                panel_title = "[bold red]🛑 EMERGENCY KILL-SWITCH: SELECT TARGET[/bold red]"
                border_clr = "red"
                action_text = "pause via SIGSTOP"

            lines = [f"[bold white]Select active agent to {action_text}:[/bold white]", ""]
            for i, target in enumerate(self._selectable_sessions, 1):
                pid = target.get("pid", "--")
                prof = target.get("profile", "generic")
                taint = target.get("taint", "CLEAN")
                taint_badge = "[red]TAINTED[/red]" if taint == "TAINTED" else "[green]CLEAN[/green]"
                lines.append(f"  [bold cyan][{i}][/bold cyan] PID [bold]{escape(str(pid))}[/bold] ({escape(str(prof))}) — {taint_badge}")
            lines.extend(["", f"[dim]Press [1-9] to select target, or [ESC] to cancel[/dim]"])
            return Panel(
                Text.from_markup("\n".join(lines)),
                title=panel_title,
                border_style=border_clr,
            )

        elif self.mode == KillSwitchMode.AGENT_PAUSED:
            pid = self.selected_pid or "--"
            prof = self.selected_profile or "generic"
            lines = [
                f"[bold white]Target Process:[/] [cyan]PID {escape(str(pid))}[/] [dim]({escape(str(prof))})[/]",
                "[bold white]Current State:[/]  [bold yellow]FROZEN via SIGSTOP[/bold yellow]",
                "",
                "[bold cyan][R] Resume[/bold cyan]      — Unfreeze agent process tree (SIGCONT)",
                "[bold red][T] Terminate[/bold red]   — Cleanly kill process tree (SIGKILL)",
                "[bold magenta][I] Inspect[/bold magenta]     — View recent commands, call stack & taint provenance",
                "[dim][ESC] Return to Cockpit (keep agent paused)[/dim]",
            ]
            return Panel(
                Text.from_markup("\n".join(lines)),
                title="[bold red]🛑 EMERGENCY KILL-SWITCH: AGENT PAUSED[/bold red]",
                border_style="red",
            )

        elif self.mode == KillSwitchMode.INSPECT_AGENT:
            data = self.inspect_data if isinstance(self.inspect_data, dict) else {}
            pid = data.get("pid") or self.selected_pid or "--"
            prof = data.get("profile") or self.selected_profile or "generic"
            st = data.get("process_status") or "stopped"

            raw_cpu = data.get("cpu_percent")
            if raw_cpu is not None:
                try:
                    c_val = float(raw_cpu)
                    cpu_val = 0.0 if (math.isnan(c_val) or math.isinf(c_val) or c_val < 0) else c_val
                except (ValueError, TypeError):
                    cpu_val = 0.0
            else:
                cpu_val = 0.0
            cpu_str = f"{cpu_val:.1f}%"

            raw_rss = data.get("memory_rss_bytes")
            if raw_rss is not None:
                try:
                    m_val = float(raw_rss)
                    mem_mb = 0.0 if (math.isnan(m_val) or math.isinf(m_val) or m_val < 0) else (m_val / (1024 * 1024))
                except (ValueError, TypeError):
                    mem_mb = 0.0
            else:
                mem_mb = 0.0

            taint = (data.get("taint_state") or "CLEAN").strip().upper()
            taint_style = "[bold red]TAINTED ☢[/bold red]" if taint == "TAINTED" else "[bold green]CLEAN[/bold green]"

            raw_chain = data.get("taint_chain")
            if isinstance(raw_chain, (list, tuple)):
                chain_list = [escape(str(x)) for x in raw_chain if x]
            else:
                chain_list = []
            chain_str = " ➔ ".join(chain_list) if chain_list else escape(f"session:{self.selected_session or '--'}")

            raw_recent = data.get("recent_commands")
            if isinstance(raw_recent, (list, tuple)):
                recent_list = []
                for x in raw_recent:
                    if not x:
                        continue
                    if isinstance(x, dict):
                        recent_list.append(str(x.get("command", x)))
                    else:
                        recent_list.append(str(x))
            else:
                recent_list = []

            lines = [
                f"[bold white]Process Tree:[/]   PID [cyan]{escape(str(pid))}[/] [dim]({escape(str(prof))})[/]  |  Status: [yellow]{escape(str(st))}[/]  |  CPU: {cpu_str}  |  RSS: {mem_mb:.1f} MB",
                f"[bold white]Taint State:[/]    {taint_style}",
                f"[bold white]Provenance:[/]     [italic cyan]{chain_str}[/italic cyan]",
                "",
                "[bold white]Recent Intercepted Commands:[/bold white]",
            ]

            if recent_list:
                for c in recent_list[-5:]:
                    lines.append(f"  • [yellow]{escape(str(c))}[/yellow]")
            else:
                lines.append("  [dim italic](No recent commands recorded)[/dim italic]")

            lines.extend([
                "",
                "[bold cyan][R] Resume (SIGCONT)[/]   [bold red][T] Terminate (SIGKILL)[/]   [dim][ESC/B] Back to Pause Menu[/dim]",
            ])

            return Panel(
                Text.from_markup("\n".join(lines)),
                title="[bold cyan]🔍 AGENT DEEP INSPECTION & PROVENANCE[/bold cyan]",
                border_style="cyan",
            )

        elif self.mode == KillSwitchMode.INSPECT_COMMANDS:
            from agentguard.cockpit.telemetry_feed import format_event_badge, format_event_timestamp

            events = list(self.recent_events)
            if self.selected_event_idx is not None and 0 <= self.selected_event_idx < len(events):
                ev = events[self.selected_event_idx]
                details = ev.get("details", {})
                cmd = details.get("command") or details.get("action") or "--"
                reason = details.get("reason") or "--"
                status = ev.get("status") or "INFO"
                ev_type = ev.get("event_type") or "COMMAND"
                pid = ev.get("pid") or "--"
                sid = ev.get("session_id") or "--"
                cwd = details.get("cwd") or "--"
                taint = details.get("taint_state") or "--"
                time_str = format_event_timestamp(ev.get("timestamp"))
                badge = format_event_badge(ev_type, status)

                lines = [
                    f"[bold white]Event ID:[/]   [cyan]{escape(str(ev.get('event_id', '--')))}[/cyan]  |  Time: [dim]{time_str}[/dim]  |  {badge}  [bold]{escape(str(status))}[/bold]",
                    f"[bold white]Target:[/]     PID [cyan]{escape(str(pid))}[/cyan]  |  Session: [cyan]{escape(str(sid))}[/cyan]  |  CWD: [dim]{escape(str(cwd))}[/dim]",
                    "",
                    "[bold white]Intercepted Command (Full Un-truncated):[/bold white]",
                    f"[bold yellow on black] {escape(str(cmd))} [/bold yellow on black]",
                    "",
                    f"[bold white]Policy Verdict:[/] [bold]{escape(str(status))}[/bold]",
                    f"[bold white]Rule / Reason:[/]  [italic yellow]{escape(str(reason))}[/italic yellow]",
                ]
                if taint != "--":
                    lines.append(f"[bold white]Taint State:[/]    {escape(str(taint))}")
                sim = details.get("similarity") or details.get("cosine_similarity")
                if sim is not None:
                    lines.append(f"[bold white]Intent Drift:[/]   Cosine {sim}")

                lines.extend([
                    "",
                    "[dim][ESC / B] Back to Command List    [Q] Return to Cockpit[/dim]",
                ])
                return Panel(
                    Text.from_markup("\n".join(lines)),
                    title=f"[bold yellow]🔍 COMMAND DETAIL #{self.selected_event_idx + 1}[/bold yellow]",
                    border_style="yellow",
                )
            else:
                table = Table(box=None, expand=True, show_header=True, header_style="bold yellow", pad_edge=False)
                table.add_column("IDX", justify="right", style="cyan", width=5, no_wrap=True)
                table.add_column("TIME", style="dim", width=10, no_wrap=True)
                table.add_column("STATUS", width=14, no_wrap=True)
                table.add_column("PID", style="cyan", width=8, no_wrap=True)
                table.add_column("COMMAND / ACTION", style="white", ratio=3, overflow="ellipsis", no_wrap=True)
                table.add_column("REASON / RULE", style="dim", ratio=2, overflow="ellipsis", no_wrap=True)

                if not events:
                    lines = [
                        "[dim italic]No audited commands or events currently in buffer.[/dim italic]",
                        "",
                        "[dim][ESC] Return to Cockpit[/dim]",
                    ]
                    return Panel(
                        Text.from_markup("\n".join(lines)),
                        title="[bold yellow]🔍 AUDITED COMMANDS & TELEMETRY INSPECTOR[/bold yellow]",
                        border_style="yellow",
                    )

                display_events = events[-9:]
                for i, ev in enumerate(display_events, 1):
                    time_str = format_event_timestamp(ev.get("timestamp"))
                    badge = format_event_badge(ev.get("event_type", ""), ev.get("status", ""))
                    pid_str = str(ev.get("pid") or "--")
                    details = ev.get("details", {})
                    cmd = details.get("command") or details.get("action") or "--"
                    reason = details.get("reason") or "--"
                    table.add_row(
                        f"[{i}]",
                        time_str,
                        badge,
                        pid_str,
                        escape(str(cmd)),
                        escape(str(reason)),
                    )

                lines = [
                    "",
                    "[bold white]Hotkeys:[/] [cyan][1-9][/cyan] Inspect Full Command  |  [dim][ESC] Return to Cockpit[/dim]",
                ]
                from rich.console import Group
                return Panel(
                    Group(table, Text.from_markup("\n".join(lines))),
                    title="[bold yellow]🔍 AUDITED COMMANDS & TELEMETRY INSPECTOR[/bold yellow]",
                    border_style="yellow",
                )

        elif self.mode == KillSwitchMode.HELP:
            lines = [
                "[bold cyan]🛡️  AGENTGUARD DEVSECOPS COCKPIT — KEYBOARD SHORTCUTS[/bold cyan]",
                "",
                "[bold white]PROCESS TREE CONTROL:[/bold white]",
                "  [bold red][K] Emergency Pause[/bold red]      — Send SIGSTOP to freeze target agent process tree",
                "  [bold green][R] Resume Agent[/bold green]         — Send SIGCONT to unfreeze paused agent process tree",
                "  [bold dark_red][T] Terminate Agent[/bold dark_red]      — Escalate to SIGKILL to cleanly terminate rogue agent",
                "",
                "[bold white]DEEP INSPECTION & AUDITING:[/bold white]",
                "  [bold cyan][I] Deep Inspect Agent[/bold cyan]   — View CPU, memory RSS, provenance DAG & recent commands",
                "  [bold yellow][C] / [Enter] Inspect Cmd[/bold yellow]  — Drill into full un-truncated commands & policy rules",
                "  [bold magenta][1-9] Direct Selection[/bold magenta]     — Instantly select target agent or command event",
                "",
                "[bold white]OPERATOR CONFIRMATION (HITL):[/bold white]",
                "  [bold black on green] [A] Allow Once [/bold black on green]          — Authorize pending dangerous command once",
                "  [bold white on red] [D] Deny & Block [/bold white on red]        — Reject pending command with zero-trust security drop",
                "",
                "[bold white]NAVIGATION:[/bold white]",
                "  [bold dim][ESC] / [B] Back[/bold dim]          — Dismiss active modal / return to live feed",
                "  [bold white][Q] Quit Cockpit[/bold white]         — Cleanly exit terminal cockpit",
            ]
            return Panel(
                Text.from_markup("\n".join(lines)),
                title="[bold cyan]❓ COCKPIT OPERATOR HELP & GUIDE[/bold cyan]",
                border_style="cyan",
            )

        return None


def render_kill_switch_modal(
    selected_pid: int,
    profile: str = "generic",
    paused: bool = True,
) -> Panel:
    """Functional convenience wrapper to render emergency paused modal."""
    controller = KillSwitchController()
    controller.selected_pid = selected_pid
    controller.selected_profile = profile
    controller.mode = KillSwitchMode.AGENT_PAUSED if paused else KillSwitchMode.IDLE
    panel = controller.render_modal()
    return panel or Panel(Text("Idle"))


def render_inspect_modal(inspect_data: Dict[str, Any]) -> Panel:
    """Functional convenience wrapper to render agent inspection modal."""
    controller = KillSwitchController()
    controller.mode = KillSwitchMode.INSPECT_AGENT
    controller.inspect_data = inspect_data
    panel = controller.render_modal()
    return panel or Panel(Text("Inspect"))


def render_hitl_prompt(hitl_data: Dict[str, Any]) -> Panel:
    """Functional convenience wrapper to render HITL confirmation prompt."""
    controller = KillSwitchController()
    panel = controller.render_modal(pending_hitl=[hitl_data])
    return panel or Panel(Text("HITL"))
