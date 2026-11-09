"""AgentGuard Cockpit: Live Audited Telemetry Feed.

Maintains a bounded auto-scrolling buffer of security events and renders
them with color-coded badges: [PASS], [BLOCKED], [VAULTED], [SANITIZED], [TAINTED].
"""

from __future__ import annotations

import collections
import datetime
import math
import time
from typing import Any, Deque, Dict, List, Optional

from rich.markup import escape
from rich.panel import Panel
from rich.text import Text


def format_event_badge(event_type: str, status: str = "") -> str:
    """Format color-coded Rich markup badge based on event type and status."""
    ev = (event_type or "").upper()
    st = (status or "").upper()

    if "BLOCKED" in ev or st == "BLOCKED" or "VIOLATION" in ev:
        return "[bold white on red][BLOCKED][/bold white on red]"
    elif "TOKEN" in ev or "VAULT" in ev:
        return "[bold white on blue][VAULTED][/bold white on blue]"
    elif "SANITIZ" in ev or "STRIP" in ev:
        return "[bold black on yellow][SANITIZED][/bold black on yellow]"
    elif "TAINT" in ev:
        return "[bold white on dark_orange][TAINTED][/bold white on dark_orange]"
    elif "HITL" in ev or st == "PROMPT_HITL":
        return "[bold black on yellow][HITL][/bold black on yellow]"
    elif "PAUSE" in ev or st == "PAUSED":
        return "[bold black on yellow][PAUSED][/bold black on yellow]"
    elif "RESUME" in ev or st == "RESUMED":
        return "[bold black on green][RESUMED][/bold black on green]"
    elif "TERMINAT" in ev or "KILL" in ev or st == "TERMINATED":
        return "[bold white on dark_red][KILLED][/bold white on dark_red]"
    elif "ALLOW" in ev or st in ("ALLOWED", "PASS", "OK") or "PASS" in ev:
        return "[bold black on green][PASS][/bold black on green]"
    else:
        return f"[dim][{escape(ev[:8])}][/dim]"


def format_event_timestamp(ts: Any) -> str:
    """Format various timestamp representations into clean HH:MM:SS string.

    Handles numeric epoch timestamps (int, float), ISO-8601 strings, and time strings.
    """
    if ts is None:
        return datetime.datetime.now().strftime("%H:%M:%S")

    # 1. Numeric epoch timestamps (int or float)
    if isinstance(ts, (int, float)):
        try:
            val = float(ts)
            if not math.isnan(val) and not math.isinf(val) and val > 0:
                return datetime.datetime.fromtimestamp(val).strftime("%H:%M:%S")
        except (ValueError, OSError, OverflowError):
            pass
        return datetime.datetime.now().strftime("%H:%M:%S")

    # 2. String timestamps
    if isinstance(ts, str):
        cleaned = ts.strip()
        if not cleaned:
            return datetime.datetime.now().strftime("%H:%M:%S")

        if "T" in cleaned:
            time_part = cleaned.split("T")[-1].split(".")[0].rstrip("Z")
            if time_part:
                return time_part

        # Numeric string (epoch)
        try:
            val = float(cleaned)
            if not math.isnan(val) and not math.isinf(val) and val > 0:
                return datetime.datetime.fromtimestamp(val).strftime("%H:%M:%S")
        except (ValueError, OSError, OverflowError):
            pass

        if len(cleaned) >= 8 and cleaned[2] == ":" and cleaned[5] == ":":
            return cleaned[:8]

    return datetime.datetime.now().strftime("%H:%M:%S")


def format_event_summary(details: Dict[str, Any]) -> str:
    """Extract a concise one-line summary from audit event details."""
    if not isinstance(details, dict):
        return escape(str(details))

    cmd = details.get("command") or details.get("action")
    reason = details.get("reason")
    path = details.get("path") or details.get("file")
    token_count = details.get("count") or details.get("tokens_count")

    parts = []
    if cmd:
        cmd_str = str(cmd).replace("\n", " ")
        if len(cmd_str) > 60:
            cmd_str = cmd_str[:57] + "..."
        parts.append(f"[bold]{escape(cmd_str)}[/bold]")
    if path:
        parts.append(f"file: {escape(str(path))}")
    if token_count:
        parts.append(f"{escape(str(token_count))} secret(s) shielded")
    if reason:
        reason_str = str(reason)
        if len(reason_str) > 50:
            reason_str = reason_str[:47] + "..."
        parts.append(f"[dim]({escape(reason_str)})[/dim]")

    if not parts:
        # Fallback to key-value pairs
        items = [f"{escape(str(k))}={escape(str(v))}" for k, v in list(details.items())[:2]]
        return " ".join(items) if items else "--"

    return "  ".join(parts)


SPARKLINE_BARS = [" ", " ", "▂", "▃", "▄", "▅", "▆", "▇", "█"]


def render_sparkline(values: List[int], width: int = 12) -> str:
    """Render a micro Unicode sparkline from historical throughput counts."""
    if not values:
        return " " * width
    sub = list(values)[-width:]
    if len(sub) < width:
        sub = [0] * (width - len(sub)) + sub
    max_v = max(sub) or 1
    chars = []
    for v in sub:
        idx = int(round((v / max_v) * (len(SPARKLINE_BARS) - 1)))
        idx = max(0, min(len(SPARKLINE_BARS) - 1, idx))
        chars.append(SPARKLINE_BARS[idx])
    return "".join(chars)


class TelemetryFeedWidget:
    """Widget managing bounded live event feed with color badges."""

    def __init__(
        self,
        max_events: int = 100,
        title: str = "📜 Live Audited Telemetry Feed",
    ):
        self.max_events = max_events
        self.title = title
        self._events: Deque[Dict[str, Any]] = collections.deque(maxlen=max_events)
        self._seen_ids: set[str] = set()
        self._rate_history: Deque[int] = collections.deque([0] * 12, maxlen=30)
        self._current_window_count: int = 0
        self._last_tick_time: float = time.time()

    def add_event(self, event: Dict[str, Any]) -> bool:
        """Add a single audit event to the feed if not duplicate."""
        if not isinstance(event, dict):
            return False
        ev_id = event.get("event_id") or str(event)
        if ev_id in self._seen_ids:
            return False
        self._seen_ids.add(ev_id)
        if len(self._seen_ids) > self.max_events * 3:
            self._seen_ids = set(list(self._seen_ids)[-self.max_events :])
        self._events.append(event)
        self._current_window_count += 1
        return True

    def add_events(self, events: List[Dict[str, Any]]) -> int:
        """Add multiple audit events."""
        added = 0
        for ev in events:
            if self.add_event(ev):
                added += 1
        return added

    def clear(self) -> None:
        """Clear all events in feed."""
        self._events.clear()
        self._seen_ids.clear()

    def get_events(self) -> List[Dict[str, Any]]:
        """Return shallow copy of all events currently buffered."""
        return list(self._events)

    def render(self, max_display_rows: int = 12) -> Panel:
        """Render the telemetry event log panel."""
        if not self._events:
            placeholder = (
                "[dim italic]Waiting for telemetry events from daemon...\n"
                "All intercepted commands, taints, and vault operations stream live here.[/dim italic]"
            )
            return Panel(
                Text.from_markup(placeholder),
                title=f"[bold yellow]{self.title}[/bold yellow]",
                border_style="yellow",
            )

        events_slice = list(self._events)[-max_display_rows:]
        lines: List[str] = []

        for ev in events_slice:
            if not isinstance(ev, dict):
                continue

            time_str = format_event_timestamp(ev.get("timestamp"))
            badge = format_event_badge(ev.get("event_type", ""), ev.get("status", ""))
            raw_sid = ev.get("session_id") or (f"pid:{ev.get('pid')}" if ev.get("pid") else "--")
            sid = str(raw_sid)
            if len(sid) > 16:
                sid = sid[:14] + ".."
            sid_escaped = escape(f"{sid:<16}")

            summary = format_event_summary(ev.get("details", {}))
            ev_type = str(ev.get("event_type", "")).strip()
            type_str = f"[dim]{escape(ev_type)}[/dim] " if ev_type else ""
            lines.append(f"[dim]{escape(time_str)}[/dim]  {badge}  {type_str}[cyan]{sid_escaped}[/cyan]  {summary}")

        content = Text.from_markup("\n".join(lines))
        now = time.time()
        if now - self._last_tick_time >= 1.0:
            self._rate_history.append(self._current_window_count)
            self._current_window_count = 0
            self._last_tick_time = now

        spark = render_sparkline(list(self._rate_history), width=8)
        recent_rate = sum(list(self._rate_history)[-5:]) / 5.0
        rate_str = f"  [dim cyan][{spark}] {recent_rate:.1f} ev/s[/dim cyan]"

        return Panel(
            content,
            title=f"[bold yellow]{escape(self.title)}[/bold yellow]  [dim]({len(self._events)} total)[/dim]{rate_str}",
            border_style="yellow",
        )


def render_telemetry_feed(
    events: List[Dict[str, Any]],
    max_rows: int = 12,
    title: str = "📜 Live Audited Telemetry Feed",
) -> Panel:
    """Functional convenience wrapper to render telemetry events list."""
    feed = TelemetryFeedWidget(max_events=len(events) + 10, title=title)
    feed.add_events(events)
    return feed.render(max_display_rows=max_rows)
