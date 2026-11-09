"""AgentGuard Cockpit: Flight-Path Intent Drift Meter.

Renders real-time cosine similarity gauge tracking whether an agent's sub-actions
drift from the operator's initial root objective (Safe >= 0.65, Warning < 0.65).
"""

from __future__ import annotations

import math
from typing import Optional

from rich.markup import escape
from rich.panel import Panel
from rich.text import Text

DEFAULT_INTENT_THRESHOLD = 0.65


def format_drift_gauge(
    similarity: Optional[float],
    threshold: float = DEFAULT_INTENT_THRESHOLD,
    width: int = 24,
) -> Text:
    """Format visual cosine similarity gauge bar and flight path status."""
    w = max(0, int(width))
    if similarity is None:
        empty_bar = "░" * w
        return Text.from_markup(
            f"[dim]--.-- [{empty_bar}] AWAITING SUB-ACTIONS (Target ≥ {threshold:.2f})[/dim]"
        )

    try:
        val = float(similarity)
        if math.isnan(val) or math.isinf(val):
            sim = 0.0
        else:
            sim = max(0.0, min(1.0, val))
    except (ValueError, TypeError):
        sim = 0.0

    filled_count = int(round(sim * w))
    empty_count = max(0, w - filled_count)
    bar = "█" * filled_count + "░" * empty_count

    if sim >= threshold:
        return Text.from_markup(
            f"[bold green]{sim:.2f} [{bar}] SAFE (Target ≥ {threshold:.2f})[/bold green]"
        )
    else:
        return Text.from_markup(
            f"[bold red]{sim:.2f} [{bar}] DRIFT WARNING (< {threshold:.2f})[/bold red]"
        )


class IntentDriftGaugeWidget:
    """Widget rendering flight-path intent drift gauge panel."""

    def __init__(
        self,
        threshold: float = DEFAULT_INTENT_THRESHOLD,
        title: str = "🧭 Flight-Path Intent Drift Meter",
    ):
        self.threshold = threshold
        self.title = title

    def render(
        self,
        similarity: Optional[float] = None,
        pid: Optional[int] = None,
        profile: str = "generic",
        root_intent: str = "",
        last_action: str = "",
    ) -> Panel:
        """Render the Intent Drift panel with metadata and gauge bar."""
        gauge_line = format_drift_gauge(similarity, threshold=self.threshold, width=20)

        is_valid_sim = False
        val = 0.0
        if similarity is not None:
            try:
                val = float(similarity)
                if not (math.isnan(val) or math.isinf(val)):
                    is_valid_sim = True
            except (ValueError, TypeError):
                is_valid_sim = False

        is_safe = is_valid_sim and (val >= self.threshold)
        is_warning = is_valid_sim and (val < self.threshold)

        if is_warning:
            status_text = "[bold red]⚠ UNEXPECTED TRAJECTORY: Divergent tool action detected[/bold red]"
            border_style = "red"
        elif is_safe:
            status_text = "[bold green]✓ FLIGHT PATH NOMINAL: Sub-actions aligned with objective[/bold green]"
            border_style = "green"
        else:
            status_text = "[dim italic]Awaiting tool invocations to evaluate trajectory[/dim italic]"
            border_style = "magenta"

        pid_display = str(pid) if pid else "--"
        intent_display = root_intent.strip() if root_intent else "(Default system policy objective)"
        action_display = last_action.strip() if last_action else "(None recorded yet)"

        lines = [
            f"[bold white]Monitored Agent:[/] [cyan]PID {escape(str(pid_display))}[/] [dim]({escape(str(profile))})[/]",
            f"[bold white]Root Objective:[/]  [italic white]\"{escape(intent_display)}\"[/italic white]",
            f"[bold white]Last Action:[/]     [yellow]\"{escape(action_display)}\"[/yellow]",
            "",
            gauge_line.markup,
            status_text,
        ]

        content = Text.from_markup("\n".join(lines))
        return Panel(
            content,
            title=f"[bold magenta]{escape(self.title)}[/bold magenta]",
            border_style=border_style,
        )


def render_intent_drift(
    similarity: Optional[float] = None,
    threshold: float = DEFAULT_INTENT_THRESHOLD,
    pid: Optional[int] = None,
    profile: str = "generic",
    root_intent: str = "",
    last_action: str = "",
) -> Panel:
    """Functional convenience wrapper to render the Intent Drift gauge panel."""
    widget = IntentDriftGaugeWidget(threshold=threshold)
    return widget.render(
        similarity=similarity,
        pid=pid,
        profile=profile,
        root_intent=root_intent,
        last_action=last_action,
    )
