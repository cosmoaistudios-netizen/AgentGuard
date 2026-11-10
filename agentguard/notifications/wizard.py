"""AgentGuard Notification Setup Wizard.

Interactive terminal wizard for configuring Discord Webhooks, Telegram Bots,
scheduled health heartbeats, and alert thresholds. Inspired by Hermes & OpenClaw CLI UX.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
import sys
from typing import Any, Dict, Optional, Tuple
import urllib.error
import urllib.request

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

from agentguard.branding import BRAND_CREDIT, BRAND_NAME, get_ascii_logo_text
from agentguard.notifications.config import (
    NotificationConfig,
    get_notifications_config_path,
    load_notification_config,
    save_notification_config,
)
from agentguard.notifications.discord import (
    COLOR_CRITICAL,
    COLOR_SUCCESS,
    COLOR_WARNING,
    build_discord_alert,
    send_discord_payload,
)
from agentguard.notifications.telegram import (
    format_telegram_threat_alert,
    send_telegram_payload,
)


def _mask_secret(val: Optional[str], show_chars: int = 4) -> str:
    """Masks sensitive tokens/urls for safe terminal rendering."""
    if not val:
        return "[dim]None[/dim]"
    clean = str(val).strip()
    if len(clean) <= show_chars * 2:
        return "*" * len(clean)
    return f"{clean[:show_chars]}...{clean[-show_chars:]}"


def _mask_webhook_url(url: Optional[str]) -> str:
    """Masks Discord webhook token while preserving server ID visibility."""
    if not url:
        return "[dim]Not Configured[/dim]"
    clean = str(url).strip()
    # Discord format: https://discord.com/api/webhooks/<id>/<token>
    m = re.match(r"(https?://[^/]+/api/webhooks/\d+/)(.+)", clean)
    if m:
        base, token = m.group(1), m.group(2)
        masked_tok = token[:4] + "..." + token[-4:] if len(token) > 8 else "********"
        return f"{base}{masked_tok}"
    return _mask_secret(clean, show_chars=8)


class NotificationSetupWizard:
    """Interactive CLI setup wizard for AgentGuard notification channels."""

    def __init__(
        self,
        config_path: Optional[Path] = None,
        console: Optional[Console] = None,
    ):
        self.console = console or Console()
        self.config_path = config_path or get_notifications_config_path()
        self.config = load_notification_config(config_path=self.config_path)

    def print_banner(self) -> None:
        """Renders the stylized AgentGuard notification wizard header."""
        self.console.clear()
        logo_text = get_ascii_logo_text(prefix_spaces=2)
        self.console.print(logo_text)
        self.console.print(
            Panel(
                Text.from_markup(
                    f"[bold white]{BRAND_NAME} Sentinel — Notification Channels Setup[/bold white]\n"
                    f"[cyan]Real-time threat alerting for Discord & Telegram[/cyan] • [dim italic]{BRAND_CREDIT}[/dim italic]"
                ),
                border_style="bright_blue",
                padding=(0, 2),
            )
        )
        self.console.print()

    def render_status_table(self) -> None:
        """Renders current configuration table with color-coded health badges."""
        table = Table(
            title="Active Notification Channels",
            title_style="bold bright_cyan",
            border_style="dim",
            header_style="bold cyan",
            expand=True,
        )
        table.add_column("Channel", style="bold white", width=18)
        table.add_column("Status", width=16)
        table.add_column("Target / Endpoint", style="dim", ratio=1)
        table.add_column("Health / Mode", width=18)

        # Discord
        if self.config.discord.enabled and self.config.discord.webhook_url:
            discord_status = "[bold green]ACTIVE[/bold green]"
            discord_mode = "[green]Rich Embeds[/green]"
        elif self.config.discord.webhook_url:
            discord_status = "[yellow]CONFIGURED (OFF)[/yellow]"
            discord_mode = "[yellow]Paused[/yellow]"
        else:
            discord_status = "[dim]NOT CONFIGURED[/dim]"
            discord_mode = "[dim]Disabled[/dim]"
        table.add_row(
            "Discord Webhook",
            discord_status,
            _mask_webhook_url(self.config.discord.webhook_url),
            discord_mode,
        )

        # Telegram
        has_tg = bool(self.config.telegram.bot_token and self.config.telegram.chat_id)
        if self.config.telegram.enabled and has_tg:
            tg_status = "[bold green]ACTIVE[/bold green]"
            tg_mode = f"[green]Chat: {self.config.telegram.chat_id}[/green]"
        elif has_tg:
            tg_status = "[yellow]CONFIGURED (OFF)[/yellow]"
            tg_mode = "[yellow]Paused[/yellow]"
        elif self.config.telegram.bot_token or self.config.telegram.chat_id:
            tg_status = "[bold red]INCOMPLETE[/bold red]"
            tg_mode = "[red]Missing Token/Chat[/red]"
        else:
            tg_status = "[dim]NOT CONFIGURED[/dim]"
            tg_mode = "[dim]Disabled[/dim]"
        tg_target = f"Bot: {_mask_secret(self.config.telegram.bot_token, 4)} | Chat: {self.config.telegram.chat_id or 'None'}"
        table.add_row(
            "Telegram Bot",
            tg_status,
            tg_target,
            tg_mode,
        )

        # Heartbeat
        hb_status = "[bold green]ACTIVE[/bold green]" if self.config.heartbeat.enabled else "[dim]DISABLED[/dim]"
        hb_mode = f"Every {self.config.heartbeat.interval_seconds}s"
        table.add_row(
            "Heartbeat Health",
            hb_status,
            f"Scheduled telemetry broadcast ({self.config.heartbeat.interval_seconds // 60}m)",
            hb_mode,
        )

        # Master Alerting Toggle
        master_status = "[bold green]ENABLED[/bold green]" if self.config.enabled else "[bold red]MUTED[/bold red]"
        sev_mode = f"Min Severity: [bold cyan]{self.config.min_severity}[/bold cyan]"
        table.add_row(
            "Global Sentinel",
            master_status,
            f"Config file: {self.config_path}",
            sev_mode,
        )

        self.console.print(table)
        self.console.print()

    def configure_discord(self) -> None:
        """Step-by-step interactive setup for Discord Webhook."""
        self.console.print(
            Panel(
                "[bold white]Step 1: Discord Webhook Setup[/bold white]\n\n"
                "[cyan]How to get your Discord Webhook URL:[/cyan]\n"
                "1. Open your Discord Server Settings -> [bold]Integrations[/bold] -> [bold]Webhooks[/bold].\n"
                "2. Click [bold]'New Webhook'[/bold] and name it [bold]'AgentGuard Sentinel'[/bold].\n"
                "3. Select your designated alert channel (e.g. [italic]#security-alerts[/italic]).\n"
                "4. Click [bold]'Copy Webhook URL'[/bold] and paste it below.\n\n"
                "[dim]Format: https://discord.com/api/webhooks/<id>/<token>[/dim]",
                title="Discord Integration Guide",
                border_style="magenta",
            )
        )

        current_url = self.config.discord.webhook_url
        if current_url:
            self.console.print(f"Current Webhook: [cyan]{_mask_webhook_url(current_url)}[/cyan]")
            action = Prompt.ask(
                "Options: [bold][K][/bold]eep current, [bold][R][/bold]eplace, [bold][D][/bold]isable",
                choices=["k", "r", "d"],
                default="k",
            )
            if action == "k":
                self.config.discord.enabled = True
                self._prompt_test_discord()
                return
            elif action == "d":
                self.config.discord.enabled = False
                self.console.print("[yellow]Discord alerts disabled.[/yellow]\n")
                return

        webhook_url = Prompt.ask("Enter Discord Webhook URL (or press Enter to cancel)").strip()
        if not webhook_url:
            self.console.print("[dim]Discord configuration skipped.[/dim]\n")
            return

        if not (webhook_url.startswith("http://") or webhook_url.startswith("https://")):
            self.console.print("[bold red]Invalid URL! Must start with http:// or https://[/bold red]\n")
            return

        self.config.discord.webhook_url = webhook_url
        self.config.discord.enabled = True
        self.console.print("[bold green]✓ Discord webhook URL saved.[/bold green]")

        self._prompt_test_discord()

    def _prompt_test_discord(self) -> None:
        """Offers to send an immediate verification alert to Discord."""
        if not self.config.discord.webhook_url:
            return

        test_now = Confirm.ask("Send a live test alert to Discord now?", default=True)
        if not test_now:
            return

        with self.console.status("[cyan]Dispatching test alert to Discord webhook...[/cyan]"):
            test_payload = build_discord_alert(
                event_type="SYNTHETIC_TEST",
                details={
                    "command": "ag notify test --channel discord",
                    "reason": "AgentGuard notification channel verified via interactive wizard",
                    "session_id": "sentinel-setup-wizard",
                    "pid": 1337,
                    "profile": "antigravity",
                    "taint_state": "CLEAN",
                },
                severity="SUCCESS",
            )
            try:
                success = send_discord_payload(
                    webhook_url=self.config.discord.webhook_url,
                    payload=test_payload,
                    timeout=6.0,
                )
                if success:
                    self.console.print("[bold green]✓ [SUCCESS] Test alert delivered to Discord channel![/bold green]\n")
                else:
                    self.console.print("[bold red]✗ [FAILED] Discord returned non-success HTTP status.[/bold red]\n")
            except Exception as exc:
                self.console.print(f"[bold red]✗ [FAILED] Error connecting to Discord: {exc}[/bold red]\n")

    def configure_telegram(self) -> None:
        """Step-by-step interactive setup for Telegram Bot."""
        self.console.print(
            Panel(
                "[bold white]Step 2: Telegram Bot API Setup[/bold white]\n\n"
                "[cyan]How to configure Telegram alerting:[/cyan]\n"
                "1. Open Telegram and search for [bold]@BotFather[/bold].\n"
                "2. Send [bold]/newbot[/bold] and follow instructions to get your [bold]Bot API Token[/bold].\n"
                "3. Open a direct chat with your new bot and click [bold]Start[/bold] (or add bot to your alerts group).\n"
                "4. Find your Chat ID (message [bold]@userinfobot[/bold] or add bot to a group and check ID).\n\n"
                "[dim]Token format: 123456789:ABCdefGHIjklMNOpqrSTUvwxYZ\n"
                "Chat ID format: 123456789 (user) or -1001234567890 (group/channel)[/dim]",
                title="Telegram Integration Guide",
                border_style="blue",
            )
        )

        current_token = self.config.telegram.bot_token
        current_chat = self.config.telegram.chat_id

        if current_token and current_chat:
            self.console.print(
                f"Current Config: Bot [cyan]{_mask_secret(current_token, 4)}[/cyan] | Chat [cyan]{current_chat}[/cyan]"
            )
            action = Prompt.ask(
                "Options: [bold][K][/bold]eep current, [bold][R][/bold]eplace, [bold][D][/bold]isable",
                choices=["k", "r", "d"],
                default="k",
            )
            if action == "k":
                self.config.telegram.enabled = True
                self._prompt_test_telegram()
                return
            elif action == "d":
                self.config.telegram.enabled = False
                self.console.print("[yellow]Telegram alerts disabled.[/yellow]\n")
                return

        bot_token = Prompt.ask("Enter Telegram Bot API Token (or press Enter to cancel)").strip()
        if not bot_token:
            self.console.print("[dim]Telegram configuration skipped.[/dim]\n")
            return

        chat_id = Prompt.ask("Enter Telegram Target Chat ID (e.g. user ID or group ID)").strip()
        if not chat_id:
            self.console.print("[yellow]Missing Chat ID! Telegram alerting requires both Token and Chat ID.[/yellow]\n")
            return

        self.config.telegram.bot_token = bot_token
        self.config.telegram.chat_id = chat_id
        self.config.telegram.enabled = True
        self.console.print("[bold green]✓ Telegram bot credentials saved.[/bold green]")

        self._prompt_test_telegram()

    def _prompt_test_telegram(self) -> None:
        """Offers to send an immediate verification alert to Telegram."""
        if not (self.config.telegram.bot_token and self.config.telegram.chat_id):
            return

        test_now = Confirm.ask("Send a live test alert to Telegram now?", default=True)
        if not test_now:
            return

        with self.console.status("[cyan]Dispatching test alert to Telegram Bot API...[/cyan]"):
            test_payload = format_telegram_threat_alert(
                event_type="SYNTHETIC_TEST",
                details={
                    "command": "ag notify test --channel telegram",
                    "reason": "AgentGuard Telegram bot verified via interactive wizard",
                    "session_id": "sentinel-setup-wizard",
                    "pid": 1337,
                    "profile": "antigravity",
                    "taint_state": "CLEAN",
                },
                severity="SUCCESS",
                config=self.config.telegram,
            )
            try:
                success = send_telegram_payload(
                    bot_token=self.config.telegram.bot_token,
                    chat_id=self.config.telegram.chat_id,
                    text=test_payload["text"],
                    parse_mode=test_payload.get("parse_mode", "HTML"),
                    timeout=6.0,
                )
                if success:
                    self.console.print("[bold green]✓ [SUCCESS] Test alert delivered to Telegram chat![/bold green]\n")
                else:
                    self.console.print("[bold red]✗ [FAILED] Telegram Bot API returned non-success HTTP status.[/bold red]\n")
            except Exception as exc:
                self.console.print(f"[bold red]✗ [FAILED] Error connecting to Telegram: {exc}[/bold red]\n")

    def configure_preferences(self) -> None:
        """Configures heartbeat intervals and minimum alert severity thresholds."""
        self.console.print(
            Panel(
                "[bold white]Step 3: Alert Preferences & Heartbeat[/bold white]\n\n"
                "[cyan]Filter alert volume and configure periodic health telemetries.[/cyan]",
                border_style="cyan",
            )
        )

        # Master alert toggle
        self.config.enabled = Confirm.ask(
            "Enable Sentinel Alert Dispatching globally?",
            default=True,
        )

        # Min Severity
        sev_choice = Prompt.ask(
            "Minimum alert severity threshold",
            choices=["INFO", "WARNING", "CRITICAL"],
            default=self.config.min_severity or "WARNING",
        )
        self.config.min_severity = sev_choice

        # Heartbeat
        hb_enabled = Confirm.ask(
            "Enable periodic system health heartbeats?",
            default=self.config.heartbeat.enabled,
        )
        self.config.heartbeat.enabled = hb_enabled

        if hb_enabled:
            current_interval = self.config.heartbeat.interval_seconds
            interval_str = Prompt.ask(
                "Heartbeat interval in seconds (e.g. 300 for 5m, 3600 for 1h)",
                default=str(current_interval),
            )
            try:
                val = int(interval_str)
                self.config.heartbeat.interval_seconds = max(10, val)
            except ValueError:
                pass

        self.console.print("[bold green]✓ Alert preferences updated.[/bold green]\n")

    def test_all_channels(self) -> None:
        """Sends a verification test to all currently configured channels."""
        self.console.print("[bold cyan]Dispatching test alerts to all configured channels...[/bold cyan]")

        has_channels = False
        if self.config.discord.webhook_url and self.config.discord.enabled:
            has_channels = True
            self._prompt_test_discord()

        if self.config.telegram.bot_token and self.config.telegram.chat_id and self.config.telegram.enabled:
            has_channels = True
            self._prompt_test_telegram()

        if not has_channels:
            self.console.print("[yellow]No active channels configured to test! Please configure Discord or Telegram first.[/yellow]\n")

    def save_and_finish(self) -> None:
        """Saves configuration to disk with strict permissions and displays next steps."""
        # Automatically enable master toggle if any channel is active
        if self.config.discord.enabled or self.config.telegram.enabled:
            self.config.enabled = True

        save_notification_config(self.config, config_path=self.config_path)

        summary = Text.from_markup(
            f"[bold green]✓ Notification configuration successfully saved![/bold green]\n\n"
            f"[bold white]File Location:[/bold white] [cyan]{self.config_path}[/cyan] [dim](mode 0600 - secure)[/dim]\n"
            f"[bold white]Global Sentinel:[/bold white] {'[green]ENABLED[/green]' if self.config.enabled else '[red]DISABLED[/red]'}\n"
            f"[bold white]Discord Alerting:[/bold white] {'[green]ACTIVE[/green]' if self.config.discord.enabled else '[dim]OFF[/dim]'}\n"
            f"[bold white]Telegram Alerting:[/bold white] {'[green]ACTIVE[/green]' if self.config.telegram.enabled else '[dim]OFF[/dim]'}\n"
            f"[bold white]Health Heartbeat:[/bold white] {'[green]ACTIVE (' + str(self.config.heartbeat.interval_seconds) + 's)[/green]' if self.config.heartbeat.enabled else '[dim]OFF[/dim]'}\n\n"
            f"[bold cyan]Useful Next Commands:[/bold cyan]\n"
            f"• [bold]ag notify test[/bold]       — Send a test threat alert\n"
            f"• [bold]ag notify status[/bold]     — View current credentials and channels\n"
            f"• [bold]ag daemon start[/bold]      — Start AgentGuard zero-trust supervisor\n"
            f"• [bold]ag cockpit[/bold]           — Open real-time terminal telemetry cockpit"
        )

        self.console.print(
            Panel(
                summary,
                title="Configuration Complete",
                border_style="green",
                padding=(1, 2),
            )
        )

    def run(self) -> NotificationConfig:
        """Main interactive wizard loop."""
        while True:
            self.print_banner()
            self.render_status_table()

            self.console.print("[bold white]Wizard Options:[/bold white]")
            self.console.print("  [bold cyan]1[/bold cyan] — Configure Discord Webhook")
            self.console.print("  [bold cyan]2[/bold cyan] — Configure Telegram Bot")
            self.console.print("  [bold cyan]3[/bold cyan] — Configure Alert Severity & Heartbeat Telemetry")
            self.console.print("  [bold cyan]4[/bold cyan] — Full Guided Setup (All Channels)")
            self.console.print("  [bold cyan]5[/bold cyan] — Send Test Alert to Active Channels")
            self.console.print("  [bold cyan]6[/bold cyan] — Save Configuration & Exit")
            self.console.print("  [bold cyan]q[/bold cyan] — Exit Without Saving")
            self.console.print()

            choice = Prompt.ask("Select an option", choices=["1", "2", "3", "4", "5", "6", "q"], default="6")

            if choice == "1":
                self.configure_discord()
                Prompt.ask("\nPress Enter to return to main menu")
            elif choice == "2":
                self.configure_telegram()
                Prompt.ask("\nPress Enter to return to main menu")
            elif choice == "3":
                self.configure_preferences()
                Prompt.ask("\nPress Enter to return to main menu")
            elif choice == "4":
                self.configure_discord()
                self.configure_telegram()
                self.configure_preferences()
                self.save_and_finish()
                break
            elif choice == "5":
                self.test_all_channels()
                Prompt.ask("\nPress Enter to return to main menu")
            elif choice == "6":
                self.save_and_finish()
                break
            elif choice.lower() == "q":
                self.console.print("[dim]Wizard exited without saving changes.[/dim]")
                break

        return self.config


def launch_notification_wizard(
    config_path: Optional[Path] = None,
    console: Optional[Console] = None,
) -> NotificationConfig:
    """Entry point for running the interactive notification setup wizard."""
    wizard = NotificationSetupWizard(config_path=config_path, console=console)
    return wizard.run()
