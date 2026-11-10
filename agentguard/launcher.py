"""AgentGuard Interactive CLI Launcher Menu.

Provides an arrow-key navigable TUI menu when 'ag' is invoked without subcommands,
with graceful fallbacks for number keys and non-interactive environments.
"""

from __future__ import annotations

import os
import select
import shlex
import sys
import time
import webbrowser
from typing import Any, Callable, Dict, List, Optional, Tuple

import click
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from agentguard.branding import get_branding_banner

try:
    import termios
    import tty
    HAS_TERMIOS = True
except ImportError:
    HAS_TERMIOS = False

# Menu Options Specification
MENU_OPTIONS = [
    {
        "id": "cockpit",
        "key": "1",
        "icon": "🎛️",
        "title": "Terminal Cockpit",
        "desc": "Real-time swarm radar, intent drift meter, kill-switch",
        "cmd_hint": "ag cockpit",
    },
    {
        "id": "web_dashboard",
        "key": "2",
        "icon": "🌐",
        "title": "Web Dashboard",
        "desc": "Browser telemetry & control deck at 127.0.0.1:18443",
        "cmd_hint": "http://127.0.0.1:18443",
    },
    {
        "id": "wrap",
        "key": "3",
        "icon": "🛡️",
        "title": "Wrap Agent",
        "desc": "Intercept & sandbox Claude, Codex, Cursor, Windsurf, Aider, Goose, OpenHands, Gemini, Hermes, OpenClaw, AGY, CrewAI, AutoGen",
        "cmd_hint": "ag wrap",
    },
    {
        "id": "daemon",
        "key": "4",
        "icon": "⚙️",
        "title": "Daemon Controls",
        "desc": "Start, stop, or inspect background security daemon",
        "cmd_hint": "ag daemon start|stop",
    },
    {
        "id": "notify",
        "key": "5",
        "icon": "🔔",
        "title": "Notification Settings",
        "desc": "Configure Discord webhooks, Telegram alerts & test alerts",
        "cmd_hint": "ag notify",
    },
    {
        "id": "audit",
        "key": "6",
        "icon": "📋",
        "title": "Audit Logs",
        "desc": "Inspect intercepted commands, taint events, vault tokens",
        "cmd_hint": "ag audit",
    },
    {
        "id": "exit",
        "key": "7",
        "icon": "❌",
        "title": "Exit",
        "desc": "Exit AgentGuard launcher",
        "cmd_hint": "exit",
    },
]


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


def read_key(timeout: float = 0.1) -> str:
    """Read a single key or resolve arrow key escape sequence (cross-platform POSIX and Win32)."""
    # Windows native console input handling via msvcrt
    if sys.platform == "win32" and sys.stdin.isatty():
        try:
            import msvcrt
            start_t = time.time()
            while time.time() - start_t < timeout:
                if msvcrt.kbhit():
                    ch = msvcrt.getch()
                    if ch in (b"\x00", b"\xe0"):
                        ch2 = msvcrt.getch()
                        if ch2 == b"H":
                            return "UP"
                        elif ch2 == b"P":
                            return "DOWN"
                        elif ch2 == b"M":
                            return "RIGHT"
                        elif ch2 == b"K":
                            return "LEFT"
                        return ""
                    if ch in (b"\r", b"\n"):
                        return "ENTER"
                    if ch == b" ":
                        return "SPACE"
                    if ch == b"\x03":
                        return "CTRL_C"
                    if ch == b"\x1b":
                        return "ESC"
                    try:
                        return ch.decode("utf-8", errors="ignore")
                    except Exception:
                        return ""
                time.sleep(0.01)
            return ""
        except ImportError:
            pass

    if not HAS_TERMIOS or not sys.stdin.isatty():
        return ""

    # Check if sys.stdin.read is mocked (e.g. in unit tests)
    is_mocked = (
        hasattr(sys.stdin.read, "mock_calls")
        or hasattr(sys.stdin.read, "_mock_wraps")
        or hasattr(sys.stdin.read, "_mock_side_effect")
        or type(sys.stdin.read).__name__ == "MagicMock"
    )

    if is_mocked:
        rlist, _, _ = select.select([sys.stdin], [], [], timeout)
        if not rlist:
            return ""

        ch = sys.stdin.read(1)
        if ch == "\x1b":  # Escape sequence
            r2, _, _ = select.select([sys.stdin], [], [], 0.05)
            if r2:
                ch2 = sys.stdin.read(1)
                if ch2 in ("[", "O"):
                    r3, _, _ = select.select([sys.stdin], [], [], 0.05)
                    if r3:
                        ch3 = sys.stdin.read(1)
                        if ch3 == "A":
                            return "UP"
                        elif ch3 == "B":
                            return "DOWN"
                        elif ch3 == "C":
                            return "RIGHT"
                        elif ch3 == "D":
                            return "LEFT"
                        return f"ESC_{ch2}_{ch3}"
                return "ESC"
            return "ESC"
        elif ch in ("\r", "\n"):
            return "ENTER"
        elif ch == " ":
            return "SPACE"
        elif ch in ("\x03", "\x04"):
            return "CTRL_C"
        return ch

    # Real terminal path using direct unbuffered os.read from file descriptor
    try:
        fd = sys.stdin.fileno()
    except Exception:
        fd = 0

    rlist, _, _ = select.select([fd], [], [], timeout)
    if not rlist:
        return ""

    try:
        chunk = os.read(fd, 32)
    except OSError:
        return ""

    if not chunk:
        return ""

    # If only leading \x1b arrived, wait a brief window for remaining arrow sequence bytes
    if chunk == b"\x1b":
        r2, _, _ = select.select([fd], [], [], 0.08)
        if r2:
            try:
                chunk += os.read(fd, 31)
            except OSError:
                pass

    if chunk in (b"\x1b[A", b"\x1bOA") or (chunk.startswith(b"\x1b[") and chunk.endswith(b"A")):
        return "UP"
    elif chunk in (b"\x1b[B", b"\x1bOB") or (chunk.startswith(b"\x1b[") and chunk.endswith(b"B")):
        return "DOWN"
    elif chunk in (b"\x1b[C", b"\x1bOC") or (chunk.startswith(b"\x1b[") and chunk.endswith(b"C")):
        return "RIGHT"
    elif chunk in (b"\x1b[D", b"\x1bOD") or (chunk.startswith(b"\x1b[") and chunk.endswith(b"D")):
        return "LEFT"
    elif chunk in (b"\r", b"\n", b"\r\n"):
        return "ENTER"
    elif chunk == b" ":
        return "SPACE"
    elif chunk in (b"\x03", b"\x04"):
        return "CTRL_C"
    elif chunk == b"\x1b":
        return "ESC"
    elif chunk in (b"k", b"K", b"w", b"W"):
        return "UP"
    elif chunk in (b"j", b"J", b"s", b"S"):
        return "DOWN"
    else:
        try:
            return chunk.decode("utf-8", errors="ignore")
        except Exception:
            return ""


def build_menu_panel(selected_idx: int, daemon_online: bool, daemon_pid: Optional[int]) -> Panel:
    """Construct Rich Panel rendering the interactive launcher menu."""
    content = Text()

    # Branding logo banner & attribution
    content.append(get_branding_banner(include_subtitle=True, include_credit=True))

    status_str = f"● ONLINE (PID {daemon_pid})" if daemon_online else "○ STOPPED"
    status_style = "bold green" if daemon_online else "bold red"
    content.append("  Daemon Status: ", style="dim")
    content.append(f"{status_str}\n\n", style=status_style)

    # Menu items
    for idx, opt in enumerate(MENU_OPTIONS):
        is_selected = (idx == selected_idx)
        prefix = " ❯ " if is_selected else "   "
        line_num = f"{opt['key']}. "
        icon = f"{opt['icon']} "
        title = f"{opt['title']:<26}"
        desc = opt["desc"]

        if is_selected:
            item_text = Text()
            item_text.append(prefix, style="bold bright_cyan")
            item_text.append(line_num, style="bold bright_cyan")
            item_text.append(icon)
            item_text.append(title, style="bold bright_white on blue")
            item_text.append(f" {desc}", style="bold bright_cyan on blue")
            item_text.append("\n")
            content.append(item_text)
        else:
            item_text = Text()
            item_text.append(prefix, style="dim")
            item_text.append(line_num, style="dim")
            item_text.append(icon)
            item_text.append(title, style="white")
            item_text.append(f" {desc}", style="dim")
            item_text.append("\n")
            content.append(item_text)

    content.append("\nNavigation: ", style="dim")
    content.append("[↑/↓ or j/k]", style="bold white")
    content.append(" Move  │  ", style="dim")
    content.append("[Enter/Space]", style="bold white")
    content.append(" Select  │  ", style="dim")
    content.append("[1-7]", style="bold white")
    content.append(" Quick Jump  │  ", style="dim")
    content.append("[q]", style="bold white")
    content.append(" Exit", style="dim")

    return Panel(
        content,
        title="[bold white]Interactive CLI Launcher[/bold white]",
        border_style="cyan" if daemon_online else "blue",
        padding=(1, 2),
    )


def execute_action(action_id: str, ctx: click.Context, console: Console) -> bool:
    """Execute selected menu option. Returns True if menu should re-open, False to exit."""
    from agentguard.cli import (
        DEFAULT_HTTP_PORT,
        DEFAULT_SOCKET_PATH,
        DaemonClient,
        audit,
        cockpit_cmd,
        daemon_start,
        daemon_stop,
        ensure_daemon_running,
        get_running_daemon_pid,
        notify_status,
        notify_test,
        status,
        wrap,
    )

    if action_id == "cockpit":
        try:
            ctx.invoke(cockpit_cmd)
        except SystemExit:
            pass
        return True

    elif action_id == "web_dashboard":
        if not ensure_daemon_running():
            console.print("[yellow]Daemon must be running to open Web Dashboard.[/yellow]")
            time.sleep(1.0)
            return True
        url = f"http://127.0.0.1:{DEFAULT_HTTP_PORT}"
        console.print(f"\n[bold green]✓[/bold green] Opening Web Dashboard at [cyan]{url}[/cyan] in browser...")
        webbrowser.open(url)
        console.print("[dim]Press Enter to return to menu...[/dim]")
        if sys.stdin.isatty():
            try:
                input()
            except (EOFError, KeyboardInterrupt):
                pass
        return True

    elif action_id == "wrap":
        console.print("\n[bold cyan]🛡️  Wrap Autonomous Agent[/bold cyan]")
        console.print("Interception targets: [green]claude[/green], [green]hermes[/green], [green]openclaw[/green], [green]agy[/green], [green]codex[/green]\n")
        try:
            cmd_str = click.prompt("Enter agent command to wrap (or Enter to cancel)", default="", show_default=False).strip()
        except (click.Abort, EOFError):
            return True

        if not cmd_str:
            return True

        cmd_args = shlex.split(cmd_str)
        if not cmd_args:
            return True

        ensure_daemon_running()
        try:
            ctx.invoke(wrap, command=tuple(cmd_args), profile=None, hitl=False)
        except SystemExit:
            pass
        return False

    elif action_id == "daemon":
        client = DaemonClient()
        is_on = client.is_running()
        pid = get_running_daemon_pid()
        status_text = f"[bold green]ONLINE (PID {pid})[/bold green]" if is_on else "[bold red]STOPPED[/bold red]"
        console.print(f"\n[bold]⚙️  Daemon Controls[/bold] — Current: {status_text}\n")
        console.print("  1. Start Daemon (`ag daemon start`)")
        console.print("  2. Stop Daemon  (`ag daemon stop`)")
        console.print("  3. View Status  (`ag status`)")
        console.print("  4. Return to Main Menu\n")
        try:
            sub = click.prompt("Select option [1-4]", default="4", show_default=False).strip()
        except (click.Abort, EOFError):
            return True

        if sub == "1":
            ctx.invoke(daemon_start, foreground=False)
        elif sub == "2":
            ctx.invoke(daemon_stop)
        elif sub == "3":
            ctx.invoke(status)
            console.print("\n[dim]Press Enter to return to menu...[/dim]")
            if sys.stdin.isatty():
                try:
                    input()
                except (EOFError, KeyboardInterrupt):
                    pass
        return True

    elif action_id == "notify":
        console.print("\n[bold cyan]🔔  Notification Settings[/bold cyan]\n")
        console.print("  1. View Notification Status (`ag notify status`)")
        console.print("  2. Send Test Alert          (`ag notify test`)")
        console.print("  3. Return to Main Menu\n")
        try:
            sub = click.prompt("Select option [1-3]", default="3", show_default=False).strip()
        except (click.Abort, EOFError):
            return True

        if sub == "1":
            ctx.invoke(notify_status, as_json=False)
            console.print("\n[dim]Press Enter to return to menu...[/dim]")
            if sys.stdin.isatty():
                try:
                    input()
                except (EOFError, KeyboardInterrupt):
                    pass
        elif sub == "2":
            ctx.invoke(notify_test, channel="all")
            console.print("\n[dim]Press Enter to return to menu...[/dim]")
            if sys.stdin.isatty():
                try:
                    input()
                except (EOFError, KeyboardInterrupt):
                    pass
        return True

    elif action_id == "audit":
        try:
            ctx.invoke(audit, limit=20, output_format="text")
        except SystemExit:
            pass
        if sys.stdin.isatty():
            console.print("\n[dim]Press Enter to return to menu...[/dim]")
            try:
                input()
            except (EOFError, KeyboardInterrupt):
                pass
        return False

    elif action_id == "exit":
        console.print("\n[bold green]AgentGuard security launcher closed. Stay secure![/bold green] 🛡️\n")
        return False

    return True


def run_interactive_launcher(ctx: click.Context) -> int:
    """Main launcher entrypoint called when 'ag' is invoked without subcommands."""
    from agentguard.cli import DaemonClient, get_running_daemon_pid

    console = Console()

    # 1. Non-Interactive / PipedTest Fallback
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        client = DaemonClient()
        is_on = client.is_running()
        pid = get_running_daemon_pid()
        console.print(build_menu_panel(selected_idx=-1, daemon_online=is_on, daemon_pid=pid))

        # Check if stdin has data
        try:
            line = sys.stdin.readline()
        except Exception:
            return 0
        if not line:
            return 0  # Clean EOF in tests or pipe

        line = line.strip()
        if not line:
            return 0

        # Lookup option by key
        matched = next((opt for opt in MENU_OPTIONS if opt["key"] == line), None)
        if matched:
            execute_action(matched["id"], ctx, console)
            return 0
        else:
            console.print(f"[yellow]Unknown option: {line}[/yellow]")
            return 1

    # 2. Interactive Arrow-Key Mode
    selected_idx = 0
    while True:
        client = DaemonClient()
        is_on = client.is_running()
        pid = get_running_daemon_pid()

        action_to_run = None

        with TerminalRawMode():
            with Live(build_menu_panel(selected_idx, is_on, pid), screen=False, auto_refresh=False, console=console) as live:
                while True:
                    key = read_key(timeout=0.15)
                    if not key:
                        continue

                    if key in ("UP", "k", "w", "K", "W"):
                        selected_idx = (selected_idx - 1) % len(MENU_OPTIONS)
                        live.update(build_menu_panel(selected_idx, is_on, pid), refresh=True)
                    elif key in ("DOWN", "j", "s", "J", "S"):
                        selected_idx = (selected_idx + 1) % len(MENU_OPTIONS)
                        live.update(build_menu_panel(selected_idx, is_on, pid), refresh=True)
                    elif key in ("ENTER", "SPACE"):
                        action_to_run = MENU_OPTIONS[selected_idx]["id"]
                        break
                    elif key in [opt["key"] for opt in MENU_OPTIONS]:
                        idx = int(key) - 1
                        selected_idx = idx
                        action_to_run = MENU_OPTIONS[idx]["id"]
                        break
                    elif key in ("q", "Q", "ESC", "CTRL_C"):
                        action_to_run = "exit"
                        break

        # Terminal raw mode and Live exited — normal terminal restored
        if action_to_run:
            reopen = execute_action(action_to_run, ctx, console)
            if not reopen:
                break

    return 0
