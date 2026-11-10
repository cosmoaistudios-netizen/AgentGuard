"""AgentGuard Command Line Interface.

Provides CLI entry points 'ag' and 'agentguard' for managing the security
daemon, wrapping autonomous agent processes, checking status, and viewing
audit logs.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import click
import yaml

try:
    from agentguard import __version__
except ImportError:
    __version__ = "0.1.0"

from agentguard.config import load_profile

AGENT_PROFILE_MAP: Dict[str, str] = {
    "claude": "claude-code",
    "claude-code": "claude-code",
    "hermes": "hermes",
    "hermes-agent": "hermes",
    "agy": "antigravity",
    "antigravity": "antigravity",
    "openclaw": "openclaw",
    "openclaw-cli": "openclaw",
    "codex": "codex",
    "codex-cli": "codex",
    "cursor": "cursor",
    "cursor-agent": "cursor",
    "windsurf": "windsurf",
    "codeium": "windsurf",
    "aider": "aider",
    "aider-chat": "aider",
    "goose": "goose",
    "goose-cli": "goose",
    "openhands": "openhands",
    "opendevin": "openhands",
    "cline": "cline",
    "roo": "cline",
    "roo-code": "cline",
    "roo_code": "cline",
    "continue": "continue",
    "cn": "continue",
    "gemini": "gemini-cli",
    "gemini-cli": "gemini-cli",
    "qwen": "qwen-code",
    "qwen-code": "qwen-code",
    "qwen-agent": "qwen-code",
    "qwen_agent": "qwen-code",
    "sweagent": "swe-agent",
    "swe-agent": "swe-agent",
    "swe_agent": "swe-agent",
    "crewai": "crewai",
    "langgraph": "crewai",
    "langchain": "crewai",
    "autogen": "autogen",
    "autogenstudio": "autogen",
}


def detect_agent_profile(command: Any) -> Optional[str]:
    """Detect AgentGuard adapter profile from command sequence."""
    if not command:
        return None
    raw_cmd = [str(c) for c in command]
    if not raw_cmd:
        return None

    tokens = list(raw_cmd)
    if tokens and Path(tokens[0]).name.lower() == "env":
        tokens = tokens[1:]
        while tokens and "=" in tokens[0] and not tokens[0].startswith("-"):
            tokens = tokens[1:]
    if not tokens:
        return None

    first = tokens[0]
    first_base = Path(first).name.lower()
    first_stem = Path(first).stem.lower()

    if first_base in AGENT_PROFILE_MAP:
        return AGENT_PROFILE_MAP[first_base]
    if first_stem in AGENT_PROFILE_MAP:
        return AGENT_PROFILE_MAP[first_stem]

    # Handle runner wrappers: python, python3, py, node, npx, bun, uvx, deno
    if first_stem.startswith("python") or first_stem in ("py", "python"):
        if len(tokens) > 1:
            if tokens[1] == "-m" and len(tokens) > 2:
                mod = tokens[2].split(".")[-1].lower()
                if mod in AGENT_PROFILE_MAP:
                    return AGENT_PROFILE_MAP[mod]
            elif not tokens[1].startswith("-"):
                script = Path(tokens[1]).stem.lower()
                if script in AGENT_PROFILE_MAP:
                    return AGENT_PROFILE_MAP[script]

    if first_stem == "node":
        if len(tokens) > 1 and not tokens[1].startswith("-"):
            script_stem = Path(tokens[1]).stem.lower()
            script_base = Path(tokens[1]).name.lower()
            if script_base in AGENT_PROFILE_MAP:
                return AGENT_PROFILE_MAP[script_base]
            if script_stem in AGENT_PROFILE_MAP:
                return AGENT_PROFILE_MAP[script_stem]

    if first_stem in ("npx", "bun", "uvx", "deno"):
        idx = 1
        while idx < len(tokens):
            tok = tokens[idx]
            if tok in ("-y", "--yes", "-q", "--quiet"):
                idx += 1
                continue
            if tok in ("-p", "--package") and idx + 1 < len(tokens):
                idx += 2
                continue
            if tok.startswith("-"):
                idx += 1
                continue
            target_base = Path(tok.split("/")[-1]).name.lower()
            target_stem = Path(tok.split("/")[-1]).stem.lower()
            if target_base in AGENT_PROFILE_MAP:
                return AGENT_PROFILE_MAP[target_base]
            if target_stem in AGENT_PROFILE_MAP:
                return AGENT_PROFILE_MAP[target_stem]
            break

    # General search across all tokens for exact matches (e.g. runner arguments)
    for tok in tokens:
        clean_base = Path(tok).name.lower()
        clean_stem = Path(tok).stem.lower()
        if clean_base in AGENT_PROFILE_MAP:
            return AGENT_PROFILE_MAP[clean_base]
        if clean_stem in AGENT_PROFILE_MAP and clean_stem not in ("main", "run", "start", "exec", "serve", "test"):
            return AGENT_PROFILE_MAP[clean_stem]

    return None


def create_custom_profile(
    name: str,
    agent_command: Optional[str] = None,
    output_dir: Optional[Path] = None,
) -> Path:
    """Create a conservative zero-trust YAML profile for an unknown agent."""
    out_dir = output_dir or (Path.home() / ".agentguard" / "profiles")
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / f"{name}.yaml"
    data = {
        "name": name,
        "description": f"Custom security profile for {name}",
        "agent_command": agent_command or name,
        "shell": {
            "safe_commands": ["ls", "cat", "pwd", "git status"],
            "dangerous_patterns": [r"rm\s+-rf", r"curl.*\|\s*(?:ba)?sh"],
            "block_tainted_only": True,
            "hitl_prompt": False,
        },
        "vault": {
            "enabled": True,
            "entropy_threshold": 4.2,
            "min_token_length": 24,
            "whitelisted_endpoints": [],
            "custom_patterns": [r"sk-[a-zA-Z0-9_-]{20,}"],
            "token_prefix": "AG_VAULT_TOKEN",
        },
        "intent": {
            "enabled": True,
            "drift_threshold": 0.65,
            "block_on_drift": False,
        },
        "filesystem": {
            "monitored_paths": ["."],
            "monitored_extensions": [".md", ".json", ".py", ".sh"],
            "instructional_stripper": {
                "enabled": True,
                "patterns": [r"(?i)(ignore\s+(?:all\s+)?previous\s+instructions)"],
                "replacement_tag": "[DECLARATIVE INACTIVE TEXT: MATCH]",
            },
            "provenance_stamping": True,
        },
    }
    with open(target, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, sort_keys=False)
    return target


def _should_prompt_daemon() -> bool:
    """Check if daemon lifecycle prompt should be presented to user."""
    if sys.stdin.isatty():
        return True
    if type(sys.stdin).__module__ == "click.testing":
        buf = getattr(sys.stdin, "buffer", None)
        return bool(buf and hasattr(buf, "getvalue") and buf.getvalue())
    return False

DEFAULT_SOCKET_PATH = os.environ.get(
    "AGENTGUARD_SOCKET", "/tmp/agentguard.sock"
)
DEFAULT_PID_FILE = os.environ.get(
    "AGENTGUARD_PID_FILE", "/tmp/agentguard.pid"
)
DEFAULT_HTTP_PORT = int(os.environ.get("AGENTGUARD_HTTP_PORT", "18443"))
DEFAULT_AUDIT_FILE = Path.home() / ".agentguard" / "audit.jsonl"
DEFAULT_SHIMS_DIR = Path.home() / ".agentguard" / "shims"


class DaemonClient:
    """Client for Unix Domain Socket IPC communication with daemon."""

    def __init__(
        self, socket_path: str = DEFAULT_SOCKET_PATH, timeout: float = 2.0
    ):
        self.socket_path = socket_path
        self.timeout = timeout

    def is_running(self) -> bool:
        """Check if daemon is reachable and responding."""
        if not os.path.exists(self.socket_path):
            return False
        try:
            res = self.send("GET_STATUS", timeout=0.8)
            return res.get("status") in ("ALLOWED", "OK") or "data" in res
        except (
            FileNotFoundError,
            ConnectionRefusedError,
            socket.timeout,
            ConnectionError,
            OSError,
        ):
            return False

    def send(
        self,
        action: str,
        payload: Optional[Dict[str, Any]] = None,
        session_id: str = "",
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Send a newline-delimited JSON request and return parsed response."""
        sock_timeout = timeout if timeout is not None else self.timeout
        if not os.path.exists(self.socket_path):
            raise FileNotFoundError(
                f"Daemon socket '{self.socket_path}' does not exist."
            )

        req = {
            "protocol_version": "1.0",
            "request_id": str(uuid.uuid4()),
            "session_id": session_id,
            "pid": os.getpid(),
            "action": action,
            "payload": payload or {},
        }
        data = (json.dumps(req) + "\n").encode("utf-8")

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(sock_timeout)
        try:
            sock.connect(self.socket_path)
            sock.sendall(data)

            buf = b""
            while b"\n" not in buf:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk

            if not buf:
                raise ConnectionError(
                    "Daemon closed connection without response."
                )

            line = buf.decode("utf-8").strip().split("\n")[0]
            return json.loads(line)
        finally:
            sock.close()


def get_running_daemon_pid(pid_file: str = DEFAULT_PID_FILE) -> Optional[int]:
    """Return PID if daemon process is currently alive, or None."""
    if not os.path.exists(pid_file):
        return None
    try:
        with open(pid_file, "r", encoding="utf-8") as f:
            pid = int(f.read().strip())
    except (ValueError, OSError):
        return None

    try:
        os.kill(pid, 0)
        return pid
    except OSError:
        # Process is dead; clean up stale PID file
        try:
            os.unlink(pid_file)
        except OSError:
            pass
        return None


def ensure_daemon_running(
    socket_path: str = DEFAULT_SOCKET_PATH,
    pid_file: str = DEFAULT_PID_FILE,
    http_port: int = DEFAULT_HTTP_PORT,
    prompt: bool = True,
) -> bool:
    """Ensure daemon is running; prompt to start it if stopped."""
    client = DaemonClient(socket_path=socket_path)
    if client.is_running():
        return True

    if not prompt:
        return False

    click.echo("AgentGuard security daemon is currently stopped.")
    try:
        confirm = click.prompt(
            "Start daemon now? [Y/n]",
            default="y",
            show_default=False,
        ).strip().lower()
        start_daemon = confirm in ("", "y", "yes")
    except (click.Abort, EOFError):
        start_daemon = False

    if not start_daemon:
        click.echo("Aborted: AgentGuard requires an active daemon.")
        return False

    click.echo("Starting AgentGuard security daemon...")
    cmd = [
        sys.executable,
        "-m",
        "agentguard.cli",
        "daemon",
        "start",
        "--socket",
        socket_path,
        "--http-port",
        str(http_port),
        "--pid-file",
        pid_file,
    ]
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        start_new_session=True,
    )

    deadline = time.time() + 3.0
    while time.time() < deadline:
        time.sleep(0.1)
        if client.is_running():
            click.echo(f"Daemon started successfully (socket: {socket_path}).")
            return True

    click.echo("Error: Timed out waiting for daemon to become active.", err=True)
    return False



def _run_fallback_server(socket_path: str, http_port: int, pid_file: str):
    """Fallback minimal socket daemon for Milestone 1."""
    if os.path.exists(socket_path):
        try:
            os.unlink(socket_path)
        except OSError:
            pass

    Path(socket_path).parent.mkdir(parents=True, exist_ok=True)
    Path(pid_file).parent.mkdir(parents=True, exist_ok=True)

    with open(pid_file, "w", encoding="utf-8") as f:
        f.write(str(os.getpid()))

    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(socket_path)
    srv.listen(10)
    srv.settimeout(0.5)

    running = [True]

    if threading.current_thread() is threading.main_thread():
        def _handle_sig(signum, frame):
            running[0] = False
        try:
            signal.signal(signal.SIGTERM, _handle_sig)
            signal.signal(signal.SIGINT, _handle_sig)
        except (ValueError, AttributeError):
            pass

    active_agents: Dict[str, Dict[str, Any]] = {}
    audit_events: List[Dict[str, Any]] = []
    start_time = time.time()

    try:
        while running[0]:
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            try:
                raw = conn.recv(8192).decode("utf-8").strip()
                if not raw:
                    conn.close()
                    continue

                req = json.loads(raw)
                action = req.get("action")
                sess_id = req.get("session_id", "")
                req_id = req.get("request_id", str(uuid.uuid4()))
                payload = req.get("payload", {})

                if action == "GET_STATUS":
                    res = {
                        "protocol_version": "1.0",
                        "request_id": req_id,
                        "status": "ALLOWED",
                        "taint_state": "CLEAN",
                        "decision_latency_ms": 0.1,
                        "message": "OK",
                        "data": {
                            "health": "healthy",
                            "pid": os.getpid(),
                            "http_port": http_port,
                            "active_agents": len(active_agents),
                            "tainted_agents": 0,
                            "vault_tokens": 0,
                            "audit_events": len(audit_events),
                            "uptime_seconds": int(time.time() - start_time),
                        },
                    }
                elif action == "REGISTER_AGENT":
                    active_agents[sess_id] = payload
                    event = {
                        "timestamp": time.strftime(
                            "%Y-%m-%dT%H:%M:%SZ", time.gmtime()
                        ),
                        "event_type": "REGISTER_AGENT",
                        "session_id": sess_id,
                        "status": "ALLOWED",
                        "details": f"Profile: {payload.get('profile')}",
                    }
                    audit_events.append(event)
                    res = {
                        "protocol_version": "1.0",
                        "request_id": req_id,
                        "status": "ALLOWED",
                        "taint_state": "CLEAN",
                        "message": "Registered",
                        "data": {},
                    }
                elif action == "UNREGISTER_AGENT":
                    active_agents.pop(sess_id, None)
                    res = {
                        "protocol_version": "1.0",
                        "request_id": req_id,
                        "status": "ALLOWED",
                        "taint_state": "CLEAN",
                        "message": "Unregistered",
                        "data": {},
                    }
                elif action == "GET_AUDIT":
                    limit = payload.get("limit", 20)
                    res = {
                        "protocol_version": "1.0",
                        "request_id": req_id,
                        "status": "ALLOWED",
                        "data": {"events": audit_events[-limit:]},
                    }
                elif action == "SHUTDOWN":
                    running[0] = False
                    res = {
                        "protocol_version": "1.0",
                        "request_id": req_id,
                        "status": "ALLOWED",
                        "message": "Shutting down",
                    }
                else:
                    res = {
                        "protocol_version": "1.0",
                        "request_id": req_id,
                        "status": "ALLOWED",
                        "message": f"Action {action} handled by M1 scaffold",
                        "data": {},
                    }

                conn.sendall((json.dumps(res) + "\n").encode("utf-8"))
                conn.close()
            except Exception:
                try:
                    conn.close()
                except OSError:
                    pass
    finally:
        srv.close()
        for p in (socket_path, pid_file):
            if os.path.exists(p):
                try:
                    os.unlink(p)
                except OSError:
                    pass


# Root Command Group
@click.group(
    name="agentguard",
    invoke_without_command=True,
    context_settings=dict(
        help_option_names=["-h", "--help"], max_content_width=100
    ),
)
@click.pass_context
@click.version_option(version=__version__, prog_name="AgentGuard")
def cli(ctx: click.Context):
    """AgentGuard - OS-Level Zero-Trust Security Kernel for Agents."""
    if ctx.invoked_subcommand is None:
        from agentguard.launcher import run_interactive_launcher
        code = run_interactive_launcher(ctx)
        if code != 0:
            sys.exit(code)


# Daemon Group
@cli.group("daemon")
def daemon_group():
    """Manage the AgentGuard background security daemon."""
    pass


@daemon_group.command("start")
@click.option(
    "--socket",
    "-s",
    "socket_path",
    default=DEFAULT_SOCKET_PATH,
    help="Path to Unix domain socket",
)
@click.option(
    "--http-port",
    "-p",
    "http_port",
    default=DEFAULT_HTTP_PORT,
    type=int,
    help="Port for local HTTP listener",
)
@click.option(
    "--foreground",
    "-f",
    is_flag=True,
    default=False,
    help="Run daemon attached in foreground",
)
@click.option(
    "--pid-file",
    default=DEFAULT_PID_FILE,
    hidden=True,
    help="Path to PID file",
)
def daemon_start(
    socket_path: str, http_port: int, foreground: bool, pid_file: str
):
    """Start the background security daemon."""
    client = DaemonClient(socket_path=socket_path)

    existing_pid = get_running_daemon_pid(pid_file)
    if existing_pid or client.is_running():
        click.echo(
            f"AgentGuard daemon is already running (PID: "
            f"{existing_pid or 'active'})."
        )
        return

    # Clean stale socket file
    if os.path.exists(socket_path):
        try:
            os.unlink(socket_path)
        except OSError:
            pass

    if foreground:
        click.echo(
            f"Starting AgentGuard daemon in foreground "
            f"(socket: {socket_path}, http-port: {http_port})..."
        )
        try:
            from agentguard.daemon.server import run_server
            run_server(
                socket_path=socket_path,
                http_port=http_port,
                pid_file=pid_file,
            )
        except (ImportError, AttributeError):
            _run_fallback_server(
                socket_path=socket_path,
                http_port=http_port,
                pid_file=pid_file,
            )
    else:
        cmd = [
            sys.executable,
            "-m",
            "agentguard.cli",
            "daemon",
            "start",
            "--foreground",
            "--socket",
            socket_path,
            "--http-port",
            str(http_port),
            "--pid-file",
            pid_file,
        ]
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
        )

        ready = False
        deadline = time.time() + 3.0
        while time.time() < deadline:
            time.sleep(0.1)
            if client.is_running():
                ready = True
                break
            if proc.poll() is not None:
                click.echo(
                    "Error: Daemon process exited unexpectedly.", err=True
                )
                sys.exit(1)

        if ready:
            click.echo(
                f"AgentGuard daemon started successfully (PID: {proc.pid}, "
                f"socket: {socket_path})."
            )
        else:
            click.echo(
                f"Warning: Daemon spawned (PID: {proc.pid}), but socket did "
                f"not respond within 3.0s.",
                err=True,
            )


@daemon_group.command("stop")
@click.option(
    "--socket",
    "-s",
    "socket_path",
    default=DEFAULT_SOCKET_PATH,
    help="Path to Unix domain socket",
)
@click.option(
    "--pid-file",
    default=DEFAULT_PID_FILE,
    hidden=True,
    help="Path to PID file",
)
def daemon_stop(socket_path: str, pid_file: str):
    """Stop the background security daemon."""
    pid = get_running_daemon_pid(pid_file)
    stopped = False

    client = DaemonClient(socket_path=socket_path)
    if client.is_running():
        try:
            client.send("SHUTDOWN", timeout=1.0)
            deadline = time.time() + 1.5
            while time.time() < deadline:
                if not client.is_running():
                    stopped = True
                    break
                time.sleep(0.05)
        except Exception:
            pass

    if not stopped and pid:
        try:
            os.kill(pid, signal.SIGTERM)
            deadline = time.time() + 2.0
            while time.time() < deadline:
                time.sleep(0.1)
                try:
                    os.kill(pid, 0)
                except OSError:
                    stopped = True
                    break
            if not stopped:
                os.kill(pid, signal.SIGKILL)
                stopped = True
        except ProcessLookupError:
            stopped = True
        except Exception as exc:
            click.echo(
                f"Error stopping daemon process (PID: {pid}): {exc}",
                err=True,
            )

    # Clean up files
    for p in (pid_file, socket_path):
        if os.path.exists(p):
            try:
                os.unlink(p)
            except OSError:
                pass

    if pid or stopped:
        click.echo("AgentGuard daemon stopped.")
    else:
        click.echo("AgentGuard daemon is not running.")


# Wrap Command
@cli.command("wrap", context_settings=dict(ignore_unknown_options=True))
@click.option(
    "--profile",
    "-p",
    required=False,
    default=None,
    help="Security adapter profile name or path (auto-detected if omitted)",
)
@click.option(
    "--hitl",
    is_flag=True,
    default=False,
    help="Enable interactive Human-in-the-Loop confirmation prompts",
)
@click.option(
    "--no-llm-proxy",
    is_flag=True,
    default=False,
    help="Disable transparent LLM HTTP reverse proxy environment injection",
)
@click.option(
    "--socket",
    "-s",
    "socket_path",
    default=DEFAULT_SOCKET_PATH,
    help="Path to Unix domain socket",
)
@click.argument("command", nargs=-1, required=True, type=click.UNPROCESSED)
def wrap(
    profile: Optional[str],
    hitl: bool,
    no_llm_proxy: bool,
    socket_path: str,
    command: Tuple[str, ...],
):
    """Wrap an agent execution with AgentGuard security shims."""
    if not command:
        raise click.UsageError(
            "No command specified to wrap. "
            "Usage: ag wrap [--profile <name>] -- <command...>"
        )

    # 1. Daemon Pre-Flight Check
    client = DaemonClient(socket_path=socket_path)
    daemon_online = client.is_running()

    if not daemon_online and _should_prompt_daemon():
        if not ensure_daemon_running(socket_path=socket_path):
            sys.exit(1)
        daemon_online = True

    # 2. Profile Auto-Detection & Resolution
    if profile is None:
        detected = detect_agent_profile(command)
        if detected:
            profile = detected
        else:
            should_prompt = sys.stdin.isatty() or (
                type(sys.stdin).__module__ == "click.testing"
                and bool(getattr(sys.stdin, "buffer", None) and hasattr(sys.stdin.buffer, "getvalue") and sys.stdin.buffer.getvalue())
            )
            created_profile = False
            if should_prompt:
                try:
                    confirm = click.prompt("Save as custom profile? [y/N]", default="n", show_default=False).strip().lower()
                    if confirm in ("y", "yes"):
                        raw_name = Path(command[0]).stem.lower() if command else "custom"
                        prof_name = click.prompt("Profile name", default=raw_name, show_default=True).strip()
                        create_custom_profile(prof_name, agent_command=" ".join(command))
                        profile = prof_name
                        created_profile = True
                except (click.Abort, EOFError):
                    pass
            if not created_profile:
                profile = "generic"

    # 3. Validate profile existence
    try:
        load_profile(profile)
    except FileNotFoundError as exc:
        click.echo(f"Error: Profile '{profile}' not found. {exc}", err=True)
        sys.exit(1)
    except Exception as exc:
        click.echo(f"Error: Invalid profile '{profile}': {exc}", err=True)
        sys.exit(1)

    session_id = f"ag-sess-{uuid.uuid4().hex[:12]}"

    if daemon_online:
        try:
            client.send(
                action="REGISTER_AGENT",
                payload={
                    "profile": profile,
                    "command": list(command),
                    "hitl": hitl,
                    "working_dir": os.getcwd(),
                    "wrapper_pid": os.getpid(),
                },
                session_id=session_id,
            )
        except Exception as exc:
            click.echo(
                f"Warning: Failed to register session with daemon: {exc}",
                err=True,
            )

    try:
        from agentguard.interceptors.shell_shim import ShimManager
        shim_mgr = ShimManager(
            shim_dir=DEFAULT_SHIMS_DIR, socket_path=socket_path
        )
        shim_mgr.install()
        env = shim_mgr.get_env(
            session_id=session_id,
            hitl=hitl,
            base_env=os.environ.copy(),
            llm_proxy=not no_llm_proxy,
        )
        env["AGENTGUARD_PROFILE"] = profile
    except Exception:
        env = os.environ.copy()
        env["AGENTGUARD_SESSION_ID"] = session_id
        env["AGENTGUARD_PROFILE"] = profile
        env["AGENTGUARD_SOCKET"] = socket_path
        env["AGENTGUARD_HITL"] = "1" if hitl else "0"
        env["AGENTGUARD_ORIGINAL_PATH"] = env.get("PATH", "")
        if DEFAULT_SHIMS_DIR.is_dir():
            env["PATH"] = f"{DEFAULT_SHIMS_DIR}:{env.get('PATH', '')}"

    exit_code = 0
    try:
        # Detect automated capture environments (e.g. Click CliRunner)
        is_captured = False
        try:
            sys.stdout.fileno()
        except Exception:
            is_captured = True

        if is_captured:
            proc = subprocess.Popen(
                list(command),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            # Post-spawn PID registration: associate actual agent PID with session
            if daemon_online:
                try:
                    client.send(
                        action="REGISTER_AGENT_PID",
                        payload={
                            "pid": proc.pid,
                            "wrapper_pid": os.getpid(),
                            "profile": profile,
                        },
                        session_id=session_id,
                        timeout=1.0,
                    )
                except Exception:
                    pass
            stdout_data, stderr_data = proc.communicate()
            if stdout_data:
                sys.stdout.write(stdout_data)
                sys.stdout.flush()
            if stderr_data:
                sys.stderr.write(stderr_data)
                sys.stderr.flush()
            exit_code = proc.returncode
        else:
            proc = subprocess.Popen(list(command), env=env)
            # Post-spawn PID registration: associate actual agent PID with session
            if daemon_online:
                try:
                    client.send(
                        action="REGISTER_AGENT_PID",
                        payload={
                            "pid": proc.pid,
                            "wrapper_pid": os.getpid(),
                            "profile": profile,
                        },
                        session_id=session_id,
                        timeout=1.0,
                    )
                except Exception:
                    pass

            if threading.current_thread() is threading.main_thread():
                def _forward_signal(signum, frame):
                    try:
                        proc.send_signal(signum)
                    except ProcessLookupError:
                        pass
                try:
                    signal.signal(signal.SIGINT, _forward_signal)
                    signal.signal(signal.SIGTERM, _forward_signal)
                except (ValueError, AttributeError):
                    pass

            exit_code = proc.wait()
    except FileNotFoundError:
        click.echo(f"Error: Command '{command[0]}' not found.", err=True)
        exit_code = 127
    except PermissionError:
        click.echo(
            f"Error: Permission denied executing '{command[0]}'.", err=True
        )
        exit_code = 126
    except Exception as exc:
        click.echo(f"Error executing command: {exc}", err=True)
        exit_code = 1
    finally:
        if daemon_online:
            try:
                client.send(
                    action="UNREGISTER_AGENT",
                    payload={"exit_code": exit_code},
                    session_id=session_id,
                    timeout=1.0,
                )
            except Exception:
                pass
        sys.exit(exit_code)


# Status Command
@cli.command("status")
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    default=False,
    help="Output status in JSON format",
)
@click.option(
    "--socket",
    "-s",
    "socket_path",
    default=DEFAULT_SOCKET_PATH,
    help="Path to Unix domain socket",
)
def status(as_json: bool, socket_path: str):
    """Show security daemon health and active agent sessions."""
    client = DaemonClient(socket_path=socket_path)

    try:
        res = client.send("GET_STATUS")
        data = res.get("data", {})
        if as_json:
            output = {
                "status": data.get("health", "healthy"),
                "pid": data.get("pid", get_running_daemon_pid()),
                "socket": socket_path,
                "http_port": data.get("http_port", DEFAULT_HTTP_PORT),
                "active_agents": data.get("active_agents", 0),
                "tainted_agents": data.get("tainted_agents", 0),
                "vault_tokens": data.get("vault_tokens", 0),
                "audit_events": data.get("audit_events", 0),
                "uptime_seconds": data.get("uptime_seconds", 0),
            }
            click.echo(json.dumps(output, indent=2))
        else:
            pid = data.get("pid", get_running_daemon_pid() or "unknown")
            port = data.get("http_port", DEFAULT_HTTP_PORT)
            click.echo("AgentGuard Security Kernel Status")
            click.echo("=================================")
            click.echo(f"Status:          ACTIVE ({data.get('health', 'ok')})")
            click.echo(f"Daemon PID:      {pid}")
            click.echo(f"UDS Socket:      {socket_path}")
            click.echo(f"HTTP Endpoint:   http://127.0.0.1:{port}")
            click.echo(f"Active Agents:   {data.get('active_agents', 0)}")
            click.echo(f"Tainted Agents:  {data.get('tainted_agents', 0)}")
            click.echo(f"Vault Tokens:    {data.get('vault_tokens', 0)}")
            click.echo(f"Audit Events:    {data.get('audit_events', 0)}")
    except (
        FileNotFoundError,
        ConnectionRefusedError,
        socket.timeout,
        ConnectionError,
        OSError,
    ):
        if as_json:
            click.echo(
                json.dumps(
                    {
                        "status": "STOPPED",
                        "error": "daemon_not_running",
                        "socket": socket_path,
                        "active_agents": 0,
                    },
                    indent=2,
                )
            )
        else:
            click.echo("AgentGuard Status: STOPPED")
            click.echo(f"Daemon socket ({socket_path}) is not reachable.")
            click.echo("Run 'ag daemon start' to start the security daemon.")


# Audit Command
@cli.command("audit")
@click.option(
    "--limit",
    "-n",
    default=20,
    type=int,
    help="Maximum number of audit events to display",
)
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["text", "json"], case_sensitive=False),
    default="text",
    help="Output format (text or json)",
)
@click.option(
    "--socket",
    "-s",
    "socket_path",
    default=DEFAULT_SOCKET_PATH,
    help="Path to Unix domain socket",
)
@click.option(
    "--file",
    "--log-path",
    "audit_file_path",
    default=str(DEFAULT_AUDIT_FILE),
    help="Path to local audit log file",
)
def audit(
    limit: int, output_format: str, socket_path: str, audit_file_path: str
):
    """Display recent security audit events."""
    client = DaemonClient(socket_path=socket_path)
    events: List[Dict[str, Any]] = []

    # 1. Query running daemon
    try:
        res = client.send("GET_AUDIT", payload={"limit": limit})
        events = res.get("data", {}).get("events", [])
    except Exception:
        # Fall back to local file
        if os.path.exists(audit_file_path):
            try:
                from agentguard.daemon.audit import AuditLogger
                logger = AuditLogger(log_path=audit_file_path)
                events = logger.read_from_disk(limit=limit)
            except Exception:
                try:
                    with open(audit_file_path, "r", encoding="utf-8") as f:
                        lines = [ln.strip() for ln in f if ln.strip()]
                        for ln in lines[-limit:]:
                            try:
                                events.append(json.loads(ln))
                            except json.JSONDecodeError:
                                pass
                except OSError:
                    pass

    if output_format == "json":
        click.echo(json.dumps(events, indent=2))
        return

    if not events:
        click.echo("No audit events recorded yet.")
        return

    header = (
        f"{'TIMESTAMP':<24} {'EVENT_TYPE':<16} {'SESSION_ID':<18} "
        f"{'STATUS':<10} {'DETAILS'}"
    )
    click.echo(header)
    click.echo("-" * 88)
    for ev in events:
        ts = str(ev.get("timestamp", ""))[:23]
        etype = str(ev.get("event_type", ev.get("action", "")))[:15]
        sess = str(ev.get("session_id", ""))[:17]
        st = str(ev.get("status", ""))[:9]
        details = str(
            ev.get("details", ev.get("message", ev.get("payload", "")))
        )
        if len(details) > 30:
            details = details[:27] + "..."
        click.echo(f"{ts:<24} {etype:<16} {sess:<18} {st:<10} {details}")


# ---------------------------------------------------------------------------
# Cockpit TUI Command
# ---------------------------------------------------------------------------
@cli.command("cockpit")
@click.option(
    "--socket",
    "-s",
    "socket_path",
    default=DEFAULT_SOCKET_PATH,
    help="Path to AgentGuard daemon Unix domain socket",
)
@click.option(
    "--url",
    "-u",
    "http_url",
    default=f"http://127.0.0.1:{DEFAULT_HTTP_PORT}",
    help="AgentGuard HTTP/SSE endpoint for event streaming",
)
@click.option(
    "--refresh-interval",
    "-r",
    default=0.5,
    type=float,
    help="Telemetry polling refresh interval in seconds (default: 0.5)",
)
@click.option(
    "--no-prompt",
    is_flag=True,
    default=False,
    hidden=True,
    help="Disable interactive first-run daemon prompt",
)
def cockpit_cmd(
    socket_path: str,
    http_url: str,
    refresh_interval: float,
    no_prompt: bool,
):
    """Launch the full-screen terminal Cockpit TUI monitoring active agents."""
    if not ensure_daemon_running(
        socket_path=socket_path,
        http_port=DEFAULT_HTTP_PORT,
        prompt=not no_prompt,
    ):
        sys.exit(1)

    from agentguard.cockpit.app import run_cockpit

    code = run_cockpit(
        socket_path=socket_path,
        http_url=http_url,
        refresh_interval=refresh_interval,
    )
    sys.exit(code)


def find_mcp_config_files(
    target_all: bool = False,
    target_claude: bool = False,
    target_cursor: bool = False,
    target_antigravity: bool = False,
    custom_paths: Optional[Tuple[str, ...]] = None,
) -> List[Path]:
    """Discovers MCP JSON configuration files across supported IDEs and runtimes."""
    candidates: List[Path] = []

    if custom_paths:
        for p in custom_paths:
            candidates.append(Path(p).resolve())
        return candidates

    scan_all = target_all or (not target_claude and not target_cursor and not target_antigravity)

    if scan_all or target_claude:
        candidates.extend([
            Path.home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
            Path.home() / ".config" / "Claude" / "claude_desktop_config.json",
            Path.home() / ".config" / "claude" / "config.json",
            Path.home() / ".claude" / "mcp.json",
            Path.home() / ".claude" / "claude_desktop_config.json",
        ])

    if scan_all or target_cursor:
        candidates.extend([
            Path.home() / ".cursor" / "mcp.json",
            Path.home() / "Library" / "Application Support" / "Cursor" / "User" / "globalStorage" / "mcp.json",
            Path.cwd() / ".cursor" / "mcp.json",
        ])

    if scan_all or target_antigravity:
        candidates.extend([
            Path.home() / ".gemini" / "antigravity" / "mcp_config.json",
            Path.home() / ".gemini" / "antigravity-cli" / "mcp.json",
            Path.home() / ".config" / "antigravity" / "mcp.json",
            Path.home() / ".antigravity" / "mcp.json",
        ])

    if scan_all:
        candidates.extend([
            Path.home() / ".codeium" / "windsurf" / "mcp_config.json",
            Path.cwd() / ".vscode" / "mcp.json",
        ])

    found: List[Path] = []
    seen: Set[str] = set()
    for c in candidates:
        norm = str(c.resolve()) if c.exists() else str(c)
        if norm not in seen and c.exists() and c.is_file():
            seen.add(norm)
            found.append(c)

    return found


def rewrite_mcp_config(config_path: Path, dry_run: bool = False) -> Tuple[bool, int, str]:
    """
    Safely inspects an MCP configuration file, creates a backup,
    and rewrites server commands to route through 'ag mcp-proxy'.
    """
    import shutil
    try:
        content = config_path.read_text(encoding="utf-8")
        data = json.loads(content)
    except Exception as exc:
        return False, 0, f"Failed to parse JSON in {config_path}: {exc}"

    if not isinstance(data, dict):
        return False, 0, f"Expected JSON object in {config_path}"

    servers = data.get("mcpServers") or data.get("servers")
    if not isinstance(servers, dict) or not servers:
        return False, 0, f"No MCP servers configured in {config_path}"

    ag_bin = shutil.which("ag") or "ag"
    modified_count = 0

    for s_name, s_cfg in servers.items():
        if not isinstance(s_cfg, dict):
            continue
        orig_cmd = s_cfg.get("command")
        orig_args = s_cfg.get("args", [])
        if not orig_cmd:
            continue

        # Skip if already routed through ag mcp-proxy
        if orig_cmd == "ag" or orig_cmd.endswith("/ag") or "mcp-proxy" in orig_args:
            continue

        new_args = ["mcp-proxy", orig_cmd] + list(orig_args)
        s_cfg["command"] = ag_bin
        s_cfg["args"] = new_args
        modified_count += 1

    if modified_count == 0:
        return True, 0, "All servers already secured with AgentGuard gateway"

    backup_path = config_path.with_name(f"{config_path.stem}.ag-backup.json")
    if not backup_path.exists():
        backup_path.write_text(content, encoding="utf-8")

    if not dry_run:
        config_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    return True, modified_count, str(backup_path)


def restore_mcp_config(config_path: Path) -> Tuple[bool, str]:
    """Restores original MCP configuration file from .ag-backup.json backup."""
    backup_path = config_path.with_name(f"{config_path.stem}.ag-backup.json")
    if not backup_path.exists():
        backup_path = config_path.with_suffix(".json.bak")

    if not backup_path.exists():
        return False, f"No backup file found for {config_path}"

    try:
        content = backup_path.read_text(encoding="utf-8")
        config_path.write_text(content, encoding="utf-8")
        return True, f"Successfully restored {config_path} from {backup_path}"
    except Exception as exc:
        return False, f"Failed restoring {config_path}: {exc}"


@cli.command("mcp-proxy", context_settings=dict(ignore_unknown_options=True))
@click.option("--transport", default="stdio", type=click.Choice(["stdio", "sse"]), help="Transport stream mode")
@click.option("--host", default="127.0.0.1", help="Host address for SSE transport server")
@click.option("--port", default=18445, type=int, help="Port for SSE transport server")
@click.argument("command", nargs=-1, type=click.UNPROCESSED, required=False)
def mcp_proxy_cmd(transport, host, port, command):
    """Run an MCP server command through the AgentGuard security proxy gateway."""
    import asyncio
    from agentguard.interceptors.mcp_gateway import run_gateway
    cmd_list = list(command) if command else []
    if transport == "stdio" and not cmd_list:
        click.echo("[AgentGuard Gateway] Error: Stdio mode requires an upstream MCP server command.", err=True)
        sys.exit(1)
    code = asyncio.run(run_gateway(cmd_list, transport=transport, host=host, port=port))
    sys.exit(code)


@cli.command("mcp-install")
@click.option("--all", "install_all", is_flag=True, help="Scan and configure all detected agent/IDE configs")
@click.option("--claude", is_flag=True, help="Configure Claude Code & Claude Desktop configs")
@click.option("--cursor", is_flag=True, help="Configure Cursor MCP configuration")
@click.option("--antigravity", is_flag=True, help="Configure Antigravity MCP configuration")
@click.option("--config", "custom_configs", multiple=True, type=click.Path(), help="Target custom MCP JSON config file")
@click.option("--dry-run", is_flag=True, help="Preview rewrites without modifying files on disk")
@click.option("--restore", is_flag=True, help="Restore original configuration files from .bak backups")
def mcp_install_cmd(install_all, claude, cursor, antigravity, custom_configs, dry_run, restore):
    """
    Automatically inspect and rewrite local IDE/agent configuration files to route
    all MCP servers through the AgentGuard security gateway.
    """
    configs = find_mcp_config_files(
        target_all=install_all,
        target_claude=claude,
        target_cursor=cursor,
        target_antigravity=antigravity,
        custom_paths=custom_configs,
    )

    if not configs:
        click.echo("[AgentGuard MCP] No MCP configuration files found to inspect.")
        click.echo("Tip: Specify explicit config via --config <path/to/mcp.json>")
        return

    click.echo(f"[AgentGuard MCP] Discovered {len(configs)} configuration file(s).")

    total_modified = 0
    for cfg in configs:
        if restore:
            success, msg = restore_mcp_config(cfg)
            symbol = "✓" if success else "✗"
            click.echo(f"  [{symbol}] {msg}")
        else:
            success, count, msg = rewrite_mcp_config(cfg, dry_run=dry_run)
            if success:
                if count > 0:
                    mode_str = "(DRY RUN) " if dry_run else ""
                    click.echo(f"  [✓] {mode_str}Secured {count} MCP server(s) in {cfg} (Backup: {msg})")
                    total_modified += count
                else:
                    click.echo(f"  [-] {cfg}: {msg}")
            else:
                click.echo(f"  [!] {cfg}: {msg}", err=True)

    if not restore:
        if dry_run:
            click.echo(f"[AgentGuard MCP] Dry run completed: {total_modified} server(s) eligible for protection.")
        else:
            click.echo(f"[AgentGuard MCP] Installation completed: {total_modified} server(s) routed through AgentGuard gateway.")


# ---------------------------------------------------------------------------
# Notification Management Group
# ---------------------------------------------------------------------------

@cli.group("notify")
def notify_group():
    """Configure and test AgentGuard security notification channels."""
    return


@notify_group.command("setup")
@click.option("--discord", "discord_webhook", default=None, help="Discord incoming webhook URL")
@click.option("--telegram", "telegram_token", default=None, help="Telegram Bot API token")
@click.option("--chat-id", "telegram_chat_id", default=None, help="Telegram target chat ID")
@click.option("--enable/--disable", "master_enabled", default=None, help="Enable or disable alerting")
@click.option("--heartbeat-interval", type=int, default=None, help="Heartbeat interval in seconds")
@click.option("--wizard", "-w", is_flag=True, default=False, help="Launch interactive terminal setup wizard")
def notify_setup(discord_webhook, telegram_token, telegram_chat_id, master_enabled, heartbeat_interval, wizard):
    """Configure notification credentials and preferences in ~/.agentguard/notifications.yaml."""
    no_flags = (
        discord_webhook is None
        and telegram_token is None
        and telegram_chat_id is None
        and master_enabled is None
        and heartbeat_interval is None
    )

    if wizard or (no_flags and sys.stdin.isatty()):
        from agentguard.notifications.wizard import launch_notification_wizard
        launch_notification_wizard()
        return

    from agentguard.notifications.config import (
        load_notification_config,
        save_notification_config,
        get_notifications_config_path,
    )

    config = load_notification_config()

    if discord_webhook is not None:
        clean_url = discord_webhook.strip()
        if clean_url:
            config.discord.webhook_url = clean_url
            config.discord.enabled = True
        else:
            config.discord.webhook_url = ""
            config.discord.enabled = False

    if telegram_token is not None:
        clean_token = telegram_token.strip()
        if clean_token:
            config.telegram.bot_token = clean_token
            config.telegram.enabled = bool(config.telegram.chat_id)
        else:
            config.telegram.bot_token = ""
            config.telegram.enabled = False

    if telegram_chat_id is not None:
        clean_chat = telegram_chat_id.strip()
        if clean_chat:
            config.telegram.chat_id = clean_chat
            config.telegram.enabled = bool(config.telegram.bot_token)
        else:
            config.telegram.chat_id = ""
            config.telegram.enabled = False

    if heartbeat_interval is not None:
        config.heartbeat.interval_seconds = max(10, heartbeat_interval)

    if master_enabled is not None:
        config.enabled = master_enabled
    elif config.discord.enabled or config.telegram.enabled:
        config.enabled = True

    save_notification_config(config)
    path = get_notifications_config_path()

    click.echo(f"Notification configuration saved successfully to {path} (mode 0600).")
    click.echo(f"Master Alerts: {'ENABLED' if config.enabled else 'DISABLED'}")
    click.echo(f"Discord:       {'CONFIGURED & ENABLED' if config.discord.enabled else 'DISABLED / NOT CONFIGURED'}")
    click.echo(f"Telegram:      {'CONFIGURED & ENABLED' if config.telegram.enabled else 'DISABLED / NOT CONFIGURED'}")
    click.echo(f"Heartbeat:     {'ENABLED (' + str(config.heartbeat.interval_seconds) + 's)' if config.heartbeat.enabled else 'DISABLED'}")


@notify_group.command("wizard")
def notify_wizard():
    """Launch the interactive terminal setup wizard for Discord and Telegram."""
    from agentguard.notifications.wizard import launch_notification_wizard
    launch_notification_wizard()


@notify_group.command("test")
@click.option(
    "--channel",
    type=click.Choice(["discord", "telegram", "all"], case_sensitive=False),
    default="all",
    help="Channel to send synthetic test notification to",
)
def notify_test(channel: str):
    """Send synthetic test alert to configured notification channels."""
    from agentguard.notifications.config import load_notification_config
    from agentguard.notifications.discord import build_discord_alert, send_discord_payload
    from agentguard.notifications.telegram import build_telegram_alert, send_telegram_payload

    config = load_notification_config()
    target_channel = channel.lower()

    if target_channel in ("discord", "all"):
        if not config.discord.webhook_url or not config.discord.enabled:
            click.echo("[SKIPPED] Discord channel is not enabled or webhook URL is not set.")
        else:
            payload = build_discord_alert(
                event_type="SYNTHETIC_TEST",
                severity="INFO",
                details={"command": "echo 'AgentGuard synthetic notification test'"},
                session_id="ag-sess-test0001",
                pid=os.getpid(),
                profile="test-profile",
                reason="Manual verification via `ag notify test`",
                username=config.discord.username,
            )
            try:
                ok = send_discord_payload(config.discord.webhook_url, payload, timeout=5.0)
                if ok:
                    click.echo("[PASS] Discord test alert sent successfully.")
                else:
                    click.echo("[FAIL] Discord webhook returned non-success response.", err=True)
            except Exception as e:
                click.echo(f"[FAIL] Discord test failed: {e}", err=True)

    if target_channel in ("telegram", "all"):
        if not config.telegram.bot_token or not (config.telegram.chat_id or config.telegram.bot_token.startswith("http")) or not config.telegram.enabled:
            click.echo("[SKIPPED] Telegram channel is not enabled or bot token / chat ID is not set.")
        else:
            text = build_telegram_alert(
                event_type="SYNTHETIC_TEST",
                severity="INFO",
                details={"command": "echo 'AgentGuard synthetic notification test'"},
                session_id="ag-sess-test0001",
                pid=os.getpid(),
                profile="test-profile",
                reason="Manual verification via `ag notify test`",
            )
            try:
                ok = send_telegram_payload(
                    config.telegram.bot_token,
                    config.telegram.chat_id,
                    text,
                    parse_mode=config.telegram.parse_mode,
                    timeout=5.0,
                )
                if ok:
                    click.echo("[PASS] Telegram test alert sent successfully.")
                else:
                    click.echo("[FAIL] Telegram Bot API returned non-success response.", err=True)
            except Exception as e:
                click.echo(f"[FAIL] Telegram test failed: {e}", err=True)


@notify_group.command("status")
@click.option("--json", "as_json", is_flag=True, default=False, help="Output status in JSON format")
def notify_status(as_json: bool):
    """Display current notification configuration and channel status."""
    import json
    from agentguard.notifications.config import load_notification_config, get_notifications_config_path

    config = load_notification_config()
    path = str(get_notifications_config_path())

    def mask_token(t: Optional[str]) -> str:
        if not t:
            return "None"
        if len(t) <= 8:
            return "********"
        return t[:4] + "..." + t[-4:]

    status_data = {
        "config_file": path,
        "master_enabled": config.enabled,
        "min_severity": config.min_severity,
        "discord": {
            "enabled": config.discord.enabled,
            "configured": bool(config.discord.webhook_url),
            "webhook_url": mask_token(config.discord.webhook_url),
        },
        "telegram": {
            "enabled": config.telegram.enabled,
            "configured": bool(config.telegram.bot_token and config.telegram.chat_id),
            "bot_token": mask_token(config.telegram.bot_token),
            "chat_id": config.telegram.chat_id or "None",
        },
        "heartbeat": {
            "enabled": config.heartbeat.enabled,
            "interval_seconds": config.heartbeat.interval_seconds,
        },
    }

    if as_json:
        click.echo(json.dumps(status_data, indent=2))
    else:
        click.echo("AgentGuard Notification Engine Status")
        click.echo("=====================================")
        click.echo(f"Config File:     {path}")
        click.echo(f"Master Alerts:   {'ENABLED' if config.enabled else 'DISABLED'}")
        click.echo(f"Min Severity:    {config.min_severity}")
        click.echo(f"Discord:         {'ENABLED' if config.discord.enabled else 'DISABLED'} (Webhook: {mask_token(config.discord.webhook_url)})")
        click.echo(f"Telegram:        {'ENABLED' if config.telegram.enabled else 'DISABLED'} (Bot: {mask_token(config.telegram.bot_token)}, Chat: {config.telegram.chat_id or 'None'})")
        click.echo(f"Heartbeat:       {'ENABLED' if config.heartbeat.enabled else 'DISABLED'} (Interval: {config.heartbeat.interval_seconds}s)")


# ---------------------------------------------------------------------------
# Enterprise SIEM Telemetry Forwarder Management Group
# ---------------------------------------------------------------------------

@cli.group("siem")
def siem_group():
    """Configure and manage enterprise SIEM telemetry forwarding."""
    return


@siem_group.command("setup")
@click.option("--endpoint", required=False, default=None, help="Enterprise SIEM endpoint URL")
@click.option("--token", required=False, default=None, help="Authentication token / API key")
@click.option(
    "--type",
    "siem_type",
    type=click.Choice(["splunk", "datadog", "webhook"], case_sensitive=False),
    default=None,
    help="SIEM ingestion format [splunk|datadog|webhook]",
)
@click.option("--hmac-secret", default=None, help="Pre-shared enterprise secret for HMAC-SHA256 signing")
@click.option("--batch-size", type=int, default=None, help="Batch size for log forwarding")
@click.option("--flush-interval", type=float, default=None, help="Flush interval in seconds")
@click.option("--spool-path", default=None, help="Local disk spool file path")
@click.option("--enable/--disable", "is_enabled", default=None, help="Enable or disable SIEM forwarding")
@click.option("--insecure", is_flag=True, default=False, help="Disable SSL certificate verification")
def siem_setup(endpoint, token, siem_type, hmac_secret, batch_size, flush_interval, spool_path, is_enabled, insecure):
    """Configure SIEM collector credentials and delivery parameters in ~/.agentguard/siem.yaml."""
    from agentguard.exporters.siem_forwarder import (
        load_siem_config,
        save_siem_config,
        get_siem_config_path,
    )

    config = load_siem_config()

    if endpoint is not None:
        clean_ep = endpoint.strip()
        config.endpoint = clean_ep
        if clean_ep and is_enabled is None:
            config.enabled = True

    if token is not None:
        config.token = token.strip()

    if siem_type is not None:
        config.siem_type = siem_type.strip().lower()

    if hmac_secret is not None:
        config.hmac_secret = hmac_secret.strip()

    if batch_size is not None:
        config.batch_size = max(1, batch_size)

    if flush_interval is not None:
        config.flush_interval_seconds = max(0.1, flush_interval)

    if spool_path is not None:
        config.spool_path = spool_path.strip()

    if insecure:
        config.verify_ssl = False

    if is_enabled is not None:
        config.enabled = is_enabled

    path = save_siem_config(config)

    def mask_secret(s: Optional[str]) -> str:
        if not s:
            return "None"
        if len(s) <= 8:
            return "********"
        return s[:3] + "..." + s[-3:]

    click.echo(f"SIEM configuration saved successfully to {path} (mode 0600).")
    click.echo(f"Status:         {'ENABLED' if config.enabled else 'DISABLED'}")
    click.echo(f"Platform:       {config.siem_type.upper()}")
    click.echo(f"Endpoint:       {config.endpoint or 'None'}")
    click.echo(f"Token:          {mask_secret(config.token)}")
    click.echo(f"HMAC Secret:    {mask_secret(config.hmac_secret)}")
    click.echo(f"Batch Size:     {config.batch_size} events")
    click.echo(f"Flush Interval: {config.flush_interval_seconds}s")
    click.echo(f"Disk Spool:     {config.spool_path}")
    click.echo(f"Verify SSL:     {config.verify_ssl}")


@siem_group.command("test")
@click.option("--dry-run", is_flag=True, default=False, help="Generate and sign payload without network delivery")
def siem_test(dry_run: bool):
    """Test SIEM connectivity, payload generation, and HMAC signing."""
    from agentguard.exporters.siem_forwarder import (
        SIEMForwarder,
        load_siem_config,
    )

    config = load_siem_config()

    if not config.endpoint and not dry_run:
        click.echo("[FAIL] No SIEM endpoint configured. Run `ag siem setup --endpoint <url>` first.", err=True)
        sys.exit(1)

    forwarder = SIEMForwarder(config=config)

    sample_event = {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "event_type": "SYNTHETIC_SIEM_TEST",
        "session_id": "test-agent-session",
        "pid": os.getpid(),
        "status": "INFO",
        "details": {
            "message": "Manual verification triggered via `ag siem test`",
            "compliance_tags": ["SOC2-CC6.1", "ISO27001-A.12.1.2"],
        },
    }

    payload_bytes, headers = forwarder.format_batch_payload([sample_event])
    sig = headers.get("X-AgentGuard-Signature", "")

    click.echo(f"SIEM Platform:    {config.siem_type.upper()}")
    click.echo(f"Endpoint:         {config.endpoint or '(Dry-Run Mode)'}")
    click.echo(f"Payload Size:     {len(payload_bytes)} bytes")
    click.echo(f"HMAC Signature:   {sig}")

    if dry_run:
        click.echo("\n[DRY RUN] Generated Headers:")
        for h, v in headers.items():
            masked_v = v if "auth" not in h.lower() and "key" not in h.lower() else "********"
            click.echo(f"  {h}: {masked_v}")
        click.echo("\n[DRY RUN] Generated Payload:")
        try:
            click.echo(payload_bytes.decode("utf-8"))
        except Exception:
            click.echo(str(payload_bytes))
        click.echo("\n[PASS] Dry run completed: payload formatted and HMAC signed successfully.")
        return

    click.echo("Streaming synthetic audit batch to endpoint...")
    success, code, body, meta = forwarder.test_connection()

    if success:
        click.echo(f"[PASS] Successfully connected to SIEM endpoint (HTTP {code}) in {meta['elapsed_ms']}ms.")
        if body:
            click.echo(f"Response: {body[:200]}")
    else:
        click.echo(f"[FAIL] SIEM delivery failed: HTTP {code} - {body}", err=True)
        sys.exit(1)


@siem_group.command("status")
@click.option("--json", "as_json", is_flag=True, default=False, help="Output status in JSON format")
def siem_status(as_json: bool):
    """Display current SIEM telemetry forwarder configuration and spool status."""
    from agentguard.exporters.siem_forwarder import (
        SIEMForwarder,
        load_siem_config,
        get_siem_config_path,
    )

    config = load_siem_config()
    forwarder = SIEMForwarder(config=config)
    path = str(get_siem_config_path())

    def mask_secret(s: Optional[str]) -> str:
        if not s:
            return "None"
        if len(s) <= 8:
            return "********"
        return s[:3] + "..." + s[-3:]

    status_data = {
        "config_file": path,
        "enabled": config.enabled,
        "siem_type": config.siem_type,
        "endpoint": config.endpoint or "None",
        "token_configured": bool(config.token),
        "hmac_secret_configured": bool(config.hmac_secret or os.environ.get("AGENTGUARD_HMAC_SECRET")),
        "batch_size": config.batch_size,
        "flush_interval_seconds": config.flush_interval_seconds,
        "spool_path": config.spool_path,
        "spooled_events_count": forwarder.spool.count(),
        "verify_ssl": config.verify_ssl,
    }

    if as_json:
        click.echo(json.dumps(status_data, indent=2))
    else:
        click.echo("AgentGuard Enterprise SIEM Forwarder Status")
        click.echo("===========================================")
        click.echo(f"Config File:     {path}")
        click.echo(f"Status:          {'ENABLED' if config.enabled else 'DISABLED'}")
        click.echo(f"Platform:        {config.siem_type.upper()}")
        click.echo(f"Endpoint:        {config.endpoint or 'None'}")
        click.echo(f"Token:           {mask_secret(config.token)}")
        click.echo(f"HMAC Secret:     {'CONFIGURED (' + mask_secret(config.hmac_secret or os.environ.get('AGENTGUARD_HMAC_SECRET')) + ')' if config.hmac_secret or os.environ.get('AGENTGUARD_HMAC_SECRET') else 'NOT CONFIGURED'}")
        click.echo(f"Batch Size:      {config.batch_size} events")
        click.echo(f"Flush Interval:  {config.flush_interval_seconds}s")
        click.echo(f"Disk Spool:      {config.spool_path} ({forwarder.spool.count()} spooled events)")
        click.echo(f"Verify SSL:      {config.verify_ssl}")


# Public Entrypoint
main = cli

if __name__ == "__main__":
    main()
