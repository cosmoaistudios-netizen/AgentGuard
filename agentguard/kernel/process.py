"""
AgentGuard Process Tree Control & Signal Management.

Provides high-reliability OS-level process tree supervision using psutil:
- pause_process_tree: recursive SIGSTOP (children first, then parent)
- resume_process_tree: recursive SIGCONT (parent first, then children)
- terminate_process_tree: recursive SIGTERM with graceful timeout, escalating to SIGKILL
- get_process_tree_info: deep diagnostic process telemetry across parent and descendants

Handles all OS edge cases:
- psutil.NoSuchProcess
- psutil.AccessDenied
- psutil.ZombieProcess
- Invalid or dead PIDs
- Un-resumed SIGSTOP signal masking
"""

from __future__ import annotations

import json
import logging
import os
import signal
import socket
import sys
import time
from typing import Any, Dict, List, Optional, Tuple, Union

import psutil

logger = logging.getLogger("agentguard.kernel.process")


def _safe_status(proc: psutil.Process) -> str:
    """Safely retrieves process status string, returning 'unknown' on error."""
    try:
        return str(proc.status())
    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        return "zombie"
    except psutil.AccessDenied:
        return "access_denied"
    except Exception:
        return "unknown"


def _safe_cpu_percent(proc: psutil.Process) -> float:
    """Safely retrieves CPU percent for a process."""
    try:
        val = proc.cpu_percent(interval=None)
        return float(val) if val is not None else 0.0
    except Exception:
        return 0.0


def _safe_memory_rss(proc: psutil.Process) -> int:
    """Safely retrieves RSS memory bytes for a process."""
    try:
        info = proc.memory_info()
        return int(info.rss) if hasattr(info, "rss") else 0
    except Exception:
        return 0


def pause_process_tree(pid: int) -> bool:
    """
    Recursively pauses an entire process tree using SIGSTOP.
    Signals children first (in reverse depth order) then the parent.

    Returns True if the target parent was successfully paused.
    Returns False if process does not exist, access is denied, or invalid PID.
    """
    if pid is None or not isinstance(pid, int) or pid <= 0:
        return False

    try:
        parent = psutil.Process(pid)
    except (psutil.NoSuchProcess, psutil.ZombieProcess, ValueError):
        return False
    except psutil.AccessDenied:
        logger.warning("Access denied opening PID %d for SIGSTOP", pid)
        return False

    # Check if parent is already a zombie
    try:
        if parent.status() == psutil.STATUS_ZOMBIE:
            return False
    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        return False
    except psutil.AccessDenied:
        pass

    # Collect all descendants
    try:
        children = parent.children(recursive=True)
    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        children = []
    except psutil.AccessDenied:
        children = []

    # 1. Suspend children in reverse order (leaves first)
    for child in reversed(children):
        try:
            if child.is_running() and child.status() != psutil.STATUS_ZOMBIE:
                child.send_signal(signal.SIGSTOP)
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            continue
        except psutil.AccessDenied:
            logger.warning("Access denied sending SIGSTOP to child PID %d", child.pid)

    # 2. Suspend parent
    try:
        if parent.is_running() and parent.status() != psutil.STATUS_ZOMBIE:
            parent.send_signal(signal.SIGSTOP)
            return True
        return False
    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        return False
    except psutil.AccessDenied:
        logger.warning("Access denied sending SIGSTOP to parent PID %d", pid)
        return False


def resume_process_tree(pid: int) -> bool:
    """
    Recursively resumes an entire paused process tree using SIGCONT.
    Signals the parent first, then all children.

    Returns True if the target parent was successfully resumed.
    Returns False if process does not exist, access is denied, or invalid PID.
    """
    if pid is None or not isinstance(pid, int) or pid <= 0:
        return False

    try:
        parent = psutil.Process(pid)
    except (psutil.NoSuchProcess, psutil.ZombieProcess, ValueError):
        return False
    except psutil.AccessDenied:
        logger.warning("Access denied opening PID %d for SIGCONT", pid)
        return False

    # Check if parent is a zombie
    try:
        if parent.status() == psutil.STATUS_ZOMBIE:
            return False
    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        return False
    except psutil.AccessDenied:
        pass

    # Collect descendants before or during resume
    try:
        children = parent.children(recursive=True)
    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        children = []
    except psutil.AccessDenied:
        children = []

    # 1. Resume parent first
    parent_resumed = False
    try:
        if parent.is_running() and parent.status() != psutil.STATUS_ZOMBIE:
            parent.send_signal(signal.SIGCONT)
            parent_resumed = True
        else:
            return False
    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        return False
    except psutil.AccessDenied:
        logger.warning("Access denied sending SIGCONT to parent PID %d", pid)
        return False

    # 2. Resume children
    for child in children:
        try:
            if child.is_running() and child.status() != psutil.STATUS_ZOMBIE:
                child.send_signal(signal.SIGCONT)
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            continue
        except psutil.AccessDenied:
            logger.warning("Access denied sending SIGCONT to child PID %d", child.pid)

    return parent_resumed


def terminate_process_tree(pid: int, timeout: float = 2.0) -> bool:
    """
    Recursively terminates an entire process tree.
    Sends SIGTERM to all processes, waits up to timeout seconds, and escalates
    to SIGKILL if any processes remain alive.

    If a process is currently paused (STATUS_STOPPED), SIGCONT is dispatched
    alongside SIGTERM/SIGKILL to ensure the kernel processes the termination.

    Returns True if all processes in the tree are gone.
    Returns False if any process remains alive after SIGKILL grace period.
    """
    if pid is None or not isinstance(pid, int) or pid <= 0:
        return False

    try:
        parent = psutil.Process(pid)
    except (psutil.NoSuchProcess, psutil.ZombieProcess, ValueError):
        return True  # Already terminated
    except psutil.AccessDenied:
        logger.warning("Access denied opening PID %d for termination", pid)
        return False

    # Collect all children and parent
    try:
        children = parent.children(recursive=True)
    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        children = []
    except psutil.AccessDenied:
        children = []

    all_procs = children + [parent]

    # 1. Dispatch SIGTERM (and wake up any stopped processes)
    for p in all_procs:
        try:
            if p.is_running():
                try:
                    if p.status() == psutil.STATUS_STOPPED:
                        p.send_signal(signal.SIGCONT)
                except (psutil.Error, OSError):
                    pass
                p.terminate()
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            pass
        except (psutil.AccessDenied, OSError):
            pass

    # 2. Wait for graceful exit
    gone, alive = psutil.wait_procs(all_procs, timeout=max(0.1, timeout))

    # 3. Escalate to SIGKILL for any stubborn survivors
    if alive:
        for p in alive:
            try:
                if p.is_running():
                    try:
                        p.send_signal(signal.SIGCONT)
                    except (psutil.Error, OSError):
                        pass
                    p.kill()
            except (psutil.NoSuchProcess, psutil.ZombieProcess):
                pass
            except (psutil.AccessDenied, OSError):
                pass

        # Brief grace wait for SIGKILL cleanup
        gone_kill, alive = psutil.wait_procs(alive, timeout=min(0.5, timeout))

    return len(alive) == 0


def get_process_tree_info(pid: int) -> Dict[str, Any]:
    """
    Returns comprehensive diagnostic information about a process tree.
    Includes PID, status, CPU %, memory RSS, child PIDs, and aggregate metrics.

    Raises psutil.NoSuchProcess if pid does not exist or is invalid.
    """
    if pid is None or not isinstance(pid, int) or pid <= 0:
        raise psutil.NoSuchProcess(pid if isinstance(pid, int) else 0, msg="Invalid PID")

    parent = psutil.Process(pid)

    status = _safe_status(parent)
    is_running = False
    try:
        is_running = parent.is_running() and status != "zombie"
    except Exception:
        pass

    parent_cpu = _safe_cpu_percent(parent)
    parent_rss = _safe_memory_rss(parent)

    num_threads = 0
    try:
        num_threads = parent.num_threads()
    except Exception:
        pass

    cmdline_parts: List[str] = []
    try:
        parts = parent.cmdline()
        if parts:
            cmdline_parts = list(parts)
    except Exception:
        pass
    cmdline_str = " ".join(cmdline_parts) if cmdline_parts else ""

    create_time = 0.0
    try:
        create_time = parent.create_time()
    except Exception:
        pass

    # Collect children details
    try:
        children = parent.children(recursive=True)
    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        children = []
    except psutil.AccessDenied:
        children = []

    child_pids: List[int] = []
    children_details: List[Dict[str, Any]] = []
    total_cpu = parent_cpu
    total_rss = parent_rss

    for child in children:
        c_pid = getattr(child, "pid", 0)
        if c_pid > 0:
            child_pids.append(c_pid)
            c_status = _safe_status(child)
            c_cpu = _safe_cpu_percent(child)
            c_rss = _safe_memory_rss(child)
            total_cpu += c_cpu
            total_rss += c_rss
            children_details.append({
                "pid": c_pid,
                "status": c_status,
                "cpu_percent": round(c_cpu, 2),
                "memory_rss_bytes": c_rss,
                "memory_rss_mb": round(c_rss / (1024 * 1024), 2),
            })

    return {
        "pid": pid,
        "status": status,
        "is_running": is_running,
        "is_stopped": (status == psutil.STATUS_STOPPED),
        "exists": True,
        "cpu_percent": round(parent_cpu, 2),
        "memory_rss_bytes": parent_rss,
        "memory_rss_mb": round(parent_rss / (1024 * 1024), 2),
        "children": child_pids,
        "child_pids": child_pids,
        "children_count": len(child_pids),
        "children_details": children_details,
        "tree_cpu_percent": round(total_cpu, 2),
        "tree_memory_rss_bytes": total_rss,
        "tree_memory_rss_mb": round(total_rss / (1024 * 1024), 2),
        "num_threads": num_threads,
        "cmdline": cmdline_str,
        "cmdline_parts": cmdline_parts,
        "create_time": create_time,
    }


# ---------------------------------------------------------------------------
# Aliases conforming to PROJECT.md § Interface Contracts
# ---------------------------------------------------------------------------
pause_tree = pause_process_tree
resume_tree = resume_process_tree
kill_tree = terminate_process_tree
inspect_tree = get_process_tree_info
get_tree_info = get_process_tree_info


# ---------------------------------------------------------------------------
# ProcessTreeController for Daemon IPC & Session Tracking
# ---------------------------------------------------------------------------
class ProcessTreeController:
    """
    Manager class coordinating process tree control, session ID lookups,
    and Human-in-the-Loop (HITL) async decision futures for AgentGuard.
    """

    def __init__(self, server: Optional[Any] = None):
        self.server = server
        self._pending_hitl: Dict[str, Any] = {}

    def resolve_pid(
        self, session_id: Optional[str] = None, pid: Optional[int] = None
    ) -> Optional[int]:
        """Resolves target PID from explicit PID or daemon session ID."""
        if pid is not None and isinstance(pid, int) and pid > 0:
            return pid
        if session_id and self.server and hasattr(self.server, "sessions"):
            sess = self.server.sessions.get(session_id)
            if sess and "pid" in sess:
                sess_pid = sess["pid"]
                if isinstance(sess_pid, int) and sess_pid > 0:
                    return sess_pid
        return None

    def pause_session(
        self, session_id: Optional[str] = None, pid: Optional[int] = None
    ) -> Dict[str, Any]:
        """Pauses agent process tree by session ID or PID."""
        target_pid = self.resolve_pid(session_id, pid)
        if target_pid is None:
            return {
                "status": "ERROR",
                "message": f"Could not resolve PID for session '{session_id}'",
                "pid": 0,
            }

        success = pause_process_tree(target_pid)
        if success:
            if self.server and hasattr(self.server, "audit_logger"):
                self.server.audit_logger.log(
                    "PROCESS_PAUSED",
                    session_id=session_id or f"pid:{target_pid}",
                    status="ALLOWED",
                    details={"pid": target_pid, "signal": "SIGSTOP"},
                )
            return {"status": "PAUSED", "pid": target_pid, "success": True}
        return {
            "status": "ERROR",
            "message": f"Failed to pause process tree for PID {target_pid}",
            "pid": target_pid,
            "success": False,
        }

    def resume_session(
        self, session_id: Optional[str] = None, pid: Optional[int] = None
    ) -> Dict[str, Any]:
        """Resumes agent process tree by session ID or PID."""
        target_pid = self.resolve_pid(session_id, pid)
        if target_pid is None:
            return {
                "status": "ERROR",
                "message": f"Could not resolve PID for session '{session_id}'",
                "pid": 0,
            }

        success = resume_process_tree(target_pid)
        if success:
            if self.server and hasattr(self.server, "audit_logger"):
                self.server.audit_logger.log(
                    "PROCESS_RESUMED",
                    session_id=session_id or f"pid:{target_pid}",
                    status="ALLOWED",
                    details={"pid": target_pid, "signal": "SIGCONT"},
                )
            return {"status": "RESUMED", "pid": target_pid, "success": True}
        return {
            "status": "ERROR",
            "message": f"Failed to resume process tree for PID {target_pid}",
            "pid": target_pid,
            "success": False,
        }

    def terminate_session(
        self,
        session_id: Optional[str] = None,
        pid: Optional[int] = None,
        timeout: float = 2.0,
    ) -> Dict[str, Any]:
        """Kills agent process tree by session ID or PID."""
        target_pid = self.resolve_pid(session_id, pid)
        if target_pid is None:
            return {
                "status": "ERROR",
                "message": f"Could not resolve PID for session '{session_id}'",
                "pid": 0,
            }

        success = terminate_process_tree(target_pid, timeout=timeout)
        if success:
            if self.server and hasattr(self.server, "audit_logger"):
                self.server.audit_logger.log(
                    "PROCESS_TERMINATED",
                    session_id=session_id or f"pid:{target_pid}",
                    status="ALLOWED",
                    details={"pid": target_pid, "signal": "SIGKILL"},
                )
            return {"status": "TERMINATED", "pid": target_pid, "success": True}
        return {
            "status": "ERROR",
            "message": f"Failed to cleanly terminate process tree for PID {target_pid}",
            "pid": target_pid,
            "success": False,
        }

    def inspect_session(
        self, session_id: Optional[str] = None, pid: Optional[int] = None
    ) -> Dict[str, Any]:
        """Returns deep telemetry for agent inspection modal and API."""
        target_pid = self.resolve_pid(session_id, pid) or 0
        info: Dict[str, Any] = {}
        if target_pid > 0:
            try:
                info = get_process_tree_info(target_pid)
            except (psutil.NoSuchProcess, psutil.ZombieProcess, ValueError):
                info = {"pid": target_pid, "status": "not_found", "is_running": False}

        profile = "generic"
        taint_state = "CLEAN"
        taint_chain: List[str] = []
        recent_commands: List[str] = []

        if session_id and self.server:
            sess = getattr(self.server, "sessions", {}).get(session_id, {})
            profile = sess.get("profile", "generic")
            if hasattr(self.server, "taint_engine"):
                taint_state = self.server.taint_engine.get_taint(session_id)
                if hasattr(self.server.taint_engine, "get_provenance_chain"):
                    taint_chain = self.server.taint_engine.get_provenance_chain(session_id)
                else:
                    taint_chain = [f"session:{session_id}"]

            if hasattr(self.server, "audit_logger"):
                events = self.server.audit_logger.get_events(limit=50)
                for ev in events:
                    if ev.get("session_id") == session_id:
                        d = ev.get("details", {})
                        cmd = d.get("command") or d.get("action")
                        if cmd and cmd not in recent_commands:
                            recent_commands.append(cmd)

        return {
            "pid": target_pid,
            "profile": profile,
            "taint_state": taint_state,
            "taint_chain": taint_chain,
            "recent_commands": recent_commands[-10:],
            "cpu_percent": info.get("tree_cpu_percent", info.get("cpu_percent", 0.0)),
            "memory_rss_bytes": info.get("tree_memory_rss_bytes", info.get("memory_rss_bytes", 0)),
            "process_info": info,
        }

    def register_hitl_request(self, request_id: str, future: Any) -> None:
        """Registers a pending HITL decision future."""
        self._pending_hitl[request_id] = future

    def resolve_hitl_decision(self, request_id: str, decision: str) -> bool:
        """Resolves a pending HITL decision ('ALLOW' or 'DENY')."""
        fut = self._pending_hitl.pop(request_id, None)
        if fut and not fut.done():
            fut.set_result(decision.upper())
            return True
        return False


# ---------------------------------------------------------------------------
# Shell Shim Interactive Terminal Fallback Helpers
# ---------------------------------------------------------------------------
def prompt_interactive_terminal_fallback(
    command: str,
    reason: str,
    tty_path: str = "/dev/tty",
    input_stream=None,
    output_stream=None,
) -> bool:
    """
    Direct /dev/tty fallback prompt for interactive terminals.
    Bypasses redirected stdin/stdout pipes to directly query the operator.
    Returns True if allowed once, False if denied.
    """
    if input_stream is not None and output_stream is not None:
        try:
            output_stream.write("\n" + "=" * 60 + "\n")
            output_stream.write("⚠️  [AgentGuard Security Alert] High-Risk Command Intercepted\n")
            output_stream.write(f"  Command: {command}\n")
            output_stream.write(f"  Reason:  {reason}\n")
            output_stream.write("=" * 60 + "\n")
            output_stream.write("Allow this operation? [A]llow once / [D]eny (default Deny): ")
            output_stream.flush()

            raw = input_stream.readline()
            choice = raw.strip().lower() if raw else ""
            if choice in ("a", "allow", "y", "yes"):
                output_stream.write("  [+] Command APPROVED by operator.\n\n")
                output_stream.flush()
                return True
            else:
                output_stream.write("  [-] Command DENIED by operator.\n\n")
                output_stream.flush()
                return False
        except Exception:
            return False

    try:
        with open(tty_path, "r+", buffering=1) as tty:
            tty.write("\n" + "=" * 60 + "\n")
            tty.write("⚠️  [AgentGuard Security Alert] High-Risk Command Intercepted\n")
            tty.write(f"  Command: {command}\n")
            tty.write(f"  Reason:  {reason}\n")
            tty.write("=" * 60 + "\n")
            tty.write("Allow this operation? [A]llow once / [D]eny (default Deny): ")
            tty.flush()

            line = tty.readline()
            choice = line.strip().lower() if line else ""
            if choice in ("a", "allow", "y", "yes"):
                tty.write("  [+] Command APPROVED by operator.\n\n")
                tty.flush()
                return True
            else:
                tty.write("  [-] Command DENIED by operator.\n\n")
                tty.flush()
                return False
    except (OSError, IOError):
        sys.stderr.write(
            f"[AgentGuard] Dangerous command intercepted but no controlling TTY: {command}\n"
        )
        return False


def notify_daemon_hitl_decision(
    socket_path: str,
    session_id: str,
    hitl_request_id: str,
    decision: str,
    timeout: float = 1.0,
) -> bool:
    """
    Submits the operator's decision to the AgentGuard daemon over UDS.
    """
    if not os.path.exists(socket_path):
        return False

    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect(socket_path)
        req = {
            "protocol_version": "1.0",
            "action": "HITL_DECISION",
            "session_id": session_id,
            "pid": os.getpid(),
            "payload": {
                "request_id": hitl_request_id,
                "decision": decision,
            },
        }
        s.sendall((json.dumps(req) + "\n").encode("utf-8"))
        raw = s.recv(4096).decode("utf-8").strip()
        s.close()
        res = json.loads(raw)
        return res.get("status") == "ALLOWED"
    except Exception:
        return False


def handle_shim_hitl_cycle(
    resp: Dict[str, Any],
    command: str,
    socket_path: str,
    session_id: str,
    tty_path: str = "/dev/tty",
    input_stream=None,
    output_stream=None,
) -> bool:
    """
    Coordinates the full shim fallback cycle if status is PROMPT_HITL.
    Returns True if allowed to proceed, False if command should be blocked.
    """
    status = resp.get("status")
    if status == "ALLOWED":
        return True
    if status == "BLOCKED":
        return False

    if status == "PROMPT_HITL":
        data = resp.get("data", {})
        hitl_req_id = data.get("hitl_request_id") or resp.get("request_id", "")
        reason = data.get("reason", "High-risk command execution")

        allowed = prompt_interactive_terminal_fallback(
            command=command,
            reason=reason,
            tty_path=tty_path,
            input_stream=input_stream,
            output_stream=output_stream,
        )

        decision = "ALLOW" if allowed else "DENY"
        if hitl_req_id:
            notify_daemon_hitl_decision(
                socket_path=socket_path,
                session_id=session_id,
                hitl_request_id=hitl_req_id,
                decision=decision,
            )

        return allowed

    return False
