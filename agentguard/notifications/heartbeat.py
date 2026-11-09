"""
agentguard.notifications.heartbeat - Health Telemetry & Periodic Heartbeat Scheduler.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import logging
import os
import sys
import time
from typing import Any, Dict, Optional, Union

from agentguard.notifications.discord import build_discord_heartbeat, format_discord_heartbeat
from agentguard.notifications.telegram import build_telegram_heartbeat, format_telegram_heartbeat

logger = logging.getLogger("agentguard.notifications")


def format_uptime(seconds: Union[int, float]) -> str:
    """Formats raw seconds into human-readable uptime strings (e.g. 45s, 1h 1m 5s, 1d 1h 0m 0s)."""
    sec = max(0, int(seconds))
    days, rem = divmod(sec, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)

    if days > 0:
        return f"{days}d {hours}h {minutes}m {secs}s"
    elif hours > 0:
        return f"{hours}h {minutes}m {secs}s"
    elif minutes > 0:
        return f"{minutes}m {secs}s"
    else:
        return f"{secs}s"


def get_process_ram_rss_bytes() -> int:
    """Returns the current process resident set size (RSS) in bytes."""
    try:
        import psutil
        return int(psutil.Process(os.getpid()).memory_info().rss)
    except Exception:
        pass

    try:
        import resource
        ru = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        if sys.platform == "darwin":
            return int(ru)
        return int(ru * 1024)
    except Exception:
        return 42 * 1024 * 1024


def get_process_ram_rss_mb() -> float:
    """Returns the current process resident set size (RSS) in megabytes."""
    return get_process_ram_rss_bytes() / (1024.0 * 1024.0)


def compile_heartbeat_metrics(server_or_data: Any = None) -> Dict[str, Any]:
    """Compiles unified health and security metrics from server instance or dictionary."""
    if isinstance(server_or_data, dict):
        data = dict(server_or_data)
        uptime = data.get("uptime_seconds", 0)
        data.setdefault("uptime_str", format_uptime(uptime))
        data.setdefault("memory_rss_bytes", get_process_ram_rss_bytes())
        data.setdefault("memory_rss_mb", get_process_ram_rss_mb())
        data.setdefault("timestamp", datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"))
        return data

    server = server_or_data
    uptime_sec = int(time.time() - getattr(server, "_start_time", time.time())) if server else 0

    active_agents = len(getattr(server, "sessions", {})) if server else 0
    tainted_count = 0
    if server and hasattr(server, "taint_engine"):
        for s in server.sessions:
            if server.taint_engine.get_taint(s) == "TAINTED":
                tainted_count += 1

    vault_count = 0
    if server and hasattr(server, "vault"):
        vault_count = len(server.vault)

    total_events = 0
    blocked_count = 0
    if server and hasattr(server, "audit_logger"):
        total_events = server.audit_logger.total_logged
        blocked_count = getattr(server.audit_logger, "blocked_count", 0)

    rss_bytes = get_process_ram_rss_bytes()
    rss_mb = rss_bytes / (1024.0 * 1024.0)

    return {
        "status": "HEALTHY",
        "health": "healthy",
        "pid": os.getpid(),
        "uptime_seconds": uptime_sec,
        "uptime_str": format_uptime(uptime_sec),
        "active_agents": active_agents,
        "active_sessions": active_agents,
        "tainted_agents": tainted_count,
        "tainted_sessions": tainted_count,
        "vault_tokens": vault_count,
        "vaulted_secrets": vault_count,
        "blocked_exploits": blocked_count,
        "blocked_count": blocked_count,
        "total_audit_events": total_events,
        "audit_events": total_events,
        "memory_rss_bytes": rss_bytes,
        "memory_rss_mb": round(rss_mb, 2),
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


# Alias
compile_heartbeat_payload = compile_heartbeat_metrics


class HealthHeartbeatTask:
    """
    Background periodic async task for compiling and enqueuing system health heartbeats.
    """

    def __init__(
        self,
        server: Any,
        dispatcher: Any,
        interval_seconds: int = 3600,
        enabled: bool = True,
        send_on_start: bool = True,
    ):
        self.server = server
        self.dispatcher = dispatcher
        self.interval_seconds = max(10, interval_seconds)
        self.enabled = enabled
        self.send_on_start = send_on_start
        self._task: Optional[asyncio.Task] = None
        self._stop_event: Optional[asyncio.Event] = None
        self._running = False

    def start(self, loop: Optional[asyncio.AbstractEventLoop] = None) -> None:
        """Starts periodic heartbeat runner loop."""
        if self._running or not self.enabled:
            return
        self._running = True
        self._stop_event = asyncio.Event()
        self._task = asyncio.create_task(self._run_loop())

    async def stop(self) -> None:
        """Stops the heartbeat loop cleanly."""
        if not self._running:
            return
        self._running = False
        if self._stop_event:
            self._stop_event.set()
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    def trigger_now(self) -> bool:
        """Immediately compiles metrics and enqueues a heartbeat."""
        if not self.dispatcher:
            return False
        metrics = compile_heartbeat_metrics(self.server)
        return self.dispatcher.enqueue_heartbeat(metrics)

    async def _run_loop(self) -> None:
        """Asynchronous execution loop for heartbeat interval."""
        if self.send_on_start:
            try:
                self.trigger_now()
            except Exception as e:
                logger.debug(f"Startup heartbeat dispatch failed: {e}")

        while self._running:
            try:
                # Wait for interval or stop event
                if self._stop_event:
                    try:
                        await asyncio.wait_for(self._stop_event.wait(), timeout=float(self.interval_seconds))
                        break  # Stop was signaled
                    except asyncio.TimeoutError:
                        pass  # Interval expired, proceed to heartbeat
                else:
                    await asyncio.sleep(float(self.interval_seconds))

                if self._running:
                    self.trigger_now()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.debug(f"Heartbeat loop iteration error: {exc}")
                await asyncio.sleep(5.0)
