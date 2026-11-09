"""
agentguard.notifications.dispatcher - Non-Blocking Async Queue Dispatcher.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import logging
from typing import Any, Dict, Optional, Union
import urllib.request
import urllib.error

from agentguard.notifications.config import NotificationConfig, load_notification_config
from agentguard.notifications.discord import (
    build_discord_alert,
    build_discord_heartbeat,
    send_discord_payload,
)
from agentguard.notifications.telegram import (
    build_telegram_alert,
    build_telegram_heartbeat,
    send_telegram_payload,
)

logger = logging.getLogger("agentguard.notifications")

HIGH_RISK_EVENT_TYPES = {
    "COMMAND_BLOCKED",
    "TAINT_ESCALATION",
    "TAINT_CHANGE",
    "MANUAL_TAINT",
    "PROPAGATE_TAINT",
    "SECRET_EXFILTRATION_ATTEMPT",
    "VAULT_DETOKENIZE_BLOCKED",
    "CRITICAL_INTENT_DRIFT",
    "INTENT_DRIFT_BLOCKED",
}


class _CompletedAwaitable:
    """Helper enabling methods to be both called synchronously and awaited."""
    def __await__(self):
        yield
        return None


class NotificationDispatcher:
    """
    Asynchronous non-blocking notification dispatcher.
    Queues security events and dispatches alerts via background worker.
    """

    def __init__(
        self,
        config: Optional[NotificationConfig] = None,
        max_queue_size: int = 1000,
        timeout: float = 3.0,
        max_retries: int = 0,
        retry_backoff: float = 0.5,
    ):
        self.config = config if config is not None else load_notification_config()
        self.max_queue_size = max(1, max_queue_size)
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_backoff = retry_backoff

        self._queue: Optional[asyncio.Queue[Dict[str, Any]]] = None
        self._worker_task: Optional[asyncio.Task] = None
        self._running = False
        self.stats_data = {
            "enqueued": 0,
            "dispatched_discord": 0,
            "dispatched_telegram": 0,
            "failures": 0,
            "dropped": 0,
        }

    @property
    def queue(self) -> asyncio.Queue[Dict[str, Any]]:
        """Returns internal queue, initializing it with event loop on demand."""
        if self._queue is None:
            try:
                asyncio.get_running_loop()
            except RuntimeError:
                try:
                    asyncio.get_event_loop()
                except RuntimeError:
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
            self._queue = asyncio.Queue(maxsize=self.max_queue_size)
        return self._queue

    @property
    def dropped_count(self) -> int:
        """Total number of dropped notifications due to queue overflow."""
        return self.stats_data["dropped"]

    def stats(self) -> Dict[str, Any]:
        """Returns diagnostic statistics of dispatcher operation."""
        return {
            "running": self._running,
            "queue_size": self.queue.qsize(),
            "enqueued": self.stats_data["enqueued"],
            "dispatched_discord": self.stats_data["dispatched_discord"],
            "dispatched_telegram": self.stats_data["dispatched_telegram"],
            "failures": self.stats_data["failures"],
            "dropped": self.stats_data["dropped"],
        }

    def start(self, loop: Optional[asyncio.AbstractEventLoop] = None) -> Any:
        """
        Starts background worker task.
        Can be called synchronously or awaited.
        """
        if not self._running:
            self._running = True
            self._worker_task = asyncio.create_task(self._worker_loop())
        return _CompletedAwaitable()

    async def stop(self, timeout: float = 1.0) -> None:
        """Stops background worker cleanly and drains remaining tasks."""
        if not self._running:
            return
        self._running = False
        if self._worker_task:
            self._worker_task.cancel()
            try:
                await asyncio.wait_for(asyncio.shield(self._worker_task), timeout=timeout)
            except (asyncio.TimeoutError, asyncio.CancelledError, Exception):
                pass
            self._worker_task = None

    async def drain(self, timeout: float = 2.0) -> None:
        """Waits for all currently queued items to be processed."""
        if self._queue is None:
            return
        try:
            await asyncio.wait_for(self.queue.join(), timeout=timeout)
        except (asyncio.TimeoutError, Exception):
            pass

    def enqueue_alert(
        self,
        event_type: str,
        details: Optional[Dict[str, Any]] = None,
        severity: Optional[str] = None,
        session_id: str = "unknown",
        pid: Optional[int] = None,
        profile: str = "generic",
        reason: str = "",
        command: str = "",
        taint_source: str = "",
        timestamp: Optional[str] = None,
    ) -> bool:
        """
        Enqueues threat alert into in-memory bounded queue.
        Sub-0.05ms non-blocking call.
        """
        if not self.config.enabled:
            return False

        now_iso = timestamp or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        item = {
            "type": "ALERT",
            "event_type": event_type,
            "severity": severity,
            "details": details or {},
            "session_id": session_id,
            "pid": pid,
            "profile": profile,
            "reason": reason,
            "command": command,
            "taint_source": taint_source,
            "timestamp": now_iso,
        }
        return self._enqueue_item(item)

    # Alias for threat alert
    enqueue_threat_alert = enqueue_alert

    def enqueue_heartbeat(self, status_data: Dict[str, Any]) -> bool:
        """Enqueues health heartbeat summary into in-memory queue."""
        if not self.config.enabled or not self.config.heartbeat.enabled:
            return False

        now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        item = {
            "type": "HEARTBEAT",
            "status_data": status_data,
            "timestamp": now_iso,
        }
        return self._enqueue_item(item)

    def enqueue(self, item: Any) -> bool:
        """Universal item enqueue supporting dictionaries or AuditEvent objects."""
        if not self.config.enabled:
            return False

        if isinstance(item, dict):
            return self._enqueue_item(item)

        # Support AuditEvent-like objects
        ev_type = getattr(item, "event_type", "AUDIT_EVENT")
        details = getattr(item, "details", {})
        status = getattr(item, "status", "INFO")
        sess_id = getattr(item, "session_id", "unknown")
        pid = getattr(item, "pid", 0)
        ts = getattr(item, "timestamp", None)
        return self.enqueue_alert(
            event_type=ev_type,
            details=details,
            severity="CRITICAL" if status == "BLOCKED" else "WARNING",
            session_id=sess_id,
            pid=pid,
            timestamp=ts,
        )

    def _enqueue_item(self, item: Dict[str, Any]) -> bool:
        """Internal bounded queue put_nowait with overflow protection."""
        try:
            self.queue.put_nowait(item)
            self.stats_data["enqueued"] += 1
            return True
        except asyncio.QueueFull:
            self.stats_data["dropped"] += 1
            logger.warning("Notification queue full; alert dropped to preserve memory bounds.")
            return False

    async def _worker_loop(self) -> None:
        """Continuous background worker loop consuming queue."""
        while self._running:
            try:
                item = await self.queue.get()
            except asyncio.CancelledError:
                break

            try:
                await self._process_item(item)
            except Exception as exc:
                self.stats_data["failures"] += 1
                logger.debug(f"Notification dispatch worker error: {exc}")
            finally:
                self.queue.task_done()

    async def _process_item(self, item: Dict[str, Any]) -> None:
        """Dispatches an item to Discord and/or Telegram."""
        item_type = item.get("type")

        # 1. Discord Channel
        if self.config.discord.enabled and self.config.discord.webhook_url:
            await self._dispatch_discord(item, item_type)

        # 2. Telegram Channel
        if (
            self.config.telegram.enabled
            and self.config.telegram.bot_token
            and (self.config.telegram.chat_id or self.config.telegram.bot_token.startswith("http"))
        ):
            await self._dispatch_telegram(item, item_type)

    async def _dispatch_discord(self, item: Dict[str, Any], item_type: Optional[str]) -> None:
        """Builds and delivers Discord payload with retry logic."""
        if item_type == "ALERT":
            discord_payload = build_discord_alert(
                event_type=item.get("event_type", "ALERT"),
                details=item.get("details"),
                severity=item.get("severity"),
                session_id=item.get("session_id", "unknown"),
                pid=item.get("pid"),
                profile=item.get("profile", "generic"),
                reason=item.get("reason", ""),
                command=item.get("command", ""),
                taint_source=item.get("taint_source", ""),
                timestamp=item.get("timestamp"),
                username=self.config.discord.username,
                avatar_url=self.config.discord.avatar_url,
            )
        else:
            discord_payload = build_discord_heartbeat(
                status_data=item.get("status_data", {}),
                timestamp=item.get("timestamp"),
                username=self.config.discord.username,
            )

        for attempt in range(self.max_retries + 1):
            try:
                ok = await asyncio.to_thread(
                    send_discord_payload,
                    self.config.discord.webhook_url,
                    discord_payload,
                    self.timeout,
                )
                if ok:
                    self.stats_data["dispatched_discord"] += 1
                    return
            except urllib.error.HTTPError as he:
                if he.code == 429 and attempt < self.max_retries:
                    retry_after = 0.5
                    try:
                        retry_after = float(he.headers.get("Retry-After", retry_after))
                    except (ValueError, TypeError):
                        pass
                    await asyncio.sleep(min(retry_after, 2.0))
                    continue
                elif attempt < self.max_retries:
                    await asyncio.sleep(self.retry_backoff * (attempt + 1))
                    continue
            except Exception as exc:
                if attempt < self.max_retries:
                    await asyncio.sleep(self.retry_backoff * (attempt + 1))
                    continue
                logger.debug(f"Discord dispatch error on attempt {attempt}: {exc}")

        self.stats_data["failures"] += 1

    async def _dispatch_telegram(self, item: Dict[str, Any], item_type: Optional[str]) -> None:
        """Builds and delivers Telegram message with retry logic."""
        if item_type == "ALERT":
            telegram_text = build_telegram_alert(
                event_type=item.get("event_type", "ALERT"),
                details=item.get("details"),
                severity=item.get("severity"),
                session_id=item.get("session_id", "unknown"),
                pid=item.get("pid"),
                profile=item.get("profile", "generic"),
                reason=item.get("reason", ""),
                command=item.get("command", ""),
                taint_source=item.get("taint_source", ""),
                timestamp=item.get("timestamp"),
            )
        else:
            telegram_text = build_telegram_heartbeat(
                status_data=item.get("status_data", {}),
                timestamp=item.get("timestamp"),
            )

        for attempt in range(self.max_retries + 1):
            try:
                ok = await asyncio.to_thread(
                    send_telegram_payload,
                    self.config.telegram.bot_token,
                    self.config.telegram.chat_id,
                    telegram_text,
                    self.config.telegram.parse_mode,
                    None,
                    self.timeout,
                )
                if ok:
                    self.stats_data["dispatched_telegram"] += 1
                    return
            except urllib.error.HTTPError as he:
                if he.code == 429 and attempt < self.max_retries:
                    retry_after = 0.5
                    try:
                        retry_after = float(he.headers.get("Retry-After", retry_after))
                    except (ValueError, TypeError):
                        pass
                    await asyncio.sleep(min(retry_after, 2.0))
                    continue
                elif attempt < self.max_retries:
                    await asyncio.sleep(self.retry_backoff * (attempt + 1))
                    continue
            except Exception as exc:
                if attempt < self.max_retries:
                    await asyncio.sleep(self.retry_backoff * (attempt + 1))
                    continue
                logger.debug(f"Telegram dispatch error on attempt {attempt}: {exc}")

        self.stats_data["failures"] += 1
