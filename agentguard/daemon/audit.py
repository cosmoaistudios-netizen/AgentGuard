"""
AgentGuard Audit Event Logger.

Provides high-performance dual-tier audit logging:
1. In-memory bounded ring buffer (collections.deque) for fast queries.
2. Crash-resilient append-only JSONL log on disk (~/.agentguard/audit.jsonl).
"""

import collections
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import threading
from typing import Any, Callable, Deque, Dict, List, Optional, Union
import uuid


class AuditEvent:
    """Structured security audit event conforming to AgentGuard schema."""

    def __init__(
        self,
        event_type: str,
        session_id: str = "",
        pid: int = 0,
        status: str = "INFO",
        details: Optional[Dict[str, Any]] = None,
        event_id: Optional[str] = None,
        timestamp: Optional[str] = None,
    ):
        self.event_type = str(event_type)
        self.session_id = str(session_id)
        self.pid = int(pid)
        self.status = str(status)
        self.details = details or {}
        self.event_id = event_id or str(uuid.uuid4())
        if timestamp:
            self.timestamp = timestamp
        else:
            self.timestamp = (
                datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            )

    @classmethod
    def create(
        cls,
        event_type: str,
        session_id: str = "",
        pid: int = 0,
        status: str = "INFO",
        details: Optional[Dict[str, Any]] = None,
        event_id: Optional[str] = None,
        timestamp: Optional[str] = None,
    ) -> "AuditEvent":
        """Convenience factory method."""
        return cls(
            event_type=event_type,
            session_id=session_id,
            pid=pid,
            status=status,
            details=details,
            event_id=event_id,
            timestamp=timestamp,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "timestamp": self.timestamp,
            "event_id": self.event_id,
            "session_id": self.session_id,
            "pid": self.pid,
            "event_type": self.event_type,
            "status": self.status,
            "details": self.details,
        }

    def to_json(self) -> str:
        """Serialize to compact JSON string."""
        return json.dumps(self.to_dict(), separators=(",", ":"))

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuditEvent":
        """Reconstruct AuditEvent from dictionary."""
        return cls(
            event_type=data.get("event_type", data.get("action", "UNKNOWN")),
            session_id=data.get("session_id", ""),
            pid=data.get("pid", 0),
            status=data.get("status", "INFO"),
            details=data.get("details", {}),
            event_id=data.get("event_id"),
            timestamp=data.get("timestamp"),
        )

    @classmethod
    def from_json(cls, json_str: str) -> "AuditEvent":
        """Reconstruct AuditEvent from JSON string."""
        data = json.loads(json_str)
        return cls.from_dict(data)

    def __repr__(self) -> str:
        return (
            f"AuditEvent(type={self.event_type!r}, "
            f"session={self.session_id!r}, "
            f"status={self.status!r}, ts={self.timestamp!r})"
        )


class AuditLogger:
    """
    Thread-safe, high-performance audit logger.

    Maintains an in-memory ring buffer for sub-millisecond IPC queries
    and writes append-only JSONL entries to disk for durability.
    """

    DEFAULT_LOG_PATH = Path.home() / ".agentguard" / "audit.jsonl"
    DEFAULT_BUFFER_CAPACITY = 1000

    def __init__(
        self,
        log_path: Optional[Union[str, Path]] = None,
        buffer_capacity: int = DEFAULT_BUFFER_CAPACITY,
        siem_forwarder: Optional[Any] = None,
        enable_siem: Optional[bool] = None,
        siem_config_path: Optional[Union[str, Path]] = None,
    ):
        if log_path is None:
            self.log_path: Optional[Path] = self.DEFAULT_LOG_PATH
        elif str(log_path).strip() == "":
            self.log_path = None
        else:
            self.log_path = Path(log_path).expanduser().resolve()

        self.buffer_capacity = max(1, buffer_capacity)
        self._buffer: Deque[AuditEvent] = collections.deque(
            maxlen=self.buffer_capacity
        )
        self._total_logged: int = 0
        self._blocked_count: int = 0
        self._listeners: List[Callable[[AuditEvent], None]] = []
        self._lock = threading.RLock()

        if self.log_path:
            try:
                self.log_path.parent.mkdir(parents=True, exist_ok=True)
            except OSError:
                pass

        # Enterprise SIEM Telemetry Forwarder Initialization
        self.siem_forwarder = siem_forwarder
        if self.siem_forwarder is None:
            should_check = (
                enable_siem is True
                or (enable_siem is None and os.environ.get("AGENTGUARD_SIEM_ENABLED", "").lower() in ("1", "true", "yes", "on"))
                or (enable_siem is None and siem_config_path is not None)
                or (enable_siem is None and (Path.home() / ".agentguard" / "siem.yaml").exists())
            )
            if should_check:
                try:
                    from agentguard.exporters.siem_forwarder import (
                        SIEMForwarder,
                        load_siem_config,
                    )
                    cfg = load_siem_config(custom_path=siem_config_path)
                    if cfg.enabled or enable_siem is True:
                        self.siem_forwarder = SIEMForwarder(config=cfg)
                except Exception:
                    self.siem_forwarder = None

        if self.siem_forwarder is not None:
            self.add_listener(self._forward_to_siem)

    def _forward_to_siem(self, event: AuditEvent) -> None:
        """Listener callback dispatching events to enterprise SIEM telemetry forwarder."""
        if self.siem_forwarder is not None:
            try:
                self.siem_forwarder.enqueue_event(event)
            except Exception:
                return

    def flush_siem(self) -> int:
        """Forces an immediate synchronous flush of pending SIEM events."""
        if self.siem_forwarder is not None:
            return self.siem_forwarder.flush_sync()
        return 0

    def close(self) -> None:
        """Flushes SIEM forwarder and prepares logger for termination."""
        if self.siem_forwarder is not None:
            try:
                self.siem_forwarder.flush_sync()
            except Exception:
                return

    @property
    def total_logged(self) -> int:
        """Total number of events logged in the lifetime of this logger."""
        with self._lock:
            return self._total_logged

    @property
    def blocked_count(self) -> int:
        """Total number of BLOCKED events intercepted."""
        with self._lock:
            return self._blocked_count

    def add_listener(self, listener: Callable[[AuditEvent], None]) -> None:
        """Register a subscriber callback invoked for every audit event."""
        with self._lock:
            if listener not in self._listeners:
                self._listeners.append(listener)

    def remove_listener(self, listener: Callable[[AuditEvent], None]) -> None:
        """Unregister an existing subscriber callback."""
        with self._lock:
            if listener in self._listeners:
                self._listeners.remove(listener)

    def log_event(self, event: AuditEvent) -> AuditEvent:
        """Append an event to ring buffer and persistent disk storage, then notify listeners."""
        with self._lock:
            self._buffer.append(event)
            self._total_logged += 1
            if event.status == "BLOCKED" or "BLOCKED" in event.event_type:
                self._blocked_count += 1

            if self.log_path:
                try:
                    with open(self.log_path, "a", encoding="utf-8") as f:
                        f.write(event.to_json() + "\n")
                        f.flush()
                except OSError:
                    pass

            listeners = list(self._listeners)

        for listener in listeners:
            try:
                listener(event)
            except Exception:
                pass

        return event

    def log(
        self,
        event_type: str,
        session_id: str = "",
        pid: int = 0,
        status: str = "INFO",
        details: Optional[Dict[str, Any]] = None,
        event_id: Optional[str] = None,
        timestamp: Optional[str] = None,
    ) -> AuditEvent:
        """Create and log an event in a single atomic call."""
        event = AuditEvent.create(
            event_type=event_type,
            session_id=session_id,
            pid=pid,
            status=status,
            details=details,
            event_id=event_id,
            timestamp=timestamp,
        )
        return self.log_event(event)

    def query(
        self,
        limit: Optional[int] = 50,
        event_type: Optional[str] = None,
        session_id: Optional[str] = None,
        since: Optional[Union[float, str]] = None,
    ) -> List[Dict[str, Any]]:
        """Query recent events from in-memory ring buffer with filtering."""
        with self._lock:
            events = list(self._buffer)

        matched: List[Dict[str, Any]] = []
        for ev in events:
            if event_type and ev.event_type.lower() != event_type.lower():
                continue
            if session_id and ev.session_id != session_id:
                continue
            if since and isinstance(since, str) and ev.timestamp < since:
                continue
            matched.append(ev.to_dict())

        if limit is not None and limit > 0:
            return matched[-limit:]
        return matched

    def get_events(
        self, limit: int = 50, **kwargs: Any
    ) -> List[Dict[str, Any]]:
        """Convenience method returning recent event dicts."""
        return self.query(limit=limit, **kwargs)

    def read_from_disk(
        self,
        limit: Optional[int] = 50,
        event_type: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Read historical events directly from JSONL file with bounded memory.
        Uses a fixed-size deque to stream file contents without high RAM usage.
        """
        if not self.log_path or not os.path.exists(self.log_path):
            return []

        max_items = limit if (limit and limit > 0) else None
        matched: Deque[Dict[str, Any]] = collections.deque(maxlen=max_items)

        with self._lock:
            try:
                with open(self.log_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            data = json.loads(line)
                        except json.JSONDecodeError:
                            continue

                        if event_type:
                            ev_type = data.get(
                                "event_type", data.get("action", "")
                            )
                            if str(ev_type).lower() != event_type.lower():
                                continue

                        if session_id and data.get("session_id") != session_id:
                            continue

                        matched.append(data)
            except OSError:
                return []

        return list(matched)

    def clear(self) -> None:
        """Clear the in-memory ring buffer."""
        with self._lock:
            self._buffer.clear()
            self._total_logged = 0
            self._blocked_count = 0

    def __len__(self) -> int:
        """Returns the number of events currently in the in-memory buffer."""
        with self._lock:
            return len(self._buffer)

    def __bool__(self) -> bool:
        """AuditLogger instances are always truthy even if buffer is empty."""
        return True
