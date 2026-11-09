"""
AgentGuard Enterprise SIEM Telemetry Forwarder.

Provides resilient, asynchronous, tamper-proof forwarding of audit security events
to enterprise log analytics and SIEM collectors:
1. Multi-Vendor SIEM Ingest Support:
   - Splunk HTTP Event Collector (HEC) with standard JSON payload format.
   - Datadog Logs API (v2) with structured tags and status mapping.
   - AWS CloudWatch / S3 JSON proxy endpoints.
   - Custom Generic Webhooks with batch envelopes.
2. Tamper-Proof Cryptographic Verification:
   - HMAC-SHA256 signature calculated over the exact raw HTTP payload bytes using
     a pre-shared enterprise secret (AGENTGUARD_HMAC_SECRET).
   - Injected in HTTP headers (X-AgentGuard-Signature: sha256=<hex>).
   - Prevents log tampering, injection, or spoofing from compromised agent runtimes.
3. High Resilience & Local Disk Spooling:
   - Non-blocking in-memory queue with backpressure controls.
   - Configurable batching window (batch_size or flush_interval).
   - Exponential backoff with jitter on network or 5xx HTTP failures.
   - Offline local disk queue spooling (~/.agentguard/siem_spool.jsonl) with automatic
     drain and replay upon network restoration.
   - Clean shutdown handlers ensuring pending events are flushed or safely spooled.
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import hmac
import json
import logging
import os
from pathlib import Path
import random
import socket
import ssl
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
import urllib.error
import urllib.parse
import urllib.request
import uuid
import yaml

logger = logging.getLogger("agentguard.siem")


class SIEMType(str, Enum):
    """Supported enterprise SIEM and telemetry collector types."""
    SPLUNK = "splunk"
    DATADOG = "datadog"
    WEBHOOK = "webhook"
    CLOUDWATCH = "cloudwatch"


@dataclass
class SIEMConfig:
    """Enterprise SIEM Forwarder Configuration."""
    enabled: bool = False
    siem_type: str = "webhook"
    endpoint: str = ""
    token: str = ""
    hmac_secret: str = ""
    batch_size: int = 50
    flush_interval_seconds: float = 2.0
    max_retries: int = 3
    initial_backoff_seconds: float = 0.5
    max_backoff_seconds: float = 10.0
    spool_path: str = field(
        default_factory=lambda: str(Path.home() / ".agentguard" / "siem_spool.jsonl")
    )
    max_spool_bytes: int = 50 * 1024 * 1024  # 50MB bound
    timeout_seconds: float = 5.0
    verify_ssl: bool = True

    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary representation."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SIEMConfig":
        """Reconstruct config from dictionary with type safety."""
        clean_data = {}
        for k in cls.__dataclass_fields__:
            if k in data:
                clean_data[k] = data[k]
        return cls(**clean_data)


def get_siem_config_path() -> Path:
    """Returns standard path to ~/.agentguard/siem.yaml."""
    return Path.home() / ".agentguard" / "siem.yaml"


def load_siem_config(custom_path: Optional[Union[str, Path]] = None) -> SIEMConfig:
    """
    Loads SIEM configuration from YAML file with environment variable overrides.
    Precedence:
    1. Environment variables (AGENTGUARD_SIEM_*)
    2. YAML configuration file (~/.agentguard/siem.yaml)
    3. Built-in defaults
    """
    target_path = Path(custom_path) if custom_path else get_siem_config_path()
    config_dict: Dict[str, Any] = {}

    if target_path.exists():
        try:
            content = target_path.read_text(encoding="utf-8")
            loaded = yaml.safe_load(content)
            if isinstance(loaded, dict):
                config_dict = loaded
        except Exception as exc:
            logger.warning(f"Failed to load SIEM configuration from {target_path}: {exc}")

    # Instantiate config with loaded values
    config = SIEMConfig.from_dict(config_dict)

    # Environment variable overrides
    env_enabled = os.environ.get("AGENTGUARD_SIEM_ENABLED")
    if env_enabled is not None:
        config.enabled = env_enabled.strip().lower() in ("1", "true", "yes", "on")

    env_type = os.environ.get("AGENTGUARD_SIEM_TYPE")
    if env_type:
        config.siem_type = env_type.strip().lower()

    env_endpoint = os.environ.get("AGENTGUARD_SIEM_ENDPOINT")
    if env_endpoint:
        config.endpoint = env_endpoint.strip()

    env_token = os.environ.get("AGENTGUARD_SIEM_TOKEN")
    if env_token:
        config.token = env_token.strip()

    env_hmac = os.environ.get("AGENTGUARD_HMAC_SECRET")
    if env_hmac:
        config.hmac_secret = env_hmac.strip()

    env_batch = os.environ.get("AGENTGUARD_SIEM_BATCH_SIZE")
    if env_batch:
        try:
            config.batch_size = max(1, int(env_batch))
        except ValueError:
            logger.warning(f"Invalid AGENTGUARD_SIEM_BATCH_SIZE: {env_batch}")

    env_flush = os.environ.get("AGENTGUARD_SIEM_FLUSH_INTERVAL")
    if env_flush:
        try:
            config.flush_interval_seconds = max(0.1, float(env_flush))
        except ValueError:
            logger.warning(f"Invalid AGENTGUARD_SIEM_FLUSH_INTERVAL: {env_flush}")

    env_spool = os.environ.get("AGENTGUARD_SIEM_SPOOL_PATH")
    if env_spool:
        config.spool_path = env_spool.strip()

    return config


def save_siem_config(
    config: SIEMConfig, custom_path: Optional[Union[str, Path]] = None
) -> Path:
    """
    Saves SIEM configuration to disk with strict 0600 file permissions.
    """
    target_path = Path(custom_path) if custom_path else get_siem_config_path()
    target_path.parent.mkdir(parents=True, exist_ok=True)

    data = config.to_dict()
    yaml_str = yaml.dump(data, default_flow_style=False, sort_keys=False)

    target_path.write_text(yaml_str, encoding="utf-8")
    try:
        os.chmod(target_path, 0o600)
    except OSError:
        logger.debug(f"Could not set 0600 permissions on {target_path}")

    return target_path


def compute_hmac_signature(payload_bytes: bytes, secret: str) -> str:
    """
    Computes an HMAC-SHA256 signature for payload bytes using a secret key.
    Returns: 'sha256=' + hex_digest
    """
    if not secret:
        return "sha256=unsigned"
    mac = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


def verify_hmac_signature(
    payload_bytes: bytes, secret: str, signature_header: str
) -> bool:
    """
    Verifies that the signature in signature_header matches the HMAC-SHA256 of payload_bytes.
    Uses constant-time comparison to prevent timing attacks.
    """
    if not secret or not signature_header:
        return False
    expected = compute_hmac_signature(payload_bytes, secret)
    sig = signature_header.strip()
    if not sig.startswith("sha256="):
        sig = f"sha256={sig}"
    return hmac.compare_digest(sig, expected)


class DiskSpoolQueue:
    """
    Thread-safe, crash-resilient local disk spool for audit events.
    Appends events when network delivery fails, and drains batches when restored.
    """

    def __init__(self, spool_path: Union[str, Path], max_bytes: int = 50 * 1024 * 1024):
        self.spool_path = Path(spool_path).expanduser().resolve()
        self.max_bytes = max_bytes
        self._lock = threading.Lock()

        try:
            self.spool_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            logger.debug(f"Could not create spool directory: {self.spool_path.parent}")

    def append_events(self, events: List[Dict[str, Any]]) -> int:
        """Appends a list of event dictionaries to the disk spool."""
        if not events:
            return 0

        with self._lock:
            # Enforce max file size before writing
            self._prune_if_needed()

            appended = 0
            try:
                is_new = not self.spool_path.exists()
                with open(self.spool_path, "a", encoding="utf-8") as f:
                    for ev in events:
                        f.write(json.dumps(ev, separators=(",", ":")) + "\n")
                        appended += 1
                    f.flush()

                if is_new:
                    try:
                        os.chmod(self.spool_path, 0o600)
                    except OSError:
                        logger.debug(f"Could not set 0600 on {self.spool_path}")

                # Ensure file is bounded after write
                self._prune_if_needed()
            except OSError as exc:
                logger.error(f"Failed to write to disk spool {self.spool_path}: {exc}")
                return 0

            return appended

    def read_batch(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Reads up to `limit` events from the head of the spool file without removing them."""
        if not self.spool_path.exists():
            return []

        batch: List[Dict[str, Any]] = []
        with self._lock:
            try:
                with open(self.spool_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            batch.append(json.loads(line))
                        except json.JSONDecodeError:
                            logger.debug("Corrupted line in spool file skipped")
                        if len(batch) >= limit:
                            break
            except OSError as exc:
                logger.error(f"Failed to read from disk spool {self.spool_path}: {exc}")
                return []

        return batch

    def commit_batch(self, count: int) -> int:
        """Removes the first `count` valid lines from the spool file after successful forward."""
        if count <= 0 or not self.spool_path.exists():
            return 0

        with self._lock:
            try:
                with open(self.spool_path, "r", encoding="utf-8") as f:
                    lines = f.readlines()

                remaining_lines = lines[count:]
                if remaining_lines:
                    with open(self.spool_path, "w", encoding="utf-8") as f:
                        f.writelines(remaining_lines)
                        f.flush()
                else:
                    self.spool_path.unlink(missing_ok=True)
                return count
            except OSError as exc:
                logger.error(f"Failed to commit batch to spool {self.spool_path}: {exc}")
                return 0

    def count(self) -> int:
        """Returns the number of spooled event entries."""
        if not self.spool_path.exists():
            return 0
        with self._lock:
            try:
                with open(self.spool_path, "r", encoding="utf-8") as f:
                    return sum(1 for line in f if line.strip())
            except OSError:
                return 0

    def clear(self) -> None:
        """Clears and removes the local spool file."""
        with self._lock:
            try:
                self.spool_path.unlink(missing_ok=True)
            except OSError:
                logger.debug(f"Could not delete spool file {self.spool_path}")

    def _prune_if_needed(self) -> None:
        """Bounds spool file size by shedding oldest entries if size exceeds max_bytes."""
        if not self.spool_path.exists():
            return
        try:
            size = self.spool_path.stat().st_size
            if size <= self.max_bytes:
                return

            with open(self.spool_path, "r", encoding="utf-8") as f:
                lines = f.readlines()

            # Discard oldest lines until remaining bytes fit within max_bytes
            while lines and sum(len(l.encode("utf-8")) for l in lines) > self.max_bytes:
                lines.pop(0)

            with open(self.spool_path, "w", encoding="utf-8") as f:
                f.writelines(lines)
                f.flush()
        except OSError:
            logger.debug("Failed to prune spool file")


class SIEMForwarder:
    """
    Asynchronous Enterprise SIEM Forwarder with HMAC signing and disk spooling.
    """

    def __init__(
        self,
        config: Optional[SIEMConfig] = None,
        custom_sender: Optional[Callable[[bytes, Dict[str, str], str, float, bool], Tuple[bool, int, str]]] = None,
    ):
        self.config = config if config is not None else load_siem_config()
        self.custom_sender = custom_sender
        self.spool = DiskSpoolQueue(
            spool_path=self.config.spool_path,
            max_bytes=self.config.max_spool_bytes,
        )

        self._buffer: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self._worker_task: Optional[asyncio.Task] = None
        self._running = False
        self._last_flush_time = time.time()

        self.stats = {
            "enqueued": 0,
            "forwarded": 0,
            "forward_batches": 0,
            "failed_attempts": 0,
            "spooled_events": 0,
            "spool_drained_events": 0,
            "last_forward_timestamp": None,
            "last_error": None,
        }

    @property
    def is_running(self) -> bool:
        """Check if background worker task is active."""
        return self._running and self._worker_task is not None and not self._worker_task.done()

    def start(self) -> None:
        """Starts the background worker loop in the current asyncio event loop."""
        if self._running:
            return
        self._running = True
        try:
            loop = asyncio.get_running_loop()
            self._worker_task = loop.create_task(self._worker_loop())
        except RuntimeError:
            logger.debug("No active asyncio event loop found during SIEMForwarder.start()")

    async def stop(self, timeout: float = 2.0) -> None:
        """Gracefully flushes pending events and stops the background worker loop."""
        self._running = False
        if self._worker_task:
            self._worker_task.cancel()
            try:
                await asyncio.wait_for(asyncio.shield(self._worker_task), timeout=timeout)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                logger.debug("SIEM forwarder worker task cancelled or timed out during stop")
            self._worker_task = None

        # Final asynchronous flush
        await self.flush(drain_spool=True)

    def enqueue_event(self, event: Any) -> bool:
        """
        Thread-safe entry point for adding an audit event to the forwarder queue.
        Supports AuditEvent instances or plain dictionaries.
        """
        if not self.config.enabled:
            return False

        if hasattr(event, "to_dict"):
            ev_dict = event.to_dict()
        elif isinstance(event, dict):
            ev_dict = dict(event)
        else:
            ev_dict = {
                "event_type": str(event),
                "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "status": "INFO",
                "details": {},
            }

        with self._lock:
            self._buffer.append(ev_dict)
            self.stats["enqueued"] += 1
            buffer_len = len(self._buffer)

        # Ensure background task is running if loop is active
        if not self.is_running:
            try:
                loop = asyncio.get_running_loop()
                if loop.is_running():
                    self.start()
            except RuntimeError:
                logger.debug("SIEM worker task not started: no active event loop")

        # If buffer exceeds batch_size, trigger an immediate async flush if loop running
        if buffer_len >= self.config.batch_size:
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(self.flush(drain_spool=False))
            except RuntimeError:
                logger.debug("Immediate batch flush deferred: no running event loop")

        return True

    def format_batch_payload(
        self, events: List[Dict[str, Any]]
    ) -> Tuple[bytes, Dict[str, str]]:
        """
        Formats a batch of events according to the configured SIEM type
        and generates the tamper-proof HMAC-SHA256 signature header.
        """
        siem_type = self.config.siem_type.lower()
        headers: Dict[str, str] = {
            "Content-Type": "application/json",
            "User-Agent": "AgentGuard-SIEM-Forwarder/1.0",
        }

        # 1. Splunk HTTP Event Collector (HEC)
        if siem_type == SIEMType.SPLUNK.value:
            if self.config.token:
                headers["Authorization"] = f"Splunk {self.config.token}"

            lines = []
            for ev in events:
                # Parse timestamp to epoch float if possible
                ts_raw = ev.get("timestamp")
                epoch_sec = time.time()
                if ts_raw:
                    try:
                        clean_ts = ts_raw.replace("Z", "+00:00")
                        dt = datetime.fromisoformat(clean_ts)
                        epoch_sec = dt.timestamp()
                    except Exception:
                        epoch_sec = time.time()

                item = {
                    "time": epoch_sec,
                    "host": socket.gethostname(),
                    "source": "agentguard",
                    "sourcetype": "_json",
                    "event": ev,
                }
                lines.append(json.dumps(item, separators=(",", ":")))
            payload_str = "\n".join(lines) + "\n"
            payload_bytes = payload_str.encode("utf-8")

        # 2. Datadog Logs API
        elif siem_type == SIEMType.DATADOG.value:
            if self.config.token:
                headers["DD-API-KEY"] = self.config.token

            dd_records = []
            for ev in events:
                is_blocked = ev.get("status") == "BLOCKED" or "BLOCKED" in str(ev.get("event_type", ""))
                rec = {
                    "ddsource": "agentguard",
                    "service": "agentguard-daemon",
                    "status": "error" if is_blocked else "info",
                    "message": json.dumps(ev, separators=(",", ":")),
                    "timestamp": ev.get("timestamp"),
                    "event": ev,
                }
                dd_records.append(rec)
            payload_bytes = json.dumps(dd_records, separators=(",", ":")).encode("utf-8")

        # 3. Custom Generic Webhook / AWS CloudWatch Proxy
        else:
            if self.config.token:
                headers["Authorization"] = f"Bearer {self.config.token}"

            envelope = {
                "batch_id": str(uuid.uuid4()),
                "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "source": "agentguard",
                "count": len(events),
                "events": events,
            }
            payload_bytes = json.dumps(envelope, separators=(",", ":")).encode("utf-8")

        # Tamper-Proof HMAC-SHA256 Signing
        secret = self.config.hmac_secret or os.environ.get("AGENTGUARD_HMAC_SECRET", "")
        sig_val = compute_hmac_signature(payload_bytes, secret)
        headers["X-AgentGuard-Signature"] = sig_val
        headers["X-AgentGuard-Signature-Timestamp"] = str(int(time.time()))

        return payload_bytes, headers

    def _send_http_sync(
        self,
        payload_bytes: bytes,
        headers: Dict[str, str],
        endpoint: str,
        timeout: float,
        verify_ssl: bool,
    ) -> Tuple[bool, int, str]:
        """Synchronous HTTP POST with SSL context and timeout controls."""
        if self.custom_sender:
            return self.custom_sender(payload_bytes, headers, endpoint, timeout, verify_ssl)

        if not endpoint:
            return False, 0, "No endpoint configured"

        req = urllib.request.Request(
            url=endpoint,
            data=payload_bytes,
            headers=headers,
            method="POST",
        )

        ctx = ssl.create_default_context()
        if not verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
                status_code = response.getcode()
                resp_body = response.read().decode("utf-8", errors="replace")
                return 200 <= status_code < 300, status_code, resp_body
        except urllib.error.HTTPError as http_err:
            body = http_err.read().decode("utf-8", errors="replace")
            return False, http_err.code, f"HTTPError {http_err.code}: {body}"
        except urllib.error.URLError as url_err:
            return False, 0, f"URLError: {url_err.reason}"
        except Exception as exc:
            return False, 0, f"NetworkException: {exc}"

    async def _send_batch_with_retry(
        self, events: List[Dict[str, Any]]
    ) -> Tuple[bool, str]:
        """
        Attempts to forward a batch with exponential backoff and jitter.
        Returns (success: bool, message: str).
        """
        if not events:
            return True, "Empty batch"

        payload_bytes, headers = self.format_batch_payload(events)
        endpoint = self.config.endpoint

        attempt = 0
        max_retries = max(1, self.config.max_retries)
        initial_backoff = self.config.initial_backoff_seconds
        max_backoff = self.config.max_backoff_seconds

        last_error = ""

        while attempt < max_retries:
            attempt += 1

            # Execute HTTP transport asynchronously without blocking loop
            success, code, msg = await asyncio.to_thread(
                self._send_http_sync,
                payload_bytes,
                headers,
                endpoint,
                self.config.timeout_seconds,
                self.config.verify_ssl,
            )

            if success:
                self.stats["forwarded"] += len(events)
                self.stats["forward_batches"] += 1
                self.stats["last_forward_timestamp"] = datetime.now(timezone.utc).isoformat()
                return True, f"Success (status {code})"

            last_error = f"Attempt {attempt}/{max_retries} failed: status={code}, {msg}"
            self.stats["failed_attempts"] += 1
            self.stats["last_error"] = last_error
            logger.warning(f"SIEM forward failed: {last_error}")

            # Do not retry on 4xx client errors other than 429 rate limit
            if 400 <= code < 500 and code != 429:
                return False, last_error

            if attempt < max_retries:
                # Exponential backoff with jitter
                delay = min(max_backoff, initial_backoff * (2 ** (attempt - 1)))
                jitter = random.uniform(0.0, 0.1 * delay)
                await asyncio.sleep(delay + jitter)

        return False, last_error

    async def flush(self, drain_spool: bool = True) -> int:
        """
        Flushes the in-memory batch and drains pending spooled events.
        Returns the total number of events successfully forwarded.
        """
        # Step 1: Drain in-memory buffer atomically
        with self._lock:
            if not self._buffer:
                current_batch: List[Dict[str, Any]] = []
            else:
                current_batch = list(self._buffer)
                self._buffer.clear()
            self._last_flush_time = time.time()

        total_forwarded = 0

        # Step 2: Attempt to drain disk spool first if requested
        if drain_spool and self.spool.count() > 0:
            spool_batch = self.spool.read_batch(limit=self.config.batch_size)
            if spool_batch:
                success, _ = await self._send_batch_with_retry(spool_batch)
                if success:
                    self.spool.commit_batch(len(spool_batch))
                    self.stats["spool_drained_events"] += len(spool_batch)
                    total_forwarded += len(spool_batch)

        # Step 3: Forward current in-memory batch
        if current_batch:
            success, err_msg = await self._send_batch_with_retry(current_batch)
            if success:
                total_forwarded += len(current_batch)
            else:
                # Resilience: spool failed events to disk
                spooled = self.spool.append_events(current_batch)
                self.stats["spooled_events"] += spooled
                logger.error(
                    f"SIEM forward exhausted retries; spooled {spooled} events to {self.config.spool_path}"
                )

        return total_forwarded

    def flush_sync(self, drain_spool: bool = True) -> int:
        """Synchronous wrapper for flush() used during CLI commands or shutdown."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            future = asyncio.run_coroutine_threadsafe(
                self.flush(drain_spool=drain_spool), loop
            )
            return future.result(timeout=self.config.timeout_seconds * 2)

        return asyncio.run(self.flush(drain_spool=drain_spool))

    async def _worker_loop(self) -> None:
        """Continuous background loop flushing pending batches on interval."""
        while self._running:
            try:
                await asyncio.sleep(self.config.flush_interval_seconds)
            except asyncio.CancelledError:
                break

            try:
                with self._lock:
                    has_items = len(self._buffer) > 0
                has_spool = self.spool.count() > 0

                if has_items or has_spool:
                    await self.flush(drain_spool=True)
            except Exception as exc:
                logger.debug(f"SIEM background flush error: {exc}")

    def test_connection(self) -> Tuple[bool, int, str, Dict[str, Any]]:
        """
        Sends a single synthetic test event to verify SIEM connectivity,
        credentials, and HMAC signature acceptance.
        """
        synthetic_event = {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "event_type": "SYNTHETIC_SIEM_TEST",
            "session_id": "siem-connectivity-check",
            "pid": os.getpid(),
            "status": "INFO",
            "details": {
                "message": "AgentGuard Enterprise SIEM Forwarder connectivity verification test",
                "environment": os.environ.get("AGENTGUARD_ENV", "production"),
            },
        }

        payload_bytes, headers = self.format_batch_payload([synthetic_event])

        t0 = time.perf_counter()
        success, code, body = self._send_http_sync(
            payload_bytes,
            headers,
            self.config.endpoint,
            timeout=self.config.timeout_seconds,
            verify_ssl=self.config.verify_ssl,
        )
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        meta = {
            "elapsed_ms": round(elapsed_ms, 2),
            "payload_size_bytes": len(payload_bytes),
            "signature": headers.get("X-AgentGuard-Signature", ""),
            "headers": {k: (v if "key" not in k.lower() and "auth" not in k.lower() else "********") for k, v in headers.items()},
        }

        return success, code, body, meta
