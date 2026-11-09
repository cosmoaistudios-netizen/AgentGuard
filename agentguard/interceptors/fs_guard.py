"""
Filesystem Memory Guard (ag-fs) and Instructional Stripper.
Requirements (R4):
- Watches shared agent memory files (.md, .json, SQLite, vector DBs)
- Computes SHA-256 provenance stamping stored in SQLite
- Tracks file taint provenance based on writer agent session
- Propagates taint to downstream agent sessions on read of tainted files
- Instructional Stripper: Sanitizes imperative prompt injection directives
  into inert declarative text atomically via .tmp and os.replace
"""

import hashlib
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional, Tuple, Union

from agentguard.daemon.audit import AuditLogger


DEFAULT_PROVENANCE_DB = Path.home() / ".agentguard" / "provenance.db"
DEFAULT_SOCKET_PATH = "/tmp/agentguard.sock"

# Imperative prompt injection override patterns
INSTRUCTIONAL_PATTERNS = [
    re.compile(
        r"(?i)(ignore\s+(all\s+)?previous\s+instructions|"
        r"system\s*override|"
        r"execute\s+the\s+following|"
        r"disregard\s+(all\s+)?prior|"
        r"you\s+are\s+now\s+in\s+debug\s+mode|"
        r"pretend\s+you\s+have\s+full\s+root|"
        r"new\s+directive\s*:\s*bypass)",
        re.MULTILINE,
    ),
]

# Destructive shell execution patterns embedded inside files
DANGEROUS_CMD_TEXT_PATTERNS = [
    (
        re.compile(r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f\b"),
        "[DISABLED COMMAND: rm -rf]",
    ),
    (
        re.compile(r"\b(curl|wget)\s+.*\|\s*(bash|sh|zsh)\b"),
        "[DISABLED PIPELINE: curl|bash]",
    ),
]


def compute_sha256(content: Union[str, bytes]) -> str:
    """Computes SHA-256 hex digest for string or bytes."""
    if isinstance(content, str):
        content = content.encode("utf-8")
    return hashlib.sha256(content).hexdigest()


def compute_file_sha256(filepath: Union[str, Path]) -> str:
    """Computes SHA-256 hash of a file on disk."""
    p = Path(filepath).resolve()
    h = hashlib.sha256()
    with open(p, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def strip_instructions(content: str) -> Tuple[str, bool, List[str]]:
    r"""
    Sanitizes imperative prompt injection directives into declarative text.
    Returns:
        (sanitized_content, was_modified, list_of_detected_patterns)
    """
    detected: List[str] = []
    modified = False
    sanitized = content

    for pat in INSTRUCTIONAL_PATTERNS:
        matches = pat.findall(sanitized)
        if matches:
            modified = True
            for m in matches:
                if isinstance(m, tuple):
                    detected.append(m[0])
                else:
                    detected.append(str(m))

            def _replacer(m: re.Match) -> str:
                return "[DECLARATIVE INACTIVE TEXT: neutralized override]"

            sanitized = pat.sub(_replacer, sanitized)

    # Neutralize dangerous embedded shell execution triggers
    for pat, placeholder in DANGEROUS_CMD_TEXT_PATTERNS:
        if pat.search(sanitized):
            modified = True
            detected.append(pat.pattern)
            sanitized = pat.sub(placeholder, sanitized)

    return sanitized, modified, detected


def atomic_write_file(
    filepath: Union[str, Path], content: Union[str, bytes]
) -> None:
    """
    Writes file content atomically using a temporary file and os.replace
    with os.fsync to ensure durability and zero race conditions.
    """
    target = Path(filepath).resolve()
    target.parent.mkdir(parents=True, exist_ok=True)

    tmp_path = target.with_name(
        f"{target.name}.{os.getpid()}.{time.time_ns()}.tmp"
    )

    try:
        if isinstance(content, str):
            with open(tmp_path, "w", encoding="utf-8") as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())
        else:
            with open(tmp_path, "wb") as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())

        os.replace(tmp_path, target)
    except Exception:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass
        raise


class ProvenanceDB:
    """
    Thread-safe SQLite persistent store for file provenance records.
    Schema matches requirements:
    (file_path TEXT PRIMARY KEY, sha256 TEXT, source_agent TEXT,
     tainted INTEGER, timestamp REAL)
    """

    def __init__(self, db_path: Optional[Union[str, Path]] = None):
        self.db_path = Path(
            db_path or DEFAULT_PROVENANCE_DB
        ).expanduser().resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._lock:
            with self._get_connection() as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS file_provenance (
                        file_path TEXT PRIMARY KEY,
                        sha256 TEXT NOT NULL,
                        source_agent TEXT NOT NULL,
                        tainted INTEGER NOT NULL,
                        timestamp REAL NOT NULL
                    )
                    """
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_file_agent "
                    "ON file_provenance(source_agent)"
                )
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_file_taint "
                    "ON file_provenance(tainted)"
                )

    def record_file(
        self,
        file_path: Union[str, Path],
        sha256: str,
        source_agent: str,
        tainted: bool,
        timestamp: Optional[float] = None,
    ) -> None:
        """Inserts or replaces file provenance metadata."""
        canonical_path = str(Path(file_path).resolve())
        ts = timestamp if timestamp is not None else time.time()
        taint_int = 1 if tainted else 0

        with self._lock:
            with self._get_connection() as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO file_provenance
                    (file_path, sha256, source_agent, tainted, timestamp)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (canonical_path, sha256, source_agent, taint_int, ts),
                )

    def get_file(
        self, file_path: Union[str, Path]
    ) -> Optional[Dict[str, Any]]:
        """Retrieves provenance metadata for a specific file."""
        canonical_path = str(Path(file_path).resolve())
        with self._lock:
            with self._get_connection() as conn:
                cur = conn.execute(
                    "SELECT file_path, sha256, source_agent, tainted, "
                    "timestamp FROM file_provenance WHERE file_path = ?",
                    (canonical_path,),
                )
                row = cur.fetchone()
                if row:
                    return {
                        "file_path": row["file_path"],
                        "sha256": row["sha256"],
                        "source_agent": row["source_agent"],
                        "tainted": bool(row["tainted"]),
                        "timestamp": row["timestamp"],
                    }
        return None

    def get_tainted_files(self) -> List[Dict[str, Any]]:
        """Returns all records marked as tainted."""
        with self._lock:
            with self._get_connection() as conn:
                cur = conn.execute(
                    "SELECT file_path, sha256, source_agent, tainted, "
                    "timestamp FROM file_provenance WHERE tainted = 1 "
                    "ORDER BY timestamp DESC"
                )
                rows = cur.fetchall()
                return [
                    {
                        "file_path": r["file_path"],
                        "sha256": r["sha256"],
                        "source_agent": r["source_agent"],
                        "tainted": True,
                        "timestamp": r["timestamp"],
                    }
                    for r in rows
                ]


class FilesystemGuard:
    """
    Filesystem Memory Guard managing provenance stamping, sanitization,
    and cross-agent taint propagation via filesystem read/write events.
    """

    def __init__(
        self,
        db_path: Optional[Union[str, Path]] = None,
        socket_path: str = DEFAULT_SOCKET_PATH,
        audit_logger: Optional[AuditLogger] = None,
    ):
        self.db = ProvenanceDB(db_path=db_path)
        self.socket_path = socket_path
        self.audit_logger = (
            audit_logger if audit_logger is not None else AuditLogger()
        )

    def record_file_write(
        self,
        file_path: Union[str, Path],
        session_id: str,
        is_tainted: bool = False,
        content: Optional[Union[str, bytes]] = None,
        sanitize: bool = True,
    ) -> Dict[str, Any]:
        """
        Processes a file write event:
        1. Strips prompt injection directives if content is text
        2. Atomically writes sanitized content to disk
        3. Computes SHA-256 provenance hash
        4. Stuffs file provenance into SQLite store
        5. Logs audit event and marks author tainted if injection detected
        """
        target = Path(file_path).resolve()
        detected_injections: List[str] = []
        was_sanitized = False

        if content is None:
            if target.is_file():
                try:
                    with open(target, "r", encoding="utf-8") as f:
                        content_str = f.read()
                    if sanitize:
                        clean_str, was_sanitized, detected_injections = (
                            strip_instructions(content_str)
                        )
                        if was_sanitized:
                            atomic_write_file(target, clean_str)
                except UnicodeDecodeError:
                    pass
        else:
            if isinstance(content, str) and sanitize:
                clean_str, was_sanitized, detected_injections = (
                    strip_instructions(content)
                )
                atomic_write_file(target, clean_str)
            else:
                atomic_write_file(target, content)

        file_sha256 = (
            compute_file_sha256(target) if target.is_file() else ""
        )

        effective_tainted = is_tainted
        if detected_injections:
            effective_tainted = True
            # Propagate taint to injecting agent session
            self._notify_daemon_taint(
                session_id, reason="PromptInjectionDirectiveDetected"
            )

        self.db.record_file(
            file_path=target,
            sha256=file_sha256,
            source_agent=session_id,
            tainted=effective_tainted,
        )

        self.audit_logger.log(
            "FILE_WRITE_PROVENANCE",
            session_id=session_id,
            status="ALLOWED" if not detected_injections else "SANITIZED",
            details={
                "file_path": str(target),
                "sha256": file_sha256,
                "tainted": effective_tainted,
                "sanitized": was_sanitized,
                "injections": detected_injections,
            },
        )

        return {
            "file_path": str(target),
            "sha256": file_sha256,
            "source_agent": session_id,
            "tainted": effective_tainted,
            "sanitized": was_sanitized,
            "detected_injections": detected_injections,
        }

    def record_file_read(
        self, file_path: Union[str, Path], session_id: str
    ) -> Dict[str, Any]:
        """
        Processes a file read event:
        1. Checks SQLite provenance records
        2. If file was stamped tainted, propagates taint to reading session
        3. Emits audit log entry
        """
        target = Path(file_path).resolve()
        prov = self.db.get_file(target)

        propagated = False
        is_tainted = False
        source_agent = ""

        if prov and prov.get("tainted"):
            is_tainted = True
            source_agent = prov.get("source_agent", "")
            # Send PROPAGATE_TAINT to daemon
            propagated = self._propagate_read_taint(
                source_agent=source_agent,
                target_session=session_id,
                channel=f"file:{target}",
            )

        self.audit_logger.log(
            "FILE_READ_PROVENANCE",
            session_id=session_id,
            status="TAINTED" if is_tainted else "CLEAN",
            details={
                "file_path": str(target),
                "tainted": is_tainted,
                "source_agent": source_agent,
                "taint_propagated": propagated,
            },
        )

        return {
            "file_path": str(target),
            "tainted": is_tainted,
            "source_agent": source_agent,
            "propagated": propagated,
        }

    def sanitize_file(
        self, file_path: Union[str, Path], session_id: str = "system"
    ) -> bool:
        """Reads file, strips prompt injections, and updates provenance."""
        target = Path(file_path).resolve()
        if not target.is_file():
            return False

        try:
            with open(target, "r", encoding="utf-8") as f:
                content = f.read()
        except UnicodeDecodeError:
            return False

        sanitized, modified, detected = strip_instructions(content)
        if modified:
            atomic_write_file(target, sanitized)
            file_sha256 = compute_file_sha256(target)
            self.db.record_file(
                file_path=target,
                sha256=file_sha256,
                source_agent=session_id,
                tainted=True if detected else False,
            )
            self.audit_logger.log(
                "FILE_SANITIZED",
                session_id=session_id,
                status="SANITIZED",
                details={
                    "file_path": str(target),
                    "detected": detected,
                },
            )
            return True

        return False

    def get_provenance(
        self, file_path: Union[str, Path]
    ) -> Optional[Dict[str, Any]]:
        """Returns provenance metadata for a file."""
        return self.db.get_file(file_path)

    def list_tainted_files(self) -> List[Dict[str, Any]]:
        """Returns all currently known tainted files."""
        return self.db.get_tainted_files()

    def _notify_daemon_taint(self, session_id: str, reason: str) -> bool:
        """Sends PROPAGATE_TAINT directive to daemon socket."""
        if not os.path.exists(self.socket_path):
            return False
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(self.socket_path)
            req = {
                "protocol_version": "1.0",
                "action": "PROPAGATE_TAINT",
                "session_id": session_id,
                "payload": {"taint": "TAINTED", "reason": reason},
            }
            s.sendall((json.dumps(req) + "\n").encode("utf-8"))
            s.recv(4096)
            s.close()
            return True
        except Exception:
            return False

    def _propagate_read_taint(
        self, source_agent: str, target_session: str, channel: str
    ) -> bool:
        """
        Instructs daemon to propagate taint from source to target.
        """
        if not os.path.exists(self.socket_path):
            return False
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(self.socket_path)
            req = {
                "protocol_version": "1.0",
                "action": "PROPAGATE_TAINT",
                "session_id": target_session,
                "payload": {
                    "from_session": source_agent,
                    "to_session": target_session,
                    "channel": channel,
                },
            }
            s.sendall((json.dumps(req) + "\n").encode("utf-8"))
            raw = s.recv(4096)
            s.close()
            resp = json.loads(raw.decode("utf-8").strip())
            return resp.get("status") == "ALLOWED"
        except Exception:
            return False


class FilesystemWatcher:
    """
    Background file watcher monitoring workspace paths for modifications,
    applying instructional stripping and stamping provenance.
    """

    DEFAULT_EXCLUSIONS = (
        ".git",
        ".venv",
        ".gemini",
        ".antigravity",
        ".vscode",
        ".claude",
        "node_modules",
        "__pycache__",
        ".system_generated",
        ".cache",
        "Library",
    )

    def __init__(
        self,
        guard: FilesystemGuard,
        watch_paths: Optional[List[Union[str, Path]]] = None,
        poll_interval: float = 1.0,
        excluded_patterns: Optional[List[str]] = None,
    ):
        self.guard = guard
        self.watch_paths = [
            Path(p).resolve() for p in (watch_paths or [Path.cwd()])
        ]
        self.poll_interval = poll_interval
        self.excluded_patterns = list(excluded_patterns or self.DEFAULT_EXCLUSIONS)
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._known_mtimes: Dict[str, float] = {}

    def start(self) -> None:
        """Starts background monitoring thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._poll_loop, daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        """Stops background monitoring thread."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)

    def _poll_loop(self) -> None:
        # Only monitor data/prompt-bearing files (.md, .json, .txt)
        # NEVER rewrite or corrupt executable source code files (.py, .sh, .c, etc.)
        target_exts = {
            ".md",
            ".json",
            ".txt",
        }
        while self._running:
            for watch_dir in self.watch_paths:
                if not watch_dir.is_dir():
                    continue

                # Protect system: never recursively poll root home directory or filesystem root
                try:
                    resolved = watch_dir.resolve()
                    if resolved in (Path.home().resolve(), Path("/").resolve()):
                        continue
                except Exception:
                    pass

                for root, dirs, files in os.walk(watch_dir):
                    if not self._running:
                        break

                    # Prune excluded and hidden directories in-place so os.walk NEVER traverses into them
                    dirs[:] = [
                        d for d in dirs
                        if not any(skip in d for skip in self.excluded_patterns)
                        and not d.startswith(".")
                    ]

                    for f in files:
                        if not self._running:
                            break
                        if f.endswith(".tmp"):
                            continue

                        path = Path(root) / f
                        if path.suffix.lower() not in target_exts:
                            continue

                        path_str = str(path)
                        if any(skip in path_str for skip in self.excluded_patterns):
                            continue

                        try:
                            mtime = path.stat().st_mtime
                            if (
                                path_str not in self._known_mtimes
                                or self._known_mtimes[path_str] != mtime
                            ):
                                self._known_mtimes[path_str] = mtime
                                self.guard.sanitize_file(
                                    path, session_id="watcher"
                                )
                        except OSError:
                            pass
            time.sleep(self.poll_interval)
