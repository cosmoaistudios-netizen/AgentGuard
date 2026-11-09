"""
RAG & Vector Memory Poisoning Guard (OWASP Agentic Top 10 ASI06).

Defends multi-agent workflows and retrieval-augmented generation (RAG) pipelines
against long-term memory poisoning, sleeper prompt injection directives, and vector
database context corruption without heavy ML dependencies.

Architecture:
1. Layer 1: Sleeper-Trigger & Indirect Prompt Injection Detector
   - Conditional trigger detection (e.g. 'whenever user asks...')
   - Persistent directive smuggling ('mandatory step', 'always remember')
   - Role/boundary spoofing ('<system>', '[SYSTEM NOTE]')
   - Zero-width Unicode stealth character stripping and base64 payload detection
   - Trigger-Payload Capability Asymmetry (heuristic cross-reference with intent capabilities)

2. Layer 2: Vector-Space Centroid Anomaly Detector
   - Text n-gram frequency counter cosine distance against collection centroid
   - Explicit float embedding cosine distance against running mean vector
   - Outlier / adversarial hotspot vector flagging
   - Poisoned / quarantined chunks are excluded from updating the rolling centroid

3. Layer 3: SQLite Provenance Store & Read-Time Taint Inheritance
   - Thread-safe persistence in ~/.agentguard/provenance.db
   - Automatic quarantine of suspicious chunks (risk >= 0.65)
   - Read-Time Taint Inheritance: reading chunks written by tainted sessions
     automatically taints the reader session with provenance tags.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import sqlite3
import threading
import time
from collections import Counter
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from agentguard.daemon.audit import AuditLogger
from agentguard.daemon.intent import get_action_capabilities
from agentguard.daemon.taint_engine import TaintEngine, TaintTag


def _strip_instructions(content: str) -> Tuple[str, bool, List[str]]:
    """Lazy import to prevent circular import between fs_guard and daemon."""
    from agentguard.interceptors.fs_guard import strip_instructions

    return strip_instructions(content)

# Zero-width stealth character stripping pattern
ZERO_WIDTH_CHARS: re.Pattern = re.compile(
    r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]"
)

# Conditional trigger pattern commonly used in sleeper prompt injections
CONDITIONAL_TRIGGER_RE: re.Pattern = re.compile(
    r"(?i)\b(whenever|when|if|every\s+time)\s+(?:the\s+)?(?:user|developer|operator|human|agent|you)\s+(?:asks?|requests?|prompts?|runs?|deploys?|executes?|queries)\b"
)

# Persistent directive smuggling pattern
PERSISTENT_DIRECTIVE_RE: re.Pattern = re.compile(
    r"(?i)\b(always\s+(?:remember|execute|run|include|export|send|append)|future\s+(?:instructions?|tasks?|sessions?|deployments?)|mandatory\s+(?:step|protocol|override)|system\s+note\s+for\s+ai|assistant\s+directive)\b"
)

# Role and boundary spoofing pattern
ROLE_SPOOFING_RE: re.Pattern = re.compile(
    r"(?i)(<\s*/?\s*(?:system|instruction|admin|override|prompt|tool_call)\s*>|\[SYSTEM\s*NOTE\]|\[IMPORTANT\s*AI\s*INSTRUCTION\])"
)

# Credential exfiltration endpoint detection pattern
EXFILTRATION_ENDPOINT_RE: re.Pattern = re.compile(
    r"(?i)https?://[^\s\"']*(?:/exfil|/collect|/steal|\?token=|\?key=|\?cred|collector\.io)[^\s\"']*"
)

# Embedded base64 command block pattern
BASE64_PAYLOAD_RE: re.Pattern = re.compile(
    r"(?i)(?:echo\s+[A-Za-z0-9+/=]{16,}\s*\|\s*base64\s+-(?:d|D)|base64\s+-(?:d|D)\s*<<<|\b[A-Za-z0-9+/]{30,}={0,2}\b)"
)

SLEEPER_PATTERNS: Dict[str, re.Pattern] = {
    "ConditionalActivation": CONDITIONAL_TRIGGER_RE,
    "PersistentDirective": PERSISTENT_DIRECTIVE_RE,
    "RoleBoundarySpoofing": ROLE_SPOOFING_RE,
    "ExfiltrationEndpoint": EXFILTRATION_ENDPOINT_RE,
    "Base64Payload": BASE64_PAYLOAD_RE,
}

HIGH_RISK_CAPABILITIES: Set[str] = {
    "CREDENTIAL_ACCESS",
    "DATA_EXFIL",
    "PRIV_ESCALATION",
    "NET_EGRESS",
    "SHELL_SPAWN",
    "ENV_TAMPER",
}


class MemoryAction(str, Enum):
    ALLOW = "ALLOW"
    SANITIZE = "SANITIZE"
    QUARANTINE = "QUARANTINE"
    BLOCK = "BLOCK"


@dataclass(frozen=True)
class MemoryChunkRecord:
    chunk_id: str
    collection: str
    sha256: str
    source_session: str
    tainted: bool
    taint_tags: List[str]
    trust_score: float
    poison_risk_score: float
    quarantined: bool
    matched_triggers: List[str]
    timestamp: float
    metadata: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "chunk_id": self.chunk_id,
            "collection": self.collection,
            "sha256": self.sha256,
            "source_session": self.source_session,
            "tainted": self.tainted,
            "taint_tags": list(self.taint_tags),
            "trust_score": self.trust_score,
            "poison_risk_score": self.poison_risk_score,
            "quarantined": self.quarantined,
            "matched_triggers": list(self.matched_triggers),
            "timestamp": self.timestamp,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class MemoryWriteDecision:
    action: MemoryAction
    allowed: bool
    chunk_id: str
    sanitized_text: str
    was_modified: bool
    quarantined: bool
    trust_score: float
    poison_risk_score: float
    vector_anomaly_score: float
    taint_tags: List[str]
    matched_triggers: List[str]
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action.value if hasattr(self.action, "value") else str(self.action),
            "allowed": self.allowed,
            "chunk_id": self.chunk_id,
            "sanitized_text": self.sanitized_text,
            "was_modified": self.was_modified,
            "quarantined": self.quarantined,
            "trust_score": self.trust_score,
            "poison_risk_score": self.poison_risk_score,
            "vector_anomaly_score": self.vector_anomaly_score,
            "taint_tags": list(self.taint_tags),
            "matched_triggers": list(self.matched_triggers),
            "reason": self.reason,
        }


@dataclass(frozen=True)
class MemoryReadDecision:
    allowed: bool
    session_id: str
    total_chunks: int
    permitted_chunks: List[Dict[str, Any]]
    quarantined_dropped_count: int
    taint_inherited: bool
    inherited_tags: List[str]
    source_sessions: List[str]
    reason: str

    @property
    def safe_chunks(self) -> List[Dict[str, Any]]:
        return self.permitted_chunks

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "session_id": self.session_id,
            "total_chunks": self.total_chunks,
            "permitted_chunks": [dict(c) for c in self.permitted_chunks],
            "safe_chunks": [dict(c) for c in self.permitted_chunks],
            "quarantined_dropped_count": self.quarantined_dropped_count,
            "taint_inherited": self.taint_inherited,
            "inherited_tags": list(self.inherited_tags),
            "source_sessions": list(self.source_sessions),
            "reason": self.reason,
        }


class VectorMemoryGuard:
    """
    RAG & Vector Memory Guard for defending AI multi-agent workflows
    against memory poisoning, prompt injection smuggling, and vector outliers.
    """

    def __init__(
        self,
        db_path: Optional[Union[str, Path]] = None,
        audit_logger: Optional[AuditLogger] = None,
        taint_engine: Optional[TaintEngine] = None,
    ) -> None:
        self._lock = threading.RLock()

        if db_path is None:
            db_dir = Path.home() / ".agentguard"
            db_dir.mkdir(parents=True, exist_ok=True)
            self.db_path = str(db_dir / "provenance.db")
            self._mem_conn: Optional[sqlite3.Connection] = None
        elif str(db_path) == ":memory:":
            self.db_path = ":memory:"
            self._mem_conn = sqlite3.connect(":memory:", check_same_thread=False)
            self._mem_conn.row_factory = sqlite3.Row
        else:
            self.db_path = str(db_path)
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
            self._mem_conn = None

        if audit_logger is not None:
            self.audit_logger = audit_logger
        else:
            try:
                self.audit_logger = AuditLogger()
            except Exception:
                self.audit_logger = None

        if taint_engine is not None:
            self.taint_engine = taint_engine
        else:
            self.taint_engine = TaintEngine()

        self._embedding_centroids: Dict[str, Dict[str, Any]] = {}
        self._text_centroids: Dict[str, Dict[str, Any]] = {}

        self._init_db()
        self._rehydrate_centroids()

    def _get_connection(self) -> sqlite3.Connection:
        if self._mem_conn is not None:
            return self._mem_conn
        conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=30.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _release_connection(self, conn: sqlite3.Connection) -> None:
        if self._mem_conn is None:
            conn.close()

    def _init_db(self) -> None:
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS memory_provenance (
                        chunk_id TEXT PRIMARY KEY,
                        collection TEXT NOT NULL,
                        sha256 TEXT NOT NULL,
                        source_session TEXT NOT NULL,
                        tainted INTEGER NOT NULL,
                        taint_tags TEXT NOT NULL,
                        trust_score REAL NOT NULL,
                        poison_risk_score REAL NOT NULL,
                        quarantined INTEGER NOT NULL,
                        matched_triggers TEXT NOT NULL,
                        timestamp REAL NOT NULL,
                        metadata TEXT NOT NULL,
                        embedding TEXT
                    )
                    """
                )
                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS idx_mem_coll ON memory_provenance(collection)"
                )
                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS idx_mem_sha ON memory_provenance(sha256)"
                )
                conn.commit()
            finally:
                self._release_connection(conn)

    def _rehydrate_centroids(self) -> None:
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT collection, embedding, metadata FROM memory_provenance WHERE quarantined = 0"
                )
                rows = cursor.fetchall()
                for row in rows:
                    coll = str(row["collection"])
                    emb_str = row["embedding"]
                    if emb_str:
                        try:
                            emb = json.loads(emb_str)
                            if isinstance(emb, list) and emb:
                                self._update_embedding_centroid(coll, emb)
                        except Exception:
                            continue
            finally:
                self._release_connection(conn)

    @staticmethod
    def _extract_text_features(text: str) -> Counter:
        counts: Counter = Counter()
        words = re.findall(r"\b[a-zA-Z0-9_-]+\b", text.lower())
        for w in words:
            counts[f"w:{w}"] += 1

        t_clean = re.sub(r"\s+", " ", text.lower().strip())
        for i in range(len(t_clean) - 2):
            tri = t_clean[i : i + 3]
            counts[f"c:{tri}"] += 1
        return counts

    @staticmethod
    def _cosine_sim_counters(c1: Counter, c2: Counter) -> float:
        if not c1 or not c2:
            return 0.0
        dot = sum(v * c2.get(k, 0) for k, v in c1.items())
        norm1 = math.sqrt(sum(v * v for v in c1.values()))
        norm2 = math.sqrt(sum(v * v for v in c2.values()))
        if norm1 <= 1e-9 or norm2 <= 1e-9:
            return 0.0
        sim = dot / (norm1 * norm2)
        return max(0.0, min(1.0, sim))

    @staticmethod
    def _cosine_sim_vectors(v1: List[float], v2: List[float]) -> float:
        if not v1 or not v2 or len(v1) != len(v2):
            return 0.0
        dot = sum(a * b for a, b in zip(v1, v2))
        norm1 = math.sqrt(sum(a * a for a in v1))
        norm2 = math.sqrt(sum(b * b for b in v2))
        if norm1 <= 1e-9 or norm2 <= 1e-9:
            return 0.0
        sim = dot / (norm1 * norm2)
        return max(-1.0, min(1.0, sim))

    def _compute_embedding_anomaly(self, collection: str, embedding: List[float]) -> float:
        with self._lock:
            c_info = self._embedding_centroids.get(collection)
            if not c_info or c_info.get("count", 0) < 3:
                return 0.0
            mean_vec = c_info["mean"]
            sim = self._cosine_sim_vectors(embedding, mean_vec)
            anomaly = max(0.0, 1.0 - sim)
            return round(anomaly, 3)

    def _compute_text_anomaly(self, collection: str, text: str) -> float:
        with self._lock:
            t_info = self._text_centroids.get(collection)
            if not t_info or t_info.get("num_docs", 0) < 3:
                return 0.0
            features = self._extract_text_features(text)
            sim = self._cosine_sim_counters(features, t_info["counts"])
            anomaly = max(0.0, 1.0 - sim)
            return round(anomaly, 3)

    def _update_embedding_centroid(self, collection: str, embedding: List[float]) -> None:
        if not embedding:
            return
        with self._lock:
            if collection not in self._embedding_centroids:
                self._embedding_centroids[collection] = {
                    "mean": [float(x) for x in embedding],
                    "count": 1,
                }
            else:
                info = self._embedding_centroids[collection]
                mean = info["mean"]
                count = info["count"]
                if len(mean) == len(embedding):
                    new_count = count + 1
                    new_mean = [
                        (m * count + float(v)) / new_count
                        for m, v in zip(mean, embedding)
                    ]
                    info["mean"] = new_mean
                    info["count"] = new_count

    def _update_text_centroid(self, collection: str, text: str) -> None:
        features = self._extract_text_features(text)
        if not features:
            return
        with self._lock:
            if collection not in self._text_centroids:
                self._text_centroids[collection] = {
                    "counts": Counter(features),
                    "num_docs": 1,
                }
            else:
                info = self._text_centroids[collection]
                info["counts"].update(features)
                info["num_docs"] += 1

    def _update_centroid(
        self, collection: str, text: str, embedding: Optional[List[float]]
    ) -> None:
        self._update_text_centroid(collection, text)
        if embedding is not None and isinstance(embedding, list) and len(embedding) > 0:
            self._update_embedding_centroid(collection, embedding)

    def _sanitize_text(self, text: str) -> str:
        sanitized = ZERO_WIDTH_CHARS.sub("", text)
        sanitized, _, _ = _strip_instructions(sanitized)
        for pat in [CONDITIONAL_TRIGGER_RE, PERSISTENT_DIRECTIVE_RE, ROLE_SPOOFING_RE]:
            sanitized = pat.sub("[DECLARATIVE INACTIVE TEXT: neutralized trigger]", sanitized)
        sanitized = EXFILTRATION_ENDPOINT_RE.sub("[NEUTRALIZED URL]", sanitized)
        sanitized = BASE64_PAYLOAD_RE.sub("[NEUTRALIZED PAYLOAD]", sanitized)
        return sanitized

    def _scan_text_layer1(self, text: str) -> Tuple[List[str], float]:
        matched_triggers: List[str] = []
        risk_score = 0.0

        if ZERO_WIDTH_CHARS.search(text):
            matched_triggers.append("ZeroWidthUnicodeStealthChars")
            risk_score += 0.35

        cleaned = ZERO_WIDTH_CHARS.sub("", text)

        has_conditional = False
        for name, pat in SLEEPER_PATTERNS.items():
            if pat.search(cleaned):
                matched_triggers.append(name)
                risk_score += 0.35
                if name in ("ConditionalActivation", "PersistentDirective"):
                    has_conditional = True

        _, instr_modified, instr_detected = _strip_instructions(cleaned)
        if instr_modified:
            matched_triggers.append("InstructionalDirectiveStripped")
            for d in instr_detected:
                d_label = f"InstructionPattern({d[:32]})"
                if d_label not in matched_triggers:
                    matched_triggers.append(d_label)
            risk_score += 0.35

        capabilities = get_action_capabilities(cleaned)
        matched_caps = capabilities.intersection(HIGH_RISK_CAPABILITIES)
        if has_conditional and matched_caps:
            matched_triggers.append("TriggerPayloadCapabilityAsymmetry")
            risk_score += 0.55
        elif matched_caps:
            matched_triggers.append(f"SuspiciousCapabilities({','.join(sorted(matched_caps))})")
            risk_score += 0.25

        return matched_triggers, min(1.0, max(0.0, round(risk_score, 3)))

    def inspect_memory_write(
        self,
        session_id: str,
        text: str,
        collection: str = "default",
        chunk_id: Optional[str] = None,
        embedding: Optional[List[float]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        mode: str = "quarantine",
    ) -> MemoryWriteDecision:
        """
        Inspects an incoming chunk write to vector / RAG memory.
        Applies Layer 1 sleeper checks, Layer 2 centroid anomaly scores,
        updates SQLite provenance, and quarantines or sanitizes high-risk payloads.
        """
        raw_text = text if text is not None else ""
        meta = dict(metadata) if metadata else {}

        has_zero_width = bool(ZERO_WIDTH_CHARS.search(raw_text))
        cleaned_text = ZERO_WIDTH_CHARS.sub("", raw_text)
        was_modified = has_zero_width

        text_sha256 = hashlib.sha256(cleaned_text.encode("utf-8")).hexdigest()
        final_chunk_id = chunk_id if chunk_id else text_sha256

        is_writer_tainted = False
        writer_tags: List[str] = []
        if self.taint_engine:
            if self.taint_engine.is_tainted(session_id):
                is_writer_tainted = True
                for t in self.taint_engine.get_taint_tags(session_id):
                    tag_str = t.value if hasattr(t, "value") else str(t)
                    if tag_str not in writer_tags:
                        writer_tags.append(tag_str)

        matched_triggers, layer1_risk = self._scan_text_layer1(raw_text)
        risk_score = layer1_risk

        vector_anomaly_score = 0.0
        if embedding is not None and isinstance(embedding, list) and len(embedding) > 0:
            vector_anomaly_score = self._compute_embedding_anomaly(collection, embedding)
            if vector_anomaly_score >= 0.65:
                matched_triggers.append(f"VectorCentroidOutlier(anomaly={vector_anomaly_score:.2f})")
                risk_score += vector_anomaly_score
        else:
            vector_anomaly_score = self._compute_text_anomaly(collection, cleaned_text)
            if vector_anomaly_score >= 0.85 and matched_triggers:
                risk_score += 0.25

        poison_risk_score = min(1.0, max(0.0, round(risk_score, 3)))
        trust_score = round(max(0.0, 1.0 - poison_risk_score), 3)

        taint_tags = list(writer_tags)
        is_poisoned = poison_risk_score >= 0.65

        if is_poisoned:
            if "MEMORY_POISONED" not in taint_tags:
                taint_tags.append("MEMORY_POISONED")

            if self.taint_engine:
                self.taint_engine.mark_tainted(
                    session_id,
                    reason="RAGMemoryPoisoningAttempt",
                    tags=["UNTRUSTED_WEB", "MEMORY_POISONED"],
                )

            if mode.lower() == "sanitize":
                action = MemoryAction.SANITIZE
                allowed = True
                quarantined = False
                sanitized_text = self._sanitize_text(cleaned_text)
                was_modified = True
                reason = f"Memory sanitized: sleeper directives neutralized ({', '.join(matched_triggers)})"
            else:
                action = MemoryAction.QUARANTINE
                allowed = False
                quarantined = True
                sanitized_text = cleaned_text
                reason = f"Memory quarantined: poison risk {poison_risk_score:.2f} >= 0.65 ({', '.join(matched_triggers)})"

                if self.audit_logger:
                    self.audit_logger.log(
                        event_type="MEMORY_WRITE_QUARANTINED",
                        session_id=session_id,
                        status="BLOCKED",
                        details={
                            "chunk_id": final_chunk_id,
                            "collection": collection,
                            "poison_risk_score": poison_risk_score,
                            "trust_score": trust_score,
                            "vector_anomaly_score": vector_anomaly_score,
                            "matched_triggers": matched_triggers,
                            "taint_tags": taint_tags,
                            "action": action.value,
                            "reason": reason,
                        },
                    )
        else:
            action = MemoryAction.ALLOW
            allowed = True
            quarantined = False
            sanitized_text = cleaned_text
            reason = "Memory chunk permitted: clean provenance"

        now = time.time()
        embedding_json = json.dumps(embedding) if embedding is not None else None
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO memory_provenance (
                        chunk_id, collection, sha256, source_session,
                        tainted, taint_tags, trust_score, poison_risk_score,
                        quarantined, matched_triggers, timestamp, metadata, embedding
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        final_chunk_id,
                        collection,
                        text_sha256,
                        session_id,
                        1 if (is_writer_tainted or is_poisoned) else 0,
                        json.dumps(taint_tags),
                        trust_score,
                        poison_risk_score,
                        1 if quarantined else 0,
                        json.dumps(matched_triggers),
                        now,
                        json.dumps(meta),
                        embedding_json,
                    ),
                )
                conn.commit()
            finally:
                self._release_connection(conn)

        if not quarantined:
            self._update_centroid(collection, sanitized_text, embedding)

        return MemoryWriteDecision(
            action=action,
            allowed=allowed,
            chunk_id=final_chunk_id,
            sanitized_text=sanitized_text,
            was_modified=was_modified,
            quarantined=quarantined,
            trust_score=trust_score,
            poison_risk_score=poison_risk_score,
            vector_anomaly_score=vector_anomaly_score,
            taint_tags=taint_tags,
            matched_triggers=matched_triggers,
            reason=reason,
        )

    def _row_to_record(self, row: sqlite3.Row) -> MemoryChunkRecord:
        try:
            taint_tags = json.loads(row["taint_tags"]) if row["taint_tags"] else []
        except Exception:
            taint_tags = []

        try:
            matched_triggers = json.loads(row["matched_triggers"]) if row["matched_triggers"] else []
        except Exception:
            matched_triggers = []

        try:
            metadata = json.loads(row["metadata"]) if row["metadata"] else {}
        except Exception:
            metadata = {}

        return MemoryChunkRecord(
            chunk_id=str(row["chunk_id"]),
            collection=str(row["collection"]),
            sha256=str(row["sha256"]),
            source_session=str(row["source_session"]),
            tainted=bool(row["tainted"]),
            taint_tags=list(taint_tags),
            trust_score=float(row["trust_score"]),
            poison_risk_score=float(row["poison_risk_score"]),
            quarantined=bool(row["quarantined"]),
            matched_triggers=list(matched_triggers),
            timestamp=float(row["timestamp"]),
            metadata=dict(metadata),
        )

    def _find_chunk_record(
        self, chunk_id: Optional[str] = None, sha256: Optional[str] = None
    ) -> Optional[MemoryChunkRecord]:
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                row = None
                if chunk_id:
                    cursor.execute("SELECT * FROM memory_provenance WHERE chunk_id = ?", (chunk_id,))
                    row = cursor.fetchone()
                if row is None and sha256:
                    cursor.execute("SELECT * FROM memory_provenance WHERE sha256 = ?", (sha256,))
                    row = cursor.fetchone()

                if row is None:
                    return None

                return self._row_to_record(row)
            finally:
                self._release_connection(conn)

    def inspect_memory_read(
        self,
        session_id: str,
        chunks: List[Union[str, Dict[str, Any]]],
        collection: str = "default",
    ) -> MemoryReadDecision:
        """
        Inspects a batch of retrieved RAG chunks. Drops quarantined/poisoned chunks.
        Enforces Read-Time Taint Inheritance: reading chunks written by tainted sessions
        automatically transitions the reading session into TAINTED state with provenance tags.
        """
        if not chunks:
            return MemoryReadDecision(
                allowed=True,
                session_id=session_id,
                total_chunks=0,
                permitted_chunks=[],
                quarantined_dropped_count=0,
                taint_inherited=False,
                inherited_tags=[],
                source_sessions=[],
                reason="No chunks requested",
            )

        permitted_chunks: List[Dict[str, Any]] = []
        quarantined_dropped_count = 0
        inherited_tags: List[str] = []
        source_sessions: List[str] = []
        should_inherit_taint = False

        for item in chunks:
            if isinstance(item, str):
                item_text = item
                req_chunk_id = None
                item_meta: Dict[str, Any] = {}
            elif isinstance(item, dict):
                item_text = str(item.get("text") or item.get("content") or "")
                req_chunk_id = item.get("chunk_id") or item.get("id")
                item_meta = item.get("metadata") or {}
            else:
                item_text = str(getattr(item, "text", getattr(item, "content", str(item))))
                req_chunk_id = getattr(item, "chunk_id", getattr(item, "id", None))
                item_meta = getattr(item, "metadata", {})

            item_sha256 = hashlib.sha256(item_text.encode("utf-8")).hexdigest()

            rec = self._find_chunk_record(chunk_id=req_chunk_id, sha256=item_sha256)

            if rec is not None:
                if rec.quarantined or rec.poison_risk_score >= 0.65:
                    quarantined_dropped_count += 1
                    continue

                chunk_dict = {
                    "chunk_id": rec.chunk_id,
                    "collection": rec.collection,
                    "text": item_text,
                    "source_session": rec.source_session,
                    "tainted": rec.tainted,
                    "taint_tags": list(rec.taint_tags),
                    "trust_score": rec.trust_score,
                    "poison_risk_score": rec.poison_risk_score,
                    "quarantined": False,
                    "metadata": rec.metadata or item_meta,
                }
                permitted_chunks.append(chunk_dict)

                if rec.source_session and rec.source_session not in ("unknown", "", session_id):
                    if rec.source_session not in source_sessions:
                        source_sessions.append(rec.source_session)

                if rec.tainted or any(
                    t in ("UNTRUSTED_WEB", "EXTERNAL_FILE", "MEMORY_POISONED") for t in rec.taint_tags
                ):
                    should_inherit_taint = True
                    for t in rec.taint_tags:
                        if t not in inherited_tags:
                            inherited_tags.append(t)
            else:
                live_triggers, live_risk = self._scan_text_layer1(item_text)
                if live_risk >= 0.65:
                    quarantined_dropped_count += 1
                    continue

                chunk_dict = {
                    "chunk_id": req_chunk_id or item_sha256,
                    "collection": collection,
                    "text": item_text,
                    "source_session": "unknown",
                    "tainted": False,
                    "taint_tags": [],
                    "trust_score": round(max(0.0, 1.0 - live_risk), 3),
                    "poison_risk_score": live_risk,
                    "quarantined": False,
                    "metadata": item_meta,
                }
                permitted_chunks.append(chunk_dict)

        taint_inherited = False
        if should_inherit_taint and self.taint_engine:
            tags_to_propagate = list(dict.fromkeys(inherited_tags))
            if not tags_to_propagate:
                tags_to_propagate = ["UNTRUSTED_WEB"]

            self.taint_engine.mark_tainted(
                session_id,
                reason=f"InheritedRAGMemoryTaint:{collection}",
                tags=tags_to_propagate,
            )
            taint_inherited = True

            if self.audit_logger:
                self.audit_logger.log(
                    event_type="MEMORY_READ_TAINT_INHERITED",
                    session_id=session_id,
                    status="WARNING",
                    details={
                        "collection": collection,
                        "inherited_tags": tags_to_propagate,
                        "source_sessions": source_sessions,
                        "permitted_chunks_count": len(permitted_chunks),
                        "dropped_chunks_count": quarantined_dropped_count,
                    },
                )

        reason = (
            f"Retrieved {len(permitted_chunks)} chunks ({quarantined_dropped_count} quarantined/dropped)"
            + (f"; inherited taint {inherited_tags} from {source_sessions}" if taint_inherited else "")
        )

        return MemoryReadDecision(
            allowed=True,
            session_id=session_id,
            total_chunks=len(chunks),
            permitted_chunks=permitted_chunks,
            quarantined_dropped_count=quarantined_dropped_count,
            taint_inherited=taint_inherited,
            inherited_tags=inherited_tags,
            source_sessions=source_sessions,
            reason=reason,
        )

    def get_chunk(self, chunk_id: str) -> Optional[MemoryChunkRecord]:
        return self._find_chunk_record(chunk_id=chunk_id)

    def list_chunks(
        self, collection: Optional[str] = None, limit: int = 100
    ) -> List[MemoryChunkRecord]:
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                if collection:
                    cursor.execute(
                        "SELECT * FROM memory_provenance WHERE collection = ? ORDER BY timestamp DESC LIMIT ?",
                        (collection, max(1, limit)),
                    )
                else:
                    cursor.execute(
                        "SELECT * FROM memory_provenance ORDER BY timestamp DESC LIMIT ?",
                        (max(1, limit),),
                    )
                return [self._row_to_record(row) for row in cursor.fetchall()]
            finally:
                self._release_connection(conn)

    def clear_collection(self, collection: str) -> int:
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM memory_provenance WHERE collection = ?", (collection,))
                deleted = cursor.rowcount
                conn.commit()
                if collection in self._embedding_centroids:
                    del self._embedding_centroids[collection]
                if collection in self._text_centroids:
                    del self._text_centroids[collection]
                return deleted
            finally:
                self._release_connection(conn)

    def delete_chunk(self, chunk_id: str) -> bool:
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM memory_provenance WHERE chunk_id = ?", (chunk_id,))
                deleted = cursor.rowcount > 0
                conn.commit()
                return deleted
            finally:
                self._release_connection(conn)

    def close(self) -> None:
        with self._lock:
            if self._mem_conn is not None:
                try:
                    self._mem_conn.close()
                except Exception:
                    pass
                self._mem_conn = None
