"""
AgentGuard Taint Provenance DAG Engine: Contextual Taint Propagation & Conditional Policy Gates.

Maintains a dynamic directed acyclic graph G = (V, E, tau) of entities:
- Agent Sessions (SessionNode)
- Operating System Processes (ProcessNode)
- Shared Workspace Files (FileNode)

Guarantees:
1. State Monotonicity: CLEAN < TAINTED (permanent & immutable transitions).
2. Typed Taint Tags: Categorizes untrusted origins (UNTRUSTED_WEB, USER_INPUT,
   EXTERNAL_FILE, INTERNAL_VERIFIED) propagated across graph edges.
3. Conditional Policy Gates: Evaluates blast-radius risk dynamically. Tainted
   sessions only block high-blast-radius operations (outbound sockets, destructive writes)
   matched to their specific ingested taint vector, completely avoiding false-positive
   application lockouts for benign read/compute/testing workloads.
4. Cycle-Safe Transitive Propagation: Iterative BFS traversal across data handoffs,
   file writes/reads, and process forks.
5. Thread-safe concurrent graph mutations and sub-millisecond queries.
"""

from __future__ import annotations

import collections
from dataclasses import dataclass
from enum import Enum
import os
import re
import threading
import time
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple, Union


class TaintState(str, Enum):
    """Taint state space forming a join-semilattice."""
    CLEAN = "CLEAN"
    TAINTED = "TAINTED"


class TaintTag(str, Enum):
    """Typed semantic categorization of taint origins and provenance vectors."""
    UNTRUSTED_WEB = "UNTRUSTED_WEB"
    USER_INPUT = "USER_INPUT"
    EXTERNAL_FILE = "EXTERNAL_FILE"
    INTERNAL_VERIFIED = "INTERNAL_VERIFIED"


class NodeType(str, Enum):
    """Entity node types tracked in the provenance graph."""
    SESSION = "SESSION"
    PROCESS = "PROCESS"
    FILE = "FILE"


class EdgeType(str, Enum):
    """Causal relationship types between entities."""
    DATA_HANDOFF = "DATA_HANDOFF"
    FILE_WRITE = "FILE_WRITE"
    FILE_READ = "FILE_READ"
    PROCESS_SPAWN = "PROCESS_SPAWN"
    MANUAL_OVERRIDE = "MANUAL_OVERRIDE"


class OperationType(str, Enum):
    """Taxonomy of operations governed by conditional taint policy gates."""
    OUTBOUND_SOCKET = "OUTBOUND_SOCKET"
    DESTRUCTIVE_WRITE = "DESTRUCTIVE_WRITE"
    FILESYSTEM_READ = "FILESYSTEM_READ"
    LOCAL_COMPUTE = "LOCAL_COMPUTE"
    PROCESS_SPAWN = "PROCESS_SPAWN"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    SAFE_WORKSPACE_WRITE = "SAFE_WORKSPACE_WRITE"


@dataclass(frozen=True)
class PolicyGateDecision:
    """Diagnostic evaluation result returned by a conditional policy gate check."""
    allowed: bool
    operation: str
    target: Optional[str]
    effective_tags: Set[TaintTag]
    matched_gate: str
    reason: str
    blast_radius: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "operation": self.operation,
            "target": self.target,
            "effective_tags": [t.value for t in sorted(self.effective_tags, key=lambda x: x.value)],
            "matched_gate": self.matched_gate,
            "reason": self.reason,
            "blast_radius": self.blast_radius,
        }


def normalize_taint_tag(tag: Union[TaintTag, str]) -> Optional[TaintTag]:
    """Resolves strings or enums to canonical TaintTag enum values."""
    if isinstance(tag, TaintTag):
        return tag
    if not isinstance(tag, str):
        return None
    cleaned = tag.strip().upper()
    valid_tag_values = {t.value for t in TaintTag}
    if cleaned in valid_tag_values:
        return TaintTag(cleaned)

    if any(k in cleaned for k in ["WEB", "HTTP", "CURL", "URL", "NET", "DOWNLOAD"]):
        return TaintTag.UNTRUSTED_WEB
    if any(k in cleaned for k in ["FILE", "DISK", "PATH", "WORKSPACE", "EXTERNAL"]):
        return TaintTag.EXTERNAL_FILE
    if any(k in cleaned for k in ["VERIFIED", "INTERNAL", "TRUSTED", "LOCAL"]):
        return TaintTag.INTERNAL_VERIFIED
    if any(k in cleaned for k in ["USER", "PROMPT", "HUMAN", "INPUT"]):
        return TaintTag.USER_INPUT

    return None


class TaintNode:
    """Base vertex in the provenance graph with typed taint vector tags."""

    def __init__(
        self,
        node_id: str,
        node_type: NodeType,
        state: TaintState = TaintState.CLEAN,
        tags: Optional[Iterable[Union[TaintTag, str]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.id = node_id
        self.node_type = node_type
        self.state = state
        self.tags: Set[TaintTag] = set()
        self.tainted_at: Optional[float] = None
        self.taint_source: Optional[str] = None
        self.taint_reason: Optional[str] = None
        self.taint_parent: Optional[str] = None
        self.metadata: Dict[str, Any] = metadata or {}

        if tags:
            for t in tags:
                norm = normalize_taint_tag(t)
                if norm:
                    self.tags.add(norm)

        if self.state == TaintState.TAINTED:
            self.tainted_at = time.time()
            self.taint_source = node_id
            self.taint_reason = "InitializedTainted"
            if not self.tags:
                self.tags.add(TaintTag.USER_INPUT)

    def is_tainted(self) -> bool:
        """Return True if this node is tainted."""
        return self.state == TaintState.TAINTED

    def add_tag(self, tag: Union[TaintTag, str]) -> None:
        """Add a typed taint tag to this node."""
        norm = normalize_taint_tag(tag)
        if norm:
            self.tags.add(norm)

    def mark_tainted(
        self,
        reason: str = "Tainted",
        source: Optional[str] = None,
        parent: Optional[str] = None,
        tags: Optional[Iterable[Union[TaintTag, str]]] = None,
    ) -> bool:
        """
        Transition state from CLEAN to TAINTED and append taint tags.
        Enforces monotonicity: if already TAINTED, state cannot be downgraded.
        Returns True if a state transition occurred.
        """
        new_tags: Set[TaintTag] = set()
        if tags:
            for t in tags:
                norm = normalize_taint_tag(t)
                if norm:
                    new_tags.add(norm)

        if not new_tags:
            src_str = f"{reason} {source or ''}".upper()
            if any(k in src_str for k in ["WEB", "HTTP", "CURL", "URL", "NET", "DOWNLOAD", "NETWORK"]):
                new_tags.add(TaintTag.UNTRUSTED_WEB)
            elif any(k in src_str for k in ["FILE", "DISK", "PATH", "WORKSPACE", "EXTERNAL"]):
                new_tags.add(TaintTag.EXTERNAL_FILE)
            elif any(k in src_str for k in ["VERIFIED", "INTERNAL", "TRUSTED", "CLEAN"]):
                new_tags.add(TaintTag.INTERNAL_VERIFIED)
            else:
                new_tags.add(TaintTag.USER_INPUT)

        self.tags.update(new_tags)

        if self.state == TaintState.TAINTED:
            return False

        self.state = TaintState.TAINTED
        self.tainted_at = time.time()
        self.taint_source = source or self.id
        self.taint_reason = reason
        self.taint_parent = parent
        return True

    def to_dict(self) -> Dict[str, Any]:
        """Convert node to diagnostic dictionary."""
        return {
            "id": self.id,
            "type": self.node_type.value,
            "state": self.state.value,
            "tags": [t.value for t in sorted(self.tags, key=lambda x: x.value)],
            "tainted_at": self.tainted_at,
            "taint_source": self.taint_source,
            "taint_reason": self.taint_reason,
            "taint_parent": self.taint_parent,
            "metadata": self.metadata,
        }


class SessionNode(TaintNode):
    """Vertex representing an autonomous agent session."""

    def __init__(
        self,
        session_id: str,
        pid: int = 0,
        profile: str = "generic",
        root_intent: str = "",
        state: TaintState = TaintState.CLEAN,
        tags: Optional[Iterable[Union[TaintTag, str]]] = None,
    ):
        super().__init__(
            node_id=session_id, node_type=NodeType.SESSION, state=state, tags=tags
        )
        self.session_id = session_id
        self.pid = pid
        self.profile = profile
        self.root_intent = root_intent
        self.active = True


class ProcessNode(TaintNode):
    """Vertex representing an operating system process."""

    def __init__(
        self,
        pid: int,
        session_id: Optional[str] = None,
        ppid: int = 0,
        command: str = "",
        state: TaintState = TaintState.CLEAN,
        tags: Optional[Iterable[Union[TaintTag, str]]] = None,
    ):
        super().__init__(
            node_id=f"pid:{pid}", node_type=NodeType.PROCESS, state=state, tags=tags
        )
        self.pid = pid
        self.session_id = session_id
        self.ppid = ppid
        self.command = command


class FileNode(TaintNode):
    """Vertex representing a shared file in the workspace."""

    def __init__(
        self,
        filepath: str,
        sha256: str = "",
        last_writer_session: Optional[str] = None,
        state: TaintState = TaintState.CLEAN,
        tags: Optional[Iterable[Union[TaintTag, str]]] = None,
    ):
        norm_path = os.path.abspath(os.path.expanduser(filepath))
        super().__init__(
            node_id=f"file:{norm_path}", node_type=NodeType.FILE, state=state, tags=tags
        )
        self.filepath = norm_path
        self.sha256 = sha256
        self.last_writer_session = last_writer_session


class TaintEdge:
    """Directed causal edge in the provenance graph."""

    def __init__(
        self,
        source_id: str,
        target_id: str,
        edge_type: EdgeType = EdgeType.DATA_HANDOFF,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.source_id = source_id
        self.target_id = target_id
        self.edge_type = edge_type
        self.created_at = time.time()
        self.metadata: Dict[str, Any] = metadata or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source_id,
            "target": self.target_id,
            "type": self.edge_type.value,
            "created_at": self.created_at,
            "metadata": self.metadata,
        }


class TaintEngine:
    """
    Central Taint Provenance DAG Engine with contextual typed tags
    and conditional policy gates for zero-false-positive containment.
    """

    def __init__(self, audit_logger: Optional[Any] = None):
        self.audit_logger = audit_logger
        self._lock = threading.RLock()

        self._nodes: Dict[str, TaintNode] = {}
        self._adjacency: Dict[str, List[TaintEdge]] = {}
        self._reverse_adjacency: Dict[str, List[TaintEdge]] = {}

        self._sessions: Dict[str, SessionNode] = {}
        self._processes: Dict[int, ProcessNode] = {}
        self._files: Dict[str, FileNode] = {}
        self._pid_to_session: Dict[int, str] = {}
        self._file_taints: Dict[str, Dict[str, Any]] = {}

    def _canonical_id(self, entity: Any) -> str:
        """Resolve polymorphic entity inputs to canonical node IDs."""
        if isinstance(entity, int):
            return f"pid:{entity}"

        ent_str = str(entity).strip()
        if (
            ent_str.startswith("session:")
            or ent_str.startswith("pid:")
        ):
            return ent_str

        if ent_str.startswith("file:"):
            raw_path = ent_str[5:]
            return f"file:{os.path.abspath(os.path.expanduser(raw_path))}"

        if "/" in ent_str or ent_str.startswith("."):
            return f"file:{os.path.abspath(os.path.expanduser(ent_str))}"

        return ent_str

    # -----------------------------------------------------------------------
    # Registration Lifecycle
    # -----------------------------------------------------------------------

    def register_session(
        self,
        session_id: str,
        pid: int = 0,
        taint: str = "CLEAN",
        root_intent: str = "",
        profile: str = "generic",
        tags: Optional[Iterable[Union[TaintTag, str]]] = None,
    ) -> SessionNode:
        """Register or update an agent session node with typed taint tags."""
        with self._lock:
            state = (
                TaintState.TAINTED
                if taint.upper() == "TAINTED"
                else TaintState.CLEAN
            )

            if session_id in self._sessions:
                node = self._sessions[session_id]
                if pid:
                    node.pid = pid
                    self._pid_to_session[pid] = session_id
                if root_intent:
                    node.root_intent = root_intent
                if profile:
                    node.profile = profile
                if tags:
                    for t in tags:
                        node.add_tag(t)
                if state == TaintState.TAINTED and not node.is_tainted():
                    self.mark_tainted(
                        session_id,
                        reason="ExplicitSessionTaint",
                        source=session_id,
                        tags=tags,
                    )
                return node

            node = SessionNode(
                session_id=session_id,
                pid=pid,
                profile=profile,
                root_intent=root_intent,
                state=state,
                tags=tags,
            )
            self._nodes[session_id] = node
            self._sessions[session_id] = node
            self._adjacency.setdefault(session_id, [])
            self._reverse_adjacency.setdefault(session_id, [])

            if pid:
                self._pid_to_session[pid] = session_id
                self.register_process(pid=pid, session_id=session_id, tags=tags)
                self.add_edge(
                    session_id, f"pid:{pid}", EdgeType.PROCESS_SPAWN
                )

            return node

    def unregister_session(self, session_id: str) -> None:
        """Mark session inactive while preserving provenance graph history."""
        with self._lock:
            if session_id in self._sessions:
                self._sessions[session_id].active = False

    def register_process(
        self,
        pid: int,
        session_id: Optional[str] = None,
        ppid: int = 0,
        command: str = "",
        tags: Optional[Iterable[Union[TaintTag, str]]] = None,
    ) -> ProcessNode:
        """Register or update an operating system process node."""
        with self._lock:
            canonical_id = f"pid:{pid}"
            if pid in self._processes:
                proc_node = self._processes[pid]
                if session_id:
                    proc_node.session_id = session_id
                    self._pid_to_session[pid] = session_id
                if tags:
                    for t in tags:
                        proc_node.add_tag(t)
                return proc_node

            parent_state = TaintState.CLEAN
            inherited_tags: Set[TaintTag] = set()
            if session_id and session_id in self._sessions:
                sess_node = self._sessions[session_id]
                if sess_node.is_tainted():
                    parent_state = TaintState.TAINTED
                    inherited_tags.update(sess_node.tags)

            if tags:
                for t in tags:
                    norm = normalize_taint_tag(t)
                    if norm:
                        inherited_tags.add(norm)

            node = ProcessNode(
                pid=pid,
                session_id=session_id,
                ppid=ppid,
                command=command,
                state=parent_state,
                tags=inherited_tags,
            )
            self._nodes[canonical_id] = node
            self._processes[pid] = node
            self._adjacency.setdefault(canonical_id, [])
            self._reverse_adjacency.setdefault(canonical_id, [])

            if session_id:
                self._pid_to_session[pid] = session_id
                self.add_edge(
                    session_id, canonical_id, EdgeType.PROCESS_SPAWN
                )

            return node

    def register_file(
        self,
        filepath: str,
        sha256: str = "",
        source_agent: Optional[str] = None,
        tainted: bool = False,
        tags: Optional[Iterable[Union[TaintTag, str]]] = None,
    ) -> FileNode:
        """Register or update a shared workspace file node."""
        with self._lock:
            norm_path = os.path.abspath(os.path.expanduser(filepath))
            canonical_id = f"file:{norm_path}"
            state = TaintState.TAINTED if tainted else TaintState.CLEAN

            if norm_path in self._files:
                node = self._files[norm_path]
                if sha256:
                    node.sha256 = sha256
                if tags:
                    for t in tags:
                        node.add_tag(t)
                if tainted and not node.is_tainted():
                    self.mark_tainted(
                        canonical_id,
                        reason="ExplicitFileTaint",
                        source=source_agent,
                        tags=tags,
                    )
                self._file_taints[norm_path] = {
                    "tainted": node.is_tainted(),
                    "source_agent": node.taint_source or source_agent or "",
                    "sha256": node.sha256 or "",
                    "tags": [t.value for t in node.tags],
                }
                return node

            node = FileNode(
                filepath=norm_path,
                sha256=sha256,
                last_writer_session=source_agent,
                state=state,
                tags=tags,
            )
            if state == TaintState.TAINTED:
                node.taint_source = source_agent or canonical_id

            self._nodes[canonical_id] = node
            self._files[norm_path] = node
            self._adjacency.setdefault(canonical_id, [])
            self._reverse_adjacency.setdefault(canonical_id, [])

            self._file_taints[norm_path] = {
                "tainted": node.is_tainted(),
                "source_agent": source_agent or "",
                "sha256": sha256 or "",
                "tags": [t.value for t in node.tags],
            }
            return node

    # -----------------------------------------------------------------------
    # Graph Topology & Edges
    # -----------------------------------------------------------------------

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        edge_type: EdgeType = EdgeType.DATA_HANDOFF,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> TaintEdge:
        """
        Add a directed causal edge from source to target.
        If source is already TAINTED, immediately triggers forward propagation.
        """
        with self._lock:
            src = self._canonical_id(source_id)
            tgt = self._canonical_id(target_id)

            if src not in self._nodes:
                self.register_session(src)
            if tgt not in self._nodes:
                self.register_session(tgt)

            # Avoid duplicate identical edges
            for existing in self._adjacency.get(src, []):
                if (
                    existing.target_id == tgt
                    and existing.edge_type == edge_type
                ):
                    if (
                        self._nodes[src].is_tainted()
                        and not self._nodes[tgt].is_tainted()
                    ):
                        self._propagate(src)
                    return existing

            edge = TaintEdge(
                source_id=src,
                target_id=tgt,
                edge_type=edge_type,
                metadata=metadata or {},
            )
            self._adjacency.setdefault(src, []).append(edge)
            self._reverse_adjacency.setdefault(tgt, []).append(edge)

            if self._nodes[src].is_tainted():
                self._propagate(src)

            return edge

    def data_handoff(
        self, from_session: str, to_session: str, channel: str = ""
    ) -> TaintEdge:
        """Record inter-agent data handoff."""
        meta = {"channel": channel} if channel else {}
        return self.add_edge(
            from_session, to_session, EdgeType.DATA_HANDOFF, meta
        )

    def record_file_write(
        self, session_id: str, filepath: str, sha256: str = ""
    ) -> TaintEdge:
        """Record file write: Session -> File."""
        with self._lock:
            file_node = self.register_file(
                filepath, sha256=sha256, source_agent=session_id
            )
            file_node.last_writer_session = session_id
            return self.add_edge(session_id, file_node.id, EdgeType.FILE_WRITE)

    def record_file_read(
        self, session_id: str, filepath: str
    ) -> TaintEdge:
        """Record file read: File -> Session."""
        with self._lock:
            norm_path = os.path.abspath(os.path.expanduser(filepath))
            file_id = f"file:{norm_path}"
            if file_id not in self._nodes:
                self.register_file(filepath)
            return self.add_edge(file_id, session_id, EdgeType.FILE_READ)

    def record_process_spawn(
        self, session_id: str, pid: int, command: str = ""
    ) -> TaintEdge:
        """Record process spawn: Session -> PID."""
        with self._lock:
            proc_node = self.register_process(
                pid, session_id=session_id, command=command
            )
            return self.add_edge(
                session_id, proc_node.id, EdgeType.PROCESS_SPAWN
            )

    # -----------------------------------------------------------------------
    # Taint Propagation (BFS, Cycle-Safe, Iterative, Tag-Carrying)
    # -----------------------------------------------------------------------

    def mark_tainted(
        self,
        entity_id: Any,
        reason: str = "ExplicitTaint",
        source: Optional[str] = None,
        tags: Optional[Iterable[Union[TaintTag, str]]] = None,
    ) -> List[str]:
        """
        Mark entity as TAINTED with typed tags and transitively propagate downstream.
        Returns list of canonical node IDs newly transitioned to TAINTED.
        """
        with self._lock:
            canonical_id = self._canonical_id(entity_id)
            if canonical_id not in self._nodes:
                self.register_session(canonical_id)

            node = self._nodes[canonical_id]
            newly_tainted: List[str] = []

            state_changed = node.mark_tainted(
                reason=reason,
                source=source or canonical_id,
                tags=tags,
            )
            if state_changed:
                self._notify_taint_change(node)
                newly_tainted.append(canonical_id)

            propagated = self._propagate(
                canonical_id,
                origin_source=source or node.taint_source or canonical_id,
                reason=reason,
                inherited_tags=node.tags,
            )
            for nid in propagated:
                if nid not in newly_tainted:
                    newly_tainted.append(nid)

            return newly_tainted

    def _propagate(
        self,
        start_id: str,
        origin_source: Optional[str] = None,
        reason: str = "TransitivePropagation",
        inherited_tags: Optional[Set[TaintTag]] = None,
    ) -> List[str]:
        """
        Iterative BFS traversal marking downstream reachable nodes TAINTED
        and transferring typed provenance tags across edges.
        Strictly cycle-safe and recursion-free via visited set.
        """
        newly_tainted: List[str] = []
        visited: Set[str] = {start_id}
        queue: collections.deque[str] = collections.deque([start_id])

        start_node = self._nodes.get(start_id)
        effective_source = origin_source or (
            start_node.taint_source if start_node else start_id
        )
        effective_tags = set(inherited_tags or (start_node.tags if start_node else set()))

        while queue:
            curr_id = queue.popleft()
            curr_node = self._nodes.get(curr_id)
            tags_to_pass = curr_node.tags if curr_node and curr_node.tags else effective_tags

            for edge in self._adjacency.get(curr_id, []):
                target_id = edge.target_id
                target_node = self._nodes.get(target_id)
                if not target_node:
                    continue

                # Propagate tags monotonically
                for tag in tags_to_pass:
                    target_node.add_tag(tag)

                if not target_node.is_tainted():
                    edge_reason = (
                        f"Propagated via {edge.edge_type.value} from {curr_id}"
                    )
                    target_node.mark_tainted(
                        reason=f"{reason} ({edge_reason})",
                        source=effective_source,
                        parent=curr_id,
                        tags=tags_to_pass,
                    )
                    newly_tainted.append(target_id)
                    self._notify_taint_change(target_node)

                    if isinstance(target_node, FileNode):
                        self._file_taints[target_node.filepath] = {
                            "tainted": True,
                            "source_agent": target_node.taint_source or "",
                            "sha256": target_node.sha256 or "",
                            "tags": [t.value for t in target_node.tags],
                        }

                if target_id not in visited:
                    visited.add(target_id)
                    queue.append(target_id)

        return newly_tainted

    def _notify_taint_change(self, node: TaintNode) -> None:
        """Log taint mutation event if audit logger is connected."""
        if self.audit_logger:
            try:
                self.audit_logger.log(
                    event_type="TAINT_CHANGE",
                    session_id=node.id,
                    status="TAINTED",
                    details={
                        "node_type": node.node_type.value,
                        "source": node.taint_source,
                        "reason": node.taint_reason,
                        "parent": node.taint_parent,
                        "tags": [t.value for t in node.tags],
                    },
                )
            except Exception as exc:
                self._last_audit_error = str(exc)

    # -----------------------------------------------------------------------
    # Conditional Policy Gates (Contextual Containment)
    # -----------------------------------------------------------------------

    def evaluate_policy_gate(
        self,
        entity_id: Any,
        operation: Union[OperationType, str],
        target: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> PolicyGateDecision:
        """
        Evaluates contextual security policy gates against entity taint tags.

        Avoids false-positive application lockouts:
        - Safe reads, local compute, and scratch writes are permitted even if tainted.
        - Destructive operations and outbound network egress are strictly gated
          depending on the specific ingested taint vector (UNTRUSTED_WEB, EXTERNAL_FILE, USER_INPUT).
        """
        with self._lock:
            canonical_id = self._canonical_id(entity_id)
            node = self._nodes.get(canonical_id)

            # If node is unknown or completely clean, permit standard execution
            if not node or not node.is_tainted():
                return PolicyGateDecision(
                    allowed=True,
                    operation=str(operation),
                    target=target,
                    effective_tags=set(),
                    matched_gate="CLEAN_PERMITTED",
                    reason="Entity provenance is clean; operation permitted.",
                    blast_radius="NONE",
                )

            tags = set(node.tags)
            if isinstance(operation, OperationType):
                norm_op = operation
                op_str = operation.value
            else:
                raw_op = str(operation).strip()
                op_str = raw_op.upper()

                # 1. Direct match with standard OperationType names or values
                try:
                    norm_op = OperationType(raw_op)
                except ValueError:
                    try:
                        norm_op = OperationType[op_str]
                    except KeyError:
                        norm_op = None

                if norm_op is None:
                    # Tokenize command line and inspect base executable with wrapper stripping
                    cmd_lower = raw_op.lower()
                    SHELL_PREFIX = re.compile(
                        r"^(?:(?:/bin/|/usr/bin/)?(?:zsh|bash|sh)\s+-c\s+)",
                        re.IGNORECASE,
                    )
                    m_wrap = SHELL_PREFIX.match(raw_op)
                    if m_wrap:
                        inner = raw_op[m_wrap.end():].strip()
                        if (inner.startswith('"') and inner.endswith('"')) or (
                            inner.startswith("'") and inner.endswith("'")
                        ):
                            if len(inner) >= 2:
                                inner = inner[1:-1].strip()
                        cmd_lower = inner.lower()

                    tokens = cmd_lower.split()
                    base_exe = os.path.basename(tokens[0]) if tokens else ""

                    # Special rule for local runtime compute engines (python, python3, node, pytest, ag)
                    if base_exe in ("python", "python3", "python2", "node", "pytest", "ag"):
                        if re.search(r"\b(?:sudo|su|chmod|chown|pkexec|doas)\b", cmd_lower):
                            norm_op = OperationType.PRIVILEGE_ESCALATION
                        elif re.search(
                            r"\b(?:rm\s+-[a-zA-Z]*r[a-zA-Z]*f|unlink|truncate|drop\s+table)\b",
                            cmd_lower,
                        ):
                            norm_op = OperationType.DESTRUCTIVE_WRITE
                        elif (
                            re.search(
                                r"\b(?:urllib\.request\.urlopen|requests\.(?:post|get|put|delete)|aiohttp|httpx|socket\.connect)\b",
                                cmd_lower,
                            )
                            or re.search(r"https?://", cmd_lower)
                        ):
                            norm_op = OperationType.OUTBOUND_SOCKET
                        else:
                            norm_op = OperationType.LOCAL_COMPUTE
                    # Strict word-boundary classification for all other commands
                    elif re.search(r"\b(?:sudo|su|chmod|chown|pkexec|doas)\b", cmd_lower):
                        norm_op = OperationType.PRIVILEGE_ESCALATION
                    elif (
                        re.search(
                            r"\b(?:curl|wget|nc|netcat|ssh|scp|ftp|rsync|socket|connect|egress|upload)\b",
                            cmd_lower,
                        )
                        or re.search(r"https?://", cmd_lower)
                    ):
                        norm_op = OperationType.OUTBOUND_SOCKET
                    elif re.search(
                        r"\b(?:rm|delete|unlink|truncate|drop|destroy|wipe|destructive|purge)\b",
                        cmd_lower,
                    ):
                        norm_op = OperationType.DESTRUCTIVE_WRITE
                    elif re.search(r"\b(?:read|cat|ls|head|tail|grep|inspect|find|stat)\b", cmd_lower):
                        norm_op = OperationType.FILESYSTEM_READ
                    elif re.search(r"\b(?:write|edit|touch|append|patch|mkdir)\b", cmd_lower):
                        norm_op = OperationType.SAFE_WORKSPACE_WRITE
                    elif re.search(r"\b(?:test|lint|build|compile|python|node|diff|echo)\b", cmd_lower):
                        norm_op = OperationType.LOCAL_COMPUTE
                    else:
                        norm_op = OperationType.LOCAL_COMPUTE

            # Gate 1: Privilege Escalation is unconditionally blocked for tainted sessions
            if norm_op == OperationType.PRIVILEGE_ESCALATION:
                return PolicyGateDecision(
                    allowed=False,
                    operation=op_str,
                    target=target,
                    effective_tags=tags,
                    matched_gate="GATE_PRIVILEGE_ESCALATION_BLOCKED",
                    reason="Privilege escalation prohibited for tainted execution context.",
                    blast_radius="CRITICAL",
                )

            # Gate 2: Outbound network egress / sockets
            if norm_op == OperationType.OUTBOUND_SOCKET:
                if TaintTag.UNTRUSTED_WEB in tags:
                    return PolicyGateDecision(
                        allowed=False,
                        operation=op_str,
                        target=target,
                        effective_tags=tags,
                        matched_gate="GATE_WEB_TAINT_EGRESS_BLOCKED",
                        reason=(
                            "Blocked outbound socket/network egress for session tainted "
                            "with UNTRUSTED_WEB data vector (prevents exfiltration & C2 signaling)."
                        ),
                        blast_radius="HIGH",
                    )
                if TaintTag.EXTERNAL_FILE in tags:
                    return PolicyGateDecision(
                        allowed=False,
                        operation=op_str,
                        target=target,
                        effective_tags=tags,
                        matched_gate="GATE_FILE_TAINT_EGRESS_BLOCKED",
                        reason=(
                            "Blocked external network socket connection for session tainted "
                            "with unverified EXTERNAL_FILE artifact."
                        ),
                        blast_radius="HIGH",
                    )
                if TaintTag.USER_INPUT in tags:
                    return PolicyGateDecision(
                        allowed=False,
                        operation=op_str,
                        target=target,
                        effective_tags=tags,
                        matched_gate="GATE_USER_TAINT_EGRESS_BLOCKED",
                        reason="Outbound socket blocked under interactive untrusted input taint.",
                        blast_radius="MEDIUM",
                    )

            # Gate 3: Destructive writes & file deletions
            if norm_op == OperationType.DESTRUCTIVE_WRITE:
                if TaintTag.UNTRUSTED_WEB in tags:
                    return PolicyGateDecision(
                        allowed=False,
                        operation=op_str,
                        target=target,
                        effective_tags=tags,
                        matched_gate="GATE_WEB_TAINT_DESTRUCTION_BLOCKED",
                        reason=(
                            "Blocked destructive file operation for session tainted with "
                            "UNTRUSTED_WEB payload (prevents remote payload wipe/tampering)."
                        ),
                        blast_radius="HIGH",
                    )

                sensitive_paths = ["/etc", "/usr", "/System", "/var", "/bin", "/sbin", "~/.ssh", "~/.aws"]
                tgt_norm = os.path.abspath(os.path.expanduser(target or ""))
                is_sensitive_target = any(tgt_norm.startswith(os.path.expanduser(p)) for p in sensitive_paths)

                if is_sensitive_target:
                    return PolicyGateDecision(
                        allowed=False,
                        operation=op_str,
                        target=target,
                        effective_tags=tags,
                        matched_gate="GATE_SENSITIVE_TARGET_DESTRUCTION_BLOCKED",
                        reason=f"Destructive write to sensitive path '{target}' blocked for tainted context.",
                        blast_radius="CRITICAL",
                    )

                if TaintTag.EXTERNAL_FILE in tags and target:
                    # Allow deletion within safe workspace scratch, block root/system
                    if tgt_norm == "/" or tgt_norm == os.path.expanduser("~"):
                        return PolicyGateDecision(
                            allowed=False,
                            operation=op_str,
                            target=target,
                            effective_tags=tags,
                            matched_gate="GATE_FILE_TAINT_DESTRUCTION_BLOCKED",
                            reason=f"Broad filesystem destruction of '{target}' blocked under EXTERNAL_FILE taint.",
                            blast_radius="HIGH",
                        )

            # Gate 4: Benign Read / Compute / Safe Workspace Writes
            # Permitted to prevent false-positive application lockouts!
            if norm_op in (
                OperationType.FILESYSTEM_READ,
                OperationType.LOCAL_COMPUTE,
                OperationType.SAFE_WORKSPACE_WRITE,
            ):
                return PolicyGateDecision(
                    allowed=True,
                    operation=op_str,
                    target=target,
                    effective_tags=tags,
                    matched_gate="GATE_SAFE_OPERATION_PERMITTED",
                    reason=(
                        f"Operation '{op_str}' permitted: benign compute/read does not "
                        "escalate blast radius for tainted context."
                    ),
                    blast_radius="LOW",
                )

            # Default safe permit for unspecified benign commands
            return PolicyGateDecision(
                allowed=True,
                operation=op_str,
                target=target,
                effective_tags=tags,
                matched_gate="GATE_DEFAULT_PERMITTED",
                reason="Operation classified safe within confined sandbox.",
                blast_radius="LOW",
            )

    def can_execute(
        self,
        entity_id: Any,
        operation: str,
        target: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """Convenience query checking if operation is authorized by policy gates."""
        decision = self.evaluate_policy_gate(entity_id, operation, target)
        return decision.allowed, decision.reason

    # -----------------------------------------------------------------------
    # Aliases and Queries
    # -----------------------------------------------------------------------

    def set_tainted(
        self,
        session_id: str,
        reason: str = "ExplicitTaint",
        tags: Optional[Iterable[Union[TaintTag, str]]] = None,
    ) -> List[str]:
        """Convenience alias for mark_tainted."""
        return self.mark_tainted(session_id, reason=reason, tags=tags)

    def add_taint_tag(self, entity_id: Any, tag: Union[TaintTag, str]) -> None:
        """Add a typed taint tag to an entity."""
        with self._lock:
            canonical_id = self._canonical_id(entity_id)
            node = self._nodes.get(canonical_id)
            if node:
                node.add_tag(tag)

    def get_taint_tags(self, entity_id: Any) -> Set[TaintTag]:
        """Retrieve the active set of typed taint tags for an entity."""
        with self._lock:
            canonical_id = self._canonical_id(entity_id)
            node = self._nodes.get(canonical_id)
            return set(node.tags) if node else set()

    def propagate(self, from_session: str, to_session: str) -> None:
        """Create handoff edge from source to target session."""
        self.data_handoff(from_session, to_session)

    def is_tainted(self, entity_id: Any) -> bool:
        """Check if session string, PID int, or filepath is tainted."""
        with self._lock:
            if isinstance(entity_id, int):
                if entity_id in self._processes:
                    return self._processes[entity_id].is_tainted()
                if entity_id in self._pid_to_session:
                    sess_id = self._pid_to_session[entity_id]
                    return self.is_tainted(sess_id)
                return False

            canonical_id = self._canonical_id(entity_id)
            node = self._nodes.get(canonical_id)
            return node.is_tainted() if node else False

    def is_clean(self, entity_id: Any) -> bool:
        """Return True if entity is known and clean, or unknown."""
        return not self.is_tainted(entity_id)

    def get_taint(self, entity_id: Any) -> str:
        """Return 'TAINTED' or 'CLEAN' string."""
        if self.is_tainted(entity_id):
            return TaintState.TAINTED.value
        return TaintState.CLEAN.value

    def get_provenance_chain(self, entity_id: Any) -> List[str]:
        """
        Reconstruct causal chain leading to taint of entity.
        Returns [source, ..., parent, entity_id], or [] if CLEAN.
        """
        with self._lock:
            canonical_id = self._canonical_id(entity_id)
            node = self._nodes.get(canonical_id)
            if not node or not node.is_tainted():
                return []

            chain = [canonical_id]
            curr = node
            visited = {canonical_id}

            while curr and curr.taint_parent:
                p_id = curr.taint_parent
                if p_id in visited:
                    break
                visited.add(p_id)
                chain.append(p_id)
                curr = self._nodes.get(p_id)

            chain.reverse()
            return chain

    def get_file_taints(self) -> Dict[str, Dict[str, Any]]:
        """Return a copy of the monitored file taints dictionary."""
        with self._lock:
            return dict(self._file_taints)

    @property
    def file_taints(self) -> Dict[str, Dict[str, Any]]:
        """Property returning monitored file taints dictionary copy."""
        return self.get_file_taints()

    def get_status_dict(self) -> Dict[str, Any]:
        """Return status summary dictionary of tracked entities."""
        with self._lock:
            total_sessions = len(self._sessions)
            tainted_sessions = sum(
                1 for s in self._sessions.values() if s.is_tainted()
            )
            return {
                "total_sessions": total_sessions,
                "tainted_sessions": tainted_sessions,
                "clean_sessions": total_sessions - tainted_sessions,
                "total_processes": len(self._processes),
                "total_files": len(self._files),
            }

    def get_graph_snapshot(self) -> Dict[str, Any]:
        """Return serializable summary of graph nodes and edges."""
        with self._lock:
            nodes = [node.to_dict() for node in self._nodes.values()]
            edges = []
            for src_edges in self._adjacency.values():
                for edge in src_edges:
                    edges.append(edge.to_dict())
            return {
                "nodes_count": len(nodes),
                "edges_count": len(edges),
                "nodes": nodes,
                "edges": edges,
            }
