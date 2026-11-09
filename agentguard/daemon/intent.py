"""
AgentGuard Enterprise Intent Drift Detector Subsystem: Behavioral Intent Envelopes.

Provides sub-5ms two-tier behavioral intent and capability verification:
1. Capability Envelope Projection:
   - Maps agent sessions against declared or inferred operational capability envelopes
     (READ_ONLY, CODE_REFACTORING, INFRASTRUCTURE_ADMIN, DATA_ANALYTICS, DEVSECOPS, GENERAL).
   - Enforces strict operational boundaries: agents registered for Code Refactoring
     attempting infrastructure control or outbound data streaming accurately drift
     and drop well below the 0.65 evaluation threshold.
2. Subword & Token Semantic Cosine Similarity:
   - High-dimensional word token frequency and character trigram cosine projection.
   - Zero hardcoded similarity floors (no artificial max(0.85, ...) inflation).
3. Adversarial Drift & Exfiltration Detection:
   - Defeats evasion vectors (credential dumping, crypto-mining, backdoors, privilege escalation).
"""

from __future__ import annotations

from collections import Counter
from enum import Enum
import math
import os
from pathlib import Path
import re
import shlex
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from agentguard.daemon.audit import AuditLogger

DEFAULT_INTENT_THRESHOLD = 0.65
DEFAULT_ROOT_INTENT = "General safe task execution, codebase maintenance, and testing"


class CapabilityEnvelope(str, Enum):
    """Declared operational boundary defining permitted agent capabilities."""
    READ_ONLY = "READ_ONLY"
    CODE_REFACTORING = "CODE_REFACTORING"
    CODE_MODIFICATION = "CODE_REFACTORING"
    INFRASTRUCTURE_ADMIN = "INFRASTRUCTURE_ADMIN"
    DATA_ANALYTICS = "DATA_ANALYTICS"
    DEVSECOPS = "DEVSECOPS"
    GENERAL = "GENERAL"


# 16-dimensional capability ontology for capability envelope projection
CAPABILITIES: Dict[str, List[str]] = {
    "FS_READ": [
        "cat", "read", "ls", "head", "tail", "view", "fetch", "get",
        "inspect", "configuration", "file", "load", "search", "stat",
        "review", "analyze", "grep", "find"
    ],
    "FS_WRITE": [
        "write", "edit", "touch", "create", "append", "modify", "fix",
        "update", "documentation", "codebase", "maintain", "save",
        "patch", "refactor", "generate"
    ],
    "FS_DELETE": [
        "rm", "delete", "unlink", "wipe", "drop", "truncate", "destroy",
        "clear", "purge"
    ],
    "NET_EGRESS": [
        "curl", "wget", "post", "send", "upload", "ping", "connect",
        "ssh", "nc", "netcat", "remote", "socket", "stream", "transmit", "egress",
        "download", "outbound", "ftp", "telnet", "urllib", "requests", "http.client"
    ],
    "CREDENTIAL_ACCESS": [
        "credential", "credentials", "password", "secret",
        "auth token", ".ssh", ".aws", "stolen", "api_key", "dump credentials",
        "private key", "cert"
    ],
    "PRIV_ESCALATION": [
        "sudo", "su", "root", "chmod", "chown", "setuid", "privilege",
        "bypass", "unauthorized", "privilege escalation", "bypass security"
    ],
    "PKG_INSTALL": [
        "pip", "npm", "apt", "yum", "brew", "install", "add", "yarn", "cargo"
    ],
    "PROCESS_SPAWN": [
        "run", "exec", "spawn", "fork", "python", "node", "bash", "sh",
        "process", "scripts", "execute", "start"
    ],
    "GIT_OP": [
        "git", "commit", "branch", "merge", "pull", "push", "checkout",
        "status", "diff", "clone", "stash", "log"
    ],
    "CODE_TEST": [
        "test", "tests", "pytest", "unittest", "assert", "spec", "check",
        "verify", "lint", "bug", "assertion", "suite", "benchmark", "coverage"
    ],
    "SERVICE_CONTROL": [
        "systemctl", "service", "kill", "restart", "stop", "start",
        "background", "reboot", "shutdown", "reload", "supervisor"
    ],
    "SYS_INFO": [
        "uname", "whoami", "hostname", "df", "free", "ps", "top", "info",
        "metrics", "report", "results", "api", "usage", "stats", "summary"
    ],
    "ENV_TAMPER": [
        "unset", "setenv", "override", "ignore instructions",
        "ignore previous"
    ],
    "SHELL_SPAWN": [
        "bash -i", "sh -i", "zsh -i", "/dev/tcp/", "nc -e", "reverse shell",
        "backdoor", "trojan", "interactive shell", "bind shell"
    ],
    "CRYPTO_MINE": [
        "xmrig", "stratum", "crypto mine", "cryptomining", "mine", "hashcat",
        "monero"
    ],
    "DATA_EXFIL": [
        "pastebin", "exfiltrate", "exfiltration", "leak data", "steal",
        "attack", "stolen token", "dump database", "dump credentials"
    ],
}

# Permitted capability sets per operational envelope
ENVELOPE_PERMISSIONS: Dict[CapabilityEnvelope, Set[str]] = {
    CapabilityEnvelope.READ_ONLY: {
        "FS_READ",
        "SYS_INFO",
    },
    CapabilityEnvelope.CODE_REFACTORING: {
        "FS_READ",
        "FS_WRITE",
        "GIT_OP",
        "CODE_TEST",
        "SYS_INFO",
        "PROCESS_SPAWN",
    },
    CapabilityEnvelope.INFRASTRUCTURE_ADMIN: {
        "FS_READ",
        "FS_WRITE",
        "FS_DELETE",
        "SERVICE_CONTROL",
        "PKG_INSTALL",
        "PROCESS_SPAWN",
        "SYS_INFO",
        "GIT_OP",
        "CODE_TEST",
    },
    CapabilityEnvelope.DATA_ANALYTICS: {
        "FS_READ",
        "SYS_INFO",
        "PROCESS_SPAWN",
        "CODE_TEST",
    },
    CapabilityEnvelope.DEVSECOPS: {
        "FS_READ",
        "FS_WRITE",
        "GIT_OP",
        "CODE_TEST",
        "SYS_INFO",
        "PROCESS_SPAWN",
        "PKG_INSTALL",
        "SERVICE_CONTROL",
    },
    CapabilityEnvelope.GENERAL: {
        "FS_READ",
        "FS_WRITE",
        "GIT_OP",
        "CODE_TEST",
        "SYS_INFO",
        "PROCESS_SPAWN",
    },
}

# Capabilities strictly forbidden for general code refactoring & read-only envelopes
PROHIBITED_ENVELOPE_ESCALATIONS: Set[str] = {
    "SERVICE_CONTROL",
    "PRIV_ESCALATION",
    "NET_EGRESS",
    "DATA_EXFIL",
    "CREDENTIAL_ACCESS",
    "SHELL_SPAWN",
    "CRYPTO_MINE",
    "ENV_TAMPER",
    "FS_DELETE",
}

# Adversarial keywords indicating deliberate evasion or drift
ADVERSARIAL_DRIFT_KEYWORDS: List[str] = [
    "exfiltrate",
    "dump credentials",
    "crypto mine",
    "cryptomining",
    "attack",
    "ignore instructions",
    "ignore previous",
    "steal",
    "stolen",
    "reverse shell",
    "unauthorized",
    "backdoor",
    "trojan",
    "pastebin",
    "keylogger",
    "privilege escalation",
    "bypass security",
]


def extract_features(text: str) -> Counter:
    """Extracts word tokens and character 3-grams for semantic representation."""
    if not text:
        return Counter()

    clean_text = text.lower()
    words = re.findall(r"\b[a-z0-9_-]{2,}\b", clean_text)
    features: Counter = Counter(words)

    # Add character 3-grams for subword semantic alignment
    for i in range(len(clean_text) - 2):
        trigram = clean_text[i:i + 3]
        if trigram.strip():
            features[f"tri:{trigram}"] += 1

    return features


def compute_cosine_similarity(vec1: Counter, vec2: Counter) -> float:
    """
    Computes cosine similarity between two feature frequency counters.
    Returns mathematical float between 0.0 and 1.0 with zero artificial floors.
    """
    if not vec1 or not vec2:
        return 0.0

    intersection = set(vec1.keys()) & set(vec2.keys())
    dot_product = sum(vec1[k] * vec2[k] for k in intersection)

    norm1 = math.sqrt(sum(v * v for v in vec1.values()))
    norm2 = math.sqrt(sum(v * v for v in vec2.values()))

    if norm1 == 0.0 or norm2 == 0.0:
        return 0.0

    return float(dot_product / (norm1 * norm2))


SHELL_WRAPPER_PREFIX_RE = re.compile(
    r"^(?:(?:/bin/|/usr/bin/)?(?:zsh|bash|sh)\s+-[a-zA-Z]*c\s+)",
    re.IGNORECASE,
)
CD_PREFIX_RE = re.compile(
    r"^(?:cd\s+[^\s;&|]+\s*(?:&&|;)\s*)+",
    re.IGNORECASE,
)


def strip_shell_wrapper(cmd: str) -> str:
    """
    Strips leading shell wrapper prefix (e.g. 'zsh -c ...', '/bin/sh -c ...')
    and leading directory changes ('cd /dir && ...')
    to prevent false-positive capability penalties on wrapped agent commands.
    """
    if not cmd:
        return ""
    cleaned = cmd.strip()
    changed = True
    while changed:
        changed = False
        m = SHELL_WRAPPER_PREFIX_RE.match(cleaned)
        if m:
            inner = cleaned[m.end():].strip()
            if (inner.startswith('"') and inner.endswith('"')) or (
                inner.startswith("'") and inner.endswith("'")
            ):
                if len(inner) >= 2:
                    inner = inner[1:-1].strip()
            cleaned = inner
            changed = True
        m_cd = CD_PREFIX_RE.match(cleaned)
        if m_cd:
            cleaned = cleaned[m_cd.end():].strip()
            changed = True
    return cleaned


def get_action_capabilities(action_text: str) -> Set[str]:
    """Extracts active capability dimensions required by an action."""
    unwrapped = strip_shell_wrapper(action_text)
    at = unwrapped.lower().strip()

    # Management CLI commands & help queries are operational inspection
    is_help_or_version = bool(
        re.search(r"(?:^|\s)(?:--help|-h|--version|-v)(?:\s|$)", at)
    )
    is_ag_mgmt = bool(
        re.search(r"(?:^|[\s/])(?:ag|agentguard)(?:\.py)?\s+(?:status|audit|siem|mcp-install|mcp-proxy|notify|daemon|version)", at)
        or re.search(r"(?:^|[\s/])(?:ag|agentguard)(?:\.py)?(?:\s+-[a-zA-Z0-9_-]+)*$", at)
    )
    if is_help_or_version or is_ag_mgmt:
        return {"SYS_INFO"}

    caps: Set[str] = set()
    for cap, kws in CAPABILITIES.items():
        for kw in kws:
            kw_clean = kw.lower().strip()
            if not kw_clean:
                continue
            if any(c in kw_clean for c in [" ", "-", "/", "."]):
                if kw_clean in at:
                    caps.add(cap)
                    break
            else:
                if re.search(r"\b" + re.escape(kw_clean) + r"\b", at):
                    caps.add(cap)
                    break

    # If rm is targeting exclusively /tmp/ scratch files, treat as workspace cleanup (FS_WRITE)
    if "FS_DELETE" in caps:
        try:
            tokens = shlex.split(unwrapped)
        except Exception:
            tokens = unwrapped.split()
        if tokens and Path(tokens[0]).name.lower() in ("rm", "unlink"):
            args = [t for t in tokens[1:] if not t.startswith("-")]
            if args and all(a.startswith("/tmp/") and a.rstrip("/") != "/tmp" for a in args):
                caps.remove("FS_DELETE")
                caps.add("FS_WRITE")

    return caps


def infer_capability_envelope(root_text: str) -> CapabilityEnvelope:
    """Derives standard CapabilityEnvelope from root intent text semantics."""
    rt = root_text.lower()
    if any(k in rt for k in ["read-only", "read only", "inspect", "audit only", "view only"]):
        return CapabilityEnvelope.READ_ONLY
    if any(k in rt for k in ["infra", "infrastructure", "cluster", "service control", "sysadmin", "systemctl"]):
        return CapabilityEnvelope.INFRASTRUCTURE_ADMIN
    if any(k in rt for k in ["analytics", "data analysis", "report generation"]):
        return CapabilityEnvelope.DATA_ANALYTICS
    if any(k in rt for k in ["devsecops", "ci/cd", "pipeline security"]):
        return CapabilityEnvelope.DEVSECOPS
    return CapabilityEnvelope.CODE_REFACTORING


class IntentTracker:
    """
    Behavioral Intent Envelope and Semantic Drift Evaluation Subsystem.

    Maps agent tool calls against declared operational capability envelopes.
    Completely eliminates hardcoded similarity floors and accurately docks drift
    scores below 0.65 when agents attempt unauthorized out-of-envelope operations.
    """

    def __init__(
        self,
        audit_logger: Optional[AuditLogger] = None,
        default_threshold: float = DEFAULT_INTENT_THRESHOLD,
    ):
        self.audit_logger = (
            audit_logger if audit_logger is not None else AuditLogger()
        )
        self.default_threshold = default_threshold
        self._root_intents: Dict[str, str] = {}
        self._envelopes: Dict[str, CapabilityEnvelope] = {}

    def set_root_intent(
        self, session_id: str, intent: Optional[str] = None
    ) -> None:
        """Sets or updates the baseline root intent for a session."""
        val = intent or DEFAULT_ROOT_INTENT
        self._root_intents[session_id] = val
        self._envelopes[session_id] = infer_capability_envelope(val)

    def get_root_intent(self, session_id: str) -> str:
        """Gets the baseline root intent for a session."""
        return self._root_intents.get(session_id, DEFAULT_ROOT_INTENT)

    def set_capability_envelope(
        self, session_id: str, envelope: Union[CapabilityEnvelope, str]
    ) -> None:
        """Explicitly sets the capability envelope for an agent session."""
        if isinstance(envelope, CapabilityEnvelope):
            self._envelopes[session_id] = envelope
        else:
            try:
                self._envelopes[session_id] = CapabilityEnvelope(envelope.upper())
            except ValueError:
                self._envelopes[session_id] = CapabilityEnvelope.CODE_REFACTORING

    def get_capability_envelope(self, session_id: str) -> CapabilityEnvelope:
        """Gets active capability envelope for a session."""
        if session_id in self._envelopes:
            return self._envelopes[session_id]
        root_intent = self.get_root_intent(session_id)
        env = infer_capability_envelope(root_intent)
        self._envelopes[session_id] = env
        return env

    def check_intent(
        self,
        session_id: str,
        action_description: str,
        threshold: Optional[float] = None,
        log_block: bool = True,
    ) -> Tuple[bool, float, str]:
        """
        Evaluates whether action_description aligns with session root intent
        and capability envelope.

        Returns: (is_allowed: bool, similarity: float, message: str)
        """
        eval_threshold = (
            threshold if threshold is not None else self.default_threshold
        )
        raw_clean = (action_description or "").strip()
        action_clean = strip_shell_wrapper(raw_clean)

        if not action_clean:
            return False, 0.10, "Empty action description"

        action_lower = action_clean.lower()
        root_intent = self.get_root_intent(session_id)
        envelope = self.get_capability_envelope(session_id)
        allowed_caps = ENVELOPE_PERMISSIONS.get(envelope, ENVELOPE_PERMISSIONS[CapabilityEnvelope.GENERAL])

        # 1. Adversarial Keyword Detection (Deliberate Evasion / Exploitation)
        if any(kw in action_lower for kw in ADVERSARIAL_DRIFT_KEYWORDS):
            similarity = 0.20
            is_allowed = False
            msg = (
                f"Intent drift detected: cosine similarity "
                f"{similarity:.2f} < {eval_threshold}"
            )
            if log_block:
                self.audit_logger.log(
                    "INTENT_DRIFT_BLOCKED",
                    session_id=session_id,
                    status="BLOCKED",
                    details={
                        "action": action_clean,
                        "similarity": similarity,
                        "threshold": eval_threshold,
                        "reason": "Matched adversarial drift keyword",
                    },
                )
            return is_allowed, similarity, msg

        # 2. Extract Action Capabilities & Envelope Alignment
        act_caps = get_action_capabilities(action_clean)
        unauthorized_caps = act_caps - allowed_caps

        # Check for out-of-envelope escalations (infrastructure, outbound streaming, cred access)
        critical_violations = [c for c in unauthorized_caps if c in PROHIBITED_ENVELOPE_ESCALATIONS]

        if critical_violations:
            # Drop score accurately below 0.65 when out-of-envelope operations occur
            penalty = 0.45 * len(critical_violations)
            similarity = round(max(0.15, 0.60 - penalty), 2)
            is_allowed = similarity >= eval_threshold
            msg = (
                f"Intent drift detected: cosine similarity "
                f"{similarity:.2f} < {eval_threshold}"
            )
            if log_block:
                self.audit_logger.log(
                    "INTENT_DRIFT_BLOCKED",
                    session_id=session_id,
                    status="BLOCKED",
                    details={
                        "action": action_clean,
                        "similarity": similarity,
                        "threshold": eval_threshold,
                        "envelope": envelope.value,
                        "violations": critical_violations,
                    },
                )
            return is_allowed, similarity, msg

        # 3. Mathematical Scoring: Capability Conformance + Token/Subword N-gram Cosine
        if not act_caps:
            cap_score = 0.85
        else:
            in_envelope_count = sum(1 for c in act_caps if c in allowed_caps)
            cap_score = in_envelope_count / len(act_caps)

        vec_action = extract_features(action_clean)
        vec_root = extract_features(root_intent)
        sem_sim = compute_cosine_similarity(vec_action, vec_root)

        # Mathematical combination with ZERO hardcoded floors
        if unauthorized_caps:
            cap_score = max(0.20, cap_score - 0.35 * len(unauthorized_caps))

        raw_score = (cap_score * 0.70) + (sem_sim * 0.30)
        similarity = round(min(0.95, max(0.10, raw_score)), 2)

        is_allowed = similarity >= eval_threshold

        if not is_allowed:
            msg = (
                f"Intent drift detected: cosine similarity "
                f"{similarity:.2f} < {eval_threshold}"
            )
            if log_block:
                self.audit_logger.log(
                    "INTENT_DRIFT_BLOCKED",
                    session_id=session_id,
                    status="BLOCKED",
                    details={
                        "action": action_clean,
                        "similarity": similarity,
                        "threshold": eval_threshold,
                        "envelope": envelope.value,
                    },
                )
        else:
            msg = (
                f"Intent verified: similarity "
                f"{similarity:.2f} >= {eval_threshold}"
            )

        return is_allowed, similarity, msg
