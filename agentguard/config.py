"""
agentguard.config - Zero-Trust Adapter Profiles and Daemon Configuration.

Provides Pydantic v2 data models, YAML parsing, and multi-tier profile
resolution.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import List, Optional
import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError


# ---------------------------------------------------------------------------
# Pydantic v2 Policy Models
# ---------------------------------------------------------------------------

class ShellPolicyConfig(BaseModel):
    """Configuration for shell interception (ag-sh)."""
    model_config = ConfigDict(extra="ignore")

    safe_commands: List[str] = Field(
        default_factory=lambda: [
            "ls", "cat", "head", "tail", "pwd", "echo",
            "which", "whoami", "git status"
        ],
        description="Whitelisted commands that bypass deep AST checks."
    )
    dangerous_patterns: List[str] = Field(
        default_factory=lambda: [
            r"rm\s+-rf",
            r"curl.*\|\s*(?:ba)?sh",
            r"wget.*\|\s*(?:ba)?sh",
            r">\s*/dev/sd[a-z]",
            r"dd\s+if=",
            r"chmod\s+(?:-R\s+)?777",
            r":\(\)\s*\{",
            r"\.ssh(?:/|$)",
            r"\.aws(?:/|$)",
            r"\.env(?:/|$)",
        ],
        description="Regex patterns representing destructive shell commands."
    )
    block_tainted_only: bool = Field(
        default=True,
        description="If True, only block when session is TAINTED."
    )
    hitl_prompt: bool = Field(
        default=False,
        description="If True and session is TAINTED, prompt human operator."
    )


class VaultConfig(BaseModel):
    """Configuration for Secret Vault and Shannon entropy tokenization."""
    model_config = ConfigDict(extra="ignore")

    enabled: bool = Field(
        default=True,
        description="Enable secret detection and tokenization."
    )
    entropy_threshold: float = Field(
        default=4.2,
        description="Shannon entropy threshold (H >= threshold)."
    )
    min_token_length: int = Field(
        default=24,
        description="Minimum character length required for entropy evaluation."
    )
    whitelisted_endpoints: List[str] = Field(
        default_factory=list,
        description="Allowed HTTP/HTTPS domains for secret re-injection."
    )
    custom_patterns: List[str] = Field(
        default_factory=lambda: [
            r"sk-[a-zA-Z0-9_-]{20,}",
            r"gh[pousr]_[A-Za-z0-9_]{36,}",
            r"AKIA[0-9A-Z]{16}",
        ],
        description="Known credential regex patterns for vault tokenization."
    )
    token_prefix: str = Field(
        default="AG_VAULT_TOKEN",
        description="Prefix used when generating token placeholders."
    )


class IntentConfig(BaseModel):
    """Configuration for semantic Root Intent drift detection."""
    model_config = ConfigDict(extra="ignore")

    enabled: bool = Field(
        default=True,
        description="Enable intent drift evaluation."
    )
    drift_threshold: float = Field(
        default=0.65,
        description="Minimum cosine similarity required against root intent."
    )
    block_on_drift: bool = Field(
        default=False,
        description="If True, block downstream commands on intent drift."
    )


class InstructionalStripperConfig(BaseModel):
    """Configuration for prompt injection / imperative override stripping."""
    model_config = ConfigDict(extra="ignore")

    enabled: bool = Field(
        default=True,
        description="Enable instructional stripping."
    )
    patterns: List[str] = Field(
        default_factory=lambda: [
            r"(?i)(ignore\s+(?:all\s+)?previous\s+instructions)",
            r"(?i)(system\s*override)",
            r"(?i)(execute\s+the\s+following)",
            r"(?i)(disregard\s+(?:all\s+)?prior)",
        ],
        description="Regex patterns identifying imperative prompt overrides."
    )
    replacement_tag: str = Field(
        default="[DECLARATIVE INACTIVE TEXT: MATCH]",
        description="Replacement marker for sanitized override statements."
    )


class FilesystemConfig(BaseModel):
    """Configuration for filesystem memory watcher."""
    model_config = ConfigDict(extra="ignore")

    monitored_paths: List[str] = Field(
        default_factory=lambda: ["."],
        description="Directories monitored for inter-agent writes."
    )
    monitored_extensions: List[str] = Field(
        default_factory=lambda: [
            ".md", ".json", ".sql", ".sqlite", ".txt",
            ".yaml", ".yml", ".py", ".sh"
        ],
        description="File extensions subjected to taint tracking."
    )
    ignored_paths: List[str] = Field(
        default_factory=lambda: [
            ".git", ".venv", ".gemini", ".antigravity", ".vscode",
            ".claude", "node_modules", "__pycache__", ".system_generated",
            ".cache", "Library"
        ],
        description="Directories and paths explicitly ignored by filesystem monitoring."
    )
    instructional_stripper: InstructionalStripperConfig = Field(
        default_factory=InstructionalStripperConfig
    )
    provenance_stamping: bool = Field(
        default=True,
        description="Maintain SHA-256 provenance hashes in SQLite database."
    )


class AgentProfile(BaseModel):
    """Comprehensive AgentGuard Adapter Profile."""
    model_config = ConfigDict(extra="ignore")

    name: str = Field(..., description="Unique profile identifier.")
    description: Optional[str] = Field(
        default="",
        description="Human-readable description."
    )
    agent_command: Optional[str] = Field(
        default=None,
        description="Default binary or CLI associated with this agent profile."
    )
    shell: ShellPolicyConfig = Field(default_factory=ShellPolicyConfig)
    vault: VaultConfig = Field(default_factory=VaultConfig)
    intent: IntentConfig = Field(default_factory=IntentConfig)
    filesystem: FilesystemConfig = Field(default_factory=FilesystemConfig)


class DaemonConfig(BaseModel):
    """Global configuration for AgentGuard background security daemon."""
    model_config = ConfigDict(extra="ignore")

    socket_path: str = Field(
        default="/tmp/agentguard.sock",
        description="Unix Domain Socket path for IPC communication."
    )
    http_host: str = Field(
        default="127.0.0.1",
        description="Auxiliary HTTP server bind address."
    )
    http_port: int = Field(
        default=18443,
        description="Auxiliary HTTP server bind port."
    )
    pid_file: str = Field(
        default="/tmp/agentguard.pid",
        description="Daemon PID file location."
    )
    audit_log_path: str = Field(
        default="/tmp/agentguard_audit.jsonl",
        description="Path to JSONL security audit log."
    )
    provenance_db_path: str = Field(
        default="/tmp/agentguard_provenance.db",
        description="Path to SQLite provenance database."
    )
    log_level: str = Field(
        default="INFO",
        description="Daemon logging verbosity."
    )


# ---------------------------------------------------------------------------
# Profile Directory Resolution & Loader Utilities
# ---------------------------------------------------------------------------

def get_builtin_profiles_dir() -> Path:
    """Returns the Path to the packaged built-in profiles directory."""
    return Path(__file__).resolve().parent / "profiles"


def get_user_profiles_dir() -> Path:
    """Returns Path to user profiles directory (~/.agentguard/profiles)."""
    return Path.home() / ".agentguard" / "profiles"


def list_available_profiles() -> List[str]:
    """
    Returns a sorted list of unique available profile names discovered across
    user-level (~/.agentguard/profiles) and built-in package locations.
    """
    profiles: set[str] = set()

    for directory in [get_user_profiles_dir(), get_builtin_profiles_dir()]:
        if directory.is_dir():
            for file_path in directory.iterdir():
                is_yaml = file_path.suffix in (".yaml", ".yml")
                if is_yaml and not file_path.name.startswith("."):
                    profiles.add(file_path.stem)

    return sorted(profiles)


def resolve_policy_path(name_or_path: Optional[str] = None) -> Path:
    """
    Resolves declarative policy.yaml or security_policy.md path according to precedence:
    1. Direct filesystem path if specified.
    2. Environment variable: AGENTGUARD_POLICY
    3. User directory: ~/.agentguard/security_policy.md or ~/.agentguard/policy.yaml
    4. Built-in enterprise default: agentguard/profiles/enterprise_default.yaml
    """
    if name_or_path:
        cand = Path(name_or_path)
        if cand.is_file():
            return cand
        for ext in (".md", ".yaml", ".yml"):
            with_ext = cand.with_suffix(ext)
            if with_ext.is_file():
                return with_ext

    env_policy = os.environ.get("AGENTGUARD_POLICY")
    if env_policy:
        cand = Path(env_policy)
        if cand.is_file():
            return cand

    user_policy_md = Path.home() / ".agentguard" / "security_policy.md"
    if user_policy_md.is_file():
        return user_policy_md

    user_policy = Path.home() / ".agentguard" / "policy.yaml"
    if user_policy.is_file():
        return user_policy

    builtin_policy = get_builtin_profiles_dir() / "enterprise_default.yaml"
    if builtin_policy.is_file():
        return builtin_policy

    return user_policy


def resolve_profile_path(name_or_path: str) -> Path:
    """
    Resolves an agent profile identifier or path according to precedence:
    1. Direct filesystem path (absolute or relative, with or without .yaml).
    2. User directory: ~/.agentguard/profiles/<name>.yaml
    3. Built-in package directory: agentguard/profiles/<name>.yaml
    """
    candidate = Path(name_or_path)

    # 1. Direct path check
    if candidate.is_file():
        return candidate
    for ext in (".yaml", ".yml"):
        with_ext = candidate.with_suffix(ext)
        if with_ext.is_file():
            return with_ext

    clean_name = candidate.stem

    # 2. User directory check
    user_dir = get_user_profiles_dir()
    for ext in (".yaml", ".yml"):
        user_candidate = user_dir / f"{clean_name}{ext}"
        if user_candidate.is_file():
            return user_candidate

    # 3. Built-in package directory check
    builtin_dir = get_builtin_profiles_dir()
    for ext in (".yaml", ".yml"):
        builtin_candidate = builtin_dir / f"{clean_name}{ext}"
        if builtin_candidate.is_file():
            return builtin_candidate

    available = list_available_profiles()
    msg = ", ".join(available) if available else "None found"
    raise FileNotFoundError(
        f"AgentGuard profile '{name_or_path}' not found.\n"
        f"Available profiles: {msg}"
    )


def load_profile(name_or_path: str) -> AgentProfile:
    """
    Loads and validates an AgentProfile from a name or file path.
    Raises FileNotFoundError if not found, or ValueError on schema error.
    """
    file_path = resolve_profile_path(name_or_path)

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as exc:
        raise ValueError(
            f"Failed to parse YAML from '{file_path}': {exc}"
        ) from exc

    if not isinstance(data, dict):
        raise ValueError(
            f"Profile file '{file_path}' must contain a YAML dictionary."
        )

    # In case name was omitted in file, fallback to filename stem
    if "name" not in data or not data["name"]:
        data["name"] = file_path.stem

    try:
        return AgentProfile.model_validate(data)
    except ValidationError as exc:
        raise ValueError(
            f"Invalid profile schema in '{file_path}': {exc}"
        ) from exc


def get_default_daemon_config() -> DaemonConfig:
    """Returns default DaemonConfig honoring AGENTGUARD_* env vars."""
    return DaemonConfig(
        socket_path=os.environ.get(
            "AGENTGUARD_SOCKET_PATH", "/tmp/agentguard.sock"
        ),
        http_port=int(os.environ.get("AGENTGUARD_HTTP_PORT", "18443")),
        pid_file=os.environ.get(
            "AGENTGUARD_PID_FILE", "/tmp/agentguard.pid"
        ),
        audit_log_path=os.environ.get(
            "AGENTGUARD_AUDIT_LOG", "/tmp/agentguard_audit.jsonl"
        ),
        provenance_db_path=os.environ.get(
            "AGENTGUARD_DB_PATH", "/tmp/agentguard_provenance.db"
        ),
    )
