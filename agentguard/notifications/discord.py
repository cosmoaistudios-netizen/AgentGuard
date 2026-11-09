"""
agentguard.notifications.discord - Discord Webhook Rich Embed Generator & Client.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional
import urllib.request
import urllib.error

# Color Constants (Hex & Decimal)
COLOR_CRITICAL = 0xDC2626  # 14428710 - Red
COLOR_WARNING = 0xF59E0B   # 16096779 - Amber
COLOR_INFO = 0x3B82F6      # 3899904  - Blue
COLOR_SUCCESS = 0x10B981   # 1096065  - Green

DISCORD_COLOR_CRITICAL = COLOR_CRITICAL
DISCORD_COLOR_WARNING = COLOR_WARNING
DISCORD_COLOR_INFO = COLOR_INFO
DISCORD_COLOR_SUCCESS = COLOR_SUCCESS

SEVERITY_COLORS = {
    "CRITICAL": COLOR_CRITICAL,
    "WARNING": COLOR_WARNING,
    "INFO": COLOR_INFO,
    "SUCCESS": COLOR_SUCCESS,
}

SEVERITY_ICONS = {
    "CRITICAL": "🚨",
    "WARNING": "⚠️",
    "INFO": "ℹ️",
    "SUCCESS": "✅",
}

DEFAULT_SEVERITY_BY_EVENT = {
    "COMMAND_BLOCKED": "CRITICAL",
    "SECRET_EXFILTRATION_ATTEMPT": "CRITICAL",
    "VAULT_DETOKENIZE_BLOCKED": "CRITICAL",
    "CRITICAL_INTENT_DRIFT": "CRITICAL",
    "INTENT_DRIFT_BLOCKED": "CRITICAL",
    "TAINT_ESCALATION": "WARNING",
    "TAINT_CHANGE": "WARNING",
    "MANUAL_TAINT": "WARNING",
    "PROPAGATE_TAINT": "WARNING",
    "HITL_PROMPT": "WARNING",
    "AGENT_REGISTERED": "INFO",
    "REGISTER_AGENT": "INFO",
    "UNREGISTER_AGENT": "INFO",
    "SYNTHETIC_TEST": "INFO",
}


def _clamp_field(val: Any, max_len: int = 1024, default: str = "N/A") -> str:
    """Clamps an embed field value or string to Discord's maximum allowed length.

    Ensures non-empty string and truncates with ellipsis if length exceeds max_len.
    """
    if val is None:
        return default
    s = str(val)
    if not s.strip():
        return default
    if len(s) <= max_len:
        return s
    if max_len <= 3:
        return s[:max_len]
    return s[: max_len - 3] + "..."


clamp_field = _clamp_field


def build_discord_alert(
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
    username: str = "AgentGuard Sentinel",
    avatar_url: Optional[str] = None,
    config: Optional[Any] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    """
    Constructs a Discord webhook payload with formatted Rich Embed.
    Handles field extraction, command truncation, character clamping, and severity mapping.
    """
    details = details or {}

    # Determine severity
    if severity is None:
        severity = details.get("severity") or DEFAULT_SEVERITY_BY_EVENT.get(event_type)
        if not severity:
            if "BLOCKED" in event_type:
                severity = "CRITICAL"
            elif "TAINT" in event_type or "WARN" in event_type:
                severity = "WARNING"
            else:
                severity = "INFO"

    sev_upper = str(severity).upper()
    color = SEVERITY_COLORS.get(sev_upper, COLOR_CRITICAL)
    icon = SEVERITY_ICONS.get(sev_upper, "🚨")

    # Extract metadata from kwargs or details
    cmd = command or details.get("command", details.get("action", ""))
    pol_reason = reason or details.get("reason", details.get("policy_reason", "Security policy violation"))
    t_source = taint_source or details.get("taint_source", details.get("source", ""))
    t_state = details.get("taint", "TAINTED" if sev_upper == "CRITICAL" else "CLEAN")

    extracted_pid = pid if pid is not None else details.get("pid", 0)
    extracted_profile = profile if profile != "generic" else details.get("profile", "generic")
    extracted_session = session_id if session_id != "unknown" else details.get("session_id", "unknown")

    fields: List[Dict[str, Any]] = [
        {"name": "Severity", "value": _clamp_field(f"**{sev_upper}**"), "inline": True},
        {"name": "Agent PID", "value": _clamp_field(extracted_pid), "inline": True},
        {"name": "Profile", "value": _clamp_field(extracted_profile), "inline": True},
        {"name": "Session ID", "value": _clamp_field(extracted_session), "inline": True},
    ]

    if t_source:
        fields.append({"name": "Taint Source", "value": _clamp_field(t_source), "inline": True})
    else:
        fields.append({"name": "Taint State", "value": _clamp_field(f"🔴 **{t_state}**"), "inline": True})

    fields.append({"name": "Policy Reason", "value": _clamp_field(pol_reason), "inline": False})

    if cmd:
        clean_cmd = str(cmd).strip()
        if len(clean_cmd) > 1000:
            formatted_cmd = f"`{clean_cmd[:1000]}...`"
        elif "\n" in clean_cmd:
            formatted_cmd = f"```bash\n{clean_cmd}\n```"
        else:
            formatted_cmd = f"`{clean_cmd}`"

        if len(formatted_cmd) > 1024:
            formatted_cmd = formatted_cmd[:1020] + "...`"

        fields.append({
            "name": "Intercepted Command",
            "value": _clamp_field(formatted_cmd),
            "inline": False,
        })

    # Defensive guarantee pass across all fields
    for f in fields:
        f["name"] = _clamp_field(f.get("name", "Field"), max_len=256)
        f["value"] = _clamp_field(f.get("value", "N/A"), max_len=1024)

    iso_ts = timestamp or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    embed = {
        "title": _clamp_field(f"{icon} [{sev_upper}] Threat Intercepted: {event_type}", max_len=256),
        "description": _clamp_field("AgentGuard zero-trust security kernel blocked an unauthorized operation.", max_len=4096),
        "color": color,
        "fields": fields,
        "footer": {"text": _clamp_field("AgentGuard Zero-Trust Kernel • Sub-2ms Interception", max_len=2048)},
        "timestamp": iso_ts,
    }

    uname = username
    aurl = avatar_url
    if config:
        uname = getattr(config, "username", getattr(getattr(config, "discord", None), "username", uname))
        aurl = getattr(config, "avatar_url", getattr(getattr(config, "discord", None), "avatar_url", aurl))

    payload: Dict[str, Any] = {
        "username": uname,
        "embeds": [embed],
    }
    if aurl:
        payload["avatar_url"] = aurl

    return payload


# Alias for test suite compatibility
format_discord_threat_alert = build_discord_alert


def build_discord_heartbeat(
    status_data: Dict[str, Any],
    timestamp: Optional[str] = None,
    username: str = "AgentGuard Sentinel",
) -> Dict[str, Any]:
    """Constructs a Discord health heartbeat summary embed."""
    health = status_data.get("health", status_data.get("status", "healthy"))
    is_healthy = str(health).lower() in ("healthy", "ok", "active", "allowed")
    color = COLOR_SUCCESS if is_healthy else COLOR_WARNING

    uptime_sec = status_data.get("uptime_seconds", 0)
    hours, rem = divmod(int(uptime_sec), 3600)
    minutes, seconds = divmod(rem, 60)
    days, hours = divmod(hours, 24)
    if days > 0:
        uptime_fmt = f"{days}d {hours}h {minutes}m {seconds}s"
    elif hours > 0:
        uptime_fmt = f"{hours}h {minutes}m {seconds}s"
    elif minutes > 0:
        uptime_fmt = f"{minutes}m {seconds}s"
    else:
        uptime_fmt = f"{seconds}s"

    active_agents = status_data.get("active_agents", status_data.get("active_sessions", 0))
    tainted_agents = status_data.get("tainted_agents", status_data.get("tainted_sessions", 0))
    vault_tokens = status_data.get("vault_tokens", status_data.get("vaulted_secrets", status_data.get("vault_count", 0)))
    audit_events = status_data.get("audit_events", status_data.get("audit_events_count", status_data.get("total_audit_events", 0)))
    blocked_exploits = status_data.get("blocked_exploits", status_data.get("blocked_count", 0))
    mem_mb = status_data.get("memory_rss_mb", 42.0)

    active_agents_str = f"{active_agents} ({tainted_agents} Tainted)" if tainted_agents else f"{active_agents}"

    fields: List[Dict[str, Any]] = [
        {"name": "Daemon Health", "value": _clamp_field(f"🟢 **{str(health).upper()}**"), "inline": True},
        {"name": "Uptime", "value": _clamp_field(uptime_fmt), "inline": True},
        {"name": "Active Agents", "value": _clamp_field(active_agents_str), "inline": True},
        {"name": "Tainted Sessions", "value": _clamp_field(f"`{tainted_agents}`"), "inline": True},
        {"name": "Vaulted Secrets", "value": _clamp_field(vault_tokens), "inline": True},
        {"name": "Blocked Exploits", "value": _clamp_field(blocked_exploits), "inline": True},
        {"name": "Total Events", "value": _clamp_field(audit_events), "inline": True},
        {"name": "Memory Usage", "value": _clamp_field(f"{mem_mb:.1f} MB"), "inline": True},
    ]

    # Defensive guarantee pass across all fields
    for f in fields:
        f["name"] = _clamp_field(f.get("name", "Field"), max_len=256)
        f["value"] = _clamp_field(f.get("value", "N/A"), max_len=1024)

    iso_ts = timestamp or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    embed = {
        "title": _clamp_field("💓 [HEARTBEAT] AgentGuard System Health Report", max_len=256),
        "description": _clamp_field("Scheduled status report from AgentGuard background security daemon.", max_len=4096),
        "color": color,
        "fields": fields,
        "footer": {"text": _clamp_field("AgentGuard Scheduled Telemetry", max_len=2048)},
        "timestamp": iso_ts,
    }

    return {
        "username": username,
        "embeds": [embed],
    }


# Alias for test suite compatibility
format_discord_heartbeat = build_discord_heartbeat


def send_discord_payload(webhook_url: str, payload: Dict[str, Any], timeout: float = 5.0) -> bool:
    """Sends payload to Discord webhook via urllib.request."""
    if not webhook_url:
        return False

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "AgentGuard-Sentinel/0.1.0",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status in (200, 204)
