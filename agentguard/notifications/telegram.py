"""
agentguard.notifications.telegram - Telegram Bot API Threat Card Generator & Client.
"""

from __future__ import annotations

from datetime import datetime, timezone
import html
import json
import re
from typing import Any, Dict, List, Optional
import urllib.request
import urllib.error


def escape_html(text: Any) -> str:
    """Escapes string content for safe embedding in Telegram HTML messages."""
    return html.escape(str(text), quote=True)


# Alias
escape_telegram_html = escape_html


def escape_markdown_v2(text: Any) -> str:
    """Escapes Telegram MarkdownV2 reserved characters."""
    return re.sub(r"([_*\[\]()~`>#+\-=|{}.!\\])", r"\\\1", str(text))


# Alias
escape_telegram_markdown = escape_markdown_v2


def truncate_html(text: str, max_length: int = 4096, ellipsis: str = "...") -> str:
    """
    Truncates an HTML string to at most max_length characters while ensuring:
    1. All opened HTML tags are properly closed in reverse (LIFO) order.
    2. Tags and HTML entities are never sliced in half.
    3. Total length strictly does not exceed max_length.
    4. Suffix (e.g. '...') is included within the max_length budget when truncated.
    """
    if len(text) <= max_length:
        tag_pattern = re.compile(
            r'(</[a-zA-Z0-9_-]+>)|(<[a-zA-Z0-9_-]+(?:\s+[^>]*)?/?>)'
        )
        tag_name_pat = re.compile(r'</?([a-zA-Z0-9_-]+)')
        stack: List[str] = []
        for m in tag_pattern.finditer(text):
            if m.group(1):  # close tag
                tn = tag_name_pat.match(m.group(1)).group(1).lower()
                if stack and stack[-1] == tn:
                    stack.pop()
                elif tn in stack:
                    while stack and stack[-1] != tn:
                        stack.pop()
                    if stack:
                        stack.pop()
            elif m.group(2):  # open tag
                raw_tag = m.group(2)
                if not raw_tag.endswith("/>"):
                    tn = tag_name_pat.match(raw_tag).group(1).lower()
                    stack.append(tn)
        if not stack:
            return text
        closing = "".join(f"</{t}>" for t in reversed(stack))
        if len(text) + len(closing) <= max_length:
            return text + closing

    # Tokenize HTML into closing tags, opening tags, entities, text runs, or fallback characters
    token_pattern = re.compile(
        r'(</[a-zA-Z0-9_-]+>)'                      # Group 1: Closing tag
        r'|(<[a-zA-Z0-9_-]+(?:\s+[^>]*)?/?>)'       # Group 2: Opening tag
        r'|(&[a-zA-Z0-9#]+;)'                       # Group 3: HTML entity
        r'|([^<&]+)'                                # Group 4: Regular text run
        r'|(.)'                                     # Group 5: Single character fallback
    )

    tag_name_pattern = re.compile(r'</?([a-zA-Z0-9_-]+)')

    active_stack: List[str] = []
    accepted_tokens: List[str] = []
    current_len = 0

    best_tokens: List[str] = []
    best_stack: List[str] = []

    for m in token_pattern.finditer(text):
        raw = m.group(0)
        is_close = bool(m.group(1))
        is_open = bool(m.group(2))
        is_text = bool(m.group(4))

        new_stack = list(active_stack)
        if is_open:
            if not raw.endswith("/>"):
                match = tag_name_pattern.match(raw)
                if match:
                    new_stack.append(match.group(1).lower())
        elif is_close:
            match = tag_name_pattern.match(raw)
            if match:
                tn = match.group(1).lower()
                if new_stack and new_stack[-1] == tn:
                    new_stack.pop()
                elif tn in new_stack:
                    while new_stack and new_stack[-1] != tn:
                        new_stack.pop()
                    if new_stack:
                        new_stack.pop()

        closing_tags_str = "".join(f"</{t}>" for t in reversed(new_stack))
        projected_len = current_len + len(raw) + len(ellipsis) + len(closing_tags_str)

        if projected_len <= max_length:
            accepted_tokens.append(raw)
            current_len += len(raw)
            active_stack = new_stack
            best_tokens = list(accepted_tokens)
            best_stack = list(active_stack)
        else:
            if is_text:
                avail = max_length - current_len - len(ellipsis) - len("".join(f"</{t}>" for t in reversed(active_stack)))
                if avail > 0:
                    accepted_tokens.append(raw[:avail])
                    best_tokens = list(accepted_tokens)
                    best_stack = list(active_stack)
            break

    closing_tags = "".join(f"</{t}>" for t in reversed(best_stack))
    result = "".join(best_tokens) + ellipsis + closing_tags
    return result


# Alias
safe_truncate_html = truncate_html


def build_telegram_alert(
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
    **kwargs: Any,
) -> str:
    """
    Constructs a concise, formatted Telegram HTML threat card string.
    Pre-clamps fields and guarantees all HTML tags are balanced within <= 4096 characters.
    """
    details = details or {}
    if severity is None:
        severity = details.get("severity", "CRITICAL" if "BLOCKED" in event_type else "WARNING")
    sev_upper = str(severity).upper()

    cmd = command or details.get("command", details.get("action", ""))
    pol_reason = reason or details.get("reason", details.get("policy_reason", "Security policy violation"))
    t_source = taint_source or details.get("taint_source", details.get("source", ""))
    t_state = details.get("taint", "TAINTED" if sev_upper == "CRITICAL" else "CLEAN")

    extracted_pid = pid if pid is not None else details.get("pid", 0)
    extracted_profile = profile if profile != "generic" else details.get("profile", "generic")
    extracted_session = session_id if session_id != "unknown" else details.get("session_id", "unknown")

    # Pre-clamp pol_reason to max 500 chars before template injection
    clean_reason = str(pol_reason).strip()
    if len(clean_reason) > 500:
        clean_reason = clean_reason[:497] + "..."

    # Pre-clamp taint_source to max 500 chars
    clean_source = str(t_source).strip()
    if len(clean_source) > 500:
        clean_source = clean_source[:497] + "..."

    taint_display = f"🔴 <b>{escape_html(t_state)}</b>"
    if clean_source:
        taint_display += f" (Source: <code>{escape_html(clean_source)}</code>)"

    lines = [
        f"🚨 <b>[{escape_html(sev_upper)}] AgentGuard Threat Alert</b>",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        f"<b>Event:</b> <code>{escape_html(event_type)}</code>",
        f"<b>Agent PID:</b> <code>{extracted_pid}</code> (Profile: <code>{escape_html(extracted_profile)}</code>)",
        f"<b>Session ID:</b> <code>{escape_html(extracted_session)}</code>",
        f"<b>Taint State:</b> {taint_display}",
        f"<b>Policy Reason:</b> <i>{escape_html(clean_reason)}</i>",
    ]

    if cmd:
        clean_cmd = str(cmd).strip()
        lines.append("")
        lines.append("<b>Intercepted Command:</b>")
        # Pre-clamp clean_cmd to max 2500 chars before template injection
        if len(clean_cmd) > 2500:
            clean_cmd = clean_cmd[:2450] + "\n... [truncated]"
        lines.append(f"<pre><code class=\"language-bash\">{escape_html(clean_cmd)}</code></pre>")

    lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    iso_ts = timestamp or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    lines.append(f"<i>AgentGuard Zero-Trust Kernel • {escape_html(iso_ts)}</i>")

    text = "\n".join(lines)
    return truncate_html(text, max_length=4096)


def format_telegram_threat_alert(
    event_type: str,
    details: Optional[Dict[str, Any]] = None,
    config: Optional[Any] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    """Constructs Telegram API message payload dictionary."""
    chat_id = ""
    parse_mode = "HTML"
    if config:
        chat_id = getattr(config, "chat_id", getattr(getattr(config, "telegram", None), "chat_id", ""))
        parse_mode = getattr(config, "parse_mode", getattr(getattr(config, "telegram", None), "parse_mode", "HTML"))

    text = build_telegram_alert(event_type=event_type, details=details, **kwargs)
    return {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": parse_mode,
        "disable_web_page_preview": True,
    }


def build_telegram_heartbeat(status_data: Dict[str, Any], timestamp: Optional[str] = None) -> str:
    """Constructs a Telegram health heartbeat summary card string."""
    health = status_data.get("health", status_data.get("status", "healthy"))
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

    lines = [
        "💓 <b>AgentGuard System Health Heartbeat</b>",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        f"<b>Daemon Health:</b> 🟢 <b>{escape_html(str(health).upper())}</b>",
        f"<b>Uptime:</b> <code>{uptime_fmt}</code>",
        f"<b>Active Agents:</b> <code>{active_agents}</code>",
        f"<b>Tainted Sessions:</b> <code>{tainted_agents}</code>",
        f"<b>Shielded Secrets:</b> <code>{vault_tokens}</code>",
        f"<b>Blocked Exploits:</b> <code>{blocked_exploits}</code>",
        f"<b>Total Events:</b> <code>{audit_events}</code>",
        f"<b>Memory Usage:</b> <code>{mem_mb:.1f} MB</code> RSS (<100MB SLA)",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        f"<i>Scheduled Report • {escape_html(timestamp or 'Active')}</i>",
    ]
    text = "\n".join(lines)
    return truncate_html(text, max_length=4096)


def format_telegram_heartbeat(
    status_data: Dict[str, Any],
    config: Optional[Any] = None,
    timestamp: Optional[str] = None,
) -> Dict[str, Any]:
    """Constructs Telegram API heartbeat message payload dictionary."""
    chat_id = ""
    parse_mode = "HTML"
    if config:
        chat_id = getattr(config, "chat_id", getattr(getattr(config, "telegram", None), "chat_id", ""))
        parse_mode = getattr(config, "parse_mode", getattr(getattr(config, "telegram", None), "parse_mode", "HTML"))

    text = build_telegram_heartbeat(status_data=status_data, timestamp=timestamp)
    return {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": parse_mode,
        "disable_web_page_preview": True,
    }


def send_telegram_payload(
    bot_token: str,
    chat_id: str,
    text: str,
    parse_mode: str = "HTML",
    api_base: Optional[str] = None,
    timeout: float = 5.0,
) -> bool:
    """Sends message to Telegram via Bot API sendMessage."""
    if not bot_token:
        return False

    clean_token = str(bot_token).strip()
    if clean_token.startswith("http://") or clean_token.startswith("https://"):
        url = clean_token
    else:
        base = api_base or "https://api.telegram.org"
        url = f"{base}/bot{clean_token}/sendMessage"

    payload = {
        "chat_id": str(chat_id),
        "text": text,
        "parse_mode": parse_mode,
        "disable_web_page_preview": True,
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "AgentGuard-Sentinel/0.1.0",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status == 200
