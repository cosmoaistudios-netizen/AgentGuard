"""
agentguard.notifications - Zero-Trust Threat Alerting & System Health Engine.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from agentguard.notifications.config import (
    DiscordConfig,
    HeartbeatConfig,
    NotificationConfig,
    NotificationsConfig,
    TelegramConfig,
    get_notifications_config_path,
    load_notification_config,
    load_notifications_config,
    save_notification_config,
    save_notifications_config,
)
from agentguard.notifications.discord import (
    COLOR_CRITICAL,
    COLOR_INFO,
    COLOR_SUCCESS,
    COLOR_WARNING,
    build_discord_alert,
    build_discord_heartbeat,
    format_discord_heartbeat,
    format_discord_threat_alert,
    send_discord_payload,
)
from agentguard.notifications.dispatcher import (
    HIGH_RISK_EVENT_TYPES,
    NotificationDispatcher,
)
from agentguard.notifications.heartbeat import (
    HealthHeartbeatTask,
    compile_heartbeat_metrics,
    compile_heartbeat_payload,
    format_uptime,
    get_process_ram_rss_bytes,
    get_process_ram_rss_mb,
)
from agentguard.notifications.telegram import (
    build_telegram_alert,
    build_telegram_heartbeat,
    escape_html,
    escape_markdown_v2,
    escape_telegram_html,
    escape_telegram_markdown,
    format_telegram_heartbeat,
    format_telegram_threat_alert,
    send_telegram_payload,
)


from agentguard.notifications.wizard import (
    NotificationSetupWizard,
    launch_notification_wizard,
)


def dispatch_threat_alert(
    event_type: str,
    details: Optional[Dict[str, Any]] = None,
    **kwargs: Any,
) -> bool:
    """Convenience helper to dispatch a threat alert with active configuration."""
    cfg = load_notification_config()
    if not cfg.enabled:
        return False
    dispatcher = NotificationDispatcher(config=cfg)
    return dispatcher.enqueue_alert(event_type=event_type, details=details, **kwargs)


def dispatch_health_heartbeat(status_data: Dict[str, Any]) -> bool:
    """Convenience helper to dispatch a health heartbeat with active configuration."""
    cfg = load_notification_config()
    if not cfg.enabled or not cfg.heartbeat.enabled:
        return False
    dispatcher = NotificationDispatcher(config=cfg)
    return dispatcher.enqueue_heartbeat(status_data)


__all__ = [
    "DiscordConfig",
    "HeartbeatConfig",
    "NotificationConfig",
    "NotificationsConfig",
    "TelegramConfig",
    "get_notifications_config_path",
    "load_notification_config",
    "load_notifications_config",
    "save_notification_config",
    "save_notifications_config",
    "NotificationDispatcher",
    "HIGH_RISK_EVENT_TYPES",
    "dispatch_threat_alert",
    "dispatch_health_heartbeat",
    "build_discord_alert",
    "format_discord_threat_alert",
    "build_discord_heartbeat",
    "format_discord_heartbeat",
    "send_discord_payload",
    "COLOR_CRITICAL",
    "COLOR_WARNING",
    "COLOR_INFO",
    "COLOR_SUCCESS",
    "build_telegram_alert",
    "format_telegram_threat_alert",
    "build_telegram_heartbeat",
    "format_telegram_heartbeat",
    "escape_html",
    "escape_telegram_html",
    "escape_markdown_v2",
    "escape_telegram_markdown",
    "send_telegram_payload",
    "HealthHeartbeatTask",
    "compile_heartbeat_metrics",
    "compile_heartbeat_payload",
    "format_uptime",
    "get_process_ram_rss_bytes",
    "get_process_ram_rss_mb",
    "NotificationSetupWizard",
    "launch_notification_wizard",
]
