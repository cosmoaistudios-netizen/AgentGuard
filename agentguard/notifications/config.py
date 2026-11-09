"""
agentguard.notifications.config - Notification Configuration & Credential Store.

Manages ~/.agentguard/notifications.yaml with strict 0o600 file permissions.
"""

from __future__ import annotations

import os
from pathlib import Path
import stat
from typing import Any, Dict, Optional, Union
import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

DEFAULT_NOTIFICATIONS_PATH = Path.home() / ".agentguard" / "notifications.yaml"


class DiscordConfig(BaseModel):
    """Configuration for Discord Webhook alerts."""
    model_config = ConfigDict(extra="ignore")

    enabled: bool = Field(default=False, description="Enable Discord notifications")
    webhook_url: str = Field(default="", description="Discord webhook URL")
    username: str = Field(default="AgentGuard Sentinel", description="Webhook bot name")
    avatar_url: Optional[str] = Field(default=None, description="Custom avatar URL")

    @field_validator("webhook_url", mode="before")
    @classmethod
    def validate_webhook_url(cls, v: Any) -> str:
        if v is None:
            return ""
        return str(v).strip()


class TelegramConfig(BaseModel):
    """Configuration for Telegram Bot API alerts."""
    model_config = ConfigDict(extra="ignore")

    enabled: bool = Field(default=False, description="Enable Telegram notifications")
    bot_token: str = Field(default="", description="Telegram Bot API token")
    chat_id: str = Field(default="", description="Target chat ID or channel")
    parse_mode: str = Field(default="HTML", description="Message parse mode (HTML or MarkdownV2)")

    @field_validator("bot_token", mode="before")
    @classmethod
    def validate_bot_token(cls, v: Any) -> str:
        if v is None:
            return ""
        return str(v).strip()

    @field_validator("chat_id", mode="before")
    @classmethod
    def validate_chat_id(cls, v: Any) -> str:
        if v is None:
            return ""
        return str(v).strip()


class HeartbeatConfig(BaseModel):
    """Configuration for scheduled system health telemetry."""
    model_config = ConfigDict(extra="ignore")

    enabled: bool = Field(default=True, description="Enable scheduled health heartbeat")
    interval_seconds: int = Field(default=3600, ge=10, description="Heartbeat interval in seconds")
    send_on_start: bool = Field(default=True, description="Send immediate heartbeat upon daemon startup")


class NotificationConfig(BaseModel):
    """Root configuration schema for AgentGuard notifications."""
    model_config = ConfigDict(extra="ignore")

    enabled: bool = Field(default=False, description="Master toggle for all alerts")
    min_severity: str = Field(default="WARNING", description="Minimum severity threshold: INFO, WARNING, CRITICAL")
    discord: DiscordConfig = Field(default_factory=DiscordConfig)
    telegram: TelegramConfig = Field(default_factory=TelegramConfig)
    heartbeat: HeartbeatConfig = Field(default_factory=HeartbeatConfig)


# Backwards compatibility and naming alias
NotificationsConfig = NotificationConfig


def get_notifications_config_path() -> Path:
    """Returns resolved path to notifications.yaml honoring environment overrides."""
    override = os.environ.get("AGENTGUARD_NOTIFY_CONFIG") or os.environ.get("AGENTGUARD_NOTIFICATIONS_PATH")
    if override:
        return Path(override).expanduser().resolve()
    return DEFAULT_NOTIFICATIONS_PATH


def load_notification_config(config_path: Optional[Union[str, Path]] = None) -> NotificationConfig:
    """
    Loads NotificationConfig from YAML file.
    Enforces 0o600 permissions if file exists on POSIX.
    Returns default config if file does not exist.
    Raises ValueError if YAML is corrupted or not a dictionary.
    """
    target = Path(config_path).expanduser().resolve() if config_path else get_notifications_config_path()
    if not target.is_file():
        return NotificationConfig()

    # Permission check and enforcement on POSIX
    if os.name == "posix":
        try:
            mode = stat.S_IMODE(target.stat().st_mode)
            if mode & 0o077 != 0:
                target.chmod(0o600)
        except OSError:
            pass

    try:
        with open(target, "r", encoding="utf-8") as f:
            raw_data = yaml.safe_load(f)
    except Exception as exc:
        raise ValueError(f"Failed to parse notification config at '{target}': {exc}") from exc

    if raw_data is None:
        return NotificationConfig()

    if not isinstance(raw_data, dict):
        raise ValueError(f"Invalid notification config format at '{target}': expected mapping dictionary.")

    return NotificationConfig.model_validate(raw_data)


# Alias
load_notifications_config = load_notification_config


def save_notification_config(config: NotificationConfig, config_path: Optional[Union[str, Path]] = None) -> None:
    """
    Saves NotificationConfig to target path with strict 0o600 permissions.
    Uses atomic temporary file write, flush, fsync, and replace.
    """
    target = Path(config_path).expanduser().resolve() if config_path else get_notifications_config_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        try:
            target.parent.chmod(0o700)
        except OSError:
            pass

    dump_data = config.model_dump(mode="json")
    yaml_str = yaml.safe_dump(dump_data, default_flow_style=False, sort_keys=False)

    temp_path = target.with_suffix(f".tmp.{os.getpid()}.{os.urandom(4).hex()}")
    try:
        if os.name == "posix":
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
            fd = os.open(temp_path, flags, 0o600)
            with open(fd, "w", encoding="utf-8") as f:
                f.write(yaml_str)
                f.flush()
                os.fsync(fd)
            # Guarantee mode 0o600 even if umask modified it
            temp_path.chmod(0o600)
        else:
            with open(temp_path, "w", encoding="utf-8") as f:
                f.write(yaml_str)

        os.replace(temp_path, target)
        if os.name == "posix":
            try:
                target.chmod(0o600)
            except OSError:
                pass
    finally:
        if temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass


# Alias
save_notifications_config = save_notification_config
