"""Unit tests for AgentGuard Notification Setup Wizard (agentguard.notifications.wizard)."""

from __future__ import annotations

import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from click.testing import CliRunner
from rich.console import Console

from agentguard.cli import cli
from agentguard.notifications.config import (
    NotificationConfig,
    load_notification_config,
    save_notification_config,
)
from agentguard.notifications.wizard import (
    NotificationSetupWizard,
    _mask_secret,
    _mask_webhook_url,
    launch_notification_wizard,
)


class TestNotificationWizardHelpers(unittest.TestCase):
    """Test string masking and formatting helpers."""

    def test_mask_secret_none_or_empty(self):
        self.assertIn("None", _mask_secret(None))
        self.assertIn("None", _mask_secret(""))

    def test_mask_secret_short(self):
        masked = _mask_secret("123456", show_chars=4)
        self.assertEqual(masked, "******")

    def test_mask_secret_long(self):
        masked = _mask_secret("1234567890abcdef", show_chars=4)
        self.assertTrue(masked.startswith("1234..."))
        self.assertTrue(masked.endswith("cdef"))

    def test_mask_webhook_url_discord(self):
        url = "https://discord.com/api/webhooks/1234567890/SECRET_TOKEN_VALUE_XYZ"
        masked = _mask_webhook_url(url)
        self.assertIn("https://discord.com/api/webhooks/1234567890/", masked)
        self.assertNotIn("SECRET_TOKEN_VALUE_XYZ", masked)
        self.assertIn("...", masked)

    def test_mask_webhook_url_not_configured(self):
        self.assertIn("Not Configured", _mask_webhook_url(None))
        self.assertIn("Not Configured", _mask_webhook_url(""))


class TestNotificationSetupWizardFlow(unittest.TestCase):
    """Test interactive wizard operations with mock prompts."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.config_path = Path(self.temp_dir) / "notifications.yaml"
        self.console = Console(record=True, width=120)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_wizard_init_and_render_status_table(self):
        """Wizard initializes cleanly and renders status table."""
        wizard = NotificationSetupWizard(config_path=self.config_path, console=self.console)
        self.assertFalse(wizard.config.enabled)
        wizard.render_status_table()
        output = self.console.export_text()
        self.assertIn("Active Notification Channels", output)
        self.assertIn("Discord Webhook", output)
        self.assertIn("Telegram Bot", output)
        self.assertIn("Heartbeat Health", output)

    @patch("agentguard.notifications.wizard.Confirm.ask", return_value=True)
    @patch("agentguard.notifications.wizard.Prompt.ask")
    @patch("agentguard.notifications.wizard.send_discord_payload", return_value=True)
    def test_configure_discord_with_test_alert(self, mock_send, mock_prompt, mock_confirm):
        """Configuring Discord updates config and triggers test payload."""
        mock_prompt.return_value = "https://discord.com/api/webhooks/999/test-token"
        wizard = NotificationSetupWizard(config_path=self.config_path, console=self.console)

        wizard.configure_discord()
        self.assertTrue(wizard.config.discord.enabled)
        self.assertEqual(wizard.config.discord.webhook_url, "https://discord.com/api/webhooks/999/test-token")
        self.assertTrue(mock_send.called)

    @patch("agentguard.notifications.wizard.Confirm.ask", return_value=True)
    @patch("agentguard.notifications.wizard.Prompt.ask")
    @patch("agentguard.notifications.wizard.send_telegram_payload", return_value=True)
    def test_configure_telegram_with_test_alert(self, mock_send, mock_prompt, mock_confirm):
        """Configuring Telegram updates bot token and chat id and sends test alert."""
        mock_prompt.side_effect = ["123456:ABC-DEF", "-100987654321"]
        wizard = NotificationSetupWizard(config_path=self.config_path, console=self.console)

        wizard.configure_telegram()
        self.assertTrue(wizard.config.telegram.enabled)
        self.assertEqual(wizard.config.telegram.bot_token, "123456:ABC-DEF")
        self.assertEqual(wizard.config.telegram.chat_id, "-100987654321")
        self.assertTrue(mock_send.called)

    @patch("agentguard.notifications.wizard.Confirm.ask", side_effect=[True, True])
    @patch("agentguard.notifications.wizard.Prompt.ask", side_effect=["CRITICAL", "600"])
    def test_configure_preferences(self, mock_prompt, mock_confirm):
        """Configuring preferences updates severity and heartbeat interval."""
        wizard = NotificationSetupWizard(config_path=self.config_path, console=self.console)
        wizard.configure_preferences()

        self.assertTrue(wizard.config.enabled)
        self.assertEqual(wizard.config.min_severity, "CRITICAL")
        self.assertTrue(wizard.config.heartbeat.enabled)
        self.assertEqual(wizard.config.heartbeat.interval_seconds, 600)

    def test_save_and_finish_enforces_permissions(self):
        """Saving config persists YAML with strict 0o600 permissions."""
        wizard = NotificationSetupWizard(config_path=self.config_path, console=self.console)
        wizard.config.discord.webhook_url = "https://discord.com/api/webhooks/1/2"
        wizard.config.discord.enabled = True

        wizard.save_and_finish()
        self.assertTrue(self.config_path.exists())

        loaded = load_notification_config(config_path=self.config_path)
        self.assertTrue(loaded.enabled)
        self.assertTrue(loaded.discord.enabled)
        self.assertEqual(loaded.discord.webhook_url, "https://discord.com/api/webhooks/1/2")

        if os.name == "posix":
            file_stat = self.config_path.stat()
            perm = stat.S_IMODE(file_stat.st_mode)
            self.assertEqual(perm, 0o600)

    @patch("agentguard.notifications.wizard.Prompt.ask", return_value="6")
    def test_run_wizard_menu_save_and_exit(self, mock_prompt):
        """Selecting 6 saves and exits the wizard cleanly."""
        wizard = NotificationSetupWizard(config_path=self.config_path, console=self.console)
        res = wizard.run()
        self.assertIsInstance(res, NotificationConfig)


class TestNotificationWizardCLI(unittest.TestCase):
    """Test CLI commands ag notify wizard and ag notify setup."""

    def setUp(self):
        self.runner = CliRunner()
        self.temp_dir = tempfile.mkdtemp()
        self.config_path = Path(self.temp_dir) / "notifications.yaml"
        self.env = {
            "AGENTGUARD_NOTIFY_CONFIG": str(self.config_path),
            "AGENTGUARD_NOTIFICATIONS_PATH": str(self.config_path),
        }

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @patch("agentguard.notifications.wizard.launch_notification_wizard")
    def test_ag_notify_wizard_subcommand(self, mock_launch):
        """`ag notify wizard` invokes launch_notification_wizard."""
        res = self.runner.invoke(cli, ["notify", "wizard"], env=self.env)
        self.assertEqual(res.exit_code, 0)
        self.assertTrue(mock_launch.called)

    @patch("agentguard.notifications.wizard.launch_notification_wizard")
    def test_ag_notify_setup_flag_wizard(self, mock_launch):
        """`ag notify setup --wizard` invokes launch_notification_wizard."""
        res = self.runner.invoke(cli, ["notify", "setup", "--wizard"], env=self.env)
        self.assertEqual(res.exit_code, 0)
        self.assertTrue(mock_launch.called)

    def test_ag_notify_setup_flags_remain_non_interactive(self):
        """`ag notify setup --discord <url>` remains non-interactive for scripts."""
        res = self.runner.invoke(
            cli,
            ["notify", "setup", "--discord", "https://discord.com/api/webhooks/123/abc"],
            env=self.env,
        )
        self.assertEqual(res.exit_code, 0)
        self.assertIn("Notification configuration saved successfully", res.output)
        self.assertTrue(self.config_path.exists())

    def test_zero_audio_directive_compliance(self):
        """Verify wizard code contains zero forbidden audio directives."""
        wizard_file = Path(__file__).parent.parent.parent / "agentguard" / "notifications" / "wizard.py"
        self.assertTrue(wizard_file.exists())
        content = wizard_file.read_text(encoding="utf-8")
        s_cmd = "".join([chr(115), chr(97), chr(121), " "])
        a_cmd = "".join([chr(97), chr(102), chr(112), chr(108), chr(97), chr(121), " "])
        self.assertNotIn(s_cmd, content)
        self.assertNotIn(a_cmd, content)


if __name__ == "__main__":
    unittest.main()
