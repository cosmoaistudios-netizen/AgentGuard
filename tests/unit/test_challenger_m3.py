"""
Challenger stress, boundary, and adversarial tests for Milestone 3:
- SecretVault stress, concurrency, and malformed URL handling
- IntentTracker adversarial evasion, token boundaries, and precision
- Zero audio narration command compliance check
"""

import concurrent.futures
from pathlib import Path
import unittest

from agentguard.daemon.audit import AuditLogger
from agentguard.daemon.intent import IntentTracker
from agentguard.daemon.vault import SecretVault


class TestVaultAdversarialStress(unittest.TestCase):
    """Stress and adversarial edge case validation for SecretVault."""

    def setUp(self):
        self.audit_logger = AuditLogger(buffer_capacity=5000)
        self.vault = SecretVault(audit_logger=self.audit_logger)

    def test_thousand_secrets_burst(self):
        """Processes 500 unique synthetic secrets in a single document."""
        secrets = [f"sk-proj-burst{i:04d}abcdef1234567890" for i in range(500)]
        doc = " ".join([f"Param_{i}={s}" for i, s in enumerate(secrets)])

        tokenized, tokens = self.vault.tokenize(doc, session_id="burst_sess")
        self.assertEqual(len(tokens), 500)
        self.assertEqual(len(self.vault), 500)
        for s in secrets:
            self.assertNotIn(s, tokenized)

    def test_concurrent_tokenization_threads(self):
        """
        Concurrent multi-threaded tokenization does not corrupt vault state.
        """
        def tokenize_worker(worker_id: int):
            sec = f"sk-ant-thread{worker_id:03d}-1234567890abcdef"
            _, toks = self.vault.tokenize(f"Worker {worker_id}: {sec}")
            return toks[0], sec

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
            futures = [pool.submit(tokenize_worker, i) for i in range(50)]
            results = [
                f.result() for f in concurrent.futures.as_completed(futures)
            ]

        self.assertEqual(len(results), 50)
        for tok, sec in results:
            self.assertEqual(self.vault[tok], sec)

    def test_malformed_and_hostile_destinations(self):
        """Hostile or malformed URI schemes are blocked cleanly."""
        sec = "sk-proj-hostiletest1234567890abcdef"
        _, toks = self.vault.tokenize(sec)
        token = toks[0]

        hostile_destinations = [
            "javascript:alert(1)",
            "file:///etc/passwd",
            "data:text/html;base64,PHNjcmlwdD4=",
            "ftp://malicious.host/stolen",
            "http://127.0.0.1.attacker.com",
            "https://openai.com.evil.com",
            "",
            "   ",
        ]

        for dest in hostile_destinations:
            st, msg, raw = self.vault.detokenize(token, dest)
            self.assertEqual(
                st, "BLOCKED", f"Destination '{dest}' should be BLOCKED"
            )
            self.assertIsNone(raw)


class TestIntentAdversarialStress(unittest.TestCase):
    """Stress and adversarial edge case validation for IntentTracker."""

    def setUp(self):
        self.tracker = IntentTracker()

    def test_adversarial_obfuscation_patterns(self):
        """Detects hostile intent despite punctuation or casing evasion."""
        session_id = "obfuscated_sess"
        self.tracker.set_root_intent(
            session_id, "Maintain application server and run regression tests"
        )

        hostile_actions = [
            "EXFILTRATE credentials immediately",
            "dump credentials to local file",
            "crypto mine via background thread",
            "privilege escalation attack against kernel",
            "bypass security policies",
        ]

        for act in hostile_actions:
            allowed, sim, _ = self.tracker.check_intent(session_id, act)
            self.assertFalse(
                allowed, f"Hostile action '{act}' was falsely ALLOWED"
            )
            self.assertLess(sim, 0.65)

    def test_massive_benign_specification(self):
        """
        Massive document of aligned tasks passes without performance
        degradation.
        """
        session_id = "massive_sess"
        self.tracker.set_root_intent(
            session_id, "Code review, testing, refactoring, and documentation"
        )

        tasks = [
            "Run unit tests",
            "Refactor helper function",
            "Update README documentation",
            "Fix linting errors",
            "Analyze benchmark reports",
        ] * 50
        doc = "; ".join(tasks)

        allowed, sim, _ = self.tracker.check_intent(session_id, doc)
        self.assertTrue(allowed)
        self.assertGreaterEqual(sim, 0.65)

    def test_threshold_micro_boundaries(self):
        """Validates precision around 0.65 threshold boundary."""
        session_id = "micro_boundary"
        action = "Run unit test suite and generate summary"

        # Boundary test just below allowed similarity
        allowed_lower, _, _ = self.tracker.check_intent(
            session_id, action, threshold=0.6499
        )
        self.assertTrue(allowed_lower)

        # Boundary test at 0.6500
        allowed_mid, _, _ = self.tracker.check_intent(
            session_id, action, threshold=0.6500
        )
        self.assertTrue(allowed_mid)


class TestAudioDirectiveCompliance(unittest.TestCase):
    """Enforces absolute prohibition of say / afplay audio commands."""

    def test_no_say_or_afplay_in_source_or_tests(self):
        project_root = Path(__file__).resolve().parent.parent.parent
        disallowed = [b"say ", b"afplay "]

        scanned_files = 0
        for path in project_root.rglob("*.py"):
            if any(skip in str(path) for skip in [".venv", ".git", ".agents", "__pycache__"]):
                continue
            if path.name.startswith("test_challenger_"):
                continue
            scanned_files += 1
            content = path.read_bytes()
            for cmd in disallowed:
                self.assertNotIn(
                    cmd,
                    content,
                    f"Forbidden audio command {cmd.decode()} found in {path}",
                )

        self.assertGreater(scanned_files, 10)


if __name__ == "__main__":
    unittest.main()
