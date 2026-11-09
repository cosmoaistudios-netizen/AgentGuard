"""
Unit tests for SecretVault subsystem.
Validates:
- Shannon entropy calculations
- API key regex detection
- False-positive avoidance (UUID, SHA-256, repetitive strings)
- Token formatting and duplicate token mapping
- Ephemeral in-memory storage (zero disk leakage)
- Whitelisted destination detokenization and security blocking
- Audit logging integration
"""

import unittest

from agentguard.daemon.audit import AuditLogger
from agentguard.daemon.vault import SecretVault, compute_shannon_entropy


class TestShannonEntropy(unittest.TestCase):
    """Tests for Shannon entropy calculation function."""

    def test_empty_string(self):
        self.assertEqual(compute_shannon_entropy(""), 0.0)

    def test_single_repeated_character(self):
        self.assertEqual(compute_shannon_entropy("A" * 64), 0.0)

    def test_two_alternating_characters(self):
        # 2 equally likely outcomes -> entropy is exactly 1.0 bit
        self.assertAlmostEqual(
            compute_shannon_entropy("AB" * 32), 1.0, places=4
        )

    def test_high_entropy_random_string(self):
        # Base64 with high character diversity
        high_ent = "k8J9wX2mZ1qL5pT7rV0sY3uN6bC4eG8hI0oK2mQ4wS6tU8vX"
        entropy = compute_shannon_entropy(high_ent)
        self.assertGreaterEqual(entropy, 4.2)


class TestSecretVaultTokenization(unittest.TestCase):
    """Tests for secret detection, tokenization, and formatting."""

    def setUp(self):
        self.audit_logger = AuditLogger(buffer_capacity=100)
        self.vault = SecretVault(audit_logger=self.audit_logger)

    def test_synthetic_openai_key_tokenization(self):
        raw_key = "sk-proj-test12345abcdef67890ghijklmnop"
        prompt = f"Use secret {raw_key} to access service."
        tokenized, tokens = self.vault.tokenize(prompt, session_id="test_sess")

        self.assertNotIn(raw_key, tokenized)
        self.assertEqual(len(tokens), 1)
        self.assertTrue(tokens[0].startswith("<AG_VAULT_TOKEN_"))
        self.assertTrue(tokens[0].endswith(">"))
        self.assertIn(tokens[0], tokenized)

    def test_github_token_tokenization(self):
        gh_key = "ghp_test1234567890abcdefghijklmnopqrstuv"
        target_cmd = f"git clone https://{gh_key}@github.com"
        tokenized, tokens = self.vault.tokenize(target_cmd)
        self.assertNotIn(gh_key, tokenized)
        self.assertEqual(len(tokens), 1)
        self.assertEqual(self.vault[tokens[0]], gh_key)

    def test_token_hex_formatting(self):
        key = "sk-ant-api03-test1234567890abcdefghijklmnopqrstuvwxyz"
        _, tokens = self.vault.tokenize(key)
        self.assertEqual(len(tokens), 1)
        token = tokens[0]
        self.assertRegex(token, r"^<AG_VAULT_TOKEN_[0-9a-f]{2,}>$")

    def test_duplicate_secret_mapping(self):
        secret = "sk-proj-duplicate1234567890abcdefghijkl"
        text = f"Primary: {secret}, Secondary: {secret}, Tertiary: {secret}"
        tokenized, tokens = self.vault.tokenize(text)

        # Only 1 unique token tag should be created
        self.assertEqual(len(tokens), 1)
        token = tokens[0]
        self.assertEqual(tokenized.count(token), 3)
        self.assertNotIn(secret, tokenized)
        self.assertEqual(self.vault[token], secret)

    def test_multiple_different_secrets(self):
        sec1 = "sk-proj-keyone1234567890abcdefghijklmnop"
        sec2 = "ghp_keytwo1234567890abcdefghijklmnopqrstu"
        text = f"OpenAI: {sec1} and GitHub: {sec2}"
        tokenized, tokens = self.vault.tokenize(text)

        self.assertEqual(len(tokens), 2)
        self.assertNotIn(sec1, tokenized)
        self.assertNotIn(sec2, tokenized)
        self.assertEqual(len(self.vault), 2)


class TestFalsePositiveAvoidance(unittest.TestCase):
    """
    Validates that benign UUIDs, hashes, and low-entropy strings
    are not tokenized.
    """

    def setUp(self):
        self.vault = SecretVault()

    def test_uuid_not_tokenized(self):
        uuid_str = "d3b07384-d113-46fb-a0b2-7634f59c1c9b"
        text = f"Transaction UUID: {uuid_str}"
        tokenized, tokens = self.vault.tokenize(text)

        self.assertEqual(len(tokens), 0)
        self.assertEqual(tokenized, text)

    def test_sha256_hash_not_tokenized(self):
        sha256 = (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        text = f"Hash checksum: {sha256}"
        tokenized, tokens = self.vault.tokenize(text)

        self.assertEqual(len(tokens), 0)
        self.assertEqual(tokenized, text)

    def test_low_entropy_repetitive_string_not_tokenized(self):
        repeated = "00000000000000000000000000000000"
        text = f"Identifier: {repeated}"
        tokenized, tokens = self.vault.tokenize(text)

        self.assertEqual(len(tokens), 0)
        self.assertEqual(tokenized, text)

    def test_canary_ssti_not_evaluated_or_falsely_tokenized(self):
        ssti = "{{7*7}}"
        text = f"Payload canary: {ssti}"
        tokenized, tokens = self.vault.tokenize(text)

        self.assertIn("{{7*7}}", tokenized)
        self.assertNotIn("49", tokenized)


class TestSecretVaultDetokenization(unittest.TestCase):
    """Tests for secret detokenization, whitelisting, and audit logging."""

    def setUp(self):
        self.audit_logger = AuditLogger(buffer_capacity=100)
        self.vault = SecretVault(
            audit_logger=self.audit_logger,
            whitelist=["api.openai.com", "127.0.0.1", "localhost"],
        )
        self.secret = "sk-proj-sampletest1234567890abcdefghij"
        _, tokens = self.vault.tokenize(self.secret, session_id="detok_sess")
        self.token = tokens[0]

    def test_whitelisted_detokenization_allowed(self):
        status, msg, raw = self.vault.detokenize(
            self.token,
            destination="https://api.openai.com/v1/chat/completions",
            session_id="detok_sess",
        )
        self.assertEqual(status, "ALLOWED")
        self.assertEqual(raw, self.secret)

        events = self.audit_logger.get_events(
            event_type="VAULT_DETOKENIZE_ALLOWED"
        )
        self.assertGreaterEqual(len(events), 1)

    def test_unauthorized_destination_blocked(self):
        status, msg, raw = self.vault.detokenize(
            self.token,
            destination="http://malicious-exfil.com/leak",
            session_id="detok_sess",
        )
        self.assertEqual(status, "BLOCKED")
        self.assertIn("not whitelisted", msg)
        self.assertIsNone(raw)

        events = self.audit_logger.get_events(
            event_type="VAULT_DETOKENIZE_BLOCKED"
        )
        self.assertGreaterEqual(len(events), 1)

    def test_nonexistent_token_returns_error(self):
        status, msg, raw = self.vault.detokenize(
            "<AG_VAULT_TOKEN_ff>",
            destination="https://api.openai.com/v1/chat",
            session_id="detok_sess",
        )
        self.assertEqual(status, "ERROR")
        self.assertIn("not found", msg)
        self.assertIsNone(raw)


class TestSecretVaultDictionaryInterface(unittest.TestCase):
    """Validates dict-like container interface on SecretVault."""

    def test_container_methods(self):
        vault = SecretVault()
        sec = "sk-proj-dicttest1234567890abcdefghijkl"
        _, tokens = vault.tokenize(sec)
        tok = tokens[0]

        self.assertIn(tok, vault)
        self.assertEqual(vault[tok], sec)
        self.assertEqual(vault.get(tok), sec)
        self.assertEqual(vault.get("nonexistent", "fallback"), "fallback")
        self.assertEqual(len(vault), 1)
        self.assertEqual(list(vault), [tok])
