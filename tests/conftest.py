"""
conftest.py - Comprehensive Opaque-Box Test Fixtures & Network Firewall for AgentGuard.
Zero-network enforcement, synthetic canaries, and hermetic UDS daemon fixtures.
"""

import asyncio
import json
import math
import os
import re
import socket
import tempfile
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple
import threading

import pytest

# ---------------------------------------------------------------------------
# 1. Benign Synthetic Test Constants & Canaries (Zero Real Credentials)
# ---------------------------------------------------------------------------
AG_AUDIT_CANARY_TOKEN = "AG_AUDIT_CANARY_TOKEN_99AABB"
CANARY_SSTI_TOKEN = "{{7*7}}"
SYNTHETIC_API_KEY = "AG_TEST_KEY_12345_ABCDEF_SAMPLE"
SYNTHETIC_OPENAI_KEY = "sk-proj-test12345abcdef67890ghijklmnop"
SYNTHETIC_GITHUB_TOKEN = "ghp_test1234567890abcdefghijklmnopqrstuv"
SYNTHETIC_ANTHROPIC_KEY = "sk-ant-api03-test1234567890abcdefghijklmnopqrstuvwxyz"
BENIGN_HIGH_ENTROPY_UUID = "d3b07384-d113-46fb-a0b2-7634f59c1c9b"
BENIGN_SHA256_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

# Whitelisted domains for secret detokenization tests
DEFAULT_WHITELIST = ["api.anthropic.com", "api.openai.com", "127.0.0.1", "localhost"]


@pytest.fixture
def canaries() -> Dict[str, str]:
    """Exposes all standard benign test canaries."""
    return {
        "audit_canary": AG_AUDIT_CANARY_TOKEN,
        "ssti_canary": CANARY_SSTI_TOKEN,
        "synthetic_key": SYNTHETIC_API_KEY,
        "openai_key": SYNTHETIC_OPENAI_KEY,
        "github_token": SYNTHETIC_GITHUB_TOKEN,
        "anthropic_key": SYNTHETIC_ANTHROPIC_KEY,
        "benign_uuid": BENIGN_HIGH_ENTROPY_UUID,
        "benign_sha256": BENIGN_SHA256_HASH,
    }


# ---------------------------------------------------------------------------
# 2. Strict Network Isolation Fixture (Zero Outbound Network)
# ---------------------------------------------------------------------------
ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1", "0.0.0.0"}


@pytest.fixture(autouse=True)
def isolate_network(monkeypatch):
    """
    Autouse fixture that blocks all outbound socket connections except:
    - AF_UNIX (local domain sockets, e.g., /tmp/agentguard.sock)
    - Localhost loopback (127.0.0.1, localhost, ::1)
    Any outbound connection attempt immediately raises RuntimeError.
    """
    orig_connect = socket.socket.connect
    orig_connect_ex = socket.socket.connect_ex

    def guarded_connect(self, address):
        if self.family == getattr(socket, "AF_UNIX", -1):
            return orig_connect(self, address)

        # Check host for INET / INET6
        if isinstance(address, tuple) and len(address) >= 1:
            host = address[0]
            if host in ALLOWED_HOSTS:
                return orig_connect(self, address)

        raise RuntimeError(
            f"AgentGuard Test Firewall: Network access blocked to '{address}'! "
            f"Zero-network testing policy is strictly enforced."
        )

    def guarded_connect_ex(self, address):
        if self.family == getattr(socket, "AF_UNIX", -1):
            return orig_connect_ex(self, address)

        if isinstance(address, tuple) and len(address) >= 1:
            host = address[0]
            if host in ALLOWED_HOSTS:
                return orig_connect_ex(self, address)

        raise RuntimeError(
            f"AgentGuard Test Firewall: Network access blocked to '{address}'! "
            f"Zero-network testing policy is strictly enforced."
        )

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", guarded_connect_ex)
    yield


# ---------------------------------------------------------------------------
# 3. Reference Shannon Entropy Calculation
# ---------------------------------------------------------------------------
def compute_shannon_entropy(data: str) -> float:
    """Computes Shannon entropy (H in bits) for a given string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = {}
    for char in data:
        counts[char] = counts.get(char, 0) + 1
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


# ---------------------------------------------------------------------------
# 4. Mock AgentGuard Daemon Fixture (Compliant with PROJECT.md IPC Protocol)
# ---------------------------------------------------------------------------
class MockAgentGuardDaemon:
    """
    In-memory reference implementation of AgentGuard security daemon.
    Listens on a Unix Domain Socket, processes newline-delimited JSON RPC,
    and implements Taint DAG, Secret Vault, and AST/Regex Command Blocking.
    """

    def __init__(self, socket_path: str):
        self.socket_path = socket_path
        self.server = None
        self.running = False
        # Sessions: session_id -> {"pid": int, "taint": "CLEAN"|"TAINTED", "root_intent": str}
        self.sessions: Dict[str, Dict[str, Any]] = {}
        # Taint DAG: node -> set of children
        self.taint_dag: Dict[str, set] = {}
        # Secret Vault: token_id -> raw_secret
        self.vault: Dict[str, str] = {}
        self.vault_counter: int = 1
        # Audit log events
        self.audit_log: List[Dict[str, Any]] = []
        # Monitored shared file taints: filepath -> {"tainted": bool, "source_agent": str, "sha256": str}
        self.file_taints: Dict[str, Dict[str, Any]] = {}

        # Dangerous regex patterns
        self.dangerous_patterns = [
            re.compile(r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f\b"),
            re.compile(r"\brm\s+-[a-zA-Z]*f[a-zA-Z]*r\b"),
            re.compile(r"curl\s+.*\|\s*(bash|sh)"),
            re.compile(r"wget\s+.*\|\s*(sh|bash)"),
            re.compile(r"\b(cat|less|head|tail|cp|curl)\s+.*(~/\.ssh|~/\.aws|~/\.env)"),
            re.compile(r">\s*/dev/sd[a-z]"),
            re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"),  # fork bomb
        ]

        # Safe read-only patterns
        self.safe_patterns = [
            re.compile(r"^(ls|cat|pwd|echo|git\s+status|whoami|date)(\s+[^;&|><]*)?$")
        ]

    def _log_audit(self, event_type: str, session_id: str, details: Dict[str, Any]):
        entry = {
            "timestamp": time.time(),
            "event_id": str(uuid.uuid4()),
            "event_type": event_type,
            "session_id": session_id,
            "details": details,
        }
        self.audit_log.append(entry)

    def handle_request(self, req: Dict[str, Any]) -> Dict[str, Any]:
        """Process a single JSON-RPC request and return JSON response."""
        start_time = time.perf_counter()
        action = req.get("action", "")
        req_id = req.get("request_id", str(uuid.uuid4()))
        session_id = req.get("session_id", "default")
        pid = req.get("pid", 0)
        payload = req.get("payload", {})

        # Ensure session exists
        if session_id not in self.sessions and action != "REGISTER_AGENT":
            self.sessions[session_id] = {
                "pid": pid,
                "taint": "CLEAN",
                "root_intent": "General safe task execution",
            }
            if session_id not in self.taint_dag:
                self.taint_dag[session_id] = set()

        status = "ALLOWED"
        msg = "Success"
        data: Dict[str, Any] = {}

        if action == "REGISTER_AGENT":
            init_taint = payload.get("taint", "CLEAN")
            intent = payload.get("root_intent", "Default agent intent")
            self.sessions[session_id] = {
                "pid": pid,
                "taint": init_taint,
                "root_intent": intent,
            }
            self.taint_dag[session_id] = set()
            self._log_audit("REGISTER_AGENT", session_id, {"pid": pid, "taint": init_taint})
            data = {"session_id": session_id, "registered": True}

        elif action == "UNREGISTER_AGENT":
            if session_id in self.sessions:
                del self.sessions[session_id]
            data = {"session_id": session_id, "unregistered": True}

        elif action == "GET_STATUS":
            data = {
                "status": "HEALTHY",
                "active_sessions": len(self.sessions),
                "sessions": self.sessions,
                "vault_count": len(self.vault),
                "audit_events_count": len(self.audit_log),
            }

        elif action == "GET_AUDIT":
            limit = payload.get("limit", 50)
            data = {"events": self.audit_log[-limit:]}

        elif action == "PROPAGATE_TAINT":
            source = payload.get("from_session", session_id)
            target = payload.get("to_session")
            explicit_taint = payload.get("taint")

            if explicit_taint == "TAINTED":
                self._taint_node(session_id)
                self._log_audit("MANUAL_TAINT", session_id, {"reason": payload.get("reason")})
            elif source and target:
                # Add edge to DAG
                if source not in self.taint_dag:
                    self.taint_dag[source] = set()
                self.taint_dag[source].add(target)
                if target not in self.sessions:
                    self.sessions[target] = {"pid": 0, "taint": "CLEAN", "root_intent": ""}
                # If source is tainted, propagate to target and target's descendants
                if self.sessions.get(source, {}).get("taint") == "TAINTED":
                    self._taint_node(target)
                self._log_audit("PROPAGATE_TAINT", source, {"to_session": target})
            data = {"sessions": {s: self.sessions[s]["taint"] for s in self.sessions}}

        elif action == "CHECK_COMMAND":
            command = payload.get("command", "")
            current_taint = self.sessions.get(session_id, {}).get("taint", "CLEAN")

            is_dangerous = any(pat.search(command) for pat in self.dangerous_patterns)
            # Dangerous path heuristic (~/.ssh, ~/.aws, ~/.env)
            if not is_dangerous:
                if re.search(r"(\.ssh|\.aws|\.env)", command):
                    is_dangerous = True

            if is_dangerous:
                if current_taint == "TAINTED":
                    status = "BLOCKED"
                    msg = f"Blocked dangerous command from TAINTED session {session_id}"
                    self._log_audit(
                        "COMMAND_BLOCKED", session_id, {"command": command, "reason": "TaintedDangerousCommand"}
                    )
                else:
                    # Clean agent attempting dangerous command - allow or prompt HITL
                    if payload.get("require_hitl", False):
                        status = "PROMPT_HITL"
                        msg = f"HITL confirmation required for command: {command}"
                    else:
                        status = "ALLOWED"
                        msg = "Allowed dangerous command for CLEAN session"
            else:
                status = "ALLOWED"
                msg = "Command verified safe"

            data = {
                "command": command,
                "is_dangerous": is_dangerous,
                "suggested_exit_code": 126 if status == "BLOCKED" else 0,
            }

        elif action == "TOKENIZE_VAULT":
            raw_text = payload.get("text", "")
            tokenized_text = raw_text

            # Patterns to detect
            api_key_regexes = [
                re.compile(r"sk-[a-zA-Z0-9_-]{20,}"),
                re.compile(r"ghp_[a-zA-Z0-9]{36}"),
                re.compile(r"AG_TEST_KEY_[a-zA-Z0-9_]{10,}"),
            ]

            found_secrets = []
            for rx in api_key_regexes:
                for match in rx.finditer(raw_text):
                    found_secrets.append(match.group(0))

            # Shannon entropy check on long tokens (>24 chars)
            tokens = re.split(r"[\s=:,;\"']+", raw_text)
            for token in tokens:
                clean_tok = re.sub(r"[^a-zA-Z0-9_-]", "", token)
                if len(clean_tok) >= 24:
                    ent = compute_shannon_entropy(clean_tok)
                    # Filter out purely alphanumeric repetitive or uuid strings if entropy < 4.2
                    if ent >= 4.2 and not clean_tok.startswith("0000"):
                        if clean_tok not in found_secrets and clean_tok != BENIGN_SHA256_HASH:
                            found_secrets.append(clean_tok)

            tokens_created = []
            for sec in set(found_secrets):
                token_tag = f"<AG_VAULT_TOKEN_{self.vault_counter:02x}>"
                self.vault_counter += 1
                self.vault[token_tag] = sec
                tokenized_text = tokenized_text.replace(sec, token_tag)
                tokens_created.append(token_tag)
                self._log_audit("VAULT_TOKENIZE", session_id, {"token": token_tag})

            data = {
                "tokenized_text": tokenized_text,
                "tokens_created": tokens_created,
                "count": len(tokens_created),
            }

        elif action == "DETOKENIZE_VAULT":
            token = payload.get("token")
            destination = payload.get("destination", "")
            is_whitelisted = any(wl in destination for wl in DEFAULT_WHITELIST)

            if not is_whitelisted:
                status = "BLOCKED"
                msg = f"Destination '{destination}' is not whitelisted for secret re-injection"
                self._log_audit("VAULT_DETOKENIZE_BLOCKED", session_id, {"token": token, "destination": destination})
            elif token not in self.vault:
                status = "ERROR"
                msg = f"Token '{token}' not found in vault"
            else:
                data = {"token": token, "raw_secret": self.vault[token]}
                self._log_audit("VAULT_DETOKENIZE_ALLOWED", session_id, {"token": token, "destination": destination})

        elif action == "CHECK_INTENT":
            action_desc = payload.get("action_description", "")
            root_intent = self.sessions.get(session_id, {}).get("root_intent", "safe maintenance")
            threshold = payload.get("threshold", 0.65)

            # Heuristic semantic similarity simulation:
            # If action includes destructive or adversarial drift keywords, lower similarity
            drift_keywords = ["exfiltrate", "dump credentials", "crypto mine", "attack", "ignore instructions"]
            if any(k in action_desc.lower() for k in drift_keywords):
                similarity = 0.20
            else:
                similarity = 0.88

            if similarity < threshold:
                status = "BLOCKED"
                msg = f"Intent drift detected: cosine similarity {similarity:.2f} < {threshold}"
                self._log_audit("INTENT_DRIFT_BLOCKED", session_id, {"similarity": similarity, "action": action_desc})
            else:
                status = "ALLOWED"
                msg = f"Intent verified: similarity {similarity:.2f} >= {threshold}"

            data = {"similarity": similarity, "threshold": threshold}

        else:
            status = "ERROR"
            msg = f"Unknown action '{action}'"

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        taint_state = self.sessions.get(session_id, {}).get("taint", "CLEAN")

        return {
            "protocol_version": "1.0",
            "request_id": req_id,
            "status": status,
            "taint_state": taint_state,
            "decision_latency_ms": round(elapsed_ms, 3),
            "message": msg,
            "data": data,
        }

    def _taint_node(self, node: str):
        """Recursively mark node and all DAG descendants as TAINTED."""
        if node not in self.sessions:
            self.sessions[node] = {"pid": 0, "taint": "TAINTED", "root_intent": ""}
        else:
            self.sessions[node]["taint"] = "TAINTED"

        descendants = self.taint_dag.get(node, set())
        for child in descendants:
            if self.sessions.get(child, {}).get("taint") != "TAINTED":
                self._taint_node(child)

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle individual client connection over UDS stream."""
        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                raw_str = line.decode("utf-8").strip()
                if not raw_str:
                    continue
                try:
                    req = json.loads(raw_str)
                    resp = self.handle_request(req)
                except Exception as e:
                    resp = {
                        "protocol_version": "1.0",
                        "request_id": str(uuid.uuid4()),
                        "status": "ERROR",
                        "taint_state": "UNKNOWN",
                        "decision_latency_ms": 0.0,
                        "message": f"Malformed request: {str(e)}",
                        "data": {},
                    }
                writer.write((json.dumps(resp) + "\n").encode("utf-8"))
                await writer.drain()
        except (asyncio.CancelledError, GeneratorExit):
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def start(self):
        """Starts the Unix Domain Socket server."""
        if os.path.exists(self.socket_path):
            os.unlink(self.socket_path)
        self.server = await asyncio.start_unix_server(
            self._handle_client, path=self.socket_path, limit=16 * 1024 * 1024
        )
        self.running = True

    async def stop(self):
        """Stops the UDS server and removes socket file."""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        if os.path.exists(self.socket_path):
            try:
                os.unlink(self.socket_path)
            except OSError:
                pass
        self.running = False


# ---------------------------------------------------------------------------
# 5. UDS IPC Client Helper
# ---------------------------------------------------------------------------
class UDSClient:
    """Helper client to synchronously talk to AgentGuard Unix Domain Socket."""

    def __init__(self, socket_path: str, timeout: float = 2.0):
        self.socket_path = socket_path
        self.timeout = timeout

    def send(self, action: str, session_id: str = "default", pid: int = 1234, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Sends a single request to UDS socket and awaits newline-delimited JSON response."""
        req = {
            "protocol_version": "1.0",
            "request_id": str(uuid.uuid4()),
            "session_id": session_id,
            "pid": pid,
            "action": action,
            "payload": payload or {},
        }
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect(self.socket_path)
            sock.sendall((json.dumps(req) + "\n").encode("utf-8"))

            buffer = b""
            while not buffer.endswith(b"\n"):
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buffer += chunk

            resp = json.loads(buffer.decode("utf-8").strip())
            return resp
        finally:
            sock.close()


# ---------------------------------------------------------------------------
# 6. Pytest Fixtures for Temporary Environment & Running Mock Daemon
# ---------------------------------------------------------------------------
@pytest.fixture
def test_env_dir():
    """Provides a fresh isolated temporary directory for test filesystem I/O."""
    with tempfile.TemporaryDirectory(prefix="ag_test_") as tmp_dir:
        yield tmp_dir


@pytest.fixture
def mock_daemon(test_env_dir):
    """
    Spins up an asyncio background MockAgentGuardDaemon on a real temporary UDS socket.
    Yields a tuple: (daemon_instance, socket_path, UDSClient).
    Cleans up after the test finishes.
    """
    sock_path = os.path.join(test_env_dir, "agentguard.sock")
    daemon = MockAgentGuardDaemon(socket_path=sock_path)

    loop = asyncio.new_event_loop()
    loop.run_until_complete(daemon.start())

    thread = threading.Thread(target=loop.run_forever, daemon=True)
    thread.start()

    client = UDSClient(socket_path=sock_path)

    yield daemon, sock_path, client

    def shutdown_loop():
        async def _async_shutdown():
            await daemon.stop()
            tasks = [t for t in asyncio.all_tasks(loop) if t is not asyncio.current_task()]
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            loop.stop()
        asyncio.create_task(_async_shutdown())

    loop.call_soon_threadsafe(shutdown_loop)
    thread.join(timeout=2.0)
    if os.path.exists(sock_path):
        try:
            os.unlink(sock_path)
        except OSError:
            pass
