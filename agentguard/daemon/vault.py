r"""
AgentGuard Enterprise Secret Vault Subsystem: Zero-False-Positive Secret Guard.

Implements zero-leakage ephemeral tokenization:
1. Shannon Entropy Calculation:
   $H = -\sum p(x) \log_2(p(x))$ bits per character ($H \ge 4.2$).
2. Known API Key & Secret Patterns:
   High-precision regex heuristics for OpenAI, Anthropic, GitHub, AWS, Slack, and JWT tokens.
3. Strict Context-Window Verification:
   Examines a sliding context window (-60 to +40 chars) surrounding high-entropy candidates
   for secret-assignment tokens (e.g. `api_key=`, `secret=`, `token:`, `Bearer `, `Authorization:`)
   to prevent false-positive tokenization of ambient non-secret high-entropy tokens.
4. Token Structural Validation:
   Eliminates false positives on UUIDs, hex hashes (MD5, SHA-1/Git, SHA-256, SHA-512),
   low-diversity alphanumeric strings, and template expressions.
5. Ephemeral In-Memory Secret Storage (<AG_VAULT_TOKEN_xx>):
   Replaces detected secrets with synthetic tokens in RAM only (zero disk leakage).
6. Destination Whitelisting Enforcement:
   Detokenizes only for strictly authorized destinations (anti-domain-spoofing).
"""

from __future__ import annotations

import math
import re
import threading
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple
import urllib.parse

from agentguard.daemon.audit import AuditLogger

# Default whitelisted destinations for secret detokenization
DEFAULT_VAULT_WHITELIST = [
    "api.anthropic.com",
    "api.openai.com",
    "127.0.0.1",
    "localhost",
]

# Standard high-confidence API key and secret patterns
API_KEY_PATTERNS = [
    re.compile(r"\bsk-[a-zA-Z0-9_-]{20,}\b"),
    re.compile(r"\bgh[pousr]_[a-zA-Z0-9]{20,}\b"),
    re.compile(r"\bglpat-[a-zA-Z0-9_-]{20,}\b"),
    re.compile(r"\bsk-ant-[a-zA-Z0-9_-]{20,}\b"),
    re.compile(r"\bAG_TEST_KEY_[a-zA-Z0-9_]{10,}\b"),
    re.compile(r"\bxox[baprs]-[0-9a-zA-Z]{10,}\b"),
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"\bey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
]

# Structural False-Positive Patterns
UUID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
HEX_HASH_PATTERN = re.compile(r"^[0-9a-fA-F]{32,128}$")
DELIMITER_PATTERN = re.compile(r"[\s=:,;\"'<>()[\]{}@/?&\\|]+|//")

# Context-window secret signaling regex indicators
CONTEXT_SIGNAL_PATTERN = re.compile(
    r"(?i)\b("
    r"api[_-]?key|secret|token|auth|authorization|password|passwd|pwd|"
    r"bearer|access[_-]?token|private[_-]?key|secret[_-]?key|credential|"
    r"client[_-]?secret|signing[_-]?key|seed|passphrase"
    r")\b"
)
CONTEXT_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)(?:[:=]|->|Bearer\s+|--api-key\s+|--token\s+|--secret\s+)"
)


def compute_shannon_entropy(data: str) -> float:
    """
    Computes Shannon entropy (H in bits per character) for a given string.
    Formula: H = - sum(p(x) * log2(p(x)))
    """
    if not data:
        return 0.0
    length = len(data)
    counts: Dict[str, int] = {}
    for ch in data:
        counts[ch] = counts.get(ch, 0) + 1

    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def is_structurally_valid_secret(token: str) -> bool:
    """
    Validates candidate token structure to eliminate false positives
    on hashes, UUIDs, compiler IDs, and natural text.
    """
    if not token or len(token) < 20:
        return False

    # 1. UUID exclusion
    if UUID_PATTERN.match(token):
        return False

    # 2. Pure hexadecimal hash exclusion (MD5, Git SHA-1, SHA-256, SHA-512)
    # API keys and bearer tokens are not pure hex digests unless prefixed
    if HEX_HASH_PATTERN.match(token):
        return False

    # 3. Repetitive character strings (e.g. 00000000...)
    if token.startswith("0000") or len(set(token)) < 8:
        return False

    # 4. Character class diversity requirement
    # Secrets require variety across character categories (upper, lower, digits, symbols)
    classes = 0
    if re.search(r"[a-z]", token):
        classes += 1
    if re.search(r"[A-Z]", token):
        classes += 1
    if re.search(r"[0-9]", token):
        classes += 1
    if re.search(r"[-_+=/]", token):
        classes += 1

    if classes < 2:
        return False

    # 5. Natural language words and slugs with hyphens or underscores
    words = re.findall(r"[a-zA-Z]{4,}", token)
    if len(words) >= 3 and len("".join(words)) / len(token) > 0.70:
        return False

    return True


class SecretVault:
    """
    Enterprise-grade in-memory ephemeral vault protecting sensitive credentials.
    Replaces detected secrets with synthetic tokens (<AG_VAULT_TOKEN_xx>).
    """

    def __init__(
        self,
        audit_logger: Optional[AuditLogger] = None,
        whitelist: Optional[List[str]] = None,
        entropy_threshold: float = 4.2,
        min_entropy_len: int = 24,
    ):
        self.audit_logger = (
            audit_logger if audit_logger is not None else AuditLogger()
        )
        self.whitelist = list(whitelist or DEFAULT_VAULT_WHITELIST)
        self.entropy_threshold = entropy_threshold
        self.min_entropy_len = min_entropy_len
        self._lock = threading.RLock()

        # In-memory storage: token_tag -> raw_secret
        self._token_to_secret: Dict[str, str] = {}
        # Reverse mapping: raw_secret -> token_tag (for token reuse)
        self._secret_to_token: Dict[str, str] = {}
        self._vault_counter: int = 1

    @property
    def token_store(self) -> Dict[str, str]:
        """Provides direct read access to token-to-secret dictionary."""
        with self._lock:
            return dict(self._token_to_secret)

    def __getitem__(self, token: str) -> str:
        with self._lock:
            return self._token_to_secret[token]

    def __contains__(self, token: str) -> bool:
        with self._lock:
            return token in self._token_to_secret

    def __len__(self) -> int:
        with self._lock:
            return len(self._token_to_secret)

    def __iter__(self) -> Iterator[str]:
        with self._lock:
            return iter(list(self._token_to_secret.keys()))

    def get(self, token: str, default: Optional[str] = None) -> Optional[str]:
        with self._lock:
            return self._token_to_secret.get(token, default)

    def items(self):
        with self._lock:
            return list(self._token_to_secret.items())

    def _verify_context_window(self, text: str, token: str) -> bool:
        """
        Examines sliding context window around candidate token to verify
        secret assignment semantics (e.g. `api_key=`, `token:`, `Bearer `).
        """
        idx = 0
        while True:
            pos = text.find(token, idx)
            if pos == -1:
                break
            idx = pos + len(token)

            # Extract window (-60 to +40 characters around token)
            start_pos = max(0, pos - 60)
            end_pos = min(len(text), pos + len(token) + 40)
            window = text[start_pos:end_pos]

            # Check for credential keyword in window
            has_signal = bool(CONTEXT_SIGNAL_PATTERN.search(window))
            has_assignment = bool(CONTEXT_ASSIGNMENT_PATTERN.search(window))

            if has_signal and has_assignment:
                return True

        return False

    def find_secrets(self, text: str) -> List[str]:
        """
        Scans text for candidate secrets via regex patterns and Shannon entropy.
        Applies structural token validation and sliding context-window verification
        to achieve zero false positives on hashes, UUIDs, and ambient identifiers.
        """
        if not text:
            return []

        found_secrets: Set[str] = set()

        # 1. High-confidence regex pattern matching (API keys, tokens, service keys)
        for rx in API_KEY_PATTERNS:
            for match in rx.finditer(text):
                found_secrets.add(match.group(0))

        # 2. Shannon entropy detection on candidate delimiter tokens
        candidates = DELIMITER_PATTERN.split(text)
        for cand in candidates:
            clean_tok = re.sub(r"^[^a-zA-Z0-9]+|[^a-zA-Z0-9]+$", "", cand)
            if len(clean_tok) < self.min_entropy_len:
                continue

            # Skip if already detected via high-confidence pattern
            if clean_tok in found_secrets or any(sec in clean_tok for sec in found_secrets):
                continue

            # Token structural validation
            if not is_structurally_valid_secret(clean_tok):
                continue

            # Shannon entropy calculation
            ent = compute_shannon_entropy(clean_tok)
            if ent < self.entropy_threshold:
                continue

            # Strict context-window verification for candidates lacking explicit secret prefix
            if self._verify_context_window(text, clean_tok):
                found_secrets.add(clean_tok)

        # Sort descending by length to avoid partial-substring replacement collisions
        return sorted(found_secrets, key=len, reverse=True)

    def tokenize(
        self, text: str, session_id: str = "default"
    ) -> Tuple[str, List[str]]:
        """
        Tokenizes all detected secrets in text with <AG_VAULT_TOKEN_xx>.
        Returns (tokenized_text, list_of_unique_tokens_created_or_referenced).
        """
        if not text:
            return text, []

        secrets = self.find_secrets(text)
        if not secrets:
            return text, []

        with self._lock:
            tokenized_text = text
            tokens_affected: List[str] = []

            for sec in secrets:
                if sec in self._secret_to_token:
                    token_tag = self._secret_to_token[sec]
                else:
                    token_tag = f"<AG_VAULT_TOKEN_{self._vault_counter:02x}>"
                    self._vault_counter += 1
                    self._token_to_secret[token_tag] = sec
                    self._secret_to_token[sec] = token_tag

                    self.audit_logger.log(
                        "VAULT_TOKENIZE",
                        session_id=session_id,
                        status="ALLOWED",
                        details={
                            "token": token_tag,
                            "secret_len": len(sec),
                        },
                    )

                tokenized_text = tokenized_text.replace(sec, token_tag)
                if token_tag not in tokens_affected:
                    tokens_affected.append(token_tag)

            return tokenized_text, tokens_affected

    def is_destination_whitelisted(self, destination: str) -> bool:
        """
        Checks whether destination URL or domain is authorized for detokenization.
        Parses URL hostname strictly to prevent domain spoofing attacks.
        """
        if not destination or not destination.strip():
            return False
        dest_clean = destination.strip().lower()

        if "://" not in dest_clean:
            dest_clean = "https://" + dest_clean

        try:
            parsed = urllib.parse.urlsplit(dest_clean)
            hostname = parsed.hostname
        except Exception:
            return False

        if not hostname:
            return False

        for allowed in self.whitelist:
            allowed_clean = allowed.strip().lower()
            if hostname == allowed_clean:
                return True
            if hostname.endswith("." + allowed_clean):
                return True

        return False

    def detokenize(
        self,
        token: str,
        destination: str,
        session_id: str = "default",
    ) -> Tuple[str, str, Optional[str]]:
        """
        Detokenizes a vault token back into its raw secret if destination
        is strictly whitelisted.
        Returns: (status: str, message: str, raw_secret: Optional[str])
        """
        if not self.is_destination_whitelisted(destination):
            msg = (
                f"Destination '{destination}' is not whitelisted "
                "for secret re-injection"
            )
            self.audit_logger.log(
                "VAULT_DETOKENIZE_BLOCKED",
                session_id=session_id,
                status="BLOCKED",
                details={"token": token, "destination": destination},
            )
            return "BLOCKED", msg, None

        with self._lock:
            if token not in self._token_to_secret:
                msg = f"Token '{token}' not found in vault"
                return "ERROR", msg, None

            raw_secret = self._token_to_secret[token]
            self.audit_logger.log(
                "VAULT_DETOKENIZE_ALLOWED",
                session_id=session_id,
                status="ALLOWED",
                details={"token": token, "destination": destination},
            )
            return "ALLOWED", "Detokenization authorized", raw_secret
