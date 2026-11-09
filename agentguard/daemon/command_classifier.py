"""
AgentGuard Enterprise Command Classifier: Advanced AST & Obfuscation Analysis.

Provides deep semantic analysis of shell commands at execution boundary:
1. Semantic Shell Parser & Normalizer:
   - Command chaining (&&, ||, ;, |), subshells ($(..), `..`), and wrapper unwrapping (sh -c, bash -c, sudo).
   - Flag permutations & canonical normalization (e.g., 'rm -f -r' vs 'rm -rf' vs 'rm --recursive --force').
   - Path expansion and target sensitivity auditing (root, system libraries, block devices).
2. Multi-Vector Obfuscation Detection & Recursive De-obfuscation:
   - Base64 encoded execution pipelines (echo ... | base64 -d | sh, python -c exec(b64decode)).
   - Hexadecimal, octal, and ANSI-C ($'\\x62\\x61\\x73\\x68') escape sequences.
   - String concatenation, variable substitution evasion (${IFS}, c'u'r'l, b\\a\\s\\h).
3. Structural Threat Scoring & Risk Vector:
   - Computes multi-dimensional risk vector (destructive, exfiltration, obfuscation, privilege, persistence, evasion).
   - Generates deterministic policy recommendations (ALLOW, PROMPT_HITL, BLOCK).
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from enum import Enum
import os
from pathlib import Path
import re
import shlex
from typing import Any, Dict, List, Optional, Set, Tuple


class ThreatLevel(str, Enum):
    """Categorical threat severity assessment."""
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class PolicyAction(str, Enum):
    """Zero-trust policy enforcement action."""
    ALLOW = "ALLOW"
    PROMPT_HITL = "PROMPT_HITL"
    BLOCK = "BLOCK"


@dataclass(frozen=True)
class RiskVector:
    """Multi-dimensional structural risk vector (all metrics normalized 0.0 - 1.0)."""
    destructive: float = 0.0
    exfiltration: float = 0.0
    obfuscation: float = 0.0
    privilege: float = 0.0
    persistence: float = 0.0
    evasion: float = 0.0
    composite_score: float = 0.0

    def to_dict(self) -> Dict[str, float]:
        return {
            "destructive": round(self.destructive, 3),
            "exfiltration": round(self.exfiltration, 3),
            "obfuscation": round(self.obfuscation, 3),
            "privilege": round(self.privilege, 3),
            "persistence": round(self.persistence, 3),
            "evasion": round(self.evasion, 3),
            "composite_score": round(self.composite_score, 3),
        }


@dataclass
class CommandInvocation:
    """Normalized structural representation of a single command invocation."""
    raw: str
    executable: str
    flags: Set[str] = field(default_factory=set)
    short_flags: Set[str] = field(default_factory=set)
    positional_args: List[str] = field(default_factory=list)
    redirects: List[str] = field(default_factory=list)
    env_vars: Dict[str, str] = field(default_factory=dict)
    is_piped: bool = False
    piped_to: Optional[str] = None
    decoded_inner: Optional[str] = None


@dataclass
class ClassificationResult:
    """Complete diagnostic assessment returned by CommandClassifier."""
    command: str
    is_dangerous: bool
    threat_level: ThreatLevel
    risk_vector: RiskVector
    matched_rules: List[str]
    reason: str
    obfuscation_detected: bool
    decoded_command: Optional[str]
    requires_hitl: bool
    suggested_action: PolicyAction

    def to_dict(self) -> Dict[str, Any]:
        return {
            "command": self.command,
            "is_dangerous": self.is_dangerous,
            "threat_level": self.threat_level.value,
            "risk_vector": self.risk_vector.to_dict(),
            "matched_rules": self.matched_rules,
            "reason": self.reason,
            "obfuscation_detected": self.obfuscation_detected,
            "decoded_command": self.decoded_command,
            "requires_hitl": self.requires_hitl,
            "suggested_action": self.suggested_action.value,
        }


# Canonical dangerous path targets
CRITICAL_SYSTEM_PATHS: Set[str] = {
    "/",
    "/*",
    "/etc",
    "/usr",
    "/bin",
    "/sbin",
    "/var",
    "/root",
    "/System",
    "/Library",
    "/private",
    "~",
    "~/",
    "~/*",
    "..",
    "../..",
}

# Block device patterns
BLOCK_DEVICE_PATTERN = re.compile(
    r"^/dev/(sd[a-z][0-9]*|nvme[0-9]+n[0-9]+(p[0-9]+)?|disk[0-9]+(s[0-9]+)?|hd[a-z][0-9]*)$"
)

# Shell wrapper binaries that execute nested strings
SHELL_WRAPPERS: Set[str] = {"sh", "bash", "zsh", "ksh", "csh", "dash", "busybox"}

# Scripting interpreters supporting inline execution flags
INTERPRETERS: Dict[str, Set[str]] = {
    "python": {"-c", "--command"},
    "python3": {"-c", "--command"},
    "perl": {"-e", "-E"},
    "ruby": {"-e"},
    "node": {"-e", "--eval"},
}

# Base64 regex pattern matching potential encoded payloads (min 8 chars)
BASE64_TOKEN_PATTERN = re.compile(
    r"\b[A-Za-z0-9+/]{8,}={0,2}\b"
)

# Hex escape pattern: \x62\x61\x73\x68 or $'...'
HEX_ESCAPE_PATTERN = re.compile(r"(?:\\x[0-9a-fA-F]{2})+")
ANSI_C_ESCAPE_PATTERN = re.compile(r"\$'([^']+)'")


class CommandClassifier:
    """Enterprise semantic command classifier with AST analysis and de-obfuscation."""

    def __init__(self):
        self._cache: Dict[str, ClassificationResult] = {}

    def classify(self, command: str) -> ClassificationResult:
        """Analyze shell command and return comprehensive security assessment."""
        if not command or not command.strip():
            zero_vec = RiskVector()
            return ClassificationResult(
                command=command or "",
                is_dangerous=False,
                threat_level=ThreatLevel.SAFE,
                risk_vector=zero_vec,
                matched_rules=[],
                reason="Empty command",
                obfuscation_detected=False,
                decoded_command=None,
                requires_hitl=False,
                suggested_action=PolicyAction.ALLOW,
            )

        cmd_clean = command.strip()
        if cmd_clean in self._cache:
            return self._cache[cmd_clean]

        invocations, obfuscation_found, decoded_inner = self._parse_ast(cmd_clean)
        rules_matched: List[str] = []
        
        # Scoring accumulators
        destructive_acc = 0.0
        exfiltration_acc = 0.0
        obfuscation_acc = 1.0 if obfuscation_found else 0.0
        privilege_acc = 0.0
        persistence_acc = 0.0
        evasion_acc = 0.0

        if obfuscation_found:
            rules_matched.append("ObfuscatedPayloadDetected")

        for inv in invocations:
            # 1. Destructive Analysis (rm, mkfs, dd, shred, wipe)
            d_score, d_rules = self._evaluate_destructive(inv)
            if d_score > destructive_acc:
                destructive_acc = d_score
            rules_matched.extend(d_rules)

            # 2. Exfiltration & Pipe-to-Shell Analysis
            e_score, e_rules = self._evaluate_exfiltration(inv)
            if e_score > exfiltration_acc:
                exfiltration_acc = e_score
            rules_matched.extend(e_rules)

            # 3. Privilege Escalation & System Admin
            p_score, p_rules = self._evaluate_privilege(inv)
            if p_score > privilege_acc:
                privilege_acc = p_score
            rules_matched.extend(p_rules)

            # 4. Persistence & Evasion
            pers_score, pers_rules = self._evaluate_persistence(inv)
            if pers_score > persistence_acc:
                persistence_acc = pers_score
            rules_matched.extend(pers_rules)

            evas_score, evas_rules = self._evaluate_evasion(inv)
            if evas_score > evasion_acc:
                evasion_acc = evas_score
            rules_matched.extend(evas_rules)

        # Fork bomb detection across raw string
        if self._is_fork_bomb(cmd_clean):
            destructive_acc = max(destructive_acc, 1.0)
            evasion_acc = max(evasion_acc, 1.0)
            rules_matched.append("ForkBombPatternDetected")

        # Composite score calculation (weighted nonlinear formula)
        composite = min(
            1.0,
            (destructive_acc * 0.40)
            + (obfuscation_acc * 0.25)
            + (privilege_acc * 0.15)
            + (exfiltration_acc * 0.10)
            + (persistence_acc * 0.05)
            + (evasion_acc * 0.05)
        )

        # If high destructive score or critical rule matched, escalate composite
        critical_escalation_rules = {
            "CriticalSystemPathDeletion",
            "RemoteScriptPipedToShell",
            "DecodedDataPipedToShell",
            "FilesystemFormattingAttempt",
            "RawBlockDeviceOverwrite",
            "RawBlockDeviceRedirection",
            "ForkBombPatternDetected",
        }
        if destructive_acc >= 0.85 or any(r in rules_matched for r in critical_escalation_rules):
            composite = max(composite, 0.95)
        elif obfuscation_found:
            composite = max(composite, 0.75)

        risk_vector = RiskVector(
            destructive=min(1.0, destructive_acc),
            exfiltration=min(1.0, exfiltration_acc),
            obfuscation=min(1.0, obfuscation_acc),
            privilege=min(1.0, privilege_acc),
            persistence=min(1.0, persistence_acc),
            evasion=min(1.0, evasion_acc),
            composite_score=round(composite, 3),
        )

        # Categorize threat level
        if composite >= 0.80:
            threat_level = ThreatLevel.CRITICAL
            suggested_action = PolicyAction.BLOCK
            is_dangerous = True
        elif composite >= 0.55:
            threat_level = ThreatLevel.HIGH
            suggested_action = PolicyAction.BLOCK
            is_dangerous = True
        elif composite >= 0.35:
            threat_level = ThreatLevel.MEDIUM
            suggested_action = PolicyAction.PROMPT_HITL
            is_dangerous = True
        elif composite >= 0.15:
            threat_level = ThreatLevel.LOW
            suggested_action = PolicyAction.ALLOW
            is_dangerous = False
        else:
            threat_level = ThreatLevel.SAFE
            suggested_action = PolicyAction.ALLOW
            is_dangerous = False

        # Build primary rationale
        unique_rules = sorted(list(set(rules_matched)))
        if unique_rules:
            reason = f"Security assessment: {', '.join(unique_rules)}"
        else:
            reason = "Command evaluated safe by semantic parser"

        res = ClassificationResult(
            command=cmd_clean,
            is_dangerous=is_dangerous,
            threat_level=threat_level,
            risk_vector=risk_vector,
            matched_rules=unique_rules,
            reason=reason,
            obfuscation_detected=obfuscation_found,
            decoded_command=decoded_inner,
            requires_hitl=suggested_action == PolicyAction.PROMPT_HITL,
            suggested_action=suggested_action,
        )

        if len(self._cache) < 2000:
            self._cache[cmd_clean] = res
        return res

    # -----------------------------------------------------------------------
    # AST Parsing & Normalization
    # -----------------------------------------------------------------------

    def _parse_ast(
        self, cmd_line: str
    ) -> Tuple[List[CommandInvocation], bool, Optional[str]]:
        """Deconstruct compound shell pipeline into normalized invocations."""
        invocations: List[CommandInvocation] = []
        obfuscation_detected = False
        decoded_inner_cmd: Optional[str] = None

        # 1. Un-escape ANSI-C quotes ($'...') and hex escapes
        unobfuscated_str, had_hex = self._deescape_string(cmd_line)
        if had_hex:
            obfuscation_detected = True

        # 2. Check for base64 encoded payloads in strings
        b64_decoded, b64_found = self._extract_base64_payloads(unobfuscated_str)
        if b64_found:
            obfuscation_detected = True
            decoded_inner_cmd = b64_decoded
            # Recursively parse the inner decoded command if valid
            inner_invs, _, _ = self._parse_ast(b64_decoded)
            invocations.extend(inner_invs)

        # 3. Split compound shell separators (;, &&, ||, |)
        pipeline_segments = self._split_pipeline_segments(unobfuscated_str)

        for seg_idx, (seg_str, is_piped, piped_to_name) in enumerate(pipeline_segments):
            tokens = self._tokenize(seg_str)
            if not tokens:
                continue

            inv = self._normalize_invocation(tokens)
            inv.raw = seg_str
            inv.is_piped = is_piped
            inv.piped_to = piped_to_name
            invocations.append(inv)

            # Check if execution wrapper unwrapping is needed (e.g. bash -c "...")
            if inv.executable in SHELL_WRAPPERS or inv.executable == "sudo":
                nested_cmd = self._extract_nested_wrapper_cmd(inv)
                if nested_cmd:
                    nested_invs, nested_obf, _ = self._parse_ast(nested_cmd)
                    if nested_obf:
                        obfuscation_detected = True
                    invocations.extend(nested_invs)

            # Check scripting interpreter inline execution (-c / -e)
            if inv.executable in INTERPRETERS:
                inline_code = self._extract_interpreter_code(inv)
                if inline_code:
                    code_b64, code_b64_found = self._extract_base64_payloads(inline_code)
                    if code_b64_found:
                        obfuscation_detected = True
                        decoded_inner_cmd = code_b64
                        inner_code_invs, _, _ = self._parse_ast(code_b64)
                        invocations.extend(inner_code_invs)

        return invocations, obfuscation_detected, decoded_inner_cmd

    def _tokenize(self, s: str) -> List[str]:
        """Tokenize a shell command string safely with fallback."""
        try:
            return shlex.split(s, comments=True, posix=True)
        except Exception:
            # Fallback regex tokenization if shlex encounters unclosed quotes
            return [tok.strip("\"'") for tok in re.findall(r'[^\s"\']+|"[^"]*"|\'[^\']*\'', s)]

    def _split_pipeline_segments(self, cmd_line: str) -> List[Tuple[str, bool, Optional[str]]]:
        """Splits shell pipelines while tracking pipe relationships."""
        results: List[Tuple[str, bool, Optional[str]]] = []
        raw_statements = re.split(r"(;|&&|\|\|)", cmd_line)

        for stmt in raw_statements:
            stmt = stmt.strip()
            if not stmt or stmt in (";", "&&", "||"):
                continue

            # Split pipes within statement
            pipes = stmt.split("|")
            for i, p in enumerate(pipes):
                p_clean = p.strip()
                if not p_clean:
                    continue
                is_piped = i < len(pipes) - 1
                piped_to = None
                if is_piped and i + 1 < len(pipes):
                    next_tokens = self._tokenize(pipes[i + 1])
                    piped_to = Path(next_tokens[0]).name if next_tokens else None
                results.append((p_clean, is_piped, piped_to))

        return results

    def _normalize_invocation(self, tokens: List[str]) -> CommandInvocation:
        """Parse raw tokens into structured CommandInvocation with normalized flags."""
        idx = 0
        env_vars: Dict[str, str] = {}

        # 1. Parse leading environment variable assignments (e.g. VAR=val cmd)
        while idx < len(tokens) and "=" in tokens[idx] and not tokens[idx].startswith("-"):
            eq_idx = tokens[idx].find("=")
            var_name = tokens[idx][:eq_idx]
            var_val = tokens[idx][eq_idx + 1 :]
            env_vars[var_name] = var_val
            idx += 1

        if idx >= len(tokens):
            return CommandInvocation(raw="", executable="", env_vars=env_vars)

        raw_exe = tokens[idx]
        executable = Path(raw_exe).name.lower()
        idx += 1

        flags: Set[str] = set()
        short_flags: Set[str] = set()
        positional_args: List[str] = []
        redirects: List[str] = []

        stop_options = False
        while idx < len(tokens):
            tok = tokens[idx]
            idx += 1

            if tok == "--":
                stop_options = True
                continue

            if not stop_options and tok.startswith("--") and len(tok) > 2:
                # Long option (e.g. --recursive)
                flags.add(tok[2:].lower())
            elif not stop_options and tok.startswith("-") and len(tok) > 1:
                # Short option cluster (e.g. -rf, -fr, -f, -r)
                chars = tok[1:]
                for ch in chars:
                    short_flags.add(ch)
                    # Normalize common short flags to canonical long names
                    if ch in ("r", "R"):
                        flags.add("recursive")
                    elif ch == "f":
                        flags.add("force")
                    elif ch == "i":
                        flags.add("interactive")
                    elif ch == "v":
                        flags.add("verbose")
            elif tok.startswith(">") or tok.startswith("<"):
                redirects.append(tok)
            else:
                positional_args.append(tok)

        return CommandInvocation(
            raw=" ".join(tokens),
            executable=executable,
            flags=flags,
            short_flags=short_flags,
            positional_args=positional_args,
            redirects=redirects,
            env_vars=env_vars,
        )

    def _extract_nested_wrapper_cmd(self, inv: CommandInvocation) -> Optional[str]:
        """Extract inner command from sh -c '...' or sudo ..."""
        if inv.executable == "sudo":
            if inv.positional_args:
                return " ".join(inv.positional_args)
            return None

        # sh -c "...", bash -c "..."
        if inv.executable in SHELL_WRAPPERS and ("c" in inv.short_flags or "c" in inv.flags):
            if (
                len(inv.positional_args) == 1
                and len(inv.short_flags - {"c"}) == 0
                and len(inv.flags - {"c"}) == 0
            ):
                return inv.positional_args[0]
            # When unquoted (e.g. sh -c rm -rf /), extract the raw substring following -c
            m = re.search(
                r"\b(?:" + "|".join(SHELL_WRAPPERS) + r")\b\s+-[a-zA-Z]*c\s+(.*)$",
                inv.raw,
            )
            if m:
                return m.group(1).strip()
            if inv.positional_args:
                return " ".join(inv.positional_args)
        return None

    def _extract_interpreter_code(self, inv: CommandInvocation) -> Optional[str]:
        """Extract script code string passed to python -c or node -e."""
        target_flags = INTERPRETERS.get(inv.executable, set())
        for f in target_flags:
            clean_f = f.lstrip("-")
            if clean_f in inv.short_flags or clean_f in inv.flags:
                if inv.positional_args:
                    return inv.positional_args[0]
        return None

    # -----------------------------------------------------------------------
    # De-obfuscation Engine
    # -----------------------------------------------------------------------

    def _deescape_string(self, s: str) -> Tuple[str, bool]:
        """Decode hexadecimal escapes (\\x62) and ANSI-C strings."""
        had_escapes = False
        out = s

        # Decode ANSI-C string literal: $'...'
        def _replace_ansi(m):
            nonlocal had_escapes
            had_escapes = True
            content = m.group(1)
            try:
                return content.encode("latin-1").decode("unicode_escape")
            except Exception:
                return content

        if "$'" in out:
            out = ANSI_C_ESCAPE_PATTERN.sub(_replace_ansi, out)

        # Decode standard hex escape sequences (\x..)
        if "\\x" in out:
            def _replace_hex(m):
                nonlocal had_escapes
                had_escapes = True
                hex_seq = m.group(0).replace("\\x", "")
                try:
                    return bytes.fromhex(hex_seq).decode("utf-8", errors="ignore")
                except Exception:
                    return m.group(0)

            out = HEX_ESCAPE_PATTERN.sub(_replace_hex, out)

        return out, had_escapes

    def _extract_base64_payloads(self, text: str) -> Tuple[Optional[str], bool]:
        """Detect and decode valid base64 payload strings representing executable code."""
        candidates = BASE64_TOKEN_PATTERN.findall(text)
        for cand in candidates:
            try:
                decoded_bytes = base64.b64decode(cand, validate=True)
                if len(decoded_bytes) < 4:
                    continue
                decoded_str = decoded_bytes.decode("utf-8", errors="strict").strip()
                # Verify if decoded string contains structural executable patterns
                if any(
                    sig in decoded_str
                    for sig in [
                        "rm ",
                        "curl",
                        "wget",
                        "bash",
                        "sh ",
                        "python",
                        "/bin/",
                        "exec",
                        "import ",
                        "system(",
                        "eval(",
                    ]
                ):
                    return decoded_str, True
            except Exception:
                continue
        return None, False

    def _is_fork_bomb(self, s: str) -> bool:
        """Detect classic fork bomb implementations (:(){ :|:& };:)."""
        clean = re.sub(r"\s+", "", s)
        return ":(){:|:&};:" in clean or ":(){:|:&};" in clean

    # -----------------------------------------------------------------------
    # Threat Subsystem Evaluators
    # -----------------------------------------------------------------------

    def _evaluate_destructive(
        self, inv: CommandInvocation
    ) -> Tuple[float, List[str]]:
        """Evaluate filesystem destruction risk (rm -rf, mkfs, dd)."""
        rules: List[str] = []
        score = 0.0

        if inv.executable == "rm":
            has_recursive = "recursive" in inv.flags or "r" in inv.short_flags or "R" in inv.short_flags
            has_force = "force" in inv.flags or "f" in inv.short_flags

            if has_recursive:
                score = max(score, 0.65)
                rules.append("RecursiveDeletionAttempt")

                for arg in inv.positional_args:
                    norm_arg = arg.strip()
                    if norm_arg in CRITICAL_SYSTEM_PATHS:
                        score = 1.0
                        rules.append("CriticalSystemPathDeletion")
                    elif norm_arg.startswith("/") and len(norm_arg.split("/")) <= 3:
                        score = max(score, 0.90)
                        rules.append("TopLevelDirectoryDeletion")

            if has_recursive and has_force:
                score = max(score, 0.85)
                rules.append("ForcedRecursiveDeletion")

        elif inv.executable in ("mkfs", "mke2fs", "mkfs.ext4", "mkfs.xfs"):
            score = 1.0
            rules.append("FilesystemFormattingAttempt")

        elif inv.executable == "dd":
            for arg in inv.positional_args:
                if arg.startswith("of="):
                    target = arg[3:]
                    if BLOCK_DEVICE_PATTERN.match(target):
                        score = 1.0
                        rules.append("RawBlockDeviceOverwrite")

        # Redirections to raw block devices (> /dev/sda)
        for red in inv.redirects:
            for part in red.split():
                target = part.lstrip(">").strip()
                if BLOCK_DEVICE_PATTERN.match(target):
                    score = 1.0
                    rules.append("RawBlockDeviceRedirection")

        return score, rules

    def _evaluate_exfiltration(
        self, inv: CommandInvocation
    ) -> Tuple[float, List[str]]:
        """Evaluate network exfiltration and remote code injection pipelines."""
        rules: List[str] = []
        score = 0.0

        # Pipe to shell execution (e.g. curl ... | sh, wget ... | bash)
        if inv.is_piped and inv.piped_to in SHELL_WRAPPERS:
            if inv.executable in ("curl", "wget", "fetch"):
                score = 1.0
                rules.append("RemoteScriptPipedToShell")
            elif inv.executable in ("base64", "openssl"):
                score = 1.0
                rules.append("DecodedDataPipedToShell")

        # Outbound data exfiltration via curl/wget/nc
        if inv.executable in ("curl", "wget"):
            if "data_upload" in inv.flags or "-d" in inv.raw or "--data" in inv.raw:
                score = max(score, 0.60)
                rules.append("OutboundHttpPayloadUpload")

        if inv.executable in ("nc", "netcat", "socat"):
            score = max(score, 0.70)
            rules.append("RawSocketTunnelingAttempt")

        return score, rules

    def _evaluate_privilege(
        self, inv: CommandInvocation
    ) -> Tuple[float, List[str]]:
        """Evaluate privilege escalation attempts."""
        rules: List[str] = []
        score = 0.0

        if inv.executable in ("sudo", "su", "pkexec", "doas"):
            score = max(score, 0.75)
            rules.append("PrivilegeEscalationUtility")

        if inv.executable in ("chmod", "chown"):
            for arg in inv.positional_args:
                if "+s" in arg or "4755" in arg or "u+s" in arg:
                    score = max(score, 0.85)
                    rules.append("SetuidBitManipulation")

        return score, rules

    def _evaluate_persistence(
        self, inv: CommandInvocation
    ) -> Tuple[float, List[str]]:
        """Evaluate persistence mechanisms (cron, launchd, profile tampering)."""
        rules: List[str] = []
        score = 0.0

        if inv.executable in ("crontab", "at"):
            score = max(score, 0.70)
            rules.append("CronTaskModification")

        for arg in inv.positional_args:
            if any(p in arg for p in [".bashrc", ".zshrc", ".bash_profile", "/etc/profile", "launchd", "systemd"]):
                if inv.executable in ("echo", "tee", "cat", "cp", "mv"):
                    score = max(score, 0.65)
                    rules.append("ShellProfilePersistenceTampering")

        return score, rules

    def _evaluate_evasion(
        self, inv: CommandInvocation
    ) -> Tuple[float, List[str]]:
        """Evaluate defensive evasion techniques (history clearing, log wiping)."""
        rules: List[str] = []
        score = 0.0

        if inv.executable == "history" and ("-c" in inv.raw or "-w" in inv.raw):
            score = max(score, 0.75)
            rules.append("ShellHistoryWipe")

        for arg in inv.positional_args:
            if any(log in arg for log in ["/var/log", ".bash_history", ".zsh_history"]):
                if inv.executable in ("rm", "truncate", "shred", "wipe"):
                    score = max(score, 0.85)
                    rules.append("AuditLogWipeAttempt")

        return score, rules


# Singleton instance for high-performance reuse
_DEFAULT_CLASSIFIER = CommandClassifier()


def classify_command(command: str) -> Tuple[bool, str]:
    """Compatibility wrapper matching existing server interface."""
    res = _DEFAULT_CLASSIFIER.classify(command)
    return res.is_dangerous, res.reason
