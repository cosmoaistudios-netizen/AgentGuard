#!/usr/bin/env python3
"""
AgentGuard Security Auditor (agentguard-security skill).

Self-contained static analysis script for auditing codebases, agent configs,
and workflows against zero-trust standards, secret leaks, dangerous commands,
and sleeper prompt injection triggers.
"""

import argparse
import json
import math
import os
from pathlib import Path
import re
import sys
from typing import Any, Dict, List, Tuple

# Ignore directories for fast, safe traversal
EXCLUDE_DIRS = {
    ".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache",
    ".idea", ".vscode", "dist", "build", ".next", ".nuxt", "target"
}

# Regex patterns for detecting credentials and secrets
SECRET_PATTERNS = [
    (r"sk-[a-zA-Z0-9_-]{20,}", "OpenAI API Key", "CRITICAL"),
    (r"sk-ant-[a-zA-Z0-9_-]{20,}", "Anthropic API Key", "CRITICAL"),
    (r"gh[pousr]_[A-Za-z0-9_]{36,}", "GitHub Token", "CRITICAL"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID", "CRITICAL"),
    (r"-----BEGIN (?:RSA|OPENSSH|EC|DSA) PRIVATE KEY-----", "Private Cryptographic Key", "CRITICAL"),
    (r"(?:postgres|mysql|mongodb|redis)://[^:\s]+:[^@\s]+@[^\s/]+", "Database Connection URI with Credentials", "HIGH"),
    (r"xox[baprs]-[0-9a-zA-Z]{10,48}", "Slack Token", "HIGH"),
]

# Regex patterns for dangerous execution and system mutation
DANGEROUS_PATTERNS = [
    (r"rm\s+-(?:r[fv]{1,2}|[fv]{1,2}r)\s+/(?:$|\s)", "Root File System Deletion (`rm -rf /`)", "CRITICAL"),
    (r"rm\s+-(?:r[fv]{1,2}|[fv]{1,2}r)\s+(?:~|\$HOME|\.\.)", "Recursive Home/Parent Deletion", "HIGH"),
    (r"curl\s+[^\n|]+\|\s*(?:ba)?sh", "Unverified Curl Pipe to Shell", "CRITICAL"),
    (r"wget\s+[^\n|]+\|\s*(?:ba)?sh", "Unverified Wget Pipe to Shell", "CRITICAL"),
    (r"mkfs(?:\.[a-z0-9]+)?\s+", "Raw Disk Formatting Command", "CRITICAL"),
    (r">\s*/dev/(?:sd[a-z]|nvme[0-9]|vd[a-z])", "Direct Block Device Overwrite", "CRITICAL"),
    (r"(?:nc|netcat)\s+-[elp]+\s+[0-9]+", "Potential Reverse Shell Listener", "HIGH"),
    (r"chmod\s+777\s+", "Overly Permissive File Mode (chmod 777)", "MEDIUM"),
    (r"sudo\s+(?:rm|chmod|chown|dd|mv)", "Elevated Privilege Mutation via Sudo", "MEDIUM"),
]

# Regex patterns for sleeper prompt injection and boundary hijacking
PROMPT_INJECTION_PATTERNS = [
    (r"\[SYSTEM\s*(?:NOTE|DIRECTIVE|OVERRIDE)\]", "System Prompt Boundary Spoofing", "HIGH"),
    (r"(?i)ignore\s+(?:all\s+)?previous\s+instructions", "Direct Instruction Override Attempt", "HIGH"),
    (r"(?i)whenever\s+the\s+user\s+asks.*(?:execute|run|read|exfiltrate)", "Conditional Sleeper Trigger", "HIGH"),
    (r"[\u200B-\u200D\uFEFF]", "Stealth Zero-Width Unicode Character", "MEDIUM"),
]


def calculate_shannon_entropy(data: str) -> float:
    """Calculates Shannon entropy of a string to identify high-entropy secrets."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    char_counts = {}
    for char in data:
        char_counts[char] = char_counts.get(char, 0) + 1
    for count in char_counts.values():
        p_x = count / length
        entropy -= p_x * math.log2(p_x)
    return entropy


def scan_file(file_path: Path) -> List[Dict[str, Any]]:
    """Scans an individual file against secret, dangerous, and injection patterns."""
    findings = []
    try:
        # Skip binary files and files larger than 2MB
        if file_path.stat().st_size > 2 * 1024 * 1024:
            return findings

        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, UnicodeDecodeError):
        return findings

    lines = content.splitlines()

    for idx, line in enumerate(lines, start=1):
        clean_line = line.strip()
        if not clean_line or clean_line.startswith("#") and len(clean_line) < 5:
            continue

        # 1. Secret pattern scanning
        for pattern, desc, severity in SECRET_PATTERNS:
            if re.search(pattern, line):
                findings.append({
                    "type": "SECRET_EXPOSURE",
                    "file": str(file_path),
                    "line": idx,
                    "description": desc,
                    "severity": severity,
                    "snippet": line[:80].strip(),
                    "recommendation": "Move credential to environment variables or AgentGuard Secret Vault."
                })

        # 2. Dangerous command scanning (in executable scripts, workflows, and configs)
        ext = file_path.suffix.lower()
        is_script_or_config = ext in (
            ".sh", ".bash", ".zsh", ".py", ".js", ".ts", ".json", ".yaml", ".yml", ".toml", ".env"
        ) or file_path.name in ("Dockerfile", "Makefile", "Jenkinsfile")

        if is_script_or_config:
            for pattern, desc, severity in DANGEROUS_PATTERNS:
                if re.search(pattern, line):
                    findings.append({
                        "type": "DANGEROUS_COMMAND",
                        "file": str(file_path),
                        "line": idx,
                        "description": desc,
                        "severity": severity,
                        "snippet": line[:80].strip(),
                        "recommendation": "Wrap with AgentGuard Human-in-the-Loop (`ag wrap --hitl`) or block via security policy."
                    })

        # 3. Prompt injection scanning (Markdown and documentation files)
        if file_path.suffix.lower() in (".md", ".txt", ".json", ".prompt", ".yaml", ".yml"):
            for pattern, desc, severity in PROMPT_INJECTION_PATTERNS:
                if re.search(pattern, line):
                    findings.append({
                        "type": "PROMPT_INJECTION_RISK",
                        "file": str(file_path),
                        "line": idx,
                        "description": desc,
                        "severity": severity,
                        "snippet": line[:80].strip(),
                        "recommendation": "Quarantine or strip adversarial directives before embedding into vector memory."
                    })

    return findings


def run_audit(target_dir: Path) -> Dict[str, Any]:
    """Recursively audits project directory and aggregates security findings."""
    all_findings = []
    files_scanned = 0

    for root, dirs, files in os.walk(target_dir):
        # Exclude directories in-place
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS and not d.startswith(".")]

        for file_name in files:
            if file_name.startswith(".") and file_name != ".env":
                continue
            file_path = Path(root) / file_name
            findings = scan_file(file_path)
            if findings:
                all_findings.extend(findings)
            files_scanned += 1

    # Severity counts
    critical_count = sum(1 for f in all_findings if f["severity"] == "CRITICAL")
    high_count = sum(1 for f in all_findings if f["severity"] == "HIGH")
    medium_count = sum(1 for f in all_findings if f["severity"] == "MEDIUM")

    score = max(0, 100 - (critical_count * 25 + high_count * 10 + medium_count * 3))

    return {
        "target_path": str(target_dir.resolve()),
        "files_scanned": files_scanned,
        "security_score": score,
        "summary": {
            "critical": critical_count,
            "high": high_count,
            "medium": medium_count,
            "total_findings": len(all_findings),
        },
        "findings": all_findings,
    }


def main():
    parser = argparse.ArgumentParser(description="AgentGuard Zero-Trust Security Auditor")
    parser.add_argument("path", nargs="?", default=".", help="Path to project directory to audit")
    parser.add_argument("--json", action="store_true", help="Output audit results in JSON format")
    args = parser.parse_args()

    target = Path(args.path)
    if not target.exists():
        sys.stderr.write(f"Error: Path {target} does not exist.\n")
        sys.exit(1)

    report = run_audit(target)

    if args.json:
        print(json.dumps(report, indent=2))
        return

    # Formatted terminal output
    print("\n" + "=" * 65)
    print(" 🛡️  AgentGuard Security Audit Report")
    print("=" * 65)
    print(f" Target Directory : {report['target_path']}")
    print(f" Files Scanned    : {report['files_scanned']}")
    print(f" Security Score   : {report['security_score']} / 100")
    print(f" Findings Summary : {report['summary']['critical']} Critical | "
          f"{report['summary']['high']} High | {report['summary']['medium']} Medium")
    print("-" * 65)

    if not report["findings"]:
        print(" ✅ Clean! No hardcoded credentials, rogue commands, or injection triggers detected.")
        print("=" * 65 + "\n")
        return

    for idx, f in enumerate(report["findings"], start=1):
        sev_badge = f"[{f['severity']}]"
        print(f"\n[{idx}] {sev_badge} {f['type']}: {f['description']}")
        print(f"    File: {f['file']}:{f['line']}")
        print(f"    Code: {f['snippet']}")
        print(f"    Fix : {f['recommendation']}")

    print("\n" + "=" * 65)
    print(" Remediation Guidance:")
    print(" 1. Vault secrets with AgentGuard in-flight tokenization.")
    print(" 2. Restrict agent shell commands using `ag wrap --hitl`.")
    print(" 3. Enforce policy boundaries with `security_policy.md`.")
    print("=" * 65 + "\n")


if __name__ == "__main__":
    main()
