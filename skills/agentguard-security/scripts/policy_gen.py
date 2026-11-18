#!/usr/bin/env python3
"""
AgentGuard Zero-Trust Policy & Profile Generator.

Generates production-grade security_policy.md and agent profile YAML configurations
tailored to specific coding agents (Claude, Cursor, Codex, Antigravity).
"""

import argparse
from pathlib import Path
import sys

POLICY_TEMPLATE = """# AgentGuard Security Policy (`security_policy.md`)
# Generated for: {project_name} | Framework: {agent_name}
# Compliance Mapping: SOC2 Type II (CC6.1/6.6/6.8), ISO 27001 (A.9/A.12), OWASP Agentic AI

---

## Phase 1: Core System & Infrastructure Protection

### Root & Critical Path Deletion Block (`SOC2-CC6.1`)
- **Rule:** Unconditionally block recursive deletions targeting `/`, `/etc`, `/usr`, `/var`, `~/.ssh`, `~/.aws`, `.env`.
- **Action:** `BLOCK`

### Raw Block Device & Disk Formatting Guard (`SOC2-CC6.8`)
- **Rule:** Block execution of `mkfs`, `fdisk`, `dd if=... of=/dev/...`, and direct block redirections.
- **Action:** `BLOCK`

---

## Phase 2: Data Exfiltration & Network Boundary Defense

### Tainted Session Network Egress Lockdown (`SOC2-CC6.6` / `OWASP-ASI01`)
- **Rule:** When an agent fetches external web or git content, lock down outbound connections (`curl`, `wget`, `nc`, `ssh`) to non-whitelisted destinations.
- **Action:** `BLOCK_ON_TAINT`
- **Whitelisted Endpoints:**
  - `api.anthropic.com`
  - `api.openai.com`
  - `github.com`

### In-Flight Secret Vaulting (`PCI-DSS-Req6.5` / `GDPR-Art32`)
- **Rule:** Mask high-entropy API tokens and passwords in RAM with `<AG_VAULT_TOKEN_xx>`.
- **Action:** `VAULT_REDACT`

---

## Phase 3: RAG & Long-Term Memory Guard

### Sleeper Injection Quarantine (`OWASP-ASI06`)
- **Rule:** Quarantine memory chunks containing boundary overrides, role spoofing, or conditional triggers.
- **Action:** `QUARANTINE_MEMORY`

---

## Phase 4: Production Environment Isolation

### Privilege Escalation Lockout (`SOC2-CC6.1`)
- **Rule:** Block `sudo`, `su`, and file permission overrides (`chmod 777`).
- **Action:** `BLOCK_IN_PRODUCTION`

---

## Specially Banned Commands

- `nmap`
- `wireshark`
- `tcpdump`
- `aircrack-ng`
"""

YAML_PROFILE_TEMPLATE = """# AgentGuard Security Profile
# Agent: {agent_name}
name: {agent_key}
description: Zero-trust security profile for {agent_name}

shell:
  safe_commands:
    - ls
    - cat
    - grep
    - git status
    - git diff
    - git log
    - pwd
    - echo
  dangerous_patterns:
    - "rm\\\\s+-(?:r[fv]{{1,2}}|[fv]{{1,2}}r)"
    - "curl.*\\\\|\\\\s*(?:ba)?sh"
    - "wget.*\\\\|\\\\s*(?:ba)?sh"
    - "mkfs"
    - ">\\\\s*/dev/"
  block_tainted_only: true
  hitl_prompt: true

vault:
  enabled: true
  entropy_threshold: 4.2
  min_token_length: 24
  whitelisted_endpoints:
    - api.openai.com
    - api.anthropic.com
    - github.com
"""


def main():
    parser = argparse.ArgumentParser(description="AgentGuard Security Policy Generator")
    parser.add_argument("--agent", choices=["antigravity", "claude", "cursor", "codex", "cline", "generic"],
                        default="generic", help="Target agent environment")
    parser.add_argument("--out-dir", default=".", help="Directory to write security files")
    args = parser.parse_args()

    out_path = Path(args.out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    agent_names = {
        "antigravity": "Antigravity Agent",
        "claude": "Claude Code CLI",
        "cursor": "Cursor AI Editor",
        "codex": "OpenAI Codex CLI",
        "cline": "Cline / Roo Code",
        "generic": "Autonomous AI Agent",
    }
    agent_name = agent_names.get(args.agent, "Autonomous AI Agent")
    project_name = Path.cwd().name

    # 1. Write security_policy.md
    policy_file = out_path / "security_policy.md"
    policy_content = POLICY_TEMPLATE.format(project_name=project_name, agent_name=agent_name)
    policy_file.write_text(policy_content, encoding="utf-8")
    print(f" ✅ Generated: {policy_file}")

    # 2. Write agent profile YAML
    profile_file = out_path / f"{args.agent}.yaml"
    profile_content = YAML_PROFILE_TEMPLATE.format(agent_name=agent_name, agent_key=args.agent)
    profile_file.write_text(profile_content, encoding="utf-8")
    print(f" ✅ Generated: {profile_file}")

    print("\nPolicy Generation Complete! Run `ag wrap --hitl -- <command>` to enforce.")


if __name__ == "__main__":
    main()
