---
name: agentguard-security
description: OS-level zero-trust security auditor, taint tracking inspector, and policy hardener for AI coding agents (Claude Code, Cursor, Codex, Antigravity, Cline, OpenClaw). Audits repositories for exposed secrets, dangerous bash commands, and sleeper prompt injection triggers, and generates compliant security policies.
tags:
  - security
  - zero-trust
  - audit
  - claude-code
  - cursor
  - agentguard
  - compliance
---

# AgentGuard: Zero-Trust Security Kernel & Agent Auditor

This skill equips AI coding agents with zero-trust security capabilities to inspect codebases, audit automated agent workflows, identify credential leaks, block dangerous shell execution patterns, and enforce compliance policies (SOC2, ISO 27001, OWASP Agentic Top 10).

---

## When to Activate This Skill

Activate this skill whenever the user asks to:
1. **Audit a codebase or repository for security vulnerabilities** (secret leaks, hardcoded tokens, dangerous scripts).
2. **Harden an AI agent against rogue actions or sandbox escape** (preventing `rm -rf`, raw disk writes, reverse shells).
3. **Generate a zero-trust security policy or profile** (`security_policy.md` or agent YAML profiles).
4. **Inspect runtime agent protection status** (verifying whether shims, secret vault, or taint tracking are active).
5. **Comply with enterprise security standards** (SOC2 Type II CC6.1/6.6/6.8, ISO 27001, OWASP Top 10 for LLMs / Agentic AI).

---

## Skill Capabilities & Workflows

### Workflow 1: Run Static Security Audit
Inspect the project directory for secret leaks, destructive commands, and sleeper prompt injection triggers:

```bash
# Run security audit on current project directory
python3 scripts/audit.py .

# Or output structured JSON results for programmatic evaluation
python3 scripts/audit.py . --json
```

**What the audit evaluates:**
- **Secret Leaks (CRITICAL / HIGH):** Scans for exposed OpenAI/Anthropic keys, GitHub tokens, AWS credentials, database URIs, and private RSA keys.
- **Dangerous Commands (CRITICAL / HIGH):** Flags destructive deletions (`rm -rf /`), unverified remote script downloads (`curl | bash`), raw disk writes (`mkfs`), and reverse shells (`nc -e`).
- **Sleeper Prompt Injections (HIGH / MEDIUM):** Detects system boundary spoofing, direct instruction override phrases, conditional sleeper triggers, and stealth zero-width unicode characters in markdown and memory files.

### Workflow 2: Generate Customized Security Policy & Agent Profile
Generate tailored, production-ready `security_policy.md` and agent YAML profiles for the active agent framework:

```bash
# Generate policy for a specific agent framework
python3 scripts/policy_gen.py --agent claude        # Claude Code CLI
python3 scripts/policy_gen.py --agent cursor        # Cursor Editor
python3 scripts/policy_gen.py --agent antigravity   # Antigravity Multi-Agent
python3 scripts/policy_gen.py --agent codex         # OpenAI Codex CLI
python3 scripts/policy_gen.py --agent generic       # General AI Agent
```

This generates:
1. `security_policy.md` with explicit phase-by-phase zero-trust rules (SOC2 / ISO 27001 mapping).
2. `<agent>.yaml` defining safe command whitelists, dangerous pattern filters, and vault endpoints.

### Workflow 3: Verify Runtime Agent Protection
Check whether the current session is executing under active AgentGuard zero-trust supervision:

```bash
python3 scripts/verify.py
```

Reports:
- Active Session ID and Process PID
- Shell shim interception status in `PATH`
- Background daemon IPC socket availability
- Human-in-the-Loop (HITL) gate enforcement
- Local and global security policy resolution

---

## Remediation & Hardening Best Practices

When findings are identified during an audit:

1. **Credenitals & Tokens:**
   - Remove plaintext API keys immediately.
   - Store sensitive keys in local `.env` files added to `.gitignore`.
   - In production, leverage in-flight secret vaulting so keys are replaced with synthetic tokens in RAM.

2. **Destructive Shell Commands:**
   - Restrict agents to safe read-only commands (`ls`, `cat`, `grep`, `git status`).
   - For high-impact mutations, enforce interactive Human-in-the-Loop confirmation:
     ```bash
     ag wrap --hitl -- <agent-command>
     ```

3. **Untrusted Web & Git Dependencies:**
   - When pulling external content via `curl`, `wget`, or cloning untrusted repositories, enforce taint tracking to lock down outbound network egress.

---

## Reference Documentation

For deep architectural and compliance details, consult the bundled reference guides:
- [Compliance Reference Matrix](reference/compliance_matrix.md) — SOC2, ISO 27001, and OWASP mapping.
- [Banned Patterns Catalog](reference/banned_patterns.md) — Catalog of dangerous syntax and shell exploits.
- [Recommended Agent Profiles](reference/agent_profiles.md) — Profile templates for Claude, Cursor, and Antigravity.
