# 🛡️ AgentGuard

**OS-level zero-trust security kernel and daemon for autonomous AI agents.**

AgentGuard intercepts, classifies, and enforces security policies on every command an AI coding agent executes — before it touches your system. Think of it as a firewall that sits between AI agents (Claude Code, Cursor, Codex, Cline, etc.) and your operating system.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-535%20passed-brightgreen.svg)](#testing)

---

## 🚀 Quick Start

```bash
# Install
pip install -e .

# Start the daemon
ag start

# Wrap any AI agent with AgentGuard protection
ag wrap claude
ag wrap cursor
ag wrap codex

# Open the live monitoring cockpit
ag cockpit

# Open the web dashboard
# → http://127.0.0.1:18443
```

---

## 🏗️ Architecture

AgentGuard operates as a machine-wide security kernel with four control planes:

```
┌─────────────────────────────────────────────────────────┐
│                    AI Agent (Claude, Cursor, etc.)       │
│                         ↓ commands                      │
│  ┌──────────────────────────────────────────────────┐   │
│  │          POSIX Shell Shim (ag-sh)                │   │
│  │     AST parsing · regex classification           │   │
│  │     < 1.5ms read-only fast pass                  │   │
│  └──────────────┬───────────────────────────────────┘   │
│                 ↓ IPC (Unix Socket / JSON-RPC)          │
│  ┌──────────────────────────────────────────────────┐   │
│  │          AgentGuard Daemon                       │   │
│  │  ┌─────────┐ ┌──────────┐ ┌───────────────┐     │   │
│  │  │  Taint  │ │  Secret  │ │    Intent     │     │   │
│  │  │ Engine  │ │  Vault   │ │   Tracker     │     │   │
│  │  └─────────┘ └──────────┘ └───────────────┘     │   │
│  │  ┌─────────┐ ┌──────────┐ ┌───────────────┐     │   │
│  │  │ Policy  │ │  Memory  │ │    HITL       │     │   │
│  │  │ Engine  │ │  Guard   │ │   Approvals   │     │   │
│  │  └─────────┘ └──────────┘ └───────────────┘     │   │
│  │  ┌─────────┐ ┌──────────┐ ┌───────────────┐     │   │
│  │  │  Audit  │ │   MCP    │ │  Filesystem   │     │   │
│  │  │ Logger  │ │ Gateway  │ │    Guard      │     │   │
│  │  └─────────┘ └──────────┘ └───────────────┘     │   │
│  └──────────────────────────────────────────────────┘   │
│                 ↓ telemetry                              │
│  ┌────────────┐ ┌────────────┐ ┌───────────────────┐    │
│  │  Cockpit   │ │    Web     │ │   Notifications   │    │
│  │   TUI      │ │ Dashboard  │ │ Discord/Telegram  │    │
│  └────────────┘ └────────────┘ └───────────────────┘    │
└─────────────────────────────────────────────────────────┘
```

---

## 🔑 Core Features

### 🔒 Zero-Trust Command Interception
- **Shell Shim** — POSIX-compatible shell wrapper (`ag-sh`) that intercepts every command before execution
- **AST + Regex Classifier** — Categorizes commands as `ALLOW`, `BLOCK`, `HITL` (human approval required), or `AUDIT`
- **Read-Only Fast Pass** — Sub-1.5ms latency for safe read-only commands (`ls`, `cat`, `grep`)

### 🧬 Taint Tracking Engine
- **Session-level taint propagation** — Automatically taints sessions that fetch external content (`curl`, `wget`, `git clone`)
- **Taint DAG** — Directed acyclic graph tracking taint flow across processes and sessions
- **Network egress lockdown** — Blocks outbound connections from tainted sessions to non-whitelisted domains

### 🔐 Secret Vault
- **Automatic tokenization** — Detects API keys, database credentials, and high-entropy strings in-flight
- **Ephemeral token replacement** — Replaces secrets with `<AG_VAULT_TOKEN_xx>` tokens in memory
- **Selective detokenization** — Only de-vaults for whitelisted official API endpoints

### 🧠 Intent Drift Detection
- **Cosine similarity tracking** — Monitors whether an agent's actions drift from its stated goal
- **Drift meter** — Real-time gauge: ≥ 0.65 Safe, < 0.65 Warning

### 🛑 Human-in-the-Loop (HITL)
- **Approval workflow** — High-risk commands require explicit human approval before execution
- **Terminal prompt** — `[A]llow once / [D]eny` directly in the agent's terminal
- **Fail-closed timeout** — Unapproved commands are denied after configurable timeout

### 🧱 Security Policy Engine
- **Markdown-based policies** — Define security rules in `security_policy.md` with compliance mapping
- **4-phase zero-trust model:**
  - Phase 1: Core system & infrastructure protection (SOC2-CC6.1, ISO27001)
  - Phase 2: Data exfiltration & network boundary defense (OWASP ASI01/ASI03)
  - Phase 3: RAG & long-term memory guard (OWASP ASI06)
  - Phase 4: Change management & environment isolation
- **Specially banned commands** — Custom blocklist with per-rule compliance citations

### 🧬 Memory Guard
- **Vector DB write inspection** — Quarantines sleeper prompt injections targeting RAG memory
- **SHA-256 provenance stamping** — Cryptographic verification of memory chunk integrity

### 🌐 MCP Gateway Proxy
- **Tool-call inspection** — Intercepts Model Context Protocol tool calls before execution
- **Schema validation** — Validates MCP tool arguments against security policies

### 📊 Monitoring & Dashboards
- **Web Dashboard** — Dark-theme DevSecOps dashboard on `127.0.0.1:18443` with live SSE telemetry
- **Cockpit TUI** — Full-screen terminal UI (`ag cockpit`) with Rich-powered layout
- **Swarm Radar** — Live table of connected agents with taint radiation meters
- **Emergency Kill Switch** — `[K]` to pause/terminate/inspect any agent's process tree

### 🔔 Notifications
- **Discord & Telegram** — Real-time threat alerts for blocked commands, taint escalations, secret exfiltration attempts
- **Health Heartbeat** — Periodic system telemetry summaries
- **SIEM Forwarding** — Export audit logs to Splunk, ELK, or S3

---

## 📦 Agent Profiles

AgentGuard ships with pre-configured security profiles for popular AI coding agents:

| Agent | Profile |
|-------|---------|
| Claude Code | `claude-code.yaml` |
| Cursor | `cursor.yaml` |
| Codex | `codex.yaml` |
| Cline | `cline.yaml` |
| Aider | `aider.yaml` |
| Continue | `continue.yaml` |
| Windsurf | `windsurf.yaml` |
| OpenHands | `openhands.yaml` |
| SWE-Agent | `swe-agent.yaml` |
| CrewAI | `crewai.yaml` |
| AutoGen | `autogen.yaml` |
| Goose | `goose.yaml` |
| Gemini CLI | `gemini-cli.yaml` |
| Antigravity | `antigravity.yaml` |
| Hermes | `hermes.yaml` |
| Qwen Code | `qwen-code.yaml` |
| OpenClaw | `openclaw.yaml` |
| Generic | `generic.yaml` |

---

## 🖥️ CLI Reference

```bash
ag start                    # Start the AgentGuard daemon
ag stop                     # Stop the daemon
ag status                   # Show daemon status and connected agents
ag wrap <agent>             # Wrap an AI agent with AgentGuard protection
ag cockpit                  # Open the terminal monitoring cockpit
ag notify setup             # Configure Discord/Telegram notifications
ag notify test              # Send a test alert
ag siem setup               # Configure SIEM log forwarding
```

---

## 🧪 Testing

AgentGuard has a comprehensive test suite with 535 tests across unit and end-to-end tiers:

```bash
# Run all tests
pytest -v

# Unit tests only
pytest tests/unit/ -v

# End-to-end tests (5 tiers)
pytest tests/e2e/ -v
```

### Test Tiers
- **Tier 1:** Feature coverage (core requirements R1–R5)
- **Tier 2:** Boundary and edge case testing
- **Tier 3:** Pairwise interaction testing
- **Tier 4:** Real-world scenario simulation
- **Tier 5:** Adversarial hardening and stress testing

---

## 📁 Project Structure

```
agentguard/
├── __init__.py
├── cli.py                          # CLI entry point
├── config.py                       # Configuration management
├── launcher.py                     # Smart launcher with auto-detection
├── daemon/
│   ├── server.py                   # Unix socket + HTTP daemon
│   ├── audit.py                    # Dual-tier audit logging
│   ├── command_classifier.py       # AST + regex command classification
│   ├── intent.py                   # Intent drift tracker
│   ├── memory_guard.py             # Vector DB write inspector
│   ├── policy_engine.py            # Markdown security policy parser
│   ├── process_control.py          # Process tree supervision
│   ├── taint_engine.py             # Session taint DAG
│   ├── vault.py                    # Secret tokenization vault
│   └── dashboard.html              # Embedded web dashboard
├── interceptors/
│   ├── shell_shim.py               # POSIX shell command interceptor
│   ├── fs_guard.py                 # Filesystem write guard
│   ├── mcp_gateway.py              # MCP tool-call proxy
│   ├── mcp_proxy.py                # MCP schema validator
│   └── shim_binary/                # C source for native shell shim
├── cockpit/
│   ├── app.py                      # Rich TUI cockpit layout
│   ├── radar.py                    # Swarm radar widget
│   ├── drift_meter.py              # Intent drift gauge
│   ├── telemetry_feed.py           # Live log feed
│   ├── kill_switch.py              # Emergency process control
│   └── client.py                   # Daemon IPC client
├── notifications/
│   ├── dispatcher.py               # Async alert queue
│   ├── discord.py                  # Discord webhook integration
│   ├── telegram.py                 # Telegram bot integration
│   ├── heartbeat.py                # Periodic health summary
│   └── config.py                   # Credential management
├── exporters/
│   └── siem_forwarder.py           # Splunk/ELK/S3 log export
├── profiles/                       # Per-agent YAML security profiles
└── web/
    └── dashboard.html              # Standalone web dashboard
```

---

## 📋 Security Policy

Define custom security rules in `security_policy.md` at the project root. The policy engine supports:

- **Compliance framework mapping** — SOC2, ISO27001, PCI-DSS, GDPR, OWASP ASI
- **Condition expressions** — Context-aware rules (taint state, time of day, environment)
- **Specially banned commands** — Custom blocklist with rule IDs and rationale
- **4-phase zero-trust model** — From infrastructure protection to change management

See [`security_policy.md`](security_policy.md) for the full reference policy.

---

## 🔧 Requirements

- Python 3.9+
- macOS or Linux
- Dependencies: `click`, `pydantic`, `pyyaml`, `rich`, `watchfiles`, `numpy`

---

## 📜 License

Apache License 2.0 — See [LICENSE](LICENSE) for details.
