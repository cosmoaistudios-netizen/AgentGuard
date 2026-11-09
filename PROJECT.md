# Project: AgentGuard Cockpit & Alerting Suite v2

## Architecture
AgentGuard v2 extends the production-grade zero-trust security kernel with an ultra-lightweight, unified monitoring, control, and alerting platform for autonomous AI agents. The architecture operates concurrently machine-wide with three primary control planes:
1. **Zero-Trust Kernel & Daemon**:
   - High-throughput Unix Domain Socket (`/tmp/agentguard.sock`) handling JSON-RPC command evaluation, AST parsing, Taint DAG propagation, Secret Vault tokenization, and Intent Drift detection (<2ms latency).
   - Local HTTP server (`127.0.0.1:18443`) with embedded dark-theme DevSecOps dashboard and Server-Sent Events (SSE) telemetry stream (`/events`).
   - Audit Logger with dual-tier storage (in-memory ring buffer `maxlen=1000` + persistent append-only `~/.agentguard/audit.jsonl`).
2. **Terminal Cockpit TUI (`ag cockpit`)**:
   - Dedicated full-screen console powered by Rich (`rich.live.Live`, `rich.layout.Layout`, `rich.table.Table`) designed for terminal/tmux panes.
   - Swarm Radar table & dynamic Taint Radiation meters (0% Clean Green ➔ 100% Radioactive Tainted Red/Amber).
   - Flight-Path Intent Drift meter (cosine similarity gauge: $\ge 0.65$ Safe, $< 0.65$ Warning).
   - Live Audited Telemetry Feed with color-coded badges (`[PASS]`, `[BLOCKED]`, `[VAULTED]`, `[SANITIZED]`, `[TAINTED]`).
   - Emergency Kill-Switch: `[K]` prompts PID selection, triggers process tree `SIGSTOP`, presents modal (`[R]` Resume, `[T]` Terminate via `SIGKILL`, `[I]` Inspect provenance & commands).
   - HITL confirmation prompt (`[A]` Allow Once / `[D]` Deny).
3. **Threat Alerting Engine (`agentguard.notifications`)**:
   - Native notification module storing credentials in `~/.agentguard/notifications.yaml` (`0o600`).
   - Asynchronous non-blocking queue (`asyncio.Queue`) background worker ensuring 0ms blocking on command interception.
   - Immediate Threat Alerts for high-risk events (`COMMAND_BLOCKED`, `TAINT_ESCALATION`, `SECRET_EXFILTRATION_ATTEMPT`, `CRITICAL_INTENT_DRIFT`) to Discord Webhooks and Telegram Bot APIs.
   - Scheduled Health Heartbeat (periodic system telemetry summary).
   - CLI setup & test commands (`ag notify setup`, `ag notify test`).
4. **Interactive CLI Launcher & Universal Auto-Detection**:
   - `ag` with no arguments opens an interactive arrow-key menu.
   - First-run daemon check prompt (`ensure_daemon_running`) prompts `Start daemon now? [Y/n]: ` on `ag cockpit`, `ag wrap`, `ag status`.
   - `ag wrap` auto-detects `claude`, `hermes`, `openclaw`, `agy`, `codex` from command binary.

---

## Feature Inventory
Every feature from user requirements is inventoried and assigned to a milestone.

| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | `agentguard.notifications` Core | Notification module configuration and credentials store (`~/.agentguard/notifications.yaml`) | M1 | R3 |
| 2 | Discord Webhook Formatting | High-priority threat alert embed formatting for Discord | M1 | R3 |
| 3 | Telegram Bot API Formatting | Markdown/HTML formatted alert dispatching to Telegram chat | M1 | R3 |
| 4 | Asynchronous Alert Dispatcher | Non-blocking `asyncio.Queue` background dispatcher (<0.2ms local latency) | M1 | R3, R4 |
| 5 | Scheduled Health Heartbeat | Configurable periodic summary (uptime, active/tainted count, secrets, exploits) | M1 | R3 |
| 6 | CLI Notification Commands | `ag notify setup --discord/--telegram`, `ag notify test`, `ag notify status` | M1 | R3 |
| 7 | Process Tree Supervision | Recursive process tree pausing (`SIGSTOP`), resuming (`SIGCONT`), and termination (`SIGKILL`) using `psutil` | M2 | R1, R4 |
| 8 | Daemon Process Control IPC | Daemon actions `PAUSE_AGENT`, `RESUME_AGENT`, `TERMINATE_AGENT`, `INSPECT_AGENT` | M2 | R1 |
| 9 | Correct PID Registration | Post-spawn PID registration capturing actual agent process root PID in `ag wrap` | M2 | R1 |
| 10 | Shell Shim HITL Prompts | Direct `/dev/tty` fallback prompt `[A]llow once / [D]eny` and daemon-level async HITL future | M2 | R1 |
| 11 | DevSecOps Web Dashboard HTML/CSS/JS | Fast zero-dependency dark-theme single-page dashboard on `127.0.0.1:18443` | M3 | R2, R4 |
| 12 | Live Metrics Cards | Web gauges for Active Agents, Tainted Sessions, Secrets Shielded, Latency (<2ms), Total Events | M3 | R2 |
| 13 | Searchable & Filterable Live Audit Table | SSE stream (`/events`) with live filtering by event type, text search, JSON/CSV export | M3 | R2 |
| 14 | Web Control Deck | Web buttons to trigger Agent Pause, Terminate, and 1-click Allow/Deny for pending HITL | M3 | R2 |
| 15 | Standalone Cockpit TUI Layout | Full-screen Rich-based terminal UI (`ag cockpit`) with header, radar, drift gauge, and log feed | M4 | R1, R4 |
| 16 | Swarm Radar & Taint Meters | Connected agent table with dynamic 0% Clean Green ➔ 100% Radioactive Tainted Red/Amber | M4 | R1 |
| 17 | Flight-Path Intent Drift Meter | Cosine similarity gauge widget ($\ge 0.65$ Safe, $< 0.65$ Warning) | M4 | R1 |
| 18 | Live Audited Telemetry Feed | Auto-scrolling event log with color-coded badges (`[PASS]`, `[BLOCKED]`, etc.) | M4 | R1 |
| 19 | Cockpit Emergency Kill-Switch | Pressing `[K]` prompts PID selection, triggers `SIGSTOP`, shows modal (`[R]`, `[T]`, `[I]`) | M4 | R1 |
| 20 | Cockpit HITL Prompt | Interactive prompt for high-risk commands with `[A]` Allow Once / `[D]` Deny | M4 | R1 |
| 21 | Interactive CLI Launcher Menu | Running `ag` alone displays interactive arrow-key launcher menu | M5 | R5 |
| 22 | First-Run Daemon Check Prompt | Interactive prompt `Start daemon now? [Y/n]: ` when daemon is stopped | M5 | R5 |
| 23 | Universal Smart Auto-Detection | `ag wrap` auto-maps `claude`, `hermes`, `openclaw`, `agy`, `codex`, and custom profiling | M5 | R5 |
| 24 | Ultra-Lightweight Resource Architecture | Combined Daemon + Cockpit RAM < 100MB, idle CPU < 1%, zero heavy dependencies | M6 | R4 |
| 25 | Comprehensive Test Suite & Zero Audio | 100% passing tests across all new modules, zero regressions on 243 tests, zero audio commands | M6 | R6 |

---

## Milestones

| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Threat Alerting Engine (`agentguard.notifications`) | Config store, Discord Webhooks, Telegram API, async non-blocking queue dispatcher, health heartbeat, `ag notify` CLI, 100% offline tests | none | DONE |
| M2 | Process Control & HITL Emergency Kill-Switch | Process tree `psutil` pause/resume/kill, daemon IPC (`PAUSE_AGENT`, `RESUME_AGENT`, `TERMINATE_AGENT`, `INSPECT_AGENT`), PID registration fix, shell shim HITL fallback & daemon future | none | DONE |
| M3 | DevSecOps Web Dashboard (`http://127.0.0.1:18443`) | Embedded dark-theme web dashboard, metrics cards, SSE `/events` stream, searchable/filterable audit table, JSON/CSV export, web control deck | M2 | DONE |
| M4 | Standalone Terminal Cockpit TUI (`ag cockpit`) | Rich Live full-screen TUI, Swarm Radar & Taint meters, Intent Drift gauge, live event feed, `[K]` kill-switch modal (`[R]`, `[T]`, `[I]`), `[A]`/`[D]` HITL, `ag cockpit` CLI | M2 | DONE |
| M5 | Interactive CLI Launcher & Smart Auto-Detection | Click launcher menu for `ag`, `ensure_daemon_running` prompt, smart auto-detection for agent CLIs, `openclaw.yaml`, `codex.yaml`, custom profile generation | M1, M2, M3, M4 | DONE |
| M6 | Comprehensive Verification & Final Hardening | Run all v1 (243) and v2 tests, verify <100MB RAM, <1% idle CPU, zero audio commands (`say`, `afplay`), adversarial hardening | M1, M2, M3, M4, M5, TEST_READY | DONE |

---

## Interface Contracts

### 1. Daemon IPC Extensions (`/tmp/agentguard.sock`)
- Actions added to `AgentGuardServer.dispatch_action`:
  - `PAUSE_AGENT`: payload `{"session_id": str}` or `{"pid": int}` ➔ calls `process_control.pause_tree()`, returns `{"status": "PAUSED", "pid": pid}`
  - `RESUME_AGENT`: payload `{"session_id": str}` or `{"pid": int}` ➔ calls `process_control.resume_tree()`, returns `{"status": "RESUMED", "pid": pid}`
  - `TERMINATE_AGENT`: payload `{"session_id": str}` or `{"pid": int}` ➔ calls `process_control.kill_tree()`, returns `{"status": "TERMINATED", "pid": pid}`
  - `INSPECT_AGENT`: payload `{"session_id": str}` ➔ returns:
    ```json
    {
      "pid": 1234,
      "profile": "claude-code",
      "taint_state": "TAINTED",
      "taint_chain": ["session:ag-sess-1", "file:/path/shared.md", "pid:1234"],
      "recent_commands": [...],
      "cpu_percent": 0.4,
      "memory_rss_bytes": 45000000
    }
    ```
  - `HITL_DECISION`: payload `{"request_id": str, "decision": "ALLOW" | "DENY"}` ➔ resolves waiting async HITL future.

### 2. HTTP Server Endpoints (`127.0.0.1:18443`)
- `GET /` ➔ Serves self-contained modern dark-theme HTML/CSS/JS dashboard.
- `GET /health` ➔ JSON health status.
- `GET /status` ➔ JSON daemon status, active sessions, metrics.
- `GET /audit` ➔ JSON recent audit events.
- `GET /events` ➔ Server-Sent Events (SSE) `text/event-stream` pushing live audit events as `data: {"id": ..., "type": ..., ...}\n\n`.
- `POST /api/agent/pause` ➔ JSON payload `{"session_id": "..."}`.
- `POST /api/agent/resume` ➔ JSON payload `{"session_id": "..."}`.
- `POST /api/agent/terminate` ➔ JSON payload `{"session_id": "..."}`.
- `POST /api/hitl/decision` ➔ JSON payload `{"request_id": "...", "decision": "ALLOW" | "DENY"}`.

### 3. Notification Engine API (`agentguard.notifications`)
- Config file: `~/.agentguard/notifications.yaml` (permissions `0o600`).
- Dispatch function: `dispatch_threat_alert(event_type, details, config)` (async, fire-and-forget).
- Channels:
  - Discord Webhook: JSON payload with embed fields (Severity, Agent PID, Profile, Intercepted Command, Taint Source, Policy Reason).
  - Telegram Bot API: `sendMessage` with Markdown formatted card.
- Health Heartbeat: `dispatch_health_heartbeat(status_data, config)`.

### 4. Cockpit TUI Entrypoint
- Command: `ag cockpit [--socket /tmp/agentguard.sock]`
- Keys:
  - `[K]` ➔ Enter Emergency Kill-Switch mode (select PID ➔ `[R]` Resume, `[T]` Terminate, `[I]` Inspect).
  - `[A]` ➔ Allow pending HITL action.
  - `[D]` ➔ Deny pending HITL action.
  - `[Q]` / `[Ctrl+C]` ➔ Exit Cockpit cleanly without terminating daemon or agents.

---

## Code Layout
```
agentguard/
├── pyproject.toml
├── setup.py
├── README.md
├── PROJECT.md
├── TEST_INFRA.md
├── TEST_READY.md
├── agentguard/
│   ├── __init__.py
│   ├── cli.py                     # ag entrypoint with launcher menu & ensure_daemon_running
│   ├── config.py                  # Profiles & notifications config
│   ├── daemon/
│   │   ├── __init__.py
│   │   ├── server.py              # UDS & HTTP server with SSE & process control IPC
│   │   ├── process_control.py     # SIGSTOP/SIGCONT/SIGKILL process tree manager
│   │   ├── taint_engine.py
│   │   ├── vault.py
│   │   ├── intent.py
│   │   └── audit.py
│   ├── notifications/
│   │   ├── __init__.py
│   │   ├── config.py              # YAML config loader/saver (~/.agentguard/notifications.yaml)
│   │   ├── discord.py             # Discord webhook payload generator & dispatcher
│   │   ├── telegram.py            # Telegram Bot API payload generator & dispatcher
│   │   ├── heartbeat.py           # Scheduled system health summary compiler
│   │   └── dispatcher.py          # Non-blocking asyncio.Queue alert worker
│   ├── web/
│   │   ├── __init__.py
│   │   ├── dashboard.html         # Embedded dark-theme DevSecOps dashboard
│   │   └── server_handlers.py     # SSE /events & /api/agent routes
│   ├── cockpit/
│   │   ├── __init__.py
│   │   ├── app.py                 # Rich-based Cockpit TUI application
│   │   ├── radar.py               # Swarm radar table & taint radiation meters
│   │   ├── drift_meter.py         # Flight-path intent drift gauge widget
│   │   ├── telemetry_feed.py      # Live scrolling telemetry feed with color badges
│   │   └── kill_switch.py         # Process pause/resume/kill modal & HITL handler
│   ├── interceptors/
│   │   ├── __init__.py
│   │   ├── shell_shim.py          # Shell interceptor with interactive HITL prompt
│   │   ├── shim_binary/
│   │   │   └── ag-sh.c
│   │   └── fs_guard.py
│   └── profiles/
│       ├── claude-code.yaml
│       ├── hermes.yaml
│       ├── antigravity.yaml
│       ├── openclaw.yaml
│       ├── codex.yaml
│       └── generic.yaml
└── tests/
    ├── conftest.py                # Network isolation, offline mocks, canaries
    ├── e2e/
    │   ├── test_tier1_features.py
    │   ├── test_tier2_boundaries.py
    │   ├── test_tier3_pairwise.py
    │   ├── test_tier4_realworld.py
    │   ├── test_tier5_adversarial_hardening.py
    │   └── test_v2_e2e_suite.py   # E2E suite for Cockpit, Web Dashboard, Notifications
    └── unit/
        ├── test_cli.py
        ├── test_daemon.py
        ├── test_taint.py
        ├── test_vault.py
        ├── test_intent.py
        ├── test_shell_shim.py
        ├── test_fs_guard.py
        ├── test_notifications.py  # M1 tests (100% offline)
        ├── test_process_control.py # M2 tests (signals & tree kill)
        ├── test_web_dashboard.py  # M3 tests (SSE & REST API)
        ├── test_cockpit_tui.py    # M4 tests (Rich TUI rendering)
        └── test_smart_launcher.py # M5 tests (auto-detection & launcher)
```
