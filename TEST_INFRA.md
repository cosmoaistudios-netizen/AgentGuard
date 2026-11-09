# AgentGuard Test Infrastructure (`TEST_INFRA.md`)

## 1. Test Philosophy

AgentGuard employs a strict **opaque-box, requirement-driven, zero-trust test philosophy**:
- **Opaque-Box Interception**: Tests interact strictly via public interfaces: CLI commands (`ag`), Unix domain socket (`/tmp/agentguard.sock`), HTTP endpoints (`127.0.0.1:18443`), environment variables (`AGENTGUARD_*`), filesystem I/O, and shell command interceptor boundaries (`ag-sh`). Internal classes and unexported methods are treated as black boxes.
- **Zero Real Credentials**: No production keys or real cloud secrets are ever used. All secret detection tests utilize synthetically generated high-entropy strings, canary tokens (`AG_AUDIT_CANARY_TOKEN`, `{{7*7}}`), and synthetic vendor-like prefixes (`sk-proj-test12345`, `AG_TEST_KEY_12345`).
- **Zero Outbound Network Access**: An autouse test fixture (`isolate_network` in `tests/conftest.py`) strictly isolates the execution environment by blocking all non-local socket creation and external network connections. Only local Unix Domain Sockets (`AF_UNIX`) and loopback interfaces (`127.0.0.1`) are permitted. All Discord/Telegram tests must run against local loopback mocks or monkeypatched transports.
- **Strict Audio Prohibition**: Zero tolerance for `say`, `afplay`, or audio synthesis commands. Enforced by automated AST/token scans across all source and test files.
- **Deterministic & Fast Execution**: The entire test suite must execute in under 60 seconds with 100% deterministic results, independent of wall-clock jitter, external daemon state, or execution order.
- **Ultra-Lightweight Resource Verification**: Automated checks ensuring combined daemon + cockpit RSS memory < 100MB and idle CPU < 1%.

---

## 2. Feature Inventory Mapping to Test Tiers

The test suite covers all features from `PROJECT.md § Feature Inventory`:

| Feature # | Feature Name | Tier 1: Feature | Tier 2: Boundary | Tier 3: Pairwise | Tier 4: Real-World | Tier 5: Adversarial |
|---|---|:---:|:---:|:---:|:---:|:---:|
| 1-6 | Notifications & Alerting (`agentguard.notifications`) | ✓ | ✓ | ✓ | ✓ | ✓ |
| 7-10 | Process Control (`SIGSTOP`/`SIGCONT`/`SIGKILL`) & HITL | ✓ | ✓ | ✓ | ✓ | ✓ |
| 11-14 | DevSecOps Web Dashboard & SSE Stream | ✓ | ✓ | ✓ | ✓ | ✓ |
| 15-20 | Standalone Terminal Cockpit TUI (`ag cockpit`) | ✓ | ✓ | ✓ | ✓ | ✓ |
| 21-23 | Smart Launcher & Universal Auto-Detection | ✓ | ✓ | ✓ | ✓ | ✓ |
| 24 | Ultra-Lightweight Memory & CPU Limits (<100MB) | ✓ | ✓ | | ✓ | ✓ |
| 25 | Zero Audio Compliance Repo-Wide | ✓ | ✓ | ✓ | ✓ | ✓ |

---

## 3. Test Suites & Layout

### 3.1 Unit Test Suites (`tests/unit/`)
1. `test_notifications.py`:
   - Config file read/write (`~/.agentguard/notifications.yaml` mode 0600)
   - Discord webhook JSON payload formatting and validation
   - Telegram Bot API Markdown payload formatting
   - Non-blocking async queue worker dispatch
   - Scheduled health heartbeat payload generation
   - `ag notify setup`, `test`, `status` CLI testing (with 100% offline mocking)
2. `test_process_control.py`:
   - Recursive process tree pausing (`SIGSTOP`) and resuming (`SIGCONT`) using `psutil`
   - Recursive process tree termination (`SIGKILL`)
   - Daemon IPC actions: `PAUSE_AGENT`, `RESUME_AGENT`, `TERMINATE_AGENT`, `INSPECT_AGENT`
   - Post-spawn PID registration verification in `ag wrap`
   - HITL decision future resolution
3. `test_web_dashboard.py`:
   - `GET /` serves HTML dashboard in <50ms without external CDN dependencies
   - `GET /events` Server-Sent Events (SSE) streaming format
   - `POST /api/agent/pause`, `resume`, `terminate` REST endpoints
   - `POST /api/hitl/decision` REST endpoint
   - JSON & CSV event export
4. `test_cockpit_tui.py`:
   - Rich Layout, Swarm Radar table, dynamic Taint Radiation meters rendering
   - Intent Drift cosine gauge rendering
   - Live Audited Telemetry Feed auto-scrolling
   - Emergency Kill-Switch keybinding (`K`) modal presentation (`[R]`, `[T]`, `[I]`)
   - Headless Rich Console capture testing
5. `test_smart_launcher.py`:
   - `ag` with no arguments opens interactive launcher menu
   - `ensure_daemon_running()` first-run prompt `Start daemon now? [Y/n]`
   - Auto-detection for `claude`, `hermes`, `openclaw`, `agy`, `codex`
   - Unknown script handling and custom profile generation

### 3.2 End-to-End Test Suite (`tests/e2e/test_v2_e2e_suite.py`)
- End-to-end integration: Wrap agent ➔ Taint occurs ➔ Dangerous command blocked ➔ Instant Discord/Telegram alert queued ➔ Event appears in Web SSE stream ➔ Cockpit TUI radar reflects radiation ➔ Operator presses `K` to pause process tree (`SIGSTOP`) ➔ Inspect modal displays provenance chain ➔ Operator resumes (`SIGCONT`) or terminates (`SIGKILL`).
- Zero regressions on pre-existing 243 tests (`test_tier1` - `test_tier5`, `test_cli`, `test_daemon`, `test_taint`, `test_vault`, `test_intent`, `test_shell_shim`, `test_fs_guard`).
- Performance and resource verification: <100MB combined RSS, <1% idle CPU.
- Zero audio compliance test across all source and test files.

---

## 4. Pass/Fail Semantics

1. **Test Pass Threshold**: 100% of pre-existing 243 tests AND 100% of new v2 tests must pass.
2. **Network Firewall Enforcement**: Zero non-loopback connections permitted during test execution.
3. **Audio Zero-Tolerance**: Any invocation of `say` or `afplay` causes immediate unconditional test failure.
4. **Latency & Resource Guarantees**: Interception decision latency < 2ms; combined memory < 100MB.
