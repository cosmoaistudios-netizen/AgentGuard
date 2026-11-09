# AgentGuard Enterprise Security Policy (`security_policy.md`)

This document defines the zero-trust security policy rules, compliance framework mappings (SOC2, ISO 27001, OWASP Agentic Top 10, HIPAA, GDPR, PCI-DSS), specially banned commands, and automated enforcement mechanisms enforced by the AgentGuard daemon.

---

## Phase 1: Core System & Infrastructure Protection (Preventing Catastrophic Wipeout)

### Root & Top-Level System Deletion Block (`SOC2-CC6.1` / `ISO27001-A.12.1.2`)
- **Rule:** Unconditionally block recursive forced deletions (`rm -rf`, `rm -fr`, `unlink`) targeting critical system paths (`/`, `/etc`, `/usr`, `/var`, `~/.ssh`, `~/.aws`, `~/.env`, `.env`) regardless of agent taint state.
- **Why:** Prevents a runaway agent, malicious LLM code generation, or injected tool call from wiping out development machines or production server disks.

### Raw Block Device & Disk Formatting Guard (`SOC2-CC6.8`)
- **Rule:** Block any execution of `mkfs`, `dd if=... of=/dev/...`, direct redirections into block devices (`> /dev/sda`), or partition table modifications (`fdisk`, `parted`).
- **Why:** Eliminates low-level storage destruction vectors and prevents permanent hardware-level data loss.

---

## Phase 2: Data Exfiltration & Network Boundary Defense (OWASP ASI01 / ASI03)

### Tainted Session Network Egress Lockdown (`SOC2-CC6.6` / `OWASP-ASI01` / `OWASP-ASI03`)
- **Rule:** When an agent session is marked `TAINTED` (automatically triggered upon fetching external web content via `curl`, `wget`, or cloning untrusted public git repositories), strictly block outbound network connections (`curl`, `wget`, `nc`, `netcat`, `ssh`, `scp`, `ftp`) to non-whitelisted external domains.
- **Why:** Stops attackers from using indirect prompt injection to smuggle environment variables, secret tokens, or private source code out to third-party endpoints.

### Secret Vault In-Flight Redaction & Shielding (`PCI-DSS-Req6.5` / `GDPR-Art32`)
- **Rule:** Intercept all LLM prompts and command-line tool calls containing high-entropy strings, OpenAI/Anthropic/GitHub API keys, or database credentials, replacing them with ephemeral tokens (`<AG_VAULT_TOKEN_xx>`) in RAM, and allowing detokenization only for whitelisted official APIs (`api.openai.com`, `api.anthropic.com`).
- **Why:** Prevents credentials from leaking to third-party telemetry, log aggregators, or model providers.

---

## Phase 3: RAG & Long-Term Memory Guard (OWASP ASI06)

### Sleeper Prompt Injection Write Quarantine (`OWASP-ASI06`)
- **Rule:** Inspect all chunk writes to vector databases or shared memory collections. Automatically quarantine any content containing conditional trigger phrases ("whenever the user asks..."), role/boundary spoofing (`[SYSTEM NOTE]`), or zero-width unicode stealth characters with a risk score >= 0.65.
- **Why:** Prevents malicious actors from embedding latent triggers into vector stores that activate in future agent sessions.

### Read-Time Taint Inheritance (`OWASP-ASI06`)
- **Rule:** Propagate `UNTRUSTED_WEB` taint to clean agent sessions reading chunks from untrusted/tainted sessions.
- **Why:** Ensures indirect prompt injection cannot spread laterally across agent memory collections without tainting consuming agents.

---

## Phase 4: Change Management & Environment Isolation (SOC2 / ISO 27001)

### Production Environment Privilege Escalation Lockout (`SOC2-CC6.1` / `ISO27001-A.9.4.2`)
- **Rule:** In production environments (`environment in ['production', 'prod']`), block `sudo`, `su`, and file permission overrides (`chmod 777`, `chmod +s`, `chown root`).
- **Why:** Enforces the principle of least privilege under SOC2 CC6.1 and prevents unauthorized administrative takeovers.

### Off-Hours Production Service Alteration Control (`ISO27001-A.12.1.2` / `SOC2-CC6.8`)
- **Rule:** Service control commands (`systemctl restart`, `docker stop`, `kubectl delete`) targeting production outside business hours (08:00–18:00) require operator approval (`REQUIRE_HITL`).
- **Why:** Prevents unauthorized or unmonitored production outages during unattended hours.

---

## Specially Banned Commands

Users can define custom banned command names, arguments, or binaries in this section. The AgentGuard PolicyEngine parses each bullet item below into an unconditional `BLOCK` rule:

- `nmap`
- `wireshark`
- `tcpdump`
- `nc -l`

---

## Declarative Policy Configuration

The following declarative policy block is loaded automatically by the AgentGuard `PolicyEngine`:

```yaml
version: "1.0"
name: enterprise-security-policy
description: AgentGuard enterprise security policy covering Phases 1 through 4 under SOC2, ISO 27001, OWASP ASI, HIPAA, and GDPR.

policies:
  # -------------------------------------------------------------------------
  # Phase 1: Core System & Infrastructure Protection
  # -------------------------------------------------------------------------
  - id: rule-catastrophic-deletion-block
    name: Root and Top-Level System Deletion Block
    description: Unconditionally blocks recursive forced deletions targeting critical system paths regardless of taint state.
    priority: 10
    match:
      profiles:
        - "*"
      command_patterns:
        - '(?i)\brm\s+-[a-zA-Z]*[rf][a-zA-Z]*\s+.*?(?:/(?:\s|$)|/etc\b|/usr\b|/var\b|~?/\.ssh\b|~?/\.aws\b|~?/\.env\b|\.env\b)'
        - '(?i)\brm\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+.*?(?:/(?:\s|$)|/etc\b|/usr\b|/var\b|~?/\.ssh\b|~?/\.aws\b|~?/\.env\b|\.env\b)'
        - '(?i)\brm\s+-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*\s+.*?(?:/(?:\s|$)|/etc\b|/usr\b|/var\b|~?/\.ssh\b|~?/\.aws\b|~?/\.env\b|\.env\b)'
        - '(?i)\bunlink\s+(?:/(?:\s|$)|/etc\b|/usr\b|/var\b|~?/\.ssh\b|~?/\.aws\b|~?/\.env\b)'
    conditions: []
    action: BLOCK
    compliance_tags:
      - "SOC2-CC6.1"
      - "ISO27001-A.12.1.2"
    message: "SOC2-CC6.1 / ISO27001-A.12.1.2 violation: Recursive forced deletion of critical system directory is strictly prohibited."

  - id: rule-raw-block-device-guard
    name: Raw Block Device and Disk Formatting Guard
    description: Blocks any execution of mkfs, dd writing to block devices, or direct redirection into raw storage.
    priority: 15
    match:
      profiles:
        - "*"
      command_patterns:
        - '(?i)\bmkfs(?:\.\w+)?\s+'
        - '(?i)\bdd\s+.*?\bof=/dev/'
        - '(?i)>\s*/dev/(?:sd[a-z]|nvme\d|hd[a-z]|vd[a-z]|disk\d|rdisk\d)'
        - '(?i)\bfdisk\s+'
        - '(?i)\bparted\s+'
    conditions: []
    action: BLOCK
    compliance_tags:
      - "SOC2-CC6.8"
    message: "SOC2-CC6.8 violation: Low-level disk formatting or direct block device writing is strictly prohibited."

  # -------------------------------------------------------------------------
  # Phase 2: Data Exfiltration & Network Boundary Defense
  # -------------------------------------------------------------------------
  - id: rule-soc2-tainted-boundary-egress
    name: Prevent Data Exfiltration on Tainted Sessions
    description: Blocks outbound network egress commands when an agent has ingested untrusted content under SOC2 CC6.6.
    priority: 20
    match:
      taint_states:
        - "TAINTED"
      command_patterns:
        - 'curl\s+'
        - 'wget\s+'
        - 'nc\s+'
        - 'netcat\s+'
        - 'ssh\s+'
        - 'scp\s+'
        - 'ftp\s+'
    conditions: []
    action: BLOCK
    compliance_tags:
      - "SOC2-CC6.6"
      - "ISO27001-A.12.1.2"
      - "OWASP-ASI01"
      - "OWASP-ASI03"
    message: "SOC2-CC6.6 violation: Outbound network egress blocked on tainted session to prevent exfiltration."

  - id: rule-secret-vault-pii-redaction
    name: Secret Vault In-Flight Redaction and Shielding
    description: Intercepts LLM prompts and CLI tool calls containing high-entropy strings, API keys, or database credentials, replacing them with ephemeral tokens in RAM.
    priority: 30
    match:
      tools:
        - "*"
      command_patterns:
        - '(?i)(?:sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{20,}|bearer\s+[a-zA-Z0-9_\-\.]{20,}|password\s*=|token\s*=|api[_-]?key\s*=|postgres://|mysql://|mongodb://)'
    conditions: []
    action: REDACT_PII
    compliance_tags:
      - "PCI-DSS-Req6.5"
      - "GDPR-Art32"
    message: "PCI-DSS-Req6.5 / GDPR-Art32 safeguard: Secret tokens and sensitive credentials shielded in flight."

  # -------------------------------------------------------------------------
  # Phase 3: RAG & Long-Term Memory Guard
  # -------------------------------------------------------------------------
  - id: rule-owasp-memory-poison-guard
    name: Sleeper Prompt Injection Write Quarantine
    description: Inspects all chunk writes to vector databases or shared memory collections, automatically quarantining sleeper triggers or zero-width unicode characters.
    priority: 40
    match:
      tools:
        - "save_memory"
        - "write_memory"
        - "add_chunk"
        - "upsert_vector"
        - "store_knowledge"
      command_patterns:
        - '(?i)(?:whenever the user asks|\[?system note\]?:?|\u200B|\u200C|\u200D|ignore previous instructions)'
    conditions: []
    action: BLOCK
    compliance_tags:
      - "OWASP-ASI06"
    message: "OWASP-ASI06 violation: Sleeper prompt injection detected in memory chunk write."

  # -------------------------------------------------------------------------
  # Phase 4: Change Management & Environment Isolation
  # -------------------------------------------------------------------------
  - id: rule-soc2-privilege-escalation
    name: Restrict Privilege Escalation in Production
    description: Prohibits sudo, root switching, and sensitive permission tampering in production environments under SOC2 CC6.1.
    priority: 50
    match:
      profiles:
        - "*"
      command_patterns:
        - 'sudo\s+'
        - 'su\s+-?'
        - 'chmod\s+(?:-R\s+)?777'
        - 'chmod\s+\+s'
        - 'chown\s+root'
    conditions:
      - "environment in ['production', 'prod']"
    action: BLOCK
    compliance_tags:
      - "SOC2-CC6.1"
      - "ISO27001-A.9.4.2"
    message: "SOC2-CC6.1 violation: Privilege escalation is strictly forbidden in production environments."

  - id: rule-iso27001-off-hours-change-control
    name: Off-Hours Production Change Control
    description: Requires Human-in-the-Loop approval for production service alterations executed outside standard business hours under ISO 27001 A.12.1.2.
    priority: 60
    match:
      command_patterns:
        - 'systemctl\s+(?:restart|stop|reload|disable)'
        - 'service\s+\w+\s+(?:restart|stop|reload)'
        - 'docker\s+(?:rm|stop|kill)'
        - 'kubectl\s+(?:delete|apply|scale)'
    conditions:
      - "environment in ['production', 'prod']"
      - "after_hours"
    action: REQUIRE_HITL
    compliance_tags:
      - "ISO27001-A.12.1.2"
      - "SOC2-CC6.8"
    message: "ISO27001-A.12.1.2 violation: Off-hours production service alteration requires operator approval."

  # -------------------------------------------------------------------------
  # Additional Compliance: HIPAA & GDPR Articles
  # -------------------------------------------------------------------------
  - id: rule-hipaa-phi-pii-redaction
    name: HIPAA PHI and PII Protection
    description: Enforces technical safeguards and PII/PHI redaction on medical and confidential data queries under HIPAA 164.312.
    priority: 70
    match:
      tools:
        - "read_file"
        - "patient_query"
        - "fetch_records"
        - "db_query"
      command_patterns:
        - '(?i)(patient|health|medical|diagnosis|prescription|ssn|mrn|phi)'
    conditions:
      - "requires_data_classification"
    action: REDACT_PII
    compliance_tags:
      - "HIPAA-164.312"
      - "GDPR-Art32"
    message: "HIPAA-164.312 safeguard: Sensitive PII/PHI automatically redacted before agent consumption."

  - id: rule-gdpr-bulk-data-dump
    name: GDPR Bulk Data Dump Protection
    description: Blocks unrestricted bulk database exports and exfiltration attempts under GDPR Article 32.
    priority: 80
    match:
      command_patterns:
        - 'mysqldump\s+'
        - 'pg_dump\s+'
        - 'mongodump\s+'
        - 'sqlite3\s+.*\.dump'
    conditions:
      - "taint_state == TAINTED"
    action: BLOCK
    compliance_tags:
      - "GDPR-Art32"
      - "SOC2-CC6.6"
    message: "GDPR-Art32 violation: Bulk database extraction blocked on tainted agent session."
```
