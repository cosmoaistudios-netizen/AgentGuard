# Security Policy — AgentGuard

AgentGuard is an OS-level zero-trust security kernel and telemetry daemon designed specifically to supervise autonomous AI coding agents. We treat security, memory safety, and isolation as foundational invariants.

---

## 🛡️ Supported Versions

We provide security updates and patches for the following versions:

| Version | Supported | Security Maintenance |
|---|---|---|
| **2.0.x (Latest)** | ✅ Yes | Active patches and zero-day mitigations |
| 1.0.x | ❌ No | Deprecated |
| < 1.0 | ❌ No | Unsupported prototype builds |

---

## 🚨 Reporting a Vulnerability

If you discover a security vulnerability, side-channel leak, or sandbox escape within AgentGuard, please report it privately and responsibly. **Do NOT open a public GitHub issue.**

### Coordinated Disclosure Channels
* **Security Contact:** [cosmoaistudios@gmail.com](mailto:cosmoaistudios@gmail.com)
* **Response SLA:**
  * **Initial Triage:** Within **24 hours**
  * **Vulnerability Assessment & Severity Rating:** Within **48 hours**
  * **Patch Release & Security Advisory:** Within **7 business days** (or expedited for critical CVSS >= 8.5)

### What to Include in Your Report
To accelerate validation and remediation, please provide:
1. Detailed description of the vulnerability or sandbox evasion mechanism.
2. Affected AgentGuard version(s) and operating system (macOS, Linux, Windows Win32 / WSL2).
3. Minimal reproducible proof-of-concept (PoC) code or command sequence.
4. Any observed failure of the Taint DAG, Shell Shim, or In-Flight Secret Vault.
5. Impact assessment on the host operating system or adjacent process trees.

---

## 🔒 Zero-Trust Security Architecture & Guarantees

AgentGuard enforces a multi-layered defense-in-depth model across autonomous agent execution:

### 1. POSIX & Win32 Interception Boundary
* **Pre-Execution Shell Shims:** Intercepts shell execution before any binary touches the operating system using native C shims (`ag-sh`), dynamic linker hooks (`DYLD_INSERT_LIBRARIES` on macOS, `LD_PRELOAD` on Linux), and Windows `.cmd` batch wrappers.
* **Deterministic AST & Regex Classification:** Evaluates commands into `ALLOW`, `BLOCK`, `HITL` (Human-in-the-Loop required), or `AUDIT`. Safe read-only commands (`ls`, `cat`, `grep`) execute with sub-1.5ms latency; dangerous mutations (`rm -rf`, disk wipes, reverse shells) are intercepted and dropped.

### 2. Taint Provenance DAG
* **Dynamic Egress Lockdown:** Sessions that ingest untrusted public web or git content (`curl`, `wget`, `git clone`) inherit `TAINTED` status in a cryptographically tracked Directed Acyclic Graph (DAG). Outbound network egress to non-whitelisted destinations is terminated immediately to prevent data exfiltration.

### 3. In-Flight Secret Vaulting
* **Shannon Entropy Detection:** High-entropy credentials (OpenAI/Anthropic keys, AWS secrets, GitHub tokens, database connection URIs) are redacted in memory and replaced with synthetic `<AG_VAULT_TOKEN_xx>` tokens. Tokens are only detokenized at outbound proxy gates targeting authenticated, whitelisted API endpoints.

### 4. Vector DB & Memory Poisoning Quarantine
* **Sleeper Prompt Injection Defense:** Vector DB chunk writes are inspected for role spoofing, boundary breaking, and conditional trigger payloads (`risk score >= 0.65`). Malicious chunks are quarantined and stamped with SHA-256 provenance hashes.

### 5. Fail-Closed Guarantees
* High-risk commands requiring operator approval (`HITL`) automatically fail closed and are denied if an interactive prompt times out.
* The daemon and interception shims enforce safe state preservation if unexpected socket or process errors occur.

---

## 📋 Compliance Framework Mapping

AgentGuard is architected to align with international enterprise security standards:

| Compliance Standard | Requirement / Control | AgentGuard Enforcement Mechanism |
|---|---|---|
| **SOC2 Type II** | CC6.1 (Logical Access Controls) | Sudo lockout, privilege escalation blocking in production |
| **SOC2 Type II** | CC6.6 (Network Boundary Defense) | Dynamic egress lockdown on tainted sessions |
| **SOC2 Type II** | CC6.8 (Unauthorized Data Alteration) | Raw block device protection & destructive deletion guard |
| **ISO/IEC 27001** | A.9.4.2 (Secure Log-on Procedures) | Ephemeral secret tokenization in memory |
| **ISO/IEC 27001** | A.12.1.2 (Change Management) | Off-hours production service alteration safeguards |
| **OWASP Top 10 for LLMs** | LLM01 & LLM02 (Prompt Injection & Insecure Output) | AST shell classifier & dynamic taint propagation |
| **OWASP Top 10 for LLMs** | LLM06 (Sensitive Information Disclosure) | In-flight secret vault with selective detokenization |
| **OWASP Agentic AI** | ASI01 (Unauthorized Autonomous Actions) | Human-in-the-Loop (HITL) approval gate |
| **OWASP Agentic AI** | ASI03 (Lateral Agent Contagion) | Memory guard read-time taint inheritance |
| **OWASP Agentic AI** | ASI06 (Memory Poisoning & Sleeper Payloads) | Vector DB write inspection & SHA-256 integrity stamping |
| **PCI-DSS v4.0** | Req 6.5 (Software Vulnerability Defense) | Ephemeral credential masking in transit and RAM |
| **GDPR** | Art. 32 (Security of Processing) | PII redaction engine (SSN, MRN, phone, email) |

For rule-by-rule definitions and custom banned command overrides, refer to [`security_policy.md`](security_policy.md).

---

## 📜 Security Policy Maintenance

This policy is maintained by **Cosmo AI Studios** and reviewed with every minor and major release.
Copyright © 2026 Cosmo AI Studios. All rights reserved.
