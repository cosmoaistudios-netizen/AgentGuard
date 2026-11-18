# Agent Security Compliance Reference Matrix

This document maps autonomous AI agent security controls to international compliance standards.

---

## 1. SOC 2 Type II Alignment

* **CC6.1 (Logical Access Controls & Privilege Minimization):**
  - AI agents must not run with root/admin privileges in production environments.
  - Sudo, su, and setuid binaries must be blocked or require explicit Human-in-the-Loop (HITL) approval.
* **CC6.6 (Network Boundary Defense & Data Exfiltration):**
  - Agents ingesting external unverified data (via curl, git clone, or web scraping) must enter a tainted state.
  - Outbound egress from tainted sessions must be restricted to authenticated, whitelisted domains.
* **CC6.8 (Unauthorized Data Alteration):**
  - Unconditional blocking of destructive system deletions (`rm -rf /`, `/etc`, `~/.ssh`).
  - Protection of raw block storage devices from formatting (`mkfs`, `fdisk`, `dd`).

---

## 2. ISO/IEC 27001:2022 Alignment

* **A.9.4.2 (Secure Log-on & Credential Handling):**
  - In-flight masking of secrets, API tokens, and database passwords.
  - Replacement of plaintext keys with ephemeral tokens in memory buffers.
* **A.12.1.2 (Change Management & System Protection):**
  - Restricting disruptive operations (container termination, database dropping) during unattended or off-business hours.

---

## 3. OWASP Top 10 for LLMs & Agentic AI

* **LLM01 / ASI01 (Unauthorized Autonomous Actions):**
  - Requiring operator confirmation before executing destructive commands.
* **LLM06 (Sensitive Information Disclosure):**
  - Real-time entropy scanning detecting high-entropy keys before they are sent to LLM endpoints.
* **ASI06 (Memory Poisoning & Sleeper Payloads):**
  - Sanitization of vector database writes to prevent latent trigger phrases from compromising future agent sessions.

---

## 4. PCI-DSS v4.0 & GDPR Article 32

* **Requirement 6.5:** Protection of software applications from injection attacks and credential leakage.
* **Article 32:** Technical measures ensuring ongoing confidentiality, integrity, and resilience of data processing systems.
