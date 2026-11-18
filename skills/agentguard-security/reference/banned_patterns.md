# Banned Patterns & Dangerous Command Catalog

Reference list of commands and syntax patterns that pose critical risks when executed by autonomous AI agents.

---

## 1. High-Risk File System Commands

| Command Pattern | Risk Level | Reason |
|---|---|---|
| `rm -rf /` or `rm -fr /` | CRITICAL | Catastrophic deletion of host operating system |
| `rm -rf ~` or `rm -rf $HOME` | CRITICAL | Deletion of user profile, configurations, and keys |
| `rm -rf /etc` or `/var` | CRITICAL | Destruction of system daemon configurations |
| `rm -rf .env` or `~/.ssh` | HIGH | Destruction or exposure of private keys & tokens |
| `chmod -R 777 /` | HIGH | Strips all security permissions across the system |

---

## 2. Unverified Remote Script Execution

| Command Pattern | Risk Level | Reason |
|---|---|---|
| `curl ... \| bash` | CRITICAL | Executes unverified remote payloads without AST validation |
| `curl ... \| sh` | CRITICAL | Bypasses local integrity checks and audit logs |
| `wget ... -O - \| bash` | CRITICAL | Direct piping of network streams into shell interpreter |

---

## 3. Storage & Low-Level Hardware Mutations

| Command Pattern | Risk Level | Reason |
|---|---|---|
| `mkfs.* /dev/...` | CRITICAL | Formats storage drives and causes irreversible data loss |
| `dd if=... of=/dev/...` | CRITICAL | Overwrites raw partition headers and master boot records |
| `> /dev/sda` | CRITICAL | Direct hardware block overwrite |

---

## 4. Lateral Network & Reverse Shells

| Command Pattern | Risk Level | Reason |
|---|---|---|
| `nc -e /bin/sh ...` | HIGH | Opens an interactive network shell |
| `bash -i >& /dev/tcp/...` | HIGH | Direct interactive reverse bash shell |
| `nmap -sS ...` | MEDIUM | Unauthorized network reconnaissance |
