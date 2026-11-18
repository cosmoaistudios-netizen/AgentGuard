# Recommended Agent Security Profiles

Default security profile baselines tailored for major AI agent platforms.

---

## 1. Claude Code (`claude-code.yaml`)

```yaml
name: claude-code
description: Security profile for Anthropic Claude Code CLI
shell:
  safe_commands:
    - ls
    - cat
    - grep
    - git
    - pwd
    - echo
  dangerous_patterns:
    - "rm\\s+-(?:r[fv]{1,2}|[fv]{1,2}r)"
    - "curl.*\\|\\s*(?:ba)?sh"
  block_tainted_only: true
  hitl_prompt: true
vault:
  enabled: true
  whitelisted_endpoints:
    - api.anthropic.com
    - github.com
```

---

## 2. Cursor (`cursor.yaml`)

```yaml
name: cursor
description: Security profile for Cursor Editor and background terminal processes
shell:
  safe_commands:
    - npm test
    - pytest
    - git status
    - git diff
  dangerous_patterns:
    - "sudo"
    - "mkfs"
  block_tainted_only: true
  hitl_prompt: false
vault:
  enabled: true
  whitelisted_endpoints:
    - api.openai.com
    - api.anthropic.com
```

---

## 3. Antigravity (`antigravity.yaml`)

```yaml
name: antigravity
description: Security profile for Antigravity autonomous multi-agent environments
shell:
  safe_commands:
    - ag status
    - git status
    - python -m unittest
  dangerous_patterns:
    - "rm\\s+-(?:r[fv]{1,2}|[fv]{1,2}r)"
    - "chmod\\s+777"
  block_tainted_only: true
  hitl_prompt: true
vault:
  enabled: true
  whitelisted_endpoints:
    - api.openai.com
    - api.anthropic.com
    - github.com
```
