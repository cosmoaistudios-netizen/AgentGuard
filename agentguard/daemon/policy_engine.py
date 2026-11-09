"""
AgentGuard Enterprise Policy Governance Engine.

Provides declarative policy-as-code enforcement mapping agent behavior
to major compliance frameworks (SOC2, HIPAA, ISO 27001, GDPR, PCI-DSS):
1. Declarative YAML Policy Schema:
   - Match selectors: agent profile, session taint state, tool name, command patterns.
   - Dynamic conditions: time-of-day, environment checks, data classification tags.
   - Enforcement actions: ALLOW, BLOCK, REQUIRE_HITL, REDACT_PII.
   - Compliance traceability: maps violations directly to framework clauses (e.g. SOC2-CC6.1).
2. Sub-2ms Rule Evaluation Engine:
   - Safe, deterministic AST condition evaluator without unsafe eval().
   - Pre-compiled regex match caches and priority ordering.
3. Integrated Audit Logging:
   - Emits structured audit events carrying compliance tags for enterprise compliance pipelines.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, time as dtime
from enum import Enum
import json
import os
from pathlib import Path
import re
import time
from typing import Any, Dict, List, Optional, Set, Tuple, Union
import yaml

from agentguard.daemon.audit import AuditLogger


class PolicyAction(str, Enum):
    """Enforcement action prescribed by a policy rule."""
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REQUIRE_HITL = "REQUIRE_HITL"
    REDACT_PII = "REDACT_PII"


class ComplianceFrameworkTag(str, Enum):
    """Standardized enterprise compliance framework requirement clauses."""
    SOC2_CC6_1 = "SOC2-CC6.1"          # Logical Access and Privilege Controls
    SOC2_CC6_6 = "SOC2-CC6.6"          # Network Boundary Protection and Egress
    SOC2_CC6_8 = "SOC2-CC6.8"          # Change Management and Unauthorized Alterations
    HIPAA_164_312 = "HIPAA-164.312"    # Technical Safeguards & PHI Protection
    ISO27001_A12_1_2 = "ISO27001-A.12.1.2"  # Change Management
    ISO27001_A9_4_2 = "ISO27001-A.9.4.2"    # Secure Log-on & Privilege Restrictions
    GDPR_ART32 = "GDPR-Art32"          # Security of Processing & Exfiltration
    PCI_DSS_REQ6_5 = "PCI-DSS-Req6.5"  # Insecure Coding & Injection Vulnerabilities
    OWASP_ASI01 = "OWASP-ASI01"        # Goal Hijacking & Execution Boundary Egress
    OWASP_ASI03 = "OWASP-ASI03"        # Supply Chain & Exfiltration
    OWASP_ASI06 = "OWASP-ASI06"        # Long-Term Memory & Context Poisoning


# High-precision PII detection regex patterns
PII_PATTERNS = {
    "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "CREDIT_CARD": re.compile(r"\b(?:\d{4}[ -]?){3}\d{4}\b"),
    "EMAIL": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
    "PHONE": re.compile(r"\b(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]?\d{3}[-. ]?\d{4}\b"),
    "MRN": re.compile(r"\b(?:MRN-\d{6,}|PATIENT[-_]\d{5,})\b", re.IGNORECASE),
}


def redact_pii_text(text: str) -> Tuple[str, bool, List[str]]:
    """
    Redacts personal identifiable information (PII/PHI) from raw text.
    Returns: (redacted_text, was_modified, list_of_redacted_categories)
    """
    if not text:
        return text, False, []

    redacted = text
    modified = False
    detected_categories: List[str] = []

    for cat_name, pat in PII_PATTERNS.items():
        if pat.search(redacted):
            redacted = pat.sub(f"<REDACTED_PII:{cat_name}>", redacted)
            modified = True
            detected_categories.append(cat_name)

    return redacted, modified, detected_categories


@dataclass
class RuleMatchCriteria:
    """Selectors determining whether an action falls within the scope of a rule."""
    profiles: List[str] = field(default_factory=lambda: ["*"])
    taint_states: List[str] = field(default_factory=lambda: ["*"])
    tools: List[str] = field(default_factory=lambda: ["*"])
    command_patterns: List[str] = field(default_factory=list)
    actions: List[str] = field(default_factory=lambda: ["*"])
    _compiled_patterns: List[re.Pattern] = field(default_factory=list, repr=False)

    def __post_init__(self):
        compiled: List[re.Pattern] = []
        for p in self.command_patterns:
            if not p:
                continue
            try:
                compiled.append(re.compile(p))
            except re.error:
                compiled.append(re.compile(re.escape(str(p))))
        self._compiled_patterns = compiled

    def matches(self, session_ctx: Dict[str, Any], action_ctx: Dict[str, Any]) -> bool:
        """Evaluates whether the combined contexts match all defined selectors."""
        # 1. Profile selector
        if self.profiles and "*" not in self.profiles:
            sess_profile = session_ctx.get("profile", "").lower()
            if not any(sess_profile == p.lower() for p in self.profiles):
                return False

        # 2. Taint state selector
        if self.taint_states and "*" not in self.taint_states:
            sess_taint = session_ctx.get("taint", session_ctx.get("taint_state", "CLEAN")).upper()
            if not any(sess_taint == t.upper() for t in self.taint_states):
                return False

        # 3. Tool selector
        if self.tools and "*" not in self.tools:
            act_tool = action_ctx.get("tool", action_ctx.get("tool_name", "")).lower()
            if not any(act_tool == t.lower() for t in self.tools):
                return False

        # 4. Action type selector
        if self.actions and "*" not in self.actions:
            act_type = action_ctx.get("action_type", action_ctx.get("action", "")).upper()
            if not any(act_type == a.upper() for a in self.actions):
                return False

        # 5. Command patterns
        if self._compiled_patterns:
            cmd = action_ctx.get("command", "")
            if isinstance(cmd, dict):
                cmd = json.dumps(cmd)
            elif not isinstance(cmd, str):
                cmd = str(cmd)
            if not any(pat.search(cmd) for pat in self._compiled_patterns):
                return False

        return True


@dataclass
class PolicyRule:
    """Individual declarative policy rule definition."""
    id: str
    name: str
    description: str = ""
    enabled: bool = True
    priority: int = 100
    match: RuleMatchCriteria = field(default_factory=RuleMatchCriteria)
    conditions: List[str] = field(default_factory=list)
    action: PolicyAction = PolicyAction.BLOCK
    compliance_tags: List[str] = field(default_factory=list)
    message: str = "Policy enforcement triggered."
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PolicyDecision:
    """Evaluation result returned by PolicyEngine for an action."""
    action: PolicyAction
    allowed: bool
    rule_id: Optional[str]
    rule_name: str
    reason: str
    compliance_tags: List[str]
    pii_redacted: bool = False
    redacted_content: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    evaluation_time_ms: float = 0.0

    def is_blocked(self) -> bool:
        return self.action == PolicyAction.BLOCK

    def requires_hitl(self) -> bool:
        return self.action == PolicyAction.REQUIRE_HITL

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action.value,
            "allowed": self.allowed,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "reason": self.reason,
            "compliance_tags": self.compliance_tags,
            "pii_redacted": self.pii_redacted,
            "evaluation_time_ms": round(self.evaluation_time_ms, 3),
            "metadata": self.metadata,
        }


def evaluate_condition_expression(
    expr: str, session_ctx: Dict[str, Any], action_ctx: Dict[str, Any]
) -> bool:
    """
    Evaluates safe deterministic expressions in <0.05ms without Python eval().
    Supports:
    - time_of_day outside 08:00-18:00, time_of_day in 09:00-17:00, after_hours, is_weekend
    - environment == production, environment in ['production', 'prod'], env != dev
    - requires_data_classification (truthy check)
    - key comparisons: ==, !=, in, not in
    """
    clean_expr = expr.strip()
    if not clean_expr:
        return True

    # Combine contexts for variable lookups
    ctx = {**session_ctx, **action_ctx}

    # 1. After Hours / Off-Hours Condition
    if clean_expr.lower() in ("after_hours", "off_hours", "is_after_hours"):
        if "after_hours" in ctx:
            val = ctx["after_hours"]
            return bool(val) and str(val).lower() not in ("false", "0", "")
        if "off_hours" in ctx:
            val = ctx["off_hours"]
            return bool(val) and str(val).lower() not in ("false", "0", "")
        now_time = datetime.now().time()
        start_biz = dtime(8, 0)
        end_biz = dtime(18, 0)
        is_weekday = datetime.now().weekday() < 5
        return (not is_weekday) or (now_time < start_biz or now_time > end_biz)

    # 2. Weekend Condition
    if clean_expr.lower() in ("weekend", "is_weekend"):
        if "weekend" in ctx:
            val = ctx["weekend"]
            return bool(val) and str(val).lower() not in ("false", "0", "")
        if "is_weekend" in ctx:
            val = ctx["is_weekend"]
            return bool(val) and str(val).lower() not in ("false", "0", "")
        return datetime.now().weekday() >= 5

    # 3. Requires Data Classification
    if clean_expr.lower() == "requires_data_classification":
        val = ctx.get("data_classification", ctx.get("requires_data_classification", ctx.get("sensitivity", "")))
        return bool(val) and str(val).lower() not in ("public", "unclassified", "false", "0", "")

    # 4. Time of Day range expression: e.g. "time_of_day outside 08:00-18:00" or "time_of_day in 09:00-17:00"
    tod_outside = re.match(r"^time_of_day\s+outside\s+(\d{1,2}:\d{2})-(\d{1,2}:\d{2})$", clean_expr, re.IGNORECASE)
    if tod_outside:
        start_str, end_str = tod_outside.groups()
        now_time = datetime.now().time()
        s_h, s_m = map(int, start_str.split(":"))
        e_h, e_m = map(int, end_str.split(":"))
        t_start, t_end = dtime(s_h, s_m), dtime(e_h, e_m)
        return now_time < t_start or now_time > t_end

    tod_in = re.match(r"^time_of_day\s+in\s+(\d{1,2}:\d{2})-(\d{1,2}:\d{2})$", clean_expr, re.IGNORECASE)
    if tod_in:
        start_str, end_str = tod_in.groups()
        now_time = datetime.now().time()
        s_h, s_m = map(int, start_str.split(":"))
        e_h, e_m = map(int, end_str.split(":"))
        t_start, t_end = dtime(s_h, s_m), dtime(e_h, e_m)
        return t_start <= now_time <= t_end

    # 5. List Membership: e.g. "environment in ['production', 'prod']"
    in_match = re.match(r"^([a-zA-Z0-9_]+)\s+in\s+\[(.*)\]$", clean_expr)
    if in_match:
        var_name, items_str = in_match.groups()
        val = str(ctx.get(var_name, "")).strip().lower()
        items = [i.strip(" '\"").lower() for i in items_str.split(",") if i.strip()]
        return val in items

    # 6. Not in list: e.g. "environment not in ['dev', 'test']"
    not_in_match = re.match(r"^([a-zA-Z0-9_]+)\s+not\s+in\s+\[(.*)\]$", clean_expr)
    if not_in_match:
        var_name, items_str = not_in_match.groups()
        val = str(ctx.get(var_name, "")).strip().lower()
        items = [i.strip(" '\"").lower() for i in items_str.split(",") if i.strip()]
        return val not in items

    # 7. Direct equality: e.g. "environment == production" or "taint_state == TAINTED"
    eq_match = re.match(r"^([a-zA-Z0-9_]+)\s*==\s*(['\"]?)(.*?)\2$", clean_expr)
    if eq_match:
        var_name, _, target_val = eq_match.groups()
        actual_val = str(ctx.get(var_name, "")).strip().lower()
        return actual_val == target_val.strip().lower()

    # 8. Inequality: e.g. "environment != dev"
    neq_match = re.match(r"^([a-zA-Z0-9_]+)\s*!=\s*(['\"]?)(.*?)\2$", clean_expr)
    if neq_match:
        var_name, _, target_val = neq_match.groups()
        actual_val = str(ctx.get(var_name, "")).strip().lower()
        return actual_val != target_val.strip().lower()

    # 9. Simple existence / boolean flag
    val = ctx.get(clean_expr)
    if val is not None:
        return bool(val) and str(val).lower() not in ("false", "0", "")

    return False


def parse_markdown_policy(content: str) -> Dict[str, Any]:
    """
    Parses an enterprise security policy from a Markdown document (e.g., security_policy.md).

    Capabilities:
    1. Extracts embedded YAML declarative policy blocks (```yaml ... ```) or YAML frontmatter (--- ... ---).
    2. Extracts user-defined "Specially Banned Commands" or "Custom Banned Commands" from markdown lists,
       automatically generating high-priority BLOCK policy rules.
    3. Parses structured markdown rule sections (### Rule: ..., - Action: ..., - Commands: ...).
    """
    if not content or not content.strip():
        return {"name": "empty-policy", "description": "", "policies": []}

    policy_data: Dict[str, Any] = {
        "name": "enterprise-security-policy",
        "description": "Enterprise Security Policy defined in security_policy.md",
        "policies": [],
    }

    # 1. YAML frontmatter check
    frontmatter_match = re.search(r"^---\s*\n(.*?)\n---", content, re.DOTALL)
    if frontmatter_match:
        try:
            fm_data = yaml.safe_load(frontmatter_match.group(1))
            if isinstance(fm_data, dict):
                policy_data["name"] = fm_data.get("name", policy_data["name"])
                policy_data["description"] = fm_data.get("description", policy_data["description"])
                fm_policies = fm_data.get("policies") or fm_data.get("rules", [])
                if isinstance(fm_policies, list):
                    policy_data["policies"].extend(fm_policies)
        except Exception:
            pass

    # 2. Embedded YAML code block check (```yaml ... ``` or ```yml ... ```)
    code_blocks = re.findall(r"```(?:yaml|yml)?\s*\n(.*?)\n```", content, re.DOTALL)
    for block in code_blocks:
        try:
            block_data = yaml.safe_load(block)
            if isinstance(block_data, dict):
                if "policies" in block_data or "rules" in block_data or "name" in block_data:
                    if "name" in block_data:
                        policy_data["name"] = block_data.get("name", policy_data["name"])
                    if "description" in block_data:
                        policy_data["description"] = block_data.get("description", policy_data["description"])
                    block_policies = block_data.get("policies") or block_data.get("rules", [])
                    if isinstance(block_policies, list):
                        policy_data["policies"].extend(block_policies)
        except Exception:
            continue

    # 3. Specially Banned Commands section check
    banned_section_match = re.search(
        r"(?:^|\n)#{1,4}\s*(?:[0-9.]+\s*)?(?:Specially\s+Banned|Custom\s+Banned|Banned\s+Commands|Blacklisted\s+Commands).*?\n([\s\S]*?)(?=(?:\n#{1,4}\s)|$)",
        content,
        re.IGNORECASE,
    )
    if banned_section_match:
        section_text = banned_section_match.group(1)
        raw_items = re.findall(r"^\s*[-*+]\s+(?:`([^`]+)`|([^\n\r]+))", section_text, re.MULTILINE)
        extracted_cmds: List[str] = []
        for backticked, plain in raw_items:
            item = (backticked or plain).strip()
            # Ignore markdown comments or notes
            if item and not item.startswith(("#", "//", "<!--", "Note:", "e.g.", "*", ">")):
                extracted_cmds.append(item)

        if extracted_cmds:
            cmd_patterns: List[str] = []
            for c in extracted_cmds:
                if any(ch in c for ch in r"^$.*+?{}[]\|()"):
                    cmd_patterns.append(c)
                else:
                    cmd_patterns.append(rf"(?i)(?:^|[;&|\s]){re.escape(c)}(?:$|[;&|\s])")

            existing = next(
                (r for r in policy_data["policies"] if r.get("id") == "rule-user-banned-commands"),
                None,
            )
            if existing:
                existing_pats = existing.setdefault("match", {}).setdefault("command_patterns", [])
                for p in cmd_patterns:
                    if p not in existing_pats:
                        existing_pats.append(p)
            else:
                policy_data["policies"].append({
                    "id": "rule-user-banned-commands",
                    "name": "User-Defined Specially Banned Commands",
                    "description": "Specially banned commands defined by operator in security_policy.md",
                    "priority": 5,
                    "match": {
                        "command_patterns": cmd_patterns,
                    },
                    "conditions": [],
                    "action": "BLOCK",
                    "compliance_tags": ["SOC2-CC6.1", "ISO27001-A.12.1.2"],
                    "message": "Security policy violation: Executing specially banned command defined in security_policy.md.",
                })

    # 4. Structured Markdown Rule sections check (### Rule: Name ...)
    rule_blocks = re.findall(
        r"(?:^|\n)#{2,4}\s*Rule:\s*([^\n]+)\n([\s\S]*?)(?=(?:\n#{2,4}\s*Rule:)|(?:\n#{1,2}\s)|$)",
        content,
    )
    for rule_title, body in rule_blocks:
        r_id = re.sub(r"[^a-zA-Z0-9_\-]", "-", rule_title.lower()).strip("-")
        id_match = re.search(r"[-*]\s*ID:\s*([a-zA-Z0-9_\-]+)", body, re.IGNORECASE)
        if id_match:
            r_id = id_match.group(1).strip()
        if any(r.get("id") == r_id for r in policy_data["policies"]):
            continue

        action_match = re.search(r"[-*]\s*Action:\s*(\w+)", body, re.IGNORECASE)
        act_str = action_match.group(1).upper() if action_match else "BLOCK"

        priority_match = re.search(r"[-*]\s*Priority:\s*(\d+)", body, re.IGNORECASE)
        priority_val = int(priority_match.group(1)) if priority_match else 100

        compliance_match = re.search(r"[-*]\s*Compliance(?:\s*Tags)?:\s*([^\n]+)", body, re.IGNORECASE)
        compliance_tags = (
            [t.strip() for t in compliance_match.group(1).split(",") if t.strip()]
            if compliance_match
            else []
        )

        message_match = re.search(r"[-*]\s*(?:Message|Why):\s*([^\n]+)", body, re.IGNORECASE)
        msg_str = (
            message_match.group(1).strip()
            if message_match
            else f"Policy rule [{rule_title.strip()}] triggered."
        )

        cond_match = re.search(r"[-*]\s*Conditions?:\s*([^\n]+)", body, re.IGNORECASE)
        conditions = [cond_match.group(1).strip()] if cond_match else []

        cmds_section = re.search(
            r"[-*]\s*Commands?:\s*\n?([\s\S]*?)(?=(?:\n[-*]\s*\w+:)|$)",
            body,
            re.IGNORECASE,
        )
        cmd_pats: List[str] = []
        if cmds_section:
            bullets = re.findall(
                r"^\s*[-*+]\s+(?:`([^`]+)`|([^\n\r]+))",
                cmds_section.group(1),
                re.MULTILINE,
            )
            for backticked, plain in bullets:
                c = (backticked or plain).strip()
                if c:
                    cmd_pats.append(c)

        policy_data["policies"].append({
            "id": r_id,
            "name": rule_title.strip(),
            "description": msg_str,
            "priority": priority_val,
            "match": {
                "command_patterns": cmd_pats,
            },
            "conditions": conditions,
            "action": act_str,
            "compliance_tags": compliance_tags,
            "message": msg_str,
        })

    return policy_data


def get_default_policy_file_path() -> Path:
    """Resolves standard security_policy.md or policy.yaml file path location."""
    # 1. Explicit environment variable
    env_policy = os.environ.get("AGENTGUARD_POLICY")
    if env_policy:
        cand = Path(env_policy)
        if cand.is_file():
            return cand

    # 2. User directory (~/.agentguard/)
    user_policy_md = Path.home() / ".agentguard" / "security_policy.md"
    if user_policy_md.is_file():
        return user_policy_md

    user_path = Path.home() / ".agentguard" / "policy.yaml"
    if user_path.is_file():
        return user_path

    # 3. Built-in enterprise default template
    pkg_root = Path(__file__).resolve().parent.parent
    builtin_path = pkg_root / "profiles" / "enterprise_default.yaml"
    if builtin_path.exists():
        return builtin_path

    return user_path


class PolicyEngine:
    """
    Enterprise Policy Governance and Compliance Engine.

    Evaluates agent actions against declarative policy rules in sub-2ms,
    enforcing zero-trust compliance gates (SOC2, HIPAA, ISO 27001, GDPR).
    """

    def __init__(
        self,
        policy_path: Optional[Union[str, Path]] = None,
        audit_logger: Optional[AuditLogger] = None,
        fallback_to_default: bool = True,
    ):
        self.audit_logger = audit_logger or AuditLogger()
        self.policy_path = Path(policy_path) if policy_path else get_default_policy_file_path()
        self.fallback_to_default = fallback_to_default
        self.name = "default-policy"
        self.description = ""
        self.rules: List[PolicyRule] = []

        self.load_policy()

    def load_policy(self, custom_path: Optional[Union[str, Path]] = None) -> bool:
        """Loads and parses declarative YAML policy rules from disk."""
        target_path = Path(custom_path) if custom_path else self.policy_path

        # If user policy does not exist, fallback to built-in enterprise template
        if not target_path.exists():
            pkg_root = Path(__file__).resolve().parent.parent
            builtin_path = pkg_root / "profiles" / "enterprise_default.yaml"
            if builtin_path.exists():
                target_path = builtin_path
            else:
                self.rules = []
                return False

        try:
            content = target_path.read_text(encoding="utf-8")
            if target_path.suffix.lower() == ".md" or "```" in content or "\n# " in content or "\n## " in content:
                data = parse_markdown_policy(content)
            else:
                data = yaml.safe_load(content)
                if not isinstance(data, dict):
                    data = parse_markdown_policy(content)
        except Exception as exc:
            self.audit_logger.log(
                "POLICY_LOAD_ERROR",
                details={"path": str(target_path), "error": str(exc)},
            )
            return False

        if not isinstance(data, dict):
            return False

        self.name = data.get("name", target_path.stem)
        self.description = data.get("description", "")
        raw_rules = data.get("policies") or data.get("rules", [])

        loaded_rules: List[PolicyRule] = []
        for r in raw_rules:
            if not isinstance(r, dict) or not r.get("id"):
                continue

            match_dict = r.get("match", {})
            criteria = RuleMatchCriteria(
                profiles=match_dict.get("profiles", ["*"]),
                taint_states=match_dict.get("taint_states", ["*"]),
                tools=match_dict.get("tools", ["*"]),
                command_patterns=match_dict.get("command_patterns", []),
                actions=match_dict.get("actions", ["*"]),
            )

            action_val = str(r.get("action", "BLOCK")).upper()
            try:
                action_enum = PolicyAction(action_val)
            except ValueError:
                action_enum = PolicyAction.BLOCK

            rule = PolicyRule(
                id=r.get("id", ""),
                name=r.get("name", r.get("id", "")),
                description=r.get("description", ""),
                enabled=r.get("enabled", True),
                priority=int(r.get("priority", 100)),
                match=criteria,
                conditions=r.get("conditions", []),
                action=action_enum,
                compliance_tags=r.get("compliance_tags", []),
                message=r.get("message", "Policy rule triggered."),
                metadata=r.get("metadata", {}),
            )
            loaded_rules.append(rule)

        # Sort by priority ascending (lower number evaluates first)
        loaded_rules.sort(key=lambda x: x.priority)
        self.rules = loaded_rules
        self.policy_path = target_path
        return True

    def reload_policy(self) -> bool:
        """Hot-reloads the active policy configuration file."""
        return self.load_policy(self.policy_path)

    def add_rule(self, rule: PolicyRule) -> None:
        """Programmatically appends a policy rule."""
        self.rules.append(rule)
        self.rules.sort(key=lambda x: x.priority)

    def evaluate_policy(
        self,
        session_context: Dict[str, Any],
        action_context: Dict[str, Any],
    ) -> PolicyDecision:
        """
        Executes sub-2ms deterministic rule evaluation against incoming action.

        Returns PolicyDecision indicating action (ALLOW, BLOCK, REQUIRE_HITL, REDACT_PII)
        and associated compliance tags.
        """
        t0 = time.perf_counter()

        for rule in self.rules:
            if not rule.enabled:
                continue

            # Step 1: Match selectors check
            if not rule.match.matches(session_context, action_context):
                continue

            # Step 2: Conditions evaluation (logical AND across all conditions)
            conditions_met = True
            for cond in rule.conditions:
                if not evaluate_condition_expression(cond, session_context, action_context):
                    conditions_met = False
                    break

            if not conditions_met:
                continue

            # Rule triggered! Compute execution elapsed time
            elapsed_ms = (time.perf_counter() - t0) * 1000.0

            # Step 3: Handle PII Redaction
            if rule.action == PolicyAction.REDACT_PII:
                raw_cmd = action_context.get("command", "")
                redacted_text, was_modified, categories = redact_pii_text(str(raw_cmd))
                return PolicyDecision(
                    action=PolicyAction.REDACT_PII,
                    allowed=True,
                    rule_id=rule.id,
                    rule_name=rule.name,
                    reason=rule.message,
                    compliance_tags=rule.compliance_tags,
                    pii_redacted=was_modified,
                    redacted_content=redacted_text,
                    metadata={"redacted_categories": categories, **rule.metadata},
                    evaluation_time_ms=elapsed_ms,
                )

            # Step 4: Handle BLOCK or REQUIRE_HITL or explicit ALLOW
            is_allowed = rule.action == PolicyAction.ALLOW

            return PolicyDecision(
                action=rule.action,
                allowed=is_allowed,
                rule_id=rule.id,
                rule_name=rule.name,
                reason=rule.message,
                compliance_tags=rule.compliance_tags,
                metadata=rule.metadata,
                evaluation_time_ms=elapsed_ms,
            )

        # Default fallback: If no rule triggers, permit action
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return PolicyDecision(
            action=PolicyAction.ALLOW,
            allowed=True,
            rule_id=None,
            rule_name="DefaultAllow",
            reason="No policy rules matched; default allow applied.",
            compliance_tags=[],
            evaluation_time_ms=elapsed_ms,
        )

    def get_compliance_matrix(self) -> Dict[str, List[str]]:
        """Maps each compliance framework tag to corresponding active policy rule names."""
        matrix: Dict[str, List[str]] = {}
        for r in self.rules:
            if not r.enabled:
                continue
            for tag in r.compliance_tags:
                matrix.setdefault(tag, []).append(r.name)
        return matrix

    def get_active_rules(self) -> List[Dict[str, Any]]:
        """Returns JSON-serializable list of loaded policy rules."""
        return [
            {
                "id": r.id,
                "name": r.name,
                "description": r.description,
                "action": r.action.value,
                "priority": r.priority,
                "compliance_tags": r.compliance_tags,
                "conditions": r.conditions,
                "enabled": r.enabled,
            }
            for r in self.rules
        ]
