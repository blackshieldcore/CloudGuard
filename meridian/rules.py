"""
meridian/rules.py
~~~~~~~~~~~~~~~~~
All IAM risk detection rules for Meridian.

Each rule is a function with signature:
    check_something(statement: dict, idx: int, filename: str) -> List[Finding]

Add new rules here and append to ALL_RULES — no other changes needed.

References:
  https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
"""

from meridian.core import Finding, normalize_to_list


# ──────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────

# Actions that enable privilege escalation
PRIVESC_ACTIONS = {
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:PassRole",
    "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile",
    "iam:AttachUserPolicy",
    "iam:AttachGroupPolicy",
    "iam:AttachRolePolicy",
    "iam:PutUserPolicy",
    "iam:PutGroupPolicy",
    "iam:PutRolePolicy",
    "iam:CreateAccessKey",
    "iam:UpdateAssumeRolePolicy",
    "sts:AssumeRole",
    "lambda:CreateFunction",
    "lambda:InvokeFunction",
    "lambda:UpdateFunctionCode",
    "ec2:RunInstances",
    "cloudformation:CreateStack",
}

# Actions that should always have conditions attached
CONDITION_REQUIRED_ACTIONS = {
    "s3:GetObject",
    "s3:PutObject",
    "s3:DeleteObject",
    "s3:ListBucket",
    "kms:Decrypt",
    "kms:Encrypt",
    "sts:AssumeRole",
}

# Service prefixes that represent high-blast-radius services
HIGH_RISK_SERVICES = {"iam", "sts", "organizations", "kms", "cloudtrail", "config"}


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

def extract_service(action: str) -> str:
    """Extract the service prefix from an action string (e.g., 'iam' from 'iam:PassRole')."""
    if ":" in action:
        return action.split(":")[0].lower()
    return action.lower()


# ──────────────────────────────────────────────
# Detection Rules — MR-001 through MR-007
# ──────────────────────────────────────────────

def check_admin_access(statement, idx, filename):
    """MR-001: Detects full admin access (Action: *, Resource: *)."""
    findings = []
    if statement.get("Effect") != "Allow":
        return findings

    actions = normalize_to_list(statement.get("Action", []))
    resources = normalize_to_list(statement.get("Resource", []))

    if "*" in actions and "*" in resources:
        findings.append(
            Finding(
                severity="CRITICAL",
                rule_id="MR-001",
                title="Full administrator access detected",
                detail=(
                    "Action: * with Resource: * grants unrestricted access to all AWS services "
                    "and resources. This is the most dangerous IAM pattern and should be avoided "
                    "except for break-glass accounts."
                ),
                policy_file=filename,
                statement_idx=idx,
            )
        )
    return findings


def check_wildcard_actions(statement, idx, filename):
    """MR-002: Detects wildcard actions on specific services (e.g., 's3:*')."""
    findings = []
    if statement.get("Effect") != "Allow":
        return findings

    actions = normalize_to_list(statement.get("Action", []))
    for action in actions:
        if action != "*" and action.endswith(":*"):
            service = extract_service(action)
            severity = "HIGH" if service in HIGH_RISK_SERVICES else "MEDIUM"
            findings.append(
                Finding(
                    severity=severity,
                    rule_id="MR-002",
                    title=f"Wildcard actions on {service} service",
                    detail=(
                        f"'{action}' grants all actions on the {service} service. "
                        f"Scope down to specific actions needed (least privilege)."
                    ),
                    policy_file=filename,
                    statement_idx=idx,
                )
            )
    return findings


def check_wildcard_resources(statement, idx, filename):
    """MR-003: Detects wildcard resources with specific actions."""
    findings = []
    if statement.get("Effect") != "Allow":
        return findings

    actions = normalize_to_list(statement.get("Action", []))
    resources = normalize_to_list(statement.get("Resource", []))

    if "*" in resources and "*" not in actions:
        action_list = ", ".join(actions[:5])
        if len(actions) > 5:
            action_list += f" (+{len(actions) - 5} more)"
        findings.append(
            Finding(
                severity="MEDIUM",
                rule_id="MR-003",
                title="Wildcard resource with specific actions",
                detail=(
                    f"Actions [{action_list}] are allowed on all resources (*). "
                    f"Restrict Resource to specific ARNs where possible."
                ),
                policy_file=filename,
                statement_idx=idx,
            )
        )
    return findings


def check_privilege_escalation(statement, idx, filename):
    """MR-004: Detects actions that enable privilege escalation."""
    findings = []
    if statement.get("Effect") != "Allow":
        return findings

    actions = normalize_to_list(statement.get("Action", []))
    for action in actions:
        if action in PRIVESC_ACTIONS:
            findings.append(
                Finding(
                    severity="HIGH",
                    rule_id="MR-004",
                    title=f"Privilege escalation path: {action}",
                    detail=(
                        f"The action '{action}' can be used to escalate privileges. "
                        f"An attacker with this permission could gain higher access than intended. "
                        f"Add conditions or restrict the resource scope."
                    ),
                    policy_file=filename,
                    statement_idx=idx,
                )
            )
    return findings


def check_missing_conditions(statement, idx, filename):
    """MR-005: Detects sensitive actions without condition constraints."""
    findings = []
    if statement.get("Effect") != "Allow":
        return findings

    actions = normalize_to_list(statement.get("Action", []))
    has_condition = bool(statement.get("Condition"))

    if not has_condition:
        for action in actions:
            if action in CONDITION_REQUIRED_ACTIONS:
                findings.append(
                    Finding(
                        severity="MEDIUM",
                        rule_id="MR-005",
                        title=f"Sensitive action without conditions: {action}",
                        detail=(
                            f"'{action}' is allowed without any Condition block. "
                            f"Consider adding conditions like source IP, MFA, or time-based restrictions."
                        ),
                        policy_file=filename,
                        statement_idx=idx,
                    )
                )
    return findings


def check_not_action(statement, idx, filename):
    """MR-006: Detects use of NotAction with Allow (inverse allow = broad access)."""
    findings = []
    if statement.get("Effect") == "Allow" and "NotAction" in statement:
        not_actions = normalize_to_list(statement.get("NotAction", []))
        findings.append(
            Finding(
                severity="HIGH",
                rule_id="MR-006",
                title="NotAction with Allow effect",
                detail=(
                    f"Using NotAction with Allow means 'allow everything EXCEPT {not_actions}'. "
                    f"This is almost always broader than intended and is a common misconfiguration."
                ),
                policy_file=filename,
                statement_idx=idx,
            )
        )
    return findings


def check_not_resource(statement, idx, filename):
    """MR-007: Detects use of NotResource with Allow."""
    findings = []
    if statement.get("Effect") == "Allow" and "NotResource" in statement:
        findings.append(
            Finding(
                severity="HIGH",
                rule_id="MR-007",
                title="NotResource with Allow effect",
                detail=(
                    "Using NotResource with Allow means 'allow on all resources EXCEPT the listed ones'. "
                    "This grants access to every other resource in the account."
                ),
                policy_file=filename,
                statement_idx=idx,
            )
        )
    return findings


# All rules in scan order — append new rules here
ALL_RULES = [
    check_admin_access,
    check_wildcard_actions,
    check_wildcard_resources,
    check_privilege_escalation,
    check_missing_conditions,
    check_not_action,
    check_not_resource,
]
