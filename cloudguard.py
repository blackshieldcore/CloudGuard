#!/usr/bin/env python3
"""
CloudGuard — AWS IAM Risk Analyzer

Reads AWS IAM policy documents (JSON) and flags risky configurations:
- Wildcard (*) actions or resources  
- Known privilege-escalation paths (iam:PassRole, sts:AssumeRole, etc.)
- Admin-level access patterns
- Missing condition constraints on sensitive actions
- Overly broad service access

Usage:
    python cloudguard.py policies/            # scan a directory of policy files
    python cloudguard.py policy.json          # scan a single file
    python cloudguard.py policies/ --severity high  # filter by severity

Author: Pratham Badgujar
"""

import json
import os
import sys
import argparse
from pathlib import Path
from datetime import datetime


# ──────────────────────────────────────────────
# Risk Rules — each maps an IAM anti-pattern to
# a severity and explanation.
# ──────────────────────────────────────────────

# Actions that enable privilege escalation
# Reference: https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
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


class Finding:
    """Represents a single risk finding."""

    def __init__(self, severity, rule_id, title, detail, policy_file, statement_idx):
        self.severity = severity  # CRITICAL, HIGH, MEDIUM, LOW, INFO
        self.rule_id = rule_id
        self.title = title
        self.detail = detail
        self.policy_file = policy_file
        self.statement_idx = statement_idx
        self.timestamp = datetime.now().isoformat()

    def __str__(self):
        return (
            f"[{self.severity}] {self.rule_id}: {self.title}\n"
            f"  File: {self.policy_file} (Statement #{self.statement_idx})\n"
            f"  Detail: {self.detail}\n"
        )

    def to_dict(self):
        return {
            "severity": self.severity,
            "rule_id": self.rule_id,
            "title": self.title,
            "detail": self.detail,
            "policy_file": str(self.policy_file),
            "statement_index": self.statement_idx,
            "timestamp": self.timestamp,
        }


def normalize_to_list(value):
    """AWS policy fields can be a string or list — normalize to list."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return value
    return []


def extract_service(action):
    """Extract the service prefix from an action string (e.g., 'iam' from 'iam:PassRole')."""
    if ":" in action:
        return action.split(":")[0].lower()
    return action.lower()


# ──────────────────────────────────────────────
# Analysis Rules
# Each rule is a function that takes a statement
# dict, its index, and the filename, and returns
# a list of Finding objects.
# ──────────────────────────────────────────────


def check_admin_access(statement, idx, filename):
    """CG-001: Detects full admin access (Action: *, Resource: *)."""
    findings = []
    if statement.get("Effect") != "Allow":
        return findings

    actions = normalize_to_list(statement.get("Action", []))
    resources = normalize_to_list(statement.get("Resource", []))

    if "*" in actions and "*" in resources:
        findings.append(
            Finding(
                severity="CRITICAL",
                rule_id="CG-001",
                title="Full administrator access detected",
                detail="Action: * with Resource: * grants unrestricted access to all AWS services and resources. "
                "This is the most dangerous IAM pattern and should be avoided except for break-glass accounts.",
                policy_file=filename,
                statement_idx=idx,
            )
        )
    return findings


def check_wildcard_actions(statement, idx, filename):
    """CG-002: Detects wildcard actions on specific services (e.g., 's3:*')."""
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
                    rule_id="CG-002",
                    title=f"Wildcard actions on {service} service",
                    detail=f"'{action}' grants all actions on the {service} service. "
                    f"Scope down to specific actions needed (least privilege).",
                    policy_file=filename,
                    statement_idx=idx,
                )
            )
    return findings


def check_wildcard_resources(statement, idx, filename):
    """CG-003: Detects wildcard resources with specific actions."""
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
                rule_id="CG-003",
                title="Wildcard resource with specific actions",
                detail=f"Actions [{action_list}] are allowed on all resources (*). "
                f"Restrict Resource to specific ARNs where possible.",
                policy_file=filename,
                statement_idx=idx,
            )
        )
    return findings


def check_privilege_escalation(statement, idx, filename):
    """CG-004: Detects actions that enable privilege escalation."""
    findings = []
    if statement.get("Effect") != "Allow":
        return findings

    actions = normalize_to_list(statement.get("Action", []))
    for action in actions:
        if action in PRIVESC_ACTIONS:
            findings.append(
                Finding(
                    severity="HIGH",
                    rule_id="CG-004",
                    title=f"Privilege escalation path: {action}",
                    detail=f"The action '{action}' can be used to escalate privileges. "
                    f"An attacker with this permission could gain higher access than intended. "
                    f"Add conditions or restrict the resource scope.",
                    policy_file=filename,
                    statement_idx=idx,
                )
            )
    return findings


def check_missing_conditions(statement, idx, filename):
    """CG-005: Detects sensitive actions without condition constraints."""
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
                        rule_id="CG-005",
                        title=f"Sensitive action without conditions: {action}",
                        detail=f"'{action}' is allowed without any Condition block. "
                        f"Consider adding conditions like source IP, MFA, or time-based restrictions.",
                        policy_file=filename,
                        statement_idx=idx,
                    )
                )
    return findings


def check_not_action(statement, idx, filename):
    """CG-006: Detects use of NotAction with Allow (inverse allow = broad access)."""
    findings = []
    if statement.get("Effect") == "Allow" and "NotAction" in statement:
        not_actions = normalize_to_list(statement.get("NotAction", []))
        findings.append(
            Finding(
                severity="HIGH",
                rule_id="CG-006",
                title="NotAction with Allow effect",
                detail=f"Using NotAction with Allow means 'allow everything EXCEPT {not_actions}'. "
                f"This is almost always broader than intended and is a common misconfiguration.",
                policy_file=filename,
                statement_idx=idx,
            )
        )
    return findings


def check_not_resource(statement, idx, filename):
    """CG-007: Detects use of NotResource with Allow."""
    findings = []
    if statement.get("Effect") == "Allow" and "NotResource" in statement:
        findings.append(
            Finding(
                severity="HIGH",
                rule_id="CG-007",
                title="NotResource with Allow effect",
                detail="Using NotResource with Allow means 'allow on all resources EXCEPT the listed ones'. "
                "This grants access to every other resource in the account.",
                policy_file=filename,
                statement_idx=idx,
            )
        )
    return findings


# All rules in scan order
ALL_RULES = [
    check_admin_access,
    check_wildcard_actions,
    check_wildcard_resources,
    check_privilege_escalation,
    check_missing_conditions,
    check_not_action,
    check_not_resource,
]


def parse_policy_file(filepath):
    """Load and validate an IAM policy JSON file."""
    try:
        with open(filepath, "r") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"  [ERROR] Invalid JSON in {filepath}: {e}", file=sys.stderr)
        return None
    except IOError as e:
        print(f"  [ERROR] Cannot read {filepath}: {e}", file=sys.stderr)
        return None

    # Handle both inline policy documents and full policy wrappers
    if "PolicyDocument" in data:
        return data["PolicyDocument"]
    if "Document" in data:
        return data["Document"]
    if "Statement" in data:
        return data
    print(f"  [WARN] No recognized policy structure in {filepath}", file=sys.stderr)
    return None


def analyze_policy(policy_doc, filename):
    """Run all rules against a parsed policy document."""
    findings = []
    statements = normalize_to_list(policy_doc.get("Statement", []))

    for idx, statement in enumerate(statements, start=1):
        for rule_fn in ALL_RULES:
            findings.extend(rule_fn(statement, idx, filename))

    return findings


def scan_path(target_path):
    """Scan a file or directory for IAM policy JSON files."""
    all_findings = []
    target = Path(target_path)

    if target.is_file():
        files = [target]
    elif target.is_dir():
        files = sorted(target.glob("**/*.json"))
    else:
        print(f"[ERROR] Path not found: {target_path}", file=sys.stderr)
        return all_findings

    if not files:
        print(f"[WARN] No .json files found in {target_path}", file=sys.stderr)
        return all_findings

    for filepath in files:
        policy_doc = parse_policy_file(filepath)
        if policy_doc:
            findings = analyze_policy(policy_doc, filepath)
            all_findings.extend(findings)

    return all_findings


def print_summary(findings):
    """Print a severity-based summary table."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    print("\n" + "=" * 60)
    print("  SCAN SUMMARY")
    print("=" * 60)
    print(f"  Total findings: {len(findings)}")
    print(f"  CRITICAL : {counts['CRITICAL']}")
    print(f"  HIGH     : {counts['HIGH']}")
    print(f"  MEDIUM   : {counts['MEDIUM']}")
    print(f"  LOW      : {counts['LOW']}")
    print(f"  INFO     : {counts['INFO']}")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="CloudGuard — AWS IAM Risk Analyzer. "
        "Scans IAM policy JSON files for misconfigurations and privilege escalation risks.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
        "  python cloudguard.py policies/\n"
        "  python cloudguard.py admin-policy.json --severity high\n"
        "  python cloudguard.py policies/ --output json > report.json\n",
    )
    parser.add_argument("path", help="Path to a policy JSON file or directory of policies")
    parser.add_argument(
        "--severity",
        choices=["critical", "high", "medium", "low", "info"],
        help="Show only findings at this severity or above",
    )
    parser.add_argument(
        "--output",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )

    args = parser.parse_args()

    # Severity ordering for filtering
    severity_order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
    min_severity = severity_order.get(args.severity.upper(), 1) if args.severity else 1

    print(f"\nCloudGuard — AWS IAM Risk Analyzer")
    print(f"Scanning: {args.path}\n")

    findings = scan_path(args.path)

    # Filter by severity
    filtered = [f for f in findings if severity_order.get(f.severity, 0) >= min_severity]

    if args.output == "json":
        print(json.dumps([f.to_dict() for f in filtered], indent=2))
    else:
        if not filtered:
            print("  No findings. Policies look clean.")
        else:
            for f in sorted(filtered, key=lambda x: -severity_order.get(x.severity, 0)):
                print(f)
        print_summary(filtered)

    # Exit code: 1 if any CRITICAL or HIGH findings
    if any(f.severity in ("CRITICAL", "HIGH") for f in filtered):
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
