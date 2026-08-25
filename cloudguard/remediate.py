"""
cloudguard/remediate.py
~~~~~~~~~~~~~~~~~~~~~~~
Terraform remediation generator for CloudGuard findings.

For each finding, generates a Terraform HCL snippet that represents the
FIXED version of the policy: scoped resources, explicit actions, added
conditions, and removed dangerous constructs (NotAction, NotResource).

These snippets are educational starting points — they must be reviewed and
integrated into your actual Terraform codebase.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

try:
    from jinja2 import Environment, BaseLoader
    HAS_JINJA2 = True
except ImportError:
    HAS_JINJA2 = False

from cloudguard.core import Finding


# ──────────────────────────────────────────────
# Terraform templates per rule
# ──────────────────────────────────────────────

TF_HEADER = """\
# ──────────────────────────────────────────────────────────────────
# CloudGuard Remediation — {{ rule_id }}: {{ title }}
# Source: {{ policy_file }} (Statement #{{ statement_idx }})
#
# This snippet shows the FIXED version of the flagged policy statement.
# Integrate into your Terraform codebase and review carefully.
# ──────────────────────────────────────────────────────────────────

"""

TEMPLATES: Dict[str, str] = {

"CG-001": TF_HEADER + """\
# FIX: Replace AdministratorAccess with least-privilege.
# Only grant the specific actions your principal actually needs.

data "aws_iam_policy_document" "least_privilege_replace_cg001" {
  statement {
    sid    = "ScopedAccess"
    effect = "Allow"

    actions = [
      # TODO: Replace with only the actions this principal requires.
      # Example for a read-only S3 + CloudWatch role:
      "s3:GetObject",
      "s3:ListBucket",
      "cloudwatch:GetMetricData",
      "cloudwatch:ListMetrics",
    ]

    resources = [
      # TODO: Replace * with specific ARNs.
      "arn:aws:s3:::YOUR-BUCKET-NAME",
      "arn:aws:s3:::YOUR-BUCKET-NAME/*",
      "arn:aws:logs:*:*:log-group:YOUR-LOG-GROUP:*",
    ]

    # Add MFA / IP condition for sensitive access
    condition {
      test     = "Bool"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["true"]
    }
  }
}
""",

"CG-002": TF_HEADER + """\
# FIX: Replace service wildcard (e.g., s3:*) with specific actions.

data "aws_iam_policy_document" "scoped_actions_cg002" {
  statement {
    sid    = "ScopedServiceAccess"
    effect = "Allow"

    actions = [
      # TODO: List only the specific actions required — not the whole service.
      # Example replacing ec2:*:
      "ec2:DescribeInstances",
      "ec2:StartInstances",
      "ec2:StopInstances",
    ]

    resources = [
      # TODO: Scope to specific resource ARNs.
      "arn:aws:ec2:us-east-1:ACCOUNT_ID:instance/*",
    ]
  }
}
""",

"CG-003": TF_HEADER + """\
# FIX: Replace Resource:* with specific ARNs.

data "aws_iam_policy_document" "scoped_resources_cg003" {
  statement {
    sid    = "ScopedResources"
    effect = "Allow"

    actions = [
      # Keep existing actions — just scope the resources.
      "s3:GetObject",
      "s3:ListBucket",
    ]

    resources = [
      # TODO: Replace * with the specific ARNs this principal needs.
      "arn:aws:s3:::company-reports",
      "arn:aws:s3:::company-reports/*",
    ]
  }
}
""",

"CG-004-iam:PassRole": TF_HEADER + """\
# FIX: Restrict iam:PassRole to specific roles + add service condition.
#
# Without restriction, iam:PassRole on Resource:* lets any role be passed
# to any service, enabling privilege escalation via Lambda, EC2, etc.

data "aws_iam_policy_document" "restricted_passrole_cg004" {
  statement {
    sid    = "RestrictedPassRole"
    effect = "Allow"

    actions = ["iam:PassRole"]

    # Scope to only the specific execution role this principal needs to pass
    resources = [
      "arn:aws:iam::ACCOUNT_ID:role/YOUR-LAMBDA-EXECUTION-ROLE",
    ]

    # Only allow passing to Lambda service, not arbitrary services
    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["lambda.amazonaws.com"]
    }
  }

  # Separate statement for Lambda function actions if needed
  statement {
    sid    = "LambdaActions"
    effect = "Allow"
    actions = [
      "lambda:CreateFunction",
      "lambda:InvokeFunction",
    ]
    resources = [
      # Scope to specific function ARNs or a naming prefix
      "arn:aws:lambda:us-east-1:ACCOUNT_ID:function:your-app-*",
    ]
  }
}
""",

"CG-004-sts:AssumeRole": TF_HEADER + """\
# FIX: Restrict sts:AssumeRole to specific role ARNs + add Org/ExternalId condition.

data "aws_iam_policy_document" "restricted_assumerole_cg004" {
  statement {
    sid    = "RestrictedAssumeRole"
    effect = "Allow"

    actions = ["sts:AssumeRole"]

    # Scope to the exact roles this principal is permitted to assume
    resources = [
      "arn:aws:iam::ACCOUNT_ID:role/SPECIFIC-ROLE-NAME",
    ]

    # Restrict to principals within your AWS Organization
    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalOrgID"
      values   = ["o-YOUR-ORG-ID"]
    }
  }
}

# The TRUST POLICY on the target role should also be scoped:
data "aws_iam_policy_document" "target_role_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::SOURCE_ACCOUNT_ID:role/SPECIFIC-CALLER-ROLE"]
    }
    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = ["YOUR-UNIQUE-EXTERNAL-ID"]
    }
  }
}
""",

"CG-005": TF_HEADER + """\
# FIX: Add a Condition block to restrict sensitive action by IP or MFA.

data "aws_iam_policy_document" "conditioned_access_cg005" {
  statement {
    sid    = "ConditionedSensitiveAccess"
    effect = "Allow"

    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:ListBucket",
    ]

    resources = [
      "arn:aws:s3:::YOUR-BUCKET",
      "arn:aws:s3:::YOUR-BUCKET/*",
    ]

    # Option A: Restrict by source IP (e.g., corporate network)
    condition {
      test     = "IpAddress"
      variable = "aws:SourceIp"
      values   = ["203.0.113.0/24"]  # TODO: Replace with your IP range
    }

    # Option B: Require MFA (uncomment to use instead of IP)
    # condition {
    #   test     = "Bool"
    #   variable = "aws:MultiFactorAuthPresent"
    #   values   = ["true"]
    # }
  }
}
""",

"CG-006": TF_HEADER + """\
# FIX: Replace NotAction+Allow with an explicit action allowlist.
#
# NotAction with Allow is almost never intentional — it grants access to
# EVERY action except the listed ones.  Replace with explicit actions.

data "aws_iam_policy_document" "explicit_allow_cg006" {
  # Instead of NotAction, list exactly what the CI/CD pipeline needs
  statement {
    sid    = "CICDExplicitActions"
    effect = "Allow"

    actions = [
      # TODO: Replace this list with exactly the actions your CI/CD needs.
      "s3:GetObject",
      "s3:PutObject",
      "s3:ListBucket",
      "ecr:GetAuthorizationToken",
      "ecr:BatchCheckLayerAvailability",
      "ecr:PutImage",
      "ecs:RegisterTaskDefinition",
      "ecs:UpdateService",
      "cloudformation:DescribeStacks",
      "cloudformation:UpdateStack",
    ]

    resources = [
      # TODO: Scope to specific resource ARNs
      "*",  # replace with specific ARNs
    ]
  }
}
""",

"CG-007": TF_HEADER + """\
# FIX: Replace NotResource+Allow with explicit resource allowlist.
#
# NotResource with Allow grants access to ALL resources except the listed
# ones.  Replace with the specific resources the principal actually needs.

data "aws_iam_policy_document" "explicit_resources_cg007" {
  statement {
    sid    = "ExplicitResourceAccess"
    effect = "Allow"

    actions = [
      # TODO: Keep your existing actions
    ]

    resources = [
      # TODO: Replace NotResource with specific ARNs of what IS allowed.
      "arn:aws:s3:::allowed-bucket",
      "arn:aws:s3:::allowed-bucket/*",
    ]
  }
}
""",
}


class RemediationGenerator:
    """Generates Terraform HCL remediation snippets for CloudGuard findings."""

    def __init__(self):
        if HAS_JINJA2:
            self._env = Environment(loader=BaseLoader(), autoescape=False)
        else:
            self._env = None

    def _render(self, template_str: str, **ctx) -> str:
        if HAS_JINJA2:
            tmpl = self._env.from_string(template_str)
            return tmpl.render(**ctx)
        result = template_str
        for k, v in ctx.items():
            result = result.replace("{{ " + k + " }}", str(v))
        return result

    def generate(self, finding: Finding) -> str:
        """Return a Terraform HCL snippet fixing the given finding."""
        rule_id = finding.rule_id

        if rule_id == "CG-004":
            if "iam:PassRole" in finding.title or "lambda" in finding.title.lower():
                tpl = TEMPLATES.get("CG-004-iam:PassRole", TEMPLATES.get("CG-003", ""))
            elif "sts:AssumeRole" in finding.title:
                tpl = TEMPLATES.get("CG-004-sts:AssumeRole", TEMPLATES.get("CG-003", ""))
            else:
                tpl = TEMPLATES.get("CG-004-iam:PassRole", TEMPLATES.get("CG-003", ""))
        else:
            tpl = TEMPLATES.get(rule_id, "")

        if not tpl:
            tpl = TF_HEADER + (
                "# No specific Terraform fix template for {{ rule_id }}.\n"
                "# Manually review: {{ detail }}\n"
            )

        return self._render(
            tpl,
            rule_id=finding.rule_id,
            title=finding.title,
            detail=finding.detail,
            policy_file=str(finding.policy_file),
            statement_idx=finding.statement_idx,
        )

    def generate_all(self, findings: List[Finding]) -> Dict[str, str]:
        """Generate Terraform fixes for all findings."""
        snippets = {}
        seen = set()
        for finding in findings:
            key = f"{finding.rule_id}_{finding.statement_idx}_{Path(str(finding.policy_file)).stem}"
            if key in seen:
                continue
            seen.add(key)
            safe = key.replace("/", "_").replace("\\", "_").replace(":", "-")
            snippets[f"fix_{safe}.tf"] = self.generate(finding)
        return snippets


def write_remediation(snippets: Dict[str, str], output_dir: str, dry_run: bool = True):
    """Write (or print) Terraform snippets to output_dir."""
    if dry_run:
        print("\n" + "=" * 60)
        print("  TERRAFORM REMEDIATION SNIPPETS (DRY-RUN)")
        print("=" * 60)
        for fname, content in snippets.items():
            print(f"\n{'─'*60}\n  File: {fname}\n{'─'*60}")
            lines = content.split("\n")
            print("\n".join(lines[:40]))
            if len(lines) > 40:
                print(f"  ... ({len(lines) - 40} more lines)")
        return

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    for fname, content in snippets.items():
        target = out / fname
        target.write_text(content, encoding="utf-8")
        print(f"  [REMEDIATE] Written: {target}")
    print(f"\n  Total: {len(snippets)} Terraform snippets in {output_dir}/")
    print("  Review and integrate each snippet into your Terraform codebase.")
