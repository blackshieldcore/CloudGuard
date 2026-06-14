# CloudGuard — AWS IAM Risk Analyzer

A lightweight, dependency-free Python tool that scans AWS IAM policy documents for misconfigurations, privilege-escalation paths, and overly permissive access patterns.

## Why this exists

IAM over-permissioning is the #1 cloud security risk. Tools like AWS Access Analyzer exist but are account-bound — they can't scan a policy *before* it's deployed, and they don't flag privilege-escalation chains. CloudGuard fills that gap: it reads raw IAM policy JSON files and flags risks *offline*, making it useful in code review, CI pipelines, and pre-deployment checks.

## What it detects

| Rule   | Severity | Description |
|--------|----------|-------------|
| CG-001 | CRITICAL | Full admin access (`Action: *`, `Resource: *`) |
| CG-002 | HIGH/MED | Wildcard service actions (e.g., `s3:*`, `iam:*`) |
| CG-003 | MEDIUM   | Wildcard resources with specific actions |
| CG-004 | HIGH     | Known privilege-escalation paths (`iam:PassRole`, `sts:AssumeRole`, `lambda:CreateFunction`, etc.) |
| CG-005 | MEDIUM   | Sensitive actions without condition constraints |
| CG-006 | HIGH     | `NotAction` with `Allow` (inverse allow = overly broad) |
| CG-007 | HIGH     | `NotResource` with `Allow` (grants access to all *other* resources) |

Privilege-escalation actions are based on [Rhino Security Labs' AWS privilege escalation research](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/).

## Usage

```bash
# Scan a directory of policy files
python cloudguard.py policies/

# Scan a single file
python cloudguard.py policies/admin-full-access.json

# Show only HIGH and CRITICAL findings
python cloudguard.py policies/ --severity high

# JSON output (for CI integration or further processing)
python cloudguard.py policies/ --output json > report.json
```

## Example output

```
CloudGuard — AWS IAM Risk Analyzer
Scanning: policies/

[CRITICAL] CG-001: Full administrator access detected
  File: policies/admin-full-access.json (Statement #1)
  Detail: Action: * with Resource: * grants unrestricted access to all AWS services...

[HIGH] CG-004: Privilege escalation path: iam:PassRole
  File: policies/developer-role.json (Statement #2)
  Detail: The action 'iam:PassRole' can be used to escalate privileges...

============================================================
  SCAN SUMMARY
============================================================
  Total findings: 14
  CRITICAL : 1
  HIGH     : 7
  MEDIUM   : 6
  LOW      : 0
  INFO     : 0
============================================================
```

## Exit codes

- `0` — No CRITICAL or HIGH findings (safe for CI gates)
- `1` — CRITICAL or HIGH findings detected (fail the pipeline)

This makes CloudGuard usable as a CI/CD gate: add it to your pipeline and block deployments that introduce dangerous IAM policies.

## Requirements

- Python 3.7+
- **Zero external dependencies** — uses only the Python standard library. Runs anywhere Python runs.

## Design decisions

- **Offline-first**: Scans JSON files, not live AWS accounts. This means it works in code review, pre-deployment, and air-gapped environments.
- **No dependencies**: Deliberate choice — the tool should run on any machine without `pip install` or version conflicts. Security tooling that introduces supply-chain dependencies defeats the purpose.
- **Severity-based filtering**: Findings are ranked CRITICAL → INFO so teams can focus on what matters. The `--severity` flag lets CI pipelines set their own threshold.
- **Exit codes for automation**: Returns 1 on CRITICAL/HIGH findings, making it a drop-in CI gate.
- **Extensible rules**: Each check is an independent function. Adding a new rule means writing one function and appending it to `ALL_RULES` — no framework, no config files.

## Adding custom rules

Every rule is a function with this signature:

```python
def check_something(statement, idx, filename):
    """Your check description."""
    findings = []
    # analyze statement dict, append Finding objects
    return findings
```

Add it to the `ALL_RULES` list and it runs automatically on every statement.

## What's next

- [ ] Scan IAM roles and trust policies (who can *assume* the role)
- [ ] Cross-policy analysis (find roles that combine to enable escalation)
- [ ] CIS Benchmark mapping for findings
- [ ] GitHub Actions workflow for automated PR scanning

## License

MIT
