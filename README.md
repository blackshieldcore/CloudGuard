# CloudGuard — AWS IAM Risk Analyzer

A multi-layer AWS IAM security tool that scans policy documents, builds attack path graphs, pulls live AWS inventory, generates Terraform remediations, and visualizes everything in an interactive dashboard.

## Architecture

```
cloudguard/
├── core.py          ← CloudGuard class (policy loading, analysis)
├── rules.py         ← 7 detection rules (CG-001 → CG-007), extensible
├── graph.py         ← NetworkX attack path engine (BFS multi-hop)
├── live.py          ← Live AWS IAM scanner (boto3)
├── exploits.py      ← Defensive PoC script generator (Jinja2)
├── remediate.py     ← Terraform fix generator (Jinja2)
├── monitor.py       ← CloudTrail anomaly + honeypot deployer
└── dashboard/
    ├── app.py       ← Flask API server
    ├── templates/
    │   └── index.html   ← Cytoscape.js interactive graph (dark theme)
    └── static/
        └── style.css    ← Premium dark dashboard CSS
cli.py               ← Unified CLI entry point (all flags)
cloudguard.py        ← Backward-compat shim (original invocation still works)
requirements.txt
Dockerfile
```

## What it detects

| Rule   | Severity | Description |
|--------|----------|-------------|
| CG-001 | CRITICAL | Full admin access (`Action: *`, `Resource: *`) |
| CG-002 | HIGH/MED | Wildcard service actions (e.g., `s3:*`, `iam:*`) |
| CG-003 | MEDIUM   | Wildcard resources with specific actions |
| CG-004 | HIGH     | Privilege escalation paths (`iam:PassRole`, `sts:AssumeRole`, `lambda:CreateFunction`, etc.) |
| CG-005 | MEDIUM   | Sensitive actions without condition constraints |
| CG-006 | HIGH     | `NotAction` with `Allow` (inverse allow = overly broad) |
| CG-007 | HIGH     | `NotResource` with `Allow` (grants access to all other resources) |

Reference: [Rhino Security Labs — AWS Privilege Escalation Methods](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)

---

## Layer 1 — Core Scanner (offline, zero dependencies)

```bash
# Scan a directory of policy files
python cli.py policies/

# Scan a single file
python cli.py policies/admin-full-access.json

# Filter by severity
python cli.py policies/ --severity high

# JSON output (for CI integration)
python cli.py policies/ --output json > report.json

# Original invocation still works
python cloudguard.py policies/
```

## Layer 1 — Graph Attack Path Engine

Builds a directed permission graph using NetworkX and finds multi-hop privilege escalation chains via BFS — the feature AWS Access Analyzer doesn't have.

```bash
# Text output: print detected attack paths
python -X utf8 cli.py policies/ --graph

# JSON output: full graph + paths
python -X utf8 cli.py policies/ --graph --output json > graph.json
```

Example output:
```
  ATTACK PATH GRAPH
============================================================
  Nodes        : 20
  Edges        : 32
  Attack paths : 29
  NetworkX     : yes

  Detected Attack Paths:

  [2 hops] developer-role.json → iam:PassRole → *
  [2 hops] developer-role.json → lambda:CreateFunction → *
  [2 hops] cicd-pipeline.json → sts:AssumeRole → *
```

## Layer 2 — Live AWS Scanner

Pulls all IAM policies from live AWS account(s). Uses the standard SDK credential chain — no credentials are hardcoded.

```bash
# Scan current account (uses default credentials)
python cli.py --live

# Named profile
python cli.py --live --profile my-security-profile

# Multi-account
python cli.py --live --accounts 123456789012,987654321098

# Auto-discover all org accounts
python cli.py --live --org-discovery

# Combine live + graph + dashboard
python -X utf8 cli.py --live --graph --dashboard
```

**Authentication** (uses AWS SDK credential chain — no config needed):
1. Environment: `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`
2. `~/.aws/credentials` profile
3. EC2/ECS/Lambda instance metadata
4. AWS SSO / IAM Identity Center

**Permissions needed (all read-only and free):**
- `iam:ListRoles`, `iam:ListUsers`, `iam:ListGroups`
- `iam:GetRole`, `iam:GetRolePolicy`, `iam:ListRolePolicies`
- `iam:ListAttachedRolePolicies`, `iam:GetPolicyVersion`
- `organizations:ListAccounts` (for org discovery)

## Layer 3 — Exploit Generator + Terraform Remediation

Generates educational boto3 PoC scripts and Terraform fixes for every finding.

```bash
# Generate PoC scripts + Terraform fixes (dry-run: print to stdout)
python -X utf8 cli.py policies/ --exploits --remediate --dry-run

# Write to files
python -X utf8 cli.py policies/ --exploits ./out/exploits --remediate ./out/remediation
```

Every PoC script:
- Has `DRY_RUN = True` by default (prints API calls, never executes)
- Includes a `WARNING: FOR AUTHORIZED SECURITY TESTING ONLY` banner
- Requires explicit `DRY_RUN = False` to run
- Is clearly commented with defensive context

## Layer 4 — Visual Dashboard

Interactive Cytoscape.js graph dashboard on localhost. Dark theme, severity-colored nodes, attack path highlighting, findings panel, search.

```bash
python -X utf8 cli.py policies/ --dashboard
python -X utf8 cli.py policies/ --dashboard --port 8080

# Live data + full graph + dashboard
python -X utf8 cli.py --live --graph --dashboard
```

Dashboard features:
- **Graph canvas**: nodes = policies (red=CRITICAL, orange=HIGH, yellow=MEDIUM, green=clean), actions (purple), resources (diamond)
- **Findings panel**: filterable by severity, click to highlight node
- **Attack Paths tab**: click a path to highlight it on the graph
- **Node detail**: click any node to see related paths and findings
- **Search**: filter by action name, ARN, or policy file
- **Controls**: fit, zoom in/out, re-layout

## Layer 5 — CloudTrail Anomaly Detection + Honeypot

```bash
# Analyze last 24h of CloudTrail for anomalous high-risk actions
python cli.py --live --monitor

# Analyze last 48h
python cli.py --live --monitor --monitor-hours 48

# Deploy honeypot IAM role + canary S3 bucket (requires IAM write permissions)
python cli.py --live --deploy-honeypot --confirm-deploy

# Deploy with specific bucket name and Org scope
python cli.py --live --deploy-honeypot --confirm-deploy \
  --honeypot-bucket my-canary-bucket --org-id o-abc123

# Watch for honeypot AssumeRole events (continuous polling)
python -X utf8 cli.py --watch-honeypot arn:aws:iam::123456789012:role/cloudguard-canary-admin

# With Slack/Discord webhook alert
python -X utf8 cli.py --watch-honeypot arn:aws:iam::123456789012:role/cloudguard-canary-admin \
  --webhook-url https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

## Exit Codes (CI/CD integration)

| Code | Meaning |
|------|---------|
| `0`  | No CRITICAL or HIGH findings — safe to deploy |
| `1`  | CRITICAL or HIGH findings detected — block the pipeline |

```yaml
# GitHub Actions example
- name: CloudGuard IAM Scan
  run: python -X utf8 cli.py policies/ --severity high --output json > iam-report.json
  # Fails the step if CRITICAL/HIGH findings exist
```

## Requirements

```bash
pip install -r requirements.txt
```

| Package    | Used for |
|------------|----------|
| `networkx` | Graph engine (Layer 1) |
| `boto3`    | Live AWS scanner + CloudTrail (Layers 2, 5) |
| `jinja2`   | PoC + Terraform template rendering (Layer 3) |
| `flask`    | Dashboard server (Layer 4) |

All packages are optional per-feature — the core scanner (offline mode, `--graph`) requires only `networkx`.

## Docker

```bash
docker build -t cloudguard .

# Scan local policies
docker run --rm -v $(pwd)/policies:/app/policies cloudguard policies/ --graph

# Live AWS scan (pass credentials via environment)
docker run --rm \
  -e AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY \
  -e AWS_DEFAULT_REGION=us-east-1 \
  cloudguard --live --graph

# Dashboard (expose port)
docker run --rm -p 5000:5000 \
  -v $(pwd)/policies:/app/policies \
  cloudguard policies/ --dashboard --port 5000
```

## Adding Custom Rules

Every rule is a function with this signature:

```python
def check_something(statement: dict, idx: int, filename: str) -> List[Finding]:
    """CG-00X: Your description."""
    findings = []
    if statement.get("Effect") != "Allow":
        return findings
    # analyze statement, append Finding objects
    return findings
```

Add it to `ALL_RULES` in `cloudguard/rules.py` — it runs automatically on every statement.

## License

MIT
