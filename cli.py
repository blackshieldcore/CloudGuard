#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cli.py — CloudGuard command-line entry point.


All original flags work identically (backward compatible):
    python cli.py policies/
    python cli.py admin-policy.json --severity high
    python cli.py policies/ --output json > report.json

New flags (each layer is independent):
    --graph              Build attack path graph; print paths as JSON
    --live               Pull live IAM policies from AWS (requires boto3 + credentials)
    --accounts ID,ID     Comma-separated account IDs to scan (multi-account, used with --live)
    --profile NAME       AWS credential profile (used with --live)
    --org-discovery      Auto-discover all org accounts (used with --live)
    --exploits [DIR]     Generate PoC scripts for CRITICAL/HIGH findings
    --remediate [DIR]    Generate Terraform fix snippets for findings
    --dry-run            Print exploits/remediation to stdout instead of writing files
    --dashboard          Start Flask dashboard on localhost:5000
    --port N             Dashboard port (default: 5000)
    --monitor            Pull CloudTrail events and flag anomalous IAM actions
    --monitor-hours N    Hours of CloudTrail history to pull (default: 24)
    --deploy-honeypot    Deploy honeypot IAM role + canary S3 bucket
    --confirm-deploy     Required safety gate for --deploy-honeypot
    --honeypot-bucket    Canary bucket name (optional, default: cloudguard-canary-<account>)
    --org-id ORG         AWS Org ID for trust policy scope (optional)
    --watch-honeypot ARN Continuously monitor CloudTrail for honeypot AssumeRole events
    --webhook-url URL    Slack/Discord webhook for honeypot alerts
"""

import argparse
import json
import sys

# Ensure UTF-8 output on Windows terminals (Python 3.7+)
if sys.stdout.encoding and sys.stdout.encoding.lower() not in ('utf-8', 'utf8'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except AttributeError:
        pass  # Python < 3.7 fallback

from cloudguard.core import CloudGuard, SEVERITY_ORDER, print_summary



def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cloudguard",
        description=(
            "CloudGuard — AWS IAM Risk Analyzer\n"
            "Scans IAM policy files (offline) or live AWS accounts for "
            "misconfigurations, privilege-escalation paths, and attack graphs."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python cli.py policies/\n"
            "  python cli.py admin-policy.json --severity high\n"
            "  python cli.py policies/ --output json > report.json\n"
            "  python cli.py policies/ --graph\n"
            "  python cli.py --live --org-discovery --graph --dashboard\n"
            "  python cli.py policies/ --exploits ./out --dry-run\n"
            "  python cli.py policies/ --remediate ./fixes --dry-run\n"
            "  python cli.py policies/ --dashboard --port 8080\n"
            "  python cli.py --live --monitor --monitor-hours 48\n"
            "  python cli.py --live --deploy-honeypot --confirm-deploy\n"
            "  python cli.py --watch-honeypot arn:aws:iam::123:role/cloudguard-canary-admin\n"
        ),
    )

    # ── Original flags (unchanged) ─────────────────────────────
    parser.add_argument(
        "path",
        nargs="?",
        default=None,
        help="Path to a policy JSON file or directory (optional when using --live)",
    )
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

    # ── Layer 1: Graph ─────────────────────────────────────────
    parser.add_argument(
        "--graph",
        action="store_true",
        help="Build IAM permission graph and output attack paths as JSON",
    )

    # ── Layer 2: Live AWS ──────────────────────────────────────
    parser.add_argument(
        "--live",
        action="store_true",
        help="Pull IAM policies from live AWS account(s) via boto3",
    )
    parser.add_argument(
        "--accounts",
        type=str,
        default=None,
        help="Comma-separated AWS account IDs to scan (used with --live)",
    )
    parser.add_argument(
        "--profile",
        type=str,
        default=None,
        help="AWS credential profile name (used with --live)",
    )
    parser.add_argument(
        "--org-discovery",
        action="store_true",
        help="Auto-discover all accounts in AWS Organization (used with --live)",
    )

    # ── Layer 3: Exploits + Remediation ───────────────────────
    parser.add_argument(
        "--exploits",
        nargs="?",
        const="./exploits",
        metavar="DIR",
        help="Generate PoC exploit scripts (default dir: ./exploits)",
    )
    parser.add_argument(
        "--remediate",
        nargs="?",
        const="./remediation",
        metavar="DIR",
        help="Generate Terraform remediation snippets (default dir: ./remediation)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print exploits/remediation to stdout instead of writing files",
    )

    # ── Layer 4: Dashboard ─────────────────────────────────────
    parser.add_argument(
        "--dashboard",
        action="store_true",
        help="Start Flask dashboard on localhost:5000",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=5000,
        help="Dashboard port (default: 5000)",
    )

    # ── Layer 5: Monitor + Honeypot ───────────────────────────
    parser.add_argument(
        "--monitor",
        action="store_true",
        help="Pull CloudTrail events and flag anomalous high-risk actions",
    )
    parser.add_argument(
        "--monitor-hours",
        type=int,
        default=24,
        metavar="N",
        help="Hours of CloudTrail history to analyse (default: 24)",
    )
    parser.add_argument(
        "--deploy-honeypot",
        action="store_true",
        help="Deploy a decoy IAM role and canary S3 bucket",
    )
    parser.add_argument(
        "--confirm-deploy",
        action="store_true",
        help="Required safety flag to confirm --deploy-honeypot",
    )
    parser.add_argument(
        "--honeypot-bucket",
        type=str,
        default=None,
        metavar="BUCKET",
        help="Name for the canary S3 bucket (auto-generated if not set)",
    )
    parser.add_argument(
        "--org-id",
        type=str,
        default=None,
        help="AWS Org ID to scope honeypot trust policy",
    )
    parser.add_argument(
        "--watch-honeypot",
        type=str,
        default=None,
        metavar="ROLE_ARN",
        help="Monitor CloudTrail for AssumeRole events on this honeypot role ARN",
    )
    parser.add_argument(
        "--webhook-url",
        type=str,
        default=None,
        metavar="URL",
        help="Slack/Discord webhook URL for honeypot alerts",
    )

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    # ── Early exit: watch-honeypot runs standalone ─────────────
    if args.watch_honeypot:
        from cloudguard.monitor import watch_honeypot
        watch_honeypot(
            role_arn=args.watch_honeypot,
            webhook_url=args.webhook_url,
        )
        return

    # ── Validate: need path OR --live ──────────────────────────
    if not args.path and not args.live:
        parser.error("Provide a path to scan or use --live to pull from AWS.")

    # ── Print banner (original behaviour) ─────────────────────
    print("\nCloudGuard — AWS IAM Risk Analyzer")

    # ── Build CloudGuard instance ──────────────────────────────
    cg = CloudGuard()

    # Load local files
    if args.path:
        print(f"Scanning: {args.path}\n")
        cg.load_path(args.path)

    # Load live AWS policies
    if args.live:
        if not args.severity:
            args.severity = "high"
        from cloudguard.live import AWSLiveScanner
        account_ids = None
        if args.accounts:
            account_ids = [a.strip() for a in args.accounts.split(",") if a.strip()]

        scanner = AWSLiveScanner(
            profile=args.profile,
            region="us-east-1",
        )

        if args.org_discovery:
            discovered = scanner.discover_org_accounts()
            if discovered:
                account_ids = discovered

        live_policies = scanner.pull_all_policies(account_ids=account_ids)
        for name, doc in live_policies.items():
            cg.load_dict(name, doc)

    # ── Run analysis ───────────────────────────────────────────
    all_findings = cg.analyze()

    # Severity filtering (original logic — unchanged)
    min_severity = SEVERITY_ORDER.get(args.severity.upper(), 1) if args.severity else 1
    filtered = [f for f in all_findings if SEVERITY_ORDER.get(f.severity, 0) >= min_severity]

    # ── Standard output (original behaviour) ──────────────────
    if args.output == "json" and not (args.graph or args.dashboard or args.monitor):
        print(json.dumps([f.to_dict() for f in filtered], indent=2))
    else:
        if args.output == "text" and not args.dashboard:
            if not filtered:
                print("  No findings. Policies look clean.")
            else:
                for f in sorted(filtered, key=lambda x: -SEVERITY_ORDER.get(x.severity, 0)):
                    print(f)
            print_summary(filtered)

    # ── Layer 1: Graph ─────────────────────────────────────────
    graph_obj  = None
    paths_list = []

    if args.graph:
        from cloudguard.graph import build_iam_graph, find_attack_paths, graph_to_dict
        graph_obj  = build_iam_graph(cg.get_policies())
        paths_list = find_attack_paths(graph_obj)

        if not args.dashboard:
            result = graph_to_dict(graph_obj, paths_list)
            print("\n" + "=" * 60)
            print("  ATTACK PATH GRAPH")
            print("=" * 60)
            if args.output == "json":
                print(json.dumps(result, indent=2))
            else:
                summary = result["summary"]
                print(f"  Nodes        : {summary['total_nodes']}")
                print(f"  Edges        : {summary['total_edges']}")
                print(f"  Attack paths : {summary['attack_paths_found']}")
                print(f"  NetworkX     : {'yes' if summary['networkx_available'] else 'no (pip install networkx)'}")
                if result["attack_paths"]:
                    print("\n  Detected Attack Paths:")
                    for p in result["attack_paths"]:
                        print(f"\n  [{p['hops']} hops] {p['readable']}")
                else:
                    print("\n  No multi-hop attack paths found in this policy set.")
            print("=" * 60)

    # ── Layer 3: Exploits ──────────────────────────────────────
    if args.exploits is not None:
        from cloudguard.exploits import ExploitGenerator, write_exploits
        gen = ExploitGenerator()
        scripts = gen.generate_all(filtered)
        if paths_list:
            from cloudguard.graph import graph_to_dict
            for i, path in enumerate(paths_list[:5]):  # top 5 paths
                fname = f"poc_graph_path_{i+1}.py"
                scripts[fname] = gen.generate_path_script(path)
        write_exploits(scripts, args.exploits, dry_run=args.dry_run)

    # ── Layer 3: Remediation ───────────────────────────────────
    if args.remediate is not None:
        from cloudguard.remediate import RemediationGenerator, write_remediation
        remgen  = RemediationGenerator()
        snippets = remgen.generate_all(filtered)
        write_remediation(snippets, args.remediate, dry_run=args.dry_run)

    # ── Layer 5: Monitor ───────────────────────────────────────
    if args.monitor:
        from cloudguard.monitor import CloudTrailMonitor
        monitor = CloudTrailMonitor()
        events  = monitor.pull_events(hours=args.monitor_hours)
        anomalies = monitor.analyze_anomalies(events)
        monitor.print_anomalies(anomalies, output_format=args.output)

    # ── Layer 5: Deploy Honeypot ───────────────────────────────
    if args.deploy_honeypot:
        if not args.confirm_deploy:
            print(
                "\n[ERROR] --deploy-honeypot requires --confirm-deploy to prevent "
                "accidental resource creation.\n"
                "Re-run with both flags to proceed.",
                file=sys.stderr,
            )
            sys.exit(1)
        from cloudguard.monitor import HoneypotDeployer
        deployer = HoneypotDeployer(org_id=args.org_id)
        role_arn = deployer.deploy(bucket_name=args.honeypot_bucket)
        print(f"\n  Honeypot role ARN: {role_arn}")
        print(f"  Monitor with: python cli.py --watch-honeypot {role_arn}")

    # ── Layer 4: Dashboard (blocking — must be last) ───────────
    if args.dashboard:
        from cloudguard.dashboard.app import run_dashboard

        run_dashboard(
            policies=cg.get_policies(),
            all_findings=all_findings,
            severity=args.severity,
            port=args.port,
        )
        return  # Flask blocks here

    # ── Exit code (original behaviour — unchanged) ─────────────
    if any(f.severity in ("CRITICAL", "HIGH") for f in filtered):
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
