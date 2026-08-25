"""
cloudguard/core.py
~~~~~~~~~~~~~~~~~~
Core CloudGuard class, Finding data model, and policy loading utilities.

The CloudGuard class is the central object — it accepts policies from files,
directories, or raw dicts (for live AWS ingestion), runs all rules, and returns
Finding objects.
"""

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional


# ──────────────────────────────────────────────
# Finding — the core result object
# ──────────────────────────────────────────────

class Finding:
    """Represents a single risk finding.  Identical to original cloudguard.py."""

    def __init__(self, severity, rule_id, title, detail, policy_file, statement_idx):
        self.severity = severity        # CRITICAL, HIGH, MEDIUM, LOW, INFO
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


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

def normalize_to_list(value) -> list:
    """AWS policy fields can be a string or list — normalize to list."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return value
    return []


def parse_policy_file(filepath) -> Optional[dict]:
    """Load and validate an IAM policy JSON file.  Handles 3 wrapper formats."""
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


# ──────────────────────────────────────────────
# CloudGuard — main analysis engine
# ──────────────────────────────────────────────

class CloudGuard:
    """
    Central analysis engine.

    Usage (file-based — same as original):
        cg = CloudGuard()
        cg.load_dir("policies/")
        findings = cg.analyze()

    Usage (dict-based — for live AWS ingestion):
        cg = CloudGuard()
        cg.load_dict("MyRolePolicy", policy_doc_dict)
        findings = cg.analyze()
    """

    def __init__(self):
        # {name: policy_doc_dict}
        self._policies: Dict[str, dict] = {}

    # ── Loading ───────────────────────────────

    def load_file(self, filepath) -> bool:
        """Parse and store one policy JSON file.  Returns True on success."""
        filepath = Path(filepath)
        doc = parse_policy_file(filepath)
        if doc is not None:
            self._policies[str(filepath)] = doc
            return True
        return False

    def load_dir(self, dirpath) -> int:
        """
        Recursively load all *.json files in a directory.
        Returns count of successfully loaded files.
        """
        dirpath = Path(dirpath)
        files = sorted(dirpath.glob("**/*.json"))
        if not files:
            print(f"  [WARN] No .json files found in {dirpath}", file=sys.stderr)
            return 0
        count = 0
        for fp in files:
            if self.load_file(fp):
                count += 1
        return count

    def load_dict(self, name: str, policy_doc: dict):
        """
        Inject a policy document directly (used by live AWS scanner and tests).
        `name` is used as the filename label in findings.
        """
        self._policies[name] = policy_doc

    def load_path(self, target_path: str):
        """
        Smart loader: detects whether target_path is a file or directory.
        Mirrors the original scan_path() logic for backward compatibility.
        """
        target = Path(target_path)
        if target.is_file():
            self.load_file(target)
        elif target.is_dir():
            self.load_dir(target)
        else:
            print(f"[ERROR] Path not found: {target_path}", file=sys.stderr)

    # ── Analysis ──────────────────────────────

    def analyze(self) -> List[Finding]:
        """
        Run all detection rules against every loaded policy.
        Returns a flat list of Finding objects, sorted by severity descending.
        """
        # Import here to avoid circular import (rules imports core)
        from cloudguard.rules import ALL_RULES

        all_findings: List[Finding] = []
        for name, policy_doc in self._policies.items():
            statements = normalize_to_list(policy_doc.get("Statement", []))
            for idx, statement in enumerate(statements, start=1):
                for rule_fn in ALL_RULES:
                    all_findings.extend(rule_fn(statement, idx, name))

        return all_findings

    # ── Graph support ─────────────────────────

    def get_policies(self) -> Dict[str, dict]:
        """Return the loaded policies dict (for graph builder and live scanner)."""
        return self._policies


# ──────────────────────────────────────────────
# Backward-compat functional API
# ──────────────────────────────────────────────

def scan_path(target_path: str) -> List[Finding]:
    """
    Backward-compatible wrapper.
    Mirrors original scan_path() — used by tests and the shim cloudguard.py.
    """
    cg = CloudGuard()
    cg.load_path(target_path)
    return cg.analyze()


def analyze_policy(policy_doc: dict, filename: str) -> List[Finding]:
    """Backward-compatible wrapper for analyze_policy()."""
    cg = CloudGuard()
    cg.load_dict(filename, policy_doc)
    return cg.analyze()


# ──────────────────────────────────────────────
# Summary printer (shared by cli.py + dashboard)
# ──────────────────────────────────────────────

SEVERITY_ORDER = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}


def print_summary(findings: List[Finding]):
    """Print a severity-based summary table.  Identical to original."""
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
