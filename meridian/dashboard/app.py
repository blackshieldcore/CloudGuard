"""
cloudguard/dashboard/app.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Flask dashboard server for CloudGuard.

Serves a single-page Cytoscape.js visualization of the IAM permission graph
with findings panel, attack paths, search, and severity filtering.

Start with:  python cli.py policies/ --dashboard
"""

from __future__ import annotations

import json
import os
import webbrowser
import threading
from typing import Any, Dict, List, Optional

try:
    from flask import Flask, jsonify, render_template, request, send_from_directory
    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False

from meridian.core import Finding, SEVERITY_ORDER


def create_app(
    graph_data: Optional[dict] = None,
    findings: Optional[List[Finding]] = None,
    paths: Optional[List[List[str]]] = None,
    policies: Optional[Dict[str, dict]] = None,
    all_findings: Optional[List[Finding]] = None,
    severity: Optional[str] = None,
) -> "Flask":
    """
    Factory that creates the Flask app with pre-loaded data or dynamically
    filtered graph data based on severity.
    """
    if not HAS_FLASK:
        raise ImportError(
            "Flask is required for --dashboard mode.\n"
            "Install with:  pip install flask"
        )

    # Resolve template/static dirs relative to this file
    base = os.path.dirname(os.path.abspath(__file__))
    app = Flask(
        __name__,
        template_folder=os.path.join(base, "templates"),
        static_folder=os.path.join(base, "static"),
    )

    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0

    @app.after_request
    def add_header(response):
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response

    app.config["SEVERITY"] = severity

    if all_findings is None:
        all_findings = findings if findings is not None else []

    app.config["ALL_FINDINGS"] = all_findings

    # 1. Severity filter findings BEFORE building graph elements
    if severity:
        min_sev = SEVERITY_ORDER.get(severity.upper(), 1)
        filtered_findings = [
            f for f in all_findings
            if SEVERITY_ORDER.get(f.severity, 0) >= min_sev
        ]
    else:
        filtered_findings = findings if findings is not None else all_findings

    # 2. Build graph elements from severity-filtered findings/policies if policies supplied
    if policies is not None:
        from meridian.graph import build_iam_graph, find_attack_paths, graph_to_dict
        from pathlib import Path
        from meridian.core import normalize_to_list

        if severity and filtered_findings:
            target_files = {str(f.policy_file) for f in filtered_findings}
            target_file_names = {Path(f.policy_file).name for f in filtered_findings}
            filtered_policies = {}
            for pname, pdoc in policies.items():
                if str(pname) in target_files or Path(pname).name in target_file_names:
                    matching_indices = {
                        f.statement_idx for f in filtered_findings
                        if str(f.policy_file) == str(pname) or Path(f.policy_file).name == Path(pname).name
                    }
                    stmts = normalize_to_list(pdoc.get("Statement", []))
                    kept_stmts = [
                        stmt for i, stmt in enumerate(stmts, start=1)
                        if i in matching_indices
                    ]
                    if kept_stmts:
                        doc_copy = dict(pdoc)
                        doc_copy["Statement"] = kept_stmts
                        filtered_policies[pname] = doc_copy
        elif severity and not filtered_findings:
            filtered_policies = {}
        else:
            filtered_policies = policies

        graph_obj = build_iam_graph(filtered_policies)
        paths_list = find_attack_paths(graph_obj)
        graph_data = graph_to_dict(graph_obj, paths_list)
        paths = paths_list

    if graph_data is None:
        graph_data = {"nodes": [], "edges": [], "attack_paths": [], "summary": {}}
    if paths is None:
        paths = []

    # 3. Hard cap on graph size (nodes > 30 or edges > 80)
    nodes = graph_data.get("nodes", [])
    edges = graph_data.get("edges", [])
    is_trimmed = False

    if len(nodes) > 30:
        # Prioritize keeping CRITICAL and HIGH severity nodes first, then MEDIUM, then LOW/INFO/clean
        from pathlib import Path
        policy_sev_scores = {}
        for f in all_findings:
            p_key = str(f.policy_file)
            p_name = Path(f.policy_file).name
            sev_val = SEVERITY_ORDER.get(f.severity, 0)
            policy_sev_scores[p_key] = max(policy_sev_scores.get(p_key, 0), sev_val)
            policy_sev_scores[p_name] = max(policy_sev_scores.get(p_name, 0), sev_val)

        node_scores = {}
        for n in nodes:
            nid = n.get("id", "")
            ntype = n.get("type", "")
            nlabel = n.get("label", "")
            score = 0
            if ntype == "policy":
                clean_id = nid.replace("policy:", "")
                clean_name = Path(clean_id).name
                score = max(
                    policy_sev_scores.get(clean_id, 0),
                    policy_sev_scores.get(clean_name, 0),
                    policy_sev_scores.get(nlabel, 0),
                )
            if n.get("is_admin"):
                score = max(score, 5)
            if n.get("is_privesc") or n.get("is_high_risk"):
                score = max(score, 4)
            node_scores[nid] = score

        # Propagate scores through edges (policy -> action -> resource)
        for e in edges:
            src = e.get("source", "")
            dst = e.get("target", "")
            src_score = node_scores.get(src, 0)
            if src_score > node_scores.get(dst, 0):
                node_scores[dst] = src_score

        # Sort nodes by score descending
        nodes = sorted(nodes, key=lambda n: node_scores.get(n["id"], 0), reverse=True)
        nodes = nodes[:30]
        is_trimmed = True

    valid_node_ids = {n["id"] for n in nodes}
    edges = [e for e in edges if e["source"] in valid_node_ids and e["target"] in valid_node_ids]

    if len(edges) > 80:
        edges = edges[:80]
        is_trimmed = True

    graph_data["nodes"] = nodes
    graph_data["edges"] = edges
    graph_data["is_trimmed"] = is_trimmed
    if "summary" in graph_data and isinstance(graph_data["summary"], dict):
        graph_data["summary"]["total_nodes"] = len(nodes)
        graph_data["summary"]["total_edges"] = len(edges)
        graph_data["summary"]["is_trimmed"] = is_trimmed

    findings_json = [f.to_dict() for f in filtered_findings]
    findings_json_sorted = sorted(
        findings_json,
        key=lambda x: -SEVERITY_ORDER.get(x["severity"], 0),
    )

    @app.route("/")
    def index():
        summary = {
            "total": len(filtered_findings),
            "critical": sum(1 for f in filtered_findings if f.severity == "CRITICAL"),
            "high":     sum(1 for f in filtered_findings if f.severity == "HIGH"),
            "medium":   sum(1 for f in filtered_findings if f.severity == "MEDIUM"),
            "low":      sum(1 for f in filtered_findings if f.severity == "LOW"),
            "info":     sum(1 for f in filtered_findings if f.severity == "INFO"),
        }
        return render_template(
            "index.html",
            summary=summary,
            graph_data_json=json.dumps(graph_data),
            findings_json=json.dumps(findings_json_sorted),
            paths_json=json.dumps([
                {
                    "path": p,
                    "readable": " → ".join(
                        n.split(":", 1)[1] if ":" in n else n for n in p
                    ),
                    "hops": len(p) - 1,
                }
                for p in paths
            ]),
        )

    @app.route("/favicon.ico")
    def favicon_ico():
        return send_from_directory(os.path.join(app.root_path, "static"), "favicon.ico", mimetype="image/vnd.microsoft.icon")

    @app.route("/report.json")
    def report_json():
        """Serve the full unfiltered findings as JSON."""
        return jsonify([f.to_dict() for f in all_findings])

    @app.route("/api/graph")
    def api_graph():
        return jsonify(graph_data)

    @app.route("/api/findings")
    def api_findings():
        sev_param = request.args.get("severity", "").upper()
        search = request.args.get("q", "").lower()
        filtered = findings_json_sorted
        if sev_param:
            filtered = [f for f in filtered if f["severity"] == sev_param]
        if search:
            filtered = [
                f for f in filtered
                if search in f["title"].lower()
                or search in f["detail"].lower()
                or search in str(f["policy_file"]).lower()
            ]
        return jsonify(filtered)

    @app.route("/api/paths")
    def api_paths():
        return jsonify([
            {
                "path": p,
                "readable": " → ".join(
                    n.split(":", 1)[1] if ":" in n else n for n in p
                ),
                "hops": len(p) - 1,
            }
            for p in paths
        ])

    @app.route("/api/node/<path:node_id>")
    def api_node(node_id):
        """Return all paths touching this node."""
        node_paths = [
            p for p in paths if any(node_id in n for n in p)
        ]
        node_findings = [
            f for f in findings_json_sorted
            if node_id in str(f.get("policy_file", ""))
        ]
        return jsonify({"paths": node_paths, "findings": node_findings})

    return app


def run_dashboard(
    graph_data: Optional[dict] = None,
    findings: Optional[List[Finding]] = None,
    paths: Optional[List[List[str]]] = None,
    policies: Optional[Dict[str, dict]] = None,
    all_findings: Optional[List[Finding]] = None,
    severity: Optional[str] = None,
    host: str = "127.0.0.1",
    port: int = 5000,
    open_browser: bool = True,
):
    """Start the Flask dashboard server."""
    app = create_app(
        graph_data=graph_data,
        findings=findings,
        paths=paths,
        policies=policies,
        all_findings=all_findings,
        severity=severity,
    )

    if open_browser:
        def _open():
            import time
            time.sleep(1.2)
            webbrowser.open(f"http://{host}:{port}")
        threading.Thread(target=_open, daemon=True).start()

    print(f"\n  Meridian Dashboard running at http://{host}:{port}")
    print("  Press Ctrl-C to stop.\n")
    app.run(host=host, port=port, debug=False, use_reloader=False)

