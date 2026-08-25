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
    from flask import Flask, jsonify, render_template, request
    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False

from cloudguard.core import Finding, SEVERITY_ORDER


def create_app(
    graph_data: dict,
    findings: List[Finding],
    paths: List[List[str]],
) -> "Flask":
    """
    Factory that creates the Flask app with all data pre-loaded.
    graph_data: output of graph_to_dict()
    findings: list of Finding objects
    paths: attack paths from find_attack_paths()
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

    findings_json = [f.to_dict() for f in findings]
    findings_json_sorted = sorted(
        findings_json,
        key=lambda x: -SEVERITY_ORDER.get(x["severity"], 0),
    )

    @app.route("/")
    def index():
        summary = {
            "total": len(findings),
            "critical": sum(1 for f in findings if f.severity == "CRITICAL"),
            "high":     sum(1 for f in findings if f.severity == "HIGH"),
            "medium":   sum(1 for f in findings if f.severity == "MEDIUM"),
            "low":      sum(1 for f in findings if f.severity == "LOW"),
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

    @app.route("/api/graph")
    def api_graph():
        return jsonify(graph_data)

    @app.route("/api/findings")
    def api_findings():
        severity = request.args.get("severity", "").upper()
        search   = request.args.get("q", "").lower()
        filtered = findings_json_sorted
        if severity:
            filtered = [f for f in filtered if f["severity"] == severity]
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
    graph_data: dict,
    findings: List[Finding],
    paths: List[List[str]],
    host: str = "127.0.0.1",
    port: int = 5000,
    open_browser: bool = True,
):
    """Start the Flask dashboard server."""
    app = create_app(graph_data, findings, paths)

    if open_browser:
        def _open():
            import time
            time.sleep(1.2)
            webbrowser.open(f"http://{host}:{port}")
        threading.Thread(target=_open, daemon=True).start()

    print(f"\n  CloudGuard Dashboard running at http://{host}:{port}")
    print("  Press Ctrl-C to stop.\n")
    app.run(host=host, port=port, debug=False, use_reloader=False)
