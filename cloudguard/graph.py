"""
cloudguard/graph.py
~~~~~~~~~~~~~~~~~~~
Attack path graph engine for CloudGuard.

Builds a directed graph from IAM policy documents where:
  - Nodes are principals (users/roles/groups), actions, and resources
  - Edges represent "this principal can perform this action on this resource"

find_attack_paths() uses BFS to surface multi-hop privilege escalation chains,
e.g.:  developer-role → iam:PassRole → lambda-execution-role → iam:* → ADMIN

This is the feature AWS Access Analyzer cannot provide.
"""

from __future__ import annotations

import json
from collections import deque
from typing import Dict, List, Optional, Tuple

try:
    import networkx as nx
    HAS_NETWORKX = True
except ImportError:
    HAS_NETWORKX = False

from cloudguard.core import normalize_to_list
from cloudguard.rules import PRIVESC_ACTIONS, HIGH_RISK_SERVICES


# ──────────────────────────────────────────────
# Node type constants
# ──────────────────────────────────────────────
NODE_PRINCIPAL = "principal"
NODE_ACTION    = "action"
NODE_RESOURCE  = "resource"


def _is_admin_node(node: str, ntype: str) -> bool:
    """Return True if this node represents administrative access."""
    if node == "*":
        return True
    if ntype == NODE_ACTION:
        # iam:* or * means admin
        svc = node.split(":")[0].lower() if ":" in node else ""
        return node == "*" or (node.endswith(":*") and svc in HIGH_RISK_SERVICES)
    if ntype == NODE_RESOURCE:
        return node == "*" or ":root" in node
    return False


def build_iam_graph(policies: Dict[str, dict]):
    """
    Build a NetworkX DiGraph from a dict of {name: policy_doc}.

    Graph schema
    ────────────
    Nodes:
      id="policy:<name>"            type="policy"
      id="action:<action>"          type="action"   risk=True/False
      id="resource:<resource>"      type="resource" is_admin=True/False

    Edges:
      policy → action    (label=policy_name)
      action → resource  (label=action)

    Returns nx.DiGraph or a plain dict (fallback if networkx not installed).
    """
    if not HAS_NETWORKX:
        # Fallback: return adjacency list so --graph still works without networkx
        return _build_adjacency_fallback(policies)

    G = nx.DiGraph()

    for policy_name, policy_doc in policies.items():
        policy_node = f"policy:{policy_name}"
        G.add_node(policy_node, type="policy", label=policy_name)

        statements = normalize_to_list(policy_doc.get("Statement", []))
        for stmt_idx, stmt in enumerate(statements, start=1):
            if stmt.get("Effect") != "Allow":
                continue

            actions   = normalize_to_list(stmt.get("Action", []))
            resources = normalize_to_list(stmt.get("Resource", []))
            sid       = stmt.get("Sid", f"stmt{stmt_idx}")

            for action in actions:
                action_node = f"action:{action}"
                is_privesc  = action in PRIVESC_ACTIONS or action == "*"
                svc         = action.split(":")[0].lower() if ":" in action else ""
                is_high_risk = action.endswith(":*") and svc in HIGH_RISK_SERVICES

                G.add_node(
                    action_node,
                    type=NODE_ACTION,
                    label=action,
                    is_privesc=is_privesc,
                    is_high_risk=is_high_risk,
                    is_admin=_is_admin_node(action, NODE_ACTION),
                )
                G.add_edge(
                    policy_node, action_node,
                    label=f"{policy_name}[{sid}]",
                    policy=policy_name,
                    sid=sid,
                )

                for resource in resources:
                    resource_node = f"resource:{resource}"
                    G.add_node(
                        resource_node,
                        type=NODE_RESOURCE,
                        label=resource,
                        is_admin=_is_admin_node(resource, NODE_RESOURCE),
                    )
                    G.add_edge(
                        action_node, resource_node,
                        label=action,
                        action=action,
                    )

    return G


def _build_adjacency_fallback(policies: Dict[str, dict]) -> dict:
    """Build a plain adjacency list when networkx is unavailable."""
    adj: Dict[str, List[str]] = {}
    edges = []

    for policy_name, policy_doc in policies.items():
        policy_node = f"policy:{policy_name}"
        adj.setdefault(policy_node, [])

        statements = normalize_to_list(policy_doc.get("Statement", []))
        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue
            for action in normalize_to_list(stmt.get("Action", [])):
                a_node = f"action:{action}"
                adj.setdefault(policy_node, []).append(a_node)
                adj.setdefault(a_node, [])
                edges.append((policy_node, a_node))
                for resource in normalize_to_list(stmt.get("Resource", [])):
                    r_node = f"resource:{resource}"
                    adj.setdefault(a_node, []).append(r_node)
                    adj.setdefault(r_node, [])
                    edges.append((a_node, r_node))

    return {"adjacency": adj, "edges": edges, "type": "fallback"}


# ──────────────────────────────────────────────
# Attack path finder
# ──────────────────────────────────────────────

def find_attack_paths(
    graph,
    source_pattern: str = "*",
    target_pattern: str = "*",
    max_depth: int = 8,
) -> List[List[str]]:
    """
    BFS to find all paths from source nodes to target nodes.

    source_pattern / target_pattern:
      "*"         → match all nodes
      "policy:*"  → all policy nodes
      "action:iam:PassRole" → exact node
      Any string  → substring match on node id

    Returns a list of paths, each path being a list of node ids.
    """
    if not HAS_NETWORKX:
        return _find_paths_fallback(graph, source_pattern, target_pattern)

    # Collect matching source and target nodes
    all_nodes = list(graph.nodes())

    def matches(node: str, pattern: str) -> bool:
        if pattern == "*":
            return True
        return pattern.lower() in node.lower()

    sources = [n for n in all_nodes if matches(n, source_pattern)]
    targets = [n for n in all_nodes if matches(n, target_pattern) and graph.nodes[n].get("is_admin")]

    if not targets:
        # Fall back to all resource:* nodes as targets
        targets = [n for n in all_nodes if n == "resource:*" or "root" in n]

    paths = []
    seen_paths = set()

    for src in sources:
        for tgt in targets:
            if src == tgt:
                continue
            try:
                for path in nx.all_simple_paths(graph, src, tgt, cutoff=max_depth):
                    key = tuple(path)
                    if key not in seen_paths:
                        seen_paths.add(key)
                        paths.append(list(path))
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                pass

    # Sort by path length (shortest = most dangerous)
    paths.sort(key=len)
    return paths


def _find_paths_fallback(graph: dict, source_pattern: str, target_pattern: str) -> List[List[str]]:
    """BFS fallback when networkx is not installed."""
    adj = graph.get("adjacency", {})
    all_nodes = list(adj.keys())

    def matches(node, pattern):
        return pattern == "*" or pattern.lower() in node.lower()

    sources = [n for n in all_nodes if matches(n, source_pattern) and n.startswith("policy:")]
    targets = [n for n in all_nodes if n == "resource:*" or "resource:arn:aws:iam" in n]

    paths = []
    for src in sources:
        for tgt in targets:
            # Simple BFS
            queue = deque([[src]])
            visited = set()
            while queue:
                path = queue.popleft()
                node = path[-1]
                if node == tgt:
                    paths.append(path)
                    break
                if node in visited or len(path) > 8:
                    continue
                visited.add(node)
                for neighbor in adj.get(node, []):
                    queue.append(path + [neighbor])
    return paths


# ──────────────────────────────────────────────
# Graph → JSON serialisation
# ──────────────────────────────────────────────

def graph_to_dict(graph, paths: List[List[str]]) -> dict:
    """
    Serialise the graph and attack paths to a JSON-compatible dict.

    Used by --graph CLI flag and the dashboard API.
    """
    if not HAS_NETWORKX or isinstance(graph, dict):
        # Fallback mode
        return {
            "nodes": [],
            "edges": graph.get("edges", []) if isinstance(graph, dict) else [],
            "attack_paths": [
                {"path": p, "length": len(p), "hops": len(p) - 1}
                for p in paths
            ],
            "summary": {
                "total_nodes": 0,
                "total_edges": 0,
                "attack_paths_found": len(paths),
                "networkx_available": False,
            },
        }

    nodes = []
    for node_id, attrs in graph.nodes(data=True):
        nodes.append({
            "id": node_id,
            "type": attrs.get("type", "unknown"),
            "label": attrs.get("label", node_id),
            "is_admin": attrs.get("is_admin", False),
            "is_privesc": attrs.get("is_privesc", False),
            "is_high_risk": attrs.get("is_high_risk", False),
        })

    edges = []
    for src, dst, attrs in graph.edges(data=True):
        edges.append({
            "source": src,
            "target": dst,
            "label": attrs.get("label", ""),
            "action": attrs.get("action", ""),
            "policy": attrs.get("policy", ""),
        })

    formatted_paths = []
    for p in paths:
        formatted_paths.append({
            "path": p,
            "length": len(p),
            "hops": len(p) - 1,
            "readable": " → ".join(
                n.split(":", 1)[1] if ":" in n else n for n in p
            ),
        })

    return {
        "nodes": nodes,
        "edges": edges,
        "attack_paths": formatted_paths,
        "summary": {
            "total_nodes": graph.number_of_nodes(),
            "total_edges": graph.number_of_edges(),
            "attack_paths_found": len(paths),
            "networkx_available": True,
        },
    }
