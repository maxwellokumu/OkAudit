"""Supply Chain Mapper — generate a Mermaid diagram and summary of vendor relationships.

Reads a CSV of vendors with their dependencies, criticality, and data access flags,
builds a directed vendor graph, generates a Mermaid flowchart, and produces a
markdown summary table. Detects circular dependencies.
"""

import argparse
import csv
import sys
from collections import defaultdict, deque
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Map vendor supply chain relationships and generate Mermaid diagram."
    )
    parser.add_argument(
        "--vendors",
        required=True,
        help="Path to CSV: vendor,dependencies,criticality,data_access,tier",
    )
    parser.add_argument(
        "--output",
        choices=["mermaid", "markdown", "both"],
        default="both",
        help="Output format (default: both)",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------


def load_vendors(path: str) -> List[Dict[str, str]]:
    """Load vendor CSV data.

    Args:
        path: Path to CSV file.

    Returns:
        List of vendor dicts.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            rows = [dict(row) for row in reader]
    except FileNotFoundError:
        print(f"ERROR: Vendors file not found: '{path}'", file=sys.stderr)
        sys.exit(1)

    required = {"vendor", "dependencies", "criticality", "data_access", "tier"}
    if rows and not required.issubset(set(rows[0].keys())):
        missing = required - set(rows[0].keys())
        print(f"ERROR: CSV missing columns: {', '.join(missing)}", file=sys.stderr)
        sys.exit(1)

    if not rows:
        print("ERROR: Vendors CSV is empty.", file=sys.stderr)
        sys.exit(1)

    return rows


# ---------------------------------------------------------------------------
# Graph analysis
# ---------------------------------------------------------------------------


def build_graph(vendors: List[Dict[str, str]]) -> Dict[str, List[str]]:
    """Build adjacency list from vendor data.

    Args:
        vendors: List of vendor dicts.

    Returns:
        Dict mapping vendor name to list of dependency names.
    """
    graph: Dict[str, List[str]] = {}
    for v in vendors:
        name = v["vendor"].strip()
        deps_raw = v.get("dependencies", "").strip()
        deps = [d.strip() for d in deps_raw.split("|") if d.strip()] if deps_raw else []
        graph[name] = deps
    return graph


def detect_cycles(graph: Dict[str, List[str]]) -> List[List[str]]:
    """Detect circular dependencies using DFS.

    Args:
        graph: Adjacency list.

    Returns:
        List of cycles, each cycle as a list of vendor names.
    """
    visited: Set[str] = set()
    rec_stack: Set[str] = set()
    cycles: List[List[str]] = []

    def dfs(node: str, path: List[str]) -> None:
        visited.add(node)
        rec_stack.add(node)
        path.append(node)

        for neighbour in graph.get(node, []):
            if neighbour not in visited:
                dfs(neighbour, path[:])
            elif neighbour in rec_stack:
                cycle_start = path.index(neighbour)
                cycles.append(path[cycle_start:] + [neighbour])

        rec_stack.discard(node)

    for node in graph:
        if node not in visited:
            dfs(node, [])

    return cycles


# ---------------------------------------------------------------------------
# Mermaid generation
# ---------------------------------------------------------------------------

CRITICALITY_STYLES = {
    "Critical": "fill:#ff4444,color:#fff,stroke:#cc0000",
    "High": "fill:#ff8c00,color:#fff,stroke:#cc6600",
}

DATA_ACCESS_STYLE = "fill:#ff8c00,color:#fff,stroke:#cc6600"


def sanitise_id(name: str) -> str:
    """Convert vendor name to a valid Mermaid node ID.

    Args:
        name: Vendor name string.

    Returns:
        Sanitised alphanumeric ID string.
    """
    return "".join(c if c.isalnum() else "_" for c in name)


def generate_mermaid(
    vendors: List[Dict[str, str]],
    graph: Dict[str, List[str]],
    cycles: List[List[str]],
) -> str:
    """Generate a Mermaid flowchart LR diagram.

    Args:
        vendors: List of vendor dicts.
        graph: Adjacency list.
        cycles: Detected circular dependencies.

    Returns:
        Mermaid diagram string.
    """
    lines: List[str] = []
    lines.append("```mermaid")
    lines.append("flowchart LR")
    lines.append("")

    # Build lookup for criticality and data_access
    vendor_meta: Dict[str, Dict] = {
        v["vendor"].strip(): v for v in vendors
    }

    all_names: Set[str] = set(graph.keys())
    for deps in graph.values():
        all_names.update(deps)

    # Node definitions
    lines.append("    %% Node definitions")
    for name in sorted(all_names):
        nid = sanitise_id(name)
        lines.append(f'    {nid}["{name}"]')

    lines.append("")
    lines.append("    %% Your organisation root")
    lines.append('    YOUR_ORG["🏢 Your Organisation"]')
    lines.append("")

    # Edges from org to tier-1 vendors
    lines.append("    %% Tier 1 — direct vendors")
    for v in vendors:
        name = v["vendor"].strip()
        tier = v.get("tier", "1").strip()
        if tier == "1":
            nid = sanitise_id(name)
            lines.append(f"    YOUR_ORG --> {nid}")

    lines.append("")
    lines.append("    %% Vendor dependencies")
    for name, deps in sorted(graph.items()):
        nid = sanitise_id(name)
        meta = vendor_meta.get(name, {})
        tier = meta.get("tier", "1").strip()
        for dep in deps:
            dep_id = sanitise_id(dep)
            if tier == "1":
                lines.append(f"    {nid} --> {dep_id}")
            else:
                lines.append(f"    {nid} -.-> {dep_id}")

    lines.append("")
    lines.append("    %% Styling")

    # Style Critical vendors
    critical_vendors = [
        v["vendor"].strip() for v in vendors
        if v.get("criticality", "").strip() == "Critical"
    ]
    for name in critical_vendors:
        nid = sanitise_id(name)
        lines.append(f"    style {nid} {CRITICALITY_STYLES['Critical']}")

    # Style data_access=yes vendors (only if not already Critical)
    data_vendors = [
        v["vendor"].strip() for v in vendors
        if v.get("data_access", "").strip().lower() == "yes"
        and v.get("criticality", "").strip() != "Critical"
    ]
    for name in data_vendors:
        nid = sanitise_id(name)
        lines.append(f"    style {nid} {DATA_ACCESS_STYLE}")

    # Style YOUR_ORG
    lines.append("    style YOUR_ORG fill:#4a90d9,color:#fff,stroke:#2c6fad")

    lines.append("```")

    if cycles:
        lines.append("")
        lines.append("**⚠️ Circular Dependencies Detected:**")
        for cycle in cycles:
            lines.append(f"- {' → '.join(cycle)}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Markdown summary
# ---------------------------------------------------------------------------

CRITICALITY_EMOJI = {
    "Critical": "🔴",
    "High": "🟠",
    "Medium": "🟡",
    "Low": "🟢",
}


def generate_summary(
    vendors: List[Dict[str, str]],
    cycles: List[List[str]],
) -> str:
    """Generate markdown summary table of vendors.

    Args:
        vendors: List of vendor dicts.
        cycles: Detected circular dependencies.

    Returns:
        Markdown summary string.
    """
    date_str = datetime.now().strftime("%Y-%m-%d")
    lines: List[str] = []

    lines.append("# Vendor Supply Chain Map\n")
    lines.append(f"**Date:** {date_str}  ")
    lines.append(f"**Total Vendors:** {len(vendors)}  ")
    critical_count = sum(1 for v in vendors if v.get("criticality", "").strip() == "Critical")
    data_access_count = sum(1 for v in vendors if v.get("data_access", "").strip().lower() == "yes")
    lines.append(f"**Critical Vendors:** {critical_count}  ")
    lines.append(f"**Vendors with Data Access:** {data_access_count}\n")
    lines.append("---\n")

    lines.append("## Vendor Inventory\n")
    lines.append("| Vendor | Tier | Criticality | Data Access | Dependencies | Risk Notes |")
    lines.append("|--------|------|-------------|-------------|--------------|------------|")

    for v in sorted(vendors, key=lambda x: (x.get("tier", "1"), x.get("criticality", "Low"))):
        name = v["vendor"].strip()
        tier = v.get("tier", "1").strip()
        crit = v.get("criticality", "Medium").strip()
        data = v.get("data_access", "no").strip().lower()
        deps_raw = v.get("dependencies", "").strip()
        deps = [d.strip() for d in deps_raw.split("|") if d.strip()] if deps_raw else []
        deps_str = ", ".join(deps) if deps else "None"

        crit_emoji = CRITICALITY_EMOJI.get(crit, "")
        data_str = "✅ Yes" if data == "yes" else "No"

        risk_notes = []
        if crit == "Critical":
            risk_notes.append("High impact if unavailable")
        if data == "yes":
            risk_notes.append("Processes customer data")
        if tier == "3":
            risk_notes.append("Nth-party — limited visibility")
        risk_str = "; ".join(risk_notes) if risk_notes else "—"

        lines.append(
            f"| **{name}** | Tier {tier} | {crit_emoji} {crit} | {data_str} | {deps_str} | {risk_str} |"
        )

    lines.append("")

    if cycles:
        lines.append("---\n")
        lines.append("## ⚠️ Circular Dependencies\n")
        for cycle in cycles:
            lines.append(f"- `{' → '.join(cycle)}`")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Main entry point."""
    args = parse_args()

    vendors = load_vendors(args.vendors)
    graph = build_graph(vendors)
    cycles = detect_cycles(graph)

    if args.output in ("mermaid", "both"):
        print(generate_mermaid(vendors, graph, cycles))
        if args.output == "both":
            print()

    if args.output in ("markdown", "both"):
        print(generate_summary(vendors, cycles))


if __name__ == "__main__":
    main()
