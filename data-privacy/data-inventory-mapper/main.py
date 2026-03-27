"""Data Inventory Mapper.

Reads a CSV data inventory and produces:
  - A Mermaid flowchart showing data flows between systems
  - A markdown summary table grouped by classification
  - Special Category data highlights
  - Legal basis coverage analysis
  - Retention period overview
"""

import argparse
import csv
import os
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set

from dotenv import load_dotenv

load_dotenv()

SPECIAL_CATEGORY_TYPES: Set[str] = {
    "health", "medical", "biometric", "genetic",
    "racial_ethnic", "racial", "ethnic", "political_opinion", "political",
    "religious_belief", "religious", "sexual_orientation", "sexual",
    "criminal_record", "criminal", "financial", "children_data", "child",
}

CLASSIFICATION_ORDER = ["Restricted", "Special_Category", "Confidential", "Internal", "Public"]

GDPR_BASES = {
    "consent", "contract", "legal_obligation", "legal obligation",
    "vital_interests", "vital interests", "public_task", "public task",
    "legitimate_interests", "legitimate interests",
}

# Mermaid-safe node ID characters
_NODE_ID_RE = re.compile(r"[^a-zA-Z0-9_]")


@dataclass
class DataRecord:
    """A single row from the data inventory CSV."""

    system: str
    data_type: str
    classification: str
    location: str
    transfers_to: str
    legal_basis: str
    retention_period: str

    def is_special_category(self) -> bool:
        """Return True if the data type is Special Category under GDPR.

        Returns:
            True if data_type matches any special category keyword.
        """
        dt_lower = self.data_type.lower().replace(" ", "_")
        for sc in SPECIAL_CATEGORY_TYPES:
            if sc in dt_lower:
                return True
        return False

    def is_external(self) -> bool:
        """Return True if the system appears to be an external/third-party system.

        Returns:
            True if location suggests external hosting.
        """
        loc = self.location.lower()
        return any(kw in loc for kw in ("cloud", "third-party", "external", "vendor", "saas", "aws", "azure", "gcp"))


def load_inventory(path: str) -> List[DataRecord]:
    """Load data inventory records from a CSV file.

    Args:
        path: Filesystem path to the CSV file.

    Returns:
        List of DataRecord objects.

    Raises:
        SystemExit: On file not found or missing required columns.
    """
    required = {"system", "data_type", "classification", "location",
                "transfers_to", "legal_basis", "retention_period"}
    if not os.path.isfile(path):
        print(f"Error: Inventory file not found: {path}", file=sys.stderr)
        sys.exit(1)
    records: List[DataRecord] = []
    try:
        with open(path, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            if not reader.fieldnames:
                print("Error: CSV is empty.", file=sys.stderr)
                sys.exit(1)
            cols = {c.strip().lower() for c in reader.fieldnames}
            missing = required - cols
            if missing:
                print(f"Error: CSV missing columns: {missing}", file=sys.stderr)
                sys.exit(1)
            for row in reader:
                r = DataRecord(
                    system=row.get("system", "").strip(),
                    data_type=row.get("data_type", "").strip(),
                    classification=row.get("classification", "").strip(),
                    location=row.get("location", "").strip(),
                    transfers_to=row.get("transfers_to", "").strip(),
                    legal_basis=row.get("legal_basis", "").strip(),
                    retention_period=row.get("retention_period", "").strip(),
                )
                if r.system:
                    records.append(r)
    except csv.Error as exc:
        print(f"Error reading CSV: {exc}", file=sys.stderr)
        sys.exit(1)
    return records


def node_id(name: str) -> str:
    """Convert a system name to a Mermaid-safe node identifier.

    Args:
        name: Display name string.

    Returns:
        Sanitised identifier string.
    """
    return _NODE_ID_RE.sub("_", name).strip("_")


def build_mermaid(records: List[DataRecord]) -> str:
    """Build a Mermaid flowchart from data inventory records.

    Args:
        records: All loaded data records.

    Returns:
        Mermaid diagram string.
    """
    # Collect all systems and their properties
    systems: Dict[str, Dict] = {}
    for r in records:
        if r.system not in systems:
            systems[r.system] = {
                "special": False,
                "restricted": False,
                "external": r.is_external(),
            }
        if r.is_special_category():
            systems[r.system]["special"] = True
        if r.classification.lower() in ("restricted",):
            systems[r.system]["restricted"] = True

        # Also register transfer targets
        if r.transfers_to and r.transfers_to.lower() not in ("none", "n/a", "-", ""):
            targets = [t.strip() for t in r.transfers_to.split(",") if t.strip()]
            for t in targets:
                if t not in systems:
                    systems[t] = {"special": False, "restricted": False, "external": True}

    lines = ["```mermaid", "flowchart LR"]

    # Style definitions
    lines += [
        "    classDef special fill:#ff4444,color:#fff,stroke:#cc0000",
        "    classDef restricted fill:#ff8800,color:#fff,stroke:#cc6600",
        "    classDef external fill:#e8e8e8,stroke:#999,color:#333",
        "    classDef normal fill:#4a90d9,color:#fff,stroke:#2c6fad",
    ]

    # Node definitions
    for sys_name, props in systems.items():
        nid = node_id(sys_name)
        if props["external"]:
            lines.append(f'    {nid}[("{sys_name}")]')
        else:
            lines.append(f'    {nid}["{sys_name}"]')

    lines.append("")

    # Edges (data transfers)
    seen_edges: Set[str] = set()
    for r in records:
        if not r.transfers_to or r.transfers_to.lower() in ("none", "n/a", "-", ""):
            continue
        targets = [t.strip() for t in r.transfers_to.split(",") if t.strip()]
        for t in targets:
            edge_key = f"{node_id(r.system)}->{node_id(t)}"
            label = r.data_type[:20]  # truncate long labels
            if edge_key not in seen_edges:
                lines.append(f'    {node_id(r.system)} -->|"{label}"| {node_id(t)}')
                seen_edges.add(edge_key)

    lines.append("")

    # Apply styles
    special_nodes = [node_id(s) for s, p in systems.items() if p["special"]]
    restricted_nodes = [node_id(s) for s, p in systems.items() if p["restricted"] and not p["special"]]
    external_nodes = [node_id(s) for s, p in systems.items() if p["external"] and not p["special"] and not p["restricted"]]
    normal_nodes = [node_id(s) for s, p in systems.items()
                    if not p["special"] and not p["restricted"] and not p["external"]]

    if special_nodes:
        lines.append(f'    class {",".join(special_nodes)} special')
    if restricted_nodes:
        lines.append(f'    class {",".join(restricted_nodes)} restricted')
    if external_nodes:
        lines.append(f'    class {",".join(external_nodes)} external')
    if normal_nodes:
        lines.append(f'    class {",".join(normal_nodes)} normal')

    lines.append("```")
    return "\n".join(lines)


def build_markdown(records: List[DataRecord]) -> str:
    """Build a markdown summary from data inventory records.

    Args:
        records: All loaded data records.

    Returns:
        Markdown summary string.
    """
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    # Group by classification
    by_class: Dict[str, List[DataRecord]] = defaultdict(list)
    for r in records:
        by_class[r.classification].append(r)

    # Special category records
    sc_records = [r for r in records if r.is_special_category()]

    # Legal basis coverage
    bases_found: Dict[str, int] = defaultdict(int)
    missing_basis: List[DataRecord] = []
    for r in records:
        if r.legal_basis:
            lb_clean = r.legal_basis.lower().strip()
            bases_found[lb_clean] += 1
        else:
            missing_basis.append(r)

    lines = [
        "# Data Inventory Report",
        "",
        f"**Generated:** {now}",
        f"**Total Records:** {len(records)}",
        f"**Systems Covered:** {len({r.system for r in records})}",
        "",
    ]

    # Data inventory by classification
    lines += ["## Data Inventory by Classification", ""]
    for cls in CLASSIFICATION_ORDER:
        group = by_class.get(cls, [])
        if not group:
            continue
        lines += [
            f"### {cls} ({len(group)} records)",
            "",
            "| System | Data Type | Location | Transfers To | Legal Basis | Retention |",
            "|--------|-----------|----------|--------------|-------------|-----------|",
        ]
        for r in group:
            marker = " 🔴" if r.is_special_category() else ""
            lines.append(
                f"| {r.system}{marker} | {r.data_type} | {r.location} | "
                f"{r.transfers_to or '—'} | {r.legal_basis or '❌ Missing'} | {r.retention_period} |"
            )
        lines.append("")

    # Other classifications not in predefined list
    for cls, group in by_class.items():
        if cls not in CLASSIFICATION_ORDER:
            lines += [f"### {cls} ({len(group)} records)", ""]
            for r in group:
                lines.append(f"- {r.system}: {r.data_type}")
            lines.append("")

    # Special Category highlight
    if sc_records:
        lines += [
            "## ⚠️ Special Category Data (High Risk)",
            "",
            "The following systems process Special Category data and require "
            "explicit legal basis, DPO oversight, and enhanced controls:",
            "",
            "| System | Data Type | Classification | Legal Basis | Retention |",
            "|--------|-----------|----------------|-------------|-----------|",
        ]
        for r in sc_records:
            lines.append(
                f"| **{r.system}** | {r.data_type} | {r.classification} | "
                f"{r.legal_basis or '❌ Missing'} | {r.retention_period} |"
            )
        lines.append("")
    else:
        lines += ["## Special Category Data", "", "No Special Category data types identified.", ""]

    # Legal basis coverage
    lines += [
        "## Legal Basis Coverage",
        "",
        "| Legal Basis | Record Count |",
        "|-------------|-------------|",
    ]
    for basis, count in sorted(bases_found.items(), key=lambda x: -x[1]):
        lines.append(f"| {basis} | {count} |")
    if missing_basis:
        lines.append(f"| ❌ **Missing / Not Documented** | {len(missing_basis)} |")
    lines.append("")

    if missing_basis:
        lines += [
            "### Records Missing Legal Basis",
            "",
        ]
        for r in missing_basis:
            lines.append(f"- **{r.system}** — {r.data_type} ({r.classification})")
        lines.append("")

    # Retention overview
    retentions: Dict[str, List[str]] = defaultdict(list)
    for r in records:
        retentions[r.retention_period].append(f"{r.system} ({r.data_type})")

    lines += [
        "## Retention Period Overview",
        "",
        "| Retention Period | Systems / Data Types |",
        "|-----------------|----------------------|",
    ]
    for period, items in sorted(retentions.items()):
        lines.append(f"| {period} | {'; '.join(items[:3])}{'...' if len(items) > 3 else ''} |")
    lines.append("")

    return "\n".join(lines)


def main() -> None:
    """Entry point for the data inventory mapper."""
    parser = argparse.ArgumentParser(
        description="Map data inventory to Mermaid flowchart and markdown summary."
    )
    parser.add_argument("--inventory", required=True, help="Path to data inventory CSV.")
    parser.add_argument(
        "--output",
        choices=["mermaid", "markdown", "both"],
        default="both",
        help="Output format (default: both).",
    )
    args = parser.parse_args()

    records = load_inventory(args.inventory)
    if not records:
        print("Warning: No records loaded from inventory.", file=sys.stderr)
        sys.exit(0)

    parts = []
    if args.output in ("mermaid", "both"):
        parts.append("## Data Flow Diagram\n")
        parts.append(build_mermaid(records))
        parts.append("")
    if args.output in ("markdown", "both"):
        parts.append(build_markdown(records))

    print("\n".join(parts))


if __name__ == "__main__":
    main()
