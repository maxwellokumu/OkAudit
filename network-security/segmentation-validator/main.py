"""Network Segmentation Validator.

Loads zone definitions and firewall rules, then classifies each rule as
intra-zone, inter-zone allowed, inter-zone denied, or unzoned.
Flags high-risk cross-zone flows such as Internet → DB or DMZ → Internal.
Uses only Python's built-in ipaddress module for all IP/CIDR matching.
"""

import argparse
import csv
import ipaddress
import json
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from dotenv import load_dotenv

load_dotenv()

# Zone pairs that are always considered high risk if ALLOWED
HIGH_RISK_FLOWS = {
    ("Internet", "DB"),
    ("Internet", "Management"),
    ("Internet", "Internal"),
    ("DMZ", "DB"),
    ("DMZ", "Management"),
    ("DMZ", "Internal"),
    ("Internal", "Management"),
}


@dataclass
class ZoneNetwork:
    """A CIDR block belonging to a named zone."""

    zone: str
    network: ipaddress.IPv4Network


@dataclass
class FirewallRule:
    """A single firewall rule with source, destination, port, protocol, action."""

    index: int
    source: str
    destination: str
    port: str
    protocol: str
    action: str


@dataclass
class ClassifiedRule:
    """A firewall rule with its resolved zone classification."""

    rule: FirewallRule
    src_zone: Optional[str]
    dst_zone: Optional[str]
    classification: str  # intra_zone | inter_zone_allowed | inter_zone_denied | unzoned
    risk_notes: str


def load_zones(path: str) -> List[ZoneNetwork]:
    """Load zone definitions from a JSON file.

    Args:
        path: Path to JSON file mapping zone names to CIDR lists.

    Returns:
        Flat list of ZoneNetwork objects.

    Raises:
        SystemExit: On file not found or parse errors.
    """
    if not os.path.isfile(path):
        print(f"Error: Zones file not found: {path}", file=sys.stderr)
        sys.exit(1)
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as exc:
        print(f"Error: Malformed JSON in zones file — {exc}", file=sys.stderr)
        sys.exit(1)
    if not isinstance(data, dict):
        print("Error: Zones JSON must be an object mapping zone names to CIDR lists.", file=sys.stderr)
        sys.exit(1)
    zone_networks: List[ZoneNetwork] = []
    for zone_name, cidrs in data.items():
        if not isinstance(cidrs, list):
            print(f"Warning: Skipping zone '{zone_name}' — value must be a list.", file=sys.stderr)
            continue
        for cidr in cidrs:
            try:
                net = ipaddress.IPv4Network(cidr, strict=False)
                zone_networks.append(ZoneNetwork(zone=zone_name, network=net))
            except ValueError:
                print(f"Warning: Invalid CIDR '{cidr}' in zone '{zone_name}' — skipping.", file=sys.stderr)
    return zone_networks


def load_rules(path: str) -> List[FirewallRule]:
    """Load firewall rules from a CSV file.

    Args:
        path: Path to CSV with columns: source,destination,port,protocol,action.

    Returns:
        List of FirewallRule objects.
    """
    if not os.path.isfile(path):
        print(f"Error: Rules file not found: {path}", file=sys.stderr)
        sys.exit(1)
    required = {"source", "destination", "port", "protocol", "action"}
    rules: List[FirewallRule] = []
    try:
        with open(path, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            if not reader.fieldnames:
                print("Error: Rules CSV is empty.", file=sys.stderr)
                sys.exit(1)
            cols = {c.strip().lower() for c in reader.fieldnames}
            missing = required - cols
            if missing:
                print(f"Error: Rules CSV missing columns: {missing}", file=sys.stderr)
                sys.exit(1)
            for i, row in enumerate(reader, 1):
                rules.append(FirewallRule(
                    index=i,
                    source=row.get("source", "").strip(),
                    destination=row.get("destination", "").strip(),
                    port=row.get("port", "").strip(),
                    protocol=row.get("protocol", "").strip(),
                    action=row.get("action", "").strip().upper(),
                ))
    except csv.Error as exc:
        print(f"Error reading rules CSV: {exc}", file=sys.stderr)
        sys.exit(1)
    return rules


def resolve_zone(ip_or_cidr: str, zone_networks: List[ZoneNetwork]) -> Optional[str]:
    """Determine which zone an IP or CIDR belongs to.

    Matches by checking if the address/network overlaps with zone CIDRs.
    First match wins.

    Args:
        ip_or_cidr: An IP address or CIDR string.
        zone_networks: List of known zone networks.

    Returns:
        Zone name string, or None if not matched.
    """
    stripped = ip_or_cidr.strip().lower()
    if stripped in ("any", "*", "0.0.0.0/0", "0.0.0.0"):
        return "Internet"
    try:
        # Try as a single IP first
        addr = ipaddress.IPv4Address(stripped)
        for zn in zone_networks:
            if addr in zn.network:
                return zn.zone
        return None
    except ValueError:
        pass
    try:
        net = ipaddress.IPv4Network(stripped, strict=False)
        for zn in zone_networks:
            if net.overlaps(zn.network):
                return zn.zone
        return None
    except ValueError:
        return None


def classify_rule(rule: FirewallRule, zone_networks: List[ZoneNetwork]) -> ClassifiedRule:
    """Classify a rule based on zone membership.

    Args:
        rule: The firewall rule to classify.
        zone_networks: All known zone definitions.

    Returns:
        ClassifiedRule with zone info and classification.
    """
    src_zone = resolve_zone(rule.source, zone_networks)
    dst_zone = resolve_zone(rule.destination, zone_networks)

    risk_notes = ""
    if src_zone is None or dst_zone is None:
        classification = "unzoned"
        risk_notes = "Source or destination does not belong to any defined zone"
    elif src_zone == dst_zone:
        classification = "intra_zone"
    elif rule.action == "ALLOW":
        classification = "inter_zone_allowed"
        pair = (src_zone, dst_zone)
        rev_pair = (dst_zone, src_zone)
        if pair in HIGH_RISK_FLOWS or rev_pair in HIGH_RISK_FLOWS:
            risk_notes = f"High-risk cross-zone flow: {src_zone} → {dst_zone}"
        else:
            risk_notes = f"Cross-zone flow: {src_zone} → {dst_zone}"
    else:
        classification = "inter_zone_denied"

    return ClassifiedRule(
        rule=rule,
        src_zone=src_zone,
        dst_zone=dst_zone,
        classification=classification,
        risk_notes=risk_notes,
    )


def render_report(
    zone_networks: List[ZoneNetwork],
    rules: List[FirewallRule],
    classified: List[ClassifiedRule],
    zones_raw: Dict,
) -> str:
    """Render the segmentation validation report as markdown.

    Args:
        zone_networks: Parsed zone network objects.
        rules: All loaded rules.
        classified: All classified rules.
        zones_raw: Original zone JSON dict for display.

    Returns:
        Markdown string.
    """
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    intra = [c for c in classified if c.classification == "intra_zone"]
    inter_allowed = [c for c in classified if c.classification == "inter_zone_allowed"]
    inter_denied = [c for c in classified if c.classification == "inter_zone_denied"]
    unzoned = [c for c in classified if c.classification == "unzoned"]
    high_risk = [c for c in inter_allowed if "High-risk" in c.risk_notes]

    lines = [
        "# Network Segmentation Validation Report",
        "",
        f"**Generated:** {now}",
        f"**Total Rules:** {len(rules)}",
        "",
        "## Zone Definitions",
        "",
        "| Zone | CIDRs |",
        "|------|-------|",
    ]
    for zone_name, cidrs in zones_raw.items():
        cidr_str = ", ".join(cidrs) if isinstance(cidrs, list) else str(cidrs)
        lines.append(f"| {zone_name} | `{cidr_str}` |")
    lines.append("")

    # Summary
    lines += [
        "## Classification Summary",
        "",
        "| Classification | Count |",
        "|----------------|-------|",
        f"| Intra-zone (compliant) | {len(intra)} |",
        f"| Inter-zone ALLOWED (flagged) | {len(inter_allowed)} |",
        f"| Inter-zone DENIED (compliant) | {len(inter_denied)} |",
        f"| Unzoned (flagged) | {len(unzoned)} |",
        f"| **High-risk cross-zone flows** | **{len(high_risk)}** |",
        "",
    ]

    # Inter-zone ALLOWED
    if inter_allowed:
        lines += [
            "## Allowed Cross-Zone Flows",
            "",
            "| Rule # | Source Zone | Dst Zone | Source | Destination | Port | Protocol | Risk Notes |",
            "|--------|-------------|----------|--------|-------------|------|----------|------------|",
        ]
        for c in sorted(inter_allowed, key=lambda x: (0 if "High-risk" in x.risk_notes else 1)):
            lines.append(
                f"| {c.rule.index} | {c.src_zone} | {c.dst_zone} | "
                f"`{c.rule.source}` | `{c.rule.destination}` | "
                f"{c.rule.port} | {c.rule.protocol} | {c.risk_notes} |"
            )
        lines.append("")
    else:
        lines += ["## Allowed Cross-Zone Flows", "", "No cross-zone ALLOW rules detected.", ""]

    # Unzoned rules
    if unzoned:
        lines += [
            "## Unzoned Rules",
            "",
            "| Rule # | Source | Destination | Port | Protocol | Action | Notes |",
            "|--------|--------|-------------|------|----------|--------|-------|",
        ]
        for c in unzoned:
            lines.append(
                f"| {c.rule.index} | `{c.rule.source}` | `{c.rule.destination}` | "
                f"{c.rule.port} | {c.rule.protocol} | {c.rule.action} | {c.risk_notes} |"
            )
        lines.append("")
    else:
        lines += ["## Unzoned Rules", "", "All rules matched defined zones.", ""]

    # Risk Assessment
    lines += [
        "## Risk Assessment",
        "",
    ]
    if high_risk:
        lines.append(f"⚠️  **{len(high_risk)} high-risk cross-zone ALLOW rule(s) detected:**")
        lines.append("")
        for c in high_risk:
            lines.append(
                f"- Rule {c.rule.index}: `{c.rule.source}` ({c.src_zone}) → "
                f"`{c.rule.destination}` ({c.dst_zone}) port {c.rule.port} — "
                f"{c.risk_notes}"
            )
        lines.append("")
        lines.append("**Recommendations:**")
        lines.append("")
        lines.append("1. Restrict or remove high-risk cross-zone ALLOW rules — use explicit deny-by-default.")
        lines.append("2. Route Internet-to-Internal traffic through DMZ proxies only.")
        lines.append("3. Ensure DB zone is only reachable from the Internal/App zone on specific ports.")
        lines.append("4. Management zone access should be restricted to bastion hosts or VPN only.")
        lines.append("5. Document all legitimate cross-zone flows and justify each ALLOW rule.")
    else:
        lines.append("✅ No high-risk cross-zone flows detected.")
        lines.append("")
        lines.append("Continue to review inter-zone ALLOW rules periodically.")

    return "\n".join(lines)


def main() -> None:
    """Entry point for the segmentation validator."""
    parser = argparse.ArgumentParser(
        description="Validate network segmentation against zone definitions."
    )
    parser.add_argument("--zones", required=True, help="Path to zone definitions JSON.")
    parser.add_argument("--rules", required=True, help="Path to firewall rules CSV.")
    args = parser.parse_args()

    with open(args.zones, encoding="utf-8") as fh:
        zones_raw: Dict = json.load(fh)

    zone_networks = load_zones(args.zones)
    if not zone_networks:
        print("Error: No valid zone networks loaded.", file=sys.stderr)
        sys.exit(1)

    rules = load_rules(args.rules)
    if not rules:
        print("Warning: No rules loaded.", file=sys.stderr)
        sys.exit(0)

    classified = [classify_rule(r, zone_networks) for r in rules]
    print(render_report(zone_networks, rules, classified, zones_raw))


if __name__ == "__main__":
    main()
