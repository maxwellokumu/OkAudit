"""Network Configuration Reviewer.

Analyses firewall and security group rules for misconfigurations,
overly permissive access, and risky patterns. Supports local CSV
files and AWS Security Groups via boto3.
"""

import argparse
import csv
import json
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

from dotenv import load_dotenv

load_dotenv()

SENSITIVE_PORTS = {22, 23, 3389, 1433, 3306, 5432, 27017, 6379, 9200, 8080, 8443, 445, 135, 5900}
DEPRECATED_PROTOCOLS_PORTS = {23: "Telnet", 21: "FTP", 514: "RSH"}
OPEN_CIDR = {"0.0.0.0/0", "::/0", "any", "*", "0.0.0.0"}

SAMPLE_RULES = [
    {"source": "0.0.0.0/0", "destination": "10.0.0.5", "port": "22", "protocol": "TCP", "action": "ALLOW", "description": ""},
    {"source": "0.0.0.0/0", "destination": "10.0.0.6", "port": "3389", "protocol": "TCP", "action": "ALLOW", "description": "RDP open to internet"},
    {"source": "any", "destination": "any", "port": "any", "protocol": "any", "action": "ALLOW", "description": "Legacy catch-all rule"},
    {"source": "10.0.1.0/24", "destination": "10.0.2.0/24", "port": "443", "protocol": "TCP", "action": "ALLOW", "description": "Internal HTTPS traffic"},
    {"source": "0.0.0.0/0", "destination": "10.0.0.7", "port": "23", "protocol": "TCP", "action": "ALLOW", "description": "Telnet access"},
    {"source": "10.0.0.0/8", "destination": "10.0.1.5", "port": "3306", "protocol": "TCP", "action": "ALLOW", "description": "MySQL from internal"},
    {"source": "192.168.1.0/24", "destination": "10.0.2.10", "port": "8080", "protocol": "TCP", "action": "ALLOW", "description": ""},
    {"source": "0.0.0.0/0", "destination": "10.0.0.8", "port": "80", "protocol": "TCP", "action": "ALLOW", "description": "Public HTTP"},
    {"source": "10.0.3.0/24", "destination": "10.0.1.0/24", "port": "1-65535", "protocol": "TCP", "action": "ALLOW", "description": "Broad port range"},
    {"source": "10.0.4.5", "destination": "10.0.1.10", "port": "443", "protocol": "TCP", "action": "DENY", "description": "Block specific host"},
    {"source": "0.0.0.0/0", "destination": "10.0.0.9", "port": "21", "protocol": "TCP", "action": "ALLOW", "description": "FTP upload server"},
    {"source": "172.16.0.0/12", "destination": "10.0.2.0/24", "port": "5432", "protocol": "TCP", "action": "ALLOW", "description": "Postgres from private"},
    {"source": "10.0.5.0/24", "destination": "10.0.2.5", "port": "27017", "protocol": "TCP", "action": "ALLOW", "description": "MongoDB internal"},
    {"source": "0.0.0.0/0", "destination": "10.0.0.10", "port": "514", "protocol": "TCP", "action": "ALLOW", "description": "RSH legacy"},
    {"source": "10.0.1.5", "destination": "10.0.3.5", "port": "22", "protocol": "TCP", "action": "ALLOW", "description": "Bastion SSH"},
    {"source": "0.0.0.0/0", "destination": "10.0.0.11", "port": "9200", "protocol": "TCP", "action": "ALLOW", "description": "Elasticsearch public"},
    {"source": "10.0.0.0/8", "destination": "10.0.4.0/24", "port": "445", "protocol": "TCP", "action": "ALLOW", "description": "SMB internal"},
    {"source": "192.168.0.0/16", "destination": "10.0.2.0/24", "port": "1000-5000", "protocol": "TCP", "action": "ALLOW", "description": "Broad range"},
    {"source": "10.0.6.0/24", "destination": "10.0.2.0/24", "port": "5432", "protocol": "TCP", "action": "DENY", "description": "Block analytics to DB"},
    {"source": "10.0.1.0/24", "destination": "10.0.5.0/24", "port": "443", "protocol": "TCP", "action": "ALLOW", "description": "App to payment API"},
]


@dataclass
class Rule:
    """Represents a single firewall rule."""

    index: int
    source: str
    destination: str
    port: str
    protocol: str
    action: str
    description: str


@dataclass
class Violation:
    """A detected rule violation."""

    rule_index: int
    source: str
    destination: str
    port: str
    protocol: str
    issue: str
    risk: str


def parse_port_range(port_str: str) -> Optional[tuple]:
    """Parse a port string into (low, high) tuple.

    Args:
        port_str: Port value such as '80', '1-1024', or 'any'.

    Returns:
        Tuple of (low, high) or None if not parseable.
    """
    port_str = port_str.strip()
    if port_str.lower() in ("any", "*", "all", ""):
        return (0, 65535)
    if "-" in port_str:
        parts = port_str.split("-", 1)
        try:
            return (int(parts[0]), int(parts[1]))
        except ValueError:
            return None
    try:
        p = int(port_str)
        return (p, p)
    except ValueError:
        return None


def is_open_cidr(value: str) -> bool:
    """Return True if value represents a fully open source/destination.

    Args:
        value: IP address, CIDR, or keyword like 'any'.

    Returns:
        True if the value is considered an open/any address.
    """
    return value.strip().lower() in {v.lower() for v in OPEN_CIDR}


def analyse_rule(rule: Rule) -> List[Violation]:
    """Detect all violations for a single rule.

    Args:
        rule: The Rule object to inspect.

    Returns:
        List of Violation objects found.
    """
    violations: List[Violation] = []
    action = rule.action.strip().upper()
    port_range = parse_port_range(rule.port)

    # 1. Open inbound source with ALLOW
    if action == "ALLOW" and is_open_cidr(rule.source):
        violations.append(Violation(
            rule_index=rule.index,
            source=rule.source,
            destination=rule.destination,
            port=rule.port,
            protocol=rule.protocol,
            issue="Inbound ALLOW from any source (0.0.0.0/0 or ::/0)",
            risk="High",
        ))

    # 2. Sensitive port exposed to any destination
    if action == "ALLOW" and is_open_cidr(rule.destination) and port_range:
        for sp in SENSITIVE_PORTS:
            if port_range[0] <= sp <= port_range[1]:
                violations.append(Violation(
                    rule_index=rule.index,
                    source=rule.source,
                    destination=rule.destination,
                    port=rule.port,
                    protocol=rule.protocol,
                    issue=f"ALLOW to 0.0.0.0/0 on sensitive port {sp}",
                    risk="Critical",
                ))
                break

    # 3. Any-to-any rule
    if (action == "ALLOW" and is_open_cidr(rule.source)
            and is_open_cidr(rule.destination)
            and rule.port.strip().lower() in ("any", "*", "all", "")):
        violations.append(Violation(
            rule_index=rule.index,
            source=rule.source,
            destination=rule.destination,
            port=rule.port,
            protocol=rule.protocol,
            issue="Any-to-any ALLOW rule — fully open traffic",
            risk="Critical",
        ))

    # 4. Missing description
    if not rule.description.strip():
        violations.append(Violation(
            rule_index=rule.index,
            source=rule.source,
            destination=rule.destination,
            port=rule.port,
            protocol=rule.protocol,
            issue="Rule has no description",
            risk="Low",
        ))

    # 5. Deprecated protocols
    if action == "ALLOW" and port_range:
        for dep_port, dep_name in DEPRECATED_PROTOCOLS_PORTS.items():
            if port_range[0] <= dep_port <= port_range[1]:
                violations.append(Violation(
                    rule_index=rule.index,
                    source=rule.source,
                    destination=rule.destination,
                    port=rule.port,
                    protocol=rule.protocol,
                    issue=f"ALLOW on deprecated protocol {dep_name} (port {dep_port})",
                    risk="High",
                ))
                break

    # 6. Overly broad port range (>1000 ports)
    if action == "ALLOW" and port_range and (port_range[1] - port_range[0]) > 1000:
        violations.append(Violation(
            rule_index=rule.index,
            source=rule.source,
            destination=rule.destination,
            port=rule.port,
            protocol=rule.protocol,
            issue=f"Overly broad port range ({port_range[0]}-{port_range[1]}, "
                  f"{port_range[1] - port_range[0] + 1} ports)",
            risk="Medium",
        ))

    return violations


def load_rules_from_csv(path: str) -> List[Rule]:
    """Load firewall rules from a CSV file.

    Args:
        path: Filesystem path to the CSV file.

    Returns:
        List of Rule objects.

    Raises:
        SystemExit: On file not found or missing required columns.
    """
    required_cols = {"source", "destination", "port", "protocol", "action", "description"}
    if not os.path.isfile(path):
        print(f"Error: Rules file not found: {path}", file=sys.stderr)
        sys.exit(1)
    rules: List[Rule] = []
    try:
        with open(path, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            if not reader.fieldnames:
                print("Error: CSV file is empty or has no header.", file=sys.stderr)
                sys.exit(1)
            cols = {c.strip().lower() for c in reader.fieldnames}
            missing = required_cols - cols
            if missing:
                print(f"Error: CSV missing columns: {missing}", file=sys.stderr)
                sys.exit(1)
            for i, row in enumerate(reader, start=1):
                rules.append(Rule(
                    index=i,
                    source=row.get("source", "").strip(),
                    destination=row.get("destination", "").strip(),
                    port=row.get("port", "").strip(),
                    protocol=row.get("protocol", "").strip(),
                    action=row.get("action", "").strip(),
                    description=row.get("description", "").strip(),
                ))
    except csv.Error as exc:
        print(f"Error reading CSV: {exc}", file=sys.stderr)
        sys.exit(1)
    return rules


def load_rules_from_aws(dry_run: bool) -> List[Rule]:
    """Fetch rules from AWS EC2 Security Groups.

    Args:
        dry_run: If True, return sample data instead of calling AWS.

    Returns:
        List of Rule objects.
    """
    if dry_run:
        print("# [dry-run] Using sample data instead of AWS API.", file=sys.stderr)
        return [Rule(index=i + 1, **{k: str(v) for k, v in r.items()})
                for i, r in enumerate(SAMPLE_RULES)]
    try:
        import boto3  # type: ignore
    except ImportError:
        print("Error: boto3 not installed. Run: pip install boto3", file=sys.stderr)
        sys.exit(1)
    ec2 = boto3.client("ec2")
    response = ec2.describe_security_groups()
    rules: List[Rule] = []
    idx = 1
    for sg in response.get("SecurityGroups", []):
        sg_id = sg.get("GroupId", "unknown")
        for perm in sg.get("IpPermissions", []):
            from_port = str(perm.get("FromPort", "any"))
            to_port = str(perm.get("ToPort", "any"))
            port = from_port if from_port == to_port else f"{from_port}-{to_port}"
            protocol = perm.get("IpProtocol", "any")
            for ip_range in perm.get("IpRanges", []):
                rules.append(Rule(
                    index=idx,
                    source=ip_range.get("CidrIp", ""),
                    destination=sg_id,
                    port=port,
                    protocol=protocol,
                    action="ALLOW",
                    description=ip_range.get("Description", ""),
                ))
                idx += 1
    return rules


def risk_order(risk: str) -> int:
    """Return sort key for risk level.

    Args:
        risk: Risk label string.

    Returns:
        Integer sort key (lower = higher risk).
    """
    return {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}.get(risk, 4)


def render_report(rules: List[Rule], violations: List[Violation]) -> str:
    """Render the analysis results as a markdown report.

    Args:
        rules: All loaded rules.
        violations: All detected violations.

    Returns:
        Markdown string.
    """
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    violated_rule_ids = {v.rule_index for v in violations}
    compliant_count = sum(1 for r in rules if r.index not in violated_rule_ids)

    risk_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for v in violations:
        risk_counts[v.risk] = risk_counts.get(v.risk, 0) + 1

    lines = [
        "# Network Configuration Review Report",
        f"\n**Generated:** {now}",
        f"**Total Rules Analysed:** {len(rules)}",
        "",
        "## Summary",
        "",
        f"| Metric | Count |",
        f"|--------|-------|",
        f"| Total Rules | {len(rules)} |",
        f"| Compliant Rules | {compliant_count} |",
        f"| Rules with Violations | {len(violated_rule_ids)} |",
        f"| Total Violations | {len(violations)} |",
        f"| Critical Violations | {risk_counts['Critical']} |",
        f"| High Violations | {risk_counts['High']} |",
        f"| Medium Violations | {risk_counts['Medium']} |",
        f"| Low Violations | {risk_counts['Low']} |",
        "",
    ]

    if violations:
        lines += [
            "## Violations",
            "",
            "| Rule # | Source | Destination | Port | Protocol | Issue | Risk |",
            "|--------|--------|-------------|------|----------|-------|------|",
        ]
        sorted_v = sorted(violations, key=lambda x: risk_order(x.risk))
        for v in sorted_v:
            lines.append(
                f"| {v.rule_index} | `{v.source}` | `{v.destination}` | "
                f"{v.port} | {v.protocol} | {v.issue} | **{v.risk}** |"
            )
        lines.append("")
    else:
        lines += ["## Violations", "", "No violations detected.", ""]

    lines += [
        "## Compliant Rules",
        "",
        f"{compliant_count} rules passed all checks with no violations.",
        "",
        "## Recommendations",
        "",
        "1. **Remove or restrict any-source (0.0.0.0/0) ALLOW rules** — scope to specific IP ranges.",
        "2. **Disable deprecated protocols** — replace Telnet (23), FTP (21), RSH (514) with SSH/SFTP.",
        "3. **Restrict sensitive port exposure** — ports 22, 3389, 3306, etc. must not be open to 0.0.0.0/0.",
        "4. **Eliminate any-to-any rules** — each rule should have explicit source, destination, and port.",
        "5. **Narrow port ranges** — avoid ranges larger than 100 ports; define only required ports.",
        "6. **Add descriptions to all rules** — undocumented rules complicate audits and incident response.",
        "7. **Review at least quarterly** — stale rules accumulate risk over time.",
    ]

    return "\n".join(lines)


def main() -> None:
    """Entry point for the network configuration reviewer."""
    parser = argparse.ArgumentParser(
        description="Review firewall/security-group rules for misconfigurations."
    )
    parser.add_argument("--rules", help="Path to CSV firewall rules file.")
    parser.add_argument(
        "--mode",
        choices=["local", "aws"],
        default="local",
        help="Execution mode: local (CSV) or aws (EC2 Security Groups).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Use bundled sample data (no live API calls).",
    )
    args = parser.parse_args()

    if args.mode == "aws":
        rules = load_rules_from_aws(dry_run=args.dry_run)
    else:
        if not args.rules:
            print("Error: --rules is required in local mode.", file=sys.stderr)
            sys.exit(1)
        rules = load_rules_from_csv(args.rules)

    if not rules:
        print("Warning: No rules loaded — nothing to analyse.", file=sys.stderr)
        sys.exit(0)

    violations: List[Violation] = []
    for rule in rules:
        violations.extend(analyse_rule(rule))

    print(render_report(rules, violations))


if __name__ == "__main__":
    main()
