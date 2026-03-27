"""Vulnerability Parser — risk-rank scan findings by host and severity.

Parses vulnerability scanner CSV output, computes per-host risk scores,
generates an executive summary with ASCII severity chart, and produces a
prioritised remediation matrix.
"""

import argparse
import csv
import json
import sys
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Tuple

SEVERITY_WEIGHT: Dict[str, int] = {
    "Critical": 10,
    "High": 5,
    "Medium": 2,
    "Low": 1,
    "Informational": 0,
}

SEVERITY_ORDER = list(SEVERITY_WEIGHT.keys())

# Common vulnerability type keywords for remediation matrix grouping
VULN_GROUPS = [
    ("SSL/TLS", ["ssl", "tls", "certificate", "cipher", "heartbleed"]),
    ("Missing Patches / EOL Software", ["patch", "update", "unsupported", "end-of-life", "eol", "outdated"]),
    ("Default / Weak Credentials", ["default credential", "weak password", "blank password", "default password"]),
    ("Remote Code Execution", ["rce", "remote code", "code execution", "command injection"]),
    ("SQL Injection", ["sql injection", "sqli"]),
    ("Cross-Site Scripting", ["xss", "cross-site scripting"]),
    ("Open Ports / Services", ["open port", "unnecessary service", "telnet", "ftp", "rsh"]),
    ("Privilege Escalation", ["privilege escalation", "local privilege", "sudo"]),
    ("Injection Vulnerabilities", ["injection", "xxe", "xpath", "ldap injection"]),
    ("Other", []),  # catch-all
]


def load_scan(path: str) -> List[Dict[str, str]]:
    """Load vulnerability scan findings from CSV.

    Args:
        path: Path to scan CSV.

    Returns:
        List of finding dicts.

    Raises:
        SystemExit: On file or schema errors.
    """
    required = {"vulnerability", "severity", "host", "port", "cve_id", "description", "plugin_id"}
    findings: List[Dict[str, str]] = []
    try:
        with open(path, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            if reader.fieldnames is None:
                print("ERROR: Scan file is empty.", file=sys.stderr)
                sys.exit(1)
            cols = {c.strip().lower() for c in reader.fieldnames}
            missing = required - cols
            if missing:
                print(
                    f"ERROR: Scan CSV missing columns: {', '.join(sorted(missing))}",
                    file=sys.stderr,
                )
                sys.exit(1)
            for i, row in enumerate(reader, start=2):
                sev = row.get("severity", "").strip()
                if sev not in SEVERITY_WEIGHT:
                    print(
                        f"WARNING: Row {i} has unknown severity '{sev}', defaulting to Low.",
                        file=sys.stderr,
                    )
                    sev = "Low"
                findings.append(
                    {
                        "vulnerability": row["vulnerability"].strip(),
                        "severity": sev,
                        "host": row["host"].strip(),
                        "port": row["port"].strip(),
                        "cve_id": row["cve_id"].strip(),
                        "description": row["description"].strip(),
                        "plugin_id": row["plugin_id"].strip(),
                    }
                )
    except FileNotFoundError:
        print(f"ERROR: Scan file not found: '{path}'", file=sys.stderr)
        sys.exit(1)
    except csv.Error as exc:
        print(f"ERROR: Malformed CSV: {exc}", file=sys.stderr)
        sys.exit(1)
    if not findings:
        print("ERROR: No findings in scan file.", file=sys.stderr)
        sys.exit(1)
    return findings


def score_hosts(findings: List[Dict[str, str]]) -> List[Dict]:
    """Compute risk score per host.

    Args:
        findings: List of scan findings.

    Returns:
        List of host dicts sorted by risk score descending.
    """
    host_data: Dict[str, Dict] = {}
    for f in findings:
        h = f["host"]
        if h not in host_data:
            host_data[h] = {"host": h, "score": 0, "Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        host_data[h]["score"] += SEVERITY_WEIGHT.get(f["severity"], 0)
        host_data[h][f["severity"]] = host_data[h].get(f["severity"], 0) + 1

    return sorted(host_data.values(), key=lambda x: x["score"], reverse=True)


def severity_counts(findings: List[Dict[str, str]]) -> Dict[str, int]:
    """Count findings by severity.

    Args:
        findings: All scan findings.

    Returns:
        Dict mapping severity to count.
    """
    counts: Dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return counts


def ascii_bar_chart(counts: Dict[str, int], total: int, width: int = 30) -> str:
    """Render an ASCII bar chart of findings by severity.

    Args:
        counts: Severity counts.
        total: Total findings.
        width: Max bar width in characters.

    Returns:
        Multi-line ASCII chart string.
    """
    max_count = max(counts.values()) if counts else 1
    lines = []
    symbols = {"Critical": "█", "High": "▓", "Medium": "▒", "Low": "░", "Informational": "·"}
    for sev in SEVERITY_ORDER:
        count = counts.get(sev, 0)
        bar_len = int(width * count / max_count) if max_count > 0 else 0
        bar = symbols.get(sev, "█") * bar_len
        pct = count / total * 100 if total > 0 else 0.0
        lines.append(f"{sev:<15} {bar:<{width}} {count:>4} ({pct:.1f}%)")
    return "\n".join(lines)


def group_vuln(vuln_name: str, description: str) -> str:
    """Classify a vulnerability into a remediation group.

    Args:
        vuln_name: Vulnerability name.
        description: Vulnerability description.

    Returns:
        Group label string.
    """
    combined = (vuln_name + " " + description).lower()
    for group_name, keywords in VULN_GROUPS[:-1]:
        if any(kw in combined for kw in keywords):
            return group_name
    return "Other"


def remediation_matrix(findings: List[Dict[str, str]]) -> Dict[str, List[Dict]]:
    """Group Critical and High findings by vulnerability type.

    Args:
        findings: All scan findings.

    Returns:
        Dict mapping group name to list of findings.
    """
    matrix: Dict[str, List[Dict]] = defaultdict(list)
    for f in findings:
        if f["severity"] in ("Critical", "High"):
            group = group_vuln(f["vulnerability"], f["description"])
            matrix[group].append(f)
    return dict(matrix)


def render_markdown(findings: List[Dict[str, str]], top_n: int) -> str:
    """Render the vulnerability report as Markdown.

    Args:
        findings: All scan findings.
        top_n: Number of top-risk hosts to show.

    Returns:
        Markdown string.
    """
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    hosts = {f["host"] for f in findings}
    counts = severity_counts(findings)
    host_scores = score_hosts(findings)
    matrix = remediation_matrix(findings)

    lines: List[str] = []
    lines.append("# Vulnerability Scan Report")
    lines.append(f"\n**Generated:** {now}  ")
    lines.append(f"**Total Findings:** {len(findings)}  ")
    lines.append(f"**Unique Hosts:** {len(hosts)}\n")

    # Executive summary + ASCII chart
    lines.append("## Executive Summary\n")
    lines.append("```")
    lines.append(ascii_bar_chart(counts, len(findings)))
    lines.append("```\n")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in SEVERITY_ORDER:
        lines.append(f"| {sev} | {counts.get(sev, 0)} |")

    # Top N riskiest hosts
    top_hosts = host_scores[:top_n]
    lines.append(f"\n## Top {len(top_hosts)} Riskiest Hosts\n")
    lines.append("| Rank | Host | Risk Score | Critical | High | Medium | Low |")
    lines.append("|------|------|-----------|---------|------|--------|-----|")
    for i, h in enumerate(top_hosts, start=1):
        lines.append(
            f"| {i} | {h['host']} | {h['score']} | {h.get('Critical', 0)} | "
            f"{h.get('High', 0)} | {h.get('Medium', 0)} | {h.get('Low', 0)} |"
        )

    # Findings grouped by severity then host
    lines.append("\n## Findings by Severity\n")
    by_sev: Dict[str, Dict[str, List[Dict]]] = {s: defaultdict(list) for s in SEVERITY_ORDER}
    for f in findings:
        by_sev[f["severity"]][f["host"]].append(f)

    for sev in SEVERITY_ORDER:
        host_map = by_sev[sev]
        if not host_map:
            continue
        total_sev = sum(len(v) for v in host_map.values())
        lines.append(f"### {sev} Findings ({total_sev})\n")
        for host in sorted(host_map.keys()):
            host_findings = host_map[host]
            lines.append(f"#### {host} ({len(host_findings)} finding{'s' if len(host_findings) != 1 else ''})\n")
            lines.append("| CVE | Vulnerability | Port | Description |")
            lines.append("|-----|--------------|------|-------------|")
            for f in host_findings:
                desc = f["description"][:80] + "…" if len(f["description"]) > 80 else f["description"]
                lines.append(
                    f"| {f['cve_id'] or 'N/A'} | {f['vulnerability']} | {f['port']} | {desc} |"
                )
            lines.append("")

    # Remediation priority matrix
    lines.append("## Remediation Priority Matrix (Critical & High)\n")
    if matrix:
        for group, group_findings in sorted(matrix.items()):
            hosts_affected = {f["host"] for f in group_findings}
            lines.append(f"### {group} ({len(group_findings)} findings, {len(hosts_affected)} host{'s' if len(hosts_affected) != 1 else ''})\n")
            lines.append("| Host | CVE | Vulnerability | Severity |")
            lines.append("|------|-----|--------------|---------|")
            for f in sorted(group_findings, key=lambda x: SEVERITY_ORDER.index(x["severity"])):
                lines.append(
                    f"| {f['host']} | {f['cve_id'] or 'N/A'} | {f['vulnerability']} | **{f['severity']}** |"
                )
            lines.append("")
    else:
        lines.append("_No Critical or High findings — no immediate remediation required._")

    return "\n".join(lines)


def render_json(findings: List[Dict[str, str]], top_n: int) -> str:
    """Render results as JSON.

    Args:
        findings: All scan findings.
        top_n: Number of top hosts to include.

    Returns:
        JSON string.
    """
    counts = severity_counts(findings)
    host_scores = score_hosts(findings)
    result = {
        "generated": datetime.utcnow().isoformat() + "Z",
        "summary": {"total_findings": len(findings), "unique_hosts": len({f["host"] for f in findings}), "by_severity": counts},
        "top_hosts": host_scores[:top_n],
        "findings": findings,
    }
    return json.dumps(result, indent=2)


def render_csv_output(findings: List[Dict[str, str]]) -> str:
    """Render findings as CSV.

    Args:
        findings: All scan findings.

    Returns:
        CSV string.
    """
    import io
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=["vulnerability", "severity", "host", "port", "cve_id", "description", "plugin_id"])
    writer.writeheader()
    writer.writerows(findings)
    return buf.getvalue()


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        description="Parse vulnerability scan results and generate risk-ranked report."
    )
    parser.add_argument("--scan", required=True, help="Path to vulnerability scan CSV")
    parser.add_argument(
        "--output",
        choices=["markdown", "json", "csv"],
        default="markdown",
        help="Output format (default: markdown)",
    )
    parser.add_argument(
        "--top-hosts",
        type=int,
        default=10,
        help="Number of riskiest hosts to highlight (default: 10)",
    )
    return parser.parse_args()


def main() -> None:
    """Main entry point."""
    args = parse_args()
    if args.top_hosts < 1:
        print("ERROR: --top-hosts must be >= 1.", file=sys.stderr)
        sys.exit(1)
    findings = load_scan(args.scan)
    if args.output == "json":
        print(render_json(findings, args.top_hosts))
    elif args.output == "csv":
        print(render_csv_output(findings))
    else:
        print(render_markdown(findings, args.top_hosts))


if __name__ == "__main__":
    main()
