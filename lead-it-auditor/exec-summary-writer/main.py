"""Executive Summary Writer — produce a polished audit executive summary from findings JSON.

Reads a findings JSON file (list of finding objects), validates each entry, and
renders a structured markdown executive summary with an overview narrative, key
findings table, risk distribution, top recommendations, and a remediation timeline.
"""

import argparse
import json
import os
import sys
from collections import Counter
from datetime import date as date_type
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv

load_dotenv()

VALID_RISK_LEVELS = ("Critical", "High", "Medium", "Low", "Informational")

RISK_EMOJI = {
    "Critical": "🔴",
    "High": "🟠",
    "Medium": "🟡",
    "Low": "🟢",
    "Informational": "🔵",
}

REMEDIATION_TIMELINE = [
    "**Immediate (0–30 days):** Address all Critical findings; assign owners and target dates for High findings.",
    "**Short-term (30–90 days):** Remediate all High findings; develop action plans for Medium findings.",
    "**Medium-term (90–180 days):** Close Medium findings; schedule reviews for Low and Informational items.",
    "**Ongoing:** Embed findings into the risk register; track progress in quarterly audit committee updates.",
]


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments.

    Returns:
        Parsed argument namespace.
    """
    parser = argparse.ArgumentParser(
        description="Generate an executive summary from a structured audit findings JSON file."
    )
    parser.add_argument(
        "--findings",
        required=True,
        type=str,
        help="Path to findings JSON file.",
    )
    parser.add_argument(
        "--scope",
        type=str,
        default=None,
        help="Audit scope description (optional).",
    )
    parser.add_argument(
        "--author",
        type=str,
        default="IT Audit Team",
        help="Report author name (default: IT Audit Team).",
    )
    parser.add_argument(
        "--date",
        type=str,
        default=None,
        help="Report date in YYYY-MM-DD format (default: today).",
    )
    return parser.parse_args()


def load_findings(findings_path: str) -> List[Dict[str, Any]]:
    """Load and validate the findings JSON file.

    Args:
        findings_path: Path to the findings JSON file.

    Returns:
        List of validated finding dictionaries.

    Raises:
        SystemExit: If the file is missing, unreadable, malformed, or empty.
    """
    if not os.path.isfile(findings_path):
        print(f"ERROR: Findings file not found: {findings_path}", file=sys.stderr)
        sys.exit(1)

    try:
        with open(findings_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as exc:
        print(f"ERROR: Malformed JSON in {findings_path}: {exc}", file=sys.stderr)
        sys.exit(1)
    except OSError as exc:
        print(f"ERROR: Cannot read {findings_path}: {exc}", file=sys.stderr)
        sys.exit(1)

    if not isinstance(data, list):
        print("ERROR: Findings file must contain a JSON array at the top level.", file=sys.stderr)
        sys.exit(1)

    if not data:
        print("ERROR: Findings file is empty — nothing to summarise.", file=sys.stderr)
        sys.exit(1)

    required_keys = {"title", "description", "risk_level", "recommendation", "affected_system"}
    invalid_findings = []
    for idx, finding in enumerate(data):
        missing = required_keys - set(finding.keys())
        if missing:
            invalid_findings.append(f"  Finding #{idx + 1}: missing fields: {', '.join(sorted(missing))}")
        elif finding["risk_level"] not in VALID_RISK_LEVELS:
            invalid_findings.append(
                f"  Finding #{idx + 1} ('{finding.get('title', '?')}'): "
                f"invalid risk_level '{finding['risk_level']}'. "
                f"Must be one of: {', '.join(VALID_RISK_LEVELS)}"
            )

    if invalid_findings:
        print("ERROR: Validation failed for the following findings:", file=sys.stderr)
        for msg in invalid_findings:
            print(msg, file=sys.stderr)
        sys.exit(1)

    return data


def resolve_date(date_arg: Optional[str]) -> str:
    """Resolve the report date string.

    Args:
        date_arg: User-supplied date string, or None to use today.

    Returns:
        Date string in YYYY-MM-DD format.

    Raises:
        SystemExit: If the date string cannot be parsed.
    """
    if date_arg is None:
        return date_type.today().isoformat()

    from datetime import datetime
    try:
        datetime.strptime(date_arg, "%Y-%m-%d")
        return date_arg
    except ValueError:
        print(f"ERROR: Invalid date format '{date_arg}'. Expected YYYY-MM-DD.", file=sys.stderr)
        sys.exit(1)


def build_overview(findings: List[Dict[str, Any]], scope: Optional[str]) -> str:
    """Generate a 2–3 sentence overview narrative from findings data.

    Args:
        findings: Validated list of finding dictionaries.
        scope: Optional audit scope description.

    Returns:
        Plain-text overview paragraph.
    """
    counts = Counter(f["risk_level"] for f in findings)
    total = len(findings)
    critical = counts.get("Critical", 0)
    high = counts.get("High", 0)
    systems = sorted({f["affected_system"] for f in findings})

    scope_phrase = f" of **{scope}**" if scope else ""
    system_phrase = (
        f"Affected systems include {', '.join(systems[:3])}"
        + (" and others" if len(systems) > 3 else "")
        + "."
    )

    sentences = [
        f"This report presents the results of an IT audit{scope_phrase}, "
        f"identifying **{total} finding{'s' if total != 1 else ''}** across the reviewed environment.",
    ]

    if critical > 0 or high > 0:
        ch_parts = []
        if critical > 0:
            ch_parts.append(f"**{critical} Critical**")
        if high > 0:
            ch_parts.append(f"**{high} High**")
        sentences.append(
            f"Of these, {' and '.join(ch_parts)} {'finding requires' if (critical + high) == 1 else 'findings require'} "
            f"prompt management attention and remediation within agreed timelines."
        )
    else:
        sentences.append("No Critical or High risk findings were identified during this review.")

    sentences.append(system_phrase)
    return " ".join(sentences)


def render_report(
    findings: List[Dict[str, Any]],
    scope: Optional[str],
    author: str,
    report_date: str,
) -> str:
    """Render the full executive summary as markdown.

    Args:
        findings: Validated list of finding dictionaries.
        scope: Optional audit scope string.
        author: Report author name.
        report_date: Report date in YYYY-MM-DD format.

    Returns:
        Formatted markdown string.
    """
    counts = Counter(f["risk_level"] for f in findings)
    total = len(findings)
    scope_display = scope or "IT General Controls Review"

    lines = [
        "# Executive Summary — IT Audit Report",
        "",
        f"**Scope:** {scope_display}  ",
        f"**Author:** {author}  ",
        f"**Date:** {report_date}",
        "",
        "---",
        "",
        "## Overview",
        "",
        build_overview(findings, scope),
        "",
        "---",
        "",
        "## Key Findings",
        "",
        "| # | Title | Affected System | Risk Level |",
        "|---|-------|-----------------|------------|",
    ]

    for idx, finding in enumerate(findings, start=1):
        icon = RISK_EMOJI.get(finding["risk_level"], "")
        lines.append(
            f"| {idx} | {finding['title']} | {finding['affected_system']} "
            f"| {icon} {finding['risk_level']} |"
        )

    lines += [
        "",
        "---",
        "",
        "## Risk Summary",
        "",
        "| Risk Level | Count | % of Total |",
        "|------------|-------|------------|",
    ]

    for level in VALID_RISK_LEVELS:
        count = counts.get(level, 0)
        pct = (count / total * 100) if total > 0 else 0.0
        icon = RISK_EMOJI.get(level, "")
        lines.append(f"| {icon} {level} | {count} | {pct:.1f}% |")

    # Top recommendations for Critical and High findings
    priority_findings = [f for f in findings if f["risk_level"] in ("Critical", "High")]

    lines += [
        "",
        "---",
        "",
        "## Top Recommendations",
        "",
    ]

    if priority_findings:
        for idx, finding in enumerate(priority_findings, start=1):
            lines.append(
                f"{idx}. **[{finding['risk_level']}] {finding['title']}** "
                f"({finding['affected_system']}): {finding['recommendation']}"
            )
    else:
        lines.append(
            "_No Critical or High findings identified. Review Medium findings for process improvement opportunities._"
        )

    lines += [
        "",
        "---",
        "",
        "## Next Steps",
        "",
    ]

    for step in REMEDIATION_TIMELINE:
        lines.append(f"- {step}")

    lines.append("")
    return "\n".join(lines)


def main() -> None:
    """Entry point for the executive summary writer CLI."""
    args = parse_args()

    findings = load_findings(args.findings)
    report_date = resolve_date(args.date)
    report = render_report(findings, args.scope, args.author, report_date)

    print(report)


if __name__ == "__main__":
    main()
