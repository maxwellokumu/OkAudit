"""Log Analyzer — parse CloudTrail/system logs and flag suspicious events.

Reads JSON-lines log files (or fetches from AWS CloudTrail) and checks each
event against a built-in library of suspicious patterns. Supports custom
pattern overrides, date range filtering, and produces a markdown summary report.
"""

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Built-in suspicious patterns
# ---------------------------------------------------------------------------

SUSPICIOUS_PATTERNS: Dict[str, str] = {
    "ConsoleLoginFailure": "High",
    "DeleteTrail": "Critical",
    "StopLogging": "Critical",
    "AuthorizationFailure": "Medium",
    "RootAccountUsage": "Critical",
    "CreateAccessKey": "Medium",
    "DeleteAccessKey": "Medium",
    "UpdateLoginProfile": "High",
    "PutBucketAcl": "High",
    "DeleteBucket": "High",
    "PutBucketPolicy": "High",
    "TerminateInstances": "Medium",
    "DeleteVpc": "High",
    "ModifySecurityGroup": "Medium",
    "CreateUser": "Low",
    "DeleteUser": "High",
    "AttachUserPolicy": "High",
    "GetSecretValue": "Low",
    "PutSecretValue": "Medium",
    "DeleteSecret": "Critical",
    "DisableKey": "High",
    "ScheduleKeyDeletion": "Critical",
    "PutEventSelectors": "High",
    "DeleteFlowLogs": "High",
}

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
SEVERITY_EMOJI = {"Critical": "🚨", "High": "🔴", "Medium": "🟠", "Low": "🟡"}

# ---------------------------------------------------------------------------
# Sample data for --dry-run / AWS mode
# ---------------------------------------------------------------------------

SAMPLE_EVENTS = [
    {"timestamp": "2025-07-01T08:00:00", "user": "alice", "action": "ListBuckets", "source_ip": "10.0.0.1", "resource": "s3"},
    {"timestamp": "2025-07-01T08:05:00", "user": "alice", "action": "GetObject", "source_ip": "10.0.0.1", "resource": "s3:::prod-bucket"},
    {"timestamp": "2025-07-01T09:00:00", "user": "bob", "action": "ConsoleLoginFailure", "source_ip": "198.51.100.5", "resource": "signin"},
    {"timestamp": "2025-07-01T09:01:00", "user": "bob", "action": "ConsoleLoginFailure", "source_ip": "198.51.100.5", "resource": "signin"},
    {"timestamp": "2025-07-01T09:02:00", "user": "bob", "action": "ConsoleLoginFailure", "source_ip": "198.51.100.5", "resource": "signin"},
    {"timestamp": "2025-07-01T10:00:00", "user": "root", "action": "RootAccountUsage", "source_ip": "203.0.113.10", "resource": "iam"},
    {"timestamp": "2025-07-01T10:05:00", "user": "root", "action": "DeleteBucket", "source_ip": "203.0.113.10", "resource": "s3:::audit-logs-2024"},
    {"timestamp": "2025-07-01T10:10:00", "user": "root", "action": "DeleteTrail", "source_ip": "203.0.113.10", "resource": "cloudtrail:::main-trail"},
    {"timestamp": "2025-07-01T11:00:00", "user": "carol", "action": "DescribeInstances", "source_ip": "10.0.0.2", "resource": "ec2"},
    {"timestamp": "2025-07-01T11:15:00", "user": "carol", "action": "AttachUserPolicy", "source_ip": "10.0.0.2", "resource": "iam:::carol"},
    {"timestamp": "2025-07-01T12:00:00", "user": "svc-deploy", "action": "PutBucketPolicy", "source_ip": "10.0.0.50", "resource": "s3:::prod-bucket"},
    {"timestamp": "2025-07-01T12:05:00", "user": "svc-deploy", "action": "StopLogging", "source_ip": "10.0.0.50", "resource": "cloudtrail"},
    {"timestamp": "2025-07-01T13:00:00", "user": "alice", "action": "CreateAccessKey", "source_ip": "10.0.0.1", "resource": "iam:::new-svc"},
    {"timestamp": "2025-07-01T13:30:00", "user": "dave", "action": "UpdateLoginProfile", "source_ip": "10.0.0.3", "resource": "iam:::carol"},
    {"timestamp": "2025-07-01T14:00:00", "user": "dave", "action": "DeleteUser", "source_ip": "10.0.0.3", "resource": "iam:::temp-user"},
    {"timestamp": "2025-07-01T14:30:00", "user": "eve", "action": "GetSecretValue", "source_ip": "10.0.0.4", "resource": "secretsmanager:::db-password"},
    {"timestamp": "2025-07-01T15:00:00", "user": "eve", "action": "DeleteSecret", "source_ip": "10.0.0.4", "resource": "secretsmanager:::api-key"},
    {"timestamp": "2025-07-01T15:30:00", "user": "frank", "action": "TerminateInstances", "source_ip": "10.0.0.5", "resource": "ec2:::i-0abc123"},
    {"timestamp": "2025-07-01T16:00:00", "user": "frank", "action": "DeleteVpc", "source_ip": "10.0.0.5", "resource": "ec2:::vpc-0123abc"},
    {"timestamp": "2025-07-01T16:30:00", "user": "alice", "action": "PutBucketAcl", "source_ip": "10.0.0.1", "resource": "s3:::prod-bucket"},
    {"timestamp": "2025-07-01T17:00:00", "user": "carol", "action": "CreateUser", "source_ip": "10.0.0.2", "resource": "iam:::new-admin"},
    {"timestamp": "2025-07-01T17:05:00", "user": "carol", "action": "AttachUserPolicy", "source_ip": "10.0.0.2", "resource": "iam:::new-admin"},
    {"timestamp": "2025-07-01T17:10:00", "user": "carol", "action": "ModifySecurityGroup", "source_ip": "10.0.0.2", "resource": "ec2:::sg-0aa111"},
    {"timestamp": "2025-07-02T09:00:00", "user": "alice", "action": "ListUsers", "source_ip": "10.0.0.1", "resource": "iam"},
    {"timestamp": "2025-07-02T09:15:00", "user": "bob", "action": "AuthorizationFailure", "source_ip": "198.51.100.5", "resource": "s3:::confidential"},
    {"timestamp": "2025-07-02T09:30:00", "user": "svc-deploy", "action": "PutSecretValue", "source_ip": "10.0.0.50", "resource": "secretsmanager:::new-key"},
    {"timestamp": "2025-07-02T10:00:00", "user": "grace", "action": "DeleteAccessKey", "source_ip": "10.0.0.6", "resource": "iam:::svc-account"},
    {"timestamp": "2025-07-02T10:30:00", "user": "grace", "action": "ScheduleKeyDeletion", "source_ip": "10.0.0.6", "resource": "kms:::prod-key"},
    {"timestamp": "2025-07-02T11:00:00", "user": "henry", "action": "PutEventSelectors", "source_ip": "10.0.0.7", "resource": "cloudtrail:::main-trail"},
    {"timestamp": "2025-07-02T11:30:00", "user": "henry", "action": "DeleteFlowLogs", "source_ip": "10.0.0.7", "resource": "ec2:::fl-0abc123"},
    {"timestamp": "2025-07-02T12:00:00", "user": "alice", "action": "GetObject", "source_ip": "10.0.0.1", "resource": "s3:::prod-bucket"},
    {"timestamp": "2025-07-02T13:00:00", "user": "dave", "action": "DisableKey", "source_ip": "10.0.0.3", "resource": "kms:::backup-key"},
]


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Analyse log files for suspicious events using built-in and custom patterns."
    )
    parser.add_argument("--logs", help="Path to JSON-lines log file (required for local mode)")
    parser.add_argument("--patterns", help="Path to JSON file: {event_name: severity}")
    parser.add_argument("--mode", choices=["local", "aws"], default="local")
    parser.add_argument("--dry-run", action="store_true", help="Use bundled sample data")
    parser.add_argument("--start", help="Filter events from this ISO timestamp")
    parser.add_argument("--end", help="Filter events until this ISO timestamp")
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------


def parse_ts(ts_str: str) -> Optional[datetime]:
    """Parse an ISO timestamp string into a datetime.

    Args:
        ts_str: Timestamp string.

    Returns:
        datetime or None if unparseable.
    """
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(ts_str[:19], fmt)
        except (ValueError, TypeError):
            pass
    return None


def load_events(args: argparse.Namespace) -> List[Dict[str, Any]]:
    """Load events from file, sample data, or AWS CloudTrail.

    Args:
        args: Parsed CLI arguments.

    Returns:
        List of event dicts.
    """
    if args.mode == "aws":
        return load_cloudtrail(args.dry_run, args.start, args.end)

    if args.dry_run:
        print("INFO: --dry-run — using built-in sample data.\n", file=sys.stderr)
        return SAMPLE_EVENTS

    if not args.logs:
        print("ERROR: --logs is required for local mode.", file=sys.stderr)
        sys.exit(1)

    try:
        with open(args.logs, "r", encoding="utf-8") as fh:
            raw = fh.read().strip()
    except FileNotFoundError:
        print(f"ERROR: Log file not found: '{args.logs}'", file=sys.stderr)
        sys.exit(1)

    events: List[Dict[str, Any]] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return events


def load_cloudtrail(dry_run: bool, start: Optional[str], end: Optional[str]) -> List[Dict[str, Any]]:
    """Fetch events from AWS CloudTrail.

    Args:
        dry_run: Use sample data if True.
        start: Start timestamp string.
        end: End timestamp string.

    Returns:
        List of event dicts.
    """
    if dry_run:
        print("INFO: --dry-run — using built-in sample data.\n", file=sys.stderr)
        return SAMPLE_EVENTS

    try:
        import boto3  # type: ignore
    except ImportError:
        print("ERROR: boto3 not installed. Run: pip install boto3", file=sys.stderr)
        sys.exit(1)

    try:
        ct = boto3.client("cloudtrail")
        end_dt = datetime.utcnow()
        start_dt = end_dt - timedelta(days=7)
        if start:
            start_dt = parse_ts(start) or start_dt
        if end:
            end_dt = parse_ts(end) or end_dt

        events: List[Dict[str, Any]] = []
        paginator = ct.get_paginator("lookup_events")
        for page in paginator.paginate(StartTime=start_dt, EndTime=end_dt):
            for e in page["Events"]:
                raw = json.loads(e.get("CloudTrailEvent", "{}"))
                events.append({
                    "timestamp": str(e.get("EventTime", "")),
                    "user": (raw.get("userIdentity", {}).get("userName")
                             or raw.get("userIdentity", {}).get("type", "unknown")),
                    "action": e.get("EventName", ""),
                    "source_ip": raw.get("sourceIPAddress", ""),
                    "resource": (e.get("Resources", [{}])[0].get("ResourceName", "")
                                 if e.get("Resources") else ""),
                })
        return events
    except Exception as exc:
        print(f"ERROR: CloudTrail API failed — {exc}", file=sys.stderr)
        sys.exit(1)


def load_patterns(path: str) -> Dict[str, str]:
    """Load custom patterns from JSON file.

    Args:
        path: Path to JSON file.

    Returns:
        Dict of event_name -> severity.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            print("ERROR: Patterns file must be a JSON object.", file=sys.stderr)
            sys.exit(1)
        return data
    except FileNotFoundError:
        print(f"ERROR: Patterns file not found: '{path}'", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as exc:
        print(f"ERROR: Invalid JSON in patterns file — {exc}", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------


def analyse(
    events: List[Dict[str, Any]],
    patterns: Dict[str, str],
    start: Optional[str],
    end: Optional[str],
) -> Tuple[List[Dict], Dict[str, int], Dict[str, int]]:
    """Analyse events against patterns with optional date filtering.

    Args:
        events: Raw event list.
        patterns: Combined pattern dict.
        start: Optional start filter.
        end: Optional end filter.

    Returns:
        Tuple of (flagged_events, severity_counts, user_counts).
    """
    start_dt = parse_ts(start) if start else None
    end_dt = parse_ts(end) if end else None

    flagged: List[Dict] = []
    user_counts: Dict[str, int] = defaultdict(int)
    severity_counts: Dict[str, int] = defaultdict(int)

    for evt in events:
        ts = parse_ts(evt.get("timestamp", ""))
        if start_dt and ts and ts < start_dt:
            continue
        if end_dt and ts and ts > end_dt:
            continue

        user = evt.get("user", "unknown")
        action = evt.get("action", "")
        user_counts[user] += 1

        severity = patterns.get(action)
        if severity:
            severity_counts[severity] += 1
            flagged.append({
                "timestamp": evt.get("timestamp", ""),
                "user": user,
                "action": action,
                "severity": severity,
                "source_ip": evt.get("source_ip", ""),
                "resource": evt.get("resource", ""),
            })

    return flagged, dict(severity_counts), dict(user_counts)


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


def ascii_bar(value: int, max_val: int, width: int = 20) -> str:
    """Generate an ASCII progress bar.

    Args:
        value: Current value.
        max_val: Maximum value for scaling.
        width: Bar character width.

    Returns:
        ASCII bar string.
    """
    if max_val == 0:
        return "░" * width
    filled = int((value / max_val) * width)
    return "█" * filled + "░" * (width - filled)


def render_report(
    events: List[Dict],
    flagged: List[Dict],
    severity_counts: Dict[str, int],
    user_counts: Dict[str, int],
    mode: str,
) -> str:
    """Render the markdown log analysis report.

    Args:
        events: All events analysed.
        flagged: Flagged events list.
        severity_counts: Counts per severity level.
        user_counts: Counts per user.
        mode: Execution mode string.

    Returns:
        Markdown string.
    """
    date_str = datetime.now().strftime("%Y-%m-%d %H:%M")
    lines: List[str] = []

    lines.append("# Log Analysis Report\n")
    lines.append(f"**Date:** {date_str}  ")
    lines.append(f"**Mode:** {mode}  ")
    lines.append(f"**Total Events:** {len(events)}  ")
    lines.append(f"**Flagged Events:** {len(flagged)}\n")
    lines.append("---\n")

    # Summary counts
    lines.append("## Summary\n")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in ["Critical", "High", "Medium", "Low"]:
        emoji = SEVERITY_EMOJI.get(sev, "")
        lines.append(f"| {emoji} {sev} | {severity_counts.get(sev, 0)} |")
    lines.append("")

    if not flagged:
        lines.append("> ✅ No suspicious events detected.\n")
        return "\n".join(lines)

    # Flagged events table
    lines.append("---\n")
    lines.append("## Flagged Events\n")
    lines.append("| Timestamp | User | Event | Severity | Source IP | Resource |")
    lines.append("|-----------|------|-------|----------|-----------|----------|")

    sorted_flagged = sorted(flagged, key=lambda x: SEVERITY_ORDER.get(x["severity"], 3))
    for f in sorted_flagged:
        emoji = SEVERITY_EMOJI.get(f["severity"], "")
        lines.append(
            f"| {f['timestamp']} | `{f['user']}` | `{f['action']}` | "
            f"{emoji} {f['severity']} | {f['source_ip']} | {f['resource']} |"
        )
    lines.append("")

    # Top 10 most active users
    lines.append("---\n")
    lines.append("## Top 10 Most Active Users\n")
    lines.append("| Rank | User | Total Events |")
    lines.append("|------|------|--------------|")
    top_users = sorted(user_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    for i, (user, count) in enumerate(top_users, 1):
        lines.append(f"| {i} | `{user}` | {count} |")
    lines.append("")

    # ASCII severity distribution
    lines.append("---\n")
    lines.append("## Severity Distribution\n")
    lines.append("```")
    max_count = max(severity_counts.values()) if severity_counts else 1
    for sev in ["Critical", "High", "Medium", "Low"]:
        count = severity_counts.get(sev, 0)
        bar = ascii_bar(count, max_count)
        lines.append(f"{sev:10s} {bar} {count}")
    lines.append("```\n")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Main entry point."""
    args = parse_args()

    events = load_events(args)
    if not events:
        print("ERROR: No events found.", file=sys.stderr)
        sys.exit(1)

    patterns = dict(SUSPICIOUS_PATTERNS)
    if args.patterns:
        custom = load_patterns(args.patterns)
        patterns.update(custom)

    flagged, severity_counts, user_counts = analyse(events, patterns, args.start, args.end)
    print(render_report(events, flagged, severity_counts, user_counts, args.mode))


if __name__ == "__main__":
    main()
