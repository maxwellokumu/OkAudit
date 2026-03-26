"""Incident Timeline Builder — construct a chronological incident timeline from logs.

Reads JSON-lines or CSV log files, filters by date range and/or actor, groups
events by hour, and flags events matching built-in IOC patterns. Outputs a
structured markdown timeline or JSON array.
"""

import argparse
import csv
import io
import json
import sys
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# IOC patterns (same as log-analyzer)
# ---------------------------------------------------------------------------

IOC_PATTERNS = {
    "ConsoleLoginFailure", "DeleteTrail", "StopLogging", "AuthorizationFailure",
    "RootAccountUsage", "CreateAccessKey", "DeleteAccessKey", "UpdateLoginProfile",
    "PutBucketAcl", "DeleteBucket", "PutBucketPolicy", "TerminateInstances",
    "DeleteVpc", "ModifySecurityGroup", "DeleteUser", "AttachUserPolicy",
    "DeleteSecret", "ScheduleKeyDeletion", "DisableKey", "PutEventSelectors",
    "DeleteFlowLogs", "PutSecretValue",
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Build a chronological incident timeline from log files."
    )
    parser.add_argument("--logs", required=True, help="Path to JSON-lines or CSV log file")
    parser.add_argument("--start", help="Include events from this ISO timestamp")
    parser.add_argument("--end", help="Include events until this ISO timestamp")
    parser.add_argument("--actor", help="Filter to events by this user or source_ip")
    parser.add_argument(
        "--output", choices=["markdown", "json"], default="markdown",
        help="Output format (default: markdown)"
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def parse_ts(ts_str: str) -> Optional[datetime]:
    """Parse an ISO timestamp string.

    Args:
        ts_str: Timestamp string.

    Returns:
        datetime or None.
    """
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(ts_str[:19], fmt)
        except (ValueError, TypeError):
            pass
    return None


def load_events(path: str) -> List[Dict[str, Any]]:
    """Auto-detect and load JSON-lines or CSV log file.

    Args:
        path: Path to log file.

    Returns:
        List of event dicts.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = fh.read().strip()
    except FileNotFoundError:
        print(f"ERROR: Log file not found: '{path}'", file=sys.stderr)
        sys.exit(1)

    if not raw:
        print("ERROR: Log file is empty.", file=sys.stderr)
        sys.exit(1)

    # Try JSON-lines
    if raw.startswith("{"):
        events: List[Dict[str, Any]] = []
        for line in raw.splitlines():
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        if events:
            return events

    # Try CSV
    try:
        reader = csv.DictReader(io.StringIO(raw))
        events = [dict(row) for row in reader]
        if events:
            return events
    except Exception:
        pass

    print("ERROR: Could not parse log file as JSON-lines or CSV.", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Timeline construction
# ---------------------------------------------------------------------------


def build_timeline(
    events: List[Dict[str, Any]],
    start: Optional[str],
    end: Optional[str],
    actor: Optional[str],
) -> List[Dict[str, Any]]:
    """Filter and sort events into timeline order.

    Args:
        events: Raw event list.
        start: Optional start filter timestamp string.
        end: Optional end filter timestamp string.
        actor: Optional user/IP filter string.

    Returns:
        Filtered, sorted list of enriched event dicts.
    """
    start_dt = parse_ts(start) if start else None
    end_dt = parse_ts(end) if end else None

    timeline: List[Dict[str, Any]] = []

    for evt in events:
        ts_str = evt.get("timestamp", "") or evt.get("time", "")
        ts = parse_ts(ts_str)
        if not ts:
            continue

        if start_dt and ts < start_dt:
            continue
        if end_dt and ts > end_dt:
            continue

        user = evt.get("user", "") or evt.get("username", "unknown")
        source_ip = evt.get("source_ip", "") or evt.get("src_ip", "")
        action = evt.get("action", "") or evt.get("event", "") or evt.get("EventName", "")
        resource = evt.get("resource", "") or evt.get("target", "")

        if actor and actor.lower() not in (user.lower(), source_ip):
            continue

        flagged = action in IOC_PATTERNS

        timeline.append({
            "timestamp": ts_str,
            "ts_obj": ts,
            "user": user,
            "source_ip": source_ip,
            "action": action,
            "resource": resource,
            "flagged": flagged,
        })

    timeline.sort(key=lambda x: x["ts_obj"])
    return timeline


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------


def render_markdown(
    timeline: List[Dict[str, Any]],
    start: Optional[str],
    end: Optional[str],
    actor: Optional[str],
    original_count: int,
) -> str:
    """Render the markdown incident timeline.

    Args:
        timeline: Sorted, enriched event list.
        start: Start filter string.
        end: End filter string.
        actor: Actor filter string.
        original_count: Total events before filtering.

    Returns:
        Markdown string.
    """
    lines: List[str] = []

    lines.append("# Incident Timeline Report\n")
    lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M')}  ")
    lines.append(f"**Total Events (after filters):** {len(timeline)}  ")
    if actor:
        lines.append(f"**Actor Filter:** `{actor}`  ")
    if start:
        lines.append(f"**From:** {start}  ")
    if end:
        lines.append(f"**To:** {end}  ")

    if not timeline:
        lines.append("\n> No events found matching the specified filters.\n")
        return "\n".join(lines)

    first_evt = timeline[0]["timestamp"]
    last_evt = timeline[-1]["timestamp"]
    flagged_count = sum(1 for e in timeline if e["flagged"])
    unique_actors = len({e["user"] for e in timeline} | {e["source_ip"] for e in timeline if e["source_ip"]})

    lines.append(f"**First Event:** {first_evt}  ")
    lines.append(f"**Last Event:** {last_evt}  ")
    lines.append(f"**Flagged Events:** {flagged_count}  ")
    lines.append(f"**Unique Actors:** {unique_actors}\n")
    lines.append("---\n")

    # Group by hour
    hourly: Dict[str, List[Dict]] = defaultdict(list)
    for evt in timeline:
        hour_key = evt["ts_obj"].strftime("%Y-%m-%d %H:00")
        hourly[hour_key].append(evt)

    for hour_key in sorted(hourly.keys()):
        hour_events = hourly[hour_key]
        lines.append(f"## {hour_key} — {len(hour_events)} event(s)\n")

        for evt in hour_events:
            flag = "🚨" if evt["flagged"] else "✅"
            resource_str = f" → `{evt['resource']}`" if evt["resource"] else ""
            ip_str = f" [{evt['source_ip']}]" if evt["source_ip"] else ""
            lines.append(
                f"- {flag} `{evt['timestamp']}` | `{evt['user']}`{ip_str} | "
                f"**{evt['action']}**{resource_str}"
            )
        lines.append("")

    # Summary
    lines.append("---\n")
    lines.append("## Summary\n")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Total Events | {len(timeline)} |")
    lines.append(f"| 🚨 Flagged Events | {flagged_count} |")
    lines.append(f"| ✅ Clean Events | {len(timeline) - flagged_count} |")
    lines.append(f"| Unique Actors | {unique_actors} |")
    lines.append(f"| First Event | {first_evt} |")
    lines.append(f"| Last Event | {last_evt} |")
    lines.append("")

    return "\n".join(lines)


def render_json(timeline: List[Dict[str, Any]]) -> str:
    """Render timeline as JSON array.

    Args:
        timeline: Sorted event list.

    Returns:
        JSON string.
    """
    output = []
    for evt in timeline:
        output.append({
            "timestamp": evt["timestamp"],
            "user": evt["user"],
            "source_ip": evt["source_ip"],
            "action": evt["action"],
            "resource": evt["resource"],
            "flagged": evt["flagged"],
        })
    return json.dumps(output, indent=2)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Main entry point."""
    args = parse_args()

    events = load_events(args.logs)
    original_count = len(events)

    timeline = build_timeline(events, args.start, args.end, args.actor)

    if args.output == "json":
        print(render_json(timeline))
    else:
        print(render_markdown(timeline, args.start, args.end, args.actor, original_count))


if __name__ == "__main__":
    main()
