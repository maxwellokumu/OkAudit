"""Physical Access Review — analyse badge access logs for anomalies.

Detects after-hours access, failed attempt bursts, tailgating/forced events,
unauthorised door access, and rapid multi-door traversal patterns.
"""

import argparse
import csv
import json
import sys
from collections import defaultdict
from datetime import datetime, time, timedelta
from typing import Dict, List, Optional, Tuple


RESULT_VALUES = {"SUCCESS", "FAILED", "TAILGATE", "FORCED"}


def parse_hours(hours_str: str) -> Tuple[time, time]:
    """Parse 'HH:MM-HH:MM' into start and end time objects.

    Args:
        hours_str: Business hours string e.g. '07:00-19:00'.

    Returns:
        Tuple of (start_time, end_time).

    Raises:
        SystemExit: On invalid format.
    """
    try:
        start_s, end_s = hours_str.split("-")
        start = datetime.strptime(start_s.strip(), "%H:%M").time()
        end = datetime.strptime(end_s.strip(), "%H:%M").time()
        return start, end
    except ValueError:
        print(f"ERROR: Invalid --hours format '{hours_str}'. Use HH:MM-HH:MM.", file=sys.stderr)
        sys.exit(1)


def is_after_hours(ts: datetime, start: time, end: time) -> bool:
    """Return True if timestamp falls outside business hours.

    Args:
        ts: Event timestamp.
        start: Business hours start time.
        end: Business hours end time.

    Returns:
        True if outside business hours.
    """
    t = ts.time()
    return t < start or t > end


def load_logs(path: str) -> List[Dict[str, str]]:
    """Load badge access logs from CSV.

    Args:
        path: Path to log CSV.

    Returns:
        List of log entry dicts with parsed 'dt' datetime key added.

    Raises:
        SystemExit: On file or schema errors.
    """
    required = {"badge_id", "door", "timestamp", "result"}
    entries: List[Dict[str, str]] = []
    try:
        with open(path, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            if reader.fieldnames is None:
                print("ERROR: Log file is empty.", file=sys.stderr)
                sys.exit(1)
            cols = {c.strip().lower() for c in reader.fieldnames}
            missing = required - cols
            if missing:
                print(f"ERROR: Log CSV missing columns: {', '.join(sorted(missing))}", file=sys.stderr)
                sys.exit(1)
            for i, row in enumerate(reader, start=2):
                result = row.get("result", "").strip().upper()
                if result not in RESULT_VALUES:
                    print(
                        f"WARNING: Row {i} has unknown result '{result}', skipping.",
                        file=sys.stderr,
                    )
                    continue
                ts_str = row.get("timestamp", "").strip()
                try:
                    dt = datetime.fromisoformat(ts_str)
                except ValueError:
                    print(
                        f"WARNING: Row {i} invalid timestamp '{ts_str}', skipping.",
                        file=sys.stderr,
                    )
                    continue
                entries.append(
                    {
                        "badge_id": row["badge_id"].strip(),
                        "door": row["door"].strip(),
                        "timestamp": ts_str,
                        "result": result,
                        "dt": dt,
                    }
                )
    except FileNotFoundError:
        print(f"ERROR: Log file not found: '{path}'", file=sys.stderr)
        sys.exit(1)
    except csv.Error as exc:
        print(f"ERROR: Malformed CSV: {exc}", file=sys.stderr)
        sys.exit(1)
    if not entries:
        print("ERROR: No valid log entries found.", file=sys.stderr)
        sys.exit(1)
    entries.sort(key=lambda e: e["dt"])
    return entries


def load_roles(path: str) -> Dict[str, Dict]:
    """Load badge role mapping from JSON.

    Args:
        path: Path to roles JSON file.

    Returns:
        Dict mapping badge_id to role info.

    Raises:
        SystemExit: On file or parse errors.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            print("ERROR: roles.json must be a JSON object.", file=sys.stderr)
            sys.exit(1)
        return data
    except FileNotFoundError:
        print(f"ERROR: Roles file not found: '{path}'", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as exc:
        print(f"ERROR: Invalid JSON in roles file: {exc}", file=sys.stderr)
        sys.exit(1)


def detect_after_hours(
    entries: List[Dict], start: time, end: time, roles: Optional[Dict]
) -> List[Dict]:
    """Find SUCCESS entries outside business hours.

    Args:
        entries: Sorted log entries.
        start: Business hours start.
        end: Business hours end.
        roles: Optional badge role mapping.

    Returns:
        List of after-hours access events.
    """
    events = []
    for e in entries:
        if e["result"] == "SUCCESS" and is_after_hours(e["dt"], start, end):
            role_info = roles.get(e["badge_id"], {}) if roles else {}
            events.append(
                {
                    "badge_id": e["badge_id"],
                    "name": role_info.get("name", "Unknown"),
                    "role": role_info.get("role", "Unknown"),
                    "door": e["door"],
                    "timestamp": e["timestamp"],
                    "day_of_week": e["dt"].strftime("%A"),
                }
            )
    return events


def detect_failed_attempts(
    entries: List[Dict], threshold: int
) -> List[Dict]:
    """Find badge IDs exceeding failed attempt threshold in any rolling 1-hour window.

    Args:
        entries: Sorted log entries.
        threshold: Max failures before flagging.

    Returns:
        List of dicts describing flagged attempt bursts.
    """
    # Group FAILED events by badge_id
    by_badge: Dict[str, List[datetime]] = defaultdict(list)
    for e in entries:
        if e["result"] == "FAILED":
            by_badge[e["badge_id"]].append(e["dt"])

    flagged = []
    for badge_id, timestamps in by_badge.items():
        timestamps.sort()
        for i, ts in enumerate(timestamps):
            window_end = ts + timedelta(hours=1)
            window_events = [t for t in timestamps if ts <= t <= window_end]
            if len(window_events) > threshold:
                # Find which doors these failures happened on
                doors_in_window = set()
                for e in entries:
                    if (
                        e["badge_id"] == badge_id
                        and e["result"] == "FAILED"
                        and ts <= e["dt"] <= window_end
                    ):
                        doors_in_window.add(e["door"])
                flagged.append(
                    {
                        "badge_id": badge_id,
                        "doors": ", ".join(sorted(doors_in_window)),
                        "attempts": len(window_events),
                        "window_start": ts.isoformat(),
                        "window_end": window_end.isoformat(),
                    }
                )
                break  # only flag once per badge per contiguous burst
    return flagged


def detect_special_events(entries: List[Dict]) -> List[Dict]:
    """Find all TAILGATE and FORCED events.

    Args:
        entries: Log entries.

    Returns:
        List of special event dicts.
    """
    return [
        {
            "badge_id": e["badge_id"],
            "door": e["door"],
            "timestamp": e["timestamp"],
            "event_type": e["result"],
        }
        for e in entries
        if e["result"] in {"TAILGATE", "FORCED"}
    ]


def detect_unauthorized(entries: List[Dict], roles: Dict) -> List[Dict]:
    """Find SUCCESS events where badge accessed a door not in their allowed list.

    Args:
        entries: Log entries.
        roles: Badge role mapping with allowed_doors lists.

    Returns:
        List of unauthorised access events.
    """
    events = []
    for e in entries:
        if e["result"] != "SUCCESS":
            continue
        role_info = roles.get(e["badge_id"])
        if role_info is None:
            continue
        allowed = [d.lower() for d in role_info.get("allowed_doors", [])]
        if allowed and e["door"].lower() not in allowed:
            events.append(
                {
                    "badge_id": e["badge_id"],
                    "name": role_info.get("name", "Unknown"),
                    "role": role_info.get("role", "Unknown"),
                    "door": e["door"],
                    "timestamp": e["timestamp"],
                }
            )
    return events


def detect_anomalous_patterns(entries: List[Dict]) -> List[Dict]:
    """Find badges accessing 3+ different doors within any 5-minute window.

    Args:
        entries: Sorted log entries.

    Returns:
        List of anomalous pattern dicts.
    """
    by_badge: Dict[str, List[Dict]] = defaultdict(list)
    for e in entries:
        by_badge[e["badge_id"]].append(e)

    anomalies = []
    for badge_id, events in by_badge.items():
        events_sorted = sorted(events, key=lambda x: x["dt"])
        for i, evt in enumerate(events_sorted):
            window_end = evt["dt"] + timedelta(minutes=5)
            window_events = [
                e for e in events_sorted[i:]
                if e["dt"] <= window_end
            ]
            doors = {e["door"] for e in window_events}
            if len(doors) >= 3:
                anomalies.append(
                    {
                        "badge_id": badge_id,
                        "doors_accessed": sorted(doors),
                        "door_count": len(doors),
                        "window_start": evt["dt"].isoformat(),
                        "window_end": window_end.isoformat(),
                        "events": len(window_events),
                    }
                )
                break  # one anomaly per badge per run
    return anomalies


def render_markdown(
    after_hours: List[Dict],
    failed: List[Dict],
    special: List[Dict],
    unauthorized: List[Dict],
    anomalous: List[Dict],
    total_entries: int,
) -> str:
    """Render physical access audit report as Markdown.

    Args:
        after_hours: After-hours access events.
        failed: Failed attempt bursts.
        special: Tailgate/forced events.
        unauthorized: Unauthorised door access events.
        anomalous: Rapid multi-door access patterns.
        total_entries: Total log entry count.

    Returns:
        Markdown string.
    """
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    lines: List[str] = []
    lines.append("# Physical Access Audit Report")
    lines.append(f"\n**Generated:** {now}  ")
    lines.append(f"**Total Log Entries Analysed:** {total_entries}\n")

    # Summary
    lines.append("## Summary\n")
    lines.append("| Category | Count |")
    lines.append("|----------|-------|")
    lines.append(f"| After-Hours Access | {len(after_hours)} |")
    lines.append(f"| Failed Attempt Bursts | {len(failed)} |")
    lines.append(f"| Tailgate / Forced Events | {len(special)} |")
    lines.append(f"| Unauthorised Door Access | {len(unauthorized)} |")
    lines.append(f"| Anomalous Patterns | {len(anomalous)} |")

    # After-hours
    lines.append(f"\n## After-Hours Access ({len(after_hours)} events)\n")
    if after_hours:
        lines.append("| Badge ID | Name | Role | Door | Timestamp | Day of Week |")
        lines.append("|----------|------|------|------|-----------|-------------|")
        for e in after_hours:
            lines.append(
                f"| {e['badge_id']} | {e['name']} | {e['role']} | {e['door']} | {e['timestamp']} | {e['day_of_week']} |"
            )
    else:
        lines.append("_No after-hours access detected._")

    # Failed attempts
    lines.append(f"\n## Failed Attempt Bursts ({len(failed)} flagged)\n")
    if failed:
        lines.append("| Badge ID | Doors Attempted | Attempts in Window | Time Window |")
        lines.append("|----------|----------------|--------------------|-------------|")
        for f in failed:
            lines.append(
                f"| {f['badge_id']} | {f['doors']} | {f['attempts']} | {f['window_start']} → {f['window_end']} |"
            )
    else:
        lines.append("_No failed attempt bursts detected._")

    # Forced/tailgate
    lines.append(f"\n## Forced / Tailgate Events ({len(special)} events)\n")
    if special:
        lines.append("| Badge ID | Door | Timestamp | Event Type |")
        lines.append("|----------|------|-----------|------------|")
        for e in special:
            lines.append(
                f"| {e['badge_id']} | {e['door']} | {e['timestamp']} | **{e['event_type']}** |"
            )
    else:
        lines.append("_No tailgate or forced events detected._")

    # Unauthorised access
    lines.append(f"\n## Unauthorised Door Access ({len(unauthorized)} events)\n")
    if unauthorized:
        lines.append("| Badge ID | Name | Role | Door Accessed | Timestamp |")
        lines.append("|----------|------|------|--------------|-----------|")
        for e in unauthorized:
            lines.append(
                f"| {e['badge_id']} | {e['name']} | {e['role']} | {e['door']} | {e['timestamp']} |"
            )
    else:
        lines.append("_No unauthorised door access detected (or --roles not provided)._")

    # Anomalous patterns
    lines.append(f"\n## Anomalous Patterns ({len(anomalous)} detected)\n")
    if anomalous:
        for a in anomalous:
            doors_str = ", ".join(a["doors_accessed"])
            lines.append(
                f"- **{a['badge_id']}** accessed {a['door_count']} doors ({doors_str}) "
                f"within 5 minutes starting {a['window_start']}"
            )
    else:
        lines.append("_No anomalous rapid multi-door access patterns detected._")

    # Recommendations
    lines.append("\n## Recommendations\n")
    recs = []
    if special:
        recs.append(
            f"1. **Investigate {len(special)} tailgate/forced event(s)** — review CCTV footage and interview badge holders."
        )
    if after_hours:
        recs.append(
            f"2. **Review {len(after_hours)} after-hours access event(s)** — confirm business justification or revoke overnight access."
        )
    if failed:
        recs.append(
            f"3. **Investigate {len(failed)} failed access burst(s)** — potential credential stuffing or lost badge."
        )
    if unauthorized:
        recs.append(
            f"4. **Remediate {len(unauthorized)} unauthorised door access event(s)** — update role permissions or investigate intent."
        )
    recs.append(
        f"{len(recs)+1}. **Enable real-time alerting** for TAILGATE, FORCED, and after-hours events."
    )
    recs.append(
        f"{len(recs)+1}. **Review badge deprovisioning process** — ensure leavers' badges are revoked same-day."
    )
    lines.extend(recs)

    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        description="Audit physical badge access logs for anomalies."
    )
    parser.add_argument("--logs", required=True, help="Path to badge access log CSV")
    parser.add_argument(
        "--hours",
        default="07:00-19:00",
        help="Business hours window HH:MM-HH:MM (default: 07:00-19:00)",
    )
    parser.add_argument("--roles", help="Path to roles JSON file")
    parser.add_argument(
        "--failed-threshold",
        type=int,
        default=3,
        help="Max failed attempts per hour before flagging (default: 3)",
    )
    return parser.parse_args()


def main() -> None:
    """Main entry point."""
    args = parse_args()

    start_time, end_time = parse_hours(args.hours)
    entries = load_logs(args.logs)
    roles = load_roles(args.roles) if args.roles else None

    after_hours = detect_after_hours(entries, start_time, end_time, roles)
    failed = detect_failed_attempts(entries, args.failed_threshold)
    special = detect_special_events(entries)
    unauthorized = detect_unauthorized(entries, roles) if roles else []
    anomalous = detect_anomalous_patterns(entries)

    print(
        render_markdown(
            after_hours, failed, special, unauthorized, anomalous, len(entries)
        )
    )


if __name__ == "__main__":
    main()
