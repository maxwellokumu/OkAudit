"""Anomaly Detector — detect behavioural anomalies in log data using statistical baselines.

Computes per-user action frequency statistics from a historical baseline log file,
then evaluates a test log file against those baselines. Flags users whose activity
in the test period deviates significantly from their historical norm.
"""

import argparse
import json
import math
import sys
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Detect behavioural anomalies by comparing logs against a baseline."
    )
    parser.add_argument("--logs", required=True, help="Path to historical baseline log file (JSON-lines)")
    parser.add_argument("--test", required=True, help="Path to test period log file (JSON-lines)")
    parser.add_argument(
        "--sensitivity",
        type=float,
        default=2.0,
        help="Number of standard deviations above mean to flag (default: 2.0, range: 1.0–3.0)",
    )
    parser.add_argument(
        "--min-events",
        type=int,
        default=5,
        help="Minimum events needed to establish a baseline per user (default: 5)",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def parse_ts(ts_str: str) -> Optional[datetime]:
    """Parse an ISO timestamp string into a datetime.

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


def load_jsonl(path: str) -> List[Dict[str, Any]]:
    """Load JSON-lines file into a list of dicts.

    Args:
        path: Path to .jsonl file.

    Returns:
        List of event dicts.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = fh.read().strip()
    except FileNotFoundError:
        print(f"ERROR: File not found: '{path}'", file=sys.stderr)
        sys.exit(1)

    events: List[Dict[str, Any]] = []
    for line in raw.splitlines():
        line = line.strip()
        if line:
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return events


def mean(values: List[float]) -> float:
    """Compute arithmetic mean.

    Args:
        values: List of floats.

    Returns:
        Mean value.
    """
    return sum(values) / len(values) if values else 0.0


def std_dev(values: List[float], mu: float) -> float:
    """Compute population standard deviation.

    Args:
        values: List of floats.
        mu: Pre-computed mean.

    Returns:
        Standard deviation.
    """
    if len(values) < 2:
        return 0.0
    variance = sum((v - mu) ** 2 for v in values) / len(values)
    return math.sqrt(variance)


# ---------------------------------------------------------------------------
# Baseline computation
# ---------------------------------------------------------------------------


def compute_baseline(
    events: List[Dict[str, Any]], min_events: int
) -> Tuple[Dict[str, Dict], Dict[str, set]]:
    """Compute per-user daily action frequency stats from baseline events.

    Args:
        events: Baseline event list.
        min_events: Minimum total events to include a user in baseline.

    Returns:
        Tuple of (stats_dict, user_ips_dict).
        stats_dict: {user: {mean, std, threshold, daily_counts, days_active}}
        user_ips_dict: {user: set of source IPs seen in baseline}
    """
    user_daily: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    user_ips: Dict[str, set] = defaultdict(set)

    for evt in events:
        user = evt.get("user", "unknown")
        ts = parse_ts(evt.get("timestamp", ""))
        ip = evt.get("source_ip", "")
        if ts:
            day_key = ts.strftime("%Y-%m-%d")
            user_daily[user][day_key] += 1
        if ip:
            user_ips[user].add(ip)

    stats: Dict[str, Dict] = {}
    for user, daily in user_daily.items():
        total = sum(daily.values())
        if total < min_events:
            continue
        counts = list(daily.values())
        mu = mean(counts)
        sd = std_dev(counts, mu)
        stats[user] = {
            "mean": round(mu, 2),
            "std": round(sd, 2),
            "days_active": len(daily),
            "total_events": total,
            "daily_counts": dict(daily),
        }

    return stats, dict(user_ips)


# ---------------------------------------------------------------------------
# Anomaly detection
# ---------------------------------------------------------------------------


def detect_anomalies(
    test_events: List[Dict[str, Any]],
    baseline_stats: Dict[str, Dict],
    baseline_ips: Dict[str, set],
    sensitivity: float,
) -> Tuple[List[Dict], List[str], List[Dict]]:
    """Detect anomalies in test events against baseline statistics.

    Args:
        test_events: Test period events.
        baseline_stats: Per-user baseline stats dict.
        baseline_ips: Per-user known source IPs.
        sensitivity: Std dev multiplier for threshold.

    Returns:
        Tuple of (anomalies, new_users, new_ip_findings).
    """
    # Aggregate test period counts per user per day
    test_daily: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    test_ips: Dict[str, set] = defaultdict(set)
    test_users: set = set()

    for evt in test_events:
        user = evt.get("user", "unknown")
        ts = parse_ts(evt.get("timestamp", ""))
        ip = evt.get("source_ip", "")
        test_users.add(user)
        if ts:
            day_key = ts.strftime("%Y-%m-%d")
            test_daily[user][day_key] += 1
        if ip:
            test_ips[user].add(ip)

    anomalies: List[Dict] = []
    new_ip_findings: List[Dict] = []

    for user, daily in test_daily.items():
        if user not in baseline_stats:
            continue  # New users handled separately

        stats = baseline_stats[user]
        mu = stats["mean"]
        sd = stats["std"]
        threshold = mu + (sensitivity * sd)

        for day, count in daily.items():
            if count > threshold:
                deviation_score = round((count - mu) / sd, 2) if sd > 0 else float("inf")
                anomalies.append({
                    "user": user,
                    "day": day,
                    "test_count": count,
                    "baseline_mean": mu,
                    "threshold": round(threshold, 2),
                    "deviation_score": deviation_score,
                    "reason": f"Daily count {count} exceeds threshold {threshold:.1f} (mean={mu}, sd={sd})",
                })

        # New source IPs
        baseline_user_ips = baseline_ips.get(user, set())
        new_ips = test_ips[user] - baseline_user_ips
        if new_ips:
            new_ip_findings.append({
                "user": user,
                "new_ips": list(new_ips),
                "known_ips": list(baseline_user_ips),
            })

    # New users (not in baseline at all)
    known_users = set(baseline_stats.keys())
    new_users = [u for u in test_users if u not in known_users]

    return anomalies, new_users, new_ip_findings


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


def render_report(
    baseline_stats: Dict[str, Dict],
    anomalies: List[Dict],
    new_users: List[str],
    new_ip_findings: List[Dict],
    sensitivity: float,
    min_events: int,
) -> str:
    """Render the anomaly detection markdown report.

    Args:
        baseline_stats: Per-user baseline stats.
        anomalies: Detected anomalies.
        new_users: Users not in baseline.
        new_ip_findings: New source IPs per user.
        sensitivity: Sensitivity value used.
        min_events: Minimum events threshold used.

    Returns:
        Markdown string.
    """
    date_str = datetime.now().strftime("%Y-%m-%d")
    lines: List[str] = []

    lines.append("# Anomaly Detection Report\n")
    lines.append(f"**Date:** {date_str}  ")
    lines.append(f"**Sensitivity:** {sensitivity} standard deviations  ")
    lines.append(f"**Min Events for Baseline:** {min_events}  ")
    lines.append(f"**Baseline Users:** {len(baseline_stats)}  ")
    lines.append(f"**Anomalies Detected:** {len(anomalies)}  ")
    lines.append(f"**New Users:** {len(new_users)}\n")
    lines.append("---\n")

    # Baseline stats
    lines.append("## Baseline Statistics\n")
    lines.append("| User | Days Active | Total Events | Mean/Day | Std Dev | Threshold |")
    lines.append("|------|-------------|--------------|----------|---------|-----------|")
    for user, stats in sorted(baseline_stats.items()):
        threshold = round(stats["mean"] + sensitivity * stats["std"], 2)
        lines.append(
            f"| `{user}` | {stats['days_active']} | {stats['total_events']} | "
            f"{stats['mean']} | {stats['std']} | {threshold} |"
        )
    lines.append("")

    if not anomalies and not new_users and not new_ip_findings:
        lines.append("> ✅ No anomalies detected in the test period.\n")
        return "\n".join(lines)

    # Anomalies table
    if anomalies:
        lines.append("---\n")
        lines.append("## 🚨 Anomalies Detected\n")
        lines.append("| User | Day | Test Count | Baseline Mean | Threshold | Deviation Score | Reason |")
        lines.append("|------|-----|------------|---------------|-----------|-----------------|--------|")
        for a in sorted(anomalies, key=lambda x: x["deviation_score"], reverse=True):
            score = f"{a['deviation_score']}σ" if a["deviation_score"] != float("inf") else "∞"
            lines.append(
                f"| `{a['user']}` | {a['day']} | {a['test_count']} | "
                f"{a['baseline_mean']} | {a['threshold']} | **{score}** | {a['reason']} |"
            )
        lines.append("")

    # New users
    if new_users:
        lines.append("---\n")
        lines.append("## 🆕 New Users (Not in Baseline)\n")
        lines.append("These users were not seen in the baseline period. Verify they are authorised.\n")
        for u in sorted(new_users):
            lines.append(f"- `{u}`")
        lines.append("")

    # New IPs
    if new_ip_findings:
        lines.append("---\n")
        lines.append("## 🌐 New Source IPs Per User\n")
        lines.append("| User | New IPs | Known Baseline IPs |")
        lines.append("|------|---------|-------------------|")
        for f in new_ip_findings:
            new_ips_str = ", ".join(f["new_ips"])
            known_ips_str = ", ".join(f["known_ips"][:3]) + ("..." if len(f["known_ips"]) > 3 else "")
            lines.append(f"| `{f['user']}` | {new_ips_str} | {known_ips_str} |")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Main entry point."""
    args = parse_args()

    if not 1.0 <= args.sensitivity <= 3.0:
        print("ERROR: --sensitivity must be between 1.0 and 3.0.", file=sys.stderr)
        sys.exit(1)

    baseline_events = load_jsonl(args.logs)
    test_events = load_jsonl(args.test)

    if not baseline_events:
        print("ERROR: Baseline log file is empty.", file=sys.stderr)
        sys.exit(1)
    if not test_events:
        print("ERROR: Test log file is empty.", file=sys.stderr)
        sys.exit(1)

    baseline_stats, baseline_ips = compute_baseline(baseline_events, args.min_events)

    if not baseline_stats:
        print(
            f"ERROR: No users met the minimum event threshold ({args.min_events}) "
            "in the baseline. Lower --min-events or provide more baseline data.",
            file=sys.stderr,
        )
        sys.exit(1)

    anomalies, new_users, new_ip_findings = detect_anomalies(
        test_events, baseline_stats, baseline_ips, args.sensitivity
    )

    print(render_report(baseline_stats, anomalies, new_users, new_ip_findings,
                        args.sensitivity, args.min_events))


if __name__ == "__main__":
    main()
