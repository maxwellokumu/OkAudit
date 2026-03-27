"""Threat Correlator.

Correlates network log events against Indicators of Compromise (IOCs)
including IPv4/IPv6 addresses, CIDR ranges, domain names, and file hashes.
Uses Python's ipaddress stdlib for all IP/CIDR matching.
"""

import argparse
import csv
import ipaddress
import json
import os
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from dotenv import load_dotenv

load_dotenv()

MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")
IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
CIDR_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$|^[0-9a-fA-F:]+/\d{1,3}$")
IPV6_RE = re.compile(r"^[0-9a-fA-F:]{2,}$")


@dataclass
class IOC:
    """Represents a parsed Indicator of Compromise."""

    raw: str
    ioc_type: str  # ipv4, ipv6, cidr, domain, md5, sha256, unknown
    network: Optional[Any] = None  # ipaddress.ip_network for CIDRs


@dataclass
class LogEvent:
    """A single parsed network log entry."""

    timestamp: str
    src_ip: str
    dst_ip: str
    src_port: str
    dst_port: str
    protocol: str
    action: str
    bytes_: str
    hash_value: str = ""
    raw: Dict[str, str] = field(default_factory=dict)


@dataclass
class Match:
    """A correlation hit between a log event and an IOC."""

    event: LogEvent
    ioc: IOC


def classify_ioc(raw: str) -> IOC:
    """Parse and classify a raw IOC string.

    Args:
        raw: The raw IOC string from the IOC file.

    Returns:
        IOC object with type and optional parsed network.
    """
    stripped = raw.strip()
    if MD5_RE.match(stripped):
        return IOC(raw=stripped, ioc_type="md5")
    if SHA256_RE.match(stripped):
        return IOC(raw=stripped, ioc_type="sha256")
    if CIDR_RE.match(stripped):
        try:
            net = ipaddress.ip_network(stripped, strict=False)
            ioc_type = "cidr_v6" if isinstance(net, ipaddress.IPv6Network) else "cidr"
            return IOC(raw=stripped, ioc_type=ioc_type, network=net)
        except ValueError:
            pass
    if IPV4_RE.match(stripped):
        try:
            ipaddress.IPv4Address(stripped)
            return IOC(raw=stripped, ioc_type="ipv4")
        except ValueError:
            pass
    if IPV6_RE.match(stripped) and ":" in stripped:
        try:
            ipaddress.IPv6Address(stripped)
            return IOC(raw=stripped, ioc_type="ipv6")
        except ValueError:
            pass
    if DOMAIN_RE.match(stripped):
        return IOC(raw=stripped, ioc_type="domain")
    return IOC(raw=stripped, ioc_type="unknown")


def load_iocs(path: str) -> List[IOC]:
    """Load and parse IOCs from a text file (one per line).

    Args:
        path: Filesystem path to IOC file.

    Returns:
        List of IOC objects.
    """
    if not os.path.isfile(path):
        print(f"Error: IOC file not found: {path}", file=sys.stderr)
        sys.exit(1)
    iocs: List[IOC] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            iocs.append(classify_ioc(line))
    return iocs


def parse_log_row(row: Dict[str, str], index: int) -> Optional[LogEvent]:
    """Parse a single log row dict into a LogEvent.

    Args:
        row: Dictionary from CSV reader.
        index: Row number for error context.

    Returns:
        LogEvent or None if the row is invalid.
    """
    required = {"timestamp", "src_ip", "dst_ip"}
    lower_row = {k.strip().lower(): v.strip() for k, v in row.items()}
    if not required.issubset(lower_row.keys()):
        return None
    return LogEvent(
        timestamp=lower_row.get("timestamp", ""),
        src_ip=lower_row.get("src_ip", ""),
        dst_ip=lower_row.get("dst_ip", ""),
        src_port=lower_row.get("src_port", ""),
        dst_port=lower_row.get("dst_port", ""),
        protocol=lower_row.get("protocol", ""),
        action=lower_row.get("action", ""),
        bytes_=lower_row.get("bytes", ""),
        hash_value=lower_row.get("hash", ""),
        raw=lower_row,
    )


def load_logs(path: str) -> List[LogEvent]:
    """Load log events from CSV or JSON-lines format.

    Args:
        path: Filesystem path to log file.

    Returns:
        List of LogEvent objects.
    """
    if not os.path.isfile(path):
        print(f"Error: Log file not found: {path}", file=sys.stderr)
        sys.exit(1)
    events: List[LogEvent] = []
    ext = os.path.splitext(path)[1].lower()

    if ext in (".jsonl", ".ndjson") or _is_jsonlines(path):
        with open(path, encoding="utf-8") as fh:
            for i, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                    ev = parse_log_row(row, i)
                    if ev:
                        events.append(ev)
                except json.JSONDecodeError as exc:
                    print(f"Warning: Skipping line {i} — {exc}", file=sys.stderr)
    else:
        try:
            with open(path, newline="", encoding="utf-8") as fh:
                reader = csv.DictReader(fh)
                for i, row in enumerate(reader, 1):
                    ev = parse_log_row(dict(row), i)
                    if ev:
                        events.append(ev)
        except csv.Error as exc:
            print(f"Error reading CSV: {exc}", file=sys.stderr)
            sys.exit(1)
    return events


def _is_jsonlines(path: str) -> bool:
    """Peek at file to detect JSON-lines format.

    Args:
        path: Filesystem path.

    Returns:
        True if first non-empty line appears to be JSON.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    json.loads(line)
                    return True
    except (json.JSONDecodeError, OSError):
        pass
    return False


def ip_matches_ioc(ip_str: str, ioc: IOC) -> bool:
    """Check whether an IP string matches an IOC.

    Args:
        ip_str: IP address string to check.
        ioc: IOC object to match against.

    Returns:
        True if the IP matches.
    """
    ip_str = ip_str.strip()
    if not ip_str:
        return False
    if ioc.ioc_type in ("ipv4", "ipv6"):
        return ip_str.lower() == ioc.raw.lower()
    if ioc.ioc_type in ("cidr", "cidr_v6") and ioc.network is not None:
        try:
            return ipaddress.ip_address(ip_str) in ioc.network
        except ValueError:
            return False
    return False


def event_matches_ioc(event: LogEvent, ioc: IOC) -> bool:
    """Check if a log event matches a given IOC.

    Args:
        event: The log event to inspect.
        ioc: The IOC to match against.

    Returns:
        True if the event matches.
    """
    if ioc.ioc_type in ("ipv4", "ipv6", "cidr", "cidr_v6"):
        return ip_matches_ioc(event.src_ip, ioc) or ip_matches_ioc(event.dst_ip, ioc)
    if ioc.ioc_type == "domain":
        return ioc.raw.lower() in event.dst_ip.lower()
    if ioc.ioc_type in ("md5", "sha256"):
        return bool(event.hash_value and event.hash_value.lower() == ioc.raw.lower())
    return False


def correlate(events: List[LogEvent], iocs: List[IOC]) -> List[Match]:
    """Run correlation of all events against all IOCs.

    Args:
        events: Loaded log events.
        iocs: Loaded IOCs.

    Returns:
        List of Match objects for every hit.
    """
    matches: List[Match] = []
    for event in events:
        for ioc in iocs:
            if event_matches_ioc(event, ioc):
                matches.append(Match(event=event, ioc=ioc))
    return matches


def render_markdown(events: List[LogEvent], iocs: List[IOC], matches: List[Match],
                    log_path: str) -> str:
    """Render correlation results as a markdown report.

    Args:
        events: All loaded log events.
        iocs: All loaded IOCs.
        matches: All correlation matches.
        log_path: Path to the log file (for display).

    Returns:
        Markdown string.
    """
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    matched_ioc_raws = {m.ioc.raw for m in matches}
    unmatched_iocs = [ioc for ioc in iocs if ioc.raw not in matched_ioc_raws]
    unique_iocs_hit = len(matched_ioc_raws)

    lines = [
        "# Threat Correlation Report",
        "",
        f"**Generated:** {now}",
        f"**Log File:** `{log_path}`",
        f"**IOC Count:** {len(iocs)}",
        "",
        "## Match Summary",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Total Log Events | {len(events)} |",
        f"| Total Matches | {len(matches)} |",
        f"| Unique IOCs Matched | {unique_iocs_hit} |",
        f"| Unmatched IOCs | {len(unmatched_iocs)} |",
        "",
    ]

    if matches:
        lines += [
            "## Matched Events",
            "",
            "| Timestamp | Src IP | Dst IP | Port | IOC Matched | IOC Type |",
            "|-----------|--------|--------|------|-------------|----------|",
        ]
        for m in matches:
            lines.append(
                f"| {m.event.timestamp} | `{m.event.src_ip}` | `{m.event.dst_ip}` | "
                f"{m.event.dst_port} | `{m.ioc.raw}` | {m.ioc.ioc_type} |"
            )
        lines.append("")

        # IOC hit frequency
        freq: Dict[str, Dict] = {}
        for m in matches:
            key = m.ioc.raw
            if key not in freq:
                freq[key] = {"ioc": m.ioc, "count": 0, "timestamps": []}
            freq[key]["count"] += 1
            freq[key]["timestamps"].append(m.event.timestamp)

        lines += [
            "## IOC Hit Frequency",
            "",
            "| IOC | Type | Hit Count | First Seen | Last Seen |",
            "|-----|------|-----------|------------|-----------|",
        ]
        for key, data in sorted(freq.items(), key=lambda x: -x[1]["count"]):
            ts = sorted(data["timestamps"])
            lines.append(
                f"| `{key}` | {data['ioc'].ioc_type} | {data['count']} | "
                f"{ts[0]} | {ts[-1]} |"
            )
        lines.append("")
    else:
        lines += ["## Matched Events", "", "No IOC matches found in the provided logs.", ""]

    if unmatched_iocs:
        lines += ["## Unmatched IOCs", "", "The following IOCs had zero hits in the log file:", ""]
        for ioc in unmatched_iocs:
            lines.append(f"- `{ioc.raw}` ({ioc.ioc_type})")
        lines.append("")
    else:
        lines += ["## Unmatched IOCs", "", "All IOCs had at least one hit.", ""]

    return "\n".join(lines)


def render_json(events: List[LogEvent], iocs: List[IOC], matches: List[Match]) -> str:
    """Render results as JSON.

    Args:
        events: All loaded log events.
        iocs: All loaded IOCs.
        matches: All correlation matches.

    Returns:
        JSON string.
    """
    return json.dumps({
        "summary": {
            "total_events": len(events),
            "total_matches": len(matches),
            "unique_iocs_matched": len({m.ioc.raw for m in matches}),
        },
        "matches": [
            {
                "timestamp": m.event.timestamp,
                "src_ip": m.event.src_ip,
                "dst_ip": m.event.dst_ip,
                "dst_port": m.event.dst_port,
                "ioc": m.ioc.raw,
                "ioc_type": m.ioc.ioc_type,
            }
            for m in matches
        ],
    }, indent=2)


def render_csv(matches: List[Match]) -> str:
    """Render matched events as CSV.

    Args:
        matches: All correlation matches.

    Returns:
        CSV string.
    """
    import io
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["timestamp", "src_ip", "dst_ip", "dst_port", "ioc", "ioc_type"])
    for m in matches:
        writer.writerow([
            m.event.timestamp, m.event.src_ip, m.event.dst_ip,
            m.event.dst_port, m.ioc.raw, m.ioc.ioc_type,
        ])
    return buf.getvalue()


def main() -> None:
    """Entry point for the threat correlator."""
    parser = argparse.ArgumentParser(
        description="Correlate network logs against IOCs."
    )
    parser.add_argument("--logs", required=True, help="Path to network log file (CSV or JSON-lines).")
    parser.add_argument("--iocs", required=True, help="Path to IOC file (one per line).")
    parser.add_argument(
        "--output",
        choices=["markdown", "json", "csv"],
        default="markdown",
        help="Output format (default: markdown).",
    )
    args = parser.parse_args()

    iocs = load_iocs(args.iocs)
    if not iocs:
        print("Error: No IOCs loaded.", file=sys.stderr)
        sys.exit(1)

    events = load_logs(args.logs)
    if not events:
        print("Warning: No log events loaded.", file=sys.stderr)
        sys.exit(0)

    matches = correlate(events, iocs)

    if args.output == "json":
        print(render_json(events, iocs, matches))
    elif args.output == "csv":
        print(render_csv(matches))
    else:
        print(render_markdown(events, iocs, matches, args.logs))


if __name__ == "__main__":
    main()
