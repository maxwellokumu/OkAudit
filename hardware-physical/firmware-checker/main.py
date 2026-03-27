"""Firmware Checker — identify devices running firmware with known CVEs.

Matches device firmware versions against a built-in or user-supplied CVE
database using exact and prefix-based version matching.
"""

import argparse
import csv
import json
import sys
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Tuple


# Built-in CVE database (vendor, model, vulnerable_version_prefix, cve_id, severity, description, remediation)
FIRMWARE_CVE_DB: List[Dict[str, str]] = [
    {
        "vendor": "Cisco",
        "model": "IOS",
        "vulnerable_version": "15.",
        "cve_id": "CVE-2023-20198",
        "severity": "Critical",
        "description": "HTTP UI privilege escalation allows unauthenticated remote attacker to create admin account",
        "remediation": "Upgrade to IOS 15.9.3M2 or later; disable HTTP server if unused",
    },
    {
        "vendor": "Cisco",
        "model": "IOS-XE",
        "vulnerable_version": "17.",
        "cve_id": "CVE-2023-20273",
        "severity": "High",
        "description": "Web UI command injection via crafted HTTP request allows privilege escalation",
        "remediation": "Apply Cisco patch cisco-sa-iosxe-webui-privesc-j22SaA4z",
    },
    {
        "vendor": "Fortinet",
        "model": "FortiOS",
        "vulnerable_version": "7.0.",
        "cve_id": "CVE-2023-27997",
        "severity": "Critical",
        "description": "SSL-VPN heap overflow allows unauthenticated remote code execution",
        "remediation": "Upgrade to FortiOS 7.0.12 or 7.2.5 or later",
    },
    {
        "vendor": "Fortinet",
        "model": "FortiOS",
        "vulnerable_version": "6.4.",
        "cve_id": "CVE-2022-40684",
        "severity": "Critical",
        "description": "Authentication bypass via alternative path allows admin interface takeover",
        "remediation": "Upgrade to FortiOS 7.0.7 or 7.2.2 or later immediately",
    },
    {
        "vendor": "Dell",
        "model": "iDRAC9",
        "vulnerable_version": "3.",
        "cve_id": "CVE-2021-21514",
        "severity": "High",
        "description": "Open redirect vulnerability in iDRAC web interface allows phishing attacks",
        "remediation": "Upgrade iDRAC9 firmware to 4.40.00.00 or later",
    },
    {
        "vendor": "HP",
        "model": "iLO4",
        "vulnerable_version": "2.",
        "cve_id": "CVE-2017-12542",
        "severity": "Critical",
        "description": "Authentication bypass via buffer overflow in Connection header allows admin access",
        "remediation": "Upgrade to iLO4 2.55 or later; isolate iLO network interface",
    },
    {
        "vendor": "Palo Alto",
        "model": "PAN-OS",
        "vulnerable_version": "10.",
        "cve_id": "CVE-2022-0028",
        "severity": "High",
        "description": "Reflected amplification DoS via malformed URL filtering policy",
        "remediation": "Apply PAN-OS update; ensure URL filtering security profiles are configured",
    },
    {
        "vendor": "F5",
        "model": "BIG-IP",
        "vulnerable_version": "16.",
        "cve_id": "CVE-2022-1388",
        "severity": "Critical",
        "description": "iControl REST authentication bypass allows unauthenticated command execution",
        "remediation": "Apply F5 advisory K23605346; block iControl REST access externally",
    },
    {
        "vendor": "VMware",
        "model": "ESXi",
        "vulnerable_version": "7.0",
        "cve_id": "CVE-2021-21985",
        "severity": "Critical",
        "description": "vCenter Server RCE via vSAN Health Check plugin enabled by default",
        "remediation": "Apply vCenter Server 7.0 U2b patch or disable affected plugins",
    },
    {
        "vendor": "Juniper",
        "model": "Junos",
        "vulnerable_version": "21.",
        "cve_id": "CVE-2023-36844",
        "severity": "Critical",
        "description": "PHP environment variable injection via J-Web allows unauthenticated RCE",
        "remediation": "Upgrade to Junos 20.4R3-S8, 21.4R3-S5 or later",
    },
    {
        "vendor": "Netgear",
        "model": "ProSAFE",
        "vulnerable_version": "",
        "cve_id": "CVE-2020-26919",
        "severity": "Critical",
        "description": "Unauthenticated remote code execution via improper access control in web management",
        "remediation": "Apply latest Netgear ProSAFE firmware; restrict management access by IP",
    },
    {
        "vendor": "QNAP",
        "model": "QTS",
        "vulnerable_version": "5.",
        "cve_id": "CVE-2022-27593",
        "severity": "Critical",
        "description": "Externally controlled reference allows attacker to access sensitive files",
        "remediation": "Update QTS to 5.0.1.2346 or later via QNAP Security Advisory QSA-22-24",
    },
    {
        "vendor": "Schneider Electric",
        "model": "APC",
        "vulnerable_version": "",
        "cve_id": "CVE-2022-22805",
        "severity": "Critical",
        "description": "Buffer overflow in TLS/SSL implementation allows remote code execution on UPS",
        "remediation": "Apply APC by Schneider Electric Security Advisory SEVD-2022-011-01",
    },
    {
        "vendor": "Hikvision",
        "model": "camera",
        "vulnerable_version": "",
        "cve_id": "CVE-2021-36260",
        "severity": "Critical",
        "description": "Command injection via URL parameter allows unauthenticated RCE with root privileges",
        "remediation": "Upgrade camera firmware to version 5.5.800 or later immediately",
    },
    {
        "vendor": "MikroTik",
        "model": "RouterOS",
        "vulnerable_version": "",
        "cve_id": "CVE-2023-30799",
        "severity": "Critical",
        "description": "Privilege escalation from admin to super-admin via Winbox or HTTP interface",
        "remediation": "Upgrade RouterOS to 6.49.8, 7.9.2 or later; restrict Winbox/HTTP access",
    },
]

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}


@dataclass
class Device:
    """Represents a network device."""

    device_id: str
    vendor: str
    model: str
    current_firmware: str


@dataclass
class Finding:
    """A CVE match for a device."""

    device: Device
    cve_id: str
    severity: str
    description: str
    remediation: str


def load_devices(path: str) -> List[Device]:
    """Load device list from CSV.

    Args:
        path: Path to devices CSV.

    Returns:
        List of Device objects.

    Raises:
        SystemExit: On file or schema errors.
    """
    devices: List[Device] = []
    required = {"device_id", "vendor", "model", "current_firmware"}
    try:
        with open(path, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            if reader.fieldnames is None:
                print("ERROR: Devices file is empty.", file=sys.stderr)
                sys.exit(1)
            missing = required - {c.strip().lower() for c in reader.fieldnames}
            if missing:
                print(f"ERROR: Devices CSV missing columns: {', '.join(sorted(missing))}", file=sys.stderr)
                sys.exit(1)
            for row in reader:
                devices.append(
                    Device(
                        device_id=row["device_id"].strip(),
                        vendor=row["vendor"].strip(),
                        model=row["model"].strip(),
                        current_firmware=row["current_firmware"].strip(),
                    )
                )
    except FileNotFoundError:
        print(f"ERROR: Devices file not found: '{path}'", file=sys.stderr)
        sys.exit(1)
    except csv.Error as exc:
        print(f"ERROR: Malformed CSV: {exc}", file=sys.stderr)
        sys.exit(1)
    if not devices:
        print("ERROR: Devices file contains no rows.", file=sys.stderr)
        sys.exit(1)
    return devices


def load_cve_db(path: str) -> List[Dict[str, str]]:
    """Load a custom CVE database from CSV.

    Args:
        path: Path to CVE DB CSV.

    Returns:
        List of CVE entry dicts.

    Raises:
        SystemExit: On file errors.
    """
    entries: List[Dict[str, str]] = []
    required = {"vendor", "model", "vulnerable_version", "cve_id", "severity", "description", "remediation"}
    try:
        with open(path, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            if reader.fieldnames is None:
                print("ERROR: CVE DB file is empty.", file=sys.stderr)
                sys.exit(1)
            missing = required - {c.strip().lower() for c in reader.fieldnames}
            if missing:
                print(f"ERROR: CVE DB missing columns: {', '.join(sorted(missing))}", file=sys.stderr)
                sys.exit(1)
            for row in reader:
                entries.append({k: v.strip() for k, v in row.items()})
    except FileNotFoundError:
        print(f"ERROR: CVE DB file not found: '{path}'", file=sys.stderr)
        sys.exit(1)
    return entries


def version_matches(current: str, vulnerable: str) -> bool:
    """Test if current version matches a vulnerable version pattern.

    Supports exact match and prefix-based matching (e.g. '15.' matches '15.2.1').

    Args:
        current: Device's current firmware version string.
        vulnerable: Vulnerable version pattern from CVE DB.

    Returns:
        True if the current version is considered vulnerable.
    """
    if not vulnerable:
        return True  # blank = affects all versions
    c = current.strip().lower()
    v = vulnerable.strip().lower()
    return c == v or c.startswith(v)


def check_firmware(devices: List[Device], cve_db: List[Dict[str, str]]) -> Tuple[List[Finding], List[Device]]:
    """Match devices against CVE database.

    Args:
        devices: List of devices to check.
        cve_db: CVE entries to match against.

    Returns:
        Tuple of (findings list, clean devices list).
    """
    findings: List[Finding] = []
    vulnerable_ids: set = set()

    for device in devices:
        for entry in cve_db:
            vendor_match = entry["vendor"].lower() in device.vendor.lower() or device.vendor.lower() in entry["vendor"].lower()
            model_match = entry["model"].lower() in device.model.lower() or device.model.lower() in entry["model"].lower()
            if vendor_match and model_match and version_matches(device.current_firmware, entry["vulnerable_version"]):
                findings.append(
                    Finding(
                        device=device,
                        cve_id=entry["cve_id"],
                        severity=entry["severity"],
                        description=entry["description"],
                        remediation=entry["remediation"],
                    )
                )
                vulnerable_ids.add(device.device_id)

    clean = [d for d in devices if d.device_id not in vulnerable_ids]
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
    return findings, clean


def severity_counts(findings: List[Finding]) -> Dict[str, int]:
    """Count findings by severity.

    Args:
        findings: List of Finding objects.

    Returns:
        Dict mapping severity to count.
    """
    counts: Dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def render_markdown(findings: List[Finding], clean: List[Device], total: int) -> str:
    """Render firmware vulnerability report as Markdown.

    Args:
        findings: List of CVE findings.
        clean: List of devices with no known CVEs.
        total: Total device count.

    Returns:
        Markdown string.
    """
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    counts = severity_counts(findings)
    vulnerable_device_ids = {f.device.device_id for f in findings}

    lines: List[str] = []
    lines.append("# Firmware Vulnerability Report")
    lines.append(f"\n**Generated:** {now}  ")
    lines.append(f"**Devices Checked:** {total}  ")
    lines.append(f"**Vulnerable Devices:** {len(vulnerable_device_ids)}  ")
    lines.append(f"**Up-to-Date Devices:** {len(clean)}  ")
    lines.append(f"**Total CVE Findings:** {len(findings)}\n")

    lines.append("## Summary\n")
    lines.append("| Severity | CVE Count |")
    lines.append("|----------|-----------|")
    for sev in ["Critical", "High", "Medium", "Low"]:
        lines.append(f"| {sev} | {counts.get(sev, 0)} |")

    if findings:
        lines.append("\n## Vulnerable Devices\n")
        lines.append("| Device ID | Vendor | Model | Current Firmware | CVE ID | Severity | Description | Remediation |")
        lines.append("|-----------|--------|-------|-----------------|--------|----------|-------------|-------------|")
        for f in findings:
            desc = f.description[:80] + "…" if len(f.description) > 80 else f.description
            rem = f.remediation[:70] + "…" if len(f.remediation) > 70 else f.remediation
            lines.append(
                f"| {f.device.device_id} | {f.device.vendor} | {f.device.model} | "
                f"{f.device.current_firmware} | {f.cve_id} | **{f.severity}** | {desc} | {rem} |"
            )

    lines.append(f"\n## Up-to-Date Devices ({len(clean)})\n")
    if clean:
        lines.append("| Device ID | Vendor | Model | Firmware |")
        lines.append("|-----------|--------|-------|----------|")
        for d in clean:
            lines.append(f"| {d.device_id} | {d.vendor} | {d.model} | {d.current_firmware} |")
    else:
        lines.append("_All checked devices have known vulnerabilities._")

    critical = [f for f in findings if f.severity == "Critical"]
    if critical:
        lines.append("\n## ⚠️ Critical Actions Required\n")
        for f in critical:
            lines.append(f"**{f.device.device_id} ({f.device.vendor} {f.device.model})** — {f.cve_id}")
            lines.append(f"- **Risk:** {f.description}")
            lines.append(f"- **Action:** {f.remediation}\n")

    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        description="Check device firmware versions against CVE vulnerability database."
    )
    parser.add_argument("--devices", required=True, help="Path to devices CSV")
    parser.add_argument("--cve-db", help="Path to custom CVE database CSV (optional)")
    return parser.parse_args()


def main() -> None:
    """Main entry point."""
    args = parse_args()

    devices = load_devices(args.devices)
    cve_db = load_cve_db(args.cve_db) if args.cve_db else FIRMWARE_CVE_DB

    findings, clean = check_firmware(devices, cve_db)
    print(render_markdown(findings, clean, len(devices)))


if __name__ == "__main__":
    main()
