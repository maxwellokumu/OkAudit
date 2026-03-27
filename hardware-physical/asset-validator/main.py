"""Asset Validator — reconcile IT inventory against discovered devices.

Classifies assets as Matched, Ghost (in inventory but not discovered),
or Rogue (discovered but not in inventory).
"""

import argparse
import csv
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple


ROGUE_RISK: Dict[str, str] = {
    "server": "Critical",
    "workstation": "High",
    "laptop": "High",
    "iot": "High",
    "printer": "Medium",
    "switch": "High",
    "router": "High",
    "firewall": "Critical",
}


@dataclass
class Asset:
    """Represents a single hardware asset."""

    asset_id: str
    hostname: str
    type: str
    location: str
    owner: str
    last_seen: str

    def key(self) -> str:
        """Return normalised asset_id for matching."""
        return self.asset_id.strip().lower()

    def hostname_key(self) -> str:
        """Return normalised hostname for secondary matching."""
        return self.hostname.strip().lower()


def load_assets(path: str, label: str) -> List[Asset]:
    """Load assets from a CSV file.

    Args:
        path: Path to the CSV file.
        label: Human-readable label for error messages.

    Returns:
        List of Asset objects.

    Raises:
        SystemExit: On missing file or malformed CSV.
    """
    assets: List[Asset] = []
    required_cols = {"asset_id", "hostname", "type", "location", "owner", "last_seen"}
    try:
        with open(path, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            if reader.fieldnames is None:
                print(f"ERROR: {label} file '{path}' is empty.", file=sys.stderr)
                sys.exit(1)
            missing = required_cols - {c.strip().lower() for c in reader.fieldnames}
            if missing:
                print(
                    f"ERROR: {label} file missing columns: {', '.join(sorted(missing))}",
                    file=sys.stderr,
                )
                sys.exit(1)
            for i, row in enumerate(reader, start=2):
                try:
                    assets.append(
                        Asset(
                            asset_id=row["asset_id"].strip(),
                            hostname=row["hostname"].strip(),
                            type=row["type"].strip().lower(),
                            location=row["location"].strip(),
                            owner=row["owner"].strip(),
                            last_seen=row["last_seen"].strip(),
                        )
                    )
                except KeyError as exc:
                    print(
                        f"WARNING: Skipping row {i} in {label} — missing field {exc}",
                        file=sys.stderr,
                    )
    except FileNotFoundError:
        print(f"ERROR: {label} file not found: '{path}'", file=sys.stderr)
        sys.exit(1)
    except csv.Error as exc:
        print(f"ERROR: Malformed CSV in {label}: {exc}", file=sys.stderr)
        sys.exit(1)
    if not assets:
        print(f"ERROR: {label} file '{path}' contains no valid asset rows.", file=sys.stderr)
        sys.exit(1)
    return assets


def classify_assets(
    inventory: List[Asset], discovered: List[Asset]
) -> Tuple[List[Tuple[Asset, Asset]], List[Asset], List[Asset]]:
    """Reconcile inventory vs discovered.

    Args:
        inventory: Authorised asset list.
        discovered: Scanned/discovered asset list.

    Returns:
        Tuple of (matched pairs, ghost assets, rogue assets).
    """
    inv_by_id: Dict[str, Asset] = {a.key(): a for a in inventory}
    inv_by_host: Dict[str, Asset] = {a.hostname_key(): a for a in inventory if a.hostname}

    matched: List[Tuple[Asset, Asset]] = []
    matched_inv_keys: set = set()
    matched_disc_indices: set = set()

    # Primary match: asset_id; secondary: hostname
    for idx, disc in enumerate(discovered):
        if disc.key() in inv_by_id:
            inv_asset = inv_by_id[disc.key()]
            matched.append((inv_asset, disc))
            matched_inv_keys.add(inv_asset.key())
            matched_disc_indices.add(idx)
        elif disc.hostname_key() in inv_by_host:
            inv_asset = inv_by_host[disc.hostname_key()]
            matched.append((inv_asset, disc))
            matched_inv_keys.add(inv_asset.key())
            matched_disc_indices.add(idx)

    ghost = [a for a in inventory if a.key() not in matched_inv_keys]
    rogue = [discovered[i] for i in range(len(discovered)) if i not in matched_disc_indices]

    return matched, ghost, rogue


def rogue_risk(asset_type: str) -> str:
    """Determine risk level for a rogue asset.

    Args:
        asset_type: Normalised device type string.

    Returns:
        Risk level string.
    """
    for key, level in ROGUE_RISK.items():
        if key in asset_type:
            return level
    return "Critical"  # unknown type = highest risk


def ascii_bar(value: int, total: int, width: int = 20) -> str:
    """Return a simple ASCII progress bar.

    Args:
        value: Current value.
        total: Maximum value.
        width: Bar character width.

    Returns:
        ASCII bar string.
    """
    if total == 0:
        return "[" + " " * width + "]"
    filled = int(width * value / total)
    return "[" + "█" * filled + "░" * (width - filled) + "]"


def render_markdown(
    matched: List[Tuple[Asset, Asset]],
    ghost: List[Asset],
    rogue: List[Asset],
    inv_total: int,
) -> str:
    """Render the asset validation report as Markdown.

    Args:
        matched: List of (inventory, discovered) asset pairs.
        ghost: Assets in inventory but not discovered.
        rogue: Assets discovered but not in inventory.
        inv_total: Total inventory count.

    Returns:
        Markdown string.
    """
    total = inv_total
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    coverage = (len(matched) / total * 100) if total > 0 else 0.0

    lines: List[str] = []
    lines.append("# Asset Validation Report")
    lines.append(f"\n**Generated:** {now}  ")
    lines.append(f"**Inventory Size:** {inv_total}  ")
    lines.append(f"**Discovered Devices:** {len(matched) + len(rogue)}  ")
    lines.append(f"**Coverage:** {coverage:.1f}%\n")

    # Summary table
    lines.append("## Summary\n")
    lines.append("| Category | Count | % of Total |")
    lines.append("|----------|-------|------------|")
    for label, count in [("Matched", len(matched)), ("Ghost", len(ghost)), ("Rogue", len(rogue))]:
        pct = count / total * 100 if total > 0 else 0.0
        lines.append(f"| {label} | {count} | {pct:.1f}% |")

    # Matched assets (top 10 sample)
    lines.append(f"\n## Matched Assets ({len(matched)} total)\n")
    if matched:
        sample = matched[:10]
        lines.append("| Asset ID | Hostname | Type | Location | Owner | Last Seen |")
        lines.append("|----------|----------|------|----------|-------|-----------|")
        for inv, _ in sample:
            lines.append(
                f"| {inv.asset_id} | {inv.hostname} | {inv.type} | {inv.location} | {inv.owner} | {inv.last_seen} |"
            )
        if len(matched) > 10:
            lines.append(f"\n_...and {len(matched) - 10} more matched assets._")

    # Ghost assets
    lines.append(f"\n## Ghost Assets ({len(ghost)} — In Inventory, Not Discovered)\n")
    if ghost:
        lines.append("| Asset ID | Hostname | Type | Location | Owner | Last Seen |")
        lines.append("|----------|----------|------|----------|-------|-----------|")
        for a in ghost:
            lines.append(
                f"| {a.asset_id} | {a.hostname} | {a.type} | {a.location} | {a.owner} | {a.last_seen} |"
            )
    else:
        lines.append("_No ghost assets detected._")

    # Rogue assets
    lines.append(f"\n## Rogue Assets ({len(rogue)} — Discovered, Not in Inventory)\n")
    if rogue:
        lines.append("| Asset ID | Hostname | Type | Location | Risk Level |")
        lines.append("|----------|----------|------|----------|------------|")
        for a in rogue:
            risk = rogue_risk(a.type)
            lines.append(
                f"| {a.asset_id} | {a.hostname} | {a.type} | {a.location} | **{risk}** |"
            )
    else:
        lines.append("_No rogue assets detected._")

    # Coverage bar
    lines.append("\n## Coverage")
    lines.append(f"\n{ascii_bar(len(matched), total)} {coverage:.1f}% of inventory confirmed discovered\n")

    # Recommendations
    lines.append("## Recommendations\n")
    recs = []
    if rogue:
        critical_rogues = [a for a in rogue if rogue_risk(a.type) == "Critical"]
        recs.append(
            f"1. **Investigate {len(rogue)} rogue device(s) immediately** — "
            f"{len(critical_rogues)} are Critical risk. Isolate unknown devices pending verification."
        )
    if ghost:
        recs.append(
            f"2. **Resolve {len(ghost)} ghost asset(s)** — confirm decommission, update CMDB, or initiate scan."
        )
    if coverage < 90:
        recs.append(
            f"3. **Improve discovery coverage** (currently {coverage:.1f}%) — "
            "expand network scan scope or correct asset_id/hostname mismatches."
        )
    recs.append(
        f"{'4' if len(recs) < 3 else str(len(recs)+1)}. **Schedule recurring reconciliation** — run asset-validator monthly or after network changes."
    )
    if not recs:
        lines.append("✅ Asset inventory is fully reconciled. No immediate actions required.")
    else:
        lines.extend(recs)

    return "\n".join(lines)


def render_json(
    matched: List[Tuple[Asset, Asset]],
    ghost: List[Asset],
    rogue: List[Asset],
    inv_total: int,
) -> str:
    """Render results as JSON.

    Args:
        matched: Matched asset pairs.
        ghost: Ghost assets.
        rogue: Rogue assets.
        inv_total: Total inventory count.

    Returns:
        JSON string.
    """
    coverage = len(matched) / inv_total * 100 if inv_total > 0 else 0.0
    result = {
        "generated": datetime.utcnow().isoformat() + "Z",
        "summary": {
            "inventory_total": inv_total,
            "matched": len(matched),
            "ghost": len(ghost),
            "rogue": len(rogue),
            "coverage_pct": round(coverage, 1),
        },
        "ghost_assets": [
            {
                "asset_id": a.asset_id,
                "hostname": a.hostname,
                "type": a.type,
                "location": a.location,
                "owner": a.owner,
                "last_seen": a.last_seen,
            }
            for a in ghost
        ],
        "rogue_assets": [
            {
                "asset_id": a.asset_id,
                "hostname": a.hostname,
                "type": a.type,
                "location": a.location,
                "risk_level": rogue_risk(a.type),
            }
            for a in rogue
        ],
    }
    return json.dumps(result, indent=2)


def render_csv(
    matched: List[Tuple[Asset, Asset]],
    ghost: List[Asset],
    rogue: List[Asset],
) -> str:
    """Render results as CSV.

    Args:
        matched: Matched asset pairs.
        ghost: Ghost assets.
        rogue: Rogue assets.

    Returns:
        CSV string.
    """
    import io

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["category", "asset_id", "hostname", "type", "location", "owner", "last_seen", "risk_level"])
    for inv, _ in matched:
        writer.writerow(["Matched", inv.asset_id, inv.hostname, inv.type, inv.location, inv.owner, inv.last_seen, ""])
    for a in ghost:
        writer.writerow(["Ghost", a.asset_id, a.hostname, a.type, a.location, a.owner, a.last_seen, ""])
    for a in rogue:
        writer.writerow(["Rogue", a.asset_id, a.hostname, a.type, a.location, a.owner, a.last_seen, rogue_risk(a.type)])
    return buf.getvalue()


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        description="Reconcile IT asset inventory against discovered devices."
    )
    parser.add_argument("--inventory", required=True, help="Path to authorised inventory CSV")
    parser.add_argument("--discovered", required=True, help="Path to discovered assets CSV")
    parser.add_argument(
        "--output",
        choices=["markdown", "json", "csv"],
        default="markdown",
        help="Output format (default: markdown)",
    )
    return parser.parse_args()


def main() -> None:
    """Main entry point."""
    args = parse_args()

    inventory = load_assets(args.inventory, "inventory")
    discovered = load_assets(args.discovered, "discovered")

    matched, ghost, rogue = classify_assets(inventory, discovered)

    if args.output == "json":
        print(render_json(matched, ghost, rogue, len(inventory)))
    elif args.output == "csv":
        print(render_csv(matched, ghost, rogue))
    else:
        print(render_markdown(matched, ghost, rogue, len(inventory)))


if __name__ == "__main__":
    main()
