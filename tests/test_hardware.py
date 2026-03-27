"""Tests for hardware-physical skills: asset-validator, firmware-checker, physical-access-review."""

import csv
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
HW_DIR = REPO_ROOT / "hardware-physical"


def run(script: Path, args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(script)] + args,
        capture_output=True,
        text=True,
    )


def write_csv(path: Path, rows: list[dict], fieldnames: list[str]) -> None:
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


ASSET_FIELDS = ["asset_id", "hostname", "type", "location", "owner", "last_seen"]


# ---------------------------------------------------------------------------
# asset-validator
# ---------------------------------------------------------------------------

class TestAssetValidator:
    script = HW_DIR / "asset-validator" / "main.py"

    def _make_inventory(self, tmp_path: Path, rows: list[dict]) -> Path:
        p = tmp_path / "inventory.csv"
        write_csv(p, rows, ASSET_FIELDS)
        return p

    def _make_discovered(self, tmp_path: Path, rows: list[dict]) -> Path:
        p = tmp_path / "discovered.csv"
        write_csv(p, rows, ASSET_FIELDS)
        return p

    def test_rogue_detection(self, tmp_path):
        """An asset in discovered but not in inventory should be classified as Rogue."""
        inventory = [
            {"asset_id": "A001", "hostname": "srv-01", "type": "server",
             "location": "DC", "owner": "Ops", "last_seen": "2024-06-01"},
        ]
        discovered = [
            {"asset_id": "A001", "hostname": "srv-01", "type": "server",
             "location": "DC", "owner": "Ops", "last_seen": "2024-06-01"},
            {"asset_id": "ROGUE-01", "hostname": "unknown-box", "type": "server",
             "location": "DC", "owner": "Unknown", "last_seen": "2024-06-01"},
        ]
        inv = self._make_inventory(tmp_path, inventory)
        disc = self._make_discovered(tmp_path, discovered)
        result = run(self.script, ["--inventory", str(inv), "--discovered", str(disc)])
        assert result.returncode == 0
        assert "Rogue" in result.stdout
        assert "ROGUE-01" in result.stdout

    def test_ghost_detection(self, tmp_path):
        """An asset in inventory but missing from discovered should be classified as Ghost."""
        inventory = [
            {"asset_id": "A001", "hostname": "srv-01", "type": "server",
             "location": "DC", "owner": "Ops", "last_seen": "2024-06-01"},
            {"asset_id": "A002", "hostname": "srv-ghost", "type": "server",
             "location": "DC", "owner": "Ops", "last_seen": "2024-01-01"},
        ]
        discovered = [
            {"asset_id": "A001", "hostname": "srv-01", "type": "server",
             "location": "DC", "owner": "Ops", "last_seen": "2024-06-01"},
        ]
        inv = self._make_inventory(tmp_path, inventory)
        disc = self._make_discovered(tmp_path, discovered)
        result = run(self.script, ["--inventory", str(inv), "--discovered", str(disc)])
        assert result.returncode == 0
        assert "Ghost" in result.stdout
        assert "A002" in result.stdout

    def test_coverage_percentage(self, tmp_path):
        """Coverage percentage should reflect matched / inventory ratio."""
        inventory = [
            {"asset_id": f"A{i:03d}", "hostname": f"host-{i}", "type": "workstation",
             "location": "Office", "owner": "IT", "last_seen": "2024-06-01"}
            for i in range(1, 5)
        ]
        # Only 2 of 4 discovered
        discovered = inventory[:2]
        inv = self._make_inventory(tmp_path, inventory)
        disc = self._make_discovered(tmp_path, discovered)
        result = run(self.script, ["--inventory", str(inv), "--discovered", str(disc)])
        assert result.returncode == 0
        # 50% coverage
        assert "50" in result.stdout


# ---------------------------------------------------------------------------
# firmware-checker
# ---------------------------------------------------------------------------

class TestFirmwareChecker:
    script = HW_DIR / "firmware-checker" / "main.py"

    def _make_devices(self, tmp_path: Path, rows: list[dict]) -> Path:
        p = tmp_path / "devices.csv"
        write_csv(p, rows, ["device_id", "vendor", "model", "current_firmware"])
        return p

    def test_vulnerability_match(self, tmp_path):
        """A Cisco IOS 15.x device should match CVE-2023-20198."""
        devices = [
            {"device_id": "D001", "vendor": "Cisco", "model": "IOS", "current_firmware": "15.2.7"}
        ]
        dev_file = self._make_devices(tmp_path, devices)
        result = run(self.script, ["--devices", str(dev_file)])
        assert result.returncode == 0
        assert "CVE-2023-20198" in result.stdout
        assert "D001" in result.stdout

    def test_version_prefix_match(self, tmp_path):
        """Prefix-based version matching: '17.' should match '17.3.4'."""
        devices = [
            {"device_id": "D002", "vendor": "Cisco", "model": "IOS-XE", "current_firmware": "17.3.4"}
        ]
        dev_file = self._make_devices(tmp_path, devices)
        result = run(self.script, ["--devices", str(dev_file)])
        assert result.returncode == 0
        assert "CVE-2023-20273" in result.stdout

    def test_clean_device_not_flagged(self, tmp_path):
        """A device with a firmware version not matching any CVE should appear as up-to-date."""
        devices = [
            {"device_id": "D099", "vendor": "UnknownVendor", "model": "UnknownModel", "current_firmware": "99.0.0"}
        ]
        dev_file = self._make_devices(tmp_path, devices)
        result = run(self.script, ["--devices", str(dev_file)])
        assert result.returncode == 0
        assert "D099" in result.stdout


# ---------------------------------------------------------------------------
# physical-access-review
# ---------------------------------------------------------------------------

class TestPhysicalAccessReview:
    script = HW_DIR / "physical-access-review" / "main.py"
    LOG_FIELDS = ["badge_id", "door", "timestamp", "result"]

    def _make_logs(self, tmp_path: Path, rows: list[dict]) -> Path:
        p = tmp_path / "logs.csv"
        write_csv(p, rows, self.LOG_FIELDS)
        return p

    def test_after_hours_detection(self, tmp_path):
        """A SUCCESS entry at 11pm should be flagged as after-hours."""
        logs = [
            {"badge_id": "B001", "door": "server-room", "timestamp": "2024-06-03T23:00:00", "result": "SUCCESS"},
            {"badge_id": "B002", "door": "main-entrance", "timestamp": "2024-06-03T09:00:00", "result": "SUCCESS"},
        ]
        log_file = self._make_logs(tmp_path, logs)
        result = run(self.script, ["--logs", str(log_file), "--hours", "07:00-19:00"])
        assert result.returncode == 0
        assert "After-Hours" in result.stdout
        assert "B001" in result.stdout
        # B002 (09:00) should NOT be in after-hours section
        lines_with_b002 = [l for l in result.stdout.splitlines()
                           if "B002" in l and "after" in l.lower()]
        assert len(lines_with_b002) == 0

    def test_failed_attempts_threshold(self, tmp_path):
        """Badge with 5 failures in one hour should be flagged (threshold=3)."""
        logs = [
            {"badge_id": "B003", "door": "server-room",
             "timestamp": f"2024-06-03T10:{i:02d}:00", "result": "FAILED"}
            for i in range(5)
        ]
        log_file = self._make_logs(tmp_path, logs)
        result = run(self.script, ["--logs", str(log_file), "--failed-threshold", "3"])
        assert result.returncode == 0
        assert "B003" in result.stdout
        out_lower = result.stdout.lower()
        assert any(w in out_lower for w in ["failed", "attempt", "burst", "threshold"])
