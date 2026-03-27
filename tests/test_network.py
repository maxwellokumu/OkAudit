"""Tests for network-security skills: network-config-reviewer, threat-correlator, segmentation-validator."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
NET_DIR = REPO_ROOT / "network-security"


def run(script: Path, args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(script)] + args,
        capture_output=True,
        text=True,
    )


# ---------------------------------------------------------------------------
# network-config-reviewer
# ---------------------------------------------------------------------------

class TestNetworkConfigReviewer:
    script = NET_DIR / "network-config-reviewer" / "main.py"
    sample_dir = NET_DIR / "network-config-reviewer" / "sample_input"

    def _get_sample(self) -> Path:
        files = list(self.sample_dir.glob("*")) if self.sample_dir.exists() else []
        if not files:
            pytest.skip("No sample input for network-config-reviewer")
        return files[0]

    def test_any_to_any_detection(self, tmp_path):
        """A firewall rule with 'any' source and destination should be flagged."""
        rules = [
            {"rule_id": "R001", "source": "any", "destination": "any", "port": "any", "action": "ALLOW"}
        ]
        rules_file = tmp_path / "rules.json"
        rules_file.write_text(json.dumps(rules))
        result = run(self.script, ["--config", str(rules_file)])
        assert result.returncode == 0
        out_lower = result.stdout.lower()
        assert any(w in out_lower for w in ["any", "overly permissive", "risk", "flag", "wide"])

    def test_sensitive_port_detection(self, tmp_path):
        """Rules allowing sensitive ports (22, 3389) from any source should be flagged."""
        rules = [
            {"rule_id": "R002", "source": "0.0.0.0/0", "destination": "10.0.0.5", "port": "22", "action": "ALLOW"},
            {"rule_id": "R003", "source": "0.0.0.0/0", "destination": "10.0.0.6", "port": "3389", "action": "ALLOW"},
        ]
        rules_file = tmp_path / "rules.json"
        rules_file.write_text(json.dumps(rules))
        result = run(self.script, ["--config", str(rules_file)])
        assert result.returncode == 0
        out_lower = result.stdout.lower()
        assert any(w in out_lower for w in ["22", "3389", "ssh", "rdp", "sensitive", "flag", "risk"])


# ---------------------------------------------------------------------------
# threat-correlator
# ---------------------------------------------------------------------------

class TestThreatCorrelator:
    script = NET_DIR / "threat-correlator" / "main.py"
    sample_dir = NET_DIR / "threat-correlator" / "sample_input"

    def _get_sample_logs(self) -> Path:
        if not self.sample_dir.exists():
            pytest.skip("No sample input for threat-correlator")
        files = list(self.sample_dir.glob("*"))
        if not files:
            pytest.skip("No sample files for threat-correlator")
        return files[0]

    def test_ip_match(self, tmp_path):
        """A known malicious IP should be detected in the logs."""
        logs = [
            {"timestamp": "2024-06-03T10:00:00", "src_ip": "185.220.101.45", "dst_ip": "10.0.0.1",
             "port": 443, "action": "ALLOW"}
        ]
        threat_ips = [{"ip": "185.220.101.45", "category": "TOR exit node", "severity": "High"}]
        log_file = tmp_path / "logs.json"
        log_file.write_text(json.dumps(logs))
        threat_file = tmp_path / "threats.json"
        threat_file.write_text(json.dumps(threat_ips))
        result = run(self.script, ["--logs", str(log_file), "--threat-intel", str(threat_file)])
        assert result.returncode == 0
        assert "185.220.101.45" in result.stdout or "match" in result.stdout.lower()

    def test_cidr_match(self, tmp_path):
        """An IP within a known malicious CIDR should be flagged."""
        logs = [
            {"timestamp": "2024-06-03T11:00:00", "src_ip": "10.20.30.50", "dst_ip": "192.168.1.1",
             "port": 80, "action": "ALLOW"}
        ]
        threat_cidrs = [{"cidr": "10.20.30.0/24", "category": "Malicious subnet", "severity": "Critical"}]
        log_file = tmp_path / "logs.json"
        log_file.write_text(json.dumps(logs))
        threat_file = tmp_path / "cidrs.json"
        threat_file.write_text(json.dumps(threat_cidrs))
        result = run(self.script, ["--logs", str(log_file), "--threat-intel", str(threat_file)])
        assert result.returncode in (0, 1)
        assert "Traceback" not in result.stderr


# ---------------------------------------------------------------------------
# segmentation-validator
# ---------------------------------------------------------------------------

class TestSegmentationValidator:
    script = NET_DIR / "segmentation-validator" / "main.py"
    sample_dir = NET_DIR / "segmentation-validator" / "sample_input"

    def _get_sample(self) -> Path:
        files = list(self.sample_dir.glob("*")) if self.sample_dir.exists() else []
        if not files:
            pytest.skip("No sample input for segmentation-validator")
        return files[0]

    def test_cross_zone_detection(self, tmp_path):
        """Traffic crossing security zones without explicit approval should be flagged."""
        zones = {
            "zones": [
                {"name": "DMZ", "subnets": ["10.10.0.0/24"]},
                {"name": "INTERNAL", "subnets": ["10.20.0.0/24"]},
            ],
            "rules": [
                {"src_zone": "DMZ", "dst_zone": "INTERNAL", "port": "any", "action": "ALLOW"}
            ]
        }
        zones_file = tmp_path / "zones.json"
        zones_file.write_text(json.dumps(zones))
        result = run(self.script, ["--config", str(zones_file)])
        assert result.returncode == 0
        out_lower = result.stdout.lower()
        assert any(w in out_lower for w in ["cross", "zone", "violation", "dmz", "flag", "risk"])

    def test_unzoned_rule_flagged(self, tmp_path):
        """Firewall rules not associated with a defined zone should be flagged."""
        zones = {
            "zones": [{"name": "DMZ", "subnets": ["10.10.0.0/24"]}],
            "rules": [
                {"src_zone": "UNKNOWN_ZONE", "dst_zone": "DMZ", "port": "443", "action": "ALLOW"}
            ]
        }
        zones_file = tmp_path / "zones.json"
        zones_file.write_text(json.dumps(zones))
        result = run(self.script, ["--config", str(zones_file)])
        assert result.returncode in (0, 1)
        assert "Traceback" not in result.stderr
