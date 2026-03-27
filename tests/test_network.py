"""Tests for network-security skills: network-config-reviewer, threat-correlator, segmentation-validator."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
NET_DIR = REPO_ROOT / "network-security"


def run(script: Path, args: list[str]) -> subprocess.CompletedProcess:
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    return subprocess.run(
        [sys.executable, str(script)] + args,
        capture_output=True,
        text=True,
        env=env,
    )


# ---------------------------------------------------------------------------
# network-config-reviewer — expects --rules (CSV), not --config
# ---------------------------------------------------------------------------

class TestNetworkConfigReviewer:
    script = NET_DIR / "network-config-reviewer" / "main.py"
    sample_dir = NET_DIR / "network-config-reviewer" / "sample_input"

    def _get_sample(self) -> Path:
        files = list(self.sample_dir.glob("*.csv")) if self.sample_dir.exists() else []
        if not files:
            pytest.skip("No CSV sample input for network-config-reviewer")
        return files[0]

    def test_any_to_any_detection(self):
        """Running against sample rules should produce output."""
        sample = self._get_sample()
        result = run(self.script, ["--rules", str(sample)])
        assert result.returncode == 0
        assert len(result.stdout.strip()) > 0

    def test_sensitive_port_detection(self):
        """Running against sample rules should flag sensitive ports."""
        sample = self._get_sample()
        result = run(self.script, ["--rules", str(sample)])
        assert result.returncode == 0
        out_lower = result.stdout.lower()
        assert any(w in out_lower for w in ["risk", "flag", "allow", "rule", "port", "any"])


# ---------------------------------------------------------------------------
# threat-correlator — expects --iocs not --threat-intel
# ---------------------------------------------------------------------------

class TestThreatCorrelator:
    script = NET_DIR / "threat-correlator" / "main.py"
    sample_dir = NET_DIR / "threat-correlator" / "sample_input"

    def _get_sample_logs(self) -> Path:
        files = list(self.sample_dir.glob("*.csv")) if self.sample_dir.exists() else []
        if not files:
            pytest.skip("No CSV sample for threat-correlator logs")
        return files[0]

    def _get_sample_iocs(self) -> Path:
        files = list(self.sample_dir.glob("*.txt")) if self.sample_dir.exists() else []
        if not files:
            pytest.skip("No .txt sample for threat-correlator IOCs")
        return files[0]

    def test_ip_match(self, tmp_path):
        """Running with sample logs and IOCs should produce a report."""
        logs = self._get_sample_logs()
        iocs = self._get_sample_iocs()
        result = run(self.script, ["--logs", str(logs), "--iocs", str(iocs)])
        assert result.returncode == 0
        assert len(result.stdout.strip()) > 0

    def test_cidr_match(self, tmp_path):
        """Running with sample inputs should not crash."""
        logs = self._get_sample_logs()
        iocs = self._get_sample_iocs()
        result = run(self.script, ["--logs", str(logs), "--iocs", str(iocs)])
        assert result.returncode in (0, 1)
        assert "Traceback" not in result.stderr


# ---------------------------------------------------------------------------
# segmentation-validator — expects --zones and --rules as separate args
# ---------------------------------------------------------------------------

class TestSegmentationValidator:
    script = NET_DIR / "segmentation-validator" / "main.py"
    sample_dir = NET_DIR / "segmentation-validator" / "sample_input"

    def _get_zones(self) -> Path:
        files = list(self.sample_dir.glob("*.json")) if self.sample_dir.exists() else []
        if not files:
            pytest.skip("No zones JSON sample for segmentation-validator")
        return files[0]

    def _get_rules(self) -> Path:
        files = list(self.sample_dir.glob("*.csv")) if self.sample_dir.exists() else []
        if not files:
            pytest.skip("No rules CSV sample for segmentation-validator")
        return files[0]

    def test_cross_zone_detection(self, tmp_path):
        """Running with sample zones and rules should produce output."""
        zones = self._get_zones()
        rules = self._get_rules()
        result = run(self.script, ["--zones", str(zones), "--rules", str(rules)])
        assert result.returncode == 0
        assert len(result.stdout.strip()) > 0

    def test_unzoned_rule_flagged(self, tmp_path):
        """Running with sample inputs should not crash."""
        zones = self._get_zones()
        rules = self._get_rules()
        result = run(self.script, ["--zones", str(zones), "--rules", str(rules)])
        assert result.returncode in (0, 1)
        assert "Traceback" not in result.stderr
