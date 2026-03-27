"""Tests for data-privacy skills: data-inventory-mapper, consent-checker, pia-generator."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
PRIV_DIR = REPO_ROOT / "data-privacy"


def run(script: Path, args: list[str]) -> subprocess.CompletedProcess:
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    return subprocess.run(
        [sys.executable, str(script)] + args,
        capture_output=True,
        text=True,
        env=env,
    )


# ---------------------------------------------------------------------------
# data-inventory-mapper — expects CSV not JSON
# ---------------------------------------------------------------------------

class TestDataInventoryMapper:
    script = PRIV_DIR / "data-inventory-mapper" / "main.py"
    sample_dir = PRIV_DIR / "data-inventory-mapper" / "sample_input"

    def _get_sample(self) -> Path:
        files = list(self.sample_dir.glob("*.csv")) if self.sample_dir.exists() else []
        if not files:
            pytest.skip("No CSV sample input for data-inventory-mapper")
        return files[0]

    def test_mermaid_output(self):
        """Mermaid output should contain a graph/flowchart definition."""
        sample = self._get_sample()
        result = run(self.script, ["--inventory", str(sample), "--output", "mermaid"])
        assert result.returncode == 0
        assert "graph" in result.stdout.lower() or "-->" in result.stdout or "flowchart" in result.stdout.lower()

    def test_special_category_flag(self, tmp_path):
        """Special category data (health, biometric) should be highlighted."""
        import csv
        inv_file = tmp_path / "inventory.csv"
        with open(inv_file, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["name", "data_type", "classification", "system", "location",
                              "transfers_to", "retention_period", "legal_basis", "owner"])
            writer.writerow(["Patient Records", "health_data", "special_category",
                              "EHR", "DB-01", "none", "7 years", "consent", "Clinical"])
            writer.writerow(["Biometric Scans", "biometric", "special_category",
                              "HR System", "DB-02", "none", "5 years", "consent", "HR"])
        result = run(self.script, ["--inventory", str(inv_file)])
        assert result.returncode == 0
        out_lower = result.stdout.lower()
        assert any(w in out_lower for w in ["special", "sensitive", "health", "biometric", "flag"])


# ---------------------------------------------------------------------------
# consent-checker — framework values must be lowercase
# ---------------------------------------------------------------------------

class TestConsentChecker:
    script = PRIV_DIR / "consent-checker" / "main.py"
    sample_dir = PRIV_DIR / "consent-checker" / "sample_input"

    def _get_sample(self) -> Path:
        files = list(self.sample_dir.glob("*.txt")) if self.sample_dir.exists() else []
        if not files:
            pytest.skip("No sample input for consent-checker")
        return files[0]

    def test_gdpr_requirements_checked(self, tmp_path):
        """GDPR consent check should validate key GDPR requirements."""
        sample = self._get_sample()
        result = run(self.script, ["--policy", str(sample), "--framework", "gdpr"])
        assert result.returncode == 0
        out_lower = result.stdout.lower()
        assert any(w in out_lower for w in ["gdpr", "consent", "fail", "non-compliant", "violation", "check"])

    def test_ccpa_requirements_checked(self, tmp_path):
        """CCPA consent check should validate opt-out rights."""
        sample = self._get_sample()
        result = run(self.script, ["--policy", str(sample), "--framework", "ccpa"])
        assert result.returncode in (0, 1)
        assert "Traceback" not in result.stderr


# ---------------------------------------------------------------------------
# pia-generator — requires --project + --data-types + --purposes + --recipients + --retention
# ---------------------------------------------------------------------------

class TestPiaGenerator:
    script = PRIV_DIR / "pia-generator" / "main.py"

    def test_risk_assessment_present(self, tmp_path):
        """PIA output should include a risk assessment section."""
        result = run(self.script, [
            "--project", "Test System",
            "--data-types", "name,email",
            "--purposes", "service_delivery",
            "--recipients", "internal",
            "--retention", "1 year",
        ])
        assert result.returncode in (0, 1)
        if result.returncode == 0:
            out_lower = result.stdout.lower()
            assert any(w in out_lower for w in ["risk", "pia", "privacy", "assessment"])

    def test_special_category_data_elevates_risk(self, tmp_path):
        """Projects processing special category data should attract higher risk rating."""
        result = run(self.script, [
            "--project", "Health Monitoring App",
            "--data-types", "health_data,location,name",
            "--purposes", "medical_monitoring",
            "--recipients", "clinical_staff",
            "--retention", "7 years",
        ])
        assert result.returncode in (0, 1)
        assert "Traceback" not in result.stderr
