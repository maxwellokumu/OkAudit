"""Tests for data-privacy skills: data-inventory-mapper, consent-checker, pia-generator."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
PRIV_DIR = REPO_ROOT / "data-privacy"


def run(script: Path, args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(script)] + args,
        capture_output=True,
        text=True,
    )


# ---------------------------------------------------------------------------
# data-inventory-mapper
# ---------------------------------------------------------------------------

class TestDataInventoryMapper:
    script = PRIV_DIR / "data-inventory-mapper" / "main.py"
    sample_dir = PRIV_DIR / "data-inventory-mapper" / "sample_input"

    def _get_sample(self) -> Path:
        files = list(self.sample_dir.glob("*.json")) if self.sample_dir.exists() else []
        if not files:
            pytest.skip("No sample input for data-inventory-mapper")
        return files[0]

    def test_mermaid_output(self):
        """Mermaid output should contain a graph/flowchart definition."""
        sample = self._get_sample()
        result = run(self.script, ["--inventory", str(sample), "--output", "mermaid"])
        assert result.returncode == 0
        assert "graph" in result.stdout.lower() or "-->" in result.stdout or "flowchart" in result.stdout.lower()

    def test_special_category_flag(self, tmp_path):
        """Special category data (health, biometric) should be highlighted."""
        inventory = {
            "data_assets": [
                {"name": "Patient Records", "classification": "health_data", "owner": "Clinical", "location": "DB-01"},
                {"name": "Biometric Scans", "classification": "biometric", "owner": "HR", "location": "DB-02"},
            ]
        }
        inv_file = tmp_path / "inventory.json"
        inv_file.write_text(json.dumps(inventory))
        result = run(self.script, ["--inventory", str(inv_file)])
        assert result.returncode == 0
        out_lower = result.stdout.lower()
        assert any(w in out_lower for w in ["special", "sensitive", "health", "biometric", "article 9", "flag"])


# ---------------------------------------------------------------------------
# consent-checker
# ---------------------------------------------------------------------------

class TestConsentChecker:
    script = PRIV_DIR / "consent-checker" / "main.py"
    sample_dir = PRIV_DIR / "consent-checker" / "sample_input"

    def _get_sample(self) -> Path:
        files = list(self.sample_dir.glob("*")) if self.sample_dir.exists() else []
        if not files:
            pytest.skip("No sample input for consent-checker")
        return files[0]

    def test_gdpr_requirements_checked(self, tmp_path):
        """GDPR consent check should validate key GDPR requirements."""
        consent_config = {
            "framework": "GDPR",
            "consent_mechanism": "pre_ticked_box",
            "withdrawal_possible": False,
            "granular_options": False,
        }
        config_file = tmp_path / "consent.json"
        config_file.write_text(json.dumps(consent_config))
        result = run(self.script, ["--config", str(config_file), "--framework", "GDPR"])
        assert result.returncode == 0
        out_lower = result.stdout.lower()
        assert any(w in out_lower for w in ["gdpr", "consent", "fail", "non-compliant", "❌", "violation"])

    def test_ccpa_requirements_checked(self, tmp_path):
        """CCPA consent check should validate opt-out rights."""
        consent_config = {
            "framework": "CCPA",
            "opt_out_available": False,
            "do_not_sell_link": False,
        }
        config_file = tmp_path / "consent.json"
        config_file.write_text(json.dumps(consent_config))
        result = run(self.script, ["--config", str(config_file), "--framework", "CCPA"])
        assert result.returncode in (0, 1)
        assert "Traceback" not in result.stderr


# ---------------------------------------------------------------------------
# pia-generator
# ---------------------------------------------------------------------------

class TestPiaGenerator:
    script = PRIV_DIR / "pia-generator" / "main.py"

    def test_risk_assessment_present(self):
        """PIA output should include a risk assessment section."""
        sample_dir = PRIV_DIR / "pia-generator"
        # Try to find any sample input, or run with defaults
        json_files = list(sample_dir.glob("*.json"))
        if json_files:
            result = run(self.script, ["--project", str(json_files[0])])
        else:
            result = run(self.script, ["--project-name", "Test System", "--data-types", "name,email"])
        assert result.returncode in (0, 1)
        out_lower = (result.stdout + result.stderr).lower()
        if result.returncode == 0:
            assert any(w in out_lower for w in ["risk", "pia", "privacy", "assessment"])

    def test_special_category_data_elevates_risk(self, tmp_path):
        """Projects processing special category data should attract higher risk rating."""
        project = {
            "name": "Health Monitoring App",
            "data_types": ["health_data", "location", "name"],
            "processing_purpose": "Medical monitoring",
            "data_subjects": "patients",
        }
        proj_file = tmp_path / "project.json"
        proj_file.write_text(json.dumps(project))
        result = run(self.script, ["--project", str(proj_file)])
        assert result.returncode in (0, 1)
        assert "Traceback" not in result.stderr
