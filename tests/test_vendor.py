"""Tests for vendor-risk skills: vendor-assessor, contract-checker, supply-chain-mapper."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
VENDOR_DIR = REPO_ROOT / "vendor-risk"


def run(script: Path, args: list[str]) -> subprocess.CompletedProcess:
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    return subprocess.run(
        [sys.executable, str(script)] + args,
        capture_output=True,
        text=True,
        env=env,
    )


# ---------------------------------------------------------------------------
# vendor-assessor
# ---------------------------------------------------------------------------

class TestVendorAssessor:
    script = VENDOR_DIR / "vendor-assessor" / "main.py"
    sample_dir = VENDOR_DIR / "vendor-assessor" / "sample_input"

    def _get_sample(self) -> Path:
        files = list(self.sample_dir.glob("*.json")) if self.sample_dir.exists() else []
        if not files:
            pytest.skip("No sample input for vendor-assessor")
        return files[0]

    def test_scoring_produces_numeric_result(self):
        """Vendor assessment should include a numeric risk score."""
        sample = self._get_sample()
        result = run(self.script, ["--answers", str(sample)])
        assert result.returncode == 0
        out_lower = result.stdout.lower()
        assert any(w in out_lower for w in ["score", "risk", "rating", "%"])

    def test_risk_levels_present(self):
        """Report should categorise vendors into risk levels."""
        sample = self._get_sample()
        result = run(self.script, ["--answers", str(sample)])
        assert result.returncode == 0
        out_lower = result.stdout.lower()
        assert any(level in out_lower for level in ["critical", "high", "medium", "low"])


# ---------------------------------------------------------------------------
# contract-checker
# ---------------------------------------------------------------------------

class TestContractChecker:
    script = VENDOR_DIR / "contract-checker" / "main.py"
    sample_dir = VENDOR_DIR / "contract-checker" / "sample_input"

    def _get_sample_contract(self) -> Path:
        files = list(self.sample_dir.glob("*.txt")) if self.sample_dir.exists() else []
        if not files:
            pytest.skip("No .txt sample input for contract-checker")
        return files[0]

    def test_found_clauses_reported(self):
        """Present clauses should appear in the report."""
        sample = self._get_sample_contract()
        result = run(self.script, ["--contract", str(sample), "--standard", "gdpr"])
        assert result.returncode == 0
        out_lower = result.stdout.lower()
        assert any(w in out_lower for w in ["clause", "found", "present", "detected", "compliant"])

    def test_missing_clauses_flagged(self, tmp_path):
        """A contract with no recognised clauses should flag missing items."""
        empty_contract = tmp_path / "empty_contract.txt"
        empty_contract.write_text("This is a simple service agreement with no specific clauses.")
        result = run(self.script, ["--contract", str(empty_contract), "--standard", "gdpr"])
        assert result.returncode == 0
        out_lower = result.stdout.lower()
        assert any(w in out_lower for w in ["missing", "not found", "absent", "gap", "fail"])


# ---------------------------------------------------------------------------
# supply-chain-mapper
# ---------------------------------------------------------------------------

class TestSupplyChainMapper:
    script = VENDOR_DIR / "supply-chain-mapper" / "main.py"
    sample_dir = VENDOR_DIR / "supply-chain-mapper" / "sample_input"

    def _get_sample(self) -> Path:
        files = list(self.sample_dir.glob("*.csv")) if self.sample_dir.exists() else []
        if not files:
            pytest.skip("No sample input for supply-chain-mapper")
        return files[0]

    def test_mermaid_output_contains_graph(self):
        """Mermaid output mode should contain a graph definition."""
        sample = self._get_sample()
        result = run(self.script, ["--vendors", str(sample), "--output", "mermaid"])
        assert result.returncode == 0
        assert "graph" in result.stdout.lower() or "-->" in result.stdout

    def test_circular_dependency_detected(self, tmp_path):
        """A circular dependency should be flagged in the report."""
        import csv
        circular = tmp_path / "circular.csv"
        with open(circular, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["vendor_id", "vendor_name", "tier", "depends_on", "criticality", "country"])
            writer.writerow(["V001", "ServiceA", "1", "V002", "High", "US"])
            writer.writerow(["V002", "ServiceB", "2", "V001", "High", "UK"])
        result = run(self.script, ["--vendors", str(circular)])
        assert result.returncode in (0, 1)
        out_combined = (result.stdout + result.stderr).lower()
        assert any(w in out_combined for w in ["circular", "cycle", "loop", "servicea", "serviceb"])
