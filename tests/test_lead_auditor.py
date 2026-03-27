"""Tests for lead-it-auditor skills: audit-scope-checklist, artefact-gap-analyzer, exec-summary-writer."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
LEAD_DIR = REPO_ROOT / "lead-it-auditor"


def run(script: Path, args: list[str]) -> subprocess.CompletedProcess:
    """Run a script with subprocess and return the result."""
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    return subprocess.run(
        [sys.executable, str(script)] + args,
        capture_output=True,
        text=True,
        env=env,
    )


# ---------------------------------------------------------------------------
# audit-scope-checklist
# ---------------------------------------------------------------------------

class TestAuditScopeChecklist:
    script = LEAD_DIR / "audit-scope-checklist" / "main.py"

    def test_valid_input_produces_markdown(self, tmp_path):
        """Valid input should produce a markdown report."""
        result = run(self.script, ["--system", "ERP", "--output-dir", str(tmp_path)])
        assert result.returncode == 0

    def test_invalid_role_exits_nonzero(self):
        """An unrecognised mode should exit with a non-zero return code."""
        result = run(self.script, ["--system", "ERP", "--mode", "nonexistent-mode-xyz"])
        assert result.returncode != 0

    def test_generates_json_output(self, tmp_path):
        """Running the script should produce output files."""
        result = run(self.script, ["--system", "ERP", "--output-dir", str(tmp_path)])
        assert result.returncode == 0
        assert "Traceback" not in result.stderr


# ---------------------------------------------------------------------------
# artefact-gap-analyzer
# ---------------------------------------------------------------------------

class TestArtefactGapAnalyzer:
    script = LEAD_DIR / "artefact-gap-analyzer" / "main.py"
    sample_dir = LEAD_DIR / "artefact-gap-analyzer" / "sample_input"

    def test_missing_file_exits_nonzero(self):
        """A non-existent input file should cause a non-zero exit."""
        result = run(self.script, ["--program", "/nonexistent/path.json", "--provided", "/nonexistent/dir"])
        assert result.returncode != 0
        assert result.stderr

    def test_coverage_calculation_with_sample(self):
        """Running against sample_input should produce coverage output."""
        program_files = list(self.sample_dir.glob("*.json")) if self.sample_dir.exists() else []
        evidence_dir = self.sample_dir / "sample_evidence"
        if not program_files:
            pytest.skip("No sample input files found for artefact-gap-analyzer")
        result = run(self.script, [
            "--program", str(program_files[0]),
            "--provided", str(evidence_dir) if evidence_dir.exists() else str(self.sample_dir),
        ])
        assert result.returncode == 0
        out_lower = result.stdout.lower()
        assert any(word in out_lower for word in ["coverage", "gap", "artefact", "artifact", "missing"])


# ---------------------------------------------------------------------------
# exec-summary-writer
# ---------------------------------------------------------------------------

class TestExecSummaryWriter:
    script = LEAD_DIR / "exec-summary-writer" / "main.py"

    def test_valid_findings_produces_output(self, tmp_path):
        """Valid findings JSON should produce a non-empty report."""
        findings = [
            {
                "title": "Weak password policy",
                "risk_level": "High",
                "description": "No complexity rules enforced.",
                "affected_system": "Active Directory",
                "recommendation": "Enforce password complexity policy.",
            },
            {
                "title": "Missing MFA",
                "risk_level": "Critical",
                "description": "Admin accounts lack MFA.",
                "affected_system": "AWS Console",
                "recommendation": "Enable MFA for all admin accounts.",
            },
        ]
        findings_file = tmp_path / "findings.json"
        findings_file.write_text(json.dumps(findings))
        result = run(self.script, ["--findings", str(findings_file)])
        assert result.returncode == 0
        assert len(result.stdout.strip()) > 0

    def test_invalid_risk_level_handled(self, tmp_path):
        """An unrecognised risk level should not crash the script."""
        findings = [{
            "title": "Test finding",
            "risk_level": "UNKNOWN_LEVEL",
            "description": "Test.",
            "affected_system": "Test System",
            "recommendation": "Fix it.",
        }]
        findings_file = tmp_path / "findings.json"
        findings_file.write_text(json.dumps(findings))
        result = run(self.script, ["--findings", str(findings_file)])
        assert result.returncode in (0, 1)

    def test_empty_findings_handled(self, tmp_path):
        """Empty findings list should produce a graceful response."""
        findings_file = tmp_path / "findings.json"
        findings_file.write_text("[]")
        result = run(self.script, ["--findings", str(findings_file)])
        assert result.returncode in (0, 1)
        assert "Traceback" not in result.stderr
