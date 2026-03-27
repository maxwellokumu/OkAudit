"""Tests for lead-it-auditor skills: audit-scope-checklist, artefact-gap-analyzer, exec-summary-writer."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
LEAD_DIR = REPO_ROOT / "lead-it-auditor"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run(script: Path, args: list[str]) -> subprocess.CompletedProcess:
    """Run a script with subprocess and return the result."""
    return subprocess.run(
        [sys.executable, str(script)] + args,
        capture_output=True,
        text=True,
    )


# ---------------------------------------------------------------------------
# audit-scope-checklist
# ---------------------------------------------------------------------------

class TestAuditScopeChecklist:
    script = LEAD_DIR / "audit-scope-checklist" / "main.py"

    def test_valid_input_produces_markdown(self, tmp_path):
        """Valid input should produce a markdown report."""
        result = run(self.script, ["--role", "lead-it-auditor", "--output", "markdown"])
        assert result.returncode == 0
        assert "Audit Scope Checklist" in result.stdout or "checklist" in result.stdout.lower()

    def test_invalid_role_exits_nonzero(self):
        """An unrecognised role should exit with a non-zero return code."""
        result = run(self.script, ["--role", "nonexistent-role-xyz"])
        assert result.returncode != 0
        assert result.stderr  # should print an error message

    def test_generates_json_output(self):
        """JSON output mode should produce valid JSON."""
        result = run(self.script, ["--role", "lead-it-auditor", "--output", "json"])
        assert result.returncode == 0
        try:
            data = json.loads(result.stdout)
            assert isinstance(data, (dict, list))
        except json.JSONDecodeError:
            pytest.fail("Output was not valid JSON")


# ---------------------------------------------------------------------------
# artefact-gap-analyzer
# ---------------------------------------------------------------------------

class TestArtefactGapAnalyzer:
    script = LEAD_DIR / "artefact-gap-analyzer" / "main.py"
    sample_dir = LEAD_DIR / "artefact-gap-analyzer" / "sample_input"

    def test_missing_file_exits_nonzero(self):
        """A non-existent input file should cause a non-zero exit."""
        result = run(self.script, ["--artefacts", "/nonexistent/path.json"])
        assert result.returncode != 0
        assert result.stderr

    def test_coverage_calculation_with_sample(self):
        """Running against sample_input should produce coverage output."""
        sample_files = list(self.sample_dir.glob("*.json")) if self.sample_dir.exists() else []
        if not sample_files:
            pytest.skip("No sample input files found for artefact-gap-analyzer")
        result = run(self.script, ["--artefacts", str(sample_files[0])])
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
            {"title": "Weak password policy", "risk": "High", "description": "No complexity rules enforced."},
            {"title": "Missing MFA", "risk": "Critical", "description": "Admin accounts lack MFA."},
        ]
        findings_file = tmp_path / "findings.json"
        findings_file.write_text(json.dumps(findings))
        result = run(self.script, ["--findings", str(findings_file)])
        assert result.returncode == 0
        assert len(result.stdout.strip()) > 0

    def test_invalid_risk_level_handled(self, tmp_path):
        """An unrecognised risk level should not crash the script."""
        findings = [{"title": "Test finding", "risk": "UNKNOWN_LEVEL", "description": "Test."}]
        findings_file = tmp_path / "findings.json"
        findings_file.write_text(json.dumps(findings))
        result = run(self.script, ["--findings", str(findings_file)])
        # Should either succeed with a warning or exit non-zero — must not crash
        assert result.returncode in (0, 1)

    def test_empty_findings_handled(self, tmp_path):
        """Empty findings list should produce a graceful response."""
        findings_file = tmp_path / "findings.json"
        findings_file.write_text("[]")
        result = run(self.script, ["--findings", str(findings_file)])
        assert result.returncode in (0, 1)
        # Should not crash with an unhandled exception
        assert "Traceback" not in result.stderr
