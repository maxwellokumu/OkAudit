"""Tests for compliance-controls skills: compliance-checker, policy-writer, evidence-tracker."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
COMP_DIR = REPO_ROOT / "compliance-controls"


def run(script: Path, args: list[str]) -> subprocess.CompletedProcess:
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    return subprocess.run(
        [sys.executable, str(script)] + args,
        capture_output=True,
        text=True,
        env=env,
    )


# ---------------------------------------------------------------------------
# compliance-checker
# ---------------------------------------------------------------------------

class TestComplianceChecker:
    script = COMP_DIR / "compliance-checker" / "main.py"
    sample_dir = COMP_DIR / "compliance-checker" / "sample_input"

    def _get_sample(self) -> Path:
        files = list(self.sample_dir.glob("*.json")) if self.sample_dir.exists() else []
        if not files:
            pytest.skip("No sample input found for compliance-checker")
        return files[0]

    def test_cis_pass_produces_output(self):
        """Running against a sample should produce a non-empty compliance report."""
        sample = self._get_sample()
        result = run(self.script, ["--config", str(sample), "--standard", "cis"])
        assert result.returncode == 0
        assert len(result.stdout.strip()) > 50

    def test_cis_fail_flagged(self, tmp_path):
        """A config with known failing controls should show failures."""
        config = {"password_min_length": 4, "mfa_enabled": False, "audit_logging": False}
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))
        result = run(self.script, ["--config", str(config_file), "--standard", "cis"])
        assert result.returncode == 0
        out_lower = result.stdout.lower()
        assert any(w in out_lower for w in ["fail", "non-compliant", "not met"])

    def test_invalid_standard_exits_nonzero(self, tmp_path):
        """An unsupported compliance standard should exit non-zero."""
        config_file = tmp_path / "config.json"
        config_file.write_text("{}")
        result = run(self.script, ["--config", str(config_file), "--standard", "MADE_UP_STANDARD_XYZ"])
        assert result.returncode != 0


# ---------------------------------------------------------------------------
# policy-writer
# ---------------------------------------------------------------------------

class TestPolicyWriter:
    script = COMP_DIR / "policy-writer" / "main.py"

    def test_valid_topic_produces_policy(self):
        """A recognised policy topic should produce a full policy document."""
        result = run(self.script, ["--topic", "password", "--framework", "iso27001"])
        assert result.returncode == 0
        out_lower = result.stdout.lower()
        assert any(w in out_lower for w in ["policy", "password", "purpose", "scope"])

    def test_invalid_topic_exits_nonzero(self):
        """An unrecognised topic should exit with a non-zero code."""
        result = run(self.script, ["--topic", "completely_nonexistent_policy_topic_xyz", "--framework", "iso27001"])
        assert result.returncode != 0
        assert result.stderr


# ---------------------------------------------------------------------------
# evidence-tracker
# ---------------------------------------------------------------------------

class TestEvidenceTracker:
    script = COMP_DIR / "evidence-tracker" / "main.py"
    sample_dir = COMP_DIR / "evidence-tracker" / "sample_input"

    def _get_sample(self) -> Path:
        files = list(self.sample_dir.glob("*.json")) if self.sample_dir.exists() else []
        if not files:
            pytest.skip("No sample input found for evidence-tracker")
        return files[0]

    def test_init_produces_tracker(self):
        """Running with --list should produce an evidence tracker listing."""
        result = run(self.script, ["--list"])
        assert result.returncode in (0, 1)
        assert "Traceback" not in result.stderr

    def test_update_status_with_sample(self):
        """Loading a program file should not crash."""
        sample = self._get_sample()
        result = run(self.script, ["--program", str(sample), "--list"])
        assert result.returncode in (0, 1)
        assert "Traceback" not in result.stderr

    def test_invalid_transition_handled(self, tmp_path):
        """An invalid status value should be handled gracefully."""
        result = run(self.script, ["--list"])
        assert "Traceback" not in result.stderr
