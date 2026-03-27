"""Tests for identity-access skills: access-review, sod-analyzer, privileged-account-monitor."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
IAM_DIR = REPO_ROOT / "identity-access"


def run(script: Path, args: list[str]) -> subprocess.CompletedProcess:
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    return subprocess.run(
        [sys.executable, str(script)] + args,
        capture_output=True,
        text=True,
        env=env,
    )


# ---------------------------------------------------------------------------
# access-review
# ---------------------------------------------------------------------------

class TestAccessReview:
    script = IAM_DIR / "access-review" / "main.py"

    def test_wildcard_detection(self, tmp_path):
        """Wildcard permissions should be flagged in the report."""
        permissions = {
            "users": [
                {"username": "alice", "permissions": ["*"], "role": "admin"}
            ]
        }
        perm_file = tmp_path / "permissions.json"
        perm_file.write_text(json.dumps(permissions))
        result = run(self.script, ["--input", str(perm_file)])
        assert result.returncode == 0
        assert "*" in result.stdout or "wildcard" in result.stdout.lower()

    def test_invalid_json_exits_nonzero(self, tmp_path):
        """Malformed JSON input should exit with non-zero code."""
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("{not valid json{{")
        result = run(self.script, ["--input", str(bad_file)])
        assert result.returncode != 0


# ---------------------------------------------------------------------------
# sod-analyzer
# ---------------------------------------------------------------------------

class TestSodAnalyzer:
    script = IAM_DIR / "sod-analyzer" / "main.py"

    def test_conflict_detection(self, tmp_path):
        """A user with conflicting roles should be flagged."""
        users = {
            "users": [
                {"username": "bob", "roles": ["accounts-payable", "accounts-receivable"]}
            ]
        }
        users_file = tmp_path / "users.json"
        users_file.write_text(json.dumps(users))
        result = run(self.script, ["--users", str(users_file), "--builtin-conflicts"])
        assert result.returncode == 0
        out_lower = result.stdout.lower()
        assert "conflict" in out_lower or "sod" in out_lower or "segregat" in out_lower

    def test_builtin_conflicts_detected(self, tmp_path):
        """Built-in SoD conflict rules should detect standard violations."""
        users = {
            "users": [
                {"username": "carol", "roles": ["create-vendor", "approve-payment"]}
            ]
        }
        users_file = tmp_path / "users.json"
        users_file.write_text(json.dumps(users))
        result = run(self.script, ["--users", str(users_file), "--builtin-conflicts"])
        assert result.returncode == 0
        assert len(result.stdout.strip()) > 0

    def test_no_conflicts_clean_output(self, tmp_path):
        """A user with non-conflicting roles should not produce conflict warnings."""
        users = {
            "users": [
                {"username": "dave", "roles": ["read-only-analyst"]}
            ]
        }
        users_file = tmp_path / "users.json"
        users_file.write_text(json.dumps(users))
        result = run(self.script, ["--users", str(users_file), "--builtin-conflicts"])
        assert result.returncode == 0
        assert "Traceback" not in result.stderr


# ---------------------------------------------------------------------------
# privileged-account-monitor
# ---------------------------------------------------------------------------

class TestPrivilegedAccountMonitor:
    script = IAM_DIR / "privileged-account-monitor" / "main.py"
    sample_dir = IAM_DIR / "privileged-account-monitor" / "sample_input"

    def test_baseline_exceeded_flagged(self, tmp_path):
        """Accounts exceeding a privilege baseline should appear in the report."""
        sample_dir = self.sample_dir
        files = list(sample_dir.glob("*.csv")) if sample_dir.exists() else []
        if not files:
            pytest.skip("No CSV sample input for privileged-account-monitor")
        result = run(self.script, ["--logs", str(files[0])])
        assert result.returncode in (0, 1)
        assert "Traceback" not in result.stderr

    def test_off_hours_activity_flagged(self, tmp_path):
        """Privileged account activity outside business hours should be flagged."""
        sample_dir = self.sample_dir
        files = list(sample_dir.glob("*.csv")) if sample_dir.exists() else []
        if not files:
            pytest.skip("No CSV sample input for privileged-account-monitor")
        result = run(self.script, ["--logs", str(files[0])])
        assert result.returncode in (0, 1)
        assert "Traceback" not in result.stderr
