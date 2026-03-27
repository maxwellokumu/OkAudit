"""Tests for application-security skills: vuln-parser, code-review-helper, devsecops-checker."""
from __future__ import annotations

import csv
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
APPSEC_DIR = REPO_ROOT / "application-security"


def run(script: Path, args: list[str]) -> subprocess.CompletedProcess:
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    return subprocess.run(
        [sys.executable, str(script)] + args,
        capture_output=True,
        text=True,
        env=env,
    )


def write_scan_csv(path: Path, rows: list[dict]) -> None:
    fields = ["vulnerability", "severity", "host", "port", "cve_id", "description", "plugin_id"]
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


# ---------------------------------------------------------------------------
# vuln-parser
# ---------------------------------------------------------------------------

class TestVulnParser:
    script = APPSEC_DIR / "vuln-parser" / "main.py"

    def test_risk_scoring(self, tmp_path):
        """Host with Critical findings should have a higher score than one with only Lows."""
        rows = [
            {"vulnerability": "RCE", "severity": "Critical", "host": "10.0.0.1",
             "port": "443", "cve_id": "CVE-2021-0001", "description": "Critical RCE", "plugin_id": "P001"},
            {"vulnerability": "Info Leak", "severity": "Low", "host": "10.0.0.2",
             "port": "80", "cve_id": "", "description": "Info disclosure", "plugin_id": "P002"},
        ]
        scan_file = tmp_path / "scan.csv"
        write_scan_csv(scan_file, rows)
        result = run(self.script, ["--scan", str(scan_file), "--output", "json"])
        assert result.returncode == 0
        data = json.loads(result.stdout)
        top_hosts = data["top_hosts"]
        host_names = [h["host"] for h in top_hosts]
        assert host_names.index("10.0.0.1") < host_names.index("10.0.0.2")

    def test_severity_grouping(self, tmp_path):
        """Markdown output should group findings under severity headers."""
        rows = [
            {"vulnerability": "SQL Injection", "severity": "Critical", "host": "db.local",
             "port": "3306", "cve_id": "CVE-2023-0001", "description": "SQLi found", "plugin_id": "P010"},
            {"vulnerability": "Open Port", "severity": "Low", "host": "db.local",
             "port": "8080", "cve_id": "", "description": "Unnecessary port", "plugin_id": "P011"},
        ]
        scan_file = tmp_path / "scan.csv"
        write_scan_csv(scan_file, rows)
        result = run(self.script, ["--scan", str(scan_file)])
        assert result.returncode == 0
        assert "Critical" in result.stdout
        assert "Low" in result.stdout


# ---------------------------------------------------------------------------
# code-review-helper
# ---------------------------------------------------------------------------

class TestCodeReviewHelper:
    script = APPSEC_DIR / "code-review-helper" / "main.py"
    sample_dir = APPSEC_DIR / "code-review-helper" / "sample_input"

    def test_python_secrets_detection(self, tmp_path):
        """Hardcoded password in Python should be flagged as Critical."""
        code = 'password = "super_secret_password_123"\nprint("hello")\n'
        code_file = tmp_path / "app.py"
        code_file.write_text(code)
        result = run(self.script, ["--code", str(code_file), "--language", "python"])
        assert result.returncode == 0
        out_lower = result.stdout.lower()
        assert "hardcoded" in out_lower or "secret" in out_lower or "cwe-798" in out_lower

    def test_python_sql_injection_detection(self, tmp_path):
        """String-formatted SQL query should be detected."""
        code = (
            'import sqlite3\n'
            'def get_user(name):\n'
            '    cursor.execute("SELECT * FROM users WHERE name = \'%s\'" % name)\n'
        )
        code_file = tmp_path / "db.py"
        code_file.write_text(code)
        result = run(self.script, ["--code", str(code_file), "--language", "python"])
        assert result.returncode == 0
        out_lower = result.stdout.lower()
        assert "sql" in out_lower or "injection" in out_lower or "cwe-89" in out_lower

    def test_javascript_eval_detection(self, tmp_path):
        """eval() in JavaScript should be detected."""
        code = 'function run(userInput) {\n    return eval(userInput);\n}\n'
        code_file = tmp_path / "app.js"
        code_file.write_text(code)
        result = run(self.script, ["--code", str(code_file), "--language", "javascript"])
        assert result.returncode == 0
        out_lower = result.stdout.lower()
        assert "eval" in out_lower or "cwe-95" in out_lower

    def test_clean_file_reports_no_findings(self, tmp_path):
        """A file with no vulnerability patterns should get a clean bill of health."""
        code = (
            'def greet(name: str) -> str:\n'
            '    """Return a greeting."""\n'
            '    return f"Hello, {name}!"\n'
        )
        code_file = tmp_path / "clean.py"
        code_file.write_text(code)
        result = run(self.script, ["--code", str(code_file), "--language", "python"])
        assert result.returncode == 0
        out_lower = result.stdout.lower()
        assert "clean" in out_lower or "no" in out_lower or "0" in out_lower


# ---------------------------------------------------------------------------
# devsecops-checker
# ---------------------------------------------------------------------------

class TestDevSecOpsChecker:
    script = APPSEC_DIR / "devsecops-checker" / "main.py"
    sample_dir = APPSEC_DIR / "devsecops-checker" / "sample_input"

    def test_github_actions_detected(self):
        """GitHub Actions config should be auto-detected as GitHub Actions."""
        config = self.sample_dir / "github_actions.yml"
        if not config.exists():
            pytest.skip("github_actions.yml sample not found")
        result = run(self.script, ["--config", str(config)])
        assert result.returncode == 0
        assert "GitHub Actions" in result.stdout

    def test_missing_controls_reported(self):
        """Missing security controls should appear in the report."""
        config = self.sample_dir / "github_actions.yml"
        if not config.exists():
            pytest.skip("github_actions.yml sample not found")
        result = run(self.script, ["--config", str(config)])
        assert result.returncode == 0
        out_lower = result.stdout.lower()
        assert "missing" in out_lower or "not present" in out_lower or "absent" in out_lower

    def test_maturity_score_in_output(self):
        """Maturity score should appear in markdown output."""
        config = self.sample_dir / "github_actions.yml"
        if not config.exists():
            pytest.skip("github_actions.yml sample not found")
        result = run(self.script, ["--config", str(config)])
        assert result.returncode == 0
        out_lower = result.stdout.lower()
        assert "maturity" in out_lower or "score" in out_lower

    def test_json_output_valid(self):
        """JSON output should be parseable and contain expected keys."""
        config = self.sample_dir / "gitlab_ci.yml"
        if not config.exists():
            pytest.skip("gitlab_ci.yml sample not found")
        result = run(self.script, ["--config", str(config), "--output", "json"])
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert "maturity_score" in data
        assert "controls" in data
        assert isinstance(data["maturity_score"], (int, float))
        assert 0 <= data["maturity_score"] <= 100
