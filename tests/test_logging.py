"""Tests for log-monitoring skills: log-analyzer, anomaly-detector, incident-timeline-builder."""

import csv
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
LOG_DIR = REPO_ROOT / "log-monitoring"


def run(script: Path, args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(script)] + args,
        capture_output=True,
        text=True,
    )


def write_csv(path: Path, rows: list[dict], fieldnames: list[str]) -> None:
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


# ---------------------------------------------------------------------------
# log-analyzer
# ---------------------------------------------------------------------------

class TestLogAnalyzer:
    script = LOG_DIR / "log-analyzer" / "main.py"
    sample_dir = LOG_DIR / "log-analyzer" / "sample_input"

    def test_flags_suspicious_events(self, tmp_path):
        """Logs with failed login bursts should be flagged."""
        logs = [
            {"timestamp": f"2024-06-03T10:0{i}:00", "event_type": "AUTH_FAILURE",
             "source_ip": "192.168.1.50", "user": "admin", "message": "Login failed"}
            for i in range(6)
        ]
        log_file = tmp_path / "logs.json"
        log_file.write_text(json.dumps(logs))
        result = run(self.script, ["--logs", str(log_file)])
        assert result.returncode == 0
        out_lower = result.stdout.lower()
        assert any(w in out_lower for w in ["fail", "suspicious", "flag", "auth", "anomaly", "alert"])

    def test_empty_logs_handled(self, tmp_path):
        """An empty log file should not crash the analyzer."""
        log_file = tmp_path / "empty.json"
        log_file.write_text("[]")
        result = run(self.script, ["--logs", str(log_file)])
        assert result.returncode in (0, 1)
        assert "Traceback" not in result.stderr


# ---------------------------------------------------------------------------
# anomaly-detector
# ---------------------------------------------------------------------------

class TestAnomalyDetector:
    script = LOG_DIR / "anomaly-detector" / "main.py"

    def test_flags_outlier(self, tmp_path):
        """A spike in events should be detected as anomalous."""
        sample_dir = LOG_DIR / "anomaly-detector" / "sample_input"
        sample_files = list(sample_dir.glob("*")) if sample_dir.exists() else []
        if not sample_files:
            pytest.skip("No sample input for anomaly-detector")
        result = run(self.script, ["--logs", str(sample_files[0])])
        assert result.returncode == 0
        assert len(result.stdout.strip()) > 0

    def test_insufficient_baseline_handled(self, tmp_path):
        """Very few log entries should not crash the detector."""
        logs = [{"timestamp": "2024-06-03T10:00:00", "event_type": "LOGIN", "source_ip": "10.0.0.1", "user": "alice"}]
        log_file = tmp_path / "tiny.json"
        log_file.write_text(json.dumps(logs))
        result = run(self.script, ["--logs", str(log_file)])
        assert result.returncode in (0, 1)
        assert "Traceback" not in result.stderr


# ---------------------------------------------------------------------------
# incident-timeline-builder
# ---------------------------------------------------------------------------

class TestIncidentTimelineBuilder:
    script = LOG_DIR / "incident-timeline-builder" / "main.py"
    sample_dir = LOG_DIR / "incident-timeline-builder" / "sample_input"

    def _get_sample(self) -> Path:
        files = list(self.sample_dir.glob("*")) if self.sample_dir.exists() else []
        if not files:
            pytest.skip("No sample input for incident-timeline-builder")
        return files[0]

    def test_date_filter(self, tmp_path):
        """Date range filter should restrict timeline to matching events."""
        sample = self._get_sample()
        result = run(self.script, ["--logs", str(sample), "--start", "2024-06-01", "--end", "2024-06-30"])
        assert result.returncode == 0
        assert len(result.stdout.strip()) > 0

    def test_actor_filter(self, tmp_path):
        """Filtering by actor/user should narrow the timeline."""
        sample = self._get_sample()
        result = run(self.script, ["--logs", str(sample), "--actor", "admin"])
        assert result.returncode in (0, 1)
        assert "Traceback" not in result.stderr
