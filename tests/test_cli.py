from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from okaudit.cli import REGISTRY
from okaudit import cli


def test_registry_contains_expected_commands():
    assert ("iam", "access-review") in REGISTRY
    assert ("iam", "sod-analyzer") in REGISTRY
    assert ("vendor", "contract-checker") in REGISTRY
    assert "description" in REGISTRY[("iam", "access-review")]


def test_list_command_returns_success(capsys):
    result = cli.handle_list([])
    captured = capsys.readouterr()

    assert result == 0
    assert "Available commands:" in captured.out
    assert "iam:" in captured.out


def test_list_domain_returns_success(capsys):
    result = cli.handle_list(["iam"])
    captured = capsys.readouterr()

    assert result == 0
    assert "Commands in iam:" in captured.out
    assert "access-review" in captured.out


def test_help_command_returns_success(capsys):
    result = cli.handle_help(["iam", "access-review"])
    captured = capsys.readouterr()

    assert result == 0
    assert "iam access-review" in captured.out
    assert "Description:" in captured.out


def test_version_command_returns_success(capsys):
    result = cli.handle_version()
    captured = capsys.readouterr()

    assert result == 0
    assert "okaudit 0.2.0" in captured.out
