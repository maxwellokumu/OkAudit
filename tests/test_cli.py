from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from okaudit.cli import REGISTRY


def test_registry_contains_expected_commands():
    assert ("iam", "access-review") in REGISTRY
    assert ("iam", "sod-analyzer") in REGISTRY
    assert ("vendor", "contract-checker") in REGISTRY
