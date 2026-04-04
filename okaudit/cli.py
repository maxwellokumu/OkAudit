import subprocess
import sys
import os
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent

REGISTRY = {
    ("iam", "access-review"): ROOT / "identity-access" / "access-review" / "main.py",
    ("iam", "sod-analyzer"): ROOT / "identity-access" / "sod-analyzer" / "main.py",
    ("vendor", "contract-checker"): ROOT / "vendor-risk" / "contract-checker" / "main.py",
    ("network", "network-config-reviewer"): ROOT / "network-security" / "network-config-reviewer" / "main.py",
    ("privacy", "pia-generator"): ROOT / "data-privacy" / "pia-generator" / "main.py",
}


def main() -> int:
    if len(sys.argv) < 3:
        print("Usage: okaudit <domain> <skill> [args...]")
        print("Example: okaudit iam access-review --input iam_policy.json")
        return 1

    domain = sys.argv[1]
    skill = sys.argv[2]
    extra_args = sys.argv[3:]

    script = REGISTRY.get((domain, skill))
    if script is None:
        print(f"Unknown command: {domain} {skill}")
        return 1

    env = os.environ.copy()
    env.setdefault("PYTHONIOENCODING", "utf-8")
    result = subprocess.run([sys.executable, str(script), *extra_args], env=env)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
