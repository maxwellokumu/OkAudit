import subprocess
import sys
import os
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
VERSION = "0.2.0"

REGISTRY = {
    ("iam", "access-review"): {
        "script": ROOT / "identity-access" / "access-review" / "main.py",
        "description": "Review IAM policies for over-privileged access and control weaknesses.",
    },
    ("iam", "sod-analyzer"): {
        "script": ROOT / "identity-access" / "sod-analyzer" / "main.py",
        "description": "Analyze users and roles for separation-of-duties conflicts.",
    },
    ("vendor", "contract-checker"): {
        "script": ROOT / "vendor-risk" / "contract-checker" / "main.py",
        "description": "Check vendor contracts for required clauses and missing protections.",
    },
    ("network", "network-config-reviewer"): {
        "script": ROOT / "network-security" / "network-config-reviewer" / "main.py",
        "description": "Review firewall and network rules for risky exposure patterns.",
    },
    ("privacy", "pia-generator"): {
        "script": ROOT / "data-privacy" / "pia-generator" / "main.py",
        "description": "Generate a structured privacy impact assessment from project inputs.",
    },
}


def available_domains():
    return sorted({domain for domain, _ in REGISTRY})


def commands_for_domain(domain: str):
    return sorted(skill for registered_domain, skill in REGISTRY if registered_domain == domain)


def command_info(domain: str, skill: str):
    return REGISTRY.get((domain, skill))


def print_usage() -> None:
    print("Usage: okaudit <domain> <skill> [args...]")
    print("       okaudit list [domain]")
    print("       okaudit help <domain> <skill>")
    print("       okaudit version")
    print("")
    print("Examples:")
    print("  okaudit list")
    print("  okaudit list iam")
    print("  okaudit help iam access-review")
    print("  okaudit version")
    print("  okaudit iam access-review --input iam_policy.json")
    print("")
    print("Available domains:")
    for domain in available_domains():
        print(f"  - {domain}")


def handle_list(args) -> int:
    if not args:
        print("Available commands:")
        for domain in available_domains():
            skills = ", ".join(commands_for_domain(domain))
            print(f"  {domain}: {skills}")
        return 0

    domain = args[0]
    skills = commands_for_domain(domain)
    if not skills:
        print(f"Unknown domain: {domain}")
        print("")
        print("Available domains:")
        for item in available_domains():
            print(f"  - {item}")
        return 1

    print(f"Commands in {domain}:")
    for skill in skills:
        print(f"  - {skill}")
    return 0


def handle_help(args) -> int:
    if len(args) < 2:
        print("Usage: okaudit help <domain> <skill>")
        return 1

    domain = args[0]
    skill = args[1]
    info = command_info(domain, skill)
    if info is None:
        print(f"Unknown command: {domain} {skill}")
        print("")
        print("Use `okaudit list` to see available commands.")
        return 1

    print(f"{domain} {skill}")
    print(f"Description: {info['description']}")
    print("")
    print("To see the wrapped script's native flags, run:")
    print(f"  okaudit {domain} {skill} --help")
    return 0


def handle_version() -> int:
    print(f"okaudit {VERSION}")
    return 0


def main() -> int:
    if len(sys.argv) < 2:
        print_usage()
        return 1

    if sys.argv[1] == "list":
        return handle_list(sys.argv[2:])

    if sys.argv[1] == "help":
        return handle_help(sys.argv[2:])

    if sys.argv[1] == "version":
        return handle_version()

    if sys.argv[1] in {"-h", "--help"}:
        print_usage()
        return 0

    if len(sys.argv) < 3:
        print_usage()
        return 1

    domain = sys.argv[1]
    skill = sys.argv[2]
    extra_args = sys.argv[3:]

    info = command_info(domain, skill)
    if info is None:
        if domain not in available_domains():
            print(f"Unknown domain: {domain}")
            print("")
            print("Available domains:")
            for item in available_domains():
                print(f"  - {item}")
            return 1

        print(f"Unknown command in domain '{domain}': {skill}")
        print("")
        print(f"Available commands in {domain}:")
        for item in commands_for_domain(domain):
            print(f"  - {item}")
        print("")
        print("Use `okaudit list` to see available commands.")
        return 1

    script = info["script"]
    env = os.environ.copy()
    env.setdefault("PYTHONIOENCODING", "utf-8")
    result = subprocess.run([sys.executable, str(script), *extra_args], env=env)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
