"""SOD Analyzer — detect segregation of duties conflicts in user role assignments.

Checks user-to-role mappings against a library of known conflicting role pairs.
Supports a built-in conflict library of 20 common SOD violations and custom
conflict definitions supplied via JSON.
"""

import argparse
import json
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Built-in conflict library
# ---------------------------------------------------------------------------

BUILTIN_CONFLICTS: List[Dict] = [
    {"role_a": "create_user", "role_b": "delete_user",
     "risk": "Critical", "category": "Identity Management",
     "rationale": "Creating and deleting users allows covering tracks by removing accounts."},
    {"role_a": "approve_payment", "role_b": "initiate_payment",
     "risk": "Critical", "category": "Financial Controls",
     "rationale": "Initiating and approving payments enables fraud without a second control."},
    {"role_a": "deploy_code", "role_b": "approve_deployment",
     "risk": "Critical", "category": "Change Management",
     "rationale": "Self-approving deployments bypasses change control and peer review."},
    {"role_a": "read_audit_logs", "role_b": "delete_audit_logs",
     "risk": "Critical", "category": "Audit Integrity",
     "rationale": "Ability to delete logs an auditor can read undermines audit trail integrity."},
    {"role_a": "create_invoice", "role_b": "approve_invoice",
     "risk": "Critical", "category": "Financial Controls",
     "rationale": "Creating and approving invoices enables fraudulent payments."},
    {"role_a": "create_vendor", "role_b": "approve_vendor",
     "risk": "Critical", "category": "Procurement",
     "rationale": "Self-approving vendor creation allows ghost vendor fraud."},
    {"role_a": "accounts_payable", "role_b": "accounts_receivable",
     "risk": "High", "category": "Financial Controls",
     "rationale": "Managing both payable and receivable functions removes segregation across cash handling."},
    {"role_a": "create_vendor", "role_b": "approve_payment",
     "risk": "High", "category": "Procurement",
     "rationale": "Creating vendors and approving payments enables fraudulent vendor setup and disbursement."},
    {"role_a": "manage_secrets", "role_b": "audit_secrets",
     "risk": "High", "category": "Security Operations",
     "rationale": "Managing and auditing secrets removes the independence of the review."},
    {"role_a": "grant_access", "role_b": "review_access",
     "risk": "High", "category": "Access Governance",
     "rationale": "Granting and reviewing access removes independent oversight of provisioning."},
    {"role_a": "configure_firewall", "role_b": "audit_network",
     "risk": "High", "category": "Network Security",
     "rationale": "Auditing network changes one can make removes independent verification."},
    {"role_a": "manage_backups", "role_b": "restore_backups",
     "risk": "High", "category": "Business Continuity",
     "rationale": "Controlling both backup management and restores creates single point of failure."},
    {"role_a": "write_policy", "role_b": "approve_policy",
     "risk": "High", "category": "Governance",
     "rationale": "Writing and approving policies removes peer review and independence."},
    {"role_a": "create_purchase_order", "role_b": "receive_goods",
     "risk": "High", "category": "Procurement",
     "rationale": "Creating POs and receiving goods enables fictitious purchase schemes."},
    {"role_a": "manage_encryption_keys", "role_b": "access_encrypted_data",
     "risk": "High", "category": "Data Security",
     "rationale": "Key management and data access together enable undetected decryption."},
    {"role_a": "create_account", "role_b": "reconcile_accounts",
     "risk": "High", "category": "Financial Controls",
     "rationale": "Creating and reconciling accounts hides fraudulent transactions."},
    {"role_a": "system_admin", "role_b": "security_auditor",
     "risk": "Medium", "category": "Audit Independence",
     "rationale": "Administering systems and auditing them removes objectivity."},
    {"role_a": "developer", "role_b": "production_deployer",
     "risk": "Medium", "category": "Change Management",
     "rationale": "Developers deploying their own code to production bypasses change control."},
    {"role_a": "manage_hr_records", "role_b": "approve_payroll",
     "risk": "Medium", "category": "HR/Payroll",
     "rationale": "Managing HR records and approving payroll enables ghost employee fraud."},
    {"role_a": "issue_credit", "role_b": "approve_credit",
     "risk": "Medium", "category": "Financial Controls",
     "rationale": "Self-approving credit issuance enables unauthorised credit grants."},
    {"role_a": "configure_monitoring", "role_b": "review_alerts",
     "risk": "Medium", "category": "Security Operations",
     "rationale": "Configuring and reviewing own monitoring removes detection independence."},
    {"role_a": "data_entry", "role_b": "data_approval",
     "risk": "Medium", "category": "Data Integrity",
     "rationale": "Entering and approving the same data removes the four-eyes principle."},
]


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Detect segregation of duties conflicts in user role assignments."
    )
    parser.add_argument(
        "--users",
        required=True,
        help='Path to JSON file: {"username": ["role1", "role2"]}',
    )
    parser.add_argument(
        "--conflicts",
        help="Path to JSON file with custom conflict pairs: [[role_a, role_b], ...]",
    )
    parser.add_argument(
        "--builtin-conflicts",
        action="store_true",
        help="Include the built-in library of 20 common SOD conflicts",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------


def normalise_role(role: Any) -> str:
    """Normalise role names so equivalent forms compare consistently."""
    value = str(role).strip().lower()
    return value.replace("-", "_").replace(" ", "_")


def load_users(path: str) -> Dict[str, List[str]]:
    """Load user-to-roles mapping from JSON file.

    Args:
        path: Path to JSON file.

    Returns:
        Dict mapping username to list of role strings.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        print(f"ERROR: Users file not found: '{path}'", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as exc:
        print(f"ERROR: Invalid JSON in users file - {exc}", file=sys.stderr)
        sys.exit(1)

    if not isinstance(data, dict):
        print("ERROR: Users file must be a JSON object mapping usernames to role lists.", file=sys.stderr)
        sys.exit(1)

    if "users" in data:
        users = data.get("users")
        if not isinstance(users, list):
            print("ERROR: 'users' must be a list of user objects.", file=sys.stderr)
            sys.exit(1)

        normalised: Dict[str, List[str]] = {}
        for entry in users:
            if not isinstance(entry, dict):
                print("ERROR: Each user entry must be an object.", file=sys.stderr)
                sys.exit(1)
            username = str(entry.get("username", "")).strip()
            roles = entry.get("roles", [])
            if not username or not isinstance(roles, list):
                print("ERROR: Each user entry must include username and roles list.", file=sys.stderr)
                sys.exit(1)
            normalised[username] = [normalise_role(role) for role in roles]
        return normalised

    return {str(k): [normalise_role(role) for role in v] for k, v in data.items()}


def load_custom_conflicts(path: str) -> List[Dict]:
    """Load custom conflict pairs from JSON file.

    Args:
        path: Path to JSON file with [[role_a, role_b], ...] or [{role_a, role_b, risk}, ...].

    Returns:
        List of conflict dicts.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        print(f"ERROR: Conflicts file not found: '{path}'", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as exc:
        print(f"ERROR: Invalid JSON in conflicts file — {exc}", file=sys.stderr)
        sys.exit(1)

    conflicts: List[Dict] = []
    for item in data:
        if isinstance(item, list) and len(item) >= 2:
            conflicts.append({
                "role_a": item[0].lower(),
                "role_b": item[1].lower(),
                "risk": item[2] if len(item) > 2 else "Medium",
                "category": "Custom",
                "rationale": item[3] if len(item) > 3 else "Custom conflict rule.",
            })
        elif isinstance(item, dict):
            conflicts.append({
                "role_a": item.get("role_a", "").lower(),
                "role_b": item.get("role_b", "").lower(),
                "risk": item.get("risk", "Medium"),
                "category": item.get("category", "Custom"),
                "rationale": item.get("rationale", "Custom conflict rule."),
            })
    return conflicts


# ---------------------------------------------------------------------------
# Conflict detection
# ---------------------------------------------------------------------------


def detect_conflicts(
    users: Dict[str, List[str]],
    conflict_rules: List[Dict],
) -> Tuple[List[Dict], List[str]]:
    """Find SOD conflicts for each user.

    Args:
        users: Username to roles mapping.
        conflict_rules: List of conflict rule dicts.

    Returns:
        Tuple of (list of conflict findings, list of clean usernames).
    """
    findings: List[Dict] = []
    clean_users: List[str] = []

    for username, roles in users.items():
        role_set = set(r.lower() for r in roles)
        user_conflicts: List[Dict] = []

        for rule in conflict_rules:
            ra = rule["role_a"].lower()
            rb = rule["role_b"].lower()
            if ra in role_set and rb in role_set:
                user_conflicts.append({
                    "user": username,
                    "role_a": rule["role_a"],
                    "role_b": rule["role_b"],
                    "risk": rule.get("risk", "Medium"),
                    "category": rule.get("category", ""),
                    "rationale": rule.get("rationale", ""),
                    "remediation": (
                        f"Remove '{rule['role_b']}' from {username} or assign "
                        f"'{rule['role_a']}' to a separate individual. "
                        "Implement compensating controls if separation is not feasible."
                    ),
                })

        if user_conflicts:
            findings.extend(user_conflicts)
        else:
            clean_users.append(username)

    return findings, clean_users


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

RISK_EMOJI = {"Critical": "🚨", "High": "🔴", "Medium": "🟠", "Low": "🟡"}
RISK_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def render_report(
    users: Dict[str, List[str]],
    findings: List[Dict],
    clean_users: List[str],
    builtin_used: bool,
    custom_count: int,
) -> str:
    """Render the markdown SOD conflict report.

    Args:
        users: All users reviewed.
        findings: Conflict findings.
        clean_users: Users with no conflicts.
        builtin_used: Whether built-in conflicts were loaded.
        custom_count: Number of custom conflict rules loaded.

    Returns:
        Markdown report string.
    """
    date_str = datetime.now().strftime("%Y-%m-%d")
    conflicted_users = list({f["user"] for f in findings})

    lines: List[str] = []
    lines.append("# Segregation of Duties Analysis Report\n")
    lines.append(f"**Date:** {date_str}  ")
    lines.append(f"**Built-in Conflicts Used:** {'Yes' if builtin_used else 'No'}  ")
    lines.append(f"**Custom Conflict Rules:** {custom_count}\n")
    lines.append("---\n")

    # Summary
    lines.append("## Summary\n")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Users Reviewed | {len(users)} |")
    lines.append(f"| Users with Conflicts | {len(conflicted_users)} |")
    lines.append(f"| Users Clean | {len(clean_users)} |")
    lines.append(f"| Total Conflicts Found | {len(findings)} |")
    lines.append("")

    if not findings:
        lines.append(
            "> ✅ No SOD conflicts detected. All users have appropriately separated roles.\n"
        )
        return "\n".join(lines)

    # Conflicts table
    lines.append("---\n")
    lines.append("## Conflicts Detected\n")
    lines.append("| User | Role A | Role B | Category | Risk | Rationale | Remediation |")
    lines.append("|------|--------|--------|----------|------|-----------|-------------|")

    sorted_findings = sorted(findings, key=lambda x: RISK_ORDER.get(x.get("risk", "Low"), 3))
    for f in sorted_findings:
        risk = f.get("risk", "Medium")
        emoji = RISK_EMOJI.get(risk, "")
        user = f["user"]
        ra = f["role_a"]
        rb = f["role_b"]
        cat = f.get("category", "")
        rationale = f.get("rationale", "").replace("|", "\\|")
        remediation = f.get("remediation", "").replace("|", "\\|")
        lines.append(f"| `{user}` | `{ra}` | `{rb}` | {cat} | {emoji} {risk} | {rationale} | {remediation} |")

    lines.append("")
    lines.append("---\n")

    # Clean users
    lines.append("## ✅ Users with No Conflicts\n")
    if clean_users:
        for u in sorted(clean_users):
            roles = users.get(u, [])
            lines.append(f"- `{u}` — roles: {', '.join(roles)}")
    else:
        lines.append("_All users have at least one conflict._")

    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Main entry point."""
    args = parse_args()

    if not args.conflicts and not args.builtin_conflicts:
        print(
            "ERROR: Provide at least one of --conflicts or --builtin-conflicts.",
            file=sys.stderr,
        )
        sys.exit(1)

    users = load_users(args.users)
    if not users:
        print("ERROR: No users found in the users file.", file=sys.stderr)
        sys.exit(1)

    conflict_rules: List[Dict] = []
    custom_count = 0

    if args.builtin_conflicts:
        conflict_rules.extend(BUILTIN_CONFLICTS)

    if args.conflicts:
        custom = load_custom_conflicts(args.conflicts)
        conflict_rules.extend(custom)
        custom_count = len(custom)

    findings, clean_users = detect_conflicts(users, conflict_rules)
    print(render_report(users, findings, clean_users, args.builtin_conflicts, custom_count))


if __name__ == "__main__":
    main()
