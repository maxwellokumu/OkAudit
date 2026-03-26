"""Contract Compliance Checker — verify contracts contain required clauses.

Checks a plain-text contract against a built-in library of required clauses
for vendor, SaaS, and data-processor contract types. Uses keyword and synonym
matching to identify present and missing clauses.
"""

import argparse
import json
import re
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Built-in clause library
# ---------------------------------------------------------------------------

CLAUSE_LIBRARY: Dict[str, List[Dict[str, Any]]] = {
    "vendor": [
        {"name": "Data Breach Notification", "keywords": ["data breach", "breach notification", "security incident notification"], "synonyms": ["security breach", "cyber incident", "data incident"], "risk_if_missing": "No contractual obligation to notify of breaches; regulatory penalties may follow."},
        {"name": "Right to Audit", "keywords": ["right to audit", "audit rights", "audit clause"], "synonyms": ["inspection rights", "right of inspection", "audit access"], "risk_if_missing": "Cannot independently verify vendor compliance or security controls."},
        {"name": "Liability Cap", "keywords": ["liability cap", "limitation of liability", "liability limit"], "synonyms": ["maximum liability", "liability ceiling", "damages cap"], "risk_if_missing": "Unlimited vendor liability exposure; difficulty recovering losses."},
        {"name": "IP Ownership", "keywords": ["intellectual property", "ip ownership", "ownership of data"], "synonyms": ["proprietary rights", "data ownership", "work product ownership"], "risk_if_missing": "Unclear ownership of data and deliverables; potential IP disputes."},
        {"name": "Confidentiality", "keywords": ["confidentiality", "non-disclosure", "confidential information"], "synonyms": ["nda", "trade secrets", "proprietary information"], "risk_if_missing": "No legal protection against vendor disclosing sensitive information."},
        {"name": "Termination Rights", "keywords": ["termination", "right to terminate", "termination for cause"], "synonyms": ["contract termination", "end of agreement", "exit clause"], "risk_if_missing": "Limited ability to exit contract if vendor fails to perform or breaches security."},
        {"name": "Service Level Agreement", "keywords": ["service level", "sla", "uptime", "availability guarantee"], "synonyms": ["performance standard", "service commitment", "availability target"], "risk_if_missing": "No enforceable performance standards; no remedies for poor service."},
        {"name": "Indemnification", "keywords": ["indemnif", "hold harmless", "indemnity"], "synonyms": ["indemnification clause", "defend and indemnify"], "risk_if_missing": "No protection against third-party claims arising from vendor actions."},
        {"name": "Governing Law", "keywords": ["governing law", "jurisdiction", "applicable law"], "synonyms": ["choice of law", "legal jurisdiction", "dispute resolution"], "risk_if_missing": "Uncertain legal jurisdiction for disputes; costly cross-border litigation."},
        {"name": "Force Majeure", "keywords": ["force majeure", "act of god", "unforeseeable circumstances"], "synonyms": ["extraordinary events", "circumstances beyond control"], "risk_if_missing": "No clarity on obligations during natural disasters or unexpected events."},
        {"name": "Subcontractor Approval", "keywords": ["subcontract", "sub-contractor", "third party provider"], "synonyms": ["outsourcing approval", "subprocessor", "delegate"], "risk_if_missing": "Vendor may subcontract to unapproved parties without oversight."},
        {"name": "Insurance Requirements", "keywords": ["insurance", "cyber insurance", "professional indemnity"], "synonyms": ["liability insurance", "coverage requirements", "insurance certificate"], "risk_if_missing": "No guarantee vendor can cover losses from security incidents or negligence."},
    ],
    "saas": [
        {"name": "Uptime SLA", "keywords": ["uptime", "availability sla", "service availability"], "synonyms": ["availability guarantee", "uptime commitment", "system availability"], "risk_if_missing": "No enforceable uptime guarantees; no remedies for outages."},
        {"name": "Data Portability", "keywords": ["data portability", "data export", "export your data"], "synonyms": ["data migration", "data extraction", "take your data"], "risk_if_missing": "Risk of vendor lock-in; inability to migrate data on contract termination."},
        {"name": "Data Deletion on Termination", "keywords": ["data deletion", "delete data", "destroy data on termination"], "synonyms": ["data erasure", "data removal", "purge data"], "risk_if_missing": "Vendor may retain your data indefinitely after contract ends."},
        {"name": "Security Standards Certification", "keywords": ["soc 2", "iso 27001", "pci dss", "security certification"], "synonyms": ["security audit", "third party security", "independent security assessment"], "risk_if_missing": "No independent verification of vendor security controls."},
        {"name": "Incident Notification", "keywords": ["incident notification", "notify customer", "security incident"], "synonyms": ["breach notification", "alert customer", "incident reporting"], "risk_if_missing": "May not be notified of incidents affecting your data in a timely manner."},
        {"name": "Support SLA", "keywords": ["support sla", "response time", "support response"], "synonyms": ["technical support", "help desk sla", "customer support commitment"], "risk_if_missing": "No guaranteed response times for critical issues affecting business operations."},
        {"name": "Data Residency", "keywords": ["data residency", "data location", "data stored in"], "synonyms": ["data sovereignty", "geographic restriction", "storage location"], "risk_if_missing": "Data may be stored in jurisdictions with inadequate privacy protections."},
        {"name": "API Rate Limits", "keywords": ["api rate limit", "rate limiting", "api throttling"], "synonyms": ["api quota", "request limit", "throughput limit"], "risk_if_missing": "Unexpected API throttling could disrupt integrated business processes."},
        {"name": "Price Change Notice", "keywords": ["price change", "pricing notice", "fee increase"], "synonyms": ["rate change", "cost adjustment notice", "billing change"], "risk_if_missing": "Vendor may increase prices without adequate notice for budget planning."},
        {"name": "Service Credits", "keywords": ["service credit", "sla credit", "credit for downtime"], "synonyms": ["uptime credit", "compensation for outage", "refund for downtime"], "risk_if_missing": "No financial remedy when vendor fails to meet availability commitments."},
    ],
    "data-processor": [
        {"name": "GDPR Article 28 Compliance", "keywords": ["article 28", "gdpr", "data processing agreement"], "synonyms": ["dpa", "data processor agreement", "gdpr compliant"], "risk_if_missing": "Non-compliant data processing arrangement; significant GDPR enforcement risk."},
        {"name": "DPA Agreement", "keywords": ["data processing agreement", "dpa", "processing agreement"], "synonyms": ["data processor contract", "article 28 agreement"], "risk_if_missing": "Required DPA not in place; processing is unlawful under GDPR Article 28."},
        {"name": "Data Subject Rights Support", "keywords": ["data subject rights", "right of access", "right to erasure"], "synonyms": ["dsar support", "data subject request", "right to be forgotten"], "risk_if_missing": "Unable to fulfil data subject requests; regulatory fines and reputational damage."},
        {"name": "Sub-processor Restrictions", "keywords": ["sub-processor", "subprocessor", "further processing"], "synonyms": ["downstream processor", "sub-contractor data", "third party processing"], "risk_if_missing": "Processor may engage sub-processors without consent, creating compliance gaps."},
        {"name": "International Transfer Safeguards", "keywords": ["international transfer", "cross-border transfer", "standard contractual clauses"], "synonyms": ["adequacy decision", "sccs", "transfer mechanism", "binding corporate rules"], "risk_if_missing": "Unlawful transfer of personal data to third countries without adequate safeguards."},
        {"name": "Audit Rights", "keywords": ["audit rights", "right to audit", "inspection"], "synonyms": ["audit access", "processor audit", "security audit right"], "risk_if_missing": "Cannot verify processor compliance with GDPR obligations."},
        {"name": "Breach Notification 72hr", "keywords": ["72 hour", "72-hour", "breach notification"], "synonyms": ["notify within 72", "breach reporting", "incident notification deadline"], "risk_if_missing": "Processor may not notify within GDPR's 72-hour requirement; regulatory penalties."},
        {"name": "Data Deletion Obligations", "keywords": ["delete personal data", "return or delete", "erasure obligation"], "synonyms": ["destroy personal data", "data return", "end of processing deletion"], "risk_if_missing": "Processor may retain personal data beyond authorised processing period."},
        {"name": "Processing Instructions", "keywords": ["processing instructions", "act on instructions", "documented instructions"], "synonyms": ["controller instructions", "written instructions", "process only as instructed"], "risk_if_missing": "Processor may process data beyond authorised purposes."},
        {"name": "Technical and Organisational Measures", "keywords": ["technical measures", "organisational measures", "appropriate security"], "synonyms": ["security measures", "toms", "appropriate technical measures", "article 32"], "risk_if_missing": "No documented security obligations on the processor; inadequate data protection."},
    ],
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Check a contract document for required clauses."
    )
    parser.add_argument("--contract", required=True, help="Path to contract text file (.txt)")
    parser.add_argument("--requirements", help="Path to JSON list of custom required clauses")
    parser.add_argument(
        "--standard",
        choices=["vendor", "saas", "data-processor"],
        help="Load built-in clause set for this contract type",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Clause matching
# ---------------------------------------------------------------------------


def load_contract(path: str) -> str:
    """Load contract text from file.

    Args:
        path: Path to contract text file.

    Returns:
        Lowercased contract text string.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read().lower()
    except FileNotFoundError:
        print(f"ERROR: Contract file not found: '{path}'", file=sys.stderr)
        sys.exit(1)


def load_custom_clauses(path: str) -> List[Dict[str, Any]]:
    """Load custom clause definitions from JSON.

    Args:
        path: Path to JSON file.

    Returns:
        List of clause dicts.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        print(f"ERROR: Requirements file not found: '{path}'", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as exc:
        print(f"ERROR: Invalid JSON in requirements file — {exc}", file=sys.stderr)
        sys.exit(1)

    clauses: List[Dict[str, Any]] = []
    for item in data:
        if isinstance(item, str):
            clauses.append({
                "name": item,
                "keywords": [item.lower()],
                "synonyms": [],
                "risk_if_missing": "Custom requirement — assess risk manually.",
            })
        elif isinstance(item, dict):
            clauses.append({
                "name": item.get("name", "Unknown"),
                "keywords": item.get("keywords", [item.get("name", "").lower()]),
                "synonyms": item.get("synonyms", []),
                "risk_if_missing": item.get("risk_if_missing", "Custom requirement."),
            })
    return clauses


def check_clause(clause: Dict[str, Any], contract_text: str) -> Tuple[bool, str]:
    """Check if a clause is present in the contract text.

    Args:
        clause: Clause definition dict.
        contract_text: Lowercased contract text.

    Returns:
        Tuple of (found: bool, matched_snippet: str).
    """
    all_terms = clause.get("keywords", []) + clause.get("synonyms", [])
    for term in all_terms:
        pattern = re.escape(term.lower())
        match = re.search(pattern, contract_text)
        if match:
            start = max(0, match.start() - 20)
            end = min(len(contract_text), match.end() + 60)
            raw_snippet = contract_text[start:end].replace("\n", " ").strip()
            # Trim to under 15 words
            words = raw_snippet.split()
            snippet = " ".join(words[:12]) + ("..." if len(words) > 12 else "")
            return True, snippet
    return False, ""


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


def render_report(
    contract_path: str,
    standard: Optional[str],
    clauses: List[Dict],
    found: List[Dict],
    missing: List[Dict],
) -> str:
    """Render the contract compliance markdown report.

    Args:
        contract_path: Path to the contract file.
        standard: Contract type standard used.
        clauses: All clauses checked.
        found: Found clause results.
        missing: Missing clause results.

    Returns:
        Markdown string.
    """
    date_str = datetime.now().strftime("%Y-%m-%d")
    total = len(clauses)
    found_count = len(found)
    pct = round(found_count / total * 100, 1) if total > 0 else 0

    if pct >= 80:
        rating = "🟢 Low Risk"
    elif pct >= 60:
        rating = "🟡 Medium Risk"
    elif pct >= 40:
        rating = "🟠 High Risk"
    else:
        rating = "🔴 Critical Risk"

    lines: List[str] = []
    lines.append("# Contract Compliance Report\n")
    lines.append(f"**Date:** {date_str}  ")
    lines.append(f"**Contract:** `{contract_path}`  ")
    if standard:
        lines.append(f"**Standard:** {standard}  ")
    lines.append(f"**Clauses Checked:** {total}  ")
    lines.append(f"**Compliance Score:** {pct}% ({found_count}/{total})  ")
    lines.append(f"**Risk Rating:** {rating}\n")
    lines.append("---\n")

    lines.append("## ✅ Found Clauses\n")
    if found:
        lines.append("| Clause | Matched On | Status |")
        lines.append("|--------|------------|--------|")
        for f in found:
            snippet = f["snippet"].replace("|", "\\|")
            lines.append(f"| {f['name']} | *\"{snippet}\"* | ✅ Present |")
    else:
        lines.append("_No required clauses found._")
    lines.append("")

    lines.append("---\n")
    lines.append("## ❌ Missing Clauses\n")
    if missing:
        lines.append("| Clause | Risk if Missing | Recommendation |")
        lines.append("|--------|----------------|----------------|")
        for m in missing:
            risk = m["risk_if_missing"].replace("|", "\\|")
            lines.append(
                f"| **{m['name']}** | {risk} | "
                f"Add a {m['name']} clause before signing. |"
            )
    else:
        lines.append("_All required clauses are present._")
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Main entry point."""
    args = parse_args()

    if not args.standard and not args.requirements:
        print(
            "ERROR: Specify at least one of --standard or --requirements.",
            file=sys.stderr,
        )
        sys.exit(1)

    contract_text = load_contract(args.contract)

    clauses: List[Dict[str, Any]] = []
    if args.standard:
        clauses.extend(CLAUSE_LIBRARY[args.standard])
    if args.requirements:
        clauses.extend(load_custom_clauses(args.requirements))

    found: List[Dict] = []
    missing: List[Dict] = []

    for clause in clauses:
        present, snippet = check_clause(clause, contract_text)
        if present:
            found.append({"name": clause["name"], "snippet": snippet})
        else:
            missing.append(clause)

    print(render_report(args.contract, args.standard, clauses, found, missing))


if __name__ == "__main__":
    main()
