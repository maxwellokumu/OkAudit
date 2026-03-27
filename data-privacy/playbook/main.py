"""Data Privacy Audit Playbook.

A structured, step-by-step guide for conducting a comprehensive data
privacy audit under GDPR, CCPA, or PDPA. Links to companion skills
for each step.
"""

import argparse
import sys
from datetime import datetime
from typing import Dict, List

from dotenv import load_dotenv

load_dotenv()

STEPS: Dict[int, Dict] = {
    1: {
        "title": "Data Discovery & Classification",
        "objective": (
            "Identify and catalogue all personal data held by the organisation across "
            "all systems, databases, cloud services, and third-party processors. "
            "Classify data by sensitivity and build or verify the Record of Processing "
            "Activities (ROPA)."
        ),
        "artefacts": [
            "Data inventory CSV (system, data_type, classification, location, transfers_to, legal_basis, retention)",
            "data-inventory-mapper Mermaid data flow diagram",
            "data-inventory-mapper markdown summary report",
            "Updated Record of Processing Activities (ROPA)",
            "Special Category data register",
        ],
        "tools_commands": [
            "# Run data-inventory-mapper to generate diagram and summary",
            "python data-privacy/data-inventory-mapper/main.py \\",
            "  --inventory data_inventory.csv",
            "",
            "# Mermaid diagram only",
            "python data-privacy/data-inventory-mapper/main.py \\",
            "  --inventory data_inventory.csv \\",
            "  --output mermaid",
            "",
            "# Search for PII in databases (example: PostgreSQL)",
            "psql -c \"SELECT table_name, column_name FROM information_schema.columns \\",
            "  WHERE column_name ILIKE '%email%' OR column_name ILIKE '%name%'\"",
            "",
            "# Scan for PII in S3 buckets (AWS Macie)",
            "aws macie2 create-classification-job \\",
            "  --job-type ONE_TIME \\",
            "  --s3-job-definition '{\"bucketDefinitions\": [{\"buckets\": [\"my-bucket\"]}]}'",
            "",
            "# Azure Purview data scan",
            "az purview account list --output table",
        ],
        "must_do_checks": [
            "All systems processing personal data are inventoried — no shadow-IT data stores missed",
            "Special Category data (health, biometric, criminal, etc.) is identified and flagged",
            "Each data type has a documented classification level",
            "All data transfers (internal and to third parties) are mapped",
            "Legal basis is documented for every processing activity",
            "Data flows to third countries are identified",
            "ROPA is up to date and signed off by DPO",
        ],
        "linked_skills": ["data-privacy/data-inventory-mapper"],
    },
    2: {
        "title": "Legal Basis & Consent Review",
        "objective": (
            "Verify that all privacy notices and consent mechanisms comply with "
            "applicable law (GDPR, CCPA, or PDPA). Identify missing disclosures, "
            "invalid consent collection, and gaps in data subject rights communication."
        ),
        "artefacts": [
            "Privacy policy / privacy notice (txt format for tool input)",
            "consent-checker compliance report",
            "Consent management platform (CMP) audit results",
            "Cookie banner compliance assessment",
            "List of missing requirements with risk ratings",
        ],
        "tools_commands": [
            "# Check privacy policy against GDPR",
            "python data-privacy/consent-checker/main.py \\",
            "  --policy privacy_policy.txt \\",
            "  --framework gdpr",
            "",
            "# Check against CCPA",
            "python data-privacy/consent-checker/main.py \\",
            "  --policy privacy_policy.txt \\",
            "  --framework ccpa",
            "",
            "# Check against PDPA (Thailand)",
            "python data-privacy/consent-checker/main.py \\",
            "  --policy privacy_policy.txt \\",
            "  --framework pdpa",
            "",
            "# Download live privacy policy as text",
            "curl -s https://example.com/privacy | \\",
            "  python3 -c \"import sys,html2text; print(html2text.html2text(sys.stdin.read()))\" \\",
            "  > live_policy.txt",
            "",
            "# Check for cookie consent (using puppeteer/playwright)",
            "npx playwright test cookie-consent.spec.js",
        ],
        "must_do_checks": [
            "Privacy notice achieves at least 85% weighted compliance score (Compliant rating)",
            "All GDPR Art. 13/14 mandatory disclosures are present in the privacy notice",
            "Consent is freely given, specific, informed, and unambiguous",
            "Consent withdrawal mechanism is as easy as giving consent (one-click unsubscribe)",
            "Cookie banner correctly categorises cookies and allows granular opt-out",
            "CCPA 'Do Not Sell My Personal Information' link is present where applicable",
            "Privacy notice is written in plain language and easily accessible",
            "Privacy notice version and date are clearly stated",
        ],
        "linked_skills": ["data-privacy/consent-checker"],
    },
    3: {
        "title": "Data Subject Rights Verification",
        "objective": (
            "Test and verify that all data subject rights mechanisms are functioning "
            "correctly — including access requests, deletion, rectification, portability, "
            "and objection. Verify response time compliance with statutory deadlines."
        ),
        "artefacts": [
            "Data subject rights process documentation",
            "SAR (Subject Access Request) test log",
            "Deletion request test results",
            "Response time compliance tracker",
            "Rights fulfilment procedure document",
        ],
        "tools_commands": [
            "# Test SAR submission form (automated)",
            "curl -X POST https://example.com/sar-request \\",
            "  -H 'Content-Type: application/json' \\",
            "  -d '{\"name\": \"Test Subject\", \"email\": \"test@example.com\", \"request_type\": \"access\"}'",
            "",
            "# Check SAR ticketing system for open requests",
            "# (replace with your ticketing system API)",
            "curl -H 'Authorization: Bearer $TOKEN' \\",
            "  https://helpdesk.example.com/api/tickets?type=SAR&status=open",
            "",
            "# Verify deletion confirmation email (manual test)",
            "# Submit deletion request and verify:",
            "# 1. Acknowledgement within 3 days",
            "# 2. Completion within 30 days (GDPR) / 45 days (CCPA)",
            "# 3. Confirmation email sent",
            "",
            "# Check if user data is fully purged",
            "# (replace with your database/API)",
            "psql -c \"SELECT * FROM users WHERE email = 'test@example.com'\"",
        ],
        "must_do_checks": [
            "SAR submissions are acknowledged within 3 working days",
            "SAR responses are fulfilled within 30 days (GDPR) or 45 days (CCPA)",
            "Deletion requests result in verifiable removal of all personal data including backups",
            "Portability requests deliver data in a structured, machine-readable format (JSON/CSV)",
            "Objection to direct marketing results in immediate cessation of marketing",
            "Rights requests can be submitted via at least two channels (web form + email/phone)",
            "Identity verification process is proportionate and does not create barriers",
            "All rights requests are logged in a register with timestamps",
        ],
        "linked_skills": [],
    },
    4: {
        "title": "PIA / DPIA Execution",
        "objective": (
            "Conduct Privacy Impact Assessments (PIAs) for all high-risk processing "
            "activities. Mandatory DPIAs must be completed before commencing any "
            "processing that is likely to result in high risk to individuals under "
            "GDPR Article 35."
        ),
        "artefacts": [
            "PIA/DPIA reports for all in-scope projects (generated by pia-generator)",
            "DPIA threshold assessment checklist",
            "DPO approval sign-offs",
            "Risk register updates",
        ],
        "tools_commands": [
            "# Generate a PIA for a high-risk project",
            "python data-privacy/pia-generator/main.py \\",
            "  --project 'Employee Monitoring System' \\",
            "  --data-types 'behavioral,location,biometric' \\",
            "  --purposes 'productivity monitoring,security,attendance' \\",
            "  --recipients 'HR department,IT Security,Line Managers' \\",
            "  --retention '2 years' \\",
            "  --controller 'Acme Solutions Ltd' \\",
            "  --dpo 'dpo@acmesolutions.com'",
            "",
            "# Save to file",
            "python data-privacy/pia-generator/main.py \\",
            "  --project 'Customer Analytics' \\",
            "  --data-types 'behavioral,contact,location' \\",
            "  --purposes 'analytics,profiling' \\",
            "  --recipients 'Analytics team,Google Analytics' \\",
            "  --retention '18 months' \\",
            "  > reports/pia_customer_analytics.md",
            "",
            "# ISO 27701 assessment",
            "python data-privacy/pia-generator/main.py \\",
            "  --project 'HR Data Platform' \\",
            "  --data-types 'employee_records,health,financial' \\",
            "  --purposes 'payroll,occupational health,legal compliance' \\",
            "  --recipients 'Payroll Provider,HMRC,Pension Provider' \\",
            "  --retention '7 years' \\",
            "  --framework iso27701",
        ],
        "must_do_checks": [
            "DPIA threshold assessment completed — all processing meeting GDPR Art. 35 triggers has a DPIA",
            "DPIA mandatory for: large-scale Special Category data, systematic monitoring, automated decision-making",
            "All PIAs reviewed and approved by DPO before processing commences",
            "PIAs stored in the ROPA alongside their corresponding processing activities",
            "High/Critical risks have documented mitigation plans with owners and target dates",
            "PIAs are reviewed annually or upon any significant change to the processing",
            "Where residual risk remains Very High after mitigation, ICO/supervisory authority is consulted",
        ],
        "linked_skills": ["data-privacy/pia-generator"],
    },
    5: {
        "title": "Reporting & Remediation",
        "objective": (
            "Consolidate all data privacy audit findings into a structured report. "
            "Prioritise gaps, assign remediation owners, and track progress against "
            "a remediation roadmap. Report outcomes to DPO and senior management."
        ),
        "artefacts": [
            "Data Privacy Audit Report (executive summary + technical findings)",
            "Remediation action plan with owners and target dates",
            "Updated ROPA",
            "Board/management presentation",
            "Evidence pack for regulatory submissions if required",
        ],
        "tools_commands": [
            "# Aggregate all reports",
            "python data-privacy/data-inventory-mapper/main.py \\",
            "  --inventory data_inventory.csv > reports/data_inventory.md",
            "",
            "python data-privacy/consent-checker/main.py \\",
            "  --policy privacy_policy.txt > reports/consent_check.md",
            "",
            "python data-privacy/pia-generator/main.py \\",
            "  --project 'Full Audit' \\",
            "  --data-types 'health,financial,contact,behavioral' \\",
            "  --purposes 'service delivery,analytics,marketing' \\",
            "  --recipients 'Internal teams,Third parties' \\",
            "  --retention 'Various' > reports/pia_summary.md",
            "",
            "# Combine reports",
            "cat reports/*.md > reports/data_privacy_audit_full.md",
            "",
            "# Convert to PDF (requires pandoc)",
            "pandoc reports/data_privacy_audit_full.md \\",
            "  -o reports/data_privacy_audit_full.pdf",
        ],
        "must_do_checks": [
            "All findings have a risk rating (Critical/High/Medium/Low) and an assigned owner",
            "Remediation deadlines are set: Critical ≤ 30 days, High ≤ 90 days, Medium ≤ 180 days",
            "Executive summary covers: scope, key risks, compliance score, and top 3 actions",
            "ROPA is updated with any new systems or processing activities found during audit",
            "DPO has reviewed and signed off the full report",
            "Any identified breaches or near-misses are escalated through the incident response process",
            "Retesting date is scheduled for all Critical and High findings",
            "Findings are mapped to relevant regulatory requirements (GDPR articles, CCPA sections, etc.)",
        ],
        "linked_skills": [
            "data-privacy/data-inventory-mapper",
            "data-privacy/consent-checker",
            "data-privacy/pia-generator",
        ],
    },
}


def render_step(step_num: int, step: Dict) -> str:
    """Render a single playbook step as markdown.

    Args:
        step_num: The step number (1-5).
        step: Step definition dictionary.

    Returns:
        Markdown string for this step.
    """
    lines = [
        f"## Step {step_num}: {step['title']}",
        "",
        f"**Objective:** {step['objective']}",
        "",
        "### Artefacts",
        "",
    ]
    for a in step["artefacts"]:
        lines.append(f"- {a}")
    lines.append("")

    lines += ["### Tools & Commands", "", "```bash"]
    lines.extend(step["tools_commands"])
    lines += ["```", ""]

    lines += ["### Must-Do Checks", ""]
    for i, check in enumerate(step["must_do_checks"], 1):
        lines.append(f"{i}. {check}")
    lines.append("")

    if step["linked_skills"]:
        lines += ["### Linked Skills", ""]
        for skill in step["linked_skills"]:
            lines.append(f"- `{skill}`")
        lines.append("")

    return "\n".join(lines)


def main() -> None:
    """Entry point for the data privacy audit playbook."""
    parser = argparse.ArgumentParser(
        description="Data Privacy Audit Playbook — step-by-step guidance."
    )
    parser.add_argument(
        "--step",
        default="full",
        help="Step number (1-5) or 'full' for all steps (default: full).",
    )
    args = parser.parse_args()

    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    header = [
        "# Data Privacy Audit Playbook",
        "",
        f"**Generated:** {now}",
        "",
        "A comprehensive, step-by-step guide for conducting a data privacy audit "
        "under GDPR, CCPA, or PDPA. Run specific steps with `--step N` or output "
        "all steps with `--step full`.",
        "",
    ]

    if args.step.lower() == "full":
        steps_to_render = list(STEPS.keys())
    else:
        try:
            step_num = int(args.step)
        except ValueError:
            print(f"Error: --step must be an integer 1-5 or 'full', got '{args.step}'.", file=sys.stderr)
            sys.exit(1)
        if step_num not in STEPS:
            print(f"Error: Step {step_num} does not exist. Valid steps: 1-5.", file=sys.stderr)
            sys.exit(1)
        steps_to_render = [step_num]

    toc = ["## Table of Contents", ""]
    for n in STEPS:
        toc.append(f"{n}. {STEPS[n]['title']}")
    toc.append("")

    body = [render_step(n, STEPS[n]) for n in steps_to_render]
    print("\n".join(header + toc + body))


if __name__ == "__main__":
    main()
