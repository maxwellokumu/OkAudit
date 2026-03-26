"""Lead IT Auditor Playbook — step-by-step guidance from engagement planning to closeout.

Prints one or all steps of the lead IT auditor playbook. Each step contains a
structured data entry with objective, expected artefacts, tool commands, critical
must-do checks, and links to related skills.
"""

import argparse
import sys
from typing import Any, Dict, List, Union

from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Playbook data structure
# ---------------------------------------------------------------------------

PLAYBOOK_STEPS: List[Dict[str, Any]] = [
    {
        "number": 1,
        "title": "Engagement Planning",
        "objective": (
            "Establish the formal basis for the audit engagement. Agree on objectives, "
            "confirm independence, allocate resources, and produce a signed planning memo "
            "before any fieldwork begins."
        ),
        "artefacts": [
            "engagement_planning_memo.docx — scope, objectives, criteria, resource plan",
            "audit_charter.pdf — signed authority document granting audit access",
            "independence_declaration.pdf — auditor independence and conflict-of-interest forms",
            "preliminary_risk_assessment.xlsx — high-level risk ranking of audit areas",
            "contact_list.xlsx — auditee stakeholders, IT owners, and escalation contacts",
        ],
        "tools_commands": [
            "# Generate the full audit program for the target system",
            "python lead-it-auditor/audit-scope-checklist/main.py --system \"<SYSTEM_NAME>\" --output-dir ./output",
            "",
            "# Limit scope to specific roles",
            "python lead-it-auditor/audit-scope-checklist/main.py \\",
            "  --system \"<SYSTEM_NAME>\" \\",
            "  --roles \"identity-access,compliance-controls,log-monitoring\" \\",
            "  --frameworks \"ISO 27001,SOC 2\" \\",
            "  --output-dir ./output",
        ],
        "must_do_checks": [
            "Obtain written sign-off on audit scope from auditee management before proceeding.",
            "Confirm all auditors have completed independence declarations and no conflicts exist.",
            "Verify the audit charter grants unrestricted access to systems, data, and personnel.",
            "Agree on a fieldwork start date and evidence submission deadline with the auditee.",
            "Ensure the planning memo is reviewed by the audit manager/director before issue.",
        ],
        "linked_skills": [
            "lead-it-auditor/audit-scope-checklist",
        ],
    },
    {
        "number": 2,
        "title": "Scope Definition",
        "objective": (
            "Translate the high-level audit objectives into a precise, agreed scope: "
            "define the systems, processes, time periods, and control domains in scope, "
            "and identify what is explicitly out of scope."
        ),
        "artefacts": [
            "audit_program.json — machine-readable control list from audit-scope-checklist",
            "scope_document.docx — formal in-scope / out-of-scope definition",
            "system_inventory.xlsx — list of in-scope systems with owners and classifications",
            "framework_mapping.xlsx — mapping of audit controls to applicable frameworks",
            "kick_off_meeting_minutes.docx — agreed scope signed off by auditee",
        ],
        "tools_commands": [
            "# Generate the scoped audit program (all roles)",
            "python lead-it-auditor/audit-scope-checklist/main.py \\",
            "  --system \"<SYSTEM_NAME>\" \\",
            "  --output-dir ./output",
            "",
            "# Generate for specific roles with framework annotations",
            "python lead-it-auditor/audit-scope-checklist/main.py \\",
            "  --system \"<SYSTEM_NAME>\" \\",
            "  --roles \"identity-access,application-security,network-security\" \\",
            "  --frameworks \"PCI-DSS\" \\",
            "  --output-dir ./output",
            "",
            "# Inspect generated audit_program.json",
            "python -m json.tool ./output/audit_program.json | head -60",
        ],
        "must_do_checks": [
            "Confirm scope in writing with the auditee — scope creep is the leading cause of audit delays.",
            "Identify all third-party systems or cloud services that fall within scope.",
            "Document any known constraints (e.g. systems unavailable during freeze periods).",
            "Ensure frameworks used for annotation match the organisation's compliance obligations.",
            "Record the agreed audit period (e.g. 1 Jan – 31 Dec 2024) in all scope artefacts.",
        ],
        "linked_skills": [
            "lead-it-auditor/audit-scope-checklist",
            "compliance-controls/compliance-checker",
        ],
    },
    {
        "number": 3,
        "title": "Risk Assessment",
        "objective": (
            "Identify and rank the key IT risks within the audit scope. Use the risk "
            "assessment to prioritise fieldwork effort, focusing deeper testing on "
            "higher-risk areas and lighter coverage on lower-risk areas."
        ),
        "artefacts": [
            "risk_assessment_matrix.xlsx — likelihood × impact scoring for each audit area",
            "threat_register.xlsx — known threats relevant to the in-scope environment",
            "prior_audit_findings.xlsx — unresolved findings from previous audit cycles",
            "control_gap_analysis.xlsx — preliminary view of potential control weaknesses",
            "risk_ranked_audit_program.xlsx — audit program sorted by risk priority",
        ],
        "tools_commands": [
            "# Check compliance posture for risk context",
            "python compliance-controls/compliance-checker/main.py \\",
            "  --controls ./output/audit_program.json \\",
            "  --framework \"ISO 27001\"",
            "",
            "# Review vendor risk for third-party exposure",
            "python vendor-risk/vendor-assessor/main.py \\",
            "  --vendors ./sample_input/vendor_list.csv",
            "",
            "# Run network threat correlation for infrastructure risk",
            "python network-security/threat-correlator/main.py \\",
            "  --indicators ./sample_input/indicators.csv",
        ],
        "must_do_checks": [
            "Review all open findings from the prior audit cycle — repeat findings carry elevated inherent risk.",
            "Consider both technical risks (vulnerabilities, misconfigurations) and process risks (policy gaps, inadequate oversight).",
            "Obtain and review the organisation's own risk register before finalising the assessment.",
            "Risk assessment must be reviewed by the audit manager before fieldwork begins.",
            "Document the rationale for any audit area scoped out due to low risk — this creates an audit trail.",
        ],
        "linked_skills": [
            "lead-it-auditor/audit-scope-checklist",
            "compliance-controls/compliance-checker",
            "vendor-risk/vendor-assessor",
            "network-security/threat-correlator",
        ],
    },
    {
        "number": 4,
        "title": "Fieldwork Coordination",
        "objective": (
            "Execute evidence collection across all in-scope audit domains. Coordinate "
            "with specialist auditors, track evidence receipt in real time, and manage "
            "auditee interactions to keep the engagement on schedule."
        ),
        "artefacts": [
            "evidence_request_list.xlsx — itemised list of artefacts requested from the auditee",
            "evidence_receipt_log.xlsx — tracking log of artefacts received vs. outstanding",
            "interview_notes/ — directory of notes from walkthroughs and discussions",
            "working_papers/ — auditor work products and test results per control",
            "fieldwork_status_report.md — weekly status update shared with audit management",
        ],
        "tools_commands": [
            "# Identify evidence gaps against the audit program",
            "python lead-it-auditor/artefact-gap-analyzer/main.py \\",
            "  --program ./output/audit_program.json \\",
            "  --provided ./evidence/",
            "",
            "# IAM — run access review against provided user list",
            "python identity-access/access-review/main.py \\",
            "  --users ./evidence/user_list.csv \\",
            "  --mode local",
            "",
            "# Log monitoring — analyse provided SIEM export",
            "python log-monitoring/log-analyzer/main.py \\",
            "  --log-file ./evidence/siem_export.csv",
            "",
            "# Application security — parse vulnerability scanner output",
            "python application-security/vuln-parser/main.py \\",
            "  --report ./evidence/vuln_scan_report.xml",
            "",
            "# Vendor risk — assess vendor questionnaire responses",
            "python vendor-risk/vendor-assessor/main.py \\",
            "  --questionnaire ./evidence/vendor_responses.json",
        ],
        "must_do_checks": [
            "Chase outstanding evidence at least every 48 hours — do not let requests go stale.",
            "Log all evidence with date received, file name, and providing contact in the receipt log.",
            "Never alter or annotate original evidence files — work on copies only.",
            "Raise an issue immediately if the auditee refuses or cannot provide a requested artefact.",
            "Ensure all specialist auditors have completed their assigned controls before the evidence cut-off date.",
            "Conduct at least one mid-fieldwork status call with audit management to surface emerging issues early.",
        ],
        "linked_skills": [
            "lead-it-auditor/artefact-gap-analyzer",
            "identity-access/access-review",
            "identity-access/sod-analyzer",
            "identity-access/privileged-account-monitor",
            "log-monitoring/log-analyzer",
            "log-monitoring/anomaly-detector",
            "vendor-risk/vendor-assessor",
            "network-security/network-config-reviewer",
            "application-security/vuln-parser",
            "data-privacy/data-inventory-mapper",
            "hardware-physical/asset-validator",
        ],
    },
    {
        "number": 5,
        "title": "Evidence Review & Quality Check",
        "objective": (
            "Review all collected evidence and working papers for completeness, accuracy, "
            "and sufficiency. Validate that each finding is supported by adequate evidence "
            "and that conclusions are logical, well-reasoned, and free from material error."
        ),
        "artefacts": [
            "completed_working_papers/ — reviewed and signed-off test results per control",
            "finding_draft_log.xlsx — draft findings with risk ratings and evidence references",
            "qa_checklist.xlsx — quality assurance checklist completed by audit reviewer",
            "artefact_coverage_report.md — final output from artefact-gap-analyzer confirming 100% coverage",
            "peer_review_sign_off.pdf — reviewer sign-off before draft report is issued",
        ],
        "tools_commands": [
            "# Final artefact coverage check — must show 100% before QA sign-off",
            "python lead-it-auditor/artefact-gap-analyzer/main.py \\",
            "  --program ./output/audit_program.json \\",
            "  --provided ./evidence/",
            "",
            "# Build incident timeline if log-based findings are present",
            "python log-monitoring/incident-timeline-builder/main.py \\",
            "  --logs ./evidence/siem_export.csv \\",
            "  --output-dir ./output",
            "",
            "# Check SOD conflicts in final access review data",
            "python identity-access/sod-analyzer/main.py \\",
            "  --roles ./evidence/role_assignments.csv",
            "",
            "# Validate network segmentation findings",
            "python network-security/segmentation-validator/main.py \\",
            "  --topology ./evidence/network_diagram.json",
        ],
        "must_do_checks": [
            "Every finding must reference at least one specific evidence item by filename and location.",
            "Risk ratings (Critical/High/Medium/Low) must be consistent with the organisation's risk taxonomy.",
            "Factual accuracy: verify all system names, dates, and statistics against source evidence.",
            "No finding should name an individual without legal/HR confirmation that this is permissible.",
            "The QA checklist must be completed and signed off by a reviewer who did not perform the testing.",
            "Resolve all review notes and open queries before issuing the draft report to management.",
        ],
        "linked_skills": [
            "lead-it-auditor/artefact-gap-analyzer",
            "lead-it-auditor/exec-summary-writer",
            "log-monitoring/incident-timeline-builder",
            "identity-access/sod-analyzer",
            "network-security/segmentation-validator",
        ],
    },
    {
        "number": 6,
        "title": "Reporting & Closeout",
        "objective": (
            "Issue the final audit report, obtain management responses with agreed action "
            "plans, present findings to the audit committee, and formally close the "
            "engagement. Enter all findings into the finding tracker for ongoing monitoring."
        ),
        "artefacts": [
            "executive_summary.md — output from exec-summary-writer for senior audience",
            "final_audit_report.docx — full audit report with findings, evidence refs, and management responses",
            "management_response_log.xlsx — management's agreed actions and due dates per finding",
            "finding_tracker.xlsx — findings entered into the central tracker for lifecycle monitoring",
            "audit_committee_presentation.pptx — slide deck summarising results for the board/committee",
            "engagement_closure_memo.docx — formal closure noting all deliverables issued and filed",
        ],
        "tools_commands": [
            "# Generate the executive summary from the final findings file",
            "python lead-it-auditor/exec-summary-writer/main.py \\",
            "  --findings ./output/findings.json \\",
            "  --scope \"Annual IT General Controls Review — FY2025\" \\",
            "  --author \"IT Audit Team\" \\",
            "  --date \"$(date +%Y-%m-%d)\" \\",
            "  > ./output/executive_summary.md",
            "",
            "# Verify all findings are in the tracker",
            "python -c \"",
            "import json",
            "with open('./output/findings.json') as f:",
            "    findings = json.load(f)",
            "print(f'Total findings to track: {len(findings)}')",
            "for i, fn in enumerate(findings, 1):",
            "    print(f'  {i}. [{fn[\\\"risk_level\\\"]}] {fn[\\\"title\\\"]}')",
            "\"",
        ],
        "must_do_checks": [
            "Draft report must be issued to management for response within 30 days of fieldwork completion.",
            "Management responses must be obtained for every finding before the report is finalised.",
            "All agreed action plans must have a named owner and a specific due date — 'ongoing' is not acceptable.",
            "The final report must be reviewed and approved by the audit director before distribution.",
            "File all working papers, evidence, and the final report in the designated audit repository.",
            "Update the finding tracker within 5 business days of report issuance.",
            "Confirm the audit committee presentation date and distribute materials at least 5 days in advance.",
        ],
        "linked_skills": [
            "lead-it-auditor/exec-summary-writer",
            "lead-it-auditor/artefact-gap-analyzer",
        ],
    },
]


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments.

    Returns:
        Parsed argument namespace.
    """
    parser = argparse.ArgumentParser(
        description=(
            "Lead IT Auditor Playbook — print one or all steps of the "
            "engagement playbook."
        )
    )
    parser.add_argument(
        "--step",
        type=str,
        default="full",
        help=(
            "Step number (1–6) to display, or 'full' to display all steps "
            "(default: full)."
        ),
    )
    return parser.parse_args()


def validate_step(step_arg: str) -> Union[int, str]:
    """Validate and normalise the --step argument.

    Args:
        step_arg: Raw value from the command line.

    Returns:
        Integer step number (1–6) or the string 'full'.

    Raises:
        SystemExit: If the value is not a valid step number or 'full'.
    """
    if step_arg.lower() == "full":
        return "full"

    try:
        step_int = int(step_arg)
    except ValueError:
        print(
            f"ERROR: Invalid --step value '{step_arg}'. "
            "Must be an integer between 1 and 6, or 'full'.",
            file=sys.stderr,
        )
        sys.exit(1)

    if step_int < 1 or step_int > 6:
        print(
            f"ERROR: --step {step_int} is out of range. "
            "Valid values are 1–6 or 'full'.",
            file=sys.stderr,
        )
        sys.exit(1)

    return step_int


def render_step(step: Dict[str, Any]) -> str:
    """Render a single playbook step as a markdown section.

    Args:
        step: Playbook step dictionary.

    Returns:
        Formatted markdown string for the step.
    """
    lines = [
        f"## Step {step['number']}: {step['title']}",
        "",
        f"**Objective:** {step['objective']}",
        "",
        "### Artefacts",
        "",
    ]

    for artefact in step["artefacts"]:
        lines.append(f"- {artefact}")

    lines += [
        "",
        "### Tools & Commands",
        "",
        "```bash",
    ]
    for cmd_line in step["tools_commands"]:
        lines.append(cmd_line)
    lines.append("```")

    lines += [
        "",
        "### Must-Do Checks",
        "",
    ]
    for check in step["must_do_checks"]:
        lines.append(f"- [ ] {check}")

    lines += [
        "",
        "### Linked Skills",
        "",
    ]
    for skill_path in step["linked_skills"]:
        lines.append(f"- `{skill_path}/`")

    lines.append("")
    return "\n".join(lines)


def render_full_playbook(steps: List[Dict[str, Any]]) -> str:
    """Render all playbook steps as a complete markdown document.

    Args:
        steps: Full list of playbook step dictionaries.

    Returns:
        Complete formatted markdown string.
    """
    header_lines = [
        "# Lead IT Auditor — Engagement Playbook",
        "",
        "A structured six-step guide for planning, executing, and closing an IT audit engagement.",
        "",
        "| Step | Title |",
        "|------|-------|",
    ]
    for step in steps:
        header_lines.append(f"| {step['number']} | {step['title']} |")

    header_lines += ["", "---", ""]

    step_sections = [render_step(s) for s in steps]
    separator = "---\n\n"
    return "\n".join(header_lines) + separator.join(step_sections)


def main() -> None:
    """Entry point for the lead IT auditor playbook CLI."""
    args = parse_args()
    step_value = validate_step(args.step)

    if step_value == "full":
        print(render_full_playbook(PLAYBOOK_STEPS))
    else:
        step_data = next((s for s in PLAYBOOK_STEPS if s["number"] == step_value), None)
        if step_data is None:
            print(f"ERROR: Step {step_value} not found in playbook.", file=sys.stderr)
            sys.exit(1)
        print(render_step(step_data))


if __name__ == "__main__":
    main()
