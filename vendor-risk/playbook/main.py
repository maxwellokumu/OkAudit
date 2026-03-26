"""Vendor & Third-Party Risk Audit Playbook — step-by-step methodology."""

import argparse
import sys
from typing import Dict, List

from dotenv import load_dotenv

load_dotenv()

PLAYBOOK: List[Dict] = [
    {
        "step": 1,
        "title": "Vendor Inventory & Tiering",
        "objective": "Build a complete inventory of all third-party vendors, classify them by tier and criticality, and identify those requiring formal risk assessment.",
        "artefacts": [
            "vendor_register.xlsx — all vendors with tier, criticality, data access, spend",
            "vendor_classification_criteria.pdf — documented tiering methodology",
            "contracts_inventory.xlsx — contract status and renewal dates per vendor",
            "supply_chain_map.md — output from supply-chain-mapper skill",
        ],
        "tools_commands": [
            "# Generate supply chain map",
            "python vendor-risk/supply-chain-mapper/main.py \\",
            "  --vendors vendor_register.csv",
            "",
            "# Mermaid diagram only",
            "python vendor-risk/supply-chain-mapper/main.py \\",
            "  --vendors vendor_register.csv --output mermaid",
        ],
        "must_do_checks": [
            "Vendor inventory must cover ALL vendors — including shadow IT and departmental tools",
            "All vendors with access to customer/personal data must be identified",
            "Tier 1 (direct) vendors must all have signed contracts",
            "Identify vendors with no formal contract — these are immediate risk items",
            "Confirm the vendor register is reviewed and updated at least annually",
        ],
        "linked_skills": ["vendor-risk/supply-chain-mapper/"],
    },
    {
        "step": 2,
        "title": "Risk Tiering & Prioritisation",
        "objective": "Assign risk ratings to all vendors based on criticality, data access, and contractual status. Prioritise vendors for formal assessment.",
        "artefacts": [
            "vendor_risk_tiering.xlsx — risk score and assessment priority per vendor",
            "assessment_schedule.xlsx — planned assessment dates per vendor",
            "high_risk_vendor_list.pdf — vendors flagged for immediate assessment",
        ],
        "tools_commands": [
            "# Review supply chain for high-risk patterns",
            "python vendor-risk/supply-chain-mapper/main.py \\",
            "  --vendors vendor_register.csv --output markdown",
        ],
        "must_do_checks": [
            "All Critical vendors must be assessed annually at minimum",
            "Any vendor processing personal/sensitive data must be assessed regardless of tier",
            "New vendors must be assessed BEFORE being onboarded",
            "Vendor criticality must factor in concentration risk (single points of failure)",
            "Include sub-processors and nth-party vendors in scope for data processors",
        ],
        "linked_skills": ["vendor-risk/supply-chain-mapper/"],
    },
    {
        "step": 3,
        "title": "Vendor Assessment",
        "objective": "Conduct formal security assessments of prioritised vendors using the standardised questionnaire. Score responses and identify gaps.",
        "artefacts": [
            "vendor_questionnaire_responses/ — completed questionnaires per vendor",
            "vendor_assessment_reports/ — output from vendor-assessor skill per vendor",
            "evidence_pack/ — certifications, pen test reports, SOC2 reports",
        ],
        "tools_commands": [
            "# Score a vendor's questionnaire responses",
            "python vendor-risk/vendor-assessor/main.py \\",
            "  --answers vendor_answers.json",
            "",
            "# With custom category weights",
            "python vendor-risk/vendor-assessor/main.py \\",
            "  --answers vendor_answers.json \\",
            "  --weights category_weights.json",
            "",
            "# JSON output for bulk processing",
            "python vendor-risk/vendor-assessor/main.py \\",
            "  --answers vendor_answers.json --output json",
        ],
        "must_do_checks": [
            "Request supporting evidence for key answers (SOC2 reports, pen test summaries)",
            "Do not accept 'partial' answers without documentation of the gap and remediation plan",
            "Any vendor scoring Critical risk must be escalated to senior management",
            "Verify certifications are current — check expiry dates on SOC2/ISO reports",
            "Document assessment date and re-assessment schedule in the vendor register",
        ],
        "linked_skills": ["vendor-risk/vendor-assessor/"],
    },
    {
        "step": 4,
        "title": "Contract Review",
        "objective": "Review all vendor contracts to ensure required clauses are present and enforceable. Flag missing clauses for legal follow-up.",
        "artefacts": [
            "contract_review_reports/ — output from contract-checker per vendor",
            "missing_clauses_register.xlsx — all missing clauses with owner and target date",
            "contract_amendment_tracker.xlsx — contracts requiring amendment",
        ],
        "tools_commands": [
            "# Check a vendor contract",
            "python vendor-risk/contract-checker/main.py \\",
            "  --contract vendor_contract.txt --standard vendor",
            "",
            "# Check a SaaS contract",
            "python vendor-risk/contract-checker/main.py \\",
            "  --contract saas_contract.txt --standard saas",
            "",
            "# Check a data processing agreement",
            "python vendor-risk/contract-checker/main.py \\",
            "  --contract dpa.txt --standard data-processor",
        ],
        "must_do_checks": [
            "All vendors processing personal data must have a signed DPA — no exceptions",
            "Right-to-audit clause must be present for all Critical and High vendors",
            "Breach notification timelines must be 72 hours or less for data processors",
            "Contracts with missing liability caps must be reviewed by legal before renewal",
            "Flag all contracts expiring within 6 months for priority renewal review",
        ],
        "linked_skills": ["vendor-risk/contract-checker/"],
    },
    {
        "step": 5,
        "title": "Ongoing Monitoring & Supply Chain Mapping",
        "objective": "Establish continuous monitoring for vendor risk changes, update the supply chain map, and report findings to management.",
        "artefacts": [
            "vendor_monitoring_plan.xlsx — monitoring frequency and triggers per vendor",
            "updated_supply_chain_map.md — refreshed map with any new vendors",
            "vendor_risk_report.md — executive summary of vendor risk posture",
            "remediation_tracker.xlsx — open findings and agreed remediation dates",
        ],
        "tools_commands": [
            "# Regenerate supply chain map after vendor changes",
            "python vendor-risk/supply-chain-mapper/main.py \\",
            "  --vendors updated_vendor_register.csv",
            "",
            "# Generate executive summary",
            "python lead-it-auditor/exec-summary-writer/main.py \\",
            "  --findings vendor_findings.json \\",
            "  --scope 'Vendor Risk Assessment Q3 2025'",
        ],
        "must_do_checks": [
            "All Critical vendor assessments must be repeated annually",
            "Trigger re-assessment on vendor acquisition, major incidents, or scope changes",
            "Monitor vendor certifications for expiry — alert 90 days before expiry",
            "Update supply chain map whenever new vendors are onboarded or removed",
            "Report Critical and High vendor risk items to the board/audit committee quarterly",
        ],
        "linked_skills": [
            "vendor-risk/supply-chain-mapper/",
            "lead-it-auditor/exec-summary-writer/",
        ],
    },
]


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Vendor & Third-Party Risk audit playbook.")
    parser.add_argument("--step", default="full", help="Step number (1-5) or 'full'")
    return parser.parse_args()


def render_step(step: Dict) -> str:
    """Render a single playbook step as markdown."""
    lines: List[str] = []
    lines.append(f"## Step {step['step']}: {step['title']}\n")
    lines.append(f"**Objective:** {step['objective']}\n")
    lines.append("### Artefacts to Collect\n")
    for a in step["artefacts"]:
        lines.append(f"- {a}")
    lines.append("")
    lines.append("### Tools & Commands\n```bash")
    for cmd in step["tools_commands"]:
        lines.append(cmd)
    lines.append("```\n")
    lines.append("### ✅ Must-Do Checks\n")
    for c in step["must_do_checks"]:
        lines.append(f"- [ ] {c}")
    lines.append("")
    if step["linked_skills"]:
        lines.append("### 🔗 Linked Skills\n")
        for s in step["linked_skills"]:
            lines.append(f"- `{s}`")
        lines.append("")
    lines.append("---\n")
    return "\n".join(lines)


def main() -> None:
    """Main entry point."""
    args = parse_args()
    if args.step == "full":
        print("# Vendor & Third-Party Risk Audit Playbook\n")
        for s in PLAYBOOK:
            print(render_step(s))
        return
    try:
        n = int(args.step)
    except ValueError:
        print(f"ERROR: --step must be 1-{len(PLAYBOOK)} or 'full'.", file=sys.stderr)
        sys.exit(1)
    if n < 1 or n > len(PLAYBOOK):
        print(f"ERROR: --step must be between 1 and {len(PLAYBOOK)}.", file=sys.stderr)
        sys.exit(1)
    step = next(s for s in PLAYBOOK if s["step"] == n)
    print("# Vendor & Third-Party Risk Audit Playbook\n")
    print(render_step(step))


if __name__ == "__main__":
    main()
