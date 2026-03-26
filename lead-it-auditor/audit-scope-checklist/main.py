"""Audit Scope Checklist — generate a scoped IT audit program with controls.

Generates a formatted markdown audit program and writes audit_program.json
to the specified output directory. Controls can be filtered by role and
annotated with one or more compliance frameworks.
"""

import argparse
import json
import os
import sys
from datetime import date
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Control catalogue
# ---------------------------------------------------------------------------

ROLE_CONTROLS: Dict[str, List[Dict[str, Any]]] = {
    "lead-it-auditor": [
        {
            "id": "LIA-001",
            "control": "Audit charter and independence",
            "artefact": "audit_charter.pdf",
            "details": "Verify the internal audit charter is approved by the board, grants unrestricted access, and establishes organisational independence.",
            "acceptance": "Signed charter on file, dated within 2 years, no management reporting line for the CAE.",
            "role": "lead-it-auditor",
        },
        {
            "id": "LIA-002",
            "control": "Annual risk-based audit plan",
            "artefact": "annual_audit_plan.pdf",
            "details": "Confirm a formal risk-based plan is produced annually, approved by the audit committee, and tracked for completion.",
            "acceptance": "Plan approved by audit committee, coverage of top-10 risks, quarterly status reports on file.",
            "role": "lead-it-auditor",
        },
        {
            "id": "LIA-003",
            "control": "Engagement planning and scoping",
            "artefact": "engagement_planning_memo.docx",
            "details": "Each audit engagement must have a documented scope, objectives, criteria, and resource plan before fieldwork begins.",
            "acceptance": "Planning memo completed and reviewed prior to fieldwork; scope sign-off by auditee management.",
            "role": "lead-it-auditor",
        },
        {
            "id": "LIA-004",
            "control": "Finding tracking and remediation",
            "artefact": "finding_tracker.xlsx",
            "details": "All audit findings must be tracked from issuance through management response to verified closure.",
            "acceptance": "Tracker current within 30 days; Critical/High findings with due dates; no overdue items without documented extension.",
            "role": "lead-it-auditor",
        },
        {
            "id": "LIA-005",
            "control": "Quality assurance and improvement programme",
            "artefact": "qaip_report.pdf",
            "details": "Internal audit must maintain a QAIP including ongoing monitoring and periodic internal/external assessments.",
            "acceptance": "External assessment within 5 years; internal assessment annual; results communicated to senior management and board.",
            "role": "lead-it-auditor",
        },
        {
            "id": "LIA-006",
            "control": "Audit report issuance and distribution",
            "artefact": "audit_report_sample.pdf",
            "details": "Final audit reports must be issued in a timely manner with management responses and agreed action plans.",
            "acceptance": "Reports issued within 30 days of fieldwork completion; management responses within 15 business days.",
            "role": "lead-it-auditor",
        },
    ],
    "identity-access": [
        {
            "id": "IAM-001",
            "control": "User access provisioning process",
            "artefact": "access_provisioning_procedure.pdf",
            "details": "Evaluate whether a formal, documented process exists for requesting, approving, and provisioning user access to systems.",
            "acceptance": "Written procedure in place; access requests approved by data owner; provisioning logs retained for 12 months.",
            "role": "identity-access",
        },
        {
            "id": "IAM-002",
            "control": "Periodic user access review",
            "artefact": "access_review.xlsx",
            "details": "All user accounts in in-scope systems must be reviewed at least semi-annually for continued business need.",
            "acceptance": "Review completed within the last 6 months; revocations actioned within 5 business days; documented sign-off by managers.",
            "role": "identity-access",
        },
        {
            "id": "IAM-003",
            "control": "Privileged account management",
            "artefact": "privileged_account_list.xlsx",
            "details": "Privileged (admin) accounts must be inventoried, approved, and their usage logged and reviewed.",
            "acceptance": "Inventory current; each privileged account tied to a named individual; activity reviewed monthly.",
            "role": "identity-access",
        },
        {
            "id": "IAM-004",
            "control": "Segregation of duties enforcement",
            "artefact": "sod_matrix.xlsx",
            "details": "Conflicting roles (e.g. create payment + approve payment) must be identified and either separated or mitigated with compensating controls.",
            "acceptance": "SOD matrix documented; conflicts <5% of user population; compensating controls evidenced for all approved conflicts.",
            "role": "identity-access",
        },
        {
            "id": "IAM-005",
            "control": "Leaver account deprovisioning",
            "artefact": "leaver_log.xlsx",
            "details": "Accounts of terminated employees must be disabled/removed within 24 hours of HR notification.",
            "acceptance": "Sample of 20 leavers; all accounts disabled same day or next business day; no active accounts for leavers.",
            "role": "identity-access",
        },
        {
            "id": "IAM-006",
            "control": "Multi-factor authentication enforcement",
            "artefact": "mfa_configuration_report.pdf",
            "details": "MFA must be enforced for all remote access, privileged accounts, and cloud management consoles.",
            "acceptance": "MFA enabled for 100% of remote-access users and admins; configuration screenshots on file.",
            "role": "identity-access",
        },
    ],
    "compliance-controls": [
        {
            "id": "CC-001",
            "control": "Information security policy",
            "artefact": "infosec_policy.pdf",
            "details": "A formally approved information security policy must exist, be communicated to all staff, and reviewed annually.",
            "acceptance": "Policy approved by board/senior management; review within 12 months; distribution records on file.",
            "role": "compliance-controls",
        },
        {
            "id": "CC-002",
            "control": "Control framework mapping",
            "artefact": "control_framework_mapping.xlsx",
            "details": "Organisation's controls must be mapped to applicable frameworks (ISO 27001, SOC 2, PCI-DSS, NIST CSF).",
            "acceptance": "Mapping document current; gaps identified and tracked; owner assigned per control.",
            "role": "compliance-controls",
        },
        {
            "id": "CC-003",
            "control": "Security awareness training",
            "artefact": "training_completion_report.xlsx",
            "details": "All employees must complete security awareness training at least annually; records retained.",
            "acceptance": "≥95% completion rate; training updated within 12 months; phishing simulation results documented.",
            "role": "compliance-controls",
        },
        {
            "id": "CC-004",
            "control": "Vulnerability management programme",
            "artefact": "vuln_scan_report.pdf",
            "details": "Regular vulnerability scans must be conducted and findings remediated within SLA (Critical: 7 days, High: 30 days).",
            "acceptance": "Scans run at least monthly; no overdue Critical/High findings; remediation tracked to closure.",
            "role": "compliance-controls",
        },
        {
            "id": "CC-005",
            "control": "Change management process",
            "artefact": "change_log.xlsx",
            "details": "All changes to production systems must follow a documented change management process with approval and rollback plans.",
            "acceptance": "Change log complete; emergency changes <10% of total; unauthorised changes: zero tolerance.",
            "role": "compliance-controls",
        },
        {
            "id": "CC-006",
            "control": "Incident response plan",
            "artefact": "incident_response_plan.pdf",
            "details": "A documented and tested incident response plan must be in place covering detection, containment, eradication, and recovery.",
            "acceptance": "Plan reviewed within 12 months; tabletop exercise completed annually; contact lists current.",
            "role": "compliance-controls",
        },
    ],
    "log-monitoring": [
        {
            "id": "LM-001",
            "control": "Centralised log aggregation",
            "artefact": "siem_configuration.pdf",
            "details": "All critical systems (servers, firewalls, endpoints, applications) must forward logs to a centralised SIEM or log platform.",
            "acceptance": "Log sources inventoried; >95% of critical assets forwarding logs; latency <5 minutes.",
            "role": "log-monitoring",
        },
        {
            "id": "LM-002",
            "control": "Log retention policy compliance",
            "artefact": "log_retention_policy.pdf",
            "details": "Logs must be retained for the period required by policy and applicable regulations (minimum 12 months online, 7 years archive).",
            "acceptance": "Retention configuration matches policy; sample log retrieval test successful for 12-month-old events.",
            "role": "log-monitoring",
        },
        {
            "id": "LM-003",
            "control": "Security alert monitoring and response",
            "artefact": "alert_response_log.xlsx",
            "details": "SIEM alerts must be triaged within defined SLAs; all Critical alerts investigated and closed within 4 hours.",
            "acceptance": "Alert queue reviewed; mean-time-to-triage <4 hours for Critical; no unacknowledged alerts >24 hours.",
            "role": "log-monitoring",
        },
        {
            "id": "LM-004",
            "control": "Log integrity and tamper protection",
            "artefact": "log_integrity_config.pdf",
            "details": "Log storage must be protected from modification; write-once storage or cryptographic hashing required.",
            "acceptance": "Log integrity mechanism in place; sample hash verification test passed; admin access to log store reviewed.",
            "role": "log-monitoring",
        },
        {
            "id": "LM-005",
            "control": "Privileged activity logging",
            "artefact": "privileged_activity_logs.csv",
            "details": "All privileged (admin) activities must be logged, including commands executed, files accessed, and configuration changes.",
            "acceptance": "Privileged session logging enabled on all admin interfaces; logs reviewed monthly.",
            "role": "log-monitoring",
        },
        {
            "id": "LM-006",
            "control": "Anomaly detection tuning",
            "artefact": "anomaly_detection_rules.pdf",
            "details": "Anomaly detection rules must be reviewed and tuned quarterly to reduce false positives and maintain detection fidelity.",
            "acceptance": "Rules reviewed within 90 days; false positive rate <20%; tuning log on file.",
            "role": "log-monitoring",
        },
    ],
    "vendor-risk": [
        {
            "id": "VR-001",
            "control": "Third-party vendor inventory",
            "artefact": "vendor_inventory.xlsx",
            "details": "A complete, classified inventory of all third-party vendors with access to systems or data must be maintained.",
            "acceptance": "Inventory current within 90 days; vendors classified by risk tier; data classification noted.",
            "role": "vendor-risk",
        },
        {
            "id": "VR-002",
            "control": "Vendor due diligence assessments",
            "artefact": "vendor_assessment_reports.pdf",
            "details": "Risk-tiered due diligence assessments (questionnaire, SOC 2 review, on-site) must be completed before onboarding.",
            "acceptance": "Assessment on file for all Tier-1/2 vendors; completed within 12 months of last review.",
            "role": "vendor-risk",
        },
        {
            "id": "VR-003",
            "control": "Data processing agreements",
            "artefact": "dpa_register.xlsx",
            "details": "A Data Processing Agreement (DPA) must be in place with all vendors processing personal or confidential data.",
            "acceptance": "DPA register complete; 100% coverage for data-handling vendors; DPAs reviewed by legal.",
            "role": "vendor-risk",
        },
        {
            "id": "VR-004",
            "control": "Vendor security clause review",
            "artefact": "contract_security_clauses.docx",
            "details": "All vendor contracts must include minimum security clauses: breach notification, right-to-audit, subprocessor controls.",
            "acceptance": "Security clause checklist completed for all contracts; gaps remediated at next renewal.",
            "role": "vendor-risk",
        },
        {
            "id": "VR-005",
            "control": "Vendor performance and risk monitoring",
            "artefact": "vendor_monitoring_log.xlsx",
            "details": "Ongoing monitoring of Tier-1 vendors must include quarterly reviews of SLA performance and security posture.",
            "acceptance": "Monitoring log current; escalation process documented; annual re-assessment for Tier-1 vendors.",
            "role": "vendor-risk",
        },
        {
            "id": "VR-006",
            "control": "Supply chain risk mapping",
            "artefact": "supply_chain_map.pdf",
            "details": "Critical software and hardware supply chains must be mapped to identify concentration risks and single points of failure.",
            "acceptance": "Map covers all Tier-1 vendors; subprocessors identified; concentration risks assessed.",
            "role": "vendor-risk",
        },
    ],
    "network-security": [
        {
            "id": "NS-001",
            "control": "Firewall rule review",
            "artefact": "firewall_ruleset.csv",
            "details": "Firewall rulesets must be reviewed annually; rules must have documented business justification and owner.",
            "acceptance": "Review completed within 12 months; no 'any-any' rules; rule count justified; unused rules removed.",
            "role": "network-security",
        },
        {
            "id": "NS-002",
            "control": "Network segmentation validation",
            "artefact": "network_segmentation_diagram.pdf",
            "details": "Critical zones (PCI, production, DMZ, management) must be separated and validated against documented architecture.",
            "acceptance": "Diagram current; segmentation verified by configuration review; inter-zone traffic policy documented.",
            "role": "network-security",
        },
        {
            "id": "NS-003",
            "control": "Wireless network security",
            "artefact": "wireless_audit_report.pdf",
            "details": "Wireless networks must use WPA3 (or WPA2 minimum), separate guest networks, and rogue AP detection.",
            "acceptance": "WPA2+ confirmed; guest network isolated; rogue AP detection active; last assessment within 12 months.",
            "role": "network-security",
        },
        {
            "id": "NS-004",
            "control": "Penetration testing",
            "artefact": "pentest_report.pdf",
            "details": "External and internal penetration tests must be conducted annually; critical findings remediated within 30 days.",
            "acceptance": "Test within 12 months by qualified third party; critical findings closed; retest evidence on file.",
            "role": "network-security",
        },
        {
            "id": "NS-005",
            "control": "Network device hardening",
            "artefact": "hardening_baseline.pdf",
            "details": "Network devices must be configured against CIS or vendor hardening benchmarks; default credentials changed.",
            "acceptance": "Hardening baseline documented; sample configuration review passed; no default credentials in use.",
            "role": "network-security",
        },
        {
            "id": "NS-006",
            "control": "Threat intelligence integration",
            "artefact": "threat_intel_feed_config.pdf",
            "details": "Threat intelligence feeds must be integrated with network controls (firewall, IPS) and reviewed for actionable indicators.",
            "acceptance": "At least one curated feed active; indicators actioned within 24 hours; review log on file.",
            "role": "network-security",
        },
    ],
    "data-privacy": [
        {
            "id": "DP-001",
            "control": "Personal data inventory (RoPA)",
            "artefact": "ropa.xlsx",
            "details": "A Record of Processing Activities must be maintained covering all personal data flows, lawful bases, and retention periods.",
            "acceptance": "RoPA current within 6 months; all processing activities documented; data flows mapped.",
            "role": "data-privacy",
        },
        {
            "id": "DP-002",
            "control": "Privacy notice adequacy",
            "artefact": "privacy_notice.pdf",
            "details": "Privacy notices must meet applicable legal requirements (GDPR, CCPA) and be presented at point of data collection.",
            "acceptance": "Legal review completed within 12 months; all required elements present; notices visible at collection points.",
            "role": "data-privacy",
        },
        {
            "id": "DP-003",
            "control": "Consent management",
            "artefact": "consent_records.csv",
            "details": "Consent records must be captured, stored, and be revocable; consent withdrawal must be processed within 30 days.",
            "acceptance": "Consent records auditable; withdrawal mechanism functional; processing halted within 30 days of withdrawal.",
            "role": "data-privacy",
        },
        {
            "id": "DP-004",
            "control": "Data subject rights fulfilment",
            "artefact": "dsr_log.xlsx",
            "details": "Processes for handling Subject Access Requests, erasure requests, and portability requests must exist and meet legal timelines.",
            "acceptance": "DSR log maintained; 100% of requests responded to within legal deadline; no overdue requests.",
            "role": "data-privacy",
        },
        {
            "id": "DP-005",
            "control": "Privacy Impact Assessments",
            "artefact": "pia_register.xlsx",
            "details": "PIAs must be completed for all new or significantly changed processing activities involving high-risk personal data.",
            "acceptance": "PIA register current; PIAs completed before go-live; DPO sign-off on file.",
            "role": "data-privacy",
        },
        {
            "id": "DP-006",
            "control": "Data breach response",
            "artefact": "breach_response_procedure.pdf",
            "details": "A documented data breach response procedure must exist; breaches must be notified to regulators within 72 hours where required.",
            "acceptance": "Procedure approved; breach log maintained; notification timeline met for all incidents in review period.",
            "role": "data-privacy",
        },
    ],
    "hardware-physical": [
        {
            "id": "HP-001",
            "control": "IT asset inventory accuracy",
            "artefact": "asset_inventory.xlsx",
            "details": "A complete hardware asset inventory must be maintained and reconciled against physical counts at least annually.",
            "acceptance": "Inventory current within 90 days; physical count reconciliation <2% discrepancy; assets labelled.",
            "role": "hardware-physical",
        },
        {
            "id": "HP-002",
            "control": "Data centre physical access control",
            "artefact": "physical_access_log.csv",
            "details": "Access to data centre and server rooms must be restricted, logged, and reviewed; no tailgating controls in place.",
            "acceptance": "Access list reviewed within 6 months; badge log retained 12 months; anti-tailgate measures active.",
            "role": "hardware-physical",
        },
        {
            "id": "HP-003",
            "control": "Firmware version management",
            "artefact": "firmware_baseline.xlsx",
            "details": "Firmware versions for servers, network devices, and endpoints must be tracked against approved baselines and patched within SLA.",
            "acceptance": "Baseline documented; no devices >2 patch cycles behind; critical firmware patches within 30 days.",
            "role": "hardware-physical",
        },
        {
            "id": "HP-004",
            "control": "Secure media disposal",
            "artefact": "media_disposal_log.xlsx",
            "details": "Storage media must be securely wiped or destroyed before disposal; certificates of destruction retained.",
            "acceptance": "Disposal log complete; certificates on file for all destroyed media; NIST 800-88 or equivalent method used.",
            "role": "hardware-physical",
        },
        {
            "id": "HP-005",
            "control": "Environmental controls",
            "artefact": "environmental_monitoring_report.pdf",
            "details": "Temperature, humidity, fire suppression, and UPS systems in data centres must be monitored and maintained.",
            "acceptance": "Environmental monitoring active; alerts configured; last maintenance within 12 months; UPS tested annually.",
            "role": "hardware-physical",
        },
        {
            "id": "HP-006",
            "control": "Mobile device management",
            "artefact": "mdm_enrolment_report.pdf",
            "details": "All corporate mobile devices and laptops must be enrolled in MDM/UEM with encryption, remote wipe, and compliance policy enforced.",
            "acceptance": "100% enrolment; encryption enforced; non-compliant devices blocked; lost device remote-wipe tested.",
            "role": "hardware-physical",
        },
    ],
    "application-security": [
        {
            "id": "AS-001",
            "control": "Secure development lifecycle (SDLC)",
            "artefact": "sdlc_policy.pdf",
            "details": "A documented SDLC must include security requirements gathering, threat modelling, code review, and security testing gates.",
            "acceptance": "SDLC policy current; security checkpoints documented; evidence of gates applied to last 3 releases.",
            "role": "application-security",
        },
        {
            "id": "AS-002",
            "control": "Static application security testing (SAST)",
            "artefact": "sast_scan_report.pdf",
            "details": "SAST tools must be integrated into CI/CD pipelines; builds with Critical/High findings must not promote to production.",
            "acceptance": "SAST integrated; gate policy enforced; no Critical findings in production release; scan history retained.",
            "role": "application-security",
        },
        {
            "id": "AS-003",
            "control": "Dependency and SCA scanning",
            "artefact": "sca_report.pdf",
            "details": "Software Composition Analysis must identify vulnerable third-party libraries; remediation SLAs enforced.",
            "acceptance": "SCA tool active in pipeline; no Critical CVEs in production; SBOM generated per release.",
            "role": "application-security",
        },
        {
            "id": "AS-004",
            "control": "OWASP Top-10 testing",
            "artefact": "owasp_test_results.pdf",
            "details": "Web applications must be tested against OWASP Top-10 vulnerabilities at least annually; findings tracked to remediation.",
            "acceptance": "Test within 12 months; no unmitigated Critical/High OWASP findings; retest evidence on file.",
            "role": "application-security",
        },
        {
            "id": "AS-005",
            "control": "API security review",
            "artefact": "api_security_assessment.pdf",
            "details": "APIs must be inventoried, authenticated (OAuth 2.0 / API keys), rate-limited, and tested for OWASP API Top-10 issues.",
            "acceptance": "API inventory current; authentication enforced on all external APIs; rate limiting active; test within 12 months.",
            "role": "application-security",
        },
        {
            "id": "AS-006",
            "control": "Secret and key management",
            "artefact": "secret_management_policy.pdf",
            "details": "Secrets (API keys, passwords, certificates) must never be stored in source code; a secrets manager must be used.",
            "acceptance": "No secrets in code repositories (verified by scan); secrets manager deployed; rotation policy enforced.",
            "role": "application-security",
        },
    ],
}

ALL_ROLE_IDS = list(ROLE_CONTROLS.keys())


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments.

    Returns:
        Parsed argument namespace.
    """
    parser = argparse.ArgumentParser(
        description="Generate a scoped IT audit program with controls mapped to roles and frameworks."
    )
    parser.add_argument(
        "--system",
        required=True,
        type=str,
        help="Name of the system or environment being audited.",
    )
    parser.add_argument(
        "--roles",
        type=str,
        default=None,
        help="Comma-separated role IDs to include (default: all roles).",
    )
    parser.add_argument(
        "--frameworks",
        type=str,
        default=None,
        help="Comma-separated framework names to annotate controls (e.g. 'ISO 27001,SOC 2').",
    )
    parser.add_argument(
        "--mode",
        choices=["local", "aws", "azure"],
        default="local",
        help="Execution mode (default: local).",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=".",
        help="Directory to write audit_program.json (default: current directory).",
    )
    return parser.parse_args()


def resolve_roles(roles_arg: Optional[str]) -> List[str]:
    """Resolve the list of role IDs from a comma-separated string.

    Args:
        roles_arg: Comma-separated role IDs, or None for all roles.

    Returns:
        List of validated role IDs.

    Raises:
        SystemExit: If any supplied role ID is not recognised.
    """
    if roles_arg is None:
        return ALL_ROLE_IDS

    requested = [r.strip() for r in roles_arg.split(",") if r.strip()]
    invalid = [r for r in requested if r not in ROLE_CONTROLS]
    if invalid:
        print(
            f"ERROR: Unrecognised role IDs: {', '.join(invalid)}\n"
            f"Valid options: {', '.join(ALL_ROLE_IDS)}",
            file=sys.stderr,
        )
        sys.exit(1)
    return requested


def resolve_frameworks(frameworks_arg: Optional[str]) -> List[str]:
    """Parse framework names from a comma-separated string.

    Args:
        frameworks_arg: Comma-separated framework names, or None.

    Returns:
        List of framework name strings.
    """
    if not frameworks_arg:
        return []
    return [f.strip() for f in frameworks_arg.split(",") if f.strip()]


def build_controls(role_ids: List[str], frameworks: List[str]) -> List[Dict[str, Any]]:
    """Collect and annotate controls for the selected roles.

    Args:
        role_ids: List of role IDs to include.
        frameworks: List of framework names to annotate each control with.

    Returns:
        Flat list of control dictionaries, each optionally annotated with frameworks.
    """
    controls: List[Dict[str, Any]] = []
    for role_id in role_ids:
        for ctrl in ROLE_CONTROLS[role_id]:
            entry = dict(ctrl)
            if frameworks:
                entry["frameworks"] = frameworks
            controls.append(entry)
    return controls


def render_markdown(system: str, role_ids: List[str], frameworks: List[str], controls: List[Dict[str, Any]]) -> str:
    """Render the audit program as a markdown document.

    Args:
        system: Name of the audited system.
        role_ids: List of role IDs included in this program.
        frameworks: List of frameworks annotating this program.
        controls: Full list of controls to include.

    Returns:
        Formatted markdown string.
    """
    today = date.today().isoformat()
    framework_str = ", ".join(frameworks) if frameworks else "N/A"

    lines = [
        f"# IT Audit Program — {system}",
        "",
        f"**Date:** {today}  ",
        f"**Frameworks:** {framework_str}  ",
        f"**Total Controls:** {len(controls)}",
        "",
        "---",
        "",
        "## 1. Audit Scope",
        "",
        f"This audit program covers the **{system}** environment. The following audit domains are in scope:",
        "",
    ]

    for role_id in role_ids:
        count = sum(1 for c in controls if c["role"] == role_id)
        friendly = role_id.replace("-", " ").title()
        lines.append(f"- **{friendly}** — {count} control(s)")

    lines += [
        "",
        "---",
        "",
        "## 2. Audit Team Roles",
        "",
        "| Role ID | Description |",
        "|---------|-------------|",
    ]

    role_descriptions = {
        "lead-it-auditor": "Overall audit coordination, scoping, and reporting",
        "identity-access": "User access reviews, privileged account management, SOD",
        "compliance-controls": "Policy compliance, framework mapping, security awareness",
        "log-monitoring": "SIEM coverage, log retention, alert triage",
        "vendor-risk": "Third-party assessments, contract review, supply chain",
        "network-security": "Firewall review, penetration testing, segmentation",
        "data-privacy": "Personal data processing, consent, PIA, DSRs",
        "hardware-physical": "Asset inventory, physical access, firmware, disposal",
        "application-security": "SDLC, SAST, SCA, OWASP, API security",
    }

    for role_id in role_ids:
        desc = role_descriptions.get(role_id, "—")
        lines.append(f"| `{role_id}` | {desc} |")

    lines += [
        "",
        "---",
        "",
        "## 3. Controls",
        "",
    ]

    # Group by role
    for role_id in role_ids:
        role_controls = [c for c in controls if c["role"] == role_id]
        if not role_controls:
            continue

        friendly = role_id.replace("-", " ").title()
        lines.append(f"### {friendly}")
        lines.append("")
        lines.append("| ID | Control | Artefact | Acceptance Criteria |")
        lines.append("|----|---------|----------|---------------------|")

        for ctrl in role_controls:
            lines.append(
                f"| `{ctrl['id']}` | {ctrl['control']} | `{ctrl['artefact']}` | {ctrl['acceptance']} |"
            )

        lines.append("")

    if frameworks:
        lines += [
            "---",
            "",
            "## 4. Framework Annotations",
            "",
            f"All controls in this program are annotated for: **{', '.join(frameworks)}**.",
            "Auditors should cross-reference the organisation's control mapping to identify coverage and gaps.",
            "",
        ]

    return "\n".join(lines)


def write_json(
    system: str,
    role_ids: List[str],
    frameworks: List[str],
    controls: List[Dict[str, Any]],
    output_dir: str,
) -> str:
    """Write the audit program to a JSON file.

    Args:
        system: Audited system name.
        role_ids: Selected role IDs.
        frameworks: Annotated frameworks.
        controls: Full control list.
        output_dir: Directory to write the file into.

    Returns:
        Absolute path of the written file.

    Raises:
        SystemExit: On I/O error.
    """
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, "audit_program.json")

    payload = {
        "system": system,
        "date": date.today().isoformat(),
        "roles": role_ids,
        "frameworks": frameworks,
        "total_controls": len(controls),
        "controls": controls,
    }

    try:
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
    except OSError as exc:
        print(f"ERROR: Could not write {output_path}: {exc}", file=sys.stderr)
        sys.exit(1)

    return os.path.abspath(output_path)


def main() -> None:
    """Entry point for the audit scope checklist CLI."""
    args = parse_args()

    role_ids = resolve_roles(args.roles)
    frameworks = resolve_frameworks(args.frameworks)
    controls = build_controls(role_ids, frameworks)

    if not controls:
        print("ERROR: No controls matched the specified roles.", file=sys.stderr)
        sys.exit(1)

    markdown = render_markdown(args.system, role_ids, frameworks, controls)
    print(markdown)

    json_path = write_json(args.system, role_ids, frameworks, controls, args.output_dir)
    print(f"\n---\n✓ Audit program written to: {json_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
