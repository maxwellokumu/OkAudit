"""Privacy Impact Assessment (PIA / DPIA) Generator.

Generates a fully structured PIA or DPIA report in markdown from
command-line parameters. Maps provided data types to risk levels,
selects applicable privacy risks from a hardcoded library, and
produces a complete structured document including risk assessment,
data subject rights checklist, DPO recommendations, and a sign-off block.
"""

import argparse
import sys
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Data type risk mapping
# ---------------------------------------------------------------------------

SPECIAL_CATEGORY_TYPES = {
    "health", "medical", "biometric", "genetic", "racial", "ethnic",
    "racial_ethnic", "political", "political_opinion", "religious",
    "religious_belief", "sexual_orientation", "sexual", "criminal",
    "criminal_record", "children_data", "child",
}

HIGH_RISK_TYPES = {
    "financial", "bank", "credit card", "payment", "location",
    "geolocation", "behavioral", "behavioural", "profiling", "tracking",
}

MEDIUM_RISK_TYPES = {
    "contact", "email", "phone", "address", "name", "identifier",
    "id", "username", "account", "employee", "staff",
}

LOW_RISK_TYPES = {
    "public", "published", "aggregated", "anonymised", "anonymized",
    "statistical", "demographic",
}


def classify_data_type(dt: str) -> Tuple[str, str]:
    """Classify a data type into a risk level.

    Args:
        dt: Data type string to classify.

    Returns:
        Tuple of (risk_level, explanation).
    """
    dt_lower = dt.lower().strip().replace(" ", "_").replace("-", "_")
    for sc in SPECIAL_CATEGORY_TYPES:
        if sc in dt_lower:
            return "Very High", "Special Category data under GDPR Article 9"
    for h in HIGH_RISK_TYPES:
        if h in dt_lower:
            return "High", "Sensitive personal data (financial/location/behavioural)"
    for m in MEDIUM_RISK_TYPES:
        if m in dt_lower:
            return "Medium", "Standard personal identifiers"
    for lo in LOW_RISK_TYPES:
        if lo in dt_lower:
            return "Low", "Publicly available or anonymised data"
    return "Medium", "Personal data — exact sensitivity unclear"


# ---------------------------------------------------------------------------
# Privacy risk library
# ---------------------------------------------------------------------------

@dataclass
class PrivacyRisk:
    """A single privacy risk with likelihood, impact, and mitigation."""

    id: str
    name: str
    description: str
    triggers: List[str]  # data type keywords or purpose keywords that activate this risk
    likelihood: str      # Low / Medium / High
    impact: str          # Low / Medium / High / Very High
    risk_score: str      # Low / Medium / High / Critical
    mitigation: str
    residual_risk: str


PRIVACY_RISKS: List[PrivacyRisk] = [
    PrivacyRisk(
        id="PR-01",
        name="Unauthorised Access to Personal Data",
        description="Personal data may be accessed by unauthorised internal or external parties.",
        triggers=["health", "financial", "biometric", "criminal", "contact", "employee"],
        likelihood="Medium",
        impact="High",
        risk_score="High",
        mitigation="Implement role-based access controls (RBAC), least-privilege principles, MFA for data access, and comprehensive audit logging.",
        residual_risk="Medium",
    ),
    PrivacyRisk(
        id="PR-02",
        name="Data Breach / Security Incident",
        description="A security incident may expose personal data to unauthorised parties.",
        triggers=["health", "financial", "biometric", "criminal", "contact", "location"],
        likelihood="Low",
        impact="Very High",
        risk_score="High",
        mitigation="Encrypt data at rest and in transit, implement intrusion detection, maintain an incident response plan, and test breach notification procedures.",
        residual_risk="Low",
    ),
    PrivacyRisk(
        id="PR-03",
        name="Excessive Data Collection",
        description="More personal data may be collected than is strictly necessary for the stated purposes.",
        triggers=["behavioral", "profiling", "tracking", "location", "biometric"],
        likelihood="Medium",
        impact="Medium",
        risk_score="Medium",
        mitigation="Conduct data minimisation review, document justification for each data field collected, and implement privacy-by-design principles.",
        residual_risk="Low",
    ),
    PrivacyRisk(
        id="PR-04",
        name="Purpose Creep",
        description="Personal data may be used for purposes beyond those originally collected and disclosed.",
        triggers=["analytics", "marketing", "profiling", "behavioral", "tracking", "research"],
        likelihood="Medium",
        impact="High",
        risk_score="High",
        mitigation="Define strict purpose limitations in system design, implement technical controls to prevent secondary use, and conduct regular purpose compliance audits.",
        residual_risk="Medium",
    ),
    PrivacyRisk(
        id="PR-05",
        name="Inaccurate Data",
        description="Personal data held may become inaccurate, incomplete, or out of date.",
        triggers=["health", "financial", "employee", "contact", "criminal"],
        likelihood="Medium",
        impact="Medium",
        risk_score="Medium",
        mitigation="Implement data quality controls, provide data subjects with mechanisms to correct their data, and schedule periodic data accuracy reviews.",
        residual_risk="Low",
    ),
    PrivacyRisk(
        id="PR-06",
        name="Unlawful Retention",
        description="Personal data may be retained beyond the defined retention period.",
        triggers=["health", "financial", "employee", "criminal", "contact"],
        likelihood="Medium",
        impact="Medium",
        risk_score="Medium",
        mitigation="Implement automated retention and deletion schedules, document retention periods per data category, and audit retention compliance annually.",
        residual_risk="Low",
    ),
    PrivacyRisk(
        id="PR-07",
        name="Cross-Border Transfer Risk",
        description="Transfer of personal data to countries without adequate data protection may expose data subjects to reduced rights.",
        triggers=["international", "transfer", "overseas", "cloud", "aws", "azure", "third-party"],
        likelihood="Medium",
        impact="High",
        risk_score="High",
        mitigation="Establish Standard Contractual Clauses (SCCs) or equivalent safeguards, conduct Transfer Impact Assessments (TIAs), and restrict transfers to countries with adequacy decisions where possible.",
        residual_risk="Medium",
    ),
    PrivacyRisk(
        id="PR-08",
        name="Automated Decision-Making Harm",
        description="Automated processing or profiling may result in decisions that significantly affect data subjects without human review.",
        triggers=["profiling", "scoring", "automated", "ai", "machine learning", "algorithm", "decision"],
        likelihood="Medium",
        impact="High",
        risk_score="High",
        mitigation="Implement human review processes for significant automated decisions, provide transparency on logic used, and give data subjects the right to contest decisions.",
        residual_risk="Medium",
    ),
    PrivacyRisk(
        id="PR-09",
        name="Consent Withdrawal Difficulty",
        description="Data subjects may find it difficult or unclear how to withdraw consent or exercise opt-out rights.",
        triggers=["consent", "marketing", "communications", "newsletter", "opt-in"],
        likelihood="Medium",
        impact="Medium",
        risk_score="Medium",
        mitigation="Provide clear, easy-to-use consent withdrawal mechanisms (one-click unsubscribe), test the withdrawal process, and confirm deletion within statutory timeframes.",
        residual_risk="Low",
    ),
    PrivacyRisk(
        id="PR-10",
        name="Re-identification of Anonymised Data",
        description="Data shared or published as anonymised may be re-identified through linkage with other datasets.",
        triggers=["analytics", "research", "statistical", "aggregated", "published", "shared"],
        likelihood="Low",
        impact="High",
        risk_score="Medium",
        mitigation="Apply robust anonymisation techniques (k-anonymity, differential privacy), conduct re-identification risk assessments before publication, and restrict access to quasi-identifiers.",
        residual_risk="Low",
    ),
]


def select_applicable_risks(
    data_types: List[str], purposes: List[str]
) -> List[PrivacyRisk]:
    """Select applicable risks based on data types and purposes.

    A risk is selected if any of its triggers appear in the combined
    set of data type and purpose keywords.

    Args:
        data_types: List of data type strings.
        purposes: List of purpose strings.

    Returns:
        Filtered list of applicable PrivacyRisk objects.
    """
    combined = " ".join(data_types + purposes).lower()
    applicable = []
    for risk in PRIVACY_RISKS:
        for trigger in risk.triggers:
            if trigger.lower() in combined:
                applicable.append(risk)
                break
    # Always include PR-01 (unauthorised access) and PR-02 (breach) as baseline
    baseline_ids = {"PR-01", "PR-02"}
    existing_ids = {r.id for r in applicable}
    for risk in PRIVACY_RISKS:
        if risk.id in baseline_ids and risk.id not in existing_ids:
            applicable.append(risk)
    return sorted(applicable, key=lambda r: r.id)


LEGAL_BASIS_MAP: Dict[str, str] = {
    "consent": "Article 6(1)(a) — Consent",
    "contract": "Article 6(1)(b) — Performance of a contract",
    "legal_obligation": "Article 6(1)(c) — Legal obligation",
    "legal obligation": "Article 6(1)(c) — Legal obligation",
    "vital_interests": "Article 6(1)(d) — Vital interests",
    "public_task": "Article 6(1)(e) — Public task",
    "legitimate_interests": "Article 6(1)(f) — Legitimate interests",
}

ISO27701_CONTROLS = [
    "7.2.1 — Identify and document purposes for PII processing",
    "7.2.2 — Identify legal basis for PII processing",
    "7.2.3 — Determine when and how consent is to be obtained",
    "7.3.1 — Obligations to PII principals",
    "7.4.1 — Limit collection of PII",
    "7.4.2 — Limit processing of PII",
    "7.4.3 — Accuracy and quality",
    "7.4.4 — PII minimisation objectives",
    "7.4.5 — De-identification and deletion of PII",
    "8.2.1 — Customer agreement",
    "8.4.1 — Temporary files",
]

DATA_SUBJECT_RIGHTS = [
    ("Right to Access", "GDPR Art. 15 / ISO 27701 §7.3.2"),
    ("Right to Rectification", "GDPR Art. 16 / ISO 27701 §7.3.4"),
    ("Right to Erasure", "GDPR Art. 17 / ISO 27701 §7.3.5"),
    ("Right to Restrict Processing", "GDPR Art. 18 / ISO 27701 §7.3.6"),
    ("Right to Data Portability", "GDPR Art. 20 / ISO 27701 §7.3.7"),
    ("Right to Object", "GDPR Art. 21 / ISO 27701 §7.3.8"),
    ("Right to Withdraw Consent", "GDPR Art. 7(3)"),
    ("Right Not to be Subject to Automated Decisions", "GDPR Art. 22"),
    ("Right to Lodge a Complaint", "GDPR Art. 77"),
]


def suggest_legal_basis(purpose: str) -> str:
    """Suggest an appropriate legal basis for a given purpose.

    Args:
        purpose: Processing purpose string.

    Returns:
        Legal basis string.
    """
    p = purpose.lower()
    if any(w in p for w in ("marketing", "newsletter", "consent", "opt-in")):
        return LEGAL_BASIS_MAP["consent"]
    if any(w in p for w in ("contract", "service", "subscription", "account", "payment")):
        return LEGAL_BASIS_MAP["contract"]
    if any(w in p for w in ("legal", "regulatory", "tax", "audit", "compliance", "law")):
        return LEGAL_BASIS_MAP["legal_obligation"]
    if any(w in p for w in ("fraud", "security", "analytics", "improve", "research")):
        return LEGAL_BASIS_MAP["legitimate_interests"]
    return LEGAL_BASIS_MAP["legitimate_interests"]


def generate_dpo_recommendations(
    data_types: List[str],
    risks: List[PrivacyRisk],
    framework: str,
) -> List[str]:
    """Generate DPO recommendations based on data types and identified risks.

    Args:
        data_types: List of data types.
        risks: List of applicable privacy risks.
        framework: Framework name.

    Returns:
        List of recommendation strings.
    """
    recs = [
        "Conduct a full data mapping exercise and update the Record of Processing Activities (ROPA) with this project.",
        "Ensure all staff with access to personal data in this project complete data protection training.",
        "Review and sign Data Processing Agreements (DPAs) with all third-party recipients before data sharing begins.",
        "Implement privacy-by-design and privacy-by-default principles from the project outset.",
        "Schedule a PIA review at project launch and annually thereafter, or upon any significant change to processing.",
    ]
    # Add Special Category specific recommendations
    combined = " ".join(data_types).lower()
    for sc in SPECIAL_CATEGORY_TYPES:
        if sc in combined:
            recs.append(
                "Special Category data is processed — ensure Article 9 conditions are met and "
                "an explicit legal basis (e.g., explicit consent or legal obligation) is documented before processing begins."
            )
            break
    # Add risk-specific recommendations
    high_risks = [r for r in risks if r.risk_score in ("High", "Critical")]
    if high_risks:
        recs.append(
            f"Prioritise mitigation of the {len(high_risks)} High/Critical risk(s) identified "
            f"(PR IDs: {', '.join(r.id for r in high_risks)}) before go-live."
        )
    if framework == "iso27701":
        recs.append(
            "Map all processing activities to relevant ISO 27701 controls and include this PIA "
            "in the PIMS (Privacy Information Management System) documentation set."
        )
    return recs


def render_pia(
    project: str,
    data_types: List[str],
    purposes: List[str],
    recipients: List[str],
    retention: str,
    controller: str,
    dpo: str,
    framework: str,
) -> str:
    """Render the complete PIA as a structured markdown document.

    Args:
        project: Project name.
        data_types: List of data types processed.
        purposes: List of processing purposes.
        recipients: List of data recipients.
        retention: Retention period string.
        controller: Data controller name.
        dpo: DPO name or email.
        framework: Framework name (gdpr or iso27701).

    Returns:
        Full PIA markdown string.
    """
    now = datetime.utcnow()
    date_str = now.strftime("%Y-%m-%d")
    datetime_str = now.strftime("%Y-%m-%d %H:%M UTC")

    classified_types = [(dt, *classify_data_type(dt)) for dt in data_types]
    applicable_risks = select_applicable_risks(data_types, purposes)
    dpo_recs = generate_dpo_recommendations(data_types, applicable_risks, framework)

    # Overall project risk level
    risk_levels = [c[2] for c in classified_types]
    if "Very High" in risk_levels:
        overall_risk = "Very High"
    elif "High" in risk_levels:
        overall_risk = "High"
    elif "Medium" in risk_levels:
        overall_risk = "Medium"
    else:
        overall_risk = "Low"

    lines = [
        f"# Privacy Impact Assessment",
        f"## {project}",
        "",
        "---",
        "",
        "## 1. PIA Header",
        "",
        "| Field | Value |",
        "|-------|-------|",
        f"| **Project / System Name** | {project} |",
        f"| **PIA Version** | 1.0 |",
        f"| **Date** | {date_str} |",
        f"| **Framework** | {framework.upper()} |",
        f"| **Data Controller** | {controller or '— (not provided)'} |",
        f"| **Data Protection Officer** | {dpo or '— (not provided)'} |",
        f"| **Overall Risk Level** | **{overall_risk}** |",
        f"| **Generated** | {datetime_str} |",
        "",
        "---",
        "",
        "## 2. Project Overview",
        "",
        f"This Privacy Impact Assessment covers the project **{project}**. "
        f"The assessment evaluates the privacy risks associated with processing "
        f"{len(data_types)} category(ies) of personal data across "
        f"{len(purposes)} stated purpose(s), shared with {len(recipients)} recipient(s), "
        f"and retained for {retention}.",
        "",
        f"**Data Types Processed:** {', '.join(data_types)}  ",
        f"**Processing Purposes:** {', '.join(purposes)}  ",
        f"**Data Recipients:** {', '.join(recipients)}  ",
        f"**Retention Period:** {retention}  ",
        "",
        "---",
        "",
        "## 3. Data Flows",
        "",
        "| Data Type | Risk Level | Source | Purpose | Recipients | Retention |",
        "|-----------|------------|--------|---------|------------|-----------|",
    ]

    for dt, risk_level, risk_note in classified_types:
        for purpose in purposes:
            for recipient in recipients:
                lines.append(
                    f"| {dt} | **{risk_level}** | {project} | {purpose} | {recipient} | {retention} |"
                )
        # Only output one row per data type for readability
        break

    for dt, risk_level, risk_note in classified_types:
        lines.append(
            f"| {dt} | **{risk_level}** | {project} | {', '.join(purposes)} | {', '.join(recipients)} | {retention} |"
        )

    # Remove duplicate header row issue by clearing and rebuilding
    lines_clean = []
    seen_dt: set = set()
    for line in lines:
        if "| Data Type |" in line and line in lines_clean:
            continue
        lines_clean.append(line)
    lines = lines_clean

    # Deduplicate data rows
    lines = []
    lines += [
        f"# Privacy Impact Assessment",
        f"## {project}",
        "",
        "---",
        "",
        "## 1. PIA Header",
        "",
        "| Field | Value |",
        "|-------|-------|",
        f"| **Project / System Name** | {project} |",
        f"| **PIA Version** | 1.0 |",
        f"| **Date** | {date_str} |",
        f"| **Framework** | {framework.upper()} |",
        f"| **Data Controller** | {controller or '— (not provided)'} |",
        f"| **Data Protection Officer** | {dpo or '— (not provided)'} |",
        f"| **Overall Risk Level** | **{overall_risk}** |",
        f"| **Generated** | {datetime_str} |",
        "",
        "---",
        "",
        "## 2. Project Overview",
        "",
        f"This Privacy Impact Assessment covers the project **{project}**. "
        f"The assessment evaluates the privacy risks associated with processing "
        f"{len(data_types)} category(ies) of personal data across "
        f"{len(purposes)} stated purpose(s), shared with {len(recipients)} recipient(s), "
        f"and retained for {retention}.",
        "",
        f"**Data Types Processed:** {', '.join(data_types)}  ",
        f"**Processing Purposes:** {', '.join(purposes)}  ",
        f"**Data Recipients:** {', '.join(recipients)}  ",
        f"**Retention Period:** {retention}  ",
        "",
        "---",
        "",
        "## 3. Data Flows",
        "",
        "| Data Type | Risk Level | Source | Purpose | Recipients | Retention |",
        "|-----------|------------|--------|---------|------------|-----------|",
    ]
    for dt, risk_level, _ in classified_types:
        lines.append(
            f"| {dt} | **{risk_level}** | {project} | {'; '.join(purposes)} | "
            f"{'; '.join(recipients)} | {retention} |"
        )
    lines.append("")

    # Legal basis assessment
    lines += [
        "---",
        "",
        "## 4. Legal Basis Assessment",
        "",
        "| Purpose | Suggested Legal Basis | Notes |",
        "|---------|----------------------|-------|",
    ]
    for purpose in purposes:
        basis = suggest_legal_basis(purpose)
        lines.append(f"| {purpose} | {basis} | Confirm legal basis with legal counsel before processing. |")
    lines.append("")

    if framework == "iso27701":
        lines += [
            "### ISO 27701 Applicable Controls",
            "",
        ]
        for ctrl in ISO27701_CONTROLS:
            lines.append(f"- {ctrl}")
        lines.append("")

    # Risk assessment
    lines += [
        "---",
        "",
        "## 5. Risk Assessment",
        "",
        f"**{len(applicable_risks)} applicable risk(s) identified** based on the data types and purposes provided.",
        "",
        "| Risk ID | Risk | Likelihood | Impact | Risk Score | Mitigation | Residual Risk |",
        "|---------|------|------------|--------|------------|------------|---------------|",
    ]
    for risk in applicable_risks:
        lines.append(
            f"| {risk.id} | {risk.name} | {risk.likelihood} | {risk.impact} | "
            f"**{risk.risk_score}** | {risk.mitigation[:80]}… | {risk.residual_risk} |"
        )
    lines.append("")

    lines += ["### Risk Detail", ""]
    for risk in applicable_risks:
        lines += [
            f"#### {risk.id} — {risk.name}",
            "",
            f"**Description:** {risk.description}  ",
            f"**Likelihood:** {risk.likelihood} | **Impact:** {risk.impact} | **Risk Score:** **{risk.risk_score}**  ",
            f"**Mitigation:** {risk.mitigation}  ",
            f"**Residual Risk after Mitigation:** {risk.residual_risk}",
            "",
        ]

    # Data subject rights
    lines += [
        "---",
        "",
        "## 6. Data Subject Rights Compliance Checklist",
        "",
        "| Right | Legal Reference | Mechanism in Place | Status |",
        "|-------|-----------------|-------------------|--------|",
    ]
    for right, ref in DATA_SUBJECT_RIGHTS:
        lines.append(f"| {right} | {ref} | To be confirmed | ☐ Pending |")
    lines.append("")

    # DPO Recommendations
    lines += [
        "---",
        "",
        "## 7. DPO Recommendations",
        "",
    ]
    for i, rec in enumerate(dpo_recs, 1):
        lines.append(f"{i}. {rec}")
    lines.append("")

    # Sign-off
    lines += [
        "---",
        "",
        "## 8. Sign-off",
        "",
        "| Role | Name | Signature | Date |",
        "|------|------|-----------|------|",
        f"| Data Controller | {controller or '_______________'} | _______________ | ___________ |",
        f"| Data Protection Officer | {dpo or '_______________'} | _______________ | ___________ |",
        "| Project Owner | _______________ | _______________ | ___________ |",
        "| IT Security Lead | _______________ | _______________ | ___________ |",
        "| Legal Counsel | _______________ | _______________ | ___________ |",
        "",
        "---",
        "",
        f"*This PIA was generated by the `pia-generator` skill on {datetime_str}. "
        "It must be reviewed and approved by the Data Protection Officer before "
        "processing commences.*",
    ]

    return "\n".join(lines)


def main() -> None:
    """Entry point for the PIA generator."""
    parser = argparse.ArgumentParser(
        description="Generate a Privacy Impact Assessment (PIA/DPIA) report."
    )
    parser.add_argument("--project", required=True, help="Project or system name.")
    parser.add_argument(
        "--data-types",
        required=True,
        help="Comma-separated list of data types (e.g. 'health,financial,contact_details').",
    )
    parser.add_argument(
        "--purposes",
        required=True,
        help="Comma-separated list of processing purposes.",
    )
    parser.add_argument(
        "--recipients",
        required=True,
        help="Comma-separated list of data recipients.",
    )
    parser.add_argument("--retention", required=True, help="Data retention period.")
    parser.add_argument("--controller", default="", help="Data controller name.")
    parser.add_argument("--dpo", default="", help="DPO name or email.")
    parser.add_argument(
        "--framework",
        choices=["gdpr", "iso27701"],
        default="gdpr",
        help="Compliance framework (default: gdpr).",
    )
    args = parser.parse_args()

    data_types = [d.strip() for d in args.data_types.split(",") if d.strip()]
    purposes = [p.strip() for p in args.purposes.split(",") if p.strip()]
    recipients = [r.strip() for r in args.recipients.split(",") if r.strip()]

    if not data_types:
        print("Error: --data-types must not be empty.", file=sys.stderr)
        sys.exit(1)
    if not purposes:
        print("Error: --purposes must not be empty.", file=sys.stderr)
        sys.exit(1)
    if not recipients:
        print("Error: --recipients must not be empty.", file=sys.stderr)
        sys.exit(1)

    report = render_pia(
        project=args.project,
        data_types=data_types,
        purposes=purposes,
        recipients=recipients,
        retention=args.retention,
        controller=args.controller,
        dpo=args.dpo,
        framework=args.framework,
    )
    print(report)


if __name__ == "__main__":
    main()
