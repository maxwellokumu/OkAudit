"""Consent & Privacy Policy Checker.

Analyses a privacy policy text file against built-in requirement libraries
for GDPR, CCPA, or PDPA (Thailand). Produces a weighted compliance score
and detailed gap analysis report.
"""

import argparse
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Tuple

from dotenv import load_dotenv

load_dotenv()


@dataclass
class Requirement:
    """A single privacy framework requirement."""

    id: str
    description: str
    keywords: List[str]
    synonyms: List[str]
    weight: int  # 1 (low) to 5 (critical)
    risk: str
    recommendation: str


# ---------------------------------------------------------------------------
# Requirement libraries
# ---------------------------------------------------------------------------

GDPR_REQUIREMENTS: List[Requirement] = [
    Requirement(
        id="GDPR-01",
        description="Identity and contact details of the data controller",
        keywords=["controller", "data controller", "company name", "organisation", "who we are"],
        synonyms=["responsible party", "data owner", "we are"],
        weight=5,
        risk="Critical — data subjects cannot identify who is responsible for their data.",
        recommendation="Clearly state the full legal name, address, and contact details of the data controller.",
    ),
    Requirement(
        id="GDPR-02",
        description="Purposes of processing personal data",
        keywords=["purpose", "why we collect", "how we use", "use your data", "processing purposes"],
        synonyms=["reason for collecting", "why we process", "use of information"],
        weight=5,
        risk="Critical — processing without stated purpose is unlawful under GDPR Art. 5(1)(b).",
        recommendation="List all specific purposes for which personal data is processed.",
    ),
    Requirement(
        id="GDPR-03",
        description="Legal basis for processing",
        keywords=["legal basis", "lawful basis", "legitimate interests", "consent", "contract", "legal obligation"],
        synonyms=["lawfulness", "basis for processing", "we process because"],
        weight=5,
        risk="Critical — processing requires a valid legal basis under GDPR Art. 6.",
        recommendation="State the specific legal basis for each processing activity.",
    ),
    Requirement(
        id="GDPR-04",
        description="Recipients or categories of recipients of personal data",
        keywords=["share", "third party", "recipients", "disclose", "transfer to", "we share"],
        synonyms=["partner", "processor", "service provider", "third-party"],
        weight=4,
        risk="High — data subjects must know who receives their data.",
        recommendation="List all third parties or categories of recipients who receive personal data.",
    ),
    Requirement(
        id="GDPR-05",
        description="Data retention periods",
        keywords=["retention", "how long", "keep your data", "store for", "delete", "retain"],
        synonyms=["storage period", "duration", "we keep", "data held for"],
        weight=4,
        risk="High — indefinite retention violates GDPR storage limitation principle.",
        recommendation="State specific retention periods or criteria for determining them.",
    ),
    Requirement(
        id="GDPR-06",
        description="Right of access to personal data",
        keywords=["right to access", "access your data", "subject access", "SAR", "access request"],
        synonyms=["view your information", "request a copy", "data access"],
        weight=4,
        risk="High — failure to inform of access rights violates GDPR Art. 15.",
        recommendation="Explicitly state the data subject's right to request access to their personal data.",
    ),
    Requirement(
        id="GDPR-07",
        description="Right to erasure (right to be forgotten)",
        keywords=["right to erasure", "right to be forgotten", "delete your data", "erasure", "deletion request"],
        synonyms=["remove your data", "request deletion", "erase personal data"],
        weight=4,
        risk="High — GDPR Art. 17 requires data subjects to be informed of this right.",
        recommendation="State the right to erasure and the conditions under which it applies.",
    ),
    Requirement(
        id="GDPR-08",
        description="Right to data portability",
        keywords=["portability", "data portability", "portable format", "transfer your data", "machine-readable"],
        synonyms=["export your data", "receive your data", "structured format"],
        weight=3,
        risk="Medium — GDPR Art. 20 right to portability must be communicated.",
        recommendation="Inform data subjects of their right to receive data in a structured, machine-readable format.",
    ),
    Requirement(
        id="GDPR-09",
        description="Right to rectification of inaccurate data",
        keywords=["rectification", "correct your data", "update your information", "accurate", "inaccurate"],
        synonyms=["amend your data", "right to correct", "fix your information"],
        weight=3,
        risk="Medium — GDPR Art. 16 requires informing data subjects of rectification rights.",
        recommendation="State the right to request correction of inaccurate personal data.",
    ),
    Requirement(
        id="GDPR-10",
        description="Right to restrict processing",
        keywords=["restrict processing", "restriction", "limit processing", "right to restrict"],
        synonyms=["suspend processing", "pause data use", "processing restriction"],
        weight=3,
        risk="Medium — GDPR Art. 18 restriction right must be communicated.",
        recommendation="Inform data subjects of their right to restrict processing in specified circumstances.",
    ),
    Requirement(
        id="GDPR-11",
        description="Right to object to processing",
        keywords=["right to object", "object to processing", "opt out", "oppose processing"],
        synonyms=["object to use", "oppose", "right to stop processing"],
        weight=3,
        risk="Medium — GDPR Art. 21 objection right must be clearly stated.",
        recommendation="Inform data subjects of their right to object, particularly for direct marketing.",
    ),
    Requirement(
        id="GDPR-12",
        description="Right to withdraw consent",
        keywords=["withdraw consent", "revoke consent", "withdraw your consent", "opt out", "unsubscribe"],
        synonyms=["remove consent", "cancel consent", "consent withdrawal"],
        weight=4,
        risk="High — GDPR Art. 7(3) requires ability to withdraw consent at any time.",
        recommendation="Clearly state that consent can be withdrawn at any time and explain how.",
    ),
    Requirement(
        id="GDPR-13",
        description="Right to lodge a complaint with a supervisory authority",
        keywords=["supervisory authority", "data protection authority", "ICO", "complaint", "lodge a complaint", "supervisory"],
        synonyms=["regulatory body", "data regulator", "DPA", "report to authority"],
        weight=3,
        risk="Medium — GDPR Art. 77 requires informing data subjects of complaint rights.",
        recommendation="State the right to lodge a complaint with the relevant data protection authority.",
    ),
    Requirement(
        id="GDPR-14",
        description="Automated decision-making and profiling disclosure",
        keywords=["automated", "profiling", "automated decision", "automated processing", "solely automated"],
        synonyms=["algorithm", "automated assessment", "automated scoring"],
        weight=3,
        risk="Medium — GDPR Art. 22 requires disclosure of automated decision-making.",
        recommendation="Disclose any automated decision-making or profiling and its significance.",
    ),
    Requirement(
        id="GDPR-15",
        description="International data transfers and safeguards",
        keywords=["international transfer", "transfer outside", "third country", "adequacy", "standard contractual", "SCCs", "cross-border"],
        synonyms=["overseas transfer", "data exported", "non-EEA", "outside EU"],
        weight=4,
        risk="High — transfers outside EEA require appropriate safeguards under GDPR Ch. V.",
        recommendation="Disclose international transfers and the safeguards in place (e.g., SCCs, adequacy decisions).",
    ),
    Requirement(
        id="GDPR-16",
        description="Data Protection Officer (DPO) contact details",
        keywords=["data protection officer", "DPO", "dpo@", "privacy officer"],
        synonyms=["privacy contact", "data officer"],
        weight=2,
        risk="Low — required where DPO is mandatory under GDPR Art. 37.",
        recommendation="Include DPO contact details where a DPO has been appointed.",
    ),
]

CCPA_REQUIREMENTS: List[Requirement] = [
    Requirement(
        id="CCPA-01",
        description="Right to know what personal information is collected",
        keywords=["categories of personal information", "types of data collected", "what we collect", "personal information we collect"],
        synonyms=["information collected", "data we gather", "personal data collected"],
        weight=5,
        risk="Critical — CCPA §1798.100 requires disclosure of PI categories collected.",
        recommendation="List all categories of personal information collected in the preceding 12 months.",
    ),
    Requirement(
        id="CCPA-02",
        description="Right to delete personal information",
        keywords=["right to delete", "delete your information", "deletion request", "request deletion"],
        synonyms=["remove your data", "erase your information", "right to erasure"],
        weight=5,
        risk="Critical — CCPA §1798.105 requires disclosure of deletion rights.",
        recommendation="Clearly state the right to request deletion and the process for submitting requests.",
    ),
    Requirement(
        id="CCPA-03",
        description="Right to opt-out of sale of personal information",
        keywords=["do not sell", "opt-out of sale", "sale of personal information", "sell your data", "opt out of sale"],
        synonyms=["selling information", "personal data sale", "data sale opt-out"],
        weight=5,
        risk="Critical — CCPA §1798.120 requires 'Do Not Sell My Personal Information' link/notice.",
        recommendation="Include a clear opt-out mechanism for the sale of personal information.",
    ),
    Requirement(
        id="CCPA-04",
        description="Right to non-discrimination for exercising privacy rights",
        keywords=["non-discrimination", "no discrimination", "will not discriminate", "equal service"],
        synonyms=["no penalty", "same service", "no retaliation"],
        weight=4,
        risk="High — CCPA §1798.125 prohibits discrimination against consumers exercising rights.",
        recommendation="State that consumers will not be discriminated against for exercising CCPA rights.",
    ),
    Requirement(
        id="CCPA-05",
        description="Categories of personal information collected",
        keywords=["categories", "identifiers", "commercial information", "geolocation", "inferences"],
        synonyms=["types of PI", "data categories", "information types"],
        weight=4,
        risk="High — specific PI categories must be disclosed under CCPA.",
        recommendation="List all CCPA-defined categories of PI collected (identifiers, commercial info, etc.).",
    ),
    Requirement(
        id="CCPA-06",
        description="Purposes for collecting personal information",
        keywords=["purpose", "why we collect", "business purpose", "commercial purpose", "use your information"],
        synonyms=["reason for collection", "how we use", "processing purposes"],
        weight=4,
        risk="High — business and commercial purposes must be disclosed.",
        recommendation="State the business or commercial purposes for each category of PI collected.",
    ),
    Requirement(
        id="CCPA-07",
        description="Third parties personal information is shared with",
        keywords=["third party", "share", "disclose to", "business partners", "service providers"],
        synonyms=["third-party sharing", "data recipients", "who we share with"],
        weight=4,
        risk="High — categories of third parties must be identified.",
        recommendation="List categories of third parties with whom personal information is shared or sold.",
    ),
    Requirement(
        id="CCPA-08",
        description="12-month lookback period for PI collection disclosure",
        keywords=["12 months", "twelve months", "past year", "preceding 12 months", "last year"],
        synonyms=["prior year", "previous 12 months"],
        weight=3,
        risk="Medium — CCPA requires disclosure covering the preceding 12-month period.",
        recommendation="Specify that disclosures cover personal information collected in the preceding 12 months.",
    ),
    Requirement(
        id="CCPA-09",
        description="Verifiable consumer request process",
        keywords=["verifiable request", "submit a request", "consumer request", "privacy request", "contact us"],
        synonyms=["request process", "how to request", "submit request"],
        weight=4,
        risk="High — consumers must have a clear mechanism to submit requests.",
        recommendation="Provide at least two methods for submitting verifiable consumer requests (e.g., web form + toll-free number).",
    ),
    Requirement(
        id="CCPA-10",
        description="Financial incentive disclosure for data collection",
        keywords=["financial incentive", "price difference", "loyalty program", "reward", "discount for data"],
        synonyms=["incentive program", "data for discount"],
        weight=2,
        risk="Low — required if financial incentives are offered for providing PI.",
        recommendation="Disclose any financial incentives offered in exchange for personal information.",
    ),
    Requirement(
        id="CCPA-11",
        description="Contact information for privacy requests",
        keywords=["contact", "privacy@", "email us", "call us", "toll-free", "phone number"],
        synonyms=["reach us", "privacy contact", "contact details"],
        weight=3,
        risk="Medium — consumers must be able to contact the business to exercise rights.",
        recommendation="Provide clear contact information (email and/or toll-free number) for privacy requests.",
    ),
]

PDPA_REQUIREMENTS: List[Requirement] = [
    Requirement(
        id="PDPA-01",
        description="Consent requirements for data collection",
        keywords=["consent", "explicit consent", "freely given", "informed consent", "you agree"],
        synonyms=["permission", "agreement", "opt-in"],
        weight=5,
        risk="Critical — PDPA requires valid consent for most personal data processing.",
        recommendation="State how consent is obtained, what it covers, and how it can be withdrawn.",
    ),
    Requirement(
        id="PDPA-02",
        description="Data subject rights (access, correction, deletion, portability)",
        keywords=["right to access", "right to correct", "right to delete", "right to erasure", "data portability"],
        synonyms=["your rights", "subject rights", "data rights"],
        weight=5,
        risk="Critical — PDPA Sections 30-37 mandate disclosure of data subject rights.",
        recommendation="List all data subject rights available under PDPA including access, correction, deletion, and portability.",
    ),
    Requirement(
        id="PDPA-03",
        description="Identity of the data controller",
        keywords=["data controller", "controller", "company", "organisation", "who we are"],
        synonyms=["responsible entity", "data owner", "controller identity"],
        weight=5,
        risk="Critical — data subjects must know who controls their data.",
        recommendation="Clearly identify the data controller with full legal name and contact details.",
    ),
    Requirement(
        id="PDPA-04",
        description="Purpose limitation for data processing",
        keywords=["purpose", "why we collect", "how we use", "specific purpose", "limited to"],
        synonyms=["processing purpose", "reason for collection"],
        weight=5,
        risk="Critical — PDPA requires processing only for specified, explicit purposes.",
        recommendation="State all specific purposes for which personal data is collected and processed.",
    ),
    Requirement(
        id="PDPA-05",
        description="Data retention periods",
        keywords=["retention", "how long", "keep your data", "storage period", "delete after"],
        synonyms=["duration", "stored for", "data held"],
        weight=4,
        risk="High — PDPA requires data not be retained longer than necessary.",
        recommendation="State retention periods for each category of personal data.",
    ),
    Requirement(
        id="PDPA-06",
        description="Security measures for protecting personal data",
        keywords=["security", "protect", "safeguard", "encryption", "secure", "technical measures"],
        synonyms=["data protection measures", "security controls", "organisational measures"],
        weight=4,
        risk="High — PDPA requires appropriate security measures to be disclosed.",
        recommendation="Describe the technical and organisational security measures used to protect personal data.",
    ),
    Requirement(
        id="PDPA-07",
        description="Cross-border data transfer disclosure",
        keywords=["international transfer", "cross-border", "transfer outside", "overseas", "foreign country"],
        synonyms=["abroad", "outside Thailand", "overseas transfer"],
        weight=4,
        risk="High — PDPA Section 28 restricts cross-border transfers without adequate protection.",
        recommendation="Disclose any cross-border data transfers and the safeguards or conditions applied.",
    ),
    Requirement(
        id="PDPA-08",
        description="Data Protection Officer (DPO) appointment",
        keywords=["data protection officer", "DPO", "privacy officer", "dpo@"],
        synonyms=["data officer", "privacy contact"],
        weight=3,
        risk="Medium — required for certain data controllers under PDPA.",
        recommendation="Include DPO contact details where a DPO has been appointed.",
    ),
    Requirement(
        id="PDPA-09",
        description="Breach notification rights",
        keywords=["data breach", "breach notification", "notify you", "security incident", "breach"],
        synonyms=["data incident", "security breach", "breach report"],
        weight=3,
        risk="Medium — PDPA requires notification of affected data subjects in case of breach.",
        recommendation="State the process for notifying data subjects in the event of a data breach.",
    ),
    Requirement(
        id="PDPA-10",
        description="Complaint mechanism",
        keywords=["complaint", "lodge a complaint", "raise concern", "PDPC", "supervisory authority"],
        synonyms=["complain", "report issue", "raise complaint", "regulatory authority"],
        weight=3,
        risk="Medium — data subjects must be informed of how to raise complaints.",
        recommendation="Provide a clear process for data subjects to raise complaints, including contact details for PDPC.",
    ),
]

FRAMEWORKS: Dict[str, List[Requirement]] = {
    "gdpr": GDPR_REQUIREMENTS,
    "ccpa": CCPA_REQUIREMENTS,
    "pdpa": PDPA_REQUIREMENTS,
}


@dataclass
class CheckResult:
    """Result of checking a single requirement against a policy."""

    requirement: Requirement
    met: bool
    matched_on: str  # keyword or phrase that matched


def check_requirement(req: Requirement, policy_text: str) -> CheckResult:
    """Check whether a policy text satisfies a single requirement.

    Searches for keywords and synonyms using case-insensitive matching.
    A requirement is considered met if any keyword or synonym appears.

    Args:
        req: The requirement to check.
        policy_text: The full policy text (lowercased).

    Returns:
        CheckResult with met status and matched term.
    """
    text = policy_text.lower()
    for kw in req.keywords + req.synonyms:
        if kw.lower() in text:
            return CheckResult(requirement=req, met=True, matched_on=kw)
    return CheckResult(requirement=req, met=False, matched_on="")


def load_policy(path: str) -> str:
    """Load policy text from a file.

    Args:
        path: Filesystem path to the policy text file.

    Returns:
        Policy text string.

    Raises:
        SystemExit: If the file does not exist or cannot be read.
    """
    if not os.path.isfile(path):
        print(f"Error: Policy file not found: {path}", file=sys.stderr)
        sys.exit(1)
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except OSError as exc:
        print(f"Error reading policy file: {exc}", file=sys.stderr)
        sys.exit(1)


def compute_score(results: List[CheckResult]) -> Tuple[float, int, int]:
    """Compute a weighted compliance score.

    Args:
        results: List of all check results.

    Returns:
        Tuple of (score_percent, earned_points, total_points).
    """
    total = sum(r.requirement.weight for r in results)
    earned = sum(r.requirement.weight for r in results if r.met)
    pct = (earned / total * 100) if total else 0.0
    return pct, earned, total


def score_rating(pct: float) -> str:
    """Convert a percentage score to a compliance rating label.

    Args:
        pct: Percentage score (0-100).

    Returns:
        Rating label string.
    """
    if pct >= 85:
        return "Compliant"
    if pct >= 60:
        return "Partial"
    return "Non-Compliant"


def render_report(
    policy_path: str,
    framework: str,
    results: List[CheckResult],
    policy_text: str,
) -> str:
    """Render the compliance analysis as a markdown report.

    Args:
        policy_path: Path to the policy file (for display).
        framework: Framework name.
        results: All check results.
        policy_text: Original policy text (for word count).

    Returns:
        Markdown string.
    """
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    met = [r for r in results if r.met]
    missing = [r for r in results if not r.met]
    pct, earned, total = compute_score(results)
    rating = score_rating(pct)

    rating_emoji = {"Compliant": "✅", "Partial": "⚠️", "Non-Compliant": "❌"}.get(rating, "")
    word_count = len(policy_text.split())

    lines = [
        "# Privacy Policy Compliance Report",
        "",
        f"**Generated:** {now}",
        f"**Policy File:** `{policy_path}`",
        f"**Framework:** {framework.upper()}",
        f"**Policy Word Count:** {word_count}",
        "",
        "## Compliance Score",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Requirements Checked | {len(results)} |",
        f"| Requirements Met | {len(met)} |",
        f"| Requirements Missing | {len(missing)} |",
        f"| Weighted Score | {earned}/{total} points ({pct:.1f}%) |",
        f"| Overall Rating | {rating_emoji} **{rating}** |",
        "",
    ]

    if met:
        lines += [
            "## Requirements Met",
            "",
            "| ID | Requirement | Matched On | Status |",
            "|----|-------------|------------|--------|",
        ]
        for r in met:
            lines.append(
                f"| {r.requirement.id} | {r.requirement.description} | "
                f"`{r.matched_on}` | ✅ Met |"
            )
        lines.append("")

    if missing:
        lines += [
            "## Missing Requirements",
            "",
            "| ID | Requirement | Weight | Risk | Recommendation |",
            "|----|-------------|--------|------|----------------|",
        ]
        sorted_missing = sorted(missing, key=lambda r: -r.requirement.weight)
        for r in sorted_missing:
            lines.append(
                f"| {r.requirement.id} | {r.requirement.description} | "
                f"{r.requirement.weight}/5 | {r.requirement.risk.split('—')[0].strip()} | "
                f"{r.requirement.recommendation} |"
            )
        lines.append("")

        lines += [
            "## Detailed Gap Analysis",
            "",
        ]
        for r in sorted_missing:
            lines += [
                f"### {r.requirement.id} — {r.requirement.description}",
                "",
                f"**Weight:** {r.requirement.weight}/5  ",
                f"**Risk:** {r.requirement.risk}  ",
                f"**Recommendation:** {r.requirement.recommendation}",
                "",
            ]
    else:
        lines += ["## Missing Requirements", "", "All requirements are met.", ""]

    return "\n".join(lines)


def main() -> None:
    """Entry point for the consent and privacy policy checker."""
    parser = argparse.ArgumentParser(
        description="Check a privacy policy against GDPR, CCPA, or PDPA requirements."
    )
    parser.add_argument("--policy", required=True, help="Path to privacy policy .txt file.")
    parser.add_argument(
        "--framework",
        choices=["gdpr", "ccpa", "pdpa"],
        default="gdpr",
        help="Compliance framework to check against (default: gdpr).",
    )
    args = parser.parse_args()

    requirements = FRAMEWORKS.get(args.framework, GDPR_REQUIREMENTS)
    policy_text = load_policy(args.policy)

    if not policy_text.strip():
        print("Error: Policy file is empty.", file=sys.stderr)
        sys.exit(1)

    results = [check_requirement(req, policy_text) for req in requirements]
    print(render_report(args.policy, args.framework, results, policy_text))


if __name__ == "__main__":
    main()
