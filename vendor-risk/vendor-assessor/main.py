"""Vendor Risk Assessor — score vendor security posture from questionnaire answers.

Evaluates vendor responses across 5 risk categories using a hardcoded 25-question
questionnaire. Produces a weighted risk score, risk level, and prioritised
recommendations.
"""

import argparse
import json
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Questionnaire definition
# ---------------------------------------------------------------------------

QUESTIONNAIRE: List[Dict[str, Any]] = [
    # Data Security (5 questions)
    {"id": "Q001", "category": "Data Security", "question": "Is all sensitive data encrypted at rest using AES-256 or equivalent?", "weight": 2},
    {"id": "Q002", "category": "Data Security", "question": "Is all data encrypted in transit using TLS 1.2 or higher?", "weight": 2},
    {"id": "Q003", "category": "Data Security", "question": "Is there a formal key management process covering creation, rotation, and deletion?", "weight": 1},
    {"id": "Q004", "category": "Data Security", "question": "Is there a documented data classification policy in place?", "weight": 1},
    {"id": "Q005", "category": "Data Security", "question": "Is there a documented and tested secure data deletion/destruction procedure?", "weight": 1},
    # Business Continuity (5 questions)
    {"id": "Q006", "category": "Business Continuity", "question": "Are RTO and RPO targets formally defined and documented for critical services?", "weight": 2},
    {"id": "Q007", "category": "Business Continuity", "question": "Has the disaster recovery plan been tested in the last 12 months?", "weight": 2},
    {"id": "Q008", "category": "Business Continuity", "question": "Is there redundant infrastructure (multi-AZ, multi-region, or equivalent)?", "weight": 1},
    {"id": "Q009", "category": "Business Continuity", "question": "Is there a documented and tested incident response plan?", "weight": 1},
    {"id": "Q010", "category": "Business Continuity", "question": "Are automated backups performed at least daily with tested restore capability?", "weight": 1},
    # Compliance (5 questions)
    {"id": "Q011", "category": "Compliance", "question": "Does the vendor hold relevant certifications (SOC2 Type II, ISO27001, or PCI-DSS)?", "weight": 2},
    {"id": "Q012", "category": "Compliance", "question": "Is the vendor compliant with applicable data protection regulations (GDPR, CCPA, etc.)?", "weight": 2},
    {"id": "Q013", "category": "Compliance", "question": "Does the contract include a right-to-audit clause?", "weight": 2},
    {"id": "Q014", "category": "Compliance", "question": "Does the vendor commit to breach notification within 72 hours?", "weight": 1},
    {"id": "Q015", "category": "Compliance", "question": "Are sub-processor agreements in place and sub-processors listed?", "weight": 1},
    # Access Control (5 questions)
    {"id": "Q016", "category": "Access Control", "question": "Is MFA enforced for all user access to production systems?", "weight": 2},
    {"id": "Q017", "category": "Access Control", "question": "Is access provisioned on least-privilege principles with regular reviews?", "weight": 2},
    {"id": "Q018", "category": "Access Control", "question": "Are access reviews conducted at least quarterly for privileged accounts?", "weight": 1},
    {"id": "Q019", "category": "Access Control", "question": "Is there a formal privileged account management (PAM) solution in place?", "weight": 1},
    {"id": "Q020", "category": "Access Control", "question": "Is there a documented and enforced off-boarding process to revoke access?", "weight": 1},
    # Incident Response (5 questions)
    {"id": "Q021", "category": "Incident Response", "question": "Is there a documented information security incident response process?", "weight": 2},
    {"id": "Q022", "category": "Incident Response", "question": "What is the guaranteed SLA for notifying customers of security incidents?", "weight": 2},
    {"id": "Q023", "category": "Incident Response", "question": "Does the vendor have forensic investigation capability (internal or contracted)?", "weight": 1},
    {"id": "Q024", "category": "Incident Response", "question": "Has the vendor disclosed all past security incidents in the last 3 years?", "weight": 1},
    {"id": "Q025", "category": "Incident Response", "question": "Has the vendor conducted penetration testing in the last 12 months?", "weight": 2},
]

SCORE_MAP = {"yes": 100, "partial": 50, "no": 0}
CATEGORIES = ["Data Security", "Business Continuity", "Compliance", "Access Control", "Incident Response"]

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Score vendor risk posture from questionnaire answers."
    )
    parser.add_argument("--answers", required=True, help='Path to JSON: {"Q001": "yes", ...}')
    parser.add_argument("--weights", help='Path to JSON: {"Data Security": 1.5, ...}')
    parser.add_argument("--output", choices=["markdown", "json"], default="markdown")
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


def load_answers(path: str) -> Dict[str, str]:
    """Load and validate answers JSON.

    Args:
        path: Path to answers JSON file.

    Returns:
        Dict mapping question ID to answer string.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        print(f"ERROR: Answers file not found: '{path}'", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as exc:
        print(f"ERROR: Invalid JSON in answers file — {exc}", file=sys.stderr)
        sys.exit(1)

    valid = set(SCORE_MAP.keys()) | {"na"}
    for qid, ans in data.items():
        if ans.lower() not in valid:
            print(
                f"ERROR: Invalid answer '{ans}' for '{qid}'. "
                f"Valid: {', '.join(valid)}",
                file=sys.stderr,
            )
            sys.exit(1)
    return {k: v.lower() for k, v in data.items()}


def load_weights(path: str) -> Dict[str, float]:
    """Load category weights from JSON file.

    Args:
        path: Path to weights JSON file.

    Returns:
        Dict mapping category name to weight float.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        print(f"ERROR: Weights file not found: '{path}'", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as exc:
        print(f"ERROR: Invalid JSON in weights file — {exc}", file=sys.stderr)
        sys.exit(1)


def score(answers: Dict[str, str], weights: Dict[str, float]) -> Tuple[Dict[str, float], float, str]:
    """Compute category and overall scores.

    Args:
        answers: Question ID to answer mapping.
        weights: Category name to weight mapping.

    Returns:
        Tuple of (category_scores, overall_score, risk_level).
    """
    cat_scores: Dict[str, float] = {}

    for cat in CATEGORIES:
        cat_qs = [q for q in QUESTIONNAIRE if q["category"] == cat]
        total_weight = 0.0
        weighted_score = 0.0
        for q in cat_qs:
            ans = answers.get(q["id"], "na")
            if ans == "na":
                continue
            w = q["weight"]
            total_weight += w
            weighted_score += SCORE_MAP.get(ans, 0) * w
        cat_scores[cat] = round(weighted_score / total_weight, 1) if total_weight > 0 else 0.0

    # Overall weighted score across categories
    total_cat_weight = sum(weights.get(c, 1.0) for c in CATEGORIES)
    overall = sum(cat_scores[c] * weights.get(c, 1.0) for c in CATEGORIES) / total_cat_weight
    overall = round(overall, 1)

    if overall >= 80:
        risk_level = "Low"
    elif overall >= 60:
        risk_level = "Medium"
    elif overall >= 40:
        risk_level = "High"
    else:
        risk_level = "Critical"

    return cat_scores, overall, risk_level


def top_recommendations(answers: Dict[str, str]) -> List[Dict[str, Any]]:
    """Return top 5 recommendations based on lowest-scoring questions.

    Args:
        answers: Question ID to answer mapping.

    Returns:
        List of top 5 question dicts with answer attached.
    """
    scored = []
    for q in QUESTIONNAIRE:
        ans = answers.get(q["id"], "na")
        if ans == "na":
            continue
        s = SCORE_MAP.get(ans, 0)
        scored.append((s, q, ans))
    scored.sort(key=lambda x: (x[0], -x[1]["weight"]))
    return [{"question": q, "answer": a, "score": s} for s, q, a in scored[:5]]


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

RISK_EMOJI = {"Low": "🟢", "Medium": "🟡", "High": "🟠", "Critical": "🔴"}


def score_bar(score: float, width: int = 20) -> str:
    """Generate ASCII score bar.

    Args:
        score: Score 0–100.
        width: Bar width.

    Returns:
        ASCII bar string.
    """
    filled = int((score / 100) * width)
    return "█" * filled + "░" * (width - filled)


def render_markdown(
    answers: Dict[str, str],
    cat_scores: Dict[str, float],
    overall: float,
    risk_level: str,
    recs: List[Dict],
) -> str:
    """Render the vendor assessment markdown report."""
    date_str = datetime.now().strftime("%Y-%m-%d")
    lines: List[str] = []

    lines.append("# Vendor Risk Assessment Report\n")
    lines.append(f"**Date:** {date_str}  ")
    lines.append(f"**Questions Answered:** {sum(1 for v in answers.values() if v != 'na')} / {len(QUESTIONNAIRE)}  ")
    lines.append(f"**Overall Score:** {overall}/100  ")
    lines.append(f"**Risk Level:** {RISK_EMOJI.get(risk_level, '')} **{risk_level}**\n")
    lines.append("---\n")

    lines.append("## Category Scores\n")
    lines.append("| Category | Score | Visual |")
    lines.append("|----------|-------|--------|")
    for cat in CATEGORIES:
        s = cat_scores[cat]
        bar = score_bar(s)
        lines.append(f"| {cat} | {s}/100 | `{bar}` |")
    lines.append("")

    lines.append("---\n")
    lines.append(f"## Overall Risk: {RISK_EMOJI.get(risk_level, '')} {risk_level} ({overall}/100)\n")
    lines.append("| Score Range | Risk Level |")
    lines.append("|-------------|------------|")
    lines.append("| 80–100 | 🟢 Low |")
    lines.append("| 60–79  | 🟡 Medium |")
    lines.append("| 40–59  | 🟠 High |")
    lines.append("| 0–39   | 🔴 Critical |")
    lines.append("")

    lines.append("---\n")
    lines.append("## Top 5 Recommendations\n")
    for i, rec in enumerate(recs, 1):
        q = rec["question"]
        ans = rec["answer"]
        lines.append(f"**{i}. [{q['category']}]** {q['question']}  ")
        lines.append(f"*Current answer: `{ans}`* — Remediate this to improve your score.\n")

    lines.append("---\n")
    lines.append("## Appendix — Full Answers\n")
    lines.append("| ID | Category | Question | Answer | Score |")
    lines.append("|----|----------|----------|--------|-------|")
    for q in QUESTIONNAIRE:
        ans = answers.get(q["id"], "na")
        s = SCORE_MAP.get(ans, "N/A")
        lines.append(f"| {q['id']} | {q['category']} | {q['question']} | `{ans}` | {s} |")
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Main entry point."""
    args = parse_args()
    answers = load_answers(args.answers)
    weights = load_weights(args.weights) if args.weights else {c: 1.0 for c in CATEGORIES}
    cat_scores, overall, risk_level = score(answers, weights)
    recs = top_recommendations(answers)

    if args.output == "json":
        print(json.dumps({
            "overall_score": overall,
            "risk_level": risk_level,
            "category_scores": cat_scores,
            "recommendations": [{"id": r["question"]["id"], "question": r["question"]["question"], "answer": r["answer"]} for r in recs],
        }, indent=2))
    else:
        print(render_markdown(answers, cat_scores, overall, risk_level, recs))


if __name__ == "__main__":
    main()
