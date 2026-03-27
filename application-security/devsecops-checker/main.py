"""DevSecOps Pipeline Security Checker.

Analyses CI/CD configuration files (GitHub Actions, GitLab CI, Jenkins)
for the presence of 8 security controls and produces a maturity score.
"""

import argparse
import json
import sys
from datetime import datetime
from typing import Dict, List, Optional, Tuple

# Security controls: (name, keywords, risk_if_missing)
CONTROLS: List[Dict] = [
    {
        "name": "SAST",
        "description": "Static Application Security Testing",
        "keywords": ["bandit", "semgrep", "sonarqube", "checkmarx", "veracode", "snyk", "fortify", "sonar"],
        "risk_if_missing": "Vulnerable code patterns reach production undetected",
        "quick_win": "Add `bandit -r . -f json` step (Python) or `semgrep --config=auto` (any language)",
        "priority": 1,
    },
    {
        "name": "SCA / Dependency Scan",
        "description": "Software Composition Analysis for known-vulnerable dependencies",
        "keywords": ["snyk", "dependabot", "safety", "owasp-dependency-check", "trivy", "dependency-check"],
        "risk_if_missing": "Third-party packages with known CVEs shipped to production",
        "quick_win": "Enable Dependabot alerts in GitHub or add `safety check` step for Python",
        "priority": 2,
    },
    {
        "name": "Secrets Scanner",
        "description": "Prevent credentials and secrets from being committed",
        "keywords": ["gitleaks", "trufflehog", "detect-secrets", "git-secrets", "talisman", "secretlint"],
        "risk_if_missing": "API keys, passwords, and certificates exposed in version control history",
        "quick_win": "Add `gitleaks detect --source . --exit-code 1` as a pre-commit and CI step",
        "priority": 1,
    },
    {
        "name": "Container Image Scan",
        "description": "Scan container images for OS and application vulnerabilities",
        "keywords": ["trivy", "snyk container", "anchore", "clair", "grype", "aqua", "docker scout"],
        "risk_if_missing": "Container images with critical OS vulnerabilities deployed to production",
        "quick_win": "Add `trivy image --exit-code 1 --severity CRITICAL myimage:tag` to build pipeline",
        "priority": 3,
    },
    {
        "name": "DAST",
        "description": "Dynamic Application Security Testing against running application",
        "keywords": ["owasp-zap", "zap", "burp", "nikto", "dastardly", "owaspzap"],
        "risk_if_missing": "Runtime vulnerabilities (XSS, injection, misconfigs) not caught before release",
        "quick_win": "Add OWASP ZAP baseline scan against staging environment in release pipeline",
        "priority": 4,
    },
    {
        "name": "Approval / Manual Gate",
        "description": "Human approval gate before production deployment",
        "keywords": ["manual", "approval", "environment:", "when: manual", "protection_rules", "reviewers"],
        "risk_if_missing": "Automated deployment to production without human review increases risk of incidents",
        "quick_win": "Add `environment: production` with required reviewers in GitHub Actions",
        "priority": 5,
    },
    {
        "name": "Environment Separation",
        "description": "Separate staging/test and production deployment jobs",
        "keywords": ["staging", "stage", "production", "prod", "deploy-staging", "deploy-prod", "environment"],
        "risk_if_missing": "No pre-production testing environment; changes go directly to production",
        "quick_win": "Create separate deploy-staging and deploy-production jobs with promotion logic",
        "priority": 5,
    },
    {
        "name": "Artifact Signing",
        "description": "Cryptographic signing of build artifacts for supply chain integrity",
        "keywords": ["cosign", "sigstore", "notation", "gpg sign", "sign-image", "artifact-sign"],
        "risk_if_missing": "Build artifacts can be tampered with in transit without detection",
        "quick_win": "Add `cosign sign` step using GitHub OIDC for keyless signing",
        "priority": 6,
    },
]

MATURITY_LEVELS = [
    (0, 25, "Initial", "❶", "Minimal security controls. Significant exposure to supply chain and runtime attacks."),
    (26, 50, "Developing", "❷", "Basic controls in place. Critical gaps remain in dynamic testing and artifact integrity."),
    (51, 75, "Defined", "❸", "Solid security foundation. Focus on DAST, environment gates, and artifact signing."),
    (76, 100, "Optimised", "❹", "Comprehensive DevSecOps posture. Continue to tune thresholds and add threat modelling."),
]

POINTS_PER_CONTROL = 12.5  # 8 controls × 12.5 = 100


def detect_pipeline_type(content: str) -> str:
    """Auto-detect CI/CD pipeline type from file content.

    Args:
        content: Raw YAML file content as string.

    Returns:
        Pipeline type string: 'GitHub Actions', 'GitLab CI', 'Jenkins', or 'Unknown'.
    """
    if ("on:" in content or '"on":' in content) and "jobs:" in content:
        return "GitHub Actions"
    if "stages:" in content or ('image:' in content and 'script:' in content):
        return "GitLab CI"
    if "pipeline" in content and "stages" in content and "steps" in content:
        return "Jenkins"
    # Fallback heuristics
    if "workflow" in content and "job" in content:
        return "GitHub Actions"
    if "stage:" in content and "script:" in content:
        return "GitLab CI"
    return "Unknown"


def check_controls(content: str) -> List[Dict]:
    """Check which security controls are present in the pipeline config.

    Args:
        content: Pipeline YAML content (lowercased for matching).

    Returns:
        List of control result dicts.
    """
    content_lower = content.lower()
    results = []
    for ctrl in CONTROLS:
        detected_tool: Optional[str] = None
        for kw in ctrl["keywords"]:
            if kw.lower() in content_lower:
                detected_tool = kw
                break
        results.append(
            {
                "name": ctrl["name"],
                "description": ctrl["description"],
                "present": detected_tool is not None,
                "detected_tool": detected_tool or "",
                "risk_if_missing": ctrl["risk_if_missing"],
                "quick_win": ctrl["quick_win"],
                "priority": ctrl["priority"],
            }
        )
    return results


def compute_maturity(results: List[Dict]) -> Tuple[float, str, str, str]:
    """Compute maturity score from control results.

    Args:
        results: Control check results.

    Returns:
        Tuple of (score, level_name, level_icon, level_description).
    """
    present_count = sum(1 for r in results if r["present"])
    score = present_count * POINTS_PER_CONTROL
    for low, high, name, icon, desc in MATURITY_LEVELS:
        if low <= score <= high:
            return score, name, icon, desc
    return score, "Optimised", "❹", MATURITY_LEVELS[-1][4]


def render_markdown(
    results: List[Dict],
    pipeline_type: str,
    config_path: str,
) -> str:
    """Render the DevSecOps report as Markdown.

    Args:
        results: Control assessment results.
        pipeline_type: Detected pipeline type.
        config_path: Path to the config file.

    Returns:
        Markdown string.
    """
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    score, level, icon, level_desc = compute_maturity(results)
    present = [r for r in results if r["present"]]
    missing = [r for r in results if not r["present"]]

    lines: List[str] = []
    lines.append("# DevSecOps Pipeline Security Report")
    lines.append(f"\n**Generated:** {now}  ")
    lines.append(f"**Config File:** `{config_path}`  ")
    lines.append(f"**Pipeline Type:** {pipeline_type}  ")
    lines.append(f"**Maturity Score:** {score:.0f}/100 — {icon} {level}\n")
    lines.append(f"> {level_desc}\n")

    lines.append("## Controls Assessment\n")
    lines.append("| Control | Status | Detected Tool / Step | Risk if Missing |")
    lines.append("|---------|--------|---------------------|-----------------|")
    for r in results:
        status = "✅ Present" if r["present"] else "❌ Missing"
        tool = f"`{r['detected_tool']}`" if r["detected_tool"] else "—"
        risk = r["risk_if_missing"][:80] + "…" if len(r["risk_if_missing"]) > 80 else r["risk_if_missing"]
        lines.append(f"| **{r['name']}** | {status} | {tool} | {risk} |")

    # Maturity score bar
    bar_width = 40
    filled = int(bar_width * score / 100)
    bar = "█" * filled + "░" * (bar_width - filled)
    lines.append(f"\n## Maturity Score: {score:.0f}/100\n")
    lines.append(f"`[{bar}]` {level} {icon}\n")

    if missing:
        lines.append("## Missing Controls — Recommendations\n")
        # Sort by priority (lower = more important)
        missing_sorted = sorted(missing, key=lambda r: next(
            c["priority"] for c in CONTROLS if c["name"] == r["name"]
        ))
        for i, r in enumerate(missing_sorted, start=1):
            lines.append(f"### {i}. Add {r['name']}\n")
            lines.append(f"**Why it matters:** {r['risk_if_missing']}\n")
            lines.append(f"**How to implement:** {r['description']}\n")

    # Quick wins (controls with priority ≤ 2 that are missing)
    quick_wins = [
        r for r in missing
        if next(c["priority"] for c in CONTROLS if c["name"] == r["name"]) <= 2
    ]
    if quick_wins:
        lines.append("## Quick Wins\n")
        lines.append("These high-value controls can typically be added in under 30 minutes:\n")
        for r in quick_wins:
            lines.append(f"- **{r['name']}:** {r['quick_win']}")

    return "\n".join(lines)


def render_json_output(results: List[Dict], pipeline_type: str, config_path: str) -> str:
    """Render results as JSON.

    Args:
        results: Control assessment results.
        pipeline_type: Detected pipeline type.
        config_path: Config file path.

    Returns:
        JSON string.
    """
    score, level, icon, desc = compute_maturity(results)
    output = {
        "generated": datetime.utcnow().isoformat() + "Z",
        "config_file": config_path,
        "pipeline_type": pipeline_type,
        "maturity_score": score,
        "maturity_level": level,
        "controls": results,
    }
    return json.dumps(output, indent=2)


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        description="Assess CI/CD pipeline configuration for DevSecOps security controls."
    )
    parser.add_argument("--config", required=True, help="Path to CI/CD YAML config file")
    parser.add_argument(
        "--output",
        choices=["markdown", "json"],
        default="markdown",
        help="Output format (default: markdown)",
    )
    return parser.parse_args()


def main() -> None:
    """Main entry point."""
    args = parse_args()
    try:
        with open(args.config, encoding="utf-8") as fh:
            content = fh.read()
    except FileNotFoundError:
        print(f"ERROR: Config file not found: '{args.config}'", file=sys.stderr)
        sys.exit(1)

    if not content.strip():
        print("ERROR: Config file is empty.", file=sys.stderr)
        sys.exit(1)

    pipeline_type = detect_pipeline_type(content)
    results = check_controls(content)

    if args.output == "json":
        print(render_json_output(results, pipeline_type, args.config))
    else:
        print(render_markdown(results, pipeline_type, args.config))


if __name__ == "__main__":
    main()
