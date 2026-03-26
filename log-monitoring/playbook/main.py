"""Logging & Monitoring Audit Playbook — step-by-step methodology."""

import argparse
import sys
from typing import Dict, List

from dotenv import load_dotenv

load_dotenv()

PLAYBOOK: List[Dict] = [
    {
        "step": 1,
        "title": "Log Source Inventory & Coverage Assessment",
        "objective": "Identify all log sources in scope, verify they are enabled and forwarding to a central store, and assess coverage gaps against critical systems.",
        "artefacts": [
            "log_source_inventory.xlsx — all systems, logging status, log types, destination",
            "siem_source_list.csv — sources currently feeding the SIEM/log management platform",
            "coverage_gap_report.md — systems not logging or with gaps",
            "log_retention_policy.pdf — documented retention periods per log type",
        ],
        "tools_commands": [
            "# AWS: verify CloudTrail is enabled in all regions",
            "aws cloudtrail describe-trails --include-shadow-trails",
            "aws cloudtrail get-trail-status --name <trail-name>",
            "",
            "# AWS: check CloudWatch log groups",
            "aws logs describe-log-groups --output json",
            "",
            "# Azure: check diagnostics settings",
            "az monitor diagnostic-settings list --resource <resource-id>",
        ],
        "must_do_checks": [
            "CloudTrail or equivalent must be enabled in ALL regions, not just primary",
            "Log retention must meet policy requirements (minimum 12 months)",
            "All privileged account activity must be captured in logs",
            "Network flow logs must be enabled for all critical network segments",
            "Verify log integrity validation is enabled (CloudTrail log file validation)",
        ],
        "linked_skills": [],
    },
    {
        "step": 2,
        "title": "Baseline Establishment",
        "objective": "Establish normal activity baselines for all users and systems to enable meaningful anomaly detection. Collect at least 14 days of historical data.",
        "artefacts": [
            "baseline_logs.jsonl — minimum 14 days of historical log data",
            "baseline_report.md — output from anomaly-detector --logs only",
            "user_activity_profiles.csv — normal ranges per user",
        ],
        "tools_commands": [
            "# Export CloudTrail events for baseline period",
            "aws cloudtrail lookup-events \\",
            "  --start-time 2025-06-01T00:00:00 \\",
            "  --end-time 2025-06-14T23:59:59 \\",
            "  --output json > baseline_logs.json",
            "",
            "# Run anomaly-detector to review baseline stats",
            "python log-monitoring/anomaly-detector/main.py \\",
            "  --logs baseline_logs.jsonl \\",
            "  --test baseline_logs.jsonl \\",
            "  --sensitivity 3.0",
        ],
        "must_do_checks": [
            "Baseline must cover at least 14 calendar days including weekdays and weekends",
            "Exclude known incident periods from the baseline to avoid skewing stats",
            "Document baseline collection date range in working papers",
            "Verify baseline covers all user types: admins, service accounts, standard users",
        ],
        "linked_skills": ["log-monitoring/anomaly-detector/"],
    },
    {
        "step": 3,
        "title": "Anomaly Detection & Log Analysis",
        "objective": "Run automated detection against the audit period logs to flag suspicious events and behavioural anomalies. Review all Critical and High findings.",
        "artefacts": [
            "audit_period_logs.jsonl — logs for the audit period",
            "log_analysis_report.md — output from log-analyzer skill",
            "anomaly_report.md — output from anomaly-detector skill",
            "flagged_events.csv — all Critical/High events for manual review",
        ],
        "tools_commands": [
            "# Run log analyzer against audit period",
            "python log-monitoring/log-analyzer/main.py \\",
            "  --logs audit_period_logs.jsonl \\",
            "  --start '2025-07-01T00:00:00' \\",
            "  --end '2025-07-31T23:59:59'",
            "",
            "# Run anomaly detector",
            "python log-monitoring/anomaly-detector/main.py \\",
            "  --logs baseline_logs.jsonl \\",
            "  --test audit_period_logs.jsonl \\",
            "  --sensitivity 2.0",
            "",
            "# AWS live mode",
            "python log-monitoring/log-analyzer/main.py --mode aws \\",
            "  --start '2025-07-01T00:00:00'",
        ],
        "must_do_checks": [
            "ALL Critical findings must be investigated — no exceptions",
            "Root account activity must be reviewed and justified for every occurrence",
            "Any DeleteTrail or StopLogging events require immediate escalation",
            "AuthorizationFailure events must be checked for targeted access attempts",
            "New unknown users appearing in logs must be verified against HR records",
        ],
        "linked_skills": [
            "log-monitoring/log-analyzer/",
            "log-monitoring/anomaly-detector/",
        ],
    },
    {
        "step": 4,
        "title": "Incident Investigation",
        "objective": "For any confirmed or suspected security incident, construct a detailed timeline, identify all affected systems and actors, and preserve evidence.",
        "artefacts": [
            "incident_timeline.md — output from incident-timeline-builder skill",
            "incident_timeline.json — machine-readable timeline for further analysis",
            "affected_resources.csv — all resources touched during the incident",
            "evidence_preservation_log.docx — chain of custody for log evidence",
        ],
        "tools_commands": [
            "# Build full incident timeline",
            "python log-monitoring/incident-timeline-builder/main.py \\",
            "  --logs audit_period_logs.jsonl \\",
            "  --start '2025-07-01T09:00:00' \\",
            "  --end '2025-07-01T15:00:00'",
            "",
            "# Focus on a specific actor",
            "python log-monitoring/incident-timeline-builder/main.py \\",
            "  --logs audit_period_logs.jsonl \\",
            "  --actor 'backdoor-user'",
            "",
            "# Export as JSON for further processing",
            "python log-monitoring/incident-timeline-builder/main.py \\",
            "  --logs audit_period_logs.jsonl \\",
            "  --output json > incident_timeline.json",
        ],
        "must_do_checks": [
            "Preserve original log files in read-only storage before any investigation",
            "Document chain of custody for all evidence",
            "Identify the initial access vector — how did the attacker first gain access?",
            "Map lateral movement — which systems did the attacker access after initial entry?",
            "Determine the blast radius — what data was potentially accessed or exfiltrated?",
        ],
        "linked_skills": ["log-monitoring/incident-timeline-builder/"],
    },
    {
        "step": 5,
        "title": "Reporting & Recommendations",
        "objective": "Compile log review findings into a structured report with risk-rated findings, root cause analysis for any incidents, and specific recommendations.",
        "artefacts": [
            "logging_audit_findings.json — structured findings for exec-summary-writer",
            "logging_executive_summary.md — output from exec-summary-writer skill",
            "recommendations_tracker.xlsx — all recommendations with owners and due dates",
        ],
        "tools_commands": [
            "python lead-it-auditor/exec-summary-writer/main.py \\",
            "  --findings logging_audit_findings.json \\",
            "  --scope 'Logging & Monitoring Audit Q3 2025'",
        ],
        "must_do_checks": [
            "Every finding must include root cause, not just symptom",
            "Recommendations must be specific, measurable, and time-bound",
            "Any incident findings must be cross-referenced with the incident response team",
            "Log retention gaps must be remediated before the next audit",
            "Confirm monitoring alerting covers all Critical pattern events before closeout",
        ],
        "linked_skills": ["lead-it-auditor/exec-summary-writer/"],
    },
]


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Logging & Monitoring audit playbook.")
    parser.add_argument("--step", default="full", help="Step number (1-5) or 'full'")
    return parser.parse_args()


def render_step(step: Dict) -> str:
    """Render a single playbook step."""
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
        print("# Logging & Monitoring Audit Playbook\n")
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
    print("# Logging & Monitoring Audit Playbook\n")
    print(render_step(step))


if __name__ == "__main__":
    main()
