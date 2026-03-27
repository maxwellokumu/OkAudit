"""Network Security Audit Playbook.

Provides a structured, step-by-step guide for conducting a comprehensive
network security audit. Outputs actionable steps with objectives, artefacts,
tool commands, and linked skills.
"""

import argparse
import sys
from datetime import datetime
from typing import Dict, List

from dotenv import load_dotenv

load_dotenv()

STEPS: Dict[int, Dict] = {
    1: {
        "title": "Network Asset Discovery & Inventory",
        "objective": (
            "Enumerate all network-connected assets including servers, workstations, "
            "network devices, IoT endpoints, and cloud resources. Build a complete "
            "network topology map to establish audit scope."
        ),
        "artefacts": [
            "Network topology diagram (logical and physical)",
            "Asset inventory spreadsheet (IP, hostname, OS, role, owner)",
            "VLAN/subnet register",
            "Cloud resource inventory (VPCs, subnets, EC2/VMs)",
        ],
        "tools_commands": [
            "# Active network scan",
            "nmap -sn 10.0.0.0/8 -oG - | grep 'Up' > live_hosts.txt",
            "",
            "# OS and service fingerprinting",
            "nmap -sV -O 10.0.0.0/8 -oX network_scan.xml",
            "",
            "# AWS: list VPCs and subnets",
            "aws ec2 describe-vpcs --output table",
            "aws ec2 describe-subnets --output table",
            "",
            "# Azure: list virtual networks",
            "az network vnet list --output table",
            "",
            "# Export routing table",
            "netstat -rn > routing_table.txt",
            "",
            "# SNMP-based device discovery (if enabled)",
            "snmpwalk -v2c -c public 10.0.0.1 1.3.6.1.2.1.4.20",
        ],
        "must_do_checks": [
            "Confirm all subnets and VLANs are documented",
            "Identify all external-facing IPs (public internet exposure)",
            "Flag any undocumented or shadow-IT devices",
            "Validate cloud inventory matches IaC/Terraform state",
            "Ensure wireless networks are included in scope",
            "Verify network diagrams are current (not older than 6 months)",
        ],
        "linked_skills": [],
    },
    2: {
        "title": "Firewall & ACL Rule Review",
        "objective": (
            "Review all firewall rules, security groups, NACLs, and ACLs for "
            "misconfigurations including open inbound access, sensitive port exposure, "
            "deprecated protocol usage, any-to-any rules, and undocumented rules."
        ),
        "artefacts": [
            "Exported firewall ruleset (CSV or vendor-specific format)",
            "AWS Security Group export",
            "network-config-reviewer markdown report",
            "List of rules to remediate with risk ratings",
        ],
        "tools_commands": [
            "# Run network-config-reviewer on exported rules",
            "python network-security/network-config-reviewer/main.py \\",
            "  --rules firewall_rules.csv",
            "",
            "# AWS: export security groups",
            "aws ec2 describe-security-groups \\",
            "  --output json > security_groups.json",
            "",
            "# Run reviewer in AWS mode",
            "python network-security/network-config-reviewer/main.py \\",
            "  --mode aws",
            "",
            "# Azure: list NSG rules",
            "az network nsg list --output table",
            "az network nsg rule list --nsg-name <NSG_NAME> -g <RG> --output table",
            "",
            "# pfSense/OPNsense: export via API",
            "curl -sk -u admin:password https://firewall/api/firewall/filter/getRules",
        ],
        "must_do_checks": [
            "No ALLOW rules with source 0.0.0.0/0 for management ports (22, 3389)",
            "No deprecated protocols enabled (Telnet/23, FTP/21, RSH/514)",
            "No any-to-any ALLOW rules exist",
            "All rules have descriptions and owners",
            "Port ranges do not exceed 1000 ports unless explicitly justified",
            "Rules reviewed against the principle of least privilege",
            "Stale rules (>12 months unused) identified for removal",
        ],
        "linked_skills": ["network-security/network-config-reviewer"],
    },
    3: {
        "title": "Network Segmentation Validation",
        "objective": (
            "Validate that network segmentation controls are correctly enforced. "
            "Verify that DMZ, Internal, DB, and Management zones cannot communicate "
            "directly unless explicitly approved, and that no high-risk cross-zone "
            "flows exist."
        ),
        "artefacts": [
            "Zone definition document (JSON format for tool input)",
            "segmentation-validator markdown report",
            "Cross-zone flow matrix (approved vs detected)",
            "List of inter-zone violations for remediation",
        ],
        "tools_commands": [
            "# Run segmentation-validator",
            "python network-security/segmentation-validator/main.py \\",
            "  --zones zones.json \\",
            "  --rules firewall_rules.csv",
            "",
            "# Verify zone isolation with nmap",
            "nmap -p 3306,5432,27017 10.0.3.0/24 --source-ip 172.16.10.5",
            "",
            "# Test DMZ → Internal connectivity (should be DENIED)",
            "nmap -p 22,443,3306 10.0.1.0/24 --source-ip 172.16.10.5",
            "",
            "# AWS: check VPC peering and routing tables",
            "aws ec2 describe-route-tables --output table",
            "aws ec2 describe-vpc-peering-connections --output table",
        ],
        "must_do_checks": [
            "Internet zone cannot reach DB or Management zones directly",
            "DMZ can only reach Internal on specific, approved ports",
            "DB zone is only reachable from Internal/App on DB ports (3306, 5432, etc.)",
            "Management zone access is restricted to bastion hosts or VPN IPs only",
            "All unzoned IPs/CIDRs are investigated and assigned to a zone",
            "Zone diagram matches actual routing and firewall rules",
            "Micro-segmentation controls verified for cloud workloads",
        ],
        "linked_skills": ["network-security/segmentation-validator"],
    },
    4: {
        "title": "Threat Intelligence Correlation",
        "objective": (
            "Correlate recent network logs against current threat intelligence IOC feeds "
            "to identify any communications with known malicious IPs, domains, CIDRs, "
            "or matching known malware hashes."
        ),
        "artefacts": [
            "Network flow logs (SIEM export, firewall logs, VPC Flow Logs)",
            "IOC file (from threat intel feeds: AlienVault, MISP, etc.)",
            "threat-correlator markdown/JSON report",
            "Incident tickets for any confirmed IOC matches",
        ],
        "tools_commands": [
            "# Run threat-correlator",
            "python network-security/threat-correlator/main.py \\",
            "  --logs network_logs.csv \\",
            "  --iocs iocs.txt",
            "",
            "# JSON output for SIEM ingestion",
            "python network-security/threat-correlator/main.py \\",
            "  --logs network_logs.csv \\",
            "  --iocs iocs.txt \\",
            "  --output json > threat_matches.json",
            "",
            "# Export AWS VPC Flow Logs",
            "aws logs filter-log-events \\",
            "  --log-group-name /aws/vpc/flowlogs \\",
            "  --start-time $(date -d '7 days ago' +%s)000",
            "",
            "# Download IOCs from AlienVault OTX (requires API key)",
            "curl -H 'X-OTX-API-KEY: $OTX_API_KEY' \\",
            "  'https://otx.alienvault.com/api/v1/pulses/subscribed' > otx_iocs.json",
        ],
        "must_do_checks": [
            "IOC list is current (sourced within the last 7 days)",
            "Logs cover a minimum of 30 days of network activity",
            "All matched events are investigated — confirm true positive vs false positive",
            "Any confirmed IOC match triggers an incident response ticket",
            "Check for IOC matches against both ingress and egress traffic",
            "Document any IOCs that had zero hits for feed quality assessment",
        ],
        "linked_skills": ["network-security/threat-correlator"],
    },
    5: {
        "title": "Vulnerability Scanning & Patch Review",
        "objective": (
            "Identify unpatched systems, open vulnerabilities, and misconfigured "
            "network services. Cross-reference CVE databases and verify that critical "
            "patches have been applied within SLA timeframes."
        ),
        "artefacts": [
            "Vulnerability scan report (Nessus, OpenVAS, Qualys, etc.)",
            "Patch compliance matrix (Critical/High/Medium CVEs vs patch status)",
            "EOL/unsupported software register",
            "Remediation plan with target dates",
        ],
        "tools_commands": [
            "# OpenVAS full scan",
            "gvm-cli socket --gmp-password admin --gmp-username admin \\",
            "  --xml '<create_task><name>Network Audit</name></create_task>'",
            "",
            "# Nmap NSE vulnerability scripts",
            "nmap --script vuln -sV 10.0.0.0/24 -oX vuln_scan.xml",
            "",
            "# Check for EternalBlue (MS17-010)",
            "nmap --script smb-vuln-ms17-010 -p 445 10.0.0.0/24",
            "",
            "# Check SSL/TLS configuration",
            "sslyze --regular 10.0.0.1:443",
            "testssl.sh --csv output.csv 10.0.0.1:443",
            "",
            "# AWS Inspector (managed scanning)",
            "aws inspector2 list-findings \\",
            "  --filter-criteria '{\"severity\":[{\"comparison\":\"EQUALS\",\"value\":\"CRITICAL\"}]}'",
            "",
            "# Check for expired certificates",
            "echo | openssl s_client -connect 10.0.0.1:443 2>/dev/null | \\",
            "  openssl x509 -noout -dates",
        ],
        "must_do_checks": [
            "All Critical CVEs patched within 24-72 hours per policy",
            "High CVEs patched within 14-30 days per policy",
            "No end-of-life (EOL) operating systems or software in production",
            "SSL/TLS configuration uses TLS 1.2+ only (disable TLS 1.0/1.1)",
            "Default credentials removed on all network devices",
            "SNMP v1/v2c replaced with SNMPv3 or disabled",
            "Certificates valid and not expiring within 30 days",
        ],
        "linked_skills": [],
    },
    6: {
        "title": "Reporting & Remediation Roadmap",
        "objective": (
            "Consolidate findings from all previous steps into a network security "
            "audit report. Prioritise findings by risk, assign owners, and define "
            "a remediation roadmap with timelines."
        ),
        "artefacts": [
            "Network Security Audit Report (executive summary + technical findings)",
            "Risk register update (new network findings added)",
            "Remediation roadmap (Gantt or action tracker)",
            "Management presentation (key metrics and top risks)",
        ],
        "tools_commands": [
            "# Aggregate all tool outputs",
            "python network-security/network-config-reviewer/main.py \\",
            "  --rules firewall_rules.csv > reports/firewall_review.md",
            "",
            "python network-security/segmentation-validator/main.py \\",
            "  --zones zones.json --rules firewall_rules.csv > reports/segmentation.md",
            "",
            "python network-security/threat-correlator/main.py \\",
            "  --logs network_logs.csv --iocs iocs.txt > reports/threat_correlation.md",
            "",
            "# Convert markdown reports to PDF (requires pandoc)",
            "pandoc reports/firewall_review.md -o reports/firewall_review.pdf",
            "",
            "# Combine reports",
            "cat reports/*.md > reports/network_security_audit_full.md",
        ],
        "must_do_checks": [
            "Every finding has a risk rating (Critical/High/Medium/Low)",
            "Every finding has an assigned owner and target remediation date",
            "Executive summary is non-technical and focuses on business impact",
            "Findings are mapped to relevant frameworks (ISO 27001, NIST CSF, CIS Controls)",
            "Previous audit findings are tracked for closure/regression",
            "Report reviewed by network team before distribution",
            "Retesting date scheduled for Critical and High findings",
        ],
        "linked_skills": [
            "network-security/network-config-reviewer",
            "network-security/segmentation-validator",
            "network-security/threat-correlator",
        ],
    },
}


def render_step(step_num: int, step: Dict) -> str:
    """Render a single playbook step as markdown.

    Args:
        step_num: The step number (1-6).
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
    """Entry point for the network security playbook."""
    parser = argparse.ArgumentParser(
        description="Network Security Audit Playbook — step-by-step guidance."
    )
    parser.add_argument(
        "--step",
        default="full",
        help="Step number (1-6) or 'full' for all steps (default: full).",
    )
    args = parser.parse_args()

    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    header = [
        "# Network Security Audit Playbook",
        "",
        f"**Generated:** {now}",
        "",
        "A comprehensive, step-by-step guide for conducting a network security audit. "
        "Run specific steps with `--step N` or output all steps with `--step full`.",
        "",
    ]

    if args.step.lower() == "full":
        steps_to_render = list(STEPS.keys())
    else:
        try:
            step_num = int(args.step)
        except ValueError:
            print(f"Error: --step must be an integer 1-6 or 'full', got '{args.step}'.", file=sys.stderr)
            sys.exit(1)
        if step_num not in STEPS:
            print(f"Error: Step {step_num} does not exist. Valid steps: 1-6.", file=sys.stderr)
            sys.exit(1)
        steps_to_render = [step_num]

    toc = ["## Table of Contents", ""]
    for n in STEPS:
        toc.append(f"{n}. {STEPS[n]['title']}")
    toc.append("")

    body = []
    for n in steps_to_render:
        body.append(render_step(n, STEPS[n]))

    print("\n".join(header + toc + body))


if __name__ == "__main__":
    main()
