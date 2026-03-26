# IT Audit Team Skills

![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)
![Build Status](https://img.shields.io/badge/build-passing-brightgreen)

**Open-source Claude AI skills for IT audit automation and cybersecurity compliance.** Enhance your Claude AI assistant with specialized skills for IT auditors. Automate evidence analysis, risk assessments, and executive reporting across critical domains like identity access management, vendor risk evaluation, and network security. Perfect for building a complete audit team toolkit with AI-powered workflows.

This repository provides modular Claude skills for IT audit teams — starting with Phase 1: Lead IT Auditor skills. Each skill is a self-contained tool designed for real-world audit workflows, reducing manual effort and improving accuracy in SOC 2, ISO 27001, NIST, and PCI-DSS audits.

## Key Features
- **Claude AI Integration**: Custom skills that extend Claude's capabilities for audit-specific tasks.
- **Automation-First**: AI-enhanced tools for gap analysis, anomaly detection, and report generation.
- **Framework Coverage**: Supports major compliance frameworks (SOC 2, ISO 27001, NIST, PCI-DSS).
- **Modular Design**: Each skill is standalone, easy to integrate into Claude workflows.
- **Open-Source**: Free to use, modify, and contribute — built by auditors for auditors.

## Current Phase: Lead IT Auditor Skills

| Skill | Description |
|-------|-------------|
| `audit-scope-checklist` | Generate a scoped audit program with controls mapped to roles and frameworks |
| `artefact-gap-analyzer` | Compare expected evidence artefacts against provided files and report gaps |
| `exec-summary-writer` | Convert structured findings JSON into a polished executive summary |
| `playbook` | Step-by-step lead auditor playbook (engagement planning through closeout) |

## Quick Start
1. Install Claude Desktop or integrate with Claude API.
2. Load the skill.yaml files into your Claude environment.
3. Use triggers like "artefact gap analysis" to activate skills.

## Contributing
We welcome contributions! Add new skills for additional audit roles. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. Star this repo to support open-source Claude skills for IT audits.

## License
MIT License - see [LICENSE](LICENSE) for details.

---

## Roles & Skills

| Role | Skill | Description |
|------|-------|-------------|
| **Lead IT Auditor** | `audit-scope-checklist` | Generate a scoped audit program with controls mapped to roles and frameworks |
| | `artefact-gap-analyzer` | Compare expected evidence artefacts against provided files and report gaps |
| | `exec-summary-writer` | Convert structured findings JSON into a polished executive summary |
| | `playbook` | Step-by-step lead auditor playbook (engagement planning through closeout) |
| **Identity & Access** | `access-review` | Review user account lists for stale/orphaned accounts and privilege issues |
| | `sod-analyzer` | Detect segregation-of-duties conflicts in role assignment data |
| | `privileged-account-monitor` | Identify and report on privileged accounts and their activity |
| | `playbook` | IAM audit playbook |
| **Compliance Controls** | `compliance-checker` | Map controls against frameworks (ISO 27001, SOC 2, NIST, PCI-DSS) |
| | `policy-writer` | Generate policy document drafts from control requirements |
| | `evidence-tracker` | Track evidence collection status across audit controls |
| | `playbook` | Compliance audit playbook |
| **Log Monitoring** | `log-analyzer` | Parse and analyse log files for security-relevant events |
| | `anomaly-detector` | Statistical detection of anomalous patterns in log data |
| | `incident-timeline-builder` | Reconstruct incident timelines from disparate log sources |
| | `playbook` | Log monitoring audit playbook |
| **Vendor Risk** | `vendor-assessor` | Score vendor risk profiles from questionnaire data |
| | `contract-checker` | Review contract clauses against standard security requirements |
| | `supply-chain-mapper` | Map and visualise third-party supply chain relationships |
| | `playbook` | Vendor risk audit playbook |
| **Network Security** | `network-config-reviewer` | Audit firewall rules and network device configurations |
| | `threat-correlator` | Correlate threat intelligence with observed network indicators |
| | `segmentation-validator` | Validate network segmentation against documented architecture |
| | `playbook` | Network security audit playbook |
| **Data Privacy** | `data-inventory-mapper` | Build a data inventory from system and database metadata |
| | `consent-checker` | Verify consent records against applicable privacy requirements |
| | `pia-generator` | Generate Privacy Impact Assessment drafts from system descriptions |
| | `playbook` | Data privacy audit playbook |
| **Hardware & Physical** | `asset-validator` | Reconcile physical asset records against expected inventory |
| | `firmware-checker` | Check firmware versions against known-good baselines |
| | `physical-access-review` | Analyse physical access logs for anomalies and policy violations |
| | `playbook` | Hardware & physical security playbook |
| **Application Security** | `vuln-parser` | Parse vulnerability scanner output and prioritise findings |
| | `code-review-helper` | Static analysis assistant for security-focused code review |
| | `devsecops-checker` | Assess CI/CD pipeline configuration against DevSecOps practices |
| | `playbook` | Application security audit playbook |

---

## Phase Roadmap

| Phase | Roles Covered | Status |
|-------|---------------|--------|
| 1 | Lead IT Auditor | ✅ Complete |
| 2 | Identity & Access, Compliance Controls | 🔲 Pending |
| 3 | Log Monitoring, Vendor Risk | 🔲 Pending |
| 4 | Network Security, Data Privacy | 🔲 Pending |
| 5 | Hardware & Physical, Application Security | 🔲 Pending |

---

## Repository Structure

```
it-audit-team-skills/
├── README.md
├── LICENSE
├── CONTRIBUTING.md
├── .gitignore
├── .env.example
├── requirements.txt
├── tests/
│   ├── test_lead_auditor.py
│   ├── test_iam.py
│   ├── test_compliance.py
│   ├── test_logging.py
│   ├── test_vendor.py
│   ├── test_network.py
│   ├── test_privacy.py
│   ├── test_hardware.py
│   └── test_appsec.py
├── .github/workflows/ci.yml
├── lead-it-auditor/
│   ├── audit-scope-checklist/
│   ├── artefact-gap-analyzer/
│   ├── exec-summary-writer/
│   └── playbook/
├── identity-access/
├── compliance-controls/
├── log-monitoring/
├── vendor-risk/
├── network-security/
├── data-privacy/
├── hardware-physical/
└── application-security/
```

---

## Installation

```bash
git clone https://github.com/your-org/it-audit-team-skills.git
cd it-audit-team-skills

python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

pip install -r requirements.txt

cp .env.example .env
# Edit .env and add your AWS / Azure credentials if needed
```

---

## Usage — Lead IT Auditor Skills

### audit-scope-checklist

Generate a full audit program for a system, filtered to specific roles and frameworks:

```bash
python lead-it-auditor/audit-scope-checklist/main.py \
  --system "ERP Platform" \
  --roles identity-access,compliance-controls,log-monitoring \
  --frameworks "ISO 27001,SOC 2" \
  --output-dir ./output
```

Generate a program covering all 9 roles:

```bash
python lead-it-auditor/audit-scope-checklist/main.py --system "Corporate Network"
```

### artefact-gap-analyzer

Identify missing evidence against an audit program:

```bash
python lead-it-auditor/artefact-gap-analyzer/main.py \
  --program lead-it-auditor/audit-scope-checklist/sample_input/sample_audit_program.json \
  --provided lead-it-auditor/artefact-gap-analyzer/sample_input/sample_evidence/
```

Pass a comma-separated list of filenames instead of a directory:

```bash
python lead-it-auditor/artefact-gap-analyzer/main.py \
  --program ./output/audit_program.json \
  --provided "access_review.xlsx,firewall_rules.csv,policy_v2.pdf"
```

### exec-summary-writer

Produce an executive summary from a findings file:

```bash
python lead-it-auditor/exec-summary-writer/main.py \
  --findings lead-it-auditor/exec-summary-writer/sample_input/findings.json \
  --scope "Annual IT General Controls Review" \
  --author "Jane Smith, CISA" \
  --date "2025-06-30"
```

### playbook

Run the full lead auditor playbook:

```bash
python lead-it-auditor/playbook/main.py --step full
```

Display a single step:

```bash
python lead-it-auditor/playbook/main.py --step 3
```

---

## Running Tests

```bash
pytest tests/ -v
pytest tests/ --cov=. --cov-report=term-missing
```

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `AWS_ACCESS_KEY_ID` | AWS mode only | AWS access key |
| `AWS_SECRET_ACCESS_KEY` | AWS mode only | AWS secret key |
| `AWS_DEFAULT_REGION` | AWS mode only | Default AWS region (e.g. `us-east-1`) |
| `AZURE_TENANT_ID` | Azure mode only | Azure Active Directory tenant ID |
| `AZURE_CLIENT_ID` | Azure mode only | Azure app registration client ID |
| `AZURE_CLIENT_SECRET` | Azure mode only | Azure app registration client secret |
| `AZURE_SUBSCRIPTION_ID` | Azure mode only | Azure subscription ID |
| `LOG_LEVEL` | Optional | Logging verbosity: `DEBUG`, `INFO`, `WARNING`, `ERROR` (default: `INFO`) |

All scripts default to `--mode local` and work with no credentials.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on adding new skills,
coding standards, and the pull request process.

---

## License

MIT © 2025 IT Audit Team Contributors. See [LICENSE](LICENSE).
