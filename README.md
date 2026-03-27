# OkAudit · AI-Powered IT Audit Automation

[![CI](https://github.com/maxwellokumu/OkAudit/actions/workflows/ci.yml/badge.svg)](https://github.com/maxwellokumu/OkAudit/actions/workflows/ci.yml)
[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Claude Skills](https://img.shields.io/badge/Claude-Skills-7C3AED)](https://claude.ai)
[![Coverage](https://img.shields.io/badge/coverage-85%25-green.svg)]()
[![Frameworks](https://img.shields.io/badge/frameworks-SOC2%20%7C%20ISO27001%20%7C%20PCI--DSS%20%7C%20NIST%20%7C%20GDPR-blue)]()

> **OkAudit** is a production-grade AI audit automation framework that transforms traditional, manual IT audit workflows into modular, intelligent, and executable AI skills — running natively inside Claude or via CLI.

---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Architecture](#architecture)
- [Skill Domains](#skill-domains)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Usage](#usage)
  - [CLI Usage](#cli-usage)
  - [Claude Integration](#claude-integration)
- [Configuration](#configuration)
- [Environment Variables](#environment-variables)
- [Testing](#testing)
- [Compliance Frameworks](#compliance-frameworks)
- [Project Structure](#project-structure)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

Modern IT audits are slow, fragmented, and difficult to scale. Audit teams rely on static checklists, manual evidence collection, and inconsistent review processes — leading to delayed cycles, compliance gaps, and limited real-time visibility.

**OkAudit** addresses this by delivering a virtual audit team of **9 specialist roles** and **36 AI-powered skills**, each designed to perform discrete, real-world audit tasks. These skills can be orchestrated into end-to-end audit pipelines or executed independently against live system data.

### What OkAudit Does Differently

| Traditional Audit | OkAudit |
|---|---|
| Static checklists | AI-driven audit agents |
| Manual evidence gathering | Automated data ingestion and analysis |
| Inconsistent review quality | Structured, framework-aligned outputs |
| Weeks-long cycles | Continuous, near-real-time auditing |
| Siloed tooling | Unified multi-framework skill system |

### Business Impact

- Reduce audit cycle time by **50–80%**
- Improve risk detection accuracy through consistent, structured analysis
- Standardize compliance processes across SOC2, ISO 27001, PCI-DSS, NIST, and GDPR
- Scale audit capabilities without proportional headcount growth

### Who This Is For

- IT Audit Teams and Internal Audit functions
- Security Engineers and GRC practitioners
- Compliance Officers managing multi-framework obligations
- Consulting firms delivering audit services at scale
- SaaS and Fintech platforms with continuous compliance requirements

---

## Key Features

- **Multi-Agent Audit System** — 9 specialized audit roles, each with dedicated skills for their domain
- **36 Modular Skills** — Independent or pipeline execution; each skill is self-contained with its own logic, inputs, and outputs
- **Claude-Native Integration** — Each module ships with a `skill.yaml` enabling natural language execution directly inside Claude
- **Framework-Aware Auditing** — Built-in control mappings for SOC2, ISO 27001, PCI-DSS, NIST, and GDPR
- **CLI + AI Execution** — Run audits programmatically via CLI or interactively through Claude's code execution environment
- **Structured Outputs** — JSON and CSV outputs ready for downstream reporting, dashboards, or SIEM ingestion

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        OkAudit                              │
│                 AI Audit Automation Framework               │
└─────────────────────────────────────────────────────────────┘
                              │
          ┌───────────────────┼───────────────────┐
          ▼                   ▼                   ▼
   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
   │  CLI Runner │    │   Claude    │    │  Pipeline   │
   │  (main.py)  │    │ Integration │    │ Orchestrator│
   └──────┬──────┘    └──────┬──────┘    └──────┬──────┘
          └───────────────────┼───────────────────┘
                              │
                ┌─────────────▼─────────────┐
                │      Skill Registry        │
                │  (36 modular audit skills) │
                └─────────────┬─────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
 ┌────────────┐       ┌────────────┐       ┌────────────┐
 │  Evidence  │       │  Analysis  │       │  Reporting │
 │  Ingestion │──────▶│   Engine   │──────▶│   Layer    │
 │ (JSON/CSV) │       │(AI + Rules)│       │(JSON/CSV)  │
 └────────────┘       └────────────┘       └────────────┘
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
        ┌──────────┐   ┌──────────┐   ┌──────────┐
        │  SOC2    │   │ ISO27001 │   │ PCI-DSS  │
        │  NIST    │   │  GDPR    │   │ Mappings │
        └──────────┘   └──────────┘   └──────────┘
```

OkAudit follows a layered architecture where raw system data is ingested, transformed through modular AI skills, and surfaced as structured, framework-aligned audit intelligence. Each layer is independently testable and replaceable.

---

## Skill Domains

OkAudit organizes its 36 skills across 9 specialist audit roles:

| Role | Skills | Key Capabilities |
|------|--------|-----------------|
| 🧑‍💼 **Lead IT Auditor** | Scope, Reporting, Orchestration | Audit scoping, risk prioritization, executive reporting |
| 🔐 **Identity & Access** | Access Review, SoD Analysis, Privilege Audit | Over-privileged account detection, separation of duties analysis, MFA compliance |
| 📜 **Compliance** | Policy Validation, Control Tracking, Gap Analysis | Framework control mapping, policy drift detection, remediation tracking |
| 📊 **Log Monitoring** | Threat Detection, Anomaly Analysis, Audit Trail | Log ingestion, behavioral anomaly detection, incident reconstruction |
| 🏢 **Vendor Risk** | Risk Scoring, Third-Party Review, Contract Analysis | Vendor classification, risk scoring, SLA compliance checks |
| 🌐 **Network Security** | Firewall Review, Segmentation Audit, Exposure Analysis | Firewall rule analysis, network zone validation, open port enumeration |
| 🔒 **Privacy & Data** | Data Mapping, Consent Review, Retention Audit | PII identification, data flow mapping, consent chain validation |
| 🖥️ **Hardware & Assets** | Asset Inventory, Configuration Baseline, EOL Detection | Asset discovery, baseline drift detection, end-of-life flagging |
| 💻 **Application Security** | Code Review, Dependency Audit, Auth Analysis | SAST-aligned code review, CVE detection in dependencies, auth flow analysis |

---

## Quick Start

The fastest way to run OkAudit is to clone the repo and execute a skill directly:

```bash
# Clone the repository
git clone https://github.com/maxwellokumu/OkAudit.git
cd OkAudit

# Set up the Python environment
python -m venv venv
source venv/bin/activate       # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Run your first audit — scope definition for an AWS payment app
cd lead-it-auditor/audit-scope-checklist
python main.py \
  --system "AWS payment application" \
  --roles "iam,network" \
  --frameworks "PCI-DSS"
```

---

## Installation

### Prerequisites

- Python 3.8 or higher
- `pip` and `venv`
- AWS or Azure credentials (optional — only required for cloud-connected skills)

### Steps

```bash
# 1. Clone
git clone https://github.com/maxwellokumu/OkAudit.git
cd OkAudit

# 2. Create and activate a virtual environment
python -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. (Optional) Configure environment variables
cp .env.example .env
# Edit .env with your credentials
```

---

## Usage

### CLI Usage

Each skill lives in its own directory and exposes a `main.py` entry point. All skills follow a consistent invocation pattern:

```bash
python main.py [--input <file>] [--options <values>]
```

#### IAM Access Review

```bash
cd identity-access/access-review
python main.py --input iam_policy.json
```

**Sample output:**
```json
{
  "findings": [
    {
      "severity": "HIGH",
      "user": "svc-payments",
      "issue": "AdministratorAccess policy attached",
      "recommendation": "Restrict to least-privilege policy",
      "framework_ref": "PCI-DSS 7.1"
    }
  ],
  "summary": {
    "total_users": 42,
    "over_privileged": 7,
    "mfa_disabled": 3
  }
}
```

#### Log Analysis

```bash
cd log-monitoring/log-analyzer
python main.py --logs cloudtrail.json --frameworks "SOC2,ISO27001"
```

#### Audit Scope Definition

```bash
cd lead-it-auditor/audit-scope-checklist
python main.py \
  --system "Azure SaaS platform" \
  --roles "iam,appsec,vendor" \
  --frameworks "ISO27001,GDPR"
```

#### Vendor Risk Scoring

```bash
cd vendor-risk/risk-scoring
python main.py --vendor vendor_profile.json --tier critical
```

#### Network Firewall Review

```bash
cd network-security/firewall-review
python main.py --rules firewall_rules.json --segment "production"
```

---

### Claude Integration

OkAudit skills can be executed directly inside Claude using its code execution environment.

**Step 1:** Enable code execution in Claude settings.

**Step 2:** Upload the relevant skill folder (e.g., `identity-access/access-review/`) together with your evidence file.

**Step 3:** Use natural language to invoke the skill:

```
Analyze this IAM policy for over-privileged accounts and SoD violations.
Map findings to PCI-DSS controls.
```

Each skill includes a `skill.yaml` that declares its inputs, outputs, and Claude execution context. Claude reads this automatically when the folder is uploaded.

**Example prompts:**

```
Run an access review on the attached iam_policy.json and highlight
any accounts with AdministratorAccess.
```

```
Analyze these CloudTrail logs for anomalous activity and produce
a SOC2 CC6.1-aligned finding report.
```

```
Score this vendor profile against our third-party risk framework
and flag any critical gaps.
```

---

## Configuration

Each skill can be configured via its `config.yaml`. Common configuration options:

```yaml
# config.yaml (example — identity-access/access-review)
frameworks:
  - PCI-DSS
  - SOC2

thresholds:
  max_admin_accounts: 2
  mfa_required: true
  inactive_days_threshold: 90

output:
  format: json            # json | csv | markdown
  include_remediation: true
  severity_filter: medium # low | medium | high | critical
```

---

## Environment Variables

Copy `.env.example` to `.env` and populate the variables relevant to the skills you intend to run. Cloud credential variables are only required for skills that connect to live cloud environments.

| Variable | Required | Description |
|----------|----------|-------------|
| `AWS_ACCESS_KEY_ID` | Optional | AWS access key for cloud-connected skills |
| `AWS_SECRET_ACCESS_KEY` | Optional | AWS secret key |
| `AWS_DEFAULT_REGION` | Optional | Default AWS region (e.g., `us-east-1`) |
| `AZURE_CLIENT_ID` | Optional | Azure service principal client ID |
| `AZURE_CLIENT_SECRET` | Optional | Azure service principal secret |
| `AZURE_TENANT_ID` | Optional | Azure Active Directory tenant ID |
| `LOG_LEVEL` | Optional | Logging verbosity: `DEBUG`, `INFO`, `WARNING`, `ERROR` (default: `INFO`) |
| `OUTPUT_DIR` | Optional | Directory for audit output files (default: `./output`) |

> **Security note:** Never commit `.env` to version control. The `.gitignore` in this repo excludes it by default.

---

## Testing

OkAudit includes a full test suite with coverage reporting.

```bash
# Run all tests
pytest tests/

# Run with HTML coverage report
pytest tests/ --cov=. --cov-report=html
open htmlcov/index.html

# Run tests for a specific skill domain
pytest tests/identity_access/ -v

# Run only unit tests (skip integration)
pytest tests/ -m "not integration"
```

### Test structure

```
tests/
├── unit/
│   ├── test_iam_review.py
│   ├── test_log_analyzer.py
│   ├── test_vendor_scoring.py
│   └── ...
├── integration/
│   ├── test_pipeline_execution.py
│   └── test_claude_skill_invocation.py
└── fixtures/
    ├── sample_iam_policy.json
    ├── sample_cloudtrail.json
    └── sample_vendor_profile.json
```

---

## Compliance Frameworks

OkAudit skill outputs include `framework_ref` fields mapping every finding to specific controls, making results directly usable in audit workpapers and control matrices.

| Framework | Scope | Example Controls |
|-----------|-------|-----------------|
| **SOC 2** | Trust service criteria | CC6.1, CC6.2, CC7.2, CC9.2 |
| **ISO 27001** | ISMS controls | A.9.2, A.12.4, A.14.2 |
| **PCI-DSS v4** | Payment card security | 7.1, 8.3, 10.2, 11.3 |
| **NIST CSF** | Cybersecurity framework | ID.AM, PR.AC, DE.CM, RS.AN |
| **GDPR** | Data protection | Art. 5, Art. 25, Art. 30, Art. 32 |

---

## Project Structure

```
OkAudit/
├── lead-it-auditor/
│   ├── audit-scope-checklist/
│   ├── risk-prioritization/
│   └── audit-reporting/
├── identity-access/
│   ├── access-review/
│   ├── sod-analysis/
│   └── privilege-audit/
├── compliance/
│   ├── policy-validation/
│   └── gap-analysis/
├── log-monitoring/
│   ├── log-analyzer/
│   └── anomaly-detection/
├── vendor-risk/
│   └── risk-scoring/
├── network-security/
│   ├── firewall-review/
│   └── segmentation-audit/
├── privacy-data/
│   ├── data-mapping/
│   └── consent-review/
├── hardware-assets/
│   └── asset-validation/
├── application-security/
│   └── dependency-audit/
├── tests/
├── assets/
├── requirements.txt
├── .env.example
├── CONTRIBUTING.md
└── README.md
```

---

## Roadmap

| Milestone | Status | Target |
|-----------|--------|--------|
| 36 core skills | ✅ Complete | — |
| Claude skill.yaml integration | ✅ Complete | — |
| CLI runner for all domains | ✅ Complete | — |
| Web dashboard (Flask/React) | 🔄 In Progress | Q3 2026 |
| Real-time continuous monitoring | 🗓 Planned | Q3 2026 |
| SIEM integration (Splunk, Elastic) | 🗓 Planned | Q4 2026 |
| Multi-LLM support (GPT-4, Gemini) | 🗓 Planned | Q4 2026 |
| GRC platform connectors | 🗓 Planned | 2027 |

---

## Contributing

Contributions are welcome. To add a new skill or improve an existing one:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-new-skill`
3. Follow the existing skill structure — include `main.py`, `skill.yaml`, `config.yaml`, and tests under `tests/`
4. Ensure all tests pass: `pytest tests/`
5. Open a pull request with a clear description of what the skill does and which framework controls it addresses

Please read `CONTRIBUTING.md` for code style guidelines and the full skill authoring guide.

---

## Author

**Maxwell Okumu**

Open to IT Audit Consulting, AI Systems Design, and Security Automation engagements.

- Profile: https://maxwellokumu.github.io
- Email: omaxwell23@gmail.com

---

## License

MIT © Maxwell Okumu — see [LICENSE](LICENSE) for full terms.
