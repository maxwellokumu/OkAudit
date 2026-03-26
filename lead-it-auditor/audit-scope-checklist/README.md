# audit-scope-checklist

Generate a scoped IT audit program with controls mapped to roles and compliance frameworks.
Outputs a formatted markdown report and an `audit_program.json` file for use by other skills.

---

## Purpose

Given a system description, this skill produces a complete audit program including:
- Scope statement and team role assignments
- Control-by-control checklist with artefacts and acceptance criteria
- Framework annotations (SOC2, CIS, ISO27001, etc.)
- Machine-readable `audit_program.json` for downstream tools

---

## Requirements

```bash
pip install python-dotenv
```

---

## Usage

```bash
# Basic — all roles, no framework filter
python main.py --system "AWS production environment with EC2, S3, RDS, and IAM"

# Filter to specific roles
python main.py \
  --system "Azure AD and Office 365 tenant" \
  --roles "identity-access,compliance-controls"

# Annotate with frameworks
python main.py \
  --system "On-premise Windows Active Directory environment" \
  --roles "identity-access,log-monitoring,network-security" \
  --frameworks "CIS,ISO27001"

# Write output JSON to a specific directory
python main.py \
  --system "SaaS application on AWS" \
  --output-dir ./audit-2025-q3/
```

---

## Sample Output (truncated)

```markdown
# IT Audit Program
**System:** AWS production environment with EC2, S3, RDS, and IAM
**Date:** 2025-07-01
**Frameworks:** SOC2, CIS

## Scope
...

## Control Checklist

| ID | Role | Control | Artefact | Acceptance Criteria |
|----|------|---------|----------|---------------------|
| LIA-001 | Lead IT Auditor | Audit charter and independence | audit_charter.pdf | Signed charter on file... |
| IAM-001 | Identity & Access | User access inventory | user_access_report.csv | Full list exported... |
```

---

## Output Files

| File | Description |
|------|-------------|
| stdout | Markdown audit program report |
| `audit_program.json` | Structured control data for artefact-gap-analyzer |

---

## Role IDs

Use these IDs with `--roles`:

| ID | Role |
|----|------|
| `lead-it-auditor` | Lead IT Auditor |
| `identity-access` | Identity & Access Management |
| `compliance-controls` | Compliance & Controls |
| `log-monitoring` | Logging & Monitoring |
| `vendor-risk` | Vendor & Third-Party Risk |
| `network-security` | Network & Cybersecurity |
| `data-privacy` | Data Privacy |
| `hardware-physical` | Hardware & Physical Security |
| `application-security` | Application Security |
