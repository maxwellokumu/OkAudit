# exec-summary-writer

Convert a structured findings JSON file into a polished executive summary report
ready for presentation to management or the audit committee.

---

## Purpose

Takes a list of audit findings and produces a professional markdown executive summary with:
- Scope, author, and date header
- Narrative overview paragraph
- Key findings table with risk levels
- Risk summary with counts by severity
- Prioritised recommendations
- Standard next steps / remediation timeline

---

## Requirements

```bash
pip install python-dotenv
```

---

## Findings JSON Schema

Each finding must have these fields:

```json
[
  {
    "title": "Overly permissive IAM policies",
    "description": "Several IAM roles were found with wildcard actions...",
    "risk_level": "High",
    "recommendation": "Implement least-privilege IAM policies...",
    "affected_system": "AWS IAM"
  }
]
```

Valid `risk_level` values: `Critical`, `High`, `Medium`, `Low`, `Informational`

---

## Usage

```bash
# Minimal usage
python main.py --findings findings.json

# With scope, author and date
python main.py \
  --findings findings.json \
  --scope "Q3 2025 AWS Infrastructure Audit" \
  --author "Jane Smith, CISA" \
  --date "2025-07-15"

# Using sample input
python main.py \
  --findings sample_input/findings.json \
  --scope "Sample Audit Engagement"
```

---

## Sample Output (truncated)

```markdown
# Executive Summary — IT Audit Report
**Scope:** Q3 2025 AWS Infrastructure Audit
**Author:** Jane Smith, CISA  
**Date:** 2025-07-15

## Overview
This report presents the findings of the Q3 2025 IT audit...

## Key Findings
| # | Title | Affected System | Risk Level |
|---|-------|----------------|------------|
| 1 | Overly permissive IAM policies | AWS IAM | 🔴 High |

## Risk Summary
| Risk Level | Count | % of Total |
|------------|-------|------------|
| 🚨 Critical | 1 | 12.5% |
| 🔴 High | 3 | 37.5% |
```
