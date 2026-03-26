# artefact-gap-analyzer

Compare expected audit evidence artefacts from an audit program against files you have
collected, and report exactly what is still missing — with coverage percentage.

---

## Purpose

After generating an audit program with `audit-scope-checklist`, use this skill to:
- Track which required artefacts have been collected
- Identify gaps with their control IDs, details, and acceptance criteria
- Report overall evidence coverage as a percentage

---

## Requirements

```bash
pip install python-dotenv
```

---

## Usage

```bash
# Compare against a comma-separated list of file names
python main.py \
  --program audit_program.json \
  --provided "iam_policy.pdf,user_access_report.csv,firewall_rules.xlsx"

# Compare against an entire directory of evidence files
python main.py \
  --program audit_program.json \
  --provided ./evidence/

# Using sample input files
python main.py \
  --program sample_input/sample_audit_program.json \
  --provided sample_input/sample_evidence/
```

---

## Sample Output (truncated)

```markdown
# Artefact Gap Analysis Report
**Date:** 2025-07-01  
**Controls reviewed:** 12 | **Matched:** 7 | **Missing:** 5 | **Coverage:** 58.3%

## ✅ Matched Artefacts
| ID | Artefact | Matched File |
|----|----------|-------------|
| IAM-001 | user_access_report.csv | user_access_report.csv |

## ❌ Missing Artefacts
| ID | Artefact | Details | Acceptance Criteria |
|----|----------|---------|---------------------|
| IAM-002 | mfa_status_report.csv | Confirm MFA enabled for all users | 100% of users enrolled... |
```

---

## Notes

- Artefact matching is **case-insensitive**
- If `--provided` is a directory, all files in that directory (non-recursive) are checked
- Partial name matches are not used — the artefact filename must appear in the provided list
