# consent-checker

Analyses a plain-text privacy policy against built-in requirement libraries for GDPR (16 requirements), CCPA (11 requirements), or PDPA Thailand (10 requirements). Produces a weighted compliance score, requirements-met table, and a detailed gap analysis with risk ratings and remediation recommendations.

## Requirements

```
python-dotenv
```

## Usage

### GDPR check (default)
```bash
python main.py --policy sample_input/privacy_policy.txt
```

### CCPA check
```bash
python main.py --policy sample_input/privacy_policy.txt --framework ccpa
```

### PDPA check
```bash
python main.py --policy sample_input/privacy_policy.txt --framework pdpa
```

## Scoring

Requirements are weighted 1–5 (5 = most critical). The compliance score is the weighted percentage of met requirements:

| Rating | Score |
|--------|-------|
| ✅ Compliant | ≥ 85% |
| ⚠️ Partial | 60–84% |
| ❌ Non-Compliant | < 60% |

## Sample Output

```markdown
# Privacy Policy Compliance Report

**Framework:** GDPR
**Policy Word Count:** 612

## Compliance Score

| Metric | Value |
|--------|-------|
| Requirements Checked | 16 |
| Requirements Met | 11 |
| Requirements Missing | 5 |
| Weighted Score | 42/57 points (73.7%) |
| Overall Rating | ⚠️ **Partial** |

## Requirements Met

| ID | Requirement | Matched On | Status |
|----|-------------|------------|--------|
| GDPR-01 | Identity of the data controller | `data controller` | ✅ Met |
...

## Missing Requirements

| ID | Requirement | Weight | Risk | Recommendation |
|----|-------------|--------|------|----------------|
| GDPR-14 | Automated decision-making disclosure | 3/5 | Medium | ... |
```
