# pia-generator

Generates a fully structured Privacy Impact Assessment (PIA / DPIA) in markdown from command-line parameters. Maps data types to risk levels, selects applicable risks from a 10-item library, and produces an 8-section document including data flows, legal basis assessment, risk scoring, data subject rights checklist, DPO recommendations, and a sign-off block.

## Requirements

```
python-dotenv
```

## Usage

### Basic GDPR PIA
```bash
python main.py \
  --project "Employee Health Portal" \
  --data-types "health,contact_details,employee_records" \
  --purposes "occupational health management,legal compliance" \
  --recipients "HR department,Occupational Health Provider,HMRC" \
  --retention "7 years" \
  --controller "Acme Solutions Ltd" \
  --dpo "dpo@acmesolutions.com"
```

### ISO 27701 assessment
```bash
python main.py \
  --project "Customer Analytics Platform" \
  --data-types "behavioral,contact,location" \
  --purposes "analytics,marketing,profiling" \
  --recipients "Marketing team,Analytics Provider" \
  --retention "2 years" \
  --framework iso27701
```

## Data Type Risk Levels

| Level | Examples |
|-------|---------|
| Very High | health, biometric, criminal_record, genetic, children_data |
| High | financial, location, behavioral, profiling |
| Medium | contact, email, employee, identifier |
| Low | public, aggregated, anonymised |

## PIA Sections Generated

1. PIA Header (project metadata, controller, DPO)
2. Project Overview
3. Data Flows (table per data type × purpose × recipient)
4. Legal Basis Assessment (per purpose)
5. Risk Assessment (10-item risk library, scored and mitigated)
6. Data Subject Rights Compliance Checklist
7. DPO Recommendations
8. Sign-off Block

## Sample Output

```markdown
# Privacy Impact Assessment
## Employee Health Portal

## 1. PIA Header

| Field | Value |
|-------|-------|
| Project / System Name | Employee Health Portal |
| Overall Risk Level | **Very High** |
...

## 5. Risk Assessment

| Risk ID | Risk | Likelihood | Impact | Risk Score |
|---------|------|------------|--------|------------|
| PR-01 | Unauthorised Access | Medium | High | **High** |
| PR-02 | Data Breach | Low | Very High | **High** |
```
