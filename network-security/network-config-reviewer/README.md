# network-config-reviewer

Analyses firewall rules and AWS Security Groups for security misconfigurations including open inbound access, sensitive port exposure, deprecated protocol usage, any-to-any rules, and overly broad port ranges. Outputs a risk-rated violations report with remediation recommendations.

## Requirements

```
python-dotenv
boto3  # only required for --mode aws
```

## Usage

### Local CSV mode
```bash
python main.py --rules sample_input/firewall_rules.csv
```

### AWS Security Groups (live)
```bash
python main.py --mode aws
```

### AWS dry-run (uses bundled sample data)
```bash
python main.py --mode aws --dry-run
```

## Sample Output

```markdown
# Network Configuration Review Report

**Generated:** 2024-01-15 09:00 UTC
**Total Rules Analysed:** 20

## Summary

| Metric | Count |
|--------|-------|
| Total Rules | 20 |
| Compliant Rules | 6 |
| Rules with Violations | 14 |
| Total Violations | 18 |
| Critical Violations | 4 |
| High Violations | 7 |
| Medium Violations | 3 |
| Low Violations | 4 |

## Violations

| Rule # | Source | Destination | Port | Protocol | Issue | Risk |
|--------|--------|-------------|------|----------|-------|------|
| 3 | `any` | `any` | any | any | Any-to-any ALLOW rule | **Critical** |
...
```
