# application-security/playbook

A six-step application security audit playbook covering the full secure development lifecycle — from threat modelling through to vulnerability management and reporting.

## Requirements

- Python 3.8+
- No external dependencies

## Usage

```bash
# Full playbook
python main.py

# Single step
python main.py --step 2
```

### Steps

| Step | Title |
|------|-------|
| 1 | Threat Modeling & Attack Surface Review |
| 2 | SAST & Code Review |
| 3 | DAST & Penetration Testing |
| 4 | Dependency & Supply Chain Security |
| 5 | DevSecOps Pipeline Review |
| 6 | Vulnerability Management & Reporting |
