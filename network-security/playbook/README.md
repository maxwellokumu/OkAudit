# network-security-playbook

Step-by-step network security audit playbook covering 6 phases: asset discovery, firewall rule review, segmentation validation, threat intelligence correlation, vulnerability scanning, and reporting. Links directly to the other network-security skills.

## Requirements

```
python-dotenv
```

## Usage

### Run full playbook
```bash
python main.py
```

### Run a specific step
```bash
python main.py --step 2
```

### Available Steps

| Step | Title |
|------|-------|
| 1 | Network Asset Discovery & Inventory |
| 2 | Firewall & ACL Rule Review |
| 3 | Network Segmentation Validation |
| 4 | Threat Intelligence Correlation |
| 5 | Vulnerability Scanning & Patch Review |
| 6 | Reporting & Remediation Roadmap |
