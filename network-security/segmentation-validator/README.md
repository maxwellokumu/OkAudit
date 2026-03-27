# segmentation-validator

Validates network segmentation by mapping firewall rules to defined network zones (Internet, DMZ, Internal, DB, Management, etc.) and detecting unauthorised cross-zone ALLOW flows. Flags high-risk paths such as DMZ → Internal or Internet → DB.

## Requirements

```
python-dotenv
```

Uses Python's built-in `ipaddress` module — no third-party IP libraries required.

## Usage

```bash
python main.py --zones sample_input/zones.json --rules sample_input/segmentation_rules.csv
```

## Input Formats

### zones.json
```json
{
  "Internet": ["0.0.0.0/0"],
  "DMZ": ["172.16.10.0/24"],
  "Internal": ["10.0.1.0/24", "10.0.2.0/24"],
  "DB": ["10.0.3.0/24"],
  "Management": ["10.0.4.0/24"]
}
```

### segmentation_rules.csv
```
source,destination,port,protocol,action
172.16.10.5,10.0.3.10,3306,TCP,ALLOW
```

## Sample Output

```markdown
# Network Segmentation Validation Report

**Generated:** 2024-01-15 09:00 UTC
**Total Rules:** 25

## Zone Definitions

| Zone | CIDRs |
|------|-------|
| Internet | `0.0.0.0/0` |
| DMZ | `172.16.10.0/24` |
...

## Classification Summary

| Classification | Count |
|----------------|-------|
| Intra-zone (compliant) | 8 |
| Inter-zone ALLOWED (flagged) | 11 |
| **High-risk cross-zone flows** | **4** |
```
