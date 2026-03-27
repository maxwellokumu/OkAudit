# firmware-checker

Audit device firmware versions against a database of known CVEs. Identifies unpatched devices with Critical, High, Medium, or Low severity vulnerabilities using a built-in library of 15+ real-world firmware CVEs.

## Requirements

- Python 3.8+
- No external dependencies

## Usage

```bash
# Use built-in CVE database
python main.py --devices sample_input/devices.csv

# Use custom CVE database
python main.py --devices sample_input/devices.csv --cve-db /path/to/custom_cves.csv
```

### Options

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--devices` | ✅ | — | Path to devices CSV |
| `--cve-db` | | built-in | Path to custom CVE database CSV |

### Devices CSV Schema

```
device_id,vendor,model,current_firmware
```

### CVE DB CSV Schema (if supplying custom DB)

```
vendor,model,vulnerable_version,cve_id,severity,description,remediation
```

## Sample Output

```
# Firmware Vulnerability Report

**Generated:** 2024-06-01 10:00 UTC
**Devices Checked:** 12
**Vulnerable Devices:** 7
**Total CVE Findings:** 9

## ⚠️ Critical Actions Required

**DEV-003 (Cisco IOS)** — CVE-2023-20198
- **Risk:** HTTP UI privilege escalation allows unauthenticated remote attacker to create admin account
- **Action:** Upgrade to IOS 15.9.3M2 or later; disable HTTP server if unused
```
