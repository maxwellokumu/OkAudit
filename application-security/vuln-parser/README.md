# vuln-parser

Parse vulnerability scanner output (Nessus, OpenVAS, or any CSV-format scan) to produce a risk-ranked report with per-host scoring, severity breakdown, ASCII chart, and a remediation priority matrix.

## Requirements

- Python 3.8+
- No external dependencies

## Usage

```bash
python main.py --scan sample_input/vuln_scan.csv
```

### Options

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--scan` | ✅ | — | Path to vulnerability scan CSV |
| `--output` | | `markdown` | Output format: `markdown` \| `json` \| `csv` |
| `--top-hosts` | | `10` | Number of riskiest hosts to highlight |

### CSV Schema

```
vulnerability,severity,host,port,cve_id,description,plugin_id
```

`severity` values: `Critical`, `High`, `Medium`, `Low`, `Informational`

## Risk Scoring

| Severity | Weight |
|----------|--------|
| Critical | 10 |
| High | 5 |
| Medium | 2 |
| Low | 1 |
| Informational | 0 |

## Sample Output

```
# Vulnerability Scan Report

**Total Findings:** 40
**Unique Hosts:** 8

## Executive Summary

Critical        ████████████████████ 8 (20.0%)
High            ██████████           10 (25.0%)
Medium          ████████████         12 (30.0%)
Low             ████████             8 (20.0%)
Informational   ██                   2 (5.0%)
```
