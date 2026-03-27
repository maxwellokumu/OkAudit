# threat-correlator

Correlates network log events against Indicators of Compromise (IOCs) — including IPv4/IPv6 addresses, CIDR ranges, domain names, and MD5/SHA256 hashes. Produces a match report with hit frequency analysis and unmatched IOC listings.

## Requirements

```
python-dotenv
```

No third-party IP libraries required — uses Python's built-in `ipaddress` module.

## Usage

### Markdown report (default)
```bash
python main.py --logs sample_input/network_logs.csv --iocs sample_input/iocs.txt
```

### JSON output
```bash
python main.py --logs sample_input/network_logs.csv --iocs sample_input/iocs.txt --output json
```

### CSV output
```bash
python main.py --logs sample_input/network_logs.csv --iocs sample_input/iocs.txt --output csv
```

## Log File Format

CSV with columns: `timestamp,src_ip,dst_ip,src_port,dst_port,protocol,action,bytes`

Or JSON-lines (`.jsonl`) with the same fields as keys.

## IOC File Format

One entry per line. Supports:
- IPv4 address: `185.220.101.5`
- IPv6 address: `2001:db8::1`
- CIDR range: `10.10.0.0/16`
- Domain name: `malicious-c2.example.com`
- MD5 hash: `d41d8cd98f00b204e9800998ecf8427e`
- SHA256 hash: `e3b0c44298fc1c149afb...`

## Sample Output

```markdown
# Threat Correlation Report

**Generated:** 2024-01-15 09:00 UTC
**Log File:** sample_input/network_logs.csv
**IOC Count:** 15

## Match Summary

| Metric | Value |
|--------|-------|
| Total Log Events | 40 |
| Total Matches | 8 |
| Unique IOCs Matched | 5 |
| Unmatched IOCs | 10 |
```
