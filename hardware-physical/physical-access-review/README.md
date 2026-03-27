# physical-access-review

Analyse badge access logs to detect after-hours access, failed attempt bursts, tailgating and forced entry events, unauthorised door access, and suspicious rapid multi-door traversal patterns.

## Requirements

- Python 3.8+
- No external dependencies

## Usage

```bash
# Basic analysis
python main.py --logs sample_input/badge_logs.csv

# With role mapping and custom business hours
python main.py \
  --logs sample_input/badge_logs.csv \
  --roles sample_input/roles.json \
  --hours 08:00-18:00 \
  --failed-threshold 5
```

### Options

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--logs` | ✅ | — | Path to badge access log CSV |
| `--hours` | | `07:00-19:00` | Business hours window (HH:MM-HH:MM) |
| `--roles` | | — | Path to roles JSON for door authorisation checks |
| `--failed-threshold` | | `3` | Max failures per hour per badge before flagging |

### Badge Log CSV Schema

```
badge_id,door,timestamp,result
```

`result` values: `SUCCESS`, `FAILED`, `TAILGATE`, `FORCED`

### Roles JSON Schema

```json
{
  "B001": {
    "name": "Alice Smith",
    "role": "Engineer",
    "allowed_doors": ["main-entrance", "office-a", "server-room"]
  }
}
```

## Sample Output

```
# Physical Access Audit Report

## Summary

| Category                  | Count |
|---------------------------|-------|
| After-Hours Access        | 4     |
| Failed Attempt Bursts     | 1     |
| Tailgate / Forced Events  | 1     |
| Unauthorised Door Access  | 2     |
| Anomalous Patterns        | 1     |
```
