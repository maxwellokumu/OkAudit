# asset-validator

Reconcile your authorised IT asset inventory against a network-discovered device list to surface **ghost assets** (inventory entries not found on the network) and **rogue assets** (unauthorised devices found on the network).

## Requirements

- Python 3.8+
- No external dependencies (stdlib only)

## Usage

```bash
python main.py \
  --inventory sample_input/asset_inventory.csv \
  --discovered sample_input/discovered_assets.csv
```

### Options

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--inventory` | ✅ | — | Path to authorised asset inventory CSV |
| `--discovered` | ✅ | — | Path to network-discovered assets CSV |
| `--output` | | `markdown` | Output format: `markdown` \| `json` \| `csv` |

### CSV Schema (both files)

```
asset_id,hostname,type,location,owner,last_seen
```

## Sample Output

```
# Asset Validation Report

**Generated:** 2024-06-01 10:00 UTC
**Inventory Size:** 20
**Coverage:** 85.0%

## Summary

| Category | Count | % of Total |
|----------|-------|------------|
| Matched  | 16    | 80.0%      |
| Ghost    | 2     | 10.0%      |
| Rogue    | 2     | 10.0%      |

## Rogue Assets (2 — Discovered, Not in Inventory)

| Asset ID   | Hostname      | Type        | Location  | Risk Level   |
|------------|---------------|-------------|-----------|--------------|
| ROGUE-001  | unknown-srv-1 | server      | DC-Floor2 | **Critical** |
| ROGUE-002  | pi-unknown    | iot         | Office-B  | **High**     |
```
