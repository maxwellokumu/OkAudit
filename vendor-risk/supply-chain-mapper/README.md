# supply-chain-mapper

Generate a Mermaid supply chain diagram and markdown inventory table from a vendor
CSV. Critical vendors appear in red, data-access vendors in orange, and tier 2+
relationships use dashed edges.

---

## Requirements

```bash
pip install python-dotenv
```

---

## Usage

```bash
# Both Mermaid diagram and markdown table
python main.py --vendors sample_input/vendors.csv

# Mermaid only
python main.py --vendors sample_input/vendors.csv --output mermaid

# Markdown table only
python main.py --vendors sample_input/vendors.csv --output markdown
```

---

## CSV Format

```csv
vendor,dependencies,criticality,data_access,tier
AWS,CloudFlare|Datadog,Critical,yes,1
Salesforce,,High,yes,1
Datadog,PagerDuty,Medium,no,2
```

- **dependencies**: pipe-separated list of vendor names, or empty
- **criticality**: Critical, High, Medium, or Low
- **data_access**: yes or no
- **tier**: 1 (direct), 2 (sub-vendor), 3 (nth-party)

---

## Node Styling

| Style | Meaning |
|-------|---------|
| 🔴 Red node | Critical vendor |
| 🟠 Orange node | Vendor with data access (non-Critical) |
| Dashed edge | Tier 2+ relationship |
| Blue node | Your Organisation |
