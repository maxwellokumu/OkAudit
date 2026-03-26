# contract-checker

Check vendor, SaaS, or data-processor contracts for required clauses using
keyword and synonym matching. Three built-in clause libraries (10–12 clauses each)
plus support for custom clause lists.

---

## Requirements

```bash
pip install python-dotenv
```

---

## Usage

```bash
# Check vendor contract
python main.py \
  --contract sample_input/vendor_contract.txt \
  --standard vendor

# Check SaaS contract
python main.py \
  --contract sample_input/vendor_contract.txt \
  --standard saas

# Check data processor agreement (GDPR)
python main.py \
  --contract sample_input/vendor_contract.txt \
  --standard data-processor

# Custom clause list
python main.py \
  --contract sample_input/vendor_contract.txt \
  --requirements sample_input/required_clauses.json

# Combine built-in + custom
python main.py \
  --contract sample_input/vendor_contract.txt \
  --standard vendor \
  --requirements sample_input/required_clauses.json
```

---

## Built-in Standards

| Standard | Clauses |
|----------|---------|
| `vendor` | Breach Notification, Right to Audit, Liability Cap, IP Ownership, Confidentiality, Termination, SLA, Indemnification, Governing Law, Force Majeure, Subcontractor Approval, Insurance |
| `saas` | Uptime SLA, Data Portability, Data Deletion, Security Certs, Incident Notification, Support SLA, Data Residency, API Limits, Price Notice, Service Credits |
| `data-processor` | GDPR Art.28, DPA, Data Subject Rights, Sub-processor Restrictions, Transfer Safeguards, Audit Rights, 72hr Breach Notification, Data Deletion, Processing Instructions, TOM |
