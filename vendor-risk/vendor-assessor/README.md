# vendor-assessor

Score a vendor's security posture using a standardised 25-question assessment
across 5 risk categories. Produces category scores, an overall weighted risk
level, and prioritised recommendations.

---

## Requirements

```bash
pip install python-dotenv
```

---

## Usage

```bash
# Basic assessment
python main.py --answers sample_input/vendor_answers.json

# With custom category weights
python main.py \
  --answers sample_input/vendor_answers.json \
  --weights sample_input/weights.json

# JSON output
python main.py --answers sample_input/vendor_answers.json --output json
```

---

## Answer Format

```json
{
  "Q001": "yes",
  "Q002": "yes",
  "Q003": "partial",
  "Q004": "no",
  "Q005": "na"
}
```

Valid values: `yes` (100pts), `partial` (50pts), `no` (0pts), `na` (excluded)

---

## Risk Levels

| Score | Risk Level |
|-------|------------|
| 80–100 | 🟢 Low |
| 60–79 | 🟡 Medium |
| 40–59 | 🟠 High |
| 0–39 | 🔴 Critical |
