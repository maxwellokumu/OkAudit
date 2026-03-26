# incident-timeline-builder

Build a chronological incident timeline from log files, grouped by hour with
suspicious events flagged. Supports actor filtering, date range scoping, and
JSON output for downstream processing.

---

## Requirements

```bash
pip install python-dotenv
```

---

## Usage

```bash
# Full timeline
python main.py --logs sample_input/incident_logs.jsonl

# Filter by time window
python main.py \
  --logs sample_input/incident_logs.jsonl \
  --start "2025-07-01T09:00:00" \
  --end "2025-07-01T15:00:00"

# Filter by actor
python main.py \
  --logs sample_input/incident_logs.jsonl \
  --actor "root"

# JSON output
python main.py \
  --logs sample_input/incident_logs.jsonl \
  --output json

# Combine filters
python main.py \
  --logs sample_input/incident_logs.jsonl \
  --actor "203.0.113.5" \
  --start "2025-07-01T00:00:00" \
  --output json
```

---

## Sample Output (truncated)

```markdown
# Incident Timeline Report

**Total Events:** 40
**Flagged Events:** 12

## 2025-07-01 09:00 — 4 event(s)

- 🚨 `2025-07-01T09:30:00` | `root` [203.0.113.5] | **RootAccountUsage** → `iam`
- 🚨 `2025-07-01T09:35:00` | `root` [203.0.113.5] | **DeleteTrail** → `cloudtrail:::audit-trail`
- ✅ `2025-07-01T09:10:00` | `alice` [10.0.0.1] | **PutObject** → `s3:::prod-bucket`
```
