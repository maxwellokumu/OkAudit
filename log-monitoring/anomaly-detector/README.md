# anomaly-detector

Detect behavioural anomalies by comparing user activity in a test period against
a historical baseline. Uses mean + N×standard deviation thresholds per user. Also
flags new users and new source IPs not seen during the baseline period.

---

## Requirements

```bash
pip install python-dotenv
```

---

## Usage

```bash
# Basic comparison
python main.py \
  --logs sample_input/baseline_logs.jsonl \
  --test sample_input/test_logs.jsonl

# Higher sensitivity (fewer false positives)
python main.py \
  --logs sample_input/baseline_logs.jsonl \
  --test sample_input/test_logs.jsonl \
  --sensitivity 3.0

# Lower sensitivity (catch more subtle anomalies)
python main.py \
  --logs sample_input/baseline_logs.jsonl \
  --test sample_input/test_logs.jsonl \
  --sensitivity 1.5 \
  --min-events 3
```

---

## Log Format

Both files use JSON-lines format:

```json
{"timestamp": "2025-07-01T09:00:00", "user": "alice", "action": "GetObject", "source_ip": "10.0.0.1"}
```

---

## How It Works

1. Reads the baseline log and computes **per-user, per-day** action counts
2. Calculates **mean** and **standard deviation** per user
3. Sets threshold = `mean + (sensitivity × std_dev)`
4. Evaluates each user in the test file against their personal threshold
5. Flags any day where count > threshold, plus new users and new IPs
