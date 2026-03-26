# log-analyzer

Parse CloudTrail-format JSON-lines logs and flag suspicious events using a built-in
library of 24 patterns. Supports custom pattern overrides, date range filtering,
and live AWS CloudTrail.

---

## Requirements

```bash
pip install python-dotenv boto3
```

---

## Usage

```bash
# Local file analysis
python main.py --logs sample_input/cloudtrail.jsonl

# Filter by date range
python main.py \
  --logs sample_input/cloudtrail.jsonl \
  --start "2025-07-01T00:00:00" \
  --end "2025-07-01T23:59:59"

# Add custom patterns
python main.py \
  --logs sample_input/cloudtrail.jsonl \
  --patterns custom_patterns.json

# AWS live mode (dry-run)
python main.py --mode aws --dry-run

# AWS live mode
python main.py --mode aws --start "2025-07-01T00:00:00"
```

---

## Log Format (JSON-lines)

```json
{"timestamp": "2025-07-01T10:00:00", "user": "root", "action": "DeleteTrail", "source_ip": "10.0.0.1", "resource": "cloudtrail:::main"}
```

---

## Built-in Patterns (24 total)

| Event | Severity |
|-------|----------|
| DeleteTrail | 🚨 Critical |
| StopLogging | 🚨 Critical |
| RootAccountUsage | 🚨 Critical |
| DeleteSecret | 🚨 Critical |
| ScheduleKeyDeletion | 🚨 Critical |
| ConsoleLoginFailure | 🔴 High |
| UpdateLoginProfile | 🔴 High |
| DeleteBucket | 🔴 High |
| PutBucketPolicy | 🔴 High |
| AttachUserPolicy | 🔴 High |
| DeleteUser | 🔴 High |
| DeleteVpc | 🔴 High |
| PutBucketAcl | 🔴 High |
| DisableKey | 🔴 High |
| PutEventSelectors | 🔴 High |
| DeleteFlowLogs | 🔴 High |
| AuthorizationFailure | 🟠 Medium |
| CreateAccessKey | 🟠 Medium |
| DeleteAccessKey | 🟠 Medium |
| TerminateInstances | 🟠 Medium |
| ModifySecurityGroup | 🟠 Medium |
| PutSecretValue | 🟠 Medium |
| CreateUser | 🟡 Low |
| GetSecretValue | 🟡 Low |
