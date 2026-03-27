# code-review-helper

Regex-based static security analysis for Python, JavaScript, Java, and Go source files. Detects 8 vulnerability classes per language with CWE references and actionable remediation guidance.

## Requirements

- Python 3.8+
- No external dependencies

## Usage

```bash
python main.py --code sample_input/vulnerable_app.py --language python

python main.py --code sample_input/vulnerable_app.js --language javascript --output json
```

### Options

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--code` | ✅ | — | Path to source file |
| `--language` | ✅ | — | `python` \| `javascript` \| `java` \| `go` |
| `--output` | | `markdown` | `markdown` \| `json` |

## Vulnerability Classes Detected

| Language | Classes |
|----------|---------|
| Python | Hardcoded Secrets, eval/exec, SQL Injection, Weak Crypto, Debug Mode, Insecure Deserialization, Path Traversal, Open Redirect |
| JavaScript | eval(), innerHTML XSS, document.write XSS, Sensitive localStorage, Prototype Pollution, dangerouslySetInnerHTML, Open Redirect, ReDoS |
| Java | SQL Injection, XXE, Insecure Deserialization, Hardcoded Secrets, Weak Crypto, Path Traversal, Command Injection, JNDI Injection |
| Go | Hardcoded Secrets, unsafe.Pointer, Command Injection, SQL Injection, Weak Crypto, Path Traversal, Open Redirect, Goroutine Leak |

## Sample Output

```
# Code Security Review

**File:** sample_input/vulnerable_app.py
**Language:** python
**Total Findings:** 8

| Line | Vulnerability     | Severity | CWE     | Code Snippet              |
|------|-------------------|----------|---------|---------------------------|
| 5    | Hardcoded Secrets | Critical | CWE-798 | password = "sup3rs3cret"  |
| 12   | SQL Injection     | Critical | CWE-89  | cursor.execute("SELECT... |
```

> This tool performs regex-based pattern matching and is not a substitute for a full SAST tool.
