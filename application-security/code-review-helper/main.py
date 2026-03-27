"""Code Review Helper — regex-based security static analysis.

Scans source files for common vulnerability patterns across Python,
JavaScript, Java, and Go, producing findings with CWE references
and remediation recommendations.
"""

import argparse
import json
import re
import sys
from datetime import datetime
from typing import Dict, List, NamedTuple, Tuple


class Pattern(NamedTuple):
    """A vulnerability detection pattern."""

    vuln_class: str
    regex: str
    severity: str
    cwe_id: str
    description: str
    recommendation: str


# CWE map
CWE: Dict[str, str] = {
    "Hardcoded Secrets": "CWE-798",
    "eval/exec Usage": "CWE-95",
    "SQL Injection": "CWE-89",
    "Weak Cryptography": "CWE-327",
    "Debug Mode Enabled": "CWE-489",
    "Insecure Deserialization": "CWE-502",
    "Path Traversal": "CWE-22",
    "Open Redirect": "CWE-601",
    "eval() Usage": "CWE-95",
    "XSS via innerHTML": "CWE-79",
    "XSS via document.write": "CWE-79",
    "Sensitive Data in localStorage": "CWE-922",
    "Prototype Pollution": "CWE-1321",
    "XSS via dangerouslySetInnerHTML": "CWE-79",
    "Command Injection": "CWE-78",
    "ReDoS": "CWE-1333",
    "XXE Injection": "CWE-611",
    "Insecure Deserialization (Java)": "CWE-502",
    "JNDI Injection": "CWE-917",
    "unsafe.Pointer Usage": "CWE-119",
    "Goroutine Leak": "CWE-404",
}

PATTERNS: Dict[str, List[Pattern]] = {
    "python": [
        Pattern(
            "Hardcoded Secrets",
            r'(?i)(password|api_key|secret|token)\s*=\s*["\'][^"\']{4,}["\']',
            "Critical",
            CWE["Hardcoded Secrets"],
            "Hardcoded credential or secret found in source code",
            "Move secrets to environment variables or a secrets manager (e.g. AWS Secrets Manager, HashiCorp Vault)",
        ),
        Pattern(
            "eval/exec Usage",
            r'\b(eval|exec)\s*\(',
            "High",
            CWE["eval/exec Usage"],
            "Dynamic code execution via eval() or exec() enables code injection",
            "Avoid eval/exec entirely; use ast.literal_eval() for safe literal parsing",
        ),
        Pattern(
            "SQL Injection",
            r'(?i)(execute|cursor\.execute|db\.execute)\s*\(\s*["\'].*%[s|d].*["\']|f["\'].*SELECT.*{',
            "Critical",
            CWE["SQL Injection"],
            "String formatting in SQL query may allow SQL injection",
            "Use parameterised queries: cursor.execute('SELECT ... WHERE id = %s', (user_id,))",
        ),
        Pattern(
            "Weak Cryptography",
            r'\bhashlib\.(md5|sha1)\s*\(',
            "High",
            CWE["Weak Cryptography"],
            "MD5 or SHA1 are cryptographically broken and unsuitable for security purposes",
            "Use hashlib.sha256() or stronger; use bcrypt/argon2 for passwords",
        ),
        Pattern(
            "Debug Mode Enabled",
            r'(?i)(DEBUG\s*=\s*True|app\.run\(.*debug\s*=\s*True)',
            "Medium",
            CWE["Debug Mode Enabled"],
            "Debug mode exposes stack traces and internal details to users",
            "Set DEBUG=False in production; use environment variable: DEBUG=os.getenv('DEBUG', False)",
        ),
        Pattern(
            "Insecure Deserialization",
            r'\bpickle\.loads?\s*\(|yaml\.load\s*\([^,)]*\)',
            "High",
            CWE["Insecure Deserialization"],
            "pickle.load or yaml.load without Loader allows arbitrary code execution",
            "Avoid pickle for untrusted data; use yaml.safe_load() instead of yaml.load()",
        ),
        Pattern(
            "Path Traversal",
            r'open\s*\(\s*[a-z_]*\s*\+|os\.path\.join\s*\([^)]*request\.|os\.path\.join\s*\([^)]*input\(',
            "High",
            CWE["Path Traversal"],
            "User-controlled input in file path may allow directory traversal",
            "Validate and sanitise file paths; use os.path.abspath() and check it starts with expected base dir",
        ),
        Pattern(
            "Open Redirect",
            r'redirect\s*\(\s*request\.(args|form|values|GET|POST)',
            "Medium",
            CWE["Open Redirect"],
            "Redirecting to user-controlled URL may enable phishing attacks",
            "Validate redirect URLs against an allowlist of safe destinations",
        ),
    ],
    "javascript": [
        Pattern(
            "eval() Usage",
            r'\beval\s*\(',
            "High",
            CWE["eval() Usage"],
            "eval() executes arbitrary JavaScript from a string, enabling code injection",
            "Remove eval(); use JSON.parse() for JSON or refactor logic",
        ),
        Pattern(
            "XSS via innerHTML",
            r'\.innerHTML\s*=',
            "High",
            CWE["XSS via innerHTML"],
            "Assigning untrusted data to innerHTML allows cross-site scripting",
            "Use textContent or innerText for plain text; sanitise HTML with DOMPurify",
        ),
        Pattern(
            "XSS via document.write",
            r'document\.write\s*\(',
            "High",
            CWE["XSS via document.write"],
            "document.write with user-controlled data enables XSS",
            "Replace document.write() with DOM manipulation methods (createElement, appendChild)",
        ),
        Pattern(
            "Sensitive Data in localStorage",
            r'localStorage\.setItem\s*\(\s*["\'][^"\']*(?:password|token|secret|key)[^"\']*["\']',
            "High",
            CWE["Sensitive Data in localStorage"],
            "Storing sensitive data in localStorage exposes it to XSS attacks",
            "Use httpOnly cookies for session tokens; never store credentials client-side",
        ),
        Pattern(
            "Prototype Pollution",
            r'(__proto__|constructor\[.{0,20}prototype)',
            "High",
            CWE["Prototype Pollution"],
            "Prototype pollution via __proto__ or constructor.prototype can affect all objects",
            "Validate input keys; use Object.create(null) for dictionaries; freeze prototypes",
        ),
        Pattern(
            "XSS via dangerouslySetInnerHTML",
            r'dangerouslySetInnerHTML',
            "High",
            CWE["XSS via dangerouslySetInnerHTML"],
            "dangerouslySetInnerHTML in React can enable XSS if value is user-controlled",
            "Sanitise HTML with DOMPurify before passing to dangerouslySetInnerHTML",
        ),
        Pattern(
            "Open Redirect",
            r'window\.location\s*=\s*(?:req\.|request\.|params\.|query\.)',
            "Medium",
            CWE["Open Redirect"],
            "User-controlled URL in window.location may redirect to malicious sites",
            "Validate redirect destinations against a server-side allowlist",
        ),
        Pattern(
            "ReDoS",
            r'new\s+RegExp\s*\(|\/(\(.*\+\).*\+|\(.*\*\).*\*|\(\.\*\).*\.\*)',
            "Medium",
            CWE["ReDoS"],
            "Complex regular expressions with nested quantifiers may cause catastrophic backtracking",
            "Use linear-time regex engines or limit input length; test with ReDoS checkers",
        ),
    ],
    "java": [
        Pattern(
            "SQL Injection",
            r'(Statement|createStatement)\b.*\.execute|".*SELECT.*"\s*\+',
            "Critical",
            CWE["SQL Injection"],
            "String concatenation in SQL statement may allow injection",
            "Use PreparedStatement with parameterised queries exclusively",
        ),
        Pattern(
            "XXE Injection",
            r'DocumentBuilderFactory\.newInstance\(\)',
            "High",
            CWE["XXE Injection"],
            "DocumentBuilderFactory without disabling external entities is vulnerable to XXE",
            "Disable external entities: factory.setFeature(FEATURE_DISALLOW_DOCTYPE, true)",
        ),
        Pattern(
            "Insecure Deserialization (Java)",
            r'ObjectInputStream\b.*readObject\s*\(\)',
            "High",
            CWE["Insecure Deserialization (Java)"],
            "Java object deserialization of untrusted data may allow RCE",
            "Avoid Java serialisation for untrusted data; use JSON/protobuf; implement serial filters",
        ),
        Pattern(
            "Hardcoded Secrets",
            r'(?i)String\s+(password|apiKey|secret|token)\s*=\s*"[^"]{4,}"',
            "Critical",
            CWE["Hardcoded Secrets"],
            "Hardcoded credential in Java string literal",
            "Load secrets from environment variables or a secrets manager at runtime",
        ),
        Pattern(
            "Weak Cryptography",
            r'MessageDigest\.getInstance\s*\(\s*"(MD5|SHA-1|SHA1)"',
            "High",
            CWE["Weak Cryptography"],
            "MD5 and SHA-1 are cryptographically broken",
            "Use MessageDigest.getInstance(\"SHA-256\") or stronger",
        ),
        Pattern(
            "Path Traversal",
            r'new\s+File\s*\([^)]*(?:request|getParameter|input)',
            "High",
            CWE["Path Traversal"],
            "User-controlled input in File constructor may allow directory traversal",
            "Canonicalise and validate file paths before use; restrict to expected base directory",
        ),
        Pattern(
            "Command Injection",
            r'Runtime\.getRuntime\(\)\.exec\s*\([^)]*\+',
            "Critical",
            CWE["Command Injection"],
            "Runtime.exec with string concatenation allows OS command injection",
            "Never pass user input to exec(); use ProcessBuilder with a fixed command array",
        ),
        Pattern(
            "JNDI Injection",
            r'InitialContext\(\)\.lookup\s*\(',
            "Critical",
            CWE["JNDI Injection"],
            "JNDI lookup with user-controlled input enables Log4Shell-style RCE",
            "Disable JNDI lookups; set com.sun.jndi.rmi.object.trustURLCodebase=false",
        ),
    ],
    "go": [
        Pattern(
            "Hardcoded Secrets",
            r'(?i)(password|apiKey|secret)\s*:?=\s*"[^"]{4,}"',
            "Critical",
            CWE["Hardcoded Secrets"],
            "Hardcoded credential in Go string literal",
            "Use os.Getenv() or a secrets manager; never hardcode credentials",
        ),
        Pattern(
            "unsafe.Pointer Usage",
            r'\bunsafe\.Pointer\b',
            "High",
            CWE["unsafe.Pointer Usage"],
            "unsafe.Pointer bypasses Go's memory safety guarantees",
            "Avoid unsafe package; if required, document rationale and add bounds checks",
        ),
        Pattern(
            "Command Injection",
            r'exec\.Command\s*\([^)]*fmt\.Sprintf|exec\.Command\s*\([^)]*\+',
            "Critical",
            CWE["Command Injection"],
            "exec.Command with string formatting may allow OS command injection",
            "Pass command and arguments as separate strings to exec.Command; never construct via fmt.Sprintf",
        ),
        Pattern(
            "SQL Injection",
            r'(?:db\.Query|db\.Exec|db\.QueryRow)\s*\([^)]*fmt\.Sprintf|(?:db\.Query|db\.Exec)\s*\([^)]*\+',
            "Critical",
            CWE["SQL Injection"],
            "String formatting in database query may allow SQL injection",
            "Use parameterised queries: db.Query(\"SELECT ... WHERE id = ?\", id)",
        ),
        Pattern(
            "Weak Cryptography",
            r'\bmd5\.New\(\)|\bsha1\.New\(\)',
            "High",
            CWE["Weak Cryptography"],
            "MD5 and SHA1 are cryptographically broken",
            "Use crypto/sha256 or crypto/sha512 for hashing",
        ),
        Pattern(
            "Path Traversal",
            r'filepath\.Join\s*\([^)]*(?:r\.FormValue|r\.URL\.Query|request\.)',
            "High",
            CWE["Path Traversal"],
            "User-controlled input in filepath.Join may allow directory traversal",
            "Validate and clean paths with filepath.Clean(); check prefix with strings.HasPrefix()",
        ),
        Pattern(
            "Open Redirect",
            r'http\.Redirect\s*\([^)]*(?:r\.FormValue|r\.URL\.Query)',
            "Medium",
            CWE["Open Redirect"],
            "User-controlled URL in http.Redirect may enable phishing",
            "Validate redirect URLs against an allowlist before redirecting",
        ),
        Pattern(
            "Goroutine Leak",
            r'\bgo\s+func\s*\(\)',
            "Low",
            CWE["Goroutine Leak"],
            "Goroutine launched without done channel or context cancellation may leak",
            "Pass a context.Context to goroutines; use sync.WaitGroup or done channels",
        ),
    ],
}

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]


def scan_file(path: str, language: str) -> List[Dict]:
    """Scan a source file for vulnerability patterns.

    Args:
        path: Path to source file.
        language: Language key (python|javascript|java|go).

    Returns:
        List of finding dicts.

    Raises:
        SystemExit: On file not found.
    """
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except FileNotFoundError:
        print(f"ERROR: Source file not found: '{path}'", file=sys.stderr)
        sys.exit(1)

    patterns = PATTERNS.get(language, [])
    if not patterns:
        print(f"ERROR: Unsupported language '{language}'. Choose: python, javascript, java, go", file=sys.stderr)
        sys.exit(1)

    findings: List[Dict] = []
    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "//", "*", "/*")):
            continue  # skip blank and comment lines
        for pat in patterns:
            if re.search(pat.regex, line):
                snippet = stripped[:100] + ("…" if len(stripped) > 100 else "")
                findings.append(
                    {
                        "line_number": lineno,
                        "code_snippet": snippet,
                        "vulnerability_class": pat.vuln_class,
                        "severity": pat.severity,
                        "cwe_id": pat.cwe_id,
                        "description": pat.description,
                        "recommendation": pat.recommendation,
                    }
                )
    return findings


def render_markdown(findings: List[Dict], file_path: str, language: str) -> str:
    """Render code review report as Markdown.

    Args:
        findings: List of detected findings.
        file_path: Path of the reviewed file.
        language: Language reviewed.

    Returns:
        Markdown string.
    """
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    lines: List[str] = []
    lines.append("# Code Security Review")
    lines.append(f"\n**File:** `{file_path}`  ")
    lines.append(f"**Language:** {language}  ")
    lines.append(f"**Date:** {now}  ")
    lines.append(f"**Total Findings:** {len(findings)}\n")

    if not findings:
        lines.append("## ✅ Clean Bill of Health\n")
        lines.append("No security vulnerabilities detected by static pattern analysis.")
        lines.append("\n> Note: This tool performs regex-based pattern matching. ")
        lines.append("A clean result does not guarantee the absence of vulnerabilities.")
        return "\n".join(lines)

    # Summary table
    counts: Dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    lines.append("## Summary\n")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in SEVERITY_ORDER:
        if counts.get(sev, 0) > 0:
            lines.append(f"| **{sev}** | {counts[sev]} |")

    # Findings table
    lines.append("\n## Findings\n")
    lines.append("| Line | Vulnerability | Severity | CWE | Code Snippet | Recommendation |")
    lines.append("|------|--------------|---------|-----|--------------|----------------|")
    sorted_findings = sorted(
        findings,
        key=lambda f: (SEVERITY_ORDER.index(f["severity"]), f["line_number"]),
    )
    for f in sorted_findings:
        snippet = f["code_snippet"].replace("|", "\\|")
        rec = f["recommendation"][:80] + "…" if len(f["recommendation"]) > 80 else f["recommendation"]
        lines.append(
            f"| {f['line_number']} | {f['vulnerability_class']} | **{f['severity']}** | "
            f"[{f['cwe_id']}](https://cwe.mitre.org/data/definitions/{f['cwe_id'].replace('CWE-','')}.html) | "
            f"`{snippet}` | {rec} |"
        )

    return "\n".join(lines)


def render_json_output(findings: List[Dict], file_path: str, language: str) -> str:
    """Render results as JSON.

    Args:
        findings: List of findings.
        file_path: Reviewed file path.
        language: Language reviewed.

    Returns:
        JSON string.
    """
    result = {
        "generated": datetime.utcnow().isoformat() + "Z",
        "file": file_path,
        "language": language,
        "total_findings": len(findings),
        "findings": findings,
    }
    return json.dumps(result, indent=2)


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        description="Regex-based security static analysis for source code."
    )
    parser.add_argument("--code", required=True, help="Path to source file")
    parser.add_argument(
        "--language",
        required=True,
        choices=["python", "javascript", "java", "go"],
        help="Source language",
    )
    parser.add_argument(
        "--output",
        choices=["markdown", "json"],
        default="markdown",
        help="Output format (default: markdown)",
    )
    return parser.parse_args()


def main() -> None:
    """Main entry point."""
    args = parse_args()
    findings = scan_file(args.code, args.language)
    if args.output == "json":
        print(render_json_output(findings, args.code, args.language))
    else:
        print(render_markdown(findings, args.code, args.language))


if __name__ == "__main__":
    main()
