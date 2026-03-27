# devsecops-checker

Assess GitHub Actions, GitLab CI, and Jenkins pipeline configurations for 8 DevSecOps security controls. Produces a maturity score (0–100), identifies gaps, and suggests quick wins.

## Requirements

- Python 3.8+
- No external dependencies

## Usage

```bash
python main.py --config sample_input/github_actions.yml

python main.py --config sample_input/gitlab_ci.yml --output json
```

### Options

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--config` | ✅ | — | Path to CI/CD YAML file |
| `--output` | | `markdown` | `markdown` \| `json` |

## Security Controls Checked

| # | Control | Points |
|---|---------|--------|
| 1 | SAST (Bandit, Semgrep, SonarQube…) | 12.5 |
| 2 | SCA / Dependency Scan (Snyk, Dependabot…) | 12.5 |
| 3 | Secrets Scanner (Gitleaks, TruffleHog…) | 12.5 |
| 4 | Container Image Scan (Trivy, Grype…) | 12.5 |
| 5 | DAST (OWASP ZAP, Burp, Dastardly…) | 12.5 |
| 6 | Approval / Manual Gate | 12.5 |
| 7 | Environment Separation (staging/prod) | 12.5 |
| 8 | Artifact Signing (Cosign, Sigstore…) | 12.5 |

## Maturity Levels

| Score | Level |
|-------|-------|
| 0–25 | ❶ Initial |
| 26–50 | ❷ Developing |
| 51–75 | ❸ Defined |
| 76–100 | ❹ Optimised |
