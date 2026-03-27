# Contributing to it-audit-team-skills

Thank you for your interest in contributing! This guide explains how to add new skills, new audit roles, run tests locally, and submit pull requests.

---

## Table of Contents

1. [How to Add a New Skill](#how-to-add-a-new-skill)
2. [How to Add a New Role](#how-to-add-a-new-role)
3. [Running Tests Locally](#running-tests-locally)
4. [Code Style](#code-style)
5. [Pull Request Checklist](#pull-request-checklist)
6. [Reporting Issues](#reporting-issues)

---

## How to Add a New Skill

### Folder Structure

Every skill lives in its role directory and must follow this layout:

```
role-name/
└── skill-name/
    ├── skill.yaml          # Skill manifest (required)
    ├── main.py             # Fully working CLI script (required)
    ├── README.md           # Documentation (required)
    └── sample_input/       # Realistic test data files (required for analysis skills)
```

### skill.yaml Schema

```yaml
name: "skill-name"
version: "1.0.0"
description: "One sentence describing what this skill does"
author: "IT Audit Team"
license: "MIT"
triggers:
  - keywords: ["keyword1", "keyword2"]
  - patterns: ["regex pattern"]
parameters:
  - name: param1
    type: string
    required: true
    description: "Description of this parameter"
execution:
  runtime: "python"
  command: "python main.py"
  args: ["--param1", "{{param1}}"]
```

### Coding Standards Checklist

Before submitting a new skill, verify:

- [ ] Python 3.8+ compatible — no walrus operator or 3.10+ features unless guards are in place
- [ ] All functions have full type hints (`def foo(x: str) -> List[str]:`)
- [ ] All functions and the module itself have Google-style docstrings
- [ ] CLI uses `argparse` — no positional-only args without `--flag` form
- [ ] `if __name__ == "__main__":` guard present
- [ ] Secrets/credentials loaded from `.env` via `python-dotenv`, never hardcoded
- [ ] `--mode local|aws|azure` flag if the skill can call cloud APIs (`local` is default)
- [ ] `--dry-run` flag if the skill calls any live external API
- [ ] Markdown output by default; JSON for structured/machine-readable data
- [ ] Graceful handling of: missing files, malformed JSON/CSV, empty inputs, invalid flag values
- [ ] Errors printed to `stderr` with descriptive messages; script exits with non-zero status on failure

---

## How to Add a New Role

1. **Create the role directory** following the pattern used by existing roles (e.g. `identity-access/`, `vendor-risk/`).

2. **Add a `playbook/` skill** as the entry point for the role, following the 5–6 step structure used by existing playbooks.

3. **Update `README.md`** (repo root):
   - Add the new role to the Phase Roadmap table
   - Add it to the Mermaid architecture diagram under the appropriate phase

4. **Update `lead-it-auditor/audit-scope-checklist/main.py`**:
   - Add the new role name and its key controls to the `ROLE_CONTROLS` dictionary so the scope checklist tool can generate checklists for it.

5. **Add tests** in `tests/test_<rolename>.py` following the pattern used by existing test files.

---

## Running Tests Locally

### Setup

```bash
git clone https://github.com/YOUR_USERNAME/it-audit-team-skills.git
cd it-audit-team-skills
pip install -r requirements.txt
pip install pytest pytest-cov
```

### Run all tests

```bash
pytest tests/ -v
```

### Run tests with coverage report

```bash
pytest tests/ --cov=. --cov-report=html
# Open htmlcov/index.html in a browser
```

### Run tests for a single role

```bash
pytest tests/test_lead_auditor.py -v
pytest tests/test_hardware.py -v
pytest tests/test_appsec.py -v
```

### Run a specific test

```bash
pytest tests/test_hardware.py::TestAssetValidator::test_rogue_detection -v
```

---

## Code Style

This project uses **flake8** for linting and **mypy** for static type checking.

### Run flake8

```bash
pip install flake8
flake8 . --max-line-length=120 --exclude=.git,__pycache__,*.egg-info
```

### Run mypy

```bash
pip install mypy types-PyYAML
mypy . --ignore-missing-imports --exclude '(tests|sample_input)'
```

Both checks run automatically on every pull request via GitHub Actions CI.

---

## Pull Request Checklist

Before opening a PR, confirm all of the following:

- [ ] **Tests pass** — `pytest tests/ -v` exits with code 0
- [ ] **Type hints** — all new functions have complete type annotations
- [ ] **Docstrings** — all new functions and modules have Google-style docstrings
- [ ] **sample_input/** — realistic test data files are included for every analysis skill
- [ ] **README.md** — the skill's README includes: purpose, requirements, usage example, and sample output
- [ ] **skill.yaml** — manifest is complete with name, version, description, triggers, parameters, and execution
- [ ] **No hardcoded secrets** — credentials and API keys are loaded from environment variables
- [ ] **Error handling** — script handles missing files, malformed inputs, empty data, and invalid flag values gracefully
- [ ] **`--dry-run` flag** — any script that calls a live external API supports `--dry-run` using bundled sample data
- [ ] **`--mode` flag** — scripts supporting cloud operations implement `--mode local|aws|azure` with `local` as default

---

## Reporting Issues

When filing a bug report, please include:

1. **Description** — what you expected to happen vs what actually happened
2. **Repro steps** — the exact command you ran, including all flags and file paths
3. **Sample input** — a minimal example of the input file that triggers the issue (anonymise any real data)
4. **Environment** — Python version (`python --version`), OS, and relevant package versions (`pip freeze`)
5. **Error output** — the full stderr output and any tracebacks

For security vulnerabilities, please do **not** open a public issue. Instead, email the maintainers directly or use GitHub's private vulnerability reporting feature.
