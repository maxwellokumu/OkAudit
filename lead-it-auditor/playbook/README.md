# lead-it-auditor playbook

Step-by-step methodology for the Lead IT Auditor role, covering all six phases
of an IT audit engagement from initial planning through final closeout.

---

## Purpose

This playbook guides the lead auditor through each stage of an engagement, providing:
- Clear objectives for each step
- Artefacts to collect
- Tools and commands to run (including references to other skills)
- Must-do checks that cannot be skipped

Reference this at the start of every engagement and share specific steps with team members.

---

## Requirements

```bash
pip install python-dotenv
```

---

## Usage

```bash
# Print the full playbook (all 6 steps)
python main.py

# Print all steps explicitly
python main.py --step full

# Print a specific step only
python main.py --step 1
python main.py --step 3
python main.py --step 6
```

---

## Steps Overview

| Step | Title | Key Activity |
|------|-------|-------------|
| 1 | Engagement Planning | Charter, scope letter, team assignment |
| 2 | Scope Definition | System boundaries, risk universe, audit program |
| 3 | Risk Assessment | Threat landscape, inherent risk rating |
| 4 | Fieldwork Coordination | Evidence requests, walkthroughs, testing |
| 5 | Evidence Review & Quality Check | Gap analysis, working paper review |
| 6 | Reporting & Closeout | Draft report, management response, final issue |

---

## Sample Output (Step 1 truncated)

```markdown
# Lead IT Auditor Playbook

---

## Step 1: Engagement Planning

**Objective:** Establish the formal basis for the audit engagement...

### Artefacts to Collect
- Signed audit charter
- Prior audit reports (last 2 cycles)
- Management-accepted risk register

### Tools & Commands
- `python lead-it-auditor/audit-scope-checklist/main.py --system "..." --roles "..."`

### ✅ Must-Do Checks
- [ ] Independence confirmed — no auditor has a reporting line to auditee management
- [ ] Audit charter grants unrestricted access to systems and personnel
```
