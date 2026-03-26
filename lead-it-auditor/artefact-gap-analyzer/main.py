"""Artefact Gap Analyzer — compare expected audit artefacts against provided evidence.

Loads an audit_program.json produced by audit-scope-checklist, then compares
the expected artefact for each control against a list of provided evidence files
(supplied as a directory path or comma-separated filenames). Outputs a markdown
gap report with matched artefacts, missing artefacts, and a coverage summary.
"""

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Tuple

from dotenv import load_dotenv

load_dotenv()


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments.

    Returns:
        Parsed argument namespace.
    """
    parser = argparse.ArgumentParser(
        description="Compare expected audit artefacts against provided evidence files."
    )
    parser.add_argument(
        "--program",
        required=True,
        type=str,
        help="Path to audit_program.json produced by audit-scope-checklist.",
    )
    parser.add_argument(
        "--provided",
        required=True,
        type=str,
        help=(
            "Comma-separated evidence filenames OR path to a directory "
            "containing the provided evidence files."
        ),
    )
    return parser.parse_args()


def load_program(program_path: str) -> Dict[str, Any]:
    """Load and validate the audit program JSON file.

    Args:
        program_path: Path to audit_program.json.

    Returns:
        Parsed program dictionary.

    Raises:
        SystemExit: If the file is missing, unreadable, or malformed.
    """
    if not os.path.isfile(program_path):
        print(f"ERROR: Program file not found: {program_path}", file=sys.stderr)
        sys.exit(1)

    try:
        with open(program_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as exc:
        print(f"ERROR: Malformed JSON in {program_path}: {exc}", file=sys.stderr)
        sys.exit(1)
    except OSError as exc:
        print(f"ERROR: Cannot read {program_path}: {exc}", file=sys.stderr)
        sys.exit(1)

    if "controls" not in data or not isinstance(data["controls"], list):
        print(
            "ERROR: Invalid audit_program.json — missing or invalid 'controls' array.",
            file=sys.stderr,
        )
        sys.exit(1)

    if not data["controls"]:
        print("ERROR: audit_program.json contains no controls.", file=sys.stderr)
        sys.exit(1)

    return data


def resolve_provided_files(provided_arg: str) -> List[str]:
    """Resolve the list of provided evidence filenames.

    If provided_arg is a path to an existing directory, list all files in it.
    Otherwise, split on commas and strip whitespace.

    Args:
        provided_arg: Directory path or comma-separated filenames.

    Returns:
        List of base filenames (no directory component).

    Raises:
        SystemExit: If the directory does not exist or is empty.
    """
    if os.path.isdir(provided_arg):
        entries = os.listdir(provided_arg)
        files = [e for e in entries if os.path.isfile(os.path.join(provided_arg, e))]
        if not files:
            print(
                f"WARNING: Directory '{provided_arg}' is empty — all artefacts will be reported as missing.",
                file=sys.stderr,
            )
        return files

    # Comma-separated filenames
    names = [f.strip() for f in provided_arg.split(",") if f.strip()]
    if not names:
        print(
            "ERROR: --provided must be a non-empty directory path or comma-separated filenames.",
            file=sys.stderr,
        )
        sys.exit(1)
    # Use only the basename in case the user supplied paths
    return [os.path.basename(n) for n in names]


def match_artefacts(
    controls: List[Dict[str, Any]], provided_names: List[str]
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Match control artefacts against provided filenames (case-insensitive).

    Args:
        controls: List of control dictionaries from the audit program.
        provided_names: List of provided evidence filenames.

    Returns:
        Tuple of (matched, missing) control lists. Matched controls include
        a 'matched_file' key; missing controls do not.
    """
    provided_lower = {name.lower(): name for name in provided_names}
    matched: List[Dict[str, Any]] = []
    missing: List[Dict[str, Any]] = []

    for ctrl in controls:
        artefact = ctrl.get("artefact", "")
        artefact_lower = artefact.lower()
        if artefact_lower in provided_lower:
            matched.append({**ctrl, "matched_file": provided_lower[artefact_lower]})
        else:
            missing.append(ctrl)

    return matched, missing


def render_report(
    program: Dict[str, Any],
    matched: List[Dict[str, Any]],
    missing: List[Dict[str, Any]],
    provided_names: List[str],
) -> str:
    """Render the gap analysis as a markdown document.

    Args:
        program: Full audit program dictionary.
        matched: Controls whose artefact was found in the provided files.
        missing: Controls whose artefact was not found.
        provided_names: Full list of provided filenames.

    Returns:
        Formatted markdown string.
    """
    system = program.get("system", "Unknown System")
    total = len(program["controls"])
    matched_count = len(matched)
    missing_count = len(missing)
    coverage = (matched_count / total * 100) if total > 0 else 0.0

    lines = [
        f"# Artefact Gap Analysis — {system}",
        "",
        f"**Audit Program Controls:** {total}  ",
        f"**Evidence Files Provided:** {len(provided_names)}  ",
        f"**Coverage:** {matched_count}/{total} ({coverage:.1f}%)",
        "",
        "---",
        "",
        "## 1. Matched Artefacts",
        "",
    ]

    if matched:
        lines.append("| ID | Control | Expected Artefact | Matched File |")
        lines.append("|----|---------|-------------------|--------------|")
        for ctrl in matched:
            lines.append(
                f"| `{ctrl['id']}` | {ctrl['control']} "
                f"| `{ctrl['artefact']}` | `{ctrl['matched_file']}` |"
            )
    else:
        lines.append("_No artefacts matched the provided files._")

    lines += [
        "",
        "---",
        "",
        "## 2. Missing Artefacts",
        "",
    ]

    if missing:
        lines.append("| ID | Control | Expected Artefact | Details | Acceptance Criteria |")
        lines.append("|----|---------|-------------------|---------|---------------------|")
        for ctrl in missing:
            lines.append(
                f"| `{ctrl['id']}` | {ctrl['control']} "
                f"| `{ctrl['artefact']}` "
                f"| {ctrl.get('details', '—')} "
                f"| {ctrl.get('acceptance', '—')} |"
            )
    else:
        lines.append("✅ _All expected artefacts have been provided._")

    # Coverage emoji
    if coverage >= 80:
        cov_icon = "🟢"
    elif coverage >= 50:
        cov_icon = "🟡"
    else:
        cov_icon = "🔴"

    lines += [
        "",
        "---",
        "",
        "## 3. Summary",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Total Controls | {total} |",
        f"| Artefacts Matched | {matched_count} |",
        f"| Artefacts Missing | {missing_count} |",
        f"| Coverage | {cov_icon} {coverage:.1f}% |",
        "",
    ]

    if missing_count > 0:
        lines += [
            "### Action Required",
            "",
            "The following artefacts must be obtained before fieldwork can be completed:",
            "",
        ]
        for ctrl in missing:
            lines.append(f"- [ ] `{ctrl['artefact']}` _(Control {ctrl['id']}: {ctrl['control']})_")
        lines.append("")

    return "\n".join(lines)


def main() -> None:
    """Entry point for the artefact gap analyzer CLI."""
    args = parse_args()

    program = load_program(args.program)
    provided_names = resolve_provided_files(args.provided)
    controls = program["controls"]

    matched, missing = match_artefacts(controls, provided_names)
    report = render_report(program, matched, missing, provided_names)

    print(report)


if __name__ == "__main__":
    main()
