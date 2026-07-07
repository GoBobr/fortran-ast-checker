#!/usr/bin/env python3
"""Compare fparser rule results against i-CodeCNES results from SonarQube.

Pulls i-CodeCNES issues from SonarQube via REST API, compares them
with fparser results, and generates a markdown comparison report.

Usage:
    python3 runners/compare_with_icode.py \
        --fparser-results results/fparser_issues.json \
        --sonarqube-url https://co2m.eumetsat.int/sonarqube \
        --sonarqube-auth admin:password \
        --project-key CO2M_SwLib_RemoTAP \
        --output results/comparison_report.md
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import ssl
import sys
import urllib.request
import urllib.parse
from collections import defaultdict


def fetch_sonarqube_issues(
    sonarqube_url: str,
    auth: str,
    project_key: str,
    rule_keys: list,
) -> list:
    """Fetch issues from SonarQube REST API for specific rules.

    Args:
        sonarqube_url: Base URL of SonarQube (e.g., https://host/sonarqube)
        auth: Basic auth string "user:password"
        project_key: SonarQube project key
        rule_keys: List of rule keys to fetch (e.g., ["F90.DATA.Declaration"])

    Returns:
        List of issue dicts with keys: rule, component, line, message
    """
    all_issues = []
    page = 1
    page_size = 500

    # Build rules parameter — SonarQube expects "repo:rule" format
    # i-CodeCNES rules are in the "f90-rules" repository
    rules_param = ",".join(f"f90-rules:{r}" for r in rule_keys)

    while True:
        params = {
            "componentKeys": project_key,
            "rules": rules_param,
            "ps": str(page_size),
            "p": str(page),
        }
        url = (
            sonarqube_url.rstrip("/")
            + "/api/issues/search?"
            + urllib.parse.urlencode(params)
        )

        req = urllib.request.Request(url)
        # Basic auth
        credentials = base64.b64encode(auth.encode()).decode()
        req.add_header("Authorization", f"Basic {credentials}")

        # Create SSL context that doesn't verify certificates
        # (needed for self-signed certs in internal networks)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            with urllib.request.urlopen(req, timeout=30, context=ctx) as response:
                data = json.loads(response.read().decode())
        except Exception as e:
            print(f"ERROR fetching SonarQube issues: {e}", file=sys.stderr)
            return all_issues

        issues = data.get("issues", [])
        all_issues.extend(issues)

        total = data.get("paging", {}).get("total", 0)
        if len(all_issues) >= total or len(issues) < page_size:
            break

        page += 1

    return all_issues


def normalize_issues(issues: list, source_dir: str = "") -> dict:
    """Normalize issues into a comparable format.

    Returns a dict keyed by (rule_key, file_path, line) -> message
    """
    normalized = {}
    for issue in issues:
        # Skip closed/fixed issues — only compare open issues
        if issue.get("status") in ("CLOSED", "RESOLVED"):
            continue

        # SonarQube issue format:
        # rule: "f90-rules:F90.DATA.Declaration"
        # component: "project_key:ext/remotap/RemoTAP_Core/..."
        # line: 42
        # message: "..."

        rule = issue.get("rule", "")
        if ":" in rule:
            rule = rule.split(":", 1)[1]

        component = issue.get("component", "")
        if ":" in component:
            file_path = component.split(":", 1)[1]
        else:
            file_path = component

        # Strip the "ext/remotap/" prefix to match fparser's relative paths
        if file_path.startswith("ext/remotap/"):
            file_path = file_path[len("ext/remotap/"):]

        line = issue.get("line", 0) or 0
        message = issue.get("message", "")

        key = (rule, file_path, line)
        normalized[key] = message

    return normalized


def generate_comparison_report(
    fparser_data: dict,
    sonarqube_issues: list,
    output_path: str,
    project_key: str,
):
    """Generate a markdown comparison report."""
    fparser_violations = fparser_data.get("violations", [])
    fparser_normalized = {}
    for v in fparser_violations:
        key = (v["rule_key"], v["file_path"], v["line"])
        fparser_normalized[key] = v["message"]

    sq_normalized = normalize_issues(sonarqube_issues)

    # Group by rule
    rules = sorted(
        set(k[0] for k in fparser_normalized) | set(k[0] for k in sq_normalized)
    )

    lines = []
    lines.append("# fparser vs i-CodeCNES Comparison Report")
    lines.append("")
    lines.append(f"**Project:** {project_key}")
    lines.append(f"**SonarQube issues:** {len(sq_normalized)}")
    lines.append(f"**fparser issues:** {len(fparser_normalized)}")
    lines.append("")

    # Summary table
    lines.append("## Summary by Rule")
    lines.append("")
    lines.append(
        "| Rule | i-CodeCNES | fparser | FPs Eliminated | New Issues |"
    )
    lines.append(
        "|------|-----------|---------|----------------|------------|"
    )

    total_icode = 0
    total_fparser = 0
    total_fps_eliminated = 0
    total_new = 0

    for rule in rules:
        icode_count = sum(
            1 for k in sq_normalized if k[0] == rule
        )
        fparser_count = sum(
            1 for k in fparser_normalized if k[0] == rule
        )

        # FPs eliminated = issues in i-CodeCNES but NOT in fparser
        icode_keys = {k for k in sq_normalized if k[0] == rule}
        fparser_keys = {k for k in fparser_normalized if k[0] == rule}
        fps_eliminated = len(icode_keys - fparser_keys)
        new_issues = len(fparser_keys - icode_keys)

        total_icode += icode_count
        total_fparser += fparser_count
        total_fps_eliminated += fps_eliminated
        total_new += new_issues

        lines.append(
            f"| {rule} | {icode_count} | {fparser_count} | "
            f"{fps_eliminated} | {new_issues} |"
        )

    lines.append(
        f"| **TOTAL** | **{total_icode}** | **{total_fparser}** | "
        f"**{total_fps_eliminated}** | **{total_new}** |"
    )
    lines.append("")

    # False positives eliminated (in i-CodeCNES but not in fparser)
    lines.append("## False Positives Eliminated by fparser")
    lines.append("")
    lines.append(
        "These issues were reported by i-CodeCNES but NOT by fparser "
        "(correctly eliminated):"
    )
    lines.append("")

    icode_only = set(sq_normalized.keys()) - set(fparser_normalized.keys())
    if icode_only:
        lines.append("| Rule | File | Line | i-CodeCNES Message |")
        lines.append("|------|------|------|-------------------|")
        for key in sorted(icode_only):
            rule, file_path, line = key
            msg = sq_normalized[key][:80]
            lines.append(f"| {rule} | {file_path} | {line} | {msg} |")
    else:
        lines.append("*(none)*")
    lines.append("")

    # New issues found by fparser (not in i-CodeCNES)
    lines.append("## New Issues Found by fparser")
    lines.append("")
    lines.append(
        "These issues were found by fparser but NOT by i-CodeCNES "
        "(potential false negatives in i-CodeCNES or new fparser FPs):"
    )
    lines.append("")

    fparser_only = set(fparser_normalized.keys()) - set(sq_normalized.keys())
    if fparser_only:
        lines.append("| Rule | File | Line | fparser Message |")
        lines.append("|------|------|------|-----------------|")
        for key in sorted(fparser_only):
            rule, file_path, line = key
            msg = fparser_normalized[key][:80]
            lines.append(f"| {rule} | {file_path} | {line} | {msg} |")
    else:
        lines.append("*(none)*")
    lines.append("")

    # Matching issues (both found)
    matching = set(fparser_normalized.keys()) & set(sq_normalized.keys())
    lines.append("## Matching Issues")
    lines.append("")
    lines.append(
        f"Both i-CodeCNES and fparser found **{len(matching)}** issues "
        f"at the same (rule, file, line) locations."
    )
    lines.append("")

    report = "\n".join(lines)

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report)

    print(f"Comparison report written to {output_path}")
    print(f"  i-CodeCNES issues: {total_icode}")
    print(f"  fparser issues: {total_fparser}")
    print(f"  FPs eliminated: {total_fps_eliminated}")
    print(f"  New issues: {total_new}")


def main():
    parser = argparse.ArgumentParser(
        description="Compare fparser results with i-CodeCNES SonarQube issues"
    )
    parser.add_argument(
        "--fparser-results",
        required=True,
        help="Path to fparser JSON results (from analyze.py)",
    )
    parser.add_argument(
        "--sonarqube-url",
        required=True,
        help="SonarQube base URL (e.g., https://host/sonarqube)",
    )
    parser.add_argument(
        "--sonarqube-auth",
        required=True,
        help="SonarQube auth string (user:password)",
    )
    parser.add_argument(
        "--project-key",
        required=True,
        help="SonarQube project key",
    )
    parser.add_argument(
        "--output",
        default="results/comparison_report.md",
        help="Output markdown report path",
    )
    args = parser.parse_args()

    # Load fparser results
    with open(args.fparser_results, "r", encoding="utf-8") as f:
        fparser_data = json.load(f)

    # Get rule keys from fparser results
    rule_keys = list(fparser_data.get("summary", {}).keys())
    if not rule_keys:
        print("ERROR: No rules found in fparser results", file=sys.stderr)
        sys.exit(1)

    print(f"Fetching i-CodeCNES issues from SonarQube for {len(rule_keys)} rules...")
    sq_issues = fetch_sonarqube_issues(
        args.sonarqube_url,
        args.sonarqube_auth,
        args.project_key,
        rule_keys,
    )
    print(f"  Found {len(sq_issues)} SonarQube issues")

    generate_comparison_report(
        fparser_data,
        sq_issues,
        args.output,
        args.project_key,
    )


if __name__ == "__main__":
    main()
