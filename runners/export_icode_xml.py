#!/usr/bin/env python3
"""Export fparser violations as i-CodeCNES AnalysisProject XML.

The output XML is imported by the existing sonar-icode-cnes-plugin via
the ``sonar.icode.reports.path`` property — no plugin changes needed.

Usage:
    python3 runners/export_icode_xml.py \
        --input results/fparser_issues.json \
        --output results/icode-results.xml
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from xml.dom import minidom
import xml.etree.ElementTree as ET


def export_icode_xml(
    violations: list,
    analyzed_files: list,
    output_path: str,
    path_prefix: str = "",
):
    """Write violations to i-CodeCNES AnalysisProject XML format.

    Args:
        violations: List of violation dicts (from analyze.py JSON output)
        analyzed_files: List of source file paths (relative to project base)
        output_path: Where to write the XML file
        path_prefix: Prefix to prepend to file paths (e.g., "ext/remotap/")
    """
    root = ET.Element("analysisProject")

    # Metadata
    info = ET.SubElement(root, "analysisInformations")
    info.set("author", "fparser PoC Analyzer")

    # Normalize prefix
    if path_prefix and not path_prefix.endswith("/"):
        path_prefix += "/"

    # Analyzed files
    for fpath in sorted(set(analyzed_files)):
        f = ET.SubElement(root, "analysisFile")
        f.set("language", "fr.cnes.analysis.tools.languages.f90")
        f.set("fileName", path_prefix + fpath)

    # Violations — one <analysisRule> per violation
    # (the i-CodeCNES plugin's AnalysisConverter only reads the first <result>
    #  in each <analysisRule>, so we must not group multiple results per rule)
    for v in sorted(violations, key=lambda x: (x["rule_key"], x["file_path"], x["line"])):
        rule_elem = ET.SubElement(root, "analysisRule")
        rule_elem.set("analysisRuleId", v["rule_key"])

        result = ET.SubElement(rule_elem, "result")
        result.set("fileName", path_prefix + v["file_path"])
        # SonarQube plugin clamps line to [1, file.lines()], so use 1 as fallback
        line = v["line"] if v["line"] > 0 else 1
        result.set("resultLine", str(line))
        result.set("resultTypePlace", "class")
        result.set("resultValue", "")

        msg = ET.SubElement(result, "resultMessage")
        msg.text = v["message"]

    # Pretty-print
    rough = ET.tostring(root, encoding="unicode")
    pretty = minidom.parseString(rough).toprettyxml(indent="  ")

    # Remove blank lines that minidom adds
    lines = [line for line in pretty.split("\n") if line.strip()]
    pretty = "\n".join(lines) + "\n"

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(pretty)


def main():
    parser = argparse.ArgumentParser(
        description="Export fparser violations as i-CodeCNES XML"
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Input JSON file (from analyze.py)",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Output XML file path",
    )
    parser.add_argument(
        "--path-prefix",
        default="",
        help="Prefix to prepend to file paths (e.g., 'ext/remotap/')",
    )
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Extract the list of analyzed files from violations
    # (files with no violations won't appear, but that's OK for the plugin)
    analyzed_files = sorted(
        set(v["file_path"] for v in data["violations"])
    )

    # Also include files that were analyzed but had no violations
    # We can get these from the source_dir + file walk, but for simplicity
    # we just use the files that have violations
    # (The plugin only needs <analysisFile> entries for files with results)

    export_icode_xml(data["violations"], analyzed_files, args.output, args.path_prefix)

    print(f"Exported {len(data['violations'])} violations to {args.output}")
    print(f"  Files with violations: {len(analyzed_files)}")
    print(f"  Rules: {len(data['summary'])}")


if __name__ == "__main__":
    main()
