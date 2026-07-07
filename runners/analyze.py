#!/usr/bin/env python3
"""Main fparser Fortran analyzer.

Parses all .f90 files in a source directory, builds a project-wide
symbol table, runs all 10 fparser-based rules, and outputs violations
as JSON.

Usage:
    python3 runners/analyze.py \
        --source /path/to/remotap \
        --output results/fparser_issues.json \
        [--rules F90.DATA.Declaration,COM.TYPE.Expression]

The output JSON has this structure:
    {
        "source_dir": "/path/to/remotap",
        "files_analyzed": 184,
        "files_failed": 8,
        "symbol_table": {
            "modules": 167,
            "scopes": 1379
        },
        "violations": [
            {
                "rule_key": "F90.DATA.Declaration",
                "message": "...",
                "file_path": "src/module.f90",
                "line": 42,
                "severity": "MAJOR"
            },
            ...
        ],
        "summary": {
            "F90.DATA.Declaration": 294,
            "COM.TYPE.Expression": 227,
            ...
        }
    }
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from dataclasses import asdict
from typing import List

# Add the project root to sys.path so we can import rules.*
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
sys.path.insert(0, PROJECT_ROOT)

from fparser.two.parser import ParserFactory
from fparser.common.readfortran import FortranFileReader

from rules.symbol_table import ProjectSymbolTable
from rules.base_rule import Violation
from rules.rule_f90_data_declaration import F90DataDeclaration
from rules.rule_com_type_expression import ComTypeExpression
from rules.rule_f90_err_openread import F90ErrOpenRead
from rules.rule_com_data_initialisation import ComDataInitialisation
from rules.rule_f90_err_allocate import F90ErrAllocate
from rules.rule_com_data_floatcompare import ComDataFloatCompare
from rules.rule_f90_design_obsolete import F90DesignObsolete
from rules.rule_com_flow_exit import ComFlowExit
from rules.rule_com_design_alloc import ComDesignAlloc
from rules.rule_f90_data_arrayaccess import F90DataArrayAccess

logger = logging.getLogger(__name__)

#: All 10 fparser-based rules, in order.
ALL_RULES = [
    F90DataDeclaration(),        # Rule 1: F90.DATA.Declaration
    ComTypeExpression(),         # Rule 2: COM.TYPE.Expression
    F90ErrOpenRead(),            # Rule 3: F90.ERR.OpenRead
    ComDataInitialisation(),     # Rule 4: COM.DATA.Initialisation
    F90ErrAllocate(),            # Rule 5: F90.ERR.Allocate
    ComDataFloatCompare(),       # Rule 6: COM.DATA.FloatCompare
    F90DesignObsolete(),         # Rule 7: F90.DESIGN.Obsolete
    ComFlowExit(),               # Rule 8: COM.FLOW.Exit
    ComDesignAlloc(),            # Rule 9: COM.DESIGN.Alloc
    F90DataArrayAccess(),        # Rule 10: F90.DATA.ArrayAccess
]


def find_f90_files(source_dir: str) -> List[str]:
    """Find all .f90 files in a directory tree."""
    files = []
    for root, dirs, filenames in os.walk(source_dir):
        for f in filenames:
            if f.endswith(".f90"):
                files.append(os.path.join(root, f))
    return sorted(files)


def select_rules(rule_keys: str | None):
    """Select rules by comma-separated keys, or return all if None."""
    if not rule_keys:
        return ALL_RULES
    keys = [k.strip() for k in rule_keys.split(",")]
    selected = []
    for rule in ALL_RULES:
        if rule.rule_key in keys:
            selected.append(rule)
    if not selected:
        print(f"ERROR: No rules matched '{rule_keys}'", file=sys.stderr)
        print(f"Available: {', '.join(r.rule_key for r in ALL_RULES)}", file=sys.stderr)
        sys.exit(1)
    return selected


def run_analysis(
    source_dir: str,
    rules: list,
    log_level: str = "WARNING",
) -> dict:
    """Run the full analysis pipeline.

    Returns a dict with results ready for JSON serialization.
    """
    logging.basicConfig(
        level=getattr(logging, log_level.upper(), logging.WARNING),
        format="%(levelname)s: %(message)s",
    )

    # Step 1: Find all .f90 files
    f90_files = find_f90_files(source_dir)
    print(f"Found {len(f90_files)} .f90 files in {source_dir}")

    # Step 2: Build symbol table
    print("Building project-wide symbol table...")
    t0 = time.time()
    symbol_table = ProjectSymbolTable()
    symbol_table.build(f90_files, source_dir)
    st_time = time.time() - t0
    print(
        f"  Symbol table built in {st_time:.1f}s: "
        f"{len(symbol_table.modules)} modules, "
        f"{len(symbol_table.scopes)} scopes"
    )

    # Step 3: Parse and run rules
    print(f"Running {len(rules)} rules...")
    parser = ParserFactory().create(std="f2003")

    all_violations: List[Violation] = []
    files_analyzed = 0
    files_failed = 0
    failed_files = []

    t0 = time.time()
    for i, fpath in enumerate(f90_files):
        rel_path = os.path.relpath(fpath, source_dir)
        try:
            reader = FortranFileReader(fpath)
            ast = parser(reader)
            files_analyzed += 1
            for rule in rules:
                try:
                    v = rule.check(ast, rel_path, symbol_table)
                    all_violations.extend(v)
                except Exception as e:
                    logger.warning(
                        f"Rule {rule.rule_key} failed on {rel_path}: {e}"
                    )
        except Exception as e:
            files_failed += 1
            failed_files.append((rel_path, str(e)))
            logger.debug(f"Parse failed for {rel_path}: {e}")

        if (i + 1) % 20 == 0:
            print(f"  Processed {i + 1}/{len(f90_files)} files...")

    analysis_time = time.time() - t0

    # Step 4: Build summary
    summary = {}
    for rule in rules:
        count = sum(1 for v in all_violations if v.rule_key == rule.rule_key)
        summary[rule.rule_key] = count

    print(f"\nAnalysis complete in {analysis_time:.1f}s")
    print(f"  Files analyzed: {files_analyzed}")
    print(f"  Files failed: {files_failed}")
    print(f"  Total violations: {len(all_violations)}")
    for key, count in summary.items():
        print(f"    {key:30s}: {count:5d}")

    # Step 5: Build result dict
    result = {
        "source_dir": source_dir,
        "files_analyzed": files_analyzed,
        "files_failed": files_failed,
        "failed_files": failed_files,
        "symbol_table": {
            "modules": len(symbol_table.modules),
            "scopes": len(symbol_table.scopes),
        },
        "violations": [asdict(v) for v in all_violations],
        "summary": summary,
        "timing": {
            "symbol_table_seconds": round(st_time, 1),
            "analysis_seconds": round(analysis_time, 1),
            "total_seconds": round(st_time + analysis_time, 1),
        },
    }

    return result


def main():
    parser = argparse.ArgumentParser(
        description="fparser-based Fortran analyzer (PoC)"
    )
    parser.add_argument(
        "--source",
        required=True,
        help="Source directory containing .f90 files",
    )
    parser.add_argument(
        "--output",
        default="results/fparser_issues.json",
        help="Output JSON file path (default: results/fparser_issues.json)",
    )
    parser.add_argument(
        "--rules",
        default=None,
        help="Comma-separated rule keys to run (default: all 10 rules)",
    )
    parser.add_argument(
        "--log-level",
        default="WARNING",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Logging level (default: WARNING)",
    )
    args = parser.parse_args()

    rules = select_rules(args.rules)
    result = run_analysis(args.source, rules, args.log_level)

    # Write output
    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print(f"\nResults written to {args.output}")


if __name__ == "__main__":
    main()
