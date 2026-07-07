#!/usr/bin/env python3
"""Unit tests for fparser-based Fortran rules.

Each test verifies that:
1. The ``noError.f90`` file produces 0 violations
2. The ``error.f90`` file produces ≥1 violations

Usage:
    cd /tcenas2/CO2M/user/co2m/dev/fparser-poc
    source venv/bin/activate
    python3 -m pytest tests/test_rules.py -v
"""

import os
import sys
import logging
import tempfile
from typing import List, Tuple

# Add project root to path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

# Suppress fparser warnings during tests
logging.disable(logging.WARNING)

import pytest
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

TEST_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_data")

#: All rules and their test data directories
RULES_AND_DIRS = [
    (F90DataDeclaration(), "f90_data_declaration"),
    (ComTypeExpression(), "com_type_expression"),
    (F90ErrOpenRead(), "f90_err_openread"),
    (ComDataInitialisation(), "com_data_initialisation"),
    (F90ErrAllocate(), "f90_err_allocate"),
    (ComDataFloatCompare(), "com_data_floatcompare"),
    (F90DesignObsolete(), "f90_design_obsolete"),
    (ComFlowExit(), "com_flow_exit"),
    (ComDesignAlloc(), "com_design_alloc"),
    (F90DataArrayAccess(), "f90_data_arrayaccess"),
]


def run_rule_on_file(rule, fpath: str, symbol_table: ProjectSymbolTable) -> List[Violation]:
    """Run a single rule on a single file and return violations."""
    parser = ParserFactory().create(std="f2003")
    reader = FortranFileReader(fpath)
    ast = parser(reader)
    rel_path = os.path.basename(fpath)
    return rule.check(ast, rel_path, symbol_table)


def build_symbol_table(fpath: str) -> ProjectSymbolTable:
    """Build a minimal symbol table from a single file."""
    st = ProjectSymbolTable()
    st.build([fpath], os.path.dirname(fpath))
    return st


@pytest.mark.parametrize("rule,dir_name", RULES_AND_DIRS)
def test_no_error_file(rule, dir_name):
    """Test that noError.f90 produces 0 violations."""
    no_error_path = os.path.join(TEST_DATA_DIR, dir_name, "noError.f90")
    if not os.path.exists(no_error_path):
        pytest.skip(f"Test file not found: {no_error_path}")

    st = build_symbol_table(no_error_path)
    violations = run_rule_on_file(rule, no_error_path, st)

    assert len(violations) == 0, (
        f"{rule.rule_key}: Expected 0 violations for noError.f90, "
        f"but got {len(violations)}:\n"
        + "\n".join(f"  line {v.line}: {v.message}" for v in violations)
    )


@pytest.mark.parametrize("rule,dir_name", RULES_AND_DIRS)
def test_error_file(rule, dir_name):
    """Test that error.f90 produces ≥1 violations."""
    error_path = os.path.join(TEST_DATA_DIR, dir_name, "error.f90")
    if not os.path.exists(error_path):
        pytest.skip(f"Test file not found: {error_path}")

    st = build_symbol_table(error_path)
    violations = run_rule_on_file(rule, error_path, st)

    assert len(violations) >= 1, (
        f"{rule.rule_key}: Expected ≥1 violations for error.f90, "
        f"but got 0."
    )


def test_symbol_table_builds():
    """Test that the symbol table can be built from test files."""
    # Find all .f90 test files
    test_files = []
    for root, dirs, files in os.walk(TEST_DATA_DIR):
        for f in files:
            if f.endswith(".f90"):
                test_files.append(os.path.join(root, f))

    assert len(test_files) > 0, "No test .f90 files found"

    st = ProjectSymbolTable()
    st.build(test_files, TEST_DATA_DIR)

    assert len(st.modules) > 0, "No modules found in symbol table"
    assert len(st.scopes) > 0, "No scopes found in symbol table"


def test_analyze_cli():
    """Test that the analyze.py CLI script exists and is importable."""
    sys.path.insert(0, os.path.join(PROJECT_ROOT, "runners"))
    import analyze
    assert hasattr(analyze, "ALL_RULES")
    assert len(analyze.ALL_RULES) == 10


def test_export_xml_cli():
    """Test that the export_icode_xml.py CLI script exists and is importable."""
    sys.path.insert(0, os.path.join(PROJECT_ROOT, "runners"))
    import export_icode_xml
    assert hasattr(export_icode_xml, "export_icode_xml")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
