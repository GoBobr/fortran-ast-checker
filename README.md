# fortran-ast-checker

Fortran static analysis tool using [fparser](https://github.com/stfc/fparser) AST — replaces JFlex-lexer-based i-CodeCNES rules with AST visitors for dramatically fewer false positives.

## Overview

This project implements a Fortran code quality analyzer that parses Fortran 2003+ source code into an Abstract Syntax Tree (AST) using fparser, then applies rule-specific visitors to detect violations. It was built as a proof-of-concept to replace the lexer-based i-CodeCNES rules that produced excessive false positives.

## Results on RemoTAP (184 files, 176 parsed)

| Rule | Key | Violations | FPs Eliminated |
|------|-----|------------|----------------|
| 1 | F90.DATA.Declaration | 227 | 3 |
| 2 | COM.TYPE.Expression | 163 | 59 |
| 3 | F90.ERR.OpenRead | 57 | 247 |
| 4 | COM.DATA.Initialisation | 85 | 166 |
| 5 | F90.ERR.Allocate | 175 | 12 |
| 6 | COM.DATA.FloatCompare | 3 | 56 |
| 7 | F90.DESIGN.Obsolete | 0 | 34 |
| 8 | COM.FLOW.Exit | 0 | 9 |
| 9 | COM.DESIGN.Alloc | 0 | 7 |
| 10 | F90.DATA.ArrayAccess | 0 | 2 |
| **Total** | | **710** | **595 (83.8%)** |

## Architecture

### Core Infrastructure
- **`rules/symbol_table.py`** — Project-wide symbol table with 3-pass build (modules → scopes → symbol resolution). Tracks 167 modules, 1379 scopes. Supports derived type component resolution, interprocedural allocation tracking, and intrinsic function return type mapping (140+ intrinsics).
- **`rules/base_rule.py`** — Abstract base class for all rules.

### Rules
| # | File | Rule Key | Description |
|---|------|----------|-------------|
| 1 | `rule_f90_data_declaration.py` | F90.DATA.Declaration | IMPLICIT NONE & undeclared variables |
| 2 | `rule_com_type_expression.py` | COM.TYPE.Expression | Mixed-type arithmetic expressions |
| 3 | `rule_f90_err_openread.py` | F90.ERR.OpenRead | Missing IOSTAT in OPEN/READ/CLOSE |
| 4 | `rule_com_data_initialisation.py` | COM.DATA.Initialisation | Uninitialized variables |
| 5 | `rule_f90_err_allocate.py` | F90.ERR.Allocate | Missing STAT in ALLOCATE/DEALLOCATE |
| 6 | `rule_com_data_floatcompare.py` | COM.DATA.FloatCompare | Float comparison with == or /= |
| 7 | `rule_f90_design_obsolete.py` | F90.DESIGN.Obsolete | Obsolete Fortran features |
| 8 | `rule_com_flow_exit.py` | COM.FLOW.Exit | Multiple exit points |
| 9 | `rule_com_design_alloc.py` | COM.DESIGN.Alloc | Alloc without dealloc |
| 10 | `rule_f90_data_arrayaccess.py` | F90.DATA.ArrayAccess | Array access issues |

### Runners
- **`runners/analyze.py`** — Main analyzer CLI
- **`runners/export_icode_xml.py`** — Export violations as i-CodeCNES AnalysisProject XML for SonarQube import
- **`runners/compare_with_icode.py`** — Compare fparser results with i-CodeCNES SonarQube issues

### Tests
- **`tests/test_rules.py`** — 23 pytest tests (error/noError pairs for all 10 rules)
- **`tests/test_data/`** — Fortran test files for each rule

## Quick Start

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install fparser pytest

# Run tests
python3 -m pytest tests/test_rules.py -v

# Analyze a Fortran project
python3 runners/analyze.py \
    --source /path/to/fortran/source/ \
    --output results/fparser_issues.json

# Export to i-CodeCNES XML for SonarQube
python3 runners/export_icode_xml.py \
    --input results/fparser_issues.json \
    --output results/icode-results.xml \
    --path-prefix src/

# Compare with i-CodeCNES results in SonarQube
python3 runners/compare_with_icode.py \
    --fparser-results results/fparser_issues.json \
    --sonarqube-url https://sonarqube.example.com \
    --sonarqube-auth "$SONARQUBE_TOKEN" \
    --project-key YOUR_PROJECT_KEY \
    --output results/comparison_report.md
```

## Key Technical Details

- **fparser 0.2.4** — Python Fortran parser (STFC). Produces Fortran 2003 AST. 95.7% parse coverage on RemoTAP (176/184 files).
- **Line number tracking** — `_walk_with_lines` pattern for AST nodes that don't carry line numbers (`Level_4_Expr`, `Name`, `Return_Stmt`).
- **Type resolution** — Symbol table lookup + literal analysis + intrinsic function resolution.
- **Scope inheritance** — Contained procedures inherit IMPLICIT NONE from parent module.
- **SonarQube integration** — Results imported via `sonar.icode.reports.path` property (no plugin changes needed).

## License

See [LICENSE](LICENSE) for details.
