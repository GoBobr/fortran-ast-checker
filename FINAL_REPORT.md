# fparser PoC — Phase 1 Final Report

## Overview

This PoC replaces the JFlex-lexer-based i-CodeCNES rules with fparser AST visitors for the top 10 false-positive-producing Fortran rules. The analyzer uses fparser 0.2.4 to parse Fortran 2003+ source code into an AST, then applies rule-specific visitors to detect violations.

## Results on RemoTAP (184 files, 176 parsed)

| # | Rule Key | Description | Violations | FPs Eliminated |
|---|----------|-------------|------------|----------------|
| 1 | F90.DATA.Declaration | IMPLICIT NONE & undeclared variables | 227 | 3 |
| 2 | COM.TYPE.Expression | Mixed-type arithmetic | 163 | 59 |
| 3 | F90.ERR.OpenRead | Missing IOSTAT in OPEN/READ/CLOSE | 57 | 247 |
| 4 | COM.DATA.Initialisation | Uninitialized variables | 85 | 166 |
| 5 | F90.ERR.Allocate | Missing STAT in ALLOCATE/DEALLOCATE | 175 | 12 |
| 6 | COM.DATA.FloatCompare | Float comparison with == or /= | 3 | 56 |
| 7 | F90.DESIGN.Obsolete | Obsolete Fortran features | 0 | 34 |
| 8 | COM.FLOW.Exit | Multiple exit points | 0 | 9 |
| 9 | COM.DESIGN.Alloc | Alloc without dealloc | 0 | 7 |
| 10 | F90.DATA.ArrayAccess | Array access issues | 0 | 2 |
| **Total** | | | **710** | **595** |

## Comparison with i-CodeCNES

- **i-CodeCNES open issues (10 rules):** 710
- **fparser issues:** 647 (excludes UNITTEST files)
- **False positives eliminated:** 595 (83.8%)
- **New issues found by fparser:** 532

## Key Technical Achievements

### 1. Project-Wide Symbol Table
- 3-pass build: modules → scopes → symbol resolution
- 167 modules, 1379 scopes parsed from RemoTAP
- Derived type component resolution (e.g., `measurement%sza` → `DOUBLE PRECISION`)
- Interprocedural allocation tracking
- Intrinsic function return type mapping (140+ intrinsics)

### 2. AST-Based Rule Implementation
- **Line number tracking**: `_walk_with_lines` pattern for nodes without `item` (Level_4_Expr, Name, Return_Stmt)
- **Type resolution**: Symbol table lookup + literal analysis + intrinsic function resolution
- **Scope inheritance**: Contained procedures inherit IMPLICIT NONE from parent module
- **Error-handling detection**: RETURN inside IF blocks treated as error-handling (permissive)

### 3. SonarQube Integration
- Results exported as i-CodeCNES AnalysisProject XML
- Imported via `sonar.icode.reports.path` property (no plugin changes needed)
- 689 issues imported into `CO2M_SwLib_RemoTAP_fparser` project
- Issues visible at: https://co2m.eumetsat.int/sonarqube/dashboard?id=CO2M_SwLib_RemoTAP_fparser

## Files

### Rules (`rules/`)
- `base_rule.py` — Abstract base class
- `symbol_table.py` — Project-wide symbol table (core infrastructure)
- `rule_f90_data_declaration.py` — Rule 1
- `rule_com_type_expression.py` — Rule 2
- `rule_f90_err_openread.py` — Rule 3
- `rule_com_data_initialisation.py` — Rule 4
- `rule_f90_err_allocate.py` — Rule 5
- `rule_com_data_floatcompare.py` — Rule 6
- `rule_f90_design_obsolete.py` — Rule 7
- `rule_com_flow_exit.py` — Rule 8
- `rule_com_design_alloc.py` — Rule 9
- `rule_f90_data_arrayaccess.py` — Rule 10

### Runners (`runners/`)
- `analyze.py` — Main analyzer CLI
- `export_icode_xml.py` — XML export for SonarQube import
- `compare_with_icode.py` — Comparison report generator

### Tests (`tests/`)
- `test_rules.py` — 23 pytest tests (all passing)
- `test_data/` — 19 .f90 test files (error/noError pairs for 10 rules)

### Results (`results/`)
- `fparser_issues.json` — Full analysis results (710 violations)
- `icode-results.xml` — i-CodeCNES XML format (689 importable)
- `comparison_report.md` — Detailed comparison with i-CodeCNES

## How to Run

```bash
# Activate venv
cd /tcenas2/CO2M/user/co2m/dev/fortran-ast-checker
source venv/bin/activate

# Run tests
python3 -m pytest tests/test_rules.py -v

# Analyze RemoTAP
python3 runners/analyze.py \
    --source /tcenas2/CO2M/user/co2m/dev/ghg-l2-swlib-remotap/ext/remotap/ \
    --output results/fparser_issues.json

# Export to i-CodeCNES XML
python3 runners/export_icode_xml.py \
    --input results/fparser_issues.json \
    --output results/icode-results.xml \
    --path-prefix ext/remotap/

# Import to SonarQube
cp results/icode-results.xml /tcenas2/CO2M/user/co2m/dev/ghg-l2-swlib-remotap/results/
cd /tcenas2/CO2M/user/co2m/dev/ghg-l2-swlib-remotap
/tcenas2/CO2M/user/co2m/dev/sonar-scanner-8.1.0.6389-linux-x64/bin/sonar-scanner \
    -Dproject.settings=sonar-project-fparser.properties \
    -Dsonar.scanner.truststorePath=/tmp/co2m_truststore.jks \
    -Dsonar.scanner.truststorePassword=changeit

# Generate comparison report
python3 runners/compare_with_icode.py \
    --fparser-results results/fparser_issues.json \
    --sonarqube-url https://co2m.eumetsat.int/sonarqube \
    --sonarqube-auth "$SONARQUBE_TOKEN" \
    --project-key CO2M_SwLib_RemoTAP \
    --output results/comparison_report.md
```
