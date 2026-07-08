"""Batch 1: Simple keyword/statement detection rules.

These rules detect forbidden Fortran statements by walking the AST for
specific node types.  No symbol table or type resolution is needed.

Rules implemented (20):
  - COM.FLOW.Abort           (STOP statement)
  - F77.INST.Save            (SAVE statement)
  - F90.INST.Equivalence     (EQUIVALENCE statement)
  - F77.BLOC.Common          (COMMON statement)
  - F77.DATA.Parameter       (PARAMETER statement, not attribute)
  - F77.PROTO.Declaration    (EXTERNAL statement)
  - COM.INST.GoTo            (GOTO statement)
  - F77.INST.Assign          (ASSIGN statement — text scan)
  - F77.INST.Pause           (PAUSE statement — text scan)
  - F90.DESIGN.Include       (INCLUDE statement)
  - F90.INST.Entry           (ENTRY statement)
  - EUM.INST.Backspace       (BACKSPACE statement)
  - EUM.INST.BlockData       (BLOCK DATA)
  - EUM.INST.NoData          (DATA statement)
  - EUM.INST.Namelist        (NAMELIST statement)
  - EUM.INST.Continue        (standalone CONTINUE)
  - F77.INST.Dimension       (DIMENSION statement, not attribute)
  - EUM.INST.NoUnderscoreKind (variable_8 kind suffix)
  - COM.INST.CodeComment     (commented-out code)
  - F90.INST.Pointer         (POINTER usage restrictions)
"""

from __future__ import annotations

import re
from typing import List

from fparser.two.Fortran2003 import (
    Backspace_Stmt,
    Block_Data,
    Common_Stmt,
    Continue_Stmt,
    Data_Stmt,
    Dimension_Stmt,
    Entry_Stmt,
    Equivalence_Stmt,
    External_Stmt,
    Goto_Stmt,
    Include_Stmt,
    Name,
    Namelist_Stmt,
    Parameter_Stmt,
    Pointer_Stmt,
    Program,
    Save_Stmt,
    Stop_Stmt,
    Type_Declaration_Stmt,
)
from fparser.two.utils import walk

from rules.base_rule import FortranRule, Violation
from rules.symbol_table import ProjectSymbolTable, _get_line, _get_source_file_path


def _read_source_lines(file_path: str, symbol_table) -> List[str]:
    """Read source file lines, trying absolute path resolution."""
    import os
    abs_path = file_path
    if hasattr(symbol_table, '_source_dir'):
        abs_path = os.path.join(symbol_table._source_dir, file_path)
    if not os.path.isfile(abs_path):
        abs_path = file_path
    if not os.path.isfile(abs_path):
        return []
    try:
        with open(abs_path, 'r', errors='replace') as f:
            return f.readlines()
    except OSError:
        return []


# ---------------------------------------------------------------------------
# COM.FLOW.Abort — STOP statement
# ---------------------------------------------------------------------------
class ComFlowAbort(FortranRule):
    """STOP shall only be used in the main program."""

    rule_key = "COM.FLOW.Abort"
    severity = "MAJOR"

    def check(self, ast, file_path, symbol_table):
        violations = []
        for node in walk(ast, Stop_Stmt):
            line = _get_line(node)
            fp = _get_source_file_path(node) or file_path
            violations.append(Violation(
                rule_key=self.rule_key,
                message="The STOP instruction shall only be used for the main program.",
                file_path=fp, line=line, severity=self.severity,
            ))
        return violations


# ---------------------------------------------------------------------------
# F77.INST.Save — SAVE statement
# ---------------------------------------------------------------------------
class F77InstSave(FortranRule):
    """SAVE shall not be used for procedure-scope variables."""

    rule_key = "F77.INST.Save"
    severity = "MAJOR"

    def check(self, ast, file_path, symbol_table):
        violations = []
        for node in walk(ast, Save_Stmt):
            line = _get_line(node)
            fp = _get_source_file_path(node) or file_path
            violations.append(Violation(
                rule_key=self.rule_key,
                message="The SAVE keyword shall not be used for variables belonging to the procedure scope.",
                file_path=fp, line=line, severity=self.severity,
            ))
        return violations


# ---------------------------------------------------------------------------
# F90.INST.Equivalence — EQUIVALENCE statement
# ---------------------------------------------------------------------------
class F90InstEquivalence(FortranRule):
    """EQUIVALENCE shall not be used."""

    rule_key = "F90.INST.Equivalence"
    severity = "MAJOR"

    def check(self, ast, file_path, symbol_table):
        violations = []
        for node in walk(ast, Equivalence_Stmt):
            line = _get_line(node)
            fp = _get_source_file_path(node) or file_path
            violations.append(Violation(
                rule_key=self.rule_key,
                message="EQUIVALENCE statement shall not be used. Use pointers or TRANSFER statement instead.",
                file_path=fp, line=line, severity=self.severity,
            ))
        return violations


# ---------------------------------------------------------------------------
# F77.BLOC.Common — COMMON statement
# ---------------------------------------------------------------------------
class F77BlocCommon(FortranRule):
    """COMMON blocks shall not be used."""

    rule_key = "F77.BLOC.Common"
    severity = "MAJOR"

    def check(self, ast, file_path, symbol_table):
        violations = []
        for node in walk(ast, Common_Stmt):
            line = _get_line(node)
            fp = _get_source_file_path(node) or file_path
            violations.append(Violation(
                rule_key=self.rule_key,
                message="COMMON blocks shall not be used. Use modules instead.",
                file_path=fp, line=line, severity=self.severity,
            ))
        return violations


# ---------------------------------------------------------------------------
# F77.DATA.Parameter — PARAMETER statement (not attribute)
# ---------------------------------------------------------------------------
class F77DataParameter(FortranRule):
    """The PARAMETER statement shall not be used. Use the PARAMETER attribute."""

    rule_key = "F77.DATA.Parameter"
    severity = "MAJOR"

    def check(self, ast, file_path, symbol_table):
        violations = []
        for node in walk(ast, Parameter_Stmt):
            line = _get_line(node)
            fp = _get_source_file_path(node) or file_path
            violations.append(Violation(
                rule_key=self.rule_key,
                message="The PARAMETER statement shall not be used. Use the PARAMETER attribute to declare constants.",
                file_path=fp, line=line, severity=self.severity,
            ))
        return violations


# ---------------------------------------------------------------------------
# F77.PROTO.Declaration — EXTERNAL statement
# ---------------------------------------------------------------------------
class F77ProtoDeclaration(FortranRule):
    """EXTERNAL shall not be used."""

    rule_key = "F77.PROTO.Declaration"
    severity = "MAJOR"

    def check(self, ast, file_path, symbol_table):
        violations = []
        for node in walk(ast, External_Stmt):
            line = _get_line(node)
            fp = _get_source_file_path(node) or file_path
            violations.append(Violation(
                rule_key=self.rule_key,
                message="EXTERNAL shall not be used. All called procedures shall have an associated interface.",
                file_path=fp, line=line, severity=self.severity,
            ))
        return violations


# ---------------------------------------------------------------------------
# COM.INST.GoTo — GOTO statement
# ---------------------------------------------------------------------------
class ComInstGoTo(FortranRule):
    """GOTO shall not be used."""

    rule_key = "COM.INST.GoTo"
    severity = "MAJOR"

    def check(self, ast, file_path, symbol_table):
        violations = []
        for node in walk(ast, Goto_Stmt):
            line = _get_line(node)
            fp = _get_source_file_path(node) or file_path
            violations.append(Violation(
                rule_key=self.rule_key,
                message="GOTO shall not be used.",
                file_path=fp, line=line, severity=self.severity,
            ))
        return violations


# ---------------------------------------------------------------------------
# F90.DESIGN.Include — INCLUDE statement
# ---------------------------------------------------------------------------
class F90DesignInclude(FortranRule):
    """INCLUDE files shall not be used."""

    rule_key = "F90.DESIGN.Include"
    severity = "MAJOR"

    def check(self, ast, file_path, symbol_table):
        violations = []
        for node in walk(ast, Include_Stmt):
            line = _get_line(node)
            fp = _get_source_file_path(node) or file_path
            violations.append(Violation(
                rule_key=self.rule_key,
                message="INCLUDE files shall not be used.",
                file_path=fp, line=line, severity=self.severity,
            ))
        return violations


# ---------------------------------------------------------------------------
# F90.INST.Entry — ENTRY statement
# ---------------------------------------------------------------------------
class F90InstEntry(FortranRule):
    """ENTRY shall not be used."""

    rule_key = "F90.INST.Entry"
    severity = "MAJOR"

    def check(self, ast, file_path, symbol_table):
        violations = []
        for node in walk(ast, Entry_Stmt):
            line = _get_line(node)
            fp = _get_source_file_path(node) or file_path
            violations.append(Violation(
                rule_key=self.rule_key,
                message="ENTRY shall not be used. Subroutines and functions shall have one entry point.",
                file_path=fp, line=line, severity=self.severity,
            ))
        return violations


# ---------------------------------------------------------------------------
# EUM.INST.Backspace — BACKSPACE statement
# ---------------------------------------------------------------------------
class EumInstBackspace(FortranRule):
    """BACKSPACE shall not be used."""

    rule_key = "EUM.INST.Backspace"
    severity = "INFO"

    def check(self, ast, file_path, symbol_table):
        violations = []
        for node in walk(ast, Backspace_Stmt):
            line = _get_line(node)
            fp = _get_source_file_path(node) or file_path
            violations.append(Violation(
                rule_key=self.rule_key,
                message="BACKSPACE shall not be used.",
                file_path=fp, line=line, severity=self.severity,
            ))
        return violations


# ---------------------------------------------------------------------------
# EUM.INST.BlockData — BLOCK DATA
# ---------------------------------------------------------------------------
class EumInstBlockData(FortranRule):
    """BLOCK DATA shall not be used."""

    rule_key = "EUM.INST.BlockData"
    severity = "INFO"

    def check(self, ast, file_path, symbol_table):
        violations = []
        for node in walk(ast, Block_Data):
            line = _get_line(node)
            fp = _get_source_file_path(node) or file_path
            violations.append(Violation(
                rule_key=self.rule_key,
                message="BLOCK DATA shall not be used. Use modules instead.",
                file_path=fp, line=line, severity=self.severity,
            ))
        return violations


# ---------------------------------------------------------------------------
# EUM.INST.NoData — DATA statement
# ---------------------------------------------------------------------------
class EumInstNoData(FortranRule):
    """Initialisation with DATA shall be avoided."""

    rule_key = "EUM.INST.NoData"
    severity = "INFO"

    def check(self, ast, file_path, symbol_table):
        violations = []
        for node in walk(ast, Data_Stmt):
            line = _get_line(node)
            fp = _get_source_file_path(node) or file_path
            violations.append(Violation(
                rule_key=self.rule_key,
                message="Initialisation with DATA shall be avoided.",
                file_path=fp, line=line, severity=self.severity,
            ))
        return violations


# ---------------------------------------------------------------------------
# EUM.INST.Namelist — NAMELIST statement
# ---------------------------------------------------------------------------
class EumInstNamelist(FortranRule):
    """NAMELIST shall not be used."""

    rule_key = "EUM.INST.Namelist"
    severity = "INFO"

    def check(self, ast, file_path, symbol_table):
        violations = []
        for node in walk(ast, Namelist_Stmt):
            line = _get_line(node)
            fp = _get_source_file_path(node) or file_path
            violations.append(Violation(
                rule_key=self.rule_key,
                message="NAMELIST shall not be used.",
                file_path=fp, line=line, severity=self.severity,
            ))
        return violations


# ---------------------------------------------------------------------------
# EUM.INST.Continue — standalone CONTINUE statement
# ---------------------------------------------------------------------------
class EumInstContinue(FortranRule):
    """CONTINUE shall not be used (except as END CONTINUE in block constructs)."""

    rule_key = "EUM.INST.Continue"
    severity = "INFO"

    def check(self, ast, file_path, symbol_table):
        violations = []
        for node in walk(ast, Continue_Stmt):
            # Skip CONTINUE that is part of a DO loop (label DO terminator)
            # — those are caught by F90.DESIGN.Obsolete instead.
            # In free-form Fortran, standalone CONTINUE is always a violation.
            line = _get_line(node)
            fp = _get_source_file_path(node) or file_path
            violations.append(Violation(
                rule_key=self.rule_key,
                message="CONTINUE shall not be used.",
                file_path=fp, line=line, severity=self.severity,
            ))
        return violations


# ---------------------------------------------------------------------------
# F77.INST.Dimension — DIMENSION statement (not attribute)
# ---------------------------------------------------------------------------
class F77InstDimension(FortranRule):
    """The DIMENSION statement shall not be used. Use the DIMENSION attribute."""

    rule_key = "F77.INST.Dimension"
    severity = "MAJOR"

    def check(self, ast, file_path, symbol_table):
        violations = []
        for node in walk(ast, Dimension_Stmt):
            line = _get_line(node)
            fp = _get_source_file_path(node) or file_path
            violations.append(Violation(
                rule_key=self.rule_key,
                message="The DIMENSION statement shall not be used. Use the DIMENSION attribute to declare arrays.",
                file_path=fp, line=line, severity=self.severity,
            ))
        return violations


# ---------------------------------------------------------------------------
# EUM.INST.NoUnderscoreKind — variable_8 kind suffix
# ---------------------------------------------------------------------------
_KIND_SUFFIX_RE = re.compile(r'\b([A-Za-z][A-Za-z0-9_]*)_(\d+)\b')


class EumInstNoUnderscoreKind(FortranRule):
    """Qualification of constants and variables by underscore + kind shall not be used."""

    rule_key = "EUM.INST.NoUnderscoreKind"
    severity = "INFO"

    def check(self, ast, file_path, symbol_table):
        violations = []
        # The rule targets kind-qualified literal constants like 1.0_8, 42_int32
        # and kind-qualified variable references like x_8.
        # Walking Name nodes produces FPs because names like mu_0, visible_0
        # are legitimate identifiers where _0 is part of the name.
        # Instead, we scan source lines for literal constants with _kind suffix.
        lines = _read_source_lines(file_path, symbol_table)
        seen = set()
        # Match: number_kind (e.g., 1.0_8, 3.14_dp, 42_int32)
        literal_kind_re = re.compile(
            r'\b(\d+\.?\d*[dDeE]?[-+]?\d*)_(\w+)\b'
        )
        for i, line in enumerate(lines, 1):
            # Skip comments
            stripped = line.strip()
            if stripped.startswith('!'):
                continue
            # Remove string literals to avoid matching numbers inside strings
            # (e.g., "AE@440_865" should not trigger a kind-notation violation)
            code_only = re.sub(r'"[^"]*"', '""', line)
            code_only = re.sub(r"'[^']*'", "''", code_only)
            for match in literal_kind_re.finditer(code_only):
                full = match.group(0)
                if full not in seen:
                    seen.add(full)
                    violations.append(Violation(
                        rule_key=self.rule_key,
                        message=f"Qualification by underscore + kind attribute shall not be used: '{full}'.",
                        file_path=file_path, line=i, severity=self.severity,
                    ))
        return violations


# ---------------------------------------------------------------------------
# F90.INST.Pointer — POINTER usage restrictions
# ---------------------------------------------------------------------------
class F90InstPointer(FortranRule):
    """Dynamic memory (POINTER) shall not be used unless accepted via RFD/RFW."""

    rule_key = "F90.INST.Pointer"
    severity = "MAJOR"

    def check(self, ast, file_path, symbol_table):
        violations = []
        for node in walk(ast, Pointer_Stmt):
            line = _get_line(node)
            fp = _get_source_file_path(node) or file_path
            violations.append(Violation(
                rule_key=self.rule_key,
                message="Dynamic memory shall not be used unless accepted via RFD or RFW.",
                file_path=fp, line=line, severity=self.severity,
            ))
        return violations


# ---------------------------------------------------------------------------
# F77.INST.Assign — ASSIGN statement (text scan, no AST node in fparser)
# ---------------------------------------------------------------------------
class F77InstAssign(FortranRule):
    """ASSIGN shall not be used."""

    rule_key = "F77.INST.Assign"
    severity = "MAJOR"

    def check(self, ast, file_path, symbol_table):
        violations = []
        # fparser has no Assign_Stmt node — text scan
        # We need to read the source lines
        import os
        abs_path = os.path.join(symbol_table._source_dir, file_path) if hasattr(symbol_table, '_source_dir') else file_path
        if not os.path.isfile(abs_path):
            abs_path = file_path
        if not os.path.isfile(abs_path):
            return violations
        try:
            with open(abs_path, 'r', errors='replace') as f:
                lines = f.readlines()
        except OSError:
            return violations
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            # Match ASSIGN label TO var
            if re.match(r'(?i)\bASSIGN\b\s+\d+\s+\bTO\b', stripped):
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message="ASSIGN shall not be used.",
                    file_path=file_path, line=i, severity=self.severity,
                ))
        return violations


# ---------------------------------------------------------------------------
# F77.INST.Pause — PAUSE statement (text scan, no AST node in fparser)
# ---------------------------------------------------------------------------
class F77InstPause(FortranRule):
    """PAUSE shall not be used."""

    rule_key = "F77.INST.Pause"
    severity = "MAJOR"

    def check(self, ast, file_path, symbol_table):
        violations = []
        import os
        abs_path = os.path.join(symbol_table._source_dir, file_path) if hasattr(symbol_table, '_source_dir') else file_path
        if not os.path.isfile(abs_path):
            abs_path = file_path
        if not os.path.isfile(abs_path):
            return violations
        try:
            with open(abs_path, 'r', errors='replace') as f:
                lines = f.readlines()
        except OSError:
            return violations
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if re.match(r'(?i)\bPAUSE\b', stripped):
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message="PAUSE shall not be used.",
                    file_path=file_path, line=i, severity=self.severity,
                ))
        return violations


# ---------------------------------------------------------------------------
# COM.INST.CodeComment — commented-out code
# ---------------------------------------------------------------------------
class ComInstCodeComment(FortranRule):
    """Comments shall not be used to eliminate code from the control flow."""

    rule_key = "COM.INST.CodeComment"
    severity = "MAJOR"

    # Heuristic: detect comment lines that look like commented-out executable
    # code.  We require strong syntactic evidence (parentheses, assignment
    # syntax, etc.) rather than just a keyword at the start, because many
    # legitimate comments begin with keywords (e.g. "! MODULE foo", "! End
    # loop over iband", "! allocate variables").
    _CODE_PATTERNS = re.compile(
        r'(?i)^\s*!\s*('
        # IF (...) THEN  or  IF (...) action
        r'IF\s*\(.*\)\s*(THEN\b|[A-Z])'
        r'|'
        # DO var = start, end
        r'DO\s+\w+\s*='
        r'|'
        # CALL name(...)
        r'CALL\s+\w+\s*\('
        r'|'
        # ALLOCATE(...) / DEALLOCATE(...)
        r'(ALLOCATE|DEALLOCATE)\s*\('
        r'|'
        # OPEN(...) / CLOSE(...) / READ(...) / WRITE(...) / INQUIRE(...)
        r'(OPEN|CLOSE|READ|WRITE|INQUIRE)\s*\('
        r'|'
        # NULLIFY(...)
        r'NULLIFY\s*\('
        r'|'
        # GOTO / GO TO label
        r'GO\s*TO\s+\d'
        r'|'
        # Assignment: var = expr  (but not == comparison)
        r'\w+\s*=(?!=)'
        r')'
    )

    def check(self, ast, file_path, symbol_table):
        violations = []
        import os
        abs_path = os.path.join(symbol_table._source_dir, file_path) if hasattr(symbol_table, '_source_dir') else file_path
        if not os.path.isfile(abs_path):
            abs_path = file_path
        if not os.path.isfile(abs_path):
            return violations
        try:
            with open(abs_path, 'r', errors='replace') as f:
                lines = f.readlines()
        except OSError:
            return violations
        for i, line in enumerate(lines, 1):
            if self._CODE_PATTERNS.match(line):
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message="Comments shall not be used to eliminate code from the control flow.",
                    file_path=file_path, line=i, severity=self.severity,
                ))
        return violations
