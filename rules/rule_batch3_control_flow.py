"""Batch 3: Control flow & structure rules.

Rules that inspect IF/DO/CASE/WHERE constructs and program structure.

Rules implemented (15):
  - F90.INST.If              (no single-line IF)
  - F77.BLOC.Else            (IF with ELSE IF must have ELSE)
  - F90.REF.Label            (two-word ending blocks)
  - COM.FLOW.CaseSwitch      (CASE DEFAULT required)
  - COM.DATA.LoopCondition   (DO loop variable not modified)
  - COM.FLOW.ExitLoop        (unique exit point for loops)
  - COM.FLOW.Recursion       (recursion forbidden)
  - F90.INST.Operator        (comparison operators .EQ./.NE. etc.)
  - EUM.INST.EqvOperators    (.EQV./.NEQV. with .TRUE./.FALSE.)
  - EUM.INST.NoSingleLineWhere (single-line WHERE)
  - EUM.BLOC.WhereElse       (WHERE with ELSE WHERE needs empty ELSE WHERE)
  - EUM.INST.NoLabelledDo    (labelled DO loops)
  - EUM.BLOC.NamedLoops      (named loops when nested/EXIT/CYCLE)
  - EUM.INST.Redundant       (redundant features)
  - F90.DESIGN.LogicUnit     (file contains a logic unit)
"""

from __future__ import annotations

import re
from typing import List, Set, Tuple

from fparser.two.Fortran2003 import (
    Assignment_Stmt,
    Case_Construct,
    Case_Stmt,
    Continue_Stmt,
    Do_Construct,
    Else_If_Stmt,
    Else_Stmt,
    End_If_Stmt,
    End_Where_Stmt,
    Elsewhere_Stmt,
    Goto_Stmt,
    If_Construct,
    If_Stmt,
    If_Then_Stmt,
    Label_Do_Stmt,
    Loop_Control,
    Masked_Elsewhere_Stmt,
    Name,
    Nonlabel_Do_Stmt,
    Program,
    Where_Construct,
    Where_Stmt,
)
from fparser.two.utils import walk

from rules.base_rule import FortranRule, Violation
from rules.symbol_table import ProjectSymbolTable, _get_line, _get_source_file_path


# ---------------------------------------------------------------------------
# F90.INST.If — no single-line IF
# ---------------------------------------------------------------------------
class F90InstIf(FortranRule):
    """Single line IF statements shall not be used."""

    rule_key = "F90.INST.If"
    severity = "MAJOR"

    def check(self, ast, file_path, symbol_table):
        violations = []
        # If_Stmt is the single-line IF (If_Construct is the block IF)
        for node in walk(ast, If_Stmt):
            line = _get_line(node)
            fp = _get_source_file_path(node) or file_path
            violations.append(Violation(
                rule_key=self.rule_key,
                message="Single line IF statements shall not be used. Use IF...THEN...END IF instead.",
                file_path=fp, line=line, severity=self.severity,
            ))
        return violations


# ---------------------------------------------------------------------------
# F77.BLOC.Else — IF with ELSE IF must have ELSE
# ---------------------------------------------------------------------------
class F77BlocElse(FortranRule):
    """IF constructs with ELSE IF options shall have an ELSE option."""

    rule_key = "F77.BLOC.Else"
    severity = "MAJOR"

    def check(self, ast, file_path, symbol_table):
        violations = []
        for construct in walk(ast, If_Construct):
            has_else_if = bool(walk(construct, Else_If_Stmt))
            has_else = bool(walk(construct, Else_Stmt))
            if has_else_if and not has_else:
                # Find the End_If_Stmt line
                end_ifs = walk(construct, End_If_Stmt)
                line = _get_line(end_ifs[0]) if end_ifs else _get_line(construct)
                fp = _get_source_file_path(construct) or file_path
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message="IF constructs with ELSE IF options shall have an ELSE option.",
                    file_path=fp, line=line, severity=self.severity,
                ))
        return violations


# ---------------------------------------------------------------------------
# F90.REF.Label — two-word ending blocks
# ---------------------------------------------------------------------------
class F90RefLabel(FortranRule):
    """End-of-block statements shall consist of two words (END DO, END IF, etc.)."""

    rule_key = "F90.REF.Label"
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

        # Valid construct keywords that can follow END.
        _VALID_END_KW = {
            'IF', 'DO', 'SUBROUTINE', 'FUNCTION', 'MODULE', 'PROGRAM',
            'SELECT', 'WHERE', 'FORALL', 'TYPE', 'INTERFACE', 'BLOCK',
            'CRITICAL', 'ASSOCIATE', 'ENUM', 'STRUCTURE',
        }
        # Match END at start of statement (after optional whitespace).
        # END must be followed by whitespace, end-of-line, or a comment.
        # This avoids matching identifiers like 'end_index' or 'END_PHi'.
        _END_RE = re.compile(r'(?i)^\s*END(?=\s|!|$)')
        # Match END concatenated with a keyword (ENDIF, ENDDO, etc.) — no blank.
        _END_CONCAT_RE = re.compile(
            r'(?i)^\s*END(' + '|'.join(_VALID_END_KW) + r')\b'
        )

        for i, line in enumerate(lines, 1):
            # First check for ENDIF/ENDDO (concatenated, no blank).
            if _END_CONCAT_RE.match(line):
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message="End-of-block statements shall consist of two words separated by a blank character.",
                    file_path=file_path, line=i, severity=self.severity,
                ))
                continue

            m = _END_RE.match(line)
            if not m:
                continue
            # Extract everything after 'END' on this line (strip trailing comment).
            rest = line[m.end():]
            if '!' in rest:
                rest = rest[:rest.index('!')]
            rest = rest.strip()
            # rest is the keyword following END (or empty for bare END).
            following = rest.split()[0].upper() if rest.split() else ''

            if not following:
                # Bare END — no construct keyword.
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message="End-of-block statements shall consist of two words separated by a blank character.",
                    file_path=file_path, line=i, severity=self.severity,
                ))
            elif following not in _VALID_END_KW:
                # END followed by an invalid keyword.
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message="End-of-block statements shall consist of two words separated by a blank character.",
                    file_path=file_path, line=i, severity=self.severity,
                ))
        return violations


# ---------------------------------------------------------------------------
# COM.FLOW.CaseSwitch — CASE DEFAULT required
# ---------------------------------------------------------------------------
class ComFlowCaseSwitch(FortranRule):
    """SELECT CASE constructs shall have a CASE DEFAULT option."""

    rule_key = "COM.FLOW.CaseSwitch"
    severity = "MAJOR"

    def check(self, ast, file_path, symbol_table):
        violations = []
        for construct in walk(ast, Case_Construct):
            # Check if any Case_Stmt has DEFAULT
            has_default = False
            for case_stmt in walk(construct, Case_Stmt):
                case_str = str(case_stmt).upper()
                if 'DEFAULT' in case_str:
                    has_default = True
                    break
            if not has_default:
                line = _get_line(construct)
                fp = _get_source_file_path(construct) or file_path
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message="SELECT CASE constructs shall have a CASE DEFAULT option.",
                    file_path=fp, line=line, severity=self.severity,
                ))
        return violations


# ---------------------------------------------------------------------------
# COM.DATA.LoopCondition — DO loop variable not modified
# ---------------------------------------------------------------------------
class ComDataLoopCondition(FortranRule):
    """A DO loop control variable shall not be altered within the loop."""

    rule_key = "COM.DATA.LoopCondition"
    severity = "MAJOR"

    def check(self, ast, file_path, symbol_table):
        violations = []
        for do_construct in walk(ast, Do_Construct):
            # Find the loop variable
            loop_var = self._get_loop_var(do_construct)
            if not loop_var:
                continue

            # Find all Assignment_Stmt inside the DO construct
            for assign in walk(do_construct, Assignment_Stmt):
                # Check if LHS is the loop variable
                lhs_str = str(assign.children[0]).strip().lower()
                if lhs_str == loop_var.lower():
                    line = _get_line(assign)
                    fp = _get_source_file_path(assign) or file_path
                    violations.append(Violation(
                        rule_key=self.rule_key,
                        message=f"A DO loop control variable '{loop_var}' shall not be altered within the loop.",
                        file_path=fp, line=line, severity=self.severity,
                    ))
        return violations

    @staticmethod
    def _get_loop_var(do_construct) -> str:
        """Extract the loop variable name from a Do_Construct."""
        for node in walk(do_construct, (Label_Do_Stmt, Nonlabel_Do_Stmt)):
            for child in walk(node, Loop_Control):
                # Loop_Control children: [var, start, end, step]
                if child.children:
                    var = child.children[0]
                    if isinstance(var, Name):
                        return str(var).strip()
        return ""


# ---------------------------------------------------------------------------
# COM.FLOW.ExitLoop — unique exit point for loops
# ---------------------------------------------------------------------------
class ComFlowExitLoop(FortranRule):
    """Loops shall have a unique exit point."""

    rule_key = "COM.FLOW.ExitLoop"
    severity = "MAJOR"

    def check(self, ast, file_path, symbol_table):
        violations = []
        from fparser.two.Fortran2003 import Exit_Stmt, Cycle_Stmt
        for do_construct in walk(ast, Do_Construct):
            exits = walk(do_construct, Exit_Stmt)
            if len(exits) > 1:
                for exit_stmt in exits[1:]:  # Skip first exit
                    line = _get_line(exit_stmt)
                    fp = _get_source_file_path(exit_stmt) or file_path
                    violations.append(Violation(
                        rule_key=self.rule_key,
                        message="Loops shall have a unique exit point.",
                        file_path=fp, line=line, severity=self.severity,
                    ))
        return violations


# ---------------------------------------------------------------------------
# COM.FLOW.Recursion — recursion forbidden
# ---------------------------------------------------------------------------
class ComFlowRecursion(FortranRule):
    """Recursion shall not be used."""

    rule_key = "COM.FLOW.Recursion"
    severity = "MAJOR"

    def check(self, ast, file_path, symbol_table):
        violations = []
        from fparser.two.Fortran2003 import (
            Subroutine_Subprogram, Function_Subprogram,
            Subroutine_Stmt, Function_Stmt, Call_Stmt,
        )

        # Walk each procedure body (Subroutine_Subprogram / Function_Subprogram)
        # and check for self-referencing CALL statements within that body only.
        for subprogram in walk(ast, (Subroutine_Subprogram, Function_Subprogram)):
            # Get the procedure name from the Subroutine_Stmt / Function_Stmt
            proc_name = ""
            for stmt in walk(subprogram, (Subroutine_Stmt, Function_Stmt)):
                proc_name = self._get_proc_name(stmt)
                break
            if not proc_name:
                continue
            proc_lower = proc_name.lower()

            # Check for CALL statements within this subprogram's body only
            for call in walk(subprogram, Call_Stmt):
                call_name = str(call.children[0]).strip().lower() if call.children else ""
                if call_name == proc_lower:
                    line = _get_line(call)
                    if not line:
                        continue
                    fp = _get_source_file_path(call) or file_path
                    violations.append(Violation(
                        rule_key=self.rule_key,
                        message=f"Recursion shall not be used: '{proc_lower}' calls itself.",
                        file_path=fp, line=line, severity=self.severity,
                    ))
        return violations

    @staticmethod
    def _get_proc_name(stmt) -> str:
        for child in stmt.children:
            if isinstance(child, Name):
                return str(child).strip()
        return ""


# ---------------------------------------------------------------------------
# F90.INST.Operator — comparison operators .EQ./.NE. etc.
# ---------------------------------------------------------------------------
class F90InstOperator(FortranRule):
    """Comparison operators .EQ., .NE., .LE., .LT., .GE., .GT. shall not be used."""

    rule_key = "F90.INST.Operator"
    severity = "MAJOR"

    _OLD_OPS = re.compile(r'(?i)\.(EQ|NE|LE|LT|GE|GT)\.')

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
            if stripped.startswith('!') or stripped.startswith('c') or stripped.startswith('C'):
                continue
            match = self._OLD_OPS.search(line)
            if match:
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message=f"Comparison operator .{match.group(1)}. shall not be used. Use ==, /=, <=, <, >=, > instead.",
                    file_path=file_path, line=i, severity=self.severity,
                ))
        return violations


# ---------------------------------------------------------------------------
# EUM.INST.EqvOperators — .EQV./.NEQV. with .TRUE./.FALSE.
# ---------------------------------------------------------------------------
class EumInstEqvOperators(FortranRule):
    """Logical comparison operators shall only be used to compare two logical variables."""

    rule_key = "EUM.INST.EqvOperators"
    severity = "INFO"

    _EQV_WITH_LITERAL = re.compile(r'(?i)\.(EQV|NEQV)\s*\.\s*(TRUE|FALSE)\s*\.')

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
            if self._EQV_WITH_LITERAL.search(line):
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message="Logical comparison operators (.EQV./.NEQV.) shall only be used to compare two logical variables, never with .TRUE. or .FALSE.",
                    file_path=file_path, line=i, severity=self.severity,
                ))
        return violations


# ---------------------------------------------------------------------------
# EUM.INST.NoSingleLineWhere — single-line WHERE
# ---------------------------------------------------------------------------
class EumInstNoSingleLineWhere(FortranRule):
    """Single line WHERE statements shall not be used."""

    rule_key = "EUM.INST.NoSingleLineWhere"
    severity = "INFO"

    def check(self, ast, file_path, symbol_table):
        violations = []
        # Where_Stmt is the single-line WHERE (Where_Construct is the block form)
        for node in walk(ast, Where_Stmt):
            line = _get_line(node)
            fp = _get_source_file_path(node) or file_path
            violations.append(Violation(
                rule_key=self.rule_key,
                message="Single line WHERE statements shall not be used. Use WHERE...END WHERE instead.",
                file_path=fp, line=line, severity=self.severity,
            ))
        return violations


# ---------------------------------------------------------------------------
# EUM.BLOC.WhereElse — WHERE with ELSE WHERE needs empty ELSE WHERE
# ---------------------------------------------------------------------------
class EumBlocWhereElse(FortranRule):
    """WHERE constructs with ELSE WHERE options shall have an empty ELSE WHERE."""

    rule_key = "EUM.BLOC.WhereElse"
    severity = "INFO"

    def check(self, ast, file_path, symbol_table):
        violations = []
        for construct in walk(ast, Where_Construct):
            has_masked_elsewhere = bool(walk(construct, Masked_Elsewhere_Stmt))
            has_elsewhere = bool(walk(construct, Elsewhere_Stmt))
            if has_masked_elsewhere and not has_elsewhere:
                end_wheres = walk(construct, End_Where_Stmt)
                line = _get_line(end_wheres[0]) if end_wheres else _get_line(construct)
                fp = _get_source_file_path(construct) or file_path
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message="WHERE constructs with ELSE WHERE options shall have an empty ELSE WHERE option.",
                    file_path=fp, line=line, severity=self.severity,
                ))
        return violations


# ---------------------------------------------------------------------------
# EUM.INST.NoLabelledDo — labelled DO loops
# ---------------------------------------------------------------------------
class EumInstNoLabelledDo(FortranRule):
    """Labelled DO loops shall not be used."""

    rule_key = "EUM.INST.NoLabelledDo"
    severity = "INFO"

    def check(self, ast, file_path, symbol_table):
        violations = []
        for node in walk(ast, Label_Do_Stmt):
            line = _get_line(node)
            fp = _get_source_file_path(node) or file_path
            violations.append(Violation(
                rule_key=self.rule_key,
                message="Labelled DO loops shall not be used.",
                file_path=fp, line=line, severity=self.severity,
            ))
        return violations


# ---------------------------------------------------------------------------
# EUM.BLOC.NamedLoops — named loops when nested or EXIT/CYCLE
# ---------------------------------------------------------------------------
class EumBlocNamedLoops(FortranRule):
    """Named loops shall be used when nested or when EXIT/CYCLE is used."""

    rule_key = "EUM.BLOC.NamedLoops"
    severity = "INFO"

    def check(self, ast, file_path, symbol_table):
        violations = []
        from fparser.two.Fortran2003 import Exit_Stmt, Cycle_Stmt

        # Find all DO constructs and check nesting depth
        all_dos = walk(ast, Do_Construct)
        for do_construct in all_dos:
            # Check nesting depth: count parent DO constructs
            # Since fparser doesn't give parent pointers, we use a heuristic:
            # if there are other DO constructs whose line range overlaps
            depth = 0
            do_line = _get_line(do_construct) or 0
            for other_do in all_dos:
                if other_do is do_construct:
                    continue
                other_line = _get_line(other_do) or 0
                if other_line < do_line:
                    # Check if other_do contains do_construct
                    # Heuristic: check if do_construct is in other_do's children
                    if self._contains(other_do, do_construct):
                        depth += 1

            has_exit_or_cycle = bool(walk(do_construct, (Exit_Stmt, Cycle_Stmt)))

            if depth >= 1 or has_exit_or_cycle:
                # Check if this DO is named
                is_named = self._is_named_do(do_construct)
                if not is_named:
                    line = _get_line(do_construct)
                    fp = _get_source_file_path(do_construct) or file_path
                    violations.append(Violation(
                        rule_key=self.rule_key,
                        message="Named loops shall be used when there are multiple levels of nested loops or when EXIT or CYCLE statements are used.",
                        file_path=fp, line=line, severity=self.severity,
                    ))
        return violations

    @staticmethod
    def _contains(parent, child) -> bool:
        """Check if parent AST node contains child."""
        if parent is child:
            return True
        if hasattr(parent, 'children'):
            for c in parent.children:
                if c is not None and EumBlocNamedLoops._contains(c, child):
                    return True
        return False

    @staticmethod
    def _is_named_do(do_construct) -> bool:
        """Check if a DO construct has a name."""
        for node in walk(do_construct, (Label_Do_Stmt, Nonlabel_Do_Stmt)):
            # Named DO: the statement starts with name:
            stmt_str = str(node)
            if re.match(r'^\s*\w+\s*:\s*DO\b', stmt_str, re.IGNORECASE):
                return True
        return False


# ---------------------------------------------------------------------------
# EUM.INST.Redundant — redundant Fortran 90 features
# ---------------------------------------------------------------------------
class EumInstRedundant(FortranRule):
    """Redundant Fortran 90 language features shall not be used."""

    rule_key = "EUM.INST.Redundant"
    severity = "INFO"

    _REDUNDANT_PATTERNS = [
        (re.compile(r'(?i)\bCHARACTER\s*\*\s*\('), "CHARACTER*(*) declaration"),
        (re.compile(r'(?i)\bCHARACTER\s*\*\s*\d+'), "CHARACTER*N declaration"),
    ]

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
            if stripped.startswith('!') or stripped.startswith('c') or stripped.startswith('C'):
                continue
            for pattern, feature in self._REDUNDANT_PATTERNS:
                if pattern.search(line):
                    violations.append(Violation(
                        rule_key=self.rule_key,
                        message=f"Redundant Fortran feature shall not be used: {feature}.",
                        file_path=file_path, line=i, severity=self.severity,
                    ))
        return violations


# ---------------------------------------------------------------------------
# F90.DESIGN.LogicUnit — file contains a logic unit
# ---------------------------------------------------------------------------
class F90DesignLogicUnit(FortranRule):
    """Each file shall contain a programming unit (PROGRAM or MODULE)."""

    rule_key = "F90.DESIGN.LogicUnit"
    severity = "MAJOR"

    def check(self, ast, file_path, symbol_table):
        violations = []
        from fparser.two.Fortran2003 import Module_Stmt, Program_Stmt
        has_module = bool(walk(ast, Module_Stmt))
        has_program = bool(walk(ast, Program_Stmt))
        if not has_module and not has_program:
            violations.append(Violation(
                rule_key=self.rule_key,
                message="Each file shall contain a programming unit (PROGRAM or MODULE).",
                file_path=file_path, line=1, severity=self.severity,
            ))
        return violations
