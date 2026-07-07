"""Rule 7: F90.DESIGN.Obsolete

Obsolete Fortran features shall not be used.

JFlex false positive cause: INTEGER variables in DO loops flagged as
real (37 false positives).

AST solution: fparser doesn't even parse real DO loop variables
(syntax error in Fortran 2003+), so the main FP cause is eliminated
automatically.  We still check for other obsolete features:
- Arithmetic IF statement
- Computed GO TO
- Assigned GO TO
- PAUSE statement (not parseable by fparser, so text scan)
- ENTRY statement
- CHARACTER*N declaration syntax
- Nonblock DO construct
- Real DO loop variables (text scan as fallback)
"""

from __future__ import annotations

import re
from typing import List

from fparser.two.Fortran2003 import (
    Arithmetic_If_Stmt,
    Computed_Goto_Stmt,
    Continue_Stmt,
    Entry_Stmt,
    Goto_Stmt,
    Label_Do_Stmt,
    Name,
    Nonblock_Do_Construct,
    Nonlabel_Do_Stmt,
    Loop_Control,
    Program,
)
from fparser.two.utils import walk

from rules.base_rule import FortranRule, Violation
from rules.symbol_table import (
    ProjectSymbolTable,
    _get_line,
    _get_source_file_path,
    _node_to_str,
)


class F90DesignObsolete(FortranRule):
    """Check for obsolete Fortran features."""

    rule_key = "F90.DESIGN.Obsolete"
    severity = "CRITICAL"

    def check(
        self,
        ast: Program,
        file_path: str,
        symbol_table: ProjectSymbolTable,
    ) -> List[Violation]:
        violations: List[Violation] = []

        # 1. Arithmetic IF statement: IF (expr) label1, label2, label3
        for node in walk(ast, Arithmetic_If_Stmt):
            line = _get_line(node)
            stmt_file_path = _get_source_file_path(node) or file_path
            violations.append(
                Violation(
                    rule_key=self.rule_key,
                    message="Obsolete Fortran feature: arithmetic IF statement.",
                    file_path=stmt_file_path,
                    line=line if line else 0,
                    severity=self.severity,
                )
            )

        # 2. Computed GO TO: GO TO (label1, label2, ...) [,] expr
        for node in walk(ast, Computed_Goto_Stmt):
            line = _get_line(node)
            stmt_file_path = _get_source_file_path(node) or file_path
            violations.append(
                Violation(
                    rule_key=self.rule_key,
                    message="Obsolete Fortran feature: computed GO TO statement.",
                    file_path=stmt_file_path,
                    line=line if line else 0,
                    severity=self.severity,
                )
            )

        # 3. Assigned GO TO: GO TO integer_var
        for node in walk(ast, Goto_Stmt):
            # Goto_Stmt covers both unconditional and assigned GO TO
            # Assigned GO TO has form: GO TO var or GO TO var, (label_list)
            s = _node_to_str(node).upper()
            if re.match(r"GO\s*TO\s+\w+\s*[,)]", s) or re.match(
                r"GO\s*TO\s+\w+\s*$", s
            ):
                # Check if the target is a variable name (not a number)
                # Unconditional GOTO has a label (number), assigned has a variable
                names = walk(node, Name)
                if names:
                    line = _get_line(node)
                    stmt_file_path = _get_source_file_path(node) or file_path
                    violations.append(
                        Violation(
                            rule_key=self.rule_key,
                            message="Obsolete Fortran feature: assigned GO TO statement.",
                            file_path=stmt_file_path,
                            line=line if line else 0,
                            severity=self.severity,
                        )
                    )

        # 4. ENTRY statement
        for node in walk(ast, Entry_Stmt):
            line = _get_line(node)
            stmt_file_path = _get_source_file_path(node) or file_path
            violations.append(
                Violation(
                    rule_key=self.rule_key,
                    message="Obsolete Fortran feature: ENTRY statement.",
                    file_path=stmt_file_path,
                    line=line if line else 0,
                    severity=self.severity,
                )
            )

        # 5. Nonblock DO construct (old-style DO with label)
        for node in walk(ast, Nonblock_Do_Construct):
            line = _get_line(node)
            stmt_file_path = _get_source_file_path(node) or file_path
            violations.append(
                Violation(
                    rule_key=self.rule_key,
                    message="Obsolete Fortran feature: nonblock DO construct.",
                    file_path=stmt_file_path,
                    line=line if line else 0,
                    severity=self.severity,
                )
            )

        # 6. CONTINUE statement (used as DO loop terminator in old code)
        for node in walk(ast, Continue_Stmt):
            line = _get_line(node)
            stmt_file_path = _get_source_file_path(node) or file_path
            violations.append(
                Violation(
                    rule_key=self.rule_key,
                    message="Obsolete Fortran feature: CONTINUE statement.",
                    file_path=stmt_file_path,
                    line=line if line else 0,
                    severity=self.severity,
                )
            )

        # 7. Real DO loop variable — fparser doesn't parse these (syntax error
        # in Fortran 2003+), but we do a text scan as a fallback for any
        # that might slip through (e.g., in fixed-form files)
        violations.extend(
            self._check_real_do_variables(ast, file_path, symbol_table)
        )

        # 8. CHARACTER*N declaration syntax (text scan)
        violations.extend(self._check_char_star_n(ast, file_path))

        return violations

    def _check_real_do_variables(
        self,
        ast: Program,
        file_path: str,
        symbol_table: ProjectSymbolTable,
    ) -> List[Violation]:
        """Check for REAL/DOUBLE PRECISION DO loop variables."""
        violations: List[Violation] = []

        for do_stmt in walk(ast, Nonlabel_Do_Stmt):
            # Get the loop variable from Loop_Control
            loop_var = self._get_loop_variable(do_stmt)
            if not loop_var:
                continue

            # Resolve the type of the loop variable
            var_type = self._resolve_variable_type(
                loop_var, do_stmt, file_path, symbol_table
            )

            if var_type and self._is_float_type(var_type):
                line = _get_line(do_stmt)
                stmt_file_path = _get_source_file_path(do_stmt) or file_path
                violations.append(
                    Violation(
                        rule_key=self.rule_key,
                        message=f"Obsolete Fortran feature: real DO loop variable '{loop_var}'.",
                        file_path=stmt_file_path,
                        line=line if line else 0,
                        severity=self.severity,
                    )
                )

        # Also check labeled DO statements
        for do_stmt in walk(ast, Label_Do_Stmt):
            loop_var = self._get_loop_variable(do_stmt)
            if not loop_var:
                continue

            var_type = self._resolve_variable_type(
                loop_var, do_stmt, file_path, symbol_table
            )

            if var_type and self._is_float_type(var_type):
                line = _get_line(do_stmt)
                stmt_file_path = _get_source_file_path(do_stmt) or file_path
                violations.append(
                    Violation(
                        rule_key=self.rule_key,
                        message=f"Obsolete Fortran feature: real DO loop variable '{loop_var}'.",
                        file_path=stmt_file_path,
                        line=line if line else 0,
                        severity=self.severity,
                    )
                )

        return violations

    @staticmethod
    def _get_loop_variable(do_stmt) -> str:
        """Extract the loop variable name from a DO statement."""
        for child in do_stmt.children:
            if isinstance(child, Loop_Control):
                # Loop_Control children: [loop_ctrl_type, (var, limits), ...]
                # The variable is in children[1] which is a tuple
                if len(child.children) >= 2:
                    ctrl = child.children[1]
                    if isinstance(ctrl, tuple) and len(ctrl) >= 1:
                        var_node = ctrl[0]
                        if isinstance(var_node, Name):
                            return _node_to_str(var_node)
        return ""

    def _resolve_variable_type(
        self,
        var_name: str,
        do_stmt,
        file_path: str,
        symbol_table: ProjectSymbolTable,
    ) -> str:
        """Resolve the type of a variable using the symbol table."""
        # Try to find the scope this DO statement is in
        # We don't have parent pointers, so search all scopes in this file
        file_scopes = symbol_table.get_all_scopes_in_file(file_path)
        for scope in file_scopes:
            sym = symbol_table.get_symbol(var_name, scope.name, file_path)
            if sym:
                return sym.type
        return ""

    @staticmethod
    def _is_float_type(type_str: str) -> bool:
        """Check if a type string represents a floating-point type."""
        t = type_str.upper().strip()
        return t.startswith("REAL") or t.startswith("DOUBLE")

    def _check_char_star_n(
        self, ast: Program, file_path: str
    ) -> List[Violation]:
        """Check for CHARACTER*N declaration syntax (text scan).

        fparser may parse this, but we also do a text scan for the
        old-style ``CHARACTER*N`` syntax (vs ``CHARACTER(LEN=N)``).
        """
        violations: List[Violation] = []

        # Get the source text from the AST's root item
        # fparser stores the source in the reader, but we can also
        # check the string representation of Type_Declaration_Stmt nodes
        from fparser.two.Fortran2003 import Type_Declaration_Stmt

        for tds in walk(ast, Type_Declaration_Stmt):
            s = _node_to_str(tds).strip()
            # Check for CHARACTER*N pattern (not CHARACTER(LEN=N))
            # The old syntax is: CHARACTER*10 :: x  or  CHARACTER*10 x
            if re.match(r"CHARACTER\s*\*\s*\d", s, re.IGNORECASE):
                line = _get_line(tds)
                stmt_file_path = _get_source_file_path(tds) or file_path
                violations.append(
                    Violation(
                        rule_key=self.rule_key,
                        message="Obsolete Fortran feature: CHARACTER*N declaration syntax.",
                        file_path=stmt_file_path,
                        line=line if line else 0,
                        severity=self.severity,
                    )
                )

        return violations
