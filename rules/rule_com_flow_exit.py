"""Rule 8: COM.FLOW.Exit

Functions, procedures and methods should have a unique exit point.

JFlex false positive cause: Multiple RETURN statements for error
handling are flagged as bad practice (10 false positives).

AST solution: Count RETURN statements per subroutine/function.  If
more than one RETURN, check if the extra RETURNs follow an error-check
pattern (e.g., ``IF (ierr /= 0) RETURN``).  Allow error-handling
RETURNs; only flag RETURNs in normal flow.
"""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

from fparser.two.Fortran2003 import (
    Assignment_Stmt,
    Execution_Part,
    Function_Stmt,
    Function_Subprogram,
    If_Stmt,
    If_Then_Stmt,
    If_Construct,
    Main_Program,
    Name,
    Program,
    Program_Stmt,
    Return_Stmt,
    Subroutine_Stmt,
    Subroutine_Subprogram,
)
from fparser.two.utils import walk

from rules.base_rule import FortranRule, Violation
from rules.symbol_table import (
    ProjectSymbolTable,
    _get_line,
    _get_source_file_path,
    _node_to_str,
)


class ComFlowExit(FortranRule):
    """Check for multiple RETURN statements (non-error-handling)."""

    rule_key = "COM.FLOW.Exit"
    severity = "CRITICAL"

    # Keywords that indicate error-handling context
    ERROR_KEYWORDS = {
        "ierr",
        "ierror",
        "error_code",
        "error_message",
        "status",
        "stat",
        "iostat",
        "ier",
        "irc",
        "ierr",
        "errno",
        "fail",
        "error",
    }

    def check(
        self,
        ast: Program,
        file_path: str,
        symbol_table: ProjectSymbolTable,
    ) -> List[Violation]:
        violations: List[Violation] = []

        # Check subroutines
        for sub_prog in walk(ast, Subroutine_Subprogram):
            sub_name = self._get_scope_name(sub_prog, Subroutine_Stmt)
            if not sub_name:
                continue
            exec_part = self._find_exec_part(sub_prog)
            if exec_part is None:
                continue
            violations.extend(
                self._check_scope(exec_part, file_path, sub_name)
            )

        # Check functions
        for func_prog in walk(ast, Function_Subprogram):
            func_name = self._get_scope_name(func_prog, Function_Stmt)
            if not func_name:
                continue
            exec_part = self._find_exec_part(func_prog)
            if exec_part is None:
                continue
            violations.extend(
                self._check_scope(exec_part, file_path, func_name)
            )

        # Check main program
        for main_prog in walk(ast, Main_Program):
            prog_name = self._get_scope_name(main_prog, Program_Stmt)
            if not prog_name:
                continue
            exec_part = self._find_exec_part(main_prog)
            if exec_part is None:
                continue
            violations.extend(
                self._check_scope(exec_part, file_path, prog_name)
            )

        return violations

    def _check_scope(
        self,
        exec_part: Execution_Part,
        file_path: str,
        scope_name: str,
    ) -> List[Violation]:
        """Check a single scope for RETURN statements in normal flow.

        A RETURN in normal flow (not inside an IF block) is flagged as
        a non-unique exit point.  RETURNs inside IF blocks are considered
        error-handling and are allowed.
        """
        violations: List[Violation] = []

        # Collect all RETURN statements with their line numbers
        returns = self._find_returns_with_lines(exec_part)
        if not returns:
            return violations

        # Get the last statement in the execution part
        last_stmt = None
        if exec_part.children:
            last_stmt = exec_part.children[-1]

        for ret_node, ret_line in returns:
            # Skip if this RETURN is the very last statement (natural exit)
            if ret_node is last_stmt:
                continue
            # Skip if this RETURN is inside an IF block (error handling)
            if self._is_error_handling_return(ret_node, exec_part):
                continue
            stmt_file_path = _get_source_file_path(ret_node) or file_path
            violations.append(
                Violation(
                    rule_key=self.rule_key,
                    message=f"Multiple exit points in '{scope_name}'. "
                    f"Use a single exit point.",
                    file_path=stmt_file_path,
                    line=ret_line,
                    severity=self.severity,
                )
            )

        return violations

    @staticmethod
    def _find_returns_with_lines(
        exec_part: Execution_Part,
    ) -> List[Tuple[Return_Stmt, int]]:
        """Find all RETURN statements with line numbers.

        Return_Stmt nodes don't have line numbers in fparser, so we
        track the nearest enclosing statement node's line.
        """
        results: List[Tuple[Return_Stmt, int]] = []

        def _walk(node, current_line):
            if node is None:
                return
            node_line = _get_line(node)
            if node_line != 0:
                current_line = node_line
            if isinstance(node, Return_Stmt):
                results.append((node, current_line))
            if hasattr(node, "children"):
                for child in node.children:
                    _walk(child, current_line)

        _walk(exec_part, 0)
        return results

    def _is_error_handling_return(
        self,
        ret_node: Return_Stmt,
        exec_part: Execution_Part,
    ) -> bool:
        """Check if a RETURN statement is part of error handling.

        A RETURN is considered error-handling if it's inside any IF
        statement or IF construct (conditional block).  Early returns
        from IF blocks are the standard Fortran error-handling pattern.

        We use a permissive approach: any RETURN inside an IF block is
        considered error-handling.  Only RETURNs in the main flow
        (not inside any conditional) are flagged.
        """
        # Check single-line IF: IF (condition) RETURN
        for if_stmt in walk(exec_part, If_Stmt):
            if self._contains_node(if_stmt, ret_node):
                return True

        # Check multi-line IF: IF (condition) THEN ... RETURN ... END IF
        for if_construct in walk(exec_part, If_Construct):
            if self._contains_node(if_construct, ret_node):
                return True

        return False

    @staticmethod
    def _contains_node(parent, target) -> bool:
        """Check if target is a descendant of parent."""
        if parent is target:
            return True
        if hasattr(parent, "children"):
            for child in parent.children:
                if child is not None and ComFlowExit._contains_node(
                    child, target
                ):
                    return True
        return False

    @staticmethod
    def _get_if_condition(if_stmt: If_Stmt) -> str:
        """Get the condition string from a single-line IF statement."""
        # If_Stmt children: [If_Then_Stmt, Action_Stmt] or similar
        # Actually, If_Stmt is: IF ( scalar-logical-expr ) action-stmt
        s = _node_to_str(if_stmt)
        # Extract the condition between IF ( and )
        m = re.match(r"IF\s*\((.+)\)\s*\w", s, re.IGNORECASE | re.DOTALL)
        if m:
            return m.group(1)
        return s

    @staticmethod
    def _get_if_then_condition(if_then_stmt: If_Then_Stmt) -> str:
        """Get the condition string from an IF-THEN statement."""
        s = _node_to_str(if_then_stmt)
        # Extract the condition between IF ( and ) THEN
        m = re.match(r"IF\s*\((.+)\)\s*THEN", s, re.IGNORECASE | re.DOTALL)
        if m:
            return m.group(1)
        return s

    def _is_error_condition(self, condition: str) -> bool:
        """Check if a condition string represents an error check.

        Looks for patterns like:
        - ierr /= 0
        - status == 1
        - error_code /= 0
        - ALLOCATED(x) .eqv. .false.
        - ierr > 0
        """
        cond_lower = condition.lower()

        # Check for error keywords in the condition
        for keyword in self.ERROR_KEYWORDS:
            if keyword in cond_lower:
                return True

        # Check for comparison with 0 or non-zero (common error pattern)
        # e.g., "ierr /= 0", "status > 0", etc.
        # Already covered by keyword check above

        return False

    @staticmethod
    def _get_scope_name(sub_prog, stmt_type) -> str:
        """Extract the scope name from a subprogram node."""
        for child in sub_prog.children:
            if isinstance(child, stmt_type):
                for c in child.children:
                    if isinstance(c, Name):
                        return _node_to_str(c)
        return ""

    @staticmethod
    def _find_exec_part(sub_prog) -> Optional[Execution_Part]:
        """Find the Execution_Part in a subprogram."""
        for child in sub_prog.children:
            if isinstance(child, Execution_Part):
                return child
        return None
