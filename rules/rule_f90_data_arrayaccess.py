"""Rule 10: F90.DATA.ArrayAccess

No duplicate items in array of indirections (vector subscripting).

JFlex false positive cause: array vector subscripting (``intens(crit)``)
is valid Fortran but flagged as an error.

AST solution: vector subscripting on the RHS (read) is always valid
Fortran.  Only flag when the subscript array has repeated values AND the
target is being written (LHS of assignment).
"""

from __future__ import annotations

import re
from typing import List

from fparser.two.Fortran2003 import (
    Assignment_Stmt,
    Name,
    Part_Ref,
    Program,
    Section_Subscript_List,
)
from fparser.two.utils import walk

from rules.base_rule import FortranRule, Violation
from rules.symbol_table import (
    ProjectSymbolTable,
    _get_line,
    _get_source_file_path,
    _node_to_str,
)


class F90DataArrayAccess(FortranRule):
    """Check for invalid vector subscripting on array writes."""

    rule_key = "F90.DATA.ArrayAccess"
    severity = "MAJOR"

    def check(
        self,
        ast: Program,
        file_path: str,
        symbol_table: ProjectSymbolTable,
    ) -> List[Violation]:
        violations: List[Violation] = []

        for node in walk(ast, Assignment_Stmt):
            # Assignment_Stmt children: [LHS, =, RHS]
            if not node.children:
                continue
            lhs = node.children[0]

            # Check if LHS is an array access (Part_Ref)
            for part_ref in walk(lhs, Part_Ref):
                # Part_Ref children: [Name, Section_Subscript_List]
                if len(part_ref.children) < 2:
                    continue
                subscript_list = part_ref.children[1]
                if not isinstance(subscript_list, Section_Subscript_List):
                    continue

                # Check each subscript — if it's a Name (not a number),
                # it could be a vector subscript
                for subscript in subscript_list.children:
                    # A vector subscript is when the subscript is an array name
                    # (not an integer literal or range)
                    if self._is_vector_subscript(subscript):
                        # Check if the vector has repeated values
                        # (only detectable for compile-time constants)
                        if self._has_repeated_values(subscript):
                            line = _get_line(node)
                            stmt_file_path = _get_source_file_path(node) or file_path
                            violations.append(
                                Violation(
                                    rule_key=self.rule_key,
                                    message="No duplicate items in array of indirections.",
                                    file_path=stmt_file_path,
                                    line=line,
                                    severity=self.severity,
                                )
                            )

        return violations

    @staticmethod
    def _is_vector_subscript(subscript) -> bool:
        """Check if a subscript is a vector subscript (array name, not scalar)."""
        # A vector subscript is a Name (array variable) used as an index
        # rather than a scalar integer expression
        if isinstance(subscript, Name):
            return True
        # Could also be an array constructor (/ 1, 2, 2, 3 /)
        s = _node_to_str(subscript)
        if s.startswith("(/") or s.startswith("( /"):
            return True
        return False

    @staticmethod
    def _has_repeated_values(subscript) -> bool:
        """Check if a vector subscript has repeated values.

        Only detectable for compile-time constant arrays (array constructors
        with literal values).  For runtime arrays, we can't know, so we
        don't flag (avoiding false positives).
        """
        s = _node_to_str(subscript)
        # Array constructor: (/ 1, 2, 2, 3 /)
        if s.startswith("(/") or s.startswith("( /"):
            # Extract numbers
            numbers = re.findall(r"\d+", s)
            if len(numbers) > len(set(numbers)):
                return True
        # For a Name (runtime array), we can't know if it has repeated values
        # Don't flag — this avoids the false positives
        return False
