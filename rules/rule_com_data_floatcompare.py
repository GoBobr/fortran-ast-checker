"""Rule 6: COM.DATA.FloatCompare

Floating point values shall not be compared with ``==`` or ``/=``.

JFlex false positive cause: INTEGER variables are flagged as
floating-point (88 false positives).

AST solution: resolve the type of both operands in comparison
expressions.  Only flag if BOTH operands are REAL or DOUBLE PRECISION.
"""

from __future__ import annotations

import re
from typing import List

from fparser.two.Fortran2003 import (
    Data_Ref,
    Execution_Part,
    Level_4_Expr,
    Name,
    Part_Ref,
    Program,
)
from fparser.two.utils import walk

from rules.base_rule import FortranRule, Violation
from rules.symbol_table import (
    FORTRAN_INTRINSICS,
    FORTRAN_KEYWORDS,
    INTRINSIC_RETURN_TYPES,
    ProjectSymbolTable,
    _get_line,
    _node_to_str,
)


class ComDataFloatCompare(FortranRule):
    """Check for floating-point comparisons with == or /=."""

    rule_key = "COM.DATA.FloatCompare"
    severity = "CRITICAL"

    def check(
        self,
        ast: Program,
        file_path: str,
        symbol_table: ProjectSymbolTable,
    ) -> List[Violation]:
        violations: List[Violation] = []

        file_scopes = symbol_table.get_all_scopes_in_file(file_path)
        if not file_scopes:
            return violations

        for scope in file_scopes:
            exec_part = self._find_execution_part(ast, scope.name)
            if exec_part is None:
                continue

            # Find all relational expressions (Level_4_Expr handles ==, /=, .EQ., .NE., etc.)
            # Level_4_Expr nodes don't have line numbers, so we need to find the
            # enclosing statement node to get the line number.
            for rel_expr, line in self._walk_with_lines(exec_part, Level_4_Expr):
                if line == 0:
                    continue

                children = list(rel_expr.children)
                if len(children) < 3:
                    continue

                left = children[0]
                op = children[1]
                right = children[2]

                if left is None or right is None or op is None:
                    continue

                op_str = _node_to_str(op).strip().upper()

                # Only check equality/inequality operators
                if op_str not in ("==", "/=", ".EQ.", ".NE."):
                    continue

                left_type = self._resolve_type(left, scope, symbol_table, file_path)
                right_type = self._resolve_type(right, scope, symbol_table, file_path)

                # Only flag if BOTH operands are floating point
                left_is_float = self._is_float_type(left_type)
                right_is_float = self._is_float_type(right_type)

                if left_is_float and right_is_float:
                    violations.append(
                        Violation(
                            rule_key=self.rule_key,
                            message=f"Floating point comparison with {op_str}.",
                            file_path=file_path,
                            line=line,
                            severity=self.severity,
                        )
                    )

        return violations

    @staticmethod
    def _walk_with_lines(root, target_type):
        """Walk AST nodes of target_type, yielding (node, line) pairs.

        Since expression nodes (Level_4_Expr, Level_2_Expr, etc.) don't have
        line numbers in fparser, we track the nearest enclosing statement node
        that does have a line number.
        """
        stack = [(root, _get_line(root))]
        while stack:
            node, current_line = stack.pop()
            if node is None:
                continue
            # Try to get a line number from this node
            node_line = _get_line(node)
            if node_line != 0:
                current_line = node_line
            if isinstance(node, target_type):
                yield (node, current_line)
            if hasattr(node, "children"):
                for child in reversed(node.children):
                    if child is not None:
                        stack.append((child, current_line))

    def _resolve_type(
        self,
        node,
        scope,
        symbol_table: ProjectSymbolTable,
        file_path: str,
    ) -> str:
        """Resolve the type of an expression node."""
        if node is None:
            return ""

        s = _node_to_str(node).strip()

        # Integer literal: 123, 100, etc.
        if re.match(r"^\d+$", s):
            return "INTEGER"

        # Real literal: 1.0, 0.5, etc.
        if re.match(r"^\d*\.\d+", s) or re.match(r"^\d+\.\d*$", s):
            if re.search(r"[dD]", s):
                return "DOUBLE PRECISION"
            return "REAL"

        # Scientific notation: 1.0E5, 1.0D5
        if re.match(r"^\d*\.?\d+[eE]\d+$", s):
            return "REAL"
        if re.match(r"^\d*\.?\d+[dD]\d+$", s):
            return "DOUBLE PRECISION"

        # Named variable or function call
        names = walk(node, Name)
        if not names:
            return ""

        first_name = _node_to_str(names[0])

        # Check if it's an intrinsic function
        if first_name.lower() in INTRINSIC_RETURN_TYPES:
            return INTRINSIC_RETURN_TYPES[first_name.lower()]

        # Check if it's a Fortran intrinsic
        if first_name.lower() in FORTRAN_INTRINSICS:
            return "UNKNOWN"

        # Look up in symbol table
        sym = symbol_table.get_symbol(first_name, scope.name, file_path)
        if sym:
            type_str = sym.type

            # If it's a derived type reference (a%b%c), resolve the component type
            if isinstance(node, Data_Ref) and type_str.upper().startswith("TYPE("):
                # Extract type name from TYPE(type_name)
                import re as _re

                m = _re.match(r"TYPE\s*\(\s*(\w+)\s*\)", type_str, _re.IGNORECASE)
                if m:
                    derived_type_name = m.group(1)
                    # Get the last component name in the Data_Ref
                    all_names = [walk(n, Name) for n in node.children if n is not None]
                    # The last component is the last Name in the Data_Ref
                    last_name = _node_to_str(names[-1]) if names else ""
                    if last_name:
                        components = symbol_table.get_derived_type_components(derived_type_name)
                        if last_name in components:
                            return components[last_name].type
                        # Case-insensitive search
                        for cname, csym in components.items():
                            if cname.lower() == last_name.lower():
                                return csym.type

            return type_str

        # Check if it's a function defined in the project
        for scope_key, scope_info in symbol_table.scopes.items():
            if scope_info.name.lower() == first_name.lower():
                if scope_info.kind == "function":
                    for sname, ssym in scope_info.symbols.items():
                        if sname.lower() == first_name.lower():
                            return ssym.type
                return "UNKNOWN"

        return ""

    @staticmethod
    def _is_float_type(type_str: str) -> bool:
        """Check if a type string represents a floating-point type."""
        t = type_str.upper().strip()
        return t.startswith("REAL") or t.startswith("DOUBLE")

    @staticmethod
    def _find_execution_part(ast: Program, scope_name: str):
        """Find the Execution_Part for a given scope name."""
        from fparser.two.Fortran2003 import (
            Function_Stmt,
            Function_Subprogram,
            Main_Program,
            Program_Stmt,
            Subroutine_Stmt,
            Subroutine_Subprogram,
        )

        for sub in walk(ast, Subroutine_Subprogram):
            for child in sub.children:
                if isinstance(child, Subroutine_Stmt):
                    for c in child.children:
                        if isinstance(c, Name) and _node_to_str(c) == scope_name:
                            for c2 in sub.children:
                                if isinstance(c2, Execution_Part):
                                    return c2
                    break

        for func in walk(ast, Function_Subprogram):
            for child in func.children:
                if isinstance(child, Function_Stmt):
                    for c in child.children:
                        if isinstance(c, Name) and _node_to_str(c) == scope_name:
                            for c2 in func.children:
                                if isinstance(c2, Execution_Part):
                                    return c2
                    break

        for main in walk(ast, Main_Program):
            for child in main.children:
                if isinstance(child, Program_Stmt):
                    for c in child.children:
                        if isinstance(c, Name) and _node_to_str(c) == scope_name:
                            for c2 in main.children:
                                if isinstance(c2, Execution_Part):
                                    return c2
                    break

        return None
