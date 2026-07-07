"""Rule 2: COM.TYPE.Expression

Mixed-type expressions shall be avoided.

JFlex false positive cause: expressions where both operands are the
same type are flagged as "mixed type" (533 false positives).

AST solution: resolve the type of each operand in arithmetic operations
via the symbol table and literal syntax analysis.  Only flag genuine
mixed-type expressions (e.g., INTEGER + REAL without explicit
conversion).
"""

from __future__ import annotations

import re
from typing import List, Optional, Set

from fparser.two.Fortran2003 import (
    Add_Operand,
    Assignment_Stmt,
    Data_Ref,
    Execution_Part,
    Intrinsic_Function_Reference,
    Intrinsic_Name,
    Level_2_Expr,
    Name,
    Part_Ref,
    Program,
    BinaryOpBase,
)
from fparser.two.utils import walk

from rules.base_rule import FortranRule, Violation
from rules.symbol_table import (
    FORTRAN_INTRINSICS,
    FORTRAN_KEYWORDS,
    INTRINSIC_RETURN_TYPES,
    ProjectSymbolTable,
    _get_line,
    _get_source_file_path,
    _node_to_str,
)


class ComTypeExpression(FortranRule):
    """Check for mixed-type arithmetic expressions."""

    rule_key = "COM.TYPE.Expression"
    severity = "MINOR"

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

            # Find all assignment statements and check their RHS expressions
            for assign in walk(exec_part, Assignment_Stmt):
                line = _get_line(assign)
                if line == 0:
                    continue

                children = list(assign.children)
                if len(children) < 3:
                    continue

                rhs = children[2]
                stmt_file_path = _get_source_file_path(assign) or file_path

                # Check for mixed-type in Level_2_Expr (arithmetic +, -, etc.)
                for expr in walk(rhs, Level_2_Expr):
                    v = self._check_mixed_type(
                        expr, scope, symbol_table, stmt_file_path, line
                    )
                    violations.extend(v)

                # Also check Add_Operand (multiplication, division)
                for expr in walk(rhs, Add_Operand):
                    v = self._check_mixed_type(
                        expr, scope, symbol_table, stmt_file_path, line
                    )
                    violations.extend(v)

        return violations

    def _check_mixed_type(
        self,
        expr,
        scope,
        symbol_table: ProjectSymbolTable,
        file_path: str,
        line: int,
    ) -> List[Violation]:
        """Check if a binary expression has mixed types."""
        violations: List[Violation] = []

        # Level_2_Expr and Add_Operand are BinaryOpBase subclasses
        # children: [operand1, operator, operand2]
        if not isinstance(expr, BinaryOpBase):
            return violations

        children = list(expr.children)
        if len(children) < 3:
            return violations

        left = children[0]
        op = children[1]
        right = children[2]

        if left is None or right is None or op is None:
            return violations

        # Skip string concatenation (// operator)
        op_str = _node_to_str(op).strip().upper()
        if op_str == "//":
            return violations

        # Skip power operations (**) — type promotion is expected
        if op_str == "**":
            return violations

        left_type = self._resolve_type(left, scope, symbol_table, file_path)
        right_type = self._resolve_type(right, scope, symbol_table, file_path)

        if not left_type or not right_type:
            return violations

        # Skip if either operand type is UNKNOWN (e.g., intrinsic with
        # unknown return type, or function not in symbol table)
        if left_type == "UNKNOWN" or right_type == "UNKNOWN":
            return violations

        # Normalize types
        left_norm = self._normalize_type(left_type)
        right_norm = self._normalize_type(right_type)

        # Same type — no violation
        if left_norm == right_norm:
            return violations

        # Both numeric but different precision (e.g., REAL vs DOUBLE PRECISION)
        # This is technically mixed type but very common and usually intentional
        # Only flag INTEGER vs REAL/DOUBLE mixing
        if left_norm in ("INTEGER",) and right_norm in ("REAL", "DOUBLE"):
            violations.append(
                Violation(
                    rule_key=self.rule_key,
                    message=f"Mixed type expression: {left_norm} {op_str} {right_norm}.",
                    file_path=file_path,
                    line=line,
                    severity=self.severity,
                )
            )
        elif left_norm in ("REAL", "DOUBLE") and right_norm in ("INTEGER",):
            violations.append(
                Violation(
                    rule_key=self.rule_key,
                    message=f"Mixed type expression: {left_norm} {op_str} {right_norm}.",
                    file_path=file_path,
                    line=line,
                    severity=self.severity,
                )
            )

        return violations

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
            # Check for double precision suffix
            if re.search(r"[dD]", s):
                return "DOUBLE PRECISION"
            return "REAL"

        # Scientific notation: 1.0E5, 1.0D5
        if re.match(r"^\d*\.?\d+[eE]\d+$", s):
            return "REAL"
        if re.match(r"^\d*\.?\d+[dD]\d+$", s):
            return "DOUBLE PRECISION"

        # Check for intrinsic function reference (e.g., REAL(a), DBLE(a))
        # Intrinsic_Function_Reference stores the name as Intrinsic_Name, not Name
        if isinstance(node, Intrinsic_Function_Reference):
            for child in node.children:
                if isinstance(child, Intrinsic_Name):
                    intrinsic_name = str(child).lower()
                    if intrinsic_name in INTRINSIC_RETURN_TYPES:
                        return INTRINSIC_RETURN_TYPES[intrinsic_name]
                    if intrinsic_name in FORTRAN_INTRINSICS:
                        return "UNKNOWN"
                    break

        # Named variable or function call
        names = walk(node, Name)
        if not names:
            return ""

        first_name = _node_to_str(names[0])

        # Check if it's an intrinsic function
        if first_name.lower() in INTRINSIC_RETURN_TYPES:
            return INTRINSIC_RETURN_TYPES[first_name.lower()]

        # Check if it's a Fortran intrinsic (but not in return type map)
        if first_name.lower() in FORTRAN_INTRINSICS:
            return "UNKNOWN"

        # Look up in symbol table
        sym = symbol_table.get_symbol(first_name, scope.name, file_path)
        if sym:
            type_str = sym.type

            # If it's a derived type reference (a%b%c), resolve the component type
            if isinstance(node, Data_Ref) and type_str.upper().startswith("TYPE("):
                m = re.match(r"TYPE\s*\(\s*(\w+)\s*\)", type_str, re.IGNORECASE)
                if m:
                    derived_type_name = m.group(1)
                    last_name = _node_to_str(names[-1]) if names else ""
                    if last_name:
                        components = symbol_table.get_derived_type_components(derived_type_name)
                        if last_name in components:
                            return components[last_name].type
                        for cname, csym in components.items():
                            if cname.lower() == last_name.lower():
                                return csym.type

            return type_str

        # Check if it's a function defined in the project
        # (look for function with this name in any scope)
        for scope_key, scope_info in symbol_table.scopes.items():
            if scope_info.name.lower() == first_name.lower():
                # It's a function — try to get its return type
                if scope_info.kind == "function":
                    # Look for a return type declaration
                    for sname, ssym in scope_info.symbols.items():
                        if sname.lower() == first_name.lower():
                            return ssym.type
                return "UNKNOWN"

        return ""

    @staticmethod
    def _normalize_type(type_str: str) -> str:
        """Normalize type strings for comparison."""
        t = type_str.upper().strip()
        if t.startswith("INTEGER"):
            return "INTEGER"
        if t.startswith("REAL"):
            return "REAL"
        if t.startswith("DOUBLE"):
            return "DOUBLE"
        if t.startswith("CHARACTER"):
            return "CHARACTER"
        if t.startswith("LOGICAL"):
            return "LOGICAL"
        if t.startswith("COMPLEX"):
            return "COMPLEX"
        if t.startswith("TYPE"):
            return "TYPE"
        return t

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
