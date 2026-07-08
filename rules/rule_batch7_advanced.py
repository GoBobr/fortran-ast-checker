"""Batch 7: Advanced AST-based rules.

These rules were originally marked as 🔮 (future implementation) because
they require semantic analysis beyond what a JFlex lexer can provide.
With fparser's AST, we can now implement them.

Rules implemented (4):
  - EUM.INST.StatAfterAlloc  (STAT check right after ALLOCATE/DEALLOCATE)
  - EUM.INST.AssignmentOp    (explicit ASSIGNMENT(=) for derived types with POINTER/ALLOCATABLE)
  - EUM.INST.InitFinal       (FINAL subroutine for derived types with POINTER/ALLOCATABLE)
  - COM.DATA.Invariant       (data never modified should be PARAMETER)
"""

from __future__ import annotations

import re
from typing import List, Set

from fparser.two.Fortran2003 import (
    Allocate_Stmt,
    Assignment_Stmt,
    Deallocate_Stmt,
    Derived_Type_Def,
    If_Stmt,
    If_Construct,
    Name,
    Part_Ref,
    Type_Declaration_Stmt,
)
from fparser.two.utils import walk

from rules.base_rule import FortranRule, Violation
from rules.symbol_table import ProjectSymbolTable, _get_line, _get_source_file_path


# ---------------------------------------------------------------------------
# EUM.INST.StatAfterAlloc — STAT check right after ALLOCATE/DEALLOCATE
# ---------------------------------------------------------------------------
class EumInstStatAfterAlloc(FortranRule):
    """The STAT variable shall be checked immediately after ALLOCATE/DEALLOCATE."""

    rule_key = "EUM.INST.StatAfterAlloc"
    severity = "INFO"

    def check(self, ast, file_path, symbol_table):
        violations = []
        # Find all ALLOCATE and DEALLOCATE statements
        for stmt in walk(ast, Allocate_Stmt) + walk(ast, Deallocate_Stmt):
            stmt_str = str(stmt).upper()
            if 'STAT' not in stmt_str:
                # No STAT variable — that's a different rule (F90.ERR.Allocate)
                continue

            # Extract the STAT variable name
            stat_match = re.search(r'STAT\s*=\s*(\w+)', stmt_str, re.IGNORECASE)
            if not stat_match:
                continue
            stat_var = stat_match.group(1)

            line_num = _get_line(stmt)
            if not line_num:
                continue

            # Get the end line of the ALLOCATE/DEALLOCATE statement.
            # Multi-line statements can span many lines, so we need the
            # end line to know where to start looking for the IF check.
            end_line = line_num
            if hasattr(stmt, 'item') and stmt.item:
                if hasattr(stmt.item, 'span') and stmt.item.span:
                    end_line = stmt.item.span[1]

            # Check if the next statement is an IF checking this variable.
            # We look for If_Stmt, If_Construct, or If_Then_Stmt near this line.
            # If_Construct nodes often have line=0 in fparser, so we also
            # walk If_Then_Stmt which has the correct line number.
            # We search from the statement start to end_line + 10 to handle
            # multi-line ALLOCATE/DEALLOCATE statements.
            from fparser.two.Fortran2003 import If_Then_Stmt
            found_check = False
            for if_node in walk(ast, (If_Stmt, If_Construct, If_Then_Stmt)):
                if_line = _get_line(if_node) or 0
                if if_line >= line_num and if_line <= end_line + 10:
                    if_str = str(if_node).upper()
                    if stat_var.upper() in if_str:
                        found_check = True
                        break

            if not found_check:
                fp = _get_source_file_path(stmt) or file_path
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message=f"The STAT variable '{stat_var}' shall be checked immediately after ALLOCATE/DEALLOCATE.",
                    file_path=fp, line=line_num, severity=self.severity,
                ))
        return violations


# ---------------------------------------------------------------------------
# EUM.INST.AssignmentOp — explicit ASSIGNMENT(=) for derived types
# ---------------------------------------------------------------------------
class EumInstAssignmentOp(FortranRule):
    """Derived types with POINTER or ALLOCATABLE members shall have an explicit ASSIGNMENT(=) interface."""

    rule_key = "EUM.INST.AssignmentOp"
    severity = "INFO"

    def check(self, ast, file_path, symbol_table):
        violations = []
        # Find all derived type definitions
        for type_def in walk(ast, Derived_Type_Def):
            type_str = str(type_def).upper()
            type_name = self._get_type_name(type_def)

            if not type_name:
                continue

            # Check if the type contains POINTER or ALLOCATABLE
            has_pointer = 'POINTER' in type_str
            has_allocatable = 'ALLOCATABLE' in type_str

            if not (has_pointer or has_allocatable):
                continue

            # Check if there's an ASSIGNMENT(=) interface for this type
            # Look for Interface_Block with ASSIGNMENT(=) mentioning this type
            from fparser.two.Fortran2003 import Interface_Block, Interface_Stmt

            has_assignment = False
            for iface in walk(ast, Interface_Block):
                iface_str = str(iface).upper()
                if 'ASSIGNMENT' in iface_str and type_name.upper() in iface_str:
                    has_assignment = True
                    break

            if not has_assignment:
                line = _get_line(type_def)
                fp = _get_source_file_path(type_def) or file_path
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message=f"Derived type '{type_name}' with POINTER/ALLOCATABLE members shall have an explicit ASSIGNMENT(=) interface.",
                    file_path=fp, line=line, severity=self.severity,
                ))
        return violations

    @staticmethod
    def _get_type_name(type_def) -> str:
        """Extract the type name from a Derived_Type_Def."""
        from fparser.two.Fortran2003 import Derived_Type_Stmt
        for stmt in walk(type_def, Derived_Type_Stmt):
            for child in walk(stmt, Name):
                return str(child).strip()
        return ""


# ---------------------------------------------------------------------------
# EUM.INST.InitFinal — FINAL subroutine for derived types
# ---------------------------------------------------------------------------
class EumInstInitFinal(FortranRule):
    """Derived types with POINTER or ALLOCATABLE members shall have a FINAL subroutine."""

    rule_key = "EUM.INST.InitFinal"
    severity = "INFO"

    def check(self, ast, file_path, symbol_table):
        violations = []
        for type_def in walk(ast, Derived_Type_Def):
            type_str = str(type_def).upper()
            type_name = EumInstAssignmentOp._get_type_name(type_def)

            if not type_name:
                continue

            has_pointer = 'POINTER' in type_str
            has_allocatable = 'ALLOCATABLE' in type_str

            if not (has_pointer or has_allocatable):
                continue

            # Check if there's a FINAL subroutine in the type's CONTAINS section
            has_final = 'FINAL' in type_str

            if not has_final:
                line = _get_line(type_def)
                fp = _get_source_file_path(type_def) or file_path
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message=f"Derived type '{type_name}' with POINTER/ALLOCATABLE members shall have a FINAL subroutine.",
                    file_path=fp, line=line, severity=self.severity,
                ))
        return violations


# ---------------------------------------------------------------------------
# COM.DATA.Invariant — data never modified should be PARAMETER
# ---------------------------------------------------------------------------
class ComDataInvariant(FortranRule):
    """Variables that are never modified shall be declared as PARAMETER (constants)."""

    rule_key = "COM.DATA.Invariant"
    severity = "MAJOR"

    def check(self, ast, file_path, symbol_table):
        violations = []
        from fparser.two.Fortran2003 import Entity_Decl, Initialization

        # Build a set of all dummy argument names across all scopes in this file
        dummy_arg_names: Set[str] = set()
        for scope in symbol_table.get_all_scopes_in_file(file_path):
            for arg in scope.dummy_args:
                dummy_arg_names.add(arg.lower())

        # Build a set of all INTENT(IN) variable names across all scopes in this file
        intent_in_names: Set[str] = set()
        for scope in symbol_table.get_all_scopes_in_file(file_path):
            for sname, sym in scope.symbols.items():
                if sym.intent == "IN":
                    intent_in_names.add(sname.lower())

        # Find all variable declarations
        for decl in walk(ast, Type_Declaration_Stmt):
            decl_str = str(decl)
            # Skip if already PARAMETER
            if 'PARAMETER' in decl_str.upper():
                continue

            # Get entity declarations (each variable in the declaration)
            for entity in walk(decl, Entity_Decl):
                # Get the variable name (first Name child)
                var_name = None
                for name in walk(entity, Name):
                    var_name = str(name).strip()
                    break
                if not var_name:
                    continue

                var_lower = var_name.lower()

                # Skip dummy arguments — they can't be PARAMETER
                if var_lower in dummy_arg_names:
                    continue

                # Skip INTENT(IN) variables — they are intentionally unmodified
                if var_lower in intent_in_names:
                    continue

                # Check if this entity has an initializer (4th child = Initialization)
                has_initializer = (
                    len(entity.children) >= 4
                    and entity.children[3] is not None
                )
                if not has_initializer:
                    continue  # No initial value — can't be PARAMETER

                # Check if the variable is ever modified
                if self._is_modified(ast, var_name):
                    continue  # Variable is modified, not invariant

                # Variable is never modified and has an initial value
                line = _get_line(decl)
                if not line:
                    continue
                fp = _get_source_file_path(decl) or file_path
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message=f"Variable '{var_name}' is never modified and shall be declared as PARAMETER.",
                    file_path=fp, line=line, severity=self.severity,
                ))
        return violations

    @staticmethod
    def _is_modified(ast, var_name: str) -> bool:
        """Check if a variable appears on the LHS of any assignment statement."""
        var_lower = var_name.lower()
        for assign in walk(ast, Assignment_Stmt):
            lhs = str(assign.children[0]).strip().lower()
            # Handle simple variable and array access (var(1,2) = ...)
            base_var = re.match(r'(\w+)', lhs)
            if base_var and base_var.group(1) == var_lower:
                return True
        return False
