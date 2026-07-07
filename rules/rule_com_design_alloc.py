"""Rule 9: COM.DESIGN.Alloc

Allocation and deallocation of resources should be at the same level.

JFlex false positive cause: Allocation and deallocation happen in
separate subroutines (init/cleanup pattern) — 7 false positives.

AST solution: Interprocedural analysis using the project-wide symbol
table.  For each ALLOCATABLE variable, track all ALLOCATE and
DEALLOCATE calls across all files.  Allow the init/cleanup pattern
(allocate in ``init_*``, deallocate in ``cleanup_*``/``free_*``/
``dealloc_*``).  Only flag variables that are allocated but never
deallocated anywhere in the project.
"""

from __future__ import annotations

import re
from typing import Dict, List, Set, Tuple

from fparser.two.Fortran2003 import (
    Allocate_Stmt,
    Deallocate_Stmt,
    Name,
    Program,
    Type_Declaration_Stmt,
)
from fparser.two.utils import walk

from rules.base_rule import FortranRule, Violation
from rules.symbol_table import (
    ProjectSymbolTable,
    _get_line,
    _get_source_file_path,
    _node_to_str,
)


class ComDesignAlloc(FortranRule):
    """Check that allocated variables are deallocated."""

    rule_key = "COM.DESIGN.Alloc"
    severity = "CRITICAL"

    # Subroutine name patterns that indicate init/cleanup roles
    INIT_PATTERNS = [
        r"init",
        r"initialize",
        r"setup",
        r"set_up",
        r"alloc",
        r"create",
        r"read",
        r"load",
    ]

    CLEANUP_PATTERNS = [
        r"cleanup",
        r"clean_up",
        r"free",
        r"dealloc",
        r"destroy",
        r"finalize",
        r"finalise",
        r"close",
        r"release",
    ]

    def check(
        self,
        ast: Program,
        file_path: str,
        symbol_table: ProjectSymbolTable,
    ) -> List[Violation]:
        violations: List[Violation] = []

        # Get all ALLOCATE statements in this file
        for alloc_node in walk(ast, Allocate_Stmt):
            line = _get_line(alloc_node)
            var_names = self._extract_var_names(alloc_node)

            for var in var_names:
                base_var = var.split("%")[0].strip()
                if not base_var:
                    continue

                # Check if this variable is ever deallocated anywhere
                if not self._is_deallocated(base_var, symbol_table):
                    # Not deallocated anywhere — check if it's in an init
                    # pattern (which implies a separate cleanup will handle it)
                    scope_name = self._find_enclosing_scope(
                        alloc_node, ast, file_path
                    )

                    if self._is_init_pattern(scope_name):
                        # Allocated in an init_* subroutine — likely has a
                        # matching cleanup_* that deallocates.  Allow it.
                        continue

                    # Also allow if the variable is a module-level ALLOCATABLE
                    # that's deallocated in a different module procedure
                    if self._is_module_allocatable(
                        base_var, file_path, symbol_table
                    ):
                        continue

                    stmt_file_path = _get_source_file_path(alloc_node) or file_path
                    violations.append(
                        Violation(
                            rule_key=self.rule_key,
                            message=f"Variable '{base_var}' is allocated but "
                            f"never deallocated.",
                            file_path=stmt_file_path,
                            line=line if line else 0,
                            severity=self.severity,
                        )
                    )

        return violations

    def _is_deallocated(
        self, var_name: str, symbol_table: ProjectSymbolTable
    ) -> bool:
        """Check if a variable is deallocated anywhere in the project."""
        allocs = symbol_table.allocations.get(var_name, [])
        for scope, op, line, fpath in allocs:
            if op == "deallocate":
                return True
        # Also check case-insensitive
        for key, allocs in symbol_table.allocations.items():
            if key.lower() == var_name.lower():
                for scope, op, line, fpath in allocs:
                    if op == "deallocate":
                        return True
        return False

    def _is_init_pattern(self, scope_name: str) -> bool:
        """Check if a scope name matches an init pattern."""
        if not scope_name:
            return False
        name_lower = scope_name.lower()
        for pattern in self.INIT_PATTERNS:
            if re.search(pattern, name_lower):
                return True
        return False

    def _is_cleanup_pattern(self, scope_name: str) -> bool:
        """Check if a scope name matches a cleanup pattern."""
        if not scope_name:
            return False
        name_lower = scope_name.lower()
        for pattern in self.CLEANUP_PATTERNS:
            if re.search(pattern, name_lower):
                return True
        return False

    def _find_enclosing_scope(
        self, node, ast: Program, file_path: str
    ) -> str:
        """Find the name of the enclosing subprogram for a node."""
        from fparser.two.Fortran2003 import (
            Function_Stmt,
            Function_Subprogram,
            Main_Program,
            Program_Stmt,
            Subroutine_Stmt,
            Subroutine_Subprogram,
        )

        for sub_prog in walk(ast, Subroutine_Subprogram):
            if self._contains_node(sub_prog, node):
                for child in sub_prog.children:
                    if isinstance(child, Subroutine_Stmt):
                        for c in child.children:
                            if isinstance(c, Name):
                                return _node_to_str(c)
        for func_prog in walk(ast, Function_Subprogram):
            if self._contains_node(func_prog, node):
                for child in func_prog.children:
                    if isinstance(child, Function_Stmt):
                        for c in child.children:
                            if isinstance(c, Name):
                                return _node_to_str(c)
        for main_prog in walk(ast, Main_Program):
            if self._contains_node(main_prog, node):
                for child in main_prog.children:
                    if isinstance(child, Program_Stmt):
                        for c in child.children:
                            if isinstance(c, Name):
                                return _node_to_str(c)
        return ""

    @staticmethod
    def _contains_node(parent, target) -> bool:
        """Check if target is a descendant of parent (or parent itself)."""
        if parent is target:
            return True
        if hasattr(parent, "children"):
            for child in parent.children:
                if child is not None and ComDesignAlloc._contains_node(
                    child, target
                ):
                    return True
        return False

    def _is_module_allocatable(
        self,
        var_name: str,
        file_path: str,
        symbol_table: ProjectSymbolTable,
    ) -> bool:
        """Check if a variable is a module-level ALLOCATABLE.

        Module-level ALLOCATABLEs are typically managed by module
        procedures (init/cleanup), so we allow them if the module has
        any procedure with a cleanup-like name.
        """
        # Check all scopes in this file
        file_scopes = symbol_table.get_all_scopes_in_file(file_path)
        for scope in file_scopes:
            if scope.kind == "module":
                # Check if the variable is declared in this module
                sym = symbol_table.get_symbol(var_name, scope.name, file_path)
                if sym and sym.is_allocatable:
                    # Check if any procedure in the module has a cleanup name
                    for s in symbol_table.scopes.values():
                        if s.parent and s.parent.lower() == scope.name.lower():
                            if self._is_cleanup_pattern(s.name):
                                return True
                        # Also check exported procedures
                    # Check module exports for cleanup patterns
                    mod_info = symbol_table.modules.get(scope.name)
                    if mod_info:
                        for export_name in mod_info.exports:
                            if self._is_cleanup_pattern(export_name):
                                return True
        return False

    @staticmethod
    def _extract_var_names(node) -> List[str]:
        """Extract variable names from an Allocate_Stmt or Deallocate_Stmt.

        Only extracts the allocation target names (the first Name in
        each Allocation/Allocate_Object), not dimension specifiers or
        STAT variables.
        """
        var_names: List[str] = []
        for child in node.children:
            if child is None:
                continue
            s = type(child).__name__
            if "Allocation" in s or "Allocate_Object" in s:
                for alloc_item in child.children:
                    if alloc_item is None:
                        continue
                    names = walk(alloc_item, Name)
                    if names:
                        var_names.append(_node_to_str(names[0]))
        return var_names
