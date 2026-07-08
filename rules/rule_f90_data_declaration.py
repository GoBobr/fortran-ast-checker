"""Rule 1: F90.DATA.Declaration

All variables shall be explicitly declared.  The statement ``IMPLICIT
NONE`` is mandatory at the beginning of each module and program.

JFlex false positive cause: variables imported via ``USE`` from other
modules are flagged as undeclared (561 false positives).

AST solution: walk ``USE`` statements, resolve imported symbols from
module files via the project-wide symbol table, and only flag
identifiers that are truly undeclared (not local, not USE-imported, not
an intrinsic, not a dummy argument).
"""

from __future__ import annotations

import re
from typing import List, Set

from fparser.two.Fortran2003 import (
    Actual_Arg_Spec,
    Assignment_Stmt,
    Associate_Stmt,
    Association,
    Association_List,
    Call_Stmt,
    Component_Spec,
    Cycle_Stmt,
    Data_Pointer_Object,
    Data_Ref,
    End_Do_Stmt,
    End_If_Stmt,
    End_Select_Stmt,
    Execution_Part,
    Exit_Stmt,
    Function_Stmt,
    Function_Reference,
    If_Stmt,
    Name,
    Part_Ref,
    Proc_Component_Ref,
    Procedure_Designator,
    Program,
    Program_Stmt,
    Subroutine_Stmt,
    Type_Name,
)
from fparser.two.utils import walk

from rules.base_rule import FortranRule, Violation
from rules.symbol_table import (
    FORTRAN_INTRINSICS,
    FORTRAN_KEYWORDS,
    ProjectSymbolTable,
    _get_line,
    _get_source_file_path,
    _node_to_str,
)


class F90DataDeclaration(FortranRule):
    """Check that all variables are declared (IMPLICIT NONE compliance)."""

    rule_key = "F90.DATA.Declaration"
    severity = "MAJOR"

    def check(
        self,
        ast: Program,
        file_path: str,
        symbol_table: ProjectSymbolTable,
    ) -> List[Violation]:
        violations: List[Violation] = []

        # Get all scopes in this file
        file_scopes = symbol_table.get_all_scopes_in_file(file_path)
        if not file_scopes:
            return violations

        # For each scope, check IMPLICIT NONE and undeclared variables
        for scope in file_scopes:
            # Check IMPLICIT NONE — contained procedures inherit it from parent module
            if not scope.has_implicit_none:
                # Check if parent module has implicit none
                parent_has_in = False
                if scope.parent:
                    parent_scope = symbol_table.get_scope(scope.parent)
                    if parent_scope and parent_scope.has_implicit_none:
                        parent_has_in = True

                if not parent_has_in:
                    # Find the line of the scope's declaration statement
                    line = self._find_scope_line(ast, scope.name)
                    scope_file_path = _get_source_file_path(
                        self._find_scope_node(ast, scope.name)
                    ) or file_path
                    violations.append(
                        Violation(
                            rule_key=self.rule_key,
                            message=f"IMPLICIT NONE is mandatory in {scope.kind} '{scope.name}'.",
                            file_path=scope_file_path,
                            line=line,
                            severity=self.severity,
                        )
                    )

            # Find undeclared variables in executable code
            exec_part = self._find_execution_part(ast, scope.name)
            if exec_part is None:
                continue

            # Build a set of Name node IDs to skip (components, keyword args, proc names)
            # and a set of variable names introduced by ASSOCIATE blocks
            skip_names, associate_names = self._collect_skip_names(exec_part)

            # Collect all Name nodes in the execution part
            # Name nodes don't have line numbers in fparser, so we track
            # the nearest enclosing statement node's line number.
            seen_names: Set[str] = set()
            for name_node, line in self._walk_names_with_lines(exec_part):
                # Skip if this Name is in the skip set
                if id(name_node) in skip_names:
                    continue

                name = _node_to_str(name_node)
                if not name:
                    continue
                name_lower = name.lower()

                # Skip if already checked
                if name_lower in seen_names:
                    continue
                seen_names.add(name_lower)

                # Skip Fortran keywords
                if name_lower in FORTRAN_KEYWORDS:
                    continue

                # Skip intrinsics
                if name_lower in FORTRAN_INTRINSICS:
                    continue

                # Skip ASSOCIATE block variables (introduced via `associate (var => expr)`)
                if name_lower in associate_names:
                    continue

                # Skip numeric literals (shouldn't be Name nodes, but just in case)
                if re.match(r"^\d", name):
                    continue

                # Skip names that contain % (derived type refs handled by skip set)
                if "%" in name:
                    continue

                # Check if declared
                if symbol_table.is_declared(name, scope.name, file_path):
                    continue

                # Not declared — flag it
                # Use the real source file for the enclosing statement (handles INCLUDE)
                name_file_path = _get_source_file_path(name_node) or file_path
                violations.append(
                    Violation(
                        rule_key=self.rule_key,
                        message=f"The variable '{name}' must be declared.",
                        file_path=name_file_path,
                        line=line,
                        severity=self.severity,
                    )
                )

        return violations

    @staticmethod
    def _walk_names_with_lines(root):
        """Walk Name nodes, yielding (node, line) pairs.

        Since Name nodes don't have line numbers in fparser, we track
        the nearest enclosing statement node that does have a line.
        """
        stack = [(_get_line(root), root)]
        while stack:
            current_line, node = stack.pop()
            if node is None:
                continue
            node_line = _get_line(node)
            if node_line != 0:
                current_line = node_line
            if isinstance(node, Name):
                yield (node, current_line)
            if hasattr(node, "children"):
                for child in reversed(node.children):
                    if child is not None:
                        stack.append((current_line, child))

    @staticmethod
    def _collect_skip_names(exec_part: Execution_Part) -> tuple[Set[int], Set[str]]:
        """Collect Name node IDs and variable names that should be skipped.

        Returns a tuple of (skip_ids, associate_names).

        skip_ids includes:
        - Derived type component names (after % in Data_Ref)
        - Keyword argument names (first child of Actual_Arg_Spec)
        - Subroutine names in Call_Stmt
        - Function names in Function_Reference

        associate_names includes:
        - Variable names introduced by ASSOCIATE blocks (checked by name, not by node ID,
          because different Name nodes refer to the same variable)
        """
        skip: Set[int] = set()
        associate_names: Set[str] = set()

        # 1. Skip component names in Data_Ref (a%b%c — skip b and c)
        for data_ref in walk(exec_part, Data_Ref):
            names = walk(data_ref, Name)
            if names:
                # First name is the base variable — keep it
                # Rest are components — skip them
                for n in names[1:]:
                    skip.add(id(n))

        # 1b. Skip type-bound procedure names in Procedure_Designator (obj%method)
        for proc_desig in walk(exec_part, Procedure_Designator):
            names = walk(proc_desig, Name)
            if names:
                # First name is the base variable — keep it
                # Second name is the method — skip it
                for n in names[1:]:
                    skip.add(id(n))

        # 1c. Skip component names in Proc_Component_Ref (compare(obj%comp, ...))
        # Proc_Component_Ref has children [Name(base), '%', Name(component)]
        for pcr in walk(exec_part, Proc_Component_Ref):
            names = walk(pcr, Name)
            if names:
                # First name is the base variable — keep it
                # Rest are components — skip them
                for n in names[1:]:
                    skip.add(id(n))

        # 1d. Skip Type_Name in Structure_Constructor (compare(...) parsed as
        # Structure_Constructor with Type_Name 'compare')
        for tn in walk(exec_part, Type_Name):
            skip.add(id(tn))

        # 1e. Skip component names in Data_Pointer_Object (tlc%comp => ...)
        # Data_Pointer_Object has children [Name(base), '%', Name(component)]
        for dpo in walk(exec_part, Data_Pointer_Object):
            names = walk(dpo, Name)
            if names:
                # First name is the base variable — keep it
                # Rest are components — skip them
                for n in names[1:]:
                    skip.add(id(n))

        # 2. Skip keyword argument names in Actual_Arg_Spec (keyword=value)
        for arg_spec in walk(exec_part, Actual_Arg_Spec):
            # Actual_Arg_Spec children: [Name(keyword), '=', expr]
            children = list(arg_spec.children)
            if children and isinstance(children[0], Name):
                skip.add(id(children[0]))

        # 2b. Skip keyword argument names in Component_Spec (keyword=value)
        # fparser parses derived-type constructors like nf90_create(cmode=...)
        # as Structure_Constructor with Component_Spec children instead of
        # Actual_Arg_Spec.
        for comp_spec in walk(exec_part, Component_Spec):
            children = list(comp_spec.children)
            if children and isinstance(children[0], Name):
                skip.add(id(children[0]))

        # 3. Skip subroutine names in Call_Stmt
        for call_stmt in walk(exec_part, Call_Stmt):
            # Call_Stmt children: [CALL, Name(subroutine_name), ...]
            for child in call_stmt.children:
                if isinstance(child, Name):
                    skip.add(id(child))
                    break

        # 4. Skip function names in Function_Reference
        for func_ref in walk(exec_part, Function_Reference):
            # Function_Reference children: [Name(function_name), Actual_Arg_Spec_List]
            children = list(func_ref.children)
            if children and isinstance(children[0], Name):
                skip.add(id(children[0]))

        # 5. Skip variable names introduced by ASSOCIATE blocks
        #    associate (var => expr, ...) — var is the first child of each Association
        #    We collect both the node ID (for the Name in the Associate_Stmt)
        #    and the name string (for Name nodes used in the body that refer to
        #    the same associated variable)
        for assoc_stmt in walk(exec_part, Associate_Stmt):
            for child in assoc_stmt.children:
                if isinstance(child, Association_List):
                    for assoc in child.children:
                        if isinstance(assoc, Association):
                            # Association children: [Name(assoc_var), '=>', expr]
                            if assoc.children and isinstance(assoc.children[0], Name):
                                skip.add(id(assoc.children[0]))
                                assoc_name = _node_to_str(assoc.children[0])
                                if assoc_name:
                                    associate_names.add(assoc_name.lower())

        # 6. Skip construct names (named DO/IF/SELECT labels)
        #    e.g. 'innerloop: DO ... EXIT innerloop ... END DO innerloop'
        #    The construct name appears as a Name node in EXIT, CYCLE,
        #    and END statements. These are not variables.
        for stmt_cls in (Exit_Stmt, Cycle_Stmt, End_Do_Stmt, End_If_Stmt, End_Select_Stmt):
            for stmt in walk(exec_part, stmt_cls):
                children = list(stmt.children)
                if len(children) > 1 and isinstance(children[1], Name):
                    skip.add(id(children[1]))
                    construct_name = _node_to_str(children[1])
                    if construct_name:
                        associate_names.add(construct_name.lower())

        return skip, associate_names

    @staticmethod
    def _find_execution_part(ast: Program, scope_name: str):
        """Find the Execution_Part for a given scope name."""
        from fparser.two.Fortran2003 import (
            Function_Subprogram,
            Main_Program,
            Module,
            Subroutine_Subprogram,
        )

        # Check subroutines
        for sub in walk(ast, Subroutine_Subprogram):
            for child in sub.children:
                if isinstance(child, Subroutine_Stmt):
                    for c in child.children:
                        if isinstance(c, Name) and _node_to_str(c) == scope_name:
                            # Found the right subroutine — return its Execution_Part
                            for c2 in sub.children:
                                if isinstance(c2, Execution_Part):
                                    return c2
                    break

        # Check functions
        for func in walk(ast, Function_Subprogram):
            for child in func.children:
                if isinstance(child, Function_Stmt):
                    for c in child.children:
                        if isinstance(c, Name) and _node_to_str(c) == scope_name:
                            for c2 in func.children:
                                if isinstance(c2, Execution_Part):
                                    return c2
                    break

        # Check main program
        for main in walk(ast, Main_Program):
            for child in main.children:
                if isinstance(child, Program_Stmt):
                    for c in child.children:
                        if isinstance(c, Name) and _node_to_str(c) == scope_name:
                            for c2 in main.children:
                                if isinstance(c2, Execution_Part):
                                    return c2
                    break

        # Check module-level execution (modules don't have Execution_Part,
        # but their contained procedures do — already checked above)
        return None

    @staticmethod
    def _find_scope_line(ast: Program, scope_name: str) -> int:
        """Find the line number of a scope's declaration statement."""
        from fparser.two.Fortran2003 import (
            Function_Stmt,
            Module_Stmt,
            Program_Stmt,
            Subroutine_Stmt,
        )

        for node in walk(ast, (Subroutine_Stmt, Function_Stmt, Program_Stmt, Module_Stmt)):
            for child in node.children:
                if isinstance(child, Name) and _node_to_str(child) == scope_name:
                    return _get_line(node)
        return 1

    @staticmethod
    def _find_scope_node(ast: Program, scope_name: str):
        """Find the AST node of a scope's declaration statement."""
        from fparser.two.Fortran2003 import (
            Function_Stmt,
            Module_Stmt,
            Program_Stmt,
            Subroutine_Stmt,
        )

        for node in walk(ast, (Subroutine_Stmt, Function_Stmt, Program_Stmt, Module_Stmt)):
            for child in node.children:
                if isinstance(child, Name) and _node_to_str(child) == scope_name:
                    return node
        return None
