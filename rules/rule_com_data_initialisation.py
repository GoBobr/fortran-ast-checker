"""Rule 4: COM.DATA.Initialisation

Variables shall be initialized before they are used.

JFlex false positive cause: ``PARAMETER`` constants, ``INTENT(IN)``
dummy arguments, ``INTENT(OUT)`` outputs, and ``=>`` pointer assignments
are not recognized as initialization (179 false positives).

AST solution: for each scope, track which variables are initialized
(PARAMETER, INTENT(IN), =>, =, USE-imported) and only flag variables
that are read before any assignment in the current scope.
"""

from __future__ import annotations

import re
from typing import Dict, List, Set, Tuple

from fparser.two.Fortran2003 import (
    Actual_Arg_Spec,
    Assignment_Stmt,
    Call_Stmt,
    Data_Ref,
    Data_Stmt,
    Data_Implied_Do,
    Execution_Part,
    Function_Stmt,
    Function_Reference,
    Name,
    Pointer_Assignment_Stmt,
    Program,
    Program_Stmt,
    Subroutine_Stmt,
)
from fparser.two.utils import walk

from rules.base_rule import FortranRule, Violation
from rules.symbol_table import (
    FORTRAN_INTRINSICS,
    FORTRAN_KEYWORDS,
    ProjectSymbolTable,
    _get_line,
    _node_to_str,
)


class ComDataInitialisation(FortranRule):
    """Check that variables are initialized before use."""

    rule_key = "COM.DATA.Initialisation"
    severity = "MAJOR"

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

            # Build the set of initialized variables for this scope
            initialized: Set[str] = set()
            self._collect_initialized(scope, symbol_table, initialized)

            # Collect variables initialized via DATA statements (Fortran 77 style)
            self._collect_data_stmt_initialized(ast, scope.name, initialized)

            # Walk execution statements in order, tracking reads before writes
            violations.extend(
                self._check_data_flow(exec_part, scope, symbol_table, initialized, file_path)
            )

        return violations

    @staticmethod
    def _collect_data_stmt_initialized(
        ast: Program,
        scope_name: str,
        initialized: Set[str],
    ):
        """Collect variables initialized via DATA statements.

        Fortran 77 style: ``data a/2.871d-04, .../`` initializes variables
        before the execution part begins.  We walk Data_Stmt nodes within
        the scope's specification part and add the variable names.
        """
        from fparser.two.Fortran2003 import (
            Function_Subprogram,
            Main_Program,
            Module,
            Subroutine_Subprogram,
        )

        # Find the subprogram node for this scope
        subprogram = None
        for sub in walk(ast, Subroutine_Subprogram):
            for child in sub.children:
                if isinstance(child, Subroutine_Stmt):
                    for c in child.children:
                        if isinstance(c, Name) and _node_to_str(c) == scope_name:
                            subprogram = sub
                    break
            if subprogram:
                break

        if subprogram is None:
            for func in walk(ast, Function_Subprogram):
                for child in func.children:
                    if isinstance(child, Function_Stmt):
                        for c in child.children:
                            if isinstance(c, Name) and _node_to_str(c) == scope_name:
                                subprogram = func
                        break
                if subprogram:
                    break

        if subprogram is None:
            for main in walk(ast, Main_Program):
                for child in main.children:
                    if isinstance(child, Program_Stmt):
                        for c in child.children:
                            if isinstance(c, Name) and _node_to_str(c) == scope_name:
                                subprogram = main
                        break
                if subprogram:
                    break

        if subprogram is None:
            return

        # Walk Data_Stmt nodes in the subprogram (they appear in spec part)
        for data_stmt in walk(subprogram, Data_Stmt):
            # Data_Stmt children: ['DATA', Data_Stmt_Set_List]
            # Data_Stmt_Set_List contains Data_Stmt_Set nodes
            # Data_Stmt_Set children: [Data_Object_List, '/', Data_Value_List, '/']
            # Data_Object_List contains Name, Part_Ref, Data_Implied_Do, etc.
            for name_node in walk(data_stmt, Name):
                # Skip names inside Data_Implied_Do (loop variables)
                # and names that are values (after the '/')
                # Simple heuristic: collect all Name nodes that appear
                # before the first '/' in the Data_Stmt_Set
                initialized.add(_node_to_str(name_node).lower())

    def _collect_initialized(
        self,
        scope,
        symbol_table: ProjectSymbolTable,
        initialized: Set[str],
    ):
        """Collect all variables that are already initialized at scope entry."""
        resolved = symbol_table._resolve_scope_symbols(scope)

        for name, sym in resolved.items():
            if sym.is_parameter:
                initialized.add(name.lower())
            # INTENT(IN) and INTENT(INOUT) variables are initialized on entry
            if sym.intent in ("IN", "INOUT"):
                initialized.add(name.lower())
            if sym.initialized:
                initialized.add(name.lower())
            # USE-imported symbols are initialized
            if sym.scope != scope.name and sym.scope != "":
                initialized.add(name.lower())
            # Dummy arguments are initialized (passed in from caller)
            if sym.is_dummy:
                initialized.add(name.lower())
            # SAVE variables persist across calls; their state is preserved
            # and they are typically guarded by allocation/status checks
            if "SAVE" in sym.attributes:
                initialized.add(name.lower())
            # Variables of derived types with default-initialized components
            # are considered initialized (e.g., type with `integer :: x = 1`)
            if sym.type.startswith("TYPE("):
                type_name = sym.type[5:-1].strip() if sym.type.endswith(")") else sym.type[5:].strip()
                dt_components = symbol_table.get_derived_type_components(type_name)
                if dt_components:
                    for comp_sym in dt_components.values():
                        if comp_sym.initialized:
                            initialized.add(name.lower())
                            break

    def _check_data_flow(
        self,
        exec_part: Execution_Part,
        scope,
        symbol_table: ProjectSymbolTable,
        initialized: Set[str],
        file_path: str,
    ) -> List[Violation]:
        """Walk execution statements in order, tracking reads before writes.

        Instead of walking Name nodes (which lack line numbers), we walk
        statement-level nodes in source order. For each statement, we
        determine which variables are written (LHS) and which are read
        (RHS and other references). A variable that is read before any
        write is flagged.
        """
        violations: List[Violation] = []
        seen_violations: Set[str] = set()  # variable names already flagged

        from fparser.two.Fortran2003 import (
            Loop_Control,
            Nonlabel_Do_Stmt,
            Read_Stmt,
            Where_Stmt,
            Forall_Stmt,
        )

        # Collect all statement-level nodes with their line numbers
        # Each entry: (line, node, writes_set, reads_set)
        # We process them in line order

        stmt_nodes: List[Tuple[int, object]] = []

        # Assignment statements
        for node in walk(exec_part, Assignment_Stmt):
            line = _get_line(node)
            if line > 0:
                stmt_nodes.append((line, node))

        # Pointer assignments
        for node in walk(exec_part, Pointer_Assignment_Stmt):
            line = _get_line(node)
            if line > 0:
                stmt_nodes.append((line, node))

        # DO loop statements (loop variable is written)
        for node in walk(exec_part, Nonlabel_Do_Stmt):
            line = _get_line(node)
            if line > 0:
                stmt_nodes.append((line, node))

        # READ statements (variables in output list are written)
        for node in walk(exec_part, Read_Stmt):
            line = _get_line(node)
            if line > 0:
                stmt_nodes.append((line, node))

        # WRITE statements (internal writes to character variables)
        from fparser.two.Fortran2003 import Write_Stmt

        for node in walk(exec_part, Write_Stmt):
            line = _get_line(node)
            if line > 0:
                stmt_nodes.append((line, node))

        # CALL statements (arguments may be written by the called routine)
        for node in walk(exec_part, Call_Stmt):
            line = _get_line(node)
            if line > 0:
                stmt_nodes.append((line, node))

        # Sort by line number
        stmt_nodes.sort(key=lambda x: x[0])

        # Build a set of Name node IDs to skip (components, keyword args, proc names)
        skip_names = self._collect_skip_names(exec_part)

        # Process statements in order
        for line, node in stmt_nodes:
            # Determine which variables are written and read in this statement
            writes, reads = self._get_writes_reads(node, skip_names)

            # First, check reads: any read variable not in initialized is a violation
            for name in reads:
                name_lower = name.lower()

                if name_lower in initialized:
                    continue
                if name_lower in FORTRAN_KEYWORDS:
                    continue
                if name_lower in FORTRAN_INTRINSICS:
                    continue
                if name_lower in seen_violations:
                    continue
                # Skip if this variable is also written in this statement
                # (e.g., implied DO loop variable)
                if name_lower in writes:
                    continue

                # Check if it's declared
                sym = symbol_table.get_symbol(name, scope.name, file_path)
                if sym is None:
                    continue  # Handled by Declaration rule
                if sym.is_procedure:
                    continue
                if sym.intent == "OUT":
                    continue

                # Flag it
                seen_violations.add(name_lower)
                violations.append(
                    Violation(
                        rule_key=self.rule_key,
                        message=f"The variable '{name}' is used before being initialized.",
                        file_path=file_path,
                        line=line,
                        severity=self.severity,
                    )
                )

            # Then, mark writes as initialized
            for name in writes:
                initialized.add(name.lower())
                # Also mark base variable (before %)
                base = name.split("%")[0].strip()
                initialized.add(base.lower())

        return violations

    @staticmethod
    def _get_writes_reads(node, skip_names: Set[int]) -> Tuple[Set[str], Set[str]]:
        """Extract written and read variable names from a statement node.

        Returns (writes, reads) where each is a set of variable names.
        """
        writes: Set[str] = set()
        reads: Set[str] = set()

        from fparser.two.Fortran2003 import (
            Assignment_Stmt,
            Call_Stmt,
            Loop_Control,
            Nonlabel_Do_Stmt,
            Pointer_Assignment_Stmt,
            Read_Stmt,
            Write_Stmt,
        )

        if isinstance(node, Assignment_Stmt):
            # children: [LHS, =, RHS]
            children = list(node.children)
            if len(children) >= 3:
                lhs = children[0]
                rhs = children[2]
                # LHS writes
                for n in walk(lhs, Name):
                    if id(n) not in skip_names:
                        writes.add(_node_to_str(n))
                # Implied DO loop variables in RHS are writes (not reads)
                from fparser.two.Fortran2003 import Ac_Implied_Do_Control

                for ido in walk(rhs, Ac_Implied_Do_Control):
                    ido_names = walk(ido, Name)
                    if ido_names:
                        # First name is the loop variable — it's a write
                        writes.add(_node_to_str(ido_names[0]))
                # Collect Name node IDs that are arguments to non-intrinsic
                # function calls — these may be intent(out) and thus writes.
                # fparser parses function calls as Part_Ref (can't distinguish
                # from array access without declarations), so we handle both
                # Function_Reference and Part_Ref nodes.
                from fparser.two.Fortran2003 import Part_Ref, Section_Subscript_List

                func_arg_ids: Set[int] = set()
                # Function_Reference nodes
                for func_ref in walk(rhs, Function_Reference):
                    for arg_spec in walk(func_ref, Actual_Arg_Spec):
                        for n in walk(arg_spec, Name):
                            func_arg_ids.add(id(n))
                # Part_Ref nodes (may be function calls)
                for part_ref in walk(rhs, Part_Ref):
                    children = list(part_ref.children)
                    if len(children) >= 2 and isinstance(children[1], Section_Subscript_List):
                        func_name = _node_to_str(children[0]).lower()
                        # Skip if it's a known intrinsic (already handled)
                        if func_name not in FORTRAN_INTRINSICS:
                            for n in walk(children[1], Name):
                                func_arg_ids.add(id(n))
                for n in func_arg_ids:
                    writes.add(_node_to_str(n))
                # RHS reads (skip implied DO loop variables and func args)
                implied_do_vars = set()
                for ido in walk(rhs, Ac_Implied_Do_Control):
                    ido_names = walk(ido, Name)
                    if ido_names:
                        implied_do_vars.add(id(ido_names[0]))
                for n in walk(rhs, Name):
                    if id(n) not in skip_names and id(n) not in implied_do_vars and id(n) not in func_arg_ids:
                        reads.add(_node_to_str(n))

        elif isinstance(node, Pointer_Assignment_Stmt):
            children = list(node.children)
            if len(children) >= 3:
                lhs = children[0]
                rhs = children[2]
                for n in walk(lhs, Name):
                    if id(n) not in skip_names:
                        writes.add(_node_to_str(n))
                for n in walk(rhs, Name):
                    if id(n) not in skip_names:
                        reads.add(_node_to_str(n))

        elif isinstance(node, Nonlabel_Do_Stmt):
            # DO var = start, end [, step]
            # var is written, start/end/step are read
            lc = None
            for child in node.children:
                if isinstance(child, Loop_Control):
                    lc = child
                    break
            if lc is not None:
                names = walk(lc, Name)
                if names:
                    # First name is the loop variable (written)
                    writes.add(_node_to_str(names[0]))
                    # Rest are reads
                    for n in names[1:]:
                        if id(n) not in skip_names:
                            reads.add(_node_to_str(n))

        elif isinstance(node, Read_Stmt):
            # READ(unit, *) var1, var2, ...
            # All variables in the output list are written
            # But unit number and format are read
            # Simple heuristic: all Names are writes (conservative)
            for n in walk(node, Name):
                if id(n) not in skip_names:
                    writes.add(_node_to_str(n))

        elif isinstance(node, Write_Stmt):
            # WRITE(unit, *) var1, var2, ...
            # For internal writes (WRITE(char_var, *) ...), char_var is written
            # For external writes, all variables are reads
            # Conservative: treat first Name as write (internal write target)
            names = walk(node, Name)
            if names:
                first = _node_to_str(names[0])
                if first.lower() not in FORTRAN_KEYWORDS:
                    writes.add(first)
                # Rest are reads
                for n in names[1:]:
                    if id(n) not in skip_names:
                        reads.add(_node_to_str(n))

        elif isinstance(node, Call_Stmt):
            # CALL sub(arg1, arg2, ...)
            # Arguments may be written by the called routine
            # For initialization purposes, treat all arguments as writes
            # (conservative — avoids false positives)
            for n in walk(node, Name):
                if id(n) not in skip_names:
                    name = _node_to_str(n)
                    if name.lower() not in FORTRAN_KEYWORDS:
                        writes.add(name)

        return writes, reads

    @staticmethod
    def _extract_variable_name(node) -> str:
        """Extract the base variable name from an LHS expression."""
        # Could be a simple Name, or a Part_Ref (array access), or a Structure_Constructor
        if isinstance(node, Name):
            return _node_to_str(node)
        # For Part_Ref (array access like a(i)), get the first Name
        for child in walk(node, Name):
            return _node_to_str(child)
        s = _node_to_str(node)
        # Extract first identifier
        m = re.match(r"\s*(\w+)", s)
        if m:
            return m.group(1)
        return ""

    @staticmethod
    def _collect_skip_names(exec_part: Execution_Part) -> Set[int]:
        """Collect Name node IDs that should be skipped.

        This includes:
        - Derived type component names (after % in Data_Ref)
        - Keyword argument names (first child of Actual_Arg_Spec)
        - Subroutine names in Call_Stmt
        - Function names in Function_Reference
        - Implied DO loop variables (in Ac_Implied_Do_Control)
        """
        from fparser.two.Fortran2003 import Ac_Implied_Do_Control

        skip: Set[int] = set()

        # 1. Skip component names in Data_Ref (a%b%c — skip b and c)
        for data_ref in walk(exec_part, Data_Ref):
            names = walk(data_ref, Name)
            if names:
                # First name is the base variable — keep it
                # Rest are components — skip them
                for n in names[1:]:
                    skip.add(id(n))

        # 2. Skip keyword argument names in Actual_Arg_Spec (keyword=value)
        for arg_spec in walk(exec_part, Actual_Arg_Spec):
            children = list(arg_spec.children)
            if children and isinstance(children[0], Name):
                skip.add(id(children[0]))

        # 3. Skip subroutine names in Call_Stmt
        for call_stmt in walk(exec_part, Call_Stmt):
            for child in call_stmt.children:
                if isinstance(child, Name):
                    skip.add(id(child))
                    break

        # 4. Skip function names in Function_Reference
        for func_ref in walk(exec_part, Function_Reference):
            children = list(func_ref.children)
            if children and isinstance(children[0], Name):
                skip.add(id(children[0]))

        # 5. Skip implied DO loop variables (/(i, i=1,n)/)
        for implied_do in walk(exec_part, Ac_Implied_Do_Control):
            names = walk(implied_do, Name)
            if names:
                # First name is the loop variable — skip it
                skip.add(id(names[0]))

        return skip

    @staticmethod
    def _is_lhs_of_assignment(name_node, exec_part) -> bool:
        """Check if a Name node is on the LHS of an assignment statement."""
        # Walk up the tree is not possible in fparser, so we check all assignments
        for assign in walk(exec_part, Assignment_Stmt):
            if assign.children:
                lhs = assign.children[0]
                # Check if name_node is in the LHS
                if name_node in walk(lhs, Name):
                    # But we need to make sure it's the base variable, not an index
                    # If the name is directly the LHS (not inside parentheses), it's a write
                    if isinstance(lhs, Name) and _node_to_str(lhs) == _node_to_str(name_node):
                        return True
                    # For array access a(i) = ..., 'a' is being written
                    from fparser.two.Fortran2003 import Part_Ref

                    if isinstance(lhs, Part_Ref):
                        for n in walk(lhs, Name):
                            if _node_to_str(n) == _node_to_str(name_node):
                                # Check if it's the first child (the array name)
                                if lhs.children and lhs.children[0] is n:
                                    return True
        # Check pointer assignments
        for ptr_assign in walk(exec_part, Pointer_Assignment_Stmt):
            if ptr_assign.children:
                lhs = ptr_assign.children[0]
                if name_node in walk(lhs, Name):
                    if isinstance(lhs, Name) and _node_to_str(lhs) == _node_to_str(name_node):
                        return True
        return False

    @staticmethod
    def _is_call_argument(name_node, exec_part) -> bool:
        """Check if a Name node is an argument to a CALL statement."""
        for call in walk(exec_part, Call_Stmt):
            if name_node in walk(call, Name):
                return True
        return False

    @staticmethod
    def _find_execution_part(ast: Program, scope_name: str):
        """Find the Execution_Part for a given scope name."""
        from fparser.two.Fortran2003 import (
            Function_Subprogram,
            Main_Program,
            Module,
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
