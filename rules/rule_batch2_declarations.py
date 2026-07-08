"""Batch 2: Declaration & type rules.

Rules that inspect Type_Declaration_Stmt, Derived_Type_Def, and related
nodes to check declaration correctness.

Rules implemented (15):
  - F90.INST.Intent           (INTENT attribute required for dummy args)
  - F90.DATA.Array            (array dummy args use DIMENSION(:))
  - F90.TYPE.Derivate         (type declarations in modules)
  - F77.TYPE.Basic            (only standard types)
  - F90.TYPE.Integer          (KIND parameter for integers)
  - F90.TYPE.Real             (KIND parameter for reals)
  - F90.DATA.Parameter        (PARAMETER with KIND)
  - F90.DATA.Constant         (constants in modules)
  - F90.DATA.ConstantFloat    (float literal format)
  - F77.DATA.Double           (double precision format)
  - F77.TYPE.Hollerith        (Hollerith notation)
  - EUM.INST.DoubleColon      (:: required)
  - EUM.INST.CharLen          (CHARACTER(LEN=n) not *n)
  - EUM.INST.OneVarPerLine    (one variable per ::)
  - EUM.TYPE.PrivateInType    (PRIVATE in TYPE)
"""

from __future__ import annotations

import re
from typing import List, Set, Tuple

from fparser.two.Fortran2003 import (
    Access_Spec,
    Attr_Spec,
    Attr_Spec_List,
    Component_Part,
    Data_Component_Def_Stmt,
    Derived_Type_Def,
    Derived_Type_Stmt,
    Dummy_Arg_List,
    Entity_Decl,
    Entity_Decl_List,
    Function_Stmt,
    Intrinsic_Type_Spec,
    Intent_Attr_Spec,
    Intent_Spec,
    Name,
    Private_Components_Stmt,
    Program,
    Specification_Part,
    Subroutine_Stmt,
    Type_Declaration_Stmt,
)
from fparser.two.utils import walk

from rules.base_rule import FortranRule, Violation
from rules.symbol_table import ProjectSymbolTable, _get_line, _get_source_file_path


# ---------------------------------------------------------------------------
# F90.INST.Intent — INTENT attribute for dummy arguments
# ---------------------------------------------------------------------------
class F90InstIntent(FortranRule):
    """An INTENT attribute shall be provided for each calling sequence argument."""

    rule_key = "F90.INST.Intent"
    severity = "MAJOR"

    def check(self, ast, file_path, symbol_table):
        violations = []

        # For each subroutine/function, get dummy args and check declarations
        # that are within this subprogram's scope only.
        for stmt in walk(ast, Subroutine_Stmt) + walk(ast, Function_Stmt):
            dummy_args = self._get_dummy_args(stmt)
            if not dummy_args:
                continue

            # Find the subprogram node (Main_Program0 / Subroutine_Subprogram
            # / Function_Subprogram / Module) that contains this stmt.
            subprogram = self._find_enclosing_subprogram(stmt)
            if subprogram is None:
                subprogram = ast  # fallback: search entire AST

            # Collect declarations within this subprogram's scope.
            # A dummy arg is flagged only if it is declared WITHOUT INTENT
            # within this subprogram.  If it is declared WITH INTENT, the
            # violation is suppressed (even if another subprogram declares
            # the same name without INTENT).
            declared_with_intent: Set[str] = set()
            declared_without_intent: Set[Tuple[str, object]] = []

            for tds in walk(subprogram, Type_Declaration_Stmt):
                declared_names = self._get_declared_names(tds)
                has_intent = self._has_intent(tds)
                if has_intent:
                    declared_with_intent.update(declared_names)
                else:
                    for name in declared_names:
                        if name in dummy_args:
                            declared_without_intent.append((name, tds))

            # Report violations for dummy args declared without INTENT,
            # but only if they are NOT also declared with INTENT in this scope.
            seen: Set[str] = set()
            for name, tds in declared_without_intent:
                if name in declared_with_intent:
                    continue  # declared with INTENT elsewhere in this scope
                if name in seen:
                    continue  # already reported
                seen.add(name)
                line = _get_line(tds)
                fp = _get_source_file_path(tds) or file_path
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message=f"An INTENT attribute shall be provided for dummy argument '{name}'.",
                    file_path=fp, line=line, severity=self.severity,
                ))

        return violations

    @staticmethod
    def _find_enclosing_subprogram(stmt):
        """Walk up the parent chain to find the enclosing subprogram node."""
        from fparser.two.Fortran2003 import (
            Subroutine_Subprogram,
            Function_Subprogram,
            Module,
            Main_Program0,
        )
        node = getattr(stmt, "parent", None)
        while node is not None:
            if isinstance(node, (Subroutine_Subprogram, Function_Subprogram, Module, Main_Program0)):
                return node
            node = getattr(node, "parent", None)
        return None

    @staticmethod
    def _get_dummy_args(stmt) -> Set[str]:
        """Extract dummy argument names from Subroutine_Stmt or Function_Stmt."""
        args = set()
        children = list(stmt.children)
        # Subroutine_Stmt: [name, Dummy_Arg_List, ...]
        # Function_Stmt: [prefix, name, Dummy_Arg_List, suffix]
        for child in children:
            if isinstance(child, Dummy_Arg_List):
                for arg in child.children:
                    if isinstance(arg, Name):
                        args.add(str(arg).strip().lower())
            elif isinstance(child, Name):
                # Function name — skip
                pass
        return args

    @staticmethod
    def _get_declared_names(tds: Type_Declaration_Stmt) -> Set[str]:
        """Get variable names from a Type_Declaration_Stmt.

        Uses ``walk()`` to find ``Name`` nodes inside ``Entity_Decl``
        nodes, which works regardless of whether the AST was produced
        by the f2003 or f2008 parser (they use different
        ``Entity_Decl_List`` classes).
        """
        names = set()
        for entity in walk(tds, Entity_Decl):
            for ec in walk(entity, Name):
                names.add(str(ec).strip().lower())
                break  # only first Name (the variable name)
        return names

    @staticmethod
    def _has_intent(tds: Type_Declaration_Stmt) -> bool:
        """Check if a Type_Declaration_Stmt has INTENT attribute.

        Uses string-based checking because the f2008 parser produces
        ``Attr_Spec_List`` from ``fparser.two.Fortran2008``, not
        ``fparser.two.Fortran2003``, so ``isinstance`` checks fail.
        """
        tds_str = str(tds).upper()
        # Match INTENT( as a word boundary to avoid false positives
        # from variable names containing 'INTENT'.
        return bool(re.search(r'\bINTENT\s*\(', tds_str))


# ---------------------------------------------------------------------------
# F90.DATA.Array — array dummy args use DIMENSION(:)
# ---------------------------------------------------------------------------
class F90DataArray(FortranRule):
    """Array dummy arguments shall use DIMENSION(:) not (*) or (n)."""

    rule_key = "F90.DATA.Array"
    severity = "MAJOR"

    def check(self, ast, file_path, symbol_table):
        violations = []

        for stmt in walk(ast, Subroutine_Stmt) + walk(ast, Function_Stmt):
            dummy_args = self._get_dummy_args(stmt)
            if not dummy_args:
                continue

            for tds in walk(ast, Type_Declaration_Stmt):
                self._check_array_dims(tds, dummy_args, file_path, violations, self)

        return violations

    @staticmethod
    def _get_dummy_args(stmt) -> Set[str]:
        args = set()
        for child in stmt.children:
            if isinstance(child, Dummy_Arg_List):
                for arg in child.children:
                    if isinstance(arg, Name):
                        args.add(str(arg).strip().lower())
        return args

    @staticmethod
    def _check_array_dims(tds, dummy_args, file_path, violations, rule):
        """Check array declarations for dummy args."""
        # Use walk() to find Entity_Decl nodes, which works regardless
        # of whether the AST was produced by the f2003 or f2008 parser.
        for entity in walk(tds, Entity_Decl):
            name_node = None
            for ec in walk(entity, Name):
                name_node = ec
                break
            if name_node and str(name_node).strip().lower() in dummy_args:
                # Check if this is an array declaration
                entity_str = str(entity)
                # Check for (*) — assumed-size array
                if re.search(r'\(\s*\*\s*\)', entity_str):
                    line = _get_line(tds)
                    fp = _get_source_file_path(tds) or file_path
                    violations.append(Violation(
                        rule_key=rule.rule_key,
                        message=f"Array dummy argument '{str(name_node).strip()}' shall use DIMENSION(:) instead of (*).",
                        file_path=fp, line=line, severity=rule.severity,
                    ))


# ---------------------------------------------------------------------------
# F90.TYPE.Derivate — type declarations in modules
# ---------------------------------------------------------------------------
class F90TypeDerivate(FortranRule):
    """Derived type definitions shall be placed in modules."""

    rule_key = "F90.TYPE.Derivate"
    severity = "MAJOR"

    def check(self, ast, file_path, symbol_table):
        violations = []
        # Check if there are derived type definitions outside modules
        # Walk the AST for Derived_Type_Def that are not inside a Module
        for node in walk(ast, Derived_Type_Def):
            # Check if parent is a Module by looking at the AST structure
            # fparser doesn't give us parent pointers, so we check if
            # the file contains a Module
            has_module = bool(walk(ast, type(ast).__mro__[1] if len(ast.children) > 0 else type(ast)))
            # Simpler: check if there's a Module_Stmt in the AST
            from fparser.two.Fortran2003 import Module_Stmt
            if not walk(ast, Module_Stmt):
                line = _get_line(node)
                fp = _get_source_file_path(node) or file_path
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message="Derived type definitions shall be placed in modules.",
                    file_path=fp, line=line, severity=self.severity,
                ))
        return violations


# ---------------------------------------------------------------------------
# F77.TYPE.Basic — only standard Fortran types
# ---------------------------------------------------------------------------
class F77TypeBasic(FortranRule):
    """Only standard Fortran types shall be used (no BYTE, etc.)."""

    rule_key = "F77.TYPE.Basic"
    severity = "MAJOR"

    _NONSTANDARD_TYPES = re.compile(
        r'(?i)\b(BYTE|INTEGER\*\d|REAL\*\d|COMPLEX\*\d|LOGICAL\*\d|'
        r'DOUBLE\s*COMPLEX|INTEGER\s*\*\s*\d|REAL\s*\*\s*\d)\b'
    )

    def check(self, ast, file_path, symbol_table):
        violations = []
        for node in walk(ast, Type_Declaration_Stmt):
            decl_str = str(node)
            match = self._NONSTANDARD_TYPES.search(decl_str)
            if match:
                line = _get_line(node)
                fp = _get_source_file_path(node) or file_path
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message=f"Non-standard type '{match.group()}' shall not be used. Use standard Fortran types.",
                    file_path=fp, line=line, severity=self.severity,
                ))
        return violations


# ---------------------------------------------------------------------------
# F90.TYPE.Integer / F90.TYPE.Real / F90.DATA.Parameter — KIND parameter
# ---------------------------------------------------------------------------
class F90TypeInteger(FortranRule):
    """KIND parameter for integers shall use globally defined constants."""

    rule_key = "F90.TYPE.Integer"
    severity = "MAJOR"

    _KIND_PATTERN = re.compile(r'(?i)INTEGER\s*\(\s*KIND\s*=\s*(\w+)\s*\)')
    _KIND_LITERAL = re.compile(r'(?i)INTEGER\s*\(\s*KIND\s*=\s*\d+\s*\)')

    def check(self, ast, file_path, symbol_table):
        violations = []
        for node in walk(ast, Type_Declaration_Stmt):
            decl_str = str(node)
            # Flag INTEGER(KIND=<number>) — should use a named constant
            if self._KIND_LITERAL.search(decl_str):
                line = _get_line(node)
                fp = _get_source_file_path(node) or file_path
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message="KIND parameter shall use globally defined constants, not literal values.",
                    file_path=fp, line=line, severity=self.severity,
                ))
        return violations


class F90TypeReal(FortranRule):
    """KIND parameter for reals shall use globally defined constants."""

    rule_key = "F90.TYPE.Real"
    severity = "MAJOR"

    _KIND_LITERAL = re.compile(r'(?i)REAL\s*\(\s*KIND\s*=\s*\d+\s*\)')

    def check(self, ast, file_path, symbol_table):
        violations = []
        for node in walk(ast, Type_Declaration_Stmt):
            decl_str = str(node)
            if self._KIND_LITERAL.search(decl_str):
                line = _get_line(node)
                fp = _get_source_file_path(node) or file_path
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message="KIND parameter shall use globally defined constants, not literal values.",
                    file_path=fp, line=line, severity=self.severity,
                ))
        return violations


class F90DataParameter(FortranRule):
    """PARAMETER constants with KIND shall use named constants."""

    rule_key = "F90.DATA.Parameter"
    severity = "MAJOR"

    def check(self, ast, file_path, symbol_table):
        violations = []
        for node in walk(ast, Type_Declaration_Stmt):
            decl_str = str(node)
            has_parameter = 'PARAMETER' in decl_str.upper()
            if has_parameter:
                # Check for KIND with literal number
                if re.search(r'(?i)(INTEGER|REAL|COMPLEX|LOGICAL)\s*\(\s*KIND\s*=\s*\d+\s*\)', decl_str):
                    line = _get_line(node)
                    fp = _get_source_file_path(node) or file_path
                    violations.append(Violation(
                        rule_key=self.rule_key,
                        message="KIND parameter shall use globally defined constants, not literal values.",
                        file_path=fp, line=line, severity=self.severity,
                    ))
        return violations


# ---------------------------------------------------------------------------
# F90.DATA.Constant — constants defined in modules
# ---------------------------------------------------------------------------
class F90DataConstant(FortranRule):
    """Magic numbers shall be defined as PARAMETER constants in modules."""

    rule_key = "F90.DATA.Constant"
    severity = "MAJOR"

    def check(self, ast, file_path, symbol_table):
        violations = []
        # Check if there are PARAMETER declarations outside modules
        from fparser.two.Fortran2003 import Module_Stmt
        has_module = bool(walk(ast, Module_Stmt))

        for node in walk(ast, Type_Declaration_Stmt):
            decl_str = str(node)
            if 'PARAMETER' in decl_str.upper() and not has_module:
                line = _get_line(node)
                fp = _get_source_file_path(node) or file_path
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message="Constants shall be defined with the PARAMETER attribute in modules.",
                    file_path=fp, line=line, severity=self.severity,
                ))
        return violations


# ---------------------------------------------------------------------------
# F90.DATA.ConstantFloat / F77.DATA.Double — float literal format
# ---------------------------------------------------------------------------
class F90DataConstantFloat(FortranRule):
    """Floating point literals shall have digits before and after the decimal point."""

    rule_key = "F90.DATA.ConstantFloat"
    severity = "MAJOR"

    # Match floats without digit before or after decimal point
    # e.g., .5 or 1. (but not 1.0 or 0.5)
    _BAD_FLOAT = re.compile(r'(?<![A-Za-z0-9_])\.\d+[dDeE]?')  # .5, .5D0
    _BAD_FLOAT2 = re.compile(r'\d+\.(?![dDeE0-9])')  # 1. (not 1.0, 1.D0)

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
            # Skip comment lines
            stripped = line.strip()
            if stripped.startswith('!') or stripped.startswith('c') or stripped.startswith('C'):
                continue
            # Check for bad float format
            if self._BAD_FLOAT.search(line) or self._BAD_FLOAT2.search(line):
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message="Floating Point literals shall have at least one digit before and after the decimal point.",
                    file_path=file_path, line=i, severity=self.severity,
                ))
        return violations


class F77DataDouble(FortranRule):
    """Double precision literals shall use proper format."""

    rule_key = "F77.DATA.Double"
    severity = "MAJOR"

    # D exponent is covered by EUM.INST.Redundant, but this rule also checks
    # for general double precision format issues
    _D_EXPONENT = re.compile(r'\d\.?\d*[dD][+-]?\d+')

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
            if self._D_EXPONENT.search(line):
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message="The D exponent letter for double precision shall not be used. Use E exponent instead.",
                    file_path=file_path, line=i, severity=self.severity,
                ))
        return violations


# ---------------------------------------------------------------------------
# F77.TYPE.Hollerith — Hollerith notation
# ---------------------------------------------------------------------------
class F77TypeHollerith(FortranRule):
    """Hollerith format notation shall not be used."""

    rule_key = "F77.TYPE.Hollerith"
    severity = "MAJOR"

    _HOLLERITH = re.compile(r'(?i)\b\d+H\b')

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
            if self._HOLLERITH.search(line):
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message="The Hollerith format notation shall not be used.",
                    file_path=file_path, line=i, severity=self.severity,
                ))
        return violations


# ---------------------------------------------------------------------------
# EUM.INST.DoubleColon — :: required in declarations
# ---------------------------------------------------------------------------
class EumInstDoubleColon(FortranRule):
    """Double colon (::) shall be used to declare a variable."""

    rule_key = "EUM.INST.DoubleColon"
    severity = "INFO"

    def check(self, ast, file_path, symbol_table):
        violations = []
        for node in walk(ast, Type_Declaration_Stmt):
            decl_str = str(node)
            # Check if :: is present
            if '::' not in decl_str:
                line = _get_line(node)
                fp = _get_source_file_path(node) or file_path
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message="Double colon (::) shall be used to declare a variable.",
                    file_path=fp, line=line, severity=self.severity,
                ))
        return violations


# ---------------------------------------------------------------------------
# EUM.INST.CharLen — CHARACTER(LEN=n) not *n
# ---------------------------------------------------------------------------
class EumInstCharLen(FortranRule):
    """Character string variables shall use the LEN=[number] attribute."""

    rule_key = "EUM.INST.CharLen"
    severity = "INFO"

    _CHAR_STAR = re.compile(r'(?i)CHARACTER\s*\*\s*(\d+|\(\s*\*\s*\))')

    def check(self, ast, file_path, symbol_table):
        violations = []
        for node in walk(ast, Type_Declaration_Stmt):
            decl_str = str(node)
            if self._CHAR_STAR.search(decl_str):
                line = _get_line(node)
                fp = _get_source_file_path(node) or file_path
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message="Character string variables shall use the LEN=[number] attribute.",
                    file_path=fp, line=line, severity=self.severity,
                ))
        return violations


# ---------------------------------------------------------------------------
# EUM.INST.OneVarPerLine — one variable per :: statement
# ---------------------------------------------------------------------------
class EumInstOneVarPerLine(FortranRule):
    """Only one variable shall be declared per source code statement."""

    rule_key = "EUM.INST.OneVarPerLine"
    severity = "INFO"

    def check(self, ast, file_path, symbol_table):
        violations = []
        for node in walk(ast, Type_Declaration_Stmt):
            # Count Entity_Decl nodes using walk(), which works
            # regardless of f2003/f2008 parser differences.
            entities = walk(node, Entity_Decl)
            count = len(entities)
            if count > 1:
                line = _get_line(node)
                fp = _get_source_file_path(node) or file_path
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message=f"Only one variable shall be declared per source code statement ({count} variables found).",
                    file_path=fp, line=line, severity=self.severity,
                ))
        return violations


# ---------------------------------------------------------------------------
# EUM.TYPE.PrivateInType — PRIVATE in TYPE definitions
# ---------------------------------------------------------------------------
class EumTypePrivateInType(FortranRule):
    """Abstract types shall always contain the PRIVATE statement."""

    rule_key = "EUM.TYPE.PrivateInType"
    severity = "INFO"

    def check(self, ast, file_path, symbol_table):
        violations = []
        for node in walk(ast, Derived_Type_Def):
            has_private = bool(walk(node, Private_Components_Stmt))
            if not has_private:
                line = _get_line(node)
                fp = _get_source_file_path(node) or file_path
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message="Abstract types shall always contain the PRIVATE statement.",
                    file_path=fp, line=line, severity=self.severity,
                ))
        return violations
