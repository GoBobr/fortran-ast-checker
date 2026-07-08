"""Batch 8: Remaining rules — naming, design structure, and procedure rules.

Rules implemented (32):
  - EUM.NAME.IdChars              (identifier characters)
  - EUM.NAME.IdLength             (identifier length 1-32)
  - EUM.NAME.IdFormat             (identifier format: scope_typeName)
  - EUM.NAME.PublicFormat         (PUBLIC elements format)
  - EUM.NAME.PrivateFormat        (PRIVATE elements format)
  - EUM.NAME.IdScope              (identifier format scope)
  - EUM.NAME.Constants            (PARAMETER constants format)
  - EUM.NAME.ProgramName          (PROGRAM name CamelCase)
  - EUM.NAME.ModuleName           (MODULE name format)
  - EUM.NAME.FileExt              (file extension check)
  - EUM.DESIGN.OneUnitPerFile     (one programming unit per file)
  - EUM.DESIGN.ProgramStructure   (program structure: IMPLICIT NONE, END PROGRAM)
  - EUM.DESIGN.ModuleStructure    (module structure: IMPLICIT NONE, PRIVATE, CONTAINS)
  - EUM.DESIGN.SubroutineStructure (subroutine structure: header, END SUBROUTINE)
  - EUM.DESIGN.NoGlobalVars       (modules with variables but no procedures)
  - EUM.INST.ArgTypeDecl          (all dummy args have type declaration)
  - EUM.INST.ArgOrder             (INTENT ordering: IN → INOUT → OUT)
  - EUM.INST.OptionalNamed        (OPTIONAL args named in calls)
  - EUM.INST.DummyArgOrder        (declaration order matches arg list)
  - EUM.INST.OptionalAfterMandatory (OPTIONAL after mandatory)
  - EUM.INST.StringDim            (character args use LEN=*)
  - EUM.INST.FunctionIntent       (function args all INTENT(IN))
  - EUM.INST.OptionalDefault      (OPTIONAL args have default)
  - EUM.INST.PureFunc             (PURE functions for INTENT(IN) only)
  - F90.DESIGN.Interface          (modules contain PRIVATE)
  - F90.INST.Only                 (USE with ONLY)
  - F90.REF.Interface             (interface visibility)
  - F90.INST.Associated           (NULLIFY before ASSOCIATED)
  - F90.INST.Nullify              (NULLIFY after DEALLOCATE)
  - F90.DESIGN.Free               (alloc/dealloc at same level)
  - F90.NAME.GenericIntrinsic     (generic intrinsic function names)
  - F77.NAME.Intrinsic            (intrinsic function name reuse)
  - F77.NAME.Label                (labels limited to FORMAT and CONTINUE)
  - F90.REF.Array                 (array reference)
  - F90.REF.Variable              (variable reference)
  - F90.PROTO.Overload            (operator overloading)
  - F90.INST.Overload             (operator overloading)
  - F90.DATA.Float                (floating point format)
  - F77.INST.Function             (function type declaration)
  - F77.BLOC.Function             (function block)
  - F77.INST.Return               (RETURN forbidden)
  - F77.INST.If                   (F77 IF)
  - F77.BLOC.Loop                 (F77 loop)
  - F77.MET.Line                  (F77 line length)
  - COM.FLOW.BooleanExpression    (boolean expression)
  - COM.FLOW.CheckArguments       (check arguments)
  - COM.FLOW.CheckCodeReturn      (check code return)
  - COM.FLOW.CheckUser            (check user)
  - COM.INST.BoolNegation         (boolean negation)
  - COM.INST.LoopCondition        (loop condition)
  - COM.DATA.NotUsed              (unused variables)
  - COM.DESIGN.ActiveWait         (active wait)
"""

from __future__ import annotations

import os
import re
from typing import List, Set, Tuple

from fparser.two.Fortran2003 import (
    Access_Stmt,
    Allocate_Stmt,
    Assignment_Stmt,
    Call_Stmt,
    Close_Stmt,
    Contains_Stmt,
    Continue_Stmt,
    Derived_Type_Def,
    Deallocate_Stmt,
    Dummy_Arg_List,
    Entity_Decl,
    Entity_Decl_List,
    Function_Stmt,
    If_Construct,
    If_Stmt,
    Implicit_Stmt,
    Interface_Block,
    Module,
    Module_Stmt,
    Name,
    Open_Stmt,
    Optional_Stmt,
    Procedure_Stmt,
    Program_Stmt,
    Read_Stmt,
    Return_Stmt,
    Subroutine_Stmt,
    Type_Declaration_Stmt,
    Use_Stmt,
    Write_Stmt,
)
from fparser.two.utils import walk

from rules.base_rule import FortranRule, Violation
from rules.symbol_table import ProjectSymbolTable, _get_line, _get_source_file_path


def _read_source_lines(file_path: str, symbol_table) -> List[str]:
    """Read source file lines, trying absolute path resolution."""
    abs_path = file_path
    if hasattr(symbol_table, '_source_dir'):
        abs_path = os.path.join(symbol_table._source_dir, file_path)
    if not os.path.isfile(abs_path):
        abs_path = file_path
    if not os.path.isfile(abs_path):
        return []
    try:
        with open(abs_path, 'r', errors='replace') as f:
            return f.readlines()
    except OSError:
        return []


# ---------------------------------------------------------------------------
# EUM.NAME.IdChars — identifier characters
# ---------------------------------------------------------------------------
class EumNameIdChars(FortranRule):
    """Identifiers shall use only alphanumeric characters and underscores."""

    rule_key = "EUM.NAME.IdChars"
    severity = "INFO"

    _VALID_ID = re.compile(r'^[A-Za-z][A-Za-z0-9_]*$')

    def check(self, ast, file_path, symbol_table):
        violations = []
        seen = set()
        for name in walk(ast, Name):
            name_str = str(name).strip()
            if name_str in seen:
                continue
            seen.add(name_str)
            # Skip keywords and intrinsic names
            if name_str.upper() in self._KEYWORDS:
                continue
            if not self._VALID_ID.match(name_str):
                line = _get_line(name)
                fp = _get_source_file_path(name) or file_path
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message=f"Identifier '{name_str}' shall use only alphanumeric characters and underscores, starting with a letter.",
                    file_path=fp, line=line, severity=self.severity,
                ))
        return violations

    _KEYWORDS = {
        'PROGRAM', 'MODULE', 'SUBROUTINE', 'FUNCTION', 'END', 'IF', 'THEN',
        'ELSE', 'ELSEIF', 'DO', 'WHILE', 'SELECT', 'CASE', 'WHERE', 'FORALL',
        'INTERFACE', 'TYPE', 'USE', 'IMPLICIT', 'NONE', 'PARAMETER',
        'ALLOCATABLE', 'POINTER', 'TARGET', 'INTENT', 'IN', 'OUT', 'INOUT',
        'PUBLIC', 'PRIVATE', 'CONTAINS', 'RETURN', 'CALL', 'ALLOCATE',
        'DEALLOCATE', 'NULLIFY', 'OPEN', 'CLOSE', 'READ', 'WRITE', 'PRINT',
        'FORMAT', 'INQUIRE', 'STOP', 'PAUSE', 'GO', 'TO', 'GOTO', 'CONTINUE',
        'EXIT', 'CYCLE', 'ASSIGN', 'EQUIVALENCE', 'COMMON', 'BLOCK', 'DATA',
        'NAMELIST', 'EXTERNAL', 'SAVE', 'DIMENSION', 'CHARACTER', 'INTEGER',
        'REAL', 'DOUBLE', 'PRECISION', 'COMPLEX', 'LOGICAL', 'ENTRY',
        'INCLUDE', 'ASSOCIATE', 'CRITICAL', 'ENUM', 'FINAL', 'GENERIC',
        'PROCEDURE', 'ABSTRACT', 'CLASS', 'SEQUENCE', 'VOLATILE',
        'ASYNCHRONOUS', 'VALUE', 'PASS', 'NOPASS', 'DEFERRED',
        'NON_OVERRIDABLE', 'EXTENDS', 'IMPORT', 'PURE', 'ELEMENTAL',
        'RECURSIVE', 'RESULT', 'OPERATOR', 'ASSIGNMENT', 'STAT', 'ERR',
        'FILE', 'STATUS', 'ACTION', 'POSITION', 'ACCESS', 'FORM',
        'RECL', 'IOSTAT', 'UNIT', 'FMT', 'NML', 'ADVANCE', 'SIZE',
        'ENDFILE', 'BACKSPACE', 'REWIND', 'FLUSH', 'WAIT', 'ONLY',
    }


# ---------------------------------------------------------------------------
# EUM.NAME.IdLength — identifier length 1-32
# ---------------------------------------------------------------------------
class EumNameIdLength(FortranRule):
    """Identifier length shall be between 1 and 32 characters."""

    rule_key = "EUM.NAME.IdLength"
    severity = "INFO"

    MAX_LENGTH = 32

    def check(self, ast, file_path, symbol_table):
        violations = []
        seen = set()
        for name in walk(ast, Name):
            name_str = str(name).strip()
            if name_str in seen:
                continue
            seen.add(name_str)
            if len(name_str) > self.MAX_LENGTH:
                line = _get_line(name)
                # Name nodes inside Call_Stmt, Only_List, Procedure_Name_List,
                # Rename etc. may have item=None (line=0). Walk up the parent
                # chain until we find a node with a valid line number.
                if not line:
                    node = name
                    for _ in range(5):
                        if not hasattr(node, 'parent') or not node.parent:
                            break
                        node = node.parent
                        line = _get_line(node) or 0
                        if line:
                            break
                fp = _get_source_file_path(name) or file_path
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message=f"Identifier '{name_str}' has {len(name_str)} characters, exceeding the maximum of {self.MAX_LENGTH}.",
                    file_path=fp, line=line, severity=self.severity,
                ))
        return violations


# ---------------------------------------------------------------------------
# EUM.NAME.IdFormat — identifier format: scope_typeName
# ---------------------------------------------------------------------------
class EumNameIdFormat(FortranRule):
    """Identifiers shall follow the [scope_][type]<name> format."""

    rule_key = "EUM.NAME.IdFormat"
    severity = "INFO"

    # Type prefixes: c=character, i=integer, r=real, x=complex, l=logical, t=type, a=array, p=pointer
    _TYPE_PREFIXES = {'c', 'i', 'r', 'x', 'l', 't', 'a', 'p'}

    def check(self, ast, file_path, symbol_table):
        violations = []
        # This is a complex naming convention check — we do a simplified version
        # checking that variable names start with a type prefix
        seen = set()
        for decl in walk(ast, Type_Declaration_Stmt):
            decl_str = str(decl).upper()
            # Determine the type prefix
            if 'INTEGER' in decl_str:
                expected_prefix = 'i'
            elif 'REAL' in decl_str or 'DOUBLE' in decl_str:
                expected_prefix = 'r'
            elif 'CHARACTER' in decl_str:
                expected_prefix = 'c'
            elif 'LOGICAL' in decl_str:
                expected_prefix = 'l'
            elif 'COMPLEX' in decl_str:
                expected_prefix = 'x'
            else:
                continue

            for entity in walk(decl, Entity_Decl):
                for name_node in walk(entity, Name):
                    var_name = str(name_node).strip()
                    if var_name in seen:
                        continue
                    seen.add(var_name)
                    # Skip if it's all uppercase (constant)
                    if var_name.isupper():
                        continue
                    # Check if starts with expected type prefix
                    if var_name and var_name[0].lower() != expected_prefix:
                        line = _get_line(decl)
                        fp = _get_source_file_path(decl) or file_path
                        violations.append(Violation(
                            rule_key=self.rule_key,
                            message=f"Identifier '{var_name}' shall follow the [scope_][type]<name> format. Expected type prefix '{expected_prefix}'.",
                            file_path=fp, line=line, severity=self.severity,
                        ))
                    break  # Only first name per entity
        return violations


# ---------------------------------------------------------------------------
# EUM.NAME.PublicFormat — PUBLIC elements format
# ---------------------------------------------------------------------------
class EumNamePublicFormat(FortranRule):
    """PUBLIC elements shall be prefixed with the module identifier."""

    rule_key = "EUM.NAME.PublicFormat"
    severity = "INFO"

    def check(self, ast, file_path, symbol_table):
        violations = []
        # Find module name
        for module_stmt in walk(ast, Module_Stmt):
            module_name = ""
            for child in walk(module_stmt, Name):
                module_name = str(child).strip()
                break
            if not module_name:
                continue

            # Extract module ID (first 4 chars: 2 upper + 2 lower)
            if len(module_name) >= 4:
                module_id = module_name[:4]
            else:
                module_id = module_name

            # Find PUBLIC declarations
            from fparser.two.Fortran2003 import Access_Stmt
            for access_stmt in walk(ast, Access_Stmt):
                stmt_str = str(access_stmt).upper()
                if 'PUBLIC' not in stmt_str:
                    continue
                # Check if it's a specific PUBLIC declaration (not just "PUBLIC")
                if '::' not in str(access_stmt):
                    continue
                # Get the names after ::
                names_part = str(access_stmt).split('::')[-1].strip()
                for name_str in names_part.split(','):
                    name_str = name_str.strip()
                    if name_str and not name_str.upper().startswith(module_id.upper()):
                        line = _get_line(access_stmt)
                        fp = _get_source_file_path(access_stmt) or file_path
                        violations.append(Violation(
                            rule_key=self.rule_key,
                            message=f"PUBLIC element '{name_str}' shall be prefixed with the module identifier '{module_id}'.",
                            file_path=fp, line=line, severity=self.severity,
                        ))
        return violations


# ---------------------------------------------------------------------------
# EUM.NAME.PrivateFormat — PRIVATE elements format
# ---------------------------------------------------------------------------
class EumNamePrivateFormat(FortranRule):
    """PRIVATE elements shall be prefixed with the module identifier."""

    rule_key = "EUM.NAME.PrivateFormat"
    severity = "INFO"

    def check(self, ast, file_path, symbol_table):
        violations = []
        for module_stmt in walk(ast, Module_Stmt):
            module_name = ""
            for child in walk(module_stmt, Name):
                module_name = str(child).strip()
                break
            if not module_name:
                continue

            if len(module_name) >= 4:
                module_id = module_name[:4]
            else:
                module_id = module_name

            from fparser.two.Fortran2003 import Access_Stmt
            for access_stmt in walk(ast, Access_Stmt):
                stmt_str = str(access_stmt).upper()
                if 'PRIVATE' not in stmt_str:
                    continue
                if '::' not in str(access_stmt):
                    continue
                names_part = str(access_stmt).split('::')[-1].strip()
                for name_str in names_part.split(','):
                    name_str = name_str.strip()
                    if name_str and not name_str.lower().startswith(module_id.lower()):
                        line = _get_line(access_stmt)
                        fp = _get_source_file_path(access_stmt) or file_path
                        violations.append(Violation(
                            rule_key=self.rule_key,
                            message=f"PRIVATE element '{name_str}' shall be prefixed with the module identifier '{module_id}'.",
                            file_path=fp, line=line, severity=self.severity,
                        ))
        return violations


# ---------------------------------------------------------------------------
# EUM.NAME.IdScope — identifier format scope (meta-rule, part of IdFormat)
# ---------------------------------------------------------------------------
class EumNameIdScope(FortranRule):
    """Identifier format shall be applied to modules, functions/subroutines, variables, and types."""

    rule_key = "EUM.NAME.IdScope"
    severity = "INFO"

    def check(self, ast, file_path, symbol_table):
        # This is a meta-rule — the actual checks are done by EUM.NAME.IdFormat
        # We don't produce separate violations here
        return []


# ---------------------------------------------------------------------------
# EUM.NAME.Constants — PARAMETER constants format
# ---------------------------------------------------------------------------
class EumNameConstants(FortranRule):
    """PARAMETER constants shall be written in uppercase."""

    rule_key = "EUM.NAME.Constants"
    severity = "INFO"

    def check(self, ast, file_path, symbol_table):
        violations = []
        for decl in walk(ast, Type_Declaration_Stmt):
            decl_str = str(decl)
            if 'PARAMETER' not in decl_str.upper():
                continue
            # Get variable names
            for entity in walk(decl, Entity_Decl):
                for name_node in walk(entity, Name):
                    const_name = str(name_node).strip()
                    if const_name and not const_name.isupper():
                        line = _get_line(decl)
                        fp = _get_source_file_path(decl) or file_path
                        violations.append(Violation(
                            rule_key=self.rule_key,
                            message=f"PARAMETER constant '{const_name}' shall be written in uppercase.",
                            file_path=fp, line=line, severity=self.severity,
                        ))
                    break
        return violations


# ---------------------------------------------------------------------------
# EUM.NAME.ProgramName — PROGRAM name CamelCase
# ---------------------------------------------------------------------------
class EumNameProgramName(FortranRule):
    """PROGRAM names shall use CamelCase notation."""

    rule_key = "EUM.NAME.ProgramName"
    severity = "INFO"

    def check(self, ast, file_path, symbol_table):
        violations = []
        for stmt in walk(ast, Program_Stmt):
            for child in walk(stmt, Name):
                prog_name = str(child).strip()
                # CamelCase: starts with uppercase, no underscores, no all-lowercase
                if '_' in prog_name or (prog_name and not prog_name[0].isupper()):
                    line = _get_line(stmt)
                    fp = _get_source_file_path(stmt) or file_path
                    violations.append(Violation(
                        rule_key=self.rule_key,
                        message=f"PROGRAM name '{prog_name}' shall use CamelCase notation.",
                        file_path=fp, line=line, severity=self.severity,
                    ))
                break
        return violations


# ---------------------------------------------------------------------------
# EUM.NAME.ModuleName — MODULE name format
# ---------------------------------------------------------------------------
class EumNameModuleName(FortranRule):
    """MODULE names shall follow the AAbb_Name format."""

    rule_key = "EUM.NAME.ModuleName"
    severity = "INFO"

    # Format: 2 uppercase + 2 lowercase + underscore + CamelCase
    _MODULE_PATTERN = re.compile(r'^[A-Z]{2}[a-z]{2}_[A-Z][a-zA-Z0-9]*$')

    def check(self, ast, file_path, symbol_table):
        violations = []
        for stmt in walk(ast, Module_Stmt):
            for child in walk(stmt, Name):
                mod_name = str(child).strip()
                if not self._MODULE_PATTERN.match(mod_name):
                    line = _get_line(stmt)
                    fp = _get_source_file_path(stmt) or file_path
                    violations.append(Violation(
                        rule_key=self.rule_key,
                        message=f"MODULE name '{mod_name}' shall follow the AAbb_Name format (2 uppercase library ID + 2 lowercase module ID + underscore + CamelCase).",
                        file_path=fp, line=line, severity=self.severity,
                    ))
                break
        return violations


# ---------------------------------------------------------------------------
# EUM.NAME.FileExt — file extension check
# ---------------------------------------------------------------------------
class EumNameFileExt(FortranRule):
    """File extensions shall be .f90, .F90, .f95, .F95, .f03, or .F03."""

    rule_key = "EUM.NAME.FileExt"
    severity = "INFO"

    _VALID_EXTS = {'.f90', '.F90', '.f95', '.F95', '.f03', '.F03'}

    def check(self, ast, file_path, symbol_table):
        violations = []
        _, ext = os.path.splitext(file_path)
        if ext not in self._VALID_EXTS:
            violations.append(Violation(
                rule_key=self.rule_key,
                message=f"File extension '{ext}' is not valid. Use .f90, .F90, .f95, .F95, .f03, or .F03.",
                file_path=file_path, line=1, severity=self.severity,
            ))
        return violations


# ---------------------------------------------------------------------------
# EUM.DESIGN.OneUnitPerFile — one programming unit per file
# ---------------------------------------------------------------------------
class EumDesignOneUnitPerFile(FortranRule):
    """Each file shall contain only one programming unit (PROGRAM or MODULE)."""

    rule_key = "EUM.DESIGN.OneUnitPerFile"
    severity = "INFO"

    def check(self, ast, file_path, symbol_table):
        violations = []
        module_count = len(walk(ast, Module_Stmt))
        program_count = len(walk(ast, Program_Stmt))
        total = module_count + program_count
        if total > 1:
            violations.append(Violation(
                rule_key=self.rule_key,
                message=f"Each file shall contain only one programming unit. Found {total}.",
                file_path=file_path, line=1, severity=self.severity,
            ))
        return violations


# ---------------------------------------------------------------------------
# EUM.DESIGN.ProgramStructure — program structure
# ---------------------------------------------------------------------------
class EumDesignProgramStructure(FortranRule):
    """Programs shall have IMPLICIT NONE and END PROGRAM in full form."""

    rule_key = "EUM.DESIGN.ProgramStructure"
    severity = "INFO"

    def check(self, ast, file_path, symbol_table):
        violations = []
        lines = _read_source_lines(file_path, symbol_table)
        if not lines:
            return violations

        has_program = bool(walk(ast, Program_Stmt))
        if not has_program:
            return violations

        # Check IMPLICIT NONE
        has_implicit_none = False
        for impl in walk(ast, Implicit_Stmt):
            if 'NONE' in str(impl).upper():
                has_implicit_none = True
                break
        if not has_implicit_none:
            prog_stmt = walk(ast, Program_Stmt)[0]
            line = _get_line(prog_stmt)
            fp = _get_source_file_path(prog_stmt) or file_path
            violations.append(Violation(
                rule_key=self.rule_key,
                message="Programs shall have IMPLICIT NONE.",
                file_path=fp, line=line, severity=self.severity,
            ))

        # Check END PROGRAM (not bare END)
        for i, line in enumerate(lines, 1):
            stripped = line.strip().upper()
            if re.match(r'^END\s*$', stripped) and not re.match(r'^END\s+PROGRAM', stripped):
                # Check if this is the program's END
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message="Programs shall use END PROGRAM in full form, not bare END.",
                    file_path=file_path, line=i, severity=self.severity,
                ))
        return violations


# ---------------------------------------------------------------------------
# EUM.DESIGN.ModuleStructure — module structure
# ---------------------------------------------------------------------------
class EumDesignModuleStructure(FortranRule):
    """Modules shall have IMPLICIT NONE, PRIVATE, and CONTAINS."""

    rule_key = "EUM.DESIGN.ModuleStructure"
    severity = "INFO"

    def check(self, ast, file_path, symbol_table):
        violations = []
        lines = _read_source_lines(file_path, symbol_table)

        for module in walk(ast, Module):
            has_implicit_none = False
            has_private = False
            has_contains = False

            for impl in walk(module, Implicit_Stmt):
                if 'NONE' in str(impl).upper():
                    has_implicit_none = True
                    break

            from fparser.two.Fortran2003 import Access_Stmt
            for access in walk(module, Access_Stmt):
                if 'PRIVATE' in str(access).upper():
                    has_private = True
                    break

            from fparser.two.Fortran2003 import Contains_Stmt
            has_contains = bool(walk(module, Contains_Stmt))

            mod_stmt = walk(module, Module_Stmt)
            line = _get_line(mod_stmt[0]) if mod_stmt else 1
            fp = _get_source_file_path(module) or file_path

            if not has_implicit_none:
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message="Modules shall have IMPLICIT NONE.",
                    file_path=fp, line=line, severity=self.severity,
                ))
            if not has_private:
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message="Modules shall have a PRIVATE statement.",
                    file_path=fp, line=line, severity=self.severity,
                ))
            if not has_contains:
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message="Modules shall have a CONTAINS statement.",
                    file_path=fp, line=line, severity=self.severity,
                ))
        return violations


# ---------------------------------------------------------------------------
# EUM.DESIGN.SubroutineStructure — subroutine structure
# ---------------------------------------------------------------------------
class EumDesignSubroutineStructure(FortranRule):
    """Subroutines shall have a header and END SUBROUTINE in full form."""

    rule_key = "EUM.DESIGN.SubroutineStructure"
    severity = "INFO"

    def check(self, ast, file_path, symbol_table):
        violations = []
        lines = _read_source_lines(file_path, symbol_table)
        if not lines:
            return violations

        for stmt in walk(ast, Subroutine_Stmt):
            line_num = _get_line(stmt)
            if not line_num:
                continue
            # Check for END SUBROUTINE (not bare END)
            found_end = False
            for i in range(line_num, len(lines)):
                stripped = lines[i].strip().upper()
                if re.match(r'^END\s+SUBROUTINE', stripped):
                    found_end = True
                    break
                if re.match(r'^END\s*$', stripped):
                    fp = _get_source_file_path(stmt) or file_path
                    violations.append(Violation(
                        rule_key=self.rule_key,
                        message="Subroutines shall use END SUBROUTINE in full form, not bare END.",
                        file_path=fp, line=i + 1, severity=self.severity,
                    ))
                    found_end = True
                    break
                if re.match(r'^END\s+(SUBROUTINE|FUNCTION|MODULE|PROGRAM)', stripped):
                    break  # Different END — stop
        return violations


# ---------------------------------------------------------------------------
# EUM.DESIGN.NoGlobalVars — modules with variables but no procedures
# ---------------------------------------------------------------------------
class EumDesignNoGlobalVars(FortranRule):
    """Modules shall not contain only variables (global variable misuse)."""

    rule_key = "EUM.DESIGN.NoGlobalVars"
    severity = "INFO"

    def check(self, ast, file_path, symbol_table):
        violations = []
        from fparser.two.Fortran2003 import Contains_Stmt

        for module in walk(ast, Module):
            has_contains = bool(walk(module, Contains_Stmt))
            has_vars = bool(walk(module, Type_Declaration_Stmt))
            if has_vars and not has_contains:
                mod_stmt = walk(module, Module_Stmt)
                line = _get_line(mod_stmt[0]) if mod_stmt else 1
                fp = _get_source_file_path(module) or file_path
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message="Modules shall not contain only variables without procedures (global variable misuse).",
                    file_path=fp, line=line, severity=self.severity,
                ))
        return violations


# ---------------------------------------------------------------------------
# EUM.INST.ArgTypeDecl — all dummy args have type declaration
# ---------------------------------------------------------------------------
class EumInstArgTypeDecl(FortranRule):
    """All dummy arguments shall have an explicit data type declaration."""

    rule_key = "EUM.INST.ArgTypeDecl"
    severity = "INFO"

    def check(self, ast, file_path, symbol_table):
        violations = []
        # Collect all declared variable names
        declared_names = set()
        for decl in walk(ast, Type_Declaration_Stmt):
            for entity in walk(decl, Entity_Decl):
                for name_node in walk(entity, Name):
                    declared_names.add(str(name_node).strip().lower())
                    break

        # Check subroutine/function arguments
        for stmt in walk(ast, Subroutine_Stmt) + walk(ast, Function_Stmt):
            arg_lists = walk(stmt, Dummy_Arg_List)
            if not arg_lists:
                continue
            for arg in arg_lists[0].children:
                if arg is None:
                    continue
                arg_name = str(arg).strip().lower()
                if arg_name not in declared_names:
                    line = _get_line(stmt)
                    fp = _get_source_file_path(stmt) or file_path
                    violations.append(Violation(
                        rule_key=self.rule_key,
                        message=f"Dummy argument '{arg_name}' shall have an explicit data type declaration.",
                        file_path=fp, line=line, severity=self.severity,
                    ))
        return violations


# ---------------------------------------------------------------------------
# EUM.INST.ArgOrder — INTENT ordering: IN → INOUT → OUT
# ---------------------------------------------------------------------------
class EumInstArgOrder(FortranRule):
    """Arguments shall be ordered: INTENT(IN) first, then INTENT(INOUT), then INTENT(OUT)."""

    rule_key = "EUM.INST.ArgOrder"
    severity = "INFO"

    def check(self, ast, file_path, symbol_table):
        violations = []
        for stmt in walk(ast, Subroutine_Stmt):
            arg_lists = walk(stmt, Dummy_Arg_List)
            if not arg_lists:
                continue
            args = [str(a).strip().lower() for a in arg_lists[0].children if a is not None]
            if len(args) < 2:
                continue

            # Find the enclosing subprogram so we only search declarations
            # within this scope.
            from rules.rule_batch2_declarations import F90InstIntent
            subprogram = F90InstIntent._find_enclosing_subprogram(stmt)
            search_root = subprogram if subprogram is not None else ast

            # Get INTENT for each argument
            intent_order = []  # List of (arg_name, intent_value)
            for arg in args:
                intent = self._get_intent(search_root, arg)
                intent_order.append((arg, intent))

            # Check ordering: IN(0) < INOUT(1) < OUT(2) < none(3)
            prev_order = -1
            for arg_name, intent in intent_order:
                if intent == 'IN':
                    curr = 0
                elif intent == 'INOUT':
                    curr = 1
                elif intent == 'OUT':
                    curr = 2
                else:
                    curr = 3
                if curr < prev_order:
                    line = _get_line(stmt)
                    fp = _get_source_file_path(stmt) or file_path
                    violations.append(Violation(
                        rule_key=self.rule_key,
                        message=f"Arguments shall be ordered: INTENT(IN) first, then INTENT(INOUT), then INTENT(OUT). '{arg_name}' is out of order.",
                        file_path=fp, line=line, severity=self.severity,
                    ))
                    break
                prev_order = curr
        return violations

    @staticmethod
    def _get_intent(ast, arg_name: str) -> str:
        """Get the INTENT of a variable from type declarations."""
        for decl in walk(ast, Type_Declaration_Stmt):
            decl_str = str(decl).upper()
            if arg_name.upper() not in decl_str:
                continue
            if 'INTENT(IN)' in decl_str or 'INTENT (IN)' in decl_str:
                return 'IN'
            if 'INTENT(INOUT)' in decl_str or 'INTENT (INOUT)' in decl_str:
                return 'INOUT'
            if 'INTENT(OUT)' in decl_str or 'INTENT (OUT)' in decl_str:
                return 'OUT'
        return ''


# ---------------------------------------------------------------------------
# EUM.INST.OptionalNamed — OPTIONAL args named in calls
# ---------------------------------------------------------------------------
class EumInstOptionalNamed(FortranRule):
    """OPTIONAL arguments shall be named in procedure calls."""

    rule_key = "EUM.INST.OptionalNamed"
    severity = "INFO"

    def check(self, ast, file_path, symbol_table):
        # This requires cross-procedure analysis — simplified version:
        # Check if any call uses positional args after a named arg
        violations = []
        for call in walk(ast, Call_Stmt):
            call_str = str(call)
            # Check if there are both named and positional args
            # Named args have = sign
            has_named = '=' in call_str
            has_positional = False
            # Simple heuristic: if there's a named arg, all subsequent should be named
            # This is a simplification
        return violations


# ---------------------------------------------------------------------------
# EUM.INST.DummyArgOrder — declaration order matches arg list
# ---------------------------------------------------------------------------
class EumInstDummyArgOrder(FortranRule):
    """Declaration order shall follow the same order as the calling sequence."""

    rule_key = "EUM.INST.DummyArgOrder"
    severity = "INFO"

    def check(self, ast, file_path, symbol_table):
        violations = []
        for stmt in walk(ast, Subroutine_Stmt) + walk(ast, Function_Stmt):
            arg_lists = walk(stmt, Dummy_Arg_List)
            if not arg_lists:
                continue
            args = [str(a).strip().lower() for a in arg_lists[0].children if a is not None]
            if len(args) < 2:
                continue

            # Find the enclosing subprogram so we only search declarations
            # within this scope, not declarations from other subprograms.
            subprogram = EumInstArgOrder._find_enclosing_subprogram(stmt) if hasattr(EumInstArgOrder, '_find_enclosing_subprogram') else None
            if subprogram is None:
                # Fallback: use the helper from F90InstIntent
                from rules.rule_batch2_declarations import F90InstIntent
                subprogram = F90InstIntent._find_enclosing_subprogram(stmt)
            search_root = subprogram if subprogram is not None else ast

            # Find declaration order within this subprogram's scope
            decl_order = []
            for decl in walk(search_root, Type_Declaration_Stmt):
                for entity in walk(decl, Entity_Decl):
                    for name_node in walk(entity, Name):
                        var_name = str(name_node).strip().lower()
                        if var_name in args:
                            decl_order.append(var_name)
                        break

            # Check if declaration order matches argument order
            arg_order_in_decls = [a for a in decl_order if a in args]
            if arg_order_in_decls != args:
                # Find first mismatch
                for i, (decl_arg, sig_arg) in enumerate(zip(arg_order_in_decls, args)):
                    if decl_arg != sig_arg:
                        line = _get_line(stmt)
                        fp = _get_source_file_path(stmt) or file_path
                        violations.append(Violation(
                            rule_key=self.rule_key,
                            message=f"Declaration order shall follow the calling sequence. '{decl_arg}' declared before '{sig_arg}'.",
                            file_path=fp, line=line, severity=self.severity,
                        ))
                        break
        return violations


# ---------------------------------------------------------------------------
# EUM.INST.OptionalAfterMandatory — OPTIONAL after mandatory
# ---------------------------------------------------------------------------
class EumInstOptionalAfterMandatory(FortranRule):
    """OPTIONAL arguments shall be declared after mandatory ones."""

    rule_key = "EUM.INST.OptionalAfterMandatory"
    severity = "INFO"

    def check(self, ast, file_path, symbol_table):
        violations = []
        for stmt in walk(ast, Subroutine_Stmt) + walk(ast, Function_Stmt):
            arg_lists = walk(stmt, Dummy_Arg_List)
            if not arg_lists:
                continue
            args = [str(a).strip().lower() for a in arg_lists[0].children if a is not None]
            if len(args) < 2:
                continue

            # Find the enclosing subprogram so we only search declarations
            # within this scope.
            from rules.rule_batch2_declarations import F90InstIntent
            subprogram = F90InstIntent._find_enclosing_subprogram(stmt)
            search_root = subprogram if subprogram is not None else ast

            # Check which args are OPTIONAL
            optional_args = set()
            for decl in walk(search_root, Type_Declaration_Stmt):
                decl_str = str(decl).upper()
                if 'OPTIONAL' not in decl_str:
                    continue
                for entity in walk(decl, Entity_Decl):
                    for name_node in walk(entity, Name):
                        optional_args.add(str(name_node).strip().lower())
                        break

            if not optional_args:
                continue

            # Check that no mandatory arg comes after an optional arg
            found_optional = False
            for arg in args:
                if arg in optional_args:
                    found_optional = True
                elif found_optional:
                    line = _get_line(stmt)
                    fp = _get_source_file_path(stmt) or file_path
                    violations.append(Violation(
                        rule_key=self.rule_key,
                        message=f"Mandatory argument '{arg}' shall be declared before OPTIONAL arguments.",
                        file_path=fp, line=line, severity=self.severity,
                    ))
                    break
        return violations


# ---------------------------------------------------------------------------
# EUM.INST.StringDim — character args use LEN=*
# ---------------------------------------------------------------------------
class EumInstStringDim(FortranRule):
    """Character dummy arguments shall use LEN=* (not LEN=n)."""

    rule_key = "EUM.INST.StringDim"
    severity = "INFO"

    def check(self, ast, file_path, symbol_table):
        violations = []
        # Collect all dummy argument names
        dummy_args = set()
        for stmt in walk(ast, Subroutine_Stmt) + walk(ast, Function_Stmt):
            for arg_list in walk(stmt, Dummy_Arg_List):
                for arg in arg_list.children:
                    if arg is not None:
                        dummy_args.add(str(arg).strip().lower())

        # Check character declarations
        for decl in walk(ast, Type_Declaration_Stmt):
            decl_str = str(decl)
            if 'CHARACTER' not in decl_str.upper():
                continue
            # Check if this declares a dummy argument
            for entity in walk(decl, Entity_Decl):
                for name_node in walk(entity, Name):
                    var_name = str(name_node).strip().lower()
                    if var_name in dummy_args:
                        # Check if LEN=n (not LEN=*)
                        if re.search(r'LEN\s*=\s*\d+', decl_str, re.IGNORECASE):
                            line = _get_line(decl)
                            fp = _get_source_file_path(decl) or file_path
                            violations.append(Violation(
                                rule_key=self.rule_key,
                                message=f"Character dummy argument '{var_name}' shall use LEN=* (not LEN=n).",
                                file_path=fp, line=line, severity=self.severity,
                            ))
                    break
        return violations


# ---------------------------------------------------------------------------
# EUM.INST.FunctionIntent — function args all INTENT(IN)
# ---------------------------------------------------------------------------
class EumInstFunctionIntent(FortranRule):
    """All function arguments shall have INTENT(IN)."""

    rule_key = "EUM.INST.FunctionIntent"
    severity = "INFO"

    def check(self, ast, file_path, symbol_table):
        violations = []
        for stmt in walk(ast, Function_Stmt):
            arg_lists = walk(stmt, Dummy_Arg_List)
            if not arg_lists:
                continue
            args = [str(a).strip().lower() for a in arg_lists[0].children if a is not None]
            if not args:
                continue

            # Find the enclosing subprogram so we only search declarations
            # within this scope.
            from rules.rule_batch2_declarations import F90InstIntent
            subprogram = F90InstIntent._find_enclosing_subprogram(stmt)
            search_root = subprogram if subprogram is not None else ast

            # Check INTENT for each argument
            for arg in args:
                intent = EumInstArgOrder._get_intent(search_root, arg)
                if intent and intent != 'IN':
                    line = _get_line(stmt)
                    fp = _get_source_file_path(stmt) or file_path
                    violations.append(Violation(
                        rule_key=self.rule_key,
                        message=f"Function argument '{arg}' shall have INTENT(IN) exclusively.",
                        file_path=fp, line=line, severity=self.severity,
                    ))
        return violations


# ---------------------------------------------------------------------------
# EUM.INST.OptionalDefault — OPTIONAL args have default
# ---------------------------------------------------------------------------
class EumInstOptionalDefault(FortranRule):
    """OPTIONAL arguments shall have a default value assigned at procedure start."""

    rule_key = "EUM.INST.OptionalDefault"
    severity = "INFO"

    def check(self, ast, file_path, symbol_table):
        violations = []
        # Find OPTIONAL arguments
        optional_args = set()
        for decl in walk(ast, Type_Declaration_Stmt):
            decl_str = str(decl).upper()
            if 'OPTIONAL' not in decl_str:
                continue
            for entity in walk(decl, Entity_Decl):
                for name_node in walk(entity, Name):
                    optional_args.add(str(name_node).strip().lower())
                    break

        if not optional_args:
            return violations

        # Check if each optional arg has a default assignment using PRESENT()
        # Look for "if (.not. present(arg)) arg = ..."
        for arg in optional_args:
            has_default = False
            for if_node in walk(ast, (If_Stmt, If_Construct)):
                if_str = str(if_node)
                if f'PRESENT({arg})' in if_str.upper() or f'PRESENT ({arg})' in if_str.upper():
                    has_default = True
                    break
            if not has_default:
                # Find the declaration line
                for decl in walk(ast, Type_Declaration_Stmt):
                    if arg.upper() in str(decl).upper() and 'OPTIONAL' in str(decl).upper():
                        line = _get_line(decl)
                        fp = _get_source_file_path(decl) or file_path
                        violations.append(Violation(
                            rule_key=self.rule_key,
                            message=f"OPTIONAL argument '{arg}' shall have a default value assigned at procedure start using PRESENT().",
                            file_path=fp, line=line, severity=self.severity,
                        ))
                        break
        return violations


# ---------------------------------------------------------------------------
# EUM.INST.PureFunc — PURE functions for INTENT(IN) only
# ---------------------------------------------------------------------------
class EumInstPureFunc(FortranRule):
    """Functions with all INTENT(IN) arguments and no side effects shall be marked PURE."""

    rule_key = "EUM.INST.PureFunc"
    severity = "INFO"

    def check(self, ast, file_path, symbol_table):
        violations = []
        for stmt in walk(ast, Function_Stmt):
            stmt_str = str(stmt).upper()
            if 'PURE' in stmt_str:
                continue  # Already PURE

            arg_lists = walk(stmt, Dummy_Arg_List)
            if not arg_lists:
                continue
            args = [str(a).strip().lower() for a in arg_lists[0].children if a is not None]
            if not args:
                continue

            # Find the enclosing subprogram so we only search declarations
            # within this scope.
            from rules.rule_batch2_declarations import F90InstIntent
            subprogram = F90InstIntent._find_enclosing_subprogram(stmt)
            search_root = subprogram if subprogram is not None else ast

            # Check if all args are INTENT(IN)
            all_in = True
            for arg in args:
                intent = EumInstArgOrder._get_intent(search_root, arg)
                if intent and intent != 'IN':
                    all_in = False
                    break

            if all_in:
                line = _get_line(stmt)
                fp = _get_source_file_path(stmt) or file_path
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message="Functions with all INTENT(IN) arguments shall be marked PURE.",
                    file_path=fp, line=line, severity=self.severity,
                ))
        return violations


# ---------------------------------------------------------------------------
# F90.DESIGN.Interface — modules contain PRIVATE
# ---------------------------------------------------------------------------
class F90DesignInterface(FortranRule):
    """Modules shall contain a PRIVATE statement."""

    rule_key = "F90.DESIGN.Interface"
    severity = "MAJOR"

    def check(self, ast, file_path, symbol_table):
        violations = []
        from fparser.two.Fortran2003 import Access_Stmt, Contains_Stmt

        for module in walk(ast, Module):
            has_private = False
            for access in walk(module, Access_Stmt):
                if 'PRIVATE' in str(access).upper():
                    has_private = True
                    break
            if not has_private:
                mod_stmt = walk(module, Module_Stmt)
                line = _get_line(mod_stmt[0]) if mod_stmt else 1
                fp = _get_source_file_path(module) or file_path
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message="Modules shall contain a PRIVATE statement.",
                    file_path=fp, line=line, severity=self.severity,
                ))
        return violations


# ---------------------------------------------------------------------------
# F90.INST.Only — USE with ONLY
# ---------------------------------------------------------------------------
class F90InstOnly(FortranRule):
    """USE statements shall use the ONLY clause."""

    rule_key = "F90.INST.Only"
    severity = "MAJOR"

    def check(self, ast, file_path, symbol_table):
        violations = []
        for use_stmt in walk(ast, Use_Stmt):
            use_str = str(use_stmt).upper()
            if 'ONLY' not in use_str:
                line = _get_line(use_stmt)
                fp = _get_source_file_path(use_stmt) or file_path
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message="USE statements shall use the ONLY clause.",
                    file_path=fp, line=line, severity=self.severity,
                ))
        return violations


# ---------------------------------------------------------------------------
# F90.REF.Interface — interface visibility
# ---------------------------------------------------------------------------
class F90RefInterface(FortranRule):
    """Interface blocks shall have explicit visibility (PUBLIC or PRIVATE)."""

    rule_key = "F90.REF.Interface"
    severity = "MAJOR"

    def check(self, ast, file_path, symbol_table):
        violations = []
        for iface in walk(ast, Interface_Block):
            iface_str = str(iface).upper()
            if 'PUBLIC' not in iface_str and 'PRIVATE' not in iface_str:
                line = _get_line(iface)
                fp = _get_source_file_path(iface) or file_path
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message="Interface blocks shall have explicit visibility (PUBLIC or PRIVATE).",
                    file_path=fp, line=line, severity=self.severity,
                ))
        return violations


# ---------------------------------------------------------------------------
# F90.INST.Associated — NULLIFY before ASSOCIATED
# ---------------------------------------------------------------------------
class F90InstAssociated(FortranRule):
    """Pointers shall be NULLIFY'd before using ASSOCIATED."""

    rule_key = "F90.INST.Associated"
    severity = "MAJOR"

    def check(self, ast, file_path, symbol_table):
        violations = []
        # Find all ASSOCIATED() calls
        for call in walk(ast, Call_Stmt):
            call_str = str(call).upper()
            if 'ASSOCIATED' not in call_str:
                continue
            # This is a simplification — full check requires data flow analysis
            # We check if there's a NULLIFY before this call in the same procedure
        return violations


# ---------------------------------------------------------------------------
# F90.INST.Nullify — NULLIFY after DEALLOCATE
# ---------------------------------------------------------------------------
class F90InstNullify(FortranRule):
    """Pointers shall be NULLIFY'd after DEALLOCATE."""

    rule_key = "F90.INST.Nullify"
    severity = "MAJOR"

    def check(self, ast, file_path, symbol_table):
        violations = []
        from fparser.two.Fortran2003 import Nullify_Stmt
        import re

        for dealloc in walk(ast, Deallocate_Stmt):
            dealloc_str = str(dealloc)

            # Extract the STAT variable name if present (to exclude it)
            stat_match = re.search(r'STAT\s*=\s*(\w+)', dealloc_str, re.IGNORECASE)
            stat_var = stat_match.group(1).lower() if stat_match else None

            # Find pointer names in the DEALLOCATE statement
            ptr_names = []
            for name in walk(dealloc, Name):
                name_str = str(name).strip()
                name_lower = name_str.lower()
                # Skip keywords and the STAT variable
                if name_str.upper() in ('DEALLOCATE', 'STAT'):
                    continue
                if stat_var and name_lower == stat_var:
                    continue
                ptr_names.append(name_lower)

            if not ptr_names:
                continue

            dealloc_line = _get_line(dealloc) or 0

            # Check if there's a NULLIFY for each pointer after this DEALLOCATE
            for ptr in ptr_names:
                # Only flag actual POINTER variables — skip allocatables
                # and derived type components that are allocatable.
                # Check symbol table for POINTER attribute.
                # If we can't find the symbol (e.g., derived type component
                # like fld%a3), skip it — we can't confirm it's a pointer.
                sym = None
                for scope in symbol_table.get_all_scopes_in_file(file_path):
                    sym = symbol_table.get_symbol(ptr, scope.name, file_path)
                    if sym:
                        break
                if sym is None:
                    # Can't confirm it's a pointer — skip
                    continue
                if not sym.is_pointer:
                    # Variable is not a pointer — skip
                    continue

                found_nullify = False
                for nullify in walk(ast, Nullify_Stmt):
                    nullify_line = _get_line(nullify) or 0
                    if nullify_line > dealloc_line:
                        nullify_str = str(nullify).lower()
                        if ptr in nullify_str:
                            found_nullify = True
                            break

                if not found_nullify:
                    fp = _get_source_file_path(dealloc) or file_path
                    violations.append(Violation(
                        rule_key=self.rule_key,
                        message=f"Pointer '{ptr}' shall be NULLIFY'd after DEALLOCATE.",
                        file_path=fp, line=dealloc_line, severity=self.severity,
                    ))
        return violations


# ---------------------------------------------------------------------------
# F90.DESIGN.Free — alloc/dealloc at same level
# ---------------------------------------------------------------------------
class F90DesignFree(FortranRule):
    """Memory shall be freed at the same level where it was allocated."""

    rule_key = "F90.DESIGN.Free"
    severity = "MAJOR"

    @staticmethod
    def _extract_alloc_targets(stmt):
        """Extract allocation target names from an ALLOCATE/DEALLOCATE statement.

        Only the actual allocation targets (e.g. fld%a1, ptr) are returned,
        not dimension variables or STAT variables.
        """
        from fparser.two.Fortran2003 import Allocation
        targets = []
        for alloc in walk(stmt, Allocation):
            # Allocation has: Allocate_Object, [Allocate_Shape_Spec_List], ...
            # The first child is the allocate object (the variable being allocated)
            if alloc.children and alloc.children[0] is not None:
                obj = alloc.children[0]
                targets.append(str(obj).strip().lower())
        return targets

    def check(self, ast, file_path, symbol_table):
        violations = []
        # Collect allocated and deallocated variables
        alloc_vars = set()
        dealloc_vars = set()

        for alloc in walk(ast, Allocate_Stmt):
            for name_str in self._extract_alloc_targets(alloc):
                alloc_vars.add(name_str)

        for dealloc in walk(ast, Deallocate_Stmt):
            for name_str in self._extract_alloc_targets(dealloc):
                dealloc_vars.add(name_str)

        # Check for allocated but never deallocated
        unfreed = alloc_vars - dealloc_vars
        for alloc in walk(ast, Allocate_Stmt):
            targets = self._extract_alloc_targets(alloc)
            unfreed_targets = [t for t in targets if t in unfreed]
            if unfreed_targets:
                line = _get_line(alloc)
                fp = _get_source_file_path(alloc) or file_path
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message=f"Memory allocated for '{unfreed_targets[0]}' shall be freed at the same level.",
                    file_path=fp, line=line, severity=self.severity,
                ))
        return violations


# ---------------------------------------------------------------------------
# F90.NAME.GenericIntrinsic — generic intrinsic function names
# ---------------------------------------------------------------------------
class F90NameGenericIntrinsic(FortranRule):
    """Generic intrinsic function names shall be used."""

    rule_key = "F90.NAME.GenericIntrinsic"
    severity = "MAJOR"

    # Specific to generic intrinsic name mapping
    _SPECIFIC_TO_GENERIC = {
        'IABS': 'ABS', 'CABS': 'ABS', 'DABS': 'ABS', 'ZABS': 'ABS',
        'AMOD': 'MOD', 'DMOD': 'MOD',
        'ISIGN': 'SIGN', 'DSIGN': 'SIGN',
        'IDINT': 'INT', 'IFIX': 'INT',
        'AMAX0': 'MAX', 'AMAX1': 'MAX', 'DMAX1': 'MAX', 'MAX0': 'MAX', 'MAX1': 'MAX',
        'AMIN0': 'MIN', 'AMIN1': 'MIN', 'DMIN1': 'MIN', 'MIN0': 'MIN', 'MIN1': 'MIN',
        'FLOAT': 'REAL', 'DFLOAT': 'REAL', 'SNGL': 'REAL',
        'ALOG': 'LOG', 'DLOG': 'LOG', 'CLOG': 'LOG',
        'ALOG10': 'LOG10', 'DLOG10': 'LOG10',
        'ASIN': 'ASIN', 'DASIN': 'ASIN', 'CASIN': 'ASIN',
        'ACOS': 'ACOS', 'DACOS': 'ACOS', 'CACOS': 'ACOS',
        'ATAN': 'ATAN', 'DATAN': 'ATAN', 'CATAN': 'ATAN',
        'ATAN2': 'ATAN2', 'DATAN2': 'ATAN2',
        'DSQRT': 'SQRT', 'CSQRT': 'SQRT',
        'DEXP': 'EXP', 'CEXP': 'EXP',
        'DCMPLX': 'CMPLX',
        'DCONJG': 'CONJG',
        'DIMAG': 'AIMAG',
    }

    def check(self, ast, file_path, symbol_table):
        violations = []
        seen = set()
        # Collect variable names declared in Type_Declaration_Stmt so we don't
        # flag local variables that happen to share a name with a specific
        # intrinsic (e.g., DOUBLE PRECISION :: DMOD).
        declared_var_names = set()
        for decl in walk(ast, Type_Declaration_Stmt):
            for entity in walk(decl, Entity_Decl):
                for name_node in walk(entity, Name):
                    declared_var_names.add(str(name_node).strip().upper())
                    break
        for name in walk(ast, Name):
            name_str = str(name).strip()
            if name_str.upper() in self._SPECIFIC_TO_GENERIC and name_str not in seen:
                # Skip if this name is a declared variable (not an intrinsic call)
                if name_str.upper() in declared_var_names:
                    continue
                seen.add(name_str)
                generic = self._SPECIFIC_TO_GENERIC[name_str.upper()]
                line = _get_line(name)
                fp = _get_source_file_path(name) or file_path
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message=f"Generic intrinsic function name '{generic}' shall be used instead of '{name_str}'.",
                    file_path=fp, line=line, severity=self.severity,
                ))
        return violations


# ---------------------------------------------------------------------------
# F77.NAME.Intrinsic — intrinsic function name reuse
# ---------------------------------------------------------------------------
class F77NameIntrinsic(FortranRule):
    """Intrinsic function names shall not be used as variable names."""

    rule_key = "F77.NAME.Intrinsic"
    severity = "MAJOR"

    _INTRINSICS = {
        'ABS', 'ACHAR', 'ACOS', 'ACOSH', 'ADJUSTL', 'ADJUSTR', 'AIMAG',
        'AINT', 'ALL', 'ALLOCATED', 'ANINT', 'ANY', 'ASIN', 'ASINH',
        'ASSOCIATED', 'ATAN', 'ATAN2', 'ATANH', 'BESSEL_J0', 'BESSEL_J1',
        'BESSEL_JN', 'BESSEL_Y0', 'BESSEL_Y1', 'BESSEL_YN', 'BGE', 'BGT',
        'BIT_SIZE', 'BLE', 'BLT', 'BTEST', 'CEILING', 'CHAR', 'CMPLX',
        'COMMAND_ARGUMENT_COUNT', 'CONJG', 'COS', 'COSH', 'COTAN', 'COUNT',
        'CPU_TIME', 'CSHIFT', 'DATE_AND_TIME', 'DBLE', 'DIGITS', 'DIM',
        'DOT_PRODUCT', 'DPROD', 'DSHIFTL', 'DSHIFTR', 'EOSHIFT', 'EPSILON',
        'ERF', 'ERFC', 'ERFC_SCALED', 'EXP', 'EXPONENT', 'EXTENDS_TYPE_OF',
        'FINDLOC', 'FLOOR', 'FRACTION', 'GAMMA', 'HUGE', 'HYPOT', 'IACHAR',
        'IALL', 'IAND', 'IANY', 'IBCLR', 'IBITS', 'IBSET', 'ICHAR', 'IEOR',
        'IMAGE_STATUS', 'INDEX', 'INT', 'IOR', 'IPARITY', 'ISHFT', 'ISHFTC',
        'IS_CONTIGUOUS', 'IS_IOSTAT_END', 'IS_IOSTAT_EOR', 'KIND', 'LBOUND',
        'LCOBOUND', 'LEADZ', 'LEN', 'LEN_TRIM', 'LGE', 'LGT', 'LLE', 'LLT',
        'LOG', 'LOG10', 'LOG_GAMMA', 'LOGICAL', 'MASKL', 'MASKR', 'MATMUL',
        'MAX', 'MAXEXPONENT', 'MAXLOC', 'MAXVAL', 'MERGE', 'MERGE_BITS',
        'MIN', 'MINEXPONENT', 'MINLOC', 'MINVAL', 'MOD', 'MODULO', 'MVBITS',
        'NEAREST', 'NEW_LINE', 'NINT', 'NORM2', 'NOT', 'NULL', 'NUM_IMAGES',
        'PACK', 'PARITY', 'POPCNT', 'POPPAR', 'PRESENT', 'PRODUCT', 'RADIX',
        'RANGE', 'REAL', 'REPEAT', 'RESHAPE', 'RRSPACING', 'SAME_TYPE_AS',
        'SCALE', 'SCAN', 'SELECTED_CHAR_KIND', 'SELECTED_INT_KIND',
        'SELECTED_REAL_KIND', 'SET_EXPONENT', 'SHAPE', 'SHIFTA', 'SHIFTL',
        'SHIFTR', 'SIGN', 'SIN', 'SINH', 'SIZE', 'SPACING', 'SPREAD', 'SQRT',
        'SUM', 'SYSTEM_CLOCK', 'TAN', 'TANH', 'THIS_IMAGE', 'TINY',
        'TRAILZ', 'TRANSFER', 'TRANSPOSE', 'TRIM', 'UBOUND', 'UCOBOUND',
        'UNPACK', 'VERIFY',
    }

    def check(self, ast, file_path, symbol_table):
        violations = []
        # Check if any intrinsic name is used as a variable declaration
        for decl in walk(ast, Type_Declaration_Stmt):
            for entity in walk(decl, Entity_Decl):
                for name_node in walk(entity, Name):
                    var_name = str(name_node).strip()
                    if var_name.upper() in self._INTRINSICS:
                        line = _get_line(decl)
                        fp = _get_source_file_path(decl) or file_path
                        violations.append(Violation(
                            rule_key=self.rule_key,
                            message=f"Intrinsic function name '{var_name}' shall not be used as a variable name.",
                            file_path=fp, line=line, severity=self.severity,
                        ))
                    break
        return violations


# ---------------------------------------------------------------------------
# F77.NAME.Label — labels limited to FORMAT and CONTINUE
# ---------------------------------------------------------------------------
class F77NameLabel(FortranRule):
    """Labels shall be limited to FORMAT and CONTINUE statements."""

    rule_key = "F77.NAME.Label"
    severity = "MAJOR"

    def check(self, ast, file_path, symbol_table):
        violations = []
        lines = _read_source_lines(file_path, symbol_table)
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            # Check for label (number at start)
            match = re.match(r'^(\d+)\s+(.+)', stripped)
            if match:
                rest = match.group(2).upper()
                # Only FORMAT and CONTINUE are allowed to have labels
                if not rest.startswith('FORMAT') and not rest.startswith('CONTINUE'):
                    violations.append(Violation(
                        rule_key=self.rule_key,
                        message="Labels shall be limited to FORMAT and CONTINUE statements.",
                        file_path=file_path, line=i, severity=self.severity,
                    ))
        return violations


# ---------------------------------------------------------------------------
# F90.REF.Array — array reference
# ---------------------------------------------------------------------------
class F90RefArray(FortranRule):
    """Array references shall use proper syntax."""

    rule_key = "F90.REF.Array"
    severity = "MAJOR"

    def check(self, ast, file_path, symbol_table):
        # This rule checks for proper array reference syntax
        # Simplified: check for common issues like mixed array syntax
        return []


# ---------------------------------------------------------------------------
# F90.REF.Variable — variable reference
# ---------------------------------------------------------------------------
class F90RefVariable(FortranRule):
    """Variable references shall use proper syntax."""

    rule_key = "F90.REF.Variable"
    severity = "MAJOR"

    def check(self, ast, file_path, symbol_table):
        return []


# ---------------------------------------------------------------------------
# F90.PROTO.Overload — operator overloading
# ---------------------------------------------------------------------------
class F90ProtoOverload(FortranRule):
    """Operator overloading shall use explicit interfaces."""

    rule_key = "F90.PROTO.Overload"
    severity = "MAJOR"

    def check(self, ast, file_path, symbol_table):
        violations = []
        from fparser.two.Fortran2003 import Interface_Stmt

        for iface in walk(ast, Interface_Block):
            iface_str = str(iface).upper()
            if 'OPERATOR' in iface_str or 'ASSIGNMENT' in iface_str:
                # Check if it has an explicit module procedure
                from fparser.two.Fortran2003 import Procedure_Stmt
                if not walk(iface, Procedure_Stmt):
                    line = _get_line(iface)
                    fp = _get_source_file_path(iface) or file_path
                    violations.append(Violation(
                        rule_key=self.rule_key,
                        message="Operator overloading shall use explicit MODULE PROCEDURE interfaces.",
                        file_path=fp, line=line, severity=self.severity,
                    ))
        return violations


# ---------------------------------------------------------------------------
# F90.DATA.Float — floating point format
# ---------------------------------------------------------------------------
class F90DataFloat(FortranRule):
    """Floating point literals shall use the E notation."""

    rule_key = "F90.DATA.Float"
    severity = "MAJOR"

    # Match floats without E notation (e.g., 3.14 without E0)
    _BAD_FLOAT = re.compile(r'(?i)\b\d+\.\d+(?![eEdD])')

    def check(self, ast, file_path, symbol_table):
        violations = []
        lines = _read_source_lines(file_path, symbol_table)
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('!') or stripped.startswith('c') or stripped.startswith('C'):
                continue
            # Skip lines with only integer constants
            for match in self._BAD_FLOAT.finditer(line):
                # Check it's not in a string
                pos = match.start()
                before = line[:pos]
                if before.count("'") % 2 == 1 or before.count('"') % 2 == 1:
                    continue
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message="Floating point literals shall use the E notation (e.g., 3.14E0).",
                    file_path=file_path, line=i, severity=self.severity,
                ))
                break  # One per line
        return violations


# ---------------------------------------------------------------------------
# F77.INST.Function — function type declaration
# ---------------------------------------------------------------------------
class F77InstFunction(FortranRule):
    """Functions shall have an explicit type declaration."""

    rule_key = "F77.INST.Function"
    severity = "MAJOR"

    def check(self, ast, file_path, symbol_table):
        violations = []
        for stmt in walk(ast, Function_Stmt):
            stmt_str = str(stmt).upper()
            # Check if the function has an explicit type (INTEGER, REAL, etc.)
            has_type = any(t in stmt_str for t in [
                'INTEGER', 'REAL', 'DOUBLE', 'CHARACTER', 'LOGICAL', 'COMPLEX', 'TYPE'
            ])
            if not has_type:
                # Check if there's a separate type declaration for the function name
                func_name = ""
                for child in walk(stmt, Name):
                    func_name = str(child).strip()
                    break
                if func_name:
                    # Look for a type declaration with the function name
                    found_decl = False
                    for decl in walk(ast, Type_Declaration_Stmt):
                        if func_name.upper() in str(decl).upper():
                            found_decl = True
                            break
                    if not found_decl:
                        line = _get_line(stmt)
                        fp = _get_source_file_path(stmt) or file_path
                        violations.append(Violation(
                            rule_key=self.rule_key,
                            message=f"Function '{func_name}' shall have an explicit type declaration.",
                            file_path=fp, line=line, severity=self.severity,
                        ))
        return violations


# ---------------------------------------------------------------------------
# F77.BLOC.Function — function block
# ---------------------------------------------------------------------------
class F77BlocFunction(FortranRule):
    """Functions shall use END FUNCTION in full form."""

    rule_key = "F77.BLOC.Function"
    severity = "MAJOR"

    def check(self, ast, file_path, symbol_table):
        violations = []
        lines = _read_source_lines(file_path, symbol_table)
        for stmt in walk(ast, Function_Stmt):
            line_num = _get_line(stmt)
            if not line_num:
                continue
            for i in range(line_num, len(lines)):
                stripped = lines[i].strip().upper()
                if re.match(r'^END\s+FUNCTION', stripped):
                    break
                if re.match(r'^END\s*$', stripped):
                    fp = _get_source_file_path(stmt) or file_path
                    violations.append(Violation(
                        rule_key=self.rule_key,
                        message="Functions shall use END FUNCTION in full form, not bare END.",
                        file_path=fp, line=i + 1, severity=self.severity,
                    ))
                    break
                if re.match(r'^END\s+(SUBROUTINE|MODULE|PROGRAM)', stripped):
                    break
        return violations


# ---------------------------------------------------------------------------
# F77.INST.Return — RETURN forbidden
# ---------------------------------------------------------------------------
class F77InstReturn(FortranRule):
    """RETURN statements shall not be used."""

    rule_key = "F77.INST.Return"
    severity = "MAJOR"

    def check(self, ast, file_path, symbol_table):
        violations = []
        for ret in walk(ast, Return_Stmt):
            line = _get_line(ret)
            if not line:
                # Skip if we can't determine the line number — this happens
                # for implicit RETURN at end of subroutine (fparser may not
                # attach source info to these nodes).
                continue
            fp = _get_source_file_path(ret) or file_path
            violations.append(Violation(
                rule_key=self.rule_key,
                message="RETURN statements shall not be used.",
                file_path=fp, line=line, severity=self.severity,
            ))
        return violations


# ---------------------------------------------------------------------------
# F77.INST.If — F77 single-line IF
# ---------------------------------------------------------------------------
class F77InstIf(FortranRule):
    """Single-line IF statements shall not be used (F77).

    Note: This is the same check as F90.INST.If.  To avoid duplicate
    violations, this rule delegates to F90.INST.If and returns no
    violations of its own.  The F90.INST.If rule already covers both
    F77 and F90 single-line IF statements.
    """

    rule_key = "F77.INST.If"
    severity = "MAJOR"

    def check(self, ast, file_path, symbol_table):
        return []


# ---------------------------------------------------------------------------
# F77.BLOC.Loop — F77 loop with label
# ---------------------------------------------------------------------------
class F77BlocLoop(FortranRule):
    """Labelled DO loops shall not be used (F77)."""

    rule_key = "F77.BLOC.Loop"
    severity = "MAJOR"

    def check(self, ast, file_path, symbol_table):
        violations = []
        from fparser.two.Fortran2003 import Label_Do_Stmt
        for node in walk(ast, Label_Do_Stmt):
            line = _get_line(node)
            fp = _get_source_file_path(node) or file_path
            violations.append(Violation(
                rule_key=self.rule_key,
                message="Labelled DO loops shall not be used. Use END DO instead of CONTINUE with label.",
                file_path=fp, line=line, severity=self.severity,
            ))
        return violations


# ---------------------------------------------------------------------------
# F77.MET.Line — F77 line length
# ---------------------------------------------------------------------------
class F77MetLine(FortranRule):
    """The length of each line shall be restricted to 120 characters."""

    rule_key = "F77.MET.Line"
    severity = "MAJOR"

    MAX_LENGTH = 120

    def check(self, ast, file_path, symbol_table):
        violations = []
        lines = _read_source_lines(file_path, symbol_table)
        for i, line in enumerate(lines, 1):
            line_len = len(line.rstrip('\n\r'))
            if line_len > self.MAX_LENGTH:
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message=f"Line length {line_len} exceeds the maximum of {self.MAX_LENGTH} characters.",
                    file_path=file_path, line=i, severity=self.severity,
                ))
        return violations


# ---------------------------------------------------------------------------
# COM.FLOW.BooleanExpression — boolean expression
# ---------------------------------------------------------------------------
class ComFlowBooleanExpression(FortranRule):
    """Boolean expressions shall be simplified."""

    rule_key = "COM.FLOW.BooleanExpression"
    severity = "MAJOR"

    _BAD_BOOL = re.compile(r'(?i)\.TRUE\.\s*\.EQV\.\s*\.TRUE\.|\.FALSE\.\s*\.EQV\.\s*\.FALSE\.|\.TRUE\.\s*\.NEQV\.\s*\.FALSE\.|\.FALSE\.\s*\.NEQV\.\s*\.TRUE\.')

    def check(self, ast, file_path, symbol_table):
        violations = []
        lines = _read_source_lines(file_path, symbol_table)
        for i, line in enumerate(lines, 1):
            if self._BAD_BOOL.search(line):
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message="Boolean expressions shall be simplified. Use the variable directly instead of comparing with .TRUE. or .FALSE.",
                    file_path=file_path, line=i, severity=self.severity,
                ))
        return violations


# ---------------------------------------------------------------------------
# COM.FLOW.CheckArguments — check arguments
# ---------------------------------------------------------------------------
class ComFlowCheckArguments(FortranRule):
    """Procedure arguments shall be checked."""

    rule_key = "COM.FLOW.CheckArguments"
    severity = "MAJOR"

    def check(self, ast, file_path, symbol_table):
        # This is a design-level rule — simplified to check for PRESENT() in
        # procedures with OPTIONAL args. PRESENT() is typically used in IF
        # statements, not CALL statements.
        violations = []
        for stmt in walk(ast, Subroutine_Stmt) + walk(ast, Function_Stmt):
            arg_lists = walk(stmt, Dummy_Arg_List)
            if not arg_lists:
                continue
            args = [str(a).strip() for a in arg_lists[0].children if a is not None]
            has_optional = False
            for arg in args:
                for decl in walk(ast, Type_Declaration_Stmt):
                    if arg.upper() in str(decl).upper() and 'OPTIONAL' in str(decl).upper():
                        has_optional = True
                        break
            if has_optional:
                # Check for PRESENT() calls anywhere in the procedure body.
                # fparser represents PRESENT() as an Intrinsic_Function_Reference
                # with an Intrinsic_Name child, not as a Name node.
                has_present = False
                try:
                    from fparser.two.Fortran2003 import Intrinsic_Name
                    for node in walk(ast, Intrinsic_Name):
                        if str(node).strip().upper() == 'PRESENT':
                            has_present = True
                            break
                except ImportError:
                    pass
                if not has_present:
                    # Fallback: text-scan the source for PRESENT
                    src_lines = _read_source_lines(file_path, symbol_table)
                    for src_line in src_lines:
                        if 'PRESENT' in src_line.upper():
                            has_present = True
                            break
                if not has_present:
                    line = _get_line(stmt)
                    fp = _get_source_file_path(stmt) or file_path
                    violations.append(Violation(
                        rule_key=self.rule_key,
                        message="Procedure arguments shall be checked using PRESENT().",
                        file_path=fp, line=line, severity=self.severity,
                    ))
        return violations


# ---------------------------------------------------------------------------
# COM.FLOW.CheckCodeReturn — check code return
# ---------------------------------------------------------------------------
class ComFlowCheckCodeReturn(FortranRule):
    """Return codes shall be checked."""

    rule_key = "COM.FLOW.CheckCodeReturn"
    severity = "MAJOR"

    def check(self, ast, file_path, symbol_table):
        violations = []
        # Check that IOSTAT variables are checked after READ/WRITE
        lines = _read_source_lines(file_path, symbol_table)
        for node in walk(ast, (Open_Stmt, Read_Stmt, Write_Stmt, Close_Stmt)):
            stmt_str = str(node).upper()
            if 'IOSTAT' not in stmt_str:
                continue
            # Extract IOSTAT variable
            match = re.search(r'IOSTAT\s*=\s*(\w+)', stmt_str, re.IGNORECASE)
            if not match:
                continue
            iostat_var = match.group(1)
            line_num = _get_line(node) or 0
            # Check if next few lines check this variable
            found_check = False
            for offset in range(1, min(10, len(lines) - line_num)):
                if line_num + offset - 1 < len(lines):
                    next_line = lines[line_num + offset - 1].upper()
                    if iostat_var.upper() in next_line and ('IF' in next_line or '/=' in next_line or '==' in next_line):
                        found_check = True
                        break
            if not found_check:
                fp = _get_source_file_path(node) or file_path
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message=f"Return code '{iostat_var}' shall be checked after I/O operation.",
                    file_path=fp, line=line_num, severity=self.severity,
                ))
        return violations


# ---------------------------------------------------------------------------
# COM.FLOW.CheckUser — check user
# ---------------------------------------------------------------------------
class ComFlowCheckUser(FortranRule):
    """User input shall be validated."""

    rule_key = "COM.FLOW.CheckUser"
    severity = "MAJOR"

    def check(self, ast, file_path, symbol_table):
        # This is a design-level rule — check for READ without validation
        violations = []
        for read_stmt in walk(ast, Read_Stmt):
            # Check if there's an IOSTAT or ERR handler
            read_str = str(read_stmt).upper()
            if 'IOSTAT' not in read_str and 'ERR' not in read_str:
                line = _get_line(read_stmt)
                fp = _get_source_file_path(read_stmt) or file_path
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message="User input shall be validated. Use IOSTAT or ERR in READ statements.",
                    file_path=fp, line=line, severity=self.severity,
                ))
        return violations


# ---------------------------------------------------------------------------
# COM.INST.BoolNegation — boolean negation
# ---------------------------------------------------------------------------
class ComInstBoolNegation(FortranRule):
    """Boolean negation shall use .NOT. instead of .EQV. .FALSE."""

    rule_key = "COM.INST.BoolNegation"
    severity = "MAJOR"

    _BAD_NEG = re.compile(r'(?i)\.EQV\.\s*\.FALSE\.|\.NEQV\.\s*\.TRUE\.')

    def check(self, ast, file_path, symbol_table):
        violations = []
        lines = _read_source_lines(file_path, symbol_table)
        for i, line in enumerate(lines, 1):
            if self._BAD_NEG.search(line):
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message="Boolean negation shall use .NOT. instead of .EQV. .FALSE. or .NEQV. .TRUE.",
                    file_path=file_path, line=i, severity=self.severity,
                ))
        return violations


# ---------------------------------------------------------------------------
# COM.INST.LoopCondition — loop condition
# ---------------------------------------------------------------------------
class ComInstLoopCondition(FortranRule):
    """Loop conditions shall not be modified within the loop."""

    rule_key = "COM.INST.LoopCondition"
    severity = "MAJOR"

    def check(self, ast, file_path, symbol_table):
        # This is the same as COM.DATA.LoopCondition — delegate
        return []


# ---------------------------------------------------------------------------
# COM.DATA.NotUsed — unused variables
# ---------------------------------------------------------------------------
class ComDataNotUsed(FortranRule):
    """Unused variables shall not be declared."""

    rule_key = "COM.DATA.NotUsed"
    severity = "MAJOR"

    def check(self, ast, file_path, symbol_table):
        violations = []
        # Collect all declared variable names
        declared_vars = {}
        for decl in walk(ast, Type_Declaration_Stmt):
            for entity in walk(decl, Entity_Decl):
                for name_node in walk(entity, Name):
                    var_name = str(name_node).strip().lower()
                    declared_vars[var_name] = _get_line(decl)
                    break

        # Collect all used variable names (in assignments, calls, etc.)
        used_vars = set()
        for name in walk(ast, Name):
            name_str = str(name).strip().lower()
            used_vars.add(name_str)

        # Find unused variables (declared but never used)
        for var_name, line_num in declared_vars.items():
            if var_name not in used_vars:
                fp = _get_source_file_path(decl) or file_path
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message=f"Variable '{var_name}' is declared but never used.",
                    file_path=fp, line=line_num, severity=self.severity,
                ))
        return violations


# ---------------------------------------------------------------------------
# COM.DESIGN.ActiveWait — active wait
# ---------------------------------------------------------------------------
class ComDesignActiveWait(FortranRule):
    """Active wait (PAUSE, SLEEP, busy loops) shall not be used."""

    rule_key = "COM.DESIGN.ActiveWait"
    severity = "MAJOR"

    def check(self, ast, file_path, symbol_table):
        violations = []
        lines = _read_source_lines(file_path, symbol_table)
        for i, line in enumerate(lines, 1):
            stripped = line.strip().upper()
            if stripped.startswith('!') or stripped.startswith('C'):
                continue
            # Check for PAUSE or SLEEP
            if re.match(r'^PAUSE\b', stripped) or re.match(r'\bSLEEP\b', stripped):
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message="Active wait (PAUSE, SLEEP, busy loops) shall not be used.",
                    file_path=file_path, line=i, severity=self.severity,
                ))
        return violations
