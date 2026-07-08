"""Batch 5: Metrics & complexity rules.

Rules that measure code metrics like file length, procedure length,
cyclomatic complexity, comment ratio, and count-based limits.

Rules implemented (8):
  - COM.MET.LineOfCode        (procedure ≤ 100 lines)
  - COM.MET.ComplexitySimplified (cyclomatic complexity ≤ 10)
  - COM.MET.RatioComment      (comment ratio ≥ 30%)
  - EUM.MET.MaxProcedures     (≤ 20 procedures per module)
  - EUM.MET.MaxArguments      (≤ 10 arguments per procedure)
  - EUM.MET.MaxAttributes     (≤ 10 attributes per type declaration)
  - EUM.MET.MaxContinuation   (≤ 10 continuation lines)
  - COM.INST.Brace            (braces/parentheses balanced)
"""

from __future__ import annotations

import os
import re
from typing import List

from fparser.two.Fortran2003 import (
    Case_Stmt,
    Continue_Stmt,
    Do_Construct,
    Else_If_Stmt,
    Function_Stmt,
    Goto_Stmt,
    If_Construct,
    If_Stmt,
    Module_Stmt,
    Name,
    Return_Stmt,
    Subroutine_Stmt,
    Type_Declaration_Stmt,
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
# COM.MET.LineOfCode — procedure ≤ 100 lines
# ---------------------------------------------------------------------------
class ComMetLineOfCode(FortranRule):
    """The number of lines of code of a function or subroutine shall not exceed 100."""

    rule_key = "COM.MET.LineOfCode"
    severity = "MAJOR"

    MAX_LINES = 100

    def check(self, ast, file_path, symbol_table):
        violations = []
        lines = _read_source_lines(file_path, symbol_table)
        if not lines:
            return violations

        proc_stmts = walk(ast, Subroutine_Stmt) + walk(ast, Function_Stmt)
        for stmt in proc_stmts:
            start_line = _get_line(stmt) or 0
            if not start_line:
                continue
            end_line = self._find_end(lines, start_line)
            proc_lines = end_line - start_line
            if proc_lines > self.MAX_LINES:
                fp = _get_source_file_path(stmt) or file_path
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message=f"Procedure has {proc_lines} lines, exceeding the maximum of {self.MAX_LINES}.",
                    file_path=fp, line=start_line, severity=self.severity,
                ))
        return violations

    @staticmethod
    def _find_end(lines: List[str], start: int) -> int:
        """Find the END SUBROUTINE/FUNCTION line after start."""
        for i in range(start, len(lines)):
            stripped = lines[i].strip().upper()
            if re.match(r'^END\s*(SUBROUTINE|FUNCTION)', stripped):
                return i + 1
        return len(lines)


# ---------------------------------------------------------------------------
# COM.MET.ComplexitySimplified — cyclomatic complexity ≤ 10
# ---------------------------------------------------------------------------
class ComMetComplexitySimplified(FortranRule):
    """The cyclomatic complexity of a function or subroutine shall not exceed 10."""

    rule_key = "COM.MET.ComplexitySimplified"
    severity = "MAJOR"

    MAX_COMPLEXITY = 10

    def check(self, ast, file_path, symbol_table):
        violations = []
        lines = _read_source_lines(file_path, symbol_table)
        if not lines:
            return violations

        proc_stmts = walk(ast, Subroutine_Stmt) + walk(ast, Function_Stmt)
        for stmt in proc_stmts:
            start_line = _get_line(stmt) or 0
            if not start_line:
                continue
            end_line = ComMetLineOfCode._find_end(lines, start_line)
            complexity = self._compute_complexity(lines, start_line, end_line)
            if complexity > self.MAX_COMPLEXITY:
                fp = _get_source_file_path(stmt) or file_path
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message=f"Cyclomatic complexity {complexity} exceeds the maximum of {self.MAX_COMPLEXITY}.",
                    file_path=fp, line=start_line, severity=self.severity,
                ))
        return violations

    @staticmethod
    def _compute_complexity(lines: List[str], start: int, end: int) -> int:
        """Compute McCabe cyclomatic complexity for a code range."""
        complexity = 1
        for i in range(start - 1, min(end, len(lines))):
            line = lines[i].strip().upper()
            if line.startswith('!') or line.startswith('C'):
                continue
            complexity += len(re.findall(r'\bIF\b', line))
            complexity += len(re.findall(r'\bELSE\s*IF\b', line))
            complexity += len(re.findall(r'\bDO\b', line))
            complexity += len(re.findall(r'\bCASE\b', line))
            complexity += len(re.findall(r'\bWHERE\b', line))
            complexity += len(re.findall(r'\bFORALL\b', line))
            complexity += len(re.findall(r'\bGO\s*TO\b', line))
            complexity += len(re.findall(r'\bRETURN\b', line))
            complexity += len(re.findall(r'\bEXIT\b', line))
            complexity += len(re.findall(r'\bCYCLE\b', line))
            complexity += len(re.findall(r'\.OR\.', line))
            complexity += len(re.findall(r'\.AND\.', line))
        return complexity


# ---------------------------------------------------------------------------
# COM.MET.RatioComment — comment ratio ≥ 30%
# ---------------------------------------------------------------------------
class ComMetRatioComment(FortranRule):
    """The ratio of comment lines to total lines shall be at least 30%."""

    rule_key = "COM.MET.RatioComment"
    severity = "MAJOR"

    MIN_RATIO = 0.30

    def check(self, ast, file_path, symbol_table):
        violations = []
        lines = _read_source_lines(file_path, symbol_table)
        if not lines:
            return violations

        total_lines = len(lines)
        if total_lines == 0:
            return violations

        comment_lines = 0
        for line in lines:
            stripped = line.strip()
            if stripped.startswith('!') or stripped.startswith('c') or stripped.startswith('C'):
                comment_lines += 1

        ratio = comment_lines / total_lines
        if ratio < self.MIN_RATIO:
            violations.append(Violation(
                rule_key=self.rule_key,
                message=f"Comment ratio {ratio:.0%} is below the minimum of {self.MIN_RATIO:.0%}.",
                file_path=file_path, line=1, severity=self.severity,
            ))
        return violations


# ---------------------------------------------------------------------------
# EUM.MET.MaxProcedures — ≤ 20 procedures per module
# ---------------------------------------------------------------------------
class EumMetMaxProcedures(FortranRule):
    """The number of procedures in a module shall not exceed 20."""

    rule_key = "EUM.MET.MaxProcedures"
    severity = "INFO"

    MAX_PROCEDURES = 20

    def check(self, ast, file_path, symbol_table):
        violations = []
        from fparser.two.Fortran2003 import Module

        for module in walk(ast, Module):
            proc_count = len(walk(module, Subroutine_Stmt)) + len(walk(module, Function_Stmt))
            if proc_count > self.MAX_PROCEDURES:
                line = _get_line(module)
                fp = _get_source_file_path(module) or file_path
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message=f"Module has {proc_count} procedures, exceeding the maximum of {self.MAX_PROCEDURES}.",
                    file_path=fp, line=line, severity=self.severity,
                ))
        return violations


# ---------------------------------------------------------------------------
# EUM.MET.MaxArguments — ≤ 10 arguments per procedure
# ---------------------------------------------------------------------------
class EumMetMaxArguments(FortranRule):
    """The number of arguments of a function or subroutine shall not exceed 10."""

    rule_key = "EUM.MET.MaxArguments"
    severity = "INFO"

    MAX_ARGS = 10

    def check(self, ast, file_path, symbol_table):
        violations = []
        from fparser.two.Fortran2003 import Dummy_Arg_List

        for stmt in walk(ast, Subroutine_Stmt) + walk(ast, Function_Stmt):
            arg_lists = walk(stmt, Dummy_Arg_List)
            if arg_lists:
                arg_list = arg_lists[0]
                arg_count = 0
                if hasattr(arg_list, 'children'):
                    for child in arg_list.children:
                        if child is not None:
                            arg_count += 1
                if arg_count > self.MAX_ARGS:
                    line = _get_line(stmt)
                    fp = _get_source_file_path(stmt) or file_path
                    violations.append(Violation(
                        rule_key=self.rule_key,
                        message=f"Procedure has {arg_count} arguments, exceeding the maximum of {self.MAX_ARGS}.",
                        file_path=fp, line=line, severity=self.severity,
                    ))
        return violations


# ---------------------------------------------------------------------------
# EUM.MET.MaxAttributes — ≤ 10 attributes per type declaration
# ---------------------------------------------------------------------------
class EumMetMaxAttributes(FortranRule):
    """The number of attributes in a type declaration shall not exceed 10."""

    rule_key = "EUM.MET.MaxAttributes"
    severity = "INFO"

    MAX_ATTRS = 10

    def check(self, ast, file_path, symbol_table):
        violations = []
        from fparser.two.Fortran2003 import Attr_Spec_List

        for stmt in walk(ast, Type_Declaration_Stmt):
            attr_lists = walk(stmt, Attr_Spec_List)
            if attr_lists:
                attr_list = attr_lists[0]
                attr_count = 0
                if hasattr(attr_list, 'children'):
                    for child in attr_list.children:
                        if child is not None:
                            attr_count += 1
                if attr_count > self.MAX_ATTRS:
                    line = _get_line(stmt)
                    fp = _get_source_file_path(stmt) or file_path
                    violations.append(Violation(
                        rule_key=self.rule_key,
                        message=f"Type declaration has {attr_count} attributes, exceeding the maximum of {self.MAX_ATTRS}.",
                        file_path=fp, line=line, severity=self.severity,
                    ))
        return violations


# ---------------------------------------------------------------------------
# EUM.MET.MaxContinuation — ≤ 10 continuation lines
# ---------------------------------------------------------------------------
class EumMetMaxContinuation(FortranRule):
    """The number of continuation lines for a statement shall not exceed 10."""

    rule_key = "EUM.MET.MaxContinuation"
    severity = "INFO"

    MAX_CONT = 10

    def check(self, ast, file_path, symbol_table):
        violations = []
        lines = _read_source_lines(file_path, symbol_table)
        cont_count = 0
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.endswith('&'):
                cont_count += 1
                if cont_count > self.MAX_CONT:
                    violations.append(Violation(
                        rule_key=self.rule_key,
                        message=f"Statement has {cont_count} continuation lines, exceeding the maximum of {self.MAX_CONT}.",
                        file_path=file_path, line=i, severity=self.severity,
                    ))
            else:
                cont_count = 0
        return violations


# ---------------------------------------------------------------------------
# COM.INST.Brace — braces/parentheses balanced
# ---------------------------------------------------------------------------
class ComInstBrace(FortranRule):
    """Opening and closing parentheses shall be balanced on each line."""

    rule_key = "COM.INST.Brace"
    severity = "MAJOR"

    def check(self, ast, file_path, symbol_table):
        violations = []
        lines = _read_source_lines(file_path, symbol_table)
        # Track parenthesis balance across continuation lines.
        # In free-form Fortran, a line is a continuation if the previous
        # line ends with '&' (ignoring trailing comments).
        stmt_start = 0          # 0-based index of first line in current statement
        paren_depth = 0         # accumulated paren balance for current statement
        in_string = False
        quote_char = None

        for i, line in enumerate(lines):
            stripped = line.strip()
            # Skip pure comment lines (but NOT continuation lines that happen
            # to start with 'c'/'C' — those are rare in free-form).
            if stripped.startswith('!'):
                continue

            # Count parens in this line, respecting string literals.
            for ch in stripped:
                if ch in ('"', "'"):
                    if not in_string:
                        in_string = True
                        quote_char = ch
                    elif ch == quote_char:
                        in_string = False
                        quote_char = None
                elif not in_string:
                    if ch == '(':
                        paren_depth += 1
                    elif ch == ')':
                        paren_depth -= 1

            # Determine if this line is a continuation line (ends with '&'
            # before any trailing comment).
            code_part = stripped
            if '!' in code_part and not in_string:
                code_part = code_part[:code_part.index('!')].strip()
            is_continuation = code_part.endswith('&')

            if not is_continuation:
                # End of statement — check accumulated balance.
                if paren_depth != 0:
                    violations.append(Violation(
                        rule_key=self.rule_key,
                        message="Opening and closing parentheses shall be balanced on each line.",
                        file_path=file_path, line=stmt_start + 1, severity=self.severity,
                    ))
                # Reset for next statement.
                paren_depth = 0
                in_string = False
                quote_char = None
                stmt_start = i + 1
        return violations
