"""Batch 4: Naming, formatting & presentation rules.

Rules that check naming conventions, indentation, comments, and
presentation style.  These are mostly text-scan rules.

Rules implemented (20):
  - COM.INST.Line            (one statement per line)
  - F90.NAME.KeyWords        (keywords uppercase, not used as variables)
  - COM.NAME.Homonymy        (identifier uniqueness)
  - COM.PRES.Data            (variables commented)
  - COM.PRES.Indent          (indentation with spaces)
  - COM.PRES.LengthLine      (line length ≤ 120)
  - COM.PRES.FileLength      (file length ≤ 1500)
  - COM.PROJECT.Header       (subroutine/function header)
  - F90.FILE.Header          (file header)
  - EUM.PRES.NoTabs          (no tab characters)
  - EUM.PRES.IndentLevel     (2-space indentation)
  - EUM.PRES.LabelJustify    (labels at column 1)
  - EUM.PRES.BlockAlign      (control blocks aligned)
  - EUM.PRES.CommentPos      (comments before control statements)
  - EUM.PRES.NoCommentMultiLine (no comments between continuations)
  - EUM.PRES.NoEndLineComment (no end-of-line comments)
  - EUM.PRES.NoEmptyComment  (no empty comment lines)
  - EUM.PRES.Doxygen         (!> allowed, !< not)
  - EUM.PRES.CommentBlock    (comment before ≥5-line constructs)
  - EUM.PRES.BlankLines      (max 2 consecutive blank lines)
"""

from __future__ import annotations

import os
import re
from typing import List

from fparser.two.Fortran2003 import (
    Call_Stmt,
    Do_Construct,
    If_Construct,
    If_Stmt,
    Name,
    Program,
    Read_Stmt,
    Select_Type_Construct,
    Type_Declaration_Stmt,
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
# COM.INST.Line — one statement per line
# ---------------------------------------------------------------------------
class ComInstLine(FortranRule):
    """There shall be one single executable statement per source code line."""

    rule_key = "COM.INST.Line"
    severity = "MAJOR"

    # Detect semicolons used to separate statements on one line
    _SEMICOLON = re.compile(r';')

    def check(self, ast, file_path, symbol_table):
        violations = []
        lines = _read_source_lines(file_path, symbol_table)
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('!'):
                continue
            # Strip inline comments (respecting string literals)
            code_part = stripped
            in_string = False
            quote_char = None
            for idx, ch in enumerate(code_part):
                if ch in ('"', "'"):
                    if not in_string:
                        in_string = True
                        quote_char = ch
                    elif ch == quote_char:
                        in_string = False
                        quote_char = None
                elif ch == '!' and not in_string:
                    code_part = code_part[:idx]
                    break
            # Count semicolons (but not inside strings)
            in_string = False
            quote_char = None
            semicolon_count = 0
            for ch in code_part:
                if ch in ('"', "'"):
                    if not in_string:
                        in_string = True
                        quote_char = ch
                    elif ch == quote_char:
                        in_string = False
                        quote_char = None
                elif ch == ';' and not in_string:
                    semicolon_count += 1
            if semicolon_count > 0:
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message="There shall be one single executable statement per source code line.",
                    file_path=file_path, line=i, severity=self.severity,
                ))
        return violations


# ---------------------------------------------------------------------------
# F90.NAME.KeyWords — keywords uppercase, not used as variables
# ---------------------------------------------------------------------------
class F90NameKeyWords(FortranRule):
    """FORTRAN keywords shall be written in uppercase and not used as variable names."""

    rule_key = "F90.NAME.KeyWords"
    severity = "MAJOR"

    _KEYWORDS = {
        'program', 'module', 'subroutine', 'function', 'end', 'if', 'then',
        'else', 'elseif', 'do', 'while', 'select', 'case', 'where', 'forall',
        'interface', 'type', 'use', 'implicit', 'none', 'parameter', 'allocatable',
        'pointer', 'target', 'intent', 'in', 'out', 'inout', 'public', 'private',
        'contains', 'return', 'call', 'allocate', 'deallocate', 'nullify',
        'open', 'close', 'read', 'write', 'print', 'format', 'inquire',
        'backspace', 'rewind', 'flush', 'wait', 'stop', 'pause', 'go', 'to',
        'goto', 'continue', 'exit', 'cycle', 'assign', 'equivalence', 'common',
        'block', 'data', 'namelist', 'external', 'save', 'dimension',
        'character', 'integer', 'real', 'double', 'precision', 'complex',
        'logical', 'entry', 'include', 'associate', 'block', 'critical',
        'enum', 'final', 'generic', 'procedure', 'abstract', 'class',
        'sequence', 'volatile', 'asynchronous', 'value', 'pass', 'nopass',
        'deferred', 'non_overridable', 'extends', 'import', 'entry',
    }

    def check(self, ast, file_path, symbol_table):
        violations = []
        lines = _read_source_lines(file_path, symbol_table)
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('!'):
                continue
            # Strip inline comments (respecting string literals)
            code_part = stripped
            in_string = False
            quote_char = None
            for idx, ch in enumerate(code_part):
                if ch in ('"', "'"):
                    if not in_string:
                        in_string = True
                        quote_char = ch
                    elif ch == quote_char:
                        in_string = False
                        quote_char = None
                elif ch == '!' and not in_string:
                    code_part = code_part[:idx].strip()
                    break
            if not code_part:
                continue
            # Check for lowercase keywords at start of statement
            # Match word boundaries
            for match in re.finditer(r'\b([a-zA-Z]+)\b', code_part):
                word = match.group(1).lower()
                if word in self._KEYWORDS and match.group(1) != match.group(1).upper():
                    # Only flag if it's clearly a keyword usage (start of statement)
                    pos = match.start()
                    if pos == 0 or code_part[:pos].strip() == '':
                        violations.append(Violation(
                            rule_key=self.rule_key,
                            message=f"FORTRAN keyword '{match.group(1)}' shall be written in uppercase.",
                            file_path=file_path, line=i, severity=self.severity,
                        ))
                        break  # One per line
        return violations


# ---------------------------------------------------------------------------
# COM.NAME.Homonymy — identifier uniqueness
# ---------------------------------------------------------------------------
class ComNameHomonymy(FortranRule):
    """Identifier names for PROGRAMs, MODULEs, SUBROUTINEs, FUNCTIONs and PUBLIC variables shall be unique."""

    rule_key = "COM.NAME.Homonymy"
    severity = "MAJOR"

    def check(self, ast, file_path, symbol_table):
        violations = []
        # This is a project-wide check — we check within the current file
        # for duplicate procedure names
        from fparser.two.Fortran2003 import Subroutine_Stmt, Function_Stmt, Module_Stmt, Program_Stmt

        seen_names = {}
        for stmt_list, kind in [
            (walk(ast, Subroutine_Stmt), 'subroutine'),
            (walk(ast, Function_Stmt), 'function'),
            (walk(ast, Module_Stmt), 'module'),
            (walk(ast, Program_Stmt), 'program'),
        ]:
            for stmt in stmt_list:
                for child in stmt.children:
                    if isinstance(child, Name):
                        name = str(child).strip().lower()
                        if name in seen_names:
                            line = _get_line(stmt)
                            fp = _get_source_file_path(stmt) or file_path
                            violations.append(Violation(
                                rule_key=self.rule_key,
                                message=f"Identifier '{str(child).strip()}' is not unique (also defined as {seen_names[name]}).",
                                file_path=fp, line=line, severity=self.severity,
                            ))
                        else:
                            seen_names[name] = kind
        return violations


# ---------------------------------------------------------------------------
# COM.PRES.Data — variables commented
# ---------------------------------------------------------------------------
class ComPresData(FortranRule):
    """The declaration of variables and types shall be preceded by a comment line."""

    rule_key = "COM.PRES.Data"
    severity = "MAJOR"

    def check(self, ast, file_path, symbol_table):
        violations = []
        lines = _read_source_lines(file_path, symbol_table)
        if not lines:
            return violations

        # Collect all declaration line numbers, then only flag the *first*
        # declaration in a group of consecutive declarations (the CNES rule
        # intent is that a declaration *block* be preceded by a comment,
        # not every individual line).
        decl_lines = set()
        for node in walk(ast, Type_Declaration_Stmt):
            line_num = _get_line(node)
            if line_num:
                decl_lines.add(line_num)

        for node in walk(ast, Type_Declaration_Stmt):
            line_num = _get_line(node)
            if not line_num or line_num <= 1:
                continue
            # Skip if the previous line is also a declaration — only flag
            # the first declaration in a group.
            if (line_num - 1) in decl_lines:
                continue
            # Check if previous line is a comment (skip blank lines)
            idx = line_num - 2  # 0-based index for previous line
            while 0 <= idx < len(lines):
                prev_line = lines[idx].strip()
                if prev_line == '':
                    # Skip blank lines — look further back
                    idx -= 1
                    continue
                break
            else:
                prev_line = ""
            if not prev_line.startswith('!'):
                fp = _get_source_file_path(node) or file_path
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message="The declaration of variables and types shall be preceded by a comment line.",
                    file_path=fp, line=line_num, severity=self.severity,
                ))
        return violations


# ---------------------------------------------------------------------------
# COM.PRES.Indent — indentation with spaces
# ---------------------------------------------------------------------------
class ComPresIndent(FortranRule):
    """Indentation shall use spaces, not tabs."""

    rule_key = "COM.PRES.Indent"
    severity = "MAJOR"

    def check(self, ast, file_path, symbol_table):
        violations = []
        lines = _read_source_lines(file_path, symbol_table)
        for i, line in enumerate(lines, 1):
            if '\t' in line:
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message="Indentation shall use blank characters, not tabs.",
                    file_path=file_path, line=i, severity=self.severity,
                ))
        return violations


# ---------------------------------------------------------------------------
# COM.PRES.LengthLine — line length ≤ 120
# ---------------------------------------------------------------------------
class ComPresLengthLine(FortranRule):
    """The length of each line of code shall be restricted to 120 characters."""

    rule_key = "COM.PRES.LengthLine"
    severity = "MAJOR"

    MAX_LENGTH = 120

    def check(self, ast, file_path, symbol_table):
        violations = []
        lines = _read_source_lines(file_path, symbol_table)
        for i, line in enumerate(lines, 1):
            # Strip trailing newline
            line_len = len(line.rstrip('\n\r'))
            if line_len > self.MAX_LENGTH:
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message=f"Line length {line_len} exceeds the maximum of {self.MAX_LENGTH} characters.",
                    file_path=file_path, line=i, severity=self.severity,
                ))
        return violations


# ---------------------------------------------------------------------------
# COM.PRES.FileLength — file length ≤ 1500
# ---------------------------------------------------------------------------
class ComPresFileLength(FortranRule):
    """Maximum number of lines of code in a program or module shall be 1500."""

    rule_key = "COM.PRES.FileLength"
    severity = "MAJOR"

    MAX_LINES = 1500

    def check(self, ast, file_path, symbol_table):
        violations = []
        lines = _read_source_lines(file_path, symbol_table)
        if len(lines) > self.MAX_LINES:
            violations.append(Violation(
                rule_key=self.rule_key,
                message=f"File has {len(lines)} lines, exceeding the maximum of {self.MAX_LINES}.",
                file_path=file_path, line=1, severity=self.severity,
            ))
        return violations


# ---------------------------------------------------------------------------
# COM.PROJECT.Header — subroutine/function header
# ---------------------------------------------------------------------------
class ComProjectHeader(FortranRule):
    """Each function or subroutine shall have a header."""

    rule_key = "COM.PROJECT.Header"
    severity = "MAJOR"

    _HEADER_KEYWORDS = ['Name:', 'Purpose:', 'Argument', 'Returns:']

    def check(self, ast, file_path, symbol_table):
        violations = []
        from fparser.two.Fortran2003 import Subroutine_Stmt, Function_Stmt
        lines = _read_source_lines(file_path, symbol_table)
        if not lines:
            return violations

        for stmt in walk(ast, Subroutine_Stmt) + walk(ast, Function_Stmt):
            line_num = _get_line(stmt)
            if not line_num:
                continue
            # Check preceding lines for header comments
            has_header = False
            for offset in range(1, min(20, line_num)):
                idx = line_num - 1 - offset
                if 0 <= idx < len(lines):
                    prev = lines[idx].strip()
                else:
                    prev = ""
                if prev.startswith('!') and any(kw.lower() in prev.lower() for kw in self._HEADER_KEYWORDS):
                    has_header = True
                    break
                if prev and not prev.startswith('!') and not prev.startswith('c') and not prev.startswith('C'):
                    break  # Hit code, stop
            if not has_header:
                fp = _get_source_file_path(stmt) or file_path
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message="Each function or subroutine shall have a header.",
                    file_path=fp, line=line_num, severity=self.severity,
                ))
        return violations


# ---------------------------------------------------------------------------
# F90.FILE.Header — file header
# ---------------------------------------------------------------------------
class F90FileHeader(FortranRule):
    """Each programming unit shall have a file header."""

    rule_key = "F90.FILE.Header"
    severity = "MAJOR"

    _HEADER_KEYWORDS = ['component name:', 'file:', 'author:', 'copyright:', 'description:']

    def check(self, ast, file_path, symbol_table):
        violations = []
        lines = _read_source_lines(file_path, symbol_table)
        if not lines:
            return violations

        # Check first 30 lines for header
        header_text = ' '.join(lines[:30]).lower()
        has_header = any(kw in header_text for kw in self._HEADER_KEYWORDS)
        if not has_header:
            violations.append(Violation(
                rule_key=self.rule_key,
                message="Each programming unit shall have a header with Component Name, File, Author, Copyright, and Description.",
                file_path=file_path, line=1, severity=self.severity,
            ))
        return violations


# ---------------------------------------------------------------------------
# EUM.PRES.NoTabs — no tab characters
# ---------------------------------------------------------------------------
class EumPresNoTabs(FortranRule):
    """The TAB character shall not be used."""

    rule_key = "EUM.PRES.NoTabs"
    severity = "INFO"

    def check(self, ast, file_path, symbol_table):
        violations = []
        lines = _read_source_lines(file_path, symbol_table)
        for i, line in enumerate(lines, 1):
            if '\t' in line:
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message="The TAB character shall not be used.",
                    file_path=file_path, line=i, severity=self.severity,
                ))
        return violations


# ---------------------------------------------------------------------------
# EUM.PRES.IndentLevel — 2-space indentation
# ---------------------------------------------------------------------------
class EumPresIndentLevel(FortranRule):
    """Each level of indentation shall consist of two blank spaces."""

    rule_key = "EUM.PRES.IndentLevel"
    severity = "INFO"

    def check(self, ast, file_path, symbol_table):
        violations = []
        lines = _read_source_lines(file_path, symbol_table)
        for i, line in enumerate(lines, 1):
            # Check leading whitespace
            leading = len(line) - len(line.lstrip(' '))
            if leading > 0 and leading % 2 != 0:
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message="Each level of indentation shall consist of two blank spaces.",
                    file_path=file_path, line=i, severity=self.severity,
                ))
        return violations


# ---------------------------------------------------------------------------
# EUM.PRES.LabelJustify — labels at column 1
# ---------------------------------------------------------------------------
class EumPresLabelJustify(FortranRule):
    """Labels shall be left justified to the same column."""

    rule_key = "EUM.PRES.LabelJustify"
    severity = "INFO"

    _LABEL = re.compile(r'^(\s*)(\d{1,5})\s')

    def check(self, ast, file_path, symbol_table):
        violations = []
        lines = _read_source_lines(file_path, symbol_table)
        for i, line in enumerate(lines, 1):
            match = self._LABEL.match(line)
            if match and len(match.group(1)) > 0:
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message="Labels shall be left justified to the first column.",
                    file_path=file_path, line=i, severity=self.severity,
                ))
        return violations


# ---------------------------------------------------------------------------
# EUM.PRES.BlockAlign — control blocks aligned
# ---------------------------------------------------------------------------
class EumPresBlockAlign(FortranRule):
    """Control blocks shall be properly aligned."""

    rule_key = "EUM.PRES.BlockAlign"
    severity = "INFO"

    def check(self, ast, file_path, symbol_table):
        violations = []
        lines = _read_source_lines(file_path, symbol_table)
        if not lines:
            return violations

        # Track DO/IF/SELECT nesting and check alignment
        stack = []  # (keyword, indent, line_num)
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith('!'):
                continue
            indent = len(line) - len(line.lstrip())

            # Check for block-starting keywords
            for kw in ['DO', 'IF', 'SELECT CASE', 'WHERE', 'FORALL']:
                if re.match(rf'(?i)^\s*{re.escape(kw)}\b', stripped):
                    stack.append((kw, indent, i))
                    break

            # Check for block-ending keywords
            for kw in ['END DO', 'END IF', 'END SELECT', 'END WHERE', 'END FORALL',
                       'ENDDO', 'ENDIF', 'ENDSELECT']:
                if re.match(rf'(?i)^\s*{re.escape(kw)}\b', stripped):
                    if stack:
                        start_kw, start_indent, start_line = stack.pop()
                        if indent != start_indent:
                            violations.append(Violation(
                                rule_key=self.rule_key,
                                message=f"Control block starting at line {start_line} is not properly aligned (indent {start_indent} vs {indent}).",
                                file_path=file_path, line=i, severity=self.severity,
                            ))
                    break
        return violations


# ---------------------------------------------------------------------------
# EUM.PRES.CommentPos — comments before control statements
# ---------------------------------------------------------------------------
class EumPresCommentPos(FortranRule):
    """Comments shall precede control statements (IF, DO, SELECT CASE, CALL, READ, WRITE)."""

    rule_key = "EUM.PRES.CommentPos"
    severity = "MINOR"

    _CONTROL_KEYWORDS = re.compile(
        r'(?i)^\s*(IF\s*\(.*\)\s*THEN\b|DO\s|SELECT\s+CASE)'
    )

    def check(self, ast, file_path, symbol_table):
        violations = []
        lines = _read_source_lines(file_path, symbol_table)
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith('!'):
                continue
            if self._CONTROL_KEYWORDS.match(line):
                # Check if previous line is a comment
                if i > 1:
                    prev = lines[i - 2].strip()
                    if not prev.startswith('!'):
                        violations.append(Violation(
                            rule_key=self.rule_key,
                            message="Comments shall precede control statements (IF, DO, SELECT CASE, CALL, READ, WRITE).",
                            file_path=file_path, line=i, severity=self.severity,
                        ))
        return violations


# ---------------------------------------------------------------------------
# EUM.PRES.NoCommentMultiLine — no comments between continuations
# ---------------------------------------------------------------------------
class EumPresNoCommentMultiLine(FortranRule):
    """Comments shall not be inserted between continuation lines."""

    rule_key = "EUM.PRES.NoCommentMultiLine"
    severity = "INFO"

    def check(self, ast, file_path, symbol_table):
        violations = []
        lines = _read_source_lines(file_path, symbol_table)
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            # Check if this line ends with continuation &
            if stripped.endswith('&'):
                # Check if next non-blank line is a comment
                for j in range(i, min(i + 5, len(lines))):
                    next_stripped = lines[j].strip()
                    if not next_stripped:
                        continue
                    if next_stripped.startswith('!'):
                        violations.append(Violation(
                            rule_key=self.rule_key,
                            message="Comments shall not be inserted between continuation lines.",
                            file_path=file_path, line=j + 1, severity=self.severity,
                        ))
                    break
        return violations


# ---------------------------------------------------------------------------
# EUM.PRES.NoEndLineComment — no end-of-line comments
# ---------------------------------------------------------------------------
class EumPresNoEndLineComment(FortranRule):
    """End-of-line comments shall not be used."""

    rule_key = "EUM.PRES.NoEndLineComment"
    severity = "INFO"

    def check(self, ast, file_path, symbol_table):
        violations = []
        lines = _read_source_lines(file_path, symbol_table)
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped:
                continue
            # Check for ! after code (not at start of line)
            if '!' in stripped and not stripped.startswith('!'):
                # Find the ! position
                in_string = False
                quote_char = None
                for idx, ch in enumerate(stripped):
                    if ch in ('"', "'"):
                        if not in_string:
                            in_string = True
                            quote_char = ch
                        elif ch == quote_char:
                            in_string = False
                            quote_char = None
                    elif ch == '!' and not in_string:
                        violations.append(Violation(
                            rule_key=self.rule_key,
                            message="End-of-line comments shall not be used.",
                            file_path=file_path, line=i, severity=self.severity,
                        ))
                        break
        return violations


# ---------------------------------------------------------------------------
# EUM.PRES.NoEmptyComment — no empty comment lines
# ---------------------------------------------------------------------------
class EumPresNoEmptyComment(FortranRule):
    """Empty comment lines shall not be used."""

    rule_key = "EUM.PRES.NoEmptyComment"
    severity = "INFO"

    def check(self, ast, file_path, symbol_table):
        violations = []
        lines = _read_source_lines(file_path, symbol_table)
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped == '!' or stripped == '!':
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message="Empty comment lines shall not be used. Use empty lines instead.",
                    file_path=file_path, line=i, severity=self.severity,
                ))
        return violations


# ---------------------------------------------------------------------------
# EUM.PRES.Doxygen — !> allowed, !< not
# ---------------------------------------------------------------------------
class EumPresDoxygen(FortranRule):
    """Doxygen comment codes should be used when declaring a function."""

    rule_key = "EUM.PRES.Doxygen"
    severity = "INFO"

    _BAD_DOXYGEN = re.compile(r'!<')

    def check(self, ast, file_path, symbol_table):
        violations = []
        lines = _read_source_lines(file_path, symbol_table)
        for i, line in enumerate(lines, 1):
            if self._BAD_DOXYGEN.search(line):
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message="Doxygen comment '!<' is not allowed. Use '!>' instead.",
                    file_path=file_path, line=i, severity=self.severity,
                ))
        return violations


# ---------------------------------------------------------------------------
# EUM.PRES.CommentBlock — comment before ≥5-line constructs
# ---------------------------------------------------------------------------
class EumPresCommentBlock(FortranRule):
    """Comment blocks shall be placed at the start of large control constructs."""

    rule_key = "EUM.PRES.CommentBlock"
    severity = "MINOR"

    def check(self, ast, file_path, symbol_table):
        violations = []
        lines = _read_source_lines(file_path, symbol_table)
        if not lines:
            return violations

        # Find IF/DO constructs and count their lines
        for construct in walk(ast, (If_Construct, Do_Construct)):
            start_line = _get_line(construct)
            if not start_line:
                continue
            # Estimate construct size by finding the END statement
            end_line = start_line
            from fparser.two.Fortran2003 import End_If_Stmt, End_Do_Stmt
            ends = walk(construct, (End_If_Stmt, End_Do_Stmt))
            if ends:
                end_line = _get_line(ends[-1]) or start_line

            construct_size = end_line - start_line
            if construct_size >= 5:
                # Check if preceding line is a comment
                if start_line > 1:
                    idx = start_line - 2
                    if 0 <= idx < len(lines):
                        prev = lines[idx].strip()
                    else:
                        prev = ""
                    if not prev.startswith('!'):
                        fp = _get_source_file_path(construct) or file_path
                        violations.append(Violation(
                            rule_key=self.rule_key,
                            message="Comment blocks shall be placed at the start of large control constructs (≥5 lines).",
                            file_path=fp, line=start_line, severity=self.severity,
                        ))
        return violations


# ---------------------------------------------------------------------------
# EUM.PRES.BlankLines — max 2 consecutive blank lines
# ---------------------------------------------------------------------------
class EumPresBlankLines(FortranRule):
    """Blank lines shall not exceed 2 consecutive lines."""

    rule_key = "EUM.PRES.BlankLines"
    severity = "INFO"

    def check(self, ast, file_path, symbol_table):
        violations = []
        lines = _read_source_lines(file_path, symbol_table)
        blank_count = 0
        for i, line in enumerate(lines, 1):
            if line.strip() == '':
                blank_count += 1
                if blank_count > 2:
                    violations.append(Violation(
                        rule_key=self.rule_key,
                        message="Blank lines shall not exceed 2 consecutive lines.",
                        file_path=file_path, line=i, severity=self.severity,
                    ))
            else:
                blank_count = 0
        return violations
