"""Batch 6: I/O, file, and miscellaneous coding rules.

Rules implemented (12):
  - F90.REF.Open            (OPEN statement parameters)
  - COM.FLOW.FilePath       (file path in OPEN)
  - F90.BLOC.File           (every open file is closed)
  - COM.FLOW.FileExistence  (file existence checked with INQUIRE)
  - EUM.INST.FormatStmt     (READ/WRITE use FORMAT labels)
  - EUM.INST.FormatPlacement (FORMAT at end of procedure)
  - EUM.INST.FreeFormatRead (READ uses * free format)
  - EUM.INST.CompilerExt    (compiler extensions forbidden)
  - EUM.INST.PercentBlank   (no spaces around %)
  - EUM.INST.Continuation   (& only at end of line)
  - EUM.NAME.FormatLabels   (FORMAT labels start at 1000, +10)
  - F90.DESIGN.IO           (I/O statements grouped)
"""

from __future__ import annotations

import os
import re
from typing import List

from fparser.two.Fortran2003 import (
    Close_Stmt,
    Format_Stmt,
    Inquire_Stmt,
    Open_Stmt,
    Read_Stmt,
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
# F90.REF.Open — OPEN statement parameters
# ---------------------------------------------------------------------------
class F90RefOpen(FortranRule):
    """OPEN statements shall contain FILE, STATUS, ACTION, IOSTAT parameters."""

    rule_key = "F90.REF.Open"
    severity = "MAJOR"

    _REQUIRED_PARAMS = ['FILE', 'STATUS', 'ACTION', 'IOSTAT']

    def check(self, ast, file_path, symbol_table):
        violations = []
        for open_stmt in walk(ast, Open_Stmt):
            stmt_str = str(open_stmt).upper()
            missing = [p for p in self._REQUIRED_PARAMS if p not in stmt_str]
            if missing:
                line = _get_line(open_stmt)
                fp = _get_source_file_path(open_stmt) or file_path
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message=f"OPEN statement shall contain FILE, STATUS, ACTION, IOSTAT parameters. Missing: {', '.join(missing)}.",
                    file_path=fp, line=line, severity=self.severity,
                ))
        return violations


# ---------------------------------------------------------------------------
# COM.FLOW.FilePath — file path in OPEN
# ---------------------------------------------------------------------------
class ComFlowFilePath(FortranRule):
    """The file path in OPEN statements shall not be hardcoded."""

    rule_key = "COM.FLOW.FilePath"
    severity = "MAJOR"

    _HARDCODED_PATH = re.compile(r"""FILE\s*=\s*['"](?:/|\\|\.\.|\w:)""", re.IGNORECASE)

    def check(self, ast, file_path, symbol_table):
        violations = []
        for open_stmt in walk(ast, Open_Stmt):
            stmt_str = str(open_stmt)
            if self._HARDCODED_PATH.search(stmt_str):
                line = _get_line(open_stmt)
                fp = _get_source_file_path(open_stmt) or file_path
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message="The file path in OPEN statements shall not be hardcoded.",
                    file_path=fp, line=line, severity=self.severity,
                ))
        return violations


# ---------------------------------------------------------------------------
# F90.BLOC.File — every open file is closed
# ---------------------------------------------------------------------------
class F90BlocFile(FortranRule):
    """Every opened file shall be closed."""

    rule_key = "F90.BLOC.File"
    severity = "MAJOR"

    def check(self, ast, file_path, symbol_table):
        violations = []
        # Collect unit numbers from OPEN and CLOSE
        open_units = set()
        close_units = set()

        for open_stmt in walk(ast, Open_Stmt):
            unit = self._extract_unit(str(open_stmt))
            if unit:
                open_units.add(unit.lower())

        for close_stmt in walk(ast, Close_Stmt):
            unit = self._extract_unit(str(close_stmt))
            if unit:
                close_units.add(unit.lower())

        # Check for unclosed units
        unclosed = open_units - close_units
        if unclosed:
            # Find the OPEN statements for unclosed units
            for open_stmt in walk(ast, Open_Stmt):
                unit = self._extract_unit(str(open_stmt))
                if unit and unit.lower() in unclosed:
                    line = _get_line(open_stmt)
                    fp = _get_source_file_path(open_stmt) or file_path
                    violations.append(Violation(
                        rule_key=self.rule_key,
                        message=f"File opened with unit {unit} shall be closed.",
                        file_path=fp, line=line, severity=self.severity,
                    ))
        return violations

    @staticmethod
    def _extract_unit(stmt_str: str) -> str:
        """Extract the unit number from an OPEN/CLOSE statement."""
        match = re.search(r'(?:OPEN|CLOSE)\s*\(\s*(?:UNIT\s*=\s*)?(\w+)', stmt_str, re.IGNORECASE)
        if match:
            return match.group(1)
        return ""


# ---------------------------------------------------------------------------
# COM.FLOW.FileExistence — file existence checked with INQUIRE
# ---------------------------------------------------------------------------
class ComFlowFileExistence(FortranRule):
    """File existence shall be checked with INQUIRE before opening."""

    rule_key = "COM.FLOW.FileExistence"
    severity = "MAJOR"

    def check(self, ast, file_path, symbol_table):
        violations = []
        has_inquire = bool(walk(ast, Inquire_Stmt))
        open_stmts = walk(ast, Open_Stmt)
        if open_stmts and not has_inquire:
            for open_stmt in open_stmts:
                line = _get_line(open_stmt)
                fp = _get_source_file_path(open_stmt) or file_path
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message="File existence shall be checked with INQUIRE before opening.",
                    file_path=fp, line=line, severity=self.severity,
                ))
        return violations


# ---------------------------------------------------------------------------
# EUM.INST.FormatStmt — READ/WRITE use FORMAT labels
# ---------------------------------------------------------------------------
class EumInstFormatStmt(FortranRule):
    """READ and WRITE statements shall use FORMAT statement labels, not inline format strings."""

    rule_key = "EUM.INST.FormatStmt"
    severity = "INFO"

    _INLINE_FMT = re.compile(r"""(READ|WRITE)\s*\([^)]*['"]""", re.IGNORECASE)

    def check(self, ast, file_path, symbol_table):
        violations = []
        lines = _read_source_lines(file_path, symbol_table)
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('!') or stripped.startswith('c') or stripped.startswith('C'):
                continue
            if self._INLINE_FMT.search(line):
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message="READ and WRITE statements shall use FORMAT statement labels, not inline format strings.",
                    file_path=file_path, line=i, severity=self.severity,
                ))
        return violations


# ---------------------------------------------------------------------------
# EUM.INST.FormatPlacement — FORMAT at end of procedure
# ---------------------------------------------------------------------------
class EumInstFormatPlacement(FortranRule):
    """FORMAT statements shall be placed at the end of the procedure scope."""

    rule_key = "EUM.INST.FormatPlacement"
    severity = "INFO"

    def check(self, ast, file_path, symbol_table):
        violations = []
        lines = _read_source_lines(file_path, symbol_table)
        if not lines:
            return violations

        # Find all FORMAT statements and check if they're near the end
        format_lines = []
        for node in walk(ast, Format_Stmt):
            line_num = _get_line(node)
            if line_num:
                format_lines.append(line_num)

        if not format_lines:
            return violations

        # Find procedure boundaries
        from fparser.two.Fortran2003 import Subroutine_Stmt, Function_Stmt
        proc_starts = []
        for stmt in walk(ast, Subroutine_Stmt) + walk(ast, Function_Stmt):
            line_num = _get_line(stmt)
            if line_num:
                proc_starts.append(line_num)

        # For each FORMAT, check if it's in the last 20% of its procedure
        for fmt_line in format_lines:
            # Find the procedure this FORMAT belongs to
            proc_start = 0
            proc_end = len(lines)
            for i, start in enumerate(proc_starts):
                if start < fmt_line:
                    proc_start = start
                    if i + 1 < len(proc_starts):
                        proc_end = proc_starts[i + 1] - 1
                else:
                    break

            proc_size = proc_end - proc_start
            threshold = proc_end - max(10, proc_size // 5)  # Last 20% or last 10 lines
            if fmt_line < threshold:
                fp = file_path
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message="FORMAT statements shall be placed at the end of the procedure scope.",
                    file_path=fp, line=fmt_line, severity=self.severity,
                ))
        return violations


# ---------------------------------------------------------------------------
# EUM.INST.FreeFormatRead — READ uses * free format
# ---------------------------------------------------------------------------
class EumInstFreeFormatRead(FortranRule):
    """READ statements shall use free format (*) for space-separated data."""

    rule_key = "EUM.INST.FreeFormatRead"
    severity = "INFO"

    _LABEL_READ = re.compile(r'\bREAD\s*\(\s*\w+\s*,\s*\d+', re.IGNORECASE)

    def check(self, ast, file_path, symbol_table):
        violations = []
        lines = _read_source_lines(file_path, symbol_table)
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('!') or stripped.startswith('c') or stripped.startswith('C'):
                continue
            if self._LABEL_READ.search(line):
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message="READ statements shall use free format (*) for space-separated data reading.",
                    file_path=file_path, line=i, severity=self.severity,
                ))
        return violations


# ---------------------------------------------------------------------------
# EUM.INST.CompilerExt — compiler extensions forbidden
# ---------------------------------------------------------------------------
class EumInstCompilerExt(FortranRule):
    """Compiler extensions shall not be used."""

    rule_key = "EUM.INST.CompilerExt"
    severity = "INFO"

    _EXT_PATTERNS = [
        re.compile(r'(?i)!DEC\$'),
        re.compile(r'(?i)!DIR\$'),
        re.compile(r'(?i)!GCC\$'),
        re.compile(r'(?i)\bBYTE\b'),
        re.compile(r'(?i)%VAL\b'),
        re.compile(r'(?i)%REF\b'),
        re.compile(r'(?i)%LOC\b'),
    ]

    def check(self, ast, file_path, symbol_table):
        violations = []
        lines = _read_source_lines(file_path, symbol_table)
        for i, line in enumerate(lines, 1):
            for pattern in self._EXT_PATTERNS:
                if pattern.search(line):
                    violations.append(Violation(
                        rule_key=self.rule_key,
                        message="Compiler extensions shall not be used.",
                        file_path=file_path, line=i, severity=self.severity,
                    ))
                    break
        return violations


# ---------------------------------------------------------------------------
# EUM.INST.PercentBlank — no spaces around %
# ---------------------------------------------------------------------------
class EumInstPercentBlank(FortranRule):
    """No blanks shall be used before or after the % operator."""

    rule_key = "EUM.INST.PercentBlank"
    severity = "INFO"

    _PERCENT_SPACE = re.compile(r'\s%\s*|%\s')

    def check(self, ast, file_path, symbol_table):
        violations = []
        lines = _read_source_lines(file_path, symbol_table)
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('!') or stripped.startswith('c') or stripped.startswith('C'):
                continue
            # Check for spaces around % (but not in strings)
            in_string = False
            quote_char = None
            for idx, ch in enumerate(line):
                if ch in ('"', "'"):
                    if not in_string:
                        in_string = True
                        quote_char = ch
                    elif ch == quote_char:
                        in_string = False
                        quote_char = None
                elif not in_string and ch == '%':
                    # Check before and after
                    if idx > 0 and line[idx - 1] == ' ':
                        violations.append(Violation(
                            rule_key=self.rule_key,
                            message="No blanks shall be used before or after the % operator.",
                            file_path=file_path, line=i, severity=self.severity,
                        ))
                        break
                    if idx < len(line) - 1 and line[idx + 1] == ' ':
                        violations.append(Violation(
                            rule_key=self.rule_key,
                            message="No blanks shall be used before or after the % operator.",
                            file_path=file_path, line=i, severity=self.severity,
                        ))
                        break
        return violations


# ---------------------------------------------------------------------------
# EUM.INST.Continuation — & only at end of line
# ---------------------------------------------------------------------------
class EumInstContinuation(FortranRule):
    """The continuation character & shall only be placed at the end of each line."""

    rule_key = "EUM.INST.Continuation"
    severity = "INFO"

    def check(self, ast, file_path, symbol_table):
        violations = []
        lines = _read_source_lines(file_path, symbol_table)
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('!') or stripped.startswith('c') or stripped.startswith('C'):
                continue
            # Check for & not at end of line (after stripping)
            if '&' in stripped:
                # Find all & positions
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
                    elif not in_string and ch == '&':
                        # Check if this & is at the end (ignoring trailing comments)
                        rest = stripped[idx + 1:].strip()
                        if rest and not rest.startswith('!'):
                            violations.append(Violation(
                                rule_key=self.rule_key,
                                message="The continuation character & shall only be placed at the end of each line.",
                                file_path=file_path, line=i, severity=self.severity,
                            ))
                            break
        return violations


# ---------------------------------------------------------------------------
# EUM.NAME.FormatLabels — FORMAT labels start at 1000, increase by 10
# ---------------------------------------------------------------------------
class EumNameFormatLabels(FortranRule):
    """FORMAT statement labels shall start at 1000 and increase by 10."""

    rule_key = "EUM.NAME.FormatLabels"
    severity = "INFO"

    def check(self, ast, file_path, symbol_table):
        violations = []
        lines = _read_source_lines(file_path, symbol_table)
        labels = []
        for node in walk(ast, Format_Stmt):
            line_num = _get_line(node)
            if line_num and line_num <= len(lines):
                line = lines[line_num - 1].strip()
                # Extract label (number at start of line)
                match = re.match(r'^(\d+)', line)
                if match:
                    labels.append((int(match.group(1)), line_num))

        if not labels:
            return violations

        expected = 1000
        for label, line_num in labels:
            if label < 1000:
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message=f"FORMAT label {label} shall start at 1000.",
                    file_path=file_path, line=line_num, severity=self.severity,
                ))
            elif label != expected and label < expected:
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message=f"FORMAT label {label} shall increase by 10 (expected {expected}).",
                    file_path=file_path, line=line_num, severity=self.severity,
                ))
            expected = max(expected, label) + 10
        return violations


# ---------------------------------------------------------------------------
# F90.DESIGN.IO — I/O statements grouped
# ---------------------------------------------------------------------------
class F90DesignIO(FortranRule):
    """I/O statements shall be grouped together."""

    rule_key = "F90.DESIGN.IO"
    severity = "MAJOR"

    def check(self, ast, file_path, symbol_table):
        violations = []
        lines = _read_source_lines(file_path, symbol_table)
        if not lines:
            return violations

        # Find all I/O statement lines
        io_lines = []
        for node in walk(ast, (Open_Stmt, Close_Stmt, Read_Stmt, Write_Stmt, Inquire_Stmt)):
            line_num = _get_line(node)
            if line_num:
                io_lines.append(line_num)

        if len(io_lines) < 3:
            return violations

        # Check if I/O statements are scattered (gaps > 20 lines between consecutive I/O)
        for i in range(1, len(io_lines)):
            gap = io_lines[i] - io_lines[i - 1]
            if gap > 20:
                violations.append(Violation(
                    rule_key=self.rule_key,
                    message="I/O statements shall be grouped together.",
                    file_path=file_path, line=io_lines[i], severity=self.severity,
                ))
        return violations
