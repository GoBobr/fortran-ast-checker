"""Rule 3: F90.ERR.OpenRead

OPEN, READ and CLOSE statements shall contain the IOSTAT argument.

JFlex false positive cause: ``IOSTAT=`` clause is present but not
recognized by the lexer (case sensitivity, multiline, etc.).

AST solution: parse ``Open_Stmt``, ``Read_Stmt``, ``Close_Stmt`` nodes
and check the control list for ``IOSTAT=``, ``ERR=`` or ``END=`` clauses
directly in the AST.  WRITE statements are not checked (the original
i-CodeCNES rule only checks OPEN, READ, CLOSE).  Reads from internal
files (character variables) and stdin (``*``) are skipped — they don't
need IOSTAT.
"""

from __future__ import annotations

from typing import List

from fparser.two.Fortran2003 import (
    Close_Spec_List,
    Close_Stmt,
    Connect_Spec,
    Connect_Spec_List,
    Io_Control_Spec,
    Io_Control_Spec_List,
    Name,
    Open_Stmt,
    Program,
    Read_Stmt,
)
from fparser.two.utils import walk

from rules.base_rule import FortranRule, Violation
from rules.symbol_table import (
    ProjectSymbolTable,
    _get_line,
    _get_source_file_path,
    _node_to_str,
)


class F90ErrOpenRead(FortranRule):
    """Check that OPEN/READ/CLOSE statements have IOSTAT or ERR."""

    rule_key = "F90.ERR.OpenRead"
    severity = "MAJOR"

    def check(
        self,
        ast: Program,
        file_path: str,
        symbol_table: ProjectSymbolTable,
    ) -> List[Violation]:
        violations: List[Violation] = []

        # Check OPEN statements
        for node in walk(ast, Open_Stmt):
            if not self._has_iostat_or_err_open(node):
                line = _get_line(node)
                stmt_file_path = _get_source_file_path(node) or file_path
                violations.append(
                    Violation(
                        rule_key=self.rule_key,
                        message="There is no parameter IOSTAT in the OPEN instruction.",
                        file_path=stmt_file_path,
                        line=line,
                        severity=self.severity,
                    )
                )

        # Check READ statements (skip internal file reads and stdin reads)
        for node in walk(ast, Read_Stmt):
            if self._is_internal_or_stdin_read(node):
                continue
            if not self._has_iostat_or_err_read(node):
                line = _get_line(node)
                stmt_file_path = _get_source_file_path(node) or file_path
                violations.append(
                    Violation(
                        rule_key=self.rule_key,
                        message="There is no parameter IOSTAT in the READ instruction.",
                        file_path=stmt_file_path,
                        line=line,
                        severity=self.severity,
                    )
                )

        # Check CLOSE statements
        for node in walk(ast, Close_Stmt):
            if not self._has_iostat_or_err_close(node):
                line = _get_line(node)
                stmt_file_path = _get_source_file_path(node) or file_path
                violations.append(
                    Violation(
                        rule_key=self.rule_key,
                        message="There is no parameter IOSTAT in the CLOSE instruction.",
                        file_path=stmt_file_path,
                        line=line,
                        severity=self.severity,
                    )
                )

        return violations

    @staticmethod
    def _has_iostat_or_err_open(node) -> bool:
        """Check if an OPEN statement has IOSTAT= or ERR=."""
        for child in node.children:
            if isinstance(child, Connect_Spec_List):
                for spec in child.children:
                    if isinstance(spec, Connect_Spec) and spec.children:
                        keyword = spec.children[0]
                        if isinstance(keyword, str):
                            kw = keyword.upper().strip()
                            if kw in ("IOSTAT", "ERR"):
                                return True
        return False

    @staticmethod
    def _has_iostat_or_err_read(node) -> bool:
        """Check if a READ statement has IOSTAT=, ERR= or END=."""
        for child in node.children:
            if isinstance(child, Io_Control_Spec_List):
                for spec in child.children:
                    if isinstance(spec, Io_Control_Spec) and spec.children:
                        keyword = spec.children[0]
                        if isinstance(keyword, str):
                            kw = keyword.upper().strip()
                            if kw in ("IOSTAT", "ERR", "END"):
                                return True
        return False

    @staticmethod
    def _has_iostat_or_err_close(node) -> bool:
        """Check if a CLOSE statement has IOSTAT= or ERR=."""
        for child in node.children:
            if isinstance(child, Close_Spec_List):
                for spec in child.children:
                    if hasattr(spec, "children") and spec.children:
                        keyword = spec.children[0]
                        if isinstance(keyword, str):
                            kw = keyword.upper().strip()
                            if kw in ("IOSTAT", "ERR"):
                                return True
        return False

    @staticmethod
    def _is_internal_or_stdin_read(node) -> bool:
        """Check if a READ is from an internal file (character variable) or stdin (*).

        These don't need IOSTAT because they can't fail in the same way
        as file I/O.
        """
        for child in node.children:
            if isinstance(child, Io_Control_Spec_List):
                for spec in child.children:
                    if isinstance(spec, Io_Control_Spec) and spec.children:
                        keyword = spec.children[0]
                        # If UNIT= is a Name (character variable), it's internal
                        if isinstance(keyword, str) and keyword.upper() == "UNIT":
                            if len(spec.children) > 1:
                                val = spec.children[1]
                                if isinstance(val, Name):
                                    return True  # internal file
                        elif not isinstance(keyword, str):
                            # First spec might be the unit directly
                            pass
                        # Check for * (stdin)
                        s = _node_to_str(spec)
                        if s == "*" or s.startswith("*,") or s.startswith("* ,"):
                            return True
                    elif isinstance(spec, Name):
                        # Internal file read: READ(string, *) ...
                        return True
                    elif _node_to_str(spec) == "*":
                        return True
        return False
