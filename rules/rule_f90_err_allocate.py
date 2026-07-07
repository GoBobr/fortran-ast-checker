"""Rule 5: F90.ERR.Allocate

ALLOCATE and DEALLOCATE statements shall contain the STAT argument.

JFlex false positive cause: ``STAT=`` clause is present but not
recognized by the lexer.

AST solution: parse ``Allocate_Stmt`` and ``Deallocate_Stmt`` nodes and
check the allocation list for ``STAT=`` clause directly in the AST.
"""

from __future__ import annotations

from typing import List

from fparser.two.Fortran2003 import (
    Alloc_Opt,
    Alloc_Opt_List,
    Allocate_Stmt,
    Dealloc_Opt,
    Dealloc_Opt_List,
    Deallocate_Stmt,
    Program,
)
from fparser.two.utils import walk

from rules.base_rule import FortranRule, Violation
from rules.symbol_table import ProjectSymbolTable, _get_line


class F90ErrAllocate(FortranRule):
    """Check that ALLOCATE/DEALLOCATE statements have STAT=."""

    rule_key = "F90.ERR.Allocate"
    severity = "MAJOR"

    def check(
        self,
        ast: Program,
        file_path: str,
        symbol_table: ProjectSymbolTable,
    ) -> List[Violation]:
        violations: List[Violation] = []

        for node in walk(ast, Allocate_Stmt):
            if not self._has_stat(node):
                line = _get_line(node)
                violations.append(
                    Violation(
                        rule_key=self.rule_key,
                        message="There is no parameter STAT in the ALLOCATE instruction.",
                        file_path=file_path,
                        line=line,
                        severity=self.severity,
                    )
                )

        for node in walk(ast, Deallocate_Stmt):
            if not self._has_stat_dealloc(node):
                line = _get_line(node)
                violations.append(
                    Violation(
                        rule_key=self.rule_key,
                        message="There is no parameter STAT in the DEALLOCATE instruction.",
                        file_path=file_path,
                        line=line,
                        severity=self.severity,
                    )
                )

        return violations

    @staticmethod
    def _has_stat(node) -> bool:
        """Check if an Allocate_Stmt has STAT= in its Alloc_Opt_List.

        Allocate_Stmt children: [None, Allocation_List, Alloc_Opt_List]
        """
        for child in node.children:
            if isinstance(child, Alloc_Opt_List):
                for opt in child.children:
                    if isinstance(opt, Alloc_Opt):
                        # Alloc_Opt children: [keyword_str, value]
                        if opt.children:
                            keyword = opt.children[0]
                            if isinstance(keyword, str):
                                kw = keyword.upper().strip()
                                if kw == "STAT":
                                    return True
        return False

    @staticmethod
    def _has_stat_dealloc(node) -> bool:
        """Check if a Deallocate_Stmt has STAT=.

        Deallocate_Stmt children: [Allocate_Object_List, Dealloc_Opt_List]
        """
        for child in node.children:
            if isinstance(child, Dealloc_Opt_List):
                for opt in child.children:
                    if isinstance(opt, Dealloc_Opt):
                        if opt.children:
                            keyword = opt.children[0]
                            if isinstance(keyword, str):
                                kw = keyword.upper().strip()
                                if kw == "STAT":
                                    return True
        return False
