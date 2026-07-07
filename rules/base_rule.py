"""Base classes for all fparser-based Fortran rules.

Defines :class:`Violation` (the output data structure) and
:class:`FortranRule` (the abstract base class every rule implements).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, List, Optional

if TYPE_CHECKING:
    from fparser.two.Fortran2003 import Program
    from rules.symbol_table import ProjectSymbolTable


@dataclass
class Violation:
    """A single rule violation found in a source file.

    Attributes
    ----------
    rule_key : str
        The i-CodeCNES rule key, e.g. ``"F90.DATA.Declaration"``.
        Must match a key in ``icode-f90-rules.xml``.
    message : str
        Human-readable violation message shown in SonarQube.
    file_path : str
        Path to the source file, **relative to the SonarQube project
        base directory** (so the plugin can match it to an ``InputFile``).
    line : int
        1-indexed line number of the violation.
    severity : str
        SonarQube severity: ``BLOCKER``, ``CRITICAL``, ``MAJOR``,
        ``MINOR``, or ``INFO``.  All 10 PoC rules are ``MAJOR``.
    """

    rule_key: str
    message: str
    file_path: str
    line: int
    severity: str = "MAJOR"


class FortranRule(ABC):
    """Abstract base class for all fparser-based Fortran rules.

    Subclasses must set :attr:`rule_key` and implement :meth:`check`.
    """

    #: The i-CodeCNES rule key (must exist in ``icode-f90-rules.xml``).
    rule_key: str = ""

    #: Default severity (all 10 PoC rules are MAJOR in the quality profile).
    severity: str = "MAJOR"

    @abstractmethod
    def check(
        self,
        ast: "Program",
        file_path: str,
        symbol_table: "ProjectSymbolTable",
    ) -> List[Violation]:
        """Run this rule on a single parsed Fortran file.

        Parameters
        ----------
        ast
            The fparser AST (``Fortran2003.Program`` node) for the file.
        file_path
            Path to the source file, relative to the SonarQube project
            base directory.
        symbol_table
            Project-wide symbol table for cross-file resolution (USE
            association, type lookup, etc.).  May be ``None`` for rules
            that don't need it, but the base signature requires it.

        Returns
        -------
        list of Violation
            Violations found in this file (empty list if none).
        """
        ...
