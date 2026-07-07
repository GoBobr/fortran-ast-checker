"""fparser-based Fortran analysis rules for the EUM SonarQube quality profile.

This package contains AST-based re-implementations of the top 10
i-CodeCNES Fortran rules that produce the most false positives on the
RemoTAP codebase.  Each rule subclasses :class:`FortranRule` and returns a
list of :class:`Violation` objects.
"""
