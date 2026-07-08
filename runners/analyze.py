#!/usr/bin/env python3
"""Main fparser Fortran analyzer.

Parses all .f90 files in a source directory, builds a project-wide
symbol table, runs all fparser-based rules, and outputs violations
as JSON.

Usage:
    python3 runners/analyze.py \
        --source /path/to/remotap \
        --output results/fparser_issues.json \
        [--rules F90.DATA.Declaration,COM.TYPE.Expression]

The output JSON has this structure:
    {
        "source_dir": "/path/to/remotap",
        "files_analyzed": 184,
        "files_failed": 8,
        "symbol_table": {
            "modules": 167,
            "scopes": 1379
        },
        "violations": [
            {
                "rule_key": "F90.DATA.Declaration",
                "message": "...",
                "file_path": "src/module.f90",
                "line": 42,
                "severity": "MAJOR"
            },
            ...
        ],
        "summary": {
            "F90.DATA.Declaration": 294,
            "COM.TYPE.Expression": 227,
            ...
        }
    }
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from dataclasses import asdict
from typing import List

# Add the project root to sys.path so we can import rules.*
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
sys.path.insert(0, PROJECT_ROOT)

from fparser.two.parser import ParserFactory
from fparser.common.readfortran import FortranFileReader

from rules.symbol_table import ProjectSymbolTable, _read_fortran_file, _get_source_file_path
from rules.base_rule import Violation
from rules.rule_f90_data_declaration import F90DataDeclaration
from rules.rule_com_type_expression import ComTypeExpression
from rules.rule_f90_err_openread import F90ErrOpenRead
from rules.rule_com_data_initialisation import ComDataInitialisation
from rules.rule_f90_err_allocate import F90ErrAllocate
from rules.rule_com_data_floatcompare import ComDataFloatCompare
from rules.rule_f90_design_obsolete import F90DesignObsolete
from rules.rule_com_flow_exit import ComFlowExit
from rules.rule_com_design_alloc import ComDesignAlloc
from rules.rule_f90_data_arrayaccess import F90DataArrayAccess

# Batch 1: Simple keyword detection rules (20 rules)
from rules.rule_batch1_simple import (
    ComFlowAbort, F77InstSave, F90InstEquivalence, F77BlocCommon,
    F77DataParameter, F77ProtoDeclaration, ComInstGoTo, F90DesignInclude,
    F90InstEntry, EumInstBackspace, EumInstBlockData, EumInstNoData,
    EumInstNamelist, EumInstContinue, F77InstDimension, EumInstNoUnderscoreKind,
    F90InstPointer, F77InstAssign, F77InstPause, ComInstCodeComment,
)

# Batch 2: Declaration & type rules (15 rules)
from rules.rule_batch2_declarations import (
    F90InstIntent, F90DataArray, F90TypeDerivate, F77TypeBasic,
    F90TypeInteger, F90TypeReal, F90DataParameter as F90DataParameterB2,
    F90DataConstant, F90DataConstantFloat, F77DataDouble, F77TypeHollerith,
    EumInstDoubleColon, EumInstCharLen, EumInstOneVarPerLine, EumTypePrivateInType,
)

# Batch 3: Control flow & structure rules (15 rules)
from rules.rule_batch3_control_flow import (
    F90InstIf, F77BlocElse, F90RefLabel, ComFlowCaseSwitch,
    ComDataLoopCondition, ComFlowExitLoop, ComFlowRecursion, F90InstOperator,
    EumInstEqvOperators, EumInstNoSingleLineWhere, EumBlocWhereElse,
    EumInstNoLabelledDo, EumBlocNamedLoops, EumInstRedundant, F90DesignLogicUnit,
)

# Batch 4: Naming & formatting rules (20 rules)
from rules.rule_batch4_naming_format import (
    ComInstLine, F90NameKeyWords, ComNameHomonymy, ComPresData,
    ComPresIndent, ComPresLengthLine, ComPresFileLength, ComProjectHeader,
    F90FileHeader, EumPresNoTabs, EumPresIndentLevel, EumPresLabelJustify,
    EumPresBlockAlign, EumPresCommentPos, EumPresNoCommentMultiLine,
    EumPresNoEndLineComment, EumPresNoEmptyComment, EumPresDoxygen,
    EumPresCommentBlock, EumPresBlankLines,
)

# Batch 5: Metrics & complexity rules (8 rules)
from rules.rule_batch5_metrics import (
    ComMetLineOfCode, ComMetComplexitySimplified, ComMetRatioComment,
    EumMetMaxProcedures, EumMetMaxArguments, EumMetMaxAttributes,
    EumMetMaxContinuation, ComInstBrace,
)

# Batch 6: I/O & file rules (12 rules)
from rules.rule_batch6_io_file import (
    F90RefOpen, ComFlowFilePath, F90BlocFile, ComFlowFileExistence,
    EumInstFormatStmt, EumInstFormatPlacement, EumInstFreeFormatRead,
    EumInstCompilerExt, EumInstPercentBlank, EumInstContinuation,
    EumNameFormatLabels, F90DesignIO,
)

# Batch 7: Advanced AST rules (4 rules)
from rules.rule_batch7_advanced import (
    EumInstStatAfterAlloc, EumInstAssignmentOp, EumInstInitFinal,
    ComDataInvariant,
)

# Batch 8: Remaining rules (32+ rules)
from rules.rule_batch8_remaining import (
    EumNameIdChars, EumNameIdLength, EumNameIdFormat, EumNamePublicFormat,
    EumNamePrivateFormat, EumNameIdScope, EumNameConstants, EumNameProgramName,
    EumNameModuleName, EumNameFileExt, EumDesignOneUnitPerFile,
    EumDesignProgramStructure, EumDesignModuleStructure,
    EumDesignSubroutineStructure, EumDesignNoGlobalVars, EumInstArgTypeDecl,
    EumInstArgOrder, EumInstOptionalNamed, EumInstDummyArgOrder,
    EumInstOptionalAfterMandatory, EumInstStringDim, EumInstFunctionIntent,
    EumInstOptionalDefault, EumInstPureFunc, F90DesignInterface, F90InstOnly,
    F90RefInterface, F90InstAssociated, F90InstNullify, F90DesignFree,
    F90NameGenericIntrinsic, F77NameIntrinsic, F77NameLabel, F90RefArray,
    F90RefVariable, F90ProtoOverload, F90DataFloat, F77InstFunction,
    F77BlocFunction, F77InstReturn, F77InstIf as F77InstIfB8, F77BlocLoop,
    F77MetLine, ComFlowBooleanExpression, ComFlowCheckArguments,
    ComFlowCheckCodeReturn, ComFlowCheckUser, ComInstBoolNegation,
    ComInstLoopCondition, ComDataNotUsed, ComDesignActiveWait,
)

logger = logging.getLogger(__name__)

#: All fparser-based rules, in order.
ALL_RULES = [
    # Original 10 rules
    F90DataDeclaration(),        # F90.DATA.Declaration
    ComTypeExpression(),         # COM.TYPE.Expression
    F90ErrOpenRead(),            # F90.ERR.OpenRead
    ComDataInitialisation(),     # COM.DATA.Initialisation
    F90ErrAllocate(),            # F90.ERR.Allocate
    ComDataFloatCompare(),       # COM.DATA.FloatCompare
    F90DesignObsolete(),         # F90.DESIGN.Obsolete
    ComFlowExit(),               # COM.FLOW.Exit
    ComDesignAlloc(),            # COM.DESIGN.Alloc
    F90DataArrayAccess(),        # F90.DATA.ArrayAccess
    # Batch 1: Simple keyword detection (20 rules)
    ComFlowAbort(),              # COM.FLOW.Abort
    F77InstSave(),               # F77.INST.Save
    F90InstEquivalence(),        # F90.INST.Equivalence
    F77BlocCommon(),             # F77.BLOC.Common
    F77DataParameter(),          # F77.DATA.Parameter
    F77ProtoDeclaration(),       # F77.PROTO.Declaration
    ComInstGoTo(),               # COM.INST.GoTo
    F90DesignInclude(),          # F90.DESIGN.Include
    F90InstEntry(),              # F90.INST.Entry
    EumInstBackspace(),          # EUM.INST.Backspace
    EumInstBlockData(),          # EUM.INST.BlockData
    EumInstNoData(),             # EUM.INST.NoData
    EumInstNamelist(),           # EUM.INST.Namelist
    EumInstContinue(),           # EUM.INST.Continue
    F77InstDimension(),          # F77.INST.Dimension
    EumInstNoUnderscoreKind(),   # EUM.INST.NoUnderscoreKind
    F90InstPointer(),            # F90.INST.Pointer
    F77InstAssign(),             # F77.INST.Assign
    F77InstPause(),              # F77.INST.Pause
    ComInstCodeComment(),        # COM.INST.CodeComment
    # Batch 2: Declaration & type rules (15 rules)
    F90InstIntent(),             # F90.INST.Intent
    F90DataArray(),              # F90.DATA.Array
    F90TypeDerivate(),           # F90.TYPE.Derivate
    F77TypeBasic(),              # F77.TYPE.Basic
    F90TypeInteger(),            # F90.TYPE.Integer
    F90TypeReal(),               # F90.TYPE.Real
    F90DataParameterB2(),        # F90.DATA.Parameter
    F90DataConstant(),           # F90.DATA.Constant
    F90DataConstantFloat(),      # F90.DATA.ConstantFloat
    F77DataDouble(),             # F77.DATA.Double
    F77TypeHollerith(),          # F77.TYPE.Hollerith
    EumInstDoubleColon(),        # EUM.INST.DoubleColon
    EumInstCharLen(),            # EUM.INST.CharLen
    EumInstOneVarPerLine(),      # EUM.INST.OneVarPerLine
    EumTypePrivateInType(),      # EUM.TYPE.PrivateInType
    # Batch 3: Control flow & structure rules (15 rules)
    F90InstIf(),                 # F90.INST.If
    F77BlocElse(),               # F77.BLOC.Else
    F90RefLabel(),               # F90.REF.Label
    ComFlowCaseSwitch(),         # COM.FLOW.CaseSwitch
    ComDataLoopCondition(),      # COM.DATA.LoopCondition
    ComFlowExitLoop(),           # COM.FLOW.ExitLoop
    ComFlowRecursion(),          # COM.FLOW.Recursion
    F90InstOperator(),           # F90.INST.Operator
    EumInstEqvOperators(),       # EUM.INST.EqvOperators
    EumInstNoSingleLineWhere(),  # EUM.INST.NoSingleLineWhere
    EumBlocWhereElse(),          # EUM.BLOC.WhereElse
    EumInstNoLabelledDo(),       # EUM.INST.NoLabelledDo
    EumBlocNamedLoops(),         # EUM.BLOC.NamedLoops
    EumInstRedundant(),          # EUM.INST.Redundant
    F90DesignLogicUnit(),        # F90.DESIGN.LogicUnit
    # Batch 4: Naming & formatting rules (20 rules)
    ComInstLine(),               # COM.INST.Line
    F90NameKeyWords(),           # F90.NAME.KeyWords
    ComNameHomonymy(),           # COM.NAME.Homonymy
    ComPresData(),               # COM.PRES.Data
    ComPresIndent(),             # COM.PRES.Indent
    ComPresLengthLine(),         # COM.PRES.LengthLine
    ComPresFileLength(),         # COM.PRES.FileLength
    ComProjectHeader(),          # COM.PROJECT.Header
    F90FileHeader(),             # F90.FILE.Header
    EumPresNoTabs(),             # EUM.PRES.NoTabs
    EumPresIndentLevel(),        # EUM.PRES.IndentLevel
    EumPresLabelJustify(),       # EUM.PRES.LabelJustify
    EumPresBlockAlign(),         # EUM.PRES.BlockAlign
    EumPresCommentPos(),         # EUM.PRES.CommentPos
    EumPresNoCommentMultiLine(), # EUM.PRES.NoCommentMultiLine
    EumPresNoEndLineComment(),   # EUM.PRES.NoEndLineComment
    EumPresNoEmptyComment(),     # EUM.PRES.NoEmptyComment
    EumPresDoxygen(),            # EUM.PRES.Doxygen
    EumPresCommentBlock(),       # EUM.PRES.CommentBlock
    EumPresBlankLines(),         # EUM.PRES.BlankLines
    # Batch 5: Metrics & complexity rules (8 rules)
    ComMetLineOfCode(),          # COM.MET.LineOfCode
    ComMetComplexitySimplified(),# COM.MET.ComplexitySimplified
    ComMetRatioComment(),        # COM.MET.RatioComment
    EumMetMaxProcedures(),       # EUM.MET.MaxProcedures
    EumMetMaxArguments(),        # EUM.MET.MaxArguments
    EumMetMaxAttributes(),       # EUM.MET.MaxAttributes
    EumMetMaxContinuation(),     # EUM.MET.MaxContinuation
    ComInstBrace(),              # COM.INST.Brace
    # Batch 6: I/O & file rules (12 rules)
    F90RefOpen(),                # F90.REF.Open
    ComFlowFilePath(),           # COM.FLOW.FilePath
    F90BlocFile(),               # F90.BLOC.File
    ComFlowFileExistence(),      # COM.FLOW.FileExistence
    EumInstFormatStmt(),         # EUM.INST.FormatStmt
    EumInstFormatPlacement(),    # EUM.INST.FormatPlacement
    EumInstFreeFormatRead(),     # EUM.INST.FreeFormatRead
    EumInstCompilerExt(),        # EUM.INST.CompilerExt
    EumInstPercentBlank(),       # EUM.INST.PercentBlank
    EumInstContinuation(),       # EUM.INST.Continuation
    EumNameFormatLabels(),       # EUM.NAME.FormatLabels
    F90DesignIO(),               # F90.DESIGN.IO
    # Batch 7: Advanced AST rules (4 rules)
    EumInstStatAfterAlloc(),     # EUM.INST.StatAfterAlloc
    EumInstAssignmentOp(),       # EUM.INST.AssignmentOp
    EumInstInitFinal(),          # EUM.INST.InitFinal
    ComDataInvariant(),          # COM.DATA.Invariant
    # Batch 8: Remaining rules (32+ rules)
    EumNameIdChars(),            # EUM.NAME.IdChars
    EumNameIdLength(),           # EUM.NAME.IdLength
    EumNameIdFormat(),           # EUM.NAME.IdFormat
    EumNamePublicFormat(),       # EUM.NAME.PublicFormat
    EumNamePrivateFormat(),      # EUM.NAME.PrivateFormat
    EumNameIdScope(),            # EUM.NAME.IdScope
    EumNameConstants(),          # EUM.NAME.Constants
    EumNameProgramName(),        # EUM.NAME.ProgramName
    EumNameModuleName(),         # EUM.NAME.ModuleName
    EumNameFileExt(),            # EUM.NAME.FileExt
    EumDesignOneUnitPerFile(),   # EUM.DESIGN.OneUnitPerFile
    EumDesignProgramStructure(), # EUM.DESIGN.ProgramStructure
    EumDesignModuleStructure(),  # EUM.DESIGN.ModuleStructure
    EumDesignSubroutineStructure(), # EUM.DESIGN.SubroutineStructure
    EumDesignNoGlobalVars(),     # EUM.DESIGN.NoGlobalVars
    EumInstArgTypeDecl(),        # EUM.INST.ArgTypeDecl
    EumInstArgOrder(),           # EUM.INST.ArgOrder
    EumInstOptionalNamed(),      # EUM.INST.OptionalNamed
    EumInstDummyArgOrder(),      # EUM.INST.DummyArgOrder
    EumInstOptionalAfterMandatory(), # EUM.INST.OptionalAfterMandatory
    EumInstStringDim(),          # EUM.INST.StringDim
    EumInstFunctionIntent(),     # EUM.INST.FunctionIntent
    EumInstOptionalDefault(),    # EUM.INST.OptionalDefault
    EumInstPureFunc(),           # EUM.INST.PureFunc
    F90DesignInterface(),        # F90.DESIGN.Interface
    F90InstOnly(),               # F90.INST.Only
    F90RefInterface(),           # F90.REF.Interface
    F90InstAssociated(),         # F90.INST.Associated
    F90InstNullify(),            # F90.INST.Nullify
    F90DesignFree(),             # F90.DESIGN.Free
    F90NameGenericIntrinsic(),   # F90.NAME.GenericIntrinsic
    F77NameIntrinsic(),          # F77.NAME.Intrinsic
    F77NameLabel(),              # F77.NAME.Label
    F90RefArray(),               # F90.REF.Array
    F90RefVariable(),            # F90.REF.Variable
    F90ProtoOverload(),          # F90.PROTO.Overload
    F90DataFloat(),              # F90.DATA.Float
    F77InstFunction(),           # F77.INST.Function
    F77BlocFunction(),           # F77.BLOC.Function
    F77InstReturn(),             # F77.INST.Return
    F77InstIfB8(),               # F77.INST.If
    F77BlocLoop(),               # F77.BLOC.Loop
    F77MetLine(),                # F77.MET.Line
    ComFlowBooleanExpression(),  # COM.FLOW.BooleanExpression
    ComFlowCheckArguments(),     # COM.FLOW.CheckArguments
    ComFlowCheckCodeReturn(),    # COM.FLOW.CheckCodeReturn
    ComFlowCheckUser(),          # COM.FLOW.CheckUser
    ComInstBoolNegation(),       # COM.INST.BoolNegation
    ComInstLoopCondition(),      # COM.INST.LoopCondition
    ComDataNotUsed(),            # COM.DATA.NotUsed
    ComDesignActiveWait(),       # COM.DESIGN.ActiveWait
]


def find_f90_files(source_dir: str) -> List[str]:
    """Find all .f90 files in a directory tree."""
    files = []
    for root, dirs, filenames in os.walk(source_dir):
        for f in filenames:
            if f.endswith(".f90"):
                files.append(os.path.join(root, f))
    return sorted(files)


def find_included_files(source_dir: str) -> set:
    """Find all .f90 files that are INCLUDE targets of other .f90 files.

    These files are included into parent modules via INCLUDE statements,
    so their code is already analyzed via the parent module.  Skipping
    them avoids false positives for variables defined in the parent
    module (e.g., ``nst`` parameter in lintran_nst3_module).
    """
    import re

    included = set()
    include_re = re.compile(r'^\s*INCLUDE\s+"([^"]+)"', re.IGNORECASE)

    for root, dirs, filenames in os.walk(source_dir):
        for fname in filenames:
            if not fname.endswith(".f90"):
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, encoding="utf-8", errors="replace") as f:
                    for line in f:
                        m = include_re.match(line)
                        if m:
                            included.add(m.group(1))
            except Exception:
                pass

    return included


def select_rules(rule_keys: str | None):
    """Select rules by comma-separated keys, or return all if None."""
    if not rule_keys:
        return ALL_RULES
    keys = [k.strip() for k in rule_keys.split(",")]
    selected = []
    for rule in ALL_RULES:
        if rule.rule_key in keys:
            selected.append(rule)
    if not selected:
        print(f"ERROR: No rules matched '{rule_keys}'", file=sys.stderr)
        print(f"Available: {', '.join(r.rule_key for r in ALL_RULES)}", file=sys.stderr)
        sys.exit(1)
    return selected


def run_analysis(
    source_dir: str,
    rules: list,
    log_level: str = "WARNING",
) -> dict:
    """Run the full analysis pipeline.

    Returns a dict with results ready for JSON serialization.
    """
    logging.basicConfig(
        level=getattr(logging, log_level.upper(), logging.WARNING),
        format="%(levelname)s: %(message)s",
    )

    # Step 1: Find all .f90 files
    f90_files = find_f90_files(source_dir)
    print(f"Found {len(f90_files)} .f90 files in {source_dir}")

    # Step 1b: Find files that are INCLUDE targets — skip them during
    # rule checking because their code is already analyzed via the
    # parent module that includes them.
    included_filenames = find_included_files(source_dir)
    if included_filenames:
        print(f"  Skipping {len(included_filenames)} INCLUDE-target files: "
              f"{', '.join(sorted(included_filenames))}")

    # Step 2: Build symbol table
    print("Building project-wide symbol table...")
    t0 = time.time()
    symbol_table = ProjectSymbolTable()
    symbol_table.build(f90_files, source_dir)
    st_time = time.time() - t0
    print(
        f"  Symbol table built in {st_time:.1f}s: "
        f"{len(symbol_table.modules)} modules, "
        f"{len(symbol_table.scopes)} scopes"
    )

    # Step 3: Parse and run rules
    print(f"Running {len(rules)} rules...")
    parser = ParserFactory().create(std="f2008")

    all_violations: List[Violation] = []
    # Track seen violations to deduplicate — when an INCLUDE file is
    # included by multiple parent modules, the same code is analyzed
    # multiple times, producing identical violations.  We keep only
    # the first occurrence of each (file_path, line, rule_key, message).
    seen_violation_keys: set = set()
    files_analyzed = 0
    files_failed = 0
    failed_files = []

    t0 = time.time()
    for i, fpath in enumerate(f90_files):
        rel_path = os.path.relpath(fpath, source_dir)
        fname = os.path.basename(fpath)

        # Skip INCLUDE-target files — already analyzed via parent module
        if fname in included_filenames:
            continue

        try:
            ast = _read_fortran_file(fpath, parser)
            files_analyzed += 1
            for rule in rules:
                try:
                    v = rule.check(ast, rel_path, symbol_table)
                    # Normalize violation file paths: if a rule reported a
                    # violation in an included file, make the path
                    # relative to the source directory.
                    for violation in v:
                        if violation.file_path and os.path.isabs(
                            violation.file_path
                        ):
                            violation.file_path = os.path.relpath(
                                violation.file_path, source_dir
                            )
                        elif not violation.file_path:
                            violation.file_path = rel_path
                    # Deduplicate: skip violations we've already seen
                    # (same file, line, rule, message — happens when an
                    # INCLUDE file is included by multiple parent modules)
                    for violation in v:
                        key = (
                            violation.file_path,
                            violation.line,
                            violation.rule_key,
                            violation.message,
                        )
                        if key not in seen_violation_keys:
                            seen_violation_keys.add(key)
                            all_violations.append(violation)
                except Exception as e:
                    logger.warning(
                        f"Rule {rule.rule_key} failed on {rel_path}: {e}"
                    )
        except Exception as e:
            files_failed += 1
            failed_files.append((rel_path, str(e)))
            logger.debug(f"Parse failed for {rel_path}: {e}")

        if (i + 1) % 20 == 0:
            print(f"  Processed {i + 1}/{len(f90_files)} files...")

    analysis_time = time.time() - t0

    # Step 4: Build summary
    summary = {}
    for rule in rules:
        count = sum(1 for v in all_violations if v.rule_key == rule.rule_key)
        summary[rule.rule_key] = count

    print(f"\nAnalysis complete in {analysis_time:.1f}s")
    print(f"  Files analyzed: {files_analyzed}")
    print(f"  Files failed: {files_failed}")
    print(f"  Total violations: {len(all_violations)}")
    for key, count in summary.items():
        print(f"    {key:30s}: {count:5d}")

    # Step 5: Build result dict
    result = {
        "source_dir": source_dir,
        "files_analyzed": files_analyzed,
        "files_failed": files_failed,
        "failed_files": failed_files,
        "symbol_table": {
            "modules": len(symbol_table.modules),
            "scopes": len(symbol_table.scopes),
        },
        "violations": [asdict(v) for v in all_violations],
        "summary": summary,
        "timing": {
            "symbol_table_seconds": round(st_time, 1),
            "analysis_seconds": round(analysis_time, 1),
            "total_seconds": round(st_time + analysis_time, 1),
        },
    }

    return result


def main():
    parser = argparse.ArgumentParser(
        description="fparser-based Fortran analyzer (PoC)"
    )
    parser.add_argument(
        "--source",
        required=True,
        help="Source directory containing .f90 files",
    )
    parser.add_argument(
        "--output",
        default="results/fparser_issues.json",
        help="Output JSON file path (default: results/fparser_issues.json)",
    )
    parser.add_argument(
        "--rules",
        default=None,
        help="Comma-separated rule keys to run (default: all rules)",
    )
    parser.add_argument(
        "--log-level",
        default="WARNING",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Logging level (default: WARNING)",
    )
    args = parser.parse_args()

    rules = select_rules(args.rules)
    result = run_analysis(args.source, rules, args.log_level)

    # Write output
    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print(f"\nResults written to {args.output}")


if __name__ == "__main__":
    main()
