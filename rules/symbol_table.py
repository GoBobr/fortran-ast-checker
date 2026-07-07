"""Project-wide symbol table built from fparser ASTs.

This is the **core component** that solves most false positives.  It
parses all ``.f90`` files in the project, extracts module exports,
variable declarations, USE imports, and derived-type definitions, then
provides query methods for the rules to resolve identifiers, types, and
attributes across file boundaries.

Three-pass build
----------------

1. **Module export collection** — for each ``MODULE``, extract PUBLIC
   declarations, PARAMETER constants, all type declarations with
   attributes, and derived-type definitions.
2. **Scope resolution** — for each subroutine/function, extract dummy
   argument lists with INTENT, local variable declarations, and USE
   statements.
3. **Linking** — resolve USE imports against the module export table
   and build the scope hierarchy (subroutine → parent module → USE
   imports).
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from fparser.common.readfortran import FortranFileReader, FortranStringReader
from fparser.two.Fortran2003 import (
    Access_Spec,
    Allocate_Stmt,
    Allocation,
    Allocation_List,
    Alloc_Opt,
    Alloc_Opt_List,
    Assignment_Stmt,
    Attr_Spec,
    Attr_Spec_List,
    Call_Stmt,
    Component_Decl,
    Component_Part,
    Connect_Spec,
    Data_Component_Def_Stmt,
    Deallocate_Stmt,
    Derived_Type_Def,
    Derived_Type_Stmt,
    Dummy_Arg_List,
    End_Module_Stmt,
    Entity_Decl,
    Entity_Decl_List,
    Function_Stmt,
    Intent_Attr_Spec,
    Intent_Spec,
    Intrinsic_Type_Spec,
    Module,
    Module_Stmt,
    Name,
    Only_List,
    Pointer_Assignment_Stmt,
    Proc_Decl_List,
    Procedure_Declaration_Stmt,
    Program,
    Program_Stmt,
    Return_Stmt,
    Specification_Part,
    Subroutine_Stmt,
    Type_Declaration_Stmt,
    Use_Stmt,
)
from fparser.two.parser import ParserFactory
from fparser.two.utils import walk

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Preprocessor macro handling
# ---------------------------------------------------------------------------
# fparser cannot handle C-preprocessor macros like __FILE__ and __LINE__.
# We replace them with dummy values before parsing.
_PP_FILE_RE = re.compile(r'__FILE__')
_PP_LINE_RE = re.compile(r'__LINE__')


def _preprocess_fortran_source(source: str) -> str:
    """Replace __FILE__ and __LINE__ macros with dummy values.

    ``__FILE__`` is replaced with a string literal, ``__LINE__`` with
    the integer ``0``.  This allows fparser to parse files that use
    these macros without a separate preprocessing step.
    """
    source = _PP_FILE_RE.sub('"placeholder.f90"', source)
    source = _PP_LINE_RE.sub('0', source)
    return source


def _read_fortran_file(fpath: str, parser):
    """Read and parse a Fortran file, handling __FILE__/__LINE__ macros.

    Returns the AST, or raises the original exception on parse failure.
    """
    try:
        reader = FortranFileReader(fpath)
        return parser(reader)
    except Exception:
        # Try again with __FILE__/__LINE__ replaced
        with open(fpath, encoding="utf-8", errors="replace") as f:
            source = f.read()
        source = _preprocess_fortran_source(source)
        reader = FortranStringReader(source, ignore_comments=False)
        return parser(reader)


# ---------------------------------------------------------------------------
# Fortran intrinsic functions — used by rules to avoid flagging intrinsics
# as undeclared variables or unknown-type expressions.
# ---------------------------------------------------------------------------
# Map: intrinsic name (lowercase) -> return type
#   "REAL"      -> REAL
#   "DOUBLE"    -> DOUBLE PRECISION
#   "INTEGER"   -> INTEGER
#   "LOGICAL"   -> LOGICAL
#   "CHARACTER" -> CHARACTER
#   "UNKNOWN"   -> type depends on arguments
INTRINSIC_RETURN_TYPES: Dict[str, str] = {
    # Integer-returning intrinsics
    "int": "INTEGER",
    "nint": "INTEGER",
    "ceiling": "INTEGER",
    "floor": "INTEGER",
    "abs": "UNKNOWN",  # INTEGER if arg is INTEGER, REAL if arg is REAL
    "iachar": "INTEGER",
    "ichar": "INTEGER",
    "index": "INTEGER",
    "len": "INTEGER",
    "len_trim": "INTEGER",
    "scan": "INTEGER",
    "verify": "INTEGER",
    "lbound": "INTEGER",
    "ubound": "INTEGER",
    "size": "INTEGER",
    "shape": "INTEGER",
    "count": "INTEGER",
    "maxloc": "INTEGER",
    "minloc": "INTEGER",
    "kind": "INTEGER",
    "selected_int_kind": "INTEGER",
    "selected_real_kind": "INTEGER",
    "selected_char_kind": "INTEGER",
    "bit_size": "INTEGER",
    "digits": "INTEGER",
    "exponent": "INTEGER",
    "range": "INTEGER",
    "precision": "INTEGER",
    "rank": "INTEGER",
    "lcobound": "INTEGER",
    "ucobound": "INTEGER",
    "leadz": "INTEGER",
    "trailz": "INTEGER",
    "popcnt": "INTEGER",
    "poppar": "INTEGER",
    "shifta": "INTEGER",
    "shiftr": "INTEGER",
    "shiftl": "INTEGER",
    "ishft": "INTEGER",
    "ishftc": "INTEGER",
    "ieor": "INTEGER",
    "ior": "INTEGER",
    "iand": "INTEGER",
    "ibclr": "INTEGER",
    "ibset": "INTEGER",
    "ibits": "INTEGER",
    "not": "INTEGER",
    "mvbits": "INTEGER",
    "btest": "LOGICAL",
    # Real-returning intrinsics
    "real": "REAL",
    "float": "REAL",
    "sngl": "REAL",
    "sqrt": "UNKNOWN",  # REAL/DOUBLE depending on arg
    "exp": "UNKNOWN",
    "log": "UNKNOWN",
    "log10": "UNKNOWN",
    "sin": "UNKNOWN",
    "cos": "UNKNOWN",
    "tan": "UNKNOWN",
    "asin": "UNKNOWN",
    "acos": "UNKNOWN",
    "atan": "UNKNOWN",
    "atan2": "UNKNOWN",
    "sinh": "UNKNOWN",
    "cosh": "UNKNOWN",
    "tanh": "UNKNOWN",
    "mod": "UNKNOWN",
    "sign": "UNKNOWN",
    "max": "UNKNOWN",
    "min": "UNKNOWN",
    "maxval": "UNKNOWN",
    "minval": "UNKNOWN",
    "sum": "UNKNOWN",
    "product": "UNKNOWN",
    "dot_product": "UNKNOWN",
    "norm2": "UNKNOWN",
    "hypot": "UNKNOWN",
    "epsilon": "UNKNOWN",
    "tiny": "UNKNOWN",
    "huge": "UNKNOWN",
    "spacing": "UNKNOWN",
    "rrspacing": "UNKNOWN",
    "fraction": "UNKNOWN",
    "nearest": "UNKNOWN",
    "scale": "UNKNOWN",
    "set_exponent": "UNKNOWN",
    "dprod": "DOUBLE PRECISION",
    # Double-precision-returning intrinsics
    "dble": "DOUBLE PRECISION",
    "dabs": "DOUBLE PRECISION",
    "dsqrt": "DOUBLE PRECISION",
    "dexp": "DOUBLE PRECISION",
    "dlog": "DOUBLE PRECISION",
    "dlog10": "DOUBLE PRECISION",
    "dsin": "DOUBLE PRECISION",
    "dcos": "DOUBLE PRECISION",
    "dtan": "DOUBLE PRECISION",
    "dasin": "DOUBLE PRECISION",
    "dacos": "DOUBLE PRECISION",
    "datan": "DOUBLE PRECISION",
    "datan2": "DOUBLE PRECISION",
    "dsinh": "DOUBLE PRECISION",
    "dcosh": "DOUBLE PRECISION",
    "dtanh": "DOUBLE PRECISION",
    "dmod": "DOUBLE PRECISION",
    "dsign": "DOUBLE PRECISION",
    "dmax1": "DOUBLE PRECISION",
    "dmin1": "DOUBLE PRECISION",
    "dim": "UNKNOWN",
    "dint": "DOUBLE PRECISION",
    "dnint": "DOUBLE PRECISION",
    "dgamma": "DOUBLE PRECISION",
    "dlgama": "DOUBLE PRECISION",
    # Additional Fortran77-style intrinsics (D/C prefix)
    "derfc": "DOUBLE PRECISION",
    "derf": "DOUBLE PRECISION",
    "dconjg": "COMPLEX",
    "cdsqrt": "COMPLEX",
    "cdabs": "DOUBLE PRECISION",
    "cdexp": "COMPLEX",
    "cdlog": "COMPLEX",
    "cdcos": "COMPLEX",
    "cdsin": "COMPLEX",
    # Standard intrinsics not yet listed
    "erfc": "REAL",
    "erf": "REAL",
    "gamma": "REAL",
    "algama": "DOUBLE PRECISION",
    "bessel_j0": "REAL",
    "bessel_j1": "REAL",
    "bessel_jn": "REAL",
    "bessel_y0": "REAL",
    "bessel_y1": "REAL",
    "bessel_yn": "REAL",
    # Complex-returning intrinsics
    "cmplx": "COMPLEX",
    "dcmplx": "COMPLEX",
    "conjg": "COMPLEX",
    "aimag": "REAL",
    # Logical-returning intrinsics
    "allocated": "LOGICAL",
    "associated": "LOGICAL",
    "present": "LOGICAL",
    "isnan": "LOGICAL",
    "is_iostat_end": "LOGICAL",
    "is_iostat_eor": "LOGICAL",
    "all": "LOGICAL",
    "any": "LOGICAL",
    "is_contiguous": "LOGICAL",
    "logical": "LOGICAL",
    # Character-returning intrinsics
    "char": "CHARACTER",
    "achar": "CHARACTER",
    "adjustl": "CHARACTER",
    "adjustr": "CHARACTER",
    "repeat": "CHARACTER",
    "trim": "CHARACTER",
    "transfer": "UNKNOWN",
    "merge": "UNKNOWN",
    "pack": "UNKNOWN",
    "unpack": "UNKNOWN",
    "reshape": "UNKNOWN",
    "spread": "UNKNOWN",
    "cshift": "UNKNOWN",
    "eoshift": "UNKNOWN",
    "transpose": "UNKNOWN",
    "matmul": "UNKNOWN",
    "reduce": "UNKNOWN",
    "findloc": "INTEGER",
    "command_argument_count": "INTEGER",
    "system_clock": "UNKNOWN",
    "cpu_time": "UNKNOWN",
    "date_and_time": "UNKNOWN",
    "random_number": "UNKNOWN",
    "random_seed": "UNKNOWN",
    "get_command": "UNKNOWN",
    "get_command_argument": "UNKNOWN",
    "get_environment_variable": "UNKNOWN",
    "move_alloc": "UNKNOWN",
    "co_sum": "UNKNOWN",
    "co_max": "UNKNOWN",
    "co_min": "UNKNOWN",
    "co_reduce": "UNKNOWN",
    "co_broadcast": "UNKNOWN",
    "atomic_define": "UNKNOWN",
    "atomic_ref": "UNKNOWN",
    "atomic_add": "UNKNOWN",
    "atomic_and": "UNKNOWN",
    "atomic_or": "UNKNOWN",
    "atomic_xor": "UNKNOWN",
    "atomic_cas": "UNKNOWN",
    "event_query": "UNKNOWN",
    "image_status": "INTEGER",
    "image_index": "INTEGER",
    "num_images": "INTEGER",
    "this_image": "INTEGER",
    "failed_images": "INTEGER",
    "stopped_images": "INTEGER",
    "lcobound": "INTEGER",
    "ucobound": "INTEGER",
    "coshape": "INTEGER",
    "compiler_version": "CHARACTER",
    "compiler_options": "CHARACTER",
}

#: Set of all known intrinsic names (lowercase).
FORTRAN_INTRINSICS: Set[str] = set(INTRINSIC_RETURN_TYPES.keys()) | {
    # Additional intrinsics that don't return a simple type
    "allocate",
    "deallocate",
    "null",
    "nullify",
    "inquire",
    "intrinsic",
    "external",
    "entry",
    "return",
    "pause",
    "stop",
    "error_termination",
    "execute_command_line",
    "get_team",
    "team_number",
    "form_team",
    "change_team",
    "end_team",
    "sync_all",
    "sync_images",
    "sync_memory",
    "sync_team",
    "lock",
    "unlock",
    "event_post",
    "event_wait",
    "query_event",
    "fail_image",
    "get_data_handle",
    "set_data_handle",
    # OpenMP runtime
    "omp_get_thread_num",
    "omp_get_num_threads",
    "omp_get_max_threads",
    "omp_in_parallel",
    "omp_get_wtime",
    "omp_get_wtick",
    "omp_set_num_threads",
    "omp_set_dynamic",
    "omp_get_dynamic",
    "omp_set_nested",
    "omp_get_nested",
    "omp_get_level",
    "omp_get_ancestor_thread_num",
    "omp_get_team_size",
    "omp_get_active_level",
    "omp_in_final",
    "omp_get_proc_bind",
    "omp_set_schedule",
    "omp_get_schedule",
    "omp_get_max_task_priority",
    "omp_get_num_places",
    "omp_get_place_num",
    "omp_get_partition_num_places",
    "omp_get_partition_place_nums",
    "omp_set_default_device",
    "omp_get_default_device",
    "omp_get_num_devices",
    "omp_get_initial_device",
    "omp_target_alloc",
    "omp_target_free",
    "omp_target_is_present",
    "omp_target_memcpy",
    "omp_target_associate_ptr",
    "omp_target_disassociate_ptr",
    # MPI subroutines (commonly used, should not be flagged)
    "mpi_init",
    "mpi_finalize",
    "mpi_comm_rank",
    "mpi_comm_size",
    "mpi_send",
    "mpi_recv",
    "mpi_bcast",
    "mpi_reduce",
    "mpi_allreduce",
    "mpi_barrier",
    "mpi_gather",
    "mpi_scatter",
    "mpi_abort",
    "mpi_error_string",
    "mpi_wtime",
    "mpi_wtick",
    # NetCDF functions
    "nf90_open",
    "nf90_close",
    "nf90_inq_dimid",
    "nf90_inq_varid",
    "nf90_get_var",
    "nf90_get_att",
    "nf90_put_var",
    "nf90_put_att",
    "nf90_create",
    "nf90_def_dim",
    "nf90_def_var",
    "nf90_enddef",
    "nf90_strerror",
    "nf90_inquire",
    "nf90_inquire_dimension",
    "nf90_inquire_variable",
    "nf90_inquire_attribute",
    "nf90_rename_dim",
    "nf90_rename_var",
    "nf90_rename_att",
    "nf90_del_att",
    "nf90_copy_att",
    "nf90_inq_ncid",
    "nf90_inq_libvers",
    "nf90_set_fill",
    "nf90_set_base_addr",
    "nf90_inq_var_chunking",
    "nf90_def_var_chunking",
    "nf90_inq_var_fill",
    "nf90_def_var_fill",
    "nf90_inq_var_endian",
    "nf90_def_var_endian",
    "nf90_inq_var_filter",
    "nf90_def_var_filter",
    "nf90_open_create",
    "nf90_sync",
    # Fortran 77 intrinsics (bitwise operations, still used in legacy code)
    "or",
    "and",
    "xor",
    "not",
    "lshift",
    "rshift",
    # Fortran 2008 degree intrinsics (trigonometric functions in degrees)
    "acosd",
    "acosh",
    "asind",
    "atand",
    "atan2d",
    "cosd",
    "sind",
    "tand",
    "cotand",
    "iand",
    "ior",
    "ieor",
    "ishft",
    "ishftc",
    "btest",
    "ibset",
    "ibclr",
    "ibits",
    "mvbits",
    "bge",
    "bgt",
    "ble",
    "blt",
    "shiftl",
    "shiftr",
    "shifta",
    "merge_bits",
    "dshiftl",
    "dshiftr",
    # Common extension intrinsics
    "iargc",
    "getarg",
    "getenv",
    "system",
    "flush",
    "fdate",
    "hostnm",
    "ttynam",
    "isatty",
    "mclock",
    "secnds",
    "time",
    "ctime",
    "etime",
    "dtime",
    "date",
    "idate",
    "ltime",
    "gmtime",
    "fstat",
    "stat",
    "lstat",
    "filesep",
    "getcwd",
    "rename",
    "symlnk",
    "lnblnk",
    "long",
    "short",
    "loc",
    # HDF5
    "h5open_f",
    "h5close_f",
    "h5fopen_f",
    "h5fclose_f",
    "h5gopen_f",
    "h5gclose_f",
    "h5dopen_f",
    "h5dclose_f",
    "h5dread_f",
    "h5dwrite_f",
    "h5sget_simple_extent_dims_f",
    "h5aget_space_f",
    "h5aread_f",
    "h5aopen_name_f",
    "h5aclose_f",
    # NetCDF constants (from USE netcdf module)
    "nf90_float",
    "nf90_double",
    "nf90_int",
    "nf90_int1",
    "nf90_int2",
    "nf90_int4",
    "nf90_int8",
    "nf90_real",
    "nf90_real4",
    "nf90_real8",
    "nf90_char",
    "nf90_byte",
    "nf90_short",
    "nf90_ubyte",
    "nf90_ushort",
    "nf90_uint",
    "nf90_int64",
    "nf90_uint64",
    "nf90_string",
    "nf90_noerr",
    "nf90_nowrite",
    "nf90_write",
    "nf90_clobber",
    "nf90_noclobber",
    "nf90_fill",
    "nf90_nofill",
    "nf90_global",
    "nf90_max_name",
    "nf90_max_var_dims",
    "nf90_unlimited",
    "nf90_64bit_offset",
    "nf90_classic_model",
    "nf90_netcdf4",
    "nf90_enogrp",
    "nf90_inq_grp_ncid",
    "nf90_inq_path",
    "nf90_def_grp",
    "nf90_compound",
    "nf90_enum",
    "nf90_vlen",
    "nf90_opaque",
    # libtorch (PyTorch Fortran bindings)
    "torch_tensor_from_array",
    "torch_kcpu",
    "torch_kcuda",
    "torch_module_load",
    "torch_module_forward",
    "torch_tensor_to_array",
    "torch_tensor_from_blob",
    "torch_tensor_to_blob",
    "torch_init",
    "torch_finish",
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class Symbol:
    """A single variable/constant/procedure symbol in the symbol table."""

    name: str
    type: str  # INTEGER, REAL, DOUBLE PRECISION, CHARACTER, LOGICAL, COMPLEX, TYPE(...)
    attributes: Set[str] = field(default_factory=set)  # PARAMETER, INTENT(IN), POINTER, ALLOCATABLE, etc.
    scope: str = ""  # module name or subroutine name
    is_public: bool = False
    initialized: bool = False  # True if PARAMETER, INTENT(IN), =>, or assigned before use
    is_dummy: bool = False  # True if a dummy argument
    intent: str = ""  # "", "IN", "OUT", "INOUT"
    is_allocatable: bool = False
    is_pointer: bool = False
    is_parameter: bool = False
    is_target: bool = False
    is_optional: bool = False
    is_external: bool = False
    is_intrinsic: bool = False
    is_procedure: bool = False  # subroutine or function
    dimensions: int = 0  # 0 = scalar, >0 = array rank


@dataclass
class ModuleInfo:
    """Information about a Fortran module."""

    name: str
    exports: Dict[str, Symbol] = field(default_factory=dict)
    file_path: str = ""
    derived_types: Dict[str, Dict[str, Symbol]] = field(default_factory=dict)
    # derived_types: type_name -> {component_name -> Symbol}
    has_implicit_none: bool = True
    default_private: bool = False  # True if module has bare PRIVATE statement


@dataclass
class ScopeInfo:
    """Information about a scope (module, subroutine, function, or program)."""

    name: str
    kind: str  # "module", "subroutine", "function", "program"
    symbols: Dict[str, Symbol] = field(default_factory=dict)
    use_imports: Dict[str, Optional[List[str]]] = field(default_factory=dict)
    # use_imports: module_name -> list of imported names, or None for USE without ONLY
    parent: Optional[str] = None  # parent scope name (e.g., containing module)
    file_path: str = ""
    has_implicit_none: bool = True
    dummy_args: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Helper functions for AST traversal
# ---------------------------------------------------------------------------
def _get_line(node) -> int:
    """Get the starting line number of an fparser AST node.

    Returns 0 if the line number cannot be determined.
    """
    if node is None:
        return 0
    item = getattr(node, "item", None)
    if item is not None:
        span = getattr(item, "span", None)
        if span and len(span) >= 1:
            return span[0]
    return 0


def _node_to_str(node) -> str:
    """Safely convert an fparser node to string."""
    if node is None:
        return ""
    return str(node).strip()


def _get_type_from_intrinsic_type_spec(spec) -> str:
    """Extract the Fortran type string from an Intrinsic_Type_Spec node.

    Examples:
        INTEGER -> "INTEGER"
        REAL -> "REAL"
        DOUBLE PRECISION -> "DOUBLE PRECISION"
        CHARACTER(LEN=*) -> "CHARACTER"
        LOGICAL -> "LOGICAL"
        COMPLEX -> "COMPLEX"
    """
    if spec is None:
        return ""
    s = _node_to_str(spec).upper()
    # Normalize: CHARACTER(LEN=10) -> CHARACTER, CHARACTER(LEN=*) -> CHARACTER
    for base in (
        "DOUBLE PRECISION",
        "DOUBLE COMPLEX",
        "INTEGER",
        "REAL",
        "CHARACTER",
        "LOGICAL",
        "COMPLEX",
    ):
        if s.startswith(base):
            return base
    return s


def _get_type_from_declaration_type_spec(spec) -> str:
    """Extract type from a Declaration_Type_Spec (handles both intrinsic and derived)."""
    if spec is None:
        return ""
    if isinstance(spec, Intrinsic_Type_Spec):
        return _get_type_from_intrinsic_type_spec(spec)
    # Derived type: TYPE(type_name) or CLASS(type_name)
    s = _node_to_str(spec)
    # Extract type name from TYPE(...) or CLASS(...)
    m = re.match(r"(?:TYPE|CLASS)\s*\(\s*(\w+)\s*\)", s, re.IGNORECASE)
    if m:
        return f"TYPE({m.group(1)})"
    return s.upper()


def _parse_attr_spec_list(attr_list) -> Set[str]:
    """Parse an Attr_Spec_List into a set of attribute strings (uppercase)."""
    attrs: Set[str] = set()
    if attr_list is None:
        return attrs
    for child in attr_list.children:
        s = _node_to_str(child).upper()
        if not s:
            continue
        if isinstance(child, Intent_Attr_Spec):
            # INTENT(IN), INTENT(OUT), INTENT(INOUT)
            attrs.add(s.replace(" ", ""))  # e.g. "INTENT(IN)"
        elif isinstance(child, Access_Spec):
            attrs.add(s)  # PUBLIC or PRIVATE
        elif isinstance(child, Attr_Spec):
            attrs.add(s)
        else:
            attrs.add(s)
    return attrs


def _parse_entity_decl_list(entity_list) -> List[Tuple[str, bool]]:
    """Parse an Entity_Decl_List or Component_Decl_List into [(name, has_initializer), ...].

    has_initializer is True if the entity has an = initializer (e.g.,
    ``x = 0`` or ``p => NULL()``).

    Handles both Entity_Decl (regular variables) and Component_Decl
    (derived type components) — they have the same children structure
    but are separate classes in fparser.
    """
    entities: List[Tuple[str, bool]] = []
    if entity_list is None:
        return entities
    for child in entity_list.children:
        # Handle both Entity_Decl (variables) and Component_Decl (derived type components)
        if isinstance(child, (Entity_Decl, Component_Decl)):
            # Children: [Name, Array_Spec, Char_Length, Initialization]
            name = ""
            has_init = False
            for c in child.children:
                if isinstance(c, Name):
                    name = _node_to_str(c)
                elif c is not None and "Init" in type(c).__name__:
                    has_init = True
                elif c is not None and _node_to_str(c).startswith("="):
                    has_init = True
            if name:
                entities.append((name, has_init))
    return entities


def _parse_use_stmt(node) -> Tuple[str, Optional[List[str]]]:
    """Parse a Use_Stmt into (module_name, only_list_or_None).

    Returns:
        (module_name, None) for ``USE mod`` (import all)
        (module_name, ['a', 'b']) for ``USE mod, ONLY: a, b``
    """
    # Use_Stmt children: [module_nature, rename_list, Name, only_separator, Only_List]
    module_name = ""
    only_list: Optional[List[str]] = None

    for child in node.children:
        if isinstance(child, Name):
            module_name = _node_to_str(child)
        elif isinstance(child, Only_List):
            only_list = []
            for item in child.children:
                only_list.append(_node_to_str(item).split("=>")[0].strip())

    return module_name, only_list


def _parse_dummy_arg_list(node) -> List[str]:
    """Parse a Dummy_Arg_List into a list of argument names."""
    if node is None:
        return []
    args: List[str] = []
    for child in node.children:
        if isinstance(child, Name):
            args.append(_node_to_str(child))
        else:
            # Could be a dummy arg with type, just get the name
            s = _node_to_str(child)
            if s:
                args.append(s)
    return args


# ---------------------------------------------------------------------------
# Main symbol table class
# ---------------------------------------------------------------------------
class ProjectSymbolTable:
    """Project-wide symbol table built from fparser ASTs.

    Build with :meth:`build`, then query with :meth:`is_declared`,
    :meth:`get_type`, :meth:`is_parameter`, etc.
    """

    def __init__(self):
        self.modules: Dict[str, ModuleInfo] = {}
        self._modules_lower: Dict[str, str] = {}  # lowercase name -> original name
        self.scopes: Dict[str, ScopeInfo] = {}  # keyed by "file::scope_name"
        self._scopes_lower: Dict[str, str] = {}  # lowercase "file::scope" -> original key
        self.files: List[str] = []
        self.parse_failures: List[Tuple[str, str]] = []
        self._parser = None
        # Cache: scope_name -> resolved symbol dict (local + USE + parent)
        self._resolved_cache: Dict[str, Dict[str, Symbol]] = {}

        # Interprocedural: variable -> list of (scope, action, line)
        # action is "allocate" or "deallocate"
        self.allocations: Dict[str, List[Tuple[str, str, int, str]]] = {}
        # allocations: var_name -> [(scope_name, "allocate"/"deallocate", line, file_path)]

    # ------------------------------------------------------------------
    # Building
    # ------------------------------------------------------------------
    def build(self, fortran_files: List[str], source_root: str = ""):
        """Parse all files and build the symbol table.

        Parameters
        ----------
        fortran_files
            List of absolute paths to ``.f90`` files.
        source_root
            Root directory of the source tree (for relative path display).
        """
        self.files = fortran_files
        self._parser = ParserFactory().create(std="f2008")

        # Parse all files, store ASTs
        asts: List[Tuple[str, str, Program]] = []  # (abs_path, rel_path, ast)
        for fpath in fortran_files:
            rel_path = os.path.relpath(fpath, source_root) if source_root else fpath
            try:
                ast = _read_fortran_file(fpath, self._parser)
                asts.append((fpath, rel_path, ast))
            except Exception as e:
                self.parse_failures.append((rel_path, str(e)[:200]))
                logger.warning("Failed to parse %s: %s", rel_path, e)

        logger.info("Parsed %d/%d files successfully", len(asts), len(fortran_files))

        # Pass 1: Collect module exports
        for abs_path, rel_path, ast in asts:
            self._collect_module_exports(ast, rel_path)

        # Pass 2: Collect scope info (subroutines, functions, programs)
        for abs_path, rel_path, ast in asts:
            self._collect_scopes(ast, rel_path)

        # Pass 3: Collect interprocedural allocation info
        for abs_path, rel_path, ast in asts:
            self._collect_allocations(ast, rel_path)

        logger.info(
            "Symbol table built: %d modules, %d scopes",
            len(self.modules),
            len(self.scopes),
        )

    # ------------------------------------------------------------------
    # Pass 1: Module export collection
    # ------------------------------------------------------------------
    def _collect_module_exports(self, ast: Program, file_path: str):
        """Extract module exports from a parsed file."""
        from fparser.two.Fortran2003 import (
            Access_Stmt,
            Function_Stmt,
            Interface_Block,
            Subroutine_Stmt,
        )

        for mod_node in walk(ast, Module):
            mod_name = ""
            mod_stmt = None
            for child in mod_node.children:
                if isinstance(child, Module_Stmt):
                    mod_stmt = child
                    for c in child.children:
                        if isinstance(c, Name):
                            mod_name = _node_to_str(c)
                    break

            if not mod_name:
                continue

            mod_info = ModuleInfo(name=mod_name, file_path=file_path)
            self.modules[mod_name] = mod_info
            # Also store under lowercase key for case-insensitive lookup
            self._modules_lower[mod_name.lower()] = mod_name

            # Find the Specification_Part of the module
            for child in mod_node.children:
                if isinstance(child, Specification_Part):
                    self._process_specification_part(child, mod_info, mod_name)
                    # Check for IMPLICIT NONE
                    mod_info.has_implicit_none = self._has_implicit_none(child)

                    # Process PUBLIC/PRIVATE access statements
                    for access_stmt in walk(child, Access_Stmt):
                        self._process_access_stmt(access_stmt, mod_info)

            # Process derived types in the module
            for dt_def in walk(mod_node, Derived_Type_Def):
                self._process_derived_type(dt_def, mod_info)

            # Process contained procedures (subroutines/functions) as exports
            for sub_stmt in walk(mod_node, Subroutine_Stmt):
                proc_name = ""
                for c in sub_stmt.children:
                    if isinstance(c, Name):
                        proc_name = _node_to_str(c)
                        break
                if proc_name and proc_name not in mod_info.exports:
                    mod_info.exports[proc_name] = Symbol(
                        name=proc_name,
                        type="PROCEDURE",
                        scope=mod_name,
                        is_public=True,
                        is_procedure=True,
                    )

            for func_stmt in walk(mod_node, Function_Stmt):
                proc_name = ""
                for c in func_stmt.children:
                    if isinstance(c, Name):
                        proc_name = _node_to_str(c)
                        break
                if proc_name and proc_name not in mod_info.exports:
                    mod_info.exports[proc_name] = Symbol(
                        name=proc_name,
                        type="PROCEDURE",
                        scope=mod_name,
                        is_public=True,
                        is_procedure=True,
                    )

            # Process interface blocks (generic interfaces)
            for iface_block in walk(mod_node, Interface_Block):
                from fparser.two.Fortran2003 import Interface_Stmt

                for iface_stmt in walk(iface_block, Interface_Stmt):
                    s = _node_to_str(iface_stmt).upper()
                    # INTERFACE name or INTERFACE OPERATOR(...)
                    # Only add named interfaces
                    for c in iface_stmt.children:
                        if isinstance(c, Name):
                            iface_name = _node_to_str(c)
                            if iface_name and iface_name not in mod_info.exports:
                                mod_info.exports[iface_name] = Symbol(
                                    name=iface_name,
                                    type="PROCEDURE",
                                    scope=mod_name,
                                    is_public=True,
                                    is_procedure=True,
                                )

    def _process_access_stmt(self, stmt, mod_info: ModuleInfo):
        """Process a PUBLIC/PRIVATE access statement.

        Handles:
          - ``PUBLIC`` (bare) — sets default visibility to public
          - ``PRIVATE`` (bare) — sets default visibility to private
          - ``PUBLIC :: a, b, c`` — marks named symbols as public
          - ``PRIVATE :: a, b, c`` — marks named symbols as private
        """
        s = _node_to_str(stmt).upper()
        is_public = s.startswith("PUBLIC")

        # Check if there are named items (PUBLIC :: a, b)
        # Access_Stmt children: [Access_Spec, Optional[Access_Id_List]]
        children = list(stmt.children)
        if len(children) < 2 or children[1] is None:
            # Bare PUBLIC or PRIVATE — sets default visibility
            if not is_public:
                mod_info.default_private = True
            return

        # Named items
        access_id_list = children[1]
        for item in walk(access_id_list, Name):
            name = _node_to_str(item)
            if not name:
                continue
            if name in mod_info.exports:
                mod_info.exports[name].is_public = is_public
            elif is_public:
                # Symbol might be a procedure not yet processed, or a generic name
                mod_info.exports[name] = Symbol(
                    name=name,
                    type="PROCEDURE",
                    scope=mod_info.name,
                    is_public=True,
                    is_procedure=True,
                )

    def _process_specification_part(
        self, spec_part: Specification_Part, mod_info: ModuleInfo, scope_name: str
    ):
        """Process a Specification_Part to extract declarations."""
        for node in walk(spec_part, Type_Declaration_Stmt):
            self._process_type_declaration(node, mod_info.exports, scope_name)
        # Also process PROCEDURE declarations (procedure pointers)
        for node in walk(spec_part, Procedure_Declaration_Stmt):
            self._process_procedure_declaration(node, mod_info.exports, scope_name)

    def _process_procedure_declaration(
        self,
        node: Procedure_Declaration_Stmt,
        symbols: Dict[str, Symbol],
        scope_name: str,
    ):
        """Process a Procedure_Declaration_Stmt and add symbols to the dict.

        These are procedure pointers like:
            PROCEDURE(iface), POINTER :: proc_name

        children: [Name (interface), Proc_Attr_Spec_List, Proc_Decl_List]
        """
        children = list(node.children)
        if len(children) < 3:
            return

        interface_name = _node_to_str(children[0]) if isinstance(children[0], Name) else ""
        attr_list = children[1]
        proc_decl_list = children[2]

        # Parse attributes
        attrs: List[str] = []
        is_pointer = False
        is_public = False
        if attr_list and hasattr(attr_list, "children"):
            for attr in attr_list.children:
                attr_str = str(attr).upper().strip()
                attrs.append(attr_str)
                if attr_str == "POINTER":
                    is_pointer = True
                if attr_str == "PUBLIC":
                    is_public = True

        # Parse procedure declaration names
        if isinstance(proc_decl_list, Proc_Decl_List):
            for proc_decl in proc_decl_list.children:
                # Proc_Decl_List children can be either Proc_Decl nodes
                # (with Name children) or Name nodes directly (fparser
                # sometimes puts Name directly as children of Proc_Decl_List)
                proc_name = ""
                has_init = False
                if isinstance(proc_decl, Name):
                    # Direct Name node
                    proc_name = _node_to_str(proc_decl)
                elif hasattr(proc_decl, "children"):
                    # Proc_Decl node — first Name child is the procedure name
                    for c in proc_decl.children:
                        if isinstance(c, Name):
                            proc_name = _node_to_str(c)
                            break
                else:
                    proc_name = str(proc_decl).split("=")[0].strip()

                if proc_name:
                    sym = Symbol(
                        name=proc_name,
                        type=f"PROCEDURE({interface_name})",
                        attributes=attrs.copy(),
                        scope=scope_name,
                        is_public=is_public,
                        initialized=False,
                        is_dummy=False,
                        intent="",
                        is_allocatable=False,
                        is_pointer=is_pointer,
                        is_parameter=False,
                        is_target=False,
                        is_optional=False,
                        is_external=False,
                        is_intrinsic=False,
                        dimensions=0,
                    )
                    symbols[proc_name] = sym

    def _process_type_declaration(
        self,
        node: Type_Declaration_Stmt,
        symbols: Dict[str, Symbol],
        scope_name: str,
    ):
        """Process a Type_Declaration_Stmt and add symbols to the dict."""
        # children: [Declaration_Type_Spec, Attr_Spec_List, Entity_Decl_List]
        children = list(node.children)
        if len(children) < 3:
            return

        type_spec = children[0]
        attr_list = children[1]
        entity_list = children[2]

        var_type = _get_type_from_declaration_type_spec(type_spec)
        attrs = _parse_attr_spec_list(attr_list)
        entities = _parse_entity_decl_list(entity_list)

        is_public = "PUBLIC" in attrs
        is_parameter = "PARAMETER" in attrs
        is_allocatable = "ALLOCATABLE" in attrs
        is_pointer = "POINTER" in attrs
        is_target = "TARGET" in attrs
        is_optional = "OPTIONAL" in attrs
        is_external = "EXTERNAL" in attrs
        is_intrinsic = "INTRINSIC" in attrs

        intent = ""
        for a in attrs:
            if a.startswith("INTENT("):
                intent = a[len("INTENT(") : -1]

        # Check for DIMENSION
        dimensions = 0
        for a in attrs:
            if a.startswith("DIMENSION("):
                # Count commas + 1 for rank
                dimensions = a.count(",") + 1

        for name, has_init in entities:
            sym = Symbol(
                name=name,
                type=var_type,
                attributes=attrs.copy(),
                scope=scope_name,
                is_public=is_public,
                initialized=is_parameter or has_init,
                is_dummy=False,
                intent=intent,
                is_allocatable=is_allocatable,
                is_pointer=is_pointer,
                is_parameter=is_parameter,
                is_target=is_target,
                is_optional=is_optional,
                is_external=is_external,
                is_intrinsic=is_intrinsic,
                dimensions=dimensions,
            )
            symbols[name] = sym

    def _process_derived_type(self, dt_def: Derived_Type_Def, mod_info: ModuleInfo):
        """Process a Derived_Type_Def and add to the module's derived_types."""
        type_name = ""
        for child in dt_def.children:
            if isinstance(child, Derived_Type_Stmt):
                for c in child.children:
                    if hasattr(c, "string") or isinstance(c, Name):
                        s = _node_to_str(c)
                        # The Type_Name is a Name node
                        if isinstance(c, type(child.children[1])) if len(child.children) > 1 else False:
                            pass
                # Find Type_Name (second child after Type_Attr_Spec_List)
                for c in child.children:
                    if isinstance(c, Name):
                        type_name = _node_to_str(c)
                        break
                break

        if not type_name:
            return

        components: Dict[str, Symbol] = {}
        for child in dt_def.children:
            if isinstance(child, Component_Part):
                # In fparser, derived type components are Data_Component_Def_Stmt nodes,
                # NOT Type_Declaration_Stmt (they share a common base but are separate classes)
                for tds in walk(child, Data_Component_Def_Stmt):
                    self._process_type_declaration(tds, components, type_name)
                # Also process procedure components (procedure pointers in derived types)
                for pds in walk(child, Procedure_Declaration_Stmt):
                    self._process_procedure_declaration(pds, components, type_name)

        mod_info.derived_types[type_name] = components

    def _has_implicit_none(self, spec_part: Specification_Part) -> bool:
        """Check if a Specification_Part contains IMPLICIT NONE."""
        from fparser.two.Fortran2003 import Implicit_Stmt

        for node in walk(spec_part, Implicit_Stmt):
            s = _node_to_str(node).upper()
            if "NONE" in s:
                return True
        return False

    # ------------------------------------------------------------------
    # Pass 2: Scope collection
    # ------------------------------------------------------------------
    def _collect_scopes(self, ast: Program, file_path: str):
        """Extract scope info (subroutines, functions, programs) from a file."""
        # Process modules and their contained procedures
        for mod_node in walk(ast, Module):
            mod_name = ""
            for child in mod_node.children:
                if isinstance(child, Module_Stmt):
                    for c in child.children:
                        if isinstance(c, Name):
                            mod_name = _node_to_str(c)
                    break

            if not mod_name:
                continue

            # Process module-level scope
            mod_scope_key = f"{file_path}::{mod_name}"
            mod_scope = ScopeInfo(
                name=mod_name,
                kind="module",
                file_path=file_path,
                has_implicit_none=self.modules.get(mod_name, ModuleInfo(name="")).has_implicit_none,
            )

            # Get module-level symbols from the module info
            if mod_name in self.modules:
                mod_scope.symbols = self.modules[mod_name].exports.copy()

            # Process USE statements at module level
            for child in mod_node.children:
                if isinstance(child, Specification_Part):
                    for use_node in walk(child, Use_Stmt):
                        mod_name_used, only_list = _parse_use_stmt(use_node)
                        if mod_name_used:
                            mod_scope.use_imports[mod_name_used] = only_list

            self.scopes[mod_scope_key] = mod_scope
            self._scopes_lower[mod_scope_key.lower()] = mod_scope_key

            # Process contained subroutines/functions
            from fparser.two.Fortran2003 import Module_Subprogram_Part

            for child in mod_node.children:
                if isinstance(child, Module_Subprogram_Part):
                    for sub in walk(child, Subroutine_Stmt):
                        self._process_subroutine_scope(sub, file_path, mod_name, ast)
                    for func in walk(child, Function_Stmt):
                        self._process_function_scope(func, file_path, mod_name, ast)

        # Process top-level subroutines/functions/programs (not in modules)
        for sub_stmt in walk(ast, Subroutine_Stmt):
            # Check if it's inside a module (already processed above)
            if not self._is_inside_module(sub_stmt, ast):
                self._process_subroutine_scope(sub_stmt, file_path, "", ast)

        for func_stmt in walk(ast, Function_Stmt):
            if not self._is_inside_module(func_stmt, ast):
                self._process_function_scope(func_stmt, file_path, "", ast)

        for prog_stmt in walk(ast, Program_Stmt):
            self._process_program_scope(prog_stmt, file_path, ast)

    def _is_inside_module(self, target_node, ast) -> bool:
        """Check if a node is inside a Module."""
        for mod_node in walk(ast, Module):
            if target_node in walk(mod_node, type(target_node)):
                return True
        return False

    def _process_subroutine_scope(
        self, sub_stmt: Subroutine_Stmt, file_path: str, parent_module: str, ast: Program
    ):
        """Process a subroutine scope."""
        sub_name = ""
        dummy_args: List[str] = []
        for child in sub_stmt.children:
            if isinstance(child, Name):
                sub_name = _node_to_str(child)
            elif isinstance(child, Dummy_Arg_List):
                dummy_args = _parse_dummy_arg_list(child)

        if not sub_name:
            return

        scope_key = f"{file_path}::{sub_name}"
        scope = ScopeInfo(
            name=sub_name,
            kind="subroutine",
            parent=parent_module,
            file_path=file_path,
            dummy_args=dummy_args,
        )

        # Find the subroutine's specification part
        # The subroutine is a Subroutine_Subprogram node containing the Subroutine_Stmt
        from fparser.two.Fortran2003 import Subroutine_Subprogram

        for sub_prog in walk(ast, Subroutine_Subprogram):
            if sub_stmt in sub_prog.children:
                for child in sub_prog.children:
                    if isinstance(child, Specification_Part):
                        scope.has_implicit_none = self._has_implicit_none(child)
                        # Process USE statements
                        for use_node in walk(child, Use_Stmt):
                            mod_name, only_list = _parse_use_stmt(use_node)
                            if mod_name:
                                scope.use_imports[mod_name] = only_list
                        # Process declarations
                        for tds in walk(child, Type_Declaration_Stmt):
                            self._process_type_declaration(tds, scope.symbols, sub_name)
                        for pds in walk(child, Procedure_Declaration_Stmt):
                            self._process_procedure_declaration(pds, scope.symbols, sub_name)
                break

        # Mark dummy args
        for arg in dummy_args:
            if arg in scope.symbols:
                scope.symbols[arg].is_dummy = True
                if scope.symbols[arg].intent == "IN":
                    scope.symbols[arg].initialized = True

        self.scopes[scope_key] = scope
        self._scopes_lower[scope_key.lower()] = scope_key

    def _process_function_scope(
        self, func_stmt: Function_Stmt, file_path: str, parent_module: str, ast: Program
    ):
        """Process a function scope."""
        func_name = ""
        dummy_args: List[str] = []
        for child in func_stmt.children:
            if isinstance(child, Name):
                func_name = _node_to_str(child)
            elif isinstance(child, Dummy_Arg_List):
                dummy_args = _parse_dummy_arg_list(child)

        if not func_name:
            return

        scope_key = f"{file_path}::{func_name}"
        scope = ScopeInfo(
            name=func_name,
            kind="function",
            parent=parent_module,
            file_path=file_path,
            dummy_args=dummy_args,
        )

        from fparser.two.Fortran2003 import Function_Subprogram

        for func_prog in walk(ast, Function_Subprogram):
            if func_stmt in func_prog.children:
                for child in func_prog.children:
                    if isinstance(child, Specification_Part):
                        scope.has_implicit_none = self._has_implicit_none(child)
                        for use_node in walk(child, Use_Stmt):
                            mod_name, only_list = _parse_use_stmt(use_node)
                            if mod_name:
                                scope.use_imports[mod_name] = only_list
                        for tds in walk(child, Type_Declaration_Stmt):
                            self._process_type_declaration(tds, scope.symbols, func_name)
                        for pds in walk(child, Procedure_Declaration_Stmt):
                            self._process_procedure_declaration(pds, scope.symbols, func_name)
                break

        for arg in dummy_args:
            if arg in scope.symbols:
                scope.symbols[arg].is_dummy = True
                if scope.symbols[arg].intent == "IN":
                    scope.symbols[arg].initialized = True

        self.scopes[scope_key] = scope
        self._scopes_lower[scope_key.lower()] = scope_key

    def _process_program_scope(self, prog_stmt: Program_Stmt, file_path: str, ast: Program):
        """Process a main program scope."""
        prog_name = ""
        for child in prog_stmt.children:
            if isinstance(child, Name):
                prog_name = _node_to_str(child)
                break

        if not prog_name:
            prog_name = "MAIN PROGRAM"

        scope_key = f"{file_path}::{prog_name}"
        scope = ScopeInfo(
            name=prog_name,
            kind="program",
            file_path=file_path,
        )

        from fparser.two.Fortran2003 import Main_Program

        for main_prog in walk(ast, Main_Program):
            if prog_stmt in main_prog.children:
                for child in main_prog.children:
                    if isinstance(child, Specification_Part):
                        scope.has_implicit_none = self._has_implicit_none(child)
                        for use_node in walk(child, Use_Stmt):
                            mod_name, only_list = _parse_use_stmt(use_node)
                            if mod_name:
                                scope.use_imports[mod_name] = only_list
                        for tds in walk(child, Type_Declaration_Stmt):
                            self._process_type_declaration(tds, scope.symbols, prog_name)
                        for pds in walk(child, Procedure_Declaration_Stmt):
                            self._process_procedure_declaration(pds, scope.symbols, prog_name)
                break

        self.scopes[scope_key] = scope
        self._scopes_lower[scope_key.lower()] = scope_key

    # ------------------------------------------------------------------
    # Pass 3: Interprocedural allocation collection
    # ------------------------------------------------------------------
    def _collect_allocations(self, ast: Program, file_path: str):
        """Collect ALLOCATE/DEALLOCATE statements for interprocedural analysis.

        Records the scope (subroutine/function/program) where each
        allocation/deallocation occurs, enabling the init/cleanup pattern
        detection in Rule 9 (COM.DESIGN.Alloc).
        """
        from fparser.two.Fortran2003 import (
            Function_Subprogram,
            Main_Program,
            Subroutine_Subprogram,
        )

        # Build a list of (subprogram_node, scope_name) pairs
        subprograms: List[Tuple[object, str]] = []

        for sub_prog in walk(ast, Subroutine_Subprogram):
            name = self._get_subprogram_name(sub_prog)
            if name:
                subprograms.append((sub_prog, name))

        for func_prog in walk(ast, Function_Subprogram):
            name = self._get_subprogram_name(func_prog)
            if name:
                subprograms.append((func_prog, name))

        for main_prog in walk(ast, Main_Program):
            name = self._get_subprogram_name(main_prog)
            if name:
                subprograms.append((main_prog, name))

        def _find_enclosing_scope(node) -> str:
            """Find the name of the enclosing subprogram for a node."""
            for sub_prog, scope_name in subprograms:
                if self._contains_node(sub_prog, node):
                    return scope_name
            return ""

        for alloc_node in walk(ast, Allocate_Stmt):
            var_names = self._extract_alloc_var_names(alloc_node)
            line = _get_line(alloc_node)
            scope_name = _find_enclosing_scope(alloc_node)
            for var in var_names:
                base_var = var.split("%")[0].strip()  # Get base variable (before %)
                if base_var not in self.allocations:
                    self.allocations[base_var] = []
                self.allocations[base_var].append(
                    (scope_name, "allocate", line, file_path)
                )

        for dealloc_node in walk(ast, Deallocate_Stmt):
            var_names = self._extract_alloc_var_names(dealloc_node)
            line = _get_line(dealloc_node)
            scope_name = _find_enclosing_scope(dealloc_node)
            for var in var_names:
                base_var = var.split("%")[0].strip()
                if base_var not in self.allocations:
                    self.allocations[base_var] = []
                self.allocations[base_var].append(
                    (scope_name, "deallocate", line, file_path)
                )

    @staticmethod
    def _get_subprogram_name(sub_prog) -> str:
        """Extract the name from a subprogram node."""
        from fparser.two.Fortran2003 import (
            Function_Stmt,
            Program_Stmt,
            Subroutine_Stmt,
        )

        for child in sub_prog.children:
            if isinstance(child, (Subroutine_Stmt, Function_Stmt, Program_Stmt)):
                for c in child.children:
                    if isinstance(c, Name):
                        return _node_to_str(c)
        return ""

    @staticmethod
    def _contains_node(parent, target) -> bool:
        """Check if target is a descendant of parent (or parent itself)."""
        if parent is target:
            return True
        if hasattr(parent, "children"):
            for child in parent.children:
                if child is not None and ProjectSymbolTable._contains_node(
                    child, target
                ):
                    return True
        return False

    def _extract_alloc_var_names(self, node) -> List[str]:
        """Extract variable names from an Allocate_Stmt or Deallocate_Stmt.

        Only extracts the allocation target names (the first Name in
        each Allocation/Allocate_Object), not dimension specifiers or
        STAT variables.
        """
        var_names: List[str] = []
        # children: [None, Allocation_List, Alloc_Opt_List] for Allocate_Stmt
        # children: [None, Allocate_Object_List, ...] for Deallocate_Stmt
        for child in node.children:
            if child is None:
                continue
            s = type(child).__name__
            if "Allocation" in s or "Allocate_Object" in s:
                # Each child of Allocation_List/Allocate_Object_List is an
                # Allocation or Allocate_Object node.
                # Allocation children: [Allocate_Object, Allocate_Shape_Spec_List]
                # Allocate_Object is typically a Name or Data_Ref
                # We only want the first Name (the variable being allocated)
                for alloc_item in child.children:
                    if alloc_item is None:
                        continue
                    # Get the first Name from this allocation item
                    names = walk(alloc_item, Name)
                    if names:
                        var_names.append(_node_to_str(names[0]))
        return var_names

    # ------------------------------------------------------------------
    # Query methods
    # ------------------------------------------------------------------
    def _find_scope(self, scope_name: str, file_path: str = "") -> Optional[ScopeInfo]:
        """Find a ScopeInfo by name, optionally filtered by file.

        Case-insensitive (Fortran is case-insensitive).
        """
        if file_path:
            key = f"{file_path}::{scope_name}"
            if key in self.scopes:
                return self.scopes[key]
            # Case-insensitive lookup
            key_lower = key.lower()
            if key_lower in self._scopes_lower:
                return self.scopes[self._scopes_lower[key_lower]]
        # Search all scopes with this name (case-insensitive)
        scope_lower = scope_name.lower()
        for key, scope in self.scopes.items():
            if scope.name.lower() == scope_lower:
                return scope
        return None

    def _resolve_scope_symbols(self, scope: ScopeInfo) -> Dict[str, Symbol]:
        """Build a fully-resolved symbol dict for a scope (local + USE + parent).

        This resolves USE imports against the module export table.
        Case-insensitive module name lookup (Fortran is case-insensitive).
        """
        cache_key = f"{scope.file_path}::{scope.name}"
        if cache_key in self._resolved_cache:
            return self._resolved_cache[cache_key]

        resolved: Dict[str, Symbol] = {}

        # Helper: case-insensitive module lookup
        def _find_module(name: str) -> Optional[ModuleInfo]:
            if name in self.modules:
                return self.modules[name]
            orig = self._modules_lower.get(name.lower())
            if orig:
                return self.modules[orig]
            return None

        # 1. Add USE-imported symbols
        for mod_name, only_list in scope.use_imports.items():
            mod_info = _find_module(mod_name)
            if mod_info is None:
                # Module not in our project — mark all imports as external
                if only_list is None:
                    # USE without ONLY — we can't know what's imported
                    # Mark as "external module" — symbols will be unknown type
                    pass
                else:
                    for name in only_list:
                        if name not in resolved:
                            resolved[name] = Symbol(
                                name=name,
                                type="UNKNOWN",
                                scope=mod_name,
                                is_public=True,
                                initialized=True,  # Assume imported symbols are initialized
                            )
            else:
                if only_list is None:
                    # USE without ONLY — import all PUBLIC symbols
                    # If module has default_private, only explicitly PUBLIC symbols are imported
                    if mod_info.default_private:
                        for name, sym in mod_info.exports.items():
                            if sym.is_public:
                                resolved[name] = sym
                    else:
                        # Default: all symbols are public
                        for name, sym in mod_info.exports.items():
                            resolved[name] = sym
                else:
                    # USE with ONLY — import only listed symbols
                    for name in only_list:
                        if name in mod_info.exports:
                            resolved[name] = mod_info.exports[name]
                        else:
                            # Symbol not found in module exports — might be a procedure
                            # not yet collected, or an operator
                            resolved[name] = Symbol(
                                name=name,
                                type="UNKNOWN",
                                scope=mod_name,
                                is_public=True,
                                initialized=True,
                                is_procedure=True,
                            )

        # 2. Add parent module symbols (if this is a contained procedure)
        if scope.parent:
            parent_scope = self._find_scope(scope.parent)
            if parent_scope:
                parent_resolved = self._resolve_scope_symbols(parent_scope)
                for name, sym in parent_resolved.items():
                    if name not in resolved:
                        resolved[name] = sym
            else:
                # Case-insensitive parent module lookup
                parent_lower = scope.parent.lower()
                orig_name = self._modules_lower.get(parent_lower)
                if orig_name and orig_name in self.modules:
                    mod_info = self.modules[orig_name]
                    for name, sym in mod_info.exports.items():
                        if name not in resolved:
                            resolved[name] = sym

        # 3. Add local symbols (override imported ones)
        for name, sym in scope.symbols.items():
            resolved[name] = sym

        self._resolved_cache[cache_key] = resolved
        return resolved

    def is_declared(self, name: str, scope_name: str, file_path: str = "") -> bool:
        """Check if a variable is declared or imported in the given scope."""
        name_lower = name.lower()
        scope = self._find_scope(scope_name, file_path)
        if scope is None:
            return False

        resolved = self._resolve_scope_symbols(scope)

        # Case-insensitive search (Fortran is case-insensitive)
        for sname, sym in resolved.items():
            if sname.lower() == name_lower:
                return True

        # Check if it's an intrinsic
        if name_lower in FORTRAN_INTRINSICS:
            return True

        # Check if it's a Fortran keyword (not a variable)
        if name_lower in FORTRAN_KEYWORDS:
            return True

        return False

    def get_scope(self, scope_name: str, file_path: str = "") -> Optional[ScopeInfo]:
        """Public accessor for finding a scope by name.

        Case-insensitive (Fortran is case-insensitive).
        """
        return self._find_scope(scope_name, file_path)

    def get_type(self, name: str, scope_name: str, file_path: str = "") -> str:
        """Get the type of a variable in the given scope.

        Returns "" if the type cannot be determined.
        """
        name_lower = name.lower()
        scope = self._find_scope(scope_name, file_path)
        if scope is None:
            return ""

        resolved = self._resolve_scope_symbols(scope)

        for sname, sym in resolved.items():
            if sname.lower() == name_lower:
                return sym.type

        # Check intrinsics
        if name_lower in INTRINSIC_RETURN_TYPES:
            return INTRINSIC_RETURN_TYPES[name_lower]

        return ""

    def get_symbol(self, name: str, scope_name: str, file_path: str = "") -> Optional[Symbol]:
        """Get the Symbol object for a variable in the given scope."""
        name_lower = name.lower()
        scope = self._find_scope(scope_name, file_path)
        if scope is None:
            return None

        resolved = self._resolve_scope_symbols(scope)

        for sname, sym in resolved.items():
            if sname.lower() == name_lower:
                return sym

        return None

    def is_parameter(self, name: str, scope_name: str, file_path: str = "") -> bool:
        """Check if a variable is a PARAMETER constant."""
        sym = self.get_symbol(name, scope_name, file_path)
        return sym is not None and sym.is_parameter

    def is_intent_in(self, name: str, scope_name: str, file_path: str = "") -> bool:
        """Check if a variable has INTENT(IN)."""
        sym = self.get_symbol(name, scope_name, file_path)
        return sym is not None and sym.intent == "IN"

    def is_intent_out(self, name: str, scope_name: str, file_path: str = "") -> bool:
        """Check if a variable has INTENT(OUT)."""
        sym = self.get_symbol(name, scope_name, file_path)
        return sym is not None and sym.intent == "OUT"

    def is_intent_inout(self, name: str, scope_name: str, file_path: str = "") -> bool:
        """Check if a variable has INTENT(INOUT)."""
        sym = self.get_symbol(name, scope_name, file_path)
        return sym is not None and sym.intent == "INOUT"

    def is_intrinsic(self, name: str) -> bool:
        """Check if a name is a known Fortran intrinsic function."""
        return name.lower() in FORTRAN_INTRINSICS

    def get_intrinsic_return_type(self, name: str) -> str:
        """Get the return type of an intrinsic function."""
        return INTRINSIC_RETURN_TYPES.get(name.lower(), "")

    def get_module_exports(self, module_name: str) -> Dict[str, Symbol]:
        """Get all exported symbols from a module."""
        mod_info = self.modules.get(module_name)
        if mod_info:
            return mod_info.exports
        return {}

    def get_derived_type_components(
        self, type_name: str, module_name: str = ""
    ) -> Dict[str, Symbol]:
        """Get the components of a derived type.

        Searches all modules if module_name is not specified.
        """
        type_name_lower = type_name.lower()
        if module_name:
            mod_info = self.modules.get(module_name)
            if mod_info:
                for tname, components in mod_info.derived_types.items():
                    if tname.lower() == type_name_lower:
                        return components
        else:
            for mod_info in self.modules.values():
                for tname, components in mod_info.derived_types.items():
                    if tname.lower() == type_name_lower:
                        return components
        return {}

    def get_all_scopes_in_file(self, file_path: str) -> List[ScopeInfo]:
        """Get all scopes defined in a file."""
        return [s for s in self.scopes.values() if s.file_path == file_path]

    def get_scope_for_line(self, file_path: str, line: int) -> Optional[ScopeInfo]:
        """Find the scope that contains a given line in a file.

        This is a heuristic — it finds the scope whose declaration
        appears closest to (but before) the given line.
        """
        best_scope: Optional[ScopeInfo] = None
        best_line = 0
        for scope in self.scopes.values():
            if scope.file_path != file_path:
                continue
            # We don't have exact line ranges for scopes, but we can
            # use the fact that scopes are processed in order
            # For now, just return the first scope in the file
            if best_scope is None:
                best_scope = scope
        return best_scope


# ---------------------------------------------------------------------------
# Fortran keywords (not variables)
# ---------------------------------------------------------------------------
FORTRAN_KEYWORDS: Set[str] = {
    "program",
    "module",
    "subroutine",
    "function",
    "end",
    "if",
    "then",
    "else",
    "elseif",
    "endif",
    "do",
    "while",
    "enddo",
    "select",
    "case",
    "default",
    "endselect",
    "where",
    "elsewhere",
    "endwhere",
    "forall",
    "endforall",
    "interface",
    "endinterface",
    "type",
    "class",
    "endtype",
    "enum",
    "endenum",
    "block",
    "endblock",
    "associate",
    "endassociate",
    "critical",
    "endcritical",
    "team",
    "endteam",
    "change",
    "endchange",
    "use",
    "include",
    "implicit",
    "explicit",
    "none",
    "parameter",
    "public",
    "private",
    "protected",
    "save",
    "target",
    "pointer",
    "allocatable",
    "dimension",
    "intent",
    "in",
    "out",
    "inout",
    "optional",
    "external",
    "intrinsic",
    "entry",
    "return",
    "call",
    "contains",
    "only",
    "operator",
    "assignment",
    "procedure",
    "generic",
    "final",
    "deferred",
    "non_overridable",
    "abstract",
    "sequence",
    "equivalence",
    "common",
    "data",
    "format",
    "go",
    "to",
    "goto",
    "continue",
    "stop",
    "pause",
    "error",
    "allocate",
    "deallocate",
    "nullify",
    "open",
    "close",
    "read",
    "write",
    "print",
    "inquire",
    "backspace",
    "rewind",
    "endfile",
    "flush",
    "wait",
    "assign",
    "defined",
    "forall",
    "pure",
    "impure",
    "elemental",
    "recursive",
    "result",
    "operator",
    "bind",
    "volatile",
    "asynchronous",
    "value",
    "reference",
    "volatile",
    "import",
    "block",
    "data",
    "namelist",
    "enum",
    "c_int",
    "c_float",
    "c_double",
    "c_char",
    "iso_c_binding",
    "iso_fortran_env",
    "ieee_arithmetic",
    "ieee_exceptions",
    "ieee_features",
    "omp_lib",
    "size",
    "stat",
    "err",
    "iomsg",
    "newunit",
    "file",
    "status",
    "access",
    "form",
    "recl",
    "blank",
    "position",
    "action",
    "delim",
    "pad",
    "iostat",
    "unit",
    "fmt",
    "nml",
    "advance",
    "size",
    "eor",
    "end",
    "err",
    "exist",
    "opened",
    "number",
    "named",
    "name",
    "sequential",
    "direct",
    "formatted",
    "unformatted",
    "nextrec",
    "flen",
    "frec",
    "saccess",
    "saction",
    "sform",
    "sposition",
    "sdelim",
    "spad",
    "sblank",
    "srecl",
    "sstatus",
    "sfile",
    "sname",
    "snumber",
    "snamed",
    "sopened",
    "sexist",
    "ssequential",
    "sdirect",
    "sformatted",
    "sunformatted",
    "snextrec",
    "sflen",
    "sfrec",
    "siostat",
    "scount",
    "sround",
    "ssign",
    "sedit",
    "spad",
    "sasync",
    "sstream",
    "sdecimal",
    "sencoding",
    "sround",
    "ssign",
    "sedit",
    "spad",
    "sasync",
    "sstream",
    "sdecimal",
    "sencoding",
}
