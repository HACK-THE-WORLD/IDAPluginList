import re
from typing import Optional, Tuple

import idaapi

import symless.cpustate.arch as arch
import symless.utils.ida_utils as ida_utils
import symless.utils.utils as utils

# global expressions for symbol selection
re_ctors = re.compile(r"\b((?:[\w_]+::)*)([\S ]+)::\2(?:\(|$)")
re_vtable_single_msvc = re.compile(r"^const (.+)::`vftable'$")
re_vtable_single_gcc = re.compile(r"^`vtable for'([\s\S]+)$")
re_tinfo_gcc = re.compile(r"^`typeinfo for'([\s\S]+)$")
re_vtable_for_msvc = re.compile(r"^const (.+)::`vftable'{for `(.+)'}")

# invalid structure names exps & replacements
re_invalid_struc_name = (
    (re.compile(r"[\s\*&]"), ""),
    (re.compile(r"[,\-+]"), "_"),
    (re.compile(r"[<>]"), "__"),
)

# invalid method field names exps & replacements
re_invalid_method_name = ((re.compile(r"[\s]+"), "_"), (re.compile(r"[^0-9a-zA-Z_]"), ""))


# full method name from method signature
# i.e get Class::Initialize from Class::Initialize(Class*)
def full_method_name_from_signature(signature: str) -> str:
    fct = signature.split("(")[0]
    return fct


# method name from method signature
# i.e get Initialize from Class::Initialize(Class*)
def method_name_from_signature(signature: str) -> str:
    full = full_method_name_from_signature(signature)
    name = full.split("::")[-1]
    for exp, repl in re_invalid_method_name:
        name = exp.sub(repl, name)
    return name.strip("_")


# replace unvalid characters from structure's name
def struc_name_cleanup(original: str) -> str:
    out = original
    for exp, repl in re_invalid_struc_name:
        out = exp.sub(repl, out)
    return out


# ea was given a (non-dummy) name
def has_relevant_name(ea: int):
    flags = idaapi.get_flags(ea)
    return idaapi.has_any_name(flags) and not idaapi.has_dummy_name(flags)


# get class name from its constructor signature
def get_classname_from_ctor(fct_name: str) -> Optional[str]:
    if fct_name is None or "::" not in fct_name:
        return None

    m = re_ctors.search(fct_name)
    if m is None:
        return None

    return m.group(1) + m.group(2)


# get vtable structure's name from its symbol
def get_vtable_name_from_ctor(vtable_ea: int) -> Optional[str]:
    derived, parent = get_classnames_from_vtable(vtable_ea)

    if derived is None:
        utils.g_logger.debug(f"No name found for vtable 0x{vtable_ea:x}")
        return None

    if parent is None:
        return f"{derived}{idaapi.VTBL_SUFFIX}"

    return f"{derived}_{parent}{idaapi.VTBL_SUFFIX}"


# get child & parent classes names from vtable symbol
def get_classnames_from_vtable(vtable_ea: int) -> Tuple[Optional[str], Optional[str]]:
    if arch.is_elf():
        return get_classnames_from_vtable_gcc(vtable_ea)
    return get_classnames_from_vtable_msvc(vtable_ea)


# get child & parent classes names from vtable symbol for gcc compiled binaries
def get_classnames_from_vtable_gcc(vtable_ea: int) -> Tuple[Optional[str], Optional[str]]:
    ptr_size = ida_utils.get_ptr_size()

    # use vtable symbol
    label_ea = vtable_ea - (2 * ptr_size)
    vtbl_name = ida_utils.demangle_ea(label_ea)

    m = re_vtable_single_gcc.search(vtbl_name)
    if m is not None:
        return (m.group(1), None)

    # fallback - use typeinfo symbol
    tinfo_ea = ida_utils.__dereference_pointer(vtable_ea - ptr_size, ptr_size)
    tinfo = ida_utils.demangle_ea(tinfo_ea)

    m = re_tinfo_gcc.search(tinfo)
    if m is not None:
        return (m.group(1), None)

    return (None, None)


# get child & parent classes names from vtable symbol for msvc compiled binaries
def get_classnames_from_vtable_msvc(vtable_ea: int) -> Tuple[Optional[str], Optional[str]]:
    vtbl_name = ida_utils.demangle_ea(vtable_ea)

    if vtbl_name is None or "::" not in vtbl_name:
        return (None, None)

    m = re_vtable_single_msvc.search(vtbl_name)
    if m is not None:
        return (m.group(1), None)

    m = re_vtable_for_msvc.search(vtbl_name)
    if m is not None:
        return (m.group(1), m.group(2))

    return (None, None)
