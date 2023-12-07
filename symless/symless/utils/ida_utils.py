from typing import List, Optional, Tuple

import idaapi
import idautils
import idc

import symless.cpustate.cpustate as cpustate
import symless.symbols as symbols
import symless.utils.utils as utils

# alias small registers on full-width registers
X64_REG_ALIASES = {
    16: 0,  # al  -> rax
    17: 1,  # cl  -> rcx
    18: 2,  # dl  -> rdx
    19: 3,  # bl  -> rbx
    20: 0,  # ah  -> rax
    21: 1,  # ch  -> rcx
    22: 2,  # dh  -> rdx
    23: 3,  # bh  -> rbx
    25: 5,  # bpl -> rbp
    26: 6,  # sil -> rsi
    27: 7,  # dil -> rdi
}


""" Imports utilities """


def get_import_module_index(name: str) -> int:
    for i in range(idaapi.get_import_module_qty()):
        if idaapi.get_import_module_name(i) == name:
            return i
    return None


# Get ea of given import, from given module
def get_import_from_module(module: int, import_name: str) -> int:
    import_ea = None

    def iterator(ea, name, ord):
        nonlocal import_ea, import_name
        if name.startswith(import_name):
            import_ea = ea
            return False
        return True

    idaapi.enum_import_names(module, iterator)
    return import_ea


""" Names utilities """


def demangle(name: str, inf_attr=idc.INF_SHORT_DN) -> str:
    if not name:
        return name

    demangled = idaapi.demangle_name(name, idc.get_inf_attr(inf_attr))
    if demangled:
        return demangled

    return name


def demangle_ea(ea: int, inf_attr=idc.INF_SHORT_DN) -> str:
    return demangle(idaapi.get_name(ea), inf_attr)


# retrieve a name in the form "fct+offset"
def addr_friendly_name(ea: int) -> str:
    fct = idaapi.get_func(ea)
    if fct is None:
        return f"ea[0x{ea:x}]"

    offset = ea - fct.start_ea
    fct_name = symbols.full_method_name_from_signature(demangle(idaapi.get_short_name(fct.start_ea)))
    return "%s%s" % (fct_name, f"+{offset:x}" if offset != 0 else "")


""" Xrefs utilities """

# The following functions can be time-consuming when an address has numerous xref
# every xref has to be fetch using an API call


def get_references(address: int) -> List[int]:
    return [ref for ref in idautils.CodeRefsTo(address, 0)]


def get_data_references(address: int) -> List[int]:
    return [ref for ref in idautils.DataRefsTo(address)]


def get_all_references(address: int) -> set:
    crefs = get_references(address)
    drefs = get_data_references(address)
    return set(crefs + drefs)


""" Pointers utilities """


def get_ptr_size():
    return 8 if idaapi.get_inf_structure().is_64bit() else 4


def __dereference_pointer(addr: int, ptr_size: int) -> int:
    return idaapi.get_qword(addr) if ptr_size == 8 else idaapi.get_dword(addr)


def dereference_pointer(addr: int) -> int:
    return __dereference_pointer(addr, get_ptr_size())


def dereference_function_ptr(addr: int, ptr_size: int) -> bool:
    fea = __dereference_pointer(addr, ptr_size)
    func = idaapi.get_func(fea)
    if func is None or func.start_ea != fea:  # addr is a function entry point
        return None
    return fea


# get size bytes from given ea, if ea is initialized with a value
def get_nb_bytes(ea: int, size: int) -> int:
    if not idaapi.is_loaded(ea):
        return None

    if size == 8:
        return idaapi.get_qword(ea)
    if size == 4:
        return idaapi.get_dword(ea)
    if size == 2:
        return idaapi.get_word(ea)

    return idaapi.get_byte(ea)


# return true if data at given ea & size has a value
def is_data_initialized(ea: int, size: int) -> bool:
    # assume there can not be uninitialized bytes between data start & end
    return idaapi.is_loaded(ea) and idaapi.is_loaded(ea + size - 1)


""" Vftable utilities """


# can instruction at given ea load a vtable
def is_vtable_load(ea: int) -> bool:
    if idaapi.get_func(ea) is None:
        return False

    insn = idaapi.insn_t()
    if idaapi.decode_insn(insn, ea) == 0:
        return False

    if insn.itype not in [idaapi.NN_lea, idaapi.NN_mov] or insn.ops[0].type not in (
        idaapi.o_reg,
        idaapi.o_phrase,
        idaapi.o_displ,
    ):
        return False

    # type 1: lea/mov rax, vtbl
    # type 2: lea/mov rax, [eax + vtbl_offset] (PIE case)
    return insn.ops[1].type in [idaapi.o_mem, idaapi.o_displ, idaapi.o_imm]


# is vtable loaded at addr load stored later in a struct disp
# returns the stored value if it is the case
# TODO: miss mv [rax + rcx*2 + 16], rbx, even if we won't use it
def is_vtable_stored(load: int, loaded: int) -> int:
    # following is: mov [rcx + n], rax
    bb = get_bb(load)
    if bb is None:
        return idaapi.BADADDR

    bb.start_ea = load

    state = cpustate.state_t()
    state.reset_arguments(cpustate.get_abi())

    insn = idaapi.insn_t()
    ea = bb.start_ea

    while cpustate.next_instruction(ea, bb, insn):
        cpustate.process_instruction(state, insn)

        if len(state.writes) > 0 and isinstance(state.writes[0].src, cpustate.mem_t):
            actual_loaded = state.writes[0].src.addr
            if loaded == actual_loaded:
                return state.writes[0].src.get_val()

        ea += insn.size

    return idaapi.BADADDR


# is given ea a vtable or a vtable ref (.got)
# returns effective vtable address
def is_vtable_start(ea: int) -> int:
    if not idaapi.is_loaded(ea):
        return idaapi.BADADDR

    for xref in get_data_references(ea):
        # code loads the ea into a register
        if not is_vtable_load(xref):
            return idaapi.BADADDR

        # value from ea is stored into a struct
        stored_value = is_vtable_stored(xref, ea)
        if stored_value == idaapi.BADADDR:
            continue  # continue because we miss the "mov [rax + rcx*n], vtbl" instructions

        # stored addr points to a functions ptrs array
        if vtable_size(stored_value) == 0:
            return idaapi.BADADDR

        utils.g_logger.debug(f"0x{ea:x} is a vtable / vtable ref for vtable 0x{stored_value:x}")
        return stored_value

    return idaapi.BADADDR


# Returns function ea if function at given addr is in vtable, None otherwise
def is_in_vtable(start_addr: int, addr: int, ptr_size: int):
    fea = dereference_function_ptr(addr, ptr_size)
    if fea is None:
        return None

    if addr == start_addr:
        return fea

    if (
        idaapi.get_first_dref_to(addr) != idaapi.BADADDR or idaapi.get_first_cref_to(addr) != idaapi.BADADDR
    ):  # data is referenced, not part of the vtable
        return None

    return fea


# yield all members of given vtable
def vtable_members(addr: int):
    ptr_size = get_ptr_size()

    current = addr
    fea = is_in_vtable(addr, current, ptr_size)
    while fea is not None:
        yield fea
        current += ptr_size
        fea = is_in_vtable(addr, current, ptr_size)


def vtable_size(addr: int) -> int:
    vtbl = [fea for fea in vtable_members(addr)]
    return len(vtbl) * get_ptr_size()


# scans given segment for vtables
# WARN: will not return vtables only used at virtual bases (vbase)
def get_all_vtables_in(seg: idaapi.segment_t):
    utils.g_logger.info(
        "scanning segment %s[%x, %x] for vtables" % (idaapi.get_segm_name(seg), seg.start_ea, seg.end_ea)
    )

    current = seg.start_ea
    while current != idaapi.BADADDR and current < seg.end_ea:
        # do not cross functions
        chunk = idaapi.get_fchunk(current)
        if chunk is not None:
            current = chunk.end_ea
            continue

        # references a vtable ?
        effective_vtable = is_vtable_start(current)
        if effective_vtable != idaapi.BADADDR:
            utils.g_logger.info(f"vtable found at 0x{effective_vtable:x}")
            yield (current, effective_vtable)

        current = idaapi.next_head(current, seg.end_ea)


# scans code segments for vtables
def get_all_vtables():
    seg = idaapi.get_first_seg()
    while seg is not None:
        # search for vtables in .data and .text segments
        if seg.type == idaapi.SEG_CODE or seg.type == idaapi.SEG_DATA:
            for i in get_all_vtables_in(seg):
                yield i

        seg = idaapi.get_next_seg(seg.start_ea)


# vtable ea from already existing vtable struc
def get_vtable_ea(vtable: idaapi.struc_t) -> Tuple[int, str]:
    name = idaapi.get_struc_name(vtable.id)
    if not name.endswith(idaapi.VTBL_SUFFIX):
        return idaapi.BADADDR, name

    return idaapi.get_first_dref_to(vtable.id), name


""" Type utilities """


# get basic type
def get_basic_type(type: int) -> idaapi.tinfo_t:
    tinfo = idaapi.tinfo_t()
    tinfo.create_simple_type(type)
    return tinfo


# returns void* tinfo_t
def void_ptr() -> idaapi.tinfo_t:
    tinfo = get_basic_type(idaapi.BT_VOID)
    tinfo.create_ptr(tinfo)
    return tinfo


# local type by name
def get_local_type(name: str) -> Optional[idaapi.tinfo_t]:
    tinfo = idaapi.tinfo_t()
    if tinfo.get_named_type(idaapi.get_idati(), name):
        return tinfo
    return None


# tinfo to struc sid, by name correspondance
def struc_from_tinfo(tinfo: idaapi.tinfo_t) -> int:
    return idaapi.get_struc_id(tinfo.get_type_name())


# struc sid to tinfo
def tinfo_from_stuc(sid: int) -> Optional[idaapi.tinfo_t]:
    return get_local_type(idaapi.get_struc_name(sid))


""" Function utilities """


# creates funcarg_t type
def make_function_argument(typ: idaapi.tinfo_t, name: str = "") -> idaapi.funcarg_t:
    farg = idaapi.funcarg_t()
    farg.type = typ
    farg.name = name
    return farg


# shift pointer
def shift_ptr(ptr: idaapi.tinfo_t, parent: idaapi.tinfo_t, shift: int):
    if shift == 0:
        return

    ptr_data = idaapi.ptr_type_data_t()
    if ptr.get_ptr_details(ptr_data):
        ptr_data.taptr_bits |= idaapi.TAPTR_SHIFTED
        ptr_data.delta = shift
        ptr_data.parent = parent
        ptr.create_ptr(ptr_data, idaapi.BT_PTR)


# add argument to function + shift ptr argument
def set_function_argument(
    func_data: idaapi.func_type_data_t,
    index: int,
    typ: idaapi.tinfo_t,
    shift: int = 0,
    parent: Optional[idaapi.tinfo_t] = None,
    name: Optional[str] = None,
):
    while index > func_data.size():
        func_data.grow(make_function_argument(void_ptr(), f"arg_{func_data.size()}"))

    # apply __shifted
    shift_ptr(typ, parent, shift)

    if name is None:
        name = f"arg_{index}"

    arg = make_function_argument(typ, name)
    if index == func_data.size():
        func_data.grow(arg)
    else:
        func_data[index] = arg


# creates a new valid func_type_data_t object
def new_func_data(cc: int = idaapi.CM_CC_UNKNOWN) -> idaapi.func_type_data_t:
    func_data = idaapi.func_type_data_t()

    # ret type to void
    ret_tinfo = idaapi.tinfo_t()
    ret_tinfo.create_simple_type(idaapi.BT_VOID)
    func_data.rettype = ret_tinfo

    # calling convention
    func_data.cc = cc

    return func_data


# get function type, create default one if none
def get_or_create_fct_type(fea: int, default_cc: int) -> Tuple[idaapi.tinfo_t, idaapi.func_type_data_t]:
    func_tinfo = idaapi.tinfo_t()
    func_data = idaapi.func_type_data_t()

    if idaapi.get_tinfo(func_tinfo, fea):
        # unable to retrieve func_data on __high fcts, maybe try get_func_details(func_data, GTD_NO_ARGLOCS) ?
        if not func_tinfo.get_func_details(func_data):
            return (idaapi.tinfo_t(), new_func_data(default_cc))
    else:
        utils.g_logger.warning(f"Could not retrieve tinfo_t for function 0x{fea:x}, trying decompile_func..")

        # call decompiler to get more info
        try:
            import ida_hexrays

            cfunc = ida_hexrays.decompile_func(idaapi.get_func(fea), ida_hexrays.hexrays_failure_t(), 0)
            if cfunc.__deref__() is not None and cfunc.get_func_type(func_tinfo):
                func_tinfo.get_func_details(func_data)
                return (func_tinfo, func_data)

        except ImportError:
            pass

        utils.g_logger.warning(f"Could not retrieve tinfo_t for function 0x{fea:x} from decompiling")
        func_data = new_func_data(default_cc)

    return (func_tinfo, func_data)


# get basic block containing ea
def get_bb(ea: int) -> idaapi.range_t:
    func = idaapi.get_func(ea)
    if func is None:
        return None

    flow = idaapi.qflow_chart_t()
    flow.create("", func, func.start_ea, func.end_ea, idaapi.FC_NOEXT)
    for i in range(flow.size()):
        if ea >= flow[i].start_ea and ea < flow[i].end_ea:
            return idaapi.range_t(flow[i].start_ea, flow[i].end_ea)

    return None


# get instruction's operands + convert registers (al -> rax)
def get_insn_ops(insn: idaapi.insn_t) -> List[idaapi.op_t]:
    ops = list()
    for index_op in range(get_len_insn_ops(insn)):
        op = insn.ops[index_op]

        if op.reg in X64_REG_ALIASES:
            op.reg = X64_REG_ALIASES[op.reg]
        ops.append(op)
    return ops


# get instruction's operands count
def get_len_insn_ops(insn: idaapi.insn_t) -> int:
    res = 0
    for op in insn.ops:
        if op.type == idaapi.o_void:
            break
        res += 1
    return res


""" Misc """


# does IDA support structures folders
def can_create_folder() -> bool:
    try:
        return idaapi.get_std_dirtree is not None
    except AttributeError:
        return False
