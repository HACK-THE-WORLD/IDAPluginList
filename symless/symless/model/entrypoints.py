import collections
import enum
from typing import Collection, Dict, Iterable, Optional, Set, Tuple, Union

import idaapi

import symless.allocators as allocators
import symless.cpustate.cpustate as cpustate
import symless.utils.ida_utils as ida_utils
from symless.model import *

""" Entry points from memory allocations """


# Type of a memory allocation
class allocation_type(enum.Enum):
    WRAPPED_ALLOCATION = 0
    STATIC_SIZE = 1
    UNKNOWN = 2


# Analyze a given call to a memory allocator
# defines if the caller is an allocator wrapper, or if the call is a static allocation (known size)
def analyze_allocation(
    caller: idaapi.func_t, allocator: allocators.allocator_t, call_ea: int
) -> Tuple[allocation_type, Optional[Union[int, Iterable[int]]]]:
    before_allocation = True
    wrapper_args = None

    params = cpustate.dflow_ctrl_t(depth=0)
    for ea, state in cpustate.generate_state(caller, params, cpustate.get_default_cc()):
        if ea == call_ea and before_allocation:
            before_allocation = False

            action, wrapper_args = allocator.on_call(state)

            # caller jumps to allocator, with size argument past through
            if action == allocators.alloc_action_t.JUMP_TO_ALLOCATOR:
                return (allocation_type.WRAPPED_ALLOCATION, wrapper_args)

            # known size allocation
            if action == allocators.alloc_action_t.STATIC_ALLOCATION:
                return (allocation_type.STATIC_SIZE, wrapper_args)

            # unknown size allocation
            if action == allocators.alloc_action_t.UNDEFINED:
                return (allocation_type.UNKNOWN, None)

            # else: allocators.alloc_action_t.WRAPPED_ALLOCATOR
            # find if the caller returns the callee return value

        elif state.ret and not before_allocation:
            # allocation returned value is returned by caller
            if allocator.on_wrapper_ret(state, call_ea):
                return (allocation_type.WRAPPED_ALLOCATION, wrapper_args)

    return (allocation_type.UNKNOWN, None)


# Analyze all calls to a memory allocator and its wrappers
# returns a set of entrypoints (static allocation) made with this allocator
def analyze_allocator_heirs(
    allocator: allocators.allocator_t,
    allocators: Set[allocators.allocator_t],
    entries: entry_record_t,
):
    if allocator in allocators:  # avoid infinite recursion if crossed xrefs
        return

    allocators.add(allocator)

    # for all calls to allocator
    for allocation in ida_utils.get_all_references(allocator.ea):
        insn = idaapi.insn_t()
        if idaapi.decode_insn(insn, allocation) <= 0:
            continue

        if insn.itype in [
            idaapi.NN_jmp,
            idaapi.NN_jmpfi,
            idaapi.NN_jmpni,
            idaapi.NN_call,
            idaapi.NN_callfi,
            idaapi.NN_callni,
        ]:
            caller = idaapi.get_func(allocation)
            if caller is None:
                continue

            type, args = analyze_allocation(caller, allocator, allocation)

            if type == allocation_type.WRAPPED_ALLOCATION:
                wrapper = allocator.get_child(caller.start_ea, args)
                analyze_allocator_heirs(wrapper, allocators, entries)

            elif type == allocation_type.STATIC_SIZE:
                entry = ret_entry_t(allocation, caller.start_ea, args)
                entries.add_entry(entry, True)


# get all entrypoints from defined allocators
def get_allocations_entrypoints(
    imports: Iterable[allocators.allocator_t], entries: entry_record_t
) -> Set[allocators.allocator_t]:
    allocators = set()

    for i in imports:
        analyze_allocator_heirs(i, allocators, entries)

    return allocators


""" Entry points from ctors & dtors """


# count of xrefs to vtable functions
def vtable_ref_count(vtable_ea: int) -> Tuple[int, int]:
    count, size = 0, 0
    for fea in ida_utils.vtable_members(vtable_ea):
        count += len(ida_utils.get_data_references(fea))
        size += 1
    return count, size


# which one is the most derived vtable
# base heuristics: biggest one, or the one with the less referenced functions
def most_derived_vtable(v1: int, v2: int) -> int:
    c1, s1 = vtable_ref_count(v1)
    c2, s2 = vtable_ref_count(v2)
    if s1 > s2:
        return v1
    if s2 > s1:
        return v2
    if c1 > c2:
        return v2
    return v1


# is given function a ctor/dtor (does it load a vtable into a class given as first arg)
def is_ctor(func: idaapi.func_t, load_addr: int) -> Tuple[bool, int]:
    state = cpustate.state_t()
    params = cpustate.dflow_ctrl_t(depth=0)
    cpustate.set_argument(cpustate.get_object_cc(), state, 0, cpustate.sid_t(0))
    for _, state in cpustate.function_data_flow(func, state, params):
        if len(state.writes) > 0:
            write = state.writes[0]

            if not isinstance(write.src, cpustate.mem_t):
                continue

            if write.src.addr != load_addr:
                continue

            dst = state.get_previous_register(write.disp.reg)
            if isinstance(dst, cpustate.sid_t):  # arg 0 = struct ptr -> ctor/dtor
                offset = cpustate.ctypes.c_int32(write.disp.offset + dst.shift).value
                if offset >= 0:
                    return (True, offset)

            # vtable moved somewhere else
            return (False, -1)

    return (False, -1)


# get ctors & dtors families
def get_ctors() -> Dict[int, Collection[int]]:
    # associate each ctor/dtor to one vtable (effective vtable of one class)
    ctor_vtbl = dict()  # ctor_ea -> vtbl_ea
    for vtbl_ref, vtbl_addr in ida_utils.get_all_vtables():
        for xref in ida_utils.get_data_references(vtbl_ref):
            if not ida_utils.is_vtable_load(xref):
                continue

            func = idaapi.get_func(xref)
            if func is None:
                continue

            ctor, shift = is_ctor(func, vtbl_ref)
            if ctor and shift == 0:  # only take first vtable in account
                if func.start_ea in ctor_vtbl:
                    ctor_vtbl[func.start_ea] = most_derived_vtable(vtbl_addr, ctor_vtbl[func.start_ea])
                else:
                    ctor_vtbl[func.start_ea] = vtbl_addr

    # regroup ctors/dtors by families
    mifa = dict()  # vtbl_ea -> list of ctors
    for ctor, vtbl in ctor_vtbl.items():
        if vtbl not in mifa:
            mifa[vtbl] = collections.deque()
        mifa[vtbl].append(ctor)

    return mifa


# get all entrypoints from identified ctors / dtors
def get_ctors_entrypoints(entries: entry_record_t):
    for _, fam in get_ctors().items():
        first = True
        for ctor in fam:
            entries.add_entry(arg_entry_t(ctor, 0), True, first)
            first = False


# find root entrypoints, from classes & allocators found in the base
def retrieve_entrypoints(imports: Iterable[allocators.allocator_t]) -> context_t:
    entries = entry_record_t()

    allocators = get_allocations_entrypoints(imports, entries)

    get_ctors_entrypoints(entries)

    return context_t(entries, allocators)
