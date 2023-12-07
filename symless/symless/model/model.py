import idaapi

import symless.cpustate.cpustate as cpustate
import symless.utils.ida_utils as ida_utils
from symless.model import *
from symless.utils.utils import g_logger as logger

""" Propagation actions handlers """


# handle function ret, record ret type for function typing
def handle_ret(ea: int, state: cpustate.state_t, ctx: context_t):
    if state.ret is None:
        return

    value = state.ret.code
    if not isinstance(value, cpustate.sid_t) or value.shift != 0:
        return

    fea = idaapi.get_func(state.ret.where).start_ea

    fct = ctx.get_function(fea)
    fct.set_ret(value.sid)


# Build model members from state access
def handle_access(ea: int, state: cpustate.state_t, ctx: context_t):
    for access in state.access:
        disp = access.key

        # use previous registers values, before insn was computed
        cur = state.get_previous_register(disp.reg)

        if not isinstance(cur, cpustate.sid_t):
            continue

        offset = cpustate.ctypes.c_int32(disp.offset + cur.shift).value

        entry = ctx.graph.get_entry_by_id(cur.sid)
        if entry.add_field(offset, disp.nbytes) is None:
            continue

        logger.debug(
            f"Handle access 0x{ea:x}: add operand to {entry.entry_id()} at offset 0x{offset:x}, ea: 0x{access.ea:x}, n: {access.op_index}"
        )
        entry.add_operand(access.ea, access.op_index, cur.shift)


# retrieve virtual methods for given vtable
# and add child entry points for each of them to current entry
def analyze_virtual_methods(vtable_ea: int, current: entry_t, offset: int, ctx: context_t):
    if not ctx.can_follow_calls():
        return

    for fea in ida_utils.vtable_members(vtable_ea):
        # add entry to analyse
        child = ctx.graph.add_entry_as_child(current, arg_entry_t(fea, 0), offset, False)
        if child is not None:
            logger.debug(f"Add virtual method 0x{fea:x}, {child.entry_id()}, as child of {current.entry_id()}")

        # mark function as virtual
        fct = ctx.get_function(fea)
        fct.set_virtual()


# Handle writes to struc members
def handle_write(ea: int, state: cpustate.state_t, ctx: context_t):
    ptr_size = ida_utils.get_ptr_size()

    for write in state.writes:
        disp = write.disp
        src = write.src

        # mov [sid + offset], mem -> ptr loaded
        cur = state.get_previous_register(disp.reg)
        if not (isinstance(cur, cpustate.sid_t) and isinstance(src, cpustate.mem_t) and disp.nbytes == ptr_size):
            continue

        value = src.get_val()
        entry = ctx.graph.get_entry_by_id(cur.sid)
        offset = cpustate.ctypes.c_int32(disp.offset + cur.shift).value

        # check if addr is a vtable
        vtbl_size = ida_utils.vtable_size(value)

        # value is not a vtable address
        if vtbl_size == 0:
            type = ftype_ptr_t(src)
            logger.debug(f'Handle write 0x{ea:x}: add type "{type}" to field 0x{offset:x} of {entry.entry_id()}')

        else:
            # get / create vtable entry point
            vtbl = ctx.graph.add_entry(vtbl_entry_t(value), True)
            type = ftype_struc_t(vtbl)

            logger.debug(
                f"Handle write 0x{ea:x}: associate {vtbl.entry_id()} to field 0x{offset:x} of {entry.entry_id()}"
            )

            # add entrypoints to analyze virtual methods
            analyze_virtual_methods(value, entry, offset, ctx)

        # type structure field with retrieved type
        entry.get_field(offset).set_type(type)


# Handle read of struct members
def handle_read(ea: int, state: cpustate.state_t, ctx: context_t):
    for read in state.reads:
        disp = read.disp
        src = state.get_previous_register(disp.reg)
        dst = cpustate.reg_string(read.dst)

        # mov reg, [sid + offset]
        if not isinstance(src, cpustate.sid_t):
            continue

        entry = ctx.graph.get_entry_by_id(src.sid)
        offset = cpustate.ctypes.c_int32(disp.offset + src.shift).value

        # no read entries hierarchy
        if isinstance(entry, read_entry_t):
            logger.debug(f"Ignoring read from {entry.entry_id()}")
            continue

        # no fixed value, propagate read entrypoint
        rtype = entry.get_field_type(offset)
        if rtype is None:
            r_entry = ctx.graph.add_entry(read_entry_t(ea, state.fct_ea, dst, entry, offset))
            logger.debug(f"Handle read at 0x{ea:x}: type not known, propagating {r_entry.entry_id()}")

        # a struc ptr is read
        elif isinstance(rtype, ftype_struc_t):
            r_entry = ctx.graph.add_entry_as_child(rtype.entry, dst_reg_entry_t(ea, state.fct_ea, dst), 0, False)
            if r_entry is not None:
                logger.debug(f"Handle read at 0x{ea:x} from {rtype.entry.entry_id()}, propagating {r_entry.entry_id()}")

        # propagate any field
        else:
            state.set_register(read.dst, rtype.get_propagated_value())
            logger.debug(f"Handle read at 0x{ea:x}: propagating read type {rtype}")


# handle call, add entrypoints in callee
def handle_call(ea: int, state: cpustate.state_t, ctx: context_t):
    if not ctx.can_follow_calls():
        return

    if state.call_to is not None:
        ctx.dive_in = False  # default: do not dive in every callee
        call_ea = state.call_to.start_ea
        fct = ctx.dflow_info.get_function(call_ea)

        # look for entries to be propagated as callee's arguments
        epc = 0
        for i in range(fct.args_count):
            arg = cpustate.get_argument(fct.cc, state, i, False, state.call_type == cpustate.call_type_t.JUMP)
            if not isinstance(arg, cpustate.sid_t):
                continue

            entry = ctx.graph.get_entry_by_id(arg.sid)  # current entry as caller-to-callee arg

            # create new arg entry point
            # one entry point is restricted to be propagated in only one function
            ctx.graph.add_entry_as_child(entry, arg_entry_t(call_ea, i), arg.shift, True)
            epc += 1

        logger.debug(f"Handle call at 0x{ea:x}, {epc} entrypoints recorded")


# handle new cpu state
def handle_state(ea: int, state: cpustate.state_t, ctx: context_t):
    handle_access(ea, state, ctx)
    handle_write(ea, state, ctx)
    handle_read(ea, state, ctx)
    handle_call(ea, state, ctx)
    handle_ret(ea, state, ctx)


""" Entrypoints analysis & entries graph building """


# diving decision callback - dive if we have sid to propagate
def dive_in(callee: cpustate.function_t, state: cpustate.state_t, ctx: context_t) -> bool:
    dive = ctx.dive_in  # get context dive_in decision

    # root function, propagate
    if ctx.dflow_info.depth == ctx.dflow_info.max_depth:
        dive = True

    if dive:
        # arguments entries are to be built (again ?), reset their states
        for ep in ctx.graph.get_entries_at(callee.ea, 0):
            ep.reset()

    utils.g_logger.debug("Diving into fct 0x%x: %s" % (callee.ea, "YES" if dive else "NO"))
    return dive


# injector callback, inject entrypoints into cpustate
def model_injector(state: cpustate.state_t, insn: idaapi.insn_t, before_update: bool, ctx: context_t):
    for ep in ctx.graph.get_entries_at(insn.ea, not before_update):
        ctx.dive_in |= ep.inject(insn.ea, state, ctx)  # dive in callee if new eps are to be analyzed
        utils.g_logger.debug(f"Injecting {ep.entry_id()} at 0x{insn.ea:x}")


# entrypoints graph builder
# from original entrypoints, builds a propagation graph
# that can later be used to build structures
def analyze_entrypoints(ctx: context_t):
    entries = ctx.get_entrypoints()

    # injector callback
    def inject_cb(state: cpustate.state_t, insn: idaapi.insn_t, before_update: bool):
        model_injector(state, insn, before_update, ctx)

    inject = cpustate.injector_t(inject_cb, 3)

    # follow callees, use dive_in() decisions
    if ctx.can_follow_calls():
        ctx.dflow_info = cpustate.dflow_ctrl_t(inject, lambda callee, state: dive_in(callee, state, ctx))

    # only propagate in root function
    else:
        ctx.dflow_info = cpustate.dflow_ctrl_t(inject, lambda callee, state: dive_in(callee, state, ctx), depth=0)

    # analyse entrypoints by waves
    current_count = 1
    current_wave = 0
    while current_count > 0:
        current_count = 0
        for entry in entries.next_to_analyze():
            current_count += 1

            logger.debug(f"Analyzing entry {entry.entry_header()} ..")

            func = idaapi.get_func(entry.ea)
            for ea, state in cpustate.generate_state(func, ctx.dflow_info, cpustate.get_default_cc()):
                handle_state(ea, state, ctx)

        logger.debug(f"Entrypoints wave {current_wave} has been analyzed (total: {current_count})")
        current_wave += 1

    # record visited functions information into model
    ctx.record_functions(ctx.dflow_info.visited)

    # remove propagation data from model
    del ctx.dflow_info
