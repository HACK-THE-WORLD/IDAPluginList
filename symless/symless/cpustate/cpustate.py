import copy
import ctypes
import logging
from typing import Collection, Dict, Iterator, List, Set, Tuple

import idaapi

import symless.config as config
import symless.cpustate.arch as arch
import symless.utils.ida_utils as ida_utils
import symless.utils.utils as utils
from symless.cpustate import *

# max functions depth to propagate a structure
MAX_PROPAGATION_RECURSION = 100

# Explicit constants
ONE_OPERAND_INSTRUCTIONS = 0
TWO_OPERAND_INSTRUCTIONS = 1


# ignore instruction
def handle_ignore(state: state_t, *args):
    pass


# drop one reg values when we do no know its new value
def handle_reg_drop(state: state_t, insn: idaapi.insn_t, op: idaapi.op_t):
    if op.type == idaapi.o_reg:
        state.drop_register(op.reg)


def handle_mov_reg_reg(state: state_t, insn: idaapi.insn_t, dst: idaapi.op_t, src: idaapi.op_t):
    cur = state.get_register(src.reg)
    state.set_register(dst.reg, cur)


def handle_mov_disp_reg(state: state_t, insn: idaapi.insn_t, dst: idaapi.op_t, src: idaapi.op_t):
    # mov [rax+rbx*2+n]
    # ignore basereg + indexreg*scale + offset cases
    if x64_index_reg(insn, dst) != x86_INDEX_NONE:
        # FIXME: stack value may be replaced here and we won't know
        return

    base = x64_base_reg(insn, dst)
    cur = state.get_register(src.reg)
    nex = state.get_register(base)
    nbytes = idaapi.get_dtype_size(dst.dtype)

    if isinstance(nex, stack_ptr_t):
        shift = ctypes.c_int32(dst.addr + nex.shift).value
        state.stack.push(shift, cur)
    else:
        # do not report src to be used when pushed in stack
        state.arguments.validate(cur)

        disp = disp_t(base, dst.addr, nbytes)
        state.write_to(insn.ea, disp, cur)


def handle_mov_reg_imm(state: state_t, insn: idaapi.insn_t, dst: idaapi.op_t, src: idaapi.op_t):
    nbytes = idaapi.get_dtype_size(dst.dtype)
    state.set_register(dst.reg, int_t(src.value, nbytes))


def handle_mov_disp_imm(state: state_t, insn: idaapi.insn_t, dst: idaapi.op_t, src: idaapi.op_t):
    # FIXME: mov [rsp + rcx*2 + 16], 200h will modify the stack
    # without us unvalidating the old value
    if x64_index_reg(insn, dst) != x86_INDEX_NONE:
        return

    base = x64_base_reg(insn, dst)
    cur = state.get_register(base)
    nbytes = idaapi.get_dtype_size(src.dtype)

    if isinstance(cur, stack_ptr_t):
        shift = ctypes.c_int32(dst.addr + cur.shift).value
        state.stack.push(shift, int_t(src.value, nbytes))

    else:
        # special win32 vtable load case
        # mov [ecx], offset vftable
        # to simplify vtable detection, consider immediate to be a mem_t

        disp = disp_t(base, dst.addr, nbytes)
        state.write_to(insn.ea, disp, mem_t(src.value, src.value, nbytes))


def handle_mov_reg_mem(state: state_t, insn: idaapi.insn_t, dst: idaapi.op_t, src: idaapi.op_t):
    nbytes = idaapi.get_dtype_size(dst.dtype)
    value = ida_utils.get_nb_bytes(src.addr, nbytes)
    if value is not None:
        state.set_register(dst.reg, mem_t(value, src.addr, nbytes))
    else:  # register loaded with bss data
        state.drop_register(dst.reg)


def handle_mov_reg_disp(state: state_t, insn: idaapi.insn_t, dst: idaapi.op_t, src: idaapi.op_t):
    base = x64_base_reg(insn, src)
    cur = state.get_register(base)

    # mov rbx, [rax+rcx*2+n], ignored
    if x64_index_reg(insn, src) != x86_INDEX_NONE:
        state.drop_register(dst.reg)
        return

    # mov rax, [rsp+0x10]
    if isinstance(cur, stack_ptr_t):
        shift = ctypes.c_int32(src.addr + cur.shift).value
        value = state.stack.pop(shift)
        if value is not None:
            state.set_register(dst.reg, value)
            return

    nbytes = idaapi.get_dtype_size(dst.dtype)

    # PIE memory move: mov rdx, [rax + vtbl_offset]
    dref = idaapi.get_first_dref_from(insn.ea)
    if dref != idaapi.BADADDR:
        value = ida_utils.get_nb_bytes(dref, nbytes)
        if value is not None:
            state.set_register(dst.reg, mem_t(value, dref, nbytes))
            return

    # other cases
    disp = disp_t(base, src.addr, nbytes)
    state.set_register(dst.reg, disp)

    state.read_from(insn.ea, disp, dst.reg)


def handle_call(state: state_t, insn: idaapi.insn_t, op: idaapi.op_t):
    state.call_type = call_type_t.CALL
    resolve_callee(insn, state)


def handle_jump(state: state_t, insn: idaapi.insn_t, op: idaapi.op_t):
    state.call_type = call_type_t.JUMP
    if insn.itype in INSN_UNCONDITIONAL_JUMPS:
        resolve_callee(insn, state)


def handle_lea_reg_mem(state: state_t, insn: idaapi.insn_t, dst: idaapi.op_t, src: idaapi.op_t):
    # avoid 'lea esi, ds:2[rax*2]' flagged as 'lea reg, mem'
    if src.specflag1:  # hasSIB
        state.drop_register(dst.reg)
    else:
        state.set_register(dst.reg, mem_t(src.addr, src.addr, ida_utils.get_ptr_size()))


def handle_lea_reg_disp(state: state_t, insn: idaapi.insn_t, dst: idaapi.op_t, src: idaapi.op_t):
    base = x64_base_reg(insn, src)
    cur = state.get_register(base)

    # mov rbx, [rax+rcx*2+n], ignored
    if x64_index_reg(insn, src) != x86_INDEX_NONE:
        state.drop_register(dst.reg)
        return

    # apply offset shift instead if input operand is a sid
    if isinstance(cur, buff_t):
        state.set_register(dst.reg, cur.offset(src.addr))
    else:
        # data can be referenced from reg disp in PIE
        # check if we have a data ref on the insn
        dref = idaapi.get_first_dref_from(insn.ea)
        if dref != idaapi.BADADDR:
            state.set_register(dst.reg, mem_t(dref, dref, ida_utils.get_ptr_size()))
        else:
            # we don't have any use for this
            state.drop_register(dst.reg)


def handle_add_reg_imm(state: state_t, insn: idaapi.insn_t, dst: idaapi.op_t, src: idaapi.op_t):
    cur = state.get_register(dst.reg)
    if not cur:
        return

    state.arguments.validate(cur)

    if not isinstance(cur, buff_t):
        state.drop_register(dst.reg)
        return

    if insn.itype == idaapi.NN_add:
        shift = src.value
    else:
        shift = -src.value

    # TODO : Le probleme c'est qu'on ne sait pas a l'avance la taille de l'acces
    # Pour l'instant on prend la taille de l'archi comme si c'etait un pointeur
    # Mais si c'est un pointeur x64 sur un DWORD a l'interieur de la structure par exemple
    #  alors la taille ne devrait pas etre la taille de l'archi
    if src.type in [idaapi.o_imm]:
        size = ida_utils.get_ptr_size()
        if size == idaapi.get_dtype_size(dst.dtype):
            state.access_to(insn.ea, 1, disp_t(dst.reg, shift, size))

    state.set_register(dst.reg, cur.offset(shift))


def handle_xor_reg_reg(state: state_t, insn: idaapi.insn_t, dst: idaapi.op_t, src: idaapi.op_t):
    if dst.reg == src.reg:
        state.set_register(dst.reg, int_t(0, ida_utils.get_ptr_size()))
    else:
        state.drop_register(dst.reg)


# handle stack alignements
def handle_and_reg_imm(state: state_t, insn: idaapi.insn_t, dst: idaapi.op_t, src: idaapi.op_t):
    cur = state.get_register(dst.reg)
    if isinstance(cur, buff_t):
        value = ctypes.c_int32(cur.shift & src.value).value
        state.set_register(dst.reg, cur.clone(value))
    else:
        state.drop_register(dst.reg)


# stack shift by a push/pop operation
def handle_stack_shift(state: state_t, op: idaapi.op_t, is_push: bool) -> stack_ptr_t:
    size = idaapi.get_dtype_size(op.dtype)
    stack_ptr = get_stack_ptr(state)
    if not isinstance(stack_ptr, stack_ptr_t):
        return None

    if is_push:
        size = -size

    stack_ptr = stack_ptr.offset(size)
    set_stack_ptr(state, stack_ptr)
    return stack_ptr


def handle_push_reg(state: state_t, insn: idaapi.insn_t, op: idaapi.op_t):
    stack_ptr = handle_stack_shift(state, op, True)
    reg = state.get_register(op.reg)
    if stack_ptr is not None and reg is not None:
        state.stack.push(stack_ptr.shift, reg)


def handle_push_imm(state: state_t, insn: idaapi.insn_t, op: idaapi.op_t):
    stack_ptr = handle_stack_shift(state, op, True)
    if stack_ptr is not None:
        nbytes = idaapi.get_dtype_size(op.dtype)
        state.stack.push(stack_ptr.shift, int_t(op.value, nbytes))


def handle_pop_reg(state: state_t, insn: idaapi.insn_t, op: idaapi.op_t):
    # drop dst reg in any case
    state.drop_register(op.reg)

    stack_ptr = get_stack_ptr(state)
    if isinstance(stack_ptr, stack_ptr_t):
        # record poped value
        value = state.stack.pop(stack_ptr.shift)
        if value is not None:
            state.set_register(op.reg, value)

        # shift stack ptr
        size = idaapi.get_dtype_size(op.dtype)
        set_stack_ptr(state, stack_ptr.offset(size))


# shift stack pointer, ignore pushed/poped value
def handle_ignored_push_pop(state: state_t, insn: idaapi.insn_t, op: idaapi.op_t):
    handle_stack_shift(state, op, (insn.itype == idaapi.NN_push))


# validate register operand to be a used argument, to keep track of function args count
# other type of operands (displ, phrase) are already validated in process_instruction()
def validate_operand(state: state_t, insn: idaapi.insn_t, op: idaapi.op_t):
    if op.type == idaapi.o_reg:
        state.arguments.validate(state.get_previous_register(op.reg))


# handle test instruction
def handle_test(state: state_t, insn: idaapi.insn_t, op1: idaapi.op_t, op2: idaapi.op_t):
    validate_operand(state, insn, op1)
    validate_operand(state, insn, op2)


# instructions specific handlers
# list of (list[insn.itype], tuple(ops.type), handler)
g_insn_handlers = [
    (
        # 1 operand instructions
        ([idaapi.NN_push], (idaapi.o_reg,), handle_push_reg),  # push rbp
        ([idaapi.NN_push], (idaapi.o_imm,), handle_push_imm),  # push 42h
        ([idaapi.NN_push], (idaapi.o_displ,), handle_ignored_push_pop),  # push [ebp+var_14]
        ([idaapi.NN_push], (idaapi.o_mem,), handle_ignored_push_pop),  # push bss_var
        ([idaapi.NN_push], (idaapi.o_phrase,), handle_ignored_push_pop),  # push dword[rcx]
        ([idaapi.NN_pop], (idaapi.o_reg,), handle_pop_reg),  # pop rbp
        ([idaapi.NN_pop], (idaapi.o_displ,), handle_ignored_push_pop),  # pop [rbp+var_14]
        ([idaapi.NN_pop], (idaapi.o_phrase,), handle_ignored_push_pop),  # pop [rcx]
        ([idaapi.NN_pop], (idaapi.o_mem,), handle_ignored_push_pop),  # pop data_var
        (INSN_CALLS, (0,), handle_call),  # call ?
        (INSN_JUMPS, (0,), handle_jump),  # jne  ?
    ),
    (
        # 2 operands instructions
        (INSN_MOVES, (idaapi.o_phrase, idaapi.o_reg), handle_mov_disp_reg),  # mov [rcx], rax
        (INSN_MOVES, (idaapi.o_displ, idaapi.o_reg), handle_mov_disp_reg),  # mov [rcx+10h], rax
        (INSN_MOVES, (idaapi.o_phrase, idaapi.o_imm), handle_mov_disp_imm),  # mov [rcx], 10h
        (INSN_MOVES, (idaapi.o_displ, idaapi.o_imm), handle_mov_disp_imm),  # mov [rcx+10h], 10h
        (INSN_MOVES, (idaapi.o_reg, idaapi.o_reg), handle_mov_reg_reg),  # mov rax, rbx
        (INSN_MOVES, (idaapi.o_reg, idaapi.o_imm), handle_mov_reg_imm),  # mov rax, 10h
        (INSN_MOVES, (idaapi.o_reg, idaapi.o_mem), handle_mov_reg_mem),  # mov rax, @addr
        (INSN_MOVES, (idaapi.o_reg, idaapi.o_phrase), handle_mov_reg_disp),  # mov rax, [rbx]
        (
            INSN_MOVES,
            (idaapi.o_reg, idaapi.o_displ),
            handle_mov_reg_disp,
        ),  # mov rax, [rbx+10h]
        (INSN_MOVES, (idaapi.o_mem, 0), handle_ignore),  # mov @addr, ?
        (INSN_TESTS, (0, 0), handle_test),  # test ?, ?
        (INSN_CMPS, (0, 0), handle_test),  # cmp ?, ?
        (INSN_LEAS, (idaapi.o_reg, idaapi.o_mem), handle_lea_reg_mem),  # lea rax, @addr
        (
            INSN_LEAS,
            (idaapi.o_reg, idaapi.o_displ),
            handle_lea_reg_disp,
        ),  # lea rax, [rbx+10h]
        (INSN_LEAS, (idaapi.o_reg, 0), handle_ignore),  # lea rax, ?
        (INSN_XORS, (idaapi.o_reg, idaapi.o_reg), handle_xor_reg_reg),  # xor rax, rax
        (INSN_ANDS, (idaapi.o_reg, idaapi.o_imm), handle_and_reg_imm),  # and esp, 0xfffffff0
        (INSN_MATHS, (idaapi.o_reg, idaapi.o_imm), handle_add_reg_imm),  # add rax, 10h
    ),
]


# check wheter given insn types meet the required ones
def check_types(effective: tuple, expected: tuple) -> bool:
    for i in range(len(expected)):
        if expected[i] != 0 and effective[i] != expected[i]:
            return False
    return True


# dump full instruction
def dump_insn(insn: idaapi.insn_t, level: int = config.LOG_LEVEL_VERBOSE_DEBUG):
    if level >= utils.g_logger.level:  # do not compute __repr__ everytime
        utils.g_logger.log(level, insn_str_full(insn))


# handle zero-operand instructions
def handle_no_op_insn(state: state_t, insn: idaapi.insn_t):
    if insn.itype in INSN_RETS:
        state.save_ret(insn.ea)


# handle one-operand instructions
def handle_one_op_insn(state: state_t, insn: idaapi.insn_t, ops):
    handler, it_type = None, None
    op = ops[0]

    for itype, optype, current in g_insn_handlers[ONE_OPERAND_INSTRUCTIONS]:
        if insn.itype in itype:
            it_type = insn.itype
            if check_types((op.type,), optype):
                handler = current
                break

    if not it_type:
        handle_reg_drop(state, insn, op)
        return

    if handler:
        handler(state, insn, op)
        return

    if False:
        dump_insn(insn)
        raise BaseException("not implemented")


# handle two-operands instructions
def handle_two_ops_insn(state: state_t, insn: idaapi.insn_t, ops):
    handler = None
    dst, src = ops[0], ops[1]
    known_type = None
    for itypes, optype, current in g_insn_handlers[TWO_OPERAND_INSTRUCTIONS]:
        if insn.itype in itypes:
            known_type = insn.itype
            if check_types((dst.type, src.type), optype):
                handler = current
                break

    if not known_type:
        # drop destination register only
        handle_reg_drop(state, insn, dst)
        return

    if handler:
        handler(state, insn, dst, src)
        return

    if dst.type == idaapi.o_reg:
        state.drop_register(dst.reg)

    if False:
        dump_insn(insn)
        raise BaseException("not implemented")


# pretty print state and insn
def dbg_dump_state_insn(insn: idaapi.insn_t, state: state_t):
    utils.g_logger.log(config.LOG_LEVEL_VERBOSE_DEBUG, "---------------------------------------------------------")
    dump_insn(insn, config.LOG_LEVEL_VERBOSE_DEBUG)
    utils.g_logger.log(config.LOG_LEVEL_VERBOSE_DEBUG, state)


def handle_struc_access(state: state_t, insn: idaapi.insn_t, ops: List[idaapi.op_t]):
    # register any access through displ missed by custom handlers
    for i, op in enumerate(ops):
        if op.type in [idaapi.o_phrase, idaapi.o_displ]:
            base = x64_base_reg(insn, op)
            index = x64_index_reg(insn, op)

            # validate base reg for parameters tracking
            cur = state.get_previous_register(base)
            state.arguments.validate(cur)

            if index == x86_INDEX_NONE:  # ignore base + index*scale + offset
                nbytes = idaapi.get_dtype_size(op.dtype)
                state.access_to(insn.ea, i, disp_t(base, op.addr, nbytes))
            else:  # validate index usage
                cur = state.get_previous_register(index)
                state.arguments.validate(cur)


# process one instruction & update current state
def process_instruction(state: state_t, insn: idaapi.insn_t):
    ops: list[idaapi.op_t] = ida_utils.get_insn_ops(insn)
    state.reset()

    op_len = len(ops)
    if op_len == 0:
        handle_no_op_insn(state, insn)
    elif op_len == 1:
        handle_one_op_insn(state, insn, ops)
    elif op_len == 2:
        handle_two_ops_insn(state, insn, ops)
    elif op_len == 3:
        handle_reg_drop(state, insn, ops[0])
    elif op_len == 4:
        handle_reg_drop(state, insn, ops[0])
    else:
        utils.g_logger.error("unsupported instruction with %d operands:" % op_len)
        dump_insn(insn, logging.ERROR)

    handle_struc_access(state, insn, ops)

    dbg_dump_state_insn(insn, state)


# read next instruction within giben basic block
def next_instruction(ea: int, block: idaapi.range_t, insn: idaapi.insn_t) -> bool:
    while (ea != idaapi.BADADDR and ea < block.end_ea) and not idaapi.is_code(idaapi.get_flags(ea)):
        ea = idaapi.get_item_end(ea)

    if ea >= block.end_ea or ea == idaapi.BADADDR:
        return False

    idaapi.decode_insn(insn, ea)
    return True


# select most interesting state (most sid_t, call_t)
def select_state(states: list) -> state_t:
    states.sort(key=lambda e: (e.get_nb_types(sid_t), e.get_nb_types(call_t)), reverse=True)
    return states[0]


# Get the starting state for a basic block
# if many states are possible, select the one with the most info in it
def get_previous_state(flow, idx, prev_states) -> state_t:
    npred = flow.npred(idx)
    initial = prev_states[idaapi.BADADDR]

    # no predecessor, just use starting state
    if npred == 0:
        out = state_t(initial.fct_ea)
        out.arguments = initial.arguments  # keep arguments tracker
        return out

    # only one predecessor, use its state
    if npred == 1:
        last_node = flow.pred(idx, 0)
        if last_node == idx:
            out = state_t(initial.fct_ea)
            out.arguments = initial.arguments
            return out

        if last_node not in prev_states.keys():
            raise BaseException("invalid previous node")

        return prev_states[last_node].copy()

    # multiple predecessors, find one suitable
    predecessors = []
    for i in range(npred):
        predecessor_node = flow.pred(idx, i)
        if predecessor_node in prev_states.keys():
            predecessors.append(prev_states[predecessor_node])

    if len(predecessors) == 0:
        raise BaseException("no previous node found")

    return select_state(predecessors).copy()


# next node to visit from given list
def pop_node(nodes: Collection[Tuple[int, Set[int]]], visited: Set[int]) -> int:
    # default: next node in graph flow
    idx = 0

    # find a block with all its predecessor visited
    sel = [i for i, (_, preds) in enumerate(nodes) if len(preds.difference(visited)) == 0]

    if len(sel):
        idx = sel[0]

    # find first node in nodes with a visited pred
    else:
        sel = [i for i, (_, preds) in enumerate(nodes) if len(visited.intersection(preds)) > 0]

        if len(sel):
            idx = sel[0]

    node = nodes[idx][0]
    visited.add(node)  # update visited
    del nodes[idx]  # remove node from list

    return node


def walk_topological(flow) -> Iterator[int]:
    # generate a list of nodes with predecessors
    nodes: Collection[Tuple[int, Set[int]]] = list()
    for i in range(flow.size()):
        # all predecessors, excluding current node
        preds = set([flow.pred(i, j) for j in range(flow.npred(i)) if flow.pred(i, j) != i])
        nodes.append((i, preds))

    visited: Set[int] = set()
    while len(nodes):
        yield pop_node(nodes, visited)


# a visited function
class function_t:
    def __init__(self, ea):
        self.ea = ea

        # guessed cc
        self.cc = get_abi()

        # approximate count of arguments
        self.args_count = self.cc.get_arg_count()
        self.args = [set() for i in range(self.args_count)]  # sets of (sid, shift)

        self.cc_not_guessed = True

    def update_visited(self, state: state_t):
        for i in range(self.args_count):
            cur = get_argument(self.cc, state, i)
            if isinstance(cur, sid_t):
                self.args[i].add((cur.sid, cur.shift))

    def has_args(self) -> bool:
        for i in range(self.args_count):
            if len(self.args[i]) > 0:
                return True
        return False

    # guess function cc & arguments count
    def guess_function_cc(self, arguments: arguments_t):
        # always use guessed cc from arguments, in case arguments'cc is de-synced with self.cc
        cc, start_arg, args_count = arguments.guess_cc()
        self.cc = cc

        fixed_args_count = min(self.cc.get_arg_count(), args_count)
        if self.cc_not_guessed:
            self.args_count = fixed_args_count

            # shift args array if needed
            if start_arg > 0:
                self.args = self.args[start_arg:]

            self.cc_not_guessed = False

        elif self.args_count < fixed_args_count:
            self.args_count = fixed_args_count

    # guessed args count
    def get_count(self) -> int:
        if self.cc_not_guessed:
            return 0
        return self.args_count

    def __repr__(self):
        return f"cpustate.function_t {hex(self.ea)}"


# Injector into state_t
class injector_t:
    def __init__(self, callback=None, when: int = 0):
        self.callback = callback  # callback(state: state_t, insn: idaapi.insn_t, before_update: bool)
        self.when = when  # when & 1 -> inject before, when & 2 -> inject after

    # inject value before processing current instruction
    def inject_before(self, state: state_t, insn: idaapi.insn_t):
        if self.when & 1:
            self.callback(state, insn, True)

    # inject value after the current instruction has been processed
    def inject_after(self, state: state_t, insn: idaapi.insn_t):
        if self.when & 2:
            self.callback(state, insn, False)


# should_propagate default callback
def always_propagate(fct: function_t, state: state_t) -> bool:
    return True


# data flow control parameters
# used to control propagation & retrieve information
class dflow_ctrl_t:
    def __init__(
        self,
        injector: injector_t = injector_t(),
        dive_cb=always_propagate,
        depth: int = MAX_PROPAGATION_RECURSION,
    ):
        self.injector = injector  # state injector
        self.visited: Dict[int, function_t] = dict()  # visited functions

        self.depth = depth  # current (reverse) depth
        self.max_depth = depth  # maximum depth to reach

        self.dive_cb = dive_cb  # callback deciding whether or not to dive into callee

    # is there a potential new state we need to visit
    def should_propagate(self, fct: function_t, state: state_t) -> bool:
        if self.depth < 0:  # max depth has been reached
            return False

        return self.dive_cb(fct, state)

    # has propagation passed by function
    def has_function(self, ea: int) -> bool:
        return ea in self.visited

    # get or create function
    def get_function(self, ea: int) -> function_t:
        if not self.has_function(ea):
            self.visited[ea] = function_t(ea)
        return self.visited[ea]

    # get function's cc
    def get_function_cc(self, ea: int) -> arch.abi_t:
        if self.has_function(ea):
            return self.visited[ea].cc
        return get_abi()  # default cc


# if given instruction is a call / jmp, get its target
def resolve_callee(insn: idaapi.insn_t, state: state_t):
    target = insn.ops[0]
    if target.type == idaapi.o_reg:  # call rax
        cur = state.get_register(target.reg)
        if not isinstance(cur, mem_t):
            return

        target_addr = cur.get_val()

    elif target.type in [idaapi.o_mem, idaapi.o_far, idaapi.o_near]:
        target_addr = target.addr
        if target.type == idaapi.o_mem:
            target_addr = ida_utils.dereference_pointer(target_addr)

    else:
        return

    callee = idaapi.get_func(target_addr)
    if callee is None or callee.start_ea != target_addr:
        return

    utils.g_logger.debug(f"call at 0x{insn.ea:x} resolved to function 0x{callee.start_ea:x}")
    state.call_to = callee


# validate that function arguments are used if they are passed to another function
def validate_passthrough_args(caller_state: state_t, callee: function_t, is_call: bool):
    for i in range(callee.get_count()):
        cur = get_argument(callee.cc, caller_state, i, False, not is_call)
        caller_state.arguments.validate(cur)


# copy callee's arguments from caller's state and propagate in callee
def flow_in_callee(call_ea: int, state: state_t, param: dflow_ctrl_t) -> Iterator[Tuple[int, state_t]]:
    ret_value = call_t(idaapi.BADADDR if state.call_to is None else state.call_to.start_ea, call_ea)
    is_call = state.call_type == call_type_t.CALL

    if state.call_to is not None:  # callee was resolved
        model = param.get_function(state.call_to.start_ea)

        cistate = state_t(model.ea)
        populate_arguments(cistate, model.cc, state, is_call)

        param.depth -= 1
        for ea, cstate in function_data_flow(state.call_to, cistate, param):
            # get callee return value
            if cstate.ret is not None and state.call_to.contains(cstate.ret.where) and not isinstance(ret_value, sid_t):
                ret_value = cstate.ret.code

            yield ea, cstate

        param.depth += 1

        # validate parameters used in callee
        validate_passthrough_args(state, model, is_call)

    set_ret_value(state, ret_value)


# propagate in given function, using given initial state and parameters
def function_data_flow(
    fct: idaapi.func_t, initial_state: state_t, param: dflow_ctrl_t
) -> Iterator[Tuple[int, state_t]]:
    model = param.get_function(fct.start_ea)  # function's model

    # record initial states for every node
    prev_states = dict()  # bb index -> state
    prev_states[idaapi.BADADDR] = initial_state

    # get nodes flooding order
    flow = idaapi.qflow_chart_t()
    flow.create("", fct, fct.start_ea, fct.end_ea, idaapi.FC_NOEXT)
    nodes = walk_topological(flow)

    try:
        entry = flow[next(nodes)]  # function's entry block
    except StopIteration:  # function has no block
        utils.g_logger.error(f"No entry block for function 0x{fct.start_ea}")
        return

    insn = idaapi.insn_t()  # current instruction
    next_instruction(entry.start_ea, entry, insn)

    # apply entry injection before recording function's arguments
    param.injector.inject_before(initial_state, insn)
    initial_state.reset_arguments(model.cc)

    # check if we can get new info by propagating there
    if not param.should_propagate(model, initial_state):
        return
    model.update_visited(initial_state)

    # process first instruction
    process_instruction(initial_state, insn)

    state = initial_state
    node_id = 0

    # for every basic block
    while True:
        # for every instruction
        while True:
            # yield state after instruction processing
            # before after-process injection
            yield insn.ea, state

            # we need to go deeper
            if state.call_to is not None or state.call_type == call_type_t.CALL:
                for cea, cstate in flow_in_callee(insn.ea, state, param):
                    yield cea, cstate

            param.injector.inject_after(state, insn)

            if not next_instruction(insn.ea + insn.size, entry, insn):
                break

            param.injector.inject_before(state, insn)
            process_instruction(state, insn)

        # add updated state to previous states
        prev_states[node_id] = state

        # next block to process
        try:
            node_id = next(nodes)
        except StopIteration:
            break

        entry = flow[node_id]  # next block
        next_instruction(entry.start_ea, entry, insn)  # assume there is at least one instruction per bb

        state = get_previous_state(flow, node_id, prev_states)
        param.injector.inject_before(state, insn)
        process_instruction(state, insn)

    # deduce function's calling convention
    model.guess_function_cc(initial_state.arguments)


# copy arguments from caller state to callee state, depending on callee cc
def populate_arguments(
    callee_state: state_t, callee_cc: arch.abi_t, caller_state: state_t = None, is_call: bool = True
):
    for i in range(callee_cc.get_arg_count()):
        arg = None
        if caller_state is not None:
            arg = get_argument(callee_cc, caller_state, i, False, not is_call)

        if arg is None or not arg.should_dive():
            set_argument(callee_cc, callee_state, i, arg_t(i))
        else:
            # copy so we have a fresh reference for args count tracking
            set_argument(callee_cc, callee_state, i, copy.copy(arg))


# generate cpu state for input function
# params.depth = when propagating in function call/jumps, max depth to go
# -1 = follow until no more sid_t in state, 0 = don't follow calls
def generate_state(
    func: idaapi.func_t, params: dflow_ctrl_t = None, cc: arch.abi_t = None
) -> Iterator[Tuple[int, state_t]]:
    starting_state = state_t(func.start_ea)

    if params is None:
        params = dflow_ctrl_t()

    if cc is None:
        cc = get_abi()

    # Set up starting state with arguments
    populate_arguments(starting_state, cc)

    for ea, state in function_data_flow(func, starting_state, params):
        yield ea, state
