import copy
import ctypes
import enum
from typing import Dict, Generator, List, Optional, Tuple

import idaapi
import idc

###################
# CPU definitions #
###################


# convert ida op_type to string
def op_type_str(op_type: int) -> str:
    if op_type == idaapi.o_void:
        return "void"
    if op_type == idaapi.o_reg:
        return "reg"
    if op_type == idaapi.o_mem:
        return "mem"
    if op_type == idaapi.o_phrase:
        return "phrase"
    if op_type == idaapi.o_displ:
        return "disp"
    if op_type == idaapi.o_imm:
        return "imm"
    if op_type == idaapi.o_far:
        return "far"
    if op_type == idaapi.o_near:
        return "near"


# convert size in bytes to string
def to_size(nbytes: int) -> str:
    if nbytes == 1:
        return "u8"
    if nbytes == 2:
        return "u16"
    if nbytes == 4:
        return "u32"
    if nbytes == 8:
        return "u64"
    if nbytes == 16:
        return "u128"
    return "invalid"


# ida x64 register names
X64_REGISTERS = {
    0: "rax",
    1: "rcx",
    2: "rdx",
    3: "rbx",
    4: "rsp",
    5: "rbp",
    6: "rsi",
    7: "rdi",
    8: "r8",
    9: "r9",
    10: "r10",
    11: "r11",
    12: "r12",
    13: "r13",
    14: "r14",
    15: "r15",
    29: "es",
    30: "cs",
    31: "ss",
    32: "ds",
    33: "fs",
    34: "gs",
    56: "mm0",
    57: "mm1",
    58: "mm2",
    59: "mm3",
    60: "mm4",
    61: "mm5",
    62: "mm6",
    63: "mm7",
    64: "xmm0",
    65: "xmm1",
    66: "xmm2",
    67: "xmm3",
    68: "xmm4",
    69: "xmm5",
    70: "xmm6",
    71: "xmm7",
    72: "xmm8",
    73: "xmm9",
    74: "xmm10",
    75: "xmm11",
    76: "xmm12",
    77: "xmm13",
    78: "xmm14",
    79: "xmm15",
    81: "ymmm0",
    82: "ymmm1",
    83: "ymmm2",
    84: "ymmm3",
    85: "ymmm4",
    86: "ymmm5",
    87: "ymmm6",
    88: "ymmm7",
    89: "ymmm8",
    90: "ymmm9",
    91: "ymmm10",
    92: "ymmm11",
    93: "ymmm12",
    94: "ymmm13",
    95: "ymmm14",
    96: "ymmm15",
}


# convert ida register to string
def reg_string(reg: int) -> str:
    return X64_REGISTERS[reg]


INSN_MOVES = [idaapi.NN_mov, idaapi.NN_movups, idaapi.NN_movdqu]

INSN_MATH = [idaapi.NN_add, idaapi.NN_or, idaapi.NN_sub]

INSN_MATHS = [idaapi.NN_add, idaapi.NN_sub]

INSN_XORS = [idaapi.NN_xor]

INSN_ANDS = [idaapi.NN_and]

INSN_CALLS = [idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni]

INSN_RETS = [idaapi.NN_retn, idaapi.NN_retf]

INSN_JUMPS = [
    idaapi.NN_ja,
    idaapi.NN_jae,
    idaapi.NN_jb,
    idaapi.NN_jbe,
    idaapi.NN_jc,
    idaapi.NN_jcxz,
    idaapi.NN_je,
    idaapi.NN_jecxz,
    idaapi.NN_jg,
    idaapi.NN_jge,
    idaapi.NN_jl,
    idaapi.NN_jle,
    idaapi.NN_jmp,
    idaapi.NN_jmpfi,
    idaapi.NN_jmpni,
    idaapi.NN_jmpshort,
    idaapi.NN_jna,
    idaapi.NN_jnae,
    idaapi.NN_jnb,
    idaapi.NN_jnbe,
    idaapi.NN_jnc,
    idaapi.NN_jne,
    idaapi.NN_jng,
    idaapi.NN_jnge,
    idaapi.NN_jnl,
    idaapi.NN_jnle,
    idaapi.NN_jno,
    idaapi.NN_jnp,
    idaapi.NN_jns,
    idaapi.NN_jnz,
    idaapi.NN_jo,
    idaapi.NN_jp,
    idaapi.NN_jpe,
    idaapi.NN_jpo,
    idaapi.NN_jrcxz,
    idaapi.NN_js,
    idaapi.NN_jz,
]

INSN_UNCONDITIONAL_JUMPS = [idaapi.NN_jmp, idaapi.NN_jmpfi, idaapi.NN_jmpni]

INSN_TESTS = [idaapi.NN_test]

INSN_CMPS = [idaapi.NN_cmp]

INSN_LEAS = [idaapi.NN_lea]


# for operand [rax + rcx*scale + disp] get base reg (rax)
def x64_base_reg(insn: idaapi.insn_t, op: idaapi.op_t) -> int:
    if op.specflag1 == 0:  # no SIB in op
        return op.phrase

    base = op.specflag2 & 7

    # REX byte, 64-bytes mode
    if insn.insnpref & 1:  # sid base extension
        base |= 8

    return base


x86_INDEX_NONE = 4


# for operand [rax + rcx*scale + disp] get index reg (rcx)
def x64_index_reg(insn: idaapi.insn_t, op: idaapi.op_t) -> int:
    if op.specflag1 == 0:
        return x86_INDEX_NONE

    index = (op.specflag2 >> 3) & 7
    if insn.insnpref & 2:  # sib index extension
        index |= 8

    return index


# insn.itype to string
def insn_itype_str(insn_itype: int) -> str:
    if insn_itype == idaapi.NN_lea:
        return "lea"
    if insn_itype == idaapi.NN_push:
        return "push"
    if insn_itype == idaapi.NN_pop:
        return "pop"
    if insn_itype in INSN_MOVES:
        return "mov"
    if insn_itype in INSN_MATH:
        return "math"
    if insn_itype in INSN_CALLS:
        return "call"
    if insn_itype in INSN_TESTS:
        return "test"
    if insn_itype in INSN_JUMPS:
        return "jump"
    if insn_itype in INSN_RETS:
        return "ret"
    return "invalid"


# op.dtype to string
def op_dtype_str(dtype: int) -> str:
    if dtype == idaapi.dt_byte:
        return "byte"
    if dtype == idaapi.dt_word:
        return "word"
    if dtype == idaapi.dt_dword:
        return "dword"
    if dtype == idaapi.dt_qword:
        return "qword"
    return ""


# get instruction str representation
def insn_str(insn: idaapi.insn_t) -> str:
    return f"insn:{insn.ea:x} type:{insn.itype} {insn_itype_str(insn.itype)} ({idc.generate_disasm_line(insn.ea, 0)})"


# get operand str representation
def op_str(op: idaapi.op_t) -> str:
    registers = [idaapi.o_reg, idaapi.o_displ]
    reg_suffix = " " + reg_string(op.reg) if op.type in registers else ""
    return f"op: type:{op_type_str(op.type)} reg:{op.reg}{reg_suffix} val:{op.value:x} ea:{op.addr:x} dtype:{op.dtype:x}:{op_dtype_str(op.dtype)}"


# get instruction + operands representation
def insn_str_full(insn: idaapi.insn_t) -> str:
    out = insn_str(insn)
    for op in insn.ops:
        if op.type == idaapi.o_void:
            break
        out += "\n\t" + op_str(op)
    return out


# convert data to given size & sign
def convert_imm(value: int, sizeof: int, signed: bool = True) -> int:
    mask = 1 << (sizeof * 8)
    out = value & (mask - 1)
    if signed and (out & (mask >> 1)):
        out -= mask
    return out


########################
# CPU state definition #
########################


# represents an instruction's operand
# implementations of this class define the operand's type & value
class absop_t:
    # should this operand value be transfered from a caller to a callee as an arg
    def should_dive(self) -> bool:
        return True

    def __eq__(self, other) -> bool:
        raise Exception('Class "%s" should implement __eq__()' % self.__class__.__name__)

    def __hash__(self) -> int:
        raise Exception('Class "%s" should implement __hash__()' % self.__class__.__name__)


# return value of an unknown call
class call_t(absop_t):
    def __init__(self, arg: int, where: int):
        self.arg = arg
        self.where = where

    def __eq__(self, other) -> bool:
        return isinstance(other, call_t) and self.where == other.where and self.arg == other.arg

    def __hash__(self) -> int:
        return self.where

    def __repr__(self):
        return f"call:0x{self.arg:x} @0x{self.where:x}"


# displacement operand
class disp_t(absop_t):
    def __init__(self, reg: int, offset: int, nbytes: int):
        self.reg = reg
        self.offset = offset
        self.nbytes = nbytes

    def __eq__(self, other) -> bool:
        return (
            isinstance(other, disp_t)
            and self.reg == other.reg
            and self.offset == other.offset
            and self.nbytes == other.nbytes
        )

    def __hash__(self) -> int:
        return hash((self.reg, self.offset, self.nbytes))

    def __repr__(self):
        return "%s[%s+0x%x]" % (to_size(self.nbytes), reg_string(self.reg), self.offset)


# (unknown) function argument operand
class arg_t(absop_t):
    def __init__(self, idx: int):
        self.idx = idx

    def should_dive(self) -> bool:
        return False

    def __eq__(self, other) -> bool:
        return isinstance(other, arg_t) and self.idx == other.idx

    def __hash__(self) -> int:
        return self.idx

    def __repr__(self):
        return "arg%d" % self.idx


# shifted buffer
class buff_t(absop_t):
    def __init__(self, shift: int = 0):
        self.shift = shift

    def offset(self, shift: int):
        return self.clone(ctypes.c_int32(self.shift + shift).value)


# structure pointer
class sid_t(buff_t):
    def __init__(self, sid, shift=0):
        super().__init__(shift)
        self.sid = sid

    def clone(self, shift: int):
        return sid_t(self.sid, shift)

    def should_dive(self) -> bool:
        return False

    def __eq__(self, other) -> bool:
        return isinstance(other, sid_t) and self.sid == other.sid and self.shift == other.shift

    def __hash__(self) -> int:
        return hash((self.sid, self.shift))

    def __repr__(self):
        return f"sid:0x{self.sid:x}+0x{self.shift:x}"


# stack pointer
class stack_ptr_t(buff_t):
    def clone(self, shift: int):
        return stack_ptr_t(shift)

    # stack tracking is local to function
    def should_dive(self) -> bool:
        return False

    def __eq__(self, other) -> bool:
        return isinstance(other, stack_ptr_t) and self.shift == other.shift

    def __hash__(self) -> int:
        return self.shift

    def __repr__(self):
        return f"stack_ptr:0x{self.shift:x}"


# immediate operand, applies to the same operation than buff_t
class int_t(buff_t):
    def __init__(self, val: int, sizeof: int):
        super().__init__(val)

        self.size = sizeof
        self.shift = convert_imm(self.shift, self.size, False)  # keep int_t unsigned

    def get_val(self) -> int:
        return self.shift

    def clone(self, shift: int):
        return int_t(shift, self.size)

    def __eq__(self, other) -> bool:
        return isinstance(other, int_t) and self.shift == other.shift and self.size == other.size

    def __hash__(self) -> int:
        return hash((self.shift, self.size))

    def __repr__(self):
        return f"int32:0x{self.get_val():x} ({self.get_val()})"


# memory operand
class mem_t(int_t):
    def __init__(self, value: int, addr: int, sizeof: int):
        super().__init__(value, sizeof)
        self.addr = addr

    def clone(self, shift: int):
        return mem_t(shift, self.addr, self.size)

    def __repr__(self):
        return f"mem:0x{self.addr:x}:0x{self.get_val():x}"


# registers values for given cpu state
class registers_t:
    def __init__(self):
        pass


# memory write
class write_t:
    def __init__(self, ea: int, disp: disp_t, src: absop_t):
        self.ea = ea
        self.disp = disp
        self.src = src

    def __repr__(self):
        return "0x%x %r=%r" % (self.ea, self.disp, self.src)


# memory read
class read_t:
    def __init__(self, ea: int, disp: disp_t, dst: int):
        self.ea = ea
        self.disp = disp
        self.dst = dst

    def __repr__(self):
        return "0x%x %r=%r" % (self.ea, X64_REGISTERS[self.dst], self.disp)


# memory access
class access_t:
    def __init__(self, ea: int, op_index: int, key: disp_t):
        self.ea = ea
        self.op_index = op_index
        self.key = key

    def __repr__(self):
        return "0x%x  key = %r op_index = %r" % (self.ea, self.key, self.op_index)


# function return value and address
class ret_t:
    def __init__(self, code: absop_t, where: int):
        self.code = code
        self.where = where

    def __repr__(self):
        return "ret:%s at 0x%x" % (self.code, self.where)


# function arguments count & calling convention guesser
# focuses on sid_t arguments, our target
class arguments_t:
    def __init__(self, state, cc):
        self.args: Dict[int, int] = dict()  # id(args) -> index
        self.cc = cc  # current function's cc (or default cc if unknown)
        self.guessed_args_count = -1  # args count - 1
        self.individual_validation = [False for i in range(cc.get_arg_count())]

        # record values of (potential) arguments
        for i in range(cc.get_arg_count()):
            arg = get_argument(cc, state, i)
            if arg is not None:
                self.args[id(arg)] = i

    # value has been used, if it comes from an arg validate it
    def validate(self, value: absop_t) -> bool:
        try:
            index = self.args[id(value)]
            self.guessed_args_count = max(self.guessed_args_count, index)
            self.individual_validation[index] = True
            return True

        except KeyError:
            return False

    # returns guessed (cc, start_arg, args_count) for current propagation
    def guess_cc(self):
        return self.cc.guess_function_cc(self.guessed_args_count + 1, self.individual_validation)


# tracks the stack state
class stack_t:
    def __init__(self):
        self.stack: Dict[int, absop_t] = dict()  # offset -> value

    def push(self, shift: int, value: absop_t):
        self.stack[shift] = value

    def pop(self, shift: int) -> absop_t:
        if shift in self.stack:
            return self.stack[shift]
        return None

    def copy(self, origin: "stack_t"):
        self.stack = origin.stack.copy()


class call_type_t(enum.Enum):
    CALL = 0
    JUMP = 1


# a cpu state (stack, registers, ..)
class state_t:
    def __init__(self, fct_ea: int = idaapi.BADADDR):
        self.fct_ea = fct_ea  # function this state is for

        self.previous = registers_t()  # registers before computing current insn
        self.registers = registers_t()  # registers after computing current insn

        self.writes: List[write_t] = []
        self.reads: List[read_t] = []
        self.access: List[access_t] = []

        self.call_type: Optional[call_type_t] = None
        self.call_to: Optional[idaapi.func_t] = None
        self.ret: Optional[ret_t] = None

        # track the use of function's args
        self.arguments = None

        # stack tracker
        self.stack = stack_t()
        set_stack_ptr(self, stack_ptr_t())

    # must be called before use
    def reset_arguments(self, cc):
        self.arguments = arguments_t(self, cc)

    # drop register state
    def drop_register(self, reg: int):
        self.drop_register_str(reg_string(reg))

    def drop_register_str(self, reg: str):
        try:
            delattr(self.registers, reg)
        except AttributeError:
            pass

    # get register state, if any
    def get_register(self, reg: int) -> absop_t:
        return self.get_register_str(reg_string(reg))

    def get_register_str(self, reg: str, n: int = 0) -> absop_t:
        source = self.previous if n else self.registers
        try:
            return getattr(source, reg)
        except AttributeError:
            return None

    # save register state
    def set_register(self, reg: int, arg: absop_t):
        self.set_register_str(reg_string(reg), arg)

    def set_register_str(self, reg: str, arg: absop_t, n: int = 0):
        source = self.previous if n else self.registers
        try:
            setattr(source, reg, arg)
        except AttributeError:
            pass

    def get_previous_register(self, reg: int) -> absop_t:
        return self.get_register_str(reg_string(reg), 1)

    def get_registers(self) -> Generator[Tuple[int, absop_t], None, None]:
        for reg in vars(self.registers):
            yield (reg, self.get_register_str(reg))

    def get_nb_types(self, wanted_type) -> int:
        ret = 0
        for _, reg in self.get_registers():
            if type(reg) == wanted_type:
                ret += 1
        return ret

    # prepare to transit to next state
    def reset(self):
        self.writes.clear()
        self.reads.clear()
        self.access.clear()
        self.ret: ret_t = None
        self.call_to = None
        self.call_type = None
        self.previous = copy.copy(self.registers)

    # copy persistent content into another state
    def copy(self) -> "state_t":
        out = state_t(self.fct_ea)
        out.registers = copy.copy(self.registers)
        out.stack.copy(self.stack)

        # keep same version of arguments tracking object
        out.arguments = self.arguments
        return out

    # save write
    def write_to(self, ea: int, key: disp_t, src: absop_t):
        if src:
            self.writes.append(write_t(ea, key, src))

    # save read
    def read_from(self, ea: int, disp: disp_t, dst: int):
        self.reads.append(read_t(ea, disp, dst))

    # save access
    def access_to(self, ea: int, n: int, key: disp_t):
        self.access.append(access_t(ea, n, key))

    # save ret
    def save_ret(self, where: int):
        item = get_ret_value(self)
        if item:
            self.ret = ret_t(item, where)

    # cpu state representation
    def __repr__(self):
        regs = []
        for k in sorted(vars(self.registers)):
            regs.append(f"{k}:{getattr(self.registers, k)}")
        str_call_to = f" call_to start_ea {self.call_to.start_ea}" if self.call_to is not None else ""
        return " ".join(regs) + str_call_to


#####################
# Arch specific ops #
#####################

import symless.cpustate.arch as arch

# global calling convention & abi
g_abi = None


def get_abi() -> arch.abi_t:
    global g_abi

    if g_abi is None:
        g_abi = arch.get_abi()
    return g_abi


# default calling convention to use on basic functions
def get_default_cc() -> arch.abi_t:
    return get_abi().get_default_cc()


# cc to use for class methods
def get_object_cc() -> arch.abi_t:
    return get_abi().get_object_cc()


# set value of stack ptr in given state_t
def set_stack_ptr(state: state_t, value: absop_t):
    get_abi().set_stack_ptr(state, value)


# get stack ptr value in given state_t
def get_stack_ptr(state: state_t) -> absop_t:
    return get_abi().get_stack_ptr(state)


# set ret register value
def set_ret_value(state: state_t, value: absop_t):
    get_abi().set_ret_value(state, value)


# get ret register value
def get_ret_value(state: state_t) -> absop_t:
    return get_abi().get_ret_value(state)


# set argument at given index in given state using given cc
def set_argument(
    cc: arch.abi_t,
    state: state_t,
    index: int,
    value: absop_t,
    from_callee: bool = True,
    is_jump: bool = False,
):
    if is_jump:  # jmp, always from caller state
        cc.set_jump_argument(state, index, value)
    else:
        cc.set_argument(state, index, value, from_callee)


# get argument at given index in given state using given cc
def get_argument(
    cc: arch.abi_t, state: state_t, index: int, from_callee: bool = True, is_jump: bool = False
) -> absop_t:
    if is_jump:
        return cc.get_jump_argument(state, index)
    return cc.get_argument(state, index, from_callee)
