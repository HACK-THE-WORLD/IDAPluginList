import idaapi

import symless.utils.utils as utils
from symless.cpustate import *


# Define arch specific calling convention & abi
class abi_t:
    def __init__(self, name: str, ret: str, stack_ptr: str):
        self.name = name
        self.ret = ret
        self.stack_ptr = stack_ptr

    # set value of stack ptr in given state_t
    def set_stack_ptr(self, state: state_t, value):
        state.set_register_str(self.stack_ptr, value)

    # get stack ptr value in given state_t
    def get_stack_ptr(self, state: state_t):
        return state.get_register_str(self.stack_ptr)

    # set ret register value
    def set_ret_value(self, state: state_t, value):
        state.set_register_str(self.ret, value)

    # get ret register value
    def get_ret_value(self, state: state_t):
        return state.get_register_str(self.ret)

    # max arguments count we are willing to consider for a function
    def get_arg_count(self) -> int:
        return 0

    # set argument at given index in given state
    def set_argument(self, state: state_t, index: int, value, from_callee: bool = True):
        pass

    # get argument at given index in given state
    def get_argument(self, state: state_t, index: int, from_callee: bool = True):
        return None

    # set argument for a jmp instruction (from caller state)
    def set_jump_argument(self, state: state_t, index: int, value):
        self.set_argument(self, state, index, value, False)

    # get argument for a jmp instruction (from caller state)
    def get_jump_argument(self, state: state_t, index: int):
        return self.get_argument(state, index, False)

    # guess function's cc & args count after propagating in it
    # guessed_args_count: count of args that have been used (using default abi/cc)
    # individual_validation: for each args, which one have been recorded to be used
    # returns (guessed_abi, first_valid_arg, guessed_args_count)
    def guess_function_cc(self, guessed_args_count: int, individual_validation: list) -> tuple:
        return (self, 0, guessed_args_count)

    # calling convention to use for normal functions
    def get_default_cc(self):
        return self

    # calling convention to use for class methods
    def get_object_cc(self):
        return self


# for calling convention passing arguments through registers (__fastcall)
class reg_cc_abi_t(abi_t):
    def __init__(self, name: str, params: list, ret: str, stack_ptr: str):
        super().__init__(name, ret, stack_ptr)
        self.params = params

    def get_arg_count(self) -> int:
        return len(self.params)

    def set_argument(self, state: state_t, index: int, value, from_callee: bool = True):
        state.set_register_str(self.params[index], value)

    def get_argument(self, state: state_t, index: int, from_callee: bool = True):
        return state.get_register_str(self.params[index])


# for calling convention passing arguments through stack (__cdecl & __stdcall)
class stack_cc_abi_t(abi_t):
    def __init__(self, name: str, ret: str, stack_ptr: str, max_args_count: int = 4):
        super().__init__(name, ret, stack_ptr)
        self.max_args_count = max_args_count  # increase default ?

    def get_arg_count(self) -> int:
        return self.max_args_count

    # index of the first argument in the function local stack
    # or None if rsp does not track stack
    def first_args_index(self, state: state_t, from_callee: bool):
        if from_callee:
            return 4  # after saved eip
        ptr = self.get_stack_ptr(state)
        if not isinstance(ptr, stack_ptr_t):
            return None
        return ptr.shift

    # consider the args to be 4 bytes aligned on stack
    def get_args_shift(self, state: state_t, index: int, from_callee: bool):
        start = self.first_args_index(state, from_callee)
        if start is not None:
            start += index * 4
        return start

    def set_argument(self, state: state_t, index: int, value, from_callee: bool = True):
        shift = self.get_args_shift(state, index, from_callee)
        if shift is not None:
            state.stack.push(shift, value)

    def get_argument(self, state: state_t, index: int, from_callee: bool = True):
        shift = self.get_args_shift(state, index, from_callee)
        if shift is None:
            return None
        return state.stack.pop(shift)

    def set_jump_argument(self, state: state_t, index: int, value):
        shift = self.get_args_shift(state, index, False)
        if shift is not None:
            # saved eip won't be pushed by jmp, it is already in stack
            # first arg index is 4 and not 0
            state.stack.push(shift + 4, value)

    def get_jump_argument(self, state: state_t, index: int):
        shift = self.get_args_shift(state, index, False)
        if shift is None:
            return None
        return state.stack.pop(shift + 4)


# default abi & cc to use before guessing function's cc
# should be called once per analysis
def get_abi() -> abi_t:
    if idaapi.inf_get_filetype() == idaapi.f_PE:
        if idaapi.get_inf_structure().is_64bit():
            selected = win_64_abi_t()
        else:
            selected = win_32_abi_t()

    elif idaapi.get_inf_structure().is_64bit():
        selected = systemv_64_abi_t()
    else:
        selected = systemv_32_abi_t()

    utils.g_logger.info("Applying %s calling convention" % selected.name)

    return selected


def is_arch_supported() -> bool:
    return is_filetype_supported() and is_proc_supported()


def is_filetype_supported() -> bool:
    return idaapi.inf_get_filetype() in [idaapi.f_PE, idaapi.f_ELF]


def is_elf() -> bool:
    return idaapi.inf_get_filetype() == idaapi.f_ELF


def is_proc_supported() -> bool:
    return idaapi.inf_get_procname() == "metapc"


def get_proc_name() -> str:
    return idaapi.inf_get_procname()


# Win i386 __thiscall ABI -> first arg (this) in ecx, rest in stack
class win_32_thiscall_abi_t(stack_cc_abi_t):
    def __init__(self):
        super().__init__("Microsoft i386 __thiscall", "rax", "rsp")
        self.cc = idaapi.CM_CC_THISCALL

    def set_argument(self, state: state_t, index: int, value, from_callee: bool = True):
        if index == 0:
            state.set_register_str("rcx", value)
        else:
            super().set_argument(state, index - 1, value, from_callee)

    def get_argument(self, state: state_t, index: int, from_callee: bool = True):
        if index == 0:
            return state.get_register_str("rcx")
        return super().get_argument(state, index - 1, from_callee)

    def set_jump_argument(self, state: state_t, index: int, value):
        if index == 0:
            state.set_register_str("rcx", value)
        else:
            super().set_jump_argument(state, index - 1, value)

    def get_jump_argument(self, state: state_t, index: int):
        if index == 0:
            return state.get_register_str("rcx")
        return super().get_jump_argument(state, index - 1)


# Win i386 __stdcall ABI
class win_32_stdcall_abi_t(stack_cc_abi_t):
    def __init__(self):
        super().__init__("Microsoft i386 __stdcall", "rax", "rsp")
        self.cc = idaapi.CM_CC_STDCALL


# win 32 abi with default cc (merged between __stdcall & __thiscall calling conventions)
class win_32_abi_t(win_32_thiscall_abi_t):
    def __init__(self):
        super().__init__()
        self.name = "Microsoft i386"
        self.max_args_count = 5  # ecx + 4 args from stack

        # possible ABIs for a function
        self.stdcall = win_32_stdcall_abi_t()
        self.thiscall = win_32_thiscall_abi_t()

    def guess_function_cc(self, guessed_args_count: int, individual_validation: list) -> tuple:
        if individual_validation[0]:  # ecx is used (thiscall)
            return (self.thiscall, 0, guessed_args_count)
        return (self.stdcall, 1, max(0, guessed_args_count - 1))  # default __stdcall

    def get_default_cc(self):
        return self.stdcall

    def get_object_cc(self):
        return self.thiscall


# System V x86_64 ABI
class systemv_64_abi_t(reg_cc_abi_t):
    def __init__(self):
        super().__init__("System V x86_64", ["rdi", "rsi", "rdx", "rcx", "r8", "r9"], "rax", "rsp")
        self.cc = idaapi.CM_CC_FASTCALL


# Win x86_64 ABI
class win_64_abi_t(reg_cc_abi_t):
    def __init__(self):
        super().__init__("Microsoft x86_64", ["rcx", "rdx", "r8", "r9"], "rax", "rsp")
        self.cc = idaapi.CM_CC_FASTCALL


# System V i386 ABI
class systemv_32_abi_t(stack_cc_abi_t):
    def __init__(self):
        super().__init__("System V i386", "rax", "rsp")  # rax & eax have the same reg_id in IDA
        self.cc = idaapi.CM_CC_STDCALL
