import enum
import re
from typing import List, Tuple

import idaapi

import symless.cpustate.cpustate as cpustate
import symless.utils.ida_utils as ida_utils
import symless.utils.utils as utils

# do not consider alloc bigger than this to be object allocs
g_max_alloc = 0xFFFFFF


def valid_size(size: int):
    return size > 0 and size <= g_max_alloc


class alloc_action_t(enum.Enum):  # allocator action
    STATIC_ALLOCATION = 0  # malloc(n)
    WRAPPED_ALLOCATOR = 1  # func(x) -> return malloc(x)
    JUMP_TO_ALLOCATOR = 2  # func(x) -> jump malloc
    UNDEFINED = 3


# a heap allocation function
class allocator_t:
    index = dict()

    def __init__(self, ea: int, type: str):
        self.ea = ea
        self.type = type
        self.index = self.next_index()

    def next_index(self) -> int:
        try:
            allocator_t.index[self.type] += 1
            return allocator_t.index[self.type]
        except KeyError:
            allocator_t.index[self.type] = 0
            return 0

    def get_name(self) -> str:
        return f"{self.type}_like_{self.index:x}"

    def get_child(self, ea: int, args: tuple):
        child = self.__class__.__new__(self.__class__)  # is there a nicer way to do this ?
        child.__init__(ea, *args)
        return child

    # how to type the allocator once identified
    def make_type(self, func_data: idaapi.func_type_data_t):
        pass

    # what type of allocation for given state + allocation size for STATIC_ALLOCATION
    def on_call(self, state: cpustate.state_t) -> Tuple[alloc_action_t, int]:
        return (alloc_action_t.UNDEFINED, 0)

    # for WRAPPED_ALLOCATOR action, does wrapper ret confirm it is a wrapper
    def on_wrapper_ret(self, state: cpustate.state_t, call_ea: int) -> bool:
        ret_val = state.ret.code
        if isinstance(ret_val, cpustate.call_t) and ret_val.where == call_ea:
            return True

        return False

    def __hash__(self):
        return self.ea

    def __eq__(self, other):
        return isinstance(other, allocator_t) and self.ea == other.ea

    def __repr__(self):
        return f"[0x{self.ea:x}] - {ida_utils.demangle_ea(self.ea)} ({self.get_name()})"


# malloc like function, takes one size parameter and returns memory space
class malloc_like_t(allocator_t):
    def __init__(self, ea: int, size_index: int = 0):
        allocator_t.__init__(self, ea, "malloc")
        self.size_index = size_index

    def on_call(self, state: cpustate.state_t) -> Tuple[alloc_action_t, int]:
        is_jump = state.call_type == cpustate.call_type_t.JUMP

        # size parameter
        arg = cpustate.get_argument(cpustate.get_default_cc(), state, self.size_index, False, is_jump)

        # size argument comes from wrapper arguments, wrapper might be an allocator
        if isinstance(arg, cpustate.arg_t):
            index = arg.idx

            if is_jump:
                return (alloc_action_t.JUMP_TO_ALLOCATOR, (index,))

            return (alloc_action_t.WRAPPED_ALLOCATOR, (index,))

        # static size - memory allocation
        if isinstance(arg, cpustate.int_t) and valid_size(arg.get_val()):
            return (alloc_action_t.STATIC_ALLOCATION, arg.get_val())

        return (alloc_action_t.UNDEFINED, 0)

    def make_type(self, func_data: idaapi.func_type_data_t):
        func_data.rettype = ida_utils.void_ptr()

        tinfo = ida_utils.get_local_type("size_t")
        if tinfo.get_decltype() == idaapi.BT_UNK:
            tinfo = ida_utils.get_basic_type(idaapi.BT_INT)

        ida_utils.set_function_argument(func_data, self.size_index, tinfo, name="size")

    def __repr__(self):
        return f"malloc_like_t : [0x{self.ea:x}] - {ida_utils.demangle_ea(self.ea)} ({self.get_name()}) index : ({self.size_index})"


# calloc like allocator, takes two parameters: count & unit size
class calloc_like_t(allocator_t):
    def __init__(self, ea: int, count_index: int = 0, size_index: int = 1):
        allocator_t.__init__(self, ea, "calloc")
        self.count_index = count_index
        self.size_index = size_index

    def on_call(self, state: cpustate.state_t) -> Tuple[alloc_action_t, int]:
        is_jump = state.call_type == cpustate.call_type_t.JUMP

        count_arg = cpustate.get_argument(cpustate.get_default_cc(), state, self.count_index, False, is_jump)
        size_arg = cpustate.get_argument(cpustate.get_default_cc(), state, self.size_index, False, is_jump)

        if isinstance(count_arg, cpustate.arg_t) and isinstance(size_arg, cpustate.arg_t):
            count_index = count_arg.idx
            size_index = size_arg.idx

            if is_jump:
                return (alloc_action_t.JUMP_TO_ALLOCATOR, (count_index, size_index))

            return (alloc_action_t.WRAPPED_ALLOCATOR, (count_index, size_index))

        if (
            isinstance(count_arg, cpustate.int_t)
            and valid_size(count_arg.get_val())
            and isinstance(size_arg, cpustate.int_t)
            and valid_size(size_arg.get_val())
        ):
            size = count_arg.get_val() * size_arg.get_val()
            return (alloc_action_t.STATIC_ALLOCATION, size)

        return (alloc_action_t.UNDEFINED, 0)

    def make_type(self, func_data: idaapi.func_type_data_t):
        func_data.rettype = ida_utils.void_ptr()

        tinfo = ida_utils.get_local_type("size_t")
        if tinfo.get_decltype() == idaapi.BT_UNK:
            tinfo = ida_utils.get_basic_type(idaapi.BT_INT)

        ida_utils.set_function_argument(func_data, self.count_index, tinfo, name="nmemb")
        ida_utils.set_function_argument(func_data, self.size_index, tinfo, name="size")

    def __repr__(self):
        return f"calloc_like_t : [0x{self.ea:x}] - {ida_utils.demangle_ea(self.ea)} ({self.get_name()}) index : ({self.size_index})"


# realloc is just a malloc with the size parameter at index 1
class realloc_t(malloc_like_t):
    def __init__(self, ea: int, size_index: int = 1):
        allocator_t.__init__(self, ea, "realloc")
        self.size_index = size_index

    def __repr__(self):
        return f"realloc_like_t : [0x{self.ea:x}] - {ida_utils.demangle_ea(self.ea)} ({self.get_name()}) index : ({self.size_index})"


available_allocators = {"malloc": malloc_like_t, "calloc": calloc_like_t, "realloc": realloc_t}


# parse calloc(0, 1) into (calloc_like_t, [0,1])
def parse_allocator(declaration: str) -> Tuple[allocator_t, list]:
    pattern = re.compile(r"^([a-zA-Z]+)(?:\((\s*[0-9]+\s*(?:\|\s*[0-9]+\s*)*)?\))?$")
    match = pattern.match(declaration)
    if match is None:
        return (None, None)

    try:
        allocator = available_allocators[match.group(1)]
    except KeyError:
        return (None, None)

    args = list()
    if match.group(2) is not None:
        for index in match.group(2).split("|"):
            if len(index) == 0:
                continue

            try:
                args.append(int(index))
            except ValueError:
                return (None, None)

    return (allocator, args)


# reads config.csv data to find memory allocators in the binary, used as entry points
def get_allocators(config_path: str) -> List[allocator_t]:
    imports = []

    try:
        config = open(config_path)
    except FileNotFoundError as e:
        utils.g_logger.error("Can not retrieve config file (%s)" % str(e))
        return None

    i = 1
    current = config.readline()
    while current:
        current = current.strip().split("#")[0]

        if len(current) == 0 or current[0] == "#":
            pass
        else:
            keys = current.split(",")
            length = len(keys)
            if length > 3 or length < 2:
                utils.g_logger.error("%s bad syntax at line %d" % (config_path, i))
                return None

            import_type, args = parse_allocator(keys[-1].strip())
            if import_type is None:
                utils.g_logger.error(
                    '%s bad syntax for allocator type "%s" at line %d' % (config_path, keys[-1].strip(), i)
                )
                return None

            # entry point from lib import
            if length == 3:
                module_name = keys[0].strip()
                import_name = keys[1].strip()

                module = ida_utils.get_import_module_index(module_name)

                if module is None:
                    utils.g_logger.debug(
                        "import %s from module %s absent from binary (module not imported)" % (import_name, module_name)
                    )
                    pass
                else:
                    ea = ida_utils.get_import_from_module(module, import_name)
                    if ea is None:
                        utils.g_logger.debug("import %s from module %s absent from binary" % (import_name, module_name))
                    else:
                        utils.g_logger.info("retrieved entry point %s from module %s" % (import_name, module_name))

                        imports.append(import_type(ea, *args))

            # entry point as function from binary
            elif length == 2:
                func_name = keys[0].strip()

                try:
                    func_ea = int(func_name, 16)
                except ValueError:
                    func_ea = idaapi.get_name_ea(idaapi.BADADDR, func_name)

                func = idaapi.get_func(func_ea)
                if func is None or func.start_ea != func_ea:
                    utils.g_logger.error('Unable to located entry point "%s"' % func_name)
                else:
                    utils.g_logger.info('Retrieved entry point "%s"' % func_name)

                    imports.append(import_type(func.start_ea, *args))

        current = config.readline()
        i += 1

    config.close()

    return imports
