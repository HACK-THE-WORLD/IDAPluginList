import collections
import copy
from typing import Any, Collection, Dict, Iterator, Optional, Set, Tuple

import idaapi

import symless.allocators as allocators
import symless.cpustate.cpustate as cpustate
import symless.generation as generation
import symless.symbols as symbols
import symless.utils.ida_utils as ida_utils
import symless.utils.utils as utils


# a field's type & potential value
class ftype_t:
    def __init__(self, value: cpustate.absop_t):
        self.value = value

    # should we propagate this type when one of its values is read from a structure's field
    def should_propagate(self) -> bool:
        return False

    # get value to use when propagating with cpustate
    def get_propagated_value(self) -> cpustate.absop_t:
        if self.should_propagate():
            return copy.copy(self.value)  # copy to be sure not to mess with arguments tracking
        return None

    def __eq__(self, other) -> bool:
        return isinstance(other, self.__class__) and self.value == other.value

    def __hash__(self) -> int:
        return hash((self.__class__, self.value))

    def __str__(self) -> str:
        return f"{self.__class__.__name__}:({self.value})"


# structure pointer type
# does not record shifted struc ptr
class ftype_struc_t(ftype_t):
    def __init__(self, entry: "entry_t"):
        super().__init__(cpustate.sid_t(entry.id))
        self.entry = entry  # entry this field points to


# function pointer type
class ftype_fct_t(ftype_t):
    def __init__(self, value: cpustate.mem_t):
        super().__init__(value)

    def should_propagate(self) -> bool:
        return True


# default pointer type
class ftype_ptr_t(ftype_t):
    def __init__(self, value: cpustate.mem_t):
        super().__init__(value)

    def should_propagate(self) -> bool:
        return True


# entry point field
class field_t:
    def __init__(self, offset: int):
        self.offset = offset
        self.size: int = 0  # bitfield of possible sizes
        self.type: Collection[ftype_t] = collections.deque()  # list of affected types, in propagation's order

    # add a type to the field's possible types list
    def set_type(self, type: ftype_t):
        self.type.appendleft(type)  # record types in propagation order

    # get last affected type
    def get_type(self) -> Optional[ftype_t]:
        if len(self.type) == 0:
            return None
        return self.type[0]

    # add possible size
    def set_size(self, size: int):
        self.size |= size

    # get all possible field's sizes
    def get_size(self) -> Collection[int]:
        out = collections.deque()
        for i in range(8):
            if self.size & (1 << i):
                out.append(pow(2, i))
        return out


# records the data flow of a structure in a basic block
# since our data flow is flattened, loops & conditions are not taken into account
# then a basic block is an execution flow ended by a call or a ret
class block_t:
    def __init__(self, owner: "entry_t", id: int = 0):
        self.owner = owner
        self.fields: dict[int, field_t] = dict()  # fields defined in the block & their types

        # block index in owner's blocks list
        self.id = id

        # structure's boundaries, from accessed fields
        self.max = 0
        self.min = 0

        # called ep following this block in the data flow
        self.callee: Optional[Tuple[int, "entry_t"]] = None

        # following & preceding block in the entrypoint flow
        self.next: Optional[block_t] = None
        self.previous: Optional[block_t] = None

    def has_callee(self) -> bool:
        return self.callee is not None

    def get_callee(self) -> Optional[Tuple[int, "entry_t"]]:
        return self.callee

    # set the called ep following this block & shift applied
    def set_callee(self, callee: "entry_t", shift: int):
        self.callee = (shift, callee)

    def get_owner(self) -> "entry_t":
        return self.owner

    # returns following block in the entrypoint
    def get_next(self) -> "block_t":
        if self.next is None:
            self.next = block_t(self.owner, self.id + 1)
            self.next.previous = self
        return self.next

    def has_field(self, offset: int) -> bool:
        return offset in self.fields

    # get field defined by this block
    def get_field(self, offset: int) -> field_t:
        return self.fields[offset]

    # get all fields
    def get_fields(self) -> Iterator[field_t]:
        return self.fields.values()

    # add / get existing field
    def add_field(self, offset: int, size: int) -> field_t:
        # accept negative offset, a field can be retrieved with a CONTAINING_RECORD()

        if offset not in self.fields:
            self.fields[offset] = field_t(offset)
        self.fields[offset].set_size(size)

        # change size upper boundary
        end = offset + size
        if end > self.max:
            self.max = end

        # change size lower boundary
        if offset < self.min:
            self.min = offset

        return self.fields[offset]

    # get the latest type for a field
    # scope: current block + following (called) entry
    def get_field_type(self, offset: int) -> Optional[ftype_t]:
        ftype = None
        if self.has_callee():
            shift, callee = self.get_callee()
            ftype = callee.get_field_type(offset - shift)

        return self.get_field(offset).get_type() if (ftype is None and self.has_field(offset)) else ftype

    # get the flow of blocks following this one
    # yields (shift, block)
    def node_flow(self) -> Iterator[Tuple[int, "block_t"]]:
        yield (0, self)

        if self.has_callee():
            shift, callee = self.get_callee()
            for c_shift, c_block in callee.node_flow():
                yield (shift + c_shift, c_block)


# data flow entrypoints
# defines a structure's entry into the data flow
# records information defining a structure propagated from the given entrypoint
class entry_t:
    # this kind of ep is to be injected before or after state updates
    inject_before = False

    # this type of ep can have children
    can_ramificate = True

    def __init__(self, ea: int):
        self.ea = ea  # entry address
        self.id = -1  # entry identifier

        # for entrypoints defining a structure (root ep)
        self.struc_id = -1

        # structure associated to this entrypoint
        # the structure we will use to type this ep
        self.struc: Optional[generation.structure_t] = None
        self.struc_shift = 0

        # data flow injection parameters
        self.to_analyze = True  # yet to analyze

        # list of instruction's operands associated with this ep
        self.operands: dict[Tuple[int, int], int] = dict()  # (insn.ea, op_index) -> (shift)

        # list of the entries that can precede this one in a data flow
        self.parents: Collection[Tuple[int, entry_t]] = collections.deque()

        # list of entries we want to analyze following this one
        self.children: Collection[Tuple[int, entry_t]] = collections.deque()

        # entrypoint size
        self.bounds: Optional[Tuple[int, int]] = None

        self.blocks: Optional[block_t] = None  # list of blocks composing this ep
        self.cblock: Optional[block_t] = None  # current active block

    # does the entry point defines a structure to be generated
    def is_root(self) -> bool:
        return self.struc_id >= 0

    def set_root(self, sid: int):
        self.struc_id = sid

    def has_structure(self) -> bool:
        return self.struc is not None

    def set_structure(self, shift: int, struc: "generation.structure_t"):
        self.struc = struc
        self.struc_shift = shift

    # get the structure associated with the entry
    def get_structure(self) -> Tuple[int, "generation.structure_t"]:
        return (self.struc_shift, self.struc)

    # return the function containing this ep
    def get_function(self) -> int:
        return idaapi.BADADDR

    # get all the structures that flow through this ep
    def get_flow(self) -> Collection[Tuple[int, "generation.structure_t"]]:
        flow = set()
        if self.is_root():
            flow.add(self.get_structure())
        for shift, parent in self.get_parents():
            flow.update([(shift + s_shift, s) for s_shift, s in parent.get_flow()])
        return flow

    def add_field(self, offset: int, size: int) -> field_t:
        return self.cblock.add_field(offset, size)

    # get field at given offset
    def get_field(self, offset: int) -> Optional[field_t]:
        return self.cblock.get_field(offset)

    # get the latest type for a field
    # scope: current entry (previous block & callees), at current state (not done analyzing)
    def get_field_type(self, offset: int) -> Optional[ftype_t]:
        ftype = None
        current = self.cblock
        while ftype is None and current is not None:
            ftype = current.get_field_type(offset)
            current = current.previous

        return ftype

    # get ep boundaries, min & max access on ep
    def get_boundaries(self) -> Tuple[int, int]:
        if self.bounds is None:
            lower, upper = 0, 0

            # ep own boundaries
            current = self.blocks
            while current is not None:
                lower = min(lower, current.min)
                upper = max(upper, current.max)
                current = current.next

            # boundaries from ep children
            for off, child in self.get_children(True):
                ci, ca = child.get_boundaries()
                lower = min(lower, ci + off)
                upper = max(upper, ca + off)

            self.bounds = (lower, upper)

        return self.bounds

    # associate operand at (ea, n) to this entrypoint, for given shift
    def add_operand(self, ea: int, n: int, shift: int):
        self.operands[(ea, n)] = shift

    def get_operands(self) -> Iterator[Tuple[int, int, int]]:
        for (ea, n), shift in self.operands.items():
            yield (ea, n, shift)

    # does the given node precede this node in the data flow
    def has_parent(self, parent: "entry_t") -> bool:
        return self == parent or any([p.has_parent(parent) for _, p in self.get_parents()])

    # add parent with given shift
    def add_parent(self, parent: "entry_t", shift: int) -> bool:
        if parent.has_parent(self):  # loop check
            return False

        if (shift, parent) not in self.parents:  # duplicate check
            self.parents.append((shift, parent))
        return True

    # add an entrypoint following this one in the data flow
    def add_child(self, child: "entry_t", shift: int) -> bool:
        if not child.add_parent(self, shift):
            return False

        if (shift, child) not in self.children:
            self.children.append((shift, child))
        return True

    # end the current block, with a call
    # the callee represents an ep to be processed after the current block and before the next one
    def end_block(self, callee: "entry_t", shift: int) -> bool:
        if not callee.add_parent(self, shift):
            return False

        self.cblock.set_callee(callee, shift)
        self.cblock = self.cblock.get_next()
        return True

    # get node's parents
    # yields (shift, parent)
    def get_parents(self) -> Iterator[Tuple[int, "entry_t"]]:
        for off, p in self.parents:
            yield (off, p)

    # get node's children
    # if all is set, returns following children + end blocks callee children
    # else only returns following children
    def get_children(self, all: bool = False) -> Iterator[Tuple[int, "entry_t"]]:
        if all:
            current = self.blocks
            while current.next is not None:
                yield current.get_callee()
                current = current.next

        for off, c in self.children:
            yield (off, c)

    # get the flow of blocks following this entrypoint
    # yields (shift, block)
    def node_flow(self) -> Iterator[Tuple[int, block_t]]:
        # flow for entry's blocks
        current = self.blocks
        while current is not None:
            for shift, block in current.node_flow():
                yield (shift, block)
            current = current.next

        # flow for entry's children
        for shift, child in self.get_children():
            for c_shift, c_block in child.node_flow():
                yield (shift + c_shift, c_block)

    # get distance to given child
    # assume self is parent of child
    def distance_to(self, child: "entry_t") -> int:
        q = collections.deque()

        q.append((child, 0))
        while len(q) > 0:
            current, distance = q.popleft()
            if current == self:
                return distance

            for _, p in current.get_parents():
                q.append((p, distance + 1))

        raise Exception(f"{self.entry_id()} is not a parent of {child.entry_id()}")

    # inject entrypoint on given state
    # return True if the ep had to be analyzed
    def inject(self, ea: int, state: cpustate.state_t, ctx: "context_t", reset: bool = True) -> bool:
        if reset:
            self.reset()
        had_to = self.to_analyze
        self.to_analyze = False  # is beeing analyzed
        return had_to

    # reset non-cumulative states when re-propagating
    def reset(self):
        # reset blocks
        self.blocks = block_t(self)
        self.cblock = self.blocks
        utils.g_logger.debug(f"Resetting {self.entry_id()}")

    # get unique key identifying the ep from others
    # to be implemented by heirs
    def get_key(self) -> Any:
        raise Exception(f"{self.__class__} does not implement method get_key")

    # find name of the structure associated to this entry point
    # using symbols information
    # returns name, relevance (the least, the more relevant)
    def find_name(self) -> Tuple[Optional[str], int]:
        return None, 0

    def entry_header(self) -> str:
        return "Entry[sid=%d], ea: 0x%x, [%s]" % (
            self.id,
            self.ea,
            ("TO_ANALYZE" if self.to_analyze else "ANALYZED"),
        )

    def entry_id(self) -> str:
        return f"ep_0x{self.ea:x}"

    def __eq__(self, other) -> bool:
        return isinstance(other, entry_t) and other.id == self.id

    def __hash__(self) -> int:
        return self.id

    def __str__(self) -> str:
        out = "%s\n" % self.entry_header()
        out += f"\t| Parents: {len([i for i in self.get_parents()])}\n"

        if len(self.operands) > 0:
            out += "\t| Operands:\n"
            for (ea, op), shift in self.operands.items():
                out += f"\t\t{ida_utils.addr_friendly_name(ea)}, ea: 0x{ea:x}, op: {op}, shift 0x{shift:x}\n"

        if len(self.children) > 0:
            out += "\t| Children:\n"
            for offset, child in self.children:
                out += f"\t\tentry[sid={child.id}], off: 0x{offset:x}, ea: 0x{child.ea:x}\n"

        return out


# entrypoint as a method's argument
class arg_entry_t(entry_t):
    inject_before = True

    def __init__(self, ea: int, index: int):
        super().__init__(ea)
        self.index = index

    def get_function(self) -> int:
        return self.ea

    def find_name(self) -> Tuple[Optional[str], int]:
        if self.index != 0:  # TODO use fct arguments types to find names of arguments that are not 'this'
            return None, 0

        fct_name = ida_utils.demangle_ea(self.ea)
        return symbols.get_classname_from_ctor(fct_name), 1

    def inject(self, ea: int, state: cpustate.state_t, ctx: "context_t") -> bool:
        had_to = super().inject(ea, state, ctx, False)
        cc = ctx.dflow_info.get_function_cc(ea)
        cpustate.set_argument(cc, state, self.index, cpustate.sid_t(self.id))
        return had_to

    def get_key(self) -> int:
        return self.index

    def entry_id(self) -> str:
        return f"ep_0x{self.ea:x}_arg{self.index}"

    def entry_header(self) -> str:
        return "Entry[sid=%d], arg %d of ea: 0x%x(%s), [%s]" % (
            self.id,
            self.index,
            self.ea,
            ida_utils.addr_friendly_name(self.ea),
            ("TO_ANALYZE" if self.to_analyze else "ANALYZED"),
        )


# entry point in a register
# as a destination operand (inject_before == False)
class dst_reg_entry_t(entry_t):
    def __init__(self, ea: int, fct_ea: int, reg: str):
        super().__init__(ea)
        self.reg = reg
        self.fct_ea = fct_ea

    def get_function(self) -> int:
        return self.fct_ea

    def inject(self, ea: int, state: cpustate.state_t, ctx: "context_t") -> bool:
        had_to = super().inject(ea, state, ctx)
        state.set_register_str(self.reg, cpustate.sid_t(self.id))
        return had_to

    def get_key(self) -> str:
        return self.reg

    def entry_id(self) -> str:
        return f"ep_0x{self.ea:x}_{self.reg}"

    def entry_header(self) -> str:
        return "Entry[sid=%d], reg %s at ea: 0x%x(%s), [%s]" % (
            self.id,
            self.reg,
            self.ea,
            ida_utils.addr_friendly_name(self.ea),
            ("TO_ANALYZE" if self.to_analyze else "ANALYZED"),
        )


# entry point in a register
# as a src operand (inject_before == True)
class src_reg_entry_t(dst_reg_entry_t):
    # inject_before needs to be a static member
    # because of its use in get_entry_by_key()
    # thus two reg_entry_t classes are required
    inject_before = True


# entry point as a value read from a structure
# can be used to propagate a structure ptr written & read from a structure
class read_entry_t(dst_reg_entry_t):
    can_ramificate = False

    def __init__(self, ea: int, fct_ea: int, reg: str, source: entry_t, off: int):
        super().__init__(ea, fct_ea, reg)

        # source ep & offset this ep was read from
        self.src = source
        self.src_off = off

    def entry_id(self) -> str:
        return f"ep_rd_0x{self.ea:x}_{self.reg}"

    def add_parent(self, parent: "entry_t", shift: int) -> bool:
        raise Exception("read_entry_t are not meant to be linked with parents")


# entry point as a callee ret value
# with known size (static allocation)
class ret_entry_t(dst_reg_entry_t):
    def __init__(self, ea: int, fct_ea: int, size: int):
        super().__init__(ea, fct_ea, cpustate.get_default_cc().ret)
        self.size = size

    # retrieve name from factory function
    # this is not an accurate name for a structure, and is to be used as a last chance name
    def find_name(self) -> Tuple[Optional[str], int]:
        fct = idaapi.get_func(self.ea)
        if fct is None:
            utils.g_logger.error(f"No function for entry {self.entry_id()}, this should not happen")
            return None, 0

        # do not use 'sub_' function names
        if not symbols.has_relevant_name(fct.start_ea):
            return None, 0

        fct_name = symbols.method_name_from_signature(ida_utils.demangle_ea(fct.start_ea))
        return f"struc_{fct_name}", 3

    def add_field(self, offset: int, size: int) -> field_t:
        if offset < 0 or offset + size > self.size:
            return False

        return super().add_field(offset, size)


# constant root entry
# define a known structure we do not need to build on the way
class cst_entry_t(entry_t):
    def __init__(self, ea: int):
        super().__init__(ea)

        self.to_analyze = False

    # do not record accessed fields
    def add_field(self, offset: int, size: int) -> None:
        return None

    # a root has no parents
    def has_parent(self, parent: entry_t) -> bool:
        return False

    def add_parent(self, parent: entry_t, shift: int) -> bool:
        return False

    def end_block(self, callee: entry_t, shift: int) -> bool:
        return False

    def inject(self, ea: int, state: cpustate.state_t, ctx: "context_t") -> bool:
        raise Exception(f"{self.entry_id()} is not to be injected in the data flow")


# vtable root entry
class vtbl_entry_t(cst_entry_t):
    def __init__(self, ea: int):
        super().__init__(ea)
        self.reset()  # add default block
        self.total_xrefs = 0  # count of xref towards vtable's functions

        # find vtable methods, build the model
        i = 0
        ptr_size = ida_utils.get_ptr_size()
        for fea in ida_utils.vtable_members(ea):
            field = entry_t.add_field(self, i, ptr_size)
            field.set_type(ftype_fct_t(cpustate.mem_t(fea, fea, ptr_size)))
            self.total_xrefs += len(ida_utils.get_data_references(fea))
            i += ptr_size

    # is self derived from other
    def is_most_derived(self, other: "vtbl_entry_t") -> bool:
        self_refs, self_size = self.total_xrefs, self.get_boundaries()[1]
        other_refs, other_size = other.total_xrefs, other.get_boundaries()[1]
        if self_size > other_size:
            return True
        if other_size > self_size:
            return False
        if self_refs > other_refs:
            return False
        return True

    def get_key(self) -> Any:
        return None

    def find_name(self) -> Tuple[Optional[str], int]:
        return symbols.get_vtable_name_from_ctor(self.ea), 0

    def entry_id(self) -> str:
        return f"ep_0x{self.ea:x}_vtbl"

    def entry_header(self) -> str:
        return f"Vtable at {ida_utils.demangle_ea(self.ea)}"


# records all entrypoints
class entry_record_t:
    g_next_sid = -1

    def __init__(self):
        self.entries_per_sid: list[entry_t] = list()  # entry per sid

        # sorted entries, by ea for quick access
        # & by inject_before / inject_after
        self.entries_per_ea: dict[int, Tuple[Collection[entry_t], Collection[entry_t]]] = dict()

    # next entry point id
    def next_id(self) -> int:
        return len(self.entries_per_sid)

    def structures_count(self) -> int:
        return entry_record_t.g_next_sid + 1

    # add an entrypoint to the graph
    def add_entry(self, entry: entry_t, as_root: bool = False, inc_sid: bool = True) -> entry_t:
        existing = self.get_entry_by_key(entry.ea, entry.__class__, entry.get_key())
        if existing is not None:
            return existing

        if entry.ea not in self.entries_per_ea:
            self.entries_per_ea[entry.ea] = (collections.deque(), collections.deque())
        self.entries_per_ea[entry.ea][int(not entry.__class__.inject_before)].append(entry)

        entry.id = self.next_id()
        self.entries_per_sid.append(entry)

        if as_root:
            entry_record_t.g_next_sid += int(inc_sid)
            entry.set_root(entry_record_t.g_next_sid)

        return entry

    # add an entry to the graph, as a child of another entry
    def add_entry_as_child(self, parent: entry_t, child: entry_t, shift: int, block_end: bool) -> Optional[entry_t]:
        # check if parent can have children
        if not parent.__class__.can_ramificate:
            return None

        effective = self.add_entry(child)

        if block_end:
            parent.end_block(effective, shift)
        else:
            parent.add_child(effective, shift)

        return effective

    # remove an entry from the graph, and its successors
    def remove_entry(self, entry: entry_t):
        # entry should not have any parents
        assert len(entry.parents) == 0

        for shift, child in entry.get_children(True):
            child.parents.remove((shift, entry))
            if len(child.parents) == 0:
                self.remove_entry(child)

        self.entries_per_ea[entry.ea][int(not entry.__class__.inject_before)].remove(entry)
        self.entries_per_sid[entry.id] = None

    # all entries to inject at given ea
    def get_entries_at(self, ea: int, inject_after: bool) -> Collection[entry_t]:
        if ea not in self.entries_per_ea:
            return []

        return self.entries_per_ea[ea][int(inject_after)]

    # entry by sid
    def get_entry_by_id(self, sid: int) -> Optional[entry_t]:
        if sid < 0 or sid >= len(self.entries_per_sid):
            return None
        return self.entries_per_sid[sid]

    # entry by ea, class & unique key identifier
    def get_entry_by_key(self, ea: int, cls: type, key: Any = None) -> Optional[entry_t]:
        if ea not in self.entries_per_ea:
            return None

        c = filter(
            lambda e: isinstance(e, cls) and e.get_key() == key,
            self.entries_per_ea[ea][int(not cls.inject_before)],
        )

        try:
            return next(c)
        except StopIteration:
            return None

    def get_entries(self) -> Iterator[entry_t]:
        for entry in self.entries_per_sid:
            if entry is not None:
                yield entry

    # yield all unexplored entrypoints
    # TODO: yield from most interesting function to less (fct having the most entrypoints)
    def next_to_analyze(self) -> Iterator[entry_t]:
        current_len = len(self.entries_per_sid)
        for i in range(current_len):
            if self.entries_per_sid[i].to_analyze:
                yield self.entries_per_sid[i]

    def __str__(self) -> str:
        out = ""
        for entry in self.entries_per_sid:
            out += f"{str(entry)}\n"
        return out


# defines a function
class function_t:
    def __init__(self, ea: int):
        self.ea = ea
        self.nargs = 0  # arguments count (minimum estimated)
        self.cc = cpustate.get_abi()  # guessed calling convention

        # optional entrypoint sid as function's ret value
        self.ret_sid: int = -1

        # is a virtual method
        self.virtual = False

    def set_ret(self, sid: int):
        self.ret_sid = sid

    def get_ret(self) -> int:
        return self.ret_sid

    def set_nargs(self, nargs: int):
        self.nargs = nargs

    def get_nargs(self) -> int:
        return self.nargs

    def set_cc(self, cc: cpustate.arch.abi_t):
        self.cc = cc

    # get IDA CM_CC_ calling convention
    def get_ida_cc(self) -> int:
        return self.cc.cc

    def set_virtual(self):
        self.virtual = True

    def is_virtual(self) -> bool:
        return self.virtual

    def __eq__(self, other: object) -> bool:
        return isinstance(other, function_t) and self.ea == other.ea


# global model
# groups information gathered by the analysis
class context_t:
    # init from a list of entrypoints and propagation context
    def __init__(self, entries: entry_record_t, allocators: Set[allocators.allocator_t]):
        self.allocators = allocators  # all registered allocators
        self.functions: dict[int, function_t] = dict()  # ea -> function_t
        self.graph = entries  # entrypoints tree hierarchy

        # information gathered by data flow
        # is to be deleted once propagation is done
        self.dflow_info: Optional[cpustate.dflow_ctrl_t]

        # propagation context depth
        self.follow_calls = True

        # dive into callee decision
        self.dive_in: bool = False

    # record all visited functions into model
    def record_functions(self, record: Dict[int, cpustate.function_t]):
        for ea, visited in record.items():
            if visited.cc_not_guessed:
                continue

            fct = self.get_function(ea)
            fct.set_nargs(visited.get_count())
            fct.set_cc(visited.cc)

    def get_function(self, ea: int) -> function_t:
        if ea not in self.functions:
            self.functions[ea] = function_t(ea)
        return self.functions[ea]

    def get_functions(self) -> Collection[function_t]:
        return self.functions.values()

    def get_entrypoints(self) -> entry_record_t:
        return self.graph

    def get_allocators(self) -> Set[allocators.allocator_t]:
        return self.allocators

    def can_follow_calls(self) -> bool:
        return self.follow_calls

    def set_follow_calls(self, follow: bool):
        self.follow_calls = follow
