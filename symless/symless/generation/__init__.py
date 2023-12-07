import collections
from typing import Collection, Iterator, Optional, Set, Tuple, Union

import idaapi

import symless.config as config
import symless.existing as existing
import symless.model as model
import symless.symbols as symbols
import symless.utils.ida_utils as ida_utils
import symless.utils.utils as utils


# a structure's field
class field_t:
    def __init__(
        self,
        offset: int,
        size: int,
        flow: model.entry_t,
        block: model.block_t,
    ):
        self.offset = offset
        self.size = size
        self.flow: model.entry_t = flow  # root of the flow this field comes from
        self.block: model.block_t = block  # block where this field was set
        self.name: Optional[str] = None  # field's name
        self.owner: Optional[structure_t] = None  # structure this field belongs to

    # get field's default name
    def get_default_name(self) -> str:
        return f"field_{self.offset:08x}"

    # get field's name
    def get_name(self) -> str:
        if self.name is None:
            return self.get_default_name()
        return self.name

    # compute wished field's name using symbols
    # does not handle conflicts
    def preferred_name(self) -> Optional[str]:
        return None

    # compute field's name
    def set_name(self, taken: Set[str]):
        self.name = self.preferred_name()
        if self.name is None:
            return

        if self.name in taken:
            self.name = f"{self.name}_0x{self.offset:x}"

        taken.add(self.name)

    # comment associated to the field
    def get_comment(self) -> Optional[str]:
        return None

    # get field's type
    def get_type(self) -> Optional[idaapi.tinfo_t]:
        return None

    # do we have information on this field's type
    def has_type(self) -> bool:
        return False

    # set the structure this fields belongs to
    def set_owner(self, struc: "structure_t"):
        self.owner = struc

    # are self & other types compatible
    def match(self, other: "field_t") -> bool:
        return self.size == other.size

    # should we replace the field by given other field
    def replace(self, other: "field_t") -> bool:
        # other has a more derived type, use it
        if isinstance(other, self.__class__) and not isinstance(self, other.__class__):
            return True

        # replacement class is less derived, keep current value
        if isinstance(self, other.__class__) and not isinstance(other, self.__class__):
            return False

        # try to keep the type set in the constructor / init function
        # i.e nearest function from the root of the data flow
        distance_new = other.flow.distance_to(other.block.get_owner())
        distance_old = self.flow.distance_to(self.block.get_owner())
        if distance_new < distance_old:
            return True
        if distance_new > distance_old:
            return False

        utils.g_logger.warning(
            f"Can not decide between fields set in {self.block.get_owner().entry_id()} and {other.block.get_owner().entry_id()} for structure {self.owner.get_name()}"
        )
        return True

    def __str__(self) -> str:
        return f"{self.__class__.__name__} (0x{self.offset:x}:0x{self.size:x}), name: {self.get_name()}"


# field typed with an unknown pointer
class ptr_field_t(field_t):
    def __init__(self, offset: int, flow: model.entry_t, block: model.block_t):
        super().__init__(offset, ida_utils.get_ptr_size(), flow, block)

    def get_default_name(self) -> str:
        return f"ptr_{self.offset:08x}"

    def has_type(self) -> bool:
        return True


# field typed with a function pointer
class fct_ptr_field_t(ptr_field_t):
    def __init__(
        self,
        fct: model.function_t,
        offset: int,
        flow: model.entry_t,
        block: model.block_t,
    ):
        super().__init__(offset, flow, block)
        self.fct = fct  # pointed function

    def get_default_name(self) -> str:
        return f"method_{self.offset:08x}"

    def preferred_name(self) -> Optional[str]:
        signature = ida_utils.demangle_ea(self.fct.ea)
        return None if len(signature) == 0 else symbols.method_name_from_signature(signature)

    def get_comment(self) -> str:
        return idaapi.get_name(self.fct.ea)

    def get_type(self) -> Optional[idaapi.tinfo_t]:
        func_tinfo, func_data = ida_utils.get_or_create_fct_type(self.fct.ea, self.fct.get_ida_cc())

        # owner is a vtable, make sure to type method's 'this' argument
        if isinstance(self.owner, vtable_t):
            this, shift = self.owner.get_class()
            this_tinfo = this.find_ptr_tinfo()
            ida_utils.set_function_argument(func_data, 0, this_tinfo, shift, this_tinfo, "this")
            func_tinfo.create_func(func_data)

        func_tinfo.create_ptr(func_tinfo)
        return func_tinfo

    def match(self, other: "fct_ptr_field_t") -> bool:
        return self.fct == other.fct


# field typed with a structure pointer
class struc_ptr_field_t(ptr_field_t):
    def __init__(
        self,
        ep: model.entry_t,
        offset: int,
        flow: model.entry_t,
        block: model.block_t,
    ):
        super().__init__(offset, flow, block)
        self.value = ep  # ep written in this field

    def get_default_name(self) -> str:
        return f"struc_{self.offset:08x}"

    # get structure this field points to
    def get_structure(self) -> Tuple[int, "structure_t"]:
        return self.value.get_structure()

    def get_type(self) -> Optional[idaapi.tinfo_t]:
        shift, struc = self.get_structure()

        tinfo = struc.find_ptr_tinfo()
        if tinfo is None:
            utils.g_logger.error('Could not retrieve local type with name "%s" for field typing' % struc.get_name())
            return None

        ida_utils.shift_ptr(tinfo, tinfo, shift)
        return tinfo

    def match(self, other: "struc_ptr_field_t") -> bool:
        self_shift, self_struc = self.get_structure()
        other_shift, other_struc = other.get_structure()

        return self_shift == other_shift and self_struc == other_struc


# field typed with a vtable pointer
class vtbl_ptr_field_t(struc_ptr_field_t):
    def __init__(
        self,
        types: Collection[model.ftype_t],
        offset: int,
        flow: model.entry_t,
        block: model.block_t,
    ):
        super().__init__(None, offset, flow, block)

        # all vtables that went in this field
        self.values: Collection[model.vtbl_entry_t] = collections.deque()

        # are we sure the list of vtables set are in the ctor order
        self.in_order = not isinstance(flow, model.arg_entry_t)

        # fill types
        for type in filter(
            lambda t: isinstance(t, model.ftype_struc_t) and isinstance(t.entry, model.vtbl_entry_t),
            types[::-1],
        ):
            self.add_vtable(type.entry, self.in_order)

    def get_default_name(self) -> str:
        return "%s%s" % (idaapi.VTBL_MEMNAME, "" if self.offset == 0 else f"_{self.offset:08x}")

    def get_comment(self) -> str:
        _, vtbl = self.get_structure()
        return vtbl.get_name()

    # add given vtable to vtables values list
    # is as_latest is set, consider it to be effective field's value
    # else use less derived vtable between first & last added
    def add_vtable(self, vtbl: model.vtbl_entry_t, as_latest: bool) -> bool:
        if vtbl in self.values:  # already encountered
            return False

        self.values.append(vtbl)
        self.value = vtbl

        if not as_latest and self.values[0].is_most_derived(vtbl):  # keep first vtbl set
            self.value = self.values[0]
            return False

        return True

    def replace(self, other: "field_t") -> bool:
        if not isinstance(other, vtbl_ptr_field_t):
            return False

        # different data flow, do not take into account
        if other.flow != self.flow:
            return False

        if self.add_vtable(other.value, self.in_order):
            other.values = self.values  # keep vtable record in new field
            return True

        return False


# model of a structure
class structure_t:
    def __init__(self, sid: int):
        self.sid = sid  # model sid
        self.size = -1  # structure size, if known
        self.ea = idaapi.BADADDR
        self.ida_sid = idaapi.BADADDR  # associated IDA struc sid

        self.fields: dict[int, field_t] = dict()  # structure's members
        self.range: Collection[tuple[int, int]] = list()  # structure's ranges occupied by fields (offset, size)

        self.name: Optional[str] = None  # struc's name

        # set of structure's entries in the data flow
        # records (shift, entry), shift is used when entry is a shift ptr on our strucs
        self.root_eps: Set[Tuple[int, model.entry_t]] = set()

    def set_size(self, size: int):
        self.size = size

    # size of struc
    # if unknown, get current size from defined fields
    def get_size(self) -> int:
        if self.size >= 0:
            return self.size
        if len(self.range) == 0:
            return 0
        last = self.range[-1]
        return last[0] + last[1]

    # add a field to the structure
    # solver_cb callback used to resolve overlapping fields
    def set_field(self, field: field_t, solver_cb) -> bool:
        offset = field.offset
        field_end = offset + field.size

        # check boundaries
        if offset < 0 or (self.size >= 0 and field_end > self.size):
            utils.g_logger.warning(
                f"Could not add field (0x{offset:x}:0x{field.size:x}) to {self.get_name()} of size {self.size:x}"
            )
            return False

        # compute overlapping fields
        i = 0
        replaced = collections.deque()
        while i < len(self.range) and self.range[i][0] < field_end:
            other_end = self.range[i][0] + self.range[i][1]

            # overlapping fields
            if other_end > offset:
                replace = solver_cb(field, self.fields[self.range[i][0]])
                if replace:
                    replaced.appendleft(i)
                else:  # do not insert new field
                    utils.g_logger.debug(
                        "Could not add %s (set in %s) to %s because of conflicts with existing (0x%x:0x%x)"
                        % (
                            field.get_name(),
                            field.block.get_owner().entry_id(),
                            self.get_name(),
                            self.range[i][0],
                            self.range[i][1],
                        )
                    )
                    return False

            i += 1

        # remove conflicting fields
        for j in replaced:
            old = self.fields[self.range[j][0]]
            utils.g_logger.debug(
                "Discarding %s (set in %s) from %s, replacing with %s (set in %s)"
                % (
                    old.get_name(),
                    old.block.get_owner().entry_id(),
                    self.get_name(),
                    field.get_name(),
                    field.block.get_owner().entry_id(),
                )
            )
            del self.fields[self.range[j][0]]
            del self.range[j]

        # add new field
        idx = i - len(replaced)
        self.range.insert(idx, (offset, field.size))
        self.fields[offset] = field
        field.set_owner(self)

        utils.g_logger.debug(f"Adding {field} to {self.get_name()}")

        return True

    def get_field(self, offset: int) -> Optional[field_t]:
        try:
            return self.fields[offset]
        except KeyError:
            return None

    def get_fields(self) -> Iterator[field_t]:
        for field in self.fields.values():
            yield field

    # add one root entrypoint
    # defining a data flow this structure follows
    def associate_root(self, entry: model.entry_t, shift: int):
        # struc's default name is based on ea, on assign it once
        if self.ea == idaapi.BADADDR:
            self.ea = entry.ea

        self.root_eps.add((shift, entry))
        entry.set_structure(shift, self)

    # get structure's entries in the data flow
    def associated_root(self) -> Iterator[Tuple[int, model.entry_t]]:
        for shift, root in self.root_eps:
            yield shift, root

    # get the flow of nodes traveled by the structure
    # yields (root node, current shift, current block)
    def node_flow(self) -> Iterator[Tuple[model.entry_t, int, model.block_t]]:
        for initial_shift, root in self.associated_root():
            for shift, node in root.node_flow():
                yield (root, initial_shift + shift, node)

    # find existing IDA structure that this model represents
    def find_existing(self) -> int:
        self.ida_sid = idaapi.get_struc_id(self.get_name())
        return self.ida_sid

    # set existing IDA struc represented by this model
    def set_existing(self, sid: int):
        self.ida_sid = sid

    # get IDA tinfo_t representing our structure
    # the structure must have been created before
    def find_tinfo(self) -> Optional[idaapi.tinfo_t]:
        if self.ida_sid == idaapi.BADADDR:
            raise Exception(f"find_tinfo on {self.get_name()} failed, no IDA structure associated")
        return ida_utils.tinfo_from_stuc(self.ida_sid)

    # get a struc pointer tinfo
    def find_ptr_tinfo(self) -> Optional[idaapi.tinfo_t]:
        simple = self.find_tinfo()
        if simple is not None:
            simple.create_ptr(simple)
        return simple

    def get_name(self) -> str:
        if self.name is not None:
            return self.name
        return self.default_name()

    def set_name(self, name: str):
        self.name = name

    def default_name(self) -> str:
        return f"struc_0x{self.ea:x}"

    # define fields names
    def compute_names(self):
        taken = set()  # used names set, avoid conflicts
        for field in self.fields.values():
            field.set_name(taken)

    # comment associated to structure
    def get_comment(self) -> str:
        if not config.g_settings.debug:
            return None

        eas = set([(shift, root.ea) for shift, root in self.associated_root()])
        return "Root nodes:\n%s" % "\n".join(
            [("%s, shift: 0x%x" % (ida_utils.addr_friendly_name(ea), shift)) for shift, ea in eas]
        )

    # do we generate this structure in IDA
    def relevant(self) -> bool:
        return True

    def __eq__(self, other) -> bool:
        return isinstance(other, structure_t) and self.sid == other.sid

    def __hash__(self) -> int:
        return self.sid


# model of a vtable
class vtable_t(structure_t):
    def __init__(self, sid: int):
        super().__init__(sid)
        self.owning_class: Optional[Tuple[structure_t, int]] = None  # class owning this vtable, with associated offset

    def default_name(self) -> str:
        return f"loc_{self.ea:x}{idaapi.VTBL_SUFFIX}"

    def get_comment(self) -> str:
        out = (
            f"Vtable at 0x{self.ea:x}\nOwned by {self.owning_class[0].get_name()} at offset 0x{self.owning_class[1]:x}"
        )
        return out

    # find existing vtable structure from typed vtable
    def find_existing(self) -> int:
        self.ida_sid = existing.find_existing_vtable(self.ea)
        if self.ida_sid != idaapi.BADADDR:
            return self.ida_sid

        return super().find_existing()

    def set_class(self, owner: structure_t, offset: int):
        self.owning_class = (owner, offset)

    def get_class(self) -> Tuple[structure_t, int]:
        return self.owning_class

    # no need to build unlinked vtables
    def relevant(self) -> bool:
        return self.owning_class is not None


# empty structure model from associated entry
def empty_model_from_ep(entry: model.entry_t) -> structure_t:
    if isinstance(entry, model.vtbl_entry_t):
        return vtable_t(entry.struc_id)

    struc = structure_t(entry.struc_id)
    if isinstance(entry, model.ret_entry_t):  # known size structure
        struc.set_size(entry.size)

    return struc


# defines a structure that has been merged into another
# identify the new structure
class merge_t:
    def __init__(self, merge: structure_t):
        self.merge_id = merge.sid


# record of all structures to be built
class structure_record_t:
    def __init__(self, entries: model.entry_record_t):
        self.structures: list[Union[structure_t, merge_t]] = [None for _ in range(entries.structures_count())]

        # fill structures array
        for entry in entries.get_entries():
            if not entry.is_root():
                continue

            # make empty structure model from entry point
            if self.structures[entry.struc_id] is None:
                self.structures[entry.struc_id] = empty_model_from_ep(entry)

            # associate structure with its entries in the data flow
            self.structures[entry.struc_id].associate_root(entry, entry.struc_shift)

    # define a structure to have been merged into another
    def replace_by(self, struc: structure_t, merge: structure_t):
        self.structures[struc.sid] = merge_t(merge)

    def _get_structure(self, sid: int) -> Union[structure_t, merge_t]:
        return self.structures[sid]

    # get effective structure
    # if given structure has been merged, return merge result
    def get_structure(self, struc: structure_t) -> structure_t:
        st = self._get_structure(struc.sid)
        while isinstance(st, merge_t):
            st = self._get_structure(st.merge_id)
        return st

    def get_structures(self, cls: type = structure_t, include_discarded: bool = True) -> Iterator[structure_t]:
        for struc in self.structures:
            if isinstance(struc, cls) and (include_discarded or struc.relevant()):
                yield struc
