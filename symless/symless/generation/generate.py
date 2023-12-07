import idaapi

import symless.allocators as allocators
import symless.existing as existing
import symless.model.entrypoints as entrypoints
import symless.symbols as symbols
from symless.generation import *

STRUC_DIR = "Symless"


# make symless structures directory
def make_structures_dir():
    if not ida_utils.can_create_folder():
        return

    root = idaapi.get_std_dirtree(idaapi.DIRTREE_STRUCTS)
    err = root.mkdir(STRUC_DIR)
    if err not in (idaapi.DTE_OK, idaapi.DTE_ALREADY_EXISTS):
        utils.g_logger.error(f'Could not create {STRUC_DIR} structures directory: "{root.errstr(err)}"')


# create an empty IDA structure used to contain given struc
def make_IDA_structure(struc: structure_t):
    if struc.ida_sid != idaapi.BADADDR:
        return

    name = struc.get_name()

    # check for existing struc
    ida_sid = struc.find_existing()
    if ida_sid != idaapi.BADADDR:
        utils.g_logger.info(f'Re-using existing structure for model "{name}"')
        return

    # create new structure
    struc.set_existing(idaapi.add_struc(-1, name, False))
    if struc.ida_sid == idaapi.BADADDR:
        utils.g_logger.error(f'Could not create empty structure "{name}"')

    elif ida_utils.can_create_folder():
        # move structure to symless dir
        root = idaapi.get_std_dirtree(idaapi.DIRTREE_STRUCTS)
        err = root.rename(name, f"{STRUC_DIR}/{name}")
        if err != idaapi.DTE_OK:
            utils.g_logger.warning(
                f'Could not move structure "{name}" into {STRUC_DIR} directory: "{root.errstr(err)}"'
            )


# do we decide to type IDA base we given entry data
def should_type_entry(entry: entrypoints.entry_t, ctx: entrypoints.context_t) -> bool:
    # root are always right
    if entry.is_root():
        return True

    shift, struc = entry.get_structure()

    # do not overwrite typing set by user on entry's operands
    for ea, n, _ in entry.get_operands():
        if existing.has_op_stroff(ea, n):
            return False

    # always type with vtbl, no matter its size
    if isinstance(struc, vtable_t):
        return True

    # arguments entries special case
    if isinstance(entry, entrypoints.arg_entry_t):
        # always type virtual functions
        fct = ctx.get_function(entry.ea)
        if fct.is_virtual():
            return True

        # avoid other shifted ptr arguments
        if shift != 0:
            return False

        # TODO: do not type when arg is already typed with different struc

    # do not type entries that do not represent a structure
    lower, upper = entry.get_boundaries()
    if lower == 0 and upper <= ida_utils.get_ptr_size():
        return False

    return True


# update given function's returned type with the given entry
def type_function_return(fct: entrypoints.function_t, entry: entrypoints.entry_t):
    # entry is not returned, exit
    if fct.get_ret() != entry.id:
        return

    shift, struc = entry.get_structure()

    # avoid prone to error shifted pointers
    if shift != 0:
        return

    func_tinfo, func_data = ida_utils.get_or_create_fct_type(fct.ea, fct.get_ida_cc())
    if not existing.can_type_be_replaced(func_data.rettype):
        return

    tinfo = struc.find_ptr_tinfo()
    func_data.rettype = tinfo

    if func_tinfo.create_func(func_data):
        idaapi.apply_tinfo(fct.ea, func_tinfo, idaapi.TINFO_DEFINITE)

        utils.g_logger.info(f"Typing return of fct_0x{fct.ea:x} with {tinfo}")


# update function's type with given arg entrypoint
def type_function_argument(fct: entrypoints.function_t, arg: entrypoints.entry_t):
    if not isinstance(arg, entrypoints.arg_entry_t):
        return

    idx = arg.index
    if idx >= fct.get_nargs():
        return

    func_tinfo, func_data = ida_utils.get_or_create_fct_type(fct.ea, fct.get_ida_cc())

    # do not replace existing (complex) type
    if idx < func_data.size() and not existing.can_type_be_replaced(func_data[idx].type):
        return

    shift, struc = arg.get_structure()
    ida_utils.set_function_argument(
        func_data,
        idx,
        struc.find_ptr_tinfo(),
        shift,
        struc.find_tinfo(),
        "this" if idx == 0 else None,
    )

    if not func_tinfo.create_func(func_data):
        utils.g_logger.error(f"Could not type arg_{idx} of fct_0x{fct.ea:x} with {arg.entry_id()}")
        return

    idaapi.apply_tinfo(fct.ea, func_tinfo, idaapi.TINFO_DEFINITE)

    utils.g_logger.info(f"Typing fct_0x{fct.ea:x} arg_{idx} with {struc.get_name()} shifted by 0x{shift:x}")


# Apply struc type on operand
def set_operand_type(ea: int, n: int, sid: int, shift: int):
    path = idaapi.tid_array(1)
    path[0] = sid
    idaapi.op_stroff(ea, n, path.cast(), 1, shift)


# type IDA base with data from given entrypoint
def type_entry(entry: entrypoints.entry_t, ctx: entrypoints.context_t):
    if not should_type_entry(entry, ctx):
        utils.g_logger.debug(f"Not typing database with {entry.entry_id()} data")
        return

    utils.g_logger.debug(f"Typing database with {entry.entry_id()} data")

    # make sure the associated structure exists in IDA
    shift, struc = entry.get_structure()
    if struc.ida_sid == idaapi.BADADDR:
        utils.g_logger.error(
            f'Structure "{struc.get_name()}" was not generated, preventing from typing {entry.entry_id()}'
        )
        return

    # type disassembly operands
    for ea, n, off in entry.get_operands():
        set_operand_type(ea, n, struc.ida_sid, shift + off)

    # type containing function
    fct_ea = entry.get_function()
    if fct_ea != idaapi.BADADDR:
        fct = ctx.get_function(fct_ea)

        # type function's arguments
        type_function_argument(fct, entry)

        # type function's return
        type_function_return(fct, entry)


# Set type & rename memory allocators if needed
def type_allocator(alloc: allocators.allocator_t, ctx: entrypoints.context_t):
    # give a default name
    if not symbols.has_relevant_name(alloc.ea):
        idaapi.set_name(alloc.ea, alloc.get_name())

    fct = ctx.get_function(alloc.ea)

    # avoid function pointer
    # TODO: be able to type them
    func_tinfo = idaapi.tinfo_t()
    idaapi.get_tinfo(func_tinfo, fct.ea)
    if func_tinfo.is_ptr():
        return

    # set function type
    func_tinfo, func_data = ida_utils.get_or_create_fct_type(fct.ea, fct.get_ida_cc())
    alloc.make_type(func_data)

    if func_tinfo.create_func(func_data):
        idaapi.apply_tinfo(fct.ea, func_tinfo, idaapi.TINFO_DEFINITE)

        utils.g_logger.info(f"Typing allocator_{fct.ea:x} ({alloc.get_name()})")


# does IDA struc with given sid have a comment
def has_struc_comment(sid: int) -> bool:
    return idaapi.get_struc_cmt(sid, False) is not None


# fill IDA structure with given model info
# does not overwrite fields of already existing IDA structure
def fill_IDA_structure(struc: structure_t):
    if struc.ida_sid == idaapi.BADADDR:
        utils.g_logger.error(f'Could not generate structure "{struc.get_name()}"')
        return

    ida_struc = idaapi.get_struc(struc.ida_sid)

    # remove padding fields
    existing.remove_padd_fields(ida_struc)

    # add fields
    for offset, field in struc.fields.items():
        err = idaapi.add_struc_member(
            ida_struc,
            field.get_name(),
            offset,
            existing.get_data_flags(field.size),
            None,
            field.size,
        )
        if err != idaapi.STRUC_ERROR_MEMBER_OK and err != idaapi.STRUC_ERROR_MEMBER_OFFSET:
            utils.g_logger.error(f"Could not add field_{offset:08x} to structure {struc.get_name()}, error: {err}")

        member = idaapi.get_member(ida_struc, offset)
        if member is None:
            continue

        # update field's type
        # TODO: do not overwrite existing field's type
        ftype = field.get_type()
        if ftype is not None:
            err = idaapi.set_member_tinfo(ida_struc, member, 0, ftype, idaapi.SET_MEMTI_COMPATIBLE)
            if err != idaapi.SMT_OK:
                utils.g_logger.error(
                    f'Could set type of field_{offset:08x} (in {struc.get_name()}) to "{ftype}", error: {err}'
                )

        # set field's comment
        # TODO: do not replace old comment
        comment = field.get_comment()
        if comment is not None:
            if not idaapi.set_member_cmt(member, comment, True):
                utils.g_logger.warning(
                    f'Could not set comment "{comment}" for member at off 0x{offset} of {struc.get_name()}'
                )

    # reset padding fields
    existing.add_padd_fields(ida_struc, struc.size)

    # set structure's comment
    comment = struc.get_comment()
    if not (has_struc_comment(ida_struc.id) or comment is None):
        if not idaapi.set_struc_cmt(ida_struc.id, comment, False):
            utils.g_logger.warning(f"Could not set comment for {struc.get_name()}")


# imports all structures defined into given record into IDA
def import_structures(record: structure_record_t):
    # prepare symless structures directory
    make_structures_dir()

    # create empty structures
    for struc in record.get_structures(include_discarded=False):
        make_IDA_structure(struc)

    # fill the structures
    for struc in record.get_structures(include_discarded=False):
        fill_IDA_structure(struc)

    # type vtables with vtables structures
    for vtbl in record.get_structures(cls=vtable_t, include_discarded=False):
        tinfo = vtbl.find_tinfo()
        if not idaapi.apply_tinfo(vtbl.ea, tinfo, idaapi.TINFO_DEFINITE):
            utils.g_logger.warning(f"Could not apply type {tinfo} to vtable 0x{vtbl.ea:x}")


# apply structures types to IDA base
def import_context(context: entrypoints.context_t):
    entries = context.get_entrypoints()

    # type entries
    for entry in entries.get_entries():
        type_entry(entry, context)

    # type allocators
    for allocator in context.get_allocators():
        type_allocator(allocator, context)
