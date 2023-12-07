import idaapi
import idc

import symless.utils.ida_utils as ida_utils


# set existing structure padding fields to undefined
def remove_padd_fields(struc: idaapi.struc_t):
    offset = idaapi.get_struc_first_offset(struc)
    size = idaapi.get_struc_size(struc)

    while offset < size and offset != idaapi.BADADDR:
        member = idaapi.get_member(struc, offset)

        if member is not None:  # avoid undefined fields
            name = idaapi.get_member_name(member.id)
            if name.startswith("padd_"):
                idaapi.del_struc_member(struc, offset)

        offset = idaapi.get_struc_next_offset(struc, offset)


# get flags giving the right type for given struct member size
def get_data_flags(size: int):
    flags = idaapi.FF_DATA
    if size < 32:  # avoid ymmword type, raises warnings
        flags |= idaapi.get_flags_by_size(size)
    return flags


# Add padding fields to structure
def add_padd_fields(struc: idaapi.struc_t, size: int):
    current, next = 0, 0
    struc_size = idaapi.get_struc_size(struc.id)

    while next != struc_size:
        if idc.get_member_id(struc.id, next) != -1:
            if next - current > 0:
                msize = next - current
                idaapi.add_struc_member(struc, f"padd__{current:08x}", current, get_data_flags(msize), None, msize)
            next = idc.get_next_offset(struc.id, next)
            current = next
        else:
            next = idc.get_next_offset(struc.id, next)

    if struc_size < size:
        msize = size - struc_size
        idaapi.add_struc_member(struc, f"padd__{struc_size:08x}", struc_size, get_data_flags(msize), None, msize)


# was a structured assigned to an assembly operand
def has_op_stroff(ea: int, n: int):
    delta, path = idaapi.sval_pointer(), idaapi.tid_array(idaapi.MAXSTRUCPATH)
    return idaapi.get_stroff_path(path.cast(), delta.cast(), ea, n) > 0


# find existing vtable structure from vtable ea
def find_existing_vtable(ea: int) -> int:
    tinfo = idaapi.tinfo_t()
    if not idaapi.get_tinfo(tinfo, ea):
        return idaapi.BADADDR
    return ida_utils.struc_from_tinfo(tinfo)


# can we replace existing type with a struct type
# only if type is a scalar or a scalar ptr
def can_type_be_replaced(tinfo: idaapi.tinfo_t) -> bool:
    ptr_data = idaapi.ptr_type_data_t()
    if tinfo.get_ptr_details(ptr_data):
        tinfo = ptr_data.obj_type
    return tinfo.is_scalar() and not tinfo.is_enum()
