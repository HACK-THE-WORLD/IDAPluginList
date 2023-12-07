import argparse

import idaapi
import idautils
import idc


def report(output: str = ""):
    if len(output) == 0:
        print(g_prefix)
        return

    for i in output.splitlines():
        print("%s%s" % (g_prefix, i))


def dump_functions() -> dict:
    out = {"total": 0}

    for fea in idautils.Functions():
        # only print user defined function types
        if not idaapi.is_userti(fea):
            continue

        name = idaapi.print_type(fea, idaapi.PRTYPE_CPP)
        if name and len(name):
            report(name)
        else:
            report("VOID[0x%x]" % fea)

        out["total"] += 1

    return out


def get_xref_type(xref: int):
    func = idaapi.get_func(xref)
    if func is not None:
        name = "%s%s" % (
            idaapi.get_short_name(func.start_ea),
            "" if xref == func.start_ea else (" + 0x%x" % (xref - func.start_ea)),
        )
        return (name, 1)

    if idaapi.is_member_id(xref):
        return (idaapi.get_member_fullname(xref), 2)

    if idaapi.get_struc(xref) is not None:
        return (idaapi.get_struc_name(xref), 4)

    name = idaapi.get_short_name(xref)

    return (name, 8)


def dump_xrefs_to(ea: int, shift: str = "", mask: int = 0xFF) -> int:
    count = 0
    for xref in idautils.XrefsTo(ea):
        name, type = get_xref_type(xref.frm)
        if (type & mask) != 0:
            count += 1
            report("%sxref: 0x%x%s" % (shift, xref.frm, (" (%s)" % name) if name else ""))

    return count


def dump_structures() -> dict:
    out = {
        "total vtables": 0,
        "total structures": 0,
        "total members": 0,
        "typed members": 0,
        "xrefs on members": 0,
        "xrefs on structs": 0,
        "xrefs on vtables": 0,
    }

    # sort structures by name
    structures = list()
    for idx, sid, name in idautils.Structs():
        structures.append((name, sid))
    structures.sort()

    for name, sid in structures:
        struc = idaapi.get_struc(sid)

        # do not dump hidden structs
        if struc.props & idaapi.SF_HIDDEN:
            continue

        is_vtable = name.endswith("_vtbl")

        if is_vtable:
            out["total vtables"] += 1
        else:
            out["total structures"] += 1

        report("struc %s:" % name)
        report("\tprops: 0x%x" % struc.props)
        report("\tsize : 0x%x" % idaapi.get_struc_size(sid))
        xref_count = dump_xrefs_to(sid, "\t", 8)
        report("\tmembers: %d" % struc.memqty)

        if is_vtable:
            out["xrefs on vtables"] += xref_count
        else:
            out["xrefs on structs"] += xref_count

        for m in struc.members:
            out["total members"] += 1

            m_name = idaapi.get_member_name(m.id)
            m_size = idaapi.get_member_size(m)

            m_type = idaapi.tinfo_t()
            if idaapi.get_member_tinfo(m_type, m):
                m_type_str = str(m_type)
            else:
                m_type_str = None

            report("\t0x%x: %s" % (m.soff, m_name))
            report("\t\tsize: 0x%x" % m_size)
            if m_type_str:
                report("\t\ttype: %s" % m_type_str)
                out["typed members"] += 1

            out["xrefs on members"] += dump_xrefs_to(m.id, "\t\t", 9)

        report()

    return out


def dump_local_types() -> dict:
    out = {"total": 0}

    idati = idaapi.get_idati()

    count = idaapi.get_ordinal_qty(idati)
    if count == 0 or count == 0xFFFFFFFF:
        return

    # get all struct types
    types = list()
    for i in range(count):
        tinfo = idaapi.tinfo_t()
        if tinfo.get_numbered_type(idati, i) and tinfo.is_struct():
            types.append((i, tinfo))

    # sort by name
    types.sort(key=lambda k: str(k[1]))

    for ordinal, tinfo in types:
        # do not print types imported as structures
        name = str(tinfo)
        if idaapi.get_struc_id(name) != idaapi.BADADDR:
            continue

        out["total"] += 1

        flags = idaapi.PRTYPE_MULTI | idaapi.PRTYPE_CPP | idaapi.PRTYPE_DEF | idaapi.PRTYPE_TYPE
        report(idaapi.print_tinfo("", 0, 0, flags, tinfo, name, ""))
        report()

    return out


if __name__ == "__main__":
    global g_prefix

    parser = argparse.ArgumentParser()
    parser.add_argument("--prefix", type=str, default="")
    args = parser.parse_args(idc.ARGV[1:])

    g_prefix = args.prefix

    seq = (
        ("Functions", dump_functions),
        ("Local types", dump_local_types),
        ("Structures", dump_structures),
    )

    report()
    for name, fct in seq:
        report("##### %s #####" % name)
        ret = fct()

        report("\n##### Statistics for %s #####" % name)
        for key, val in ret.items():
            report("%s: %d" % (key, val))
        report()

    idc.qexit(0)
