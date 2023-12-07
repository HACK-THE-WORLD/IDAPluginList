import inspect
import os
import sys

import idc

# add symless dir to search path
symless_dir = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(inspect.getsourcefile(lambda: 0))), ".."))
sys.path.append(symless_dir)

import symless.utils.ida_utils as ida_utils

""" Debug script - Scans binary for vtables """

if __name__ == "__main__":
    stats = [0, 0]

    for vtbl_ref, vtbl_addr in ida_utils.get_all_vtables():
        name = ida_utils.demangle_ea(vtbl_addr)
        size = ida_utils.vtable_size(vtbl_addr)
        print("%x ref for %x (size: 0x%x) -> %s" % (vtbl_ref, vtbl_addr, size, name))

        stats[1] += 1
        stats[0] += 1 if "vftable" in name else 0

    print("Total: %d, corrects (for sure): %d" % (stats[1], stats[0]))

idc.qexit(0)
