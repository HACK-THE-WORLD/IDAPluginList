import inspect
import os
import re
import sys

import idaapi
import idc

# add symless dir to search path
symless_dir = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(inspect.getsourcefile(lambda: 0))), ".."))
sys.path.append(symless_dir)

import symless.model.entrypoints as entrypoints
import symless.utils.ida_utils as ida_utils

re_ctors = re.compile(r"\b((?:[\w_]+::)*)([\S ]+)::(~?)\2(?:\(|$)")


""" Debug script - Find ctors/dtors in binary """

if __name__ == "__main__":
    # wait for autoanalysis, we'll need its results
    idaapi.auto_wait()

    families = entrypoints.get_ctors()

    i = 0
    for vtbl in families:
        print("Family %x:" % vtbl)

        for ctor in families[vtbl]:
            name = ida_utils.demangle_ea(ctor)

            match = re_ctors.match(name)
            if match is None:
                if "vector deleting destructor" in name:
                    typ = "[V-DESTRUCTOR]"
                elif "scalar deleting destructor" in name:
                    typ = "[S-DESTRUCTOR]"
                else:
                    typ = "[UNKNOWN]"
            elif len(match.group(3)):
                typ = "[DESTRUCTOR]"
            else:
                typ = "[CONSTRUCTOR]"

            print("  %s %x -> %s" % (typ, ctor, name))
        print()

        i += 1

idc.qexit(0)
