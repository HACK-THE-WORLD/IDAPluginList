import argparse
import inspect
import os
import sys

import idaapi
import idc

# add symless dir to search path
symless_dir = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(inspect.getsourcefile(lambda: 0))), ".."))
sys.path.append(symless_dir)

import symless.allocators as allocators
import symless.model.entrypoints as entrypoints
import symless.model.model as model
import symless.utils.ida_utils as ida_utils

""" Debug script - Dump information about analyzed functions """

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--prefix", type=str, default="")
    args = parser.parse_args(idc.ARGV[1:])

    idaapi.auto_wait()

    config_path = os.path.abspath(os.path.join(symless_dir, "symless", "config", "imports.csv"))

    imports = allocators.get_allocators(config_path)
    if imports is None:
        print("%sNo allocators identified" % args.prefix)
        imports = list()

    # get initial entrypoints
    ctx = entrypoints.retrieve_entrypoints(imports)

    # build entries tree
    model.analyze_entrypoints(ctx)
    entries = ctx.get_entrypoints()
    allocs = ctx.get_allocators()

    # dump analyzed functions
    for fct in ctx.get_functions():
        fct_name = ida_utils.demangle_ea(fct.ea).split("(")[0]
        print("%s%s (0x%x), at least %d args" % (args.prefix, fct_name, fct.ea, fct.get_nargs()))

idc.qexit(0)
