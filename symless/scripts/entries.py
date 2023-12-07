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

""" Debug script - Get all entrypoints (structures creations) identified in one binary """

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

    e_str = str(entries)
    print("%sEntrypoints:" % args.prefix)
    for line in e_str.splitlines():
        print("%s%s" % (args.prefix, line))

    print(args.prefix)

    print("%sAllocators:" % args.prefix)
    for i in allocs:
        print("%s%s" % (args.prefix, i))

idc.qexit(0)
