import time

import idaapi

import symless.allocators as allocators
import symless.config as config
import symless.cpustate.arch as arch
import symless.generation.generate as generate
import symless.generation.structures as structures
import symless.model.entrypoints as entrypoints
import symless.model.model as model
import symless.utils.utils as utils


def start_analysis(config_path):
    # check binary type
    if not arch.is_arch_supported():
        utils.g_logger.error("Unsupported arch (%s) or filetype" % arch.get_proc_name())
        return

    # rebase if required
    if config.g_settings.rebase_db:
        err = idaapi.rebase_program(-idaapi.get_imagebase(), idaapi.MSF_FIXONCE)
        if err != idaapi.MOVE_SEGM_OK:
            utils.g_logger.error(f"Unable to rebase program: {err}")

    # initial ida autoanalysis
    start = time.time()
    idaapi.auto_wait()
    utils.print_delay("Initial IDA autoanalysis", start, time.time())

    # retrieve allocators
    imports = allocators.get_allocators(config_path)
    if imports is None:
        utils.g_logger.error("No allocators identified")
        imports = list()

    # retrieve first entrypoints
    start = time.time()
    ctx = entrypoints.retrieve_entrypoints(imports)
    utils.print_delay("Initial entrypoints retrieved", start, time.time())

    # build entrypoints graph
    start = time.time()
    model.analyze_entrypoints(ctx)
    utils.print_delay("Entrypoints graph built", start, time.time())

    # structure generation
    start = time.time()
    strucs = structures.define_structures(ctx)
    utils.print_delay("Structures defined", start, time.time())

    # structure generation
    start = time.time()
    generate.import_structures(strucs)
    generate.import_context(ctx)
    utils.print_delay("IDA database typed", start, time.time())

    # finalize operations
    start = time.time()
    idaapi.auto_wait()
    utils.print_delay("Final IDA autoanalysis", start, time.time())
