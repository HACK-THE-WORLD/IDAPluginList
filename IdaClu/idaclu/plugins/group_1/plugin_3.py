import collections
import json
import re
#
import idaapi
import idautils
#
from idaclu import ida_shims
from idaclu.qt_utils import i18n


SCRIPT_NAME = i18n('Xref Destination')
SCRIPT_TYPE = 'func'
SCRIPT_VIEW = 'tree'
SCRIPT_ARGS = []

def is_fname_main(func_name):
    is_main = func_name.startswith('_') and 'main' in func_name.lower()
    return is_main

def is_func_lib(func_addr):
    func_name = ida_shims.get_func_name(func_addr)
    is_dummy = func_name.startswith('sub_')
    is_main = is_fname_main(func_name)
    func_flags = ida_shims.get_func_flags(func_addr)
    is_lib_flag = func_flags & idaapi.FUNC_LIB
    return is_lib_flag and not is_dummy and not is_main

def is_func_thunk(func_addr):
    func_flags = ida_shims.get_func_flags(func_addr)
    return func_flags & idaapi.FUNC_THUNK

def is_func_imp(func_addr):
    dasm_line = ida_shims.generate_disasm_line(func_addr, idaapi.GENDSM_FORCE_CODE)
    dasm_norm = ' '.join(dasm_line.split())
    return dasm_norm.startswith('jmp ds:__imp_')

def is_lib(func_addr):
    func_name = ida_shims.get_func_name(func_addr)
    if (is_func_lib(func_addr) or
        is_fname_lib(func_name, True) or
        ida_shims.get_segm_name(func_addr) == 'extern'):
        return True
    else:
        return False

def is_fname_lib(func_name, is_main=True):
    exclude_funcs = []
    if is_main == True:
        exclude_funcs.extend(['_main', '_wmain', '_WinMain@16'])

    if (not func_name in exclude_funcs) and \
        (
            func_name.startswith('_') or
            func_name.startswith('?') or
            func_name.startswith('unknown_libname_') or
            func_name.startswith('@_') or
            func_name.startswith('j_@_')
        ):
        return True
    else:
        return False

def is_fname_payload(func_name):
    lib_payload = [
        "`anonymous namespace'",
        "??1exception@boost@@MAE@XZ",
        "___std_parallel_algorithms_hw_threads@0",
        "?try_lock_for@stl_critical_section_concrt@details@Concurrency@@UAE_NI@Z",
        "?source_line@dbg_eng_data@?A0xbc047679@@QAEIQBX@Z"
    ]
    return any(func_name.startswith(x) for x in lib_payload)

def get_lib_prefixes():
    lib_prefix = [
        'lib_explicit_',
        'lib_implicit_',
        'j_lib_explicit_',
        'j_lib_implicit_'
    ]
    return lib_prefix

def is_fname_prefix(func_name):
    return any(func_name.startswith(p) for p in get_lib_prefixes())

def get_xref_addrs(func_addr):
    for xref in idautils.XrefsTo(func_addr):
        yield xref.frm

def get_cref_addrs(func_addr):
    for cref in idautils.CodeRefsTo(func_addr, 1):
        yield cref

def get_func_types_dst(func_addr):
    func_name = ida_shims.get_func_name(func_addr)
    func_type_dst = []

    for xref_addr in get_xref_addrs(func_addr):
        if ida_shims.is_code(ida_shims.get_full_flags(xref_addr)):
            xref_desc = idaapi.get_func(xref_addr)
            xref_name = ida_shims.get_func_name(xref_addr)

            if is_lib(xref_addr) and not is_fname_payload(xref_name):
                func_type_dst.append('lib_explicit')
            elif is_fname_prefix(xref_name):
                func_type_dst.append('lib_implicit')
            else:
                func_type_dst.append('payload')
        else:
            if ida_shims.get_segm_name(xref_addr) in ['.rdata', '.data']:
                func_type_dst.append('vftable')
            else:
                func_type_dst.append('unknown')

    return func_type_dst

def cleanup_lib_funcs(func_gen):
    for func_addr in func_gen():
        func_name = ida_shims.get_func_name(func_addr)
        if is_fname_prefix(func_name):
            lib_prefix = get_lib_prefixes()
            func_name = re.sub("|".join(lib_prefix), "", func_name)
            ida_shims.set_name(func_addr, func_name, idaapi.SN_NOWARN)

def discover_lib_funcs(func_gen):
    pass_count = 2

    for i in range(pass_count):
        for func_addr in func_gen():
            prefix = None
            func_name = ida_shims.get_func_name(func_addr)
            if is_fname_prefix(func_name):
                continue

            if is_lib(func_addr) or is_func_imp(func_addr) or is_fname_main(func_name):
                continue

            for xref_addr in get_cref_addrs(func_addr):
                xref_name = ida_shims.get_func_name(xref_addr)

                if is_fname_payload(xref_name):
                    continue

                if is_func_lib(xref_addr) or is_fname_lib(xref_name, True):
                    prefix = 'lib_explicit'
                    break
                elif any(xref_name.startswith(p) for p in get_lib_prefixes()):
                    prefix = 'lib_implicit'
                    break

            if prefix:
                ida_shims.set_name(func_addr, '{}_{}'.format(prefix, func_name), idaapi.SN_CHECK)

def get_data(func_gen=None, env_desc=None, plug_params=None):
    report = {
        'data': collections.defaultdict(list),
        'stat': collections.defaultdict(int)
    }

    cleanup_lib_funcs(func_gen)
    discover_lib_funcs(func_gen)

    for func_addr in func_gen():
        func_name = ida_shims.get_func_name(func_addr)
        func_types_dst = []

        lib_prefix = get_lib_prefixes()
        func_name = re.sub("|".join(lib_prefix), "", func_name)
        if is_lib(func_addr) or is_func_imp(func_addr):
            continue

        func_types_dst = get_func_types_dst(func_addr)
        # unique types only
        func_types_dst = list(set(func_types_dst))

        func_type = None
        if len(func_types_dst) == 1:
            func_type = func_types_dst[0]
        else:

            if 'lib_explicit' in func_types_dst:
                func_type = 'lib_explicit'
            elif 'lib_implicit' in func_types_dst:
                func_type = 'lib_implicit'
            elif 'vftable' in func_types_dst:
                func_type = 'vftable'
            else:
                func_type = 'mix'

        report['data'][func_type].append(func_addr)
        report['stat'][func_type] += 1

    cleanup_lib_funcs(func_gen)
    return report if __name__ == '__main__' else report['data']

def debug():
    data_obj = get_data(func_gen=idautils.Functions)
    ida_shims.msg(json.dumps(data_obj, indent=4))

if __name__ == '__main__':
    debug()
