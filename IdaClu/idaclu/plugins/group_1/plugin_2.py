import collections
import json
#
import idaapi
import idautils
#
from idaclu import ida_shims


SCRIPT_NAME = 'Xref Source'
SCRIPT_TYPE = 'func'
SCRIPT_VIEW = 'tree'
SCRIPT_ARGS = []


def get_func_item_eas(func_addr):
    for item_ea in list(idautils.FuncItems(func_addr)):
        if ida_shims.is_code(ida_shims.get_full_flags(func_addr)):
            yield item_ea

def is_func_leaf(func_addr):
    item_eas = list(get_func_item_eas(func_addr))
    for item_ea in item_eas:
        if ida_shims.ua_mnem(item_ea) == 'call':
            return False
    else:
        if ida_shims.ua_mnem(item_eas[-1]) == 'jmp':
            return False
        else:
            return True

def is_func_expl(func_addr):
    call_afacts = [
        'call sub_',
        'call _',
        'call ds:',
        'call nullsub_',
        'call loc_',
        'call off_',
        'call j_',
        'call ??',
        ';',
        'jmp',
        'jz short sub_'
    ]

    for item_addr in get_func_item_eas(func_addr):
        if ida_shims.ua_mnem(item_addr) == 'call':

            dasm_flag = idaapi.GENDSM_FORCE_CODE
            dasm_line = ida_shims.generate_disasm_line(item_addr, dasm_flag)
            dasm_norm = ' '.join(dasm_line.split())

            if (not any(dasm_norm.startswith(art) for art in call_afacts) and
                ' ; ' not in dasm_line):
                return False
    else:
        return True

def get_func_type_src(func_addr):
    if is_func_leaf(func_addr):
        return 'leaf'
    elif is_func_expl(func_addr):
        return 'expl'
    else:
        return 'impl'

def get_data(func_gen=None, env_desc=None, plug_params=None):
    report = {
        'data': collections.defaultdict(list),
        'stat': collections.defaultdict(int)
    }

    for func_addr in func_gen():
        func_type = get_func_type_src(func_addr)

        report['data'][func_type].append(func_addr)
        report['stat'][func_type] += 1

    return report if __name__ == '__main__' else report['data']

def debug():
    data_obj = get_data(func_gen=idautils.Functions)
    ida_shims.msg(json.dumps(data_obj, indent=4))

if __name__ == '__main__':
    debug()
