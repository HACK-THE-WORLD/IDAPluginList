import collections
import json
#
import idaapi
import idautils
#
from idaclu import ida_shims
from idaclu.qt_utils import i18n


SCRIPT_NAME = i18n('Lib Usage Analysis')
SCRIPT_TYPE = 'func'
SCRIPT_VIEW = 'tree'
SCRIPT_ARGS = []


def order_item_len(input_dict):
    def get_len(val):
        fs = val[1]
        if isinstance(fs, int):
            return fs
        elif isinstance(fs, list):
            return len(fs)

    return collections.OrderedDict(sorted(input_dict.items(), key=get_len, reverse=True))

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

def get_data(func_gen=None, env_desc=None, plug_params=None):
    report = {
        'data': collections.defaultdict(list),
        'stat': collections.defaultdict(int)
    }

    for func_addr in func_gen():
        if is_func_lib(func_addr):
            func_name = ida_shims.get_func_name(func_addr)
            xrefs = idautils.XrefsTo(func_addr)
            for xref in xrefs:
                xref_addr = xref.frm
                xref_desc = idaapi.get_func(xref_addr)

                if xref_desc:
                    report['data'][func_name].append(ida_shims.start_ea(xref_desc))
                    report['stat'][func_name] += 1

    report['data'] = order_item_len(report['data'])
    report['stat'] = order_item_len(report['stat'])

    return report if __name__ == '__main__' else report['data']

def debug():
    data_obj = get_data(func_gen=idautils.Functions)
    ida_shims.msg(json.dumps(data_obj, indent=4))

if __name__ == '__main__':
    debug()
