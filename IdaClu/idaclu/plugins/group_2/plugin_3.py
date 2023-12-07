import collections
import json
#
import idaapi
import idautils
#
from idaclu import ida_shims


SCRIPT_NAME = 'Global Variable Analysis'
SCRIPT_TYPE = 'custom'
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

def get_global_type(name_addr):
    flags = ida_shims.get_full_flags(name_addr)
    types = [
        'dword',
        'strlit',
        'char0',
        'byte',
        'word',
        'unknown',
        'struct',
        'float',
        'double',
        'enum0',
        'qword',
        'off0'
    ]
    for dt in types:
        is_data_type = getattr(ida_shims, 'is_{}'.format(dt))
        if is_data_type(flags):
            return dt
    return None

def get_data(progress_callback=None, env_desc=None, plug_params=None):
    report = {
        'data': collections.defaultdict(list),
        'stat': collections.defaultdict(int)
    }

    names = list(idautils.Names())
    names_count = len(names)

    for i, (name_addr, name_line) in enumerate(names):
        g_type = get_global_type(name_addr)
        if g_type:
            for xref in idautils.XrefsTo(name_addr):
                xref_addr = xref.frm
                func_desc = idaapi.get_func(xref_addr)
                if func_desc:
                    name = "{} / {}".format(g_type, name_line)
                    func_addr = ida_shims.start_ea(func_desc)
                    if not func_addr in report['data'][name]:
                        report['data'][name].append(func_addr)
                        report['stat'][name] += 1

        if progress_callback:
            progress_callback(i, names_count)

    report['data'] = order_item_len(report['data'])
    report['stat'] = order_item_len(report['stat'])

    return report if __name__ == '__main__' else report['data']

def debug():
    data_obj = get_data()
    ida_shims.msg(json.dumps(data_obj, indent=4))

if __name__ == '__main__':
    debug()
