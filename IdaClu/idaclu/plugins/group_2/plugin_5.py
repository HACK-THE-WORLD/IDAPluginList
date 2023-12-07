import collections
import json
#
import idaapi
import idautils
#
from idaclu import ida_shims


SCRIPT_NAME = 'API Usage Analysis'
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

def get_idata():
        imports = {}
        module = ""

        def callback(ea, name, ordinal):
            imports[module].append((ea, name, ordinal))
            return True

        nimps = idaapi.get_import_module_qty()
        for i in range(0, nimps):
            module = idaapi.get_import_module_name(i)
            imports[module] = []
            idaapi.enum_import_names(i, callback)

        for mod in imports:
            for addr, name, ordi in imports[mod]:
                yield addr, mod, name, ordi


def get_data(progress_callback=None, env_desc=None, plug_params=None):
    report = {
        'data': collections.defaultdict(list),
        'stat': collections.defaultdict(int)
    }

    imps = list(get_idata())
    imps_count = len(imps)

    for i, (addr, module, name, ordi) in enumerate(imps):
        for xref in idautils.XrefsTo(addr):
            xref_addr = xref.frm
            func_desc = idaapi.get_func(xref_addr)

            if func_desc:
                key_name = "{}_{}".format(module, name)
                report['data'][key_name].append(ida_shims.start_ea(func_desc))
                report['stat'][key_name] += 1

        if progress_callback:
            progress_callback(i, imps_count)

    report['data'] = order_item_len(report['data'])
    report['stat'] = order_item_len(report['stat'])

    return report if __name__ == '__main__' else report['data']

def debug():
    data_obj = get_data()
    ida_shims.msg(json.dumps(data_obj, indent=4))

if __name__ == '__main__':
    debug()
