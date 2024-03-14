import collections
import json
#
import idaapi
import idautils
import idc
#
from idaclu import ida_shims
from idaclu.qt_utils import i18n


SCRIPT_NAME = i18n('String Refs')
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

def get_data(progress_callback=None, env_desc=None, plug_params=None):
    report = {
        'data': collections.defaultdict(list),
        'stat': collections.defaultdict(int)
    }

    strs = list(idautils.Strings())
    strs_count = len(strs)

    for i, tstr in enumerate(strs):
        str_raw = ida_shims.get_strlit_contents(tstr)
        str_dec = str_raw.decode('utf-8', errors='replace').encode('ascii', errors='replace')

        for xref in idautils.XrefsTo(tstr.ea):
            xref_addr = xref.frm
            func_desc = idaapi.get_func(xref_addr)

            if func_desc:
                report['data'][str_dec].append(ida_shims.start_ea(func_desc))
                report['stat'][str_dec] += 1

        if progress_callback:
            progress_callback(i, strs_count)

    report['data'] = order_item_len(report['data'])
    report['stat'] = order_item_len(report['stat'])

    return report if __name__ == '__main__' else report['data']

def debug():
    data_obj = get_data()
    ida_shims.msg(json.dumps(data_obj, indent=4))

if __name__ == '__main__':
    debug()
