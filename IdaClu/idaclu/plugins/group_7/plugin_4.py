import collections
import json
import re
#
import idaapi
import idautils
#
from idaclu import ida_shims
from idaclu import ida_utils
from idaclu.qt_utils import i18n


SCRIPT_NAME = i18n('Distinct Prefixes')
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

def get_data(func_gen=None, env_desc=None, plug_params=None):
    report = {
        'data': collections.defaultdict(list),
        'stat': collections.defaultdict(int)
    }

    for func_addr in func_gen():
        func_name = ida_shims.get_func_name(func_addr)
        prefs = set()

        func_prefs = ida_utils.get_func_prefs(func_name, False)
        prefs.update(func_prefs)
        for pfx in list(prefs):
            report['data'][pfx].append(func_addr)
            report['stat'][pfx] += 1

    report['data'] = order_item_len(report['data'])
    report['stat'] = order_item_len(report['stat'])
    return report if __name__ == '__main__' else report['data']

def debug():
    data_obj = get_data(func_gen=idautils.Functions)
    ida_shims.msg(json.dumps(data_obj, indent=4))

if __name__ == '__main__':
    debug()
