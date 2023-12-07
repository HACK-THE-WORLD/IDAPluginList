import collections
import json
import re
#
import idaapi
import idautils
#
from idaclu import ida_shims
from idaclu import ida_utils


SCRIPT_NAME = 'Distinct Prefixes (IdaClu)'
SCRIPT_TYPE = 'func'
SCRIPT_VIEW = 'tree'
SCRIPT_ARGS = []


def get_data(func_gen=None, env_desc=None, plug_params=None):
    report = {
        'data': collections.defaultdict(list),
        'stat': collections.defaultdict(int)
    }

    sep_char = '%'
    for func_addr in func_gen():
        func_name = ida_shims.get_func_name(func_addr)
        prefs = set()

        if sep_char in func_name:
            func_prefs = ida_utils.get_func_prefs(func_name, False)
            prefs.update(func_prefs)
        for pfx in list(prefs):
            report['data'][pfx].append(func_addr)
            report['stat'][pfx] += 1

    return report if __name__ == '__main__' else report['data']

def debug():
    data_obj = get_data(func_gen=idautils.Functions)
    ida_shims.msg(json.dumps(data_obj, indent=4))

if __name__ == '__main__':
    debug()
