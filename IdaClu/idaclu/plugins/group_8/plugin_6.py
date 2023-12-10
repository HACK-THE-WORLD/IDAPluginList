import collections
import json
import re
#
import idaapi
import idautils
#
from idaclu import ida_shims
#
import helpers


SCRIPT_NAME = 'XOR Const Decryption Loops'
SCRIPT_TYPE = 'func'
SCRIPT_VIEW = 'tree'
SCRIPT_ARGS = []


def get_data(func_gen=None, env_desc=None, plug_params=None):

    report = {
        'data': collections.defaultdict(list),
        'stat': collections.defaultdict(int)
    }

    for func_addr in func_gen():
        is_xor = helpers.contains_xor_decryption_loop(func_addr)
        if is_xor:
            report['data']['xor'].append(func_addr)
            report['stat']['xor'] += 1

    return report if __name__ == '__main__' else report['data']


def debug():
    data_obj = get_data(func_gen=idautils.Functions)
    ida_shims.msg(json.dumps(data_obj, indent=4))

if __name__ == '__main__':
    debug()
