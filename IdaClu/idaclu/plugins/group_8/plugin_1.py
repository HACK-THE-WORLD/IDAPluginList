import collections
import json
import math
#
import idaapi
import idautils
#
from idaclu import ida_shims
#
import helpers


SCRIPT_NAME = 'Flattened Functions'
SCRIPT_TYPE = 'func'
SCRIPT_VIEW = 'tree'
SCRIPT_ARGS = []


def get_data(func_gen=None, env_desc=None, plug_params=None):

    report = {
        'data': collections.defaultdict(list),
        'stat': collections.defaultdict(int)
    }

    flattened_funcs = []
    func_count = 0

    for func_addr in func_gen():
        func_score = helpers.calc_flattening_score(func_addr)
        flattened_funcs.append((func_addr, func_score))
        func_count += 1

    flattened_funcs = sorted(flattened_funcs, key=lambda x: x[1])

    bound = max(min(math.ceil(((func_count * 10) / 100)), 1000), 10)

    for func_addr, func_score in list(reversed(flattened_funcs))[:bound]:
        score_fmt = str(round(func_score, 2))
        report['data'][score_fmt].append(func_addr)
        report['stat'][score_fmt] += 1

    return report if __name__ == '__main__' else report['data']

def debug():
    data_obj = get_data(func_gen=idautils.Functions)
    ida_shims.msg(json.dumps(data_obj, indent=4))

if __name__ == '__main__':
    debug()
