import collections
import json
import re
#
import idaapi
import idautils
#
from idaclu import ida_shims
from idaclu.qt_utils import i18n
#
import helpers


SCRIPT_NAME = i18n('Uncommon Instruction Sequences')
SCRIPT_TYPE = 'func'
SCRIPT_VIEW = 'tree'
SCRIPT_ARGS = []


def sort_nat(input_dict):
    def fun(k, v):
        return [k, float(v)]

    def cmp_key(t):
        return fun(*re.match(r'([a-zA-Z/\: ]+)(\d\.\d+)', t[0]).groups())

    return collections.OrderedDict(sorted(input_dict.items(), key=cmp_key, reverse=True))

def get_data(func_gen=None, env_desc=None, plug_params=None):

    report = {
        'data': collections.defaultdict(list),
        'stat': collections.defaultdict(int)
    }

    for func_addr in func_gen():
        unique_score = helpers.calc_uncommon_instruction_sequences_score(func_addr)

        unique_key = "score: {}".format(round(unique_score, 2))
        
        report['data'][unique_key].append(func_addr)
        report['stat'][unique_key] += 1
        
    report['data'] = sort_nat(report['data'])
    report['stat'] = sort_nat(report['stat'])

    return report if __name__ == '__main__' else report['data']


def debug():
    data_obj = get_data(func_gen=idautils.Functions)
    ida_shims.msg(json.dumps(data_obj, indent=4))

if __name__ == '__main__':
    debug()
