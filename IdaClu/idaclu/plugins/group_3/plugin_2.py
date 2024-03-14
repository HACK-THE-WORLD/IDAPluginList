import collections
import json
import re
#
import idaapi
import idautils
#
from idaclu import ida_shims
from idaclu.qt_utils import i18n


SCRIPT_NAME = i18n('Pseudocode Size')
SCRIPT_TYPE = 'func'
SCRIPT_VIEW = 'tree'
SCRIPT_ARGS = []


def sort_nat(input_dict):
    def fun(k, v):
        return [k, int(v)]

    def cmp_key(t):
        return fun(*re.match(r'([a-zA-Z\: ]+)(\d+)', t[0]).groups())

    return collections.OrderedDict(sorted(input_dict.items(), key=cmp_key))

def get_psdo_list(func_ea):
    func_pseudocode = []
    decomp_str = ""
    try:
       decomp_str = idaapi.decompile(func_ea)
    except idaapi.DecompilationFailure:
       return []
    for line in str(decomp_str).split('\n'):
        if '//' in line:
            code = line.split('//')[0]
            if code != '':
                func_pseudocode.append(code.lstrip())
        else:
            if line != '':
                func_pseudocode.append(line.lstrip())
    return func_pseudocode
    
def get_psdo_body(func_ea):
    psdo_list = get_psdo_list(func_ea)
    return psdo_list[2:-1]

def get_data(func_gen=None, env_desc=None, plug_params=None):
    report = {
        'data': collections.defaultdict(list),
        'stat': collections.defaultdict(int)
    }

    for func_addr in func_gen():
        func_psdo_size = len(get_psdo_body(func_addr))
        key_name = "size: {}".format(func_psdo_size)
        report['data'][key_name].append(func_addr)
        report['stat'][key_name] += 1

    report['data'] = sort_nat(report['data'])
    report['stat'] = sort_nat(report['stat'])
    return report if __name__ == '__main__' else report['data']

def debug():
    data_obj = get_data(func_gen=idautils.Functions)
    ida_shims.msg(json.dumps(data_obj, indent=4))

if __name__ == '__main__':
    debug()
