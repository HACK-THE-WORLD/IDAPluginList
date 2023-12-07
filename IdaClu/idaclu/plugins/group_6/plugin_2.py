import collections
import json
import re
#
import idautils
import idaapi
#
from idaclu import ida_shims


SCRIPT_NAME = 'Implicit Calls'
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

def remove_casts(call_str):
    call_res = call_str
    for m in re.finditer('\(\*(\([a-zA-Z0-9_\s\*\,\.\(\)]+\)\))\(', call_res):
        call_res = call_res.replace(m.group(1), '')
    call_res = re.sub(r"\(_.*\*\)", "", call_res)
    return call_res

def get_data(func_gen=None, env_desc=None, plug_params=None):

    report = {
        'data': collections.defaultdict(list),
        'stat': collections.defaultdict(int)
    }

    for func_addr in func_gen():
        caller_name = idaapi.get_func_name(func_addr)
        caller_psdo = get_psdo_body(func_addr)

        psdo_size = len(caller_psdo)

        for i in range(psdo_size):
            psdo_line = caller_psdo[i]
            is_func_matched = re.match('(\(\*.*[A-Za-z0-9_]+\s\+\s[A-Za-z0-9_\s\*\)\+]+\)\))\(', psdo_line)
            if is_func_matched:
                call_raw = is_func_matched.group(1)
                call_fmt = remove_casts(call_raw)

                func_comm = psdo_line
                while ';' not in func_comm and i + 1 < psdo_size:
                    i += 1
                    if func_comm[-1] == ',':
                        func_comm += ' '
                    func_comm += caller_psdo[i]

                report['data'][call_fmt].append((func_addr, func_comm))
                report['stat'][call_fmt] += 1

    report['data'] = order_item_len(report['data'])
    report['stat'] = order_item_len(report['stat'])

    return report if __name__ == '__main__' else report['data']

def debug():
    data_obj = get_data(func_gen=idautils.Functions)
    ida_shims.msg(json.dumps(data_obj, indent=4))

if __name__ == '__main__':
    debug()
