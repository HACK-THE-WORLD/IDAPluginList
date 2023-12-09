import collections
import json
import os
import re
#
import yara
#
import idaapi
import idautils
#
from idaclu import ida_shims


SCRIPT_NAME = 'Rule Match'
SCRIPT_TYPE = 'func'
SCRIPT_VIEW = 'tree'
SCRIPT_ARGS = [('filePath', 'file_path', 'path to folder with .yar files')]


def get_func_bytes(func_addr):
    func_bytes = b''
    for beg, end in idautils.Chunks(func_addr):
        fb = ida_shims.get_bytes(beg, end-beg)
        func_bytes += fb
    return func_bytes
    
def order_item_len(input_dict):
    def get_len(val):
        fs = val[1]
        if isinstance(fs, int):
            return fs
        elif isinstance(fs, list):
            return len(fs)

    return collections.OrderedDict(
        sorted(input_dict.items(), key=get_len, reverse=True)
    )

def get_data(func_gen=None, env_desc=None, plug_params=None):
    report = {
        'data': collections.defaultdict(list),
        'stat': collections.defaultdict(int)
    }

    dist_path = plug_params['file_path']
    yar_paths = [
        os.path.join(dist_path, f) 
        for f in os.listdir(dist_path) 
        if os.path.isfile(os.path.join(dist_path, f)) and f.endswith('.yar')
    ]
    yara_rules = {}

    for p in yar_paths:
        try:
            n = os.path.basename(p)
            yara_rules[n] = yara.compile(filepath=p)
        except yara.Error as e:
            ida_shims.msg("Error compiling rule '{}': {}".format(n, e))

    for func_addr in func_gen():
        func_data = get_func_bytes(func_addr)
        for _, rule_data in yara_rules.items():
            match = rule_data.match(data=func_data)
            for rule_name in match:
                report['data'][rule_name].append(func_addr)
                report['stat'][rule_name] += 1

    report['data'] = order_item_len(report['data'])
    report['stat'] = order_item_len(report['stat'])

    return report if __name__ == '__main__' else report['data']

def debug():
    data_obj = get_data(func_gen=idautils.Functions)
    ida_shims.msg(json.dumps(data_obj, indent=4))

if __name__ == '__main__':
    debug()
