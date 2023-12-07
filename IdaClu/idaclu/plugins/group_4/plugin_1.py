import bisect
import collections
import json
import os

import idautils
import idaapi
from idaclu import ida_shims
import drcov


SCRIPT_NAME = 'Covered Functions'
SCRIPT_TYPE = 'func'
SCRIPT_VIEW = 'tree'
SCRIPT_ARGS = [('filePath', 'file_path', 'input the file path')]


def find_function(block_start, function_ranges):
    index = bisect.bisect_right(function_ranges, (block_start, block_start))

    if index > 0 and block_start <= function_ranges[index - 1][1]:
        return function_ranges[index - 1]
    return None


def get_data(func_gen=None, env_desc=None, plug_params=None):
    REPORT = {
        'data': {},
        'stat': {},
        'tree': [
            {'unique_id': 1, 'parent_id': 0, 'Function': '', 'VA': ' ', 'Size': ' '}
        ]
    }
    raw_data = {}
    unseen_functions = []
    seen_functions = []

    function_ranges = []
    for func_addr in func_gen():
        func_name = ida_shims.get_func_name(func_addr)
        func_desc = idaapi.get_func(func_addr)
        func_size = ida_shims.calc_func_size(func_desc)
        function_ranges.append((func_addr, func_addr + func_size))
        unseen_functions.append(func_addr)

    x = None
    file_path = plug_params['file_path']
    try:
        x = drcov.DrcovData(file_path)
    except IOError:
        ida_shims.msg("ERROR: Cannot open coverage file: {}".format(file_path))
        return REPORT['data']

    coverage_blocks = x.get_offset_blocks(env_desc.ida_module)
    imagebase = idaapi.get_imagebase()

    for bb in coverage_blocks:
        block_start = imagebase + bb[0]
        func_start = find_function(block_start, function_ranges)
        if func_start:
            if not func_start[0] in seen_functions:
                seen_functions.append(func_start[0])

    group_name = 'covered'
    if not group_name in raw_data:
        raw_data[group_name] = []
        REPORT['stat'][group_name] = 0

    for sf in seen_functions:
        raw_data[group_name].append(sf)
        REPORT['stat'][group_name] += 1

    unseen = list(set(unseen_functions) - set(seen_functions))
    group_name = 'uncovered'
    if not group_name in raw_data:
        raw_data[group_name] = []
        REPORT['stat'][group_name] = 0

    for uf in unseen:
        raw_data[group_name].append(uf)
        REPORT['stat'][group_name] += 1


    REPORT['data'] = collections.OrderedDict(sorted(raw_data.items()))
    return REPORT['data']


def debug():
    env_desc = lambda: None
    env_desc.ida_module = os.path.basename(ida_shims.get_input_file_path())

    log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'drcov.proc.log')
    plug_params = { 'file_path': log_path }

    data_obj = get_data(func_gen=idautils.Functions, env_desc=env_desc, plug_params=plug_params)
    ida_shims.msg(json.dumps(data_obj, indent=4))

if __name__ == '__main__':
    debug()
