import collections
import json
import re
#
import idaapi
import idautils
import ida_dirtree
#
from idaclu import ida_shims


SCRIPT_NAME = 'Distinct Folders'
SCRIPT_TYPE = 'func'
SCRIPT_VIEW = 'tree'
SCRIPT_ARGS = []


def get_dirs(root_dir):
    func_dir = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_FUNCS)
    ite = ida_dirtree.dirtree_iterator_t()

    s_folders = [root_dir]
    u_folders = [root_dir]

    while len(s_folders):
        curr_path = s_folders.pop()
        func_dir.chdir(curr_path)
        status = func_dir.findfirst(ite, "*")

        while status:
            entry_name = func_dir.get_entry_name(func_dir.resolve_cursor(ite.cursor))
            if func_dir.isdir(func_dir.get_abspath(ite.cursor)):
                current_dir_new = '{}/{}'.format('' if curr_path == '/' else curr_path, entry_name)
                s_folders.append(current_dir_new)
                if not current_dir_new in u_folders:
                    u_folders.append(current_dir_new)
            status = func_dir.findnext(ite)

    return u_folders

def get_dir_funcs(folders):
    func_dir = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_FUNCS)
    ite = ida_dirtree.dirtree_iterator_t()
    idx = 0

    funcs = {}
    while idx < len(folders):
        curr_path = folders[idx]
        func_dir.chdir(curr_path)
        status = func_dir.findfirst(ite, "*")

        while status:
            entry_name = func_dir.get_entry_name(func_dir.resolve_cursor(ite.cursor))
            func_addr = ida_shims.get_name_ea(0, entry_name)
            if func_dir.isfile(func_dir.get_abspath(ite.cursor)):
                if curr_path != '/':
                    funcs[func_addr] = curr_path
            status = func_dir.findnext(ite)
        idx += 1

    return funcs


def get_data(func_gen=None, env_desc=None, plug_params=None):
    report = {
        'data': collections.defaultdict(list),
        'stat': collections.defaultdict(int)
    }

    dirs = get_dirs('/')
    dir_funcs = get_dir_funcs(dirs)

    for func_addr in func_gen():
        if func_addr in dir_funcs:
            dir_name = dir_funcs[func_addr]
            report['data'][dir_name].append(func_addr)
            report['stat'][dir_name] += 1

    return report if __name__ == '__main__' else report['data']

def debug():
    data_obj = get_data(func_gen=idautils.Functions)
    ida_shims.msg(json.dumps(data_obj, indent=4))

if __name__ == '__main__':
    debug()
