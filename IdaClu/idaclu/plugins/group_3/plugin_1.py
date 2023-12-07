import collections
import json
#
import idaapi
import idautils
#
from idaclu import ida_shims


SCRIPT_NAME = 'Control Flow Analysis'
SCRIPT_TYPE = 'func'
SCRIPT_VIEW = 'tree'
SCRIPT_ARGS = []


def get_func_item_eas(func_addr):
    for item_ea in list(idautils.FuncItems(func_addr)):
        if ida_shims.is_code(ida_shims.get_full_flags(func_addr)):
            yield item_ea

def is_func_proxy(func_addr):
    item_eas = list(get_func_item_eas(func_addr))
    if ida_shims.ua_mnem(item_eas[-1]) == 'jmp':
        return True
    else:
        return False

def is_func_switch(func_addr):
    for (f_beg, f_end) in idautils.Chunks(func_addr):
        for head_ea in idautils.Heads(f_beg, f_end):
            if ida_shims.is_code(ida_shims.get_full_flags(head_ea)):
                si = ida_shims.get_switch_info(head_ea)
                if si == None:
                    continue
                results = idaapi.calc_switch_cases(head_ea, si)
                if results:
                    return True
                return False

def is_func_loop(func_desc):
    func_start_ea = ida_shims.start_ea(func_desc)

    blocks = [func_start_ea]
    for block in idaapi.FlowChart(func_desc):
        end_ea = ida_shims.end_ea(block)
        blocks.append(end_ea)

    for block in blocks:
        for xref in idautils.XrefsTo(block):
            xref_func = idaapi.get_func(xref.frm)
            xref_start_ea = ida_shims.start_ea(xref_func)

            if xref_func and xref_start_ea == func_start_ea:
                if xref.frm >= block:
                    return True
    return False


def is_func_simple_recursion(func_addr):
    for h in idautils.FuncItems(func_addr):
        for r in idautils.XrefsFrom(h, 0):
            if ((r.type == idaapi.fl_CF or r.type == idaapi.fl_CN) and
                r.to == func_addr):
                return True
    return False

stack = []
def is_func_recursion(func_addr):
    global stack
    if func_addr in stack:
        # print "This is recursive function", hex(func_addr), Name(func_addr)
        # for x in stack:
        #     print "\t", hex(x)
        # #insert your renaming here, it should be idc.MakeName
        return

    stack.append(func_addr)
    for h in idautils.FuncItems(func_addr):
        for r in idautils.XrefsFrom(h, 0):
            if ((r.type == idaapi.fl_CF or r.type == idaapi.fl_CN) and
                r.to != func_addr):
                is_func_recursion(r.to)
    stack = stack[:-1]

def is_func_condition(func_desc):
    bb_list = list(idaapi.FlowChart(func_desc))
    bb_num = len(bb_list)
    bb_conn_count = len(list(bb_list[0].succs()))
    if ((bb_num == 1 and bb_conn_count == 0) or
        (bb_num == 2 and bb_conn_count == 1 and is_func_proxy(ida_shims.start_ea(func_desc)))):
        return False
    return True

def get_data(func_gen=None, env_desc=None, plug_params=None):
    global stack

    report = {
        'data': collections.defaultdict(list),
        'stat': collections.defaultdict(int)
    }

    for func_addr in func_gen():
        func_desc = idaapi.get_func(func_addr)
        func_groups = []
        if is_func_proxy(func_addr):
            func_groups.append('proxy')

        is_switch = False
        if is_func_switch(func_addr):
            func_groups.append('switch')
            is_switch = True

        is_loop = False
        if is_func_loop(func_desc):
            func_groups.append('loop')
            is_loop = True

        if is_switch == False and is_loop == False:
            if is_func_condition(func_desc):
                func_groups.append('conditions')
            else:
                func_groups.append('simple')

        stack = []
        if is_func_simple_recursion(func_addr):
            if func_addr in stack:
                func_groups.append('simple_recursion')

        for g_name in func_groups:
            report['data'][g_name].append(func_addr)
            report['stat'][g_name] += 1

    return report if __name__ == '__main__' else report['data']

def debug():
    data_obj = get_data(func_gen=idautils.Functions)
    ida_shims.msg(json.dumps(data_obj, indent=4))

if __name__ == '__main__':
    debug()
