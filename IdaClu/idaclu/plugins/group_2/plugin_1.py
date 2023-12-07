import collections
import json
import re
#
import idaapi
import idautils
import idc
#
from idaclu import ida_shims


SCRIPT_NAME = 'Common Constants'
SCRIPT_TYPE = 'func'
SCRIPT_VIEW = 'tree'
SCRIPT_ARGS = []


def sort_nat(input_dict):
    def fun(k, v):
        return [k, int(v)]

    def cmp_key(t):
        return fun(*re.match(r'([a-zA-Z\: ]+)(\d+)', t[0]).groups())

    return collections.OrderedDict(sorted(input_dict.items(), key=cmp_key))

def get_data(func_gen=None, env_desc=None, plug_params=None):
    report = {
        'data': collections.defaultdict(list),
        'stat': collections.defaultdict(int)
    }

    for func_addr in func_gen():
        func_desc = idaapi.get_func(func_addr)
        for head in idautils.Heads(ida_shims.start_ea(func_desc), ida_shims.end_ea(func_desc)):
            for opnd_index in range(idaapi.UA_MAXOP):
                opnd_type = ida_shims.get_operand_type(head, opnd_index)
                if opnd_type in [idaapi.o_void]:
                    break
                if opnd_type in [idaapi.o_reg, idaapi.o_phrase]:
                    opnd_str = ida_shims.print_operand(head, opnd_index)
                    if opnd_str in ['rsp', 'esp', 'rbp', 'ebp']:
                        break
                if opnd_type == idc.o_imm:
                    opnd_val = ida_shims.get_operand_value(head, opnd_index)
                    if ida_shims.is_loaded(opnd_val):
                        continue

                    # avoiding values that can be interpreted as addresses
                    # within the current sample:
                    #   SEH-handlers, callback-arguments, string-offsets, etc.

                    dasm_flag = idaapi.GENDSM_FORCE_CODE
                    dasm_line = ida_shims.generate_disasm_line(head, dasm_flag)
                    dasm_norm = ' '.join(dasm_line.split())
                    func_comm = '{} / {}'.format(hex(head), dasm_norm)

                    opnd_key = "const: {} / {}".format(opnd_val, hex(opnd_val))
                    report['data'][opnd_key].append((func_addr, func_comm))
                    report['stat'][opnd_key] += 1

    report['data'] = sort_nat(report['data'])
    report['stat'] = sort_nat(report['stat'])

    return report if __name__ == '__main__' else report['data']

def debug():
    data_obj = get_data(func_gen=idautils.Functions)
    ida_shims.msg(json.dumps(data_obj, indent=4))

if __name__ == '__main__':
    debug()
