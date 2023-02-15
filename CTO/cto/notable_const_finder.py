import idc
import idautils
import ida_idaapi
import ida_bytes
import ida_funcs
import ida_gdl
import ida_ua
import ida_segment

import os
import json

import cto_utils
ida_idaapi.require("cto_utils")
#import segments
#ida_idaapi.require("segments")

def get_op_size(dtyp):
    if dtyp == ida_ua.dt_dword:
        size = 4
    elif dtyp == ida_ua.dt_word:
        size = 2
    elif dtyp == ida_ua.dt_byte:
        size = 1
    elif dtyp == ida_ua.dt_qword:
        size = 8
    else:
        size = -1
    return size

class notable_const_t(object):
    def __init__(self, frules=os.path.join(os.path.dirname(__file__),"notable_consts.json"), show_high_ent=False, cmt_prefix="NT_CON: "):
        with open(frules) as f:
            consts = json.load(f)
        self.consts = {}
        for rule_name in consts:
            if rule_name not in self.consts:
                self.consts[rule_name] = {}
            if rule_name == "single":
                for val in consts[rule_name]:
                    self.consts[rule_name][int(val, 16)] = consts[rule_name][val]
            else:
                for rule_name2 in consts[rule_name]:
                    if rule_name2 not in self.consts[rule_name]:
                        self.consts[rule_name][rule_name2] = {}
                    for item_name in consts[rule_name][rule_name2]:
                        if item_name in ["consts", "max"]:
                            if item_name not in self.consts[rule_name][rule_name2]:
                                self.consts[rule_name][rule_name2][item_name] = {}
                            for val in consts[rule_name][rule_name2][item_name]:
                                if int(val, 16) not in self.consts[rule_name][rule_name2][item_name]:
                                    self.consts[rule_name][rule_name2][item_name][int(val, 16)] = {}
                                self.consts[rule_name][rule_name2][item_name][int(val, 16)] = consts[rule_name][rule_name2][item_name][val]
                        elif item_name == "require":
                            if item_name not in self.consts[rule_name][rule_name2]:
                                self.consts[rule_name][rule_name2][item_name] = []
                            for val in consts[rule_name][rule_name2][item_name]:
                                self.consts[rule_name][rule_name2][item_name].append(int(val, 16))
                        else:
                            self.consts[rule_name][rule_name2][item_name] = consts[rule_name][rule_name2][item_name]
        self.cmt_prefix = cmt_prefix
        self.show_high_ent = show_high_ent
        
    @staticmethod
    def get_const_eas(ea=idc.get_inf_attr(idc.INF_MIN_EA), max_ea=idc.get_inf_attr(idc.INF_MAX_EA)):
        flags = ida_bytes.get_flags(ea)
        if ida_bytes.has_immd(flags):
            yield ea
        
        ea = ida_bytes.next_that(ea, max_ea, ida_bytes.has_immd)
        while ea != ida_idaapi.BADADDR:
            yield ea
            ea = ida_bytes.next_that(ea, max_ea, ida_bytes.has_immd)
            
    @staticmethod
    def get_const_eas_in_func(ea):
        func = ida_funcs.get_func(ea)
        if not func:
            return
        fc = ida_gdl.FlowChart(func)
        for block in fc:
            #print("%x, %x" % (block.start_ea, block.end_ea))
            for const_ea in notable_const_t.get_const_eas(block.start_ea, block.end_ea):
                yield const_ea
                
    def is_it_in_rule(self, v, target, keyword, rule):
        flag = False
        if v in rule:
            if rule[v][keyword]:
                if target in rule[v][keyword]:
                    flag = True
            else:
                flag = True
        return flag
        
    def check_const_ea(self, ea, consts, b_high_ent=False):
        insn = ida_ua.insn_t()
        inslen = ida_ua.decode_insn(insn, ea)
        mnem = insn.get_canon_mnem()
        for i in range(inslen):
            if ida_ua.o_void == insn.ops[i].type:
                i = -1
                break
            
            optype = idc.get_operand_type(ea, i)
            op = insn.ops[i]
            dtype = op.dtype
            opsz = get_op_size(dtype)
            v = idc.get_operand_value(ea, i)
            if cto_utils.is_32bit(ea):
                v &= 0xffffffff
                #print(hex(v))
            flags = ida_bytes.get_full_flags(v)
            op_flag = ida_bytes.get_item_flag(ida_idaapi.BADADDR, i, ea, 0)
            if ida_bytes.is_numop(op_flag, i) or (optype in [ida_ua.o_phrase, ida_ua.o_imm, ida_ua.o_displ] and not ida_bytes.is_stkvar(op_flag, i) and not ida_bytes.is_stroff(op_flag, i) and not ida_bytes.is_enum(op_flag, i) and not ida_bytes.is_off(op_flag, i)):
            #if not ida_bytes.is_stkvar(op_flag, i) and not ida_bytes.is_stroff(op_flag, i) and not ida_bytes.is_enum(op_flag, i) and not ida_bytes.is_off(op_flag, i):
                if v in consts and self.is_it_in_rule(v, optype, "optype", consts) and self.is_it_in_rule(v, mnem, "mnems", consts) and self.is_it_in_rule(v, i, "opn", consts) and self.is_it_in_rule(v, opsz, "opsz", consts):
                    return v
                if b_high_ent and self.show_high_ent:
                    #print(hex(ea), opsz)
                    if self.is_high_ent(v, opsz):
                        return v
        return -1
            
    @staticmethod
    def is_high_ent(val, opsz):
        if opsz < 4:
            return False
        byte_count = {}
        for i in range(opsz):
            byte = (val >> i*8) & 0xff
            if byte in [0xff, 0x00]:
                continue
            if byte in byte_count:
                byte_count[byte] += 1
            else:
                byte_count[byte] = 1
        if len(byte_count) > 2:
            #print(hex(val), byte_count)
            return True
        return False
        
    def get_notable_consts_in_func_for_single(self, const_ea, rule):
        #print("%x" % const_ea)
        return self.check_const_ea(const_ea, rule, b_high_ent=True)
        """
        val = self.check_const_ea(const_ea, rule, b_high_ent=True)
        #print(val)
        if val >= 0: and (val in rule or match_type == "highent"):
            return val, match_type
        return -1, ""
        """
                    
    def get_notable_consts_in_func_for_multiple(self, const_ea, rule, result):
        #print("%x" % const_ea)
        for rule_name in rule:
            consts = rule[rule_name]["consts"]
            #min_cnt = rule[rule_name]["min"]
            v = self.check_const_ea(const_ea, consts)
            if v >= 0:
                if rule_name in result:
                    if v in result[rule_name]:
                        result[rule_name][v].append(const_ea)
                    else:
                        result[rule_name][v] = [const_ea]
                else:
                    result[rule_name] = {v: [const_ea]}
        
    @staticmethod
    def get_seg_item_size(ea):
        seg = ida_segment.getseg(ea)
        if seg:
            return 1 << (seg.bitness + 1)
        return -1
        
    def check_requirement(self, requirements, result):
        for r in requirements:
            if r not in result:
                return False
        return True
        
    def check_max_count(self, max_cnts, result):
        for c in max_cnts:
            if c in result and max_cnts[c] < len(result[c]):
                return False
        return True
        
    def get_notable_consts_in_func(self, func_ea):
        rule = self.consts["single"]
        multi_rule_result = {}
        for const_ea in self.get_const_eas_in_func(func_ea):
            #print(const_ea)
            val = self.get_notable_consts_in_func_for_single(const_ea, rule)
            if val >= 0:
                if val in rule:
                    yield func_ea, const_ea, val, rule[val]['name']
                else:
                    yield func_ea, const_ea, val, "highent"
            self.get_notable_consts_in_func_for_multiple(const_ea, self.consts["multiple"], multi_rule_result)
        for rule_name in multi_rule_result:
            min_cnt = self.consts["multiple"][rule_name]["min"]
            requirements = self.consts["multiple"][rule_name]["require"]
            max_cnts = self.consts["multiple"][rule_name]["max"]
            if len(multi_rule_result[rule_name]) >= min_cnt and self.check_requirement(requirements, multi_rule_result[rule_name]) and self.check_max_count(max_cnts, multi_rule_result[rule_name]):
                for val in multi_rule_result[rule_name]:
                    for const_ea in multi_rule_result[rule_name][val]:
                        name = self.consts["multiple"][rule_name]["consts"][val]["name"]
                        yield func_ea, const_ea, val, rule_name + ": " + name
                #print("%x" % func_ea, multi_rule_result[rule_name], rule_name)
    
    def set_cmt(self, const_ea, rule_name):
        cmt = ida_bytes.get_cmt(const_ea, False)
        if not cmt or cmt.find(rule_name) < 0:
            new_cmt = self.cmt_prefix + rule_name
            if cmt:
                cmt = self.cmt_prefix + rule_name + ", " + cmt
            ida_bytes.set_cmt(const_ea, new_cmt, False)
                
    def collect_notable_consts(self, ea=ida_idaapi.BADADDR):
        if ea == ida_idaapi.BADADDR:
            for func_ea in idautils.Functions():
                for func_ea, const_ea, val, rule_name in self.get_notable_consts_in_func(func_ea):
                    self.set_cmt(const_ea, rule_name)
                    yield func_ea, const_ea, val, rule_name
        else:
            func_ea = ea
            if f:
                func_ea = f.start_ea
            for func_ea, const_ea, val, rule_name in self.get_notable_consts_in_func(func_ea):
                self.set_cmt(const_ea, rule_name)
                yield func_ea, const_ea, val, rule_name

def main():
    c = notable_const_t()
    for func_ea, const_ea, val, rule_name in c.collect_notable_consts():
        print("%x %s: %x, %x, %s" % (func_ea, idc.get_name(func_ea), const_ea, val, rule_name))

if __name__ == "__main__":
    main()
