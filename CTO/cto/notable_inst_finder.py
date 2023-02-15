import idc
import ida_idaapi
import ida_search
import ida_bytes
import ida_funcs
import ida_gdl
import ida_ua
import ida_segment

import os
import json

class notable_inst_t(object):
    def __init__(self, frules=os.path.join(os.path.dirname(__file__),"notable_insts.json"), show_high_ent=False, cmt_prefix="NT_INST: "):
        with open(frules) as f:
            insts = json.load(f)
        self.insts = {}
        for rule_type in insts:
            if rule_type not in self.insts:
                self.insts[rule_type] = {}
            if rule_type == "single":
                for rule_name in insts[rule_type]:
                    self.insts[rule_type][rule_name] = insts[rule_type][rule_name]
            else:
                pass
        #print(self.insts)
        self.cmt_prefix = cmt_prefix
        
    @staticmethod
    def get_inst_eas(rule, regex=False, ea=idc.get_inf_attr(idc.INF_MIN_EA)):
        flags = ida_search.SEARCH_DOWN|ida_search.SEARCH_NEXT
        if regex:
            flags |= ida_search.SEARCH_REGEX
        ea = ida_search.find_text(ea, 0, 0, rule, flags)
        while ea != ida_idaapi.BADADDR:
            yield ea
            ea = ida_bytes.next_head(ea, ida_idaapi.BADADDR)
            ea = ida_search.find_text(ea, 0, 0, rule, flags)
            
    def get_notable_insts(self):
        multi_rule_result = {}
        for rule_name in self.insts["single"]:
            rule = self.insts["single"][rule_name]["rule"]
            regex = self.insts["single"][rule_name]["regex"]
            for ea in self.get_inst_eas(rule, regex=regex):
                yield ea, rule_name
    
    def set_cmt(self, ea, rule_name):
        cmt = ida_bytes.get_cmt(ea, False)
        if not cmt or cmt.find(rule_name) < 0:
            new_cmt = self.cmt_prefix + rule_name
            if cmt:
                cmt = self.cmt_prefix + rule_name + ", " + cmt
            ida_bytes.set_cmt(ea, new_cmt, False)
                
    def collect_notable_insts(self):
        for inst_ea, rule_name in self.get_notable_insts():
            self.set_cmt(inst_ea, rule_name)
            disasm = idc.generate_disasm_line(inst_ea, 0)
            f = ida_funcs.get_func(inst_ea)
            func_ea = idc.BADADDR
            if f:
                func_ea = f.start_ea
            yield func_ea, inst_ea, rule_name, disasm

def main():
    i = notable_inst_t()
    for func_ea, inst_ea, rule_name, disasm in i.collect_notable_insts():
        print("%x %s: %x: %s: %s" % (func_ea, idc.get_name(func_ea), inst_ea, rule_name, disasm))

if __name__ == "__main__":
    main()
