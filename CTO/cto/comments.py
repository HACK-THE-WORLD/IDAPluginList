import json
import re
import os

import idc
import ida_bytes
import ida_funcs
import ida_idaapi
import ida_gdl
import idautils

#import cto_utils
#ida_idaapi.require("cto_utils")

class comment_t(object):
    def __init__(self, frules=os.path.join(os.path.dirname(__file__),"cmt_rules.json")):
        with open(frules) as f:
            rules = json.load(f)
        self.rules = self.create_comment_rules(rules)
        
    @staticmethod
    def create_comment_rules(rules):
        result = {}
        for cmt_type in rules:
            if cmt_type not in result:
                result[cmt_type] = {}
            for incdec in rules[cmt_type]:
                if incdec == "default":
                    result[cmt_type][incdec] = rules[cmt_type][incdec]
                    continue
                elif incdec not in result[cmt_type]:
                    result[cmt_type][incdec] = []
                for rule_name in rules[cmt_type][incdec]:
                    rule = rules[cmt_type][incdec][rule_name]
                    result[cmt_type][incdec].append(re.compile(rule))
        return result

    @staticmethod
    def get_cmt_eas(ea=idc.get_inf_attr(idc.INF_MIN_EA), max_ea=idc.get_inf_attr(idc.INF_MAX_EA)):
        flags = ida_bytes.get_flags(ea)
        if ida_bytes.has_cmt(flags):
            yield ea
        
        ea = ida_bytes.next_that(ea, max_ea, ida_bytes.has_cmt)
        while ea != ida_idaapi.BADADDR:
            yield ea
            ea = ida_bytes.next_that(ea, max_ea, ida_bytes.has_cmt)
            
    @staticmethod
    def get_cmt_eas_in_func(ea):
        func = ida_funcs.get_func(ea)
        if not func:
            return
        fc = ida_gdl.FlowChart(func)
        for block in fc:
            #print("%x, %x" % (block.start_ea, block.end_ea))
            for cmt_ea in comment_t.get_cmt_eas(block.start_ea, block.end_ea):
                yield cmt_ea
            
    @staticmethod
    def get_cmt_eas_in_func_with_ida77(ea):
        func = ida_funcs.get_func(ea)
        if not func:
            return
        fii = ida_funcs.func_item_iterator_t()
        ok = fii.set(func)
        while ok:
            yield fii.current()
            ok = fii.next(ida_bytes.has_cmt)
            
    @staticmethod
    def get_cmts(ea=ida_idaapi.BADADDR):
        if ea == ida_idaapi.BADADDR:
            cmt_eas = comment_t.get_cmt_eas()
        else:
            cmt_eas = comment_t.get_cmt_eas_in_func(ea)
        for cmt_ea in cmt_eas:
            f = ida_funcs.get_func(cmt_ea)
            func_ea = ida_idaapi.BADADDR
            cmt = ida_bytes.get_cmt(cmt_ea, False)
            rcmt = ida_bytes.get_cmt(cmt_ea, True)
            if f:
                func_ea = f.start_ea
            yield func_ea, cmt_ea, cmt, rcmt
    
    def is_matched(self, incexc, cmt_type, text):
        for r in self.rules[cmt_type][incexc]:
            if r.match(text):
                return True
        return False

    def chk_filter(self, cmt_type, text):
        default_flag = self.rules[cmt_type]["default"]
        flag = default_flag
        # if default is false, include filter process BEFORE the exclude filter
        if not default_flag and self.is_matched("include", cmt_type, text):
            flag = True
        if self.is_matched("exclude", cmt_type, text):
            flag = False
        # if default is true, include filter process AFTER the exclude filter
        if default_flag and self.is_matched("include", cmt_type, text):
            flag = True
        return flag
    
    def collect_cmts(self, ea=ida_idaapi.BADADDR):
        for func_ea, cmt_ea, cmt, rcmt in self.get_cmts(ea):
            cmt_flag = False
            if cmt and self.chk_filter("cmt", cmt):
                yield func_ea, cmt_ea, cmt, "cmt"
            if rcmt and self.chk_filter("rcmt", rcmt):
                yield func_ea, cmt_ea, rcmt, "rcmt"
                        
    def collect_cmts_as_dict(self, ea=ida_idaapi.BADADDR):
        result = {}
        if ea == ida_idaapi.BADADDR:
            for func_ea in idautils.Functions():
                result[func_ea] = {"cmt":{}, "rcmt":{}}
        else:
            f = ida_funcs.get_func(ea)
            func_ea = ea
            if f:
                func_ea = f.start_ea
            result[func_ea] = {"cmt":{}, "rcmt":{}}
            
        cmt_obj = comment_t()
        for func_ea, cmt_ea, cmt, cmt_type in cmt_obj.collect_cmts(ea):
            if func_ea != ida_idaapi.BADADDR:
                if func_ea not in result:
                    result[func_ea] = {"cmt":{}, "rcmt":{}}
                result[func_ea][cmt_type][cmt_ea] = cmt
        return result
        
if __name__ == "__main__":
    cmt_obj = comment_t()
    for func_ea, cmt_ea, cmt, cmt_type in cmt_obj.collect_cmts(here()):
        print("%x, %x, %s, %s" % (func_ea, cmt_ea, cmt, cmt_type))
