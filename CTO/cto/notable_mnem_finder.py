import ida_funcs
import ida_ua
import ida_idp
import idc
import idautils
import ida_search
import ida_xref
import ida_bytes
import ida_idaapi

class notable_mnem_t(object):
    def __init__(self, cmt_prefix="NT_MNEM: "):
        self.cmt_prefix = cmt_prefix
        
    @staticmethod
    def get_code_eas(ea=idc.get_inf_attr(idc.INF_MIN_EA), max_ea=idc.get_inf_attr(idc.INF_MAX_EA)):
        flags = ida_bytes.get_flags(ea)
        if ida_bytes.is_code(flags):
            yield ea
        
        ea = ida_bytes.next_that(ea, max_ea, ida_bytes.is_code)
        while ea != ida_idaapi.BADADDR:
            yield ea
            ea = ida_bytes.next_that(ea, max_ea, ida_bytes.is_code)
            
    def collect_mnems(self):
        for ea in self.get_code_eas():
            mnem = idc.print_insn_mnem(ea)
            if mnem in c.mnems:
                yield ea, mnem
                
    def push_handler(self, ea):
        #nea = ida_search.find_code(ea, ida_search.SEARCH_DOWN|ida_search.SEARCH_NEXT|ida_search.SEARCH_NOSHOW)
        nea = ida_xref.get_first_cref_from(ea)
        if nea != idc.BADADDR:
            mnem = idc.print_insn_mnem(nea)
            if mnem == "ret":
                #print("%x, %s %x, %s" % (ea, idc.print_insn_mnem(ea), nea, mnem))
                return "push-ret jump", ea, nea
        return "", idc.BADADDR, idc.BADADDR
        
    def jmp_handler(self, ea):
        op1 = idc.print_operand(ea, 0)
        if op1.startswith("fword ptr "):
            #print("%x, %s, %s" % (ea, idc.print_insn_mnem(ea), op1))
            return "jump far (possible heaven's gate)", ea, idc.BADADDR
        return "", idc.BADADDR, idc.BADADDR
            
    def call_handler(self, ea):
        v = idc.get_operand_value(ea, 0)
        op1 = idc.print_operand(ea, 0)
        #print(op1)
        f = ida_bytes.get_full_flags(v)
        if ida_bytes.is_code(f):
            #print("%x, %x, %s" % (ea, v, idc.print_insn_mnem(v)))
            if idc.print_insn_mnem(v) in ["pop"]:
                #print("%x, %x, %s" % (ea, v, idc.print_insn_mnem(v)))
                return "get pc", ea, v
            elif idc.print_insn_mnem(v) in ["mov"]:
                f = ida_bytes.get_full_flags(v)
                if ida_bytes.is_stkvar1(f):
                    stkoff = idc.get_operand_value(v, 1)
                    if stkoff == 0:
                        #print("%x, %x, %s, %x" % (ea, v, idc.print_insn_mnem(v), stkoff))
                        return "get pc", ea, v
            elif op1.startswith("fword ptr "):
                #print("%x, %s, %s" % (ea,idc.print_insn_mnem(ea), op1))
                return "call far (possible heaven's gate)", ea, idc.BADADDR
        elif op1.startswith("fword ptr "):
            #print("%x, %s, %s" % (ea, idc.print_insn_mnem(ea), op1))
            return "call far (possible heaven's gate)", ea, idc.BADADDR
        return "", idc.BADADDR, idc.BADADDR
    
    def retf_handler(self, ea):
        f = ida_funcs.get_func(ea)
        if f:
            for fea in idautils.FuncItems(f.start_ea):
                mnem = idc.print_insn_mnem(fea)
                if mnem == "push":
                    if ida_ua.o_imm == idc.get_operand_type(fea, 0):
                        v = idc.get_operand_value(fea, 0)
                        if v == 0x33:
                            #print("%x, %s, %x, %s" % (ea, idc.print_insn_mnem(ea), fea, idc.print_insn_mnem(fea)))
                            return "possible heaven's gate (x86->x64)", ea, fea
                        elif v == 0x23:
                            #print("%x, %s, %x, %s" % (ea, idc.print_insn_mnem(ea), fea, idc.print_insn_mnem(fea)))
                            return "possible heaven's gate (x64->x86)", ea, fea
        
        #print("%x, %s" % (ea, idc.print_insn_mnem(ea)))
        return "ret far (possible heaven's gate)", ea, idc.BADADDR
    
    def fstenv_handler(self, ea):
        #print("%x, %s" % (ea, idc.print_insn_mnem(ea)))
        return "possible get pc", ea, v, idc.BADADDR
        
    
    def set_cmt(self, ea, comment):
        cmt = ida_bytes.get_cmt(ea, False)
        if not cmt or cmt.find(comment) < 0:
            new_cmt = self.cmt_prefix + comment
            if cmt:
                cmt = self.cmt_prefix + comment + ", " + cmt
            ida_bytes.set_cmt(ea, new_cmt, False)
            
    def mnem_handlers(self):
        #for ea, mnem in self.collect_mnems():
        for ea in self.get_code_eas():
            flag = False
            
            mnem = idc.print_insn_mnem(ea)
            if mnem == "push":
                mnem_type, ea, dst_ea = self.push_handler(ea)
                flag = True
            elif mnem == "call":
                mnem_type, ea, dst_ea = self.call_handler(ea)
                flag = True
            elif mnem == "jmp":
                mnem_type, ea, dst_ea = self.jmp_handler(ea)
                flag = True
            elif mnem == "retf":
                mnem_type, ea, dst_ea = self.retf_handler(ea)
                flag = True
            elif mnem in ["fnstenv", "fstenv", "fnsave", "fsave", "fxsave"]:
                mnem_type, ea, dst_ea = self.fstenv_handler(ea)
                flag = True
                
            if flag and ea != idc.BADADDR:
                yield ea, mnem_type, dst_ea
                self.set_cmt(ea, mnem_type)
                if dst_ea != idc.BADADDR:
                    self.set_cmt(dst_ea, mnem_type)
            #print("%x" % ea, mnem)
            
def main():
    c = notable_mnem_t()
    for ea, mnem_type, dst_ea in c.mnem_handlers():
        print("%x: %s, %x" % (ea, mnem_type, dst_ea))

if __name__ == "__main__":
    main()
