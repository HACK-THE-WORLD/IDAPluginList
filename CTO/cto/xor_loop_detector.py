import idc
import ida_xref
import ida_idaapi
import ida_name
import ida_funcs
import ida_bytes
import idautils

import loop_detector
import cto_utils
ida_idaapi.require("loop_detector")
ida_idaapi.require("cto_utils")

g_rename_prefix = ('sub_',)

def rename_func(ea, xref_cnt, prefix='xorloop_', rename_prefix=g_rename_prefix, force=False):
    name = idc.get_name(ea)
    if name.find(prefix) >= 0:
        return
    
    rename_flag = False
    for n in g_rename_prefix:
        if name.startswith(n):
            rename_flag = True
    if force:
        rename_flag = True
    if not rename_flag:
        return

    new_name = "%s%d_%s" % (prefix, xref_cnt, name)
    ida_name.set_name(ea, new_name)

def get_xor_insns_all_funcs():
    for func_ea in idautils.Functions():
        for ea in get_xor_insns(func_ea):
            yield func_ea, ea

def get_xor_insns(func_ea):
    for ea in idautils.FuncItems(func_ea):
        mnem = idc.print_insn_mnem(ea)
        if mnem == 'xor':
            op1 = idc.print_operand(ea, 0)
            op2 = idc.print_operand(ea, 1)
            if op1 != op2:
                yield ea

def find_xor_loop(xor=False, comment=True, rename=False, cmt_prefix="CTO-"):
    to_rename_funcs = {}
    for func_ea, ea in get_xor_insns_all_funcs():
        ld = loop_detector.loop_detector(func_ea)
        bb = ld.get_bb(ea)
        annotation_type = ""
        # skip the candidate for xor loop if the basic block is function start or function end because it is not in a loop.
        if len(tuple(bb.preds())) == 0 or len(tuple(bb.succs())) == 0:
            if xor:
                annotation_type = "xor"
                yield func_ea, ea, annotation_type
            continue
        # xor loop
        elif len(ld.find_loop_bbs_by_ea(ea)):
            annotation_type = "xorloop"
            yield func_ea, ea, annotation_type
        # xor
        else:
            if xor:
                annotation_type = "xor"
                yield func_ea, ea, annotation_type
                
        if annotation_type:
            # get functions to be renamed
            if func_ea != idc.BADADDR and rename:
                rename_flag = True
                if func_ea in to_rename_funcs and "xorloop" == to_rename_funcs[func_ea]:
                    rename_flag = False
                if rename_flag:
                    xref_cnt = cto_utils.count_xref(ea)
                    to_rename_funcs[func_ea] = (annotation_type, xref_cnt)
            # set a comment to a xor or a xor loop
            if comment:
                cmt = ida_bytes.get_cmt(ea, False)
                if cmt is None:
                    cmt = ""
                if cmt.find("%s%s" % (cmt_prefix, annotation_type)) < 0:
                    delimiter = ""
                    if cmt:
                        delimiter = ", "
                    ida_bytes.set_cmt(ea, "%s%s%s%s" % (cmt, delimiter, cmt_prefix, annotation_type), False)
    # rename functions
    for func_ea in to_rename_funcs:
        annotation_type, xref_cnt = to_rename_funcs[func_ea]
        rename_func(func_ea, xref_cnt, prefix=annotation_type+"_")

def main():
    for func_ea, ea, annotation_type in find_xor_loop():
        print("%x: %s, %x: %s" % (func_ea, annotation_type, ea, idc.generate_disasm_line(ea, 0)))

if __name__ == '__main__':
    main()
