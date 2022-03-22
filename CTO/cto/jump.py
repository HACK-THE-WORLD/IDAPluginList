import ida_kernwin
import ida_lines
import ida_funcs
import ida_moves
import ida_name
import ida_ua
import ida_idaapi
import ida_xref
import idc

#import cto_utils
#ida_idaapi.require("cto_utils")

def jump_to_func_ptr_line_pos(text, func_name, w, tweak=0, add_x=False):
    flag = False
    idx = text.find(func_name)
    
    #w = find_widget(wname)
    if w is None:
        return flag
        
    # we are already at a certain point. but ida sometimes does not point to a function in the middle of the instruction.
    # that's why I use position 0 of x first, and then move to the right position again.
    if idx == 0:
        pos, x, y = ida_kernwin.get_custom_viewer_place(w, 0)
        orig_x = x
        if not add_x:
            orig_x = 0
        ida_kernwin.jumpto(w, pos, 0, y)
        pos, x, y = ida_kernwin.get_custom_viewer_place(w, 0)
        ida_kernwin.jumpto(w, pos, orig_x+tweak, y)
        flag = True
    elif idx > 0:
        pos, x, y = ida_kernwin.get_custom_viewer_place(w, 0)
        if not add_x:
            x = 0
        ida_kernwin.jumpto(w, pos, x+idx+tweak, y)
        flag = True
    return flag

"""
def get_apiname_line(ea, wname=g_wname):
    fn = idc.get_name(ea)
    if not fn:
        return None, None

    fn, line, idx = get_funcname_line(ea)
    if not fn:
        return None, None
        
    w = find_widget(wname)
    if w is None:
        return None, None
    pos, x, y = ida_kernwin.get_custom_viewer_place(w, 0)
    ida_kernwin.jumpto(w, pos, 0, y)
        
    l = ida_kernwin.get_curline()
    if l and l.find(fn) >= 0:
        l_removed = ida_lines.tag_remove(l)
        return fn, l_removed
        
    return None, None
"""

def jump_to_line(ea, i, w):
    #w = find_widget(wname)
    if w is None:
        return False
    pos, x, y = ida_kernwin.get_custom_viewer_place(w, 0)
    pos.lnnum = i
    ida_kernwin.jumpto(w, pos, x, y)
    return True

"""
def check_line(ea, i, fn, wname=g_wname):
    w = find_widget(wname)
    if w is None:
        return None, -1
    pos, x, y = ida_kernwin.get_custom_viewer_place(w, 0)
    pos.lnnum = i
    ida_kernwin.jumpto(w, pos, x, y)
    l = ida_kernwin.get_curline()
    l_removed = ida_lines.tag_remove(l)
    l_removed_content = l_removed.split(";")[0]
    idx = l_removed_content.find(fn)
    if idx >= 0:
        return l_removed_content, idx
    return None, -1
"""

def get_line_no_decomp(text, vu, max_trial=200):
    line = ""
    lineno = -1
    x = -1
    lnnum = 0
    y = 0
    for i, l in enumerate(vu.cfunc.get_pseudocode()):
        if ida_lines.tag_remove(l.line).startswith("//"):
            y += 1
            continue
        #print(i, ida_lines.tag_remove(l.line))
        ln = ida_lines.tag_remove(l.line)
        ln = ln.split("//", 1)[0]
        x = ln.find(text)
        if x >= 0:
            line = ln
            lineno = i
            break
        if max_trial > 0 and i > max_trial:
            break
        lnnum += 1
        y = 0
    return line, lineno, lnnum, x, y

def get_funcname_line_decomp(ea, vu, max_trial=200):
    func_decl_str = ida_lines.tag_remove(vu.cfunc.print_dcl())
    f = ida_funcs.get_func(ea)
    func_name = ida_funcs.get_func_name(f.start_ea)
    func_name = ida_name.validate_name(func_name, ida_name.VNT_VISIBLE)
    # for API thunk call (e.g. __WSADisSet -> _WSADisSet)
    if func_decl_str.find(func_name) < 0 and func_name.startswith("_"):
        func_name = func_name[1:]
    line, lineno, lnnum, x, y = get_line_no_decomp(func_name, vu)
    return line, lineno, lnnum, x, y

def get_line_no(ea, text, max_trial=200, chk_cmt=False):
    _, disass = ida_lines.generate_disassembly(
        ea,
        max_trial,  # maximum number of lines
        False,      # as_stack=False
        True)       # notags
    for i, l in enumerate(disass):
        if chk_cmt:
            l_content = ''
            if l.find(";") >= 0:
                l_content = l.split(";")[1]
        else:
            l_content = l.split(";")[0]
        #print(l_content)
        idx = l_content.find(text)
        if idx >= 0:
            return l, i, idx
    return "", -1, -1

def get_funcname_line(ea, w, max_trial=200):
    f = ida_funcs.get_func(ea)
    if f:
        func_ea = f.start_ea
        fn = idc.get_func_name(func_ea)
    else:
        fn = ida_name.get_name(ea)
        
    if fn:
        fn = ida_name.validate_name(fn, ida_name.VNT_VISIBLE)
        #print(fn)
        line, i, idx = get_line_no(ea, fn, max_trial)
        if i < 0:
            return None, None, -1

        jump_to_line(ea, i, w)
        if jump_to_func_ptr_line_pos(line, fn, w):
            return fn, line, idx
        
    return None, None, -1

def push_lochist_jump(w):
    r = False
    if w is None:
        return False
    loc = ida_moves.lochist_entry_t()
    r = ida_kernwin.get_custom_viewer_location(loc, w)
    if r:
        loc.renderer_info().pos.cx = 0
        r = ida_kernwin.custom_viewer_jump(w, loc, ida_kernwin.CVNF_JUMP)
    return False

def jumpto_name_decomp(ea, w):
    try:
        import ida_hexrays
        ida_hexrays.init_hexrays_plugin()
    except ImportError:
        return
    vu = ida_hexrays.get_widget_vdui(w)
    #print(vu.cfunc)
    vu.get_current_item(ida_hexrays.USE_KEYBOARD)
    
    ea = vu.cfunc.entry_ea
    line, lineno, lnnum, x, y = get_funcname_line_decomp(ea, vu)
    if line:
        #print(line, lineno, lnnum, x, y)
        pos, _x, _y = ida_kernwin.get_custom_viewer_place(w, 0)
        #print(pos.lnnum, _x, _y)
        
        idaplace = ida_kernwin.place_t_as_idaplace_t(pos)
        idaplace.lnnum = lnnum
        idaplace.ea = ea
        ida_kernwin.jumpto(w, idaplace, x, y)

        vu.refresh_cpos(ida_hexrays.USE_KEYBOARD)
        ##vu.refresh_ctext(ida_hexrays.USE_KEYBOARD)
        #pos, _x, _y = ida_kernwin.get_custom_viewer_place(w, 0)
        #print(pos.lnnum, _x, _y)

def jumpto_name(ea, w):
    wt = ida_kernwin.get_widget_type(w)
    if wt == ida_kernwin.BWN_DISASM:
        jumpto_name_ida(ea, w)
    elif wt == ida_kernwin.BWN_PSEUDOCODE:
        jumpto_name_decomp(ea, w)
    
def jumpto_name_ida(ea, w):
    flag = False
    ida_kernwin.jumpto(ea)
    func = ida_funcs.get_func(ea)
    # for callee
    if func:
        #print("%x" % func.start_ea)
        fn, line, idx = get_funcname_line(func.start_ea, w)
        if idx >= 0:
            if w is None:
                return False
            pos, x, y = ida_kernwin.get_custom_viewer_place(w, 0)
            ida_kernwin.jumpto(w, pos, idx, 0)
        flag = True
    # for APIs and strings
    else:
        fn, line, idx = get_funcname_line(ea, w)
        if fn:
            flag = jump_to_func_ptr_line_pos(line, fn, w)
    return flag

def jumpto_offset(ea, w):
    flag = False
    wt = ida_kernwin.get_widget_type(w)
    if wt == ida_kernwin.BWN_DISASM:
        flag = jumpto_offset_ida(ea, w)
    elif wt == ida_kernwin.BWN_PSEUDOCODE:
        pass
    return flag
        
def jumpto_offset_ida(ea, w):
    curr_line = ida_lines.tag_remove(ida_kernwin.get_curline())
    search_key = " offset "
    x = curr_line.find(search_key)
    if x > 0:
        x += len(search_key)
        func_name = ida_name.extract_name(curr_line.split(search_key)[1], 0)
        
        # sometimes mismatch actual function name and and validate name.
        # to fix it, get name and compare its name with it.
        off_v = ida_xref.get_first_dref_from(ea)
        fn = ida_name.get_name(off_v)
        vfn = ida_name.validate_name(fn, ida_name.VNT_VISIBLE)
        if vfn == func_name and fn != vfn:
            func_name = fn
            
        if func_name:
            func_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, func_name)
            if func_ea != ida_idaapi.BADADDR:
                pos, _x, y = ida_kernwin.get_custom_viewer_place(w, 0)
                ida_kernwin.jumpto(w, pos, x, y)
                return True
    return False

def jumpto_opn(ea, opn, w):
    flag = False
    if opn >= 0:
        tweak = 0
        #ida_kernwin.jumpto(ea, opn, ida_kernwin.UIJMP_DONTPUSH)
        ida_kernwin.jumpto(ea, opn)
        
        wt = ida_kernwin.get_widget_type(w)
        if wt == ida_kernwin.BWN_DISASM:
            jumpto_opn_ida(ea, opn, w)
        elif wt == ida_kernwin.BWN_PSEUDOCODE:
            jumpto_opn_decomp(ea, opn, w)
    return flag

def get_highlight_decomp(w):
    vu = None
    highlight = None
    
    try:
        import ida_hexrays
        ida_hexrays.init_hexrays_plugin()
    except ImportError:
        return None, None
    
    vu = ida_hexrays.get_widget_vdui(w)
    #print(vu.cfunc)
    vu.get_current_item(ida_hexrays.USE_KEYBOARD)
    
    if vu.item.is_citem():
        highlight = vu.item.e
    return highlight, vu

def get_current_line_decomp(highlight, vu):
    x, y = vu.cfunc.find_item_coords(highlight)
    return ida_lines.tag_remove(list(vu.cfunc.get_pseudocode())[y].line)

def get_highlight_name_decomp(w):
    highlight, vu = get_highlight_decomp(w)
    if highlight and highlight.is_expr():
        hl_str = highlight.print1(None)
        return hl_str
    return None

def jumpto_opn_decomp(ea, opn, w):
    flag = False
    try:
        import ida_hexrays
        ida_hexrays.init_hexrays_plugin()
    except ImportError:
        return False
    
    highlight, vu = get_highlight_decomp(w)
    if highlight and highlight.is_expr():
        hl_str = highlight.print1(None)
        #print(ida_lines.tag_remove(hl_str))
        #print(type(highlight))
        #print(highlight.op)
        if highlight.op in [ida_hexrays.cot_call, ida_hexrays.cot_ptr, ida_hexrays.cot_ref, ida_hexrays.cot_cast, ida_hexrays.cot_idx]:
            #print(type(highlight.x))
            #print(highlight.x.op)
            if highlight.x.op in [ida_hexrays.cot_cast, ida_hexrays.cot_idx]:
                #print(highlight.x.x.op)
                if highlight.x.x.op in [ida_hexrays.cot_idx]:
                    x, y = vu.cfunc.find_item_coords(highlight.x.x.x)
                else:
                    x, y = vu.cfunc.find_item_coords(highlight.x.x)
            else:
                x, y = vu.cfunc.find_item_coords(highlight.x)
            pos, _x, _y = ida_kernwin.get_custom_viewer_place(w, 0)
            #print(pos.lnnum, _x, _y)
    
            idaplace = ida_kernwin.place_t_as_idaplace_t(pos)
            ida_kernwin.jumpto(w, idaplace, x, y)
            flag = True
    
    return flag

def jumpto_opn_ida(ea, opn, w):
    flag = False
    if True:
        tweak = 0
        op = idc.print_operand(ea, opn)
        optype = idc.get_operand_type(ea, opn)
        v = idc.get_operand_value(ea, opn)
        f = ida_funcs.get_func(ea)
        func_flags = idc.get_func_attr(ea, idc.FUNCATTR_FLAGS)
        func_name = ida_funcs.get_func_name(ea)
        if func_flags & ida_funcs.FUNC_THUNK:
            func_name = ida_name.get_name(v)
        elif not f:
            func_name = ida_name.get_name(ea)
        fn = ""
        if func_name:
            fn = ida_lines.tag_remove(func_name)
        if optype in [ida_ua.o_displ, ida_ua.o_phrase, ida_ua.o_mem]:
            # IDA's jumpto API does not point to the first character
            # if an operand starts with "[" like "lea     rax, [rdi+0B0h]".
            # This is a tweak value for it.
            if op and op[0] == '[':
                tweak = -1
            # for an applied structure member
            if op.find(".") >= 0:
                fn = op.rsplit(".", 1)[1]
            # for a stack variable name or a non-applied structure member
            elif op.find("+") >= 0:
                fn = op.rsplit("+", 1)[1]
                if fn.find("]") >= 0:
                    fn = fn.split("]")[0]
                if fn.find(")") >= 0:
                    fn = fn.split(")")[0]
            elif op.find("[") >= 0:
                fn = op.rsplit("[", 1)[1]
                if fn.find("]") >= 0:
                    fn = fn.split("]")[0]
            elif op.find(":") >= 0:
                fn = op.rsplit(":", 1)[1]
            else:
                fn = op
        # mov     [ebp+lpMultiByteStr], (offset MultiByteStr+40h)
        elif optype in [ida_ua.o_imm]:
            if op.find(".") >= 0:
                fn = op.rsplit(".", 1)[1]
            elif op.find("offset ") >= 0:
                fn = op.rsplit("offset ", 1)[1]
                if fn.find("+") >= 0:
                    fn = fn.split("+")[0]
            else:
                fn = op
        # for offset
        else:
            fn = ida_name.get_name(v)
            if fn:
                fn = ida_lines.tag_remove(fn)
        if fn:
            fn = ida_name.validate_name(fn, ida_name.VNT_VISIBLE)
            flag = jump_to_func_ptr_line_pos(op, fn, w, tweak, add_x=True)
    return flag
