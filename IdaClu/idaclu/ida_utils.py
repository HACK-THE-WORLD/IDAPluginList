import re
#
import idc
import idaapi
import idautils

# new backward-incompatible modules
try:
    import ida_dirtree
    from ssdeep import (
        hash as ssdeep_hash,
        compare as ssdeep_compare
    )
    from tlsh import (
        hash as tlsh_hash,
        diff as tlsh_diff
    )
except ImportError:
    pass

from idaclu import ida_shims

# logic / prefixes '%' and '_' are the opposites:
# 1. '%' - has always single occurence, '_' - not;
# 2. '%' cannot appear at the very beginning of a function name, '_' - can;
# 3. '%' is purely internal prefix representation, '_' - human representation;
# 4. '%' are the prefixes added automatically, '_' - manually

def get_func_prefs(func_name, is_dummy=True):
    pfx_dummy = 'sub_'
    prefs = []
    pfx = ''

    idx = 0
    while idx < len(func_name):
        char = func_name[idx]
        if char == '%':
            prefs.append('{}_'.format(pfx))
            pfx = ''

        elif char == "_":
            pfx_len = 1
            while func_name[idx+pfx_len] == '_':
                pfx_len += 1

            if idx != 0:
                pfx += func_name[idx:idx+pfx_len]
                if (not any(a in pfx for a in ['@', '$', '?', '-', '+']) and 
                    not re.match('^[0-9]+_', pfx)):
                    prefs.append(pfx)
                pfx = ''
                
            idx += pfx_len-1
        else:
            pfx += char

        idx += 1

    if not is_dummy and pfx_dummy in prefs:
        prefs.remove(pfx_dummy)
    return prefs

def refresh_ui():
    ida_shims.refresh_idaview_anyway()
    widget = ida_shims.get_current_widget()
    widget_vdui = ida_shims.get_widget_vdui(widget)
    if widget_vdui:
        widget_vdui.refresh_ctext()

def create_folder(merge_name):
    func_dir = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_FUNCS)
    func_dir.chdir('/')
    if not func_dir.isdir(merge_name):
        func_dir.mkdir(merge_name)
        return True
    return False

def graph_down(ea, path=set()):
    path.add(ea)
    call_instructions = []
    for address in idautils.FuncItems(ea):
        if not ida_shims.decode_insn(address):
            continue
        if not idaapi.is_call_insn(address):
            continue
        call_instructions.append(address)

    for x in call_instructions:
        for r in idautils.XrefsFrom(x, idaapi.XREF_FAR):
            if not r.iscode:
                continue
            func = idaapi.get_func(r.to)
            if not func:
                continue
            if (func.flags & (idaapi.FUNC_THUNK | idaapi.FUNC_LIB)) != 0:
                continue
            if r.to not in path:
                graph_down(r.to, path)
    return path

def recursive_prefix(addr):
    func_addr = ida_shims.get_name_ea(idaapi.BADADDR, ida_shims.get_func_name(addr))
    if func_addr == idaapi.BADADDR:
        ida_shims.msg("ERROR: function is not defined at 0x%08X\n" % addr)
        return
    nodes_xref_down = graph_down(func_addr, path=set([]))
    return nodes_xref_down

def get_nodes_edges(func_addr):
    func = idaapi.get_func(func_addr)
    g = idaapi.FlowChart(func)

    node_count = len(list(g))
    edge_count = 0
    for x in g:
        succ_count = len(list(x.succs()))
        pred_count = len(list(x.preds()))
        edge_count += (succ_count + pred_count)
    return (node_count, edge_count)

def get_func_ea_by_ref(func_ref):
    if isinstance(func_ref, int):
        return func_ref
    elif isinstance(func_ref, str):
        return idc.get_name_ea_simple(func_ref)
    elif isinstance(func_ref, func_t):
        return func_ref.start_ea

def get_func_item_eas(func_ref):
    func_ea = get_func_ea_by_ref(func_ref)
    for item_ea in list(idautils.FuncItems(func_ea)):
        if idaapi.is_code(ida_shims.get_full_flags(func_ea)):
            yield item_ea

def get_func_item_eas_once(func_ref):
    item_eas = []
    for ea in get_func_item_eas(func_ref):
        item_eas.append(ea)
    return item_eas

def get_func_set_attrs(fn_start=['sub_'], is_fn_start=True, attrs=['indx','addr','name', 'size', 'attr']):
    for func_idx, func_addr in enumerate(idautils.Functions()):
        func_name = ida_shims.get_func_name(func_addr)
        func_attr = idc.get_func_attr(func_addr, idc.FUNCATTR_FLAGS)
        func_desc = idaapi.get_func(func_addr)
        func_size = ida_shims.calc_func_size(func_desc)
        if any(func_name.startswith(pat) == is_fn_start for pat in fn_start):  # all ??
            attr_set = ()
            if 'indx' in attrs:
                attr_set += (func_idx,)
            if 'addr' in attrs:
                attr_set += (func_addr,)
            if 'name' in attrs:
                attr_set += (func_name,)
            if 'size' in attrs:
                attr_set += (func_size,)
            if 'attr' in attrs:
                attr_set += (func_attr,)
            yield attr_set


def is_function_solved(func_ref):
    EXPL_CALL_ARTS = [
        'call sub_',
        'call _',
        'call ds:',
        'call nullsub_',
        'call loc_',
        'call off_',
        'call j_j__',
        'call ??',
        ';',
        'jmp',
        'jz short sub_'
    ]

    func_ea = get_func_ea_by_ref(func_ref)
    item_eas = get_func_item_eas_once(func_ea)
    for item_idx, item_ea in enumerate(item_eas):
        if ida_shims.ua_mnem(item_ea) == 'call':
            item_dasm = idc.generate_disasm_line(item_ea, idaapi.GENDSM_FORCE_CODE)
            item_dasm_norm = ' '.join(item_dasm.split())
            if not any(item_dasm_norm.startswith(art) for art in EXPL_CALL_ARTS) and ' ; ' not in item_dasm:
                return False
    else:
        return True


def is_function_leaf(func_ref):
    func_ea = get_func_ea_by_ref(func_ref)
    item_eas = [item_ea for item_ea in get_func_item_eas(func_ea)]
    for item_ea in item_eas:
        if ida_shims.ua_mnem(item_ea) == 'call':
            return False
    else:
        if ida_shims.ua_mnem(item_eas[-1]) == 'jmp':
            return False
        else:
            return True  # until some "calling activity" is discovered inside,
                         # each function is considered as a "leaf"-function

def get_func_dirs(root_dir):
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

def get_func_name(func_ref):
    func_name = None
    if isinstance(func_ref, str):
        func_name = func_ref
    elif isinstance(func_ref, int):
        func_name = ida_shims.get_func_name(func_ref)
    else:
        raise ValueError("Invalid func reference")
    return func_name

def get_folder_norm(folder):
    return '' if folder == '/' else folder

def set_func_folder(func_ref, folder_src, folder_dst):
    func_name = get_func_name(func_ref)
    func_src = '{}/{}'.format(get_folder_norm(folder_src), func_name)
    func_dst = '{}/{}'.format(get_folder_norm(folder_dst), func_name)

    func_dir = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_FUNCS)
    func_dir.chdir('/')
    func_dir.rename(func_src, func_dst)

def change_dir(dir):
    func_dir = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_FUNCS)
    func_dir.chdir(dir)
