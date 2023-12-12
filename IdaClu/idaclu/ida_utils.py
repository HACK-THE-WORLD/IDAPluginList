import collections
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


def manage_dir(dir_name, operation, is_abs):
    func_dir = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_FUNCS)
    dir_ops = {
        'mkdir': False,
        'rmdir': True,
        'chdir': True
    }
    if is_abs:
        func_dir.chdir('/')
    is_dir = func_dir.isdir(dir_name)
    if is_dir if dir_ops[operation] else not is_dir:
        if operation in dir_ops.keys():
            getattr(func_dir, operation)(dir_name)
        else:
            raise Exception('%s - invalid ida_dirtree operation' % (operation))
        return True
    return False

def create_dir(dir_name, is_abs=True):
    return manage_dir(dir_name, 'mkdir', is_abs)
    
def remove_dir(dir_name, is_abs=True):
    return manage_dir(dir_name, 'rmdir', is_abs)
    
def change_dir(dir_name, is_abs=True):
    return manage_dir(dir_name, 'chdir', is_abs)

# logic / prefixes '%' and '_' are the opposites:
# 1. '%' - has always single occurence, '_' - not;
# 2. '%' cannot appear at the very beginning of a function name, '_' - can;
# 3. '%' is purely internal prefix representation, '_' - human representation;
# 4. '%' are the prefixes added automatically, '_' - manually

def get_func_prefs(func_name, is_dummy=True):
    if ((func_name.startswith('?') and '@' in func_name) or 
        func_name.startswith('_')):
        return []
    pfx_dummy = 'sub_'
    prefs = []
    pfx = ''

    idx = 0
    while idx < len(func_name):
        char = func_name[idx]
        if char == '%':
            prefs.append(pfx)
            pfx = ''

        elif char == "_":
            pfx_len = 1
            while func_name[idx+pfx_len] == '_':
                pfx_len += 1

            if idx != 0:
                # uncomment, if underscore tail in pfx is needed
                # pfx += func_name[idx:idx+pfx_len]
                if (not any(a in pfx for a in ['@', '$', '?', '-', '+']) and 
                    not re.match('^[0-9]+', pfx) and pfx != ''):
                    prefs.append(pfx)
                pfx = ''
                
            idx += pfx_len-1
        else:
            pfx += char

        idx += 1

    if not is_dummy and pfx_dummy in prefs:
        prefs.remove(pfx_dummy)
    return prefs

def get_cleaned_funcname(func_name, is_diff=False):
    bad_part = ''
    for char in func_name:
        if not char.isalpha():
            bad_part += char
        else:
            break

    if is_diff:
        return bad_part
    else:
        return func_name[len(bad_part):]

def refresh_ui():
    ida_shims.refresh_idaview_anyway()
    widget = ida_shims.get_current_widget()
    widget_vdui = ida_shims.get_widget_vdui(widget)
    if widget_vdui:
        widget_vdui.refresh_ctext()

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

def get_dir_metrics(root_dir):
    func_dir = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_FUNCS)
    ite = ida_dirtree.dirtree_iterator_t()

    s_folders = [root_dir]
    u_folders = collections.defaultdict(int)

    while len(s_folders):
        curr_path = s_folders.pop()
        func_dir.chdir(curr_path)
        status = func_dir.findfirst(ite, "*")

        while status:
            entry_name = func_dir.get_entry_name(func_dir.resolve_cursor(ite.cursor))
            cursor_abspath = func_dir.get_abspath(ite.cursor)
            if func_dir.isdir(cursor_abspath):
                current_dir_new = '{}/{}'.format('' if curr_path == '/' else curr_path, entry_name)
                s_folders.append(current_dir_new)
            elif func_dir.isfile(cursor_abspath):
                func_addr = idaapi.get_name_ea(0, entry_name)
                u_folders[curr_path] += 1   
            status = func_dir.findnext(ite)

    return list(u_folders.items())

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

def get_dir_funcs(folders, is_root=True):
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
                if is_root == False and curr_path == '/':
                    # if only the functions with non-standard dir are needed
                    pass
                else:
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

def is_in_interval(addr, func_ivals, is_strict):
    if is_strict:
        return any(beg < addr < end for beg, end in func_ivals)
    else:
        return any(beg <= addr <= end for beg, end in func_ivals)

def get_func_ivals(func_addr):
    return [(func_beg, func_end) for func_beg, func_end in ida_shims.get_chunk_eas(func_addr)]

def get_chunk_count(func_addr):
    num_chunks = len(get_func_ivals(func_addr))
    return num_chunks

def is_addr_func(addr, func_addr, is_chunks, is_strict):
    func_ivals = None
    if is_chunks:
        func_ivals = get_func_ivals(func_addr)
    else:
        func_beg = func_addr
        func_end = idc.get_func_attr(func_addr, idc.FUNCATTR_END)
        func_ivals = [(func_beg, func_end)]

    return is_in_interval(addr, func_ivals, is_strict)

def is_func_wrapper(func_addr, is_precise=True):
    """
    Wrapper functions are typically short.
    x86_64 instructions can be up to 15 bytes in length, at average - 4/5;
    The defined frame is 64b, then a very rough approximation is as follows:
        15 bytes/instr ->  4 instr/func ->  1- 2 statements (min)
         5 bytes/instr -> 12 instr/func ->  4- 6 statements
         4 bytes/instr -> 16 instr/func ->  5- 8 statements
         2 bytes/instr -> 32 instr/func -> 10-11 statements (max)
    It is not sufficient to look up solely for function size,
    important to have instruction count boundary as well,
    because of the function chunks e.g. func_size=14 bytes, inst_count=99;
    Small function with many instructions is either "super slim" function,
    or it has unaccounted chunks.
    """

    flags = ida_shims.get_func_flags(func_addr)
    func_items = list(idautils.FuncItems(func_addr))

    api_pairs = [
        ('EnterCriticalSection', 'LeaveCriticalSection'),
        ('__SEH_prolog', '__SEH_epilog'),
        ('__lock', '__unlock'),
        ('__lockexit', '__unlockexit'),
        ('__lock_fhandle', '__unlock_fhandle'),
        ('__lock_file', '__unlock_file'),
        ('__lock_file2', '__unlock_file2'),
        ('_malloc', '_free'),
        ('_calloc', '_free'),
        ('_realloc', '_free'),
        ('___initstdio', '___endstdio'),
        ('__Init_thread_header', '__Init_thread_footer'),
        ('_fopen', '_fclose'),
        ('CreateMutexA', 'ReleaseMutex'),
        ('CreateMutexW', 'ReleaseMutex'),
        ('CreateSemaphoreA', 'ReleaseSemaphore'),
        ('CreateSemaphoreW', 'ReleaseSemaphore'),
        ('CreateThread', 'ExitThread'),
        ('AcquireSRWLockExclusive ', 'ReleaseSRWLockExclusive'),
        ('InitializeSRWLock  ', 'DeleteSRWLock'),
        ('CreateFileA', 'CloseHandle'),
        ('CreateFileW', 'CloseHandle'),
        ('VirtualProtect', 'VirtualFree'),
        ('HeapAlloc', 'HeapFree'),
        ('HeapReAlloc', 'HeapFree'),
        ('HeapCreate', 'HeapDestroy'),
        ('RegOpenKeyA', 'RegCloseKey'),
        ('RegOpenKeyW', 'RegCloseKey'),
        ('TlsAlloc', 'TlsFree'),
        ('GlobalLock', 'GlobalUnlock'),
        ('BeginPaint', 'EndPaint'),
        ('OpenProcess', 'ExitProcess'),
        ('CreateWindowExA', 'DestroyWindow'),
        ('CreateWindowExW', 'DestroyWindow'),
        ('___sbh_alloc_block', '___sbh_free_block')
    ]
    api_pair_beg = [p[0] for p in api_pairs]
    api_pair_end = [p[1] for p in api_pairs]

    func_beg = func_addr
    func_end = ida_shims.get_func_attr(func_addr, idc.FUNCATTR_END)

    call_num = 0
    pair_unm = []
    call_reg = set()
    func_nam = ida_shims.get_name(func_addr)
    func_mod = set()
    func_res = False
    # exclude recursive calls
    call_reg.add(func_nam)
    for inst_addr in idautils.FuncItems(func_addr):
        if is_precise:
            mnem = ida_shims.print_insn_mnem(inst_addr)
            oprd_val = ida_shims.get_operand_value(inst_addr, 0)
            oprd_typ = ida_shims.get_operand_type(inst_addr, 0)
            if (mnem == 'jmp' and 
                not is_addr_func(oprd_val, func_addr, is_precise, True)):
                call_nam = ida_shims.get_name(oprd_val)
                # exclude jump tables;
                # consider the case when there is more than one jmp/call inst.
                # pointing to the same function: call x, call x, jmp x
                if not call_nam.startswith('loc_') and not call_nam in call_reg:
                    call_num += 1
                    call_reg.add(call_nam)

            if mnem == 'call':
                if oprd_typ in [idc.o_mem, idc.o_far, idc.o_near]:
                    call_dst = list(idautils.CodeRefsFrom(inst_addr, 0))
                    if len(call_dst):
                        call_nam = ida_shims.get_name(call_dst[0])
                        if call_nam in api_pair_beg:
                            pair_unm.append(api_pair_beg.index(call_nam))
                        elif call_nam in api_pair_end:
                            elem_idx = api_pair_end.index(call_nam)
                            if elem_idx in pair_unm:
                                # there are numerous pair APIs of the form:
                                # alloc/free, open/close, create/destroy;
                                # consider the impact of a wrapping pair as - 0
                                pair_unm.remove(elem_idx)
                            else:
                                pair_unm.append(elem_idx)
                        else:
                            if not call_nam in call_reg and not call_nam in ['j__free']:
                                call_num += 1
                                call_reg.add(call_nam)
                elif is_precise and (oprd_typ in [idc.o_displ]):
                    dasm_line = ida_shims.generate_disasm_line(inst_addr, idaapi.GENDSM_FORCE_CODE)
                    call_vft = ' '.join(' '.join(dasm_line.split()).split()[1:])
                    if not call_vft in call_reg:
                        func_mod.add("ptr")
                        call_num += 1
                        call_reg.add(call_vft)

    if (call_num + len(pair_unm)) == 1:
        func_res = True
        if ((func_end - func_addr) > 0 and (func_end - func_addr) < 64) and len(func_items) <= 32:
            func_mod.add("small")
        else:
            # an attempt to collect wrapper functions that
            # otherwise will be missed due to too strict size constraint;
            # they are not that simple, have some additional logic
            # that probably should be considered separately
            func_mod.add("large")

    return (func_res, list(func_mod))
