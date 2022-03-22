import ida_typeinf
import ida_nalt
import ida_idaapi
import ida_name
#import idaapi

import re

#def get_tinfo(ea, func_flag=True):
def get_tinfo(ea):
    tif = ida_typeinf.tinfo_t()
    result = ida_nalt.get_tinfo(tif, ea)
    #if result and func_flag:
    #    result = ida_typeinf.is_type_func(tif.get_realtype())
    return tif if result else None

#def get_tinfo_by_name(name, func_flag=True):
def get_tinfo_by_name(name):
    tinfo = None
    result = ida_typeinf.get_named_type(ida_typeinf.cvar.idati, name, 0)

    if result:
        tinfo = ida_typeinf.tinfo_t()
        ret = tinfo.deserialize(ida_typeinf.cvar.idati, result[1], result[2])
        if not ret:
            return None
        #if ret and func_flag:
        #    ret = ida_typeinf.is_type_func(tinfo.get_realtype())
        #    if not ret:
        #        return None
    return tinfo

def get_local_tinfo_by_name(name, func_flag=True):
    ea = ida_name.get_name_ea(ida_idaapi.BADADDR, name)
    if ea == ida_idaapi.BADADDR:
        return None
    tinfo = ida_typeinf.tinfo_t()
    ret = ida_nalt.get_tinfo(tinfo, ea)
    if not ret:
        tinfo = None
    if ret and func_flag:
        #ret = ida_typeinf.is_type_func(tinfo.get_realtype())
        #if not ret:
        if not (tinfo.is_func() or tinfo.is_funcptr()):
            tinfo = None
    return tinfo

def apply_tinfo_to_ea(tinfo, ea, opn=0):
    if not tinfo:
        return False
    if not tinfo.is_funcptr():
        tinfo.create_ptr(tinfo)
    # why do we apply both apply_callee_tinfo & set_op_tinfo?
    # it is because set_op_tinfo() causes change in hexrays decompilation
    # apply_callee_tinfo() updates ida's stack analysis
    ida_typeinf.apply_callee_tinfo(ea, tinfo)
    # apply_callee_tinfo doesn't have return value, so we have to return the result of set_op_tinfo2.
    ret = ida_nalt.set_op_tinfo(ea, opn, tinfo)
    return ret

def get_op_tif(ea, opn=0):
    tif = ida_typeinf.tinfo_t()
    result = ida_nalt.get_op_tinfo(tif, ea, opn)
    return tif  if result else None

def comp_tifs(name, ea, opn=0):
    tif = get_op_tif(ea, opn)
    tif2 = get_tinfo_by_name(name)
    
    if _comp_tifs(tif, tif2):
        return True
    return False

def _comp_tifs(tif, tif2):
    tif2 = get_op_tif(ea, opn)
    
    if not tif2.is_funcptr():
        tif2.create_ptr(tif2)
    
    if not tif.is_funcptr():
        tif.create_ptr(tif)
    
    if tif == tif2:
        return True
    return False

def del_tinfo_from_ea(ea, opn=0):
    ida_nalt.del_op_tinfo(ea, opn)
    # remove comments and reset var names for the result of appy_callee_tinfo()?
    #for ea in ida_typeinf.get_arg_addrs(caller):
    #    print(hex(ea))


g_api_name_postfix_regex = re.compile(r'(.*)_[0-9]+$')
def get_true_name(name):
    r = g_api_name_postfix_regex.search(name)
    if r:
        grps = r.groups()
        if len(grps) > 0:
            return grps[0]
    return name

def guess_true_names(name):
    names = [name]
    removed_postfix = get_true_name(name)
    result = [name]
    if name != removed_postfix:
        names.append(removed_postfix)
        result.append(removed_postfix)
    for n in names:
        for prefix in ["_", "__", "Rtl"]:
            result.append(prefix+n)
    return result


"""
def del_op_tinfo(func_relations, func_ea, ea):
    if func_ea in func_relations:
        if ea in func_relations[func_ea]['children']:
            callee, func_type, opn, func_name = func_relations[func_ea]['children'][ea]
            if callee == ida_idaapi.BADADDR and func_name:
                ida_nalt.del_op_tinfo(ea, opn)

def get_callee_info(func_relations, caller_ea):
    f = ida_funcs.get_func(caller_ea)
    if f and f.start_ea in func_relations:
        if caller_ea in func_relations[f.start_ea]['children']:
            callee, func_type, op, func_name =  func_relations[f.start_ea]['children'][caller_ea]
            return callee, func_type, op, func_name
    return None, None, None, None
        
def apply_tif(caller, func_name):
    callee, func_type, opn, _func_name = get_callee_info(caller)
    if callee is not None:
        tif = get_tinfo_by_name(func_name)
        if tif:
            apply_tinfo_to_ea(tif, caller, opn)
                
def update_caller_tif(ea, func_name=None):
    callee_ea, func_type, opn, _func_name = get_callee_info(ea)
    if callee_ea is not None:
        if func_name is None:
            #if callee_ea == ida_idaapi.BADADDR and _func_name:
            if _func_name:
                func_name = _func_name
            else:
                func_name, func_type, v = get_func_relation.get_func_info_by_opstr(ea, opn)
        ida_nalt.del_op_tinfo(ea, opn)
        #if ea in self.dyn_apicalls:
        #    self.dyn_apicalls.pop(ea)
        get_func_relation.partial_cache_update(ea)
        if func_name:
            apply_tif(ea, func_name)
        return True
    return False
"""
