import ida_xref
import ida_funcs
import ida_gdl
import ida_idaapi
import ida_kernwin
import ida_strlist
import ida_bytes
import ida_segment

import sys

try:
    import collections.abc as colls
except ImportError:
    import collections as colls

def get_strlist_items():
    si = ida_strlist.string_info_t()
    for i in range(ida_strlist.get_strlist_qty()):
        if ida_strlist.get_strlist_item(si, i):
            yield si

def get_str_content(si):
    strbytes = ida_bytes.get_strlit_contents(si.ea, si.length, si.type, ida_bytes.STRCONV_ESCAPE)
    if sys.version_info.major >= 3:
         return strbytes.decode("UTF-8", "replace")
    else:
         return strbytes
    return strbytes

def get_str_content_by_ea(ea):
    result = None
    for si in get_strlist_items():
        if si.ea == ea:
            result = get_str_content(si)
            break
    return result

def deep_update(source, overrides):
    """
    Update a nested dictionary or similar mapping.
    Modify ``source`` in place.
    """
    for key, value in overrides.items():
        if key in source and type(source[key]) != type(value):
            print("Error! Couldn't merge because the types of source and dest values are different. Key:", key, type(source[key]), type(value)) 
        elif isinstance(value, colls.Mapping):
            if value:
                if key in source:
                    deep_update(source.get(key, {}), value)
                else:
                    source[key] = value
            else:
                source[key] = value
        elif isinstance(value, list):
            source[key] = (source.get(key, []) + value)
        elif isinstance(value, tuple):
            source[key] = (source.get(key, ()) + value)
        elif isinstance(value, set):
            source[key] = (source.get(key, set([])).union(value))
        else:
            source[key] = overrides[key]

g_wname = "IDA View-A"
g_decomp_name = "Pseudocode-A"
def get_widget(ida_view=g_wname, decomp_view=g_decomp_name, curr_view=None):
    w = ida_kernwin.get_current_widget()
    wt = ida_kernwin.BWN_UNKNOWN
    if w:
        wt = ida_kernwin.get_widget_type(w)
        if wt == ida_kernwin.BWN_DISASM:
            pass
        elif wt == ida_kernwin.BWN_PSEUDOCODE:
            pass
        else:
            if curr_view:
                w = curr_view
            else:
                w = ida_kernwin.find_widget(decomp_view)
            if w:
                wt = ida_kernwin.get_widget_type(w)
            else:
                w = ida_kernwin.find_widget(ida_view)
                if w:
                    wt = ida_kernwin.get_widget_type(w)
                else:
                    wt = ida_kernwin.BWN_UNKNOWN
    return w, wt

def get_xrefs(ea):
    next_addr = ida_xref.get_first_cref_to(ea)
    while next_addr != ida_idaapi.BADADDR:
        yield next_addr
        next_addr = ida_xref.get_next_cref_to(ea,next_addr)

def count_xref(ea):
    return len(list(get_xrefs(ea)))

def count_bbs(ea):
    f = ida_funcs.get_func(ea)
    if f:
        fc = ida_gdl.FlowChart(f)
        #print("%x" % ea, list(fc))
        return len(list(fc))
    return 0

def is_64bit(ea):
    flag = False
    seg = ida_segment.getseg(ea)
    if seg and seg.use64():
        flag = True
    return flag

def is_32bit(ea):
    flag = False
    seg = ida_segment.getseg(ea)
    if seg:
        if hasattr(seg, "use32"):
            if seg.use32():
                flag = True
        else:
            if not is_64bit(ea):
                flag = True
    return flag
