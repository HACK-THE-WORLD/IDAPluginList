import idc
import ida_idaapi
import ida_kernwin
import ida_ua
import ida_bytes
import ida_xref
import ida_funcs
import ida_nalt
import ida_name
import ida_lines

import traceback
import os
import sys
#import re
#import threading

import get_func_relation
import cache_data
import jump
import tinfo
import config_base
import debug_print
import comments
import cto_utils
import xor_loop_detector
import notable_mnem_finder
import notable_const_finder
import notable_inst_finder

ida_idaapi.require("get_func_relation")
ida_idaapi.require("cache_data")
ida_idaapi.require("jump")
ida_idaapi.require("tinfo")
ida_idaapi.require("config_base")
ida_idaapi.require("debug_print")
ida_idaapi.require("comments")
ida_idaapi.require("cto_utils")
ida_idaapi.require("xor_loop_detector")
ida_idaapi.require("notable_mnem_finder")
ida_idaapi.require("notable_const_finder")
ida_idaapi.require("notable_inst_finder")

FT_UNK = get_func_relation.FT_UNK
FT_GEN = get_func_relation.FT_GEN
FT_LIB = get_func_relation.FT_LIB
FT_API = get_func_relation.FT_API
FT_MEM = get_func_relation.FT_MEM
FT_VAR = get_func_relation.FT_VAR
FT_STR = get_func_relation.FT_STR
FT_STO = get_func_relation.FT_STO
FT_VTB = get_func_relation.FT_VTB

class cto_base(debug_print.debug):
    orig_title = "CTO"
    
    def __init__(self, cto_data=None, curr_view=None, debug=False):
        #super(cto_base, self).__init__(debug)
        debug_print.debug.__init__(self, debug)
        
        self.cmt_obj = comments.comment_t()

        self.decomp_avail = False
        try:
            import ida_hexrays
            self.decomp_avail = ida_hexrays.init_hexrays_plugin()
        except ImportError:
            pass
        
        # get current available widget
        self.curr_view = curr_view
        if self.curr_view is None:
            w, wt = self.get_widget()
            self.curr_view = w
        
        # it should be the first instance
        if cto_data is None:
            self.config = self._config()
            if debug:
                self.config.debug = debug
            if self.config.debug: self.dbg_print("newly created and cto_data is None")
            self.cto_data = {'cto_data':{}, 'refcnt':1, 'master':id(self), 'config': self.config, 'insts':set([self])}
            self.cd = cache_data.cache_data(self.cto_data['cto_data'], self.config, self.config.debug)
            result = self.cd.dh.load_data(self.config)
            if result:
                self.cto_data['cto_data'] = result
                self.copy_cache_data()
                if debug:
                    self.config.debug = debug
            else:
                self.update_data()
                #self.cache_update()
                if debug:
                    self.config.debug = debug
                self.cd.dh.save_data(self.cd.dh.convert_data(self.config, self.cto_data['cto_data']))
        # it has an external data
        else:
            self.cto_data = cto_data
            self.copy_cache_data()
            self.cto_data['insts'].add(self)
            self.config = self.cto_data["config"]
            if debug:
                self.config.debug = debug
            if self.config.debug: self.dbg_print("cto_data is NOT None")
            if self.config.debug: self.dbg_print(id(self), id(self.cto_data))
            # take master if ref count is less than 1. Note that, at this moment,
            # ref count is not increased yet. Do not include 1.
            if self.cto_data['refcnt'] < 1:
                if self.config.debug: self.dbg_print("took master")
                self.cto_data['master'] = id(self)
            self.cd = cache_data.cache_data(self.cto_data['cto_data'], self.config, self.config.debug)
            # if this instance is a slave, 
            if self.cto_data['master'] != id(self):
                self.cto_data["refcnt"] += 1
        
    # for potable config values for taking over subgraphs
    class _config(config_base._config_base):
        def __init__(self):
            self.get_default_config()
        
        def get_default_config(self):
            self.debug = False
            self.skip_caller = False
            self.center_node = True
            self.display_children_in_parent_funcs = False
            self.dark_mode = False
            self.show_strings_nodes = False
            self.show_gvars_nodes = False
            self.show_stroff_nodes = False
            self.show_comment_nodes = False
            self.show_indirect_calls = True
            self.auto_reload_outside_node = True
            self.save_caches = False
    
    def dbg_print(self, *msg):
        if self.config.debug:
            self._dbg_print(*msg)

    def copy_cache_data(self):
        self.func_relations = self.cto_data["cto_data"]["func_relations"]
        self.import_eas = self.cto_data["cto_data"]["import_eas"]
        self.string_eas = self.cto_data["cto_data"]["string_eas"]
        self.paths_cache = self.cto_data["cto_data"]["paths_cache"]
        self.dyn_apicalls = self.cto_data["cto_data"]["dyn_apicalls"]
        self.opnums = self.cto_data["cto_data"]["opnums"]
        self.eps = self.cto_data["cto_data"]["eps"]
        self.vtbl_refs = self.cto_data["cto_data"]["vtbl_refs"]

    def cache_cmt_update(self):
        # clear cache
        for func_ea in self.cto_data["cto_data"]["func_relations"]:
            self.cto_data["cto_data"]["func_relations"][func_ea]['cmt'] = {}
            self.cto_data["cto_data"]["func_relations"][func_ea]['rcmt'] = {}
            
        # get comments and merge them
        cmts = self.cmt_obj.collect_cmts_as_dict()
        cto_utils.deep_update(self.cto_data["cto_data"]["func_relations"], cmts)
        
        # recursive for instance
        for inst in self.cto_data["insts"]:
            inst.copy_cache_data()
            
        
    def cache_update(self):
        self.cto_data["cto_data"] = {}
        self.cto_data["cto_data"]["func_relations"], self.cto_data["cto_data"]["import_eas"], self.cto_data["cto_data"]["string_eas"] = get_func_relation.get_func_relations()
        self.cto_data["cto_data"]["paths_cache"] = {}
        self.cto_data["cto_data"]["dyn_apicalls"] = get_func_relation.get_dyn_apicalls(self.cto_data["cto_data"]["func_relations"])
        self.cto_data["cto_data"]["opnums"] = get_func_relation.get_opnums(self.cto_data["cto_data"]["func_relations"], "children")
        self.cto_data["cto_data"]["eps"] = list(get_func_relation.get_entry_points())
        self.cto_data["cto_data"]["vtbl_refs"] = get_func_relation.get_vtbl_refs(self.cto_data["cto_data"]["func_relations"])
        self.cto_data["cto_data"]["internal_caches"] = {}
        
        self.cache_cmt_update()
        
        # recursive for instance
        for inst in self.cto_data["insts"]:
            inst.copy_cache_data()
    
    def partial_cache_update(self, ea):
        f = ida_funcs.get_func(ea)
        if ea in self.func_relations:
            func_type = self.func_relations[ea]["func_type"]
            if func_type == FT_VTB:
                vtbl = {}
                for _, _ in get_func_relation.get_vtbl_methods(ea, vtbl):
                    pass
                for ea in vtbl:
                    if ea == ida_idaapi.BADADDR:
                        continue
                    parents = get_func_relation.get_xrefs(ea)
                    self.func_relations[ea] = {"parents":parents, "children":vtbl[ea], "func_type":func_type, "gvars":{}, "strings":{}, "struct_offsets":{}, "vftables":{}, "cmt":{}, "rcmt":{}}
            elif func_type == FT_API:
                parents = get_func_relation.get_xrefs(ea)
                self.func_relations[ea] = {"parents":parents, "children":{}, "func_type":func_type, "gvars":{}, "strings":{}, "struct_offsets":{}, "vftables":{}, "cmt":{}, "rcmt":{}}
            else:
                self._partial_cache_update(ea)
        elif f and f.start_ea in self.func_relations:
            self._partial_cache_update(f.start_ea)
        else:
            # updating paths cache (just removing paths related to the ea)
            self.remove_paths_cache(ea)
    
    def _partial_cache_update(self, ea):
        # updating a function that the ea belongs to.
        f, bbs = get_func_relation.get_func_bbs(ea)
        if f:
            ea = f.start_ea
        parents, children, apicalls, gvars, strings, stroff, vtbl = get_func_relation.get_family_members(ea, bbs, self.import_eas, self.string_eas)
        func_type = get_func_relation.get_func_type(ea, self.import_eas)
        self.func_relations[ea] = {"parents":parents, "children":children, "func_type":func_type, "gvars":gvars, "strings":strings, "struct_offsets":stroff, "vftables":vtbl , "cmt":{}, "rcmt":{}}
        get_func_relation.fix_parent(self.func_relations, self.vtbl_refs, ea)
        cmts = self.cmt_obj.collect_cmts_as_dict(ea)
        cto_utils.deep_update(self.func_relations, cmts)
        
        # updating apicalls that are called in the function
        for api_ea in apicalls:
            if api_ea == ida_idaapi.BADADDR:
                continue
            func_type = apicalls[api_ea]
            parents = get_func_relation.get_xrefs(api_ea)
            self.func_relations[api_ea] = {"parents":parents, "children":{}, "func_type":func_type, "gvars":{}, "strings":{}, "struct_offsets":{}, "vftables":{}, "cmt":{}, "rcmt":{}}
            
        # updating vftables that are called in the function
        for vtbl_ea in vtbl:
            if vtbl_ea == ida_idaapi.BADADDR:
                continue
            func_type = FT_VTB
            parents = get_func_relation.get_xrefs(vtbl_ea)
            self.func_relations[vtbl_ea] = {"parents":parents, "children":vtbl[vtbl_ea], "func_type":func_type, "gvars":{}, "strings":{}, "struct_offsets":{}, "vftables":{}, "cmt":{}, "rcmt":{}}
            
        # updating dyn_apicalls table
        if ea in self.dyn_apicalls:
            self.dyn_apicalls.pop(ea)
        for caller, func_name in get_func_relation.get_dyn_apicalls_partial(self.func_relations, ea):
            self.dyn_apicalls[caller] = func_name
            
        # updating paths cache (just removing paths related to the ea)
        self.remove_paths_cache(ea)
            
    def remove_paths_cache(self, ea):
        to_be_removed = set([])
        for k in self.paths_cache:
            if ea in [k[0], k[1]]:
                to_be_removed.add(k)
            else:
                for path in self.paths_cache[k]:
                    for p in path:
                        if ea in [p[0], p[1]]:
                            to_be_removed.add(k)
                            break
        for k in to_be_removed:
            self.paths_cache.pop(k)
        #self.cd.dh.save_data(self.cd.dh.convert_data(self.config, self.cto_data['cto_data']))
            
    # update data online
    def update_data(self):
        # check the refcount
        if self in self.cto_data['insts']:
            if self.cto_data["refcnt"] <= 1 or self.cto_data["master"] == id(self):
                # raise to the master if recount == 1
                if self.config.debug: self.dbg_print("took over the master to the %d" % self.cto_data["master"])
                self.cto_data["master"] = id(self)
                
            self.cache_update()
            #self.cd.dh.save_data(self.cd.dh.convert_data(self.config, self.cto_data['cto_data']))
    
    def close_data(self):
        if self in self.cto_data['insts']:
            # decrease the refcount
            self.cto_data['refcnt'] -= 1
            if self.config.debug: self.dbg_print(id(self), id(self.cto_data), self.cto_data['refcnt'])
            # remove instance from the cached data
            self.cto_data['insts'].remove(self)
            if self.cto_data["refcnt"] <= 1 or self.cto_data["master"] == id(self) or len(self.cto_data['insts']) == 0:
                # save the pickle
                if self.config.debug: self.dbg_print("save pickle")
                self.cd.dh.save_data(self.cd.dh.convert_data(self.config, self.cto_data['cto_data']))
            if self.cto_data["master"] == id(self) and len(self.cto_data['insts']) > 0:
                self.cto_data["master"] = id(next(iter(self.cto_data['insts'])))
                if self.config.debug: self.dbg_print("took over the master to the %d" % self.cto_data["master"])
                
    def __del__(self):
        if self.config.debug: self.dbg_print("close_data was called")
        self.close_data()
            
    #def refresh(self, ea=ida_idaapi.BADADDR):
    #    self.refresh_all(ea)
    
    def refresh(self, ea=ida_idaapi.BADADDR, center=False):
        pass
    
    def refresh_all(self, ea=ida_idaapi.BADADDR, center=False):
        for inst in self.cto_data['insts']:
            inst.refresh(ea, center)
            
    def _jumpto(self, ea, use_opn=False):
        w, wt = self.get_widget()
        flag = False
        ida_kernwin.jumpto(ea)
        if ea in self.func_relations and not use_opn:
            flag = jump.jumpto_name(ea, w)
        elif ea in self.opnums:
            opn = self.opnums[ea]
            if opn >= 0:
                flag = jump.jumpto_opn(ea, opn, w)
            else:
                # find offset line for vftable funcs
                flag = jump.jumpto_offset(ea, w)
                
        # for others such as referenced strings in an instruction
        else:
            flags = ida_bytes.get_flags(ea)
            if idc.is_code(flags):
                # for strings in funcs and other variables in funcs
                insn = ida_ua.insn_t()
                inslen = ida_ua.decode_insn(insn, ea)
                for opn in range(inslen):
                    if ida_ua.o_void == insn.ops[opn].type:
                        opn = -1
                        break
                    flag = jump.jumpto_opn(ea, opn, w)
                    if flag:
                        break
            else:
                flag = jump.jumpto_name(ea, w)
        return flag

    def jumpto(self, ea, use_opn=False):
        r = False
        try:
            r = self._jumpto(ea, use_opn)
        except Exception as e:
            exc_type, exc_obj, tb = sys.exc_info()
            lineno = tb.tb_lineno
            ida_kernwin.msg("Got a unexpected error (%s: %s) (%d)%s" % (str(type(e)), e, lineno, os.linesep))
            if self.config.debug:
                self.dbg_print(traceback.format_exc())
            else:
                traceback.print_exc()
        return r
    
    def push_lochist_jump(self, w=None):
        r = False
        try:
            r = jump.push_lochist_jump(w)
        except Exception as e:
            exc_type, exc_obj, tb = sys.exc_info()
            lineno = tb.tb_lineno
            ida_kernwin.msg("Got a unexpected error (%s: %s) (%d)%s" % (str(type(e)), e, lineno, os.linesep))
            if self.config.debug:
                self.dbg_print(traceback.format_exc())
            else:
                traceback.print_exc()
        return r
    
    def check_and_rename_var(self):
        flag = True
        w, wt = self.get_widget()
        if wt == ida_kernwin.BWN_DISASM:
            flag = self.check_and_rename_var_ida(w)
        elif wt == ida_kernwin.BWN_PSEUDOCODE:
            flag = self.check_and_rename_var_decomp(w)
        return flag
    
    def check_and_rename_var_decomp(self, w):
        highlight, vu = jump.get_highlight_decomp(w)
        if highlight:
            line = jump.get_current_line_decomp(highlight, vu)
        else:
            return False
        if line is None:
            return False
        self.dbg_print(line)
        
        self.exec_ida_ui_action("hx:Rename")
        
        highlight, vu = jump.get_highlight_decomp(w)
        if highlight:
            curr_line = jump.get_current_line_decomp(highlight, vu)
        else:
            return False
        self.dbg_print(curr_line)
        if line != curr_line:
            ea = ida_kernwin.get_screen_ea()
            self.dbg_print("Refreshing")
            self.refresh_all(ea)
        else:
            return False
        return True
        
    def check_and_rename_var_ida(self, w):
        ea = ida_kernwin.get_screen_ea()
        self.dbg_print("%x" % ea)
        name = self.get_highlighted_name(ea, w=w)
        self.dbg_print(name)
        line = ida_lines.tag_remove(ida_kernwin.get_curline())
        #line = ida_kernwin.get_curline()
        op = None
        if ea in self.opnums:
            op = idc.print_operand(ea, self.opnums[ea])
        self.exec_ida_ui_action("MakeName")
        curr_name = self.get_highlighted_name(ea, w=w)
        #ida_kernwin.refresh_idaview_anyway()
        #curr_line = ida_kernwin.get_curline()
        curr_op = None
        if ea in self.opnums:
            curr_op = idc.print_operand(ea, self.opnums[ea])
        self.dbg_print(curr_name)
        curr_line = ida_lines.tag_remove(ida_kernwin.get_curline())
        if name != curr_name or line != curr_line:
            self.dbg_print("Start refreshing")
            self.refresh_all(ea)
        # for renaming a struct member
        #elif line != curr_line or curr_op != op:
        elif curr_op != op:
            self.dbg_print("Start refreshing", curr_op, op)
            callee, func_type, opn, _func_name = self.get_callee_info(ea)
            if callee is not None:
                optype = idc.get_operand_type(ea, opn)
                if optype in [ida_ua.o_displ, ida_ua.o_phrase]:
                    self.update_caller_tif(ea)
                      #self.exec_ui_action("EmptyStack")
                    self.refresh_all(ea)
        else:
            self.dbg_print("Not changed")
            return False
        return True

    def check_and_rename_func_info(self):
        flag = True
        w, wt = self.get_widget()
        if wt == ida_kernwin.BWN_DISASM:
            flag = self.check_and_rename_func_info_ida(w)
        elif wt == ida_kernwin.BWN_PSEUDOCODE:
            pass
        return flag
    
    def check_and_rename_func_info_ida(self, w):
        ea = ida_kernwin.get_screen_ea()
        name = self.get_highlighted_name(ea, w=w)
        line = ida_lines.tag_remove(ida_kernwin.get_curline())
        self.exec_ida_ui_action("EditFunction")
        #ida_kernwin.refresh_idaview_anyway()
        curr_name = self.get_highlighted_name(ea, w=w)
        curr_line = ida_lines.tag_remove(ida_kernwin.get_curline())
        if name != curr_name or line != curr_line:
            self.refresh_all(ea)
        return True
            
    def check_and_add_rcmt(self):
        flag = True
        w, wt = self.get_widget()
        if wt == ida_kernwin.BWN_DISASM:
            flag = self.check_and_add_rcmt_ida()
        elif wt == ida_kernwin.BWN_PSEUDOCODE:
            pass
        return flag
    
    def check_and_add_rcmt_ida(self):
        # repeatable comment
        ea = ida_kernwin.get_screen_ea()
        rcmt = ida_bytes.get_cmt(ea, 1)
        self.exec_ida_ui_action("MakeRptCmt")
        #ida_kernwin.refresh_idaview_anyway()
        curr_rcmt = ida_bytes.get_cmt(ea, 1)
        if rcmt != curr_rcmt:
            self.partial_cache_update(ea)
            #self.exec_ui_action("EmptyStack")
            self.refresh_all(ea)
        return True
            
    def check_and_add_cmt(self):
        flag = True
        w, wt = self.get_widget()
        if wt == ida_kernwin.BWN_DISASM:
            flag = self.check_and_add_cmt_ida()
        elif wt == ida_kernwin.BWN_PSEUDOCODE:
            pass
        return flag
    
    def check_and_add_cmt_ida(self):
        # comment
        ea = ida_kernwin.get_screen_ea()
        cmt = ida_bytes.get_cmt(ea, 0)
        self.exec_ida_ui_action("MakeComment")
        #ida_kernwin.refresh_idaview_anyway()
        curr_cmt = ida_bytes.get_cmt(ea, 0)
        if cmt != curr_cmt:
            self.update_caller_tif(ea, curr_cmt)
            #self.exec_ui_action("EmptyStack")
            #self.refresh()
            self.partial_cache_update(ea)
            self.refresh_all(ea, center=True)
        return True
            
    def check_and_apply_strunct(self):
        flag = True
        w, wt = self.get_widget()
        if wt == ida_kernwin.BWN_DISASM:
            flag = self.check_and_apply_strunct_ida()
        elif wt == ida_kernwin.BWN_PSEUDOCODE:
            pass
        return flag
    
    def check_and_apply_strunct_ida(self):
        # apply structure
        ea = ida_kernwin.get_screen_ea()
        line = ida_kernwin.get_curline()
        self.exec_ida_ui_action("OpStructOffset")
        #ida_kernwin.refresh_idaview_anyway()
        curr_line = ida_kernwin.get_curline()
        #f = ida_funcs.get_func(ea)
        if line != curr_line:
            self.update_caller_tif(ea)
            #self.exec_ui_action("EmptyStack")
            #self.refresh_with_center_node()
            self.refresh_all(ea, center=True)
            #self.refresh()
        return True
            
    def check_xrefs(self):
        # show xrefs to
        self.exec_ida_ui_action("JumpOpXref")
        
    def add_cref(self, ea, func_chooser_t):
        fc = func_chooser_t("Choose the destination", self)
        selected = fc.Show(modal=True)
        if selected >= 0:
            callee_ea, func_name = fc.items[selected]
            callee_ea = int(callee_ea, 16)
            func_type = get_func_relation.get_func_type(callee_ea, self.import_eas)
            cref_type = 0
            optype = idc.get_operand_type(ea, 0)
            if optype in [ida_ua.o_reg, ida_ua.o_displ, ida_ua.o_phrase] and get_func_relation.is_call_insn(ea):
                if func_type == FT_GEN:
                    cref_type = ida_xref.fl_CN
                elif func_type in [FT_LIB, FT_API]:
                    cref_type = ida_xref.fl_CF
            elif (get_func_relation.is_indirect_jump_insn(ea) and not get_func_relation.get_switch_info(ea)):
                if func_type == FT_GEN:
                    cref_type = ida_xref.fl_JN
                elif func_type in [FT_LIB, FT_API]:
                    cref_type = ida_xref.fl_JF
            else:
                ida_kernwin.msg("Do it on a indirecet calls or jumps" + os.linesep)
            if cref_type > 0:
                r = ida_xref.add_cref(ea, callee_ea, cref_type|ida_xref.XREF_USER)
                self.apply_tif(ea, func_name)
                return True
        return False
        
    def del_cref(self, ea, cref_chooser_t):
        fc = cref_chooser_t("Choose the destination", self, ea)
        selected = fc.Show(modal=True)
        if selected >= 0:
            callee_ea, _ = fc.items[selected]
            callee_ea = int(callee_ea, 16)
            ida_xref.del_cref(ea, callee_ea, 0)
            f = ida_funcs.get_func(ea)
            if f:
                self.del_op_tinfo(f.start_ea, ea)
            return True
        return False
        
    def del_op_tinfo(self, func_ea, ea):
        if func_ea in self.func_relations:
            if ea in self.func_relations[func_ea]['children']:
                callee, func_type, opn, func_name = self.func_relations[func_ea]['children'][ea]
                if callee == ida_idaapi.BADADDR and func_name:
                    ida_nalt.del_op_tinfo(ea, opn)
        
    def get_callee_info(self, caller_ea):
        f = ida_funcs.get_func(caller_ea)
        if f and f.start_ea in self.func_relations:
            if caller_ea in self.func_relations[f.start_ea]['children']:
                callee, func_type, op, func_name =  self.func_relations[f.start_ea]['children'][caller_ea]
                return callee, func_type, op, func_name
        return None, None, None, None
        
    def apply_tif(self, caller, func_name):
        callee, func_type, opn, _func_name = self.get_callee_info(caller)
        if callee is not None:
            tif = tinfo.get_tinfo_by_name(func_name)
            if tif:
                tinfo.apply_tinfo_to_ea(tif, caller, opn)
                
    def update_caller_tif(self, ea, func_name=None):
        callee_ea, func_type, opn, _func_name = self.get_callee_info(ea)
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
            self.partial_cache_update(ea)
            if func_name:
                self.apply_tif(ea, func_name)
            return True
        return False
    
    def get_func_name(self, ea):
        f = ida_funcs.get_func(ea)
        func_name = ""
        if ea in self.opnums:
            opn = self.opnums[ea]
            if opn >= 0:
                v = idc.get_operand_value(ea, opn)
                func_name = ida_funcs.get_func_name(v)
                if not func_name:
                    func_name = ida_name.get_name(v)
        elif f and f.start_ea == ea:
            func_name = ida_funcs.get_func_name(ea)
        if not func_name:
            func_name = ida_name.get_name(ea)
        func_name = ida_name.validate_name(func_name, ida_name.VNT_VISIBLE)
        return func_name
    
    def _get_highlighted_name(self, ea, w):
        if w is None:
            return ""
        hl = ida_kernwin.get_highlight(w)
        self.dbg_print(hl)
        name = ""
        if hl is not None:
            for opn in range(2):
                v = idc.get_operand_value(ea, opn)
                fn = ida_name.get_name(v)
                if fn:
                    fn = ida_lines.tag_remove(fn)
                    fn = ida_name.validate_name(fn, ida_name.VNT_VISIBLE)
                    if fn == hl[0]:
                        name = fn
                        break
            if not name:
                fn = self.get_func_name(ea)
                #fn = ida_name.validate_name(fn, ida_name.VNT_VISIBLE)
                self.dbg_print("fn: %s" % fn)
                if fn == hl[0]:
                    name = fn
        return name
    
    def get_highlighted_name(self, ea, w=None):
        if w is None:
            return ""
        return self._get_highlighted_name(ea, w)
    
    def get_widget(self):
        w, wt = cto_utils.get_widget(curr_view=self.curr_view)
        return w, wt
    
    def get_focus(self, w=None):
        if w is None:
            w = self.GetWidget()
        if w is None:
            return False
        return ida_kernwin.activate_widget(w, True)
    
    def _exec_ui_action(self, action, w):
        if w is None:
            return False
        ida_kernwin.activate_widget(w, True)
        ida_kernwin.process_ui_action(action)
        return True
            
    def exec_ui_action(self, action, w=None):
        return self._exec_ui_action(action, w)

    def does_use_opn(self):
        return False
    
    def exec_ida_ui_action(self, action):
        ea = ida_kernwin.get_screen_ea()
        self.jumpto(ea, self.does_use_opn())
        #w = ida_kernwin.find_widget(self.ida_view)
        w, wt = self.get_widget()
        return self.exec_ui_action(action, w=w)
        
    def print_config_info(self):
        for k in self.config:
            ida_kernwin.msg("%s: %s%s" % (k, str(self.config[k]), os.linesep))
        ida_kernwin.msg("max_depth: %d%s" % (self.max_depth, os.linesep))
        ida_kernwin.msg("start_ea: %x%s" %  (self.start_ea, os.linesep))
        
    def find_xor_loop(self):
        ida_kernwin.msg("Checking XOR instruction in a loop...%s" % (os.linesep))
        for func_ea, ea, annotation_type in xor_loop_detector.find_xor_loop(rename=True):
            ida_kernwin.msg("%x: %s, %x: %s%s" % (func_ea, annotation_type, ea, idc.generate_disasm_line(ea, 0), os.linesep))
        self.cache_cmt_update()
        self.refresh_all()

    def find_notable_mnem(self):
        ida_kernwin.msg("Checking notable mnemonics...%s" % (os.linesep))
        c = notable_mnem_finder.notable_mnem_t()
        for ea, mnem_type, dst_ea in c.mnem_handlers():
            ida_kernwin.msg("%x: %s, %x%s" % (ea, mnem_type, dst_ea, os.linesep))
        self.cache_cmt_update()
        self.refresh_all()
        
    def find_notable_const(self):
        ida_kernwin.msg("Checking notable immediate values...%s" % (os.linesep))
        c = notable_const_finder.notable_const_t()
        for func_ea, const_ea, val, rule_name in c.collect_notable_consts():
            ida_kernwin.msg("%x %x, %x, %s%s" % (func_ea, const_ea, val, rule_name, os.linesep))
        self.cache_cmt_update()
        self.refresh_all()
        
    def find_notable_inst(self):
        ida_kernwin.msg("Checking notable instructions...%s" % (os.linesep))
        i = notable_inst_finder.notable_inst_t()
        for inst_ea, rule_name, disasm in i.collect_notable_insts():
            ida_kernwin.msg("%x: %s: %s%s" % (inst_ea, rule_name, disasm, os.linesep))
        self.cache_cmt_update()
        self.refresh_all()
        
    def change_widget_icon(self, icon_data=None, bg_change=False, w=None):
        if icon_data is None:
            icon_data = self.icon.icon_data
        if w is None:
            w = self.GetWidget()
        return self.icon.change_widget_icon(w, icon_data, bg_change)
        
    @staticmethod
    def get_main_window():
        try:
            from PyQt5 import QtWidgets
        except ImportError:
            return None
        
        widget = QtWidgets.QApplication.activeWindow()
        QtWidgets.QApplication.focusWidget()
        for widget in [QtWidgets.QApplication.activeWindow(), QtWidgets.QApplication.focusWidget()] + QtWidgets.QApplication.topLevelWidgets():
            while widget:
                if isinstance(widget, QtWidgets.QMainWindow):
                    break
                widget = widget.parent()
            if isinstance(widget, QtWidgets.QMainWindow):
                return widget
        return None
    
    @staticmethod
    def _is_dark_mode(bgcolor, threshold=128):
        if bgcolor >= 0:
            alpha = bgcolor >> 24
            bgcolor &= 0xffffff
            green = bgcolor >> 16
            blue = (bgcolor >> 8) & 0xff
            red = bgcolor & 0xff
            #print("%x, %x, %x, %x, %x" % (bgcolor, green, blue, red, alpha))
            if green < threshold and blue < threshold and red < threshold:
                return True
        return False
    
    def is_dark_mode(self, w=None):
        return is_dark_mode_with_main()
    
    @staticmethod
    def is_dark_mode_with_main():
        try:
            from PyQt5 import QtWidgets
        except ImportError:
            return False

        widget = cto_base.get_main_window()
        if not isinstance(widget, QtWidgets.QMainWindow):
            return False
        bgcolor = cto_base.get_bgcolor(x=0, y=0, w=widget)
        if bgcolor < 0:
            return False
        return cto_base._is_dark_mode(bgcolor)
        
    @staticmethod
    def get_bgcolor(x=0, y=0, w=None):
        bgcolor = -1
        if w is None:
            return bgcolor
        
        try:
            import sip
            from PyQt5 import QtCore
            from PyQt5 import QtWidgets
            from PyQt5 import QtGui
        except ImportError:
            return bgcolor
        
        if str(w).startswith("<Swig Object of type 'TWidget *' at") and str(type(w)) in ["<class 'SwigPyObject'>", "<type 'SwigPyObject'>"]: # type: for py2, class: for py3
            widget = sip.wrapinstance(int(w), QtWidgets.QWidget)
        else:
            widget = w
            
        pixmap = widget.grab(QtCore.QRect(x, y, x+1, y+1))
        image = QtGui.QImage(pixmap.toImage())
        bgcolor = image.pixel(0, 0)
        
        return bgcolor
        
