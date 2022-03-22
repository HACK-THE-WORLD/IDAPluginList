import ida_kernwin
import ida_ua
import ida_idaapi
import ida_funcs
import ida_name
import ida_bytes
import ida_lines
import idc

import os
import sys
import traceback

# Temoprary classes for UI and view hooks.
# Their classes are only available in init function to avoid to forget unhooking and deleting.
# Their instances are available while CallTreeOverviewer instance is available because they are generated at the end of init function below.
class my_ui_hooks_t(ida_kernwin.UI_Hooks):
    def __init__(self, g):
        ida_kernwin.UI_Hooks.__init__(self)
        self.hook()
        # let's use weakrefs, so as soon as the last ref to
        # the 'CallTreeOverviewer' instance is dropped, the 'my_ui_hooks_t'
        # instance hooks can be automatically un-hooked, and deleted.
        # (in other words: avoid circular reference.)
        import weakref
        self.v = weakref.ref(g)
        self.cmdname = "<no command>"
        self.ctx = None
        self.cur_ea = ida_idaapi.BADADDR
        self.cur_func = None
        self.cur_value = ida_idaapi.BADADDR
        self.func_name = ""
        self.value_name = ""
        self.make_name_line = ""
        self.func_cmt = ""
        self.cmt = ""
        self.func_rcmt = ""
        self.rcmt = ""
        self.line = ""
        self.func = None
        
        self.decomp_avail = False
        try:
            import ida_hexrays
            self.decomp_avail = ida_hexrays.init_hexrays_plugin()
        except ImportError:
            pass
        
    def _log(self, *msg):
        ida_kernwin.msg(">>> MyUiHook: %s%s" % (" ".join([str(x) for x in msg], os.linesep)))
        
    def current_widget_changed(self, widget, prev_widget):
        wt = ida_kernwin.get_widget_type(widget)
        if wt in [ida_kernwin.BWN_DISASM, ida_kernwin.BWN_PSEUDOCODE]:
            self.v().curr_view = widget
            
    def widget_closing(self, widget):
        wt = ida_kernwin.get_widget_type(widget)
        if wt in [ida_kernwin.BWN_DISASM, ida_kernwin.BWN_PSEUDOCODE]:
            self.v().curr_view = None
            
    def is_ea_to_be_processed(self, ea):
        r = False
        if hasattr(self.v(), "nodes"):
            if ea in self.v().nodes:
                r = True
        f = ida_funcs.get_func(ea)
        if ea in self.v().func_relations:
            r = True
        elif f and f.start_ea in self.v().func_relations:
            for k in self.v().func_relations[f.start_ea]:
                if k == "func_type":
                    continue
                if ea in self.v().func_relations[f.start_ea][k]:
                    r = True
                    break
                if ea in [self.v().func_relations[f.start_ea][k][x][0] for x in self.v().func_relations[f.start_ea][k] if len(self.v().func_relations[f.start_ea][k][x]) > 0 and isinstance(self.v().func_relations[f.start_ea][k][x], tuple)]:
                    r = True
                    break
        elif ea in self.v().import_eas:
            r = True
        elif ea in self.v().string_eas:
            r = True
        return r
    
    def is_ea_to_be_processed_cmt(self, ea):
        r = False
        f = ida_funcs.get_func(ea)
        if f and f.start_ea in self.v().func_relations:
            r = True
        elif ea in self.v().import_eas:
            r = True
        return r
    
    def preprocess_action(self, name):
        self._log("IDA preprocessing command: %s" % name)
        self.cmdname = name
        if self.v().cto_data["master"] != id(self.v()):
            return 0
        ea = ida_kernwin.get_screen_ea()
        f = ida_funcs.get_func(ea)
        if self.cmdname == 'hx:Rename' and self.decomp_avail and self.is_ea_to_be_processed(ea):
            try:
                import ida_hexrays
            except ImportError:
                return 0
            w, wt = self.v().get_widget()
            if f and f.start_ea == ea and self.cur_func is not None:
                if hasattr(self.cur_func, "start_ea") and self.cur_func.start_ea == ea:
                    self.func_name = ida_funcs.get_func_name(ea)
            elif w and wt == ida_kernwin.BWN_PSEUDOCODE:
                vu = ida_hexrays.get_widget_vdui(w)
                cfunc = vu.cfunc
                vu.get_current_item(ida_hexrays.USE_KEYBOARD)
                if vu.item.is_citem():
                    highlight = vu.item.e
                    if(highlight and highlight.is_expr()):
                        hl_str = highlight.print1(None)
                        self.value_name = ida_lines.tag_remove(hl_str)
        elif self.cmdname == 'MakeName' and self.is_ea_to_be_processed(ea):
            if f and f.start_ea == ea and self.cur_func is not None:
                if hasattr(self.cur_func, "start_ea") and self.cur_func.start_ea == ea:
                    self.func_name = ida_funcs.get_func_name(ea)
            if self.cur_value != ida_idaapi.BADADDR and self.is_ea_to_be_processed(self.cur_value):
                self.value_name = ida_funcs.get_func_name(self.cur_value)
            if not self.value_name:
                self.value_name = ida_name.get_name(self.cur_value)
            if not self.value_name:
                w, wt = self.v().get_widget()
                self.value_name = self.v().get_highlighted_name(ea, w=w)
            self.make_name_line = ida_lines.tag_remove(ida_kernwin.get_curline())
        elif self.cmdname == 'MakeRptCmt':
            if self.is_ea_to_be_processed_cmt(ea):
                if f and f.start_ea == ea and self.cur_func is not None:
                    if hasattr(self.cur_func, "start_ea") and self.cur_func.start_ea == ea:
                        self.func_cmt = ida_funcs.get_func_cmt(f, 1)
                self.rcmt = ida_bytes.get_cmt(ea, 1)
            elif self.is_ea_to_be_processed(ea):
                self.rcmt = ida_bytes.get_cmt(ea, 1)
        elif self.cmdname == 'MakeComment':
            if self.is_ea_to_be_processed_cmt(ea):
                if f and f.start_ea == ea and self.cur_func is not None:
                    if hasattr(self.cur_func, "start_ea") and self.cur_func.start_ea == ea:
                        self.func_rcmt = ida_funcs.get_func_cmt(f, 0)
                self.cmt = ida_bytes.get_cmt(ea, 0)
            elif self.is_ea_to_be_processed(ea):
                self.cmt = ida_bytes.get_cmt(ea, 0)
        elif self.cmdname == 'OpStructOffset':
            if f and self.is_ea_to_be_processed(f.start_ea):
                self.line = ida_lines.tag_remove(ida_kernwin.get_curline())
        elif self.cmdname == 'JumpText':
            self.ask_next_text()
        elif self.cmdname == 'AskNextText':
            self.ask_next_text()
        elif self.cmdname == 'msglist:FindNext':
            self.ask_next_text()
        # observing make a function and renew the cache
        elif self.cmdname == 'MakeFunction':
            self.make_func(ea, f)
        return 0
            
    def postprocess_action(self):
        if self.v().cto_data["master"] != id(self.v()) and self.cmdname not in ["SetColors"]:
            return 0
        self._log("IDA finished processing command: %s" % self.cmdname)
        ea = ida_kernwin.get_screen_ea()
        f = ida_funcs.get_func(ea)
        refresh_flag = False
        if self.cmdname == 'hx:Rename' and self.decomp_avail and self.is_ea_to_be_processed(ea):
            try:
                import ida_hexrays
            except ImportError:
                return 0
            w, wt = self.v().get_widget()
            if f and f.start_ea == ea and self.cur_func is not None:
                if hasattr(self.cur_func, "start_ea") and self.cur_func.start_ea == ea:
                    func_name = ida_funcs.get_func_name(ea)
                    self._log("prev:", self.func_name, "curr:", func_name)
                    if self.func_name is not None and func_name != self.func_name:
                        refresh_flag = True
                    self.func_name = None
            elif w and wt == ida_kernwin.BWN_PSEUDOCODE:
                vu = ida_hexrays.get_widget_vdui(w)
                cfunc = vu.cfunc
                vu.get_current_item(ida_hexrays.USE_KEYBOARD)
                if vu.item.is_citem():
                    highlight = vu.item.e
                    if(highlight and highlight.is_expr()):
                        hl_str = highlight.print1(None)
                        value_name = ida_lines.tag_remove(hl_str)
                        self._log("prev:", self.value_name, "curr:", value_name)
                        if self.value_name is not None and value_name != self.value_name:
                            refresh_flag = True
                        self.value_name = None
        elif self.cmdname == 'MakeName' and self.is_ea_to_be_processed(ea):
            if f and f.start_ea == ea and self.cur_func is not None:
                if hasattr(self.cur_func, "start_ea") and self.cur_func.start_ea == ea:
                    func_name = ida_funcs.get_func_name(ea)
                    self._log("prev:", self.func_name, "curr:", func_name)
                    if self.func_name is not None and func_name != self.func_name:
                        refresh_flag = True
                    self.func_name = None
            value_name = ""
            if self.cur_value != ida_idaapi.BADADDR and self.is_ea_to_be_processed(self.cur_value):
                value_name = ida_funcs.get_func_name(self.cur_value)
            if not value_name:
                value_name = ida_name.get_name(self.cur_value)
            if not value_name:
                w, wt = self.v().get_widget()
                value_name = self.v().get_highlighted_name(ea, w=w)
            self._log("prev:", self.value_name, "curr:", value_name)
            if self.value_name is not None and value_name != self.value_name:
                refresh_flag = True
            self.value_name = None
                
            # for renaming a struct member name
            make_name_line = ida_lines.tag_remove(ida_kernwin.get_curline())
            self._log("prev:", self.make_name_line, "curr:", make_name_line)
            if self.make_name_line is not None and make_name_line != self.make_name_line:
                callee, func_type, opn, _func_name = self.v().get_callee_info(ea)
                if callee is not None:
                    optype = idc.get_operand_type(ea, opn)
                    if optype in [ida_ua.o_displ, ida_ua.o_phrase]:
                        self.update_tif(ea)
                        refresh_flag = True
            self.make_name_line = None
        elif self.cmdname == 'MakeRptCmt':
            if self.is_ea_to_be_processed_cmt(ea):
                if f and f.start_ea == ea and self.cur_func is not None:
                    if hasattr(self.cur_func, "start_ea") and self.cur_func.start_ea == ea:
                        func_rcmt = ida_funcs.get_func_cmt(f, 1)
                        self._log("prev: ", self.func_rcmt, "curr:", func_rcmt)
                        if func_rcmt != self.func_rcmt:
                            self.v().partial_cache_update(f.start_ea)
                            refresh_flag = True
                        self.func_rcmt = None
                rcmt = ida_bytes.get_cmt(ea, 1)
                self._log("prev: ", self.rcmt, "curr:", rcmt)
                if rcmt != self.rcmt and f:
                    refresh_flag = True
                    self.v().partial_cache_update(f.start_ea)
                self.rcmt = None
            elif self.is_ea_to_be_processed(ea):
                rcmt = ida_bytes.get_cmt(ea, 1)
                self._log("prev: ", self.rcmt, "curr:", rcmt)
                if rcmt != self.rcmt and f:
                    refresh_flag = True
                    self.v().partial_cache_update(f.start_ea)
                self.rcmt = None
        elif self.cmdname == 'MakeComment':
            if self.is_ea_to_be_processed_cmt(ea):
                if f and f.start_ea == ea and self.cur_func is not None:
                    if hasattr(self.cur_func, "start_ea") and self.cur_func.start_ea == ea:
                        func_cmt = ida_funcs.get_func_cmt(f, 0)
                        self._log("prev: ", self.func_cmt, "curr:", func_cmt)
                        if func_cmt != self.func_cmt:
                            self.v().partial_cache_update(f.start_ea)
                            refresh_flag = True
                        self.func_cmt = None
                cmt = ida_bytes.get_cmt(ea, 0)
                self._log("prev: ", self.cmt, "curr:", cmt)
                if cmt != self.cmt:
                    self.update_tif(ea, cmt)
                    refresh_flag = True
                self.cmt = None
            elif self.is_ea_to_be_processed(ea):
                cmt = ida_bytes.get_cmt(ea, 0)
                self._log("prev: ", self.cmt, "curr:", cmt)
                if cmt != self.cmt:
                    self.update_tif(ea, cmt)
                    refresh_flag = True
                self.cmt = None
        elif self.cmdname == 'OpStructOffset':
            if f and self.is_ea_to_be_processed(f.start_ea):
                line = ida_lines.tag_remove(ida_kernwin.get_curline())
                self._log("prev: ", self.line, "curr:", line)
                if self.line is not None and line != self.line:
                    self.update_tif(ea)
                    refresh_flag = True
                self.line = None
        # for checking theme change
        elif self.cmdname == 'SetColors':
            refresh_flag = self.chk_dark_mode()
        # do not reload while searching text
        elif self.cmdname == 'JumpText':
            self.after_ask_next_text()
        elif self.cmdname == 'AskNextText':
            self.after_ask_next_text()
        elif self.cmdname == 'msglist:FindNext':
            self.after_ask_next_text()
        # observing make a function and renew the cache
        elif self.cmdname == 'MakeFunction':
            refresh_flag = self.after_make_func(ea, f)
            
        if refresh_flag:
            self._log("refresh_flag is true. refreshing...")
            #self.v().refresh_all(ea)
            self.refresh_all(ea)
            
        # reset the command name
        self.cmdname = "<no command>"
        return 0

    def refresh(self, ea=ida_idaapi.BADADDR, center=False):
        self.v().refresh(ea, center)
    
    def refresh_all(self, ea=ida_idaapi.BADADDR, center=False):
        for inst in self.v().cto_data['insts']:
            inst.my_ui_hooks.refresh(ea, center)
            
    def update_tif(self, ea, name=None):
        self.v().update_caller_tif(ea, name)
    
    def clear_history(self):
        pass
    
    def chk_dark_mode(self):
        return False

    def ask_next_text(self):
        return False
    
    def after_ask_next_text(self):
        return False
    
    def make_func(self, ea, f):
        self.func = f
        return False
    
    def after_make_func(self, ea, f):
        if not self.func and f:
            self.v().partial_cache_update(ea)
            self.v().use_internal_function_cache = False
            return True
        self.func = None
        return False
    
    """
    def screen_ea_changed(self, ea, prev_ea):
        self._log("Screen EA has been changed from %x to %x" % (prev_ea, ea))
        pass
    """
            
    def updating_actions(self, ctx):
        if self.v().cto_data["master"] != id(self.v()):
            return 0
        #self._log("Updating actions")
        #self._log(ctx.action, hex(ctx.cur_ea).rstrip("L"), ctx.cur_func, hex(ctx.cur_value).rstrip("L"))
        self.cur_ea = ctx.cur_ea
        self.cur_func = ctx.cur_func
        self.cur_value = ctx.cur_value
               
    """
    def updated_actions(self):
        #self._log("Updated actions")
        #self._log(hex(self.cur_ea).rstrip("L"), self.cur_func, hex(self.cur_value).rstrip("L"))
        pass
    """
            
# observing "IDA View-A" window
class my_view_hooks_t(ida_kernwin.View_Hooks):
    def __init__(self, g):
        ida_kernwin.View_Hooks.__init__(self)
        self.hook()
        # let's use weakrefs, so as soon as the last ref to
        # the 'CallTreeOverviewer' instance is dropped, the 'my_view_hooks_t'
        # instance hooks can be automatically un-hooked, and deleted.
        # (in other words: avoid circular reference.)
        import weakref
        self.v = weakref.ref(g)
        #self.title = title

    def _log(self, *msg):
        ida_kernwin.msg(">>> MyViewHook: %s%s" % (" ".join([str(x) for x in msg], os.linesep)))
        
    def _view_loc_changed(self, w, now, was):
        # for hooking and observing IDA View-A and synchronize with CTO's node
        if self.v().curr_view == w:
            self._log("changed to %x from %x" % (now.place().toea(), was.place().toea()))
            # color the corresponded CTO's node
            self.update_widget_b(now, was)
                
        # for hooking and observing the CTO window and synchronize with IDA View-A's ea
        elif self.v().GetWidget() == w:
            self.view_loc_change_on_widget_b(now, was)
                    
    def view_loc_changed(self, w, now, was):
        try:
            self._view_loc_changed(w, now, was)
        except Exception as e:
            exc_type, exc_obj, tb = sys.exc_info()
            lineno = tb.tb_lineno
            ida_kernwin.msg("Got a unexpected error (%s: %s) (%d)%s" % (str(type(e)), e, lineno, os.linesep))
            if self.v().config.debug:
                self.v().dbg_print(traceback.format_exc())
            else:
                traceback.print_exc()
                    
    def update_widget_b(self, now, was):
        now_ea = now.place().toea()
        was_ea = was.place().toea()
        self.update_widget_b_ea(now_ea, was_ea)
                
    def update_widget_b_ea(self, now_ea, was_ea):
        pass
    
    def view_loc_change_on_widget_b(self, now, was):
        pass
    
                            
    def _view_click(self, w, ve):
        pass
                
    def view_click(self, w, ve):
        try:
            self._view_click(w, ve)
        except Exception as e:
            exc_type, exc_obj, tb = sys.exc_info()
            lineno = tb.tb_lineno
            ida_kernwin.msg("Got a unexpected error (%s: %s) (%d)%s" % (str(type(e)), e, lineno, os.linesep))
            if self.v().config.debug:
                self.v().dbg_print(traceback.format_exc())
            else:
                traceback.print_exc()
