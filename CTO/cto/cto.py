import idc
import ida_idaapi
import ida_name
import ida_funcs
import ida_xref
import ida_bytes
import ida_kernwin
import ida_graph
import ida_lines
import ida_moves
import ida_auto
import ida_ua
import idautils

import re
import inspect
import os
import sys
import codecs
import tempfile
import traceback
import time
import copy

# import internal libraries
import get_func_relation
import tinfo
import cto_base
import icon
import syncui
import cto_utils
ida_idaapi.require("get_func_relation")
ida_idaapi.require("tinfo")
ida_idaapi.require("cto_base")
ida_idaapi.require("icon")
ida_idaapi.require("syncui")
ida_idaapi.require("cto_utils")

g_max_recursive = 10

FT_UNK = get_func_relation.FT_UNK
FT_GEN = get_func_relation.FT_GEN
FT_LIB = get_func_relation.FT_LIB
FT_API = get_func_relation.FT_API
FT_MEM = get_func_relation.FT_MEM
FT_VAR = get_func_relation.FT_VAR
FT_STR = get_func_relation.FT_STR
FT_STO = get_func_relation.FT_STO
FT_VTB = get_func_relation.FT_VTB

if not hasattr(ida_kernwin, "WOPN_NOT_CLOSED_BY_ESC"):
    setattr(ida_kernwin, "WOPN_NOT_CLOSED_BY_ESC", 0x100) # 7.5 lacks the definition

if not hasattr(ida_kernwin, "CVNF_LAZY"):
    setattr(ida_kernwin, "CVNF_LAZY", 0x1) # 7.5 lacks the definition
if not hasattr(ida_kernwin, "CVNF_JUMP"):
    setattr(ida_kernwin, "CVNF_JUMP", 0x2) # 7.5 lacks the definition
if not hasattr(ida_kernwin, "CVNF_ACT"):
    setattr(ida_kernwin, "CVNF_ACT", 0x4) # 7.5 lacks the definition

class CallTreeOverviewer(cto_base.cto_base, ida_graph.GraphViewer):
    orig_title = "CTO"
    DO_NOT_SKIP = 0
    SKIP_CHILDREN = 1
    SKIP_PARENTS = 2
    def __init__(self, start_ea, end_ea=ida_idaapi.BADADDR, max_depth=1, cto_data=None, curr_view=None, close_open=True, title_postfix="", parent=None, skip=DO_NOT_SKIP, debug=False, skip_lib=True, skip_api=True):
        # generate title
        self.title = self.orig_title
        if title_postfix:
            self.title += title_postfix
        
        # init super class
        ida_graph.GraphViewer.__init__(self, self.title, close_open=close_open)
        
        # for the first execution, force refresh flag is enable to build from internal caches if the option is enabled.
        self.force_refresh_flag = True
        self.use_internal_function_cache = True
        self.dont_auto_reload = False
        self.to_be_saved_ea = ida_idaapi.BADADDR
        
        self.skip_children = False
        self.skip_parents = False
        if skip == self.SKIP_CHILDREN:
            self.skip_children = True
        elif skip == self.SKIP_PARENTS:
            self.skip_parents = True
        self.skip_api = True
        if not skip_api:
            self.skip_api = False
        self.skip_lib = True
        if not skip_lib:
            self.skip_lib = False
        
        self.icon = icon.icon_handler(icon_data=icon.g_icon_data_ascii, hexify=True)
        self.icon_id = 0
        
        # basic config
        f = ida_funcs.get_func(start_ea)
        if f:
            start_ea = f.start_ea
        self.start_ea = start_ea
        
        self.end_ea = end_ea
        self.max_depth = max_depth
        self.sub_graphs = []
        
        # init cto base
        cto_base.cto_base.__init__(self, cto_data, curr_view, debug)
        
        # jump to start ea
        #self.jumpto(self.start_ea)
        
        self.parent = None
        if parent and isinstance(parent, CallTreeOverviewer):
            self.parent = parent
        
        # for filtering out nodes
        self.max_recursive = 30
        self.clear_internal_caches()

        self.color_settings()
        
        self.remove_comment = True
        self.limit_depth = 10
        self.max_nodes = 300
        self.maximum_string_length = 20
        self.maximum_comment_length = 50
        self.canvas_margin = 0.07
        
        # node settings
        self.exceeded_node_symbol = '...'
        
        self.rm_space_rule = re.compile(r'    +')
        
        # Temoprary classes for UI and view hooks.
        # Their classes are only available in init function to avoid to forget unhooking and deleting.
        # Their instances are available while CallTreeOverviewer instance is available because they are generated at the end of init function below.
        class my_ui_hooks_t(syncui.my_ui_hooks_t):
            def _log(self, *msg):
                if self.v().config.debug:
                    self.v().dbg_print(">>> MyUiHook: %s" % " ".join([str(x) for x in msg]))
            
            def update_tif(self, ea, name=None):
                self.v().update_caller_tif(ea, name)
                
            def clear_history(self):
                pass
                
            def refresh(self, ea=ida_idaapi.BADADDR, center=False):
                self._log("refresh without cache (%x)" % ea, center)
                self.v().use_internal_function_cache = False
                self.v().refresh(ea, center)
                self.v().color_settings()
                self.v().color_all_nodes()
                self.v().change_widget_icon(bg_change=self.v().config.dark_mode)
                
            def ask_next_text(self):
                # if you do not unhook ui, IDA sometimes crashes.
                self.v().my_view_hooks.unhook()
                self.v().dont_auto_reload = True
                return False
            
            def after_ask_next_text(self):
                # hook ui again after find text.
                self.v().my_view_hooks.hook()
                self.v().dont_auto_reload = False
                return False
            
            def chk_dark_mode(self):
                refresh_flag = False
                if self.v().is_dark_mode_with_main():
                    self._log("dark mode is disabled in main window")
                    if not self.v().config.dark_mode:
                        self._log("dark mode is disabled in cto's config")
                        self.v().config.dark_mode = True
                        self.v().color_settings()
                        self.v().color_all_nodes()
                        self.v().change_widget_icon(bg_change=self.v().config.dark_mode)
                else:
                    if self.v().config.dark_mode:
                        self.v().config.dark_mode = False
                        self.v().color_settings()
                        self.v().color_all_nodes()
                        self.v().change_widget_icon(bg_change=self.v().config.dark_mode)
                return refresh_flag
            
            def populating_widget_popup(self, w, popup_handle):
                my_w = self.v().GetWidget()
                self._log("popup handler is called", my_w, w)
                wt = ida_kernwin.get_widget_type(w)
                if wt in [ida_kernwin.BWN_DISASM, ida_kernwin.BWN_PSEUDOCODE] and my_w:
                    for actname, skip, direction, direction2 in self.v().path_finder_permanent_action_name():
                        if actname not in ida_kernwin.get_registered_actions():
                            # register it again because the action is unregistered after cto is reloaded sometimes.
                            desc = ida_kernwin.action_desc_t(actname, "Find the path(s) %s this node%s" % (direction, direction2), self.v().path_finder_by_ea(self.v(), skip, actname, prefix="cto:path_finder"))
                            ida_kernwin.register_action(desc)
                            if self.v().icon_id > 0:
                                ida_kernwin.update_action_icon(actname, self.v().icon_id)
                        # add to a popup menu on IDA
                        ida_kernwin.attach_action_to_popup(my_w, popup_handle, actname)
                    
        # observing "IDA View-A" window
        class my_view_hooks_t(syncui.my_view_hooks_t):
            def _log(self, *msg):
                if self.v().config.debug:
                    self.v().dbg_print(">>> MyViewHook: %s" % " ".join([str(x) for x in msg]))
                
            def view_loc_change_on_widget_b(self, now, was):
                now_node = now.renderer_info().pos.node
                was_node = was.renderer_info().pos.node
                if self.v().config.debug:
                    self._log("Click on the node id %d, was on %d" % (now_node, was_node))

                # remove the previous node frame color
                if now_node != was_node:
                    if was_node in self.v().node_ids:
                        self.v().color_node(was_node)
                        
                if now_node >= 0 and now_node != was_node:
                            
                    if now_node in self.v().node_ids:
                        if self.v().config.debug:
                            self._log("Click on the node id %d in node_ids list" % (now_node))
                                    
                        if now_node < len(self.v()._nodes):
                            if self.v().config.center_node and not self.v().is_node_in_canvas(now_node):
                                self.v().do_center_node(now_node)
                            ni = ida_graph.node_info_t()
                            ni.frame_color = self.v().selected_frame_color
                            ni.bg_color    = self.v().selected_bg_color
                            self.v().SetNodeInfo(now_node, ni, ida_graph.NIF_BG_COLOR|ida_graph.NIF_FRAME_COLOR)
                            
                        # jump to the ea corresponded to the now_node in IDA View-A.
                        # this jump leads to another view_loc_changed event for the CTO widget that will call self.update_widget_b() above.
                        self.v().jumpto(self.v().node_ids[now_node])
                        self.v().get_focus(self.v().GetWidget())
            
            def update_widget_b_ea(self, now_ea, was_ea):
                if self.v().config.debug:
                    self._log("now_ea: %x, was_ea: %x" % (now_ea, was_ea))
                    
                w = ida_kernwin.get_current_widget()
                does_use_opn = self.v().does_use_opn()
                nid = -1
                f = ida_funcs.get_func(now_ea)
                
                # Make sure I am in the same function
                if now_ea in self.v().nodes or now_ea in self.v().caller_nodes:
                    if now_ea in self.v().nodes:
                        nid = self.v().nodes[now_ea]
                    if (does_use_opn or nid < 0) and now_ea in self.v().caller_nodes:
                        nid = self.v().caller_nodes[now_ea]
                    if nid < len(self.v()._nodes):
                        if self.v().config.center_node and not self.v().is_node_in_canvas(nid):
                            self.v().do_center_node(nid)
                        ni = ida_graph.node_info_t()
                        ni.frame_color = self.v().selected_frame_color
                        ni.bg_color    = self.v().selected_bg_color
                        self.v().SetNodeInfo(nid, ni, ida_graph.NIF_BG_COLOR|ida_graph.NIF_FRAME_COLOR)
                # if now_ea is not in ea, and auto reload flag is enabled, then reload and return to draw a new graph based on now_ea.
                # disable for subgraphs
                elif self.v().config.auto_reload_outside_node and (now_ea in self.v().func_relations or f or now_ea in self.v().vtbl_refs) and not self.v().parent and not self.v().dont_auto_reload:
                    if self.v().config.debug:
                        self._log("auto reloading")
                        
                    # relace ea with a head of vtable if ea is one of functions in a vtable
                    ea = now_ea
                    if ea in self.v().vtbl_refs:
                        ea = self.v().vtbl_refs[now_ea]
                        
                    # change the primary node and rebuild the tree
                    self.v().force_reload(ea)
                    
                    # take focus back on the current widget
                    if w:
                        self.v().get_focus(w)
                    return
                        
                # remove the previous node frame color
                if now_ea != was_ea or does_use_opn:
                    if was_ea in self.v().nodes:
                        wnid = self.v().nodes[was_ea]
                        if wnid < len(self.v()._nodes):
                            self.v().color_node(wnid)
                    if was_ea in self.v().caller_nodes:
                        wnid = self.v().caller_nodes[was_ea]
                        if wnid < len(self.v()._nodes):
                            self.v().color_node(wnid)
                elif now_ea == was_ea:
                    if was_ea in self.v().caller_nodes:
                        wnid = self.v().caller_nodes[was_ea]
                        if wnid < len(self.v()._nodes):
                            self.v().color_node(wnid)
                            
            def _view_click(self, w, ve):
                if self.v().GetWidget() == w:
                    item = None
                    if ve.rtype in [ida_kernwin.TCCRT_GRAPH, ida_kernwin.TCCRT_PROXIMITY]:
                        item = ve.location.item
                            
        # wait until IDA gets ready
        r = ida_auto.auto_wait()
        
        # Note that this is still in the init method of the CallTreeOverviewer class
        # get the UI and View Hooks
        self.my_ui_hooks = my_ui_hooks_t(self)
        self.my_view_hooks = my_view_hooks_t(self)
        
        # show the graph
        self.show_graph()
        
    ###############################################################################
    
    # jump to a node with chooser
    class node_chooser_t(ida_kernwin.Choose):
        def __init__(self, title, g, flags=ida_kernwin.Choose.CH_MODAL):
            ida_kernwin.Choose.__init__(
                self,
                title,
                [
                    ["nid", 3],
                    ["Address", 10],
                    ["Name", 20],
                    ["Type", 8],
                    ["Has Exceeded Node", 4],
                ],
                flags=flags,
                embedded=False,
                width=60,
                height=20)

            import weakref
            self.v = weakref.ref(g)

            self.items = self.create_item_list()
            self.icon = 5

        def create_item_list(self):
            items = []
            for i, (text, color) in enumerate(self.v()._nodes):
                
                # for address
                address = "N/A"
                if i in self.v().node_ids and self.v().node_ids[i] != ida_idaapi.BADADDR:
                    address = hex(self.v().node_ids[i]).rstrip("L")
                
                # for has_excceded_nodes
                src = self.v().find_src_node_from_edges(i, text=self.v().exceeded_node_symbol)
                dst = self.v().find_dst_node_from_edges(i, text=self.v().exceeded_node_symbol)
                has_exceeded_node = ""
                if src >= 0 or dst >= 0:
                    has_exceeded_node = "True"
                
                # for text
                text = ida_lines.tag_remove(text)
                text_displayed = text
                if i in self.v().exceeded_node_ids:
                    src = self.v().find_src_node_from_edges(i)
                    dst = self.v().find_dst_node_from_edges(i)
                    if src >= 0:
                        text_displayed += " (parent [%d]: %x)" % (src, self.v().node_ids[src])
                    elif dst >= 0:
                        text_displayed += " (child [%d]: %x)" % (dst, self.v().node_ids[dst])

                # node type
                node_type = "Unknown"
                if i in self.v().node_types:
                    node_type, func_type, caller = self.v().node_types[i]
                items.append((str(i), address, text_displayed, node_type, has_exceeded_node))
            
            return items
        
        def OnGetLine(self, n):
            #print("getline %d" % n)
            return self.items[n]
        
        def OnGetSize(self):
            n = len(self.items)
            return n
    
    class func_chooser_t(ida_kernwin.Choose):
        def __init__(self, title, g, flags=ida_kernwin.Choose.CH_MODAL):
            ida_kernwin.Choose.__init__(
                self,
                title,
                [
                    ["Address", 10],
                    ["Name", 20],
                ],
                flags=flags,
                embedded=False,
                width=60,
                height=20)

            import weakref
            self.v = weakref.ref(g)

            self.items = self.create_item_list()
            self.icon = 5
        
        def create_item_list(self):
            items = []
            for func_ea in self.v().func_relations:
                func_type = self.v().func_relations[func_ea]['func_type']
                
                func_name = self.v().get_callee_name(func_ea, func_type)
                if func_ea != ida_idaapi.BADADDR:
                    items.append((hex(func_ea).rstrip("L"), ida_lines.tag_remove(func_name)))
            
            return items
        
        def OnGetLine(self, n):
            #print("getline %d" % n)
            return self.items[n]
        
        def OnGetSize(self):
            n = len(self.items)
            return n
    
    class cref_chooser_t(ida_kernwin.Choose):
        def __init__(self, title, g, ea, flags=ida_kernwin.Choose.CH_MODAL):
            ida_kernwin.Choose.__init__(
                self,
                title,
                [
                    ["Address", 10],
                    ["Name", 20],
                ],
                flags=flags,
                embedded=False,
                width=60,
                height=20)

            import weakref
            self.v = weakref.ref(g)
            self.ea = ea

            self.items = self.create_item_list()
            self.icon = 5
        
        def create_item_list(self):
            items = []
            for ref in idautils.CodeRefsFrom(self.ea, False):
                if ref in self.v().func_relations:
                    func_type = self.v().func_relations[ref]['func_type']
                    func_name = self.v().get_callee_name(ref, func_type)
                    if ref != ida_idaapi.BADADDR:
                        items.append((hex(ref).rstrip("L"), ida_lines.tag_remove(func_name)))
            
            return items
        
        def OnGetLine(self, n):
            #print("getline %d" % n)
            return self.items[n]
        
        def OnGetSize(self):
            n = len(self.items)
            return n
    
    class next_node_chooser_t(ida_kernwin.Choose):
        def __init__(self, title, g, node_id, direction, flags=ida_kernwin.Choose.CH_MODAL):
            ida_kernwin.Choose.__init__(
                self,
                title,
                [
                    ["nid", 3],
                    ["Address", 10],
                    ["Name", 20],
                ],
                flags=flags,
                embedded=False,
                width=60,
                height=20)

            import weakref
            self.v = weakref.ref(g)
            self.node_id = node_id
            self.direction = direction
            
            self.items = self.create_item_list()
            self.icon = 5
        
        def create_item_list(self):
            items = []
            node_id = self.node_id
            
            if self.direction == 'parents':
                nid_iter = self.v().find_src_nodes_from_edges(node_id)
            else:
                nid_iter = self.v().find_dst_nodes_from_edges(node_id)
            
            for nid in nid_iter:
                name = self.v()._nodes[nid][0]
                address = "N/A"
                if nid in self.v().exceeded_node_ids:
                    next_node_ea = self.v().exceeded_node_ids[nid]
                    next_node_id = self.v().nodes[next_node_ea]
                    address += " (%s nid:%d @ %x)" % (self.direction, next_node_id, next_node_ea)
                elif nid in self.v().node_ids:
                    address = hex(self.v().node_ids[nid]).rstrip("L")
                
                items.append((str(nid), address, ida_lines.tag_remove(name)))
            
            return items
        
        def OnGetLine(self, n):
            #print("getline %d" % n)
            return self.items[n]
        
        def OnGetSize(self):
            n = len(self.items)
            return n
    
    # for right-click context menu
    class _base_graph_action_handler_t(ida_kernwin.action_handler_t):
        def __init__(self, g):
            ida_kernwin.action_handler_t.__init__(self)
            import weakref
            self.v = weakref.ref(g)
        
        def update(self, ctx):
            return ida_kernwin.AST_ENABLE_ALWAYS

    class expand_collapse_node(_base_graph_action_handler_t):
        def activate(self, ctx):
            r = self.v().get_selected_node()
            if r:
                if len(r) == 1:
                    self.v().OnDblClick(r[0])
            return 1
        
    class hint_printer(_base_graph_action_handler_t):
        def activate(self, ctx):
            x = self.v().get_node_hint()
            if x:
                ida_kernwin.msg(x)
            return 1
    
    class add_cref_from(_base_graph_action_handler_t):
        def activate(self, ctx):
            r = self.v().get_selected_node()
            node_ea = ida_idaapi.BADADDR
            if r:
                if len(r) == 1:
                    nid = r[0]
                    if nid in self.v().node_ids:
                        node_ea = self.v().node_ids[nid]
            if node_ea != ida_idaapi.BADADDR and self.v().add_cref(node_ea, CallTreeOverviewer.func_chooser_t):
                self.v().partial_cache_update(node_ea)
                #self.v().exec_ui_action("EmptyStack")
                self.v().use_internal_function_cache = False
                self.v().refresh()
                ida_kernwin.msg("added the cref to the node." + os.linesep)
            return 1
    
    class del_cref_from(_base_graph_action_handler_t):
        def activate(self, ctx):
            r = self.v().get_selected_node()
            node_ea = ida_idaapi.BADADDR
            if r:
                if len(r) == 1:
                    nid = r[0]
                    if nid in self.v().node_ids:
                        node_ea = self.v().node_ids[nid]
            if node_ea != ida_idaapi.BADADDR and self.v().del_cref(node_ea, CallTreeOverviewer.cref_chooser_t):
                self.v().partial_cache_update(node_ea)
                #self.v().exec_ui_action("EmptyStack")
                self.v().use_internal_function_cache = False
                self.v().refresh()
                ida_kernwin.msg("deleted the cref from the node." + os.linesep)
    
    class go_to_node(_base_graph_action_handler_t):
        def __init__(self, g, direction):
            CallTreeOverviewer._base_graph_action_handler_t.__init__(self, g)
            self.direction = direction
            
        def activate(self, ctx):
            r = self.v().get_selected_node()
            if r:
                if len(r) == 1:
                    nid = r[0]
                    nnc = CallTreeOverviewer.next_node_chooser_t("Choose the %s" % self.direction, self.v(), nid, self.direction)
                    selected = nnc.Show(modal=True)
                    if selected >= 0:
                        snid = nnc.items[selected][0]
                        nid = int(snid)
                        if self.v().config.center_node and not self.v().is_node_in_canvas(nid):
                            self.v().do_center_node(nid)
                        self.v().select(nid)
                        
            return 1
        
    class path_finder(_base_graph_action_handler_t):
        def __init__(self, g, skip, act_name, prefix="path_finder"):
            CallTreeOverviewer._base_graph_action_handler_t.__init__(self, g)
            self.skip = skip
            self.act_name = act_name
            self.prefix = prefix
            
        def generate_sub_graph(self, node_ea):
            parent = self.v()
            if self.v().parent:
                parent = self.v().parent
            title = self.v().orig_title + "_%x" % node_ea
            
            flag = False
            for sg in self.v().sub_graphs:
                if sg.title == title:
                    flag = True
                    break
            if parent.start_ea == node_ea:
                flag = True
            
            if flag:
                ida_kernwin.msg("%s is already displayed as a subgraph. Close it first.%s" % (title, os.linesep))
            else:
                dst_ea = ida_idaapi.BADADDR
                depth = 1
                if self.skip == CallTreeOverviewer.SKIP_CHILDREN:
                    depth = 3
                    
                exec_flag = True
                src_ea = node_ea
                skip_api = True
                skip_lib = True
                if self.act_name.startswith("%s_start_end" % self.prefix) or self.act_name.startswith("%s_end_start" % self.prefix) or self.act_name.startswith("%s_start_end_skip" % self.prefix) or self.act_name.startswith("%s_end_start_skip" % self.prefix):
                    # choosing destination with a chooser
                    fc = CallTreeOverviewer.func_chooser_t("Choose the destination", self.v())
                    selected = fc.Show(modal=True)
                    if selected >= 0:
                        end_ea, _ = fc.items[selected]
                        dst_ea = int(end_ea, 16)
                        depth = -1
                        skip_api = False
                        skip_lib = False
                        if self.act_name.startswith("%s_end_start" % self.prefix) or self.act_name.startswith("%s_end_start_skip" % self.prefix):
                            _ = dst_ea
                            dst_ea = src_ea
                            src_ea = _
                        if self.act_name.startswith("%s_start_end_skip" % self.prefix) or self.act_name.startswith("%s_end_start_skip" % self.prefix):
                            skip_api = True
                            skip_lib = True
                    else:
                        exec_flag = False
                        ida_kernwin.msg("You did not select an address.%s" % (os.linesep))
                    
                if exec_flag:
                    g = CallTreeOverviewer(src_ea, end_ea=dst_ea, max_depth=depth, cto_data=self.v().cto_data, curr_view=self.v().curr_view, close_open=True, title_postfix="_%x" % node_ea, parent=parent, skip=self.skip, skip_api=skip_api, skip_lib=skip_lib)
                    if g and g.parent:
                        g.parent.sub_graphs.append(g)
                        
        def get_ea(self):
            r = self.v().get_selected_node()
            if r:
                if len(r) == 1:
                    nid = r[0]
                    if nid in self.v().node_ids:
                        node_ea = self.v().node_ids[nid]
                        return node_ea
            return ida_idaapi.BADADDR
        
        def _activate(self, ctx):
            node_ea = self.get_ea()
            if node_ea != ida_idaapi.BADADDR:
                self.generate_sub_graph(node_ea)
            
        def activate(self, ctx):
            try:
                self._activate(ctx)
            except Exception as e:
                exc_type, exc_obj, tb = sys.exc_info()
                lineno = tb.tb_lineno
                ida_kernwin.msg("Got a unexpected error (%s: %s) (%d)%s" % (str(type(e)), e, lineno, os.linesep))
                traceback.print_exc()
                return 0
            return 1
    
    class path_finder_by_ea(path_finder):
        def __del__(self):
            # unregister path_finder* actions
            ida_kernwin.unregister_action(self.act_name)
            
        def get_ea(self):
            return ida_kernwin.get_screen_ea()
            
    class change_primary_node(_base_graph_action_handler_t):
        def activate(self, ctx):
            r = self.v().get_selected_node()
            if r:
                if len(r) == 1 and r[0] in self.v().node_ids:
                    old_start_ea = self.v().start_ea
                    start_ea = self.v().node_ids[r[0]]
                    f = ida_funcs.get_func(start_ea)
                    if f:
                        start_ea = f.start_ea
                    self.v().start_ea = start_ea
                    self.v().force_reload()
                    ida_kernwin.msg("Change the primary node to %x from %x.%s" % (start_ea, old_start_ea, os.linesep))
            return 1
        
    # wrapper for Show()
    def show(self):
        r = False
        try:
            t1 = time.time()
            if self.config.debug: self.dbg_print("Showing...")
            
            r = self.Show()
            if r:
                w = self.GetWidget()
                if w is None:
                    r = False
            
            if self.config.debug: self.dbg_print("Showed!")
            
            t2 = time.time()
            if self.config.debug: self.dbg_print("show() time: %d" % (t2-t1))
            
        except Exception as e:
            exc_type, exc_obj, tb = sys.exc_info()
            lineno = tb.tb_lineno
            ida_kernwin.msg("Got a unexpected error (%s: %s) (%d)%s" % (str(type(e)), e, lineno, os.linesep))
            if self.config.debug:
                self.dbg_print(traceback.format_exc())
            else:
                traceback.print_exc()
        return r
    
    # for all cto instances. It's used for synchronizing renaming and so on.
    # disable caching here because of changing node state.
    # that's why cto overrides this method.
    def refresh_all(self, ea=ida_idaapi.BADADDR, center=False):
        for inst in self.cto_data['insts']:
            # here, I don't wny but type(i) and isinstance and i.__class__
            # aren't match with the class. That's why compare these strings here.
            #if isinstance(inst, CallTreeOverviewer):
            if str(type(inst)) == str(CallTreeOverviewer):
                inst.use_internal_function_cache = False
            inst.refresh(ea, center)
            
    # wrapper for Refresh() that ends up to call OnRefresh() internally.
    def refresh(self, ea=ida_idaapi.BADADDR, center=False):
        if self.config.debug:
            callee_stk = inspect.stack()[1]
            
            #for python2
            if isinstance(callee_stk, tuple):
                frame, filename, lineno, function, source_code, source_index = callee_stk
            # for python 3
            else:
                filename = callee_stk.filename
                lineno = callee_stk.lineno
                function = callee_stk.function
            self.dbg_print("Called from %s:%d" % (function, lineno))
                
        if center:
            self.refresh_with_center_node(ea)
        else:
            self._refresh(ea)
            
    def _refresh(self, ea=ida_idaapi.BADADDR, center=False):
        if self.config.debug:
            callee_stk = inspect.stack()[2]
            
            #for python2
            if isinstance(callee_stk, tuple):
                frame, filename, lineno, function, source_code, source_index = callee_stk
            # for python 3
            else:
                filename = callee_stk.filename
                lineno = callee_stk.lineno
                function = callee_stk.function
            self.dbg_print("Called from %s:%d" % (function, lineno))
                
        try:
            t1 = time.time()
            if self.config.debug: self.dbg_print("Refreshing...")
            
            w = self.GetWidget()
            if w:
                gv = ida_graph.get_graph_viewer(w)
                mg = ida_graph.get_viewer_graph(gv)
                if mg is not None:
                    mg.del_custom_layout()
                    
            saved_ea = ida_kernwin.get_screen_ea()
            use_cache = self.use_internal_function_cache
            self.Refresh()
            
            # if it has a subgraph or the parent graph, they need to be refreshed
            # and select the primary node. Otherwise, IDA will crash if a node
            # is disappeared in a case such as disablling global nodes.
            if self.parent:
                    
                self.parent.use_internal_function_cache = use_cache
                self.parent.Refresh()
                if saved_ea not in self.parent.nodes:
                    self.parent.select(0)
                    
                len_sb = len(self.sub_graphs)
                for i in reversed(range(len_sb)):
                    if self.sub_graphs[i].title != self.title:
                        self.sub_graphs[i].use_internal_function_cache = use_cache
                        self.sub_graphs[i].Refresh()
                        if saved_ea not in self.sub_graphs[i].nodes:
                            self.sub_graphs[i].select(0)
            self.jumpto(saved_ea)
                
            #self.exec_ui_action("GraphLayout")
            if self.config.debug: self.dbg_print("Refreshed!")
            t2 = time.time()
            if self.config.debug: self.dbg_print("refresh() time: %d" % (t2-t1))
        except Exception as e:
            exc_type, exc_obj, tb = sys.exc_info()
            lineno = tb.tb_lineno
            ida_kernwin.msg("Got a unexpected error (%s: %s) (%d)%s" % (str(type(e)), e, lineno, os.linesep))
            if self.config.debug:
                self.dbg_print(traceback.format_exc())
            else:
                traceback.print_exc()
    
    def _refresh_with_center_node(self, ea=ida_idaapi.BADADDR):
        if ea == ida_idaapi.BADADDR:
            ea = ida_kernwin.get_screen_ea()
        orig_ea = ea
        if ea not in self.nodes:
            f = ida_funcs.get_func(ea)
            if f:
                ea = f.start_ea
            else:
                ea = self.start_ea
        else:
            ea = self.start_ea
        self._refresh(ea)
        if orig_ea in self.nodes:
            ea = orig_ea
        if ea in self.nodes:
            nid = self.nodes[ea]
            if self.config.center_node and not self.is_node_in_canvas(nid):
                self.do_center_node(nid)
                self.select(nid)
            elif nid in self.node_ids:
                self.select(nid)
                
    def refresh_with_center_node(self, ea=ida_idaapi.BADADDR):
        if self.config.debug:
            callee_stk = inspect.stack()[1]
            
            #for python2
            if isinstance(callee_stk, tuple):
                frame, filename, lineno, function, source_code, source_index = callee_stk
            # for python 3
            else:
                filename = callee_stk.filename
                lineno = callee_stk.lineno
                function = callee_stk.function
            self.dbg_print("Called from %s:%d" % (function, lineno))
                
        try:
            self._refresh_with_center_node(ea)
        except Exception as e:
            exc_type, exc_obj, tb = sys.exc_info()
            lineno = tb.tb_lineno
            ida_kernwin.msg("Got a unexpected error (%s: %s) (%d)%s" % (str(type(e)), e, lineno, os.linesep))
            if self.config.debug:
                self.dbg_print(traceback.format_exc())
            else:
                traceback.print_exc()
        
    def force_reload(self, ea=ida_idaapi.BADADDR):
        # enable force flag and it is referred in OnRefresh method.
        self.force_refresh_flag = True
        
        # to update the primary ea with the current ea, get the current ea to use later
        if ea == ida_idaapi.BADADDR:
            ea = ida_kernwin.get_screen_ea()
        f = ida_funcs.get_func(ea)
        if f:
            ea = f.start_ea
            
        # convert start address if it is a vfunc
        if ea in self.vtbl_refs:
            ea = self.vtbl_refs[ea]
            
        if ea != self.start_ea:
            self.to_be_saved_ea = ea
            
        # check if it can reload or not.
        #drefs = list(get_func_relation.get_drefs_to(self.start_ea))
        #if self.start_ea not in self.func_relations and len(drefs) == 0:
        drefs = list(get_func_relation.get_drefs_to(ea))
        if ea not in self.func_relations and len(drefs) == 0:
            ida_kernwin.msg("Must be in a function" + os.linesep)
            return False
            
        # replace the primary node ea to screen ea.
        self.start_ea = ea
        self.partial_cache_update(ea)
        self.refresh_with_center_node()
        return True
    
    def OnRefresh(self):
        try:
            if self.config.debug: self.dbg_print("OnRefresh() started.")
            
            # clear tree state
            self.clear_all_node_infos()
            self.Clear()
            all_clear_flag = False
            if self.force_refresh_flag:
                all_clear_flag = True
            self.clear_internal_caches(all_clear=all_clear_flag)
            self.color_settings()
            
            # get current function's ea
            ea = ida_kernwin.get_screen_ea()
            f = ida_funcs.get_func(ea)
            if f:
                ea = f.start_ea
                
            # get ea to restore
            restore_ea = self.start_ea
            if self.force_refresh_flag and self.to_be_saved_ea != ida_idaapi.BADADDR:
                restore_ea = self.to_be_saved_ea
            if self.config.debug: self.dbg_print("ea to be refreshed is %x" % restore_ea)
            
            # build tree or get past result from cache
            if not self.config.save_caches or not self.use_internal_function_cache or not self.restore_function_internal_cache(restore_ea):
                if self.config.debug: self.dbg_print("restoring data from cache was failed. building the tree by tracing", self.config.save_caches, self.use_internal_function_cache)
                self.draw_call_tree()
                
            # color all nodes, for example, the primary node and API/static linked library nodes
            self.color_all_nodes()
                
            # update the cache
            # do not save data when just refreshing
            if self.config.save_caches and (self.force_refresh_flag or not self.use_internal_function_cache):
                if self.to_be_saved_ea != ida_idaapi.BADADDR:
                   ea = self.to_be_saved_ea
                self.save_function_internal_cache(ea)
                
            # clear flags
            self.force_refresh_flag = False
            self.use_internal_function_cache = True
            self.to_be_saved_ea = ida_idaapi.BADADDR
            
            if self.config.debug: self.dbg_print("OnRefresh() finished.")
            
        except Exception as e:
            exc_type, exc_obj, tb = sys.exc_info()
            lineno = tb.tb_lineno
            ida_kernwin.msg("Got a unexpected error (%s: %s) (%d)%s" % (str(type(e)), e, lineno, os.linesep))
            if self.config.debug:
                self.dbg_print(traceback.format_exc())
            else:
                traceback.print_exc()
            return False
        return True
    
    def clear_internal_caches(self, all_clear=True):
        self.nodes = {}
        self.caller_nodes = {}
        self.exceeded_nodes = {}
        self.node_ids = {}
        self.caller_node_ids = {}
        self.exceeded_node_ids = {}
        self.related_nodes = {}
        self.strings_contents = {}
        self.gvars_contents = {}
        self.stroff_contents = {}
        self.unresolved_indirect_calls = {}
        self.node_id_relationships = {}
        self.node_types = {}
        if all_clear:
            self.additional_trace_points = {}
            self.filtered_nodes = {}
            self.trace_points_relations = {}
            
    def clear_function_internal_cache(self, ea=ida_idaapi.BADADDR):
        # clear all caches
        if ea == ida_idaapi.BADADDR:
            self.cto_data["cto_data"]["internal_caches"] = {}
        # clear a function cache
        elif ea in self.cto_data["cto_data"]["internal_caches"]:
            self.cto_data["cto_data"]["internal_caches"][ea] = {}
        
    def restore_function_internal_cache(self, ea):
        """
        if not (self.parent is None or id(self.parent) == id(self)):
            if self.config.debug: self.dbg_print("restoring was canceled. parent:%d self:%d" % (id(self.parent), id(self)), self.parent)
            return False
        """
        if not self.use_internal_function_cache or ea not in self.cto_data["cto_data"]["internal_caches"] or not self.config.save_caches:
            if self.config.debug: self.dbg_print("restoring was canceled. use_cache_flag:", self.use_internal_function_cache, "config:", self.config.save_caches)
            return False
        
        if self.config.debug: self.dbg_print("Restoring all internal caches for %x%s" % (ea, os.linesep))
        
        self._nodes = copy.deepcopy(self.cto_data["cto_data"]["internal_caches"][ea]["_nodes"])
        self._edges = copy.deepcopy(self.cto_data["cto_data"]["internal_caches"][ea]["_edges"])
        self.nodes = copy.deepcopy(self.cto_data["cto_data"]["internal_caches"][ea]["nodes"])
        self.caller_nodes = copy.deepcopy(self.cto_data["cto_data"]["internal_caches"][ea]["caller_nodes"])
        self.exceeded_nodes = copy.deepcopy(self.cto_data["cto_data"]["internal_caches"][ea]["exceeded_nodes"])
        self.node_ids = copy.deepcopy(self.cto_data["cto_data"]["internal_caches"][ea]["node_ids"])
        self.caller_node_ids = copy.deepcopy(self.cto_data["cto_data"]["internal_caches"][ea]["caller_node_ids"])
        self.exceeded_node_ids = copy.deepcopy(self.cto_data["cto_data"]["internal_caches"][ea]["exceeded_node_ids"])
        self.related_nodes = copy.deepcopy(self.cto_data["cto_data"]["internal_caches"][ea]["related_nodes"])
        self.strings_contents = copy.deepcopy(self.cto_data["cto_data"]["internal_caches"][ea]["strings_contents"])
        self.gvars_contents = copy.deepcopy(self.cto_data["cto_data"]["internal_caches"][ea]["gvars_contents"])
        self.stroff_contents = copy.deepcopy(self.cto_data["cto_data"]["internal_caches"][ea]["stroff_contents"])
        self.unresolved_indirect_calls = copy.deepcopy(self.cto_data["cto_data"]["internal_caches"][ea]["unresolved_indirect_calls"])
        self.node_id_relationships = copy.deepcopy(self.cto_data["cto_data"]["internal_caches"][ea]["node_id_relationships"])
        self.node_types = copy.deepcopy(self.cto_data["cto_data"]["internal_caches"][ea]["node_types"])
        self.additional_trace_points = copy.deepcopy(self.cto_data["cto_data"]["internal_caches"][ea]["additional_trace_points"])
        self.filtered_nodes = copy.deepcopy(self.cto_data["cto_data"]["internal_caches"][ea]["filtered_nodes"])
        self.trace_points_relations = copy.deepcopy(self.cto_data["cto_data"]["internal_caches"][ea]["trace_points_relations"])
        
        if self.config.debug: self.dbg_print("Restored all internal caches for %x%s" % (ea, os.linesep))
        return True
    
    def save_function_internal_cache(self, ea):
        if not self.config.save_caches:
            return False
        # do not cache if it is a sub graph.
        if not (self.parent is None or id(self.parent) == id(self)):
            return False
            
        if ea not in self.cto_data["cto_data"]["internal_caches"]:
            self.cto_data["cto_data"]["internal_caches"][ea] = {}
            
        if self.config.debug: self.dbg_print("Saving all internal caches for %x%s" % (ea, os.linesep))
        
        self.cto_data["cto_data"]["internal_caches"][ea]["_nodes"] = copy.deepcopy(self._nodes)
        self.cto_data["cto_data"]["internal_caches"][ea]["_edges"] = copy.deepcopy(self._edges)
        self.cto_data["cto_data"]["internal_caches"][ea]["nodes"] = copy.deepcopy(self.nodes)
        self.cto_data["cto_data"]["internal_caches"][ea]["caller_nodes"] = copy.deepcopy(self.caller_nodes)
        self.cto_data["cto_data"]["internal_caches"][ea]["exceeded_nodes"] = copy.deepcopy(self.exceeded_nodes)
        self.cto_data["cto_data"]["internal_caches"][ea]["node_ids"] = copy.deepcopy(self.node_ids)
        self.cto_data["cto_data"]["internal_caches"][ea]["caller_node_ids"] = copy.deepcopy(self.caller_node_ids)
        self.cto_data["cto_data"]["internal_caches"][ea]["exceeded_node_ids"] = copy.deepcopy(self.exceeded_node_ids)
        self.cto_data["cto_data"]["internal_caches"][ea]["related_nodes"] = copy.deepcopy(self.related_nodes)
        self.cto_data["cto_data"]["internal_caches"][ea]["strings_contents"] = copy.deepcopy(self.strings_contents)
        self.cto_data["cto_data"]["internal_caches"][ea]["gvars_contents"] = copy.deepcopy(self.gvars_contents)
        self.cto_data["cto_data"]["internal_caches"][ea]["stroff_contents"] = copy.deepcopy(self.stroff_contents)
        self.cto_data["cto_data"]["internal_caches"][ea]["unresolved_indirect_calls"] = copy.deepcopy(self.unresolved_indirect_calls)
        self.cto_data["cto_data"]["internal_caches"][ea]["node_id_relationships"] = copy.deepcopy(self.node_id_relationships)
        self.cto_data["cto_data"]["internal_caches"][ea]["node_types"] = copy.deepcopy(self.node_types)
        self.cto_data["cto_data"]["internal_caches"][ea]["additional_trace_points"] = copy.deepcopy(self.additional_trace_points)
        self.cto_data["cto_data"]["internal_caches"][ea]["filtered_nodes"] = copy.deepcopy(self.filtered_nodes)
        self.cto_data["cto_data"]["internal_caches"][ea]["trace_points_relations"] = copy.deepcopy(self.trace_points_relations)
        
        if self.config.debug: self.dbg_print("Saved all internal caches for %x%s" % (ea, os.linesep))
    
    # This method is mandary.
    def OnGetText(self, node_id):
        # If it returns self[node_id], IDA can color background nodes
        # automatically. However, you can not use SetNodeInfo for the
        # background of the nodes.
        # Here, it returns just a text instead of a tuple.
        # Then you can use SetNodeInfo afterward.
        try:
            return self[node_id][0]
            #return self[node_id]
        except Exception as e:
            exc_type, exc_obj, tb = sys.exc_info()
            lineno = tb.tb_lineno
            ida_kernwin.msg("Got a unexpected error (%s: %s) (%d)%s" % (str(type(e)), e, lineno, os.linesep))
            if self.config.debug:
                self.dbg_print(traceback.format_exc())
            else:
                traceback.print_exc()
        return ""
    
    def append_result_every_given_items(self, ar_input, ar_result, divided_by=3, separator=", "):
        tmp = []
        for i, name in enumerate(ar_input, 1):
            tmp.append(name)
            if i % divided_by == 0:
                ar_result.append(", ".join(tmp) + ", ")
                tmp = []
        if len(tmp) > 0:
            ar_result.append(", ".join(tmp))
        
    def get_focus(self, w=None):
        if w is None:
            w = self.GetWidget()
        if w is None:
            return False
        if self.config.debug: self.dbg_print("take focus")
        return ida_kernwin.activate_widget(w, True)

    def generate_hint(self, node_id):
        if node_id in self.node_ids:
            ar_result = []
            ea = self.node_ids[node_id]

            if ea in self.func_relations:
                func_type = self.func_relations[ea]['func_type']
                name = self.get_callee_name(ea, func_type) + " (" + hex(ea).rstrip("L") + ")"
                ar_result.append(name)
            else:
                name = ida_name.get_name(ea)
                if name:
                    name += " (" + hex(ea).rstrip("L") + ")"
                else:
                    name = hex(ea).rstrip("L")
                ar_result.append(name)

            f = ida_funcs.get_func(ea)
            if f and f.start_ea == ea:
                fcmt = ida_funcs.get_func_cmt(f, 1)
                if fcmt:
                    ar_result.append("")
                    ar_result.append("[Function Comment]")
                    ar_result.append(fcmt)

            if ea in self.func_relations:
                ar_apis = set([])
                ar_st_libs = set([])
                ar_mem_calls = set([])
                ar_gen_calls = set([])
                ar_vtb_refs = set([])
                for caller, (func_ea, func_type, op, func_name) in [(x, self.func_relations[ea]['children'][x]) for x in self.func_relations[ea]['children']]:
                    if func_name:
                        name = func_name + " (" + hex(caller).rstrip("L") + ")"
                    else:
                        name = self.get_callee_name(func_ea, func_type) + " (" + hex(caller).rstrip("L") + ")"
                    if func_type == FT_API:
                        ar_apis.add(name)
                    elif func_type == FT_LIB:
                        ar_st_libs.add(name)
                    elif func_type == FT_VTB:
                        ar_vtb_refs.add(name)
                    elif func_type == FT_MEM and func_ea == ida_idaapi.BADADDR:
                        name = "%x: %s" % (caller, self.get_space_removed_disasm(caller))
                        ar_mem_calls.add(name)
                    elif func_type in [FT_STR, FT_VAR, FT_STO]:
                        pass
                    else:
                        ar_gen_calls.add(name)

                if len(ar_apis) > 0:
                    ar_result.append("")
                    ar_result.append("[APIs]")
                    self.append_result_every_given_items(ar_apis, ar_result)
                        
                if len(ar_st_libs) > 0:
                    ar_result.append("")
                    ar_result.append("[Static Linked Libraries]")
                    self.append_result_every_given_items(ar_st_libs, ar_result)
            
                if len(ar_vtb_refs) > 0:
                    ar_result.append("")
                    ar_result.append("[Vftables]")
                    self.append_result_every_given_items(ar_vtb_refs, ar_result)
            
                if len(ar_mem_calls) > 0:
                    ar_result.append("")
                    ar_result.append("[Unresolved Indirect Calls]")
                    self.append_result_every_given_items(ar_mem_calls, ar_result)
            
                if len(ar_gen_calls) > 0:
                    ar_result.append("")
                    ar_result.append("[General Internal Calls]")
                    self.append_result_every_given_items(ar_gen_calls, ar_result)
            
                if len(self.func_relations[ea]["strings"]) > 0:
                    ar_result.append("")
                    ar_result.append("[Strings]")
                    for ref_ea in self.func_relations[ea]["strings"]:
                        str_ea = self.func_relations[ea]["strings"][ref_ea][0]
                        str_var_name = ida_name.get_name(str_ea)
                        str_cont = self.func_relations[ea]["strings"][ref_ea][3].replace('\r', '\\r').replace('\n', '\\n')
                        ar_result.append("%x -> %s (%x): %s" % (ref_ea, str_var_name, str_ea, str_cont))
            
                if len(self.func_relations[ea]["gvars"]) > 0:
                    ar_result.append("")
                    ar_result.append("[Global/Static Variables]")
                    for src_ea in self.func_relations[ea]["gvars"]:
                        dst_ea = self.func_relations[ea]["gvars"][src_ea][0]
                        dst_var_name = ida_name.get_name(dst_ea)
                        dst_val = self.func_relations[ea]["gvars"][src_ea][3]
                        ar_result.append("%x -> %s (%x): %s" % (src_ea, dst_var_name, dst_ea, dst_val))
            
                if len(self.func_relations[ea]["struct_offsets"]) > 0:
                    ar_result.append("")
                    ar_result.append("[Struct Members]")
                    for src_ea in self.func_relations[ea]["struct_offsets"]:
                        dst_ea = self.func_relations[ea]["struct_offsets"][src_ea][0]
                        dst_var_name = ida_name.get_name(dst_ea)
                        dst_val = self.func_relations[ea]["struct_offsets"][src_ea][3]
                        opn = self.func_relations[ea]["struct_offsets"][src_ea][2]
                        opstr = idc.print_operand(src_ea, opn)
                        ar_result.append("%x: %s" % (src_ea, opstr))
            
                if len(self.func_relations[ea]["rcmt"]) > 0:
                    ar_result.append("")
                    ar_result.append("[Repeatable Comments]")
                    for cmt_ea in self.func_relations[ea]["rcmt"]:
                        ar_result.append("%x: %s" % (cmt_ea, self.func_relations[ea]["rcmt"][cmt_ea].replace('\r', '\\r').replace('\n', '\\n')))
                if len(self.func_relations[ea]["cmt"]) > 0:
                    ar_result.append("")
                    ar_result.append("[Comments (for the output of several tools)]")
                    for cmt_ea in self.func_relations[ea]["cmt"]:
                        ar_result.append("%x: %s" % (cmt_ea, self.func_relations[ea]["cmt"][cmt_ea].replace('\r', '\\r').replace('\n', '\\n')))
            else:
                # for a node referring to a string or a global/static variable
                if f and f.start_ea in self.func_relations:
                    if ea in self.func_relations[f.start_ea]["strings"]:
                        ar_result.append("")
                        ar_result.append("[Strings]")
                        str_ea = self.func_relations[f.start_ea]["strings"][ea][0]
                        str_var_name = ida_name.get_name(str_ea)
                        str_cont = self.func_relations[f.start_ea]["strings"][ea][3].replace('\r', '\\r').replace('\n', '\\n')
                        ar_result.append("%x -> %s (%x): %s" % (ea, str_var_name, str_ea, str_cont))
                        
                    if ea in self.func_relations[f.start_ea]["gvars"]:
                        ar_result.append("")
                        ar_result.append("[Global/Static Variables]")
                        str_ea = self.func_relations[f.start_ea]["gvars"][ea][0]
                        str_var_name = ida_name.get_name(str_ea)
                        str_cont = self.func_relations[f.start_ea]["gvars"][ea][3]
                        ar_result.append("%x -> %s (%x): %s" % (ea, str_var_name, str_ea, str_cont))
                        
                    if ea in self.func_relations[f.start_ea]["struct_offsets"]:
                        ar_result.append("")
                        ar_result.append("[Struct Members]")
                        str_ea = self.func_relations[f.start_ea]["struct_offsets"][ea][0]
                        str_var_name = ida_name.get_name(str_ea)
                        str_cont = self.func_relations[f.start_ea]["struct_offsets"][ea][3]
                        opn = self.func_relations[f.start_ea]["struct_offsets"][ea][2]
                        opstr = idc.print_operand(ea, opn)
                        ar_result.append("%x: %s" % (ea, opstr))
                        
                # for a node of a string content or a global/static variable
                else:
                    dref_to = ida_xref.get_first_dref_to(ea)
                    while dref_to != ida_idaapi.BADADDR:
                        tmp_f = ida_funcs.get_func(dref_to)
                        if tmp_f and tmp_f.start_ea in self.func_relations and (dref_to in self.func_relations[tmp_f.start_ea]["strings"] or dref_to in self.func_relations[tmp_f.start_ea]["gvars"]):
                            break
                        dref_to = ida_xref.get_first_dref_to(dref_to)
                        
                    if dref_to != ida_idaapi.BADADDR and dref_to in self.func_relations[tmp_f.start_ea]["strings"]:
                        ar_result.append("")
                        ar_result.append("[Strings]")
                        str_ea = self.func_relations[tmp_f.start_ea]["strings"][dref_to][0]
                        str_var_name = ida_name.get_name(str_ea)
                        str_cont = self.func_relations[tmp_f.start_ea]["strings"][dref_to][3].replace('\r', '\\r').replace('\n', '\\n')
                        ar_result.append("%x -> %s (%x): %s" % (dref_to, str_var_name, str_ea, str_cont))
                        for i, x in enumerate(idautils.DataRefsTo(str_ea)):
                            pass
                        ar_result.append("and %d more references" % (i))
                    if dref_to != ida_idaapi.BADADDR and dref_to in self.func_relations[tmp_f.start_ea]["gvars"]:
                        ar_result.append("")
                        ar_result.append("[Global/Static Variables]")
                        str_ea = self.func_relations[tmp_f.start_ea]["gvars"][dref_to][0]
                        str_var_name = ida_name.get_name(str_ea)
                        str_cont = self.func_relations[tmp_f.start_ea]["gvars"][dref_to][3]
                        ar_result.append("%x -> %s (%x): %s" % (dref_to, str_var_name, str_ea, str_cont))
                        for i, x in enumerate(idautils.DataRefsTo(str_ea)):
                            pass
                        ar_result.append("and %d more references" % (i))
                        
                rcmt = ida_bytes.get_cmt(ea, 1)
                if rcmt:
                    ar_result.append("")
                    ar_result.append("[repeatable Comments]")
                    ar_result.append(rcmt)
                cmt = ida_bytes.get_cmt(ea, 0)
                if cmt:
                    ar_result.append("")
                    ar_result.append("[Comments]")
                    ar_result.append(cmt)
            
            x = os.linesep.join(ar_result)
        # for exceeded nodes
        elif node_id > 0 and node_id in self.exceeded_node_ids:
            x = "<more nodes>"
            next_to_ea = self.exceeded_node_ids[node_id]
            
            ids = list(self.find_src_nodes_from_edges(node_id))
            direction = "parents"
            src = self.find_src_node_from_edges(node_id, text=self.exceeded_node_symbol)
            if src < 0:
                direction = "children"
                ids = list(self.find_dst_nodes_from_edges(node_id))

            f = ida_funcs.get_func(next_to_ea)
            if f:
                func_ea = f.start_ea
                num = len(self.func_relations[func_ea][direction])
                if self.config.skip_caller:
                    num = 0
                    callees = set([])
                    for caller in self.func_relations[func_ea][direction]:
                        callee, _, _, _ = self.func_relations[func_ea][direction][caller]
                        if callee != ida_idaapi.BADADDR:
                            callees.add(callee)
                        # for unresolved indirect calls
                        # count up num for each indirect call instead of adding the callee address because they are represented by BADADDR
                        else:
                            num += 1
                    num += len(callees)
                if len(ids) > 1:
                    num -= len(ids) - 1 # minus one is for an exceeded node

                if num >= 0:
                    x = "<%d more function call nodes>" % num
        else:
            x = ""
        return x
    
    def OnHint(self, node_id):
        """
        Triggered when the graph viewer wants to retrieve hint text associated with a given node

        @return: None if no hint is avail or a string designating the hint
        """
        try:
            x = self.generate_hint(node_id)
        except Exception as e:
            exc_type, exc_obj, tb = sys.exc_info()
            lineno = tb.tb_lineno
            ida_kernwin.msg("Got a unexpected error (%s: %s) (%d)%s" % (str(type(e)), e, lineno, os.linesep))
            if self.config.debug:
                self.dbg_print(traceback.format_exc())
            else:
                traceback.print_exc()
            return ""
        return x
        
    def generate_edge_hint(self, src, dst):
        """
        Triggered when the graph viewer wants to retrieve hint text associated with a edge

        @return: None if no hint is avail or a string designating the hint
        """
        if src in self.node_ids:
            src_str = self._nodes[src][0]
            src_ea = self.node_ids[src]
            f = ida_funcs.get_func(src_ea)
            if f and src_ea not in self.func_relations:
                func_name = ida_funcs.get_func_name(src_ea)
                src_str += " (in %s)" % func_name
        elif src > 0:
            src_str = "<more nodes>"
        else:
            src_str = ""

        if dst in self.node_ids:
            dst_str = self._nodes[dst][0]
            dst_ea = self.node_ids[dst]
            f = ida_funcs.get_func(dst_ea)
            if f and dst_ea not in self.func_relations:
                func_name = ida_funcs.get_func_name(dst_ea)
                dst_str += " (in %s)" % func_name
        elif dst > 0:
            dst_str = "<more nodes>"
        else:
            dst_str = ""
        if not src_str and not dst_str:
            return ""
        return "%s -> %s" % (src_str, dst_str)
    
    def OnEdgeHint(self, src, dst):
        """
        Triggered when the graph viewer wants to retrieve hint text associated with a edge

        @return: None if no hint is avail or a string designating the hint
        """
        try:
            x = self.generate_edge_hint(src, dst)
        except Exception as e:
            exc_type, exc_obj, tb = sys.exc_info()
            lineno = tb.tb_lineno
            ida_kernwin.msg("Got a unexpected error (%s: %s) (%d)%s" % (str(type(e)), e, lineno, os.linesep))
            if self.config.debug:
                self.dbg_print(traceback.format_exc())
            else:
                traceback.print_exc()
            return ""
        return x
    
    # path_finder's config
    pf_args = ((SKIP_CHILDREN,  "_skip_children" , "to"     , ""),
               (SKIP_PARENTS,   "_skip_parents"  , "from"   , ""),
               (DO_NOT_SKIP,    "_do_not_skip"   , "from/to", ""),
               (DO_NOT_SKIP,    "_start_end"     , "from"   , " to ... (extremely slow)"),
               (DO_NOT_SKIP,    "_end_start"     , "to"     , " from ... (extremely slow)"),
               (DO_NOT_SKIP,    "_start_end_skip", "from"   , " to ... (tracing til libs and APIs) (very slow)"),
               (DO_NOT_SKIP,    "_end_start_skip", "to"     , " from ... (tracing til libs and APIs) (very slow)"),
               )
    
    def path_finder_permanent_action_name(self, prefix="cto:path_finder"):
        for skip, act_postfix, direction, direction2 in self.pf_args:
            actname = "%s%s" % (prefix, act_postfix)
            yield actname, skip, direction, direction2
    
    def popup_dispatcher(self, form, popup_handle):
        # get the selected node
        r = self.get_selected_node()
        if not r or len(r) != 1:
            return
        
        # Print hint
        actname = "hint_printer:%s" % self.title
        desc = ida_kernwin.action_desc_t(actname, "Print hint", self.hint_printer(self))
        ida_kernwin.attach_dynamic_action_to_popup(form, popup_handle, desc)

        # Change Primary Node
        if r and len(r) == 1:
            nid = r[0]
            if nid in self.node_ids and self.node_ids[nid] in self.func_relations:
                actname = "change_primary_node:%s" % self.title
                desc = ida_kernwin.action_desc_t(actname, "Change the primary node here", self.change_primary_node(self))
                ida_kernwin.attach_dynamic_action_to_popup(form, popup_handle, desc)
        
        # Go to a next to node
        if r and len(r) == 1:
            for d in ["parents", "children"]:
                actname = "go_to_%s:%s" % (d, self.title)
                if d == "parents":
                    desc_direction = "parent"
                else:
                    desc_direction = "child"
                desc = ida_kernwin.action_desc_t(actname, "Go to a %s node" % desc_direction, self.go_to_node(self, d))
                ida_kernwin.attach_dynamic_action_to_popup(form, popup_handle, desc)
        
        # Add a "cref from" to this node
        if r and len(r) == 1:
            nid = r[0]
            if nid in self.node_ids:
                ea = self.node_ids[nid]
                f = ida_funcs.get_func(ea)
                if f and f.start_ea in self.func_relations:
                    if ea in self.func_relations[f.start_ea]['children']:
                        callee, func_type, op, func_name =  self.func_relations[f.start_ea]['children'][ea]
                        if callee == ida_idaapi.BADADDR and not func_name:
                            actname = "add_cref_from:%s" % self.title
                            desc = ida_kernwin.action_desc_t(actname, "Add a \"cref from\" to this node", self.add_cref_from(self))
                            ida_kernwin.attach_dynamic_action_to_popup(form, popup_handle, desc)
        
        # Delete a "cref from" from this node
        if r and len(r) == 1:
            nid = r[0]
            if nid in self.node_ids:
                ea = self.node_ids[nid]
                f = ida_funcs.get_func(ea)
                if f and f.start_ea in self.func_relations:
                    if ea in self.func_relations[f.start_ea]['children']:
                        callee, func_type, op, func_name =  self.func_relations[f.start_ea]['children'][ea]
                        if callee != ida_idaapi.BADADDR and not func_name:
                            actname = "del_cref_from:%s" % self.title
                            desc = ida_kernwin.action_desc_t(actname, "Delete a \"cref from\" to this node", self.del_cref_from(self))
                            ida_kernwin.attach_dynamic_action_to_popup(form, popup_handle, desc)
        
        # Expand/Collapse a node
        actname = "expand_collapse:%s" % self.title
        if r and len(r) == 1:
            msg = ""
            nid = r[0]
            if nid in self.node_ids:
                msg = "Collapse under/over this node"
            elif nid in self.exceeded_node_ids:
                msg = "Expand this"
            if msg:
                desc = ida_kernwin.action_desc_t(actname, msg, self.expand_collapse_node(self))
                ida_kernwin.attach_dynamic_action_to_popup(form, popup_handle, desc)
        
        # Path finder
        for skip, act_postfix, direction, direction2 in self.pf_args:
            actname = "path_finder%s:%s" % (act_postfix, self.title)
            if r and len(r) == 1:
                nid = r[0]
                if nid in self.node_ids:
                    desc = ida_kernwin.action_desc_t(actname, "Find the path(s) %s this node%s" % (direction, direction2), self.path_finder(self, skip, actname))
                    ida_kernwin.attach_dynamic_action_to_popup(form, popup_handle, desc)
                    
    def OnPopup(self, form, popup_handle):
        try:
            self.popup_dispatcher(form, popup_handle)
        except Exception as e:
            exc_type, exc_obj, tb = sys.exc_info()
            lineno = tb.tb_lineno
            ida_kernwin.msg("Got a unexpected error (%s: %s) (%d)%s" % (str(type(e)), e, lineno, os.linesep))
            if self.config.debug:
                self.dbg_print(traceback.format_exc())
            else:
                traceback.print_exc()
            
    def _get_selected_node(self, w=None):
        if w is None:
            w = self.GetWidget()
        if w is None:
            return None
        sel = ida_graph.screen_graph_selection_t()
        gv = ida_graph.get_graph_viewer(w)
        ida_graph.viewer_get_selection(gv, sel)
        if sel:
            for s in sel:
                if s.is_node:
                    if self.config.debug: self.dbg_print("Selected node %d" % s.node)
                    return (s.node,)
                else:
                    if self.config.debug: self.dbg_print("Selected edge %d -> %d" % (s.elp.e.src, s.elp.e.dst))
                    return (s.elp.e.src, s.elp.e.dst)
        return None
    
    def get_selected_node(self, w=None):
        r = None
        try:
            r = self._get_selected_node(w)
        except Exception as e:
            exc_type, exc_obj, tb = sys.exc_info()
            lineno = tb.tb_lineno
            ida_kernwin.msg("Got a unexpected error (%s: %s) (%d)%s" % (str(type(e)), e, lineno, os.linesep))
            if self.config.debug:
                self.dbg_print(traceback.format_exc())
            else:
                traceback.print_exc()
        return r
            # action before quitting
    def _close(self):
        to_be_removed = []
        # for main CTO
        if self.parent is None:
            len_sb = len(self.sub_graphs)
            for i in reversed(range(len_sb)):
                if self.config.debug: self.dbg_print("Quitting %s%s" % (self.sub_graphs[i].title, os.linesep))

                # unhook subgraph's hooks
                # note that it seems that IDA does not wait to finish Close() method of the call graph.
                # that's why it unhooks them manually here.
                r = self.sub_graphs[i].ui_hooks_trampoline.unhook()
                if self.config.debug: self.dbg_print("unhooked ui_hooks_trampoline for %s. result: %s%s" % (self.sub_graphs[i].title, str(r), os.linesep))
                
                r = self.sub_graphs[i].my_ui_hooks.unhook()
                if self.config.debug: self.dbg_print("unhooked my_ui_hooks for %s. result: %s%s" % (self.sub_graphs[i].title, str(r), os.linesep))
                r = self.sub_graphs[i].my_view_hooks.unhook()
                if self.config.debug: self.dbg_print("unhooked my_view_hooks for %s. result: %s%s" % (self.sub_graphs[i].title, str(r), os.linesep))

                # close a debug file if available
                if self.sub_graphs[i].f:
                    fn = self.sub_graphs[i].f.name
                    self.sub_graphs[i].f.close()
                    self.sub_graphs[i].f = None
                    if self.config.debug: self.dbg_print("closed debug file (%s) for %s. %s" % (fn, self.sub_graphs[i].title, os.linesep))

                # close the subgraph window
                self.sub_graphs[i].Close()
                if self.config.debug: self.dbg_print("Close() method executed for %s%s" % (self.sub_graphs[i].title, os.linesep))
                
                if i < len(self.sub_graphs):
                    to_be_removed.append(i)
            if self.icon_id > 0:
                ida_kernwin.free_custom_icon(self.icon_id)
            
        # for a subgraph
        else:
            for i, sg in enumerate(self.parent.sub_graphs):
                if sg.title == self.title:
                    to_be_removed.append(i)
                    break
                
        # unhook ui hooks and view hooks
        # I do not need to care about what unhook methods are called twice. it might occur when this method (Close()) is called from a subgraph.
        if self.config.debug: self.dbg_print("Unhooking ui and view hooks for %s%s" % (self.title, os.linesep))
        self.ui_hooks_trampoline.unhook()
        self.my_ui_hooks.unhook()
        self.my_view_hooks.unhook()
        if self.config.debug: self.dbg_print("Unhooked ui and view hooks for %s%s" % (self.title, os.linesep))
        
        # remove subgraphs
        for i in sorted(to_be_removed, reverse=True):
            if self.config.debug: self.dbg_print("removing %s from the subgraph list%s" % (self.title, os.linesep))
            # for main CTO
            if self.parent is None:
                if  len(self.sub_graphs) > i:
                    self.sub_graphs.pop(i)
            # for subgraphs
            else:
                if len(self.parent.sub_graphs) > i:
                    self.parent.sub_graphs.pop(i)
        if self.config.debug: self.dbg_print("Quited %s%s" % (self.title, os.linesep))

        self.close_data()
        if hasattr(self, "sd"):
            self.sd.close()
        
        # close tempfile for debug log
        if self.f:
            self.f.close()
            self.f = None
        
    def close(self):
        try:
            self._close()
        except Exception as e:
            exc_type, exc_obj, tb = sys.exc_info()
            lineno = tb.tb_lineno
            ida_kernwin.msg("Got a unexpected error (%s: %s) (%d)%s" % (str(type(e)), e, lineno, os.linesep))
            if self.config.debug:
                self.dbg_print(traceback.format_exc())
            else:
                traceback.print_exc()
            
    def OnClose(self):
        if self.config.debug: self.dbg_print("Quitting %s%s" % (self.title, os.linesep))
        self.close()
    
    def print_caches(self):
        ida_kernwin.msg("additona_trace_points: %s%s" % (str([hex(x).rstrip("L") for x in self.additional_trace_points]), os.linesep))
        ida_kernwin.msg("filtered_nodes       : %s%s" % (str([hex(x).rstrip("L") for x in self.filtered_nodes]), os.linesep))
        import pprint
        class MyPrettyPrinter(pprint.PrettyPrinter):
            def format(self, object, context, maxlevels, level):
                if isinstance(object, int):
                    return '0x{:X}'.format(object), True, False
                return super().format(object, context, maxlevels, level)

        pp = MyPrettyPrinter()
        ida_kernwin.msg("related_nodes: " + os.linesep)
        pp.pprint(self.related_nodes)
        ida_kernwin.msg("trace_points_relations: " + os.linesep)
        pp.pprint(self.trace_points_relations)
        ida_kernwin.msg("exceeded_nodes: " + os.linesep)
        pp.pprint(self.exceeded_nodes)
        ida_kernwin.msg("node_id_relationships: " + os.linesep)
        pp.pprint(self.node_id_relationships)
    
    # ida_graph.viewer_center_on will crash if the give node id is invalid.
    # so I need to protect.
    def do_center_node(self, nid, w=None):
        r = False
        try:
            if w is None:
                w = self.GetWidget()
            if w is None:
                return False
            if nid < len(self._nodes):
                gv = ida_graph.get_graph_viewer(w)
                ida_graph.viewer_center_on(gv, nid)
                r = True
        except Exception as e:
            exc_type, exc_obj, tb = sys.exc_info()
            lineno = tb.tb_lineno
            ida_kernwin.msg("Got a unexpected error (%s: %s) (%d)%s" % (str(type(e)), e, lineno, os.linesep))
            if self.config.debug:
                self.dbg_print(traceback.format_exc())
            else:
                traceback.print_exc()
        return r
        
    def select(self, nid):
        try:
            if nid < len(self._nodes):
                self.Select(nid)
        except Exception as e:
            exc_type, exc_obj, tb = sys.exc_info()
            lineno = tb.tb_lineno
            ida_kernwin.msg("Got a unexpected error (%s: %s) (%d)%s" % (str(type(e)), e, lineno, os.linesep))
            if self.config.debug:
                self.dbg_print(traceback.format_exc())
            else:
                traceback.print_exc()
        
    # this action is implemented in viewer hooks. see my_view_hooks_t
    '''
    def OnClick(self, node_id):
        """
        Triggered when a node is clicked
        @return: False to ignore the click and True otherwise
        """
        self.dbg_print("clicked on node:", node_id, node_text)
        return True
    '''
        
    def trace_additional_points(self, ea, target_ea=ida_idaapi.BADADDR, direction="parents", result=None, force_trace=False, nrecursive=0):
        if result is None:
            result = [ea]

        if self.config.debug:
            self.dbg_print("ea: %x, related_nodes: %s" % (ea, str([hex(x).rstrip("L") for x in self.related_nodes])))
        if target_ea != ida_idaapi.BADADDR and target_ea in self.related_nodes[ea]:
            yield tuple(result)
        elif nrecursive >= self.max_recursive and target_ea == ida_idaapi.BADADDR and force_trace == False:
            if len(self.trace_points_relations[ea][direction]) > 0:
                result.append(ida_idaapi.BADADDR)
                yield tuple(result)
                result.pop(-1)
            else:
                yield tuple(result)
        else:
            # ea reached a limitation
            if ea == ida_idaapi.BADADDR:
                if target_ea == ida_idaapi.BADADDR:
                    yield tuple(result)
            # ea is a leaf node
            elif len(self.trace_points_relations[ea][direction]) == 0:
                if target_ea == ida_idaapi.BADADDR:
                    yield tuple(result)
            # ea is in the middle of the function tree
            else:
                for next_ea in self.trace_points_relations[ea][direction]:
                    # trace a upper or lower function
                    if next_ea not in result:
                        result.append(next_ea)
                        for r in self.trace_additional_points(next_ea, target_ea, direction, result, force_trace, nrecursive+1):
                            yield r
                        result.pop(-1)
                    else:
                        # detecting a recursive call
                        if target_ea == ida_idaapi.BADADDR:
                            result.append(next_ea)
                            yield tuple(result)
                            result.pop(-1)
    
    def filter_nodes(self, node_id):
        refresh_flag = False
        node_ea = self.node_ids[node_id]
        if self.config.debug:
            self.dbg_print("filtering out %x (%d)" % (node_ea, node_id))
        start_ea = ida_idaapi.BADADDR
        if node_ea in self.additional_trace_points:
            start_ea = node_ea
        else:
            if self.config.debug:
                self.dbg_print("keys and quantities of related_nodes:", [(hex(x).rstrip("L"), len(self.related_nodes[x])) for x in self.related_nodes])
            for ea in self.related_nodes:
                if self.config.debug:
                    self.dbg_print("node_ea:", hex(node_ea).rstrip("L"), ", ea of related_nodes'key:", hex(ea).rstrip("L"), ", related_nodes:", [hex(x).rstrip("L") for x in self.related_nodes[ea]])
                if node_ea in self.related_nodes[ea]:
                    start_ea = ea
                    break
        if start_ea == ida_idaapi.BADADDR:
            ida_kernwin.msg("I cannot filter the node" + os.linesep)
            return refresh_flag

        # get the direction to the primary ea        
        direction = None
        # I skip this process if start_ea is the primary node. I need node-to-node tracing.
        if start_ea != self.start_ea:
            r = list(self.trace_additional_points(start_ea, target_ea=self.start_ea, direction="parents"))
            if self.config.debug: self.dbg_print([hex(x).rstrip("L") for y in r for x in y])
            if len(r) > 0:
                direction = "parents"
                if self.config.debug: self.dbg_print("parents1")
            else:
                r = list(self.trace_additional_points(start_ea, target_ea=self.start_ea, direction="children"))
                if self.config.debug: self.dbg_print([hex(x).rstrip("L") for y in r for x in y])
                if len(r) > 0:
                    direction = "children"
                    if self.config.debug: self.dbg_print("children1")
        if direction is None:
            r = list(self.find_path(node_id, end_nid=self.nodes[self.start_ea], direction='up'))
            if self.config.debug: self.dbg_print(r)
            if len(r) > 0:
                if self.config.debug: self.dbg_print("parents2")
                direction = "parents"
            else:
                r = list(self.find_path(node_id, end_nid=self.nodes[self.start_ea], direction='down'))
                if self.config.debug: self.dbg_print(r)
                if len(r) > 0:
                    if self.config.debug: self.dbg_print("children2")
                    direction = "children"
        
        if start_ea == ida_idaapi.BADADDR:
            ida_kernwin.msg("I cannot filter the node" + os.linesep)
            return refresh_flag

        if self.config.debug: self.dbg_print("start_ea:", hex(start_ea).rstrip("L"))
        
        if direction == "children":
            next_nids = self.find_src_nodes_from_edges(node_id)
        else:
            next_nids = self.find_dst_nodes_from_edges(node_id)
        
        # if the next_nid isn't in nodes, it is already filtered out. I do not need to do anything.
        # remove additional points beyond a filtered node
        tobe_removed = set([])
        for next_nid in next_nids:
            if self.config.debug: self.dbg_print("next_nid:", next_nid, "next_ea:", hex(self.node_ids[next_nid]).rstrip("L"))
            if next_nid in self.node_ids:
                node_id_ea = self.node_ids[node_id]
                next_id_ea = self.node_ids[next_nid]
                call_type = 'caller'
                if node_id_ea in self.func_relations and node_id_ea not in self.caller_nodes:
                    call_type = 'callee'
                if call_type == 'callee':
                    callee_ea = node_id_ea
                else:
                    callee_ea = next_id_ea
                if self.config.debug: self.dbg_print("filtering out node key: %x, value: %x, call_type: %s" % (node_id_ea, callee_ea, call_type))
                self.filtered_nodes[node_id_ea] = (callee_ea, self._nodes[node_id], call_type)
                if self.config.debug:
                    self.dbg_print(direction, [(hex(x).rstrip("L"), hex(self.filtered_nodes[x][0]).rstrip("L"), self.filtered_nodes[x][1], self.filtered_nodes[x][2]) for x in self.filtered_nodes])
                refresh_flag = True
                if len(self.additional_trace_points) > 0:
                    opposite_direction = "parents"
                    if direction == "parents":
                        opposite_direction = "children"
                    for r in self.trace_additional_points(start_ea, target_ea=ida_idaapi.BADADDR, direction=opposite_direction):
                        if self.config.debug:
                            self.dbg_print("opposite_direction (to start address):", opposite_direction, ", start_ea:", hex(start_ea).rstrip("L"), ", node_ea:", hex(node_ea).rstrip("L"), ", trace result:", [hex(x).rstrip("L") for x in r], ", additional_points:", [hex(x).rstrip("L") for x in self.additional_trace_points])
                        remove_flag = False
                        first_flag = True
                        for i, ea in enumerate(r):
                            if self.config.debug: self.dbg_print("i: %d, node_ea:%x, loop_ea: %x, additonal_trace_points:%s, related_nodes: %s" % (i, node_ea, ea, str([hex(x).rstrip("L") for x in self.additional_trace_points]), str([hex(x).rstrip("L") for x in self.related_nodes[ea]])))
                            # if the path starts in the midle of the additional trace points, ignore the first node.
                            if first_flag and self.start_ea == start_ea:
                                # if flag is turned on, remove the additional tracing point and further ones.
                                if self.config.debug: self.dbg_print("remove_flag turned on, but it will affect next time")
                                remove_flag = True
                                first_flag = False
                                continue
                            elif node_ea in self.additional_trace_points:
                                # if flag is turned on, remove the additional tracing point and further ones.
                                if self.config.debug: self.dbg_print("remove_flag turned on")
                                remove_flag = True
                                #continue
                            elif ea in self.related_nodes and node_ea in self.related_nodes[ea]:
                                # I need to trace in ea reladted nodes if they have multiple paths.
                                tmp_direction = 'up'
                                if opposite_direction == 'children':
                                    tmp_direction = 'down'
                                for p in self.find_path(self.nodes[ea], end_nid=-1, direction=tmp_direction, nodes_limitation=set([self.nodes[x] for x in self.related_nodes[ea]])):
                                    if self.config.debug: self.dbg_print("path (id):", [x for x in p])
                                    if self.config.debug:
                                        tmp_ar = []
                                        for x in p:
                                            if x in self.node_ids:
                                                tmp_ar.append(hex(self.node_ids[x]).rstrip("L"))
                                            elif x in self.exceeded_node_ids:
                                                tmp_ar.append(hex(self.exceeded_node_ids[x]).rstrip("L") + " (exceeded)")
                                            else:
                                                tmp_ar.append("error_id (%d)" % x)
                                        self.dbg_print("path (ea):", tmp_ar)
                                    if node_id in p:
                                        last_id = p[-1]
                                        if self.config.debug: self.dbg_print("last_id: %d, %x, i: %d, len(r):%d" % (last_id, self.node_ids[last_id], i, len(r)))
                                        if i+1 < len(r):
                                            next_additional_point_ea = r[i+1]
                                            if self.config.debug: self.dbg_print("next_additonal_point: %x" % (next_additional_point_ea))
                                            if direction == "children":
                                                next_nids = self.find_src_nodes_from_edges(last_id)
                                            else:
                                                next_nids = self.find_dst_nodes_from_edges(last_id)
                                            for tmp_id in next_nids:
                                                if tmp_id in self.node_ids:
                                                    if self.config.debug:
                                                        self.dbg_print("tmp_id: %d, tmp_id_ea: %x" % (tmp_id, self.node_ids[tmp_id]))
                                                        self.dbg_print("next id of the last id: %d, %x, next_additional_point_ea: %x" % (tmp_id, self.node_ids[tmp_id], next_additional_point_ea))
                                                    if next_additional_point_ea == self.node_ids[tmp_id]:
                                                        if self.config.debug: self.dbg_print("add %x to be removed list" % self.node_ids[tmp_id])
                                                        tobe_removed.add(self.node_ids[tmp_id])
                                                        remove_flag = True
                                                else:
                                                    if self.config.debug: self.dbg_print("tmp_id: %d, exceeded_tmp_id_ea: %x" % (tmp_id, self.exceeded_node_ids[tmp_id]))
                                # turned on but skip this area into the remove list
                                if remove_flag:
                                    if self.config.debug: self.dbg_print("remove_flag turned on (2)")
                                    continue
                            if remove_flag:
                                if self.config.debug:
                                    self.dbg_print("to be removed %x from the additional tracing point list" %ea)
                                if ea != self.start_ea:
                                    tobe_removed.add(ea)
                                """
                                if ea == self.start_ea:
                                    for r in self.trace_additional_points(start_ea, direction=direction):
                                        for tmp_ea in r:
                                            tobe_removed.add(tmp_ea)
                                    break
                                else:
                                    tobe_removed.add(ea)
                                """
        """
        # to be implemented if needed
        # second selection
        if self.config.debug: self.dbg_print("to_be_removed:", str([hex(x) for x in tobe_removed]))
        d = 'up'
        if direction == 'parents':
            d = 'down'
        r = list(self.find_path(self.nodes[self.start_ea], end_nid=node_id, direction=d))
        print("r (id):", r)
        print("r (ea):", [hex(self.node_ids[y]) for x in r for y in x])
        print("tobe_removed:", [hex(x) for x in tobe_removed])
        second_tobe_removed = []
        for i, p in enumerate(r):
            for ea in tobe_removed:
                print(self.nodes[ea])
                if self.nodes[ea] in p:
                    if i == len(second_tobe_removed):
                        second_tobe_removed.append([ea])
                    else:
                        second_tobe_removed[i].append(ea)
        if len(second_tobe_removed) > 0:
            final_tobe_removed = set(second_tobe_removed[0])
            for x in second_tobe_removed:
                final_tobe_removed &= set(x)
                print("a second candidate list", [hex(y) for y in x])
            print("final list:", [hex(x) for x in final_tobe_removed])
        """
        
        d = 'down'
        if direction == 'parents':
            d = 'up'
        second_tobe_removed = []
        for ea in tobe_removed:
            if ea in self.additional_trace_points:
                # check if node id has another path and if it has, skip removing.
                flag = True
                r = list(self.find_path(self.nodes[ea], end_nid=self.nodes[self.start_ea], direction=d))
                if self.config.debug: self.dbg_print(r)
                if len(r) > 1:
                    for i, p in enumerate(r):
                        # if a point is not in the path, it means the point has another path.
                        if self.config.debug: self.dbg_print("node_id:", node_id, "nid of an additional_trace_point:", self.nodes[ea], "a path:", p)
                        if node_id not in p:
                            flag = False
                            break
                        """
                        # to be implemented if needed
                        else:
                            for nid in p:
                                #if nid in self.additional_trace_points:
                                if self.node_ids[nid] in tobe_removed:
                                    if i == len(second_tobe_removed):
                                        second_tobe_removed.append([self.node_ids[nid]])
                                    else:
                                        second_tobe_removed[i].append(self.node_ids[nid])
                            print(second_tobe_removed)
                        """
                                    
                if flag:
                    if self.config.debug: self.dbg_print("removing %x from the additonal_trace_points list" % ea)
                    self.additional_trace_points.pop(ea)
                    if ea in self.trace_points_relations:
                        self.trace_points_relations.pop(ea)
                        for tmp_ea in self.trace_points_relations:
                            if ea in self.trace_points_relations[tmp_ea]['parents']:
                                self.trace_points_relations[tmp_ea]['parents'].remove(ea)
                            if ea in self.trace_points_relations[tmp_ea]['children']:
                                self.trace_points_relations[tmp_ea]['children'].remove(ea)
                            
        return refresh_flag
    
    def _expand_collapse_node(self, node_id):
        """
        Triggered when a node is double-clicked.
        @return: False to ignore the click and True otherwise
        """
        if self.config.debug:
            self.dbg_print("double-clicked on", self[node_id])
            
        # disable auto reload until this function ends
        self.dont_auto_reload = True
        
        refresh_flag = False
        skip_add_trace_points = False
        saved_ea = ida_idaapi.BADADDR
        # for double clicking on an exceeded node to expand the node.
        if node_id in self.exceeded_node_ids:
            if self.config.debug:
                self.dbg_print(node_id, hex(self.exceeded_node_ids[node_id]).rstrip("L"))
            next_ea = self.exceeded_node_ids[node_id]
            src = self.find_src_node_from_edges(node_id)
            dst = self.find_dst_node_from_edges(node_id)
            # next_id will be its previous caller if a callee is filtered. Otherwise, it will be its previous callee.
            if self.config.debug:
                self.dbg_print(src, dst)
            next_id = src
            if dst >= 0:
                next_id = dst
            saved_ea = self.node_ids[next_id]
            # for a filtered out callee
            if self.config.debug:
                self.dbg_print("next_id:", next_id, ", next_ea:", hex(next_ea).rstrip("L"), ", next_node_ea:", hex(self.node_ids[next_id]).rstrip("L"), ", filtered_nodes:", [hex(x).rstrip("L") for x in self.filtered_nodes], ", additional trace points:", [hex(x).rstrip("L") for x in self.additional_trace_points], ", exceeded_nodes:", [hex(x).rstrip("L") for x in self.exceeded_nodes])
            if next_ea in self.filtered_nodes:
                callee_or_caller = self.filtered_nodes.pop(next_ea)
                self.dbg_print("filtered_node_value:", hex(callee_or_caller[0]).rstrip("L"), ". it might be a callee address.")
                # the double-clicked node was caller. I need to register a callee ea. replace next_ea with the callee ea.
                if next_ea != callee_or_caller[0]:
                    next_ea = callee_or_caller[0]
                    # I will skip adding additional trace points and updating relationships between those points if the next to ea of the exceeded node is not callee but caller.
                    skip_add_trace_points = True
            
            # get the exact node id of the callee/caller node and push to to the additional trace points's queue
            if not skip_add_trace_points:
                if next_ea not in self.trace_points_relations:
                    self.trace_points_relations[next_ea] = {"parents":set([]), "children":set([])}
                
                # for parents nodes
                src = self.find_src_node_from_edges(next_id, text=self.exceeded_node_symbol)
                if self.config.debug:
                    self.dbg_print("exceeded_node:", src, ", prev_node:", hex(self.node_ids[next_id]).rstrip("L"), next_id, [hex(x).rstrip("L") for x in self.filtered_nodes])
                if src == node_id:
                    self.additional_trace_points[next_ea] = "parents"
                    # build parents/children or succs/preds relations
                    for start_ea in self.related_nodes:
                        if self.config.debug:
                            self.dbg_print("start_ea: %x, next_ea: %x, related_nodes:%s" % (start_ea, next_ea, str([hex(x).rstrip("L") for x in self.related_nodes[start_ea]])))
                        if next_ea in self.related_nodes[start_ea]:
                            self.trace_points_relations[next_ea]["children"].add(start_ea)
                            if start_ea not in self.trace_points_relations:
                                self.trace_points_relations[start_ea] = {"parents":set([]), "children":set([])}
                            self.trace_points_relations[start_ea]["parents"].add(next_ea)
                
                # for children nodes
                dst = self.find_dst_node_from_edges(next_id, text=self.exceeded_node_symbol)
                if self.config.debug:
                    self.dbg_print("exceeded_node:", dst, ", next_node:", hex(self.node_ids[next_id]).rstrip("L"), next_id, [hex(x).rstrip("L") for x in self.filtered_nodes])
                if dst == node_id:
                    self.additional_trace_points[next_ea] = "children"
                    # build parents/children or succs/preds relations
                    for start_ea in self.related_nodes:
                        if self.config.debug:
                            self.dbg_print("start_ea: %x, next_ea: %x, related_nodes:%s" % (start_ea, next_ea, str([hex(x).rstrip("L") for x in self.related_nodes[start_ea]])))
                        if next_ea in self.related_nodes[start_ea]:
                            self.trace_points_relations[next_ea]["parents"].add(start_ea)
                            if start_ea not in self.trace_points_relations:
                                self.trace_points_relations[start_ea] = {"parents":set([]), "children":set([])}
                            self.trace_points_relations[start_ea]["children"].add(next_ea)
            
            refresh_flag = True
        
        # for double-clicking on a general node for filtering out nodes under/over it.
        elif node_id in self.node_ids:
            if self.config.debug:
                self.dbg_print(node_id, hex(self.node_ids[node_id]).rstrip("L"))
            if node_id == self.nodes[self.start_ea]:
                ida_kernwin.msg("The primary node cannot be filtered out." + os.linesep)
                return False
            
            saved_ea = self.node_ids[node_id]

            # check if the node is leaf or not
            src = self.find_src_node_from_edges(node_id)
            dst = self.find_dst_node_from_edges(node_id)
            if src < 0 or dst < 0:
                next_node = src
                direction = "parents"
                if dst >= 0:
                    next_node = dst
                    direction = "children"
                ida_kernwin.msg("if you want to filter out the leaf node, double-click \"%s\" node, which is the %s node of the node.%s" % (ida_lines.tag_remove(self._nodes[next_node][0]), direction, os.linesep))
                return False

            # filter the node
            refresh_flag = self.filter_nodes(node_id)
            
        # if refresh_flag is enabled, refresh the tree.
        if refresh_flag:
            if saved_ea != ida_idaapi.BADADDR:
                ea = saved_ea
                f = ida_funcs.get_func(saved_ea)
                if f:
                    ea = f.start_ea
                    
            self.to_be_saved_ea = self.start_ea
            self.use_internal_function_cache = False
            self.refresh()
            
        # jump to double-clicked location
        if saved_ea != ida_idaapi.BADADDR:
            self.jumpto(saved_ea)
            flag = True
            if saved_ea in self.nodes:
                nid = self.nodes[saved_ea]
            elif self.start_ea in self.nodes:
                nid = self.nodes[self.start_ea]
            else:
                nid = -1
                flag = False
            if flag and nid >= 0:
                if self.config.center_node and not self.is_node_in_canvas(nid):
                    self.do_center_node(nid)
                self.select(nid)
        
        # enable auto reload again
        self.dont_auto_reload = False
        
        if self.config.debug:
            self.dbg_print("OnDblClick() finished.")
        self.get_focus(self.GetWidget())
        return True
    
    def OnDblClick(self, node_id):
        r = False
        try:
            r = self._expand_collapse_node(node_id)
        except Exception as e:
            exc_type, exc_obj, tb = sys.exc_info()
            lineno = tb.tb_lineno
            ida_kernwin.msg("Got a unexpected error (%s: %s) (%d)%s" % (str(type(e)), e, lineno, os.linesep))
            if self.config.debug:
                self.dbg_print(traceback.format_exc())
            else:
                traceback.print_exc()
        return r
    
    def does_use_opn(self):
        use_opn = False
        w = self.GetWidget()
        if w:
            gv = ida_graph.get_graph_viewer(w)
            nid = ida_graph.viewer_get_curnode(gv)
            if nid >= 0 and nid in self.caller_node_ids:
                use_opn = True
        return use_opn
    
    def jumpto(self, ea, use_opn=None):
        r = False
        if use_opn is None:
            use_opn = self.does_use_opn()
        try:
            if ea in self.nodes or ea in self.caller_nodes:
                r = self._jumpto(ea, use_opn=use_opn)
        except Exception as e:
            exc_type, exc_obj, tb = sys.exc_info()
            lineno = tb.tb_lineno
            ida_kernwin.msg("Got a unexpected error (%s: %s) (%d)%s" % (str(type(e)), e, lineno, os.linesep))
            if self.config.debug:
                self.dbg_print(traceback.format_exc())
            else:
                traceback.print_exc()
        return r

    def exec_ui_action(self, action, w=None):
        if w is None:
            w = self.GetWidget()
        return self._exec_ui_action(action, w)
            
    def get_node_hint(self):
        r = self.get_selected_node()
        if r:
            if len(r) == 1:
                x = self.OnHint(r[0])
            else:
                x = self.OnEdgeHint(*r)
            if x:
                hint = ida_lines.tag_remove(x) + os.linesep
                return hint
        return ""
    
    def OnViewKeydown(self, key, state):
        # for state
        SHIFT = 1
        ALT = 2
        CTRL = 4
        ESC_KEY = 0x1000000
        ENTER_KEY = 0x1000004
        RETURN_KEY = 0x1000005

        if self.config.debug: self.dbg_print("pressed key: %d, state; %d" % (key, state))
        
        c = chr(key & 0xFF)

        # toggle Centering the clicked node
        if key == ESC_KEY and state == 0:
            self.exec_ida_ui_action("Return")
        elif key in [ENTER_KEY, RETURN_KEY] and state == CTRL:
            self.exec_ida_ui_action("UndoReturn")
        elif c == 'C' and state == 0:
            self.config.center_node = not self.config.center_node
            ida_kernwin.msg("centering graph %sabled%s" % ("en" if self.config.center_node else "dis", os.linesep))
        # toggle Debug message
        elif c == 'D' and state == 0:
            self.config.debug = not self.config.debug
            ida_kernwin.msg("debugging %sabled%s" % ("en" if self.config.debug else "dis", os.linesep))
        # Reload the current view
        elif c == 'R' and state == 0:
            self.refresh()
            ida_kernwin.msg("Refreshed." + os.linesep)
        # Force refresh
        elif c == 'F' and state == 0:
            if self.force_reload():
                ida_kernwin.msg("Force reloaded." + os.linesep)
            else:
                ida_kernwin.msg("Not reloaded." + os.linesep)
        # toggle Auto reload option
        elif c == 'A' and state == ALT:
            self.config.auto_reload_outside_node = not self.config.auto_reload_outside_node
            ida_kernwin.msg("Auto-reload option %sabled%s" % ("en" if self.config.auto_reload_outside_node else "dis", os.linesep))
        # toggle Auto reload option
        elif c == 'S' and state == SHIFT:
            self.config.save_caches = not self.config.save_caches
            ida_kernwin.msg("Save all internal caches option %sabled%s" % ("en" if self.config.save_caches else "dis", os.linesep))
            if self.config.save_caches:
                ida_kernwin.msg("This option is an ***EXPERIMENTAL*** feature. It may cause a problem.%s" % (os.linesep))
        # go to the Start address
        elif c == 'S' and state == 0:
            self.jumpto(self.start_ea)
            nid = self.nodes[self.start_ea]
            if self.config.center_node and not self.is_node_in_canvas(nid):
                self.do_center_node(nid)
            self.select(nid)
        # go to the End address
        elif c == 'E':
            if self.end_ea != ida_idaapi.BADADDR:
                self.jumpto(self.end_ea)
                nid = self.nodes[self.end_ea]
                if self.config.center_node and not self.is_node_in_canvas(nid):
                    self.do_center_node(nid)
                self.select(nid)
        # show referred String in functions
        elif c == 'S' and state == ALT:
            self.config.show_strings_nodes = not self.config.show_strings_nodes
            ## remove past navigation history of this graph.
            self.use_internal_function_cache = False
            # to avoid orphan nodes, clear additional points and other internal caches and build the tree from scratch
            self.clear_internal_caches(all_clear=True)
            self.refresh_with_center_node()
            self.exec_ui_action("EmptyStack")
            ida_kernwin.msg("Strings %sabled%s" % ("en" if self.config.show_strings_nodes else "dis", os.linesep))
        # show referred global/static Variables in functions
        elif c == 'V' and state == 0:
            self.config.show_gvars_nodes = not self.config.show_gvars_nodes
            ## remove past navigation history of this graph.
            self.use_internal_function_cache = False
            # to avoid orphan nodes, clear additional points and other internal caches and build the tree from scratch
            self.clear_internal_caches(all_clear=True)
            self.refresh_with_center_node()
            self.exec_ui_action("EmptyStack")
            ida_kernwin.msg("global/static Variables %sabled%s" % ("en" if self.config.show_gvars_nodes else "dis", os.linesep))
        # show structure member access in functions
        elif c == 'T' and state == SHIFT:
            self.config.show_stroff_nodes = not self.config.show_stroff_nodes
            ## remove past navigation history of this graph.
            self.use_internal_function_cache = False
            # to avoid orphan nodes, clear additional points and other internal caches and build the tree from scratch
            self.clear_internal_caches(all_clear=True)
            self.refresh_with_center_node()
            self.exec_ui_action("EmptyStack")
            ida_kernwin.msg("sTructure members %sabled%s" % ("en" if self.config.show_stroff_nodes else "dis", os.linesep))
        # show cOmments in functions
        elif c == 'O' and state == 0:
            self.config.show_comment_nodes = not self.config.show_comment_nodes
            ## remove past navigation history of this graph.
            self.use_internal_function_cache = False
            self.refresh_with_center_node()
            self.exec_ui_action("EmptyStack")
            ida_kernwin.msg("cOmments %sabled%s" % ("en" if self.config.show_comment_nodes else "dis", os.linesep))
        # show unresolved Indirect calls
        elif c == 'I' and state == 0:
            self.config.show_indirect_calls = not self.config.show_indirect_calls
            self.use_internal_function_cache = False
            # to avoid orphan nodes, clear additional points and other internal caches and build the tree from scratch
            self.clear_internal_caches(all_clear=True)
            self.refresh_with_center_node()
            self.exec_ui_action("EmptyStack")
            ida_kernwin.msg("unresolved Indirect Calls %sabled%s" % ("en" if self.config.show_indirect_calls else "dis", os.linesep))
        # disable to display cAller functions
        elif c == 'A' and state == 0:
            self.config.skip_caller = not self.config.skip_caller
            self.use_internal_function_cache = False
            self.refresh_with_center_node()
            self.exec_ui_action("EmptyStack")
            ida_kernwin.msg("skip cAller %sabled%s" % ("en" if self.config.skip_caller else "dis", os.linesep))
        # show Parent's children node
        elif c == 'P' and state == 0:
            self.config.display_children_in_parent_funcs = not self.config.display_children_in_parent_funcs
            self.use_internal_function_cache = False
            self.refresh_with_center_node()
            self.exec_ui_action("EmptyStack")
            ida_kernwin.msg("display child nodes in Parent functions %sabled%s" % ("en" if self.config.display_children_in_parent_funcs else "dis", os.linesep))
        # Update func relations
        elif c == 'U' and state == 0:
            ida_kernwin.show_wait_box("Wait for updating the cache")
            self.clear_internal_caches(all_clear=True)
            self.update_data()
            self.use_internal_function_cache = False
            self.refresh_all()
            ida_kernwin.msg("the caches of the function relationships and the referred string were Updated." + os.linesep)
            ida_kernwin.hide_wait_box()
        # Update func relations partially
        elif c == 'U' and state == SHIFT:
            ea = ida_kernwin.get_screen_ea()
            self.partial_cache_update(ea)
            self.use_internal_function_cache = False
            self.refresh_all(ea)
            ida_kernwin.msg("the caches of the function relationships and the referred string were Updated partially." + os.linesep)
        # Update func relations partially
        elif c == 'U' and state == CTRL:
            self.cache_cmt_update()
            self.use_internal_function_cache = False
            self.refresh_all()
            ida_kernwin.msg("the caches related to comments were Updated." + os.linesep)
        # Help
        elif c == 'H' and state == 0:
            self.print_help()
        # darK mode
        elif c == 'K' and state == 0:
            self.config.dark_mode = not self.config.dark_mode
            self.change_widget_icon(bg_change=self.config.dark_mode)
            self.color_settings()
            self.refresh()
            ida_kernwin.msg("darK mode %sabled%s" % ("en" if self.config.dark_mode else "dis", os.linesep))
        # print several important caches for debugging
        elif c == '_':
            self.print_caches()
        # Print node hint
        elif c == 'P' and state == SHIFT:
            hint = self.get_node_hint()
            if hint is not None:
                ida_kernwin.msg(hint)
            else:
                ida_kernwin.msg("Select a node first.")
        # go to an address or an address of a function name
        elif c == 'G' and state == 0:
            self.exec_ida_ui_action("JumpAsk")
            """
            new_ea = ida_kernwin.get_screen_ea()
            if self.config.auto_reload_outside_node and new_ea not in self.nodes and new_ea not in self.caller_nodes:
                if new_ea in self.vtbl_refs:
                    new_ea = self.vtbl_refs[new_ea]
                # change the primary node and rebuild the tree
                self.force_reload(new_ea)
                
                # take focus back on the current widget
                self.get_focus()
            """
        # rename a function
        elif c == 'N' and state == 0:
            flag = self.check_and_rename_var()
            if not flag:
                self.dbg_print("Failed to rename.")
                self.get_focus(self.GetWidget())
                return False
        # edit function
        elif c == 'P' and state == ALT:
            self.check_and_rename_func_info()
        # repeatable comment
        elif c == ';':
            self.check_and_add_rcmt()
        # comment
        elif c == ':':
            self.check_and_add_cmt()
        # apply structure
        elif c == 'T' and state == 0:
            self.check_and_apply_struct()
        # show xrefs to
        elif c == 'X' and state == 0:
            self.check_xrefs()
        # add cref
        elif c == 'A' and state == CTRL:
            ea = ida_kernwin.get_screen_ea()
            if self.add_cref(ea, CallTreeOverviewer.func_chooser_t):
                self.partial_cache_update(ea)
                self.use_internal_function_cache = False
                self.refresh_with_center_node()
                ida_kernwin.msg("added the cref to the node." + os.linesep)
        # del cref
        elif c == 'D' and state == CTRL:
            ea = ida_kernwin.get_screen_ea()
            if self.del_cref(ea, CallTreeOverviewer.cref_chooser_t):
                self.partial_cache_update(ea)
                self.use_internal_function_cache = False
                self.refresh()
                ida_kernwin.msg("deleted the cref from the node." + os.linesep)
        elif c == '!' and state == SHIFT:
            ida_kernwin.msg("the maximum depth is one." + os.linesep)
            self.max_depth = 1
            self.use_internal_function_cache = False
            self.clear_internal_caches(all_clear=True)
            self.refresh_with_center_node()
            self.jumpto(self.start_ea)
            # CTO needs to clear the navigation history to avoid crash IDA.
            # If you access a node that has a high number after expanding tree with "+" key and
            # then "-" key to shrink the tree and then press escape key to try to return to the previous location,
            # IDA will crash because CTO does not have the node anymore but CTO tries to access it.
            #self.exec_ida_ui_action("EmptyStack")
            self.exec_ui_action("EmptyStack")
        # decrease the maximum depth to dig deeper
        elif c == '-':
            if self.max_depth > 1:
                self.max_depth -= 1
                ida_kernwin.msg("the maximum depth is now %d.%s" % (self.max_depth, os.linesep))
                self.use_internal_function_cache = False
                # to avoid orphan nodes, clear additional points and other internal caches and build the tree from scratch
                self.clear_internal_caches(all_clear=True)
                self.refresh_with_center_node()
                # CTO needs to clear the navigation history to avoid crash IDA.
                # If you access a node that has a high number after expanding tree with "+" key and
                # then "-" key to shrink the tree and then press escape key to try to return to the previous location,
                # IDA will crash because CTO does not have the node anymore but CTO tries to access it.
                #self.exec_ida_ui_action("EmptyStack")
                self.exec_ui_action("EmptyStack")
            else:
                ida_kernwin.msg("the maximum depth is already one." + os.linesep)
        # increase the maximum depth to dig deeper
        elif c == '+':
            if self.max_depth < self.limit_depth and len(self._nodes) < self.max_nodes:
                self.max_depth += 1
                ida_kernwin.msg("the maximum depth is now %d.%s" % (self.max_depth, os.linesep))
                self.use_internal_function_cache = False
                self.refresh_with_center_node()
                # CTO needs to clear the navigation history to avoid crash IDA.
                # If you access a node that has a high number after expanding tree with "+" key and
                # then "-" key to shrink the tree and then press escape key to try to return to the previous location,
                # IDA will crash because CTO does not have the node anymore but CTO tries to access it.
                #self.exec_ida_ui_action("EmptyStack")
                self.exec_ui_action("EmptyStack")
            else:
                ida_kernwin.msg("the maximum depth (%d) or the number of the nodes (%d) is too big. Expand a node you want manually.%s" % (self.max_depth, len(self.nodes), os.linesep))
        # show portable config information
        elif c == '*':
            self.print_config_info()
        # jump to a node with chooser
        elif c == 'J' and state == 0:
            ch = self.node_chooser_t("Which node do you want to move to?", self)
            r = ch.Show(modal=True)
            if r >= 0 and len(self._nodes) > r:
                self.select(r)
                ida_kernwin.msg("%d was selected.%s" % (r, os.linesep))
        # detect xor loops
        elif c == 'X' and state == CTRL:
            self.find_xor_loop()
        # detect notable consts
        elif c == 'C' and state == CTRL:
            self.find_notable_const()
        # search notable instructions
        elif c == 'I' and state == ALT:
            self.find_notable_inst()
        # detect notable mnems
        elif c == 'M' and state & (ALT|SHIFT):
            self.find_notable_mnem()
        
        self.get_focus(self.GetWidget())
        return True

    def print_help(self):
        ida_kernwin.msg("""
[How to use]
- If you see \"""" + self.exceeded_node_symbol + """\", you can double-click such nodes to expand them to look into.
- If you want to filter out nodes under/over a node, double-click the node after single-clicking
  the node once. If you double-click the node directly, it might fail because of centring the node.
  In that case, sigle-click it first, or disable centering a node feature by pressing the "C" key.
  See the [Shortcuts] section below. Note that the node itself is not removed by design.
- If you use the shortcuts below, click the background of the call graph window before pushing a
  shortcut key.
- If the mouse cursor on a node or an edge (a blue arrow), you can see a hint such as the function
  name, referred strings of the node and the other side node of the edge.
- If you see a complete messy nodes layout, right-click on the call graph window and choose
  "Layout graph". It rarely happens, but I do not know how to deal with automatically if it does.
  In that case, please deal with it manually like this way.
- If you right-click a node, you will see some context menu items such as "Find path(s) to this
  node" and "Print hint" (summarised information of a node).

[Shortcuts]
H: Help that you are looking.
R: Refresh the call graph manually.
F: Force relaod for the call graph. This is useful to look into a function out of the
   current call tree without executing this script again.
S: go back to the Start node.
E: go to the End node (if you specify for finding a path between two points).
J: Jump to a displayed node with a chooser.
A: enable/disable displaying cAllers (default is caller/callee mode)
Alt+A: enable/disable Auto-reload feature which draws a new tree if a user
       refers to a node outside the current tree.
Shift+S: enable/disable Saving expanded/collapsed information data for later use with location history.
         NOTE: this feature is EXPERIMENTAL!!! It may cause a problem.
K: enable/disable darK mode.
-: decrease the number of depth for digging into at once.
+: increase the number of depth for digging into at once.
!: set one to the number of depth.
U: Update function relationships which is a cache and used for building the call tree.
Shift+U: Update function relationships partially. It updates only the node on the caches
   and its parent function and its parent functions's children if the node is a caller.
Ctrl+U: Update all comment caches. This is useful for collecting some tools'a results such as
   ironstrings and findcrypt.py.
N: reName a function (this option redirects to IDA View-A so that you can use it transparently).
G: Go to a place (this option redirects to IDA View-A so that you can use it transparently).
X: display Xrefs (this option redirects to IDA View-A so that you can use it transparently).
T: apply a sTructure member to an operand (this option redirects to IDA View-A so that
   you can use it transparently).
;: make repeatable comment (this option redirects to IDA View-A so that you can use it
   transparently).
:: make comment (this option redirects to IDA View-A so that you can use it transparently).
Alt+P: edit function (this option redirects to IDA View-A so that you can use it transparently).
Ctrl+A: add "cref from" on an indirect call/jump node.
Ctrl+D: del "cref from" on an indirect call/jump node.
Shift+P: Print the hint of a selected node.
P: enable/disable to show children nodes in Parents.
I: enable/disable to show unresolved Indirect calls as nodes.
O: enable/disable to show repeatable cOmments as nodes.
V: enable/disable to show global/static Variables as nodes.
Alt+S: enable/disable to show referenced Strings in functions as nodes.
Shift+T: enable/disable to show sTructure members as nodes.
Ctrl+X: detect Xor instructions in a loop.
Alt+Shift+M: detect several important mnemonics.
Ctrl+C: detect several important immediate values.
Alt+I: search important instructions.
C: enable/disable Centering the node you are looking at on the call graph window.
D: enable/disable Debug mode
_: print several important internal caches for debugging.
*: print config values
""")
    
    # for node backgrounds and node frame colors
    def color_settings(self):
        self.start_color = 0x00ff00
        self.end_color = 0xbfdcf7
        self.ep_color = 0xbfdcf7
        self.lib_color = 0xffffc0
        self.api_color = 0xffffc0
        self.default_color = 0xffffff
        self.transparent_color = 0xffffff
        self.selected_frame_color = 0x0000ff
        self.selected_bg_color = 0x00d8ff
        self.strings_color = 0xc4c4c4
        self.gvars_color = 0xc4c4c4
        self.stroff_color = 0xc4c4c4
        self.comments_color = 0x999999
        if self.config.dark_mode:
            self.start_color = 0x005a00
            self.end_color = 0x2f3c7a
            self.ep_color = 0x2f3c7a
            self.lib_color = 0x703726
            self.api_color = 0x703726
            self.selected_frame_color = 0x0000aa
            self.selected_bg_color = 0x004077
            self.strings_color = self.strings_color ^ 0xffffff
            self.stroff_color = self.stroff_color ^ 0xffffff
            self.comments_color = self.comments_color ^ 0xffffff
    
    def clear_all_node_infos(self):
        try:
            if len(self._nodes) > 0:
                self.DelNodesInfos(*[x for x in range(len(self._nodes))])
        except Exception as e:
            exc_type, exc_obj, tb = sys.exc_info()
            lineno = tb.tb_lineno
            ida_kernwin.msg("Got a unexpected error (%s: %s) (%d)%s" % (str(type(e)), e, lineno, os.linesep))
            if self.config.debug:
                self.dbg_print(traceback.format_exc())
            else:
                traceback.print_exc()
    
    def color_node(self, nid):
        try:
            if len(self._nodes) <= nid:
                return None
            
            self.DelNodesInfos(nid)
            color = self._nodes[nid][1]
            if self.default_color == self.transparent_color and color != self.default_color:
                ni = ida_graph.node_info_t()
                ni.bg_color = color
                self.SetNodeInfo(nid, ni, ida_graph.NIF_BG_COLOR|ida_graph.NIF_FRAME_COLOR)
        except Exception as e:
            exc_type, exc_obj, tb = sys.exc_info()
            lineno = tb.tb_lineno
            ida_kernwin.msg("Got a unexpected error (%s: %s) (%d)%s" % (str(type(e)), e, lineno, os.linesep))
            if self.config.debug:
                self.dbg_print(traceback.format_exc())
            else:
                traceback.print_exc()
    
    def color_all_nodes(self):
        for nid in range(len(self._nodes)):
            self.color_node(nid)
    
    def get_color(self, func_type, target_ea=ida_idaapi.BADADDR):
        color = self.default_color
        if target_ea != ida_idaapi.BADADDR and target_ea == self.end_ea:
            color = self.end_color
        elif func_type == FT_API:
            color = self.api_color
        elif func_type == FT_LIB:
            color = self.lib_color
        elif func_type == FT_STO:
            color = self.stroff_color
        elif func_type == FT_STR:
            color = self.strings_color
        elif func_type == FT_VAR:
            color = self.gvars_color
        return color
    
    # for string color for callee nodes
    def color_callee_str(self, callee_str, func_type):
        color_tag = ida_lines.SCOLOR_CNAME
        if func_type == FT_LIB and self.config.dark_mode:
            color_tag = ida_lines.SCOLOR_LIBNAME
        elif func_type == FT_API:
            color_tag = ida_lines.SCOLOR_IMPNAME
        return ida_lines.COLSTR(callee_str, color_tag)
    
    """
    def get_func_name(self, ea):
        name = idc.get_func_name(ea)
        mask = idc.get_inf_attr(idc.INF_SHORT_DN)
        demangled = idc.demangle_name(name, mask)
        if demangled:
            return demangled
        else:
            return name
    """

    """
    def get_space_removed_disasm(self, ea):
        mnem = idc.print_insn_mnem(ea)
        #mnem = ida_lines.COLSTR(mnem, ida_lines.SCOLOR_INSN)
        op = idc.print_operand(ea, 0)
        if op:
            op2 = idc.print_operand(ea, 1)
            if op2:
                op += ", " + op2
        return "%s %s" % (mnem, op)
    """

    # I can get a disassembly line with string color tag as I use the API in ida_lines.
    def get_space_removed_disasm(self, ea, remove_comment=True):
        flags = ida_bytes.get_flags(ea)
        if ida_bytes.is_data(flags):
            disasm = ida_lines.generate_disasm_line(ea, 0)
        else:
            disasm = self.rm_space_rule.sub(" ", ida_lines.generate_disasm_line(ea, 0))
        if self.remove_comment and remove_comment and not self.config.show_comment_nodes:
            disasm = disasm.split(";", 1)[0].strip()
        if self.config.show_comment_nodes:
            disasm = disasm[:self.maximum_comment_length+ida_lines.tag_strlen(disasm)]
        return disasm
    
    def get_callee_name(self, ea, func_type):
        if self.config.debug: self.dbg_print("getting callee name:%x, %x" % (ea, func_type))
        func_name = ida_funcs.get_func_name(ea)
        func_flags = idc.get_func_attr(ea, idc.FUNCATTR_FLAGS)
        f = ida_funcs.get_func(ea)
        if func_type == FT_API:
            func_name = ida_name.get_name(ea)
        #elif func_type == FT_GEN:
        #    if f and func_flags & ida_funcs.FUNC_THUNK and ea in self.caller_nodes:
        #        func_name = self.get_space_removed_disasm(ea)
        elif func_type == FT_VTB:
            func_name = ida_name.get_name(ea)
        elif func_type == FT_STR:
            func_name = ida_name.get_name(ea)
        elif func_type == FT_VAR:
            func_name = ida_name.get_name(ea)
            head_ea = ida_bytes.get_item_head(ea)
            # for in the middle of a struct
            if ea != head_ea and not func_name:
                func_name = ida_name.get_name(head_ea)
        if self.config.debug: self.dbg_print("func name in the middle:%s" % (func_name))
        if not func_name:
            func_name = ida_name.get_name(ea)
        # for a func chunk but it's located in a different segment or something like that.
        # it happens in a certain type of packer.
        elif f and ea != f.start_ea:
            func_name = ida_name.get_name(ea)
        if not func_name:
            func_name = hex(ea).rstrip("L")
        if self.config.debug: self.dbg_print("func name at last:%s" % (func_name))
        return self.color_callee_str(func_name, func_type)
    
    def get_widget_offset(self, w=None):
        if w is None:
            w = self.GetWidget()
        if w is None:
            return None, None
        w_gli = ida_moves.graph_location_info_t()
        if ida_graph.viewer_get_gli(w_gli, w, 0):
            return w_gli.orgx, w_gli.orgy
        return None, None
    
    def get_widget_size(self, w=None):
        if w is None:
            w = self.GetWidget()
        if w is None:
            return None, None
        x, y = self.get_widget_offset(w)
        w_gli = ida_moves.graph_location_info_t()
        if x and y and ida_graph.viewer_get_gli(w_gli, w, ida_graph.GLICTL_CENTER):
            return (w_gli.orgx-x)*2, (w_gli.orgy-y)*2
        return None, None
    
    def get_node_offset_of_displayed_canvas(self, nid, w=None):
        if w is None:
            w = self.GetWidget()
        if w is None:
            return (None, None), (None, None)
        gv = ida_graph.get_graph_viewer(w)
        mg = ida_graph.get_viewer_graph(gv)
        if mg is None:
            return (None, None), (None, None)
        return ((mg.nrect(nid).topleft().x,     mg.nrect(nid).topleft().y),
                (mg.nrect(nid).bottomright().x, mg.nrect(nid).bottomright().y))
    
    def get_node_offset(self, nid, w=None):
        if w is None:
            w = self.GetWidget()
        if w is None:
            return (None, None), (None, None)
        co_x, co_y = self.get_widget_offset(w)
        if co_x is not None and co_y is not None:
            (top_left_x, top_lef_y), (bottom_right_x, bottom_right_y) = self.get_node_offset_of_displayed_canvas(nid, w)
            if top_left_x is not None and top_lef_y is not None and bottom_right_x is not None and bottom_right_y is not None:
                return (top_left_x-co_x, top_lef_y-co_y), (bottom_right_x-co_x, bottom_right_y-co_y)
        return (None, None), (None, None)
        
    def _is_node_in_canvas(self, nid, w=None, margin=None):
        if nid >= len(self._nodes):
            return False
        
        if w is None:
            w = self.GetWidget()
        if w is None:
            return False
        
        if margin is None:
            margin = self.canvas_margin
        
        (node_tl_x, node_tl_y), (node_br_x, node_br_y) = self.get_node_offset(nid, w)
        canvas_br_x, canvas_br_y = self.get_widget_size(w)
        
        if node_br_x and node_br_y and canvas_br_x and canvas_br_y:
            if node_tl_x < (canvas_br_x*margin) or node_tl_y < (canvas_br_y*margin):
                self.dbg_print("left or top of the node frame is out of the canvas or around the canvas edge")
                return False
            if node_br_x > canvas_br_x - (canvas_br_x*margin) or node_br_y > canvas_br_y - (canvas_br_y*margin):
                self.dbg_print("right or bottom of the node frame is out of the canvas or around the canvas edge")
                return False
        return True
    
    def is_node_in_canvas(self, nid, w=None, margin=None):
        r = False
        try:
            r = self._is_node_in_canvas(nid, w, margin)
        except Exception as e:
            exc_type, exc_obj, tb = sys.exc_info()
            lineno = tb.tb_lineno
            ida_kernwin.msg("Got a unexpected error (%s: %s) (%d)%s" % (str(type(e)), e, lineno, os.linesep))
            if self.config.debug:
                self.dbg_print(traceback.format_exc())
            else:
                traceback.print_exc()
        return r

    def get_node_default_bgcolor(self, w=None, nid=0, adjustment=3):
        bg_color = -1
        if w is None:
            w = self.GetWidget()
        if w is None:
            return bg_color

        self.DelNodesInfos(nid)
        (node_tl_x, node_tl_y), (node_br_x, node_br_y) = self.get_node_offset(nid, w)
        bg_color = self.get_bgcolor(node_tl_x+adjustment, node_tl_y+adjustment, w)
        self.color_node(nid)
        return bg_color
    
    def is_dark_mode(self, w=None):
        if w is None:
            w = self.GetWidget()
        if w is None:
            return False
        
        bgcolor = self.get_node_default_bgcolor(w)
        return self._is_dark_mode(bgcolor)
        
    # this is available after drawing. Do not use it before or during drawing process.
    def _find_src_nodes_from_edges(self, nid, text=""):
        gv = ida_graph.get_graph_viewer(self.GetWidget())
        mg = ida_graph.get_viewer_graph(gv)
        npred = self.mg.npred(nid)
        for i in range(npred):
            pred_id = self.mg.pred(nid, i)
            if text:
                if text == self._nodes[pred_id][0]:
                    yield pred_id
            else:
                yield pred_id
    
    # this is available after drawing. Do not use it before or during drawing process.
    def _find_dst_nodes_from_edges(self, nid, text=""):
        gv = ida_graph.get_graph_viewer(self.GetWidget())
        mg = ida_graph.get_viewer_graph(gv)
        nsucc = self.mg.nsucc(nid)
        for i in range(nsucc):
            succ_id = self.mg.succ(nid, i)
            if text:
                if text == self._nodes[succ_id][0]:
                    yield succ_id
            else:
                yield succ_id
        
    def find_src_nodes_from_edges(self, nid, text=""):
        if nid in self.node_id_relationships:
            for pred_id in self.node_id_relationships[nid]["preds"]:
                if text:
                    if text == self._nodes[pred_id][0]:
                        yield pred_id
                else:
                    yield pred_id
    
    def find_dst_nodes_from_edges(self, nid, text=""):
        if nid in self.node_id_relationships:
            for succ_id in self.node_id_relationships[nid]["succs"]:
                if text:
                    if text == self._nodes[succ_id][0]:
                        yield succ_id
                else:
                    yield succ_id
    
    def find_dst_node_from_edges(self, nid, text=""):
        for x in self.find_dst_nodes_from_edges(nid, text=text):
            # return only the first node
            return x
        return -1
    
    def find_src_node_from_edges(self, nid, text=""):
        for x in self.find_src_nodes_from_edges(nid, text=text):
            # return only the first node
            return x
        return -1
    
    def trace_edges(self, tracer, start_nid, end_nid=-1, nodes_limitation=None, stop_primary_node=False, result=None, i=0):
        if result is None:
            result = []
        if nodes_limitation is None:
            nodes_limitation = []
        
        if i > self.max_recursive:
            if end_nid == -1:
                yield tuple(result)
                return
        # detect a recursive call
        elif start_nid in result:
            if end_nid == -1:
                yield tuple(result)
                return
        elif start_nid not in nodes_limitation:
            if end_nid == -1:
                yield tuple(result)
                return
        
        result.append(start_nid)
        if stop_primary_node and start_nid == self.nodes[self.start_ea]:
            yield tuple(result)
            return
        else:
            flag = False
            for dst in tracer(start_nid):
                flag = True
                if dst >= 0:
                    result.append(dst)
                    if dst == end_nid:
                        yield tuple(result)
                        result.pop(-1)
                        break
                    elif stop_primary_node and dst == self.nodes[self.start_ea]:
                        yield tuple(result)
                        result.pop(-1)
                        break
                    # recursive call
                    elif dst in result:
                        if end_nid == -1:
                            yield tuple(result)
                            result.pop(-1)
                        break
                    else:
                        for r in self.trace_edges(tracer, dst, end_nid, nodes_limitation, stop_primary_node, result=result, i=i+1):
                            yield tuple(r)
                            r.pop(-1)
            if flag == False and end_nid == -1:
                yield tuple(result)
        result.pop(-1)
    
    def find_path(self, start_nid, end_nid, direction="up", nodes_limitation=None, stop_primary_node=False):
        if direction == "up":
            tracer = self.find_src_nodes_from_edges
        else:
            tracer = self.find_dst_nodes_from_edges
        
        for p in self.trace_edges(tracer, start_nid, end_nid, nodes_limitation, stop_primary_node):
            yield p
    
    def add_edge(self, src, dst):
        if self.config.debug:
            callee_stk = inspect.stack()[1]
            
            #for python2
            if isinstance(callee_stk, tuple):
                frame, filename, lineno, function, source_code, source_index = callee_stk
            # for python 3
            else:
                filename = callee_stk.filename
                lineno = callee_stk.lineno
                function = callee_stk.function
            
            src_ea = ida_idaapi.BADADDR
            src_list_name = "N/A"
            if src in self.node_ids:
                src_ea = self.node_ids[src]
                src_list_name = "nodes"
            elif src in self.exceeded_node_ids:
                src_ea = self.exceeded_node_ids[src]
                src_list_name = "exceeded_nodes"
            dst_ea = ida_idaapi.BADADDR
            dst_list_name = "N/A"
            if dst in self.node_ids:
                dst_ea = self.node_ids[dst]
                dst_list_name = "nodes"
            elif dst in self.exceeded_node_ids:
                dst_ea = self.exceeded_node_ids[dst]
                dst_list_name = "exceeded_nodes"
            if self.config.debug: self.dbg_print("Adding an edge src: %x (%d, %s), dst: %x (%d, %s) from %s:%d" % (src_ea, src, src_list_name, dst_ea, dst, dst_list_name, function, lineno))
        '''
        # for a certain packer
        # even if a node is a part of a function and is a callee node and its ea is not at a function head, this script connects this node to destination.
        # but it's not correct. so I skip to insert an edge for the cases except for a correct callee and caller pair.
        if src in self.node_ids and dst in self.node_ids:
            src_ea = self.node_ids[src]
            dst_ea = self.node_ids[dst]
            v = idc.get_operand_value(src_ea, 0)
            # src is a caller
            if src_ea not in self.func_relations:
                f = ida_funcs.get_func(src_ea)
                if f:
                    if f.start_ea != src_ea and src_ea not in self.func_relations and f.start_ea in self.func_relations:
                        add_flag = False
                        for direction in ["parents", "children", "gvars", "strings", "struct_offsets"]:
                            for caller in self.func_relations[f.start_ea][direction]:
                                if caller in self.func_relations[f.start_ea][direction]:
                                    callee, ftype, _, _ = self.func_relations[f.start_ea][direction][caller]
                                    if ftype == FT_VTB and callee in self.func_relations[f.start_ea]["vftables"]:
                                        add_flag = True
                                        #vfunc = self.func_relations[f.start_ea]["vftables"][callee]
                                
                                if caller == src_ea and callee == dst_ea:
                                    add_flag = True
                                    break
                                
                        if dst_ea == v:
                            add_flag = True
                        """
                        if self.config.show_strings_nodes and dst_ea in self.strings_contents:
                            add_flag = True
                        if self.config.show_gvars_nodes and dst_ea in self.gvars_contents:
                            add_flag = True
                        if self.config.show_stroff_nodes and dst_ea in self.stroff_contents:
                            add_flag = True
                        """
                        if dst_ea in self.strings_contents:
                            add_flag = True
                        if dst_ea in self.gvars_contents:
                            add_flag = True
                        if dst_ea in self.stroff_contents:
                            add_flag = True
                        #if src_ea in self.vtbl_refs and dst_ea in self.vtbl_refs[src_ea]:
                        #    add_flag = True
                        #"""
                            
                        if not add_flag:
                            if self.config.debug: self.dbg_print("Skipping adding an edge src: %x (%d, %s), dst: %x (%d, %s) from %s:%d because this pair does not have proper callee/caller relationships." % (src_ea, src, src_list_name, dst_ea, dst, dst_list_name, function, lineno))
                            return None
                        
                elif src_ea in self.strings_contents or dst_ea in self.strings_contents:
                    add_flag = True
                elif src_ea in self.gvars_contents or dst_ea in self.gvars_contents:
                    add_flag = True
                elif src_ea in self.stroff_contents or dst_ea in self.stroff_contents:
                    add_flag = True
                elif src_ea in self.vtbl_refs or dst_ea in self.vtbl_refs:
                    add_flag = True
                    """
                elif src_ea in self.strings_contents:
                    add_flag = True
                elif src_ea in self.gvars_contents:
                    add_flag = True
                elif src_ea in self.stroff_contents:
                    add_flag = True
                elif src_ea in self.vtbl_refs:
                    add_flag = True
                    """
                else:
                    if self.config.debug: self.dbg_print("Skipping adding an edge src: %x (%d, %s), dst: %x (%d, %s) from %s:%d because this pair does not have proper callee/caller relationships." % (src_ea, src, src_list_name, dst_ea, dst, dst_list_name, function, lineno))
                    return None
        '''
                
        self.AddEdge(src, dst)
        if src in self.node_id_relationships:
            self.node_id_relationships[src]["succs"].add(dst)
        else:
            self.node_id_relationships[src] = {"succs":set([dst]), "preds":set([])}
        if dst in self.node_id_relationships:
            self.node_id_relationships[dst]["preds"].add(src)
        else:
            self.node_id_relationships[dst] = {"succs":set([]), "preds":set([src])}
    
    def _add_exceeded_node(self, ea, text, color):
        if ea in self.eps:
            color = self.ep_color
        nid = self.AddNode((text, color))
        if self.config.debug:
            callee_stk = inspect.stack()[2]
            
            #for python2
            if isinstance(callee_stk, tuple):
                frame, filename, lineno, function, source_code, source_index = callee_stk
            # for python 3
            else:
                filename = callee_stk.filename
                lineno = callee_stk.lineno
                function = callee_stk.function
            
            self.dbg_print("inserted an exceeded node next to ea:%x, nid:%d from %s:%d" % (ea, nid, function, lineno))
        self.exceeded_nodes[ea] = nid
        self.exceeded_node_ids[nid] = ea
        return nid

    def update_related_nodes(self, ea, start_ea):
        if start_ea != ida_idaapi.BADADDR:
            # if a node is in addtional_trace_points, It is not added to related node list. It will be added later.
            if start_ea == ea or ea not in self.additional_trace_points:
                for tmp_ea in self.related_nodes:
                    if tmp_ea != start_ea and ea in self.related_nodes[tmp_ea]:
                        self.related_nodes[tmp_ea].remove(ea)
                if start_ea in self.related_nodes:
                    self.related_nodes[start_ea].add(ea)
                else:
                    self.related_nodes[start_ea] = set([ea])

    def get_node_type(self, func_type=FT_UNK, caller=False):
        node_type="Callee"
        if caller:
            node_type="Caller"
            
        if func_type == FT_STR:
            node_type = "String"
        elif func_type == FT_VAR:
            node_type = "Global Variable"
        elif func_type == FT_STO:
            node_type = "Structure Offset"
        elif func_type == FT_VTB:
            node_type = "Vftable"
            
        if node_type in ["Callee", "Caller"]:
            if func_type == FT_LIB:
                node_type += " (LIB)"
            elif func_type == FT_API:
                node_type += " (API)"
            elif func_type == FT_MEM:
                node_type += " (Indirect Call)"
            
        if func_type in [FT_VTB, FT_STR, FT_VAR] and caller:
            node_type += " (Ref)"            
        return node_type
    
    def get_node_type_with_nid(self, nid, func_type=FT_UNK, caller=False):
        node_type = self.get_node_type(func_type=func_type, caller=caller)
            
        if nid in self.node_ids and self.start_ea == self.node_ids[nid]:
            node_type = "Primary Node"
        elif nid in self.node_ids and self.node_ids[nid] in self.eps:
            node_type = "Entry Point"
            
        return node_type
    
    def update_node_type(self, nid, func_type=FT_UNK, caller=False, node_type="Unknown"):
        if node_type == "Unknown":
            node_type = self.get_node_type_with_nid(nid, func_type=func_type, caller=caller)
        self.node_types[nid] = (node_type, func_type, caller)
    
    def _add_node(self, ea, text, color, start_ea=ida_idaapi.BADADDR, caller=False):
        if ea in self.eps and not caller:
            color = self.ep_color
        nid = self.AddNode((text, color))
        if self.config.debug:
            callee_stk = inspect.stack()[2]
            
            # for python 2
            if isinstance(callee_stk, tuple):
                frame, filename, lineno, function, source_code, source_index = callee_stk
            # for python 3
            else:
                filename = callee_stk.filename
                lineno = callee_stk.lineno
                function = callee_stk.function
            
            self.dbg_print("inserted a node. ea: %x, nid:%d from %s:%d" % (ea, nid, function, lineno))
        if caller:
            self.caller_nodes[ea] = nid
            self.caller_node_ids[nid] = ea
        else:
            self.nodes[ea] = nid
        self.node_ids[nid] = ea
        self.update_related_nodes(ea, start_ea)
        return nid
        
    def add_node(self, ea, text, color, start_ea=ida_idaapi.BADADDR, func_type=FT_UNK, caller=False, node_type="Unknown"):
        if text == self.exceeded_node_symbol:
            nid = self._add_exceeded_node(ea, text, color)
            node_type = "Exceeded Node"
        else:
            nid = self._add_node(ea, text, color, start_ea=start_ea, caller=caller)
        self.update_node_type(nid, func_type=func_type, caller=caller, node_type=node_type)
        return nid

    def replace_node(self, nid, text, color, start_ea=ida_idaapi.BADADDR, dst_ea=ida_idaapi.BADADDR, func_type=FT_UNK, caller=False, node_type="Unknown"):
        if self.config.debug:
            callee_stk = inspect.stack()[1]
            
            # for python 2
            if isinstance(callee_stk, tuple):
                frame, filename, lineno, function, source_code, source_index = callee_stk
            # for python 3
            else:
                filename = callee_stk.filename
                lineno = callee_stk.lineno
                function = callee_stk.function
            
            self.dbg_print("the node id (%d) is in exceeded nodes. replace the exceeded node with %x from %s:%d" % (nid, self.exceeded_node_ids[nid], function, lineno))
        self._nodes[nid] = (text, color)
        ea = self.exceeded_node_ids.pop(nid)
        self.exceeded_nodes.pop(ea)
        #self.remove_trace_cache(ea, self.start_ea)
        if nid in self.exceeded_node_ids and dst_ea == ida_idaapi.BADADDR and self.exceeded_node_ids[nid] != dst_ea:
            pass
        else:
            ea = dst_ea
        if caller:
            self.caller_nodes[ea] = nid
            self.caller_node_ids[nid] = ea
        else:
            self.nodes[ea] = nid
        self.node_ids[nid] = ea
        self.update_related_nodes(ea, start_ea)
        self.update_node_type(nid, func_type=func_type, caller=caller, node_type=node_type)
        return ea
    
    def get_node_id(self, ea, start_ea, caller=False, update=True):
        if caller:
            nid = self.caller_nodes[ea]
        elif ea in self.nodes:
            nid = self.nodes[ea]
        if update:
            self.update_related_nodes(ea, start_ea)
        return nid
    
    def cut_string_node(self, str_contents, str_ea):
        str_contents = str_contents.replace('\r', '\\r').replace('\n', '\\n')
        self.strings_contents[str_ea] = str_contents
        taglen = len(str_contents) - ida_lines.tag_strlen(str_contents)
        if len(str_contents) - taglen > self.maximum_string_length:
            str_contents = str_contents[:self.maximum_string_length+taglen] + "..."
        return str_contents
    
    def insert_string_node(self, ea, func_ea, psid, ref_ea=ida_idaapi.BADADDR):
        if self.config.debug: self.dbg_print("Entering insert_string_node function for %x" % ea)
        flags = ida_bytes.get_flags(ea)
        if ida_bytes.is_strlit(flags):
            # get string content by ea
            self.dbg_print("%x is a strlit" % ea)
            str_contents = cto_utils.get_str_content_by_ea(ea)
            str_ea = ea
            to_be_checked = ea
            if str_contents is None and func_ea in self.func_relations:
                # sometimes, get_str_content_by_ea is failed such as the string is too short, then try getting the string from func_relations.
                for cea in self.func_relations[func_ea]["children"]:
                    if cea in self.func_relations[func_ea]["children"]:
                        gcea, ft, _, _str_contents = self.func_relations[func_ea]["children"][cea]
                        to_be_checked = ea
                        if ref_ea != ida_idaapi.BADADDR:
                            to_be_checked = ref_ea
                        if gcea == to_be_checked and ft == FT_STR:
                            self.dbg_print("to be checked: %x" % to_be_checked, "gcea: %x" %gcea)
                            str_ea = gcea
                            str_contents = _str_contents
            if str_contents is None:
                return
            
            str_contents = self.cut_string_node(str_contents, str_ea)
            # found the node that is already inserted
            found_flag = False
            for i, (txt, color) in enumerate(self._nodes):
                if txt == str_contents:
                    tmp_srcs = self.find_src_nodes_from_edges(i)
                    if to_be_checked in [self.node_ids[x] for x in tmp_srcs if x in self.node_ids]:
                        found_flag = True
                        sid = i
                        break
            # for the first insertion
            if not found_flag:
                #sid = self.add_node(str_ea, str_contents, self.strings_color, func_type=FT_STR, caller=False)
                sid = self.AddNode((str_contents, self.strings_color))
                self.node_ids[sid] = str_ea
                self.update_node_type(sid, func_type=FT_STR, node_type="String Content")
            self.add_edge(psid, sid)
        if self.config.debug: self.dbg_print("Finished insert_string_node function for %x" % ea)
        
    """
    def insert_string_node(self, ea):
        if self.config.debug: self.dbg_print("Entering insert_string_node function for %x" % ea)
        # adding strings nodes
        if self.config.show_strings_nodes and ea in self.nodes:
            #if ea in self.func_relations and ea not in self.filtered_nodes:
            if ea in self.func_relations:
                for ref_str_ea in self.func_relations[ea]["strings"]:
                    if not self.config.skip_caller:
                        if ref_str_ea in self.caller_nodes:
                            rsid = self.caller_nodes[ref_str_ea]
                        elif ref_str_ea in self.nodes:
                            rsid = self.nodes[ref_str_ea]
                        else:
                            line = self.get_space_removed_disasm(ref_str_ea)
                            rsid = self.add_node(ref_str_ea, line, self.strings_color, func_type=FT_STR, caller=True)
                        self.add_edge(self.nodes[ea], rsid)
                    else:
                        if ref_str_ea in self.caller_nodes:
                            rsid = self.caller_nodes[ref_str_ea]
                        else:
                            rsid = self.nodes[ea]
                    str_ea, _, _, str_contents = self.func_relations[ea]["strings"][ref_str_ea]
                    if str_ea in self.caller_nodes:
                        sid = self.caller_nodes[str_ea]
                        self.add_edge(rsid, sid)
                    elif str_ea in self.nodes:
                        sid = self.nodes[str_ea]
                        self.add_edge(rsid, sid)
                    else:
                        str_contents = self.cut_string_node(str_contents, str_ea)
                        sid = self.add_node(str_ea, str_contents, self.strings_color, func_type=FT_STR, caller=False)
                        self.add_edge(rsid, sid)
        if self.config.debug: self.dbg_print("Finished insert_string_node function for %x" % ea)
    """
        
    """
    def insert_var_node(self, ea, func_type, node_type, node_color, loc_cache, show_flag, skip_content):
        if self.config.debug: self.dbg_print("Entering insert_var_node function for %x" % ea)
        # adding strings nodes
        if show_flag and ea in self.nodes:
            #if ea in self.func_relations and ea not in self.filtered_nodes:
            if ea in self.func_relations:
                for ref_str_ea in self.func_relations[ea][func_type]:
                    if not self.config.skip_caller:
                        if ref_str_ea in self.caller_nodes:
                            rsid = self.caller_nodes[ref_str_ea]
                        elif ref_str_ea != ea and ref_str_ea in self.nodes:
                            rsid = self.nodes[ref_str_ea]
                        else:
                            line = self.get_space_removed_disasm(ref_str_ea)
                            rsid = self.add_node(ref_str_ea, line, node_color, func_type=func_type, caller=True)
                        self.add_edge(self.nodes[ea], rsid)
                    else:
                        rsid = self.nodes[ea]

                    str_ea, _, _, str_contents = self.func_relations[ea][func_type][ref_str_ea]
                    if not skip_content:
                        if str_ea in self.caller_nodes:
                            sid = self.caller_nodes[str_ea]
                            self.add_edge(rsid, sid)
                        elif str_ea in self.nodes:
                            sid = self.nodes[str_ea]
                            self.add_edge(rsid, sid)
                        else:
                            var_name = ida_name.get_name(str_ea)
                            if var_name:
                                str_contents = var_name + " (" + str_contents + ")"
                            loc_cache[str_ea] = str_contents
                            sid = self.add_node(str_ea, str_contents, node_color, func_type=func_type, caller=False)
                            self.add_edge(rsid, sid)
        if self.config.debug: self.dbg_print("Finished insert_var_node function for %x" % ea)
    """
    
    def insert_comment_node(self, ea):
        if self.config.debug: self.dbg_print("Entering insert_comment_node function for %x" % ea)
        # adding comment nodes
        #if self.config.show_comment_nodes and ea in self.nodes and ea not in self.filtered_nodes:
        if self.config.show_comment_nodes and ea in self.nodes and ea in self.func_relations:
            for node_type in self.func_relations[ea]:
                if node_type in ["cmt", "rcmt"]:
                    cmt_type = node_type
                    for cmt_ea in self.func_relations[ea][cmt_type]:
                        if cmt_ea not in self.nodes and cmt_ea not in self.caller_nodes:
                            line = self.get_space_removed_disasm(cmt_ea, False)
                            taglen = ida_lines.tag_strlen(line)
                            if (len(line) - taglen) > self.maximum_comment_length+3:
                                line = line[:self.maximum_comment_length+taglen] + "..."
                            if cmt_type == 'cmt':
                                node_type = 'Comment'
                            else:
                                node_type = 'Repeatable Comment'
                            nid = self.add_node(cmt_ea, line, self.comments_color, node_type=node_type, caller=True)
                            self.add_edge(self.nodes[ea], nid)
        if self.config.debug: self.dbg_print("Finished insert_comment_node function for %x" % ea)

    def trace_paths_append_cache(self, start_ea, end_ea, fn_keys, cache, max_recursive=g_max_recursive, direction="parents", result=None):
        found_flag = False
        self.dbg_print("trace the call tree", hex(start_ea).rstrip("L"), hex(end_ea).rstrip("L"), direction, max_recursive, [hex(x).rstrip("L") for x in fn_keys], self.skip_api, self.skip_lib)
        for r in get_func_relation.trace_func_calls(self.func_relations, ea=start_ea, target_ea=end_ea, direction=direction, vtbl_refs=self.vtbl_refs, max_recursive=max_recursive, filtered_nodes=self.filtered_nodes, skip_api=self.skip_api, skip_lib=self.skip_lib, debug=self.config.debug, dbg_print_func=self.dbg_print, result=result):
        #for r in get_func_relation.trace_nodes(self.func_relations, start_ea=start_ea, target_ea=end_ea, direction=direction, vtbl_refs=self.vtbl_refs, max_recursive=max_recursive, filtered_nodes=self.filtered_nodes, skip_api=self.skip_api, skip_lib=self.skip_lib, debug=self.config.debug, dbg_print_func=self.dbg_print, result=result):
            yield r
            found_flag = True
            if (start_ea, end_ea, direction, max_recursive, fn_keys, self.skip_api, self.skip_lib) in cache:
                cache[(start_ea, end_ea, direction, max_recursive, fn_keys, self.skip_api, self.skip_lib)].add(tuple(r))
            else:
                cache[(start_ea, end_ea, direction, max_recursive, fn_keys, self.skip_api, self.skip_lib)] = set([tuple(r)])
        if found_flag == False:
            cache[(start_ea, end_ea, direction, max_recursive, fn_keys, self.skip_api, self.skip_lib)] = set([])
                
    def trace_paths_with_cache(self, start_ea, end_ea, max_recursive=g_max_recursive, direction="parents", use_cache=True):
        cache = self.paths_cache
        if self.parent:
            cache = self.parent.paths_cache
        fn_keys = tuple(self.filtered_nodes.keys())
        
        if use_cache and (start_ea, end_ea, direction, max_recursive, fn_keys, self.skip_api, self.skip_lib) in cache:
            self.dbg_print("hit a cache", hex(start_ea).rstrip("L"), hex(end_ea).rstrip("L"), direction, max_recursive, [hex(x).rstrip("L") for x in fn_keys], self.skip_api, self.skip_lib)
            for p in cache[(start_ea, end_ea, direction, max_recursive, fn_keys, self.skip_api, self.skip_lib)]:
                yield p
        else:
            for r in self.trace_paths_append_cache(start_ea, end_ea, fn_keys, cache, max_recursive=max_recursive, direction=direction):
                yield r
                
    """
    def remove_trace_cache(self, ea, start_ea):
        self.dbg_print("enter remove_trace_cache", hex(ea))
        cache = self.paths_cache
        if self.parent:
            cache = self.parent.paths_cache
        
        if start_ea in [x[0] for x in cache]:
            for sea, eea, direction, max_recursive, fn_keys, skip_api, skip_lib in cache:
                if sea == start_ea:
                    to_be_removed = set([])
                    for routes in cache[(sea, eea, direction, max_recursive, fn_keys, skip_api, skip_lib)]:
                        for r in routes:
                            if r[0] == ea or r[1] == ea:
                                to_be_removed.add(routes)
                                self.dbg_print("this cache will be removed", [hex(x) for x in r])
                    for routes in to_be_removed:
                        cache[(sea, eea, direction, max_recursive, fn_keys, skip_api, skip_lib)].remove(routes)
    """
                        
    """
    def insert_dref_node_info(self, start_ea, direction):
        if start_ea in self.func_relations:
            return
        if direction == "parents":
            drefs = get_func_relation.get_dref_belong_to_func(start_ea, self.vtbl_refs)
        else:
            drefs = get_func_relation.get_dref_from_belong_to_func(start_ea)
        for dref_ea, dref_func_ea, dref_off_ea in drefs:
            func_type = FT_VAR
            if dref_func_ea in self.func_relations and dref_ea in self.func_relations[dref_func_ea]["strings"]:
                str_ea, _, _, str_contents = self.func_relations[dref_func_ea]["strings"][dref_ea]
                str_contents = self.cut_string_node(str_contents, str_ea)
                str_contents = self.cut_string_node(str_contents, start_ea)
            elif dref_func_ea in self.func_relations and dref_ea in self.func_relations[dref_func_ea]["gvars"]:
                gvar_ea, _, _, gvar_contents = self.func_relations[dref_func_ea]["gvars"][dref_ea]
                var_name = ida_name.get_name(gvar_ea)
                if var_name:
                    gvar_contents = var_name + " (" + gvar_contents + ")"
                self.gvars_contents[start_ea] = gvar_contents
    """
                
    def is_path_displayable(self, r):
        if len(r) == 0:
            return True
        
        caller, callee, func_type = r[-1]
        depth = self.max_depth
        if caller == ida_idaapi.BADADDR:
            caller, callee, func_type = r[-2]
            depth += 1
            
        flag = False
        if func_type == FT_MEM and not self.config.show_indirect_calls:
            if self.config.debug: self.dbg_print("node_type: FT_MEM and show_indirect_calls is disabled.")
            return False
        elif func_type == FT_STR and not self.config.show_strings_nodes:
            if self.config.debug: self.dbg_print("node_type: FT_STR and show_strings_nodes is disabled.")
            return False
        elif func_type == FT_VAR and not self.config.show_gvars_nodes:
            if self.config.debug: self.dbg_print("node_type: FT_VAR and show_gvars_nodes is disabled.")
            return False
        elif func_type == FT_STO and not self.config.show_stroff_nodes:
            if self.config.debug: self.dbg_print("node_type: FT_STO and show_stroff_nodes is disabled.")
            return False
        return True
    
    def dref_data_type(self, dref_ea, dref_func_ea, dref_off_ea):
        if self.config.debug: self.dbg_print(hex(dref_ea), hex(dref_func_ea), hex(dref_off_ea))
        dref_flag = False
        func_type = FT_VAR
        if dref_off_ea != ida_idaapi.BADADDR:
            if dref_ea in self.func_relations[dref_func_ea]["strings"]:
                func_type = FT_STR
                dref_flag = True
            elif dref_ea in self.func_relations[dref_func_ea]["gvars"]:
                dref_flag = True
        else:
            vflags = ida_bytes.get_full_flags(dref_ea)
            if ida_bytes.is_strlit(vflags):
                func_type = FT_STR
                dref_flag = True
            else:
                dref_flag = True
        return dref_flag, func_type
    
    def draw_parents_call_tree(self, start_ea, end_ea, max_recursive=g_max_recursive):
        if start_ea not in self.related_nodes:
            self.related_nodes[start_ea] = set([start_ea])
        prev_id = None
        
        if self.config.debug:
            self.dbg_print("##################### Start processing %x #################" % start_ea)
            
        # push a starter node
        #self.insert_dref_node_info(start_ea, direction="parents")
        dref_flag = False
        func_type = FT_UNK
        if start_ea not in self.nodes:
            # for functions
            if start_ea in self.func_relations:
                func_type = self.func_relations[start_ea]["func_type"]
                func_name = self.get_callee_name(start_ea, func_type)
            # for strings and global variables
            else:
                func_type = FT_VAR
                for dref_ea, dref_func_ea, dref_off_ea in get_func_relation.get_dref_belong_to_func(start_ea, self.vtbl_refs):
                    dref_flag, func_type = self.dref_data_type(dref_ea, dref_func_ea, dref_off_ea)
                    if dref_flag:
                        break
                func_name = self.get_callee_name(start_ea, func_type)
                    
            nid = self.add_node(start_ea, func_name, self.start_color, start_ea, func_type=func_type, caller=False)
        else:
            nid = self.get_node_id(start_ea, start_ea, caller=False)
            if start_ea not in self.func_relations:
                func_type = FT_VAR
                for dref_ea, dref_func_ea, dref_off_ea in get_func_relation.get_dref_belong_to_func(start_ea, self.vtbl_refs):
                    dref_flag, func_type = self.dref_data_type(dref_ea, dref_func_ea, dref_off_ea)
                    if dref_flag:
                        break
        
        if self.config.debug: self.dbg_print("before tracing... start_ea: %x, end_ea: %x, max_recursive: %d" % (start_ea, end_ea, max_recursive))
        for r in self.trace_paths_with_cache(start_ea, end_ea, max_recursive=max_recursive, direction="parents"):
            if self.config.debug:
                self.dbg_print("$$$$$$$$$$$$$$$$ found a path:", [(hex(y).rstrip("L"), hex(x).rstrip("L"), z) for x,y,z in reversed(r)], "to ", hex(start_ea).rstrip("L"))
            # for path_finder popup menu
            if max_recursive < 0 and self.max_nodes < (len(self._nodes) + len(r)):
                ida_kernwin.msg("The number of max_nodes is exceeded (%d < %d). Note that this graph result is incompleted.%s" % (self.max_nodes, len(self._nodes)+len(r), os.linesep))
                ida_kernwin.msg("Change the graph type and dig into it manually.%s" % (os.linesep))
                break
            
            # skip the path if the last node is not a node displayed by config
            if not dref_flag and not self.is_path_displayable(r):
                continue
            
            # to skip nodes in a result if a filtered node is included, check a result first.
            idx = -1
            last_hit = -1
            tmp_flag = False
            for idx, (caller, callee, callee_func_type) in reversed(list(enumerate(r))):
                if caller in self.filtered_nodes or callee in self.filtered_nodes or (((self.skip_api and callee_func_type in [FT_API]) or (self.skip_lib and callee_func_type in [FT_LIB])) and callee not in self.additional_trace_points):
                    tmp_flag = True
                    self.dbg_print("idx: %d, callee: %x or caller: %x was hit" % (idx, callee, caller), [hex(x).rstrip("L") for x in self.filtered_nodes])
                    # do not break. get the last filtered item.
                    #break
                    last_hit = idx
            if not tmp_flag:
                last_hit = -1
            
            # for other nodes except for start nodes
            prev_id = None
            next_callee = None
            next_callee_func_type = FT_UNK
            next_caller = None
            prev_caller = None
            # note that r and its item indice are reversed for parent nodes.
            for i, (caller, callee, callee_func_type) in reversed(list(enumerate(r))):
                # This is right because the order is reversed. Do not doubt.
                if (len(r) - 1) > i:
                    prev_caller = r[i+1][0]
                    if self.config.skip_caller:
                        prev_caller = r[i+1][1]
                else:
                    prev_caller = None
                # This is right because the order is reversed. Do not doubt.
                if i > 0:
                    next_callee = r[i-1][1]
                    next_caller = r[i-1][0]
                    next_callee_func_type = r[i-1][2]
                # i == 0 for start_ea ( the bottom item of the parents node)
                else:
                    next_callee = start_ea
                    next_caller = None
                    next_callee_func_type = func_type
                    
                # skip nodes until a filtered node appears
                if last_hit >= 0 and last_hit < i:
                    if self.config.debug:
                        self.dbg_print("Skipping inserting process (%d/%d) last_hit: %d, i: %d" % (len(r)-i, len(r), last_hit, i))
                    continue
                elif last_hit >= 0 and last_hit >= i:
                    # if the path is already existent, just stop it.
                    if not self.config.skip_caller and caller in self.filtered_nodes and caller in self.caller_nodes:
                        if self.config.debug:
                            self.dbg_print("Skipping inserting process (%d/%d) last_hit: %d, i: %d" % (len(r)-i, len(r), last_hit, i))
                        continue
                    elif self.config.skip_caller and callee in self.filtered_nodes and callee in self.nodes:
                        if self.config.debug:
                            self.dbg_print("Skipping inserting process (%d/%d) last_hit: %d, i: %d" % (len(r)-i, len(r), last_hit, i))
                        continue
                # if the current pair is for an exceeded node and its beyond nodes are not related to code and show_gvars_nodes is disabled, skip inserting exceeded node
                elif caller == ida_idaapi.BADADDR and callee_func_type == FT_VAR and not self.config.show_gvars_nodes:
                    if self.config.debug:
                        self.dbg_print("Skipping inserting process (%d/%d) last_hit: %d, i: %d" % (len(r)-i, len(r), last_hit, i))
                    continue
                    
                do_it_flag = False
                ##########################
                #
                # for callee functions
                #
                if self.config.debug:
                    self.dbg_print("++++++++++ processing the callee (%x)" % callee)
                if callee != ida_idaapi.BADADDR and ((not self.config.skip_caller and caller not in self.filtered_nodes) or self.config.skip_caller):
                    if self.config.debug:
                        self.dbg_print("callee is not BADADDR (%x)" % callee)
                    # for existing nodes (general nodes)
                    if callee in self.nodes:
                        if self.config.debug:
                            self.dbg_print("callee (%x) is in nodes" % callee)
                        if not self.config.skip_caller:
                            callee_id = self.get_node_id(callee, start_ea, caller=False)
                        else:
                            callee_id = self.get_node_id(callee, start_ea, caller=False)
                            if prev_id is not None and prev_caller != callee:
                                self.add_edge(prev_id, callee_id)
                            else:
                                pass
                        do_it_flag = True
                        
                    #####################
                    # in skip caller mode
                    # for new nodes to be added
                    elif self.config.skip_caller:
                        line = self.get_callee_name(callee, callee_func_type)
                        color = self.get_color(callee_func_type, callee)
                        if self.config.debug:
                            self.dbg_print("skip caller mode")
                            
                        if callee in self.nodes:
                            if self.config.debug:
                                self.dbg_print("callee (%x) is in nodes" % callee)
                            callee_id = self.get_node_id(callee, start_ea, caller=False)
                        elif next_callee in self.exceeded_nodes:
                            if self.config.debug:
                                self.dbg_print("next_callee (%x) is in exceeded nodes" % next_callee)
                            callee_id = self.exceeded_nodes[next_callee]
                            nea = self.replace_node(callee_id, line, color, start_ea, callee, func_type=callee_func_type, caller=False)
                        
                        # find a set of callee and caller but they are not connected yet because the max path limitation is exceeded.
                        elif callee in self.func_relations and len(self.func_relations[callee]['children']) >= 1:
                            if self.config.debug:
                                self.dbg_print("callee (%x) is in func_relations" % callee)
                            src = -1
                            for tmp_ea in [self.func_relations[callee]['children'][x][0] for x in self.func_relations[callee]['children']]:
                                if self.config.debug:
                                    self.dbg_print("tmp_ea:", hex(tmp_ea).rstrip("L"), ", next_callee:", hex(next_callee).rstrip("L"), ", callee:", hex(callee).rstrip("L"))
                                if tmp_ea != next_callee:
                                    if self.config.debug:
                                        self.dbg_print("tmp_ea (%x) != next_callee (%x)" % (tmp_ea, next_callee))
                                    if tmp_ea in self.func_relations and callee in [self.func_relations[tmp_ea]['parents'][x][0] for x in self.func_relations[tmp_ea]['parents']]:
                                        if self.config.debug:
                                            self.dbg_print("next_callee (%x) is a child of tmp_ea (%x)" % (next_callee, tmp_ea))
                                        if tmp_ea in self.nodes:
                                            if tmp_ea not in self.filtered_nodes:
                                                tmp_src = self.find_src_node_from_edges(self.nodes[tmp_ea], self.exceeded_node_symbol)
                                                if tmp_src >= 0:
                                                    if len(self.func_relations[tmp_ea]["parents"]) > 1:
                                                        src = -1
                                                        if self.config.debug:
                                                            self.dbg_print("tmp_ea's (%x) source is an exceeded node (%d), but there are two or more nodes. I do not process it." % (tmp_ea, tmp_src))
                                                        break
                                                    else:
                                                        if self.config.debug:
                                                            self.dbg_print("tmp_ea's (%x) source is an exceeded node (%d)" % (tmp_ea, tmp_src))
                                                        src = tmp_src
                                                        break
                                                else:
                                                    self.dbg_print("There are no exceeded nodes of tmp_ea's (%x) (%d)" % (tmp_ea, tmp_src))
                                            else:
                                                if self.config.debug:
                                                    self.dbg_print("tmp_ea (%x) is in filtered nodes list. skip it." % tmp_ea)
                                        elif tmp_ea in self.exceeded_nodes:
                                            if self.config.debug:
                                                self.dbg_print("tmp_ea (%x) is in the exceeded node list." % tmp_ea)
                                            src = self.exceeded_nodes[tmp_ea]
                                            break
                                        else:
                                            if self.config.debug:
                                                self.dbg_print("tmp_ea (%x) is not displayed on this graph yet." % tmp_ea)
                            if src >= 0:
                                if self.config.debug:
                                    self.dbg_print("found the parent exceeded_node (%x, %d) of tmp_ea (%x)" % (self.exceeded_node_ids[src], src, tmp_ea))
                                callee_id = src
                                if tmp_ea in self.exceeded_nodes:
                                    if self.config.debug:
                                        self.dbg_print("tmp_ea (%x) is in exceeded_nodes" % tmp_ea)
                                    src_ea = self.replace_node(callee_id, line, color, start_ea, callee, func_type=callee_func_type, caller=False)
                                else:
                                    if self.config.debug:
                                        self.dbg_print("tmp_ea (%x) is not in exceeded_nodes" % tmp_ea)
                                    pass
                            else:
                                if self.config.debug:
                                    self.dbg_print("Adding a node for callee (%x)" % callee)
                                callee_id = self.add_node(callee, line, color, start_ea, func_type=callee_func_type, caller=False)
                        # create a new node for a new function
                        else:
                            if self.config.debug:
                                self.dbg_print("callee (%x) is not displayed yet. Adding the node." % callee)
                            callee_id = self.add_node(callee, line, color, start_ea, func_type=callee_func_type, caller=False)
                        
                    #####################
                    #
                    # callee-caller mode
                    #
                    else:
                        if self.config.debug:
                            self.dbg_print("Adding a callee node (%x)." % callee)
                        func_name = self.get_callee_name(callee, callee_func_type)
                        color = self.get_color(callee_func_type, callee)
                        callee_id = self.add_node(callee, func_name, color, start_ea, func_type=callee_func_type, caller=False)

                    if prev_id is not None:
                        self.add_edge(prev_id, callee_id)
                        if self.config.debug:
                            self.dbg_print("Adding an edge for %d and %d" % (prev_id, callee_id))
                    prev_id = callee_id
                    do_it_flag = True
                
                # caller is BADADDR means this path is exceeded of the path length limitation.
                elif self.config.skip_caller:
                    if self.config.debug:
                        self.dbg_print("caller is BADADDR and skip_caller is ON.")
                    if caller == ida_idaapi.BADADDR:
                        insert_flag = False
                        if self.config.debug:
                            self.dbg_print("next_callee (%x)" % next_callee)
                        if next_callee in self.nodes:
                            if self.config.debug:
                                self.dbg_print("next_callee (%x) is in nodes " % next_callee)
                            next_callee_id = self.get_node_id(next_callee, start_ea, caller=False)
                            src = self.find_src_node_from_edges(next_callee_id)
                            if src < 0:
                                if self.config.debug:
                                    self.dbg_print("not found any source nodes of next_callee (%x)" % (next_callee))
                                insert_flag = True
                            else:
                                src_node_ea = ida_idaapi.BADADDR
                                if src in self.node_ids:
                                    src_node_ea = src
                                if self.config.debug:
                                    self.dbg_print("found a source node (%x, %d) of next_callee (%x)" % (src_node_ea, src, next_callee))
                                callee_id = src
                        else:
                            if self.config.debug:
                                self.dbg_print("there are no source nodes of next_callee (%x) in nodes" % next_callee)
                            insert_flag = True

                        # find a set of callee and caller but they are not connected yet because the max path limitation is exceeded.
                        if insert_flag and next_callee in self.func_relations and len(self.func_relations[next_callee]['parents']) >= 1:
                            if self.config.debug:
                                self.dbg_print("next_callee (%x) is in func_relations" % next_callee)
                            src = -1
                            for tmp_ea in [self.func_relations[next_callee]['parents'][x][0] for x in self.func_relations[next_callee]['parents']]:
                                if self.config.debug:
                                    self.dbg_print("tmp_ea:", hex(tmp_ea).rstrip("L"), ", next_callee:", hex(next_callee).rstrip("L"), ", callee:", hex(callee).rstrip("L"))
                                if tmp_ea in self.nodes:
                                    dst_eas = [self.node_ids[x] for x in self.find_dst_nodes_from_edges(self.nodes[tmp_ea]) if x in self.node_ids]
                                    if next_callee not in dst_eas:
                                        if self.config.debug:
                                            self.dbg_print("next_callee (%x) is not in the destinations of tmp_ea (%x)" % (next_callee, tmp_ea))
                                        if tmp_ea in self.func_relations and next_callee in [self.func_relations[tmp_ea]['children'][x][0] for x in self.func_relations[tmp_ea]['children']]:
                                            if self.config.debug:
                                                self.dbg_print("next_callee (%x) is a child of the tmp_ea (%x)" % (next_callee, tmp_ea))
                                            src = self.nodes[tmp_ea]
                                            if next_callee in self.nodes:
                                                if self.config.debug:
                                                    self.dbg_print("next_callee (%x) is already displayed." % next_callee)
                                                callee_id = self.nodes[next_callee]
                                                self.add_edge(src, callee_id)
                                            elif next_callee in self.additional_trace_points:
                                                insert_flag = False
                                                src = -1
                                                if self.config.debug:
                                                    self.dbg_print("next_callee (%x) is one of the additional trace points" % next_callee)
                                                pass
                                            #elif tmp_ea in self.nodes and next_callee not in self.nodes:
                                            #    self.dbg_print("a src node (tmp_ea) (%x) is already inserted." % tmp_ea)
                                            #    insert_flag = False
                                            else:
                                                insert_flag = False
                                                #src = -1
                                                if self.config.debug:
                                                    self.dbg_print("next_callee (%x) is not displayed yet." % next_callee)
                                            break
                                else:
                                    if tmp_ea in self.func_relations and next_callee in [self.func_relations[tmp_ea]['children'][x][0] for x in self.func_relations[tmp_ea]['children']]:
                                        if self.config.debug:
                                            self.dbg_print("next_callee (%x) is a child of tmp_ea (%x)" % (next_callee, tmp_ea))
                                        if next_callee in self.nodes and tmp_ea in self.exceeded_nodes:
                                            src = self.exceeded_nodes[tmp_ea]
                                            src_ea = self.replace_node(src, line, color, start_ea, next_callee, func_type=next_callee_func_type, caller=False)
                                            if self.config.debug:
                                                self.dbg_print("next_callee (%x) is an exceeded node and it's already displayed. it was replaced with next_callee." % next_callee)
                                            self.add_edge(src, callee_id)
                                        elif next_callee in self.additional_trace_points:
                                            insert_flag = False
                                            src = -1
                                            if self.config.debug:
                                                self.dbg_print("next_callee (%x) is one of the additional trace points" % next_callee)
                                        else:
                                            src = -1
                                            if self.config.debug:
                                                self.dbg_print("next_callee (%x) is not displayed yet" % next_callee)
                                        break
                            if src >= 0:
                                callee_id = src
                                self.update_related_nodes(self.node_ids[callee_id], start_ea)
                                insert_flag = False
                                if self.config.debug:
                                    self.dbg_print("callee (%x) has a source" % self.node_ids[callee_id])
                            elif not insert_flag:
                                callee_id = None
                                pass
                            else:
                                insert_flag = True
                        
                        if insert_flag:
                            callee_id = self.add_node(next_callee, self.exceeded_node_symbol, self.default_color)
                    if self.config.debug:
                        self.dbg_print("updating prev_id, was: ", prev_id, "now: ", callee_id)
                    prev_id = callee_id
                    do_it_flag = True
                # callee is BADADDR or caller is in self.filtered_nodes
                else:
                    if self.config.debug:
                        self.dbg_print("callee is BADADDR (means the path is exceeded of limitation) or caller is in filtered_list or caller is not in a function but a part of code")
                    if callee in self.nodes:
                        if self.config.debug: self.dbg_print("updating prev_id, was: ", prev_id, "now: ", self.nodes[callee])
                        prev_id = self.nodes[callee]
                    do_it_flag = True

                if do_it_flag:
                    # insert an exceeded node behind the callee if the callee node is in the filter list.
                    if self.config.debug:
                        self.dbg_print("enter checking if callee (%x) is filtered nodes or not" % callee)
                        self.dbg_print("last_hit: %d, i: %d, callee: %x, filtered_nodes: %s" % (last_hit, i, callee, str([hex(x).rstrip("L") for x in self.filtered_nodes])))
                    if last_hit >= i and callee in self.filtered_nodes:
                        if self.config.debug:
                            self.dbg_print("callee (%x) is in filtered_nodes" % callee)
                            self.dbg_print("exceeded_nodes:", [hex(x).rstrip("L") for x in self.exceeded_nodes])
                        callee_id = -1
                        if callee in self.nodes:
                            callee_id = self.get_node_id(callee, start_ea, caller=False)
                        if callee_id >= 0:
                            src = self.find_src_node_from_edges(callee_id, self.exceeded_node_symbol)
                            if src < 0:
                                if self.config.debug:
                                    self.dbg_print("callee (%x) does not have an exceeded node. Inserting it." % callee)
                                nid = self.add_node(callee, self.exceeded_node_symbol, self.default_color)
                                self.add_edge(nid, callee_id)
                    # skip underneath nodes of library functions for simple layout
                    elif (self.skip_api and callee_func_type in [FT_API]) or (self.skip_lib and callee_func_type in [FT_LIB]):
                        callee_id = -1
                        if callee in self.nodes:
                            callee_id = self.get_node_id(callee, start_ea, caller=False)
                        elif callee in self.exceeded_nodes:
                            callee_id = self.exceeded_nodes[callee]
                        src = -1
                        if callee_id >= 0:
                            src = self.find_src_node_from_edges(callee_id)
                            # there are no nodes under this callee at the moment.
                        if src < 0 and callee not in self.additional_trace_points:
                            if callee_id >= 0 and prev_caller is not None:
                                # if there are no nodes under the node yet and there
                                # is a next node, insert an exceeded node.
                                callee_id = self.add_node(callee, self.exceeded_node_symbol, self.default_color)
                                self.add_edge(callee_id, prev_id)
                            else:
                                # no more nodes on the result. Nothing to do. Continue processing...
                                pass
                        # there is a node at least.
                        else:
                            if self._nodes[src][0] == self.exceeded_node_symbol:
                                pass
                            else:
                                # there is a node. In this case, this might be a situation,
                                # that a user expanded an exceeded node.
                                # I do not need to do anything. Contineue processing...
                                pass
                    """
                    else:
                        if caller != ida_idaapi.BADADDR and not ida_funcs.get_func(caller):
                            self.dbg_print("%x, %x" % (caller, callee))
                            if self.config.debug:
                                self.dbg_print("updating prev_id. (old) prev_id:", prev_id, "(new) callee_id:", None)
                            prev_id = None
                            callee_id = -1
                    """
                
                #################################
                #
                # for caller nodes
                #
                if self.config.debug:
                    self.dbg_print("------------- processing the caller (%x)" % caller)
                if not self.config.skip_caller:
                    # upper or lower function is exceeded of maximum limitation.
                    if caller == ida_idaapi.BADADDR:
                        if next_callee in self.exceeded_nodes:
                            caller_id = self.exceeded_nodes[next_callee]
                        else:
                            str_next_caller = "None"
                            if self.config.debug:
                                if next_caller is not None:
                                    str_next_caller = hex(next_caller).rstrip("L")
                                self.dbg_print("next_callee:", hex(next_callee).rstrip("L"), "filtered_nodes (keys):", str([hex(x).rstrip("L") for x in self.filtered_nodes]), "next_caller:", str_next_caller, "filtered_nodes (values):", str([hex(x).rstrip("L") for x in self.filtered_nodes]))
                            if next_callee in self.nodes:
                                next_callee_id = self.nodes[next_callee]
                                src = self.find_src_node_from_edges(next_callee_id)
                                self.dbg_print("src:", src)
                                if src < 0:
                                    if next_callee not in self.additional_trace_points:
                                        caller_id = self.add_node(next_callee, self.exceeded_node_symbol, self.default_color)
                                    else:
                                        caller_id = None
                                else:
                                    caller_id = self.get_node_id(self.node_ids[src], start_ea, caller=True)
                            elif next_callee in self.filtered_nodes or next_caller in self.filtered_nodes:
                                caller_id = None
                            elif start_ea in self.trace_points_relations and "parents" in self.trace_points_relations[start_ea] and next_callee in self.trace_points_relations[start_ea]["parents"]:
                                caller_id = None
                            else:
                                caller_id = self.add_node(next_callee, self.exceeded_node_symbol, self.default_color)
                    
                    # for existing nodes (general nodes)
                    elif caller in self.caller_nodes:
                        if prev_id is not None and prev_caller != caller:
                            caller_id = self.get_node_id(caller, start_ea, caller=True)
                            self.add_edge(prev_id, caller_id)
                        else:
                            pass
                    
                    # for new nodes to be added
                    else:
                        line = self.get_space_removed_disasm(caller)
                        color = self.get_color(callee_func_type, caller)
                        if next_callee in self.nodes:
                            next_callee_id = self.nodes[next_callee]
                            src = self.find_src_node_from_edges(next_callee_id, self.exceeded_node_symbol)
                            if src >= 0:
                                src_ea = self.exceeded_node_ids[src]
                                # src_ea is callee. continue the replacing process.
                                if src_ea in self.func_relations:
                                    pass
                                # src_ea is caller. caller's parent is not caller. I do not replace.
                                else:
                                    src = -1
                            if self.config.debug:
                                self.dbg_print("caller: %x, next_callee: %x, next_callee_id: %d, src:%d" % (caller, next_callee, next_callee_id, src,))
                        else:
                            src = -1
                        
                        # if a callee has a "..." node, replace it with actual a function pointer.
                        if src >= 0:
                            caller_id = src
                            src_ea = self.replace_node(src, line, color, start_ea, caller, func_type=callee_func_type, caller=True)
                            if self.config.debug:
                                self.dbg_print("replace an exceeded_node with the caller (%x %d)" % (src_ea, caller_id))
                        # create a new node for a new function
                        else:
                            caller_id = self.add_node(caller, line, color, start_ea, func_type=callee_func_type, caller=True)
                        
                        if prev_id is not None and caller not in self.filtered_nodes:
                            self.add_edge(prev_id, caller_id)

                    if self.config.debug:
                        self.dbg_print("updating prev_id. (old) prev_id:", prev_id, "(new) caller_id:", caller_id)
                    prev_id = caller_id
                    
                    # insert an exceeded node if the caller node is in the filter list.
                    if self.config.debug:
                        pid = prev_id
                        if prev_id is None:
                            pid = -1
                        if self.config.debug:
                            self.dbg_print("last_hit: %d, i: %d, caller: %x, filtered_nodes(keys): %s, filtered_nodes (values): %s, prev_id:%d" % (last_hit, i, caller, str([hex(x).rstrip("L") for x in self.filtered_nodes]), str([hex(self.filtered_nodes[x][0]).rstrip("L") for x in self.filtered_nodes]), pid))
                    if last_hit >= i and caller in self.filtered_nodes and prev_id is not None:
                        src = self.find_src_node_from_edges(prev_id, self.exceeded_node_symbol)
                        if src < 0:
                            nid = self.add_node(caller, self.exceeded_node_symbol, self.default_color)
                            self.add_edge(nid, prev_id)
                    
                if callee != ida_idaapi.BADADDR and callee in self.func_relations:
                    # adding strings nodes
                    #self.insert_string_node(callee)
                    
                    # adding global/static variable nodes
                    #self.insert_var_node(callee, func_type="gvars", node_type="Global/Static Vars Ref", node_color=self.gvars_color, loc_cache=self.gvars_contents, show_flag=self.config.show_gvars_nodes, skip_content=False)
                    
                    # adding structure member access nodes
                    #self.insert_var_node(callee, func_type="struct_offsets", node_type="Struct Members", node_color=self.stroff_color, loc_cache=self.stroff_contents, show_flag=self.config.show_stroff_nodes, skip_content=True)
                    
                    # adding comments nodes
                    self.insert_comment_node(callee)
            
                    # get children under the callee function.
                    if self.config.display_children_in_parent_funcs:
                        if self.config.debug: self.dbg_print("#################### Start diging into children in  %x #########################" % callee)
                        self.draw_children_call_tree(callee, self.end_ea, max_recursive=1)
                        if self.config.debug: self.dbg_print("#################### Finished diging into children in  %x #########################" % callee)
                    
            # for start node
            if start_ea in self.nodes:
                nid = self.get_node_id(start_ea, start_ea, caller=False)
                if nid == self.nodes[self.start_ea] and self._nodes[nid][1] != self.start_color:
                    self._nodes[nid] = (self._nodes[nid][0], self.start_color)
            else:
                func_type = self.func_relations[start_ea]["func_type"]
                func_name = self.get_callee_name(start_ea, func_type)
                nid = self.add_node(start_ea, func_name, self.start_color, start_ea, func_type=func_type, caller=False)
            
            if prev_id is not None:
                self.add_edge(prev_id, nid)
        
        # adding strings nodes
        #self.insert_string_node(start_ea)
        
        # adding global/static variable nodes
        #self.insert_var_node(start_ea, func_type="gvars", node_type="Global/Static Vars Ref", node_color=self.gvars_color, loc_cache=self.gvars_contents, show_flag=self.config.show_gvars_nodes, skip_content=False)
        
        # adding structure member access nodes
        #self.insert_var_node(start_ea, func_type="struct_offsets", node_type="Struct Members", node_color=self.stroff_color, loc_cache=self.stroff_contents, show_flag=self.config.show_stroff_nodes, skip_content=True)
        
        # adding comments nodes
        self.insert_comment_node(start_ea)
        
        if self.config.debug: self.dbg_print("#################### Finished processing for parents at %x #########################" % start_ea)
    
    def draw_children_call_tree(self, start_ea, end_ea, max_recursive=g_max_recursive):
        if start_ea not in self.related_nodes:
            self.related_nodes[start_ea] = set([start_ea])
            
        # push a starter node
        #self.insert_dref_node_info(start_ea, direction="children")
        dref_flag = False
        func_type = FT_UNK
        if start_ea not in self.nodes:
            # for functions
            if start_ea in self.func_relations:
                func_type = self.func_relations[start_ea]["func_type"]
                func_name = self.get_callee_name(start_ea, func_type)
            # for strings and global variables
            else:
                func_type = FT_VAR
                for dref_ea, dref_func_ea, dref_off_ea in get_func_relation.get_dref_from_belong_to_func(start_ea):
                    dref_flag, func_type = self.dref_data_type(dref_ea, dref_func_ea, dref_off_ea)
                    if dref_flag:
                        break
                func_name = self.get_callee_name(start_ea, func_type)
            nid = self.add_node(start_ea, func_name, self.start_color, start_ea, func_type=func_type, caller=False)
            if nid == self.nodes[self.start_ea] and self._nodes[nid][1] != self.start_color:
                self._nodes[nid] = (self._nodes[nid][0], self.start_color)
        else:
            nid = self.get_node_id(start_ea, start_ea, caller=False)
            if start_ea not in self.func_relations:
                func_type = FT_VAR
                for dref_ea, dref_func_ea, dref_off_ea in get_func_relation.get_dref_from_belong_to_func(start_ea):
                    dref_flag, func_type = self.dref_data_type(dref_ea, dref_func_ea, dref_off_ea)
                    if dref_flag:
                        break
        
        # adding strings nodes
        #self.insert_string_node(start_ea)
        self.insert_string_node(start_ea, start_ea, nid)
        
        # adding global/static variable nodes
        #self.insert_var_node(start_ea, func_type="gvars", node_type="Global/Static Vars Ref", node_color=self.gvars_color, loc_cache=self.gvars_contents, show_flag=self.config.show_gvars_nodes, skip_content=False)
        
        # adding structure member access nodes
        #self.insert_var_node(start_ea, func_type="struct_offsets", node_type="Struct Members", node_color=self.stroff_color, loc_cache=self.stroff_contents, show_flag=self.config.show_stroff_nodes, skip_content=True)
        
        # adding comments nodes
        self.insert_comment_node(start_ea)
        
        if self.config.debug: self.dbg_print("before tracing... start_ea: %x, end_ea: %x, max_recursive: %d" % (start_ea, end_ea, max_recursive))
        for r in self.trace_paths_with_cache(start_ea, end_ea, max_recursive=max_recursive, direction="children"):
            if self.config.debug:
                self.dbg_print("########### found a path", [(hex(x).rstrip("L"), hex(y).rstrip("L"), z) for x,y,z in r])
            
            # for path_finder popup menu
            if max_recursive < 0 and self.max_nodes < (len(self._nodes) + len(r)):
                ida_kernwin.msg("The number of max_nodes is exceeded (%d < %d). Note that this graph result is incompleted.%s" % (self.max_nodes, len(self._nodes)+len(r), os.linesep))
                ida_kernwin.msg("Change the graph type and dig into it manually.%s" % (os.linesep))
                break
                
            # skip the path if the last node is not a node displayed by config
            if not dref_flag and not self.is_path_displayable(r):
                continue
            
            # to skip nodes in a result if a filtered node is included, check a result first.
            last_hit = -1
            idx = -1
            tmp_flag = False
            for idx, (caller, callee, callee_func_type) in enumerate(r):
                if caller in self.filtered_nodes or callee in self.filtered_nodes:
                    if self.config.debug:
                        self.dbg_print("found a filteed node:", idx, hex(caller).rstrip("L"), hex(callee).rstrip("L"), [hex(x).rstrip("L") for x in self.filtered_nodes])
                    first_hit = idx
                    tmp_flag = True
                    #### need to break. get the first filtered item.
                    break
            if not tmp_flag:
                first_hit = -1
            
            prev_id = self.get_node_id(start_ea, start_ea, caller=False, update=False)
            prev_callee = None
            prev_callee_func_type = FT_UNK
            next_caller = None
            for i, (caller, callee, callee_func_type) in enumerate(r):
                if self.config.debug:
                    self.dbg_print("i:", i, "first_hit:", first_hit, "caller:", hex(caller).rstrip("L"), "callee:", hex(callee).rstrip("L"))
                if i > 0:
                    prev_callee = r[i-1][1]
                    prev_callee_func_type = r[i-1][2]
                # i == 0 for start_ea as the top item of the child nodes
                else:
                    prev_callee = start_ea
                    prev_callee_func_type = func_type
                if (len(r) - 1) > i:
                    next_caller = r[i+1][0]
                    if self.config.skip_caller:
                        next_caller = r[i+1][1]
                else:
                    next_caller = None
                
                if self.config.debug:
                    self.dbg_print("processing %d/%d for a set of caller/callee (%x/%x)" % (i+1, len(r), caller, callee))
                
                # insert an exceeded node and
                # skip nodes after a filter node matched
                if first_hit >= 0 and first_hit < i:
                    # CTO will insert an exceeded node after inserting the callee
                    if self.config.debug:
                        self.dbg_print("Skipping inserting process (%d/%d) first_hit: %d, i: %d" % (i+1, len(r), first_hit, i))
                    break
                elif first_hit >= 0 and first_hit >= i:
                    if self.config.debug:
                        self.dbg_print("Skipping inserting process (%d/%d) first_hit: %d, i: %d" % (i+1, len(r), first_hit, i))
                    # if the path is already existent, just stop it.
                    if not self.config.skip_caller and caller in self.filtered_nodes and caller in self.caller_nodes:
                        break
                    elif self.config.skip_caller and callee in self.filtered_nodes and callee in self.nodes:
                        break
                # if the current pair is for an exceeded node and its beyond nodes are not related to code and show_gvars_nodes is disabled, skip inserting exceeded node
                elif caller == ida_idaapi.BADADDR and callee_func_type == FT_VAR and not self.config.show_gvars_nodes:
                    break

                #################################
                #
                # for caller functions
                #
                if self.config.debug:
                    self.dbg_print("------------- processing the caller (%x)" % caller)
                # upper or lower function is exceeded of maximum limitation.
                if not self.config.skip_caller:
                    if caller == ida_idaapi.BADADDR:
                        if prev_callee in self.nodes:
                            prev_callee_id = self.nodes[prev_callee]
                            dst = self.find_dst_node_from_edges(prev_callee_id)
                            if dst < 0 and prev_callee not in self.additional_trace_points:
                                caller_id = self.add_node(prev_callee, self.exceeded_node_symbol, self.default_color)
                                self.add_edge(prev_callee_id, caller_id)
                            else:
                                # in a case that it has a child node but is string or other type of node, not caller nodes.
                                dst = self.find_dst_node_from_edges(prev_callee_id, self.exceeded_node_symbol)
                                if dst < 0 and prev_callee not in self.additional_trace_points:
                                    # check if there is a displayed child node or not
                                    dsts = self.find_dst_nodes_from_edges(prev_callee_id)
                                    child_flag = False
                                    for d in dsts:
                                        if d in self.node_ids and prev_callee in self.func_relations and self.node_ids[d] in self.func_relations[prev_callee]['children']:
                                            child_flag = True
                                            break
                                        
                                    if not child_flag and prev_callee in self.func_relations and len(self.func_relations[prev_callee]['children']) >= 0:
                                        # if no children and no exceeded symbol, insert exceeded node
                                        caller_id = self.add_node(prev_callee, self.exceeded_node_symbol, self.default_color)
                                        self.add_edge(prev_callee_id, caller_id)
                                    else:
                                        caller_id = None
                                else:
                                    caller_id = None
                        elif prev_callee in self.exceeded_nodes:
                            caller_id = self.exceeded_nodes[prev_callee]
                            if prev_id is not None:
                                self.add_edge(prev_id, caller_id)
                        elif prev_callee not in self.additional_trace_points:
                            caller_id = self.add_node(prev_callee, self.exceeded_node_symbol, self.default_color)
                            if prev_id is not None:
                                self.add_edge(prev_id, caller_id)
                        else:
                            caller_id = None
                    # for existing nodes (general nodes)
                    elif caller in self.caller_nodes:
                        if self.config.debug: self.dbg_print("caller is already existing in nodes list. (caller: %x)" % (caller), prev_callee)
                        if caller in self.caller_nodes:
                            caller_id = self.caller_nodes[caller]
                        else:
                            caller_id = self.nodes[caller]
                        dst = self.find_dst_node_from_edges(caller_id, self.exceeded_node_symbol)
                        if dst >= 0:
                            dst_ea = self.exceeded_node_ids[dst]
                            if self.config.debug: self.dbg_print("dst exceeded_node %d, %x" % (dst, dst_ea))
                            # dst_ea is callee. continue the replacing process.
                            if dst_ea in self.func_relations:
                                pass
                            # dst_ea is caller. caller's child is not caller. I do not replace.
                            else:
                                dst = -1
                        # if a callee has a "..." node, replace it with actual a function pointer.
                        if dst >= 0:
                            line = self.get_space_removed_disasm(caller)
                            color = self.get_color(callee_func_type, caller)
                            # change caller_id to the replaced node
                            caller_id = dst
                            dst_ea = self.replace_node(dst, line, color, start_ea, caller, func_type=callee_func_type, caller=True)
                        else:
                            self.update_related_nodes(caller, start_ea)
                            if prev_id is not None and prev_callee != caller:
                                self.add_edge(prev_id, caller_id)
                    # for new nodes to be added
                    else:
                        if self.config.debug: self.dbg_print("try to insert a node (caller: %x)" % (caller))
                        line = self.get_space_removed_disasm(caller)
                        color = self.get_color(callee_func_type, caller)
                        if prev_callee in self.nodes:
                            prev_callee_id = self.nodes[prev_callee]
                            dst = self.find_dst_node_from_edges(prev_callee_id, self.exceeded_node_symbol)
                            if self.config.debug: self.dbg_print("dst exceeded_node %d" % (dst))
                        else:
                            dst = -1
                        if dst < 0 and callee in self.nodes:
                            callee_id = self.nodes[callee]
                            dst = self.find_src_node_from_edges(callee_id, self.exceeded_node_symbol)
                            if self.config.debug: self.dbg_print("dst exceeded_node %d (callee: %x)" % (dst, callee))
                        
                        if dst >= 0:
                            dst_ea = self.exceeded_node_ids[dst]
                            if self.config.debug: self.dbg_print("dst exceeded_node %d (dst=ea: %x)" % (dst, dst_ea))
                            # dst_ea is callee. continue the replacing process.
                            if dst_ea in self.func_relations:
                                if self.config.debug: self.dbg_print("dst is callee %d, %x" % (dst, dst_ea))
                                dst = -1
                            # dst_ea is caller. caller's child is not caller. I do not replace.
                            else:
                                if self.config.debug: self.dbg_print("dst is caller: %d, %x" % (dst, dst_ea))
                                pass

                        add_node_flag = False
                        # if a callee has a "..." node, replace it with actual a function pointer.
                        if dst >= 0:
                            caller_id = dst
                            #src_ea = self.replace_node(dst, line, color, start_ea, caller, func_type=callee_func_type, caller=True)
                            src_ea = self.replace_node(dst, line, color, start_ea, caller, func_type=callee_func_type, caller=True)
                            srcs = self.find_src_nodes_from_edges(dst)
                            if prev_id not in srcs:
                                add_node_flag = True
                                
                            # after replacing a node, check if cto still needs to insert an exceeded node or not.
                            if callee in self.nodes:
                                tmp_callee_id = self.nodes[callee]
                                tmp_src = self.find_src_node_from_edges(tmp_callee_id, self.exceeded_node_symbol)
                                if tmp_src < 0:
                                    # there is no exceeded node
                                    # get all inserted node ids
                                    srcs = self.find_src_nodes_from_edges(tmp_callee_id)
                                    # get all referenced parent paths of the callee address
                                    for tmp_r in self.trace_paths_with_cache(callee, end_ea, max_recursive=1, direction="parents"):
                                        # check if there is an undisplayed node
                                        add_exceeded_node_flag = False
                                        if len(tmp_r) > 0:
                                            tmp_caller, tmp_callee, tmp_callee_func_type = tmp_r[0]
                                            if tmp_caller in self.caller_nodes:
                                                if self.caller_nodes[tmp_caller] not in srcs:
                                                    add_exceeded_node_flag = True
                                            else:
                                                add_exceeded_node_flag = True
                                        if add_exceeded_node_flag:
                                            # if no children and no exceeded symbol, insert exceeded node
                                            tmp_caller_id = self.add_node(callee, self.exceeded_node_symbol, self.default_color)
                                            tmp_callee_id = self.nodes[callee]
                                            self.add_edge(tmp_caller_id, tmp_callee_id)
                                            break
                                
                        # create a new node for a new function
                        else:
                            caller_id = self.add_node(caller, line, color, start_ea, func_type=callee_func_type, caller=True)
                            add_node_flag = True
                            
                        if prev_id is not None and add_node_flag:
                            self.add_edge(prev_id, caller_id)
                    if self.config.debug:
                        self.dbg_print("updating prev_id, was: ", prev_id, "now: ", caller_id)
                    prev_id = caller_id

                    # insert an exceeded node if the caller node is in the filter list.
                    if first_hit >= i and caller in self.filtered_nodes:
                        nid = self.add_node(caller, self.exceeded_node_symbol, self.default_color)
                        self.add_edge(prev_id, nid)
                        if self.config.debug:
                            self.dbg_print("updating prev_id, was: ", None, "now: ", prev_id)
                        prev_id = None
                        break
                
                ##########################
                #
                # for callee functions
                #
                if self.config.debug:
                    self.dbg_print("++++++++++ processing the callee (%x)" % callee)
                if callee != ida_idaapi.BADADDR:
                    if self.config.debug:
                        self.dbg_print("callee (%x) is not BADADDR" % callee)
                    if callee in self.nodes:
                        if self.config.debug:
                            self.dbg_print("callee (%x) is in nodes" % callee)
                        callee_id = self.get_node_id(callee, start_ea, caller=False)
                        if not self.config.skip_caller:
                            if self.config.debug:
                                self.dbg_print("skip caller is disabled and callee (%x) is in nodes" % callee)
                        else:
                            if self.config.debug:
                                self.dbg_print("skip caller is enabled and callee (%x) is in nodes" % callee)
                            if prev_id is not None and prev_callee != callee:
                                self.add_edge(prev_id, callee_id)
                            else:
                                pass
                            
                    elif self.config.skip_caller:
                        line = self.get_callee_name(callee, callee_func_type)
                        color = self.get_color(callee_func_type, callee)
                        if self.config.debug:
                            self.dbg_print("skip_caller is enabled. callee (%x)" % callee)
                        if callee in self.nodes:
                            if self.config.debug:
                                self.dbg_print("callee (%x) is in nodes" % callee)
                            callee_id = self.get_node_id(callee, start_ea, caller=False)
                        elif next_caller in self.exceeded_nodes:
                            if self.config.debug:
                                self.dbg_print("callee (%x) is in exceeded nodes" % callee)
                            callee_id = self.exceeded_nodes[next_caller]
                            n_ea = self.replace_node(callee_id, line, color, start_ea, callee, func_type=callee_func_type, caller=False)
                        elif next_caller in self.exceeded_nodes and callee not in self.nodes:
                            callee_id = self.exceeded_nodes[next_caller]
                            dst_ea = self.replace_node(callee_id, line, color, start_ea, callee, func_type=callee_func_type, caller=False)
                            dst = -1
                        # find a set of callee and caller but they are not connected yet because the max path limitation is exceeded.
                        elif callee in self.func_relations and len(self.func_relations[callee]['parents']) >= 1:
                            if self.config.debug:
                                self.dbg_print("callee (%x) is not in nodes and exceeded nodes" % callee)
                            dst = -1
                            for tmp_ea in [self.func_relations[callee]['parents'][x][0] for x in self.func_relations[callee]['parents']]:
                                if self.config.debug:
                                    self.dbg_print("tmp_ea:", hex(tmp_ea).rstrip("L"), ", prev_callee:", hex(prev_callee).rstrip("L"), ", callee:", hex(callee).rstrip("L"))
                                if tmp_ea != prev_callee:
                                    if self.config.debug:
                                        self.dbg_print("tmp_ea (%x) is a parent of callee (%x) and tmp_ea != prev_callee (%x)" % (tmp_ea, callee, prev_callee))
                                    if tmp_ea in self.func_relations and callee in [self.func_relations[tmp_ea]['children'][x][0] for x in self.func_relations[tmp_ea]['children']]:
                                        if self.config.debug:
                                            self.dbg_print("tmp_ea (%x) is a child of callee (%x)" % (tmp_ea, callee))
                                        if tmp_ea in self.nodes:
                                            if tmp_ea not in self.filtered_nodes:
                                                tmp_dst = self.find_dst_node_from_edges(self.nodes[tmp_ea], self.exceeded_node_symbol)
                                                if tmp_dst >= 0:
                                                    if len(self.func_relations[tmp_ea]["children"]) > 1:
                                                        dst = -1
                                                        if self.config.debug:
                                                            self.dbg_print("tmp_ea's (%x) destination is an exceeded node (%d), but there are two or more nodes. I do not process it." % (tmp_ea, tmp_dst))
                                                        break
                                                    else:
                                                        if self.config.debug:
                                                            self.dbg_print("tmp_ea's (%x) destination is an exceeded node (%d)" % (tmp_ea, tmp_dst))
                                                        dst = tmp_dst
                                                        break
                                            else:
                                                if self.config.debug:
                                                    self.dbg_print("tmp_ea (%x) is in filtered nodes list. skip it." % tmp_ea)
                                        elif tmp_ea in self.exceeded_nodes:
                                            if self.config.debug:
                                                self.dbg_print("tmp_ea (%x) is in exceeded nodes" % tmp_ea)
                                            dst = self.exceeded_nodes[tmp_ea]
                                            dst_ea = self.replace_node(dst, line, color, start_ea, prev_callee, func_type=prev_callee_func_type, caller=False)
                                            if self.config.debug:
                                                self.dbg_print("next_callee (%x) is an exceeded node and it's already displayed. it was replaced with next_callee." % next_callee)
                                            break
                                        else:
                                            if self.config.debug:
                                                self.dbg_print("tmp_ea (%x) is not displayed yet." % tmp_ea)
                            if dst >= 0:
                                if self.config.debug:
                                    self.dbg_print("found tmp_ea (%x) has a destination" % tmp_ea)
                                callee_id = dst
                                if tmp_ea in self.exceeded_nodes:
                                    dst_ea = self.replace_node(dst, line, color, start_ea, callee, func_type=callee_func_type, caller=False)
                                else:
                                    if self.config.debug:
                                        self.dbg_print("tmp_ea (%x) is not in exceeded nodes" % tmp_ea)
                                    pass
                            else:
                                if self.config.debug:
                                    self.dbg_print("callee (%x) does not have any destinations. just add it as a node" % callee)
                                callee_id = self.add_node(callee, line, color, start_ea, func_type=callee_func_type, caller=False)
                        # create a new node for a new function
                        else:
                            if self.config.debug:
                                self.dbg_print("callee (%x) is a new node. add it as a node" % callee)
                            callee_id = self.add_node(callee, line, color, start_ea, func_type=callee_func_type, caller=False)
                        
                    else:
                        func_name = self.get_callee_name(callee, callee_func_type)
                        color = self.get_color(callee_func_type, callee)
                        callee_id = self.add_node(callee, func_name, color, start_ea, func_type=callee_func_type, caller=False)
                    if prev_id is not None:
                        self.add_edge(prev_id, callee_id)
                    if self.config.debug:
                        self.dbg_print("updating prev_id, was: ", prev_id, "now: ", callee_id)
                    prev_id = callee_id
                    
                    # insert an exceeded node if the callee node is in the filter list.
                    if first_hit >= i and callee in self.filtered_nodes and next_caller is not None and (callee != next_caller or next_caller in self.caller_nodes):
                        dst = self.find_dst_node_from_edges(callee_id, self.exceeded_node_symbol)
                        if dst < 0 and callee not in self.additional_trace_points:
                            nid = self.add_node(callee, self.exceeded_node_symbol, self.default_color)
                            self.add_edge(callee_id, nid)
                        break
                    # skip underneath nodes of library functions for simple layout
                    elif (self.skip_api and callee_func_type in [FT_API]) or (self.skip_lib and callee_func_type in [FT_LIB]):
                        dst = self.find_dst_node_from_edges(callee_id)
                        # there are no nodes under this callee at the moment.
                        if dst < 0 and callee not in self.additional_trace_points:
                            if next_caller is not None:
                                # if there are no nodes under the node yet and there
                                # is a next node, insert an exceeded node.
                                caller_id = self.add_node(callee, self.exceeded_node_symbol, self.default_color)
                                self.add_edge(prev_id, caller_id)
                                break
                            else:
                                # no more nodes on the result. Nothing to do. Continue processing...
                                pass
                        # there is a node at least.
                        else:
                            if self._nodes[dst][0] == self.exceeded_node_symbol:
                                break
                            else:
                                # there is a node. In this case, this might be a situation,
                                # that a user expanded an exceeded node.
                                # I do not need to do anything. Contineue processing...
                                pass
                    
                    # there is a node. I do not need to do anything.
                    else:
                        pass
                # for caller skip mode
                elif self.config.skip_caller:
                    if self.config.debug:
                        self.dbg_print("skip caller mode is enabled. this path is for exceeded nodes.")
                    # for exceeded nodes (...)
                    # caller is BADADDR means this path is exceeded of the path length limitation.
                    if caller == ida_idaapi.BADADDR:
                        insert_flag = False
                        if self.config.debug:
                            self.dbg_print("caller is BADADDR. prev_caller (%x)" % prev_callee)
                        if prev_callee in self.nodes:
                            if self.config.debug:
                                self.dbg_print("prev_callee (%x) is in nodes" % prev_callee)
                            prev_callee_id = self.nodes[prev_callee]
                            dst = self.find_dst_node_from_edges(prev_callee_id)
                            if dst < 0:
                                if self.config.debug:
                                    self.dbg_print("prev_callee (%x) does not have any destination nodes." % prev_callee)
                                insert_flag = True
                                if prev_callee in self.additional_trace_points:
                                    insert_flag = False
                            else:
                                if self.config.debug:
                                    self.dbg_print("prev_callee (%x) has a destination node in nodes or exceeded_nodes" % (prev_callee))
                                callee_id = dst
                        else:
                            if self.config.debug:
                                self.dbg_print("prev_callee (%x) has no destinations or has an exceeded node" % prev_callee)
                            insert_flag = True

                        # find a set of callee and caller but they are not connected yet because the max path limitation is exceeded.
                        if insert_flag and prev_callee in self.func_relations and len(self.func_relations[prev_callee]['children']) >= 1:
                            if self.config.debug:
                                self.dbg_print("insert_flag is true")
                            dst = -1
                            for tmp_ea in [self.func_relations[prev_callee]['children'][x][0] for x in self.func_relations[prev_callee]['children']]:
                                if self.config.debug:
                                    self.dbg_print("tmp_ea:", hex(tmp_ea).rstrip("L"), ", prev_callee:", hex(prev_callee).rstrip("L"), ", callee:", hex(callee).rstrip("L"))
                                if tmp_ea in self.nodes:
                                    src_eas = [self.node_ids[x] for x in self.find_src_nodes_from_edges(self.nodes[tmp_ea]) if x in self.node_ids]
                                    if prev_callee not in src_eas:
                                        if self.config.debug:
                                            self.dbg_print("tmp_ea (prev_callee's child (%x)) is not a parent of tmp_ea" % (tmp_ea))
                                        if tmp_ea in self.func_relations and prev_callee in [self.func_relations[tmp_ea]['parents'][x][0] for x in self.func_relations[tmp_ea]['parents']]:
                                            if self.config.debug:
                                                self.dbg_print("prev_callee (%x) is in a tmp_ea's (%x) parent" % (prev_callee, tmp_ea))
                                            dst = self.nodes[tmp_ea]
                                            if prev_callee in self.nodes:
                                                if self.config.debug:
                                                    self.dbg_print("prev_callee (%x) is already displayed as a node" % prev_callee)
                                                callee_id = self.nodes[prev_callee]
                                                self.add_edge(callee_id, dst)
                                            elif prev_callee in self.additional_trace_points:
                                                insert_flag = False
                                                dst = -1
                                                if self.config.debug:
                                                    self.dbg_print("prev_callee (%x) is in additional trace points" % prev_callee)
                                                pass
                                            #elif tmp_ea in self.nodes and prev_callee not in self.nodes:
                                            #    self.dbg_print("a dst node (tmp_ea) (%x) is already inserted." % tmp_ea)
                                            #    insert_flag = False
                                            else:
                                                insert_flag = False
                                                #dst = -1
                                                if self.config.debug:
                                                    self.dbg_print("prev_callee (%x) is not displayed yet." % prev_callee)
                                            break
                                else:
                                    if tmp_ea in self.func_relations and prev_callee in [self.func_relations[tmp_ea]['parents'][x][0] for x in self.func_relations[tmp_ea]['parents']]:
                                        if self.config.debug:
                                            self.dbg_print("prev_callee (%x) is a tmp_ea's (%x) child" % (prev_callee, tmp_ea))
                                        if prev_callee in self.nodes and tmp_ea in self.exceeded_nodes:
                                            dst = self.exceeded_nodes[tmp_ea]
                                            dst_ea = self.replace_node(dst, line, color, start_ea, prev_callee, func_type=prev_callee_func_type, caller=False)
                                            if self.config.debug:
                                                self.dbg_print("prev_callee (%x) is an exceeded node and it's already displayed. it was replaced with next_callee." % prev_callee)
                                            self.add_edge(callee_id, dst)
                                            break
                                        elif prev_callee in self.additional_trace_points:
                                            insert_flag = False
                                            dst = -1
                                            if self.config.debug:
                                                self.dbg_print("prev_callee (%x) is in additional trace points" % prev_callee)
                                            break
                            if dst >= 0:
                                callee_id = dst
                                self.update_related_nodes(self.node_ids[callee_id], start_ea)
                                insert_flag = False
                                if self.config.debug:
                                    self.dbg_print("callee (%x) has a destination" % callee)
                            elif not insert_flag:
                                callee_id = None
                                pass
                            else:
                                insert_flag = True
                        
                        if insert_flag:
                            callee_id = self.add_node(prev_callee, self.exceeded_node_symbol, self.default_color)
                            prev_callee_id = self.nodes[prev_callee]
                            self.add_edge(prev_callee_id, callee_id)
                            
                    # for displaying indirect calls even if it's in skip caller mode while show_indirect_calls flag is enabled.
                    #if self.config.skip_caller and self.config.show_indirect_calls:
                    if self.config.show_indirect_calls:
                        if callee_func_type == FT_MEM and caller != ida_idaapi.BADADDR:
                            line = self.get_space_removed_disasm(caller)
                            color = self.get_color(callee_func_type, caller)
                            nid = self.add_node(caller, line, color, start_ea, func_type=callee_func_type, caller=True)
                            self.add_edge(prev_id, nid)
                            callee_id = nid

                    # for indirect call but it has a pointer to an API
                    if callee == ida_idaapi.BADADDR:
                        if caller != ida_idaapi.BADADDR:
                            _, func_type, opn, func_name = self.func_relations[prev_callee]['children'][caller]
                            if func_name:
                                found_flag = False
                                for i, (txt, color) in enumerate(self._nodes):
                                    if func_name == ida_lines.tag_remove(txt):
                                        found_flag = True
                                        callee_id = i
                                        break
                                if not found_flag:
                                    callee_id = self.add_node(ida_idaapi.BADADDR, self.color_callee_str(func_name, func_type), self.get_color(func_type), start_ea, func_type=func_type, caller=False, node_type="Dynamic Call")
                                    tif = tinfo.get_tinfo_by_name(func_name)
                                    if tif:
                                        tinfo.apply_tinfo_to_ea(tif, caller, opn)
                                prev_callee_id = self.nodes[prev_callee]
                                self.add_edge(prev_callee_id, callee_id)
                    
                    if self.config.debug:
                        self.dbg_print("updating prev_id, was: ", prev_id, "now: ", callee_id)
                    prev_id = callee_id
                
                # caller skip mode is disabled and callee is BADADDR
                elif callee == ida_idaapi.BADADDR:
                    # for indirect call but it has a pointer to an API
                    if caller != ida_idaapi.BADADDR:
                        func_name = ""
                        func_type = FT_UNK
                        opn = -1
                        if prev_callee in self.func_relations:
                            _, func_type, opn, func_name = self.func_relations[prev_callee]['children'][caller]
                        else:
                            func_type = FT_UNK
                            opn = -1
                            func_name = ""
                            for dref_ea, dref_func_ea, dref_off_ea in get_func_relation.get_dref_from_belong_to_func(prev_callee):
                                if dref_ea in self.func_relations[dref_func_ea]["strings"]:
                                    _, func_type, opn, func_name = self.func_relations[dref_func_ea]["strings"][dref_ea]
                                    break
                                elif dref_ea in self.func_relations[dref_func_ea]["gvars"]:
                                    _, func_type, opn, func_name = self.func_relations[dref_func_ea]['gvars'][dref_ea]
                                    break
                        if func_name:
                            found_flag = False
                            for i, (txt, color) in enumerate(self._nodes):
                                if func_name == ida_lines.tag_remove(txt):
                                    found_flag = True
                                    callee_id = i
                                    break
                            if not found_flag:
                                callee_id = self.add_node(ida_idaapi.BADADDR, self.color_callee_str(func_name, func_type), self.get_color(func_type), start_ea, func_type=func_type, caller=False, node_type="Dynamic Call")
                                tif = tinfo.get_tinfo_by_name(func_name)
                                if tif:
                                    tinfo.apply_tinfo_to_ea(tif, caller, opn)
                            caller_id = self.nodes[caller]
                            self.add_edge(caller_id, callee_id)
                
                            if self.config.debug:
                                self.dbg_print("updating prev_id, was: ", prev_id, "now: ", callee_id)
                            prev_id = callee_id
                    
                # insert an exceeded node behind the callee if the callee node is in the filter list.
                if first_hit >= i and callee in self.filtered_nodes:
                    dst = self.find_dst_node_from_edges(callee_id, self.exceeded_node_symbol)
                    if dst < 0 and callee not in self.additional_trace_points:
                        nid = self.add_node(callee, self.exceeded_node_symbol, self.default_color)
                        self.add_edge(callee_id, nid)
                        # if CTO inserts an exceeded nodes, skip the strings, variables and comments and so on
                        #continue
                        
                # insert a string content node
                if callee_func_type == FT_STR and callee != ida_idaapi.BADADDR:
                    ref_func_ea = prev_callee
                    ref_ea = ida_idaapi.BADADDR
                    if prev_callee not in self.func_relations:
                        if len(r) > 2 and i >= 2:
                            ref_func_ea = r[i-2][1]
                            ref_ea = prev_callee
                        elif len(r) >= 2 and i == 1:
                            ref_func_ea = start_ea
                            ref_ea = r[0][1]
                    if ref_func_ea != ida_idaapi.BADADDR:
                        self.insert_string_node(callee, ref_func_ea, prev_id, ref_ea)
                
                #if i < self.max_depth - 1:
                if callee != ida_idaapi.BADADDR and callee in self.func_relations:
                    # adding strings nodes
                    #self.insert_string_node(callee)
                    
                    # adding global/static variable nodes
                    #self.insert_var_node(callee, func_type="gvars", node_type="Global/Static Vars Ref", node_color=self.gvars_color, loc_cache=self.gvars_contents, show_flag=self.config.show_gvars_nodes, skip_content=False)
                    
                    # adding structure member access nodes
                    #self.insert_var_node(callee, func_type="struct_offsets", node_type="Struct Members", node_color=self.stroff_color, loc_cache=self.stroff_contents, show_flag=self.config.show_stroff_nodes, skip_content=True)
                    
                    # adding comments nodes
                    self.insert_comment_node(callee)
        
        if self.config.debug: self.dbg_print("#################### Finished processing for children at %x #########################" % start_ea)
    
    def draw_call_tree(self):
        if self.config.debug:
            self.dbg_print("############################## start_ea: %x" % self.start_ea)
        
        # for parents tracing
        t1 = time.time()
        if not self.skip_parents:
            if self.config.debug:
                self.dbg_print("############################## parents: ")
            self.draw_parents_call_tree(self.start_ea, self.end_ea, self.max_depth)
        t2 = time.time()
        if self.config.debug: self.dbg_print("parents time: %d" % (t2-t1))

        # for children tracing
        if not self.skip_children:
            if self.config.debug:
                self.dbg_print("############################## children: ")
            self.draw_children_call_tree(self.start_ea, self.end_ea, self.max_depth)
        t3 = time.time()
        if self.config.debug: self.dbg_print("children time: %d" % (t3-t2))

        # for expanded nodes
        for p in self.additional_trace_points:
            if self.config.debug:
                self.dbg_print("############################## additional tracing point at %x" % p)
            direction = self.additional_trace_points[p]
            if direction == "parents":
                if not self.skip_parents:
                    self.draw_parents_call_tree(p, self.end_ea, max_recursive=self.max_depth)
            elif direction == "children":
                if not self.skip_children:
                    self.draw_children_call_tree(p, self.end_ea, max_recursive=self.max_depth)

        if self.config.debug:
            self.dbg_print("############################## finished to build call tree process.")
    
    def change_widget_icon(self, icon_data=None, bg_change=False, w=None):
        if icon_data is None:
            icon_data = self.icon.icon_data
        if w is None:
            w = self.GetWidget()
        return self.icon.change_widget_icon(w, icon_data, bg_change)
        
    def zoom_graph(self, w=None, zoom=1, x=None, y=None):
        if w is None:
            w = self.GetWidget()
        if w is None:
            return None
        w_gli = ida_moves.graph_location_info_t()
        if ida_graph.viewer_get_gli(w_gli, w, ida_graph.GLICTL_CENTER):
            if x is not None:
                w_gli.orgx = x
            if y is not None:
                w_gli.orgy = y
            w_gli.zoom = zoom
            ida_graph.viewer_set_gli(w, w_gli, ida_graph.GLICTL_CENTER)
            
    def show_graph(self, zoom=1):
        drefs = list(get_func_relation.get_drefs_to(self.start_ea))
        if self.start_ea not in self.func_relations and len(drefs) == 0 and self.start_ea not in self.vtbl_refs:
            ida_kernwin.msg("Must be in a function" + os.linesep)
            return False
        
        # convert start address if it is a vfunc
        if self.start_ea in self.vtbl_refs:
            self.start_ea = self.vtbl_refs[self.start_ea]
            
        # display IDA View window
        w, wt = self.get_widget()
        wname = ida_kernwin.get_widget_title(w)
        if not w:
            ida_kernwin.msg("IDA-View is not available. Opening.%s" % (os.linesep))
            ida_kernwin.open_disasm_window("A")
            w, wt = self.get_widget()
            wname = ida_kernwin.get_widget_title(w)
        
        # show the call graph
        r = self.show()

        # if show() is failed or the widget instance does not exist, do not continue.
        if not r:
            ida_kernwin.msg("Failed to display the call tree graph.%s" % (os.linesep))
            self.close()
            return False
        if not self.GetWidget():
            # if self.GetWidget() returns None, do not show the graph.
            ida_kernwin.msg("Failed to display the call tree graph because it failed to get the widget instance.%s" % (os.linesep))
            self.close()
            return False
        
        # use the option not to close by pressing ESC key
        ida_kernwin.display_widget(self.GetWidget(), ida_kernwin.WOPN_NOT_CLOSED_BY_ESC, None)
        
        # zoom the call graph
        self.zoom_graph(self.GetWidget(), zoom=zoom)
        
        # docking to IDA View-A
        if self.parent is not None:
            ida_kernwin.set_dock_pos(self.title, self.parent.title, ida_kernwin.DP_TAB)
        else:
            ida_kernwin.set_dock_pos(self.title, wname, ida_kernwin.DP_RIGHT)
        
        # use the option not to close by pressing ESC key
        ida_kernwin.display_widget(self.GetWidget(), ida_kernwin.WOPN_NOT_CLOSED_BY_ESC, None)
        
        # jump to start ea
        self.jumpto(self.start_ea)
        
        # center the start address
        nid = self.nodes[self.start_ea]
        self.do_center_node(nid)
        # color all nodes
        self.color_all_nodes()
        
        # try to automatically detect dark mode for the first execution
        prev_dark_mode = self.config.dark_mode
        if self.GetWidget():
            self.config.dark_mode = self.is_dark_mode_with_main()
        else:
            self.config.dark_mode = self.is_dark_mode()
        self.change_widget_icon(bg_change=self.config.dark_mode)
        if prev_dark_mode != self.config.dark_mode or self.config.dark_mode:
            self.refresh()
            
        # register path_finder* actions
        if self.parent:
            self.icon_id = self.parent.icon_id
        else:
            self.icon_id = ida_kernwin.load_custom_icon(data=self.icon.icon_data)
            
        for actname, skip, direction, direction2 in self.path_finder_permanent_action_name():
            desc = ida_kernwin.action_desc_t(actname, "Find the path(s) %s this node%s" % (direction, direction2), self.path_finder_by_ea(self, skip, actname, prefix="cto:path_finder"))
            # unregister it once if it has already registered
            ida_kernwin.unregister_action(actname)
            # register it again
            ida_kernwin.register_action(desc)
            
            if self.icon_id > 0:
                ida_kernwin.update_action_icon(actname, self.icon_id)
                
        self.get_focus(self.GetWidget())
        return r

def exec_cto(cto_data=None, curr_view=None, max_depth=1, debug=False):
    if debug or ("g_debug" in globals() and g_debug):
        debug = True
    try:
        r = ida_auto.auto_wait()
        if r:
            cto = CallTreeOverviewer(ida_kernwin.get_screen_ea(), cto_data=cto_data, curr_view=curr_view, max_depth=max_depth, debug=debug)
        else:
            ida_kernwin.msg("IDA is still in automatic analysis and you have canceled the plugin execution. Do it later again if you need.%s" % (os.linesep))
    except Exception as e:
        exc_type, exc_obj, tb = sys.exc_info()
        lineno = tb.tb_lineno
        ida_kernwin.msg("Got a unexpected error (%s: %s) (%d)%s" % (str(type(e)), e, lineno, os.linesep))
        traceback.print_exc()
        
    return cto

def main():
    global g_cto
    g_cto = exec_cto()

if __name__ == '__main__':
    main()
