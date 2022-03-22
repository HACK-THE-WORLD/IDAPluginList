import ida_idaapi
import ida_kernwin
import ida_funcs

import os
import sys
import codecs

dirpath = os.path.dirname(os.path.abspath(__file__))
cto_dir = os.path.join(dirpath, "cto")
if cto_dir not in sys.path:
    sys.path.append(cto_dir)

ida_idaapi.require("cto_base")
ida_idaapi.require("cto_func_lister")
ida_idaapi.require("icon")
ida_idaapi.require("syncdata")
ida_idaapi.require("qtutils")

class cto_func_lister_plugin_t(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP
    comment = "CTO Function Lister"
    toolbar_displayed_name = cto_base.cto_base.orig_title
    toolbar_name = toolbar_displayed_name + 'Toolbar'
    wanted_name = comment
    wanted_hotkey = "Alt-Shift-F"
    help = "Press '" + wanted_hotkey + "' to display the " + comment + " widget."
    
    action_name = "cto_func_lister:execute"
    menu_path = "Edit/Plugins/"
    icon = icon.icon_handler(icon.g_icon_data_ascii, True)
    icon_data = icon.icon_data
    icon_data_dark = icon.icon_bg_change(icon_data, True, True)
    if icon_data_dark is None:
        icon_data_dark = icon_data
    act_icon = ida_kernwin.load_custom_icon(data=icon_data, format="png")
    act_icon_dark = ida_kernwin.load_custom_icon(data=icon_data_dark, format="png")
    
    class exec_from_toolbar(ida_kernwin.action_handler_t):
        action_name = "cto_func_lister:execute_toolbar"
        def __init__(self, plugin):
            ida_kernwin.action_handler_t.__init__(self)
            import weakref
            self.v = weakref.ref(plugin)
        
        def activate(self, ctx):
            self.v().exec_cto_func_lister()
            
        def update(self, ctx):
            return ida_kernwin.AST_ENABLE_ALWAYS
    
    def init(self):
        ida_kernwin.msg("############### %s (%s) ###############%s" % (self.wanted_name, self.comment, os.linesep))
        ida_kernwin.msg("%s%s" % (self.help, os.linesep))

        # attach to menu
        self.g = None
        ida_kernwin.attach_action_to_menu(
            self.menu_path,
            self.action_name,
            ida_kernwin.SETMENU_APP)

        # attach to toolbar
        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
            cto_func_lister_plugin_t.exec_from_toolbar.action_name,
            cto_func_lister_plugin_t.comment,
            cto_func_lister_plugin_t.exec_from_toolbar(self),
            None,
            self.wanted_name,
            self.act_icon))
        
        # Insert the action in a toolbar
        ida_kernwin.create_toolbar(self.toolbar_name, self.toolbar_displayed_name)
        ida_kernwin.attach_action_to_toolbar(self.toolbar_name, cto_func_lister_plugin_t.exec_from_toolbar.action_name)
        
        # install ui hook to enable toolbar later
        self.ph = qtutils.enable_toolbar_t(self.toolbar_name)
        
        # Check if IDA is darkmode or not.
        # It might fail if the mode is darcula or similar themes
        # because the window color is the same as the default theme color.
        # However, it can still distinguish the default and the dark mode.
        if cto_base.cto_base.is_dark_mode_with_main():
            ida_kernwin.update_action_icon(cto_func_lister_plugin_t.exec_from_toolbar.action_name, self.act_icon_dark)
            ida_kernwin.update_action_icon(self.menu_path + self.wanted_name, self.act_icon_dark)
            
        return self.flags

    def exec_cto_func_lister(self):
        global g_cto_func_lister

        # for degub mode handling
        debug = False
        if "g_debug" in globals() and g_debug:
            debug = True
        elif hasattr(sys.modules["__main__"], "g_debug") and sys.modules["__main__"].g_debug:
            debug = True

        # for the first message when this plugin is launched by a user by pressing shortcut key or going to menu.
        if 'g_cto_func_lister' not in globals():
            ida_kernwin.msg("Launching %s (%s) ...%s" % (self.wanted_name, self.comment, os.linesep))
            ida_kernwin.msg("For the first execution, %s will analyze all functions to build the call tree. Please wait for a while.%s" % (self.wanted_name, os.linesep))
        else:
            ida_kernwin.msg("Reloading %s.%s" % (self.wanted_name, os.linesep))
            
        if self.g:
            # save several important data with pickle and closing hooks...
            self.g.Close(0)
        
        # reload the main modules
        ida_idaapi.require("cto_func_lister")

        # get sync data on a global variable
        sd = syncdata.sync_data()
        sync_data = sd.get()
        # execute the main function
        self.g = cto_func_lister.exec_cto_function_lister(cto_data=sync_data, debug=debug)
        self.g.__dict__["sd"] = sd
        if sync_data is None:
            self.g.sd.set(self.g.cto_data)
            
        # update icon on menu
        act_icon_id = self.act_icon
        # update icon on menu
        act_icon_id = self.act_icon
        if self.g and self.g.config.dark_mode:
            act_icon_id = self.act_icon_dark
        ida_kernwin.update_action_icon(cto_func_lister_plugin_t.exec_from_toolbar.action_name, act_icon_id)
        ida_kernwin.update_action_icon(self.menu_path + self.wanted_name, act_icon_id)
        
        # install ui hook to enable toolbar later
        self.ph = qtutils.enable_toolbar_t(self.toolbar_name)
        
        # show the messages after launching
        if 'g_cto_func_lister' not in globals():
            ida_kernwin.msg("Launched %s.%s" % (self.wanted_name, os.linesep))
        else:
            ida_kernwin.msg("Reloaded %s.%s" % (self.wanted_name, os.linesep))
            
        # put the instance in the global variables
        g_cto_func_lister = self.g
        if not hasattr(sys.modules["__main__"], "g_cto_func_lister"):
            setattr(sys.modules["__main__"], "g_cto_func_lister", self.g)
        else:
            sys.modules["__main__"].g_cto_func_lister = self.g
            
    def run(self, arg):
        self.exec_cto_func_lister()
        
    def term(self):
        if self.g:
            self.g.Close(0)
        if hasattr(self.g, "sd"):
            self.g.sd.close()
            
        ida_kernwin.free_custom_icon(self.act_icon)
        ida_kernwin.detach_action_from_menu(self.menu_path, self.action_name)
        
        ida_kernwin.detach_action_from_toolbar(self.wanted_name, cto_func_lister_plugin_t.exec_from_toolbar.action_name)
        ida_kernwin.delete_toolbar(self.wanted_name)
        
        if hasattr(sys.modules["__main__"], "g_cto_func_lister"):
            delattr(sys.modules["__main__"], "g_cto_func_lister")

def PLUGIN_ENTRY():
    return cto_func_lister_plugin_t()

def main():
    global g_cto_func_lister
    g_cto_func_lister = cto_func_lister.exec_cto_function_lister()

if __name__ == '__main__':
    main()
