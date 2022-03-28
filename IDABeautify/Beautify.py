import idaapi
import ida_idp
import ida_hexrays
import idautils
import netnode
import ida_kernwin

DEBUG_MODE = True

def parse_reg(reg_name):
    reg_info = ida_idp.reg_info_t()
    if not ida_idp.parse_reg_name(reg_info, reg_name):
        print("Bad reg name:", reg_name)
        return None, None
    mreg = ida_hexrays.reg2mreg(reg_info.reg)
    if mreg == -1:
        print("Faild to covert %s to microregister", reg_name)
        return None, None
    return mreg, reg_info.size

def create_move(ea, mreg, size, value):
    m = ida_hexrays.minsn_t(ea)
    m.opcode = ida_hexrays.m_mov
    m.l.make_number(value, size, ea)
    m.d.make_reg(mreg, size)
    m.iprops |= ida_hexrays.IPROP_ASSERT
    return m

def refresh_pseudocode():
    w = ida_kernwin.get_current_widget()
    if ida_kernwin.get_widget_type(w) == ida_kernwin.BWN_PSEUDOCODE:
        vu = ida_hexrays.get_widget_vdui(w)
        vu.refresh_ctext()


class SpecifyRegValueManager(object):
    def __init__(self) -> None:
        self.isInitialized = False
        self.reg_val_list = {} # {ea: {reg_name: value}}

    def initialize(self):
        if not self.isInitialized:
            self.node = netnode.Netnode("Beautify.SpecifyRegValueManager")
            self.load_node()
            self.isInitialized = True

    def load_node(self):
        if "data" in self.node:
            self.reg_val_list = {}
            for key, item in self.node["data"].items():
                self.reg_val_list[int(key)] = item

    def store_node(self):
        self.node["data"] = self.reg_val_list

    def add(self, ea, reg_name, value):
        ea -= idaapi.get_imagebase()
        if ea not in self.reg_val_list:
            self.reg_val_list[ea] = {}
        self.reg_val_list[ea][reg_name] = value
        self.store_node()
    
    def remove(self, ea, reg_name):
        ea -= idaapi.get_imagebase()
        if ea not in self.reg_val_list:
            return
        if reg_name not in self.reg_val_list[ea]:
            return
        del(self.reg_val_list[ea][reg_name])

        if len(self.reg_val_list[ea].keys()) == 0:
            del(self.reg_val_list[ea])
        self.store_node()
    
    def get_reg_list(self, ea):
        ea -= idaapi.get_imagebase()
        if ea not in self.reg_val_list:
            return None
        return self.reg_val_list[ea]

    def show_list(self):
        print("================= specify reg value list =================")
        for ea, item in self.reg_val_list.items():
            print("ea: %x" % (ea + idaapi.get_imagebase()))
            for reg_name, value in item.items():
                print("\t%s = %x" % (reg_name, value))
            print("")
        print("==========================================================")

class RemoverAddressManager(object):
    def __init__(self) -> None:
        self.isInitialized = False

    def initialize(self):
        if not self.isInitialized:
            self.node = netnode.Netnode("Beautify.RemoverAddressManager")
            self.load_netnode()
            self.isInitialized = True

    def load_netnode(self):
        if "data" in self.node:
            self.remove_list = self.node["data"]
        else:
            self.remove_list = []
    
    def store_netnode(self):
        self.node["data"] = self.remove_list

    def add(self, addr):
        addr -= idaapi.get_imagebase()
        if addr not in self.remove_list:
            self.remove_list.append(addr)
            self.store_netnode()
        
    def remove(self, addr):
        addr -= idaapi.get_imagebase()
        if addr in self.remove_list:
            self.remove_list.remove(addr)
            self.store_netnode()

    def check(self, addr):
        addr -= idaapi.get_imagebase()
        return addr in self.remove_list

remover_address_manager = RemoverAddressManager()
specify_manager = SpecifyRegValueManager()


class InsnVisitor(ida_hexrays.minsn_visitor_t):
    def __init__(self, *args):
        super().__init__(*args)
    def visit_minsn(self, *args) -> "int":
        insn_addr = self.topins.ea
        if remover_address_manager.check(insn_addr):
            self.blk.make_nop(self.topins)
        specify = specify_manager.get_reg_list(insn_addr)
        if specify != None and len(specify) > 0:
            for reg_name, value in specify.items():
                mreg, size = parse_reg(reg_name)
                if mreg != None:
                    m = create_move(insn_addr, mreg, size, value)
                    self.blk.insert_into_block(m, self.curins.prev)
        return 0 # continue


class MicrocodeCallback(ida_hexrays.Hexrays_Hooks):
    def __init__(self, *args):
        super().__init__(*args)

    def microcode(self, mba: ida_hexrays.mba_t) -> "int":
        # must in function.
        func = mba.get_curfunc()
        if func == None:
            print("not in function")
            return 0
        mba.for_all_topinsns(InsnVisitor())
        return 0


####################### menu ##########################################
# from: https://github.com/igogo-x86/HexRaysPyTools
class ActionManager(object):
    def __init__(self):
        self.__actions = []

    def register(self, action):
        self.__actions.append(action)
        idaapi.register_action(
                idaapi.action_desc_t(action.name, action.description, action, action.hotkey)
            )


    def initialize(self):
        pass

    def finalize(self):
        for action in self.__actions:
            idaapi.unregister_action(action.name)

action_manager = ActionManager()

class Action(idaapi.action_handler_t):
    """
    Convenience wrapper with name property allowing to be registered in IDA using ActionManager
    """
    description = None
    hotkey = None

    def __init__(self):
        super(Action, self).__init__()

    @property
    def name(self):
        return "Beautify:" + type(self).__name__

    def activate(self, ctx):
        # type: (idaapi.action_activation_ctx_t) -> None
        raise NotImplementedError

    def update(self, ctx):
        # type: (idaapi.action_activation_ctx_t) -> None
        raise NotImplementedError

############################################################################


class BeautifyHideMenuAction(Action):
    TopDescription = "Beautify"
    description = "Hide All References"
    def __init__(self):
        super(BeautifyHideMenuAction, self).__init__()

    def activate(self, ctx) -> None:
        target = ctx.cur_extracted_ea
        print("active target:", hex(target))
        for xref in idautils.XrefsTo(target):
            if xref.frm != target:
                remover_address_manager.add(xref.frm)
        refresh_pseudocode()
    
    def update(self, ctx) -> None:
        if ctx.widget_type in [idaapi.BWN_PSEUDOCODE, idaapi.BWN_DISASM]:
            idaapi.attach_action_to_popup(ctx.widget, None, self.name, self.TopDescription + "/")
            return idaapi.AST_ENABLE_FOR_WIDGET
        return idaapi.AST_DISABLE_FOR_WIDGET

class BeautifyShowMenuAction(Action):
    TopDescription = "Beautify"
    description = "Show All References"
    def __init__(self):
        super(BeautifyShowMenuAction, self).__init__()

    def activate(self, ctx) -> None:
        target = ctx.cur_extracted_ea
        print("active target:", hex(target))
        for xref in idautils.XrefsTo(target):
            if xref.frm != target:
                remover_address_manager.remove(xref.frm)
        refresh_pseudocode()
    
    def update(self, ctx) -> None:
        if ctx.form_type in [idaapi.BWN_PSEUDOCODE, idaapi.BWN_DISASM]:
            idaapi.attach_action_to_popup(ctx.widget, None, self.name, self.TopDescription + "/")
            return idaapi.AST_ENABLE_FOR_WIDGET
        return idaapi.AST_DISABLE_FOR_WIDGET



class SpecifyMenuAction(Action):
    TopDescription = "Beautify"
    description = "Specify Value"
    def __init__(self):
        super(SpecifyMenuAction, self).__init__()

    def activate(self, ctx) -> None:
        ea = ctx.cur_ea
        highlight = idaapi.get_highlight(idaapi.get_current_viewer())
        if highlight != None:
            reg_name = highlight[0]
            mreg, size = parse_reg(reg_name)
            if mreg != None:
                reg_list = specify_manager.get_reg_list(ea)
                value = 0
                if reg_list != None and reg_name in reg_list:
                    value = reg_list[reg_name]
                ask_form = "Input value for register:%s"
                value = idaapi.ask_long(value, ask_form % reg_name)
                if value != None:
                    specify_manager.add(ea, reg_name, value)
                    refresh_pseudocode()

    def update(self, ctx) -> None:
        if ctx.form_type in [idaapi.BWN_DISASM]:
            idaapi.attach_action_to_popup(ctx.widget, None, self.name, self.TopDescription + "/")
            return idaapi.AST_ENABLE_FOR_WIDGET
        return idaapi.AST_DISABLE_FOR_WIDGET


class UnSpecifyMenuAction(Action):
    TopDescription = "Beautify"
    description = "Unspecify Value"
    def __init__(self):
        super(UnSpecifyMenuAction, self).__init__()

    def activate(self, ctx) -> None:
        ea = ctx.cur_ea
        highlight = idaapi.get_highlight(idaapi.get_current_viewer())
        if highlight != None:
            reg_name = highlight[0]
            mreg, size = parse_reg(reg_name)
            if mreg != None:
                specify_manager.remove(ea, reg_name)
                refresh_pseudocode()

    def update(self, ctx) -> None:
        if ctx.form_type in [idaapi.BWN_DISASM]:
            idaapi.attach_action_to_popup(ctx.widget, None, self.name, self.TopDescription + "/")
            return idaapi.AST_ENABLE_FOR_WIDGET
        return idaapi.AST_DISABLE_FOR_WIDGET

class ShowMenuAction(Action):
    TopDescription = "Beautify"
    description = "Show Specified Reg List"
    def __init__(self):
        super(ShowMenuAction, self).__init__()

    def activate(self, ctx) -> None:
        specify_manager.show_list()

    def update(self, ctx) -> None:
        if ctx.form_type in [idaapi.BWN_DISASM]:
            idaapi.attach_action_to_popup(ctx.widget, None, self.name, self.TopDescription + "/")
            return idaapi.AST_ENABLE_FOR_WIDGET
        return idaapi.AST_DISABLE_FOR_WIDGET

action_manager.register(BeautifyHideMenuAction())
action_manager.register(BeautifyShowMenuAction())
action_manager.register(SpecifyMenuAction())
action_manager.register(UnSpecifyMenuAction())
action_manager.register(ShowMenuAction())

if ida_hexrays.init_hexrays_plugin():
    remover_address_manager.initialize()
    specify_manager.initialize()

    r = MicrocodeCallback()
    r.hook()

# r.unhook()
# action_manager.finalize()
