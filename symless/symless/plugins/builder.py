import os
from typing import Optional, Tuple, Union

import idaapi
from PyQt5 import QtCore, QtGui, QtWidgets

import symless
import symless.cpustate as cpustate
import symless.cpustate.arch as arch
import symless.generation.generate as generate
import symless.generation.structures as structures
import symless.model.model as model
import symless.utils.ida_utils as ida_utils
import symless.utils.utils as utils
from symless.plugins import *

# builder window title
WINDOW_TITLE = "Symless structure builder"


# Structure builder plugin extension
class BuilderPlugin(plugin_t):
    def __init__(self):
        self.uihook = PopUpHook()
        self.uihook.hook()

    def term(self):
        self.uihook.unhook()
        self.uihook.term()


# retrieve the extension
def get_plugin() -> plugin_t:
    return BuilderPlugin()


# base class for a tab in our plugin's UI
class BuilderTabBase(QtWidgets.QWidget):
    def __init__(self, label: str, window: "BuilderMainWid", parent: QtWidgets.QWidget = None):
        super().__init__(parent)
        self.window = window

        # build widget
        lmain = QtWidgets.QVBoxLayout()

        # window's hint
        whint = QtWidgets.QLabel(self)
        whint.setTextFormat(QtCore.Qt.TextFormat.RichText)
        whint.setText(label)
        whint.setAlignment(QtCore.Qt.AlignCenter)

        lmain.addWidget(whint)
        lmain.setAlignment(whint, QtCore.Qt.AlignTop)

        self.populate(lmain)

        lbottom = QtWidgets.QGridLayout()
        cancel_btn = QtWidgets.QPushButton("Cancel", self)
        cancel_btn.clicked.connect(self.window.reject)
        ok_btn = QtWidgets.QPushButton("Propagate", self)
        ok_btn.clicked.connect(self.execute)
        lbottom.addWidget(cancel_btn, 0, 0)
        lbottom.addWidget(ok_btn, 0, 1)

        lmain.addLayout(lbottom)
        lmain.setAlignment(lbottom, QtCore.Qt.AlignBottom)
        self.setLayout(lmain)

    # populate widget's components
    def populate(self, layout: QtWidgets.QLayout):
        pass

    # is the form filled correctly
    def completed(self) -> Tuple[bool, str]:
        return True, None

    # call after popup is built, used to give focus
    def give_focus(self):
        pass

    def execute(self):
        valid, err = self.completed()
        if valid:
            self.window.execute(self)
        else:
            idaapi.warning(err)

    def get_shift(self) -> int:
        raise Exception("Not implemented")

    def get_dive(self) -> bool:
        raise Exception("Not implemented")

    def get_struc(self) -> Union[int, str]:
        raise Exception("Not implemented")


# an item in a list, representing a structure
class StrucSelItem(QtWidgets.QListWidgetItem):
    def __init__(self, sid: int, display: str):
        super().__init__(display)
        self.sid = sid

    def get_struc(self) -> int:
        return self.sid


# structure selector
class StrucSelWid(QtWidgets.QListWidget):
    def __init__(self, parent: QtWidgets.QWidget = None):
        super().__init__(parent)

        idx = idaapi.get_first_struc_idx()
        while idx != idaapi.BADADDR:
            sid = idaapi.get_struc_by_idx(idx)
            self.addItem(StrucSelItem(sid, idaapi.get_struc_name(sid)))
            idx = idaapi.get_next_struc_idx(idx)
        self.sortItems()

    def sizeHint(self) -> QtCore.QSize:
        size = super().sizeHint()
        size.setHeight(384)
        return size


# UI for propagating a new structure
class BuilderNewTab(BuilderTabBase):
    def __init__(self, window: "BuilderMainWid", parent: QtWidgets.QWidget = None):
        super().__init__("<h2>Create a new structure</h2>", window, parent)

    def populate(self, layout: QtWidgets.QLayout):
        # central box
        wcenter = QtWidgets.QFrame(self)
        wcenter.setFrameStyle(QtWidgets.QFrame.Shape.Panel | QtWidgets.QFrame.Shadow.Raised)

        # structure's name selector
        self.selector = QtWidgets.QLineEdit(self)
        self.selector.setPlaceholderText("New structure's name..")

        # shift selector
        self.shift = QtWidgets.QLineEdit(self)
        int_valid = QtGui.QIntValidator(self)
        int_valid.setBottom(0)
        self.shift.setValidator(int_valid)
        self.shift.setText("0")
        self.shift.setMaxLength(5)
        self.shift.setAlignment(QtCore.Qt.AlignVCenter | QtCore.Qt.AlignRight)
        self.shift.setFixedWidth(64)
        lshift = QtWidgets.QLabel(self)
        lshift.setText("shifted by")
        lshift.setBuddy(self.shift)

        # deep dive checkbox
        self.chk = QtWidgets.QCheckBox("spread in callees", self)
        self.chk.setChecked(True)

        # layout
        lcenter = QtWidgets.QVBoxLayout()
        lbar = QtWidgets.QHBoxLayout()

        lbar.addWidget(lshift)
        lbar.setAlignment(lshift, QtCore.Qt.AlignRight)
        lbar.addWidget(self.shift)
        lbar.setAlignment(self.shift, QtCore.Qt.AlignLeft)
        lbar.addWidget(self.chk)

        lcenter.addWidget(self.selector)
        lcenter.addLayout(lbar)

        wcenter.setLayout(lcenter)
        layout.addWidget(wcenter)

        self.setWhatsThis(
            "Choose a name for your new structure, a shift to apply and specify if we should follow function calls."
        )

    def give_focus(self):
        self.selector.setFocus(QtCore.Qt.FocusReason.PopupFocusReason)

    def get_dive(self) -> bool:
        return self.chk.isChecked()

    def get_shift(self) -> int:
        try:
            return int(self.shift.text())
        except ValueError:
            return 0

    def get_struc(self) -> str:
        return self.selector.text()

    def completed(self) -> Tuple[bool, str]:
        name = self.selector.text()
        if len(name) == 0:
            return False, "Please provide a name for the new structure"

        sid = idaapi.get_struc_id(name)
        if sid != idaapi.BADADDR:
            return False, f'Structure "{name}" already exists'

        return True, None


# UI for propagating an existing structure
class BuilderExistingTab(BuilderTabBase):
    def __init__(self, window: "BuilderMainWid", parent: QtWidgets.QWidget = None):
        super().__init__("<h2>Select an existing structure</h2>", window, parent)

    def populate(self, layout: QtWidgets.QLayout):
        # structure selector
        self.selector = StrucSelWid(self)

        # structure selector search bar
        self.search_bar = QtWidgets.QLineEdit(self)
        self.search_bar.setPlaceholderText("Search for a structure..")
        self.search_bar.textChanged.connect(self.find_struc)

        # shift selector
        self.shift = QtWidgets.QLineEdit(self)
        int_valid = QtGui.QIntValidator(self)
        int_valid.setBottom(0)
        self.shift.setValidator(int_valid)
        self.shift.setText("0")
        self.shift.setMaxLength(5)
        self.shift.setAlignment(QtCore.Qt.AlignVCenter | QtCore.Qt.AlignRight)
        self.shift.setFixedWidth(64)
        lshift = QtWidgets.QLabel(self)
        lshift.setText("shifted by")
        lshift.setBuddy(self.shift)

        # deep dive checkbox
        self.chk = QtWidgets.QCheckBox("spread in callees", self)
        self.chk.setChecked(True)

        # layout
        lcenter = QtWidgets.QHBoxLayout()

        lcenter.addWidget(lshift)
        lcenter.setAlignment(lshift, QtCore.Qt.AlignRight)
        lcenter.addWidget(self.shift)
        lcenter.setAlignment(self.shift, QtCore.Qt.AlignLeft)
        lcenter.addWidget(self.chk)

        layout.addWidget(self.selector)
        layout.addWidget(self.search_bar)
        layout.addLayout(lcenter)

        self.setWhatsThis(
            "Select an existing structure to build & propagate.\nChoose an optional shift to apply and specify the need to follow function calls."
        )

    def give_focus(self):
        self.search_bar.setFocus(QtCore.Qt.FocusReason.PopupFocusReason)

    # filter structures list with given keyword
    def find_struc(self, key: str):
        lkey = key.lower()
        for i in range(self.selector.count()):
            current = self.selector.item(i)

            if lkey in current.text().lower():
                current.setHidden(False)
            else:
                current.setHidden(True)

    def get_dive(self) -> bool:
        return self.chk.isChecked()

    def get_shift(self) -> int:
        try:
            return int(self.shift.text())
        except ValueError:
            return 0

    def get_struc(self) -> int:
        selected: StrucSelItem = self.selector.currentItem()
        if selected is None:
            return idaapi.BADADDR
        return selected.get_struc()

    def completed(self) -> Tuple[bool, str]:
        selected = self.selector.currentItem()
        if selected is None:
            return False, "Please select a structure"
        return True, None


# plugin's main UI
class BuilderMainWid(QtWidgets.QDialog):
    def __init__(self, parent: QtWidgets.QWidget = None):
        super().__init__(parent)

        # properties to gather using this form
        self.dive: bool = False
        self.struc: Union[int, str] = idaapi.BADADDR
        self.shift: int = 0

        # tabs
        self.tabWidget = QtWidgets.QTabWidget(self)
        self.tabWidget.setMovable(False)
        self.tabWidget.setTabsClosable(False)

        f_tab = BuilderExistingTab(self, self.tabWidget)
        self.tabWidget.addTab(f_tab, "From existing")

        s_tab = BuilderNewTab(self, self.tabWidget)
        self.tabWidget.addTab(s_tab, "Build new")

        # main layout
        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.tabWidget)
        self.setLayout(layout)

        # window's properties
        self.setWindowTitle(WINDOW_TITLE)
        self.setWhatsThis("You may use this form to automatically rebuild structures using Symless")

        # window's icon
        icon = QtGui.QIcon(os.path.join(os.path.abspath(symless.__path__[0]), "resources", "champi.png"))
        self.setWindowIcon(icon)

        # set focused widget
        f_tab.give_focus()

    # execute form action
    def execute(self, form: BuilderTabBase):
        self.dive = form.get_dive()
        self.shift = form.get_shift()
        self.struc = form.get_struc()

        if self.shift < 0 or self.struc == idaapi.BADADDR:
            self.reject()

        self.accept()


# Hook to attach new action to popup menu
class PopUpHook(idaapi.UI_Hooks):
    def __init__(self):
        idaapi.UI_Hooks.__init__(self)

        icon_path = os.path.join(utils.get_resources_path(), "propag.png")
        self.icon = idaapi.load_custom_icon(icon_path)

        self.action = idaapi.action_desc_t(
            "symless:live",
            "Propagate structure",
            BuildHandler(),
            "Shift+t",
            "Automatic t-t-t",
            self.icon,
            idaapi.ADF_OWN_HANDLER,
        )
        idaapi.register_action(self.action)

    def term(self):
        idaapi.unregister_action(self.action.name)
        idaapi.free_custom_icon(self.icon)

    # right click menu popup
    def finish_populating_widget_popup(self, widget, popup, ctx):
        # window is DISASM & no selection
        if idaapi.get_widget_type(widget) != idaapi.BWN_DISASM or (ctx.cur_flags & idaapi.ACF_HAS_SELECTION) != 0:
            return

        current_ea = idaapi.get_screen_ea()
        current_op = idaapi.get_opnum()

        # install the action if target is a register or a call insn
        if operand_is_reg(current_ea, current_op) or insn_is_call(current_ea):
            idaapi.attach_action_to_popup(widget, popup, self.action.name)


# context menu structure builder action
class BuildHandler(idaapi.action_handler_t):
    def activate(self, ctx) -> int:
        current_ea = ctx.cur_ea
        reg_id, op, nb_ops = target_op_reg(current_ea, idaapi.get_opnum())

        # selection is a register as an instruction's operand
        if reg_id >= 0:
            dst_op = op.n == 0 and nb_ops != 1

        # selection is a call instruction
        elif insn_is_call(current_ea):
            reg_id = 0  # rax, return of malloc..
            dst_op = True

        # should not happen
        else:
            return 0

        # arch supported
        if not arch.is_arch_supported():
            utils.g_logger.error("Unsupported arch (%s) or filetype" % arch.get_proc_name())
            return 0

        # convert to full register
        if reg_id in ida_utils.X64_REG_ALIASES:
            reg_id = ida_utils.X64_REG_ALIASES[reg_id]

        # display plugin's UI
        reg = cpustate.reg_string(reg_id)
        form = BuilderMainWid()
        form.exec()

        # close if form cancel button was hit
        code = form.result()
        if code == QtWidgets.QDialog.Rejected:
            return 0

        # build existing structure
        propagate_structure(current_ea, reg, dst_op, form.struc, form.shift, form.dive)

        return 0

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


# propagate & build an existing structure
# from given ea an reg (register)
# for given struc (sid or name), shift and dive (should follow callees) option
# dst_op: is selected register a src or dst operand
def propagate_structure(ea: int, reg: str, dst_op: bool, struc: Union[int, str], shift: int, dive: bool):
    idaapi.show_wait_box("HIDECANCEL\nPropagating struct info..")

    try:
        # get containing function
        fct = idaapi.get_func(ea)

        # define entry for selected register
        entries = model.entry_record_t()
        entry_before = model.src_reg_entry_t(ea, fct.start_ea, reg)
        entry_before.struc_shift = shift  # set right shift on associated structure
        entries.add_entry(entry_before, True)

        # hack: if reg is on dst operand, create both inject_before and inject_after entries
        if dst_op:
            entry_after = model.dst_reg_entry_t(ea, fct.start_ea, reg)
            entry_after.struc_shift = shift
            entries.add_entry(entry_after, True, False)

        # build entrypoints graph
        ctx = model.context_t(entries, set())
        ctx.set_follow_calls(dive)
        model.analyze_entrypoints(ctx)

        # define structures
        strucs = structures.define_structures(ctx)

        # associate generated model with chosen structure
        _, struc_model = entry_before.get_structure()

        # struc is a structure id
        if isinstance(struc, int):
            struc_model.set_existing(struc)

        # struc is a structure name
        else:
            struc_model.set_name(struc)

        # import structures into IDA
        generate.import_structures(strucs)

        # type operands with structures
        generate.import_context(ctx)

    except Exception as e:
        import traceback

        utils.g_logger.critical(repr(e) + "\n" + traceback.format_exc())

    finally:
        idaapi.hide_wait_box()


# get the register at given adress & operand
# returns (reg id, operand, nb operands)
def target_op_reg(ea: int, op_num: int) -> Tuple[int, Optional[idaapi.op_t], int]:
    insn = idaapi.insn_t()
    insn_len = idaapi.decode_insn(insn, ea)
    nb_ops = ida_utils.get_len_insn_ops(insn)

    if insn_len == 0 or op_num < 0 or op_num >= nb_ops:
        return -1, None, 0

    op = insn.ops[op_num]
    if op.type == idaapi.o_reg:
        return op.reg, op, nb_ops

    if op.type in [idaapi.o_phrase, idaapi.o_displ]:
        return cpustate.x64_base_reg(insn, op), op, nb_ops

    return -1, None, 0


# is given operand a register
def operand_is_reg(ea: int, op_num: int) -> bool:
    reg_id, _, _ = target_op_reg(ea, op_num)
    return reg_id >= 0


# is given instruction a call
def insn_is_call(ea: int) -> bool:
    insn = idaapi.insn_t()
    idaapi.decode_insn(insn, ea)
    return insn.itype in cpustate.INSN_CALLS
