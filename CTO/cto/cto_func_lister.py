import ida_kernwin
import ida_nalt
import ida_lines
import ida_funcs
import ida_idaapi
import ida_name
import ida_entry
import ida_bytes
import ida_ua
import idc
import idautils
import ida_auto

from PyQt5 import QtGui, QtCore, QtWidgets
import sip

#from modeltest import ModelTest

import os
import json
import time

import cto_base
import syncui
import qtutils
import cto_utils
import icon
#import cto
import get_func_relation
ida_idaapi.require("cto_base")
ida_idaapi.require("syncui")
ida_idaapi.require("qtutils")
ida_idaapi.require("cto_utils")
ida_idaapi.require("icon")
#ida_idaapi.require("cto")
ida_idaapi.require("get_func_relation")

if not hasattr(ida_kernwin, "WOPN_NOT_CLOSED_BY_ESC"):
    setattr(ida_kernwin, "WOPN_NOT_CLOSED_BY_ESC", 0x100) # 7.5 lacks the definition

FT_UNK = get_func_relation.FT_UNK
FT_GEN = get_func_relation.FT_GEN
FT_LIB = get_func_relation.FT_LIB
FT_API = get_func_relation.FT_API
FT_MEM = get_func_relation.FT_MEM
FT_VAR = get_func_relation.FT_VAR
FT_STR = get_func_relation.FT_STR
FT_STO = get_func_relation.FT_STO
FT_VTB = get_func_relation.FT_VTB

class MyFilterProxyModel(QtCore.QSortFilterProxyModel):
    itemDataChanged = QtCore.pyqtSignal(QtCore.QModelIndex, str, str, int)
    
    def __init__(self, parent=None):
        super(MyFilterProxyModel, self).__init__(parent)
        self.idx_set = set([])
        self.disabled_keyword_set = set([])
        
        try:
            # the option is available only 5.10 and above
            self.setRecursiveFiltering(True)
        except AttributeError:
            #self.__index__ = self.___index__
            self.filterAcceptsRow = self._filterAcceptsRow
            
    # for observing renaming events
    def setData(self, index, value, role=QtCore.Qt.EditRole):
        oldvalue = index.data(role)
        result = super(MyFilterProxyModel, self).setData(index, value, role)
        if result and value != oldvalue:
            self.itemDataChanged.emit(index, oldvalue, value, role)
        return result
    
    # for sorting by integer
    def lessThan(self, left, right):
        leftData = self.sourceModel().data(left)
        rightData = self.sourceModel().data(right)
        try:
            return int(leftData) < int(rightData)
        except TypeError:
            return False
        except ValueError:
            return leftData < rightData
        
    # for incremental filtering
    def _filterAcceptsRow(self, row, parent):
        res = super(MyFilterProxyModel, self).filterAcceptsRow(row, parent)
        idx = self.sourceModel().index(row, 0, parent)
        
        # for getting all the child nodes after matching a parent
        if parent in self.idx_set:
            res = True
        
        if idx is not None and idx.isValid():
            #item = self.sourceModel().itemFromIndex(idx)
            # for keyword limitation
            #if item.text() in self.disabled_keyword_set:
            if self.sourceModel().data(idx) in self.disabled_keyword_set:
                return False
        
        if res and idx.isValid():
            self.idx_set.add(idx)
            
        # find child nodes recursively
        if idx.isValid() and self.sourceModel().hasChildren(idx):
            num_items = self.sourceModel().rowCount(idx)
            for i in range(num_items):
                res = res or self.filterAcceptsRow(i, idx)
            
        return res

class limit_keywords_dialog(QtWidgets.QDialog):
    state_changed = QtCore.pyqtSignal(str)
    def __init__(self, parent=None):
        super().__init__()
        self.setAttribute(QtCore.Qt.WA_DeleteOnClose)
        self.setWindowFlags(QtCore.Qt.FramelessWindowHint | QtCore.Qt.WindowStaysOnTopHint)
        self.v = QtWidgets.QVBoxLayout()
        self.setLayout(self.v)
        self.key_cboxes = {}
        
    @QtCore.pyqtSlot(dict)
    def init_data_and_show(self, keywords):
        self.keywords = keywords
        for k in keywords:
            if k not in self.key_cboxes:
                self.key_cboxes[k] = QtWidgets.QCheckBox(k)
                self.v.addWidget(self.key_cboxes[k])
            if keywords[k]:
                self.key_cboxes[k].setCheckState(QtCore.Qt.Checked)
            else:
                self.key_cboxes[k].setCheckState(QtCore.Qt.Unchecked)
        pos = QtGui.QCursor.pos()
        self.move(pos)
        self.show()
        
    def leaveEvent(self, event):
        if self.isVisible():
            self.hide()
        for k in self.keywords:
            if k in self.keywords:
                if self.key_cboxes[k].isChecked():
                    self.keywords[k] = True
                else:
                    self.keywords[k] = False
        self.state_changed.emit("")
    
class MyWidget(QtWidgets.QTreeView):
    key_pressed = QtCore.pyqtSignal(QtGui.QKeyEvent)
    current_changed = QtCore.pyqtSignal(QtCore.QModelIndex, QtCore.QModelIndex)
    state_changed = QtCore.pyqtSignal(str)
    after_filtered = QtCore.pyqtSignal(str)
    item_changed = QtCore.pyqtSignal(QtCore.QModelIndex, str, str)
    builtin_exec = QtCore.pyqtSignal(str)
    
    def __init__(self):
        #super(MyWidget, self).__init__(self)
        QtWidgets.QTreeView.__init__(self)
        
        self.keywords = {}
        self.h = limit_keywords_dialog()
        self.timer = QtCore.QTimer()
        self.wait_msec = 300

        self.qt_ver = qtutils.get_qver()
        
        self.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        
        # sort setting
        self.setSortingEnabled(False)
        #self.setSortingEnabled(True)
        #self.sortByColumn(1, QtCore.Qt.AscendingOrder)

        # generate source model
        self.model = QtGui.QStandardItemModel()
        #self.modeltest = ModelTest(self.model, self)
        self.model.setHorizontalHeaderLabels(['Name','Address', 'CRefs', 'BBs'])
        
        # set proxy model for filter
        if (self.qt_ver[0] >= 5 and self.qt_ver[1] >= 10) or self.qt_ver >= 6:
            self.proxy_model = QtCore.QSortFilterProxyModel()
            # the option is available only 5.10 and above
            self.proxy_model.setRecursiveFilteringEnabled(True)
        else:
            self.proxy_model = MyFilterProxyModel()
        # cange the filter method according to the version
        if (self.qt_ver[0] >= 5 and self.qt_ver[1] >= 12) or self.qt_ver >= 6:
            self.filterChanged = self._filterChanged_512
        else:
            self.filterChanged = self._filterChanged
        
        # check all columns
        self.proxy_model.setFilterKeyColumn(-1)

        # connect tree view with source item model through proxy model
        self.setModel(self.proxy_model)
        self.proxy_model.setSourceModel(self.model)
        if self.qt_ver[0] == 5 and self.qt_ver[1] < 12:
            self.proxy_model.itemDataChanged.connect(self.handleItemDataChanged)
        
        # set selection model for synchronizing with ida
        self.sel_model = QtCore.QItemSelectionModel(self.proxy_model)
        self.setSelectionModel(self.sel_model)
        
        # --------------------------------------
        # Create line edit widget for filter
        self.filter = QtWidgets.QLineEdit()
        self.filter.setToolTip('You can filter with this bar by inputting a keyword with regex and case sensitive options.')
        # --------------------------------------
        
        # Create check boxes
        self.regex_box = QtWidgets.QCheckBox("RegEx")
        self.regex_box.setToolTip('Enable/disable using regex pattern')
        self.cs_box = QtWidgets.QCheckBox("CS")
        self.cs_box.setToolTip('Enable/disable case sensitive option')
        self.clear_btn = QtWidgets.QPushButton("X")
        self.clear_btn.setContentsMargins(0,0,0,0)
        self.clear_btn.setFixedWidth(25)
        self.clear_btn.setToolTip('Clear filter conditions')
        self.menu_btn = QtWidgets.QPushButton("")
        self.menu_btn.setContentsMargins(0,0,0,0)
        self.menu_btn.setFixedWidth(20)
        self.menu_btn.setToolTip('Other actions and filter presets')
        
        # Create menu
        self.filter_menu = QtWidgets.QMenu("")
        self.filter_menu.addAction("Expand all", self.expandAll)
        self.filter_menu.addAction("Collpapse all", self.collapseAll)
        self.filter_menu.addAction("Limit keywords", lambda a=self.keywords: self.h.init_data_and_show(a))
        preset_filter = self.filter_menu.addMenu("Preset filters")
        builtin_scripts = self.filter_menu.addMenu("Built-in scripts")
        
        # load preset filters
        preset_rule_file = os.path.join(os.path.dirname(__file__),"lister_filter.json")
        with open(preset_rule_file) as f:
            self.preset_rules = json.load(f)
        
        # add preset filters to menu
        for r in self.preset_rules:
            rule = self.preset_rules[r]["rule"]
            regex_flag = self.preset_rules[r]["regex"]
            cs_flag = self.preset_rules[r]["cs"]
            keywords = self.preset_rules[r]["keywords"]
            # I need a lambda here to pass the arguments to the action, although default arguments of lambda are not recommended.
            preset_filter.addAction(r, lambda a=rule, b=regex_flag, c=cs_flag, d=keywords: self.set_filter_rule(a,b,c,d))
            
        # add built-in command
        builtin_scripts.addAction("Find xor instructions in a loop", lambda a="xorloop": self.builtin_exec_submitter(a))
        builtin_scripts.addAction("Find notable mnemonics", lambda a="mnem": self.builtin_exec_submitter(a))
        builtin_scripts.addAction("Find notable instructions", lambda a="inst": self.builtin_exec_submitter(a))
        builtin_scripts.addAction("Find notable constants", lambda a="const": self.builtin_exec_submitter(a))
        builtin_scripts.addAction("Update cache", lambda a="cache": self.builtin_exec_submitter(a))
        builtin_scripts.addAction("Update cache partially", lambda a="partial": self.builtin_exec_submitter(a))
        builtin_scripts.addAction("Update cache for comments", lambda a="comments": self.builtin_exec_submitter(a))
        builtin_scripts.addAction("Show help", lambda a="help": self.builtin_exec_submitter(a))
        
        # set the menu button to the filter menu
        self.menu_btn.setMenu(self.filter_menu)
        
        # Create parent widget
        self.pfilter = QtWidgets.QWidget()
        filter_layout = QtWidgets.QHBoxLayout(self.pfilter)
        filter_layout.setContentsMargins(0,0,0,0)
        clear_btn_layout = QtWidgets.QHBoxLayout()
        clear_btn_layout.setContentsMargins(0,0,0,0)
        clear_btn_layout.setSpacing(0)
        filter_layout.addLayout(clear_btn_layout)
        filter_layout.addWidget(self.filter)
        filter_layout.addWidget(self.regex_box)
        filter_layout.addWidget(self.cs_box)
        
        clear_btn_layout.addWidget(self.clear_btn)
        clear_btn_layout.addWidget(self.menu_btn)
        
        # hook events of itself and filter box
        self.pfilter.installEventFilter(self)
        for c in self.pfilter.children():
            if c.isWidgetType():
                c.installEventFilter(self)
        self.installEventFilter(self)
        
        # set hooks for incremental search, regex and case sensitive check box state changed
        self.filter.textChanged.connect(self.setTimer)
        #self.filter.textChanged.connect(self.filterChanged)
        self.regex_box.stateChanged.connect(self.regexBoxChangedAction)
        self.cs_box.stateChanged.connect(self.csBoxChangedAction)
        self.state_changed.connect(self.filterChanged)
        self.clear_btn.pressed.connect(self.clear_filter)
        self.h.state_changed.connect(self.change_disabled_keywords)
        
    # ida clears default button size when the color theme is changed into dark mode.
    #Is it a bug? I don't know why. To avoid that, call this when dark mode is enabled.
    def reset_btn_size(self):
        self.clear_btn.setContentsMargins(0,0,0,0)
        self.clear_btn.setFixedWidth(25)
        self.menu_btn.setContentsMargins(0,0,0,0)
        self.menu_btn.setFixedWidth(20)

    def builtin_exec_submitter(self, script_name):
        self.builtin_exec.emit(script_name)
        
    # action for filter preset
    @QtCore.pyqtSlot(str, bool, bool, list)
    def set_filter_rule(self, rule, regex, cs, keywords):
        if regex:
            self.regex_box.setCheckState(QtCore.Qt.Checked)
        else:
            self.regex_box.setCheckState(QtCore.Qt.Unchecked)
            
        if cs:
            self.cs_box.setCheckState(QtCore.Qt.Checked)
        else:
            self.cs_box.setCheckState(QtCore.Qt.Unchecked)
            
        for k in self.keywords:
            if len(keywords) > 0:
                if k in keywords:
                    self.keywords[k] = True
                else:
                    self.keywords[k] = False
            else:
                self.keywords[k] = True
        self.set_disabled_keywords()
        
        self.filterChanged(rule)
        self.filter.textChanged.disconnect()
        self.filter.setText(rule)
        self.filter.textChanged.connect(self.setTimer)
        self.expandAll()
        
    def clear_text_and_hide_bar(self):
        self.pfilter.hide()
        self.clear_filter()
        self.setFocus()
        
    def clear_filter(self):
        self.cs_box.setCheckState(QtCore.Qt.Unchecked)
        self.proxy_model.setFilterCaseSensitivity(QtCore.Qt.CaseInsensitive)
        self.regex_box.setCheckState(QtCore.Qt.Unchecked)
        self.proxy_model.disabled_keyword_set = set([])
        self.reset_keywords()
        self.filterChanged("")
        self.filter.textChanged.disconnect()
        self.filter.setText("")
        self.filter.textChanged.connect(self.setTimer)
        self.setFocus()
        
    def change_disabled_keywords(self):
        self.set_disabled_keywords()
        text = self.filter.text()
        if text:
            self.state_changed.emit(text)
        
    def set_disabled_keywords(self):
        self.proxy_model.disabled_keyword_set = set([])
        for k in self.keywords:
            if not self.keywords[k]:
                self.proxy_model.disabled_keyword_set.add(k)
        
    def reset_keywords(self):
        self.proxy_model.disabled_keyword_set = set([])
        for k in self.keywords:
            self.keywords[k] = True
        
    def currentChanged(self, current, previous):
        QtWidgets.QTreeView.currentChanged(self, current, previous)
        self.current_changed.emit(current, previous)
        #print(current, previous)
        
    def handleItemDataChanged(self, idx, old_val, new_val, role):
        if role == QtCore.Qt.EditRole:
            if idx is not None and idx.isValid():
                #self.dbg_print(idx.model())
                if idx.model() == self.proxy_model:
                    idx = self.proxy_model.mapToSource(idx)
            #if idx is not None and idx.isValid(): self.dbg_print(idx.model())
            if idx is not None and idx.isValid():
                # send the single to the parent widget
                self.item_changed.emit(idx, old_val, new_val)
            
    def eventFilter(self, src, event):
        flag = False
        if event.type() == QtCore.QEvent.KeyPress:
            flag = self.on_key_pressed(src, event)
        return flag
        
    def on_key_pressed(self, src, key_event):
        #QtCore.Qt.CTRL | QtCore.Qt.ALT | QtCore.Qt.SHIFT
        #print('key pressed: %i, %i' % (key_event.key(), key_event.modifiers()))
        
        flag = True
        key = key_event.key()
        state = int(key_event.modifiers())
        c = chr(key & 0xff)
        
        # if a user editing an item like renaming a function, do nothing.
        if self.state() == QtWidgets.QAbstractItemView.EditingState:
            return False
        # show/hide filter box for all widgets
        elif c == 'F' and state == QtCore.Qt.CTRL:
            self.pfilter.setVisible(not self.pfilter.isVisible())
            if self.pfilter.isVisible():
                self.filter.setFocus()
            else:
                self.setFocus()
        # handling arrow keys for the widget
        elif key in [QtCore.Qt.Key_Left, QtCore.Qt.Key_Up, QtCore.Qt.Key_Right, QtCore.Qt.Key_Down]:
            return False
        # ESC for hiding filter box
        elif src != self and key == QtCore.Qt.Key_Escape:
            self.clear_filter()
        # for the filter and check box widgets, disable to pass the input to the tree,
        # instead pass it to the filter box 
        elif src != self:
            flag = False
        # for the tree widget, call key press event handler for the tree
        else:
            # send the event to the parent plugin form
            self.key_pressed.emit(key_event)
        return flag
        
    def regexBoxChangedAction(self, state):
        self.use_regex = self.regex_box.isChecked()
        text = self.filter.text()
        if text:
            self.state_changed.emit(text)
    
    def csBoxChangedAction(self, state):
        self.use_cs = self.cs_box.isChecked()
        text = self.filter.text()
        if text:
            self.state_changed.emit(text)
            
    # for cancelling filter changed events to avoid applying filter every time
    def setTimer(self, text):
        # stop the timer and disconnect the timeout connections
        if self.timer.isActive():
            self.timer.stop()
        try:
            self.timer.timeout.disconnect()
        except TypeError:
            pass
        self.timer.timeout.connect(lambda a=text: self.filterChanged(a))
        self.timer.setSingleShot(True)
        self.timer.start(self.wait_msec)
        
    # this will be overwritten in the constructor when a class instance is created.
    def filterChanged(self, text):
        self._filterChanged(text)
        
    # setFilterRegularExpression is only supported since >= 5.12.
    # That's why I use QRegExp above instead of using QRegularExpression.
    # Unoforgunately, I cannot use full PCRE featrure such as negative
    # lookbehind ((?<!s)t) because of the version and the API in that case.
    # https://www.regular-expressions.info/refadv.html
    # https://www.debuggex.com/
    # https://www.regexpal.com/
    def _filterChanged(self, text):
        #print("Filter triggered. (%s)" % text)
        
        # if many tree items are expanded, it will take a long time. So Collapes them first.
        self.collapseAll()
        
        self.sel_model.clearCurrentIndex()
        self.proxy_model.idx_set = set([])
        
        cs = QtCore.Qt.CaseInsensitive
        if self.cs_box.isChecked():
            cs = QtCore.Qt.CaseSensitive
            
        regex = QtCore.QRegExp.FixedString
        if self.regex_box.isChecked():
            regex = QtCore.QRegExp.RegExp2
            
        regExp = QtCore.QRegExp(
            text,
            cs,
            regex
        )
        if regExp.isValid():
            self.proxy_model.setFilterRegExp(regExp)
        
        self.after_filtered.emit(text)
        
    def _filterChanged_512(self, text):
        #print("Filter triggered. (%s)" % text)
        
        # if many tree items are expanded, it will take a long time. So Collapes them first.
        self.collapseAll()
        
        self.sel_model.clearCurrentIndex()
        self.proxy_model.idx_set = set([])
        
        cs = QtCore.Qt.CaseInsensitive
        if self.cs_box.isChecked():
            cs = QtCore.Qt.CaseSensitive
            
        if self.regex_box.isChecked():
            cs = QtCore.QRegularExpression.CaseInsensitiveOption
            if self.cs_box.isChecked():
                cs = QtCore.QRegularExpression.NoPatternOption
            re = QtCore.QRegularExpression(text, cs)
            if re.isValid():
                self.proxy_model.setFilterRegularExpression(re)
        else:
            self.proxy_model.setFilterCaseSensitivity(cs)
            self.proxy_model.setFilterFixedString(text)
        
        self.after_filtered.emit(text)
        
class cto_func_lister_t(cto_base.cto_base, ida_kernwin.PluginForm):
    imports = {}
    imports_ids = {}
    exports = {}
    exports_ids = {}
    funcs = {}
    func_ids = {}
    callers = {}
    caller_ids = {}
    default_bg = None
    selected_bg = None
    title = "CTO Function Lister"
    
    def __init__(self, cto_data=None, curr_view=None, debug=False):

        # wait for auto analysis
        r = ida_auto.auto_wait()
        
        # init super class
        ida_kernwin.PluginForm.__init__(self)
        cto_base.cto_base.__init__(self, cto_data, curr_view, debug)
        
	
        # Create tree control
        self.tree = MyWidget()
        self.model = self.tree.model
        self.proxy_model = self.tree.proxy_model
        self.sel_model = self.tree.sel_model
        
        self.selected_bg = self.get_selected_bg(0x99999999)
        
        self.icon = icon.icon_handler(icon_data=icon.g_icon_data_ascii, hexify=True)
        
        # observing "IDA View" or decompiler window
        class my_ui_hooks_t(syncui.my_ui_hooks_t):
            def _log(self, *msg):
                if self.v().config.debug:
                    self.v().dbg_print(">>> MyUiHook: %s" % " ".join([str(x) for x in msg]))
                    
            def refresh(self, ea=ida_idaapi.BADADDR, center=False):
                if ea == ida_idaapi.BADADDR:
                    ea = ida_kernwin.get_screen_ea()
                self.v().change_widget_icon(bg_change=self.v().config.dark_mode)
                self.v().tree.reset_btn_size()
                self.v().refresh(ea, center)
                
            def chk_dark_mode(self):
                refresh_flag = False
                if self.v().is_dark_mode_with_main():
                    self._log("dark mode is disabled in main window")
                    if not self.v().config.dark_mode:
                        self._log("dark mode is disabled in cto's config")
                        self.v().config.dark_mode = True
                        self.v().change_widget_icon(bg_change=self.v().config.dark_mode)
                        self.v().tree.reset_btn_size()
                else:
                    if self.v().config.dark_mode:
                        self.v().config.dark_mode = False
                        self.v().change_widget_icon(bg_change=self.v().config.dark_mode)
                return refresh_flag
                
        class my_view_hooks_t(syncui.my_view_hooks_t):
            def _log(self, *msg):
                if self.v().config.debug:
                    self.v().dbg_print(">>> MyViewHook: %s" % " ".join([str(x) for x in msg]))
                    
            def update_widget_b_ea(self, now_ea, was_ea):
                if now_ea != was_ea:
                    if was_ea != ida_idaapi.BADADDR:
                        self.v().deselect_item_by_ea(was_ea)
                        
                    if now_ea != ida_idaapi.BADADDR:
                        self.v().expand_item_by_ea(now_ea)

        # Note that this is still in the init method of the CallTreeOverviewer class
        # get the UI and View Hooks
        self.my_ui_hooks = my_ui_hooks_t(self)
        self.my_view_hooks = my_view_hooks_t(self)
        
    def exec_ui_action(self, action, w=None):
        if w is None:
            w = self.GetWidget()
        return self._exec_ui_action(action, w)

    def get_focus(self, w=None):
        if w is None:
            w = self.GetWidget()
        if w is None:
            return False
        return ida_kernwin.activate_widget(w, True)
        
    def clear_item_ids(self):
        imports = {}
        imports_ids = {}
        exports = {}
        exports_ids = {}
        funcs = {}
        func_ids = {}
        callers = {}
        caller_ids = {}

    def delete_func_idx_in_cache(self, idx, del_itself=True):
        # remove child indices
        root_item = self.model.itemFromIndex(idx)
        func_ea, _, _, _ = self.get_ea_by_idx(idx)
        for item in self.iter_items(root_item):
            curr_idx = self.model.indexFromItem(item)
            caller, _, _, _ = self.get_ea_by_idx(curr_idx)
            keyword = item.parent().text()
            
            self.delete_idx_in_cache(curr_idx, self.callers, self.caller_ids)
            
        # remove the index of the target function
        if del_itself:
            idx_addr = idx.sibling(idx.row(), 1)
            self.delete_idx_in_cache(idx, self.funcs, self.func_ids)
            self.delete_idx_in_cache(idx_addr, self.funcs, self.func_ids)

    def delete_idx_in_cache(self, idx, ea_dict, idx_dict):
        if idx in idx_dict:
            ea = idx_dict[idx]
            ea = idx_dict.pop(idx)
            if ea in ea_dict:
                ea_idx = ea_dict[ea]
                if ea_idx == idx:
                    ea_dict.pop(ea)
        
    def delete_row(self, idx):
        #self.model.beginRemoveRows(idx.parent(), idx.row(), idx.row())
        self.model.removeRow(idx.row(), idx.parent())
        #self.model.endRemoveRows()
        
    def delete_child_rows(self, parent):
        row_count = self.model.rowCount(parent)
        self.model.beginRemoveRows(parent, 0, row_count-1)
        #self.model.clear()
        self.model.removeRows(0, row_count, parent)
        self.model.endRemoveRows()
    
    def clear_tree(self):
        self.clear_item_ids()
        row_count = self.model.rowCount()
        self.model.beginRemoveRows(QtCore.QModelIndex(), 0, row_count-1)
        #self.model.clear()
        self.model.removeRows(0, row_count)
        self.model.endRemoveRows()
        #self.proxy_model.invalidate()
        
    def update_callee_function(self, ea):
        f = ida_funcs.get_func(ea)
        func_ea = ea
        if f:
            func_ea = f.start_ea
        if func_ea in self.func_relations:
            for caller_ea in self.func_relations[func_ea]['children']:
                if caller_ea == ea:
                    callee_ea = self.func_relations[func_ea]["children"][caller_ea][0]
                    if callee_ea != ida_idaapi.BADADDR and callee_ea in self.func_relations:
                        self.update_function(callee_ea)
        
    def update_function(self, ea):
        idx = self.get_idx_by_ea_and_eatype(ea, "func")
        #print("%x" % ea)
        #print(idx)
        #print(self.model.itemFromIndex(idx).text())
        #idcs = self.sel_model.selectedIndexes()
        #if idcs > 0:
        #    _idx = idcs[0]
        #    print(_idx)
        #    print(self.model.itemFromIndex(self.proxy_model.mapToSource(_idx)).text())
        if idx is not None and ea in self.func_relations:
            parent = self.model.itemFromIndex(idx).parent()
            
            # to avoid vftables
            if parent and parent.text() != "Functions":
                return None

            rownum = idx.row()
            self.clear_function(idx)
            # add new data to the tree again
            item = self.model.itemFromIndex(idx)
            parent = item.parent()
            self.PopulateFuncTree(parent, ea, rownum)
            # change the callee data 
            for caller_ea in self.func_relations[ea]["parents"]:
                #print("%x" % caller_ea)
                callee_ea = self.func_relations[ea]["parents"][caller_ea][0]
                #print("  %x" % callee_ea)
                idx = self.get_idx_by_ea_and_eatype(callee_ea, "func")
                if idx is not None:
                    root_item = self.model.itemFromIndex(idx)
                    for item in self.iter_items(root_item):
                        item_ea, _, _, _ = self.get_ea_by_item(item)
                        idx = self.model.indexFromItem(item)
                        #print("item_ea %x" % item_ea)
                        if caller_ea == item_ea and idx.column() == 0:
                            #print("caller_ea:%x" % caller_ea)
                            text = idc.generate_disasm_line(item_ea, 0)
                            item.setText(text)
                            item.setToolTip(text)
        
    def clear_function(self, idx):
        if idx is not None:
            self.delete_func_idx_in_cache(idx)
            self.delete_row(idx)
            #self.delete_child_rows(idx)
            
    def refresh(self, ea=ida_idaapi.BADADDR, center=False):
        # to avoid crashing IDA, remove the filter first
        filter_text = self.tree.filter.text()
        if filter_text:
            self.tree.filterChanged("")
        
        # refresh
        orig_ea = ea
        if orig_ea == ida_idaapi.BADADDR:
            orig_ea = ida_kernwin.get_screen_ea()
        f = ida_funcs.get_func(ea)
        if f:
            ea = f.start_ea
        self.copy_cache_data()
        if ea == ida_idaapi.BADADDR:
            self.clear_tree()
            self.PopulateTree()
        else:
            # if ea is string, check string and update string name ...
            for ea, func_ea, dref_off_ea in get_func_relation.get_dref_belong_to_func(orig_ea, self.vtbl_refs):
                self.update_function(func_ea)
                
            # for general functions
            self.update_callee_function(orig_ea)
            self.update_function(ea)
            
        # restore filter text
        if filter_text:
            self.tree.filterChanged(filter_text)
            self.tree.setFocus()
        
        # jump to the original ea and expand the item again
        #self.jumpto(orig_ea)
        self.expand_item_by_ea(orig_ea)
            
    def force_reload(self):
        self.refresh()
        return True
        
    # utilities
    # ============================
    def get_ea_by_item(self, item):
        ea = ida_idaapi.BADADDR
        name = ""
        mod_name = ""
        _ord = -1
        ea_type = ""
        idx = self.model.indexFromItem(item)
        if idx in self.func_ids:
            ea = self.func_ids[idx]
            ea_type = "func"
        elif idx in self.caller_ids:
            ea = self.caller_ids[idx]
            ea_type = "caller"
        elif idx in self.imports_ids:
            ea, name, _ord, mod_name = self.imports_ids[idx]
            ea_type = "import"
        elif idx in self.exports_ids:
            ea, name, _ord, mod_name = self.exports_ids[idx]
            ea_type = "export"
        return ea, name, idx, ea_type
        
    def get_ea_by_idx(self, idx):
        ea = ida_idaapi.BADADDR
        name = ""
        mod_name = ""
        _ord = -1
        ea_type = ""
        if idx in self.func_ids:
            ea = self.func_ids[idx]
            ea_type = "func"
        elif idx in self.caller_ids:
            ea = self.caller_ids[idx]
            ea_type = "caller"
        elif idx in self.imports_ids:
            ea, name, _ord, mod_name = self.imports_ids[idx]
            ea_type = "import"
        elif idx in self.exports_ids:
            ea, name, _ord, mod_name = self.exports_ids[idx]
            ea_type = "export"
        return ea, name, mod_name, ea_type
        
    def expand_parents(self, idx):
        if idx is None:
            return False
        #self.tree.expand(idx)
        idx = idx.parent()
        while idx.isValid():
            if not self.tree.isExpanded(idx):
                self.tree.expand(idx)
            idx = idx.parent()
            
    def get_idx_by_ea_and_eatype(self, ea, ea_type):
        idx = None
        ea_type = ""
        if ea in self.funcs:
            idx = self.funcs[ea]
            ea_type = "func"
        elif ea in self.callers:
            idx = self.callers[ea]
            ea_type = "caller"
        elif ea in self.imports:
            idx = self.imports[ea]
            ea_type = "import"
        elif ea in self.exports:
            idx = self.exports[ea]
            ea_type = "export"
        return idx
        
    def iter_items(self, root):
        def recurse(parent):
            for row in range(parent.rowCount()):
                for column in range(parent.columnCount()):
                    child = parent.child(row, column)
                    yield child
                    if child.hasChildren():
                        for item in recurse(child):
                            yield item
        if root is not None:
            for item in recurse(root):
                yield item
    
    def get_all_idx_by_ea(self, ea):
        idx = None
        for ea_type in ["func", "caller", "import", "export"]:
            idx = self.get_idx_by_ea_and_eatype(ea, ea_type)
            if idx is not None:
                yield idx, ea_type
        
    def _get_idx_by_ea(self, ea):
        idx = None
        ea_type = ""
        if ea in self.funcs:
            idx = self.funcs[ea]
            ea_type = "func"
        elif ea in self.callers:
            idx = self.callers[ea]
            ea_type = "caller"
        elif ea in self.imports:
            idx = self.imports[ea]
            ea_type = "import"
        elif ea in self.exports:
            idx = self.exports[ea]
            ea_type = "export"
        return idx, ea_type
        
    def get_idx_by_ea(self, ea):
        idx = None
        ea_type = ""
        idx, ea_type = self._get_idx_by_ea(ea)
        return idx, ea_type

    def deselect_item_by_ea(self, ea):
        idx, _ = self.get_idx_by_ea(ea)
        if idx is not None and idx.isValid():
            self.dbg_print(idx.model())
            if idx.model() == self.model:
                idx = self.proxy_model.mapFromSource(idx)
        if idx is not None and idx.isValid(): self.dbg_print(idx.model())
        if idx is not None and idx.isValid():
            self.sel_model.select(idx, QtCore.QItemSelectionModel.Deselect|QtCore.QItemSelectionModel.Rows)
            item = self.model.itemFromIndex(idx)
            if item is not None:
                item.setBackground(self.default_bg)

    def expand_item_by_ea(self, ea):
        # check if I need to expand or not
        # This is mainly for Exports/EPs.
        same_flag = False
        curr_idx = self.tree.currentIndex()
        if curr_idx is not None and curr_idx.isValid():
            self.dbg_print(curr_idx.model())
            if curr_idx.model() == self.proxy_model:
                curr_idx = self.proxy_model.mapToSource(curr_idx)
        if curr_idx is not None and curr_idx.isValid(): self.dbg_print(curr_idx.model())
        if curr_idx is not None and curr_idx.isValid():
            self.deselect_item_by_ea(ea)
            curr_ea, _, _, _ = self.get_ea_by_idx(curr_idx)
            if curr_ea == ea:
                same_flag = True
                #return

        if same_flag:
            idx = curr_idx
        else:
            idx, _ = self.get_idx_by_ea(ea)
            
        if idx is not None and idx.isValid():
            self.dbg_print(idx.model())
            if idx.model() == self.model:
                idx = self.proxy_model.mapFromSource(idx)
        if idx is not None and idx.isValid(): self.dbg_print(idx.model())
                
        # Expand the tree.
        if idx is not None and idx.isValid():
            self.sel_model.select(idx, QtCore.QItemSelectionModel.Select|QtCore.QItemSelectionModel.Rows)
            self.tree.scrollTo(idx, QtWidgets.QAbstractItemView.EnsureVisible)
            self.expand_parents(idx)
            item = self.model.itemFromIndex(idx)
            if item is not None:
                item.setBackground(self.selected_bg)
                
    def does_use_opn(self, idx=None):
        if idx is None:
            idx = self.tree.currentIndex()
        if idx is not None and idx.isValid():
            if idx.model() == self.proxy_model:
                idx = self.proxy_model.mapToSource(idx)
        ea, name, mod_name, ea_type = self.get_ea_by_idx(idx)
        use_opn = False
        if ea_type == "caller":
            use_opn = True
        return use_opn
    
    def jump_to_idx(self, idx):
        use_opn = self.does_use_opn(idx)
        ea, name, mod_name, ea_type = self.get_ea_by_idx(idx)
        if ea != ida_idaapi.BADADDR:
            self.jumpto(ea, use_opn)
            self.expand_item_by_ea(ea)
            
    def jump_to_item(self, item, column_no=0):
        ea, name, idx, ea_type = self.get_ea_by_item(item)
        use_opn = False
        if ea_type == "caller":
            use_opn = True
        if ea != ida_idaapi.BADADDR:
            self.jumpto(ea. use_opn)
            self.expand_item_by_ea(ea)
            
    def jump_to_callee(self, idx):
        if idx is None or not idx.isValid():
            return
        self.dbg_print(idx.model())
        if idx.model() == self.proxy_model:
            idx = self.proxy_model.mapToSource(idx)
        if idx is not None and idx.isValid(): self.dbg_print(idx.model())
        item = self.model.itemFromIndex(idx)
        if idx in self.caller_ids:
            idx_caller = idx.sibling(idx.row(), 0)
            caller = self.caller_ids[idx_caller]
            #print("%x" % caller)
            
            if not idx_caller.isValid():
                return
            
            idx_key = idx_caller.parent()
            if not idx_key.isValid():
                return
            
            idx_key = idx_key.sibling(idx_key.row(), 0)
            #item_key = self.model.itemFromIndex(idx_key)
            #keyword = item_key.text()
            keyword = self.model.data(idx_key)
            func_idx = idx_key.parent()
            
            if func_idx.isValid() and func_idx in self.func_ids:
                func_ea = self.func_ids[func_idx]
                if func_ea in self.func_relations and keyword in self.func_relations[func_ea] and caller in self.func_relations[func_ea][keyword]:
                    if keyword != "vftables":
                        # for comments, it does nothing.
                        if keyword in ["cmt", "rcmt"]:
                            callee = ida_idaapi.BADADDR
                        else:
                            callee = self.func_relations[func_ea][keyword][caller][0]
                    else:
                        callee = self.func_relations[func_ea][keyword][caller][caller][0]
                    if callee != ida_idaapi.BADADDR:
                        self.jumpto(callee)
                        self.expand_item_by_ea(callee)
            # for children of vftables
            elif idx_key in self.caller_ids:
                vtbl_func_offset = caller
                idx_caller = idx_key
                caller = self.caller_ids[idx_caller]
                idx_key = idx_caller.parent()
                if not idx_key.isValid():
                    return
                idx_key = idx_key.sibling(idx_key.row(), 0)
                #item_key = self.model.itemFromIndex(idx_key)
                #keyword = item_key.text()
                keyword = self.model.data(idx_key)
                func_idx = idx_key.parent()
                if func_idx.isValid() and func_idx in self.func_ids and keyword == "vftables":
                    func_ea = self.func_ids[func_idx]
                    if func_ea in self.func_relations and keyword in self.func_relations[func_ea] and caller in self.func_relations[func_ea][keyword]:
                        if vtbl_func_offset in self.func_relations[func_ea][keyword][caller]:
                            callee = self.func_relations[func_ea][keyword][caller][vtbl_func_offset][0]
                            
                            self.jumpto(callee)
                            self.expand_item_by_ea(callee)
                
    @staticmethod
    def parse_rgba32(color=0xffffffff):
        r = color & 0xff
        g = (color >> 8) & 0xff
        b = (color >> 16) & 0xff
        a = (color >> 24) & 0xff
        return r, g, b, a
    
    def get_selected_bg(self, color=0xffffffff):
        brush = QtGui.QBrush(QtGui.QColor(*self.parse_rgba32(color)))
        return brush
        
    # actions and events
    # ---------------------------------------------------
    def on_dbl_clk(self, idx):
        if self.config.debug: self.dbg_print("double click", idx)
        self.jump_to_callee(idx)
                            
        #print(item.text(0))
        
    def on_clk(self, idx):
        if idx.model() == self.proxy_model:
            idx = self.proxy_model.mapToSource(idx)
        if idx:
            print(self.model.data(idx))
        """
        item = self.model.itemFromIndex(idx)
        if item:
            print(item.text())
        """
        
    def on_curr_item_changed(self, curr, prev):
        #print(curr, prev)
        if prev is not None and prev.isValid():
            self.dbg_print(prev.model())
            if prev.model() == self.proxy_model:
                prev = self.proxy_model.mapToSource(prev)
            if prev is not None and prev.isValid(): self.dbg_print(prev.model())
            if prev.isValid():
                item = self.model.itemFromIndex(prev)
                if item is not None:
                    item.setBackground(self.default_bg)
                self.sel_model.select(prev, QtCore.QItemSelectionModel.Deselect|QtCore.QItemSelectionModel.Rows)
        if curr is not None and curr.isValid() and curr != prev:
            self.dbg_print(curr.model())
            if curr.model() == self.proxy_model:
                curr = self.proxy_model.mapToSource(curr)
            if curr is not None and curr.isValid(): self.dbg_print(curr.model())
            if curr.isValid():
                self.jump_to_idx(curr)
                item = self.model.itemFromIndex(curr)
                if item is not None:
                    item.setBackground(self.selected_bg)
                self.tree.setFocus()
                self.sel_model.select(curr, QtCore.QItemSelectionModel.Select|QtCore.QItemSelectionModel.Rows)

    def on_item_changed(self, idx, old_val, new_val):
        ea, _name, _mod_name, _ = self.get_ea_by_idx(idx)
        if ea != ida_idaapi.BADADDR and old_val != new_val:
            r = ida_name.set_name(ea, new_val, ida_name.SN_NOCHECK|ida_name.SN_NOWARN)
            if not r:
                ida_kernwin.msg("Could not rename because of invalid characters%s" % os.linesep)
                # revert back to the old val
                item = self.tree.model.itemFromIndex(idx)
                item.setText(old_val)
            else:
                name = ida_name.get_name(ea)
                if name != new_val:
                    item = self.tree.model.itemFromIndex(idx)
                    if name == old_val:
                        ida_kernwin.msg("Could not rename because of invalid name or reserved prefix%s" % os.linesep)
                        # revert back to the old val
                        item.setText(old_val)
                    else:
                        # change the name to modified name that the specific charasters are replaced
                        item.setText(name)
                        # refresh other cto instanses
                        self.refresh_all(ea)
                else:
                    # refresh other cto instances
                    self.refresh_all(ea)
            
    def buildContextMenu(self, event):
        cmenu = QtWidgets.QMenu(self.tree)
        idx = self.tree.indexAt(event)
        #print("right-click")

        # install CTO's finding path from/to node
        cto_inst = None
        for i in self.cto_data['insts']:
            # here, I don't wny but type(i) and isinstance and i.__class__
            # aren't match with the class. That's why compare these strings here.
            if str(type(i)) == "<class 'cto.CallTreeOverviewer'>":
                if i.parent is None:
                    cto_inst = i
                    break
        act_dict = {}
        if cto_inst:
            for skip, act_postfix, direction, direction2 in cto_inst.pf_args:
                actname = "path_finder%s:%s" % (act_postfix, cto_inst.title)
                desc = ida_kernwin.action_desc_t(actname, "Find the path(s) %s this node%s" % (direction, direction2), cto_inst.path_finder_by_ea(cto_inst, skip, actname))
                act_text = "Find the path(s) %s this node%s" % (direction, direction2)
                act = cmenu.addAction(act_text)
                act_dict[act] = cto_inst.path_finder_by_ea(cto_inst, skip, actname)
        
        action = cmenu.exec(self.tree.mapToGlobal(event))
        if action in act_dict:
            act_dict[action].activate(None)
        
        """
        #newAct = cmenu.addAction("New")
        #opnAct = cmenu.addAction("Open")
        #quitAct = cmenu.addAction("Quit")
        action = cmenu.exec_(self.tree.mapToGlobal(event))
        if action == quitAct:
            self.Close(0)
        elif action == newAct:
            print("new")
        elif action == opnAct:
            print("open")
        """
        
    def on_key_pressed(self, key_event):
        # for state
        SHIFT = QtCore.Qt.SHIFT
        ALT = QtCore.Qt.ALT
        CTRL = QtCore.Qt.CTRL
        ESC_KEY = QtCore.Qt.Key_Escape
        ENTER_KEY = QtCore.Qt.Key_Enter
        RETURN_KEY = QtCore.Qt.Key_Return
        TAB_KEY = QtCore.Qt.Key_Tab
        F5_KEY = QtCore.Qt.Key_F5
        SPACE_KEY = QtCore.Qt.Key_Space
        
        if self.config.debug: self.dbg_print('key pressed: %x, %x' % (key_event.key(), int(key_event.modifiers())))
        key = key_event.key()
        state = int(key_event.modifiers())
        c = chr(key & 0xff)
        
        w, wt = self.get_widget()
        # for IDA history (back)
        if key == ESC_KEY:
            self.exec_ui_action("Return", w=w)
            self.expand_item_by_ea(ida_kernwin.get_screen_ea())
            self.tree.setFocus()
        # for IDA history (forward)
        elif key in [ENTER_KEY, RETURN_KEY] and state == CTRL:
            self.exec_ui_action("UndoReturn", w=w)
            self.expand_item_by_ea(ida_kernwin.get_screen_ea())
            self.tree.setFocus()
        # toggle Debug message
        elif c == 'D' and state == 0:
            self.config.debug = not self.config.debug
            ida_kernwin.msg("debugging %sabled%s" % ("en" if self.config.debug else "dis", os.linesep))
        elif c == "R" and state == 0:
            self.refresh()
            ida_kernwin.msg("refreshed" + os.linesep)
        # Force refresh
        elif c == 'F' and state == 0:
            if self.force_reload():
                ida_kernwin.msg("Force reloaded." + os.linesep)
            else:
                ida_kernwin.msg("Not reloaded." + os.linesep)
        # Update func relations
        elif c == 'U' and state == 0:
            ida_kernwin.show_wait_box("Wait for updating the cache")
            self.update_data()
            self.refresh_all()
            ida_kernwin.msg("the caches of the function relationships and the referred string were Updated." + os.linesep)
            ida_kernwin.hide_wait_box()
        # Update func relations partially
        elif c == 'U' and state == SHIFT:
            ea = ida_kernwin.get_screen_ea()
            self.partial_cache_update(ea)
            self.refresh_all(ea)
            ida_kernwin.msg("the caches of the function relationships and the referred string were Updated partially." + os.linesep)
        # Update func relations partially
        elif c == 'U' and state == CTRL:
            self.cache_cmt_update()
            self.refresh_all()
            ida_kernwin.msg("the caches related to comments were Updated." + os.linesep)
        # Help
        elif c == 'H' and state == 0:
            self.print_help()
            """
        # darK mode
        elif c == 'K' and state == 0:
            self.config.dark_mode = not self.config.dark_mode
            #self.change_widget_icon(bg_change=self.config.dark_mode)
            #self.color_settings()
            self.refresh()
            ida_kernwin.msg("darK mode %sabled%s" % ("en" if self.config.dark_mode else "dis", os.linesep))
            """
        # toggle ida-view and text view
        elif c == ' ' and state == 0:
            self.exec_ida_ui_action("ToggleRenderer")
        # launch decompiler
        elif key == TAB_KEY and state == 0:
            self.exec_ida_ui_action("hx:JumpPseudo")
        # launch decompiler
        elif key == F5_KEY and state == 0:
            self.exec_ida_ui_action("hx:GenPseudo")
        # go to an address or an address of a function name
        elif c == 'G' and state == 0:
            self.exec_ida_ui_action("JumpAsk")
        # rename a function
        elif c == 'N' and state == 0:
            flag = self.check_and_rename_var()
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
        # jump to callee on a caller
        elif key in [ENTER_KEY, RETURN_KEY] and state == 0:
            curr_idx = self.tree.currentIndex()
            self.jump_to_callee(curr_idx)
            
        self.get_focus(w=self.GetWidget())
        self.tree.setFocus()
        self.expand_item_by_ea(ida_kernwin.get_screen_ea())
        return 0
            
    def print_help(self):
        ida_kernwin.msg("""
[How to use]
- You can think this is an enhanced version of "Functions" view.

[Shortcuts]
H: Help that you are looking.
R: Refresh the call graph manually.
F: Currently, this is the same as the refresh.
U: Update function relationships which is a cache and used for building the call tree.
Shift+U: Update function relationships partially. It updates only the node on the caches
   and its parent function and its parent functions's children if the node is a caller.
Ctrl+U: Update all comment caches. This is useful for collecting some tools'a results such as
   ironstrings and findcrypt.py.
N: reName a function (this option redirects to IDA View-A so that you can use it transparently).
 : (Space bar) toggle graph-view and text-view
F5: decompile a function
TAB: launch decompiler
G: Go to a place (this option redirects to IDA View-A so that you can use it transparently).
X: display Xrefs (this option redirects to IDA View-A so that you can use it transparently).
T: apply a sTructure member to an operand (this option redirects to IDA View-A so that
   you can use it transparently).
;: make repeatable comment (this option redirects to IDA View-A so that you can use it
   transparently).
:: make comment (this option redirects to IDA View-A so that you can use it transparently).
Alt+P: edit function (this option redirects to IDA View-A so that you can use it transparently).
Ctrl+X: detect Xor instructions in a loop.
Alt+Shift+M: detect several important mnemonics.
Ctrl+C: detect several important immediate values.
Alt+I: search important instructions.
ESC: Clear the filter on the filter bar. Move back of the IDA's location history.
Ctrl+Enter: Move forward  of the IDA's location history.
Ctrl+F: display/hide Filter bar.
D: enable/disable Debug mode
""")
        
    def builtin_exec(self, script):
        if script == 'xorloop':
            self.find_xor_loop()
        elif script == 'mnem':
            self.find_notable_mnem()
        elif script == 'inst':
            self.find_notable_inst()
        elif script == 'const':
            self.find_notable_const()
        elif script == 'cache':
            ida_kernwin.show_wait_box("Wait for updating the cache")
            self.update_data()
            self.refresh_all()
            ida_kernwin.msg("the caches of the function relationships and the referred string were Updated." + os.linesep)
            ida_kernwin.hide_wait_box()
        elif script == 'partial':
            ea = ida_kernwin.get_screen_ea()
            self.partial_cache_update(ea)
            self.refresh_all(ea)
            ida_kernwin.msg("the caches of the function relationships and the referred string were Updated partially." + os.linesep)
        elif script == 'comments':
            self.cache_cmt_update()
            self.refresh_all()
            ida_kernwin.msg("the caches related to comments were Updated." + os.linesep)
        elif script == 'help':
            self.print_help()
        
    def after_filtered(self, text):
        # if it empty, expand the current location and move to it
        # I can do it always, but it's a little bit heavy.
        ea = ida_kernwin.get_screen_ea()
        if ea != ida_idaapi.BADADDR:
            self.expand_item_by_ea(ea)
        self.tree.filter.setFocus()
        
    def OnCreate(self, form):
        """
        Called when the plugin form is created
        """
        
        # Get parent widget
        self.parent = self.FormToPyQtWidget(form)
        
        self.create_tree()
        
    def create_tree(self):
        # =================================
	#"""
        # Create tree control
        #self.tree = MyWidget()
        #self.model = self.tree.model
        #self.proxy_model = self.tree.proxy_model
        #self.sel_model = self.tree.sel_model
        #"""
        
        # =========================
        # build the function list
        self.tree.setSortingEnabled(False)
        self.tree.reset()
        self.PopulateTree()
        
        # adjust header length manually
        #self.tree.header().setCascadingSectionResizes(True)
        self.tree.header().setSectionResizeMode(0, self.tree.header().Interactive)
        self.tree.header().setSectionResizeMode(1, self.tree.header().Interactive)
        self.tree.header().setStretchLastSection(False)
        self.tree.header().resizeSection(0, 180)
        for i in range(2,4):
            self.tree.resizeColumnToContents(i)
        
        # =============================
        # for actions like when clicking, right-clicking or for events when changing selected items
        # focus an item (for sync with IDA View-A by jumping to the corresponding EA)
        self.tree.current_changed.connect(self.on_curr_item_changed)
        
        # for hooking renaming events
        self.tree.item_changed.connect(self.on_item_changed)
        
        # shortcut keys for passing to IDA
        self.tree.key_pressed.connect(self.on_key_pressed)
        
        # processes after filtering
        self.tree.after_filtered.connect(self.after_filtered)
        
        # execute built-in scripts
        self.tree.builtin_exec.connect(self.builtin_exec)
        
        # click
        #self.tree.clicked.connect(self.on_clk)
        
        # double-click
        self.tree.doubleClicked.connect(self.on_dbl_clk)
        
        # right-click
        self.tree.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self.buildContextMenu)
        
        # =========================
        # Create layout
        layout = QtWidgets.QVBoxLayout()
        layout.setContentsMargins(2,0,0,0)
        layout.addWidget(self.tree)
        layout.addWidget(self.tree.pfilter)
        
        # Populate PluginForm
        self.parent.setLayout(layout)
        
        # sort settings
        self.tree.setSortingEnabled(True)
        self.tree.sortByColumn(1, QtCore.Qt.AscendingOrder)
        
        # =========================
        # move to the current screen ea location
        ea = ida_kernwin.get_screen_ea()
        if ea != ida_idaapi.BADADDR:
            self.expand_item_by_ea(ea)

        # focus the tree widget
        self.tree.setFocus()

    def OnClose(self, form):
        """
        Called when the plugin form is closed
        """
        self.close()
        
    def close(self):
        # for closing cached data of cto_base class
        self.close_data()
        if hasattr(self, "sd"):
            self.sd.close()
            
        # unhook UI and View hooks
        if self.config.debug: self.dbg_print("Unhooking ui and view hooks%s" % (os.linesep))
        self.my_ui_hooks.unhook()
        self.my_view_hooks.unhook()
        if self.config.debug: self.dbg_print("Unhooked ui and view hooks%s" % (os.linesep))
        
        # close tempfile for debug log
        if self.f:
            self.f.close()
            self.f = None

    def __del__(self):
        self.close()
        
    def Show(self):
        """Creates the form is not created or focuses it if it was"""
        return ida_kernwin.PluginForm.Show(self,
                               "CTO Function Lister",
                               options = ida_kernwin.PluginForm.WOPN_PERSIST)
    
    #-----------------------------------------------------
    def imports_names_cb(self, ea, name, ordinal):
        self.items.append((ea, str(ordinal) if not name else name, ordinal))
        # True -> Continue enumeration
        return True
        
    def BuildImports(self):
        tree = {}
        nimps = ida_nalt.get_import_module_qty()
        
        for i in range(0, nimps):
            name = ida_nalt.get_import_module_name(i)
            if not name:
                continue
            # Create a list for imported names
            self.items = []

            # Enum imported entries in this module
            ida_nalt.enum_import_names(i, self.imports_names_cb)

            if name not in tree:
                tree[name] = []
            tree[name].extend(self.items)
            
        return tree
        
    def BuildExports(self):
        return list(idautils.Entries())

    def PopulateFuncTree(self, root, func_ea, row=-1):
        func_name = self.get_name(func_ea)
        func_name, ifunc, idx = self.RegisterFuncToTree(root, func_ea, func_name, self.funcs, self.func_ids, row=row)
        for keyword in self.func_relations[func_ea]:
            # skip func_type column
            if keyword == "func_type":
                continue
            
            self.tree.keywords[keyword] = True
            
            # skip keyword insertion if the keyword list is empty
            if len(self.func_relations[func_ea][keyword]) == 0:
                continue
            
            first_insertion = True
            for caller in sorted(self.func_relations[func_ea][keyword]):
                # skip a child func type is one of these ones.
                if keyword == "children":
                    callee, func_type, _, _ = self.func_relations[func_ea][keyword][caller]
                    if func_type in [FT_STO, FT_STR, FT_VAR]:
                        continue
                # add keyword node for the first insertion
                if first_insertion:
                    ikey = QtGui.QStandardItem("%s" % (keyword))
                    ikey.setEditable(False)
                    ifunc.appendRow(ikey)
                    first_insertion = False
                # add caller to the tree
                disasm, icaller, idx = self.RegisterCallerToTree(ikey, caller, keyword, func_ea)
                if keyword == "vftables":
                    for vtbl_off in sorted(self.func_relations[func_ea][keyword][caller]):
                        _disasm, _ivff_off, _idx = self.RegisterCallerToTree(icaller, vtbl_off, "", caller)
                    
                
    def RegisterCallerToTree(self, ikey, caller, keyword, func_ea):
        if keyword == "vftables":
            disasm = ida_name.get_name(caller)
            if not disasm:
                disasm = idc.generate_disasm_line(caller, 0)
        else:
            disasm = idc.generate_disasm_line(caller, 0)
        icaller_name = QtGui.QStandardItem("%s" % (disasm))
        icaller_addr = QtGui.QStandardItem("%x" % (caller))
        icaller_name.setToolTip(disasm)
        icaller_name.setEditable(False)
        icaller_addr.setEditable(False)
        ikey.appendRow((icaller_name, icaller_addr))
        idx = self.model.indexFromItem(icaller_name)
        idx_addr = self.model.indexFromItem(icaller_addr)
        self.caller_ids[idx] = caller
        self.caller_ids[idx_addr] = caller
        f = ida_funcs.get_func(caller)
        if keyword != "parents" or (keyword == "parents" and f and f.start_ea == func_ea):
            self.callers[caller] = idx
        return disasm, icaller_name, idx

    def get_name(self, func_ea):
        f = ida_funcs.get_func(func_ea)
        if f:
            func_name = ida_funcs.get_func_name(f.start_ea)
        else:
            func_name = ida_name.get_name(func_ea)
        return func_name
    
    def RegisterFuncToTree(self, parent, func_ea, func_name, ea_dict, idx_dict, other_data=None, row=-1):
        ifunc_name = QtGui.QStandardItem("%s" % (func_name))
        ifunc_addr = QtGui.QStandardItem("%x" % (func_ea))
        ifunc_xref_cnt = QtGui.QStandardItem("%d" % (cto_utils.count_xref(func_ea)))
        ifunc_bb_cnt = QtGui.QStandardItem("%d" % (cto_utils.count_bbs(func_ea)))
        ifunc_name.setToolTip(func_name)
        ifunc_addr.setEditable(False)
        ifunc_xref_cnt.setEditable(False)
        ifunc_bb_cnt.setEditable(False)
        if row >= 0:
            parent.insertRow(row, (ifunc_name, ifunc_addr, ifunc_xref_cnt, ifunc_bb_cnt))
        else:
            parent.appendRow((ifunc_name, ifunc_addr, ifunc_xref_cnt, ifunc_bb_cnt))
        
        idx = self.model.indexFromItem(ifunc_name)
        idx_addr = self.model.indexFromItem(ifunc_addr)
        
        idx_dict[idx] = func_ea
        if other_data is not None:
            idx_dict[idx] = [func_ea]
            idx_dict[idx].extend(other_data)
            
        idx_dict[idx_addr] = func_ea
        if other_data is not None:
            idx_dict[idx_addr] = [func_ea]
            idx_dict[idx_addr].extend(other_data)
            
        ea_dict[func_ea] = idx
        
        return func_name, ifunc_name, idx
    
    def find_toplevel_child(self, text):
        for i in range(self.tree.topLevelItemCount()):
            item = self.tree.topLevelItem(i)
            if item.text(0) == text:
                return item
        return None
    
    def PopulateTree(self):
        self.tree.setUpdatesEnabled(False)
        
        # Build functions
        root = QtGui.QStandardItem("Functions")
        root.setEditable(False)
        self.default_bg = root.background()
        self.model.appendRow(root)
        
        #for func_ea in sorted(self.func_relations):
        for func_ea in idautils.Functions():
            if func_ea in self.func_relations:
                self.PopulateFuncTree(root, func_ea)
            else:
                ida_kernwin.msg("Could not find %x in the cache. It might be old. Please renew the cache by pressing \"U\" after clicking CTO Function Lister window. %s" % (func_ea, os.linesep))
        
        # Build imports
        root = QtGui.QStandardItem("Imports")
        root.setEditable(False)
        self.model.appendRow(root)

        for dll_name, imp_entries in self.BuildImports().items():
            imp_dll = QtGui.QStandardItem(dll_name)
            imp_dll.setEditable(False)
            root.appendRow(imp_dll)
            for imp_ea, imp_name, imp_ord in imp_entries:
                func_name, ifunc, idx = self.RegisterFuncToTree(imp_dll, imp_ea, imp_name, self.imports, self.imports_ids, other_data=(imp_name, imp_ord, dll_name))
                
        # Build exports
        root = QtGui.QStandardItem("Exports")
        root.setEditable(False)
        self.model.appendRow(root)

        for exp_i, exp_ord, exp_ea, exp_name in self.BuildExports():
            name = idc.get_module_name(exp_ea)
            if exp_name is None:
                exp_name = ida_name.get_name(exp_ea)
            func_name, ifunc, idx = self.RegisterFuncToTree(root, exp_ea, exp_name, self.exports, self.exports_ids, other_data=(exp_name, exp_ord, name))
        
        self.tree.setUpdatesEnabled(True)
        
    def show(self):
        # show the list
        r = self.Show()

        if r:
            # use the option not to close by pressing ESC key
            ida_kernwin.display_widget(self.GetWidget(), ida_kernwin.WOPN_NOT_CLOSED_BY_ESC, None)
            
            ida_kernwin.set_dock_pos(self.title, "Functions window", ida_kernwin.DP_TAB)
            
        self.change_widget_icon(bg_change=self.config.dark_mode)
        if self.config.dark_mode:
            self.tree.reset_btn_size()
            
        return r

# --------------------------------------------------------------------------
def exec_cto_function_lister(cto_data=None, debug=False):
    cto_func_lister = cto_func_lister_t(cto_data=cto_data, debug=debug)

    r = cto_func_lister.show()
    if r:
        return cto_func_lister
    return None

def main():
    global cto_func_lister
    try:
        cto_func_lister.Close(0)
        del cto_func_lister
        cto_func_lister = cto_func_lister_t()
    except:
        cto_func_lister = cto_func_lister_t()

# --------------------------------------------------------------------------
if __name__ == '__main__':
    main()
