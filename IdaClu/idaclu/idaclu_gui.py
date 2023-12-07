import collections
import json
import os
import re
import sys
import time
#
import idc
import idaapi
import idautils
#
from idaclu import ida_shims
from idaclu.qt_shims import (
    QCoreApplication,
    QCursor,
    Qt,
    QtCore,
    QFrame,
    QIcon,
    QLineEdit,
    QMenu,
    QPushButton,
    QSize,
    QSizePolicy,
    QSpacerItem,
    QStyledItemDelegate,
    QVBoxLayout,
    QWidget
)
from idaclu import ida_utils
from idaclu import plg_utils
from idaclu.ui_idaclu import Ui_PluginDialog
from idaclu.qt_widgets import FrameLayout
from idaclu.models import ResultModel, ResultNode
from idaclu.assets import resource

# new backward-incompatible modules
try:
    import ida_dirtree
except ImportError:
    pass


class AppendTextEditDelegate(QStyledItemDelegate):
    def createEditor(self, parent, option, index):
        editor = QLineEdit(parent)
        return editor

    def setEditorData(self, editor, index):
        current_text = index.data()
        editor.setText(current_text)

    def setModelData(self, editor, model, index):
        current_text = index.data()
        new_text = editor.text()
        appended_text = "{}".format(new_text)
        model.setData(index, appended_text)
        func_addr = ida_shims.get_name_ea(0, current_text)
        ida_shims.set_name(func_addr, new_text, idaapi.SN_NOWARN)


class IdaCluDialog(QWidget):
    def __init__(self, env_desc):
        super(IdaCluDialog, self).__init__()
        self.env_desc = env_desc
        self.ui = Ui_PluginDialog(env_desc)
        self.ui.setupUi(self)

        self.ui.rvTable.setItemDelegate(AppendTextEditDelegate())

        self.is_sidebar_on_left = True
        self.is_filters_shown = True
        self.option_sender = None
        self.is_mode_recursion = False
        # values to initialize the corresponding filter

        if self.env_desc.feat_folders:
            self.folders = ida_utils.get_func_dirs('/')
            self.folders_funcs = ida_utils.get_dir_funcs(self.folders)

        self.prefixes = self.getFuncPrefs(is_dummy=True)
        self.sel_dirs = []
        self.sel_prfx = []
        self.sel_colr = []
        self.rec_indx = collections.defaultdict(list)

        self.heads = ['Name', 'Address', 'Size', 'Chunks', 'Nodes', 'Edges', 'Comment', 'Color']
        if env_desc.feat_folders:
            self.heads.insert(1, 'Folder')

        sp_path = self.get_splg_root(self.env_desc.plg_loc, 'idaclu')
        for frame in self.get_sp_controls(sp_path):
            self.ui.ScriptsContentsLayout.addWidget(frame)

        self.ui.wColorTool.setClickHandler(self.changeFuncColor)

        self.initFoldersFilter()
        self.initPrefixFilter()
        self.bindUiElems()

    def toggleRecursion(self):
        self.is_mode_recursion = not self.is_mode_recursion

    def bindUiElems(self):
        self.bindClicks()
        self.ui.rvTable.doubleClicked.connect(self.treeDoubleClick)
        self.ui.rvTable.customContextMenuRequested.connect(self.showContextMenu)

    def bindClicks(self):
        feat_folders = self.env_desc.feat_folders
        bind_data = [
            (self.ui.ScriptsHeader, self.swapPosition, True),
            (self.ui.FiltersHeader, self.showFilters, True)
        ]
        for (elem, meth, cond) in bind_data:
            if cond:
                elem.clicked.connect(meth)
        self.ui.wLabelTool.setModeHandler(self.toggleRecursion)
        self.ui.wLabelTool.setSetHandler(self.addLabel)
        self.ui.wLabelTool.setClsHandler(self.clsLabel)

    def getFuncPrefs(self, is_dummy=False):
        pfx_afacts = ['%', '_']
        prefs = set()
        for func_addr in idautils.Functions():
            func_name = ida_shims.get_func_name(func_addr)
            func_name = func_name.lstrip('_')
            if any(pa in func_name for pa in pfx_afacts):
                func_prefs = ida_utils.get_func_prefs(func_name, is_dummy)
                prefs.update(func_prefs)
        return list(prefs)

    def viewSelChanged(self):
        self.ui.wLabelTool.setEnabled(True)
        self.ui.wColorTool.setEnabled(True)

    def initPrefixFilter(self):
        self.ui.wPrefixFilter.addItems(self.prefixes)
        self.ui.wPrefixFilter.setText("")

    def initFoldersFilter(self):
        if self.env_desc.feat_folders:
            self.ui.wFolderFilter.addItems(self.folders)
            self.ui.wFolderFilter.setText("")
        else:
            self.ui.wFolderFilter.removeSelf()
            self.ui.FolderFilterLayout.setParent(None)
            layout = self.ui.vlFiltersGroup
            item = layout.takeAt(0)
            if item:
                widget = item.widget()
                if widget:
                    widget.deleteLater()
                del item

    def get_plugin_data(self):
        def sort_with_progress(constant, mcounter):
            def custom_sort(item):
                index, element = item
                mcounter[0] += 1
                finished = 65 + int(15 * (mcounter[0] / float(constant)))
                self.ui.wProgressBar.updateProgress(finished)
                return element['func_size']
            return custom_sort

        sender_button = self.sender()

        full_spec_name = sender_button.objectName()
        elem, cat, plg = full_spec_name.split('#')

        root_folder = self.env_desc.plg_loc
        module = None
        with plg_utils.PluginPath(os.path.join(root_folder, 'idaclu', 'plugins', cat)):
            module = __import__(plg)
            del sys.modules[plg]

        script_name = getattr(module, 'SCRIPT_NAME')
        script_type = getattr(module, 'SCRIPT_TYPE', 'custom')
        script_view = getattr(module, 'SCRIPT_VIEW', 'table')
        script_args = getattr(module, 'SCRIPT_ARGS', [])

        plug_params = {}
        if self.option_sender != None:
            widget = self.ui.ScriptsArea.findChild(QPushButton, self.option_sender)
            parent_layout = widget.parent().layout()

            if self.option_sender == full_spec_name:
                for i in range(parent_layout.count()):
                    sub_item = parent_layout.itemAt(i)
                    if sub_item:
                        sub_widget = sub_item.widget()
                        if sub_widget and (isinstance(sub_widget, QLineEdit)):
                            param_name = sub_widget.objectName().replace("{}__".format(full_spec_name), "")
                            plug_params[param_name] = sub_widget.text()  # .toPlainText()

            for i in range(parent_layout.count()):
                sub_item = parent_layout.itemAt(i)
                if sub_item:
                    if isinstance(sub_item, QSpacerItem):
                        parent_layout.removeItem(sub_item)
                        continue
                    sub_widget = sub_item.widget()
                    if sub_widget and (isinstance(sub_widget, QLineEdit)):
                        parent_layout.removeWidget(sub_widget)
                        sub_widget.setParent(None)

            self.option_sender = None

        elif self.option_sender == None and len(script_args) > 0:
            parent_widget = sender_button.parent()
            if parent_widget:
                for i, (ctrl_name, var_name, ctrl_ph) in enumerate(script_args):
                    text_edit = QLineEdit()
                    text_edit.setPlaceholderText(ctrl_ph)
                    text_edit.setMaximumSize(QSize(16777215, 30))
                    parent_widget.layout().addWidget(text_edit)
                    text_edit.setObjectName("{}__{}".format(full_spec_name, var_name))
                spacer = QSpacerItem(20, 30, QSizePolicy.Fixed, QSizePolicy.MinimumExpanding)
                parent_widget.layout().addStretch(1)
                self.option_sender = full_spec_name
                return

        agroup = getattr(module, 'get_data')

        is_filter_embed = False
        if script_type == 'func':
            is_filter_embed = True
            sdata = agroup(self.updatePbFunc, self.env_desc, plug_params)  # pre-filter
        elif script_type == 'custom':
            is_filter_embed = False
            sdata = agroup(self.updatePb, self.env_desc, plug_params)  # post-filter
        else:
            ida_shims.msg('ERROR: Unknown plugin type')
            return
        sitems = None

        self.items = []

        sdatt = collections.defaultdict(list)
        overall_count = sum(len(lst) for lst in sdata.values())
        global_index = 0
        for dt in sdata:
            for tt in sdata[dt]:
                func_addr = None
                func_comm = None
                if isinstance(tt, int):
                    func_addr = tt
                    func_comm = ""
                elif self.env_desc.ver_py == 2 and isinstance(tt, long):
                    func_addr = int(tt)
                    func_comm = ""
                elif isinstance(tt, tuple):
                    func_addr = int(tt[0])
                    func_comm = tt[1]

                if is_filter_embed == False:
                    self.sel_dirs = self.ui.wFolderFilter.getData()
                    self.sel_prfx = self.ui.wPrefixFilter.getData()
                    self.sel_colr = self.ui.wColorFilter.getSelectedColors()
                    if not self.isFuncRelevant(func_addr):
                        continue

                node_count, edge_count = ida_utils.get_nodes_edges(func_addr)
                func_desc = idaapi.get_func(func_addr)
                func_name = ida_shims.get_func_name(func_addr)
                func_colr = ida_shims.get_color(func_addr, idc.CIC_FUNC)
                func_path = None
                if self.env_desc.feat_folders:
                    func_path = self.folders_funcs[func_addr] if func_addr in self.folders_funcs else '/'

                entry = collections.OrderedDict()
                entry['func_name'] = func_name
                if func_path:
                    entry['func_path'] = func_path
                entry['func_addr'] = hex(int(func_addr))
                entry['func_size'] = ida_shims.calc_func_size(func_desc)
                entry['func_chnk'] = len(list(idautils.Chunks(func_addr)))
                entry['func_node'] = node_count
                entry['func_edge'] = edge_count
                entry['func_comm'] = func_comm
                entry['func_colr'] = plg_utils.RgbColor(func_colr).get_to_str()

                sdatt[dt].append(entry)
                global_index += 1
                finished = 50 + int(15 * (global_index / float(overall_count)))
                self.ui.wProgressBar.updateProgress(finished)

        mut_counter = [0]
        for key, value in sdatt.items():
            sdatt[key] = sorted(enumerate(value), key=sort_with_progress(overall_count, mut_counter))

        global_index = 0
        for i, dt in enumerate(sdatt):
            self.items.append(ResultNode("{} ({})".format(dt, len(sdatt[dt]))))
            for j, (idx, tt) in enumerate(sdatt[dt]):
                self.items[-1].addChild(ResultNode(list(tt.values())))
                global_index += 1
                finished = 80 + int(15 * (global_index / float(overall_count)))
                self.rec_indx[int(tt['func_addr'], 16)].append((i, j))
                self.ui.wProgressBar.updateProgress(finished)


        self.some_options_shown = None
        self.ui.rvTable.setModel(ResultModel(self.heads, self.items, self.env_desc))
        self.ui.wProgressBar.updateProgress(100)
        self.prepareView()

    def prepareView(self):
        self.ui.rvTable.setColumnHidden(self.heads.index('Color'), True)
        # color component values; irrelevant
        rvTableSelModel = self.ui.rvTable.selectionModel()
        rvTableSelModel.selectionChanged.connect(self.viewSelChanged)
        self.ui.rvTable.header().resizeSection(0, 240)
        self.ui.rvTable.header().resizeSection(1, 96)
        self.ui.rvTable.header().resizeSection(2, 96)
        self.ui.rvTable.header().resizeSection(3, 96)

    def updatePb(self, curr_idx, total_count):
        finished = int(70 * (curr_idx / float(total_count)))
        self.ui.wProgressBar.updateProgress(finished)

    def updatePbFunc(self):
        self.sel_dirs = self.ui.wFolderFilter.getData()
        self.sel_prfx = self.ui.wPrefixFilter.getData()
        self.sel_colr = self.ui.wColorFilter.getSelectedColors()

        func_desc = list(idautils.Functions())
        func_count = len(func_desc)
        for func_idx, func_addr in enumerate(func_desc):

            if not self.isFuncRelevant(func_addr):
                continue

            finished = int(50 * (func_idx/float(func_count)))
            self.ui.wProgressBar.updateProgress(finished)
            yield func_addr

    def isFuncRelevant(self, func_addr):
        # function directories
        if len(self.sel_dirs) and self.sel_dirs[0] != '':
            if not (func_addr in self.folders_funcs and
                self.folders_funcs[func_addr] in self.sel_dirs):
                return False
        # function name prefixes
        func_name = ida_shims.get_func_name(func_addr)
        func_prfx = ida_utils.get_func_prefs(func_name, True)
        if len(self.sel_prfx) and self.sel_prfx[0] != '':
            if self.ui.wPrefixFilter.getState() == True:
                if len(func_prfx) != len(self.sel_prfx) or not all(p in self.sel_prfx for p in func_prfx):
                    return False
            else:
                if not any(p in self.sel_prfx for p in func_prfx):
                    return False
        # function highlight color
        func_colr = plg_utils.RgbColor(ida_shims.get_color(func_addr, idc.CIC_FUNC))
        if len(self.sel_colr):
            if not any(func_colr == c for c in self.sel_colr):
                return False
        return True

    def treeDoubleClick(self, index):
        if not index.isValid():
            return None
        addr_index = index.sibling(index.row(), self.getFuncAddrCol())
        cell_data = addr_index.data()
        if cell_data and cell_data.startswith('0x'):
            idaapi.jumpto(plg_utils.from_hex(cell_data))

    def updateFilters(self, label_mode):
        label_name = None
        if label_mode == 'folder':
            label_name = self.ui.wLabelTool.getLabelName(prfx="/")
            self.ui.wFolderFilter.addItemNew(label_name, is_sorted=True)
        elif label_mode == 'prefix':
            label_name = self.ui.wLabelTool.getLabelName(sufx="_")
            self.ui.wPrefixFilter.addItemNew(label_name, is_sorted=True)
        return label_name

    def isDataSelected(self):
        return self.ui.rvTable.selectionModel().hasSelection()

    def addLabel(self):
        if self.isDataSelected():
            label_mode = self.ui.wLabelTool.getLabelMode()
            label_norm = self.updateFilters(label_mode)

            if self.env_desc.feat_folders and label_mode == 'folder':
                ida_utils.change_dir('/')
                ida_utils.create_folder(label_norm)

            addr_queue = self.getLabelAddrSet()
            for func_addr in addr_queue:
                func_name = ida_shims.get_func_name(func_addr)

                for id_group, id_child in self.rec_indx[func_addr]:
                    id_col = self.heads.index('Address')
                    indx_group = self.ui.rvTable.model().index(id_group, 0, QtCore.QModelIndex())
                    indx_child = self.ui.rvTable.model().index(id_child, id_col, indx_group)
                    if label_mode == 'prefix':
                        if not re.match("{0}%|{0}_".format(label_norm[:-1]), func_name):
                            func_name_new = plg_utils.add_prefix(func_name, label_norm, False)
                            ida_shims.set_name(func_addr, func_name_new, idaapi.SN_CHECK)
                            self.ui.rvTable.model().setData(indx_child, func_name_new)
                    else:  # == 'folder'
                        folder_src = self.folders_funcs.get(func_addr, '/')
                        ida_utils.set_func_folder(func_addr, folder_src, label_norm)
                        self.ui.rvTable.model().setData(indx_child, label_norm)

            if self.env_desc.feat_folders:
                self.folders = ida_utils.get_func_dirs('/')
                self.folders_funcs = ida_utils.get_dir_funcs(self.folders)

            ida_utils.refresh_ui()

    def clsLabel(self):
        if self.ui.rvTable.selectionModel().hasSelection():
            indexes = [index for index in self.ui.rvTable.selectionModel().selectedRows()]
            data = [index.sibling(index.row(), self.getFuncAddrCol()).data() for index in indexes]
            for idx, addr_field in enumerate(set(data)):
                func_addr = int(addr_field, base=16)
                func_name = ida_shims.get_func_name(func_addr)
                for id_group, id_child in self.rec_indx[func_addr]:
                    id_col = self.heads.index('Address')
                    indx_group = self.ui.rvTable.model().index(id_group, 0, QtCore.QModelIndex())
                    indx_child = self.ui.rvTable.model().index(id_child, id_col, indx_group)
                    label_mode = self.ui.wLabelTool.getLabelMode()
                    if label_mode == 'prefix':
                        func_prefs = ida_utils.get_func_prefs(func_name, True)
                        if len(func_prefs) >= 1 and func_prefs[0] != 'sub_':
                            # get last prefix
                            name_token = str(func_prefs[0]).replace('_', '%')
                            func_name_new = func_name.replace(name_token, '')
                            ida_shims.set_name(func_addr, func_name_new, idaapi.SN_NOWARN)
                            self.ui.rvTable.model().setData(indx_child, func_name_new)
                    elif label_mode == 'folder':
                        func_fldr = self.folders_funcs.get(func_addr, '/')
                        ida_utils.set_func_folder(func_addr, func_fldr, '/')
                        self.ui.rvTable.model().setData(indx_child, '/')
                    else:
                        ida_shims.msg('ERROR: unknown label mode')
            ida_utils.refresh_ui()

    def showContextMenu(self, point):
        ix = self.ui.rvTable.indexAt(point)
        if ix.column() == 0:
            menu = QMenu()
            menu.addAction(QIcon(':/idaclu/icon_64.png'), "Rename")
            action = menu.exec_(self.ui.rvTable.mapToGlobal(point))
            if action:
                if action.text() == "Rename":
                    self.ui.rvTable.edit(ix)

    def getFuncAddrCol(self):
        if self.env_desc.feat_folders:
            return 2
        else:
            return 1

    def changeFuncColor(self):
        if self.isDataSelected():
            sender_button = self.sender()
            btn_name = sender_button.objectName()
            color = None
            if btn_name == 'SetColorBlue':
                color = plg_utils.RgbColor((199,255,255), 'blue')
            elif btn_name == 'SetColorYellow':
                color = plg_utils.RgbColor((255,255,191), 'yellow')
            elif btn_name == 'SetColorGreen':
                color = plg_utils.RgbColor((191,255,191), 'green')
            elif btn_name == 'SetColorPink':
                color = plg_utils.RgbColor((255,191,239), 'pink')
            elif btn_name == 'SetColorNone':
                color = plg_utils.RgbColor((255,255,255), 'white')
            else:
                ida_shims.msg('ERROR: unknown palette button')

            addr_queue = self.getLabelAddrSet()

            for func_addr in addr_queue:
                for id_group, id_child in self.rec_indx[func_addr]:
                    id_col = self.heads.index('Address')
                    indx_group = self.ui.rvTable.model().index(id_group, 0, QtCore.QModelIndex())
                    indx_child = self.ui.rvTable.model().index(id_child, id_col, indx_group)
                    ida_shims.set_color(func_addr, idc.CIC_FUNC, color.get_to_int())
                    self.ui.rvTable.model().setData(indx_child, color.get_to_str())

            ida_utils.refresh_ui()

    def getLabelAddrSet(self):
        id_col = self.heads.index('Address')
        indexes = [idx for idx in self.ui.rvTable.selectionModel().selectedRows()]
        fields = [idx.sibling(idx.row(), id_col).data() for idx in indexes]

        addr_queue = set()
        for idx, field in enumerate(fields):
            func_addr = int(field, base=16)
            addr_queue.add(func_addr)

        addr_calees = set()
        if self.is_mode_recursion == True:
            for func_addr in addr_queue:
                addr_calees.update(ida_utils.recursive_prefix(func_addr))

        addr_queue.update(addr_calees)
        return addr_queue

    def swapPosition(self):
        layout = self.ui.DialogSplitter

        self.ui.SidebarFrame.setParent(None)
        self.ui.MainFrame.setParent(None)

        if not self.is_sidebar_on_left:
            layout.insertWidget(0, self.ui.SidebarFrame)
            layout.insertWidget(1, self.ui.MainFrame)
        else:
            layout.insertWidget(0, self.ui.MainFrame)
            layout.insertWidget(1, self.ui.SidebarFrame)

        layout.setCollapsible(0,False)
        layout.setCollapsible(1,False)

        self.is_sidebar_on_left = not self.is_sidebar_on_left

    def showFilters(self):
        if not self.is_filters_shown:
            self.ui.FiltersGroup.setMinimumSize(QSize(16777215, 16777215))
            self.ui.FiltersGroup.setMaximumSize(QSize(16777215, 16777215))
        else:
            self.ui.FiltersGroup.setMinimumSize(QSize(16777215, 1))
            self.ui.FiltersGroup.setMaximumSize(QSize(16777215, 1))

        self.is_filters_shown = not self.is_filters_shown

    def get_splg_root(self, plg_path, plg_fldr):
        splg_root = os.path.join(plg_path, plg_fldr, 'plugins')
        return splg_root

    def get_splg_tree(self, plg_splg_path):
        plg_tree = {}
        if os.path.exists(plg_splg_path):
            plg_tree = plg_utils.get_ordered_folder_tree(plg_splg_path)
        return plg_tree

    def is_sp_fname(self, sp_fname):
        return sp_fname.startswith('plugin_') and sp_fname.endswith('.py') and sp_fname != '__init__.py'

    def get_sp_controls(self, sp_path):
        sp_tree = self.get_splg_tree(sp_path)

        # depth of folder tree containing plugins is known
        for gdx, spg_ref in enumerate(sp_tree):
            if len(sp_tree[spg_ref]):
                spg_path = str(os.path.join(sp_path, spg_ref))
                spg_name = getattr(plg_utils.import_path(spg_path), 'PLUGIN_GROUP_NAME')
                spg_title = '{}. {}'.format(str(gdx+1), spg_name)

                spg_layout = FrameLayout(title=spg_title, env=self.env_desc)
                spg_layout.setProperty('class', 'frame')
                for sp_fname in sp_tree[spg_ref]:
                    plg_btn = None
                    if not self.is_sp_fname(sp_fname):
                        continue
                    sp_bname = sp_fname.replace('.py', '')
                    sp_name = sp_bname
                    # initial name is equal to file base name
                    # in case name will be not defined in plugin

                    sp_module = None
                    spe_msg = ""
                    # make sub-plugin discoverable in its group for importing
                    with plg_utils.PluginPath(os.path.join(sp_path, spg_ref)):
                        is_plug_ok = False
                        try:
                            sp_module = __import__(sp_bname)
                            del sys.modules[sp_bname]
                        except ImportError as err:
                            # in case some dependency is sub-plugin is missing
                            # the corresponding button will be disabled and
                            # tooltip will show this error
                            module_name = None
                            if self.env_desc.ver_py == 3:
                                module_name = err.name
                            else:
                                module_name = err.args[0].rsplit(' ',1)[-1]  # there is no .name attribute for Python2
                            spe_msg = "Module not found: {}".format(module_name)
                            # Attempt to open the module as a text file
                            # at least to recover sub-plugin name
                            try:
                                with open(os.path.join(sp_path, spg_ref, sp_fname), 'r') as file:
                                    for line in file:
                                        match = re.search(r'SCRIPT_NAME\s*=\s*["\']([^"\']+)', line)
                                        if match:
                                            sp_name = match.group(1)
                                            # self.log.debug("Recovered SCRIPT_NAME:", sp_name)
                                            break
                                    else:
                                        pass
                                        # self.log.debug("SCRIPT_NAME definition was not found")
                            except FileNotFoundError:
                                pass
                                # self.log.debug("Module file not found")
                        else:
                            is_plug_ok = True

                    # an attempt to load sub-plugin finished
                    # let's draw a corresponding button
                    sp_name = getattr(sp_module, 'SCRIPT_NAME', sp_name)
                    sp_layout = QVBoxLayout()
                    sp_frame = QFrame()
                    sp_frame.setSizePolicy(QSizePolicy.Minimum, QSizePolicy.Minimum)
                    sp_frame.setObjectName('Frame#{}#{}'.format(spg_ref, sp_bname))

                    sp_button = QPushButton(sp_name)
                    if is_plug_ok:
                        sp_button.clicked.connect(self.get_plugin_data)
                    else:
                        sp_button.setEnabled(False)
                        sp_button.setToolTip(spe_msg)

                    sp_button.setObjectName('Button#{}#{}'.format(spg_ref, sp_bname))
                    sp_layout.addWidget(sp_button)
                    sp_frame.setLayout(sp_layout)
                    spg_layout.addWidget(sp_frame)
                yield spg_layout
