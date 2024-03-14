# -*- coding: utf-8 -*-
from collections import OrderedDict

from idaclu.qt_shims import (
    QAbstractItemView,
    QComboBox,
    QColor,
    QCursor,
    QEvent,
    QFont,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPainter,
    QPoint,
    QPointF,
    QProgressBar,
    QPushButton,
    QSize,
    QSizePolicy,
    QStandardItem,
    QStyledItemDelegate,
    Qt,
    QTreeView,
    QThread,
    QVBoxLayout,
    QWidget,
    Signal
)

from idaclu.qt_utils import i18n
from idaclu import plg_utils


class LabelTool(QWidget):
    PREFIX = 0
    FOLDER = 1

    def __init__(self, name, env_desc, parent=None):
        super(LabelTool, self).__init__(parent)

        self.env_desc = env_desc
        self.label_mode = LabelTool.PREFIX
        self.data = [
            {'caption': i18n('PREFIX'), 'pholder': i18n('Insert name')},
            {'caption': i18n('FOLDER'), 'pholder': i18n('Insert name')}
        ]
        font = QFont()
        font.setBold(True)
        font.setWeight(75)
        self.font = font
        layout = QHBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.initRecursionToggle(parent))
        layout.addLayout(self.initLabelEdit(parent))
        for actn in ['SetLabel', 'ClsLabel']:
            layout.addWidget(self.initActionButton(actn, parent))
        if self.env_desc.feat_folders:
            self._label.clicked.connect(self.toggleLabelMode)
        self.retranslateUi()
        self.setLayout(layout)
        self.decorateUi()


    def initActionButton(self, ref, parent):
        btn_name = "{}Button".format(ref)
        btn = QPushButton(parent)
        btn.setMinimumSize(QSize(75, 30))
        btn.setMaximumSize(QSize(75, 30))
        btn.setFont(self.font)
        btn.setEnabled(False)
        setattr(self, btn_name, btn)
        return btn

    def initRecursionToggle(self, parent):
        toggle = QPushButton(parent)
        toggle.setMinimumSize(QSize(30, 30))
        toggle.setMaximumSize(QSize(30, 30))
        toggle.setFont(self.font)
        toggle.setCheckable(True)
        toggle.setCursor(QCursor(Qt.PointingHandCursor))
        self._recur_toggle = toggle
        return toggle

    def initLabelEdit(self, parent):
        _PointingHandCursor = Qt.PointingHandCursor

        layout = QHBoxLayout()
        layout.setSpacing(0)

        label = QPushButton(parent)
        label.setCursor(QCursor(_PointingHandCursor))
        label.setMinimumSize(QSize(75, 30))
        label.setMaximumSize(QSize(75, 30))
        label.setFont(self.font)
        label.setCheckable(False)
        label.setAutoExclusive(False)
        self._label = label

        edit = QLineEdit(parent)
        edit.setMinimumSize(QSize(16777215, 30))
        edit.setMaximumSize(QSize(16777215, 30))
        edit.setPlaceholderText(i18n("Insert prefix"))
        self._edit = edit

        layout.addWidget(self._label)
        layout.addWidget(self._edit)
        layout.setStretch(0, 2)
        layout.setStretch(1, 5)
        return layout

    def toggleLabelMode(self):
        self.label_mode = not self.label_mode
        caption = str(self.data[self.label_mode]['caption']).upper()
        pholder = self.data[self.label_mode]['pholder']
        self._label.setText(i18n(caption))
        self._edit.setPlaceholderText(i18n(pholder))

    def setEnabled(self, state):
        self.SetLabelButton.setEnabled(state)
        self.ClsLabelButton.setEnabled(state)

    def getLabelName(self, prfx='', sufx=''):
        text = self._edit.text()
        if not text.startswith(prfx):
            text = "{}{}".format(prfx, text)
        if not text.endswith(sufx):
            text = "{}{}".format(text, sufx)
        return text

    def getLabelMode(self):
        return self.data[self.label_mode]['caption']

    def setModeHandler(self, handler):
        self._recur_toggle.clicked.connect(handler)

    def setSetHandler(self, handler):
        self.SetLabelButton.clicked.connect(handler)

    def setClsHandler(self, handler):
        self.ClsLabelButton.clicked.connect(handler)

    def decorateUi(self):
        self._recur_toggle.setProperty('class','tool-btn tool-btn-hov')
        if self.env_desc.feat_folders:
            self._label.setProperty('class','tool-btn tool-btn-hov edit-head')
        else:
            self._label.setProperty('class','tool-btn edit-head')
            self._label.setCursor(QCursor(Qt.ArrowCursor))
        self.SetLabelButton.setProperty('class','tool-btn tool-btn-hov')
        self.ClsLabelButton.setProperty('class','tool-btn tool-btn-hov')

    def retranslateUi(self):
        self._recur_toggle.setText(i18n("R"))
        self._label.setText(i18n("PREFIX"))
        self.SetLabelButton.setText(i18n("ADD"))
        self.ClsLabelButton.setText(i18n("CLEAR"))
        self._recur_toggle.setToolTip(i18n("Toggle recursive mode on/off"))
        self._label.setToolTip(i18n("Switch between Prefix/Folder modes"))


class ProgressIndicator(QWidget):
    def __init__(self, name, parent=None):
        super(ProgressIndicator, self).__init__(parent)
        layout = QVBoxLayout()
        layout.addWidget(self.initProgressBar(parent))
        layout.setContentsMargins(0, 0, 0, 0)
        self.setLayout(layout)
        self.setProgress(0)
        self._worker = Worker()
        self._worker.updateProgress.connect(self.setProgress)

    def initProgressBar(self, parent):
        progress = QProgressBar(parent)
        progress.setMinimumSize(QSize(0, 5))
        progress.setMaximumSize(QSize(16777215, 5))
        progress.setTextVisible(False)
        self._progress = progress
        return progress

    def setProgress(self, progress):
        if progress == 0:
            self.setVisible(False)
        elif progress == 100:
            self.setVisible(False)
            self._progress.setValue(0)
        else:
            self.setVisible(True)
            self._progress.setValue(progress)

    def updateProgress(self, progress):
        self._worker.updateProgress.emit(progress)


class ColorButton(QPushButton):
    def __init__(self, name, size=(30, 30), parent=None):
        QPushButton.__init__(self, parent=parent)
        self.setObjectName(name)
        self.setMinimumSize(QSize(*size))
        self.setMaximumSize(QSize(*size))
        self.setCheckable(True)
        self.setCursor(QCursor(Qt.PointingHandCursor))


class Worker(QThread):
    updateProgress = Signal(int)

    def __init__(self):
        QThread.__init__(self)

    def run(self):
        for i in range(1, 101):
            self.updateProgress.emit(i)
            # time.sleep(0.01)


class PaletteTool(QWidget):
    COLOR_NAME = 0
    COLOR_VAL = 1

    def __init__(self, name, size, pref, is_enbl=True, is_excl=True, parent=None):
        super(PaletteTool, self).__init__(parent)
        self.colors = [
            ("yellow", (255,255,191)),
            ("blue", (199,255,255)),
            ("green", (191,255,191)),
            ("pink", (255,191,239)),
            ("none", (255,255,255))
        ]

        self.setObjectName(name)
        self.layout = QHBoxLayout()
        self.layout.setContentsMargins(0, 0, 0, 0)

        for name, _ in self.colors:
            btn_name = '{}{}'.format(pref, name.capitalize())
            btn_obj = ColorButton(u"{}".format(btn_name), size, parent)
            btn_obj.setProperty('class','plt-btn plt-btn-{}'.format(name))
            btn_obj.setText("")
            self.layout.addWidget(btn_obj)

        self.setEnabled(is_enbl)
        self.setAutoExclusive(is_excl)
        self.setLayout(self.layout)

    def setClickHandler(self, handler):
        for _, btn in self.enumButtons():
            btn.clicked.connect(handler)

    def setPrefix(self, pref):
        for _, btn in self.enumButtons():
            color = str(btn.objectName()).replace('SetColor', '').lower()
            btn.setToolTip("{} {}".format(pref, i18n(color)))

    def enumButtons(self):
        for i in range(self.layout.count()):
            widget = self.layout.itemAt(i).widget()
            if isinstance(widget, QPushButton):
                yield (i, widget)

    def setEnabled(self, state):
        for _, btn in self.enumButtons():
            btn.setEnabled(state)

    def setAutoExclusive(self, state):
        for _, btn in self.enumButtons():
            btn.setAutoExclusive(state)

    def getSelectedColors(self):
        colors = []
        for i, btn in self.enumButtons():
            if btn.isChecked():
                color_val = self.colors[i][PaletteTool.COLOR_VAL]
                colors.append(plg_utils.RgbColor(color_val))
        return colors


class FilterInputGroup(QWidget):
    def __init__(self, names, pholder, env_desc, parent=None):
        super(FilterInputGroup, self).__init__(parent)

        self._items = OrderedDict()

        self.env_desc = env_desc
        is_unicode = isinstance(names, basestring) if env_desc.ver_py == 2 else isinstance(names, str)
        if is_unicode:
            self._has_state = False
            names = [names]
        elif isinstance(names, list) and len(names) == 2:
            self._has_state = True
            self._names = names
            self._state = False

        name = names[0]
        layout = QHBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self.initText(name, self))
        layout.addWidget(self.initSelect(name))
        layout.setStretch(0, 0)
        layout.setStretch(1, 5)
        layout.setStretch(2, 7)
        layout.setStretch(3, 0)
        self.setPlaceholder(pholder)
        self.setLayout(layout)

    def initText(self, name, parent=None):
        font = QFont()
        font.setBold(True)
        font.setWeight(75)

        label = QPushButton(parent)
        label.setText(name.upper())
        label.setFont(font)
        label.setMinimumSize(QSize(96, 26))
        label.setMaximumSize(QSize(96, 26))
        label.setProperty('class', 'select-head')
        self._label = label
        if self._has_state:
            self._label.setCursor(QCursor(Qt.PointingHandCursor))
            self._label.clicked.connect(self.toggleMode)
        return label

    def initSelect(self, name, parent=None):
        select = CheckableComboBox()
        select.setEnabled(True)
        select.setAutoFillBackground(False)
        select.setMinimumSize(QSize(16777215, 26))
        select.setMaximumSize(QSize(16777215, 26))
        select.lineEdit().setText("")
        self._select = select
        return select

    def setPlaceholder(self, pholder):
        self._select.lineEdit().setPlaceholderText(pholder)

    def addItems(self, items, is_sorted=False):
        for tpl in items:
            self.addItem(tpl, False)
        if len(items):
            self.setEnabled(True)
            if is_sorted:
                self.sortItems()
        else:
            self.setEnabled(False)

    def sortItems(self):
        self._items = OrderedDict(sorted(self._items.items()))
        self._select.sortItems()

    def addItem(self, item, is_sorted=False, is_unique=False):
        is_skip = False
        txt, num, col = None, None, None
        if isinstance(item, str):
            item = (item)
        for t in item:
            if isinstance(t, str):
                txt = t
            if isinstance(t, int):
                num = t
            if isinstance(t, tuple):
                col = t
        if txt in self._items:
            if not is_unique:
                self._items[txt] += num
            else:
                is_skip = True
        else:
            self._items[txt] = num
        if num:
            txt = '{} ({})'.format(txt, num)
        if not is_skip:
            self._select.addItem((txt, col), userData=None)
        if is_sorted:
            self.sortItems()

    def chgItems(self, changelog, is_sorted=False):
        rem_items = []
        for mod in changelog:
            for lbl, val in changelog[mod].items():
                idx = list(self._items.keys()).index(lbl) if lbl in self._items else -1
                if mod == 'sub':
                    self._items[lbl] -= val
                    if self._items[lbl] == 0:
                        self._items.pop(lbl)
                        sel_count = len(self.getData())
                        self._select.removeItem(idx)
                        if sel_count == 1:
                            self.setText('')
                        else:
                            self._select.updateLineEditField()
                        rem_items.append(lbl)
                        continue
                elif mod == 'add':
                    if lbl in self._items:
                        self._items[lbl] += val
                    else:
                        self._items[lbl] = val
                new_entry = '{} ({})'.format(lbl, self._items[lbl])
                self._select.chgItem(idx, new_entry)

        if is_sorted:
            self.sortItems()
        return rem_items

    def setEnabled(self, state=False):
        self._select.setEnabled(state)

    def removeSelf(self):
        self._label.setParent(None)
        self._select.setParent(None)
        self.setParent(None)

    def setText(self, text):
        self._select.lineEdit().setText(text)

    def getData(self):
        entries = self._select.getData().split('; ')
        data = []
        for e in entries:
            data.append(e.split(' ')[0])
        return data

    def toggleMode(self):
        self._state = not self._state
        caption = self._names[int(self._state)].upper()
        self._label.setText(i18n(caption))

    def getState(self):
        return self._state


class CheckableComboBox(QComboBox):
    def __init__(self):
        super(CheckableComboBox, self).__init__()
        self.setEditable(True)
        self.lineEdit().setReadOnly(True)
        self.closeOnLineEditClick = False
        self.lineEdit().installEventFilter(self)
        self.view().viewport().installEventFilter(self)
        self.model().dataChanged.connect(self.updateLineEditField)
        self.itemDelegate = QStyledItemDelegate(self)
        self.setItemDelegate(self.itemDelegate)

    def hidePopup(self):
        super(CheckableComboBox, self).hidePopup()
        self.startTimer(100)

    def addItem(self, entry, userData=None):
        text, colr = entry
        item = QStandardItem()
        item.setText(text)
        if not userData is None:
            item.setData(userData)
        if not colr is None:
            item.setBackground(QColor(*colr))
        item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsUserCheckable)
        item.setData(Qt.Unchecked, Qt.CheckStateRole)
        self.model().appendRow(item)

    def chgItem(self, row, text):
        if row == -1:
            self.addItem((text, None))
        else:
            item = self.model().item(row)
            item.setData(text, role=Qt.DisplayRole)
            
    def removeItem(self, row):
        self.model().removeRow(row)

    def sortItems(self):
        self.model().sort(0)

    def eventFilter(self, widget, event):
        if widget == self.lineEdit():
            if event.type() == QEvent.MouseButtonRelease:
                if self.closeOnLineEditClick:
                    self.hidePopup()
                else:
                    self.showPopup()
                return True
            return super(CheckableComboBox, self).eventFilter(widget, event)
        if widget == self.view().viewport():
            if event.type() == QEvent.MouseButtonRelease:
                indx = self.view().indexAt(event.pos())
                item = self.model().item(indx.row())

                if item.checkState() == Qt.Checked:
                    item.setCheckState(Qt.Unchecked)
                else:
                    item.setCheckState(Qt.Checked)
                return True
            return super(CheckableComboBox, self).eventFilter(widget, event)

    def updateLineEditField(self):
        text_container = []
        for i in range(self.model().rowCount()):
            if self.model().item(i).checkState() == Qt.Checked:
                text_container.append(self.model().item(i).text())
            text_string = '; '.join(text_container)
            self.lineEdit().setText(text_string)

    def getData(self):
        return self.lineEdit().text()

    def clearData(self):
        self.clear()


class FrameLayout(QWidget):
    def __init__(self, parent=None, title=None, env=None):
        self.env_desc = env
        QWidget.__init__(self, parent=parent)

        self._is_collasped = True
        self._title_frame = None
        self._content, self._content_layout = (None, None)

        title_frame = self.initTitleFrame(title, self._is_collasped)
        content_widget = self.initContent(self._is_collasped)

        self._main_v_layout = QVBoxLayout(self)
        self._main_v_layout.addWidget(title_frame)
        self._main_v_layout.addWidget(content_widget)

        self.initCollapsable()

    def initTitleFrame(self, title, collapsed):
        self._title_frame = self.TitleFrame(
            title=title,
            collapsed=collapsed,
            env=self.env_desc)
        return self._title_frame

    def initContent(self, collapsed):
        self._content = QWidget()
        self._content_layout = QVBoxLayout()

        self._content.setLayout(self._content_layout)
        self._content.setVisible(not collapsed)

        return self._content

    def addWidget(self, widget):
        self._content_layout.addWidget(widget)

    def initCollapsable(self):
        self._title_frame.clicked.connect(self.toggleCollapsed)

    def toggleCollapsed(self):
        self._content.setVisible(self._is_collasped)
        self._is_collasped = not self._is_collasped
        self._title_frame._arrow.setArrow(int(self._is_collasped))


    class TitleFrame(QFrame):

        clicked = Signal()
        def __init__(self, parent=None, title="", collapsed=False, env=None):
            QFrame.__init__(self, parent=parent)
            self.env_desc = env
            self.setMinimumHeight(24)
            self.move(QPoint(24, 0))

            self._hlayout = QHBoxLayout(self)
            self._hlayout.setContentsMargins(0, 0, 0, 0)
            self._hlayout.setSpacing(0)

            self._arrow = None
            self._title = None

            self._hlayout.addWidget(self.initArrow(collapsed))
            self._hlayout.addWidget(self.initTitle(title))

        def initArrow(self, collapsed):
            self._arrow = FrameLayout.Arrow(collapsed=collapsed, env=self.env_desc)
            return self._arrow

        def initTitle(self, title=None):
            self._title = QLabel(title)
            self._title.setMinimumHeight(24)
            self._title.move(QPoint(24, 0))

            return self._title

        def mousePressEvent(self, event):
            self.clicked.emit()
            return super(FrameLayout.TitleFrame, self).mousePressEvent(event)


    class Arrow(QFrame):
        def __init__(self, parent=None, collapsed=False, env=None):
            QFrame.__init__(self, parent=parent)
            self.env_desc = env
            self.setMaximumSize(24, 24)

            # horizontal == 0
            ha_point1 = QPointF(7.0, 8.0)
            ha_point2 = QPointF(17.0, 8.0)
            ha_point3 = QPointF(12.0, 13.0)
            self._arrow_horizontal = (ha_point1, ha_point2, ha_point3)
            # vertical == 1
            va_point1 = QPointF(8.0, 7.0)
            va_point2 = QPointF(13.0, 12.0)
            va_point3 = QPointF(8.0, 17.0)
            self._arrow_vertical = (va_point1, va_point2, va_point3)
            # arrow
            self._arrow = None
            self.setArrow(int(collapsed))

        def setArrow(self, arrow_dir):
            if arrow_dir:
                self._arrow = self._arrow_vertical
            else:
                self._arrow = self._arrow_horizontal

        def paintEvent(self, event):
            painter = QPainter()
            painter.begin(self)
            painter.setBrush(QColor(192, 192, 192))
            painter.setPen(QColor(64, 64, 64))
            if self.env_desc.lib_qt == 'pyqt5':
                painter.drawPolygon(*self._arrow)
            else:  # 'pyside'
                painter.drawPolygon(self._arrow)
            painter.end()


class CluTreeView(QTreeView):
    def __init__(self, parent=None):
        QTreeView.__init__(self, parent=parent)
        self.setSortingEnabled(True)
        self.setAlternatingRowColors(True)
        self.setObjectName(u"rvTable")
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.setAlternatingRowColors(True)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)

        self.header().sectionClicked.connect(self.sortByColumn)
        self.expanded.connect(self.save_expanded_state)
        self.collapsed.connect(self.save_expanded_state)
        self.expanded_state = {}

    def sortByColumn(self, logicalIndex):
        currentOrder = self.header().sortIndicatorOrder()
        isChildSort = bool(self.expanded_state) and any(value == True for value in self.expanded_state.values())
        self.model().sort(logicalIndex, currentOrder, int(isChildSort))
        for index, state in self.expanded_state.items():
            self.setExpanded(index, state)

    def save_expanded_state(self, index):
        self.expanded_state[index] = self.isExpanded(index)

