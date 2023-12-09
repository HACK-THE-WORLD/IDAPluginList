# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'idacluaBebKo.ui'
##
## Created by: Qt User Interface Compiler version 5.15.2
##
## WARNING! All changes made in this file will be lost when recompiling UI file!
################################################################################

# from PySide2.QtCore import *
# from PySide2.QtGui import *
# from PySide2.QtWidgets import *
from idaclu.qt_shims import (
    Signal,
    QSizePolicy,
    QAbstractItemView,
    QComboBox,
    QCoreApplication,
    QCursor,
    QEvent,
    QFont,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QIcon,
    QLineEdit,
    QMetaObject,
    QProgressBar,
    QPushButton,
    QRect,
    QScrollArea,
    QSize,
    QSizePolicy,
    QSpacerItem,
    QSplitter,
    QStandardItem,
    QStyledItemDelegate,
    Qt,
    QThread,
    QTreeView,
    QVBoxLayout,
    QWidget
)
from idaclu.qt_utils import i18n

from idaclu.qt_widgets import (
    FilterInputGroup,
    LabelTool,
    PaletteTool,
    ProgressIndicator
)

class Ui_PluginDialog(object):
    def __init__(self, env_desc):
        self.env_desc = env_desc

    def setupUi(self, PluginDialog):
        if not PluginDialog.objectName():
            PluginDialog.setObjectName(u"PluginDialog")
        PluginDialog.resize(1024, 600)
        icon = QIcon()
        icon.addFile(u":/idaclu/icon_64.png", QSize(), QIcon.Normal, QIcon.Off)
        PluginDialog.setWindowIcon(icon)
        self.vlPluginDialog = QVBoxLayout(PluginDialog)
        self.vlPluginDialog.setObjectName(u"vlPluginDialog")
        self.DialogSplitter = QSplitter(PluginDialog)
        self.DialogSplitter.setObjectName(u"DialogSplitter")
        self.DialogSplitter.setOrientation(Qt.Horizontal)
        self.DialogSplitter.setChildrenCollapsible(False)
        self.SidebarFrame = QFrame(self.DialogSplitter)
        self.SidebarFrame.setObjectName(u"SidebarFrame")
        self.SidebarLayout = QVBoxLayout(self.SidebarFrame)
        self.SidebarLayout.setSpacing(0)
        self.SidebarLayout.setObjectName(u"SidebarLayout")
        self.SidebarLayout.setContentsMargins(0, 0, 0, 0)
        self.ScriptsLayout = QVBoxLayout()
        self.ScriptsLayout.setSpacing(0)
        self.ScriptsLayout.setObjectName(u"ScriptsLayout")
        self.ScriptsHeader = QPushButton(self.SidebarFrame)
        self.ScriptsHeader.setObjectName(u"ScriptsHeader")
        self.ScriptsHeader.setMinimumSize(QSize(200, 30))
        font = QFont()
        font.setBold(True)
        font.setWeight(75)
        self.ScriptsHeader.setFont(font)
        self.ScriptsHeader.setCursor(QCursor(Qt.PointingHandCursor))
        self.ScriptsHeader.setProperty("class", "head")
        self.ScriptsLayout.addWidget(self.ScriptsHeader)

        self.ScriptsArea = QScrollArea(self.SidebarFrame)
        self.ScriptsArea.setObjectName(u"ScriptsArea")
        self.ScriptsArea.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.ScriptsArea.setWidgetResizable(True)
        self.wScriptsContents = QWidget()
        self.wScriptsContents.setObjectName(u"wScriptsContents")
        self.wScriptsContents.setGeometry(QRect(0, 0, 235, 372))

        # custom layout
        self.ScriptsContentsLayout = QVBoxLayout(self.wScriptsContents)
        self.ScriptsContentsLayout.setSpacing(0)
        self.ScriptsContentsLayout.setAlignment(Qt.AlignTop)

        self.ScriptsArea.setWidget(self.wScriptsContents)

        self.ScriptsLayout.addWidget(self.ScriptsArea)


        self.SidebarLayout.addLayout(self.ScriptsLayout)

        self.sScriptsBottom = QSpacerItem(20, 10, QSizePolicy.Minimum, QSizePolicy.Fixed)

        self.SidebarLayout.addItem(self.sScriptsBottom)

        self.FiltersLayout = QVBoxLayout()
        self.FiltersLayout.setSpacing(0)
        self.FiltersLayout.setObjectName(u"FiltersLayout")
        self.FiltersHeader = QPushButton(self.SidebarFrame)
        self.FiltersHeader.setObjectName(u"FiltersHeader")
        self.FiltersHeader.setMinimumSize(QSize(200, 30))
        font1 = QFont()
        font1.setBold(True)
        font1.setWeight(75)
        self.FiltersHeader.setFont(font1)
        self.FiltersHeader.setCursor(QCursor(Qt.PointingHandCursor))
        self.FiltersHeader.setProperty("class", "head")
        self.FiltersLayout.addWidget(self.FiltersHeader)

        self.FiltersGroup = QGroupBox(self.SidebarFrame)
        self.FiltersGroup.setObjectName(u"FiltersGroup")
        self.vlFiltersGroup = QVBoxLayout(self.FiltersGroup)
        self.vlFiltersGroup.setSpacing(0)
        self.vlFiltersGroup.setObjectName(u"vlFiltersGroup")
        self.vlFiltersGroup.setContentsMargins(0, 0, 0, 0)
        self.sFilters1 = QSpacerItem(20, 15, QSizePolicy.Minimum, QSizePolicy.Fixed)

        self.vlFiltersGroup.addItem(self.sFilters1)

        self.FolderFilterLayout = QHBoxLayout()
        self.FolderFilterLayout.setObjectName(u"FolderFilterLayout")
        self.sFolderFilterBeg = QSpacerItem(20, 26, QSizePolicy.Fixed, QSizePolicy.Minimum)

        self.FolderFilterLayout.addItem(self.sFolderFilterBeg)

        self.wFolderFilter = FilterInputGroup(u"Folders", u"Pick folders...", self.env_desc, self.FiltersGroup)
        self.wFolderFilter.setObjectName(u"wFolderFilter")
        self.wFolderFilter.setMinimumSize(QSize(0, 26))
        self.wFolderFilter.setMaximumSize(QSize(16777215, 26))

        self.FolderFilterLayout.addWidget(self.wFolderFilter)

        self.sFolderFilterEnd = QSpacerItem(20, 26, QSizePolicy.Fixed, QSizePolicy.Minimum)

        self.FolderFilterLayout.addItem(self.sFolderFilterEnd)


        self.vlFiltersGroup.addLayout(self.FolderFilterLayout)

        self.sFilters2 = QSpacerItem(20, 15, QSizePolicy.Minimum, QSizePolicy.Fixed)

        self.vlFiltersGroup.addItem(self.sFilters2)

        self.PrefixFilterLayout = QHBoxLayout()
        self.PrefixFilterLayout.setObjectName(u"PrefixFilterLayout")
        self.sPrefixFilterBeg = QSpacerItem(20, 26, QSizePolicy.Fixed, QSizePolicy.Minimum)

        self.PrefixFilterLayout.addItem(self.sPrefixFilterBeg)

        self.wPrefixFilter = FilterInputGroup([u"Prefixes (i)", u"Prefixes (e)"], u"Pick prefixes...", self.env_desc, self.FiltersGroup)
        self.wPrefixFilter.setObjectName(u"wPrefixFilter")
        self.wPrefixFilter.setMinimumSize(QSize(0, 26))
        self.wPrefixFilter.setMaximumSize(QSize(16777215, 26))

        self.PrefixFilterLayout.addWidget(self.wPrefixFilter)

        self.sPrefixFilterEnd = QSpacerItem(20, 26, QSizePolicy.Fixed, QSizePolicy.Minimum)

        self.PrefixFilterLayout.addItem(self.sPrefixFilterEnd)


        self.vlFiltersGroup.addLayout(self.PrefixFilterLayout)

        self.sFilters3 = QSpacerItem(20, 15, QSizePolicy.Minimum, QSizePolicy.Fixed)

        self.vlFiltersGroup.addItem(self.sFilters3)

        self.ColorFilterLayout = QHBoxLayout()
        self.ColorFilterLayout.setObjectName(u"ColorFilterLayout")
        self.sColorFilterBeg = QSpacerItem(40, 26, QSizePolicy.Fixed, QSizePolicy.Minimum)

        self.ColorFilterLayout.addItem(self.sColorFilterBeg)

        self.wColorFilter = PaletteTool(
            u"ColorFilter",
            (26, 26),
            u"Filter",
            True,
            False,
            self.FiltersGroup)
        self.wColorFilter.setObjectName(u"wColorFilter")
        self.wColorFilter.setMinimumSize(QSize(0, 26))
        self.wColorFilter.setMaximumSize(QSize(16777215, 26))

        self.ColorFilterLayout.addWidget(self.wColorFilter)

        self.sColorFilterEnd = QSpacerItem(40, 26, QSizePolicy.Fixed, QSizePolicy.Minimum)

        self.ColorFilterLayout.addItem(self.sColorFilterEnd)


        self.vlFiltersGroup.addLayout(self.ColorFilterLayout)

        self.sFilters4 = QSpacerItem(20, 15, QSizePolicy.Minimum, QSizePolicy.Fixed)

        self.vlFiltersGroup.addItem(self.sFilters4)


        self.FiltersLayout.addWidget(self.FiltersGroup)


        self.SidebarLayout.addLayout(self.FiltersLayout)

        self.sFiltersBottom = QSpacerItem(20, 14, QSizePolicy.Minimum, QSizePolicy.Fixed)

        self.SidebarLayout.addItem(self.sFiltersBottom)

        self.DialogSplitter.addWidget(self.SidebarFrame)
        self.MainFrame = QFrame(self.DialogSplitter)
        self.MainFrame.setObjectName(u"MainFrame")
        self.MainLayout = QVBoxLayout(self.MainFrame)
        self.MainLayout.setSpacing(0)
        self.MainLayout.setObjectName(u"MainLayout")
        self.MainLayout.setContentsMargins(5, 0, 0, 0)
        self.wProgressBar = ProgressIndicator(self.MainFrame)
        self.wProgressBar.setObjectName(u"wProgressBar")
        self.wProgressBar.setMinimumSize(QSize(0, 5))
        self.wProgressBar.setMaximumSize(QSize(16777215, 5))

        self.MainLayout.addWidget(self.wProgressBar)

        self.wResultsView = QWidget(self.MainFrame)
        self.wResultsView.setObjectName(u"wResultsView")
        self.hlResultsView = QHBoxLayout(self.wResultsView)
        self.hlResultsView.setObjectName(u"hlResultsView")
        self.hlResultsView.setContentsMargins(0, 0, 0, 0)
        self.rvTable = QTreeView(self.wResultsView)
        self.rvTable.setObjectName(u"rvTable")
        self.rvTable.setContextMenuPolicy(Qt.CustomContextMenu)
        self.rvTable.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.rvTable.setAlternatingRowColors(True)
        self.rvTable.setSelectionMode(QAbstractItemView.ExtendedSelection)

        self.hlResultsView.addWidget(self.rvTable)


        self.MainLayout.addWidget(self.wResultsView)

        self.sToolsTop = QSpacerItem(20, 10, QSizePolicy.Minimum, QSizePolicy.Fixed)

        self.MainLayout.addItem(self.sToolsTop)

        self.ToolsLayout = QHBoxLayout()
        self.ToolsLayout.setObjectName(u"ToolsLayout")
        self.sToolsBeg = QSpacerItem(10, 20, QSizePolicy.Fixed, QSizePolicy.Minimum)

        self.ToolsLayout.addItem(self.sToolsBeg)

        self.wLabelTool = LabelTool(u"LabelTool", self.env_desc, self.MainFrame)
        self.wLabelTool.setObjectName(u"wLabelTool")
        self.wLabelTool.setMinimumSize(QSize(320, 30))
        self.wLabelTool.setMaximumSize(QSize(16777215, 30))

        self.ToolsLayout.addWidget(self.wLabelTool)

        self.sToolsMid = QSpacerItem(80, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)

        self.ToolsLayout.addItem(self.sToolsMid)

        self.wColorTool = PaletteTool(
            u"PaletteTool",
            (30, 30),
            u"SetColor",
            False,
            True,
            self.MainFrame)
        self.wColorTool.setObjectName(u"wColorTool")
        self.wColorTool.setMinimumSize(QSize(192, 30))
        self.wColorTool.setMaximumSize(QSize(16777215, 30))

        self.ToolsLayout.addWidget(self.wColorTool)

        self.sToolsEnd = QSpacerItem(10, 20, QSizePolicy.Fixed, QSizePolicy.Minimum)

        self.ToolsLayout.addItem(self.sToolsEnd)


        self.MainLayout.addLayout(self.ToolsLayout)

        self.sToolsBottom = QSpacerItem(20, 14, QSizePolicy.Minimum, QSizePolicy.Fixed)

        self.MainLayout.addItem(self.sToolsBottom)

        self.MainLayout.setStretch(1, 8)
        self.MainLayout.setStretch(2, 1)
        self.MainLayout.setStretch(4, 1)
        self.DialogSplitter.addWidget(self.MainFrame)

        self.vlPluginDialog.addWidget(self.DialogSplitter)


        self.retranslateUi(PluginDialog)

        QMetaObject.connectSlotsByName(PluginDialog)
    # setupUi

    def retranslateUi(self, PluginDialog):
        PluginDialog.setWindowTitle(i18n("IdaClu v1.0"))
        self.ScriptsHeader.setText(i18n("TOOLSET"))
        self.FiltersHeader.setText(i18n("FILTERS"))
    # retranslateUi
