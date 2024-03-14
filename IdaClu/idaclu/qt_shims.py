# Shim file to support PySide v1.x and PyQt v5.x
# Documentation provided by Qt and Riverbank Computing Ltd.:
#  - https://srinikom.github.io/pyside-docs/
#  - https://doc.qt.io/qtforpython-5/
# Inspired by the gist of Willi Ballenthin:
#  - https://gist.github.com/williballenthin/277eedca569043ef0984


is_ida = True
try:
    import idaapi
except ImportError:
    is_ida = False


def get_DescendingOrder():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtCore as QtCore
        return QtCore.Qt.SortOrder.DescendingOrder
    else:
        import PyQt5.QtCore as QtCore
        return QtCore.Qt.DescendingOrder

def get_Signal():
    if is_ida and is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtCore as QtCore
        return QtCore.Signal
    else:
        import PyQt5.QtCore as QtCore
        return QtCore.pyqtSignal

def get_QAbstractItemModel():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtCore as QtCore
        return QtCore.QAbstractItemModel
    else:
        import PyQt5.QtCore as QtCore
        return QtCore.QAbstractItemModel

def get_QAbstractItemView():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QAbstractItemView
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QAbstractItemView

def get_QAction():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QAction
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QAction

def get_QApplication():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QApplication
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QApplication

def get_QBrush():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QBrush
    else:
        import PyQt5.QtGui as QtGui
        return QtGui.QBrush

def get_QByteArray():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtCore as QtCore
        return QtCore.QByteArray
    else:
        import PyQt5.QtCore as QtCore
        return QtCore.QByteArray

def get_QCheckBox():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QCheckBox
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QCheckBox

def get_QColor():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QColor
    else:
        import PyQt5.QtGui as QtGui
        return QtGui.QColor

def get_QComboBox():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QComboBox
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QComboBox

def get_QCompleter():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QCompleter
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QCompleter

def get_QCoreApplication():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtCore as QtCore
        return QtCore.QCoreApplication
    else:
        import PyQt5.QtCore as QtCore
        return QtCore.QCoreApplication

def get_QCursor():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QCursor
    else:
        import PyQt5.QtGui as QtGui
        return QtGui.QCursor

def get_QDialog():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QDialog
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QDialog

def get_QEvent():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtCore as QtCore
        return QtCore.QEvent
    else:
        import PyQt5.QtCore as QtCore
        return QtCore.QEvent

def get_QFont():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QFont
    else:
        import PyQt5.QtGui as QtGui
        return QtGui.QFont

def get_QFrame():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QFrame
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QFrame

def get_QGroupBox():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QGroupBox
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QGroupBox

def get_QHBoxLayout():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QHBoxLayout
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QHBoxLayout

def get_QIcon():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QIcon
    else:
        import PyQt5.QtGui as QtGui
        return QtGui.QIcon

def get_QImage():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QImage
    else:
        import PyQt5.QtGui as QtGui
        return QtGui.QImage

def get_QLabel():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QLabel
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QLabel

def get_QLineEdit():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QLineEdit
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QLineEdit


def get_QMainWindow():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QMainWindow
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QMainWindow

def get_QMenu():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QMenu
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QMenu

def get_QMessageBox():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QMessageBox
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QMessageBox

def get_QMetaObject():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtCore as QtCore
        return QtCore.QMetaObject
    else:
        import PyQt5.QtCore as QtCore
        return QtCore.QMetaObject

def get_QModelIndex():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtCore as QtCore
        return QtCore.QModelIndex
    else:
        import PyQt5.QtCore as QtCore
        return QtCore.QModelIndex

def get_QPainter():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QPainter
    else:
        import PyQt5.QtGui as QtGui
        return QtGui.QPainter

def get_QPixmap():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QPixmap
    else:
        import PyQt5.QtGui as QtGui
        return QtGui.QPixmap

def get_QPoint():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtCore as QtCore
        return QtCore.QPoint
    else:
        import PyQt5.QtCore as QtCore
        return QtCore.QPoint

def get_QPointF():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtCore as QtCore
        return QtCore.QPointF
    else:
        import PyQt5.QtCore as QtCore
        return QtCore.QPointF

def get_QProgressBar():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QProgressBar
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QProgressBar

def get_QPushButton():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QPushButton
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QPushButton

def get_QRadioButton():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QRadioButton
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QRadioButton

def get_QRect():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtCore as QtCore
        return QtCore.QRect
    else:
        import PyQt5.QtCore as QtCore
        return QtCore.QRect

def get_QScrollArea():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QScrollArea
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QScrollArea

def get_QSize():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtCore as QtCore
        return QtCore.QSize
    else:
        import PyQt5.QtCore as QtCore
        return QtCore.QSize

def get_QSizePolicy():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QSizePolicy
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QSizePolicy

def get_QSlider():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QSlider
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QSlider

def get_QSpacerItem():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QSpacerItem
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QSpacerItem

def get_QSplitter():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QSplitter
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QSplitter

def get_QStandardItem():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QStandardItem
    else:
        import PyQt5.QtGui as QtGui
        return QtGui.QStandardItem

def get_QStringListModel():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QStringListModel
    else:
        import PyQt5.QtCore as QtCore
        return QtCore.QStringListModel

def get_QStyle():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QStyle
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QStyle

def get_QStyledItemDelegate():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QStyledItemDelegate
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QStyledItemDelegate

def get_QStyleFactory():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QStyleFactory
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QStyleFactory

def get_QStyleOptionComboBox():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QStyleOptionComboBox
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QStyleOptionComboBox

def get_QStyleOptionSlider():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QStyleOptionSlider
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QStyleOptionSlider

def get_Qt():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtCore as QtCore
        return QtCore.Qt
    else:
        import PyQt5.QtCore as QtCore
        return QtCore.Qt

def get_QTableWidget():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QTableWidget
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QTableWidget

def get_QTableWidgetItem():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QTableWidgetItem
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QTableWidgetItem

def get_QTabWidget():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QTabWidget
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QTabWidget

def get_QtCore():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtCore as QtCore
        return QtCore
    else:
        import PyQt5.QtCore as QtCore
        return QtCore

def get_QTextBrowser():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QTextBrowser
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QTextBrowser

def get_QTextEdit():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QTextEdit
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QTextEdit

def get_QtGui():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui
    else:
        import PyQt5.QtGui as QtGui
        return QtGui

def get_QThread():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtCore as QtCore
        return QtCore.QThread
    else:
        import PyQt5.QtCore as QtCore
        return QtCore.QThread

def get_QTranslator():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtCore as QtCore
        return QtCore.QTranslator
    else:
        import PyQt5.QtCore as QtCore
        return QtCore.QTranslator

def get_QTreeView():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QTreeView
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QTreeView

def get_QTreeWidget():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QTreeWidget
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QTreeWidget

def get_QTreeWidgetItem():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QTreeWidgetItem
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QTreeWidgetItem

def get_QtWidgets():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        return None
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets

def get_QVBoxLayout():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QVBoxLayout
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QVBoxLayout

def get_QWidget():
    if is_ida and idaapi.IDA_SDK_VERSION <= 680:
        import PySide.QtGui as QtGui
        return QtGui.QWidget
    else:
        import PyQt5.QtWidgets as QtWidgets
        return QtWidgets.QWidget


DescendingOrder = get_DescendingOrder()
Signal = get_Signal()

QAbstractItemModel = get_QAbstractItemModel()
QAbstractItemView = get_QAbstractItemView()
QAction = get_QAction()
QApplication = get_QApplication()
QBrush = get_QBrush()
QByteArray = get_QByteArray()
QCheckBox = get_QCheckBox()
QColor = get_QColor()
QComboBox = get_QComboBox()
QCompleter = get_QCompleter()
QCoreApplication = get_QCoreApplication()
QCursor = get_QCursor()
QDialog = get_QDialog()
QEvent = get_QEvent()
QFont = get_QFont()
QFrame = get_QFrame()
QGroupBox = get_QGroupBox()
QHBoxLayout = get_QHBoxLayout()
QIcon = get_QIcon()
QImage = get_QImage()
QLabel = get_QLabel()
QLineEdit = get_QLineEdit()
QMainWindow = get_QMainWindow()
QMenu = get_QMenu()
QMessageBox = get_QMessageBox()
QMetaObject = get_QMetaObject()
QModelIndex = get_QModelIndex()
QPainter = get_QPainter()
QPixmap = get_QPixmap()
QPoint = get_QPoint()
QPointF = get_QPointF()
QProgressBar = get_QProgressBar()
QPushButton = get_QPushButton()
QRadioButton = get_QRadioButton()
QRect = get_QRect()
QScrollArea = get_QScrollArea()
QSize = get_QSize()
QSizePolicy = get_QSizePolicy()
QSlider = get_QSlider()
QSpacerItem = get_QSpacerItem()
QSplitter = get_QSplitter()
QStandardItem = get_QStandardItem()
QStringListModel = get_QStringListModel()
QStyle = get_QStyle()
QStyledItemDelegate = get_QStyledItemDelegate()
QStyleFactory = get_QStyleFactory()
QStyleOptionComboBox = get_QStyleOptionComboBox()
QStyleOptionSlider = get_QStyleOptionSlider()
Qt = get_Qt()
QTableWidget = get_QTableWidget()
QTableWidgetItem = get_QTableWidgetItem()
QTabWidget = get_QTabWidget()
QtCore = get_QtCore()
QTextBrowser = get_QTextBrowser()
QTextEdit = get_QTextEdit()
QtGui = get_QtGui()
QThread = get_QThread()
QTranslator = get_QTranslator()
QTreeView = get_QTreeView()
QTreeWidget = get_QTreeWidget()
QTreeWidgetItem = get_QTreeWidgetItem()
QtWidgets = get_QtWidgets()
QVBoxLayout = get_QVBoxLayout()
QWidget = get_QWidget()
