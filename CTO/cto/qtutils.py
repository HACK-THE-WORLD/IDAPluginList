import ida_kernwin


def can_use_qt():
    try:
        import sip
        from PyQt5 import QtCore
        from PyQt5 import QtWidgets
        from PyQt5 import QtGui
    except ImportError:
        return False
    return True
    

def get_qmain_window(w, max_try = 100):
    if not can_use_qt():
        return None
    import sip
    from PyQt5 import QtWidgets
    if w is None:
        return None
    widget = sip.wrapinstance(int(w), QtWidgets.QWidget)
    find_flag = False
    i = 0
    while i < max_try and widget:
        if  type(widget) == QtWidgets.QMainWindow:
            return widget
        widget = widget.parent()
        i += 1
    return None

def find_toolbar(widget, toolbar_name):
    if not can_use_qt():
        return None
    from PyQt5 import QtWidgets
    for cwidget in widget.children():
        if type(cwidget) == QtWidgets.QToolBar:
            #print(cwidget.objectName())
            #print(cwidget.accessibleName())
            if cwidget.objectName() == toolbar_name:
                return cwidget
    return None

def set_toobar_visible(w, toolbar_name):
    if not can_use_qt():
        return False
    from PyQt5 import QtCore
    widget = get_qmain_window(w)
    if widget:
        tb_widget = find_toolbar(widget, toolbar_name)
        if tb_widget and not tb_widget.isVisible():
            tb_widget.setEnabled(True)
            tb_widget.setVisible(True)
            return True
        widget.addToolBar(QtCore.Qt.TopToolBarArea, tb_widget)
    return False

class enable_toolbar_t(ida_kernwin.UI_Hooks):
    def __init__(self, toolbar_name):
        self.toolbar_name = toolbar_name
        ida_kernwin.UI_Hooks.__init__(self)
        self.hook()
        
    def ready_to_run(self):
        self.enable_toolbar()
        
    def enable_toolbar(self):
        widget = ida_kernwin.open_navband_window(ida_kernwin.get_screen_ea(),1)
        set_toobar_visible(widget, self.toolbar_name)
        
    def __del__(self):
        self.unhook()
