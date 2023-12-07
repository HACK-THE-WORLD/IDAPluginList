#!/usr/bin/python
###############################################################
# Copyright (c) 2023
# Sergejs 'HRLM' Harlamovs <harlamism<at>gmail<dot>com>
# Licensed under the MIT License. All rights reserved.
###############################################################

import collections
import json
import os
import sys

lib_qt = None
try:
    from PyQt5 import QtCore, QtGui, QtWidgets
    lib_qt = "pyqt5"
except ImportError:
    try:
        from PySide import QtCore, QtGui
        from PySide import QtGui as QtWidgets
        lib_qt = "pyside"
    except ImportError:
        pass

is_ida = True
try:  # almost version-agnostic imports
    import idc
    import idaapi
    from idaapi import plugin_t, PluginForm
    from idaclu import ida_shims
except ImportError:
    is_ida = False

    # standalone-run caps
    class plugin_t:
        pass
    class PluginForm:
        pass

from idaclu.qt_shims import (
    QIcon,
    QMessageBox
)
from idaclu import idaclu_gui
from idaclu.assets import resource


# make sub-plugins discoverable
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))


class ScriptEnv():
    def __init__(self, is_ida, lib_qt):
        # generic environment
        self.is_ida = is_ida
        self.lib_qt = lib_qt
        self.run_mode = 'script'
        self.dir_script = SCRIPT_DIR
        self.ver_py = sys.version_info[0]
        # ida-specific environment
        self.detectEnv()

    def __repr__(self):
        return self.get_dump(is_banner=True)

    def dump(self, is_banner=False):
        d_text = self.get_dump(is_banner=is_banner)
        if self.is_ida:
            ida_shims.msg(d_text)
        else:
            print(d_text)

    def get_dump(self, is_banner=False):
        env_repr = []
        if is_banner:
            env_repr.append(self.get_banner())

        env_repr.append('ENVIRONMENT\n')
        for prop in collections.OrderedDict(sorted(self.__dict__.items())):
            value = getattr(self, prop)
            if isinstance(value, list):
                for i, v in enumerate(value):
                    dots = '.' * (80 - (len(prop) + len(str(v))) + 4)
                    prop = " " * len(prop) if i > 0 else prop
                    env_repr.append("{} {} {}".format(prop, dots, v))
            else:
                dots = '.' * (80 - (len(prop) + len(str(value))) + 4)
                env_repr.append("{} {} {}".format(prop, dots, value))
        env_repr.append('\n')
        return "\n".join(env_repr)

    def get_banner(self):
        banner = "                                      \n" \
               + "     ____    __      ________         \n" \
               + "    /  _/___/ /___ _/ ____/ /_  __    \n" \
               + "    / // __  / __ `/ /   / / / / /    \n" \
               + "  _/ // /_/ / /_/ / /___/ / /_/ /     \n" \
               + " /___/\__,_/\__,_/\____/_/\__,_/      \n" \
               + "         by Sergejs Harlamovs         \n" \
               + "                                      \n"
        return banner

    def get_script_mode(self):  # in case of certainty of IDA environment
        mode = 'script'
        if idaapi.IDA_SDK_VERSION >= 720:
            if __name__ == "__main__":
                mode = "script"
            elif __name__.startswith('__plugins__'):
                # __plugins__<plugin_script_name>, ex.: __plugins__idaclu
                mode = "plugin"
        else:
            # maybe even more preferrable way of determining
            # if the plugin was run "as a plugin" or "as a script" -
            # location in one of default plugin directories
            plugin_dirs = ida_shims.get_ida_subdirs('plugins')
            if SCRIPT_DIR in plugin_dirs:
                mode = 'plugin'
            else:
                mode = 'script'
        return mode

    def get_plugin_ort(self):
        plg_loc = None
        plg_scope = 'None'
        g_plg_path = os.path.join(self.dir_plugin[0], 'idaclu')
        l_plg_path = os.path.join(self.dir_plugin[1], 'idaclu')
        if os.path.isdir(g_plg_path):
            plg_loc = self.dir_plugin[0]
            plg_scope = 'global'
        elif os.path.isdir(l_plg_path):
            plg_loc = self.dir_plugin[1]
            plg_scope = 'local'
        return (plg_loc, plg_scope)

    def detectEnv(self):
        if self.is_ida:
            self.ver_sdk = idaapi.IDA_SDK_VERSION
            self.ida_sample = ida_shims.get_input_file_path()
            ##
            self.dir_plugin = ida_shims.get_ida_subdirs("plugins")
            # self.dir_script
            self.feat_bookmarks = self.ver_sdk >= 760
            self.feat_cpp_oop = self.ver_sdk >= 720
            # C++ class hierarchy and virtual function recognition
            self.feat_folders = self.ver_sdk >= 750
            self.feat_golang = self.ver_sdk >= 760
            self.feat_ida6 = self.ver_sdk < 740
            # Point at which IDA v6.95 compatibility APIs was off
            self.feat_ioi64 = self.ver_sdk >= 820
            # "IdaOnIda64" - decompiling of 32-bit files in IDA64
            self.feat_lumina = self.ver_sdk >= 720
            self.feat_microcode = self.ver_sdk >= 710
            self.feat_microcode_new = self.ver_sdk >= 720
            # Microcode feature was introduced in v7.1, improved in v7.2
            self.feat_python3 = self.ver_sdk >= 740
            self.feat_undo = self.ver_sdk >= 730
            self.ida_arch = "x64" if idc.__EA64__ else "x86"
            self.ida_exe = sys.executable
            self.ida_kernel = idaapi.get_kernel_version()
            self.ida_module = os.path.basename(self.ida_sample) if self.ida_sample else None
            self.idb_path = ida_shims.get_idb_path()
            self.is_dbg = idaapi.is_debugger_on()
            # self.is_ida
            self.lib_qt = self.lib_qt = "pyside" if self.ver_sdk < 690 else "pyqt5"
            self.platform = sys.platform
            plg_loc, plg_scope = self.get_plugin_ort()
            self.plg_loc = plg_loc
            self.plg_scope = plg_scope
            self.run_mode = self.get_script_mode()
            self.ver_hexrays = idaapi.get_hexrays_version() if idaapi.init_hexrays_plugin() else None
            # self.ver_py

def common_init():
    env_desc = ScriptEnv(is_ida, lib_qt)
    return env_desc


__AUTHOR__ = "Sergejs 'HRLM' Harlamovs"

PLUGIN_NAME = "IdaClu"
PLUGIN_HOTKEY = 'Ctrl+Alt+O'
PLUGIN_VERSION = '1.0'
PLUGIN_TITLE = '{0} v{1}'.format(PLUGIN_NAME, PLUGIN_VERSION)
PLUGIN_URL = "https://github.com/harlamism/IdaClu"
PLUGIN_INFO = 'For usage see: <a href="{0}">{0}</a>'.format(PLUGIN_URL)

class IdaCluForm(PluginForm):
    def __init__(self, env_desc):
        super(IdaCluForm, self).__init__()
        self.env_desc = env_desc
        self.icon = QIcon(':/idaclu/icon_64.png')
        self.qss = os.path.join(SCRIPT_DIR, 'idaclu', 'assets', 'style.qss')

    def OnCreate(self, form):
        self.env_desc.dump(True)
        if self.env_desc.lib_qt == 'pyqt5':
            self.parent = self.FormToPyQtWidget(form)
        elif self.env_desc.lib_qt == 'pyside':
            self.parent = self.FormToPySideWidget(form)
        self.parent.setWindowTitle(PLUGIN_TITLE)
        self.parent.setWindowIcon(self.icon)
        self.dialog = idaclu_gui.IdaCluDialog(self.env_desc)
        # environment footprint is passed deeper
        self.dialog.setStyleSheet(open(self.qss).read())
        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.dialog)
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)
        self.parent.setLayout(layout)

    def OnClose(self, form):
        pass


def open_form(env_desc):
    if env_desc.is_ida:
        f = IdaCluForm(env_desc)
        f.Show('IdaClu')

def PLUGIN_ENTRY():
    return IdaCluPlugin()

class IdaCluPlugin(plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Function Clusterization Tool"
    help = "Edit->Plugin->IdaClu or {}.".format(PLUGIN_HOTKEY)
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    def init(self):
        super(IdaCluPlugin, self).__init__()
        self.icon_id = 0
        ida_shims.msg("%s %s loaded\n" % (self.wanted_name, PLUGIN_VERSION))
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        env_desc = common_init()
        open_form(env_desc)
        return

    def term(self):
        pass


def main(env_desc):
    env_desc.dump(True)
    if env_desc.is_ida:
        open_form(env_desc)
    else:
        app = QtWidgets.QApplication(sys.argv) if not is_ida else None
        if app:
            sys.exit(app.exec_())

if __name__ == "__main__":
    env_desc = common_init()
    if env_desc.run_mode == 'script':
        if not ida_shims.get_input_file_path():
            QMessageBox.information(None, "File Missing", "Please load a file in IDA first, then run script again.")
        else:
            main(env_desc)

    if not is_ida:
        main(env_desc)
