import base64
import collections
import importlib
import inspect
import os
import pkgutil
import sys
from typing import Collection

import idaapi

import symless
import symless.plugins as plugins
import symless.utils.utils as utils


class fixedBtn(idaapi.Form.ButtonInput):
    def __init__(self, plugin: "SymlessPlugin"):
        super().__init__(self.reload, "0")
        self.plugin = plugin

    def reload(self, code):
        idaapi.show_wait_box("Reloading Symless..")

        try:
            # terminate all extensions
            self.plugin.term()

            # reload symless code
            reload_plugin()

            # rebind all extensions
            self.plugin.find_extensions()

        except Exception as e:
            import traceback

            utils.g_logger.critical(repr(e) + "\n" + traceback.format_exc())
        finally:
            idaapi.hide_wait_box()

    def get_tag(self):
        return "<Reload:%s%d:%s%s:%s:%s>" % (
            self.tp,
            self.id,
            "+" if self.is_relative_offset else "",
            self.width,
            self.swidth,
            ":" if self.hlp is None else self.hlp,
        )


class SymlessInfoForm(idaapi.Form):
    def __init__(self, plugin: "SymlessPlugin"):
        icon_path = os.path.join(os.path.abspath(symless.__path__[0]), "resources", "bigger_champi.png")
        with open(icon_path, "rb") as file:
            icon_b64 = base64.b64encode(file.read()).decode()

        img_html = "<img src='data:image/png;base64,%s'>" % icon_b64
        info_html = """
            <div style='text-align: center; margin: 6px; font-size: 16px;'>
                <pre style='font-size: 72px;'>Symless</pre>
                <pre style='font-size: 16px; text-align: left;'>%s<br><br>Version: <b>%.1f</b></pre>
            </div>
        """ % (
            symless.PLUGIN_DESC,
            symless.PLUGIN_VERSION,
        )

        super().__init__(
            "BUTTON YES NONE\nBUTTON CANCEL NONE\nSymless plugin\n{img}<|>{info}\n{reload}",
            {
                "img": idaapi.Form.StringLabel(img_html, tp=idaapi.Form.FT_HTML_LABEL, size=None),
                "info": idaapi.Form.StringLabel(info_html, tp=idaapi.Form.FT_HTML_LABEL, size=None),
                "reload": fixedBtn(plugin),
            },
        )


# Symless plugin
class SymlessPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_MOD | idaapi.PLUGIN_PROC  # | idaapi.PLUGIN_HIDE
    comment = "Symless interactive plugin"
    wanted_name = "Symless"
    help = ""  # not used, IDA < 7.6 compatibility
    wanted_hotkey = ""  # not used, IDA < 7.6 compatibility

    # find & initialize all extensions
    def init(self) -> idaapi.plugmod_t:
        self.ext: Collection[plugins.plugin_t] = collections.deque()
        self.find_extensions()
        return idaapi.PLUGIN_KEEP

    # find and load extensions from symless plugins folder
    def find_extensions(self):
        for mod_info in pkgutil.walk_packages(plugins.__path__, prefix="symless.plugins."):
            if mod_info.ispkg:
                continue

            spec = mod_info.module_finder.find_spec(mod_info.name)
            module = importlib.util.module_from_spec(spec)

            # module is already loaded
            if module.__name__ in sys.modules:
                module = sys.modules[module.__name__]

            # load the module
            else:
                sys.modules[module.__name__] = module
                try:
                    spec.loader.exec_module(module)
                except BaseException as e:
                    sys.modules.pop(module.__name__)
                    print(f"Error while loading extension {mod_info.name}: {e}")
                    continue

            # module defines an extension
            if not hasattr(module, "get_plugin"):
                continue

            ext: plugins.plugin_t = module.get_plugin()
            self.ext.append(ext)

    # debug - reload plugin action
    def run(self, args):
        info = SymlessInfoForm(self)
        info.Compile()
        return info.Execute()

    # term all extensions
    def term(self):
        while len(self.ext) > 0:
            ext = self.ext.pop()
            ext.term()


def PLUGIN_ENTRY() -> idaapi.plugin_t:
    return SymlessPlugin()


# reload one module, by first reloading all imports from that module
# to_reload contains all modules to reload
def reload_module(module, to_reload: set):
    if module not in to_reload:
        return

    # remove from set first, avoid infinite recursion if recursive imports
    to_reload.remove(module)

    # reload all imports first
    for _, dep in inspect.getmembers(module, lambda k: inspect.ismodule(k)):
        reload_module(dep, to_reload)

    # reload the module
    utils.g_logger.info(f"Reloading {module.__name__} ..")
    importlib.reload(module)


# reload all symless code
def reload_plugin():
    # list all modules to reload, unordered
    to_reload = set()
    for k, mod in sys.modules.items():
        if k.startswith("symless"):
            to_reload.add(mod)

    for mod in list(to_reload):  # copy to alter
        reload_module(mod, to_reload)
