import collections
import json
import os
#
import idc
import idaapi
import idautils
#
from idaclu import ida_shims
from idaclu import ida_utils
from idaclu.qt_utils import i18n


SCRIPT_NAME = i18n('Windows API Semantics')
SCRIPT_TYPE = 'custom'
SCRIPT_VIEW = 'tree'
SCRIPT_ARGS = []


def get_idata():
        imports = {}
        module = ""

        def callback(ea, name, ordinal):
            imports[module].append((ea, name, ordinal))
            return True

        nimps = idaapi.get_import_module_qty()
        for i in range(0, nimps):
            module = idaapi.get_import_module_name(i)
            imports[module] = []
            idaapi.enum_import_names(i, callback)

        for mod in imports:
            for addr, name, ordi in imports[mod]:
                yield addr, mod, name, ordi


def get_data(progress_callback=None, env_desc=None, plug_params=None):
    report = {
        'data': collections.defaultdict(list),
        'stat': collections.defaultdict(int)
    }

    imps = list(get_idata())
    imps_count = len(imps)

    sem_cats = []
    plugin_path = os.path.abspath(os.path.dirname(__file__))
    with open(os.path.join(plugin_path, "winapi_semantics.json"), "r") as jh:
        def_data = json.load(jh)
        sem_cats = def_data['desc']

    func_reg = collections.defaultdict(set)
    for i, (addr, module, name, ordi) in enumerate(imps):
        for xref_addr in ida_utils.get_refs_to(addr):
            func_addr = ida_shims.get_func_attr(xref_addr, idc.FUNCATTR_START)
            if func_addr != idc.BADADDR and not ida_utils.is_func_thunk(func_addr):
                func_reg[func_addr].add(name)

    for idx, func_addr in enumerate(func_reg):
        cat_reg = collections.defaultdict(list)
        for imp_name in func_reg[func_addr]:
            key_name = None
            for cat_dsc in sem_cats:
                if imp_name in cat_dsc["api_names"]:
                    key_name = "{} / {}".format(cat_dsc['api_semantics'], cat_dsc['api_group'])
                    break
            else:
                key_name = "Unknown"
            cat_reg[key_name].append(imp_name)

        for cat in cat_reg:
            report['data'][cat].append((func_addr, ', '.join(cat_reg[cat])))
            report['stat'][cat] += 1

        if progress_callback:
            progress_callback(idx, len(func_reg))

    report['data'] = collections.OrderedDict(sorted(report['data'].items()))
    report['stat'] = collections.OrderedDict(sorted(report['stat'].items()))

    return report if __name__ == '__main__' else report['data']


def debug():
    data_obj = get_data()
    ida_shims.msg(json.dumps(data_obj, indent=4))

if __name__ == '__main__':
    debug()
