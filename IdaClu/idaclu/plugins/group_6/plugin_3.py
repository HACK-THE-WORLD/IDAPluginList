import collections
import json
#
import idaapi
import idautils
import idc
#
from idaclu import ida_shims
from idaclu import ida_utils
from idaclu.qt_utils import i18n


SCRIPT_NAME = i18n('Virtual Funtion Tables (MSVC)')
SCRIPT_TYPE = 'custom'
SCRIPT_VIEW = 'tree'
SCRIPT_ARGS = []


def order_item_len(input_dict):
    def get_len(val):
        fs = val[1]
        if isinstance(fs, int):
            return fs
        elif isinstance(fs, list):
            return len(fs)

    return collections.OrderedDict(sorted(input_dict.items(), key=get_len, reverse=True))


def get_data(progress_callback=None, env_desc=None, plug_params=None):
    report = {
        'data': collections.defaultdict(list),
        'stat': collections.defaultdict(int)
    }

    if ida_utils.is_GCC_auto():
        pass
    else:
        PTR_SIZE = ida_utils.get_ptr_size()
        vf_tables = {}
        over_methods = {}
        vft_count = 0
        for seg_ea in idautils.Segments():
            if ida_shims.get_segm_attr(seg_ea, idc.SEGATTR_TYPE) != idc.SEG_CODE:
                seg = idaapi.getseg(seg_ea)
                seg_beg = ida_shims.start_ea(seg)
                seg_end = ida_shims.end_ea(seg)
                seg_size = seg_end - seg_beg
                for offset in range(0, seg_size - PTR_SIZE, PTR_SIZE):
                    scan_ea = seg_beg + offset
                    if ida_utils.is_vtable(scan_ea):
                        vft_count += 1
                        vf_name = 'vtable_{}_{}'.format(vft_count, hex(scan_ea))
                        vf_tables[vf_name] = {'addr': scan_ea, 'funcs': []}

        if progress_callback:
            progress_callback(30, 100)

        for i, vf_name in enumerate(vf_tables):
            vf_addr = vf_tables[vf_name]['addr']
            func_ea = ida_utils.get_ptr(vf_addr)
            func_desc = idaapi.get_func(func_ea)
            if func_desc:
                vf_tables[vf_name]['funcs'].append(func_ea)
                if not func_ea in over_methods:
                    over_methods[func_ea] = set()
                over_methods[func_ea].add(vf_name)
            vf_addr += PTR_SIZE

            while not ida_utils.has_xref(vf_addr):
                func_ea = ida_utils.get_ptr(vf_addr)
                func_desc = idaapi.get_func(func_ea)
                if func_desc:
                    vf_tables[vf_name]['funcs'].append(func_ea)
                    if not func_ea in over_methods:
                        over_methods[func_ea] = set()
                    over_methods[func_ea].add(vf_name)
                vf_addr += PTR_SIZE

            if progress_callback:
                progress_callback(30 + int((i / len(vf_tables) * 40)), 100)

        for i, vf_name in enumerate(vf_tables):
            for func_ea in vf_tables[vf_name]['funcs']:
                comment = ""
                func_refs = list(over_methods[func_ea])
                if len(func_refs) > 1:
                    comment += ", ".join(func_refs)
                report['data'][vf_name].append((func_ea, comment))
                report['stat'][vf_name] += 1

            if progress_callback:
                progress_callback(70 + int((i / len(vf_tables) * 30)), 100)

    report['data'] = order_item_len(report['data'])
    report['stat'] = order_item_len(report['stat'])

    return report if __name__ == '__main__' else report['data']

def debug():
    data_obj = get_data()
    ida_shims.msg(json.dumps(data_obj, indent=4))

if __name__ == '__main__':
    debug()
