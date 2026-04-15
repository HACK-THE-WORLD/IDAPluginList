# -*- coding:utf-8 -*-

from idaapi import plugin_t
from idaapi import PLUGIN_PROC
from idaapi import PLUGIN_OK
from PySide6 import QtWidgets

import os
import ida_nalt
import idaapi
import idautils
import idc
import time
import re
import ida_hexrays
import ida_funcs
import ida_xref
import ida_segment
import ida_bytes
import ida_entry

# 获取当前反编译的文件名
def getSoName():
    fullpath = ida_nalt.get_input_file_path()
    filepath, filename = os.path.split(fullpath)
    return filename

def ensure_dir(path):
    """确保目录存在"""
    if not os.path.exists(path):
        os.makedirs(path)

def get_callers(func_ea):
    """获取调用当前函数的地址列表"""
    callers = []
    for ref in idautils.XrefsTo(func_ea, 0):
        if idc.is_code(idc.get_full_flags(ref.frm)):
            caller_func = ida_funcs.get_func(ref.frm)
            if caller_func:
                callers.append(caller_func.start_ea)
    return sorted(list(set(callers)))

def get_callees(func_ea):
    """获取当前函数调用的函数地址列表"""
    callees = []
    func = ida_funcs.get_func(func_ea)
    if not func:
        return callees
    
    for head in idautils.Heads(func.start_ea, func.end_ea):
        if idc.is_code(idc.get_full_flags(head)):
            for ref in idautils.XrefsFrom(head, 0):
                if ref.type in [ida_xref.fl_CF, ida_xref.fl_CN]:
                    callee_func = ida_funcs.get_func(ref.to)
                    if callee_func:
                        callees.append(callee_func.start_ea)
    return sorted(list(set(callees)))

def format_address_list(addr_list):
    """格式化地址列表为逗号分隔的十六进制字符串"""
    return ", ".join([hex(addr) for addr in addr_list])

def export_call_graph(export_dir):
    """导出全局调用链分析文件"""
    call_graph_path = os.path.join(export_dir, "call_graph.txt")
    
    ea, ed = getSegAddr()
    functions_data = {}
    total_funcs = 0
    
    # 收集所有函数信息
    print("[*] Analyzing function call relationships...")
    for func_ea in idautils.Functions(ea, ed):
        func_name = idc.get_func_name(func_ea)
        demangled_name = idc.demangle_name(func_name, idc.get_inf_attr(idc.INF_SHORT_DN))
        display_name = demangled_name if demangled_name else func_name
        
        callers = get_callers(func_ea)
        callees = get_callees(func_ea)
        
        functions_data[func_ea] = {
            'name': display_name,
            'original_name': func_name,
            'callers': callers,
            'callees': callees
        }
        total_funcs += 1
    
    # 写入调用图文件
    with open(call_graph_path, 'w', encoding='utf-8') as f:
        f.write("# Global Call Graph Analysis\n")
        f.write("# This file contains the complete function call relationships\n")
        f.write("# Format: FUNCTION -> [calls] -> [called_by]\n")
        f.write("#" + "=" * 80 + "\n\n")
        
        # 统计信息
        leaf_functions = []
        root_functions = []
        highly_called = []
        
        for func_ea, data in functions_data.items():
            if not data['callees']:  # 叶子函数（不调用其他函数）
                leaf_functions.append((func_ea, data['name'], len(data['callers'])))
            if not data['callers']:  # 根函数（不被其他函数调用）
                root_functions.append((func_ea, data['name'], len(data['callees'])))
            if len(data['callers']) >= 5:  # 被频繁调用的函数
                highly_called.append((func_ea, data['name'], len(data['callers'])))
        
        # 写入概要统计
        f.write("## OVERVIEW\n")
        f.write(f"Total Functions: {total_funcs}\n")
        f.write(f"Root Functions (entry points): {len(root_functions)}\n")
        f.write(f"Leaf Functions: {len(leaf_functions)}\n")
        f.write(f"Highly Called Functions (5+ callers): {len(highly_called)}\n")
        f.write("\n")
        
        # 写入根函数列表
        f.write("## ROOT FUNCTIONS (Entry Points)\n")
        for func_ea, name, callees_count in sorted(root_functions, key=lambda x: x[2], reverse=True):
            f.write(f"{hex(func_ea)}: {name} -> calls {callees_count} functions\n")
        f.write("\n")
        
        # 写入高频调用函数
        f.write("## HIGHLY CALLED FUNCTIONS\n")
        for func_ea, name, callers_count in sorted(highly_called, key=lambda x: x[2], reverse=True):
            f.write(f"{hex(func_ea)}: {name} -> called by {callers_count} functions\n")
        f.write("\n")
        
        # 写入详细调用关系
        f.write("## DETAILED CALL RELATIONSHIPS\n")
        f.write("#" + "-" * 80 + "\n")
        
        for func_ea in sorted(functions_data.keys()):
            data = functions_data[func_ea]
            f.write(f"\nFUNCTION: {hex(func_ea)} - {data['name']}\n")
            
            if data['original_name'] != data['name']:
                f.write(f"  Original: {data['original_name']}\n")
            
            # 调用的函数
            if data['callees']:
                f.write("  CALLS:\n")
                for callee_ea in data['callees']:
                    callee_data = functions_data.get(callee_ea)
                    if callee_data:
                        f.write(f"    -> {hex(callee_ea)}: {callee_data['name']}\n")
                    else:
                        callee_name = idc.get_func_name(callee_ea)
                        f.write(f"    -> {hex(callee_ea)}: {callee_name}\n")
            else:
                f.write("  CALLS: (leaf function)\n")
            
            # 被调用
            if data['callers']:
                f.write("  CALLED BY:\n")
                for caller_ea in data['callers']:
                    caller_data = functions_data.get(caller_ea)
                    if caller_data:
                        f.write(f"    <- {hex(caller_ea)}: {caller_data['name']}\n")
                    else:
                        caller_name = idc.get_func_name(caller_ea)
                        f.write(f"    <- {hex(caller_ea)}: {caller_name}\n")
            else:
                f.write("  CALLED BY: (entry point)\n")
            
            f.write(f"  STATS: calls={len(data['callees'])}, called_by={len(data['callers'])}\n")
    
    print("[*] Call Graph Summary:")
    print(f"    Total functions analyzed: {total_funcs}")
    print(f"    Root functions: {len(root_functions)}")
    print(f"    Leaf functions: {len(leaf_functions)}")
    print(f"    Highly called functions: {len(highly_called)}")

def export_strings(export_dir):
    """导出所有字符串"""
    strings_path = os.path.join(export_dir, "strings.txt")
    
    string_count = 0
    with open(strings_path, 'w', encoding='utf-8') as f:
        f.write("# Strings exported from IDA\n")
        f.write("# Format: address | length | type | string\n")
        f.write("#" + "=" * 80 + "\n\n")
        
        for s in idautils.Strings():
            try:
                string_content = str(s)
                str_type = "ASCII"
                if s.strtype == ida_nalt.STRTYPE_C_16:
                    str_type = "UTF-16"
                elif s.strtype == ida_nalt.STRTYPE_C_32:
                    str_type = "UTF-32"
                
                f.write("{} | {} | {} | {}\n".format(
                    hex(s.ea),
                    s.length,
                    str_type,
                    string_content.replace('\n', '\\n').replace('\r', '\\r')
                ))
                string_count += 1
            except Exception as e:
                continue
    
    print("[*] Strings Summary:")
    print("    Total strings exported: {}".format(string_count))

def export_imports(export_dir):
    """导出导入表"""
    imports_path = os.path.join(export_dir, "imports.txt")
    
    import_count = 0
    with open(imports_path, 'w', encoding='utf-8') as f:
        f.write("# Imports\n")
        f.write("# Format: func-addr:func-name\n")
        f.write("#" + "=" * 60 + "\n\n")
        
        nimps = ida_nalt.get_import_module_qty()
        for i in range(nimps):
            module_name = ida_nalt.get_import_module_name(i)
            
            def imp_cb(ea, name, ordinal):
                nonlocal import_count
                if name:
                    f.write("{}:{}\n".format(hex(ea), name))
                else:
                    f.write("{}:ordinal_{}\n".format(hex(ea), ordinal))
                import_count += 1
                return True
            
            ida_nalt.enum_import_names(i, imp_cb)
    
    print("[*] Imports Summary:")
    print("    Total imports exported: {}".format(import_count))

def export_exports(export_dir):
    """导出导出表"""
    exports_path = os.path.join(export_dir, "exports.txt")
    
    export_count = 0
    with open(exports_path, 'w', encoding='utf-8') as f:
        f.write("# Exports\n")
        f.write("# Format: index:func-addr:func-name\n")
        f.write("#" + "=" * 60 + "\n\n")
        
        for i in range(ida_entry.get_entry_qty()):
            export_index = i + 1
            ordinal = ida_entry.get_entry_ordinal(i)
            ea = ida_entry.get_entry(ordinal)
            name = ida_entry.get_entry_name(ordinal)
            
            if name:
                # 尝试获取去修饰的名称，如果失败则使用原始名称
                demangled_name = idc.demangle_name(name, idc.get_inf_attr(idc.INF_SHORT_DN))
                if demangled_name:
                    display_name = demangled_name
                else:
                    display_name = name
                
                f.write("{}:{}:{}\n".format(export_index, hex(ea), display_name))
            else:
                f.write("{}:{}:ordinal_{}\n".format(export_index, hex(ea), ordinal))
            export_count += 1
    
    print("[*] Exports Summary:")
    print("    Total exports exported: {}".format(export_count))

def export_memory(export_dir):
    """导出内存数据，按 1MB 分割，hexdump 格式"""
    memory_dir = os.path.join(export_dir, "memory")
    ensure_dir(memory_dir)
    
    CHUNK_SIZE = 1 * 1024 * 1024  # 1MB
    BYTES_PER_LINE = 16
    
    total_bytes = 0
    file_count = 0
    
    for seg_idx in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(seg_idx)
        if seg is None:
            continue
        
        seg_start = seg.start_ea
        seg_end = seg.end_ea
        seg_name = ida_segment.get_segm_name(seg)
        
        print("[*] Processing segment: {} ({} - {})".format(
            seg_name, hex(seg_start), hex(seg_end)))
        
        current_addr = seg_start
        while current_addr < seg_end:
            chunk_end = min(current_addr + CHUNK_SIZE, seg_end)
            
            filename = "{:08X}--{:08X}.txt".format(current_addr, chunk_end)
            filepath = os.path.join(memory_dir, filename)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write("# Memory dump: {} - {}\n".format(hex(current_addr), hex(chunk_end)))
                f.write("# Segment: {}\n".format(seg_name))
                f.write("#" + "=" * 76 + "\n\n")
                f.write("# Address        | Hex Bytes                                       | ASCII\n")
                f.write("#" + "-" * 76 + "\n")
                
                addr = current_addr
                while addr < chunk_end:
                    line_bytes = []
                    for i in range(BYTES_PER_LINE):
                        if addr + i < chunk_end:
                            byte_val = ida_bytes.get_byte(addr + i)
                            if byte_val is not None:
                                line_bytes.append(byte_val)
                            else:
                                line_bytes.append(0)
                        else:
                            break
                    
                    if not line_bytes:
                        addr += BYTES_PER_LINE
                        continue
                    
                    hex_part = ""
                    for i, b in enumerate(line_bytes):
                        hex_part += "{:02X} ".format(b)
                        if i == 7:
                            hex_part += " "
                    remaining = BYTES_PER_LINE - len(line_bytes)
                    if remaining > 0:
                        if len(line_bytes) <= 8:
                            hex_part += " "
                        hex_part += "   " * remaining
                    
                    ascii_part = ""
                    for b in line_bytes:
                        if 0x20 <= b <= 0x7E:
                            ascii_part += chr(b)
                        else:
                            ascii_part += "."
                    
                    f.write("{:016X} | {} | {}\n".format(addr, hex_part.ljust(49), ascii_part))
                    
                    addr += BYTES_PER_LINE
                    total_bytes += len(line_bytes)
            
            file_count += 1
            current_addr = chunk_end
    
    print("\n[*] Memory Export Summary:")
    print("    Total bytes exported: {} ({:.2f} MB)".format(total_bytes, total_bytes / (1024*1024)))
    print("    Files created: {}".format(file_count))

def export_decompiled_functions(export_dir):
    """导出反编译函数"""
    decompile_dir = os.path.join(export_dir, "decompile")
    ensure_dir(decompile_dir)
    
    ea, ed = getSegAddr()
    
    total_funcs = sum(1 for _ in idautils.Functions(ea, ed))
    exported_funcs = 0
    failed_funcs = []
    
    print(f"[*] Found {total_funcs} functions to decompile...")
    
    for func in idautils.Functions(ea, ed):
        func_name = idc.get_func_name(func)
        
        try:
            # 处理ARM Thumb模式
            decompile_addr = func
            arm_or_thumb = idc.get_sreg(func, "T")
            if arm_or_thumb:
                decompile_addr = func | 1
            
            dec_obj = ida_hexrays.decompile(decompile_addr)
            if dec_obj is None:
                failed_funcs.append((func, func_name, "decompile returned None"))
                continue
            
            dec_str = str(dec_obj)
            callers = get_callers(func)
            callees = get_callees(func)
            
            output_lines = []
            output_lines.append("/*")
            output_lines.append(" * func-name: {}".format(func_name))
            output_lines.append(" * func-address: {}".format(hex(func)))
            output_lines.append(" * callers: {}".format(format_address_list(callers) if callers else "none"))
            output_lines.append(" * callees: {}".format(format_address_list(callees) if callees else "none"))
            output_lines.append(" */")
            output_lines.append("")
            output_lines.append(dec_str)
            
            # 使用地址作为文件名
            output_filename = "{}.c".format(hex(func))
            output_path = os.path.join(decompile_dir, output_filename)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(output_lines))
            
            exported_funcs += 1
            
            # 显示进度信息
            if exported_funcs % 50 == 0 or exported_funcs == total_funcs:
                progress_percent = (exported_funcs + len(failed_funcs)) / total_funcs * 100
                print("[+] Progress: {}/{} processed ({:.1f}%) - {} exported, {} failed".format(
                    exported_funcs + len(failed_funcs), total_funcs, progress_percent, 
                    exported_funcs, len(failed_funcs)))
                
        except Exception as e:
            failed_funcs.append((func, func_name, str(e)))
            continue
    
    print("\n[*] Decompilation Summary:")
    print("    Total functions: {}".format(total_funcs))
    print("    Exported: {}".format(exported_funcs))
    print("    Failed: {}".format(len(failed_funcs)))
    
    if failed_funcs:
        failed_log_path = os.path.join(export_dir, "decompile_failed.txt")
        with open(failed_log_path, 'w', encoding='utf-8') as f:
            for addr, name, reason in failed_funcs:
                f.write("{} {} - {}\n".format(hex(addr), name, reason))
        print("    Failed list saved to: decompile_failed.txt")

# 获取代码段的范围
def getSegAddr():
    """获取可执行代码段的范围，如果没有找到则返回整个程序的地址范围"""
    textStart = []
    textEnd = []

    # 尝试查找常见的代码段名称
    code_segment_names = ['.text', 'text', '__text', 'CODE', '.code', 
                          '__TEXT', '_text', 'code', '__CODE']
    
    for seg in idautils.Segments():
        seg_name = idc.get_segm_name(seg)
        # 检查段名是否匹配或者段是否可执行
        if (seg_name.lower() in [name.lower() for name in code_segment_names] or 
            idc.get_segm_attr(seg, idc.SEGATTR_PERM) & idaapi.SEGPERM_EXEC):
            tempStart = idc.get_segm_start(seg)
            tempEnd = idc.get_segm_end(seg)
            textStart.append(tempStart)
            textEnd.append(tempEnd)
    
    # 如果没有找到代码段，使用整个程序的地址范围
    if not textStart:
        print("[!] Warning: No code segment found, using entire address space")
        min_ea = idaapi.cvar.inf.min_ea
        max_ea = idaapi.cvar.inf.max_ea
        return min_ea, max_ea
    
    return min(textStart), max(textEnd)

class myForm(QtWidgets.QDialog):
    def __init__(self, parent=None):
        super(myForm, self).__init__(parent)

    def selectDir(self):
        dir_path = QtWidgets.QFileDialog.getExistingDirectory(self, 'Select a directory')
        return dir_path

class traceNatives(plugin_t):
    flags = PLUGIN_PROC
    comment = "FuncExporter"
    help = ""
    wanted_name = "FuncExporter"
    wanted_hotkey = ""

    def init(self):
        print("FuncExport(v0.3) plugin has been loaded.")
        print("Original author: https://github.com/jitcor")
        return PLUGIN_OK
    
    def run(self, arg):
        so_name = getSoName()
        form = myForm()
        dir_path = form.selectDir()
        
        if not dir_path:
            print("[!] No directory selected, export cancelled.")
            return
        
        # 创建导出目录
        save_path = os.path.join(dir_path, f"{so_name.split('.')[0]}_export")
        ensure_dir(save_path)
        
        print(f"[+] Export directory: {save_path}")
        print("")
        
        # 检查Hex-Rays是否可用
        if not ida_hexrays.init_hexrays_plugin():
            print("[!] Hex-Rays decompiler is not available!")
            print("[!] Other data will still be exported, but no decompilation.")
            has_hexrays = False
        else:
            has_hexrays = True
            print("[+] Hex-Rays decompiler initialized")
        print("")
        
        # 导出字符串
        print("[*] Exporting strings...")
        try:
            export_strings(save_path)
        except Exception as e:
            print(f"[!] Error exporting strings: {e}")
        print("")
        
        # 导出导入表
        print("[*] Exporting imports...")
        try:
            export_imports(save_path)
        except Exception as e:
            print(f"[!] Error exporting imports: {e}")
        print("")
        
        # 导出导出表
        print("[*] Exporting exports...")
        try:
            export_exports(save_path)
        except Exception as e:
            print(f"[!] Error exporting exports: {e}")
        print("")
        
        # 导出调用链分析
        print("[*] Exporting call graph analysis...")
        try:
            export_call_graph(save_path)
        except Exception as e:
            print(f"[!] Error exporting call graph: {e}")
        print("")
        
        # 导出内存
        print("[*] Exporting memory...")
        try:
            export_memory(save_path)
        except Exception as e:
            print(f"[!] Error exporting memory: {e}")
        print("")
        
        # 导出反编译函数
        if has_hexrays:
            print("[*] Exporting decompiled functions...")
            try:
                export_decompiled_functions(save_path)
            except Exception as e:
                print(f"[!] Error exporting decompiled functions: {e}")
        
        print("")
        print("=" * 60)
        print("[+] Export completed!")
        print("    Output directory: {}".format(save_path))
        print("=" * 60)

    def term(self):
        pass

def PLUGIN_ENTRY():
    return traceNatives()
