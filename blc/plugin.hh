/*
   Source for the blc IdaPro plugin
   Copyright (c) 2019 Chris Eagle

   This program is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by the Free
   Software Foundation; either version 2 of the License, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful, but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
   FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
   more details.

   You should have received a copy of the GNU General Public License along with
   this program; if not, write to the Free Software Foundation, Inc., 59 Temple
   Place, Suite 330, Boston, MA 02111-1307 USA
*/

#ifndef __BLC_PLUGIN_H
#define __BLC_PLUGIN_H

#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <stdint.h>

using std::istream;
using std::ostream;
using std::string;
using std::map;
using std::vector;
   
#include "ast.hh"

extern string ghidra_dir;
//extern int blc_index;

typedef void (*arch_setup_t)(uint64_t start, uint64_t end);
typedef map<int,arch_setup_t> arch_map_t;

extern arch_map_t arch_map;

int get_proc_id();

void init_ida_ghidra();

void get_ida_bytes(uint8_t *buf, uint64_t size, uint64_t ea);

int64_t get_name(string &name, uint64_t ea, int flags);

int64_t get_func_name(string &name, uint64_t ea);

bool is_function_start(uint64_t ea);

void get_input_file_path(string &path);

bool get_saved_sleigh_id(string &sleigh);
bool set_saved_sleigh_id(string &sleigh);
bool get_sleigh_id(string &sleigh);

bool does_func_return(/*func_t*/ void *f);

uint64_t get_func_start(/*func_t*/ void *f);

uint64_t get_func_start(uint64_t ea);
uint64_t get_func_end(uint64_t ea);

int do_decompile(uint64_t start_ea, uint64_t end_ea, Function **ast);

const char *tag_remove(const char *tagged);

bool is_thumb_mode(uint64_t ea);

//is ea a function internal jump target, if so 
//return true and place its name in name
//else return false
bool is_code_label(uint64_t ea, string &name);

//is ea an external function, if so 
//return true and place its import table address in fptr
//else return false
bool is_extern_addr(uint64_t ea);
bool is_external_ref(uint64_t ea, uint64_t *fptr);
bool is_extern(const string &name);

//is ea a library function, if so 
//return true
//else return false
bool is_library_func(const string &name);

bool is_named_addr(uint64_t ea, string &name);

bool is_pointer_var(uint64_t ea, uint32_t size, uint64_t *tgt);

bool is_read_only(uint64_t ea);

bool address_of(const string &name, uint64_t *ea);

bool simplify_deref(const string &name, string &new_name);

void adjust_thunk_name(string &name);

void mips_setup(uint64_t start, uint64_t end);

bool get_value(uint64_t addr, uint64_t *val);

bool get_string(uint64_t addr, string &str);
bool get_string(string name, string &str);

bool ghidra_init(void);
void ghidra_term(void);

#endif

