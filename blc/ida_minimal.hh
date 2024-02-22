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

// We can't include any ida sdk headers here because IDA 
// typedefs conflict with ghidra typedefs
// eg ida::uint8 != ghidra::uint8
// So we declare some IDA requirements here using compatible
// types

#ifndef __IDA_MINIMAL_H
#define __IDA_MINIMAL_H

#if defined(__NT__)                   // MS Windows
#include <windows.h>
#else
#include <stddef.h>
#include <stdarg.h>
#endif

#include <stdint.h>

#if defined(__cplusplus)
#define EXTERNC         extern "C"
#define INLINE          inline
#else
#define EXTERNC
#define INLINE          __inline
#endif

#if defined(__NT__)                   // MS Windows
  #define idaapi            __stdcall
  #define ida_export        idaapi
  #define ida_export_data __declspec(dllimport)
  #define idaman EXTERNC
#elif defined(__UNIX__)                 // for unix
  #define idaapi
  #if defined(__MAC__)
    #define idaman            EXTERNC __attribute__((visibility("default")))
  #else
    #if __GNUC__ >= 4
      #define idaman          EXTERNC __attribute__ ((visibility("default")))
    #else
      #define idaman          EXTERNC
    #endif
  #endif
  #define ida_export
  #define ida_export_data
#endif

#if defined(__GNUC__)
#define DEPRECATED __attribute__((deprecated))
#define NORETURN  __attribute__((noreturn))
#define PACKED __attribute__((__packed__))
#define AS_STRFTIME(format_idx) __attribute__((format(strftime, format_idx, 0)))
#define AS_PRINTF(format_idx, varg_idx) __attribute__((format(printf, format_idx, varg_idx)))
#define AS_SCANF(format_idx, varg_idx)  __attribute__((format(scanf, format_idx, varg_idx)))
#define WARN_UNUSED_RESULT __attribute__((__warn_unused_result__))
#else
#define DEPRECATED __declspec(deprecated)
#define NORETURN  __declspec(noreturn)
#define PACKED
#define AS_STRFTIME(format_idx)
#define AS_PRINTF(format_idx, varg_idx)
#define AS_SCANF(format_idx, varg_idx)
#define WARN_UNUSED_RESULT
#endif

/// Functions callable from any thread are marked with this keyword
#define THREAD_SAFE

//-------------------------------------------------------------------------
/// THREADS
//-------------------------------------------------------------------------

/// Thread callback function
typedef int idaapi qthread_cb_t(void *ud);

/// Thread opaque handle
#ifdef __cplusplus
#define OPAQUE_HANDLE(n) typedef struct __ ## n {} *n
#else
#define OPAQUE_HANDLE(n) typedef struct __ ## n  { char __dummy; } *n
#endif
OPAQUE_HANDLE(qthread_t);

/// Create a thread and return a thread handle
idaman THREAD_SAFE qthread_t ida_export qthread_create(qthread_cb_t *thread_cb, void *ud);

/// Free a thread resource (does not kill the thread)
/// (calls pthread_detach under unix)
idaman THREAD_SAFE void ida_export qthread_free(qthread_t q);

/// Wait a thread until it terminates
idaman THREAD_SAFE bool ida_export qthread_join(qthread_t q);

/// Forcefully kill a thread (calls pthread_cancel under unix)
idaman THREAD_SAFE bool ida_export qthread_kill(qthread_t q);

#define PLUGIN_SKIP  0  ///< Plugin doesn't want to be loaded
#define PLUGIN_OK    1  ///< Plugin agrees to work with the current database.
#define PLUGIN_KEEP  2  ///< Plugin agrees to work with the current database and wants to stay in the memory

#define ui_msg 23

typedef int ui_notification_t;

idaman void ida_export_data (idaapi*callui)(ui_notification_t what,...);

THREAD_SAFE AS_PRINTF(1, 0) inline void vmsg(const char *format, va_list va) {
   callui(ui_msg, format, va);
}

THREAD_SAFE AS_PRINTF(1, 2) inline void msg(const char *format, ...) {
   va_list va;
   va_start(va, format);
   vmsg(format, va);
   va_end(va);
}

idaman bool ida_export is_loaded(uint64_t ea);

idaman size_t ida_export get_func_qty(void);

idaman uint64_t ida_export get_item_end(uint64_t ea);

inline size_t get_item_size(uint64_t ea) { return get_item_end(ea) - ea; }

struct func_t;
idaman func_t *ida_export getn_func(size_t n);

idaman int64_t ida_export get_bytes(
        void *buf,
        int64_t size,
        uint64_t ea,
        int gmb_flags=0,
        void *mask=NULL);

// From IDA's lines.hpp

/// A typical color sequence looks like this:
///
/// #COLOR_ON COLOR_xxx text #COLOR_OFF COLOR_xxx
///
/// The first 2 items turn color 'xxx' on, then the text follows,
/// and the color is turned off by two last items.
///
/// For the convenience we've defined a set of macro definitions
/// and functions to deal with colors.
//@{

/// \defgroup color_esc Color escape characters
/// Initiate/Terminate a color tag
//@{
#define COLOR_ON        '\1'     ///< Escape character (ON).
                                 ///< Followed by a color code (::color_t).
#define COLOR_OFF       '\2'     ///< Escape character (OFF).
                                 ///< Followed by a color code (::color_t).
#define COLOR_ESC       '\3'     ///< Escape character (Quote next character).
                                 ///< This is needed to output '\1' and '\2'
                                 ///< characters.
#define COLOR_INV       '\4'     ///< Escape character (Inverse foreground and background colors).
                                 ///< This escape character has no corresponding #COLOR_OFF.
                                 ///< Its action continues until the next #COLOR_INV or end of line.

/// \defgroup COLOR_ Color tags
/// Specify a color for a syntax item
//@{
const char 
  COLOR_DEFAULT  = '\x01',         ///< Default
  COLOR_REGCMT   = '\x02',         ///< Regular comment
  COLOR_RPTCMT   = '\x03',         ///< Repeatable comment (comment defined somewhere else)
  COLOR_AUTOCMT  = '\x04',         ///< Automatic comment
  COLOR_INSN     = '\x05',         ///< Instruction
  COLOR_DATNAME  = '\x06',         ///< Dummy Data Name
  COLOR_DNAME    = '\x07',         ///< Regular Data Name
  COLOR_DEMNAME  = '\x08',         ///< Demangled Name
  COLOR_SYMBOL   = '\x09',         ///< Punctuation
  COLOR_CHAR     = '\x0A',         ///< Char constant in instruction
  COLOR_STRING   = '\x0B',         ///< String constant in instruction
  COLOR_NUMBER   = '\x0C',         ///< Numeric constant in instruction
  COLOR_VOIDOP   = '\x0D',         ///< Void operand
  COLOR_CREF     = '\x0E',         ///< Code reference
  COLOR_DREF     = '\x0F',         ///< Data reference
  COLOR_CREFTAIL = '\x10',         ///< Code reference to tail byte
  COLOR_DREFTAIL = '\x11',         ///< Data reference to tail byte
  COLOR_ERROR    = '\x12',         ///< Error or problem
  COLOR_PREFIX   = '\x13',         ///< Line prefix
  COLOR_BINPREF  = '\x14',         ///< Binary line prefix bytes
  COLOR_EXTRA    = '\x15',         ///< Extra line
  COLOR_ALTOP    = '\x16',         ///< Alternative operand
  COLOR_HIDNAME  = '\x17',         ///< Hidden name
  COLOR_LIBNAME  = '\x18',         ///< Library function name
  COLOR_LOCNAME  = '\x19',         ///< Local variable name
  COLOR_CODNAME  = '\x1A',         ///< Dummy code name
  COLOR_ASMDIR   = '\x1B',         ///< Assembler directive
  COLOR_MACRO    = '\x1C',         ///< Macro
  COLOR_DSTR     = '\x1D',         ///< String constant in data directive
  COLOR_DCHAR    = '\x1E',         ///< Char constant in data directive
  COLOR_DNUM     = '\x1F',         ///< Numeric constant in data directive
  COLOR_KEYWORD  = '\x20',         ///< Keywords
  COLOR_REG      = '\x21',         ///< Register name
  COLOR_IMPNAME  = '\x22',         ///< Imported name
  COLOR_SEGNAME  = '\x23',         ///< Segment name
  COLOR_UNKNAME  = '\x24',         ///< Dummy unknown name
  COLOR_CNAME    = '\x25',         ///< Regular code name
  COLOR_UNAME    = '\x26',         ///< Regular unknown name
  COLOR_COLLAPSED= '\x27',         ///< Collapsed line
  COLOR_FG_MAX   = '\x28';         ///< Max color number

#define SN_AUTO         0x20    ///< if set, make name autogenerated
#define SN_NOWARN       0x100   ///< don't display a warning if failed

idaman bool ida_export set_name(uint64_t ea, const char *name, int flags = 0);

#endif
