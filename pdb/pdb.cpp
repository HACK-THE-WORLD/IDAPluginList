
// IDA plugin to load function name information from PDB files
//      26-02-2008 Complete rewrite to use DIA API

#ifdef __NT__
#define USE_STANDARD_FILE_FUNCTIONS
#define _CRT_SECURE_NO_WARNINGS
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <objidl.h>
#  define PDB_PLUGIN

#include "stdafx.h"

#else
#  define ENABLE_REMOTEPDB
#endif

#include <memory>

#include <ida.hpp>
#include <idp.hpp>
#include <err.h>
#include <md5.h>
#include <dbg.hpp>
#include <auto.hpp>
#include <name.hpp>
#include <frame.hpp>
#include <loader.hpp>
#include <diskio.hpp>
#include <struct.hpp>
#include <typeinf.hpp>
#include <demangle.hpp>

#include <intel.hpp>
#include <network.hpp>
#include <workarounds.hpp>
int data_id;

#include "pdb.hpp"
#include "common.cpp"
#ifdef ENABLE_REMOTEPDB
// We only enable remote PDB fetching in case
// we are building the plugin, for the moment.
// While this is an annoying limitation, it's mostly
// because the pdbremote code requires that
// the 'win32' (stub) debugger be loadable, in order
// to work: Ideally, we should only use an rpc_client
// instance, but currently we channel PDB requests
// through the remote debugger connection.
// (Neither efd.exe, nor tilib.exe can use of a
//  running win32_remote.exe debugger instance for the
//  moment)
#  include "pdbremote.cpp"
#else
#  include "oldpdb.h"
#  include "msdia.cpp"
#endif
#include "tilbuild.cpp"


#include "sip.cpp"


//----------------------------------------------------------------------
static bool looks_like_function_name(const char *name)
{
  // this is not quite correct: the presence of an opening brace
  // in the demangled name indicates a function
  // we can have a pointer to a function and there will be a brace
  // but this logic is not applied to data segments
  if ( strchr(name, '(') != nullptr )
    return true;

  // check various function keywords
  static const char *const keywords[] =
  {
    "__cdecl ",
    "public: ",
    "virtual ",
    "operator ",
    "__pascal ",
    "__stdcall ",
    "__thiscall ",
  };
  for ( int i=0; i < qnumber(keywords); i++ )
    if ( strstr(name, keywords[i]) != nullptr )
      return true;
  return false;
}

//----------------------------------------------------------------------
bool pdb_ctx_t::check_for_ids(ea_t ea, const char *name)
{
  // Seems to be a GUID?
  const char *ptr = name;
  while ( *ptr == '_' )
    ptr++;

  static const char *const guids[] = { "IID", "DIID", "GUID", "CLSID", "LIBID", nullptr };
  static const char *const sids[] = { "SID", nullptr };

  struct id_info_t
  {
    const char *const *names;
    const char *type;
  };
  static const id_info_t ids[] =
  {
    { guids, "GUID x;" },
    { sids,  "SID x;" },
  };
  if ( !checked_types )
  {
    if ( get_named_type(nullptr, "GUID", NTF_TYPE) == 0 )
    {
      static const char decl[] = "typedef struct _GUID { unsigned long  Data1; unsigned short Data2; unsigned short Data3; unsigned char Data4[8];} GUID;";
      h2ti(nullptr, nullptr, decl, HTI_DCL, nullptr, nullptr, msg);
    }
    // SID type is pretty complex, so we won't add it manually but just check if it exists
    has_sid = get_named_type(nullptr, "SID", NTF_TYPE) != 0;
    checked_types = true;
  }
  for ( int k=0; k < qnumber(ids); k++ )
  {
    if ( k == 1 && !has_sid )
      continue;
    for ( const char *const *p2=ids[k].names; *p2; p2++ )
    {
      const char *guid = *p2;
      size_t len = strlen(guid);
      if ( strncmp(ptr, guid, len) == 0
        && (ptr[len] == '_' || ptr[len] == ' ') ) // space can be in demangled names
      {
        apply_cdecl(nullptr, ea, ids[k].type);
        return true;
      }
    }
  }
  if ( strncmp(name, "_guid", 5) == 0 )
  {
    apply_cdecl(nullptr, ea, ids[0].type);
    return true;
  }
  return false;
}

//----------------------------------------------------------------------
static bool is_data_prefix(ea_t ea, const char *name)
{
  static const char *const data_prefixes[] =
  {
    "__IMPORT_DESCRIPTOR",
    //"__imp_",             // imported function pointer
  };
  for ( int i=0; i < qnumber(data_prefixes); i++ )
    if ( strncmp(name, data_prefixes[i], strlen(data_prefixes[i])) == 0 )
      return true;

  // __real@xxxxxxxx            - floating point number, 4 bytes
  // __real@xxxxxxxxxxxxxxxx    - floating point number, 8 bytes
  if ( strncmp(name, "__real@", 7) == 0 )
  {
    const char *ptr = name + 7;
    const char *hex = ptr;
    while ( qisxdigit(*ptr) )
      ptr++;
    size_t len = ptr - hex;
    if ( len == 8 )
    {
      create_float(ea, 4);
      return true;
    }
    if ( len == 16 )
    {
      create_double(ea, 8);
      return true;
    }
    if ( len == 20 )
    { // i haven't seen this, but probably it exists too
      create_tbyte(ea, 10);
      return true;
    }
  }
  return false;
}

//-------------------------------------------------------------------------
// Names that we prefer to ignore
static bool ignore_name(const char *name)
{
  struct ida_local sfxlen_t
  {
    const char *const sfx;
    size_t len;       // strlen(sfx)
  };

  static const sfxlen_t unwanted_suffixes[] =
  {
    { "_epilog1_start", 14 },
  };

  size_t len = qstrlen(name);

  for ( auto &sfx : unwanted_suffixes )
  {
    if ( len > sfx.len && streq(&name[len-sfx.len], sfx.sfx) )
      return true;
  }

  // MSVS debug symbols may contain the temporary labels "Temp.00000001"
  if ( strneq(name, "Temp.", 5) )
  {
    const char *p = &name[5];
    if ( *p != '\0' )
    {
      for ( ; *p != '\0' && isdigit(*p); ++p )
        ;
      if ( *p == '\0' )
        return true;
    }
  }

  // _lc002_004933_
  if ( strneq(name, "_lc", 3) )
  {
    const char *p = &name[3];
    if ( isdigit(p[0])
      && isdigit(p[1])
      && isdigit(p[2])
      && p[3] == '_'
      && isdigit(p[4])
      && isdigit(p[5])
      && isdigit(p[6])
      && isdigit(p[7])
      && isdigit(p[8])
      && isdigit(p[9])
      && p[10] == '_' )
    {
      return true;
    }
  }

  return false;
}

//-------------------------------------------------------------------------
int pdb_ctx_t::get_utf16_encoding_idx()
{
  if ( utf16_encidx < 0 )
    utf16_encidx = add_encoding(inf_is_be() ? "UTF-16BE" : "UTF-16LE");
  return utf16_encidx;
}

//----------------------------------------------------------------------
// maybe_func: -1:no, 0-maybe, 1-yes, 2:no,but iscode
bool pdb_ctx_t::apply_name_in_idb(ea_t ea, const qstring &name, int maybe_func, uint32 the_machine_type)
{
  show_addr(ea); // so the user doesn't get bored

  if ( ignore_name(name.c_str()) )
    return true;

  // check for meaningless 'string' names
  if ( strncmp(name.c_str(), "??_C@_", 6) == 0 )
  {
    // ansi:    ??_C@_0<len>@xxx
    // unicode: ??_C@_1<len>@xxx
    // TODO: parse length?
    uint32 strtype = STRTYPE_C;
    if ( name[6] == '1' )
      strtype = make_str_type(STRTYPE_C_16, get_utf16_encoding_idx());
    create_strlit(ea, 0, strtype);
    return true;
  }

  qstring demangled;
  if ( maybe_func <= 0 && demangle_name(&demangled, name.c_str(), MNG_SHORT_FORM) > 0 )
  {
    if ( demangled == "`string'" )
    {
      int utf16_idx = get_utf16_encoding_idx();
      uint32 utf16_strtype = make_str_type(STRTYPE_C_16, utf16_idx);
      size_t s1 = get_max_strlit_length(ea, STRTYPE_C);
      size_t s2 = get_max_strlit_length(ea, utf16_strtype);
      create_strlit(ea, 0, s1 >= s2 ? STRTYPE_C : utf16_strtype);
      return true;
    }
  }

  // Renaming things immediately right here can lead to bad things.
  // For example, if the name is a well known function name, then
  // ida will immediately try to create a function. This is a bad idea
  // because IDA does not know exact function boundaries and will try
  // to guess them. Since the database has little information yet, there
  // is a big chance that the function will end up to be way too long.
  // That's why we collect names here and will rename them later.
  namelist[ea] = name;

  if ( check_for_ids(ea, name.c_str())
    || check_for_ids(ea, demangled.c_str())
    || is_data_prefix(ea, name.c_str())
    || maybe_func < 0 )
  {
    set_notcode(ea); // should not be code
    return true;
  }
  if ( maybe_func == 0 && get_mangled_name_type(name.c_str()) == MANGLED_DATA )
  {
    // NB: don't call set_notcode() here
    // since demangler may give false positives
    return true;
  }

  // do not automatically create functions in debugger segments
  segment_t *s = getseg(ea);
  if ( s == nullptr || !s->is_loader_segm() )
    return true;

  // ARMv7 PDBs don't use bit 0 for Thumb mode
  if ( ph.has_code16_bit() && the_machine_type != CV_CFL_ARM7 )
  {
    // low bit is Thumb/MIPS16 mode
    bool func16 = (ea & 1) != 0;
    ea &= ~1;
    if ( func16 )
    {
      // move the entry in namelist
      namelist.erase(ea|1);
      namelist[ea] = name;
    }
  }

  if ( maybe_func == 0 )
  {
    do
    {
      // check for function telltales
      if ( segtype(ea) != SEG_DATA
        && demangle_name(&demangled, name.c_str(), MNG_LONG_FORM) > 0
        && looks_like_function_name(demangled.c_str()) )
      {
        maybe_func = 1;
        break;
      }

      int stype = segtype(ea);
      if ( stype != SEG_NORM && stype != SEG_CODE ) // only for code or normal segments
        break;

      insn_t insn;
      if ( decode_insn(&insn, ea) == 0 )
        break;

      if ( processor_t::is_sane_insn(insn, 1) < 0 )
        break;
      maybe_func = 1;
    } while ( false );
  }
  if ( maybe_func == 1 )
    auto_make_proc(ea); // fixme: when we will implement lvars, we have to process these request
                        // before handling lvars
  return true;
}

//----------------------------------------------------------------------------
// These two funcs for old.cpp only
bool apply_name(ea_t ea, const qstring &name, int maybe_func)
{
  pdb_ctx_t &pv = *GET_MODULE_DATA(pdb_ctx_t);
  return pv.apply_name_in_idb(ea, name, maybe_func, pv.g_machine_type);
}

void load_vc_til(void)
{
  pdb_ctx_t &pv = *GET_MODULE_DATA(pdb_ctx_t);
  pv.load_vc_til();
}

//----------------------------------------------------------------------
void pdb_ctx_t::load_vc_til(void) const
{
  // We managed to load the PDB file.
  // It is very probably that the file comes from VC
  // Load the corresponding type library immediately
  if ( ph.id == PLFM_386 && pe.signature == PEEXE_ID )
  {
    if ( pe.is_userland() )
      add_til(pe.is_pe_plus() ? "mssdk64_win7" : "mssdk_win7", ADDTIL_INCOMP);
    else
      add_til(pe.is_pe_plus() ? "ntddk64_win7" : "ntddk_win7", ADDTIL_INCOMP);
  }
}

//----------------------------------------------------------------------------
class pdb_til_builder_t : public til_builder_t
{
  int npass;
public:
  pdb_til_builder_t(pdb_ctx_t &_pv, til_t *_ti, pdb_access_t *_pa)
    : til_builder_t(_pv, _ti, _pa), npass(0) {}

  virtual HRESULT before_iterating(pdb_sym_t &global_sym) override;
  virtual bool iterate_symbols_once_more(pdb_sym_t & /*global_sym*/) override
  {
    handled.clear();
    return ++npass == 1;
  }
  virtual void type_created(ea_t ea, int id, const char *name, const tinfo_t &tif) const override;
  virtual bool handle_symbol_at_ea(pdb_sym_t &sym, DWORD tag, ea_t ea, qstring &name) override;
  virtual void handle_function_type(pdb_sym_t &fun_sym, ea_t ea) override;
  virtual HRESULT handle_function_child(
        pdb_sym_t &fun_sym,
        ea_t ea,
        pdb_sym_t &child_sym,
        DWORD child_tag,
        DWORD child_loc_type) override;
};

//----------------------------------------------------------------------------
HRESULT pdb_til_builder_t::before_iterating(pdb_sym_t &)
{
  pv.load_vc_til();
  if ( default_compiler() == COMP_UNK )
    set_compiler_id(COMP_MS);
  return S_OK;
}

//----------------------------------------------------------------------------
void pdb_til_builder_t::type_created(ea_t ea, int id, const char *name, const tinfo_t &tif) const
{
  pv.check_tinfo(ea, id, name, tif);
}

//----------------------------------------------------------------------------
// add the annotation strings to 'ea'
// following types are commonly used in windows drivers
// 1) assertion:
// #define NT_ASSERT(_exp)
//     ((!(_exp)) ?
//         (__annotation(L"Debug", L"AssertFail", L#_exp),
//          DbgRaiseAssertionFailure(), FALSE) :
//         TRUE)
// 2) trace message
//
//   TMF:
//   2158e7d3-9867-cde3-18b5-9713c628abdf TEEDriver // SRC=Queue.c MJ= MN=
//   #typev Queue_c2319 207 "%0PowerDown = %10!x!" //   LEVEL=TRACE_LEVEL_VERBOSE FLAGS=TRACE_QUEUE
//   {
//   devExt->powerDown, ItemLong -- 10
//   }, Constant
//
// 3) trace message control
// WPP_DEFINE_CONTROL_GUID(Name,Guid,Bits) __annotation(L"TMC:", WPP_GUID_WTEXT Guid, _WPPW(WPP_STRINGIZE(Name)) Bits WPP_TMC_ANNOT_SUFIX);
//  expands into:
//
//  TMC:
//  0b67e6f7-ae91-470c-b4b6-dcd6a9034e18
//  TEEDriverTraceGuid
//  MYDRIVER_ALL_INFO
//  TRACE_DRIVER
//  TRACE_DEVICE
//  [..]
//  TRACE_BUS_DRIVER_LAYER
//
// In all other cases we just use plain __annotation(a,b,c,...)
// TODO: use anterior lines for big annotations (over 1KB)
static void apply_annotation(ea_t ea, const qstrvec_t &params)
{
  if ( params.empty() )
    return;

  qstring full_cmt;
  if ( params.size() >= 3 && params[0] == "Debug" && params[1] == "AssertFail" )
  {
    full_cmt.sprnt("NT_ASSERT(\"%s\"", params[2].c_str());
    for ( size_t i = 3; i < params.size(); i++ )
      full_cmt.cat_sprnt(",\n  \"%s\"", params[i].c_str());
    full_cmt.append(")");
  }
  else if ( params[0] == "TMF:" )
  {
    full_cmt = "__annotation(\"TMF:\"";
    bool add_newline = true;
    for ( size_t i = 1; i < params.size(); i++ )
    {
      full_cmt.cat_sprnt(",%s\"%s\"", add_newline ? "\n  " : " ", params[i].c_str());
      // print args betwen { } on one line
      if ( params[i] == "{" )
        add_newline = false;
      else if ( params[i] == "}" )
        add_newline = true;
    }
    full_cmt.append(")");
  }
  else
  {
    full_cmt.sprnt("__annotation(\"%s\"", params[0].c_str());
    for ( size_t i = 1; i < params.size(); i++ )
      full_cmt.cat_sprnt(", \"%s\"", params[i].c_str());
    full_cmt.append(")");
  }
  set_cmt(ea, full_cmt.c_str(), false);
}

//----------------------------------------------------------------------------
bool pdb_til_builder_t::handle_symbol_at_ea(
        pdb_sym_t &sym,
        DWORD tag,
        ea_t ea,
        qstring &name)
{
  int maybe_func = 0;
  switch ( tag )
  {
    case SymTagFunction:
    case SymTagThunk:
      maybe_func = 1;
      break;
    case SymTagBlock:
    case SymTagLabel:
    case SymTagFuncDebugStart:
    case SymTagFuncDebugEnd:
      maybe_func = 2;
      break;
    case SymTagData:
    case SymTagVTable:
      maybe_func = -1;
      break;
    case SymTagPublicSymbol:
      {
        BOOL b;
        if ( sym.get_function(&b) == S_OK && b )
          maybe_func = 1;
      }
      break;
    case SymTagAnnotation:
      {
        struct annotation_value_collector_t : public pdb_access_t::children_visitor_t
        {
          const til_builder_t *tb;
          qstrvec_t ann_params;
          HRESULT visit_child(pdb_sym_t &child) override
          {
            qstring v;
            if ( tb->get_variant_string_value(&v, child) )
              // set_cmt(ea, v.c_str(), false);
              ann_params.push_back(v);
            return S_OK;
          }
          annotation_value_collector_t(const til_builder_t *_tb)
            : tb(_tb) {}
        };
        annotation_value_collector_t avc(this);
        pdb_access->iterate_children(sym, SymTagNull, avc);
        apply_annotation(ea, avc.ann_params);
        maybe_func = segtype(ea) == SEG_CODE ? 2 /*no func, but code*/ : 0 /*unclear*/;
      }
      break;
    default:
      break;
  }

  // symbols starting with __imp__ cannot be functions
  if ( strncmp(name.c_str(), "__imp__", 7) == 0 )
  {
    if ( inf_is_64bit() )
      create_qword(ea, 8);
    else
      create_dword(ea, 4);
    maybe_func = -1;
  }

  BOOL iscode;
  if ( sym.get_code(&iscode) == S_OK )
  {
    if ( iscode )
    {
      if ( is_notcode(ea) )
      {
        // clear wrong notcode mark
        // (was seen happening with bogus SymTagData symbol for _guard_dispatch_icall_nop)
        clr_notcode(ea);
        create_insn(ea);
      }
    }
    else
    {
      // not a function
      maybe_func = -1;
    }
  }

  tpinfo_t tpi;
  if ( get_symbol_type(&tpi, sym, nullptr) )
  {
    // Apparently _NAME_ is a wrong symbol generated for file names
    // It has wrong type information, so correct it
    if ( tag == SymTagData && name == "_NAME_" && tpi.type.get_decltype() == BTF_CHAR )
      tpi.type = tinfo_t::get_stock(STI_ACHAR); // char []
    if ( tag == SymTagFunction )
    {
      // convert the type again, this time passing function symbol
      // this allows us to get parameter names and handle static class methods
      pdb_sym_t *func_sym = pdb_access->create_sym();
      pdb_sym_janitor_t janitor_pType(func_sym);
      if ( sym.get_type(func_sym) == S_OK )
      {
        tpinfo_t tpi2;
        if ( really_convert_type(&tpi2, *func_sym, &sym, SymTagFunctionType) == cvt_ok )
          tpi.type.swap(tpi2.type); // successfully retrieved
      }
    }
    if ( tpi.type.is_func() || tag == SymTagFunction )
    {
      maybe_func = 1;
      handle_function_type(sym, ea);
    }
    else
    {
      maybe_func = -1;
    }
    if ( npass != 0 )
    {
      bool use_ti = true;
      func_type_data_t fti;
      if ( tpi.type.get_func_details(&fti)
        && fti.empty()
        && fti.rettype.is_decl_void() )
      { // sometimes there are functions with linked FunctionType but no parameter or return type info in it
        // we get better results by not forcing type info on them
        use_ti = false;
      }
      if ( use_ti )
      {
        type_created(ea, 0, nullptr, tpi.type);
        apply_tinfo(ea, tpi.type, TINFO_STRICT);
      }
    }
  }
  else if ( maybe_func == 1 )
  {
    auto_make_proc(ea); // certainly a func
  }
  pv.apply_name_in_idb(ea, name, maybe_func, pdb_access->get_machine_type());
  return true;
}

//---------------------------------------------------------------------------
HRESULT pdb_til_builder_t::handle_function_child(
        pdb_sym_t &fun_sym,
        ea_t ea,
        pdb_sym_t &child_sym,
        DWORD child_tag,
        DWORD child_loc_type)
{
  LONG offset;
  DWORD reg_id;
  switch ( child_loc_type )
  {
    case LocIsEnregistered:
      if ( child_sym.get_registerId(&reg_id) == S_OK )
      {
        if ( enregistered_bug && reg_id > 0 )
          reg_id--;
        func_t *pfn = get_func(ea);
        qstring name;
        child_sym.get_name(&name);
        qstring canon;
        print_pdb_register(&canon, pdb_access->get_machine_type(), reg_id);
        if ( pfn != nullptr )
          add_regvar(pfn, pfn->start_ea, pfn->end_ea, canon.c_str(), name.c_str(), nullptr);
      }
      break;

    case LocIsRegRel:
      if ( child_sym.get_registerId(&reg_id) == S_OK
        && child_sym.get_offset(&offset) == S_OK
        && (is_frame_reg(reg_id) || is_stack_reg(reg_id)) )
        // attempt at handling both stack and frame regs (was ebp only)
      {
        func_t *pfn = get_func(ea);
        if ( pfn != nullptr )
        {
          qstring name;
          child_sym.get_name(&name);
          tpinfo_t tpi;
          if ( get_symbol_type(&tpi, child_sym, nullptr) )
          {
            opinfo_t mt;
            size_t size;
            flags_t flags;
            if ( get_idainfo_by_type(&size, &flags, &mt, tpi.type) )
            {
              // DIA's offset is bp-based, not frame-based like in IDA
              if ( is_frame_reg(reg_id) )
                offset -= pfn->fpd;
              else // SP-based; turn into frame-based
                offset -= pfn->frsize;
              // make sure the new variable is not overwriting the return address
              // for some reason some PDBs have bogus offsets for some params/locals...
              if ( !is_intel386(pdb_access->get_machine_type()) && !is_intel64(pdb_access->get_machine_type())
                || offset > 0
                || size <= -offset )
              {
                if ( define_stkvar(pfn, name.c_str(), offset, flags, &mt, size) )
                {
                  insn_t insn;
                  insn.ea = pfn->start_ea;
                  member_t *mptr = get_stkvar(nullptr, insn, *(op_t*)nullptr, offset); //lint !e413 deref null ptr
                  if ( mptr != nullptr )
                  {
                    struc_t *sptr = get_frame(pfn);
                    set_member_tinfo(sptr, mptr, 0, tpi.type, 0);
                    set_userti(mptr->id);
                  }
                }
              }
            }
          }
          else // no type info...
          {
            msg("%a: stkvar '%s' with no type info\n", ea, name.c_str());
          }
        }
      }
      break;
    default:
      return til_builder_t::handle_function_child(fun_sym, ea, child_sym,
                                                  child_tag, child_loc_type);
  }
  return S_OK;
}

//---------------------------------------------------------------------------
void pdb_til_builder_t::handle_function_type(pdb_sym_t &sym, ea_t ea)
{
  if ( npass == 0 )
  {
    if ( !create_insn(ea) )
      return;

    // add the address to the queue - this will help to determine better function boundaries
    auto_make_proc(ea);
  }
  else
  {
    ea_t end = BADADDR;
    DWORD64 ulLen;
    if ( sym.get_length(&ulLen) == S_OK )
      end = ea + asize_t(ulLen);
    ea_t next_planned = peek_auto_queue(ea+1, AU_PROC);

    // before adding a function, try to create all its instructions.
    // without this the frame analysis may fail.
    func_t fn(ea);
    find_func_bounds(&fn, FIND_FUNC_DEFINE);

    bool created = false;
    bool acceptable_end = end <= next_planned;   // end is wrong for fragmented functions
    if ( acceptable_end )
      created = add_func(ea, end);
    if ( !created )
      add_func(ea);

    til_builder_t::handle_function_type(sym, ea);
  }
}

//---------------------------------------------------------------------------
static HRESULT common_handler(pdb_ctx_t &pv, pdb_access_t &pdb_access)
{
  try
  {
    pdb_til_builder_t builder(pv, CONST_CAST(til_t *)(get_idati()), &pdb_access);
    pdb_sym_t *global = pdb_access.create_sym(pdb_access.get_global_symbol_id());
    pdb_sym_janitor_t janitor_global(global);
    return builder.build(*global);
  }
  catch ( const pdb_exception_t &e )
  {
    msg("Couldn't parse PDB data: %s\n", e.what.c_str());
    return E_FAIL;
  }
}

//---------------------------------------------------------------------------
#ifdef ENABLE_REMOTEPDB
// On Unix computers use remote_pdb_access
static HRESULT remote_handler(pdb_ctx_t &pv, const pdbargs_t &args)
{
  int chosen_remote_port = pv.pdb_remote_port;
  if ( pv.pdb_remote_port_64 != -1 && inf_is_64bit() )
    chosen_remote_port = pv.pdb_remote_port_64;
  remote_pdb_access_t remote_pdb_access(args,
                                        pv.pdb_remote_server.c_str(),
                                        chosen_remote_port,
                                        pv.pdb_remote_passwd.c_str());
  HRESULT hr = remote_pdb_access.open_connection();
  if ( hr == S_OK )
    hr = common_handler(pv, remote_pdb_access);
  return hr;
}
#endif


/*====================================================================
                      IDA PRO INTERFACE START HERE
====================================================================*/

//-------------------------------------------------------------------------
static const cfgopt_t g_opts[] =
{
  CFGOPT_R ("PDB_REMOTE_PORT",    pdb_ctx_t, pdb_remote_port,    0, 65535),
  CFGOPT_R ("PDB_REMOTE_PORT_64", pdb_ctx_t, pdb_remote_port_64, 0, 65535),
  CFGOPT_QS("_NT_SYMBOL_PATH",    pdb_ctx_t, full_sympath,       true),
  CFGOPT_QS("PDB_REMOTE_SERVER",  pdb_ctx_t, pdb_remote_server,  true),
  CFGOPT_QS("PDB_REMOTE_PASSWD",  pdb_ctx_t, pdb_remote_passwd,  true),
  CFGOPT_R ("PDB_NETWORK",        pdb_ctx_t, pdb_network,        PDB_NETWORK_OFF, PDB_NETWORK_ON),
  CFGOPT_R("PDB_PROVIDER",		  pdb_ctx_t, pdb_provider,       PDB_PROVIDER_MSDIA, PDB_PROVIDER_PDBIDA),
  CFGOPT_QS("PDB_MSDIA_FALLBACK", pdb_ctx_t, opt_fallback,       true),
};

//----------------------------------------------------------------------
#ifndef ENABLE_REMOTEPDB
static uint32 get_machine_from_idb(const processor_t &ph)
{
  uint32 mt;
  switch ( ph.id )
  {
    case PLFM_ARM:
      mt = CV_CFL_ARM6;
      break;
    case PLFM_MIPS:
      mt = CV_CFL_MIPSR4000;
      break;
    case PLFM_PPC:
      mt = inf_is_be() ? CV_CFL_PPCBE : CV_CFL_PPCFP;
      break;
    case PLFM_SH:
      mt = CV_CFL_SH4;
      break;
    case PLFM_IA64:
      mt = CV_CFL_IA64;
      break;
    case PLFM_386:
    default:
      mt = CV_CFL_80386;
      break;
  }
  return mt;
}
#endif

//----------------------------------------------------------------------
void pdb_ctx_t::init_sympaths()
{
  // user specified symbol path?
  full_sympath.qclear();
  read_config_file2("pdb", g_opts, qnumber(g_opts), nullptr, nullptr, 0, this);
  if (pdb_provider != PDB_PROVIDER_MSDIA)
  {
	  msg("PDB: This modified version of PDB plug-in currently only supports MSDIA interface\n");
  }

  qstring env_sympath;
  if ( qgetenv("_NT_SYMBOL_PATH", &env_sympath) )
    full_sympath.swap(env_sympath);

  // default symbol search path
  if ( full_sympath.empty() )
  {
    char cache_path[QMAXPATH];
    #ifdef __NT__
    if ( !GetTempPath(sizeof(cache_path), cache_path) )
      cache_path[0] = '\0';
    else
      qstrncat(cache_path, "ida", sizeof(cache_path));
    #else
    qstring tmpdir;
    if ( !qgetenv("TMPDIR", &tmpdir) && !qgetenv("TMP", &tmpdir) )
      tmpdir = "/tmp";
    qmakepath(cache_path, sizeof(cache_path), tmpdir.c_str(), "ida", nullptr);
    if ( !qisdir(cache_path) && qmkdir(cache_path, 0777) != 0 )
      cache_path[0] = '\0';
    #endif
    full_sympath.sprnt("%s%s%s", g_spath_prefix, cache_path, g_spath_suffix);
  }
  deb(IDA_DEBUG_DBGINFO, "PDB: _NT_SYMBOL_PATH=%s\n", full_sympath.c_str());

  if ( opt_provider != 0 )
    pdb_provider = opt_provider;
}

//----------------------------------------------------------------------
#define MAX_DISP_PATH 80
// If path name is too long then replace some directories with "...."
static qstring truncate_path(const qstring &path)
{
  qstring str = path;
  int len = str.length();
  if ( len > MAX_DISP_PATH )
  {
    char slash = '\\';
    size_t start = str.find(slash);
    if ( start == qstring::npos )
    {
      slash = '/';
      start = str.find(slash);
    }
    if ( start != qstring::npos )
    {
      size_t end = str.rfind(slash);
      size_t prev_start;
      do
      {
        prev_start = start;
        start = str.find(slash, start + 1);
      } while ( len - (end - start) < MAX_DISP_PATH );
      start = prev_start + 1;
      if ( end > start )
      {
        str.remove(start, end - start);
        str.insert(start, "....");
      }
    }
  }
  return str;
}

//----------------------------------------------------------------------------
static bool read_pdb_signature(pdb_signature_t *pdb_sign)
{
  netnode penode(PE_NODE);
  rsds_t rsds;
  size_t size = sizeof(rsds_t);
  if ( penode.getblob(&rsds, &size, 0, RSDS_TAG) != nullptr && size == sizeof(rsds_t) ) // RSDS
  {
    pdb_sign->age = rsds.age;
    pdb_sign->sig = 0;
    memcpy(pdb_sign->guid, &rsds.guid, sizeof(pdb_sign->guid));
    CASSERT(sizeof(pdb_sign->guid) == sizeof(rsds.guid));
  }
  else
  {
    cv_info_pdb20_t nb10;
    size = sizeof(nb10);
    if ( penode.getblob(&nb10, &size, 0, NB10_TAG) != nullptr && size == sizeof(nb10) ) // NB10
    {
      pdb_sign->age = nb10.age;
      pdb_sign->sig = nb10.signature;
    }
    else
    {
      return false;
    }
  }
  return true;
}

//----------------------------------------------------------------------------
// moved into a separate function to diminish the stack consumption
static qstring get_input_path()
{
  char input_path[QMAXPATH];
  if ( get_input_file_path(input_path, sizeof(input_path)) <= 0 )
    input_path[0] = '\0';
  return input_path;
}

//--------------------------------------------------------------------------
static int idaapi details_modcb(int fid, form_actions_t &fa)
{
  switch ( fid )
  {
    // "Types only"
    case 20:
      {
        ushort c;
        if ( fa.get_checkbox_value(20, &c) )
          fa.enable_field(10, c == 0); // enable/disable address field
      }
      break;
  }

  return 1;
}

//-------------------------------------------------------------------------
static void set_file_by_ext(pdbargs_t *args, const char *buf)
{
  const char *ext = get_file_ext(buf);
  if ( ext != nullptr && strieq(ext, "pdb") )
  {
    args->pdb_path = buf;
    args->input_path.clear();
  }
  else
  {
    args->input_path = buf;
    args->pdb_path.clear();
  }
}

//----------------------------------------------------------------------------
static bool ask_pdb_details(pdbargs_t *args)
{
  netnode penode(PE_NODE);
  args->loaded_base = penode.altval(PE_ALT_IMAGEBASE);

  static const char form[] =
    "Load PDB file\n"
    "%/"
    "<#Specify the path to the file to load symbols for#~I~nput file:f:0:64::>\n"
    "<#Specify the loading address of the exe/dll file#~A~ddress   :N10::64::>\n"
    "<#Load only types, do not rename program locations#~T~ypes only:C20>>\n"
    "Note: you can specify either a .pdb, or an .exe/.dll file name.\n"
    "In the latter case, IDA will try to find and load\n"
    "the PDB specified in its debug directory.\n"
    "\n";

  char buf[QMAXPATH];
  const char *src = nullptr;
  if ( !args->pdb_path.empty() )
    src = args->pdb_path.begin();
  else if ( !args->input_path.empty() )
    src = args->input_path.begin();
  if ( src == nullptr )
    src = "*.pdb";

  qstrncpy(buf, src, sizeof(buf));

  CASSERT(sizeof(args->loaded_base) == sizeof(ea_t));
  sval_t typesonly = (args->flags & PDBFLG_ONLY_TYPES) != 0;
  if ( !ask_form(form, details_modcb, buf, &args->loaded_base, &typesonly) )
    return false;

  set_file_by_ext(args, buf);

  setflag(args->flags, PDBFLG_ONLY_TYPES, typesonly != 0);

  return true;
}

//-------------------------------------------------------------------------
static bool get_details_from_netnode(pdbargs_t *args)
{
  netnode pdbnode;
  pdbnode.create(PDB_NODE_NAME);

  args->loaded_base = pdbnode.altval(PDB_DLLBASE_NODE_IDX);
  if ( args->loaded_base == 0 )
  {
    msg("PDB: PDB_CC_USER_WITH_DATA called without an imagebase, cannot proceed\n");
fail:
    // set failure result
    pdbnode.altset(PDB_DLLBASE_NODE_IDX, 0);
    return false;
  }

  // TODO dllname shouldn't be needed when we're reading from debugger memory
  qstring tmp;
  pdbnode.supstr(&tmp, PDB_DLLNAME_NODE_IDX);
  if ( tmp.empty() )
  {
    msg("PDB: PDB_CC_USER_WITH_DATA called without a filename, cannot proceed\n");
    goto fail;
  }

  set_file_by_ext(args, tmp.c_str());

  bool typesonly = pdbnode.altval(PDB_TYPESONLY_NODE_IDX) != 0;
  setflag(args->flags, PDBFLG_ONLY_TYPES, typesonly);

  return true;
}

//-------------------------------------------------------------------------
static bool get_pdb_path(pdbargs_t *args, netnode penode)
{
  penode.supstr(&args->pdb_path, PE_SUPSTR_PDBNM);

  return !args->pdb_path.empty(); // do not ask to load pdb with empty name
}

//-------------------------------------------------------------------------
static bool get_details_from_pe(pdbargs_t *args)
{
  netnode penode(PE_NODE);
  if ( !get_pdb_path(args, penode) )
    return false;
  args->input_path = get_input_path();
  args->loaded_base = penode.altval(PE_ALT_IMAGEBASE);

  return ask_yn(ASKBTN_YES,
                "AUTOHIDE REGISTRY\nHIDECANCEL\n"
                "The input file was linked with debug information\n"
                " and the symbol filename is:\n"
                "\"%s\"\n"
                "Do you want to look for this file at the specified path\n"
                "and the Microsoft Symbol Server?\n",
                args->pdb_path.c_str()) == ASKBTN_YES;
}

//-------------------------------------------------------------------------
static bool ask_for_pdb_file(pdbargs_t *pdbargs, const char *err_str)
{
  qstring disp_path = truncate_path(pdbargs->input_path);
  if ( ask_yn(ASKBTN_YES,
              "HIDECANCEL\n"
              "AUTOHIDE REGISTRY\n"
              "%s: failed to load pdb info.\n%s\n"
              "Do you want to browse for the pdb file on disk?",
              disp_path.c_str(),
              err_str == nullptr ? "" : err_str) == ASKBTN_YES )
  {
    char *pdb_file = ask_file(false, "*.pdb", "Choose PDB file");
    if ( pdb_file != nullptr )
    {
      pdbargs->pdb_path = pdb_file;
      return true;
    }
  }
  return false;
}

//-------------------------------------------------------------------------
bool pdb_ctx_t::apply_debug_info(pdbargs_t &pdbargs)
{
  // we may run out of memory on huge pdb files. prefer to keep the partial
  // idb file in this case.
  bool restore_kill_flag = is_database_flag(DBFL_KILL);
  clr_database_flag(DBFL_KILL);

  netnode pdbnode;
  if ( pdbargs.is_pdbfile() )
    pdbnode.create(PDB_NODE_NAME);

  init_sympaths();
  pdbargs.spath = full_sympath;

  setflag(pdbargs.flags, PDBFLG_USE_HTTP, use_http(pdbargs.is_pdbfile()));

  bool ok = true;
  HRESULT hr = E_FAIL;

  {
    msg("PDB: using MSDIA provider\n");
#ifdef ENABLE_REMOTEPDB
    hr = remote_handler(*this, pdbargs);
#else
    bool was_load_error = false;
LOAD_PDB:
    try
    {
      pdb_session_ref_t ref;
      hr = ref.open_session(pdbargs);
      if ( hr == S_OK )
        hr = common_handler(*this, *ref.session->pdb_access);
    }
    catch ( const std::bad_alloc & )
    {
      warning("It appears IDA has run out of memory while loading the PDB file.\n"
              "This can happen when using the DIA SDK dll with big and/or corrupt PDBs.\n"
              "While you will now be able to continue your work, IDA cannot proceed with PDB parsing, sorry.\n\n"
              "It is also HIGHLY recommended that you save the database as soon as possible,\n"
              "quit, and restart IDA with that database.");
      hr = E_PDB_OUT_OF_MEMORY;
      was_load_error = true;
    }
#endif

    if ( pdbargs.input_path.empty() )
      pdbargs.input_path = pdbargs.pdb_path;

    if ( FAILED(hr) )
    {
      ok = false;
#ifndef ENABLE_REMOTEPDB
      const char *err_str = pdberr(hr);
      msg("PDB: could not process file \"%s\" with DIA: %s\n", pdbargs.input_path.c_str(), err_str);
      pdberr_suggest_vs_runtime(hr);

      // DIA interface failed, try the old methods
      if ( hr != E_PDB_INVALID_SIG
        && hr != E_PDB_INVALID_AGE
        && hr != E_PDB_NOT_FOUND
        && hr != E_PDB_INVALID_EXECUTABLE
        && !inf_test_mode() )
      {
        g_machine_type = get_machine_from_idb(ph); // See 'g_machine_type' comment above
        ok = old_pdb_plugin(pdbargs.loaded_base, pdbargs.input_path.c_str(), pdbargs.spath.c_str());
        if ( ok )
          msg("Old method of loading PDB files (dbghelp) was successful\n");
      }
      if ( !was_load_error && !ok )
      {
        was_load_error = true;
        if ( ask_for_pdb_file(&pdbargs, err_str) )
        {
          ok = true; // reset to default
          goto LOAD_PDB;
        }
      }
#else
      if ( !pdbargs.is_dbg_module() ) // called as main plugin routine
        warning("IDA could not open \"%s\". Please check that the file "
                "exists on the remote computer.", pdbargs.fname());
      else
        msg("No PDB information found for \"%s\"\n", pdbargs.fname());
#endif
    }
  }

  if ( ok && (pdbargs.flags & PDBFLG_ONLY_TYPES) == 0 )
  {
    // Now all information is loaded into the database (except names)
    // We are ready to use names.
    int counter = 0;
    for ( namelist_t::iterator p=namelist.begin(); p != namelist.end(); ++p )
    {
      ea_t ea = p->first;
      // do not override name for COFF file
      if ( pdbargs.is_pdbfile() || !has_name(get_flags(ea)) )
      {
        if ( pdbargs.is_dbg_module() )
          counter += set_debug_name(ea, p->second.c_str());
        else
          counter += force_name(ea, p->second.c_str());
      }
      // Every now & then, make sure the UI has had a chance to refresh.
      if ( (counter % 10) == 0 )
        user_cancelled();
    }
    namelist.clear();
    msg("PDB: total %d symbol%s loaded for \"%s\"\n",
        counter,
        counter != 1 ? "s" : "",
        pdbargs.input_path.c_str());
  }

  pdbnode.altset(PDB_DLLBASE_NODE_IDX, ok);
  check_added_types();

  // we have to restore the kill flag; otherwise the logic of the other parts
  // of ida may change. for example, in the absence of DBFL_KILL we remember
  // the idb path in the idb history (displayed in the File menu)
  if ( restore_kill_flag )
    set_database_flag(DBFL_KILL);

  return ok;
}

//----------------------------------------------------------------------------
bool idaapi pdb_ctx_t::run(size_t _call_code)
{


  // PDB
  pdbargs_t pdbargs;
  if ( inf_get_filetype() != f_PE && !is_miniidb() )
    pdbargs.flags |= PDBFLG_ONLY_TYPES;

  netnode penode(PE_NODE);
  penode.valobj(&pe, sizeof(pe));

  bool ok = false;
  switch ( (pdb_callcode_t)_call_code )
  {
    case PDB_CC_USER:
      // user explicitly invoked the plugin
      ok = ask_pdb_details(&pdbargs);
      // pdb_path, input_path: only one is set (depending on the file
      //                       extension), the other is cleared
      // loaded_base: specified by user (default obtained from PE)
      break;
    case PDB_CC_USER_WITH_DATA:
      // user invoked the plugin programmatically
      ok = get_details_from_netnode(&pdbargs);
      // pdb_path, input_path: only one is set (depending on the file
      //                       extension), the other is cleared
      // loaded_base: specified by user
      break;
    case PDB_CC_IDA:
      // IDA decided to call the plugin
      ok = get_details_from_pe(&pdbargs);
      // pdb_path: obtained from PE
      // input_path: IDA's input file name
      // loaded_base: obtained from PE
      break;
    default:
      break;
  }

  if ( ok )
  {
    // read pdb signature from the database, if any
    if ( !read_pdb_signature(&pdbargs.pdb_sign) )
    {
      // make it invalid but not empty
      // so that check_and_load_pdb() does not fail silently
      pdbargs.pdb_sign.age = 0xFFFFFFFF;
    }

    apply_debug_info(pdbargs);
  }

  return true;
}

//--------------------------------------------------------------------------
void pdb_ctx_t::parse_options(bool *opt_skip)
{
  *opt_skip = false;
  qstring opts(get_plugin_options("pdb"));
  if ( opts.empty() )
    return;
  char *opt = opts.begin();
  opt_provider = 0;
  opt_fallback = -1;
  do
  {
    char *end = qstrchr(opt, ':');
    if ( end != nullptr )
      *end++ = '\0';

    if ( streq(opt, "off") )
    {
      *opt_skip = true;
    }
    else if ( streq(opt, "msdia") )
    {
      opt_provider = PDB_PROVIDER_MSDIA;
    }
    else
    {
      error("AUTOHIDE NONE\n"
            "Wrong option for the PDB plugin.\n"
            "\n"
            "The valid options are:\n"
            "off     do not load plugin\n"
            "msdia   use MSDIA provider\n");
    }

    if ( end == nullptr )
      break;
    opt = end;
  } while ( true );
}

//--------------------------------------------------------------------------
// initialize plugin
static plugmod_t *idaapi init()
{
  auto pv = std::unique_ptr<pdb_ctx_t>(new pdb_ctx_t);
  bool opt_skip;
  pv->parse_options(&opt_skip);
  if ( opt_skip )
    return nullptr;
  register_srcinfo_provider(pv->pdb_srcinfo_provider);

  auto plugmod = pv.release();
  set_module_data(&data_id, plugmod);
  return plugmod;
}

//--------------------------------------------------------------------------
ssize_t idaapi pdb_ctx_t::on_event(ssize_t event_id, va_list va)
{
  qnotused(event_id);
  qnotused(va);
  return 0;                     // event is not processed
}

//--------------------------------------------------------------------------
pdb_ctx_t::pdb_ctx_t() : ph(PH)
{
  hook_event_listener(HT_IDP, this);
  memset(&pe, 0, sizeof(pe));
  alloc_pdb_srcinfo_provider();
  g_machine_type = CV_CFL_80386;
}

//--------------------------------------------------------------------------
// terminate
pdb_ctx_t::~pdb_ctx_t()
{
  namelist.clear();
  unregister_srcinfo_provider(pdb_srcinfo_provider);
  free_pdb_srcinfo_provider();
  clr_module_data(data_id);
}

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_MOD | PLUGIN_HIDE | PLUGIN_MULTI, // plugin flags:
  init,                 // initialize
  nullptr,              // terminate. this pointer may be nullptr.
  nullptr,              // invoke plugin

  // long comment about the plugin
  // it could appear in the status line
  // or as a hint
  "Load debug information from a PDB file",

  // multiline help about the plugin
  "PDB file loader\n"
  "\n"
  "This module allows you to load debug information about function names\n"
  "from a PDB file.\n"
  "\n"
  "The PDB file should be in the same directory as the input file\n",

  // the preferred short name of the plugin
  "Load PDB file (dbghelp 4.1+)",
  // the preferred hotkey to run the plugin
  ""
};


//lint -esym(766, md5.h, diskio.hpp) Unused header files.
