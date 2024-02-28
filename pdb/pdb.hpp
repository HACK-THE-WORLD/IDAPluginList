//
// Copyright (c) 2005-2024 Hex-Rays SA <support@hex-rays.com>
// ALL RIGHTS RESERVED.
//
#pragma once
#include <idp.hpp>
#include <idd.hpp>
#include <typeinf.hpp>
#include "../../ldr/pe/pe.h"

#define PDB_NODE_NAME             "$ pdb"
#define PDB_DLLBASE_NODE_IDX       0
#define PDB_DLLNAME_NODE_IDX       0
#define PDB_LOADING_WIN32_DBG      1
#define PDB_TYPESONLY_NODE_IDX     2

enum pdb_callcode_t
{
  // user invoked 'load pdb' command, load pdb for the input file.
  // after invocation, result (boolean) is stored in: netnode(PDB_NODE_NAME).altval(PDB_DLLBASE_NODE_IDX)
  PDB_CC_USER = 0,
  // ida decided to call the plugin itself
  PDB_CC_IDA  = 1,
  // load additional pdb. This is semantically the same as
  // PDB_CC_USER (i.e., "File > Load file > PDB file..."), except
  // it won't ask the user for the data; rather it expects it in
  // netnode(PDB_NODE_NAME):
  //   load_addr: netnode(PDB_NODE_NAME).altval(PDB_DLLBASE_NODE_IDX)
  //   dll_name:  netnode(PDB_NODE_NAME).supstr(PDB_DLLNAME_NODE_IDX)
  PDB_CC_USER_WITH_DATA = 3,
  // load debug info from the COFF file
  // ida decided to call the plugin itself
  //   dbginfo_params_t: netnode(DBGINFO_PARAM_NODE_NAME).supval(DBGINFO_PARAMS_KEY)
  PDB_CC_IDA_COFF = 4,
};

//----------------------------------------------------------------------
struct pdb_signature_t
{
  uint32 guid[4]; // if all zeroes, then consider as non-existing
  uint32 sig;
  uint32 age;
  pdb_signature_t(void) { memset(this, 0, sizeof(*this)); }
};

//----------------------------------------------------------------------------
struct pdbargs_t
{
  qstring pdb_path;     // Path to PDB file.
  qstring input_path;   // Path to PE file with associated PDB.
  pdb_signature_t pdb_sign;
  qstring spath;
  ea_t loaded_base;
  void *user_data;
  uint32 flags;
#define PDBFLG_DBG_MODULE  0x0001
#define PDBFLG_ONLY_TYPES  0x0002
#define PDBFLG_EFD         0x0004
#define PDBFLG_COFF_FILE   0x0008
#define PDBFLG_IS_MINIPDB  0x0010
#define PDBFLG_USE_HTTP    0x0100

  pdbargs_t(void)
    : loaded_base(BADADDR),
      user_data(nullptr),
      flags(0)
  {}

  // If true, we are in a debugging session and the file specified by
  // input_path is an additional module that has been loaded by the
  // debugger itself.
  bool is_dbg_module(void) const
  {
    return (flags & PDBFLG_DBG_MODULE) != 0;
  }
  // PDB?
  bool is_pdbfile(void) const { return (flags & PDBFLG_COFF_FILE) == 0; }
  bool use_http() const { return (flags & PDBFLG_USE_HTTP) != 0; }

  const char *fname(void) const
  {
    return !pdb_path.empty() ? pdb_path.begin() : input_path.c_str();
  }
};

//----------------------------------------------------------------------------
struct pdb_ctx_t : public plugmod_t, public event_listener_t
{
  processor_t &ph;

  // PDB search path (in _NT_SYMBOL_PATH format)
  qstring full_sympath;

  peheader_t pe;

  // config options
  int  pdb_remote_port = DEBUGGER_PORT_NUMBER;
  int  pdb_remote_port_64 = -1;
  qstring pdb_remote_server;
  qstring pdb_remote_passwd;
#define PDB_PROVIDER_MSDIA  1   // use MSDIA local/remote provider
#define PDB_PROVIDER_PDBIDA 2   // use PDBIDA provider
  uint pdb_provider = PDB_PROVIDER_MSDIA;
#define PDB_NETWORK_OFF 0   // local directories search only
#define PDB_NETWORK_PE  1   // local directories search for COFF, full search for PE
#define PDB_NETWORK_ON  2   // no restrictions
  uint pdb_network = PDB_NETWORK_PE;
  bool use_http(bool is_pe) const
  {
    bool ok = pdb_network == PDB_NETWORK_PE && is_pe
           || pdb_network == PDB_NETWORK_ON;
    deb(IDA_DEBUG_DBGINFO, ok ? "PDB: symbol servers will be used\n"
                              : "PDB: local directories search only\n");
    return ok;
  }

  // Plugin options
  uint opt_provider = 0;
  // -1 don't specified
  // 0  set PDB_FALLBACK to false
  // 1  set PDB_FALLBACK to true
  bool opt_fallback = -1;

  using namelist_t = std::map<ea_t, qstring>;
  namelist_t namelist;

  // srcinfo provider
  class pdb_provider_t *pdb_srcinfo_provider = nullptr;

  pdb_ctx_t();
  virtual ~pdb_ctx_t();
  virtual bool idaapi run(size_t arg) override;
  virtual ssize_t idaapi on_event(ssize_t code, va_list va) override;

  void parse_options(bool *opt_skip);

  void init_sympaths();
  void load_vc_til(void) const;

  // maybe_func: -1:no, 0-maybe, 1-yes, 2:no,but iscode
  bool apply_name_in_idb(ea_t ea, const qstring &name, int maybe_func, uint32 the_machine_type);
  bool apply_debug_info(pdbargs_t &pdbargs);

  // printable register name
  bool get_pdb_register_info(int *p_reg, uint64 *p_mask, int machine, int reg);

  // Because we need to be able to call the 'old' pdb plugin
  // code, which knows nothing about the til_builder_t (and
  // thus its 'machine_type' field, and also because, at the
  // very time we call the old pdb code, our til_builder_t
  // instance will have been long forgotten and destroyed,
  // we must keep this machine type information somewhere.
  uint32 g_machine_type = 0;  // will be set to CV_CFL_80386 in ctor

private:
  //-------------------------------------------------------------------------
  int utf16_encidx = -1;
  int get_utf16_encoding_idx();

  bool checked_types = false;
  bool has_sid       = false;
  bool check_for_ids(ea_t ea, const char *name);

  void alloc_pdb_srcinfo_provider();
  void free_pdb_srcinfo_provider();

public:
  //-------------------------------------------------------------------------
  //#define  CHECK_CREATED_TYPES
#ifdef CHECK_CREATED_TYPES
  struct type_to_check_t
  {
    // one of the following 3 will be valid:
    ea_t ea;
    int id;
    qstring name;

    // the type itself
    tinfo_t type;
  };

  qvector<type_to_check_t> types_to_check;
  int check_n = 0;

  void check_tinfo(ea_t ea, int id, const char *name, const tinfo_t &tif)
  {
    type_to_check_t &tc = types_to_check.push_back();
    tc.ea = ea;
    tc.id = id;
    tc.name = name;
    tc.type = tif;
  }

  void check_added_types(void)
  {
    for ( const auto &tc : types_to_check )
    {
      if ( !tc.type.is_correct() )
      {
        msg("%d: INCORRECT TYPE ", check_n);
        if ( !tc.name.empty() )
          msg("%s", tc.name.begin());
        else if ( tc.ea != BADADDR )
          msg("%a", tc.ea);
        else
          msg("#%d", tc.id);
        qstring res;
        tc.type.print(&res);
        msg(": %s\n", res.c_str());
        check_n++;
      }
    }
  }
#else
  inline void check_tinfo(ea_t,int,const char*,const tinfo_t &) {}
  inline void check_added_types(void) {}
#endif
};
extern int data_id;
