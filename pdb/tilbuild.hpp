#pragma once

//----------------------------------------------------------------------------
enum cvt_code_t
{
  cvt_failed,
  cvt_ok,
  cvt_typedef           // conversion resulted in a typedef to a named type
};

//----------------------------------------------------------------------------
// PBD provides the offset of a bitfield inside a bitfield group.
// We subclass udt_member_t in order to keep that information separate from
// the 'offset' field.
struct pdb_udt_member_t : public udt_member_t
{
  uint32 bit_offset;    ///< member offset in bits from start of bitfield group
};
DECLARE_TYPE_AS_MOVABLE(pdb_udt_member_t);
typedef qvector<pdb_udt_member_t> pdbudtmembervec_t; ///< vector of pdb udt member objects

//----------------------------------------------------------------------------
// stripped-down version of udt_type_data_t with only the fields used by pdb.
struct pdb_udt_type_data_t : public pdbudtmembervec_t
{
  size_t total_size;    ///< total structure size in bytes
  uint32 taudt_bits;    ///< TA... and TAUDT... bits
  bool is_union;        ///< is union or struct?

  pdb_udt_type_data_t(void)
    : total_size(0),
      taudt_bits(0),
      is_union(false)
  {
  }

  void convert_to_tinfo_udt(udt_type_data_t *out);
};
DECLARE_TYPE_AS_MOVABLE(pdb_udt_type_data_t);

//----------------------------------------------------------------------------
class til_builder_t
{
protected:
  pdb_ctx_t &pv;
public:

  //----------------------------------------------------------------------------
  struct tpinfo_t
  {
    cvt_code_t cvt_code;
    bool is_notype;
    tinfo_t type;
    til_t *ti;  // FIXME: do we need this?
    tpinfo_t(void) : cvt_code(cvt_ok), is_notype(false), ti(nullptr) {}
    tpinfo_t(til_t *_ti, const tinfo_t &t) : cvt_code(cvt_ok), is_notype(false), type(t), ti(_ti) {}
    const char *dstr(void) const
    {
      if ( cvt_code == cvt_failed )
        return "#cvt_failed";

      static qstring res;
      if ( !type.print(&res) )
        res = "#print_failed";
      return res.c_str();
    }
  };

  //----------------------------------------------------------------------------
  til_builder_t(pdb_ctx_t &_pv, til_t *_ti, pdb_access_t *_pa)
    : pv(_pv),
      unnamed_idx(0),
      level(0),
      ti(_ti),
      pdb_access(nullptr),
      enregistered_bug(false)
  {
    set_pdb_access(_pa);
  }

  virtual ~til_builder_t()
  {
    typemap.clear();
    tpdefs.clear();
    handled.clear();
    creating.clear();
    unnamed_types.clear();
  }

  void set_pdb_access(pdb_access_t *_pdb_access)
  {
    pdb_access = _pdb_access;
  }

  typedef std::map<DWORD, tpinfo_t> typemap_t;
  typedef std::map<DWORD, tinfo_t> tpdefs_t;
  typedef std::set<DWORD> idset_t;
  typedef std::map<qstring, int> creating_t;
  typedef std::set<uint32> unnamed_t;

  struct vft_info_t
  {
    udt_type_data_t udt;  // collected vft members
    qstring base0;        // base vftable at offset 0

    vft_info_t() { udt.taudt_bits |= TAUDT_VFTABLE; }
    bool empty() const { return udt.empty() && base0.empty(); }
  };
  typedef std::map<qstring, vft_info_t> vftmap_t;

  //      remove `anonymous-namespace'::
  // also remove `anonymous namespace'::
  void remove_anonymous_namespaces(qstring &storage);

  bool get_symbol_type(tpinfo_t *out, pdb_sym_t &sym, int *p_id);
  bool retrieve_type(tpinfo_t *out, pdb_sym_t &sym, pdb_sym_t *parent, int *p_id);
  bool retrieve_arguments(
        pdb_sym_t &sym,
        func_type_data_t &fi,
        pdb_sym_t *funcSym);
  cm_t convert_cc(DWORD cc0) const;
  bool get_variant_string_value(qstring *out, pdb_sym_t &sym) const;
  uint32 get_variant_long_value(pdb_sym_t &sym) const;
  bool begin_creation(DWORD tag, const qstring &name, uint32 *p_id);
  uint32 end_creation(const qstring &name);
  bool is_member_func(tinfo_t *class_type, pdb_sym_t &typeSym, pdb_sym_t *funcSym);
  bool is_frame_reg(int regnum) const;
  bool is_stack_reg(int regnum) const;
  bool is_complex_return(pdb_sym_t &sym) const;
  bool is_unnamed_tag_typedef(const tinfo_t &tif) const;
  int get_symbol_funcarg_info(
        funcarg_t *out,
        pdb_sym_t &sym,
        DWORD /*dwDataKind*/,
        DWORD locType,
        int stack_off);
  void enum_function_args(pdb_sym_t &sym, func_type_data_t &args);
  cvt_code_t verify_struct(pdb_udt_type_data_t &udt) const;
  bool verify_union_stem(pdb_udt_type_data_t &udt) const;
  cvt_code_t fix_bit_union(pdb_udt_type_data_t *udt) const;
  cvt_code_t verify_union(
        pdb_udt_type_data_t *out,
        pdb_udt_type_data_t::iterator p1,
        pdb_udt_type_data_t::const_iterator p2) const;
  cvt_code_t create_union(
        tinfo_t *out,
        size_t *p_total_size,
        pdb_udt_type_data_t::iterator p1,
        pdb_udt_type_data_t::const_iterator p2) const;
  cvt_code_t convert_basetype(tpinfo_t *out, DWORD baseType, int size) const;
  cvt_code_t make_vtable_struct(tinfo_t *out, pdb_sym_t &sym);
  cvt_code_t convert_udt(tinfo_t *out, pdb_sym_t &sym, DWORD64 size);
  cvt_code_t create_udt(tinfo_t *out, pdb_udt_type_data_t *udt, int udtKind, const char *udt_name) const;
  cvt_code_t create_udt_ref(tinfo_t *out, pdb_udt_type_data_t *udt, int udt_kind) const;
  cvt_code_t really_convert_type(tpinfo_t *out, pdb_sym_t &sym, pdb_sym_t *parent, DWORD tag);
  cvt_code_t convert_type(
        tpinfo_t *out,
        pdb_sym_t &sym,
        pdb_sym_t *parent,
        DWORD type,
        DWORD tag);
  cvt_code_t handle_overlapping_members(pdb_udt_type_data_t *udt) const;
  // Will iterate on children, and call handle_function_child()
  HRESULT handle_symbols(pdb_sym_t &pGlobal);
  HRESULT handle_globals(pdb_sym_t &pGlobal);
  HRESULT handle_publics(pdb_sym_t &pGlobal);
  HRESULT handle_types(pdb_sym_t &pGlobal);
  HRESULT build(pdb_sym_t &pGlobal);
  ea_t get_load_address() const { return pdb_access->get_base_address(); }
  HRESULT handle_symbol(pdb_sym_t &sym);
  size_t get_symbol_type_length(pdb_sym_t &sym) const;
  void create_vftables();
  // check for MS or IDA vftable name,
  // get type ordinal of vftable
  // returns the type is creating
  bool get_vft_name(qstring *vft_name, uint32 *ord, const char *udt_name, uint32_t offset=0);
  void fix_thisarg_type(const qstring &udt_name);

  virtual HRESULT before_iterating(pdb_sym_t &global_sym);
  virtual HRESULT after_iterating(pdb_sym_t &global_sym);
  virtual bool iterate_symbols_once_more(pdb_sym_t & /*global_sym*/) { return false; }
  virtual bool get_symbol_name(pdb_sym_t &sym, qstring &storage);
  virtual bool handle_symbol_at_ea(
        pdb_sym_t &sym,
        DWORD tag,
        ea_t ea,
        qstring &name);
  virtual void type_created(ea_t /*ea*/, int /*id*/, const char * /*name*/, const tinfo_t & /*ptr*/) const;
  virtual void handle_function_type(pdb_sym_t &fun_sym, ea_t ea);
  virtual HRESULT handle_function_child(
        pdb_sym_t &fun_sym,
        ea_t ea,
        pdb_sym_t &child_sym,
        DWORD child_tag,
        DWORD child_loc_type);
  virtual cvt_code_t handle_unnamed_overlapping_member(
        pdb_udt_type_data_t * /*udt*/,
        qstack<qstring> * /*union_names*/,
        qstring * /*name*/) const
  {
    return cvt_ok;
  }

protected:
  typemap_t typemap;            // id -> type info
  tpdefs_t tpdefs;              // id -> enum type defined in base til
  idset_t handled;              // set of handled symbols
  creating_t creating;
  unnamed_t unnamed_types;
  vftmap_t vftmap;              // vftable name -> vft info
  int unnamed_idx;
  int level;

public:
  til_t *ti;
  pdb_access_t *pdb_access;
  bool enregistered_bug;
};
