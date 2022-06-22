

#ifndef PDBACCESS__H
#define PDBACCESS__H

#include <pro.h>
#include "cvconst.h"
#include "cvadd.h"

#ifdef __NT__
#include <windows.h>
#include <oaidl.h>
#include "dia2.h"
#else
// FIXME: It'd be good if those windows declarations for non-windows
// systems were somewhere else than in the PE loader.
#include "../../ldr/pe/mycor.h"
#endif
#include "pdb.hpp"

//----------------------------------------------------------------------------
class pdb_access_t;
class local_pdb_access_t;
class remote_pdb_access_t;

struct pdb_exception_t
{
  pdb_exception_t(const qstring &_what) : what(_what) {}
  qstring what;
};

//----------------------------------------------------------------------------
#ifdef __NT__
enum sym_token_t : uint64
#else
enum sym_token_t
#endif
{
  t_start                     = 1 << 0,
  // bool
  t_bool_start                = t_start,
  t_constType                 = t_bool_start,
  t_isStatic                  = 1 << 1,
  t_virtual                   = 1 << 2,
  t_volatileType              = 1 << 3,
  t_code                      = 1 << 4,
  t_hasAssignmentOperator     = 1 << 5,
  t_hasCastOperator           = 1 << 6,
  t_function                  = 1 << 7, // FIXME!
  t_constructor               = 1 << 8,
  t_isVirtualBaseClass        = 1 << 9,
  t_bool_end                  = t_isVirtualBaseClass,

  // dword
  t_dword_start               = 1 << 10,
  t_backEndMajor              = t_dword_start,
  t_baseType                  = 1 << 11,
  t_bitPosition               = 1 << 12,
  t_callingConvention         = 1 << 13,
  t_count                     = 1 << 14,
  t_dataKind                  = 1 << 15,
  t_locationType              = 1 << 16,
  t_registerId                = 1 << 17,
  t_relativeVirtualAddress    = 1 << 18,
  t_symIndexId                = 1 << 19,
  t_symTag                    = 1 << 20,
  t_udtKind                   = 1 << 21,
  t_virtualBaseOffset         = 1 << 22,
  t_machineType               = 1 << 23,
  t_classParentId             = 1 << 24,
  t_typeId                    = 1 << 25,
  t_lexicalParentId           = 1 << 26,
  t_dword_end                 = t_lexicalParentId,

  // dword64
  t_dword64_start             = 1 << 27,
  t_length                    = t_dword64_start,
  t_dword64_end               = t_length,

  // string
  t_string_start              = 1 << 28,
  t_name                      = t_string_start,
  t_string_end                = t_name,

  // long
  t_long_start                = 1 << 29,
  t_offset                    = t_long_start,
  t_long_end                  = t_offset,

  // ulonglong
  t_ulonglong_start           = 1 << 30,
  t_virtualAddress            = t_ulonglong_start,
  t_ulonglong_end             = t_virtualAddress,

  // variant
  t_variant_start             = 1ULL << 31,
  t_value                     = t_variant_start,
  t_variant_end               = t_value,

  t_end                       = 1ULL << 32,
};
CASSERT(sizeof(sym_token_t) == 8);

inline bool is_sym_token_bool(sym_token_t t) { return t >= t_bool_start && t <= t_bool_end; }
inline bool is_sym_token_dword(sym_token_t t) { return t >= t_dword_start && t <= t_dword_end; }
inline bool is_sym_token_dword64(sym_token_t t) { return t >= t_dword64_start && t <= t_dword64_end; }
// inline bool is_sym_token_pdb_sym(sym_token_t t) { return t >= t_pdb_sym_start && t <= t_pdb_sym_end; }
inline bool is_sym_token_string(sym_token_t t) { return t >= t_string_start && t <= t_string_end; }
inline bool is_sym_token_long(sym_token_t t) { return t >= t_long_start && t <= t_long_end; }
inline bool is_sym_token_ulonglong(sym_token_t t) { return t >= t_ulonglong_start && t <= t_ulonglong_end; }
inline bool is_sym_token_variant(sym_token_t t) { return t >= t_variant_start && t <= t_variant_end; }  //-V560 is always true


typedef uint64 token_mask_t;
#define TOKEN_MASK_FULL token_mask_t(-1)

//----------------------------------------------------------------------------
// engine PDB symbol implementation identity
enum pdb_sym_id_t
{
  DIA_PDB_SYM,
  REMOTE_PDB_SYM,
  OWN_PDB_SYM,
};

//----------------------------------------------------------------------------
struct pdb_sym_t
{
  virtual HRESULT get_backEndMajor(DWORD *out) = 0;
  virtual HRESULT get_baseType(DWORD *out) = 0;
  virtual HRESULT get_bitPosition(DWORD *out) = 0;
  virtual HRESULT get_callingConvention(DWORD *out) = 0;
  virtual HRESULT get_code(BOOL *out) = 0;
  virtual HRESULT get_constructor(BOOL *out) = 0;
  virtual HRESULT get_isVirtualBaseClass(BOOL *out) = 0;
  virtual HRESULT get_constType(BOOL *out) = 0;
  virtual HRESULT get_count(DWORD *out) = 0;
  virtual HRESULT get_dataKind(DWORD *out) = 0;
  virtual HRESULT get_function(BOOL *out) = 0;
  virtual HRESULT get_hasAssignmentOperator(BOOL *out) = 0;
  virtual HRESULT get_hasCastOperator(BOOL *out) = 0;
  virtual HRESULT get_isStatic(BOOL *out) = 0;
  virtual HRESULT get_length(DWORD64 *out) = 0;
  virtual HRESULT get_lexicalParent(pdb_sym_t *out) = 0;
  virtual HRESULT get_locationType(DWORD *out) = 0;
  virtual HRESULT get_machineType(DWORD *out) = 0;
  virtual HRESULT get_name(qstring *out) = 0;
  virtual HRESULT get_offset(LONG *out) = 0;
  virtual HRESULT get_registerId(DWORD *out) = 0;
  virtual HRESULT get_relativeVirtualAddress(DWORD *out) = 0;
  virtual HRESULT get_symIndexId(DWORD *out) = 0;
  virtual HRESULT get_symTag(DWORD *out) = 0;
  virtual HRESULT get_udtKind(DWORD *out) = 0;
  virtual HRESULT get_value(VARIANT *out) = 0;
  virtual HRESULT get_virtual(BOOL *out) = 0;
  virtual HRESULT get_virtualAddress(ULONGLONG *out) = 0;
  virtual HRESULT get_virtualBaseOffset(DWORD *out) = 0;
  virtual HRESULT get_volatileType(BOOL *out) = 0;
  // Be very, very careful to _not_ use classParent if you can avoid it:
  // In case the symbol was *not* resolved through get_type(), the link
  // to the parent might be lost, and a bug in the DIA SDK will
  // return S_FALSE.
  virtual HRESULT get_classParent(pdb_sym_t *out) = 0;
  virtual HRESULT get_type(pdb_sym_t *out) = 0;
  //------------------------------------------------------------
  virtual HRESULT get_ordinal(DWORD *pRetVal) = 0;

  // careful with this!
  virtual void steal_data(pdb_sym_t &other) = 0;

  virtual pdb_sym_id_t whoami(void) = 0;
  virtual bool empty(void) = 0;

  virtual ~pdb_sym_t() {}

  // Declare, but ***don't*** define: we don't want
  // that to happen, and thus we'll have a linker
  // error if that would happen in the code.
  DECLARE_UNCOPYABLE(pdb_sym_t);

protected:
  pdb_sym_t() {}
};
DECLARE_TYPE_AS_MOVABLE(pdb_sym_t);

typedef janitor_t<pdb_sym_t*> pdb_sym_janitor_t;
template <> inline pdb_sym_janitor_t::~janitor_t()
{
  delete resource;
  resource = nullptr;
}

//----------------------------------------------------------------------------
enum packing_info_t
{
  SYMDAT_PACKED = 1,
  SYMDAT_UNPACKED
};

//----------------------------------------------------------------------------
struct sym_data_t
{
  sym_data_t(token_mask_t _tokens, const uchar *buf, size_t bufsize, packing_info_t _packing, bool *_warned);
  ~sym_data_t();

  DWORD get_id() const
  {
    DWORD id;
    if ( get_dword(t_symIndexId, &id) != S_OK )
      INTERR(30211);
    return id;
  }
  HRESULT get_bool(sym_token_t token, BOOL *out) const;
  HRESULT get_dword(sym_token_t token, DWORD *out) const;
  HRESULT get_dword64(sym_token_t token, DWORD64 *out) const;
  HRESULT get_pdb_sym(sym_token_t token, pdb_sym_t *out) const;
  HRESULT get_string(sym_token_t token, qstring *out) const;
  HRESULT get_dword(sym_token_t token, LONG *out) const;
  HRESULT get_ulonglong(sym_token_t token, ULONGLONG *out) const;
  HRESULT get_variant(sym_token_t token, VARIANT *out) const;

private:
  sym_data_t();

  bool token_present(sym_token_t token) const
  {
    return (present & token) == token;
  }

  void assert_token(sym_token_t token) const
  {
    if ( !token_present(token) )
      INTERR(30210);
  }

  const BOOL *bool_ptr(sym_token_t token) const
  {
    return (const BOOL *)any_ptr(token, t_bool_start, t_bool_end);
  }

  const DWORD *dword_ptr(sym_token_t token) const
  {
    return (const DWORD *)any_ptr(token, t_dword_start, t_dword_end);
  }

  const DWORD64 *dword64_ptr(sym_token_t token) const
  {
    return (const DWORD64 *)any_ptr(token, t_dword64_start, t_dword64_end);
  }

  const LONG *long_ptr(sym_token_t token) const
  {
    return (const LONG *)any_ptr(token, t_long_start, t_long_end);
  }

  const ULONGLONG *uint64_ptr(sym_token_t token) const
  {
    return (const ULONGLONG *)any_ptr(token, t_ulonglong_start, t_ulonglong_end);
  }

  const char **string_ptr(sym_token_t token) const
  {
    return (const char **)any_ptr(token, t_string_start, t_string_end);
  }

  const VARIANT *variant_ptr(sym_token_t token) const
  {
    return (const VARIANT *)any_ptr(token, t_variant_start, t_variant_end);
  }

  enum type_t
  {
    t_bool = 0,
    t_dword,
    t_dword64,
    t_string,
    t_long,
    t_ulonglong,
    t_variant,
    t_max
  };

  static const uint32 sizes[];

  const void *any_ptr(sym_token_t token, sym_token_t start, sym_token_t end) const;

  token_mask_t present; // The tokens that are present in this instance.
  bytevec_t data;
  uint8 counters[t_max];

  struct children_t
  {
    DWORD *ids;
    uint32 cnt;
  };
  children_t children_infos[SymTagMax];
  friend class remote_pdb_access_t; // accesses children_infos directly
  bool *warned;
};


//----------------------------------------------------------------------------
#ifdef __NT__
struct dia_pdb_sym_t : public pdb_sym_t
{
  dia_pdb_sym_t(pdb_access_t *_pdb_access, IDiaSymbol *_data, bool _own_sym)
    : pdb_access(_pdb_access),
      data(_data),
      own_sym(_own_sym)
  {}

  ~dia_pdb_sym_t()
  {
    if ( data != nullptr && own_sym )
    {
      data->Release();
      data = nullptr;
    }
    pdb_access = nullptr;
  }

  pdb_access_t *pdb_access;
  IDiaSymbol *data;
  bool own_sym;

  pdb_sym_id_t whoami(void) { return DIA_PDB_SYM; }
  void set_symbol_data(IDiaSymbol *s, bool own)
  {
    data    = s;
    own_sym = own;
  }
  bool empty(void) { return data == nullptr; }

  HRESULT get_backEndMajor(DWORD *out)            { return data->get_backEndMajor(out); }
  HRESULT get_baseType(DWORD *out)                { return data->get_baseType(out); }
  HRESULT get_bitPosition(DWORD *out)             { return data->get_bitPosition(out); }
  HRESULT get_callingConvention(DWORD *out)       { return data->get_callingConvention(out); }
  HRESULT get_code(BOOL *out)                     { return data->get_code(out); }
  HRESULT get_constType(BOOL *out)                { return data->get_constType(out); }
  HRESULT get_count(DWORD *out)                   { return data->get_count(out); }
  HRESULT get_constructor(BOOL *out)              { return data->get_constructor(out); }
  HRESULT get_isVirtualBaseClass(BOOL *out)       { return data->get_virtualBaseClass(out); }
  HRESULT get_dataKind(DWORD *out)                { return data->get_dataKind(out); }
  HRESULT get_function(BOOL *out)                 { return data->get_function(out); }
  HRESULT get_hasAssignmentOperator(BOOL *out)    { return data->get_hasAssignmentOperator(out); }
  HRESULT get_hasCastOperator(BOOL *out)          { return data->get_hasCastOperator(out); }
  HRESULT get_isStatic(BOOL *out)                 { return data->get_isStatic(out); }
  HRESULT get_length(DWORD64 *out)                { return data->get_length(out); }
  HRESULT get_lexicalParent(pdb_sym_t *out)
  {
    IDiaSymbol *t;
    HRESULT res = data->get_lexicalParent(&t);
    return handle_related_symbol(res, t, out);
  }
  HRESULT get_locationType(DWORD *out)            { return data->get_locationType(out); }
  HRESULT get_machineType(DWORD *out)             { return data->get_machineType(out); }
  HRESULT get_name(qstring *out)
  {
    BSTR name;
    HRESULT hr = data->get_name(&name);
    return maybe_convert_bstr(out, hr, &name);
  }
  HRESULT get_offset(LONG *out)                   { return data->get_offset(out); }
  HRESULT get_registerId(DWORD *out)              { return data->get_registerId(out); }
  HRESULT get_relativeVirtualAddress(DWORD *out)  { return data->get_relativeVirtualAddress(out); }
  HRESULT get_symIndexId(DWORD *out)              { return data->get_symIndexId(out); }
  HRESULT get_symTag(DWORD *out)                  { return data->get_symTag(out); }
  HRESULT get_udtKind(DWORD *out)                 { return data->get_udtKind(out); }
  HRESULT get_value(VARIANT *out)                 { return data->get_value(out); }
  HRESULT get_virtual(BOOL *out)                  { return data->get_virtual(out); }
  HRESULT get_virtualAddress(ULONGLONG *out)      { return data->get_virtualAddress(out); }
  HRESULT get_virtualBaseOffset(DWORD *out)       { return data->get_virtualBaseOffset(out); }
  HRESULT get_volatileType(BOOL *out)             { return data->get_volatileType(out); }
  HRESULT get_classParent(pdb_sym_t *out)
  {
    IDiaSymbol *t;
    HRESULT res = data->get_classParent(&t);
    return handle_related_symbol(res, t, out);
  }

  HRESULT get_type(pdb_sym_t *out)
  {
    IDiaSymbol *t;
    HRESULT res = data->get_type(&t);
    return handle_related_symbol(res, t, out);
  }

  //------------------------------------------------------------
  virtual HRESULT get_ordinal(DWORD *) override { return S_FALSE; }

  HRESULT handle_related_symbol(HRESULT fetch_success, IDiaSymbol *t, pdb_sym_t *out)
  {
    if ( out == nullptr )
      return S_FALSE;
    QASSERT(30545, out->whoami() == DIA_PDB_SYM);
    dia_pdb_sym_t *sym = (dia_pdb_sym_t *)out;
    sym->set_symbol_data(fetch_success == S_OK ? t : nullptr, true);
    return fetch_success;
  }

  // careful with this!
  void steal_data(pdb_sym_t &other)
  {
    QASSERT(30541, whoami() == other.whoami());
    dia_pdb_sym_t &other_dia = (dia_pdb_sym_t &)other;
    QASSERT(30503, other_dia.own_sym && other_dia.data != nullptr && data == nullptr);
    data = other_dia.data;
    own_sym = true;
    other_dia.own_sym = false;
    other_dia.data = nullptr;
  }

private:
  dia_pdb_sym_t();

  HRESULT maybe_convert_bstr(qstring *out, HRESULT hr, BSTR *s)
  {
    if ( hr == S_OK )
    {
      utf16_utf8(out, *s);
      SysFreeString(*s);
    }
    return hr;
  }
};
DECLARE_TYPE_AS_MOVABLE(dia_pdb_sym_t);

//----------------------------------------------------------------------------
#else   // __NT__
struct remote_pdb_sym_t : public pdb_sym_t
{
  remote_pdb_sym_t(pdb_access_t *_pdb_access, sym_data_t *_data)
    : pdb_access(_pdb_access),
      data(_data)
  {}

  ~remote_pdb_sym_t()
  {
    data = nullptr;
    pdb_access = nullptr;
  }

  void set_symbol_data(sym_data_t *s) { data = s; }

  HRESULT get_backEndMajor(DWORD *out) override           { return data->get_dword(t_backEndMajor, out); }
  HRESULT get_baseType(DWORD *out) override               { return data->get_dword(t_baseType, out); }
  HRESULT get_bitPosition(DWORD *out) override            { return data->get_dword(t_bitPosition, out); }
  HRESULT get_callingConvention(DWORD *out) override      { return data->get_dword(t_callingConvention, out); }
  HRESULT get_code(BOOL *out) override                    { return data->get_bool(t_code, out); }
  HRESULT get_constructor(BOOL *out) override             { return data->get_bool(t_constructor, out); }
  HRESULT get_isVirtualBaseClass(BOOL *out) override      { return data->get_bool(t_isVirtualBaseClass, out); }
  HRESULT get_constType(BOOL *out) override               { return data->get_bool(t_constType, out); }
  HRESULT get_count(DWORD *out) override                  { return data->get_dword(t_count, out); }
  HRESULT get_dataKind(DWORD *out) override               { return data->get_dword(t_dataKind, out); }
  HRESULT get_function(BOOL *out) override                { return data->get_bool(t_function, out); }
  HRESULT get_hasAssignmentOperator(BOOL *out) override   { return data->get_bool(t_hasAssignmentOperator, out); }
  HRESULT get_hasCastOperator(BOOL *out) override         { return data->get_bool(t_hasCastOperator, out); }
  HRESULT get_isStatic(BOOL *out) override                { return data->get_bool(t_isStatic, out); }
  HRESULT get_length(DWORD64 *out) override               { return data->get_dword64(t_length, out); }
  HRESULT get_lexicalParent(pdb_sym_t *out) override;
  HRESULT get_locationType(DWORD *out) override           { return data->get_dword(t_locationType, out); }
  HRESULT get_machineType(DWORD *out) override            { return data->get_dword(t_machineType, out); }
  HRESULT get_name(qstring *out) override                 { return data->get_string(t_name, out); }
  HRESULT get_offset(LONG *out) override                  { return data->get_dword(t_offset, out); }
  HRESULT get_registerId(DWORD *out) override             { return data->get_dword(t_registerId, out); }
  HRESULT get_relativeVirtualAddress(DWORD *out) override { return data->get_dword(t_relativeVirtualAddress, out); }
  HRESULT get_symIndexId(DWORD *out) override             { return data->get_dword(t_symIndexId, out); }
  HRESULT get_symTag(DWORD *out) override                 { return data->get_dword(t_symTag, out); }
  HRESULT get_udtKind(DWORD *out) override                { return data->get_dword(t_udtKind, out); }
  HRESULT get_value(VARIANT *out) override                { return data->get_variant(t_value, out); }
  HRESULT get_virtual(BOOL *out) override                 { return data->get_bool(t_virtual, out); }
  HRESULT get_virtualAddress(ULONGLONG *out) override     { return data->get_ulonglong(t_virtualAddress, out); }
  HRESULT get_virtualBaseOffset(DWORD *out) override      { return data->get_dword(t_virtualBaseOffset, out); }
  HRESULT get_volatileType(BOOL *out) override            { return data->get_bool(t_volatileType, out); }
  HRESULT get_classParent(pdb_sym_t *out) override;
  HRESULT get_type(pdb_sym_t *out) override;
  //------------------------------------------------------------
  virtual HRESULT get_ordinal(DWORD *) override { return S_FALSE; }

  // careful with this!
  void steal_data(pdb_sym_t &other) override
  {
    QASSERT(30542, whoami() == other.whoami());
    remote_pdb_sym_t &other_rem = (remote_pdb_sym_t &)other;
    QASSERT(30492, other_rem.data != nullptr && data == nullptr);
    data = other_rem.data;
    // we don't want to set 'other.data = nullptr', because in remote access,
    // the pdb_sym_t doesn't actually own the data anyway: it's part of
    // the cache.
  }

  pdb_sym_id_t whoami(void) override { return REMOTE_PDB_SYM; }
  bool empty(void) override          { return data == nullptr; }

  pdb_access_t *pdb_access;
  sym_data_t *data;

private:
  remote_pdb_sym_t();
};
DECLARE_TYPE_AS_MOVABLE(remote_pdb_sym_t);
#endif // !__NT__

//----------------------------------------------------------------------------
#define BAD_MACHINE_TYPE ((uint32) -1)

#define BADSYM ((uint32) -1)

//-------------------------------------------------------------------------
struct pdb_lnnum_t
{
  pdb_lnnum_t()
    : va(BADADDR), length(0),
      columnNumber(0), columnNumberEnd(0),
      lineNumber(0), lineNumberEnd(0),
      file_id(DWORD(-1)), statement(0) {}
  ULONGLONG va;
  DWORD length;
  DWORD columnNumber;
  DWORD columnNumberEnd;
  DWORD lineNumber;
  DWORD lineNumberEnd;
  DWORD file_id;
  BOOL statement;
};

//--------------------------------------------------------------------------
typedef qvector<pdb_lnnum_t> pdb_lnnum_vec_t;
typedef std::map<int, pdb_lnnum_vec_t> lnmap_t;

//-------------------------------------------------------------------------
struct pdb_lnnums_t : pdb_lnnum_vec_t
{
  pdb_lnnums_t() : inited(false) {}

  bool get_item_bounds(rangeset_t *set) const;
  int get_lnnum() const;
  int get_colnum() const;
  int get_end_lnnum() const;
  int get_end_colnum() const;

  bool inited;
};

//----------------------------------------------------------------------------
class pdb_access_t
{
public:
  pdb_access_t(const pdbargs_t &args)
    : pdbargs(args),
      machine_type((uint32) -1),
      dia_version(0),
      base_address(BADADDR),
      global_sym_id(BADSYM)
  {
  }
  virtual ~pdb_access_t() {}

  //----------------------------------------------------------------------
  struct children_visitor_t
  {
    children_visitor_t()
      : parent(nullptr) {}

    virtual HRESULT visit_child(pdb_sym_t &child) = 0;
    virtual ~children_visitor_t() {}

    pdb_sym_t *parent;
  };

  //-------------------------------------------------------------------------
  struct dummy_visitor_t : public children_visitor_t
  {
    virtual HRESULT visit_child(pdb_sym_t &) override { return S_OK; }
  };

  //----------------------------------------------------------------------------
  HRESULT iterate_children(
          pdb_sym_t &sym,
          enum SymTagEnum type,
          children_visitor_t &visitor);

  //----------------------------------------------------------------------------
  virtual HRESULT do_iterate_children(
        pdb_sym_t &sym,
        enum SymTagEnum type,
        children_visitor_t &visitor) = 0;
  virtual HRESULT iterate_subtags(
        pdb_sym_t &sym,
        enum SymTagEnum type,
        children_visitor_t &visitor);
  virtual HRESULT load(pdb_sym_t &sym, DWORD id) = 0;

  // source-level debugging-specific
  virtual HRESULT sip_retrieve_lines_by_va(
        pdb_lnnums_t *out,
        ULONGLONG va,
        ULONGLONG length) = 0;
  virtual HRESULT sip_retrieve_lines_by_coords(
        pdb_lnnums_t *out,
        DWORD file_id,
        int lnnum,
        int colnum) = 0;
  virtual HRESULT sip_iterate_symbols_at_ea(
        ULONGLONG va,
        ULONGLONG size,
        enum SymTagEnum tag,
        children_visitor_t &visitor) = 0;
  virtual HRESULT sip_iterate_file_compilands(
        DWORD file_id,
        children_visitor_t &visitor) = 0;
  virtual HRESULT sip_retrieve_file_path(
        qstring *out,
        qstring *errbuf,
        DWORD file_id) = 0;
  virtual HRESULT sip_retrieve_symbol_files(
        qvector<DWORD> *out,
        pdb_sym_t &sym) = 0;
  virtual HRESULT sip_find_files(
        qvector<DWORD> *out,
        const char *filename) = 0; // case insensitive search
  // /source-level debugging-specific

  //----------------------------------------------------------------------------
  virtual DWORD  get_global_symbol_id() const { return global_sym_id; }
  virtual ea_t   get_base_address()     const { return base_address; }
  virtual uint32 get_machine_type()     const { return machine_type; }
  virtual int    get_dia_version()      const { return dia_version; }

  void set_global_symbol_id(DWORD _global_sym_id) { global_sym_id = _global_sym_id; }
  void set_machine_type(uint32 _machine_type)     { machine_type  = _machine_type; }
  void set_base_address(ea_t _base_address)       { base_address  = _base_address; }
  void set_dia_version(int _dia_version)          { dia_version   = _dia_version; }

  //----------------------------------------------------------------------------
  virtual pdb_sym_t *create_sym(void *data=nullptr, bool own=false) = 0;
  pdb_sym_t *create_sym(DWORD sym_id)
  {
    pdb_sym_t *sym = create_sym();
    if ( load(*sym, sym_id) != S_OK )
    {
      qstring err;
      err.sprnt("Failed loading symbol data for ID %u", sym_id);
      delete sym;
      throw pdb_exception_t(err.c_str());
    }
    return sym;
  }

  //----------------------------------------------------------------------------
  const pdbargs_t &pdbargs;

private:
  uint32 machine_type;
  int dia_version;
  ea_t base_address;
  DWORD global_sym_id;
  DECLARE_UNCOPYABLE(pdb_access_t)
};


#endif // PDBACCESS__H
