
#include "sip.hpp"
#include "tilbuild.hpp"

#include <dbg.hpp>

struct pdb_modinfo_t;

static source_item_t *new_pdb_symbol(
        pdb_modinfo_t *pdb_module,
        DWORD sym_id);
static source_item_t *new_pdb_symbol_or_delete(
        pdb_modinfo_t *pdb_module,
        pdb_sym_t *sym);

typedef qvector<source_item_ptr> source_items_vec_t;

//-------------------------------------------------------------------------
// will steal data from all 'child' instances passed to 'visit_child()',
// and create new pdb_sym_t objects (wrapped in source_item_t's) with
// that data.
struct source_items_vec_builder_t : public pdb_access_t::children_visitor_t
{
  source_items_vec_t items;
  pdb_modinfo_t *pdb_module;
  source_items_vec_builder_t(pdb_modinfo_t *_mod) : pdb_module(_mod) {}
  virtual HRESULT visit_child(pdb_sym_t &child) override;
};

//--------------------------------------------------------------------------
// Implementation of source information provider using PDB information
// and the DIA SDK

//--------------------------------------------------------------------------
// Information about a PDB module. Contains a type cache, that'll
// last the same time as the debugging session.
struct pdb_modinfo_t
{
  pdb_ctx_t &pv;

  pdb_modinfo_t()
    : pv(*GET_MODULE_DATA(pdb_ctx_t)),
      base(BADADDR),
      size(0),
      opened(false),
      pdb_access(nullptr),
      type_cache(nullptr),
      use_pdbida(false)
  {}

  ~pdb_modinfo_t()
  {
    delete type_cache;
#ifdef __NT__
    // on windows with MSDIA provider, 'session_ref' owns the pdb_access
    if ( use_pdbida )
#endif
    {
      delete pdb_access;
    }
  }

  pdb_access_t *get_access() { return pdb_access; }

  HRESULT open(const char *input_file, const char *user_spath, ea_t load_address);
  source_item_t *find_static_item_in_module(const char *iname);

  typedef std::map<qstring,DWORD> module_globals_t;
  module_globals_t module_globals;

  qstring path;
  ea_t base;
  asize_t size;
  bool opened;
  pdb_access_t *pdb_access;
#ifndef ENABLE_REMOTEPDB
  pdb_session_ref_t session_ref;
#endif
  til_builder_t *type_cache;
  bool use_pdbida;
};
typedef std::map<ea_t, pdb_modinfo_t> pdb_modules_t;

//-------------------------------------------------------------------------
HRESULT pdb_modinfo_t::open(
        const char *input_file,
        const char *user_spath,
        ea_t load_address)
{
  QASSERT(30212, type_cache == nullptr);
  pdbargs_t args;
  args.input_path = input_file;
  args.spath = user_spath;
  args.loaded_base = load_address;
  HRESULT hr = E_FAIL;
  {
    msg("PDB: using MSDIA provider\n");
    #ifdef ENABLE_REMOTEPDB
    if ( is_win32_remote_debugger_loaded() )
    {
      args.flags |= PDBFLG_DBG_MODULE;
      remote_pdb_access_t *rpdb_access = new remote_pdb_access_t(
              args,
              "TESTER-SQUISH",
              23946,
              "");
      hr = rpdb_access->open_connection();
      if ( hr == S_OK )
        pdb_access = rpdb_access;
      else
        delete rpdb_access;
    }
    #else // ENABLE_REMOTEPDB
    hr = session_ref.open_session(args);
    if ( hr == S_OK )
      pdb_access = session_ref.session->pdb_access;
    #endif // ENABLE_REMOTEPDB
  }
  if ( hr == S_OK )
  {
    type_cache = new til_builder_t(pv, CONST_CAST(til_t *)(get_idati()), nullptr);
    type_cache->set_pdb_access(pdb_access);
  }
  return hr;
}

//-------------------------------------------------------------------------
source_item_t *pdb_modinfo_t::find_static_item_in_module(
        const char *iname)
{
  if ( !opened )
    return nullptr;

  DWORD id = 0;
  module_globals_t::iterator p = module_globals.find(iname);
  if ( p != module_globals.end() )
  {
    id = p->second;
  }
  else
  {
    struct ida_local iter_t : public pdb_access_t::children_visitor_t
    {
      pdb_modinfo_t *pdb_module;
      const char *name;
      DWORD id;
      iter_t(
              pdb_modinfo_t *_pdb_module,
              const char *_name)
        : pdb_module(_pdb_module), name(_name), id(0) {}
      virtual HRESULT visit_child(pdb_sym_t &data) override
      {
        qstring cname;
        if ( data.get_name(&cname) == S_OK && cname == name )
          data.get_symIndexId(&id);
        return id == 0 ? S_OK : E_FAIL; // 'id' still 0? keep iterating
      }
    };
    iter_t iter(this, iname);
    pdb_sym_t *global = get_access()->create_sym(get_access()->get_global_symbol_id());
    pdb_sym_janitor_t janitor_global(global);
    get_access()->iterate_children(*global, SymTagData, iter);
    id = iter.id;
    module_globals[iname] = id; // populate
  }
  return id != 0 ? new_pdb_symbol(this, id) : nullptr;
}

//-------------------------------------------------------------------------
//
//-------------------------------------------------------------------------
bool pdb_ctx_t::get_pdb_register_info(int *p_reg, uint64 *p_mask, int machine, int reg)
{
  qstring name;
  print_pdb_register(&name, machine, reg);
  reg_info_t ri;
  if ( !parse_reg_name(&ri, name.c_str()) )
    return false;
  *p_reg = ri.reg;
  *p_mask = left_shift(uint64(1), 8*ri.size) - 1;
  return true;
}

//--------------------------------------------------------------------------
struct pdb_source_file_t : public source_file_t
{
  pdb_modinfo_t *pdb_module;
  DWORD file_id;
  qstring my_path;

  pdb_source_file_t(pdb_modinfo_t *_mod, DWORD _fid)
    : pdb_module(_mod), file_id(_fid) {}

  srcinfo_provider_t *idaapi get_provider(void) const override;
  virtual ~pdb_source_file_t(void) {}
  virtual void idaapi release() override { delete this; }
  const char *idaapi get_path(qstring *errbuf) override
  {
    if ( my_path.empty() )
    {
      pdb_module->get_access()->sip_retrieve_file_path(
              &my_path,
              errbuf,
              file_id);
    }
    return my_path.c_str();
  }

  bool idaapi read_file(strvec_t *buf, qstring *errbuf) override
  {
    buf->clear();
    const char *path = get_path(errbuf);

    // Always favor file mapping first.
    qstring mapbuf = path;
    callui(ui_dbg_map_source_path, &mapbuf);
    path = mapbuf.c_str();

    if ( !qfileexist(path) )
    {
      if ( errbuf != nullptr )
        errbuf->sprnt("source file not found: %s", path);
      return false;
    }

    FILE *fp = fopenRT(path);
    if ( fp == nullptr )
    {
      if ( errbuf != nullptr )
        *errbuf = get_errdesc(path);
      return false;
    }

    int tabsize = get_tab_size(path);
    qstring line;
    while ( qgetline(&line, fp) >= 0 )
    {
      simpleline_t &sl = buf->push_back();
      sl.line.clear();
      replace_tabs(&sl.line, line.c_str(), tabsize);
    }

    qfclose(fp);
    return true;
  }

  TWidget *open_srcview(strvec_t ** /*strvec*/, TWidget ** /*pview*/, int, int) override
  {
    return nullptr;
  }
};

//--------------------------------------------------------------------------
struct pdb_file_iterator : public _source_file_iterator
{
  struct entry_t
  {
    pdb_modinfo_t *pdb_module;
    DWORD file_id;
  };
  qvector<entry_t> entries;
  int idx;

  pdb_file_iterator() : idx(-1) {}
  virtual ~pdb_file_iterator(void) {}

  virtual void idaapi release(void) override { delete this; }
  bool idaapi first(void) override
  {
    idx = -1;
    return next();
  }

  bool idaapi next(void) override
  {
    ++idx;
    return idx < entries.size();
  }

  source_file_ptr idaapi operator *() override
  {
    const entry_t &e = entries[idx];
    return source_file_ptr(
            new pdb_source_file_t(e.pdb_module, e.file_id));
  }
};

//--------------------------------------------------------------------------
// Dummy source item: provides no information.
struct dummy_item_t : public source_item_t
{
  pdb_modinfo_t *pdb_module;

  dummy_item_t(pdb_modinfo_t *_pdb_module) : pdb_module(_pdb_module) {}
  virtual ~dummy_item_t(void) { pdb_module = nullptr; }
  void idaapi release(void) override { delete this; }
  source_file_iterator idaapi get_source_files(void) override { return source_file_iterator(nullptr); }
  int idaapi get_lnnum() const override { return -1; }
  int idaapi get_end_lnnum() const override { return -1; }
  int idaapi get_colnum() const override { return -1; }
  int idaapi get_end_colnum() const override { return -1; }
  ea_t idaapi get_ea() const override { return BADADDR; }
  asize_t idaapi get_size() const override { return 0; }
  bool idaapi get_item_bounds(rangeset_t *set) const override
  {
    ea_t ea = get_ea();
    if ( ea == BADADDR )
      return false;
    asize_t size = get_size();    //-V779 Unreachable code detected
    set->add(range_t(ea, ea+size));
    return true;
  }
  source_item_ptr idaapi get_parent(src_item_kind_t) const override { return source_item_ptr(nullptr); }
  source_item_iterator idaapi create_children_iterator() override { return source_item_iterator(nullptr); }
  bool idaapi get_hint(qstring *hint, const eval_ctx_t *, int *nlines) const override
  {
    // TODO: remove these test lines
    *hint = "test";
    *nlines = 1;
    return true;
  }
  bool idaapi evaluate(const eval_ctx_t *, idc_value_t *, qstring *) const override { return false; }
  // bool idaapi get_stkvar_info(char *, size_t, uval_t *, ea_t) const { return false; }
  // bool idaapi get_regvar_info(char *, size_t) const { return false; }
  // bool idaapi get_rrlvar_info(char *, size_t, uval_t *) const { return false; }
  bool idaapi get_expr_tinfo(tinfo_t *) const override { return false; }

  virtual bool idaapi get_location(argloc_t *, const eval_ctx_t *) const override { return false; }

  virtual srcinfo_provider_t *idaapi get_provider(void) const override;
};

//-------------------------------------------------------------------------
//
//-------------------------------------------------------------------------
bool pdb_lnnums_t::get_item_bounds(rangeset_t *set) const
{
  for ( size_t i = 0, sz = size(); i < sz; ++i )
  {
    const pdb_lnnum_t &ln = at(i);
    set->add(ln.va, ln.va + ln.length);
  }
  return !set->empty();
}

//-------------------------------------------------------------------------
int pdb_lnnums_t::get_lnnum() const
{
  return empty() ? -1 : at(0).lineNumber;
}

//-------------------------------------------------------------------------
int pdb_lnnums_t::get_colnum() const
{
  return empty() ? -1 : at(0).columnNumber;
}

//-------------------------------------------------------------------------
int pdb_lnnums_t::get_end_lnnum() const
{
  return empty() ? -1 : at(size() - 1).lineNumber; //should it be lineNumberEnd; ?
}

//-------------------------------------------------------------------------
int pdb_lnnums_t::get_end_colnum() const
{
  return empty() ? -1 : at(size() - 1).columnNumber; //should it be columnNumberEnd; ?
}


//--------------------------------------------------------------------------
//                               pdb_item_iterator
//--------------------------------------------------------------------------
struct pdb_item_iterator : public _source_item_iterator
{
  pdb_modinfo_t *pdb_module;
  source_items_vec_t items;
  int index;

  pdb_item_iterator(pdb_modinfo_t *_mod, source_items_vec_t &_items)
    : pdb_module(_mod), index(-1)
  {
    items.swap(_items);
  }

  virtual ~pdb_item_iterator(void) {}

  void idaapi release(void) override
  {
    delete this;
  }

  bool idaapi first(void) override
  {
    index = -1;
    return next();
  }

  bool idaapi next(void) override
  {
    ++index;
    return index < items.size();
  }

  source_item_ptr idaapi operator *() override
  {
    return items[index];
  }
};


//-------------------------------------------------------------------------
//                               pdb_symbol_t
//--------------------------------------------------------------------------
// source item based on dia symbol
class pdb_symbol_t : public dummy_item_t
{
  pdb_sym_t *sym;
  mutable pdb_lnnums_t lnnums; // cached ptr to line number enumerator
  src_item_kind_t kind;
  bool own_sym;

  bool init_lnnums() const
  {
    if ( !lnnums.inited )
    {
      ULONGLONG va;
      if ( sym->get_virtualAddress(&va) == S_OK )
      {
        ULONGLONG length;
        if ( sym->get_length(&length) == S_OK )
        {
          pdb_access_t *pa = pdb_module->get_access();
          if ( pa->sip_retrieve_lines_by_va(&lnnums, va, length) == S_OK )
            lnnums.inited = true;
        }
      }
    }
    return lnnums.inited;
  }

public:
  pdb_symbol_t(pdb_modinfo_t *_pdb_module,
               pdb_sym_t *_sym,
               bool _own_sym,
               src_item_kind_t k)
    : dummy_item_t(_pdb_module),
      sym(_sym),
      kind(k),
      own_sym(_own_sym)
  {
  }

  virtual ~pdb_symbol_t(void)
  {
    if ( own_sym )
      delete sym;
  }

  pdb_sym_t *get_pdb_sym() { return sym; }

  source_file_iterator idaapi get_source_files(void) override
  {
    pdb_file_iterator *ret = nullptr;
    qvector<DWORD> ids;
    HRESULT hr = pdb_module->get_access()->sip_retrieve_symbol_files(
            &ids, *sym);
    if ( hr == S_OK )
    {
      ret = new pdb_file_iterator();
      for ( size_t i = 0; i < ids.size(); ++i )
      {
        pdb_file_iterator::entry_t &e = ret->entries.push_back();
        e.pdb_module = pdb_module;
        e.file_id = ids[i];
      }
    }
    return source_file_iterator(ret);
  }

  bool idaapi get_name(qstring *buf) const override
  {
    return sym->get_name(buf) == S_OK;
  }

  int idaapi get_lnnum() const override
  {
    return init_lnnums() ? lnnums.get_lnnum() : 0;
  }

  int idaapi get_end_lnnum() const override
  {
    return init_lnnums() ? lnnums.get_end_lnnum() : 0;
  }

  int idaapi get_colnum() const override
  {
    return init_lnnums() ? lnnums.get_colnum() : 0;
  }

  int idaapi get_end_colnum() const override
  {
    if ( !init_lnnums() )
      return 0;
    return lnnums.get_end_colnum();
  }

  ea_t idaapi get_ea() const override
  {
    ULONGLONG va = ULONGLONG(-1);
    return FAILED(sym->get_virtualAddress(&va)) ? BADADDR : va;
  }

  asize_t idaapi get_size() const override
  {
    ULONGLONG len = 0;
    return FAILED(sym->get_length(&len)) ? BADADDR : len;
  }

  bool idaapi get_item_bounds(rangeset_t *set) const override
  {
    return init_lnnums() && lnnums.get_item_bounds(set);
  }

  source_item_ptr idaapi get_parent(src_item_kind_t /*max_kind*/) const override
  {
    source_item_t *ret = nullptr;
    pdb_sym_t *lpar = pdb_module->get_access()->create_sym();
    pdb_sym_janitor_t janitor_lpar(lpar);
    DWORD par_id = 0;
    if ( sym->get_lexicalParent(lpar) == S_OK
      && lpar->get_symIndexId(&par_id) == S_OK )
    {
      ret = new_pdb_symbol(pdb_module, par_id);
    }
    return source_item_ptr(ret);
  }

  source_item_iterator idaapi create_children_iterator() override;

  // TODO: not implemented yet
  /*bool idaapi get_hint(qstring *hint, const eval_ctx_t *ctx, int *nlines) const
  {
    return false;
  }*/

  bool idaapi evaluate(const eval_ctx_t * /*ctx*/, idc_value_t * /*res*/, qstring * /*errbuf*/) const override
  {
    // not implemented yet
    return false;
  }

  virtual src_item_kind_t idaapi get_item_kind(const eval_ctx_t * /*ctx*/) const override
  {
    return kind;
  }

  virtual bool idaapi get_location(argloc_t *out, const eval_ctx_t *) const override
  {
    DWORD loctype = LocIsNull;
    HRESULT hr = sym->get_locationType(&loctype);
    if ( FAILED(hr) )
      return false;
    bool ok = false;
    int machine = pdb_module->get_access()->get_machine_type();
    switch ( loctype )
    {
      case LocIsRegRel:
        {
          DWORD dwReg = 0;
          LONG lOffset;
          if ( sym->get_registerId(&dwReg) == S_OK
            && sym->get_offset(&lOffset) == S_OK )
          {
            int regno;
            uint64 mask;
            if ( pdb_module->pv.get_pdb_register_info(&regno, &mask, machine, dwReg) )
            {
              rrel_t *rrel = new rrel_t();
              rrel->reg = regno;
              rrel->off = lOffset;
              out->consume_rrel(rrel);
              ok = true;
            }
          }
        }
        break;
      case LocIsEnregistered:
        {
          DWORD dwReg = 0;
          if ( sym->get_registerId(&dwReg) == S_OK )
          {
            int regno;
            uint64 mask;
            if ( pdb_module->pv.get_pdb_register_info(&regno, &mask, machine, dwReg) )
            {
              out->set_reg1(regno, 0); // off=0?
              ok = true;
            }
          }
        }
        break;
      default:
        break;
    }
    return ok;
  }

  bool idaapi get_expr_tinfo(tinfo_t *tif) const override
  {
    til_builder_t::tpinfo_t tpi;
    bool res = pdb_module->type_cache->retrieve_type(&tpi, *sym, nullptr, nullptr);

    *tif = tpi.type;

    if ( (debug & IDA_DEBUG_SRCDBG) != 0 )
    {
      qstring type_str;
      tpi.type.print(&type_str);
      DWORD sym_id = 0;
      sym->get_symIndexId(&sym_id);
      qstring name;
      deb(IDA_DEBUG_SRCDBG, "Retrieved type for %s (symbol #%u): %s\n",
          get_name(&name) ? name.c_str() : "<unnamed>",
          sym_id,
          type_str.c_str());
    }

    return res;
  }

  bool idaapi equals(const source_item_t *othr) const override
  {
    DWORD this_id, other_id;
    pdb_symbol_t *other = (pdb_symbol_t*) othr;
    return other != nullptr
        && other->sym != nullptr
        && pdb_module == other->pdb_module
        && sym->get_symIndexId(&this_id) == S_OK
        && other->sym->get_symIndexId(&other_id) == S_OK
        && this_id == other_id;
  }
};

//--------------------------------------------------------------------------
source_item_iterator idaapi pdb_symbol_t::create_children_iterator()
{
  pdb_item_iterator *ret = nullptr;
  source_items_vec_builder_t items_builder(pdb_module);
  if ( pdb_module->get_access()->iterate_children(
               *sym, SymTagNull, items_builder) == S_OK )
    ret = new pdb_item_iterator(pdb_module, items_builder.items);
  return source_item_iterator(ret);
}

//--------------------------------------------------------------------------
class pdb_lnnum_item_t : public dummy_item_t
{
  pdb_lnnum_t *lnnum;        // we do not own this pointer

public:
  pdb_lnnum_item_t(pdb_modinfo_t *_pdb_module, pdb_lnnum_t *l)
    : dummy_item_t(_pdb_module),
      lnnum(l) {}

  virtual ~pdb_lnnum_item_t(void) {}

  virtual source_file_iterator idaapi get_source_files(void) override
  {
    pdb_file_iterator *ret = nullptr;
    if ( lnnum->file_id != DWORD(-1) )
    {
      ret = new pdb_file_iterator();
      pdb_file_iterator::entry_t &e = ret->entries.push_back();
      e.pdb_module = pdb_module;
      e.file_id = lnnum->file_id;
    }
    return source_file_iterator(ret);
  }

  virtual bool idaapi get_name(qstring *) const override
  {
    return false;
  }

  virtual int idaapi get_lnnum() const override
  {
    return lnnum->lineNumber;
  }

  virtual int idaapi get_end_lnnum() const override
  {
    return lnnum->lineNumberEnd;
  }

  virtual int idaapi get_colnum() const override
  {
    return lnnum->columnNumber;
  }

  virtual int idaapi get_end_colnum() const override
  {
    return lnnum->columnNumberEnd;
  }

  virtual ea_t idaapi get_ea() const override
  {
    return ea_t(lnnum->va);
  }

  virtual asize_t idaapi get_size() const override
  {
    return lnnum->length;
  }

  virtual src_item_kind_t idaapi get_item_kind(const eval_ctx_t * /*ctx*/) const override
  {
    return lnnum->statement ? SRCIT_STMT : SRCIT_EXPR;
  }

  virtual source_item_ptr idaapi get_parent(src_item_kind_t /*max_kind*/) const override
  {
    source_item_t *ret = nullptr;
    ea_t ea = get_ea();
    if ( ea != BADADDR )
    {
      source_items_vec_builder_t items_builder(pdb_module);
      HRESULT hr = pdb_module->get_access()->sip_iterate_symbols_at_ea(
              ea, /*size=*/ 1, SymTagFunction, items_builder);
      if ( hr == S_OK && !items_builder.items.empty() )
      {
        DWORD sym_id = 0;
        pdb_symbol_t &pit = (pdb_symbol_t &) *items_builder.items[0];
        hr = pit.get_pdb_sym()->get_symIndexId(&sym_id);
        if ( hr == S_OK )
          ret = new_pdb_symbol(pdb_module, sym_id);
      }
    }
    return source_item_ptr(ret);
  }

  bool idaapi equals(const source_item_t *othr) const override
  {
    pdb_lnnum_item_t *other = (pdb_lnnum_item_t*) othr;
    return other != nullptr
        && other->lnnum != nullptr
        && lnnum->va != BADADDR
        && other->lnnum->va != BADADDR
        && lnnum->va == other->lnnum->va;
  }
};

//-------------------------------------------------------------------------
static src_item_kind_t find_srcitem_kind(pdb_sym_t *sym)
{
  src_item_kind_t kind = SRCIT_NONE;
  DWORD tag = 0;
  HRESULT hr = sym->get_symTag(&tag);
  if ( hr == S_OK )
  {
    switch ( tag )
    {
      case SymTagFunction:
        kind = SRCIT_FUNC;
        break;

      case SymTagBlock:
        kind = SRCIT_STMT;
        break;

      case SymTagData:
      case SymTagPublicSymbol:
        {
          DWORD loctype = LocIsNull;
          sym->get_locationType(&loctype);
          switch ( loctype )
          {
            case LocIsStatic:
            case LocIsTLS:
              kind = SRCIT_STTVAR;
              break;

            case LocIsRegRel:
              DWORD dwReg;
              if ( sym->get_registerId(&dwReg) == S_OK
                && (dwReg == CV_REG_EBP || dwReg == CV_AMD64_RSP) )
              {
                kind = SRCIT_LOCVAR;
              }
              break;

            case LocIsEnregistered:
              kind = SRCIT_LOCVAR;
              break;
          }
        }
        break;
    }
  }
  return kind;
}

//--------------------------------------------------------------------------
static source_item_t *new_pdb_symbol(pdb_modinfo_t *pdb_module, DWORD sym_id)
{
  pdb_sym_t *sym = pdb_module->get_access()->create_sym(sym_id);
  src_item_kind_t kind = find_srcitem_kind(sym);
  if ( kind != SRCIT_NONE )
    return new pdb_symbol_t(pdb_module, sym, /*own=*/ true, kind);
  delete sym;
  return nullptr;
}

//--------------------------------------------------------------------------
static source_item_t *new_pdb_symbol_or_delete(pdb_modinfo_t *pdb_module, pdb_sym_t *sym)
{
  src_item_kind_t kind = find_srcitem_kind(sym);
  if ( kind != SRCIT_NONE )
    return new pdb_symbol_t(pdb_module, sym, /*own=*/ true, kind);
  delete sym;
  return nullptr;
}

//--------------------------------------------------------------------------
class pdb_provider_t : public srcinfo_provider_t
{
  pdb_ctx_t &pv;
  pdb_modules_t modules;
  qstring search_path;
  pdb_modinfo_t *open_module(pdb_modules_t::iterator p)
  {
    pdb_modinfo_t &mod = p->second;
    if ( !mod.opened )
    {
      msg("PDBSRC: loading symbols for '%s'...\n", mod.path.c_str());
      HRESULT hr = mod.open(mod.path.c_str(), search_path.c_str(), mod.base);
      if ( FAILED(hr) )
      { // failed to open the corresponding pdb file
        modules.erase(p);
        return nullptr;
      }
      mod.opened = true;
    }
    return &mod;
  }
  pdb_modinfo_t *find_module(ea_t ea)
  {
    deb(IDA_DEBUG_SRCDBG, "PDB: find_module(%a)\n", ea);
    pdb_modules_t::iterator p = modules.lower_bound(ea);
    if ( p == modules.end() || p->first > ea )
    {
      if ( p == modules.begin() )
        return nullptr; // could not find the module

      --p;
      if ( p->first > ea || p->first+p->second.size <= ea )
        return nullptr;
    }
    return open_module(p);
  }
  pdb_modinfo_t *find_module(const char *path)
  {
    deb(IDA_DEBUG_SRCDBG, "PDB: find_module(%s)\n", path);
    pdb_modules_t::iterator p = modules.begin();
    for ( ; p != modules.end(); ++p )
      if ( p->second.path == path )
        return &p->second;
    return nullptr;
  }

public:
  bool idaapi enable_provider(bool enable) override;
  const char *idaapi set_options(const char *keyword, int value_type, const void *value) override;
  void idaapi add_module(const char *path, ea_t base, asize_t size) override;
  void idaapi del_module(ea_t base) override;
  void idaapi get_ready(void) override;
  int idaapi get_change_flags(void) override;
  source_item_iterator idaapi find_source_items(ea_t ea, asize_t size, src_item_kind_t level, bool) override;
  source_item_iterator idaapi find_source_items(source_file_t *sf, int lnnum, int colnum) override;
  source_file_iterator idaapi create_file_iterator(const char *filename) override;
  source_item_iterator idaapi create_item_iterator(const source_file_t *sf) override;
  bool idaapi apply_module_info(const char *path) override;
  source_item_ptr idaapi find_static_item(const char *name, ea_t ea) override;

  pdb_provider_t(pdb_ctx_t &_pv, const char *nm, const char *dnm)
    : srcinfo_provider_t(nm, dnm),
      pv(_pv)
  {}
  virtual ~pdb_provider_t(void) {}
};

//---------------------------------------------------------------------------
static bool is_pdb_supported(void)
{
  // PE files.
  filetype_t ftype = inf_get_filetype();
  if ( ftype == f_PE )
    return true;

  // Otherwise check for debugger.
  if ( dbg == nullptr )
    return false;

  // Win32 debugger.
  qstring platform;
  debapp_attrs_t pattrs;
  if ( dbg->get_debapp_attrs(&pattrs) )
    platform.swap(pattrs.platform);
  else
    platform = dbg->name;
  if ( platform.find("win32") != qstring::npos )
    return true;

  // Some other debugger (e.g.: "gdb") with unknown filetype.
  // This is needed to debug windows kernels under VMware.
  if ( ftype == 0 )
    return true;

  return false;
}

//--------------------------------------------------------------------------
bool idaapi pdb_provider_t::enable_provider(bool enable)
{
  if ( enable )
  {
    if ( !is_pdb_supported() )
      return false;
    pv.init_sympaths();
    if ( pv.full_sympath.empty() )
      search_path.qclear();
    else
      search_path = pv.full_sympath;
  }
  return enable;
}

//--------------------------------------------------------------------------
const char *idaapi pdb_provider_t::set_options(
        const char * /*keyword*/,
        int /*value_type*/,
        const void * /*value*/)
{
  // todo: add option to set search path
  return IDPOPT_BADKEY;
}

//--------------------------------------------------------------------------
void idaapi pdb_provider_t::add_module(
        const char *path,
        ea_t base,
        asize_t size)
{
  deb(IDA_DEBUG_DEBUGGER, "PDB: add_module(%s, [%a -> %a))\n", path, base, ea_t(base + size));
  pdb_modinfo_t &mod = modules[base];
  mod.path = path;
  mod.base = base;
  mod.size = size;
  // do not open the module immediately, we will do it only when we
  // really need the module
  mod.opened     = false;
  mod.type_cache = nullptr;
}


//--------------------------------------------------------------------------
void idaapi pdb_provider_t::del_module(ea_t base)
{
  modules.erase(base);
}

//--------------------------------------------------------------------------
void idaapi pdb_provider_t::get_ready(void)
{
  // nothing to do
}

//--------------------------------------------------------------------------
int idaapi pdb_provider_t::get_change_flags(void)
{
  // nothing ever changes?
  return 0;
}

//--------------------------------------------------------------------------
// Retrieve the line numbers into a map
// 'enumerator' will be freed by this function
static void lnnums_to_lnmap(lnmap_t *map, const pdb_lnnums_t &lnnums)
{
  const size_t lncnt = lnnums.size();
  if ( lncnt > 0 )
  {
    pdb_lnnum_vec_t vec;
    vec.resize(lncnt);
    for ( size_t i = 0; i < lncnt; ++i )
    {
      const pdb_lnnum_t &lnnum = lnnums[i];
      (*map)[lnnum.lineNumber].push_back(lnnum);
    }
  }
}

//--------------------------------------------------------------------------
class pdb_lnmap_iterator : public _source_item_iterator
{
  pdb_modinfo_t *pdb_module;
  lnmap_t lnmap;        // lnnum -> pdb_lnnum_vec_t
  pdb_lnnum_t *item;    // holds the answer after next()
  lnmap_t::iterator p;  // current lnnum
  size_t idx;           // current item on the line
public:

  pdb_lnmap_iterator(pdb_modinfo_t *_pdb_module, lnmap_t *map)
    : pdb_module(_pdb_module), item(nullptr), idx(0)
  {
    map->swap(lnmap);
    p = lnmap.end();
  }

  virtual ~pdb_lnmap_iterator(void)
  {
  }

  void idaapi release(void) override
  {
    delete this;
  }

  bool idaapi first(void) override
  {
    p = lnmap.begin();
    idx = 0;
    return next();
  }

  bool idaapi next(void) override
  {
    // at the end?
    if ( p == lnmap.end() )
      return false;

    size_t size = p->second.size();
    if ( idx >= size )
      return false;

    // remember the item to return when dereferenced
    item = &p->second[idx];

    // advance pointer
    if ( ++idx >= size )
    {
      // go to next pdb_lnnum_vec_t
      ++p;

      // reset the index in the vector
      idx = 0;
    }

    return true;
  }

  source_item_ptr idaapi operator *() override
  {
    pdb_lnnum_item_t *ret = new pdb_lnnum_item_t(pdb_module, item);
    return source_item_ptr(ret);
  }
};

//--------------------------------------------------------------------------
source_item_iterator idaapi pdb_provider_t::find_source_items(
        ea_t ea,
        asize_t size,
        src_item_kind_t level,
        bool)
{
  deb(IDA_DEBUG_SRCDBG, "PDB: find_source_items(ea=%a, size=%" FMT_64 "u)\n", ea, (uint64) size);
  pdb_item_iterator *ret = nullptr;
  pdb_modinfo_t *pdb_module = find_module(ea);
  if ( pdb_module != nullptr )
  {
    enum SymTagEnum tag;
    switch ( level )
    {
      default:
        INTERR(30171);

      case SRCIT_STMT:       // a statement (if/while/for...)
      case SRCIT_EXPR:       // an expression (a+b*c)
        {
          pdb_lnmap_iterator *ret2 = nullptr;
          pdb_lnnums_t lnnums;
          HRESULT hr = pdb_module->get_access()->sip_retrieve_lines_by_va(
                  &lnnums, ea, size);
          if ( hr == S_OK )
          {
            // Precompute the lines associated with the given address
            lnmap_t lnmap;
            lnnums_to_lnmap(&lnmap, lnnums);
            ret2 = new pdb_lnmap_iterator(pdb_module, &lnmap);
          }
          return source_item_iterator(ret2);
        }

      case SRCIT_FUNC:       // function
        tag = SymTagFunction;
        break;

      case SRCIT_LOCVAR:     // variable
        tag = SymTagData;
        break;
    }
    source_items_vec_builder_t items_builder(pdb_module);
    if ( pdb_module->get_access()->sip_iterate_symbols_at_ea(
                 ea, size, tag, items_builder) == S_OK )
    {
      ret = new pdb_item_iterator(pdb_module, items_builder.items);
    }
  }
  return source_item_iterator(ret);
}

//--------------------------------------------------------------------------
source_item_iterator idaapi pdb_provider_t::find_source_items(
        source_file_t *sf,
        int lnnum,
        int colnum)
{
  pdb_lnmap_iterator *ret = nullptr;
  pdb_source_file_t *psf = (pdb_source_file_t *)sf;
  pdb_lnnums_t lnnums;
  HRESULT hr = psf->pdb_module->get_access()->sip_retrieve_lines_by_coords(
          &lnnums, psf->file_id, lnnum, colnum);
  if ( hr == S_OK && !lnnums.empty() )
  {
    lnmap_t lnmap;
    lnnums_to_lnmap(&lnmap, lnnums);
    ret = new pdb_lnmap_iterator(psf->pdb_module, &lnmap);
  }
  return source_item_iterator(ret);
}

//--------------------------------------------------------------------------
static bool is_hexrays_filename(const char *fname)
{
  if ( fname != nullptr && *fname == '$' )
  {
    while ( true )
    {
      char c = *++fname;
      if ( c == '\0' )
        return true;
      if ( qislower(c) || !qisxdigit(c) )
        break;
    }
  }
  return false;
}

//--------------------------------------------------------------------------
source_file_iterator idaapi pdb_provider_t::create_file_iterator(const char *filename)
{
  pdb_file_iterator *ret = nullptr;
  // hack: check if the filename is like "$12345678"
  // if so, immediately return because such names are used by the decompiler sip
  if ( !is_hexrays_filename(filename) )
  {
    ret = new pdb_file_iterator();

    // Get a source file item iterators from each module
    for ( pdb_modules_t::iterator p=modules.begin(); p != modules.end(); )
    {
      pdb_modinfo_t *m = open_module(p++);
      if ( m != nullptr )
      {
        qvector<DWORD> files_ids;
        m->get_access()->sip_find_files(&files_ids, filename);
        for ( size_t i = 0; i < files_ids.size(); ++i )
        {
          pdb_file_iterator::entry_t &e = ret->entries.push_back();
          e.pdb_module = m;
          e.file_id = files_ids[i];
        }
      }
    }

    if ( ret->entries.empty() )
    {
      delete ret;
      ret = nullptr;
    }
  }
  return source_file_iterator(ret);
}

//--------------------------------------------------------------------------
source_item_iterator idaapi pdb_provider_t::create_item_iterator(const source_file_t *sf)
{
  pdb_source_file_t *psf = (pdb_source_file_t *) sf;
  pdb_item_iterator *ret = nullptr;
  pdb_modinfo_t *mod = psf->pdb_module;
  source_items_vec_builder_t svec_builder(mod);
  if ( mod->get_access()->sip_iterate_file_compilands(
               psf->file_id, svec_builder) == S_OK )
  {
    ret = new pdb_item_iterator(mod, svec_builder.items);
  }
  return source_item_iterator(ret);
}

//-------------------------------------------------------------------------
bool idaapi pdb_provider_t::apply_module_info(const char *path)
{
#ifdef ENABLE_REMOTEPDB
  if ( !is_win32_remote_debugger_loaded() )
    return false;
#endif

  pdb_modinfo_t *module = find_module(path);
  if ( module == nullptr )
    return false;
  pdbargs_t pdbargs;
  pdbargs.flags = PDBFLG_DBG_MODULE;
  if ( inf_get_filetype() != f_PE && !is_miniidb() )
    pdbargs.flags |= PDBFLG_ONLY_TYPES;
  pdbargs.loaded_base = module->base;
  pdbargs.input_path = module->path.c_str();
  show_wait_box("HIDECANCEL\nRetrieving symbol information from '%s'",
                qbasename(module->path.c_str()));
  // pdb_path: cleared
  // input_path: module name
  // loaded_base: module base
  bool rc = pv.apply_debug_info(pdbargs);
  hide_wait_box();
  return rc;
}

//-------------------------------------------------------------------------
source_item_ptr idaapi pdb_provider_t::find_static_item(
        const char *iname,
        ea_t ea)
{
  source_item_t *si = nullptr;
  pdb_modinfo_t *pdb_module = find_module(ea);

  // find in current module
  if ( pdb_module != nullptr )
    si = pdb_module->find_static_item_in_module(iname);

  // not found? search in other modules
  if ( si == nullptr )
  {
    pdb_modules_t::iterator p = modules.begin();
    for ( ; si == nullptr && p != modules.end(); ++p )
      if ( &p->second != pdb_module )
        si = p->second.find_static_item_in_module(iname);
  }

  return source_item_ptr(si);
}

//-------------------------------------------------------------------------
HRESULT source_items_vec_builder_t::visit_child(pdb_sym_t &child)
{
  pdb_sym_t *cur = pdb_module->get_access()->create_sym();
  cur->steal_data(child);
  source_item_t *si = new_pdb_symbol_or_delete(pdb_module, cur);
  if ( si != nullptr )
    items.push_back(source_item_ptr(si));
  return S_OK;
}

//--------------------------------------------------------------------------
void pdb_ctx_t::alloc_pdb_srcinfo_provider()
{
  pdb_srcinfo_provider = new pdb_provider_t(*this, "PDB", "PDB");
}

void pdb_ctx_t::free_pdb_srcinfo_provider()
{
  delete pdb_srcinfo_provider;
  pdb_srcinfo_provider = nullptr;
}

//----------------------------------------------------------------------------
srcinfo_provider_t *idaapi pdb_source_file_t::get_provider(void) const
{
  return pdb_module->pv.pdb_srcinfo_provider;
}

//----------------------------------------------------------------------------
srcinfo_provider_t *idaapi dummy_item_t::get_provider(void) const
{
  return pdb_module->pv.pdb_srcinfo_provider;
}
