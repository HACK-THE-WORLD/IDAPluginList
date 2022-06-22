
#ifndef PDBLOCAL_HPP
#define PDBLOCAL_HPP

// The PDB related code that works on Windows and uses DIA

//----------------------------------------------------------------------------
class local_pdb_access_t : public pdb_access_t
{
public:
  local_pdb_access_t(
        const pdbargs_t &args,
        IDiaDataSource *pSource,
        IDiaSession *pSession,
        IDiaSymbol *pGlobal)
    : pdb_access_t(args),
      dia_source(pSource),
      dia_session(pSession),
      dia_global(pGlobal)
  {
  }

  virtual ~local_pdb_access_t()
  {
#define RELEASE(thing) do { if ( thing != nullptr ) { (thing)->Release(); thing = nullptr; } } while ( false )
    RELEASE(dia_global);
    RELEASE(dia_session);
    RELEASE(dia_source);
#undef RELEASE
    set_global_symbol_id(BADSYM);
  }

  HRESULT init()
  {
    DWORD id;
    HRESULT hr = dia_global->get_symIndexId(&id);
    if ( hr != S_OK )
      return hr;
    set_global_symbol_id(id);

    DWORD64 load_addr;
    hr = dia_session->get_loadAddress(&load_addr);
    if ( hr != S_OK )
      return hr;
    set_base_address(load_addr);

    return S_OK;
  }

  virtual HRESULT do_iterate_children(
        pdb_sym_t &sym,
        enum SymTagEnum type,
        children_visitor_t &visitor) override;
  virtual HRESULT load(pdb_sym_t &sym, DWORD id) override;

  virtual HRESULT sip_retrieve_lines_by_va(
        pdb_lnnums_t *out,
        ULONGLONG va,
        ULONGLONG length) override;
  virtual HRESULT sip_retrieve_lines_by_coords(
        pdb_lnnums_t *out,
        DWORD file_id,
        int lnnum,
        int colnum) override;
  virtual HRESULT sip_iterate_symbols_at_ea(
        ULONGLONG va,
        ULONGLONG size,
        enum SymTagEnum tag,
        children_visitor_t &visitor) override;
  virtual HRESULT sip_iterate_file_compilands(
        DWORD file_id,
        children_visitor_t &visitor) override;
  virtual HRESULT sip_retrieve_file_path(
        qstring *out,
        qstring *errbuf,
        DWORD file_id) override;
  virtual HRESULT sip_retrieve_symbol_files(
        qvector<DWORD> *out,
        pdb_sym_t &sym) override;
  virtual HRESULT sip_find_files(
        qvector<DWORD> *out,
        const char *name) override;

  virtual pdb_sym_t *create_sym(void *data, bool own) override
  {
    IDiaSymbol *sym = (IDiaSymbol *)data;
    return new dia_pdb_sym_t(this, sym, own);
  }
  pdb_sym_t *create_sym(DWORD sym_id) { return pdb_access_t::create_sym(sym_id); }

  IDiaDataSource *dia_source;
  IDiaSession    *dia_session;
  IDiaSymbol     *dia_global;

private:
  HRESULT safe_iterate_children(
        pdb_sym_t &sym,
        enum SymTagEnum type,
        children_visitor_t &visitor);
  HRESULT _do_iterate_symbols_enumerator(
        IDiaEnumSymbols *sym_enum,
        children_visitor_t &visitor);

  HRESULT _copy_line_numbers(
        pdb_lnnums_t *out,
        IDiaEnumLineNumbers *enumerator) const;

  HRESULT _copy_files_ids(
        qvector<DWORD> *out,
        IDiaEnumSourceFiles *enumerator) const;

  DECLARE_UNCOPYABLE(local_pdb_access_t)
};


#endif // PDBLOCAL_HPP
