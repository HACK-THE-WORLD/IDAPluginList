
//----------------------------------------------------------------------------
template <typename T>
struct dia_ptr_t
{
  dia_ptr_t() : thing(nullptr) {}

  ~dia_ptr_t()
  {
    if ( thing != nullptr )
      thing->Release();
  }

  T *thing;
};

//----------------------------------------------------------------------------
HRESULT local_pdb_access_t::_do_iterate_symbols_enumerator(
        IDiaEnumSymbols *sym_enum,
        children_visitor_t &visitor)
{
  std::set<DWORD> seen;
  HRESULT hr = S_OK;
  while ( true )
  {
    ULONG celt = 0;
    IDiaSymbol *pChild = nullptr;
    hr = sym_enum->Next(1, &pChild, &celt);
    if ( FAILED(hr) || celt != 1 )
    {
      hr = S_OK; // end of enumeration
      break;
    }
    pdb_sym_t *child = create_sym(pChild, true);
    pdb_sym_janitor_t janitor_pType(child);
    DWORD sym_id;
    hr = child->get_symIndexId(&sym_id);
    if ( hr != S_OK )
      break;
    // It seems we can, in some cases, iterate over the
    // same child more than once.
    // Fortunately, it appears to be the same symbol data;
    // and not another symbol w/ the same ID
    // See also: sip_iterate_symbols_at_ea()
    if ( seen.insert(sym_id).second )
    {
      hr = visitor.visit_child(*child);
      if ( FAILED(hr) )
        break;
    }
  }

  return hr;
}

//----------------------------------------------------------------------------
HRESULT local_pdb_access_t::safe_iterate_children(
        pdb_sym_t &sym,
        enum SymTagEnum type,
        children_visitor_t &visitor)
{
  HRESULT hr = E_FAIL;
  IDiaEnumSymbols *pEnumSymbols;
  try
  {
    QASSERT(30536, sym.whoami() == DIA_PDB_SYM);
    dia_pdb_sym_t &diasym = (dia_pdb_sym_t &)sym;
    hr = dia_session->findChildren(diasym.data, type, nullptr, nsNone, &pEnumSymbols);
    if ( hr == S_OK )
    {
      hr = _do_iterate_symbols_enumerator(pEnumSymbols, visitor);
      pEnumSymbols->Release();
    }
  }
  catch ( const std::bad_alloc & )
  {
    // try to free some memory before quitting (and saving the idb)
    delete this;
    nomem("pdb");
  }
  catch ( const std::exception &e )
  {
    error("Unhandled C++ exception: %s", e.what());
  }
  catch ( ... )
  {
    error("Unhandled C++ exception!");
  }
  return hr;
}

//----------------------------------------------------------------------------
HRESULT local_pdb_access_t::do_iterate_children(
        pdb_sym_t &sym,
        enum SymTagEnum type,
        children_visitor_t &visitor)
{
  int code;
  HRESULT hr = E_FAIL;
  __try
  {
    hr = safe_iterate_children(sym, type, visitor);
  }
  __except ( code=GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER )
  {
    // complain to the user
    ask_for_feedback(
            "%s: %s\n"
            "Is the corresponding PDB file valid?",
            pdbargs.input_path.c_str(),
            winerr(code));

    // we may arrive here because we ran out of memory
    // try to free some memory before quitting (and saving the idb)
    delete this;
    error(nullptr); // and die... this will save the idb
  }
  return hr;
}

//----------------------------------------------------------------------------
HRESULT local_pdb_access_t::load(pdb_sym_t &pdbsym, DWORD id)
{
  IDiaSymbol *dia_sym;
  HRESULT hr = dia_session->symbolById(id, &dia_sym);
  if ( hr == S_OK )
  {
    QASSERT(30543, pdbsym.whoami() == DIA_PDB_SYM);
    dia_pdb_sym_t &sym = (dia_pdb_sym_t &)pdbsym;
    sym.set_symbol_data(dia_sym, true);
  }
  return hr;
}

//-------------------------------------------------------------------------
HRESULT local_pdb_access_t::_copy_line_numbers(
        pdb_lnnums_t *out,
        IDiaEnumLineNumbers *enumerator) const
{
  LONG count = 0;
  HRESULT hr = enumerator->get_Count(&count);
  if ( hr == S_OK )
  {
    IDiaLineNumber *lines[64];
    ULONG got = 0;
    for ( LONG i=0; i < count; i += got )
    {
      // Fetch many line number information at once
      enumerator->Next(qnumber(lines), lines, &got);
      if ( got == 0 )
        break;

      for ( ULONG j=0; j < got; j++ )
      {
        IDiaLineNumber *l = lines[j];
        pdb_lnnum_t &lo = out->push_back();
        l->get_virtualAddress(&lo.va);
        l->get_length(&lo.length);
        l->get_columnNumber(&lo.columnNumber);
        l->get_columnNumberEnd(&lo.columnNumberEnd);
        l->get_lineNumber(&lo.lineNumber);
        l->get_lineNumberEnd(&lo.lineNumberEnd);
        l->get_statement(&lo.statement);
        IDiaSourceFile *f = nullptr;
        if ( l->get_sourceFile(&f) == S_OK )
        {
          f->get_uniqueId(&lo.file_id);
          f->Release();
        }
        lines[j]->Release();
      }
    }
  }
  return hr;
}

//-------------------------------------------------------------------------
HRESULT local_pdb_access_t::sip_retrieve_lines_by_va(
        pdb_lnnums_t *out,
        ULONGLONG va,
        ULONGLONG length)
{
  dia_ptr_t<IDiaEnumLineNumbers> pEnumLineNumbers;
  HRESULT hr = dia_session->findLinesByVA(va, length, &pEnumLineNumbers.thing);
  if ( hr == S_OK )
    hr = _copy_line_numbers(out, pEnumLineNumbers.thing);
  return hr;
}

//-------------------------------------------------------------------------
HRESULT local_pdb_access_t::sip_retrieve_lines_by_coords(
        pdb_lnnums_t *out,
        DWORD file_id,
        int lnnum,
        int colnum)
{
  dia_ptr_t<IDiaSourceFile> pFile;
  HRESULT hr = dia_session->findFileById(file_id, &pFile.thing);
  if ( FAILED(hr) )
    return hr;

  dia_ptr_t<IDiaEnumSymbols> pEnumSymbols;
  hr = pFile.thing->get_compilands(&pEnumSymbols.thing);
  if ( FAILED(hr) )
    return hr;

  while ( true )
  {
    ULONG got = 0;
    IDiaSymbol *compiland;
    pEnumSymbols.thing->Next(1, &compiland, &got);
    if ( got == 0 )
      break;

    dia_ptr_t<IDiaEnumLineNumbers> pEnumLineNumbers;
    HRESULT hr2;
    if ( lnnum == 0 )
      hr2 = dia_session->findLines(
              compiland,
              pFile.thing,
              &pEnumLineNumbers.thing);
    else
      hr2 = dia_session->findLinesByLinenum(
              compiland,
              pFile.thing,
              lnnum,
              colnum,
              &pEnumLineNumbers.thing);
    compiland->Release();

    if ( hr == S_OK )
      _copy_line_numbers(out, pEnumLineNumbers.thing);
  }
  return hr;
}

//-------------------------------------------------------------------------
HRESULT local_pdb_access_t::sip_iterate_symbols_at_ea(
        ULONGLONG va,
        ULONGLONG size,
        enum SymTagEnum tag,
        children_visitor_t &visitor)
{
  // See also: _do_iterate_symbols_enumerator
  std::set<DWORD> seen;

  ea_t cur = va;
  while ( true )
  {
    if ( cur >= va + size )
      break;

    ea_t old = cur;
    qnotused(old);

    LONG disp;
    IDiaSymbol *sym = nullptr;
    HRESULT hr = dia_session->findSymbolByVAEx(cur, tag, &sym, &disp);
    if ( FAILED(hr) || sym == nullptr )
      break;

    // perform all get_*'s on 'sym' _before_ the visitor is called: it might
    // very well 'steal' the symbol & destroy it in case it's not needed.
    // (see source_items_vec_builder_t::visit_child())
    pdb_sym_t *psym = create_sym(sym, true);
    pdb_sym_janitor_t janitor_psym(psym);
    DWORD sym_id;
    hr = psym->get_symIndexId(&sym_id);
    if ( hr != S_OK )
      break;

    ULONGLONG length = 0;
    sym->get_length(&length);

    if ( seen.insert(sym_id).second )
    {
      hr = visitor.visit_child(*psym);
      if ( FAILED(hr) )
        break;
    }

    cur -= disp;
    cur += length;

    QASSERT(30169, cur > old); // to avoid endless loops - i do not know if they are possible
  }
  return S_OK;
}

//-------------------------------------------------------------------------
HRESULT local_pdb_access_t::sip_iterate_file_compilands(
        DWORD file_id,
        children_visitor_t &visitor)
{
  dia_ptr_t<IDiaSourceFile> pFile;
  HRESULT hr = dia_session->findFileById(file_id, &pFile.thing);
  if ( FAILED(hr) )
    return hr;

  dia_ptr_t<IDiaEnumSymbols> pEnumSymbols;
  hr = pFile.thing->get_compilands(&pEnumSymbols.thing);
  if ( hr == S_OK )
    hr = _do_iterate_symbols_enumerator(pEnumSymbols.thing, visitor);
  return hr;
}

//-------------------------------------------------------------------------
HRESULT local_pdb_access_t::sip_retrieve_file_path(
        qstring *out,
        qstring *errbuf,
        DWORD file_id)
{
  dia_ptr_t<IDiaSourceFile> pFile;
  HRESULT hr = dia_session->findFileById(file_id, &pFile.thing);
  if ( hr == S_OK )
  {
    BSTR path;
    hr = pFile.thing->get_fileName(&path);
    if ( hr == S_OK )
    {
      utf16_utf8(out, path);
      SysFreeString(path);
    }
  }

  if ( FAILED(hr) )
  {
    if ( errbuf != nullptr )
      *errbuf = winerr(hr);
  }

  return hr;
}

//-------------------------------------------------------------------------
HRESULT local_pdb_access_t::_copy_files_ids(
        qvector<DWORD> *out,
        IDiaEnumSourceFiles *enumerator) const
{
  ULONG celt = 0;
  IDiaSourceFile *file = nullptr;
  while ( enumerator->Next(1, &file, &celt) == S_OK && celt > 0 )
  {
    DWORD file_id;
    if ( file->get_uniqueId(&file_id) == S_OK )
      out->push_back(file_id);
    file->Release();
  }
  return S_OK;
}

//-------------------------------------------------------------------------
HRESULT local_pdb_access_t::sip_retrieve_symbol_files(
        qvector<DWORD> *out,
        pdb_sym_t &sym)
{
  // Retrieve source file name associated with the current symbol
  QASSERT(30537, sym.whoami() == DIA_PDB_SYM);
  dia_pdb_sym_t &diasym = (dia_pdb_sym_t &)sym;
  BSTR path;
  HRESULT hr = diasym.data->get_sourceFileName(&path);
  if ( hr == S_OK ) // cannot use SUCCEEDED(hr) because S_OK means success
  {
    dia_ptr_t<IDiaEnumSourceFiles> pEnumSourceFiles;
    hr = dia_session->findFile(nullptr, path, nsfFNameExt, &pEnumSourceFiles.thing);
    SysFreeString(path);

    if ( hr == S_OK )
      _copy_files_ids(out, pEnumSourceFiles.thing);
  }
  return hr;
}

//-------------------------------------------------------------------------
HRESULT local_pdb_access_t::sip_find_files(
        qvector<DWORD> *out,
        const char *filename)
{
  qwstring fnamebuf;
  wchar16_t *fname = nullptr;
  if ( filename != nullptr )
  {
    qstring fnametmp = filename;
    utf8_utf16(&fnamebuf, &fnametmp[0]);
    fname = fnamebuf.begin();
  }

  dia_ptr_t<IDiaEnumSourceFiles> pEnumSourceFiles;
  HRESULT hr = dia_session->findFile(
          nullptr,
          fname,
          nsfFNameExt | nsfCaseInsensitive,
          &pEnumSourceFiles.thing);

  if ( hr == S_OK )
    _copy_files_ids(out, pEnumSourceFiles.thing);

  return hr;
}
