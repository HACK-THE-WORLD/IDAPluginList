
#include <pro.h>

#include "pdbremote.hpp"
#include "varser.hpp"

// Since we're using the win32 local stup debugger at the moment,
// this is necessary.
#include <dbg.hpp>

//-------------------------------------------------------------------------
bool is_win32_remote_debugger_loaded()
{
  return dbg != nullptr && dbg->is_remote() && streq(dbg->name, "win32");
}

//----------------------------------------------------------------------------
HRESULT remote_pdb_sym_t::get_classParent(pdb_sym_t *out)
{
  DWORD parent_id;
  HRESULT hr = data->get_dword(t_classParentId, &parent_id);
  if ( hr == S_OK )
    hr = pdb_access->load(*out, parent_id);
  return hr;
}

//----------------------------------------------------------------------------
HRESULT remote_pdb_sym_t::get_type(pdb_sym_t *out)
{
  DWORD type_id;
  HRESULT hr = data->get_dword(t_typeId, &type_id);
  if ( hr == S_OK )
    hr = pdb_access->load(*out, type_id);
  return hr;
}

//----------------------------------------------------------------------------
HRESULT remote_pdb_sym_t::get_lexicalParent(pdb_sym_t *out)
{
  DWORD lparent_id;
  HRESULT hr = data->get_dword(t_lexicalParentId, &lparent_id);
  if ( hr == S_OK )
    hr = pdb_access->load(*out, lparent_id);
  return hr;
}

//----------------------------------------------------------------------------
const uint32 sym_data_t::sizes[] =
{
  sizeof(BOOL),
  sizeof(DWORD),
  sizeof(DWORD64),
  sizeof(char *),
  sizeof(LONG),
  sizeof(ULONGLONG),
  sizeof(VARIANT)
};

//----------------------------------------------------------------------------
sym_data_t::sym_data_t(
        token_mask_t _tokens,
        const uchar *buf,
        size_t bufsize,
        packing_info_t _packing,
        bool *_warned)
  : present(_tokens),
    warned(_warned)
{
  memset(counters, 0, sizeof(counters));
  memset(children_infos, 0, sizeof(children_infos));

  if ( _packing == SYMDAT_PACKED )
  {
    const uchar *ptr = buf;
    const uchar *const end = buf + bufsize;
    for ( uint64 bit = t_start; bit != t_end; bit <<= 1 )
    {
      sym_token_t token = sym_token_t(bit);
      if ( !token_present(token) )
        continue;

      if ( is_sym_token_bool(token) )
      {
        counters[t_bool]++;
        uint8 tmp = unpack_db(&ptr, end);
        data.append(&tmp, sizeof(tmp));
      }
      else if ( is_sym_token_dword(token) )
      {
        counters[t_dword]++;
        uint32 tmp = unpack_dd(&ptr, end);
        data.append(&tmp, sizeof(tmp));
      }
      else if ( is_sym_token_dword64(token) )
      {
        counters[t_dword64]++;
        uint64 tmp = unpack_dq(&ptr, end);
        data.append(&tmp, sizeof(tmp));
      }
      else if ( is_sym_token_string(token) )
      {
        counters[t_string]++;
        char *tmp = qstrdup(unpack_str(&ptr, end));
        data.append(&tmp, sizeof(tmp));
      }
      else if ( is_sym_token_long(token) )
      {
        counters[t_long]++;
        LONG tmp = unpack_dd(&ptr, end);
        data.append(&tmp, sizeof(tmp));
      }
      else if ( is_sym_token_ulonglong(token) )
      {
        counters[t_ulonglong]++;
        ULONGLONG tmp = unpack_dq(&ptr, end);
        data.append(&tmp, sizeof(tmp));
      }
      else if ( is_sym_token_variant(token) )
      {
        counters[t_variant]++;
        VARIANT var;
        if ( varser_t::deserialize(var, &ptr, end) )
        {
          data.append(&var, sizeof(var));
        }
        else
        {
          if ( !*warned )
          {
            warning("The PDB file contains VARIANT items that cannot be deserialized.");
            *warned = true;
          }
        }
      }
      else
      {
        INTERR(30200);
      }
    }

    QASSERT(30201, data.size() == counters[t_bool]      * sizes[t_bool]
                                + counters[t_dword]     * sizes[t_dword]
                                + counters[t_dword64]   * sizes[t_dword64]
                                + counters[t_string]    * sizes[t_string]
                                + counters[t_long]      * sizes[t_long]
                                + counters[t_ulonglong] * sizes[t_ulonglong]
                                + counters[t_variant]   * sizes[t_variant]);
    QASSERT(30202, ptr == end);
  }
  else
  {
    data.append(buf, bufsize);
    // Not supported yet. All that's left to do
    // is count the types (counters[]), though.
    INTERR(30203);
  }
}

//----------------------------------------------------------------------------
sym_data_t::~sym_data_t()
{
  for ( int i = 0; i < SymTagMax; i++ )
  {
    children_t &children = children_infos[i];
    if ( children.ids != nullptr )
    {
      qfree(children.ids);
      children.ids = nullptr;
      children.cnt = 0;
    }
  }

  uint8 nstring = counters[t_string];
  if ( nstring > 0 )
  {
    char **cur_str_ptr = (char **)string_ptr(t_string_start);
    for ( uint8 i = 0; i < nstring; i++, cur_str_ptr++ )
      qfree(*cur_str_ptr);
  }

  uint8 nvariant = counters[t_variant];
  if ( nvariant > 0 )
  {
    VARIANT *cur_variant_ptr = (VARIANT *)variant_ptr(t_variant_start);
    for ( uint8 i = 0; i < nvariant; i++, cur_variant_ptr++ )
      if ( cur_variant_ptr->vt == VT_LPSTR )
        qfree(cur_variant_ptr->punkVal);
  }

  warned = nullptr;
}


#define READ_IF_FOUND(type, fun)                \
  const type *ptr = fun##_ptr(token);           \
  if ( ptr == nullptr )                            \
  {                                             \
    return S_FALSE;                             \
  }                                             \
  else                                          \
  {                                             \
    *out = *ptr;                                \
    return S_OK;                                \
  }

//----------------------------------------------------------------------------
HRESULT sym_data_t::get_bool(sym_token_t token, BOOL *out) const
{
  READ_IF_FOUND(BOOL, bool)
}

//----------------------------------------------------------------------------
HRESULT sym_data_t::get_dword(sym_token_t token, DWORD *out) const
{
  READ_IF_FOUND(DWORD, dword)
}

//----------------------------------------------------------------------------
HRESULT sym_data_t::get_dword64(sym_token_t token, DWORD64 *out) const
{
  READ_IF_FOUND(DWORD64, dword64)
}

//----------------------------------------------------------------------------
HRESULT sym_data_t::get_string(sym_token_t token, qstring *out) const
{
  READ_IF_FOUND(char *, string)
}

//----------------------------------------------------------------------------
HRESULT sym_data_t::get_dword(sym_token_t token, LONG *out) const
{
  READ_IF_FOUND(LONG, long)
}

//----------------------------------------------------------------------------
HRESULT sym_data_t::get_ulonglong(sym_token_t token, ULONGLONG *out) const
{
  READ_IF_FOUND(ULONGLONG, uint64)
}

//----------------------------------------------------------------------------
HRESULT sym_data_t::get_variant(sym_token_t token, VARIANT *out) const
{
  READ_IF_FOUND(VARIANT, variant)
}

#undef READ_IF_FOUND

//----------------------------------------------------------------------------
const void *sym_data_t::any_ptr(sym_token_t token, sym_token_t start, sym_token_t end) const
{
  if ( !token_present(token) )
    return nullptr;

  static const sym_token_t ends[] =
  {
    t_bool_end,
    t_dword_end,
    t_dword64_end,
    t_string_end,
    t_long_end,
    t_ulonglong_end,
    t_variant_end,
  };
  CASSERT(qnumber(ends) == qnumber(counters));
  CASSERT(qnumber(sizes) == qnumber(counters));

  // count how many bytes we have to skip and determine the type size
  uint32 type_size = 0;
  const uchar *ptr = data.begin();
  for ( int i=0; i < qnumber(ends); i++ )
  {
    if ( token <= ends[i] )
    {
      type_size = sizes[i];
      break;
    }
    ptr += counters[i] * sizes[i];
  }
  QASSERT(30204, type_size != 0);

  // how many tokens of our type we have to skip?
  uint32 bit;
  for ( bit = start; bit <= end; bit <<= 1 )
  {
    sym_token_t t = sym_token_t(bit);
    if ( token_present(t) )
    {
      if ( t == token )
        return ptr;
      ptr += type_size;
    }
  }
  return nullptr; // did not find the requested token
}

//----------------------------------------------------------------------------
remote_pdb_access_t::~remote_pdb_access_t()
{
  typedef std::map<DWORD,sym_data_t*>::iterator iter;
  for ( iter it = cache.begin(), end = cache.end(); it != end; it++ )
    delete it->second;

  close_connection();
}

//----------------------------------------------------------------------------
void remote_pdb_access_t::close_connection()
{
  if ( remote_session_id > 0 )
  {
    bytevec_t dummy;
    perform_op(WIN32_IOCTL_PDB_CLOSE, dummy, nullptr);
    remote_session_id = -1;
  }

  if ( !was_connected && dbg != nullptr )
    dbg->term_debugger();
}

//----------------------------------------------------------------------
// load and connect to a remote win32 debugger, if necessary
bool remote_pdb_access_t::load_win32_debugger(void)
{
  was_connected = false;
  if ( dbg != nullptr && !is_win32_remote_debugger_loaded() )
  {
    // a debugger is loaded, but it's not a remote win32
    warning("Loading PDB symbols requires a remote win32 debugger. "
            "Please stop the current debugging session and try again.");
    return false;
  }
  if ( get_process_state() != DSTATE_NOTASK )
  {
    // the debugger is already connected
    was_connected = true;
    return true;
  }

  netnode pdbnode(PDB_NODE_NAME);
  pdbnode.altset(PDB_LOADING_WIN32_DBG, true);
  bool win32_dbg_loaded = load_debugger("win32", true) && dbg != nullptr;
  pdbnode.altdel(PDB_LOADING_WIN32_DBG);

  if ( !win32_dbg_loaded )
  {
    warning("Could not load remote Win32 debugger.");
    return false;
  }

  qstring server;
  server = host[0] != '\0' ? host : "localhost";

  qstring pass;
  if ( pwd != nullptr )
    pass = pwd;

  qstring dbg_errbuf;
  while ( !dbg->init_debugger(server.c_str(), port, pass.c_str(), &dbg_errbuf) )
  {
    if ( batch ) // avoid endless (and useless) loop in batch mode
    {
      msg("PDB: Could not load remote Win32 debugger\n");
      return false;
    }
    if ( !dbg_errbuf.empty() )
      msg("%s\n", dbg_errbuf.begin());
    // hrw
    const char *winremote = inf_is_64bit() ? "win64_remote64.exe" : "win32_remote.exe";
    qstring formstr;
    formstr.sprnt(
      "Remote PDB server\n"
      "In order to load PDB information, IDA requires a running %s debugger server\n"
      "running on a Windows host, but it could not connect to the %s debugger\n"
      "at the current specified address.\n"
      "Please make sure that %s is running there.\n\n"
      "<#Name of the remote host#~H~ostname :q:1023:30::> <#Remote port number#Po~r~t:D::8::>\n"
      "<#Password for the remote host#Pass~w~ord :q:1023:30::>\n"
      "Hint: to change this permanently, edit pdb.cfg.\n\n",
      winremote, winremote, winremote);
    uval_t sport = port;
    int r = ask_form(formstr.c_str(), &server, &sport, &pass);
    if ( r != 1 )
      return false;
    port = sport;
  }
  msg("PDB: successfully connected to %s\n", server.c_str());
  return true;
}


//----------------------------------------------------------------------------
#define REPORT_ERROR(Msg, Rc)                   \
  do                                            \
  {                                             \
    qfree(outbuf);                              \
    qstrncpy(errbuf, Msg, sizeof(errbuf));      \
    return Rc;                                  \
  } while ( false )

//-------------------------------------------------------------------------
HRESULT remote_pdb_access_t::open_connection()
{
  // Load win32 debugger (FIXME: Should just use an RPC client, not a full debugger!)
  if ( !load_win32_debugger() )
    return S_FALSE;

  // Init remote.
  bytevec_t oper;
  compiler_info_t cc;
  inf_get_cc(&cc);
  oper.append(&cc, sizeof(cc));
  oper.pack_str(pdbargs.pdb_path);
  oper.pack_str(pdbargs.input_path);
  oper.append(&pdbargs.pdb_sign, sizeof(pdbargs.pdb_sign));
  oper.pack_str(pdbargs.spath);
  oper.pack_ea64(get_base_address());
  oper.pack_dd(pdbargs.flags);

  void *outbuf = nullptr;
  ssize_t outsize = 0;
  ioctl_pdb_code_t rc = send_ioctl(
          WIN32_IOCTL_PDB_OPEN,
          oper.begin(), oper.size(), &outbuf, &outsize);
  if ( rc != pdb_ok || outsize < 1 )
    REPORT_ERROR(
            "PDB symbol extraction is not supported by the remote server",
            E_FAIL);

  // remote PDB session has become active
  bytevec_t sidbuf;
  {
    const uchar *ptr = (const uchar *) outbuf;
    const uchar *const end = ptr + outsize;
    remote_session_id = unpack_dd(&ptr, end);
    QASSERT(30493, remote_session_id > 0);
    sidbuf.pack_dd(remote_session_id);
  }

  // now, do the polling game.
  bool done = false;
  while ( !done )
  {
    qfree(outbuf);
    outbuf = nullptr;
    qsleep(100);
    user_cancelled(); // refresh the output window
    rc = send_ioctl(
            WIN32_IOCTL_PDB_OPERATION_COMPLETE,
            sidbuf.begin(), sidbuf.size(),
            &outbuf, &outsize);
    if ( rc != pdb_ok || outsize <= 0 )
      REPORT_ERROR(
              "remote server reported error while opening PDB",
              E_FAIL);
    const uchar *ptr = (const uchar *)outbuf;
    const uchar *const end = ptr + outsize;
    pdb_op_completion_t status = pdb_op_completion_t(unpack_dd(&ptr, end));
    done = true; // only 'not complete' status will make us continue.
    switch ( status )
    {
      case pdb_op_not_complete:
        done = false;
        break;
      case pdb_op_complete:
        {
          set_global_symbol_id(unpack_dd(&ptr, end));
          set_machine_type(unpack_dd(&ptr, end));
          set_dia_version(unpack_dd(&ptr, end));
          const char *fname = unpack_str(&ptr, end);
          // TODO The printed path is wrong (test with pc_gdb_notepad.exe).
          msg("PDB: opened \"%s\"\n", fname);
        }
        break;
      case pdb_op_failure:
        {
          const char *errmsg = unpack_str(&ptr, end);
          REPORT_ERROR(errmsg, E_FAIL);
          // if opening pdb fails, win32_remote closes the MSDIA pdb
          // session automatically.
          remote_session_id = -1;   //-V779 Unreachable code detected
        }
        break;
      default:
        break;
    }
  }
  qfree(outbuf);

  return remote_session_id > 0 ? S_OK : E_FAIL;
}


//----------------------------------------------------------------------------
ioctl_pdb_code_t remote_pdb_access_t::send_ioctl(
        int fn,
        const void *buf,
        size_t size,
        void **outbuf,
        ssize_t *outsz)
{
  if ( dbg == nullptr )
    return pdb_error;

  deb(IDA_DEBUG_DEBUGGER, "PDB: send_ioctl(fn=%d, size=%" FMT_Z ")\n", fn, size);
  // internal_ioctl() will either send the request to the debugger thread if
  // it exists (i.e., we are in a debugging session), or perform it directly.
  ioctl_pdb_code_t code = ioctl_pdb_code_t(internal_ioctl(fn, buf, size, outbuf, outsz));
  // ioctl_pdb_code_t code = ioctl_pdb_code_t(internal_ioctl  dbg->send_ioctl(fn, buf, size, outbuf, outsz));
  deb(IDA_DEBUG_DEBUGGER, "PDB: send_ioctl(fn=%d) complete. Code=%d\n", fn, int(code));
  return code;
}

//-------------------------------------------------------------------------
HRESULT remote_pdb_access_t::_do_iterate_symbols_ids(
        const DWORD *ids,
        size_t count,
        enum SymTagEnum type,
        children_visitor_t &visitor)
{
  HRESULT hr = S_OK;
  for ( size_t i = 0, n = count; i < n; ++i, ++ids )
  {
    DWORD tag;
    pdb_sym_t *cur = create_sym(*ids);
    pdb_sym_janitor_t janitor_cur(cur);
    if ( type == SymTagNull
      || cur->get_symTag(&tag) == S_OK && tag == type )
    {
      hr = visitor.visit_child(*cur);
      if ( FAILED(hr) )
        break;
    }
  }
  return hr;
}

//----------------------------------------------------------------------------
HRESULT remote_pdb_access_t::do_iterate_children(
        pdb_sym_t &sym,
        enum SymTagEnum type,
        children_visitor_t &visitor)
{
  sym_data_t *symbol;
  ioctl_pdb_code_t code = get_sym_data(sym, &symbol);
  QASSERT(30205, code == pdb_ok);
  QASSERT(30206, type < SymTagMax);
  sym_data_t::children_t &children = symbol->children_infos[type];
  if ( children.ids == nullptr )
  {
    qvector<DWORD> children_ids;
    code = fetch_children_infos(sym, type, &children_ids);
    if ( code == pdb_ok )
    {
      children.cnt = children_ids.size();
      children.ids = children_ids.extract();
    }
  }

  HRESULT hr = E_FAIL;
  if ( code == pdb_ok )
    hr = _do_iterate_symbols_ids(
            children.ids,
            children.cnt,
            type,
            visitor);
  return hr;
}

//----------------------------------------------------------------------------
HRESULT remote_pdb_access_t::load(pdb_sym_t &pdbsym, DWORD id)
{
  sym_data_t *sd;
  if ( get_sym_data(id, &sd) != pdb_ok )
    return E_FAIL;
  QASSERT(30544, pdbsym.whoami() == REMOTE_PDB_SYM);
  remote_pdb_sym_t &sym = (remote_pdb_sym_t &)pdbsym;
  sym.set_symbol_data(sd);
  return S_OK;
}

#define HAS_REMAINING_OR_FAIL(Ptr, End)         \
  do                                            \
  {                                             \
    if ( Ptr >= End )                           \
      return E_FAIL;                            \
  } while ( false )

#define ALL_CONSUMED_OR_FAIL(Ptr, End)          \
  do                                            \
  {                                             \
    if ( Ptr != End )                           \
      return E_FAIL;                            \
  } while ( false )

//-------------------------------------------------------------------------
HRESULT remote_pdb_access_t::handle_fetch_lnnums(
        pdb_lnnums_t *out,
        const bytevec_t &resp) const
{
  const uchar *ptr = resp.begin();
  const uchar *const end = resp.end();
  uint32 nlines = unpack_dd(&ptr, end);
  for ( uint32 i = 0; i < nlines; ++i )
  {
    HAS_REMAINING_OR_FAIL(ptr, end);
    pdb_lnnum_t &ln = out->push_back();
    ln.va = ULONGLONG(unpack_ea64(&ptr, end));
    ln.length = unpack_dd(&ptr, end);
    ln.columnNumber = unpack_dd(&ptr, end);
    ln.columnNumberEnd = unpack_dd(&ptr, end);
    ln.lineNumber = unpack_dd(&ptr, end);
    ln.lineNumberEnd = unpack_dd(&ptr, end);
    ln.file_id = unpack_dd(&ptr, end);
    ln.statement = unpack_db(&ptr, end);
  }
  ALL_CONSUMED_OR_FAIL(ptr, end);
  return S_OK;
}

//-------------------------------------------------------------------------
HRESULT remote_pdb_access_t::sip_retrieve_lines_by_va(
        pdb_lnnums_t *out,
        ULONGLONG va,
        ULONGLONG length)
{
  bytevec_t req, resp;
  req.pack_ea64(va);
  req.pack_dq(length);
  ioctl_pdb_code_t code = perform_op(
          WIN32_IOCTL_PDB_SIP_FETCH_LINES_BY_VA, req, &resp);
  return code == pdb_ok ? handle_fetch_lnnums(out, resp) : E_FAIL;
}

//-------------------------------------------------------------------------
HRESULT remote_pdb_access_t::sip_retrieve_lines_by_coords(
        pdb_lnnums_t *out,
        DWORD file_id,
        int lnnum,
        int colnum)
{
  bytevec_t req, resp;
  req.pack_dd(file_id);
  req.pack_dd(lnnum);
  req.pack_dd(colnum);
  ioctl_pdb_code_t code = perform_op(
          WIN32_IOCTL_PDB_SIP_FETCH_LINES_BY_COORDS, req, &resp);
  return code == pdb_ok ? handle_fetch_lnnums(out, resp) : E_FAIL;
}

//-------------------------------------------------------------------------
HRESULT remote_pdb_access_t::sip_iterate_symbols_at_ea(
        ULONGLONG va,
        ULONGLONG size,
        enum SymTagEnum tag,
        children_visitor_t &visitor)
{
  qvector<DWORD> ids;
  bytevec_t req;
  req.pack_ea64(va);
  req.pack_dq(size);
  req.pack_dd(tag);
  ioctl_pdb_code_t code = perform_op(
          WIN32_IOCTL_PDB_SIP_FETCH_SYMBOLS_AT_VA, req, &ids);
  if ( code != pdb_ok )
    return E_FAIL;
  return _do_iterate_symbols_ids(
          ids.begin(),
          ids.size(),
          tag,
          visitor);
}

//-------------------------------------------------------------------------
HRESULT remote_pdb_access_t::sip_iterate_file_compilands(
        DWORD file_id,
        children_visitor_t &visitor)
{
  qvector<DWORD> ids;
  bytevec_t req;
  req.pack_dd(file_id);
  ioctl_pdb_code_t code = perform_op(
          WIN32_IOCTL_PDB_SIP_FETCH_FILE_COMPILANDS, req, &ids);
  if ( code != pdb_ok )
    return E_FAIL;
  return _do_iterate_symbols_ids(
          ids.begin(),
          ids.size(),
          SymTagNull,
          visitor);
}

//-------------------------------------------------------------------------
HRESULT remote_pdb_access_t::sip_retrieve_file_path(
        qstring *out,
        qstring *,
        DWORD file_id)
{
  bytevec_t req, resp;
  req.pack_dd(file_id);
  ioctl_pdb_code_t code = perform_op(
          WIN32_IOCTL_PDB_SIP_FETCH_FILE_PATH, req, &resp);
  if ( code != pdb_ok )
    return E_FAIL;

  const uchar *ptr = resp.begin();
  const uchar *const end = resp.end();
  HAS_REMAINING_OR_FAIL(ptr, end);
  *out = unpack_str(&ptr, end);
  ALL_CONSUMED_OR_FAIL(ptr, end);
  return S_OK;
}

//-------------------------------------------------------------------------
HRESULT remote_pdb_access_t::handle_fetch_file_ids(
        qvector<DWORD> *out,
        const bytevec_t &resp) const
{
  const uchar *ptr = resp.begin();
  const uchar *const end = resp.end();
  uint32 nfiles = unpack_dd(&ptr, end);
  out->resize(nfiles);
  for ( uint32 i = 0; i < nfiles; ++i )
  {
    HAS_REMAINING_OR_FAIL(ptr, end);
    out->at(i) = unpack_dd(&ptr, end);
  }
  ALL_CONSUMED_OR_FAIL(ptr, end);
  return S_OK;
}

//-------------------------------------------------------------------------
HRESULT remote_pdb_access_t::sip_retrieve_symbol_files(
        qvector<DWORD> *out,
        pdb_sym_t &pdbsym)
{
  QASSERT(30538, pdbsym.whoami() == REMOTE_PDB_SYM);
  remote_pdb_sym_t &sym = (remote_pdb_sym_t &)pdbsym;
  bytevec_t req, resp;
  req.pack_dd(sym.data->get_id());
  ioctl_pdb_code_t code = perform_op(
          WIN32_IOCTL_PDB_SIP_FETCH_SYMBOL_FILES, req, &resp);
  return code == pdb_ok ? handle_fetch_file_ids(out, resp) : E_FAIL;
}

//-------------------------------------------------------------------------
HRESULT remote_pdb_access_t::sip_find_files(
        qvector<DWORD> *out,
        const char *fileName)
{
  bytevec_t req, resp;
  req.pack_str(fileName);
  ioctl_pdb_code_t code = perform_op(
          WIN32_IOCTL_PDB_SIP_FIND_FILES, req, &resp);
  return code == pdb_ok ? handle_fetch_file_ids(out, resp) : E_FAIL;
}

//----------------------------------------------------------------------------
DWORD remote_pdb_access_t::build_and_register_sym_data(
        const uchar **raw,
        const uchar *end)
{
  DWORD child_sym     = unpack_dd(raw, end);
  token_mask_t tokens = unpack_dq(raw, end);
  uint32 datasz       = unpack_dd(raw, end);
  const uchar *data = (const uchar *)unpack_obj_inplace(raw, end, datasz);
  cache[child_sym] = new sym_data_t(tokens, data, datasz, SYMDAT_PACKED, &warned);
  return child_sym;
}

//----------------------------------------------------------------------------
void remote_pdb_access_t::handle_fetch_response(
        const uchar **ptr,
        const uchar *end,
        qvector<DWORD> *ids_storage)
{
  // Build cache!
  uint32 nchildren = 0;
  unpack_obj(&nchildren, sizeof(nchildren), ptr, end);
  if ( ids_storage != nullptr )
    ids_storage->reserve(nchildren);
  for ( uint32 i = 0; i < nchildren; i++ )
  {
    DWORD created = build_and_register_sym_data(ptr, end);
    if ( ids_storage != nullptr )
      ids_storage->push_back(created);
  }
}

//----------------------------------------------------------------------------
ioctl_pdb_code_t remote_pdb_access_t::perform_op(
        int op_type,
        const bytevec_t &oper,
        void *data)
{
  void *outbuf = nullptr;
  ssize_t outsize = 0;
  bytevec_t raw;
  QASSERT(30494, remote_session_id > 0);
  raw.pack_dd(remote_session_id);
  if ( !oper.empty() )
    raw.append(oper.begin(), oper.size());
  ioctl_pdb_code_t rc = send_ioctl(op_type, raw.begin(), raw.size(), &outbuf, &outsize);
  if ( rc != pdb_ok )
    REPORT_ERROR(
            "PDB symbol extraction is not supported by the remote server",
            rc);

  // msg(" ok\n");

  // By now, the operation will be done. Let's parse
  // the contents of the output buffer.
  const uchar *ptr = (const uchar *)outbuf;
  const uchar *const end = ptr + outsize;
  switch ( op_type )
  {
    case WIN32_IOCTL_PDB_FETCH_SYMBOL:
    case WIN32_IOCTL_PDB_FETCH_CHILDREN:
    case WIN32_IOCTL_PDB_SIP_FETCH_SYMBOLS_AT_VA:
    case WIN32_IOCTL_PDB_SIP_FETCH_FILE_COMPILANDS:
      QASSERT(30207, outsize >= (4 /*(unpacked) nchildren*/));
      handle_fetch_response(&ptr, end, (qvector<DWORD> *)data);
      break;
    case WIN32_IOCTL_PDB_SIP_FETCH_LINES_BY_VA:
    case WIN32_IOCTL_PDB_SIP_FETCH_LINES_BY_COORDS:
    case WIN32_IOCTL_PDB_SIP_FETCH_FILE_PATH:
    case WIN32_IOCTL_PDB_SIP_FETCH_SYMBOL_FILES:
    case WIN32_IOCTL_PDB_SIP_FIND_FILES:
      {
        bytevec_t *bvout = (bytevec_t *) data;
        bvout->append(outbuf, outsize);
      }
      break;
    case WIN32_IOCTL_PDB_CLOSE:
      break;
    default:
      INTERR(30208);
  }

  qfree(outbuf);

  return pdb_ok;
}

//----------------------------------------------------------------------------
ioctl_pdb_code_t remote_pdb_access_t::fetch_children_infos(
        pdb_sym_t &pdbsym,
        enum SymTagEnum type,
        qvector<DWORD> *children_ids)
{
  QASSERT(30539, pdbsym.whoami() == REMOTE_PDB_SYM);
  remote_pdb_sym_t &sym = (remote_pdb_sym_t &)pdbsym;
  bytevec_t oper;
  oper.pack_dd(sym.data->get_id());
  oper.pack_dd(type);
  // msg("Fetching children: 0x%x", sym);
  return perform_op(WIN32_IOCTL_PDB_FETCH_CHILDREN, oper, children_ids);
}

//----------------------------------------------------------------------------
sym_data_t *remote_pdb_access_t::get_sym_data_from_cache(DWORD id)
{
  typedef std::map<DWORD,sym_data_t*>::const_iterator citer;
  citer it = cache.find(id);
  if ( it != cache.end() )
    return it->second;
  return nullptr;
}

//----------------------------------------------------------------------------
ioctl_pdb_code_t remote_pdb_access_t::get_sym_data(pdb_sym_t &pdbsym, sym_data_t **out)
{
  QASSERT(30540, pdbsym.whoami() == REMOTE_PDB_SYM);
  remote_pdb_sym_t &sym = (remote_pdb_sym_t &)pdbsym;
  DWORD id = sym.data->get_id();
  return get_sym_data(id, out);
}

//----------------------------------------------------------------------------
ioctl_pdb_code_t remote_pdb_access_t::get_sym_data(DWORD id, sym_data_t **out)
{
  sym_data_t *found = get_sym_data_from_cache(id);
  if ( found != nullptr )
  {
    *out = found;
    return pdb_ok;
  }
  else
  {
    bytevec_t oper;
    oper.pack_dd(id);
    ioctl_pdb_code_t rc = perform_op(WIN32_IOCTL_PDB_FETCH_SYMBOL, oper, nullptr);
    if ( rc == pdb_ok )
    {
      rc = get_sym_data(id, out);
      QASSERT(30209, rc == pdb_ok);
    }
    return rc;
  }
}
