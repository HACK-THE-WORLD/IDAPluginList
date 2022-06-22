
#ifndef PDBREMOTE_HPP
#define PDBREMOTE_HPP

#include <network.hpp>
#include "../../dbg/win32/win32_rpc.h"
#include "pdbaccess.hpp"

// The PDB related code that works on Unix
// It connects to a Windows computer and asks to retrieve PDB info

//----------------------------------------------------------------------------
bool is_win32_remote_debugger_loaded();

//----------------------------------------------------------------------------
//-V:remote_pdb_access_t:730 not all members of a class are initialized inside the constructor
class remote_pdb_access_t : public pdb_access_t
{
public:
  remote_pdb_access_t(
        const pdbargs_t &args,
        const char *_host,
        int _port,
        const char *_pwd)
    : pdb_access_t(args),
      host(_host),
      port(_port),
      pwd(_pwd),
      remote_session_id(-1)
  {
    set_base_address(args.loaded_base);
  }

  virtual ~remote_pdb_access_t();

  // Open connection, create PDB session.
  HRESULT open_connection();
  // Close PDB session, close connection.
  void close_connection();

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

  virtual pdb_sym_t *create_sym(void *data, bool) override
  {
    sym_data_t *sym = (sym_data_t *)data;
    return new remote_pdb_sym_t(this, sym);
  }
  pdb_sym_t *create_sym(DWORD sym_id) { return pdb_access_t::create_sym(sym_id); }

  // Possibly remote operation.
  // If nullptr is returned, it means the symbol is not available, nor
  // could it be fetched remotely.
  ioctl_pdb_code_t get_sym_data(pdb_sym_t &sym, sym_data_t **);
  ioctl_pdb_code_t get_sym_data(DWORD sym_id, sym_data_t **);


private:
  HRESULT _do_iterate_symbols_ids(
        const DWORD *ids,
        size_t count,
        enum SymTagEnum type,
        children_visitor_t &visitor);

#define SAFE_GET(type)                                          \
  sym_data_t *sym_data;                                         \
  ioctl_pdb_code_t result = get_sym_data(sym, &sym_data);       \
  if ( result == pdb_ok )                                       \
    return sym_data->get_##type(token, out);                    \
  else                                                          \
    return E_FAIL

  // Build sym_data_t instance, and register it into the 'cache'.
  DWORD build_and_register_sym_data(const uchar **raw, const uchar *end);

  // Whenever fetch_children_infos() or get_sym_data() performs
  // a remote operation, this is used to handle the response
  // and add the fetched symbol data to the cache.
  void handle_fetch_response(
        const uchar **ptr,
        const uchar *end,
        qvector<DWORD> *ids_storage);

  // Remote operation.
  ioctl_pdb_code_t fetch_children_infos(
        pdb_sym_t &sym,
        enum SymTagEnum type,
        qvector<DWORD> *children_ids);

  HRESULT handle_fetch_lnnums(
        pdb_lnnums_t *out,
        const bytevec_t &resp) const;

  HRESULT handle_fetch_file_ids(
        qvector<DWORD> *out,
        const bytevec_t &resp) const;

  sym_data_t *get_sym_data_from_cache(DWORD id);

  // Low-level interface used by open_connection(), fetch_children_infos(), and get_sym_data().
  // 'fetch_type' is one of
  //   WIN32_IOCTL_PDB_OPEN,
  //   WIN32_IOCTL_PDB_FETCH_SYMBOL,
  //   WIN32_IOCTL_PDB_FETCH_CHILDREN
  ioctl_pdb_code_t perform_op(int op_type, const bytevec_t &oper, void *data);

  ioctl_pdb_code_t send_ioctl(
        int fn,
        const void *buf,
        size_t size,
        void **poutbuf,
        ssize_t *poutsize);

  std::map<DWORD, sym_data_t*> cache;
  const char *user_spath;
  char errbuf[MAXSTR];

  // For the moment, we'll channel all IOCTL requests
  // through the debugger. Ideally, we should be able to just
  // use a RPC client.
  bool load_win32_debugger(void);

  const char *host;
  int port;
  const char *pwd;
  bool was_connected;
  bool is_dbg_module;
  int remote_session_id;
  bool warned = false;
};

#endif // PDBREMOTE_HPP
