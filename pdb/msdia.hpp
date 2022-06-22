
#ifndef MSDIA_HPP
#define MSDIA_HPP

#include "pdbaccess.hpp"
#include "pdblocal.hpp"

//----------------------------------------------------------------------------
struct pdb_session_t
{
  HMODULE dia_hmod;
  int refcount;
  local_pdb_access_t *pdb_access;

  pdb_session_t()
    : dia_hmod(nullptr),
      refcount(1),
      pdb_access(nullptr),
      pSource(nullptr)
  {
    session_count++;
  }
  ~pdb_session_t();

  HRESULT check_and_load_pdb(
	  LPCOLESTR pdb_path,
	  const pdb_signature_t &pdb_sign,
	  bool load_anyway,
	  pdbargs_t &pdbargs);
  HRESULT open_session(pdbargs_t &pdbargs);
  void close();
  const char *get_used_fname() const { return used_fname.begin(); }

private:
  DECLARE_UNCOPYABLE(pdb_session_t)
  HRESULT create_dia_source(int *dia_version);

  IDiaDataSource *pSource;
  qwstring winput;
public:
  qwstring wspath;
private:
  enum load_data_type_t
  {
    EXE_LOCAL,
    MEM_LOCAL,  // PDB_PLUGIN
    EXE_WIN32,  // PDB_WIN32_SERVER
    MEM_WIN32,  // PDB_WIN32_SERVER
  };
  HRESULT load_data_for_exe(const pdbargs_t &pdbargs, load_data_type_t type);
  HRESULT load_input_path(const pdbargs_t &pdbargs, const char *input_path);

  // The total number of different PDB sessions; kept track of
  // in order to know when we can safely CoUninitialize().
  static int session_count;

  // Whether COM is initialized in this thread.
  static bool co_initialized;
#ifdef _DEBUG
public:
  qstring _pdb_path;
#endif
  qstring used_fname;
};


//----------------------------------------------------------------------------
class pdb_session_ref_t
{
public:
  pdb_session_t *session;  // refcounted object

  pdb_session_ref_t(void) : session(nullptr) {}
  pdb_session_ref_t(const pdb_session_ref_t &r);
  ~pdb_session_ref_t();

  pdb_session_ref_t &operator=(const pdb_session_ref_t &r);
  void create_session();
  void close();
  bool empty() const { return session == nullptr; }
  bool opened() const { return !empty() && session->pdb_access != nullptr; }
  HRESULT open_session(pdbargs_t &args);
};

//----------------------------------------------------------------------------
const char *pdberr(int code);

#endif
