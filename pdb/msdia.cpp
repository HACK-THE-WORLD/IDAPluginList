
// This file is included from 4 places:
//      - efd/pdb.cpp                   efd: to dump pdb contents
//      - base/pdb2til.cpp              tilib: to convert pdb to til
//      - plugins/pdb/pdb.cpp           ida: read pdb info and populate idb
//      - dbg/win32_server/tilfuncs.cpp win32_server: read pdb info and send it to ida
//
// The following symbols may be defined:
// PDB_PLUGIN           pdb
// PDB_WIN32_SERVER     win32_server

#include <diskio.hpp>

#include "msdia.hpp"

#include "../../ldr/pe/pe.h"
#include "pdblocal.cpp"
#include "dia2_internal.h"
#include "Program.h"
//因为从Visual Studio 2010开始DIA SDK的各个接口的虚表结构就改变了(虽然接口名字并没改变还是叫IDiaSession、IDiaSymbol等)，
//因此一套源码不能编译为同时支持两种不同虚表结构的接口的组件
//使用低于Visual Studio 2010提供的DIA SDK的版本时需要注释掉下面这个__IS_MSDIA100_OR_GREATER__宏，不然会报错提示
#define __IS_MSDIA100_OR_GREATER__
#ifdef __IS_MSDIA100_OR_GREATER__
__if_not_exists(IDiaSession::findChildrenEx)
{
    static int temp_result_for__IS_MSDIA100_OR_GREATER__ = _CrtDbgReportW(_CRT_ASSERT, _CRT_WIDE(__FILE__), __LINE__, nullptr, L"%ls", L"PLEASE undefine __IS_MSDIA100_OR_GREATER__");
}
#endif

//lint -esym(843, g_diadlls, g_pdb_errors, PathIsUNC) could be declared as const

int pdb_session_t::session_count = 0;
bool pdb_session_t::co_initialized = false;

#ifndef _INC_SHLWAPI
typedef BOOL (__stdcall *PathIsUNC_t)(LPCTSTR pszPath);
static PathIsUNC_t PathIsUNC = nullptr;
#endif

static bool check_for_odd_paths(const char *fname);

//---------------------------------------------------------------------------
class msdia_reader_t
{
public:
  virtual ~msdia_reader_t() {}
  virtual bool read(uint64 offset, void *buf, uint32 count, uint32 *nread) = 0;
  virtual bool setup(void) { return true; }
};

//---------------------------------------------------------------------------
class local_exe_msdia_reader_t : public msdia_reader_t
{
  LPCWSTR FileName;
  HANDLE hFile;

public:
  local_exe_msdia_reader_t(LPCWSTR _FileName)
  {
    FileName = _FileName;
    hFile = INVALID_HANDLE_VALUE;
  }

  ~local_exe_msdia_reader_t(void)
  {
    if ( hFile != INVALID_HANDLE_VALUE )
      CloseHandle(hFile);
  }

  virtual bool setup(void) override
  {
    hFile = CreateFileW(
      FileName,
      GENERIC_READ,
      FILE_SHARE_READ | FILE_SHARE_WRITE,
      nullptr,
      OPEN_EXISTING,
      0,
      nullptr);
    return hFile != INVALID_HANDLE_VALUE;
  }

  virtual bool read(uint64 offset, void *buf, uint32 count, uint32 *nread) override
  {
    if ( hFile == INVALID_HANDLE_VALUE )
      return false;

    LARGE_INTEGER pos;
    pos.QuadPart = (LONGLONG) offset;
    if ( SetFilePointerEx(hFile, pos, nullptr, FILE_BEGIN) == 0 )
      return false;

    if ( ReadFile(hFile, buf, count, (DWORD *) nread, nullptr) == 0 )
      return false;

    return true;
  }
};

#ifdef PDB_PLUGIN
//---------------------------------------------------------------------------
class local_mem_msdia_reader_t : public msdia_reader_t
{
public:
  virtual bool read(uint64 offset, void *buf, uint32 count, uint32 *nread) override
  {
    if ( get_bytes(buf, count, offset) != count )
      return false;
    *nread = count;
    return true;
  }
};

#elif defined(PDB_WIN32_SERVER)
//---------------------------------------------------------------------------
class win32_msdia_reader_t : public msdia_reader_t
{
  pdb_remote_session_t *pdb_rsess;
  pdb_rr_kind_t kind;
public:
  win32_msdia_reader_t(void *_pdb_rsess, pdb_rr_kind_t _kind)
  {
    pdb_rsess = (pdb_remote_session_t *) _pdb_rsess;
    kind = _kind;
  }

  virtual bool read(uint64 offset, void *buf, uint32 count, uint32 *nread) override
  {
    return pdb_rsess->client_read_request.request_read(kind, offset, count, buf, nread);
  }
};

#endif

//----------------------------------------------------------------------
// Common code for PDB handling
//----------------------------------------------------------------------
class CCallback : public IDiaLoadCallback2,
                  public IDiaReadExeAtRVACallback,
                  public IDiaReadExeAtOffsetCallback
{
  unsigned int m_nRefCount;
  ea_t m_load_address;
  msdia_reader_t *msdia_reader;
  pdb_session_t *pdb_session;
  DWORDLONG last_cv_off;
  ea_t last_cv_rva;
public:
  CCallback(pdb_session_t *_pdb_session,
        msdia_reader_t *_msdia_reader,
        ea_t _load_address)
    : msdia_reader(_msdia_reader),
      m_load_address(_load_address),
      // Note: we initialize the reference count to 1 since the only
      //       instance of this object is created in the stack, and
      //       the destructor will take care of the cleanup.
      m_nRefCount(1),
      pdb_session(_pdb_session),
      last_cv_off(0),
      last_cv_rva(BADADDR)
  {
  }

  // IUnknown
  ULONG STDMETHODCALLTYPE AddRef()
  {
    return InterlockedIncrement(&m_nRefCount);
  }

  ULONG STDMETHODCALLTYPE Release()
  {
    // Note: we don't check the reference count and delete the object
    //       (see comment for the m_nRefCount field).
    return InterlockedDecrement(&m_nRefCount);
  }

  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID rid, void **ppUnk)
  {
    if ( ppUnk == nullptr )
      return E_INVALIDARG;

    *ppUnk = nullptr;
    if ( rid == __uuidof(IDiaLoadCallback2) || rid == __uuidof(IDiaLoadCallback) )
    {
      *ppUnk = (IDiaLoadCallback2 *)this;
    }
    else if ( rid == __uuidof(IDiaReadExeAtRVACallback) )
    {
      // we may use only one of IDiaReadExeAtRVACallback and IDiaReadExeAtOffsetCallback
      // claiming that both are supported will lead to crashes in MSDIA
      if ( m_load_address != BADADDR )
        *ppUnk = (IDiaReadExeAtRVACallback *)this;
    }
    else if ( rid == __uuidof(IDiaReadExeAtOffsetCallback) )
    {
      // see the comment above about IDiaReadExeAtRVACallback
      if ( m_load_address == BADADDR )
        *ppUnk = (IDiaReadExeAtOffsetCallback *)this;
    }
    else if ( rid == __uuidof(IUnknown) )
    {
      *ppUnk = (IUnknown *)(IDiaLoadCallback *)this;
    }
    if ( *ppUnk == nullptr )
      return E_NOINTERFACE;
    AddRef();
    return S_OK;
  }

  HRESULT STDMETHODCALLTYPE NotifyDebugDir(
        BOOL fExecutable,
        DWORD cbData,
        BYTE data[])
  {
    // msdia90.dll can crash on bogus CV data
    // so we remember the offset here and check it in ReadFileAt
    if ( fExecutable && cbData >= sizeof(debug_entry_t) )
    {
      debug_entry_t &de = *(debug_entry_t *)data;
      if ( de.type == DBG_CV )
      {
        last_cv_off = de.seek;
        last_cv_rva = de.rva;
      }
    }
    return S_OK;
  }
  HRESULT STDMETHODCALLTYPE NotifyOpenDBG(
        LPCOLESTR dbgPath,
        HRESULT resultCode)
  {
    if ( resultCode == S_OK )
      deb(IDA_DEBUG_DEBUGGER, "MSDIA: dbg file \"%S\" matched\n", dbgPath);
    else
      deb(IDA_DEBUG_DEBUGGER, "MSDIA: \"%S\": %s\n", dbgPath, pdberr(resultCode));

    return S_OK;
  }

  HRESULT STDMETHODCALLTYPE NotifyOpenPDB(
        LPCOLESTR pdbPath,
        HRESULT resultCode)
  {
    if ( resultCode == S_OK )
      deb(IDA_DEBUG_DEBUGGER, "MSDIA: pdb file \"%S\" matched\n", pdbPath);
    else
      deb(IDA_DEBUG_DEBUGGER, "MSDIA: \"%S\": %s\n", pdbPath, pdberr(resultCode));
#ifdef _DEBUG
    qstring spath;
    utf16_utf8(&spath, pdbPath);
    pdb_session->_pdb_path = spath;
#endif
    return S_OK;
  }
  HRESULT STDMETHODCALLTYPE RestrictRegistryAccess()
  {
    // return hr != S_OK to prevent querying the registry for symbol search paths
    return S_OK;
  }
  HRESULT STDMETHODCALLTYPE RestrictSymbolServerAccess()
  {
    // return hr != S_OK to prevent accessing a symbol server
    return S_OK;
  }
  HRESULT STDMETHODCALLTYPE RestrictOriginalPathAccess()
  {
    // return hr != S_OK to prevent querying the registry for symbol search paths
    return S_OK;
  }
  HRESULT STDMETHODCALLTYPE RestrictReferencePathAccess()
  {
    // return hr != S_OK to prevent accessing a symbol server
    return S_OK;
  }
  HRESULT STDMETHODCALLTYPE RestrictDBGAccess()
  {
    return S_OK;
  }
  HRESULT STDMETHODCALLTYPE RestrictSystemRootAccess()
  {
    return S_OK;
  }

  bool check_codeview_data(BYTE pbData[], DWORD cbData, qwstring& wspath)
  {
    bool ok = true;
    if ( cbData > 4 )
    {
      // check that the data has a valid NB or RSDS signature and PDB path doesn't look suspicious
      ok = false;
      if ( pbData[0] == 'N' && pbData[1] == 'B' && cbData >= sizeof(cv_info_pdb20_t) )
      {
        char *pdbname = (char*)pbData + sizeof(cv_info_pdb20_t);
        pbData[cbData-1] = '\0';
        ok = check_for_odd_paths(pdbname);
      }
      else if ( memcmp(pbData, "RSDS", 4) == 0 && cbData >= sizeof(rsds_t) )
      {
        char *pdbname = (char*)pbData + sizeof(rsds_t);
        pbData[cbData-1] = '\0';
        ok = check_for_odd_paths(pdbname);
        if (ok)
        {
            void try_download_pdb_from_sym_server_by_idm_when_not_exist(clsid_t & guid, uint32 age, const char* pdb_path, qstring & spath);

            rsds_t* pdb_info = (rsds_t*)pbData;
            qstring spath = utf16_utf8(wspath.c_str());
            try_download_pdb_from_sym_server_by_idm_when_not_exist(pdb_info->guid, pdb_info->age, pdbname, spath);
        }
      }
    }
    return ok;
  }

  // IDiaReadExeAtRVACallback
  HRESULT STDMETHODCALLTYPE ReadExecutableAtRVA(
        DWORD relativeVirtualAddress,
        DWORD cbData,
        DWORD *pcbData,
        BYTE data[])
  {
    ea_t ea = m_load_address + relativeVirtualAddress;
    if ( !msdia_reader->read(ea, data, cbData, (uint32 *) pcbData) )
      return E_FAIL;
    // are we reading the CV debug directory entry?
    if ( relativeVirtualAddress == last_cv_rva )
      return check_codeview_data(data, cbData, pdb_session->wspath) ? S_OK : E_FAIL;
    return S_OK;
  }

  // IDiaReadExeAtOffsetCallback
  HRESULT STDMETHODCALLTYPE ReadExecutableAt(
        DWORDLONG fileOffset,
        DWORD cbData,
        DWORD *pcbData,
        BYTE data[])
  {
    if ( !msdia_reader->read(fileOffset, data, cbData, (uint32 *) pcbData) )
      return E_FAIL;
    // are we reading the CV debug directory entry?
    if ( fileOffset != 0 && last_cv_off == fileOffset )
      return check_codeview_data(data, cbData, pdb_session->wspath) ? S_OK : E_FAIL;
    return S_OK;
  }
};

//---------------------------------------------------------------------------
template<class T> void print_generic(T t)
{
  IDiaPropertyStorage *pPropertyStorage;
  HRESULT hr = t->QueryInterface(__uuidof(IDiaPropertyStorage), (void **)&pPropertyStorage);
  if ( hr == S_OK )
  {
    print_property_storage(pPropertyStorage);
    pPropertyStorage->Release();
  }
}

//---------------------------------------------------------------------------
static const char *const g_pdb_errors[] =
{
  "Operation successful (E_PDB_OK)",
  "(E_PDB_USAGE)",
  "Out of memory (E_PDB_OUT_OF_MEMORY)",
  "(E_PDB_FILE_SYSTEM)",
  "Failed to open the file, or the file has an invalid format (E_PDB_NOT_FOUND)",
  "Signature does not match (E_PDB_INVALID_SIG)",
  "Age does not match (E_PDB_INVALID_AGE)",
  "(E_PDB_PRECOMP_REQUIRED)",
  "(E_PDB_OUT_OF_TI)",
  "(E_PDB_NOT_IMPLEMENTED)",
  "(E_PDB_V1_PDB)",
  "Attempted to access a file with an obsolete format (E_PDB_FORMAT)",
  "(E_PDB_LIMIT)",
  "(E_PDB_CORRUPT)",
  "(E_PDB_TI16)",
  "(E_PDB_ACCESS_DENIED)",
  "(E_PDB_ILLEGAL_TYPE_EDIT)",
  "(E_PDB_INVALID_EXECUTABLE)",
  "(E_PDB_DBG_NOT_FOUND)",
  "(E_PDB_NO_DEBUG_INFO)",
  "(E_PDB_INVALID_EXE_TIMESTAMP)",
  "(E_PDB_RESERVED)",
  "(E_PDB_DEBUG_INFO_NOT_IN_PDB)",
  "(E_PDB_SYMSRV_BAD_CACHE_PATH)",
  "(E_PDB_SYMSRV_CACHE_FULL)",
};

//---------------------------------------------------------------------------
inline void pdberr_suggest_vs_runtime(HRESULT hr)
{
  if ( hr == E_NOINTERFACE )
  {
    msg("<< It appears that MS DIA SDK is not installed.\n");
#ifndef __IS_MSDIA100_OR_GREATER__
#ifdef __X86__
    msg("Please try installing \"Microsoft Visual C++ 2008 Redistributable Package / x86\" >>\n");
#else
    msg("Please try installing \"Microsoft Visual C++ 2008 Redistributable Package / x64\" >>\n");
#endif
#endif
  }
}

//---------------------------------------------------------------------------
const char *pdberr(int code)
{
  switch ( code )
  {                         // tab in first pos is flag for replace warning to msg
    case E_INVALIDARG:      return "Invalid parameter.";
    case E_UNEXPECTED:      return "Data source has already been prepared.";
    default:
      if ( code >= E_PDB_OK && (code - E_PDB_OK) < qnumber(g_pdb_errors) )
        return g_pdb_errors[code - E_PDB_OK];
  }
  return winerr(code);
}

//----------------------------------------------------------------------
#ifdef __IS_MSDIA100_OR_GREATER__
static const GUID* const g_msdiav[] = { &__uuidof(DiaSource) };
static const int         g_diaver[] = { 1400 };
static const char* const g_diadlls[] = { "msdia140.dll" };
#else
class DECLSPEC_UUID("4C41678E-887B-4365-A09E-925D28DB33C2") DiaSource90;
class DECLSPEC_UUID("1fbd5ec4-b8e4-4d94-9efe-7ccaf9132c98") DiaSource80;
class DECLSPEC_UUID("31495af6-0897-4f1e-8dac-1447f10174a1") DiaSource71;
static const GUID *const g_d90 = &__uuidof(DiaSource90);  // msdia90.dll
static const GUID *const g_d80 = &__uuidof(DiaSource80);  // msdia80.dll
static const GUID *const g_d71 = &__uuidof(DiaSource71);  // msdia71.dll
static const GUID *const g_msdiav[] = { g_d90, g_d80, g_d71 };
static const int         g_diaver[] = { 900,   800,   710 };
static const char *const g_diadlls[] = { "msdia90.dll", "msdia80.dll", "msdia71.dll" };
#endif

//----------------------------------------------------------------------
HRESULT __stdcall CoCreateInstanceNoReg(
        LPCTSTR szDllName,
        IN REFCLSID rclsid,
        IUnknown *pUnkOuter,
        IN REFIID riid,
        OUT LPVOID FAR *ppv,
        OUT HMODULE *phMod)
{
  // http://lallousx86.wordpress.com/2007/01/29/emulating-cocreateinstance/
  HRESULT hr = REGDB_E_CLASSNOTREG;
  HMODULE hDll;
  do
  {
    hDll = LoadLibrary(szDllName);
    if ( hDll == nullptr )
      break;

    HRESULT (__stdcall *GetClassObject)(REFCLSID rclsid, REFIID riid, LPVOID FAR *ppv);
    *(FARPROC*)&GetClassObject = GetProcAddress(hDll, "DllGetClassObject");
    if ( GetClassObject == nullptr )
      break;

    IClassFactory *pIFactory;
    hr = GetClassObject(rclsid, IID_IClassFactory, (LPVOID *)&pIFactory);
    if ( FAILED(hr) )
      break;

    hr = pIFactory->CreateInstance(pUnkOuter, riid, ppv);
    pIFactory->Release();
  }
  while ( false );

  if ( FAILED(hr) && hDll != nullptr )
    FreeLibrary(hDll);
  else
    *phMod = hDll;

  return hr;
}

//----------------------------------------------------------------------------
// Note: This will return the machine type, as it is known
// by the IDB, which might not be what you think. For example,
// if you need to tell x86 and x64 apart, you're out of luck.
// You may want to consider looking at pdbaccess_t's
// get_machine_type().
static DWORD get_machine_type(DWORD dwMachType)
{
  DWORD machine;
  switch ( dwMachType )
  {
    default:
      machine = CV_CFL_80386;
      break;
    case IMAGE_FILE_MACHINE_IA64:
      machine = CV_CFL_IA64;
      break;
    case IMAGE_FILE_MACHINE_AMD64:
      machine = CV_CFL_AMD64;
      break;
    case IMAGE_FILE_MACHINE_THUMB:
    case IMAGE_FILE_MACHINE_ARM:
      machine = CV_CFL_ARM6;
      break;
    case PECPU_ARMV7:
      machine = CV_CFL_ARM7;
      break;
    case PECPU_PPC:
      machine = CV_CFL_PPC620;
      break;
    case PECPU_PPCFP:
      machine = CV_CFL_PPCFP;
      break;
    case PECPU_PPCBE:
      machine = CV_CFL_PPCBE;
      break;
  }
  return machine;
}

//----------------------------------------------------------------------
pdb_session_t::~pdb_session_t()
{
  if ( --session_count == 0 && co_initialized )
  {
    CoUninitialize();
    co_initialized = false;
  }
}

//----------------------------------------------------------------------
void pdb_session_t::close()
{
  if ( pdb_access != nullptr )
  {
    delete pdb_access;
    pdb_access = nullptr;
  }

  if ( dia_hmod != nullptr )
  {
    FreeLibrary(dia_hmod);
    dia_hmod = nullptr;
  }

#ifdef _DEBUG
  if ( !_pdb_path.empty() && qfileexist(_pdb_path.begin() ) )
  {
    HANDLE hFile = CreateFileA(_pdb_path.begin(), GENERIC_READ, /*FILE_SHARE_READ*/ 0, 0, OPEN_EXISTING, 0, 0);
    if ( hFile == INVALID_HANDLE_VALUE )
      warning("Couldn't acquire probing lock to \"%s\"; file might be still locked by IDA", _pdb_path.begin());
    else
      CloseHandle(hFile);
  }
#endif
}

//----------------------------------------------------------------------
#include "dbghelp.h"
// copied from dbghelp.h
#ifndef SSRVOPT_CALLBACK
#define SSRVOPT_CALLBACK            0x000001
#endif
#ifndef SSRVOPT_SETCONTEXT
#define SSRVOPT_SETCONTEXT          0x000800
#endif
#ifndef SSRVOPT_TRACE
#define SSRVOPT_TRACE               0x000400
#endif
#ifndef SSRVACTION_TRACE
#define SSRVACTION_TRACE        1
#define SSRVACTION_QUERYCANCEL  2
#define SSRVACTION_EVENT        3
#define SSRVACTION_EVENTW       4
#endif
#ifndef SSRVACTION_SIZE
#define SSRVACTION_SIZE         5
#endif

//----------------------------------------------------------------------
static void symsrv_dprint(const char *str)
{
  qstring qbuf(str);
  qbuf.replace("\b", ""); // remove backspaces
  if ( qbuf.empty() )
    return;
  // strings usually already start with "SYMSRV:  "
  if ( strncmp(qbuf.c_str(), "SYMSRV:  ", 9) != 0 )
    qbuf.insert(0, "SYMSRV:  ");
  // strings usually already end with '\n'
  if ( qbuf.last() != '\n' )
    qbuf.append('\n');
  deb(IDA_DEBUG_DEBUGGER, "%s", qbuf.c_str());
}

static int GetDownloadPercentFromSymbolServerMessage(CString& Src)
{
	int result = 0;
	if (Src.Find("copied") == -1)
	{
		if (Src.Find("percent") != -1)
		{
			Src.TrimLeft('\b');
			char* EndPtr = nullptr;
			result = strtol(Src, &EndPtr, 10);
		}
	}
	else
	{
		result = 100;
	}
	return result;
}

//----------------------------------------------------------------------
static BOOL CALLBACK SymbolServerCallback(
        UINT_PTR action,
        ULONG64 data,
        ULONG64 context)
{
  bool *wait_box_shown = (bool *) context;
  switch ( action )
  {
    case SSRVACTION_SIZE:
      {
        if ( !*wait_box_shown )
          show_wait_box("Downloading pdb...");
        *wait_box_shown = true;
      }
      break;
    case SSRVACTION_QUERYCANCEL:
      {
        //https://docs.microsoft.com/en-us/windows/win32/api/dbghelp/nc-dbghelp-psymbolservercallbackproc
        //文档说明是取消变量*data是ULONG64类型
        ULONG64* do_cancel = (ULONG64*)data;
        // apparently this can arrive before SSRVACTION_SIZE
        // so check that we did show the waitbox
        if ( *wait_box_shown && user_cancelled() )
          *do_cancel = TRUE;
        else
          *do_cancel = FALSE;
      }
      break;
    case SSRVACTION_TRACE:
      symsrv_dprint((const char *)data);
      ATLTRACE((const char*)data);
      break;
    case SSRVACTION_EVENT:
      IMAGEHLP_CBA_EVENT *pev = (IMAGEHLP_CBA_EVENT*)data;
      // Event information is usually all zero.
      if ( pev->severity != 0 || pev->code != 0 || pev->object != nullptr )
        deb(IDA_DEBUG_DEBUGGER, "SYMSRV: event severity: %d code: %d object: %p\n", pev->severity, pev->code, pev->object);
	  CString strText;
	  if (IS_INTRESOURCE(pev->desc))
	  {
		  strText.LoadString((UINT)pev->desc);
	  }
	  else
	  {
		  strText = pev->desc;
	  }
	  if (strText.Find('\b') == -1 && strText.Find("percent") == -1 && strText.Find("copied") == -1)
	  {
		  symsrv_dprint(strText);
		  ATLTRACE(strText);
	  }
	  else
	  {
		  int nPercent = GetDownloadPercentFromSymbolServerMessage(strText);
		  replace_wait_box("Downloading pdb (%d%%)", nPercent);
	  }
      break;
  }
  return TRUE;
}

void try_download_pdb_from_sym_server_by_idm_when_not_exist(clsid_t& guid, uint32 age, const char* pdb_path, qstring& spath)
{
	CRegKey key;
	if (!key.Open(HKEY_CURRENT_USER, "Software\\DownloadManager", KEY_READ))
	{
		TCHAR szExePath[MAX_PATH];
		ULONG nChars = _countof(szExePath);
		if (!key.QueryStringValue("ExePath", szExePath, &nChars))
		{
			if (qfileexist(szExePath))
			{
				typedef BOOL(WINAPI* HTTPOPENFILEHANDLE)(LPCSTR, LPCSTR, DWORD, HANDLE*, HANDLE*);
				typedef BOOL(WINAPI* HTTPQUERYDATAAVAILABLE)(HANDLE, LPDWORD, DWORD, DWORD_PTR);
				typedef BOOL(WINAPI* HTTPREADFILE)(HANDLE, LPVOID, DWORD, LPDWORD);
				typedef BOOL(WINAPI* HTTPCLOSEHANDLE)(HANDLE);
				HMODULE symsrv_hmod = GetModuleHandle("symsrv.dll");
				HTTPOPENFILEHANDLE httpOpenFileHandle = (HTTPOPENFILEHANDLE)GetProcAddress(symsrv_hmod, "httpOpenFileHandle");
				HTTPQUERYDATAAVAILABLE httpQueryDataAvailable = (HTTPQUERYDATAAVAILABLE)GetProcAddress(symsrv_hmod, "httpQueryDataAvailable");
				HTTPREADFILE httpReadFile = (HTTPREADFILE)GetProcAddress(symsrv_hmod, "httpReadFile");
				HTTPCLOSEHANDLE httpCloseHandle = (HTTPCLOSEHANDLE)GetProcAddress(symsrv_hmod, "httpCloseHandle");
				BOOL bHttpIsValid = httpOpenFileHandle && httpQueryDataAvailable && httpReadFile && httpCloseHandle;
				ASSERT(bHttpIsValid);
				if (bHttpIsValid)
				{
					PSYMBOLSERVERSETOPTIONSPROC set_options = (PSYMBOLSERVERSETOPTIONSPROC)(void*)GetProcAddress(symsrv_hmod, "SymbolServerSetOptions");
					PSYMBOLSERVERGETINDEXSTRING get_index_string = (PSYMBOLSERVERGETINDEXSTRING)GetProcAddress(symsrv_hmod, "SymbolServerGetIndexString");
					ASSERT(set_options && get_index_string);
					if (set_options && get_index_string)
					{
						CHAR szIndexString[sizeof(GUID) * 2 + 1 + 1 + 1];
						set_options(SSRVOPT_PARAMTYPE, SSRVOPT_GUIDPTR);
						BOOL bResult = get_index_string(&guid, age, 0, szIndexString, _countof(szIndexString));
						ASSERT(bResult);
						if (bResult)
						{
							const char* pdb_name = qbasename(pdb_path);
							qstring path;
							path.sprnt("%s/%s/%s", pdb_name, szIndexString, pdb_name);

							bool bFindCache = false;
							qvector<qstring> cache_paths;
							qvector<qstring> srvs;

							LPSTR next_token = nullptr;
							LPSTR token = qstrtok(spath.begin(), ";", &next_token);
							while (token != nullptr)
							{
								qstring item(token);
								LPSTR next_token_item = nullptr;
								LPTSTR spath_prefix = qstrtok(item.begin(), "*", &next_token_item);
								ASSERT(spath_prefix);
								if (!strnicmp(spath_prefix, "srv", _countof("srv") - 1))
								{
									LPTSTR cache_path = qstrtok(nullptr, "*", &next_token_item);
									ASSERT(cache_path);
									if (cache_path)
									{
										qstring cache_file;
										cache_file.sprnt("%s\\%s", cache_path, path.c_str());
										if (qfileexist(cache_file.c_str()))
										{
											bFindCache = true;
											break;
										}
										cache_paths.push_back(cache_path);
										LPTSTR srv = qstrtok(nullptr, "*", &next_token_item);
										if (srv)
										{
											srvs.push_back(srv);
										}
										else
										{
											ASSERT(srv);
											break;
										}
									}
								}
								else
								{
									ASSERT(FALSE);
									break;
								}

								// Get next token: 
								token = qstrtok(nullptr, ";", &next_token);
							}

							if (!bFindCache)
							{
								for (size_t i = 0; i < cache_paths.size(); i++)
								{
									LPCSTR srv = srvs[i].c_str();
									HANDLE hsite, hfile;
									BOOL bResult = httpOpenFileHandle(srv, path.c_str(), 0, &hsite, &hfile);
									if (!bResult)
									{
										//尝试查找压缩格式的PDB文件(Mozilla服务器只提供了压缩格式，目前版本的IDA的PDB插件并不支持)
										qstring path_Compressed;//CompressedFileName
										path_Compressed = path.substr(0, path.length() - 1);
										path_Compressed.append('_');
										BOOL bResult_Compressed = httpOpenFileHandle(srv, path_Compressed.c_str(), 0, &hsite, &hfile);
										if (bResult_Compressed)
										{
											//由于需要处理CAB,LZExpand,ZIP的解压，所以目前我们暂时不处理，UncompressFile
											//此时回落到使用symsrv.dll进行下载
											msg("PDB: The external downloader currently does not support downloading compressed PDB files.\n");
											break;
										}
									}
									BOOL bDownloadPdbCompleted = FALSE;
									if (bResult)
									{
										DWORD dwNumberOfBytesAvailable;
										if (httpQueryDataAvailable(hfile, &dwNumberOfBytesAvailable, 0, 0))
										{
											char szBuffer[64];
											DWORD dwNumberOfBytesToRead = __min(_countof(szBuffer), dwNumberOfBytesAvailable);
											DWORD dwNumberOfBytesRead;
											if (httpReadFile(hfile, szBuffer, dwNumberOfBytesToRead, &dwNumberOfBytesRead))
											{
												if (dwNumberOfBytesRead == dwNumberOfBytesToRead)
												{
													//下载下来的不一定是一个PDB文件，老版本symsrv.dll甚至会把HTTP 404 Not Found的数据都读取出来
													if (!strncmp(szBuffer, "Microsoft C/C++ ", _countof("Microsoft C/C++ ") - 1))
													{
														ATLTRACE("FIND PDB IN SERVER: %s\n", srv);
														qstring url(srv);
														if (url[url.length() - 1] != '/')
														{
															url.append('/');
														}
														url.append(path);

														char szRelPath[MAX_PATH];
														szRelPath[0] = 0;
														qdirname(szRelPath, _countof(szRelPath), path.c_str());
														size_t nRelPathLen = qstrlen(szRelPath);
														for (size_t j = 0; j < nRelPathLen; j++)
														{
															if (szRelPath[j] == '/')
															{
																szRelPath[j] = '\\';
															}
														}
														qstring local_path(cache_paths[i]);
														if (local_path[local_path.length() - 1] != '\\')
														{
															local_path.append('\\');
														}
														local_path.append(szRelPath);

														qstring local_full_path(local_path);
														local_full_path.append('\\');
														local_full_path.append(pdb_name);
														if (qfileexist(local_full_path.c_str()))
														{
															qunlink(local_full_path.c_str());
														}

														show_wait_box("Waiting for external download to complete...\n%s", url.c_str());

														qstring strArgs;
														strArgs.sprnt("/d \"%s\" /p \"%s\" /f \"%s\" /q /n", url.c_str(), local_path.c_str(), pdb_name);
														launch_process_params_t lpp;
														lpp.flags = 0;
														lpp.path = szExePath;
														lpp.args = strArgs.c_str();
														qstring errbuf;
														void* handle = launch_process(lpp, &errbuf);
														if (handle)
														{
															while (!qfileexist(local_full_path.c_str()))
															{
																if (handle)
																{
																	int exit_code = 0;
																	if (check_process_exit(handle, &exit_code, 50) == 0)
																	{
																		handle = nullptr;
																	}
																}
																else
																{
																	Sleep(50);
																}
																if (user_cancelled())
																{
																	break;
																}
															}

															if (qfileexist(local_full_path.c_str()))
															{
																//等待第三方下载工具写入完成，也即我们能获取到独占写入权限的时候
																do
																{
																	FILE* file = qfopen(local_full_path.c_str(), "a+b");
																	if (file)
																	{
																		qfclose(file);
																		file = nullptr;

																		bDownloadPdbCompleted = TRUE;

																		break;
																	}
																	Sleep(50);
																} while (TRUE);
															}
														}
														hide_wait_box();
													}
												}
											}
										}
										httpCloseHandle(hfile);
										hfile = nullptr;
										httpCloseHandle(hsite);
										hsite = nullptr;
									}
									if (bDownloadPdbCompleted)
									{
										break;
									}
								}
							}
						}
					}
				}
			}
		}
	}
}

//----------------------------------------------------------------------------
class symsrv_cb_t
{
  HMODULE symsrv_hmod;
  bool wait_box_shown;
  PSYMBOLSERVERGETOPTIONDATAPROC get_option_data; // "DbgHelp.dll 10.0 or later"
  PSYMBOLSERVERSETOPTIONSPROC set_options;
  ULONG64 was_context;
  ULONG64 was_callback;

public:
  symsrv_cb_t(void)
  {
    symsrv_hmod = LoadLibrary("symsrv.dll");
	if (!symsrv_hmod)
	{
		warning("The \"symsrv.dll\" file cannot be found, so it may not be possible to download symbols online!");
	}
	else
	{
		TCHAR szVersionFile[MAX_PATH];
		GetModuleFileName(symsrv_hmod, szVersionFile, _countof(szVersionFile));
		ASSERT(szVersionFile[0]);

		//https://stackoverflow.com/questions/940707/how-do-i-programmatically-get-the-version-of-a-dll-or-exe-file
		DWORD  verHandle = 0;
		UINT   size = 0;
		LPBYTE lpBuffer = nullptr;
		DWORD  verSize = GetFileVersionInfoSize(szVersionFile, &verHandle);

		if (verSize != 0)
		{
			BYTE* verData = new BYTE[verSize];

			if (GetFileVersionInfo(szVersionFile, verHandle, verSize, verData))
			{
				if (VerQueryValue(verData, _T("\\"), (LPVOID*)&lpBuffer, &size))
				{
					if (size)
					{
						VS_FIXEDFILEINFO* verInfo = (VS_FIXEDFILEINFO*)lpBuffer;
						if (verInfo->dwSignature == 0xfeef04bd)
						{

							// Doesn't matter if you are on 32 bit or 64 bit,
							// DWORD is always 32 bits, so first two revision numbers
							// come from dwFileVersionMS, last two come from dwFileVersionLS
							ULONGLONG ullCurVersion = make_ulonglong(verInfo->dwFileVersionLS, verInfo->dwFileVersionMS);
							ULONGLONG ullMinVersion = make_ulonglong(MAKELONG(1001, 19596), MAKELONG(0, 10));
							if (ullCurVersion < ullMinVersion)
							{
								warning("The version of the symsrv.dll file is lower than 10.0.19596.1001, so it cannot support immediate cancellation of the download operation!");
							}
						}
					}
				}
			}
			delete[] verData;
			verData = nullptr;
		}
	}
    wait_box_shown = false;
    get_option_data = nullptr;
    set_options = nullptr;
    was_context = 0;
    was_callback = 0;
  }

  void init(void)
  {
    if ( symsrv_hmod != nullptr )
    {
      get_option_data = (PSYMBOLSERVERGETOPTIONDATAPROC)(void *)GetProcAddress(symsrv_hmod, "SymbolServerGetOptionData");
      if ( get_option_data != nullptr )
      {
        get_option_data(SSRVOPT_SETCONTEXT, &was_context);
        get_option_data(SSRVOPT_CALLBACK, &was_callback);
      }

      set_options = (PSYMBOLSERVERSETOPTIONSPROC)(void *)GetProcAddress(symsrv_hmod, "SymbolServerSetOptions");
      if ( set_options != nullptr )
      {
        set_options(SSRVOPT_SETCONTEXT, (ULONG64) (intptr_t) &wait_box_shown);
        set_options(SSRVOPT_CALLBACK, (ULONG64) SymbolServerCallback);
        if ( (debug & IDA_DEBUG_DEBUGGER) != 0 )
        {
          set_options(SSRVOPT_TRACE, (ULONG64) TRUE);
        }
      }
    }
  }

  void term(void)
  {
    if ( symsrv_hmod != nullptr )
    {
      if ( set_options != nullptr )
      {
        set_options(SSRVOPT_SETCONTEXT, was_context);
        set_options(SSRVOPT_CALLBACK, was_callback);
      }
      FreeLibrary(symsrv_hmod);
      symsrv_hmod = nullptr;
      if ( wait_box_shown )
        hide_wait_box();
    }
  }
};

//----------------------------------------------------------------------------
static qstring print_guid(GUID *guid)
{
  qstring guid_str;
  if ( guid != nullptr )
  {
    OLECHAR *guid_wstr = nullptr;
    StringFromCLSID(*guid, &guid_wstr);
    if ( guid_wstr != nullptr )
    {
      utf16_utf8(&guid_str, guid_wstr);
      CoTaskMemFree(guid_wstr);
    }
  }
  if ( guid_str.empty() )
    guid_str = "{00000000-0000-0000-0000-000000000000}";
  return guid_str;
}

//----------------------------------------------------------------------------
HRESULT pdb_session_t::check_and_load_pdb(
        LPCOLESTR pdb_path,
        const pdb_signature_t &pdb_sign,
        bool load_anyway,
		pdbargs_t &pdbargs)
{
  HRESULT hr = E_FAIL;
  if ( !load_anyway )
  {
    uint32 sig = pdb_sign.sig;
    uint32 age = pdb_sign.age;
    GUID *pcsig70 = nullptr;
    for ( int i=0; i < qnumber(pdb_sign.guid); i++ )
    {
      if ( pdb_sign.guid[i] != 0 )
      {
        pcsig70 = (GUID *)&pdb_sign.guid;
        break;
      }
    }
    if ( sig == 0 && age == 0 && pcsig70 == nullptr )
      return E_FAIL;
    qstring guid_str = print_guid(pcsig70);
    deb(IDA_DEBUG_DEBUGGER, "PDB: Trying to load PDB \"%S\" (guid %s, sig 0x%08X, age 0x%08X)\n", pdb_path, guid_str.c_str(), sig, age);
    hr = pSource->loadAndValidateDataFromPdb(pdb_path, pcsig70, sig, age);
    deb(IDA_DEBUG_DEBUGGER, "PDB: loadAndValidateDataFromPdb(\"%S\"): %s\n", pdb_path, pdberr(hr));
    if ( hr == E_PDB_INVALID_SIG || hr == E_PDB_INVALID_AGE )
    {
      load_anyway = ask_yn(ASKBTN_NO,
                           "HIDECANCEL\nICON WARNING\nAUTOHIDE NONE\n"
                           "PDB signature and/or age does not match the input file.\n"
                           "Do you want to load it anyway?") == ASKBTN_YES;
    }
  }
  if ( load_anyway )
  {
    hr = pSource->loadDataFromPdb(pdb_path);
    deb(IDA_DEBUG_DEBUGGER, "PDB: loadDataFromPdb(\"%S\"): %s\n", pdb_path, pdberr(hr));
  }

  pdbargs.flags &= ~PDBFLG_IS_MINIPDB;
  if (hr == S_OK)
  {
	  IDiaSession* pDiaSession = nullptr;
	  HRESULT hr = pSource->openSession(&pDiaSession);

	  ASSERT(hr == S_OK);
	  if (hr == S_OK)
	  {
		  IDiaSession10* pIDiaSession10 = nullptr;
		  hr = pDiaSession->QueryInterface(IID_IDiaSession10, (void **)&pIDiaSession10);
		  pDiaSession->Release();
		  pDiaSession = nullptr;

		  //ASSERT(hr == S_OK);
		  if (hr == S_OK)
		  {
			  BOOL fMinimalDbgInfo = FALSE;
			  hr = pIDiaSession10->isMiniPDB(&fMinimalDbgInfo);
			  pIDiaSession10->Release();
			  pIDiaSession10 = nullptr;

			  ASSERT(hr == S_OK);
			  if (hr == S_OK)
			  {
				  if (fMinimalDbgInfo)
				  {
					  pdbargs.flags |= PDBFLG_IS_MINIPDB;
					  bool convert = ask_yn(ASKBTN_NO,
						  "HIDECANCEL\nICON WARNING\nAUTOHIDE NONE\n"
						  "PDB is a partial pdb file(build with /DEBUG:FASTLINK).\n"
						  "Do you want to convert it to a full pdb file(build with /DEBUG:FULL)?") == ASKBTN_YES;
					  if (convert)
					  {
						  qstring strPdbPath(utf16_utf8(pdb_path));
						  qstring strFileExtName(get_file_ext(strPdbPath.c_str()));
						  qstring strPdbPath_Full;
						  if (strFileExtName.length())
						  {
							  strFileExtName.insert(0, '.');
							  strPdbPath_Full = strPdbPath.substr(0, strPdbPath.length() - strFileExtName.length()) + "_Full" + strFileExtName;
						  }
						  else
						  {
							  strPdbPath_Full = strPdbPath + "_Full";
						  }
						  if (qfileexist(strPdbPath_Full.c_str()))
						  {
							  qunlink(strPdbPath_Full.c_str());
						  }

						  qstring strExeFile;

                          bstr_t bstrVsInstallationPath;
						  ULONGLONG ullVersion;
						  hr = GetMaxVersionVsInstallationPath(bstrVsInstallationPath, ullVersion);
						  ASSERT(hr == S_OK);
						  BOOL bUseVs2015MsPdbCmf = FALSE;
						  if (hr == S_OK)
						  {
							  qstring strVsInstallationPath(utf16_utf8(bstrVsInstallationPath));

							  ULARGE_INTEGER uli;
							  uli.QuadPart = ullVersion;
							  WORD wVsMainVersion = HIWORD(uli.HighPart);
							  ASSERT(wVsMainVersion > 14);
							  if (wVsMainVersion > 14)
							  {
								  strExeFile.append(strVsInstallationPath.c_str());
								  qstring qstrPath_Microsoft_VCToolsVersion_default_txt = strExeFile + "\\VC\\Auxiliary\\Build\\Microsoft.VCToolsVersion.default.txt";
								  uint64 nFileSize = qfilesize_utf8(qstrPath_Microsoft_VCToolsVersion_default_txt.c_str());
								  qstring strVersion = GetFileContext(qstrPath_Microsoft_VCToolsVersion_default_txt.c_str(), nFileSize);
								  strVersion.rtrim('\n');
								  strVersion.rtrim('\r');
								  strExeFile.cat_sprnt("\\VC\\Tools\\MSVC\\%s\\bin\\Hostx86\\x86\\mspdbcmf.exe", strVersion.c_str());
							  }
						  }
						  else
						  {
							  qstring strVs140ComnTools;
							  qgetenv("VS140COMNTOOLS", &strVs140ComnTools);
							  if (!strVs140ComnTools.empty())
							  {
								  strExeFile = strVs140ComnTools + "..\\..\\VC\\bin\\mspdbcmf.exe";
								  bUseVs2015MsPdbCmf = TRUE;
							  }
						  }

						  if (!qfileexist(strExeFile.c_str()))
						  {
							  warning("\"mspdbcmf.exe\" is not existed!");
						  }
						  else
						  {
							  BOOL bConverted = FALSE;
							  uchar md5Pdb_Old_for_Vs2015[16];
							  qstring strArgs;
							  if (bUseVs2015MsPdbCmf)
							  {
								  int result = qcopyfile(strPdbPath.c_str(), strPdbPath_Full.c_str());
								  ASSERT(!result);
								  if (!result)
								  {
									  uint64 nFileSize = qfilesize_utf8(strPdbPath_Full.c_str());
									  qstring strFileContext = GetFileContext(strPdbPath_Full.c_str(), nFileSize);
									  MD5_FromData((uchar*)strFileContext.c_str(), nFileSize, md5Pdb_Old_for_Vs2015);
									  strArgs.sprnt("/STATUS %s", strPdbPath_Full.c_str());
								  }
							  }
							  else
							  {
								  strArgs.sprnt("/STATUS /OUT:%s %s", strPdbPath_Full.c_str(), strPdbPath.c_str());
							  }
							  if (!strArgs.empty())
							  {
								  launch_process_params_t lpp;
								  lpp.flags = 0;
								  lpp.path= strExeFile.c_str();
								  lpp.args = strArgs.c_str();
								  qstring errbuf;
								  void * handle = launch_process(lpp, &errbuf);
								  if (handle)
								  {
									  int exit_code = 0;
									  check_process_exit(handle, &exit_code);
									  handle = nullptr;

									  if (bUseVs2015MsPdbCmf)
									  {
										  uint64 nFileSize = qfilesize_utf8(strPdbPath_Full.c_str());
										  qstring strFileBuffer = GetFileContext(strPdbPath_Full.c_str(), nFileSize);
										  uchar md5Pdb_New_for_Vs2015[16];
										  MD5_FromData((uchar*)strFileBuffer.c_str(), nFileSize, md5Pdb_New_for_Vs2015);
										  if (memcmp(md5Pdb_New_for_Vs2015, md5Pdb_Old_for_Vs2015, sizeof(md5Pdb_New_for_Vs2015)))
										  {
											  bConverted = TRUE;
										  }
										  else
										  {
											  qunlink(strPdbPath_Full.c_str());
										  }
									  }
									  else
									  {
										  bConverted = qfileexist(strPdbPath_Full.c_str());
									  }
								  }
							  }

							  if (bConverted)
							  {
								  pSource->Release();
								  pSource = nullptr;

								  int dia_version;
								  hr = create_dia_source(&dia_version);
								  if (hr == S_OK)
								  {
									  int result = qmove(strPdbPath_Full.c_str(), strPdbPath.c_str(), QMOVE_OVERWRITE);
									  if (!result)
									  {
										  hr = check_and_load_pdb(pdb_path, pdb_sign, load_anyway, pdbargs);
									  }
									  else
									  {
										  DWORD dwErrorCode = GetLastError();
										  char* pszError(winerr(dwErrorCode));

										  warning("Failed to move file, %s\n(from \"%s\" to \"%s\")", pszError, strPdbPath_Full.c_str(), strPdbPath.c_str());
										  qwstring pdb_path_full(utf8_utf16(strPdbPath_Full.c_str()));
										  hr = check_and_load_pdb(pdb_path_full.c_str(), pdb_sign, load_anyway, pdbargs);
									  }
								  }
							  }
							  else
							  {
								  warning("Try to convert to full pdb has failed!");
							  }
						  }
					  }
				  }
			  }
		  }
	  }
  }
  return hr;
}

//----------------------------------------------------------------------------
// warn the user about eventual UNC or other problematic paths
static bool check_for_odd_paths(const char *fname)
{
  if ( PathIsUNC == nullptr )
  {
#ifndef _INC_SHLWAPI
    HMODULE h = GetModuleHandle("shlwapi.dll");
    if ( h != nullptr )
      PathIsUNC = (PathIsUNC_t)(void*)GetProcAddress(h, "PathIsUNCA");
#else
	ASSERT(FALSE);
#endif
  }
  if ( fname[0] == '\\'
    || fname[0] == '/'
    || PathIsUNC != nullptr && PathIsUNC(fname) )
  {
    if ( ask_yn(ASKBTN_NO,
                "AUTOHIDE NONE\nHIDECANCEL\n"
                "Please be careful, the debug path looks odd!\n"
                "\"%s\"\n"
                "Do you really want IDA to access this path (possibly a remote server)?",
                fname) != ASKBTN_YES )
    {
      return false;
    }
  }
  return true;
}

//---------------------------------------------------------------------------
HRESULT pdb_session_t::load_data_for_exe(
        const pdbargs_t &pdbargs,
        load_data_type_t type)
{
  // First check for load address.
  ea_t load_address = BADADDR;
  if ( type == MEM_LOCAL || type == MEM_WIN32 )
  {
    load_address = pdbargs.loaded_base;
    if ( load_address == BADADDR )
      return E_FAIL;
  }

  msdia_reader_t *msdia_reader = nullptr;
  HRESULT hr = E_FAIL;
  switch ( type )
  {
    case EXE_LOCAL:
      msdia_reader = new local_exe_msdia_reader_t(winput.c_str());
      break;
#ifdef PDB_PLUGIN
    case MEM_LOCAL:
      msdia_reader = new local_mem_msdia_reader_t;
      break;
#elif defined(PDB_WIN32_SERVER)
    case EXE_WIN32:
      msdia_reader = new win32_msdia_reader_t(pdbargs.user_data, READ_INPUT_FILE);
      break;
    case MEM_WIN32:
      msdia_reader = new win32_msdia_reader_t(pdbargs.user_data, READ_MEMORY);
      break;
#endif
    default:
      break;
  }
  if ( msdia_reader->setup() )
  {
    qstring buf;
    if ( load_address != BADADDR )
      buf.sprnt(" with load address %a", load_address);
    deb(IDA_DEBUG_DEBUGGER, "PDB: Trying loadDataForExe(\"%S\", \"%S\")%s\n", winput.c_str(), wspath.c_str(), buf.c_str());

    CCallback callback(this, msdia_reader, load_address);
	//目前新版本中需要symsrv.dll才行
	//https://github.com/MicrosoftDocs/visualstudio-docs/issues/5781
    hr = pSource->loadDataForExe(winput.c_str(), wspath.c_str(), (IDiaLoadCallback *)&callback);

    deb(IDA_DEBUG_DEBUGGER, "PDB: %s\n", pdberr(hr));
  }
  delete msdia_reader;

  return hr;
}

//----------------------------------------------------------------------------
HRESULT pdb_session_t::load_input_path(
        const pdbargs_t &pdbargs,
        const char *input_path)
{
  utf8_utf16(&wspath, pdbargs.spath.c_str());
  utf8_utf16(&winput, input_path);

  qvector<load_data_type_t> methods;
#ifdef PDB_PLUGIN
  // Is the debugger active?
  if ( get_process_state() != DSTATE_NOTASK )
  {
    // First try using program data from debugger memory.
    methods.push_back(MEM_LOCAL);
    // Then try reading the executable (unless we're remote debugging).
    if ( !dbg->is_remote() )
      methods.push_back(EXE_LOCAL);
  }
  else // debugger not active
  {
    // First try reading the executable.
    methods.push_back(EXE_LOCAL);
    // Then try using program data from the IDB.
    methods.push_back(MEM_LOCAL);
  }
#elif defined(PDB_WIN32_SERVER)
  // First try reading the executable.
  if ( pdbargs.is_dbg_module() )
  {
    // If the module has been loaded by the debugger itself, we can
    // read the file locally on the server side.
    // TODO isn't this a security issue? the user can specify
    //      any input_path to be read on the server.
    methods.push_back(EXE_LOCAL);
  }
  else
  {
    // Otherwise we want to read the input file from the remote stub.
    methods.push_back(EXE_WIN32);
  }
  // Then try reading memory locally on the server side (the process
  // being debugged).
  methods.push_back(MEM_WIN32);
#else
  // For efd and tilib, only try loading the executable locally.
  methods.push_back(EXE_LOCAL);
#endif

  HRESULT hr = E_FAIL;
  for ( size_t i = 0; i < methods.size(); i++ )
  {
    hr = load_data_for_exe(pdbargs, methods[i]);
    if ( hr == S_OK )
      break;
    if ( hr == E_PDB_NOT_FOUND )
      break; // another address won't help
  }

  return hr;
}

//----------------------------------------------------------------------------
HRESULT pdb_session_t::open_session(pdbargs_t &pdbargs)
{
  // Already open?
  if ( pdb_access != nullptr )
    return S_OK;

  // Not initialized yet?
  if ( !co_initialized )
  {
    // Initialize COM
    CoInitialize(nullptr);
    co_initialized = true;
  }

  int dia_version;
  HRESULT hr;
  IDiaSession    *pSession = nullptr;
  IDiaSymbol     *pGlobal  = nullptr;
  bool pdb_loaded = false;

  // No interface was created?
  hr = create_dia_source(&dia_version);
  if ( FAILED(hr) )
    goto fail;

  // First try to open PDB file if it was specified.
  const qstring &pdb_path = pdbargs.pdb_path;
  if ( !pdb_path.empty()
    && check_for_odd_paths(pdb_path.c_str())
    && qfileexist(pdb_path.c_str()) )
  {
    qwstring wpdb_path;
    utf8_utf16(&wpdb_path, pdb_path.c_str());
    bool force_load = (pdbargs.flags & (PDBFLG_ONLY_TYPES|PDBFLG_EFD)) != 0;
    hr = check_and_load_pdb(wpdb_path.c_str(), pdbargs.pdb_sign, force_load, pdbargs);
    if ( hr == E_PDB_INVALID_SIG || hr == E_PDB_INVALID_AGE ) // Mismatching PDB
      goto fail;
    pdb_loaded = (hr == S_OK);
    used_fname = pdb_path; // TODO is this needed?
  }

  // Failed? Try to load input_path as EXE if it was specified.
  const qstring &input_path = pdbargs.input_path;
  if ( !pdb_loaded && !input_path.empty() )
  {
    qstring path = input_path;
    if ( !qfileexist(path.c_str()) )
    {
      // If the input path came from a remote system, it is unlikely to be
      // correct on our system. DIA does not care about the exact file name
      // but uses the directory path to locate the PDB file. It combines
      // the name of the pdb file from the debug directory and the directory
      // from the input path.
      // Since we cannot rely on remote paths, we simply use the current dir
      char buf[QMAXPATH];
      qgetcwd(buf, sizeof(buf));
      path.sprnt("%s\\%s", buf, qbasename(input_path.c_str()));
      msg("PDB: \"%s\": not found, trying \"%s\"\n", path.c_str(), buf);
    }
    if ( !check_for_odd_paths(path.c_str()) )
      return E_PDB_NOT_FOUND;

    used_fname = path;

    // Setup symsrv callback to show wait box for pdb downloading
    symsrv_cb_t symsrv_cb;
    symsrv_cb.init();

    // Try searching for PDB information from the debug directory in a
    // PE file. Either the input file is read directly or the contents
    // of a loaded module are read from memory.
    hr = load_input_path(pdbargs, path.c_str());
    pdb_loaded = (hr == S_OK);

    // Hide wait box for pdb downloading if needed
    symsrv_cb.term();
  }

  // Failed? Then nothing else to try, quit
  if ( !pdb_loaded )
  {
    // make sure we do return an error
    if ( hr == S_OK )
      hr = E_FAIL;
    goto fail;
  }

  // Open a session for querying symbols
  hr = pSource->openSession(&pSession);
  deb(IDA_DEBUG_DEBUGGER, "PDB: openSession(): %s\n", pdberr(hr));
  if ( FAILED(hr) )
    goto fail;

  // Set load address
  // TODO check if load_address should be set when loading PDB works directly.
  ea_t load_address = pdbargs.loaded_base;
  if ( load_address != BADADDR )
  {
    msg("PDB: using load address %a\n", load_address);
    pSession->put_loadAddress(load_address);  //-V595 'pSession' was utilized before it was verified against nullptr
  }

  // Retrieve a reference to the global scope
  hr = pSession->get_globalScope(&pGlobal); //-V595 'pSession' was utilized before it was verified against nullptr
  if ( hr != S_OK )
    goto fail;

  pdb_access = new local_pdb_access_t(pdbargs, pSource, pSession, pGlobal);

  DWORD pdb_machType, machType;
  if ( pGlobal->get_machineType(&pdb_machType) != S_OK ) //-V595 The 'pGlobal' pointer was utilized before it was verified against nullptr
    pdb_machType = IMAGE_FILE_MACHINE_I386;
  machType = get_machine_type(pdb_machType);

  pdb_access->set_machine_type(machType);
  pdb_access->set_dia_version(dia_version);

  hr = pdb_access->init();
  if ( hr == S_OK )
    return hr;

  // TODO clear pdb_access since above test failed

fail:
  // In the event of an error, this will be reached.
  if ( pdb_access == nullptr )
  {
    if ( pGlobal != nullptr )
      pGlobal->Release();
    if ( pSession != nullptr )
      pSession->Release();
    if ( pSource != nullptr )
      pSource->Release();
  }
  return hr;
}

static qstring get_msdia140_dll_path()
{
	bstr_t bstrVsInstallationPath;
	ULONGLONG ullVersion;
	HRESULT hr = GetMaxVersionVsInstallationPath(bstrVsInstallationPath, ullVersion);
	if (hr == S_OK)
	{
        //Remote Debugger目录下的msdia140.dll的版本比DIA SDK目录下的高一个修订版本号且带有symsrv.dll，
        //所以我们使用这个目录下的版本，
        //虽然目前这个目录下的symsrv.dll版本会太低了，无法支持立刻取消下载，但是未来这个symsrv.dll的版本肯定会被升级的，
        //到时候我们就不需要自己提供更高版本的symsrv.dll文件了
		bstrVsInstallationPath += L"\\Common7\\IDE\\Remote Debugger\\x64\\msdia140.dll";
        return utf16_acp(bstrVsInstallationPath);
	}
    else
    {
        return "";
    }
}

//----------------------------------------------------------------------
HRESULT pdb_session_t::create_dia_source(int *dia_version)
{
  HRESULT hr;
  // VC80/90 CRT installs msdiaNN.dll in this folder:
  // "C:\Program Files (x86)\Common Files\microsoft shared\VC"
  char common_files[QMAXPATH];
  qstring vc_shared;
#ifndef __IS_MSDIA100_OR_GREATER__
  if ( get_special_folder(common_files, sizeof(common_files), CSIDL_PROGRAM_FILES_COMMON) )
  {
    vc_shared = common_files;
    vc_shared.append("\\Microsoft Shared\\VC");
  }
#endif

  for ( size_t i=0; i < qnumber(g_msdiav); i++ )
  {
    // Try to create using CoCreateInstance()
    hr = CoCreateInstance(*g_msdiav[i],
                          nullptr,
                          CLSCTX_INPROC_SERVER,
                          __uuidof(IDiaDataSource),
                          (void**)&pSource);

    // Try to create with CoCreateInstanceNoReg()
    if ( FAILED(hr) )
    {
      // Search for this interface in DIA dlls
      char path[QMAXPATH];
	  path[0] = 0;
	  if (g_diaver[i] == 1400)
	  {
		  qstring msdia140_dll_path = get_msdia140_dll_path();
		  if (!msdia140_dll_path.empty())
		  {
			  char dir_path[QMAXPATH];
			  qdirname(dir_path, qnumber(dir_path), msdia140_dll_path.c_str());
			  SetDllDirectory(dir_path);

			  qstrncpy(path, msdia140_dll_path.c_str(), qnumber(path));
		  }
	  }
	  if (!path[0])
	  {
		  if (SearchPathA(nullptr, g_diadlls[i], nullptr, qnumber(path), path, nullptr) == 0
              && !search_path(path, sizeof(path), g_diadlls[i], false)
			  && (vc_shared.empty()
				  || SearchPathA(vc_shared.c_str(), g_diadlls[i], nullptr,
					  qnumber(path), path, nullptr) == 0))
		  {
			  continue;
		  }
	  }

      for ( size_t j=0; j < qnumber(g_msdiav); j++ )
      {
        hr = CoCreateInstanceNoReg(path,
                                   *g_msdiav[j],
                                   nullptr,
                                   __uuidof(IDiaDataSource),
                                   (void**)&pSource,
                                   &dia_hmod);

        if ( hr == S_OK )
        {
          static bool displayed = false;
          if ( !displayed )
          {
            displayed = true;
            msg("PDB: using DIA dll \"%s\"\n", path);
          }
          i = j;
          break;
        }
      }
    }

    if ( hr == S_OK )
    {
      *dia_version = g_diaver[i];
      static bool displayed = false;
      if ( !displayed )
      {
        displayed = true;
        msg("PDB: DIA interface version %d.%d\n", (*dia_version)/100, (*dia_version)%100);
      }
      return hr;
    }
    else
    {
      *dia_version = 0;
    }
  }
  return E_NOINTERFACE;
}

//----------------------------------------------------------------------
pdb_session_ref_t::pdb_session_ref_t(const pdb_session_ref_t &r)
  : session(r.session)
{
  if ( session != nullptr )
    session->refcount++;
}

//----------------------------------------------------------------------
pdb_session_ref_t &pdb_session_ref_t::operator=(const pdb_session_ref_t &r)
{
  if ( &r != this )
  {
    this->~pdb_session_ref_t();
    new (this) pdb_session_ref_t(r);
  }
  return *this;
}

//----------------------------------------------------------------------------
pdb_session_ref_t::~pdb_session_ref_t()
{
  close();
  if ( session != nullptr )
  {
    delete session;
    session = nullptr;
  }
}

//----------------------------------------------------------------------
void pdb_session_ref_t::create_session(void)
{
  QASSERT(30462, session == nullptr);
  session = new pdb_session_t();
}

//----------------------------------------------------------------------
void pdb_session_ref_t::close()
{
  if ( session != nullptr )
  {
    // shared instance? then detach
    if ( session->refcount > 1 )
    { // unlink
      session->refcount--;
      session = nullptr;
    }
    else
    {
      session->close();
    }
  }
}

//----------------------------------------------------------------------
HRESULT pdb_session_ref_t::open_session(pdbargs_t &pdbargs)
{
  if ( opened() )
    return S_OK;

  if ( empty() )
    create_session();

  return session->open_session(pdbargs);
}
