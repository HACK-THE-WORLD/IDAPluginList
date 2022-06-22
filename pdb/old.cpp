
// Old interface to PDB files
// It is used as a fallback method if DIA interface fails

#include <windows.h>

#pragma pack(push, 8)
#include "cvconst.h"
#include "dbghelp.h"
#pragma pack(pop)

#include <ida.hpp>
#include <idp.hpp>
#include <err.h>
#include "oldpdb.h"

//----------------------------------------------------------------------
typedef DWORD IMAGEAPI SymSetOptions_t(IN DWORD SymOptions);
typedef BOOL IMAGEAPI SymInitialize_t(IN HANDLE hProcess, IN LPCSTR UserSearchPath, IN BOOL fInvadeProcess);
typedef DWORD64 IMAGEAPI SymLoadModule64_t(IN HANDLE hProcess, IN HANDLE hFile, IN PSTR ImageName, IN PSTR ModuleName, IN DWORD64 BaseOfDll, IN DWORD SizeOfDll);
typedef BOOL IMAGEAPI SymEnumSymbols_t(IN HANDLE hProcess, IN ULONG64 BaseOfDll, IN PCSTR Mask, IN PSYM_ENUMERATESYMBOLS_CALLBACK EnumSymbolsCallback, IN PVOID UserContext);
typedef BOOL IMAGEAPI SymUnloadModule64_t(IN HANDLE hProcess, IN DWORD64 BaseOfDll);
typedef BOOL IMAGEAPI SymCleanup_t(IN HANDLE hProcess);

static HINSTANCE dbghelp = nullptr;
static SymSetOptions_t     *pSymSetOptions     = nullptr;
static SymInitialize_t     *pSymInitialize     = nullptr;
static SymLoadModule64_t   *pSymLoadModule64   = nullptr;
static SymEnumSymbols_t    *pSymEnumSymbols    = nullptr;
static SymUnloadModule64_t *pSymUnloadModule64 = nullptr;
static SymCleanup_t        *pSymCleanup        = nullptr;
static int symbols_found = 0;

//----------------------------------------------------------------------
// Dynamically load and link to DBGHELP or IMAGEHLP libraries
// Return: success
static bool setup_pointers(bool *must_free)
{
  char dll[QMAXPATH];

  // check if it's already loaded
  dbghelp = GetModuleHandle("dbghelp.dll");

  *must_free = false;
  if ( dbghelp == nullptr )
  {
    // nope, load it
    // use search_path to avoid dll current directory attacks
    if ( !search_path(dll, sizeof(dll), "dbghelp.dll", false) )
      return false;
    dbghelp = LoadLibrary(dll);
    *must_free = true;
  }

  if ( dbghelp == nullptr )
  {
    deb(IDA_DEBUG_DBGINFO, "PDB plugin: failed to load DBGHELP.DLL");
  }
  else
  {
    *(FARPROC*)&pSymSetOptions     = GetProcAddress(dbghelp, "SymSetOptions");
    *(FARPROC*)&pSymInitialize     = GetProcAddress(dbghelp, "SymInitialize");
    *(FARPROC*)&pSymLoadModule64   = GetProcAddress(dbghelp, "SymLoadModule64");
    *(FARPROC*)&pSymEnumSymbols    = GetProcAddress(dbghelp, "SymEnumSymbols");
    *(FARPROC*)&pSymUnloadModule64 = GetProcAddress(dbghelp, "SymUnloadModule64");
    *(FARPROC*)&pSymCleanup        = GetProcAddress(dbghelp, "SymCleanup");

    if ( pSymSetOptions     != nullptr
      && pSymInitialize     != nullptr
      && pSymLoadModule64   != nullptr
      && pSymUnloadModule64 != nullptr
      && pSymCleanup        != nullptr
      && pSymEnumSymbols    != nullptr ) // required XP or higher
    {
      return true;
    }
  }
  deb(IDA_DEBUG_DBGINFO, "PDB plugin: Essential DBGHELP.DLL functions are missing\n");
  if ( dbghelp != nullptr )
  {
    FreeLibrary(dbghelp);
    dbghelp = nullptr;
  }
  return false;
}

//----------------------------------------------------------------------
// New method: symbol enumeration callback
//lint -e{818} could be declared as pointing to const
static BOOL CALLBACK EnumerateSymbolsProc(
        PSYMBOL_INFO psym,
        ULONG /*SymbolSize*/,
        PVOID delta)
{
  symbols_found++;
  ea_t ea = (ea_t)(psym->Address + *(adiff_t*)delta);
  const char *name = psym->Name;

  int maybe_func = 0; // maybe
  switch ( psym->Tag )
  {
    case SymTagFunction:
    case SymTagThunk:
      maybe_func = 1;
      break;
    case SymTagNull:
    case SymTagExe:
    case SymTagCompiland:
    case SymTagCompilandDetails:
    case SymTagCompilandEnv:
    case SymTagData:
    case SymTagAnnotation:
    case SymTagUDT:
    case SymTagEnum:
    case SymTagFunctionType:
    case SymTagPointerType:
    case SymTagArrayType:
    case SymTagBaseType:
    case SymTagTypedef:
    case SymTagBaseClass:
    case SymTagFunctionArgType:
    case SymTagUsingNamespace:
    case SymTagVTableShape:
    case SymTagVTable:
    case SymTagCustom:
    case SymTagCustomType:
    case SymTagManagedType:
    case SymTagDimension:
      maybe_func = -1;
      break;
    case SymTagBlock:
    case SymTagLabel:
    case SymTagFuncDebugStart:
    case SymTagFuncDebugEnd:
      maybe_func = 2;
      break;
    case SymTagPublicSymbol:
    case SymTagFriend:
    default:
      break;
  }

  bool ok = apply_name(ea, name, maybe_func);
  // New dbghelp.dll/symsrv.dll files return names without the terminating zero.
  // So, as soon as we have a long name, shorter names will have garbage at the end.
  // Clean up the name to avoid problems.
  size_t len = strlen(name);
  memset((void*)name, '\0', len);
  return ok;
}

//----------------------------------------------------------------------
// Display a system error message
static void error_msg(const char *name)
{
  int code = GetLastError();
  if ( code != 0 )
    msg("%s: %s\n", name, winerr(code));
}

//----------------------------------------------------------------------
// Try old method of loading symbols
bool old_pdb_plugin(ea_t loaded_base, const char *input, const char *spath)
{
  bool ok = false;
  bool must_free;
  if ( setup_pointers(&must_free) )
  {
    pSymSetOptions(SYMOPT_LOAD_LINES|SYMOPT_FAVOR_COMPRESSED|SYMOPT_NO_PROMPTS);

    void *fake_proc = (void *)(uintptr_t)0xBEEFFEED;
    if ( !pSymInitialize(fake_proc, spath, FALSE) )
    {
      error_msg("SymInitialize");
    }
    else
    {
      DWORD64 symbase = pSymLoadModule64(fake_proc, 0, (char*)input, nullptr, loaded_base, 0);
      if ( symbase != 0 )
      {
        load_vc_til();

        symbols_found = 0;
        adiff_t delta = adiff_t(loaded_base - symbase);
        ok = pSymEnumSymbols(fake_proc, symbase, nullptr, EnumerateSymbolsProc, &delta)
          && symbols_found > 0;
        if ( !ok )
          error_msg("EnumSymbols");
        if ( !pSymUnloadModule64(fake_proc, symbase) )
          error_msg("SymUnloadModule64");
      }
      if ( !pSymCleanup(fake_proc) )
        error_msg("SymCleanup");
    }
    if ( must_free )
    {
      FreeLibrary(dbghelp);
      dbghelp = nullptr;
    }
  }
  return ok;
}
