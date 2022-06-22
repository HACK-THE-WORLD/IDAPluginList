#pragma once

#include <dia2.h>
#include "pro.h"

typedef unsigned long   ulong;
enum MDTokenMapKind;

extern "C" const IID IID_IDiaSession10;
MIDL_INTERFACE("167e13cf-984d-ef4e-bd42-1723e6f34244")
IDiaSession10 :public IDiaSession
{
public:
	virtual HRESULT STDMETHODCALLTYPE addPublicSymbol(ushort const *, ulong, ulong, ulong, ulong, ulong, IDiaSymbol *, IDiaSymbol * *) = 0;
	virtual HRESULT STDMETHODCALLTYPE addStaticSymbol(ushort const *, ulong, ulong, ulong, ulong, ulong, IDiaSymbol *) = 0;
	virtual HRESULT STDMETHODCALLTYPE findSectionAddressByCrc(ulong, ulong, ulong, ulong, IDiaSymbol *, ulong *, ulong *, ulong *) = 0;
	virtual HRESULT STDMETHODCALLTYPE findThunkSymbol(IDiaSymbol *, IDiaSymbol * *) = 0;
	virtual HRESULT STDMETHODCALLTYPE makeThunkSymbol(ulong, ulong, IDiaSymbol * *) = 0;
	virtual HRESULT STDMETHODCALLTYPE mergeObjPDB(IDiaSymbol *) = 0;
	virtual HRESULT STDMETHODCALLTYPE commitObjPDBMerge(IDiaSymbol *) = 0;
	virtual HRESULT STDMETHODCALLTYPE cancelObjPDBMerge(IDiaSymbol *) = 0;
	virtual HRESULT STDMETHODCALLTYPE getLinkInfo(uchar *, ulong *, ulong *, ulong *, ulong *, ulong *) = 0;
	virtual HRESULT STDMETHODCALLTYPE isMiniPDB(int *) = 0;
	virtual HRESULT STDMETHODCALLTYPE prepareEnCRebuild(IDiaSymbol *) = 0;
	virtual HRESULT STDMETHODCALLTYPE dispose(void) = 0;
	virtual HRESULT STDMETHODCALLTYPE getRawSymbolsFromMiniPDB(ulong, ulong, ulong *, uchar * *) = 0;
	virtual HRESULT STDMETHODCALLTYPE getRawTypesFromMiniPDB(ulong, ulong *, uchar * *) = 0;
	virtual HRESULT STDMETHODCALLTYPE getPdbMappingsForMiniPDB(ulong *, ushort * *, ushort * *) = 0;
	virtual HRESULT STDMETHODCALLTYPE disposeObjForMiniPDB(ulong) = 0;
	virtual HRESULT STDMETHODCALLTYPE EnablePrefetching(void) = 0;
	virtual HRESULT STDMETHODCALLTYPE isPCTModuleFromMiniPDB(ulong, int *) = 0;
	virtual HRESULT STDMETHODCALLTYPE EnableMemoryMappedFileIO(void) = 0;
	virtual HRESULT STDMETHODCALLTYPE VSDebuggerPreloadPDBDone(void) = 0;
	virtual HRESULT STDMETHODCALLTYPE isLinkerGeneratedModuleInMiniPDB(ulong, int *) = 0;
	virtual HRESULT STDMETHODCALLTYPE getInlineeMDTokenMapSize(ulong *) = 0;
	virtual HRESULT STDMETHODCALLTYPE getInlineeMDTokenMap(ulong, ulong *, uchar *) = 0;
	virtual HRESULT STDMETHODCALLTYPE findChildrenHelper(IDiaSymbol *, enum SymTagEnum, ushort const *, ulong, ulong, bool, bool, IDiaEnumSymbols * *) = 0;
	virtual HRESULT STDMETHODCALLTYPE findLinesByLinenumHelper(bool, IDiaSymbol *, IDiaSourceFile *, ulong, ulong, IDiaEnumLineNumbers * *) = 0;
	virtual HRESULT STDMETHODCALLTYPE findSymbolsForAcceleratorPointerTagHelper(IDiaSymbol *, ulong, ulong, bool, IDiaEnumSymbols * *) = 0;
	virtual HRESULT STDMETHODCALLTYPE getMDTokenMapHelper(MDTokenMapKind, ulong, ulong *, uchar *) = 0;
	virtual HRESULT STDMETHODCALLTYPE getMDTokenMapHelper2(ulong, MDTokenMapKind, ulong, ulong *, uchar *) = 0;
	virtual HRESULT STDMETHODCALLTYPE getMDTokenRemapHelper(MDTokenMapKind, ulong, ulong *, uchar *) = 0;
	virtual HRESULT STDMETHODCALLTYPE getFunctionFragmentsHelper(ulong, ulong, ulong, ulong *, ulong *, ulong *) = 0;
};

//https://github.com/riverar/mach2/blob/master/src/dia2_internal.h
extern "C" const IID IID_IDiaDataSource10;
MIDL_INTERFACE("5c7e382a-93b4-4677-a6b5-cc28c3accb96")
IDiaDataSource10: public IDiaDataSource
{
public:
	virtual HRESULT STDMETHODCALLTYPE getRawPDBPtr(void** pppdb) = 0;
	virtual HRESULT STDMETHODCALLTYPE loadDataFromRawPDBPtr(void* ppdb) = 0;
	virtual HRESULT STDMETHODCALLTYPE getStreamSize(ushort const * stream, ulong* pcb) = 0;
	virtual HRESULT STDMETHODCALLTYPE getStreamRawData(ushort const * stream, ulong cbRead, uchar* pbData) = 0;
	virtual HRESULT STDMETHODCALLTYPE loadDataFromPdbEx(ushort const *, int) = 0;
	virtual HRESULT STDMETHODCALLTYPE loadAndValidateDataFromPdbEx(ushort const *, _GUID *, ulong, ulong, int) = 0;
	virtual HRESULT STDMETHODCALLTYPE loadDataForExeEx(ushort const *, ushort const *, IUnknown *, int) = 0;
	virtual HRESULT STDMETHODCALLTYPE loadDataFromIStreamEx(IStream *, int) = 0;
	virtual HRESULT STDMETHODCALLTYPE UNSUPPORTED_Method() = 0;
	virtual HRESULT STDMETHODCALLTYPE setPfnMiniPDBErrorCallback2(void *, long(*)(void *, ulong, ushort const * const, ushort const * const)) = 0;
	virtual HRESULT STDMETHODCALLTYPE setPfnMiniPDBNHBuildStatusCallback(void *, int(*)(void *, ulong)) = 0;
	virtual HRESULT STDMETHODCALLTYPE loadDataFromPdbEx2(ushort const *, int, int) = 0;
	virtual HRESULT STDMETHODCALLTYPE loadAndValidateDataFromPdbEx2(ushort const *, _GUID *, ulong, ulong, int, int) = 0;
	virtual HRESULT STDMETHODCALLTYPE loadDataForExeEx2(ushort const *, ushort const *, IUnknown *, int, int) = 0;
	virtual HRESULT STDMETHODCALLTYPE loadDataFromIStreamEx2(IStream *, int, int) = 0;
	virtual HRESULT STDMETHODCALLTYPE loadDataFromCodeViewInfoEx(ushort const *, ushort const *, ulong, uchar *, IUnknown *, int) = 0;
	virtual HRESULT STDMETHODCALLTYPE VSDebuggerPreloadPDBDone(void) = 0;
	virtual HRESULT STDMETHODCALLTYPE loadDataForExeEx3(ushort const *, ushort const *, IUnknown *, int, int, int) = 0;
	virtual HRESULT STDMETHODCALLTYPE usePdb(void *) = 0;
	virtual HRESULT STDMETHODCALLTYPE loadDataFromCodeViewInfoHelper(ushort const *, ushort const *, ulong, uchar *, IUnknown *, char const *) = 0;
};

class PDB1
{
public:
	virtual int32_t QueryInterfaceVersion() = 0;
	virtual int32_t QueryImplementationVersion() = 0;
	virtual BOOL QueryLastError() = 0;
	virtual PWSTR* QueryPDBName() = 0;
	virtual uint32_t QuerySignature() = 0;
	virtual uint32_t QueryAge() = 0;
	virtual void CreateDBI() = 0;
	virtual void OpenDBI() = 0;
	virtual void OpenTpi() = 0;
	virtual void OpenIpi() = 0;
	virtual void Commit() = 0;
	virtual void Close() = 0;
	virtual void OpenStream() = 0;
	virtual void GetEnumStreamNameMap() = 0;
	virtual void GetRawBytes() = 0;
	virtual void QueryPdbImplementationVersion() = 0;
	virtual void OpenDBIEx() = 0;
	virtual void CopyTo() = 0;
	virtual void OpenSrc() = 0;
	virtual void QueryLastErrorExW() = 0;
	virtual void QueryPDBNameExW() = 0;
	virtual BOOL QuerySignature2(GUID* guid) = 0;
	// ...
};