// <copyright file="Program.cpp" company="Microsoft Corporation">
// Copyright (C) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license. See LICENSE.txt in the project root for license information.
// </copyright>

#include "stdafx.h"

using namespace std;

// Use smart pointers (without ATL) to release objects when they fall out of scope.
_COM_SMARTPTR_TYPEDEF(ISetupInstance, __uuidof(ISetupInstance));
_COM_SMARTPTR_TYPEDEF(ISetupInstance2, __uuidof(ISetupInstance2));
_COM_SMARTPTR_TYPEDEF(IEnumSetupInstances, __uuidof(IEnumSetupInstances));
_COM_SMARTPTR_TYPEDEF(ISetupConfiguration, __uuidof(ISetupConfiguration));
_COM_SMARTPTR_TYPEDEF(ISetupConfiguration2, __uuidof(ISetupConfiguration2));
_COM_SMARTPTR_TYPEDEF(ISetupHelper, __uuidof(ISetupHelper));
_COM_SMARTPTR_TYPEDEF(ISetupPackageReference, __uuidof(ISetupPackageReference));
_COM_SMARTPTR_TYPEDEF(ISetupPropertyStore, __uuidof(ISetupPropertyStore));
_COM_SMARTPTR_TYPEDEF(ISetupInstanceCatalog, __uuidof(ISetupInstanceCatalog));

void PrintInstance(
    _In_ ISetupInstance* pInstance,
	_In_ ISetupHelper* pHelper,
	bstr_t& MaxVsInstanceVersion
);

//void PrintPackageReference(
//    _In_ ISetupPackageReference* pPackage
//);
//
//void PrintProperties(
//    _In_ ISetupPropertyStore* pStore
//);

BOOL FindVcInWorkloads(
    _In_ LPSAFEARRAY psaPackages
);

HRESULT GetMaxVersionVsInstallationPath(bstr_t& bstrVsInstallationPath, ULONGLONG& ullVersion)
{
    try
    {
        CoInitializer init;
        ISetupConfigurationPtr query;

		std::vector<ISetupInstancePtr> SetupInstances;
        bstr_t MaxVsInstanceVersion;

        auto hr = query.CreateInstance(__uuidof(SetupConfiguration));
        if (REGDB_E_CLASSNOTREG == hr)
        {
            cout << "The query API is not registered. Assuming no instances are installed." << endl;
            return hr;
        }
        else if (FAILED(hr))
        {
            throw win32_exception(hr, "failed to create query class");
        }

        ISetupConfiguration2Ptr query2(query);
        IEnumSetupInstancesPtr e;

        hr = query2->EnumAllInstances(&e);
        if (FAILED(hr))
        {
            throw win32_exception(hr, "failed to query all instances");
        }

        ISetupHelperPtr helper(query);

        ISetupInstance* pInstances[1] = {};
        hr = e->Next(1, pInstances, nullptr);
        while (S_OK == hr)
        {
            // Wrap instance without AddRef'ing.
            ISetupInstancePtr instance(pInstances[0], false);
            PrintInstance(instance, helper, MaxVsInstanceVersion);
			SetupInstances.push_back(instance);

            hr = e->Next(1, pInstances, nullptr);
        }

        if (FAILED(hr))
        {
            throw win32_exception(hr, "failed to enumerate all instances");
        }

		for (auto instance : SetupInstances)
		{
			HRESULT hr;
			bstr_t bstrVersion;
			if (FAILED(hr = instance->GetInstallationVersion(bstrVersion.GetAddress())))
			{
				throw win32_exception(hr, "failed to get InstallationVersion");
			}
			if (!wcscmp(bstrVersion, MaxVsInstanceVersion))
			{
				if (FAILED(hr = helper->ParseVersion(bstrVersion, &ullVersion)))
				{
					throw win32_exception(hr, "failed to parse InstallationVersion");
				}

				bstr_t bstrInstallationPath;
				if (FAILED(hr = instance->GetInstallationPath(bstrInstallationPath.GetAddress())))
				{
					throw win32_exception(hr, "failed to get InstallationPath");
				}

				//wcout << L"Max Vs InstallationPath: " << bstrInstallationPath << endl;
				bstrVsInstallationPath = bstrInstallationPath;
			}
		}
		SetupInstances.clear();
    }
    catch (win32_exception& ex)
    {
        cerr << hex << "Error 0x" << ex.code() << ": " << ex.what() << endl;
        return ex.code();
    }
    catch (exception& ex)
    {
        cerr << "Error: " << ex.what() << endl;
        return E_FAIL;
    }

    return ERROR_SUCCESS;
}

void PrintInstance(
    _In_ ISetupInstance* pInstance,
    _In_ ISetupHelper* pHelper,
    bstr_t& MaxVsInstanceVersion
)
{
    HRESULT hr = S_OK;
    ISetupInstance2Ptr instance(pInstance);

    bstr_t bstrId;
    if (FAILED(hr = instance->GetInstanceId(bstrId.GetAddress())))
    {
        throw win32_exception(hr, "failed to get InstanceId");
    }

    InstanceState state;
    if (FAILED(hr = instance->GetState(&state)))
    {
        throw win32_exception(hr, "failed to get State");
    }

    //wcout << L"InstanceId: " << bstrId << L" (" << (eComplete == state ? L"Complete" : L"Incomplete") << L")" << endl;

    bstr_t bstrVersion;
    if (FAILED(hr = instance->GetInstallationVersion(bstrVersion.GetAddress())))
    {
        throw win32_exception(hr, "failed to get InstallationVersion");
    }

    //ULONGLONG ullVersion;
    //if (FAILED(hr = pHelper->ParseVersion(bstrVersion, &ullVersion)))
    //{
    //    throw win32_exception(hr, "failed to parse InstallationVersion");
    //}

    //wcout << L"InstallationVersion: " << bstrVersion << L" (" << ullVersion << L")" << endl;

    // Reboot may have been required before the installation path was created.
    //if ((eLocal & state) == eLocal)
    //{
    //    bstr_t bstrInstallationPath;
    //    if (FAILED(hr = instance->GetInstallationPath(bstrInstallationPath.GetAddress())))
    //    {
    //        throw win32_exception(hr, "failed to get InstallationPath");
    //    }

    //    wcout << L"InstallationPath: " << bstrInstallationPath << endl;
    //}

    ISetupInstanceCatalogPtr catalog;
    if (SUCCEEDED(instance->QueryInterface(&catalog)))
    {
        VARIANT_BOOL fIsPrerelease;
        if (FAILED(hr = catalog->IsPrerelease(&fIsPrerelease)))
        {
            throw win32_exception(hr, "failed to get IsPrerelease");
        }

        const auto wzIsPrerelease = VARIANT_FALSE == fIsPrerelease ? FALSESTRING : TRUESTRING;
        //wcout << L"IsPrerelease: " << wzIsPrerelease << endl;
    }

    // Reboot may have been required before the product package was registered (last).
    if ((eRegistered & state) == eRegistered)
    {
        ISetupPackageReferencePtr product;
        if (FAILED(hr = instance->GetProduct(&product)))
        {
            throw win32_exception(hr, "failed to get Product");
        }

        //wcout << L"Product: ";
        //PrintPackageReference(product);

        //wcout << endl;

        LPSAFEARRAY psa = nullptr;
        if (FAILED(hr = instance->GetPackages(&psa)))
        {
            throw win32_exception(hr, "failed to get Packages");
        }

        // Make sure the SAFEARRAY is freed when it falls out of scope.
        safearray_ptr psa_ptr(&psa);

        //wcout << L"Workloads:" << endl;
		BOOL bFind = FindVcInWorkloads(psa);
		if (bFind)
		{
			if (MaxVsInstanceVersion.length() == 0)
			{
				MaxVsInstanceVersion = bstrVersion;
			}
			else if (CompareFileVersion(bstrVersion, MaxVsInstanceVersion) > 0)
			{
				MaxVsInstanceVersion = bstrVersion;
			}
		}
    }

    //ISetupPropertyStorePtr properties;
    //if (SUCCEEDED(instance->GetProperties(&properties)) && properties)
    //{
    //    wcout << L"Custom properties:" << endl;
    //    PrintProperties(properties);
    //}

    //if (catalog && SUCCEEDED(catalog->GetCatalogInfo(&properties)) && properties)
    //{
    //    wcout << L"Catalog properties:" << endl;
    //    PrintProperties(properties);
    //}

    //wcout << endl;
}

BOOL FindPackageReference(
    _In_ ISetupPackageReference* pPackage, LPOLESTR pszId
)
{
	BOOL bFind = FALSE;

    HRESULT hr = S_OK;
    ISetupPackageReferencePtr ref(pPackage);
    
    bstr_t bstrId;
    if (FAILED(hr = ref->GetId(bstrId.GetAddress())))
    {
        throw win32_exception(hr, "failed to get reference Id");
    }

    // Check that an ID is registered; unexpected otherwise, but would throw in RCW.
    if (!!bstrId)
    {
        //wcout << bstrId;
		if (!wcscmp(bstrId, pszId))
		{
			bFind = TRUE;
		}
    }

	return bFind;
}

void PrintProperties(
    _In_ ISetupPropertyStore* pStore
)
{
    HRESULT hr = S_OK;
    LPSAFEARRAY psaNames = nullptr;

    if (FAILED(hr = pStore->GetNames(&psaNames)))
    {
        throw win32_exception(hr, "failed to get property names");
    }

    // Make sure the SAFEARRAY is freed when it falls out of scope.
    safearray_ptr psaNames_ptr(&psaNames);

    // Lock the SAFEARRAY to get the raw pointer array.
    if (FAILED(hr = ::SafeArrayLock(psaNames)))
    {
        throw win32_exception(hr, "failed to lock property name array");
    }

    auto rgpNames = reinterpret_cast<BSTR*>(psaNames->pvData);
    auto cNames = psaNames->rgsabound[0].cElements;

    if (0 == cNames)
    {
        return;
    }

    vector<BSTR> names(rgpNames, rgpNames + cNames);
    sort(names.begin(), names.end(), [&](const BSTR bstrA, const BSTR bstrB) -> bool
    {
        return 0 > _wcsicmp((LPCWSTR)bstrA, (LPCWSTR)bstrB);
    });

    for_each(names.begin(), names.end(), [&](const BSTR bstrName)
    {
        variant_t var;
        if (FAILED(hr = pStore->GetValue((LPCWSTR)bstrName, &var)))
        {
            throw win32_exception(hr, "failed to get property value");
        }

        wcout << L"    " << bstrName << L": " << var << endl;
    });

    // SafeArrayDeleter will unlock if exception thrown.
    ::SafeArrayUnlock(psaNames);
}

BOOL FindVcInWorkloads(
    _In_ LPSAFEARRAY psaPackages
)
{
    // Lock the SAFEARRAY to get the raw pointer array.
    auto hr = ::SafeArrayLock(psaPackages);
    if (FAILED(hr))
    {
        throw win32_exception(hr, "failed to lock package arrays");
    }

    auto rgpPackages = reinterpret_cast<ISetupPackageReference**>(psaPackages->pvData);
    auto cPackages = psaPackages->rgsabound[0].cElements;

    if (0 == cPackages)
    {
        return FALSE;
    }

    vector<ISetupPackageReference*> packages(rgpPackages, rgpPackages + cPackages);

    const WCHAR wzType[] = L"Workload";
    const size_t cchType = sizeof(wzType) / sizeof(WCHAR) - 1;

    // Find all the workload package types.
    vector<ISetupPackageReference*> workloads;
    for (auto pPackage : packages)
    {
        bstr_t bstrType;

        if (SUCCEEDED(hr = pPackage->GetType(bstrType.GetAddress())))
        {
            if (cchType == bstrType.length() && 0 == _wcsnicmp(wzType, bstrType, cchType))
            {
                workloads.push_back(pPackage);
            }
        }
    }

    //sort(workloads.begin(), workloads.end(), [&](ISetupPackageReference* pA, ISetupPackageReference* pB) -> bool
    //{
    //    bstr_t bstrA;
    //    bstr_t bstrB;

    //    if (SUCCEEDED(hr = pA->GetId(bstrA.GetAddress())))
    //    {
    //        if (SUCCEEDED(hr = pB->GetId(bstrB.GetAddress())))
    //        {
    //            return 0 > _wcsicmp(bstrA, bstrB);
    //        }
    //    }

    //    return 0 > _wcsicmp(__nameof(bstrA), __nameof(bstrB));
    //});

	BOOL bFind = FALSE;
    for(ISetupPackageReference* pWorkload: workloads)
    {
        //wcout << L"    ";
        bFind = FindPackageReference(pWorkload, L"Microsoft.VisualStudio.Workload.NativeDesktop");
		if (bFind)
		{
			break;
		}

        //wcout << endl;
    }

    // SafeArrayDeleter will unlock if exception thrown.
    ::SafeArrayUnlock(psaPackages);

	return bFind;
}
