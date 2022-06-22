// <copyright file="Helpers.cpp" company="Microsoft Corporation">
// Copyright (C) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license. See LICENSE.txt in the project root for license information.
// </copyright>

#include "stdafx.h"

using namespace std;

wostream& operator<<(_In_ wostream& os, _In_ const variant_t& var)
{
    switch (var.vt)
    {
    case VT_BOOL:
        if (VARIANT_FALSE == var.boolVal)
        {
            os << FALSESTRING;
        }
        else
        {
            os << TRUESTRING;
        }

        return os;

    case VT_BSTR:
        os << var.bstrVal;
        return os;

    case VT_I1:
    case VT_I2:
    case VT_I4:
    case VT_I8:
    case VT_UI1:
    case VT_UI2:
    case VT_UI4:
        os << var.llVal;
        return os;

    default:
        throw win32_exception(E_UNEXPECTED, "variant type not supported");
    }
}
