// <copyright file="targetver.h" company="Microsoft Corporation">
// Copyright (C) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license. See LICENSE.txt in the project root for license information.
// </copyright>

#pragma once

// Including SDKDDKVer.h defines the highest available Windows platform.

// If you wish to build your application for a previous Windows platform, include WinSDKVer.h and
// set the _WIN32_WINNT macro to the platform you wish to support before including SDKDDKVer.h.

#include <winsdkver.h>

#ifdef  _WIN32_WINNT
#undef  _WIN32_WINNT
#endif

#define _WIN32_WINNT 0x0601

#include <SDKDDKVer.h>
