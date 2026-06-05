#pragma once
#include "include/describe/vuln_description.hpp"

#include <windows.h>
#include <string_view>
#include <iostream>


namespace CVE_2021_1732
{
    typedef struct _OSVersionInfo
    {
        ULONG dwOSVersionInfoSize;
        ULONG dwMajorVersion;
        ULONG dwMinorVersion;
        ULONG dwBuildNumber;
        ULONG dwPlatformId;
        WCHAR szCSDVersion[128];
    }OSVersionInfo, * pOSVersionInfo;

    using RtlGetVersionFn = LONG(WINAPI*)(OSVersionInfo*);

    namespace env
    {
        // 64bit system check
        bool checkX64System();

        // Check if current system is: Windows 11 64-bit, build 10.0.22621.1105
        bool envCheck();

    } // namespace env

} // namespace CVE_2021_1732
