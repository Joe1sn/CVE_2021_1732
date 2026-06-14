#pragma once
#define WIN32_LEAN_AND_MEAN
#include "include/core/def.hpp"
#include "include/utils/gadget.hpp"
#include "include/describe/vuln_description.hpp"

#include <vector>

namespace CVE_2021_1732
{
    LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
    bool PoC();
    NTSTATUS MyxxxClientAllocWindowClassExtraBytes(unsigned int* pSize);
} // namespace CVE_2021_1732
