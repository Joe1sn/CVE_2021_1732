#pragma once
#include <iostream>

namespace CVE_2021_1732
{
    // basic vulnerable infomation
    inline const char* name = "CVE-2021-1732";

    inline const char* mslink = "https://msrc.microsoft.com/update-guide/zh-CN/vulnerability/CVE-2021-1732";
    inline constexpr unsigned int osVersionSize = 4;
    static_assert(osVersionSize == 4, "osVersionSize must be 4");

    inline const unsigned int osVersion[4] = { 10, 0, 17763, 737 };   //必须为4
    static_assert(sizeof(osVersion) == 4 * sizeof(unsigned int), "osVersion must have exactly 4 elements");

} // namespace CVE_2021_1732
