#pragma once
#include <iostream>
#include <iomanip>
#include <cctype>

namespace Debug
{
    void HexDump(const void* data, size_t size);
} // namespace Debug