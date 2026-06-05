#include "include/utils/gadget.hpp"


namespace Debug
{
    void HexDump(const void* data, size_t size)
    {
        const unsigned char* p = static_cast<const unsigned char*>(data);

        for (size_t i = 0; i < size; i += 16)
        {
            //
            // offset
            //
            std::cout << std::setw(8)
                << std::setfill('0')
                << std::hex
                << i
                << "  ";

            //
            // hex bytes
            //
            for (size_t j = 0; j < 16; ++j)
            {
                if (i + j < size)
                {
                    std::cout << std::setw(2)
                        << static_cast<int>(p[i + j])
                        << " ";
                }
                else
                {
                    std::cout << "   ";
                }
            }

            std::cout << " ";

            //
            // ascii
            //
            for (size_t j = 0; j < 16 && i + j < size; ++j)
            {
                unsigned char c = p[i + j];

                if (std::isprint(c))
                    std::cout << c;
                else
                    std::cout << ".";
            }

            std::cout << std::endl;
        }
    }
} // namespace Debug