#include <iostream>
// #include "include/utils/environment.hpp"
#include "include/core/poc.hpp"
#include "include/core/exp.hpp"
// #include "include/common/memtools.hpp"
using namespace CVE_2021_1732;
int main()
{
    CVE_2021_1732::PoC();
    // CVE_2021_1732::Exp();
    // std::cout << CVE_2021_1732::CheckSeDebugPrivilege() << std::endl;

    return 0;
}
