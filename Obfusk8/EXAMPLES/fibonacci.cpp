#include "../Instrumentation/materialization/state/Obfusk8Core.hpp"
#include <cstdio>
#include <iostream>

using namespace std;

/*

to hide the main use :
    _main({})

to Obfuscate STRINGS use :
    OBFUSCATE_STRING
*/

// https://www.geeksforgeeks.org/dsa/program-for-nth-fibonacci-number/
int fib(size_t n)
{
    OBF_BOGUS_FLOW_LABYRINTH();
    if (n <= 1) {
        OBF_BOGUS_FLOW_WEAVER();
        return n;
    }
    OBF_BOGUS_FLOW_GRID();
    return (fib(n - 1) + fib(n - 2));
}

_main
({
    cout << OBFUSCATE_STRING("fib : ").c_str() << fib(8);
})




