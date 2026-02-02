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

_main
({
    cout << OBFUSCATE_STRING("hello world from Obfusk8").c_str();
})