#include "../Instrumentation/materialization/state/Obfusk8Core.hpp"
#include "../Instrumentation/materialization/transform/K8_UTILS/k8_utils.hpp"
#include <iostream>

using namespace std;

/*

to hide the main use :
    _main({})

to Obfuscate STRINGS use :
    OBFUSCATE_STRING

to Obfuscate methods use :
    OBF_METHOD_
    put firstly the return type of the method
    then the name of the method
    then the parameters
    then the body of ur parameter

*/

class Obfusk8_C
{
public:

    void PrintStatus(void)
    {
        printf_("method\n");
    }

    OBF_METHOD_(void, Obfusk8_PrintStatus, (void),
    {
        printf_("same method but Obfuscated\n");
    })
};

_main
({
    Obfusk8_C * pp = new Obfusk8_C;
    pp->PrintStatus();
    pp->Obfusk8_PrintStatus();
    delete pp;
 })