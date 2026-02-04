#include "../K8_UTILS/k8_utils.hpp"
#include "../../state/Obfusk8Core.hpp"

NOOPT
    #define OBF_METHOD_(ret_type, func_name, params, method_body) \
        ret_type func_name params { \
            OBF_BOGUS_FLOW_CYCLONE(); \
            if (OBF_OPAQUE_PREDICATE_TRUE_1() || !OBF_OPAQUE_PREDICATE_TRUE_1())\
                OBF_BOGUS_FLOW_LABYRINTH();\
            OBF_BOGUS_FLOW_SCRAMBLE(); \
            \
            uintptr_t entropy = (uintptr_t)this; \
            volatile unsigned int _d_seed = OBF_MBA_ADD((int)std::time(nullptr) ^ (int)entropy, _obf_global_opaque_seed ^ __COUNTER__); \
            _obf_global_opaque_seed = _d_seed; \
            \
            OBF_FAKE_PROLOGUE_MANIP(); \
            obf_vm_engine::VMState vm_s(_obf_global_opaque_seed); \
            constexpr size_t VM_BYTECODE_LEN = 30; \
            std::array<unsigned int, VM_BYTECODE_LEN> _obf_vm_bytecode; \
            \
            vm_s.r0 = (unsigned int)_obf_global_opaque_seed ^ (0x1337339 + __LINE__); \
            vm_s.r1 = (unsigned int)(__TIME__[0] << 8) ^ __COUNTER__; \
            vm_s.r2 = (unsigned int)entropy ^ (0xBADF00DU + (unsigned int)__TIME__[2]); \
            vm_s.dispatch_key = OBF_MBA_ADD((unsigned int)entropy, (unsigned int)__COUNTER__); \
            vm_s.pc = ((unsigned int)__TIME__[4] ^ (unsigned int)_obf_global_opaque_seed) % VM_BYTECODE_LEN; \
            \
            HANDLER_TABLE_MUTATE(obf_vm_engine::vm_handler_table, obf_vm_engine::VM_HANDLER_TABLE_SIZE, vm_s); \
            obf_vm_engine::dsptch(vm_s, 0, nullptr, (5 + (vm_s.pc % 5))); \
            \
            method_body \
            \
            OBF_BOGUS_FLOW_WEAVER(); \
        }
OPT