#pragma once

#include <array>
#include <string>
#include <ctime>
#include <cstdint>
#include <random>
#include <type_traits>
#include "../transform/K8_UTILS/k8_utils.hpp"

NOOPT
    #pragma region AES
    // --------------------------------------
    
        #include "../transform/AES8.hpp"

    // --------------------------------------
    #pragma endregion AES
    
    #pragma region API_OBF
    // --------------------------------------
    
        #include "../transform/Resolve8.hpp"
    
        #define STEALTH_API_OBFSTR(dll_lit, api_lit) \
                StealthResolver::GetProcAddressH( \
                    StealthResolver::GetModuleHandleH(runtime_hash_aes(OBFUSCATE_STRING(dll_lit).c_str())), \
                    runtime_hash_aes(OBFUSCATE_STRING(api_lit).c_str()) \
                )
    
    // --------------------------------------
    #pragma endregion API_OBF

    #pragma region IND_SYS
    // --------------------------------------

        #include "../transform/k8_indsys.hpp"

        #define K8_SYSCALL(name, ...) \
            idrct_sys::GetGate().Invoke(OBFUSCATE_STRING(name).c_str(), __VA_ARGS__)

    // --------------------------------------
    #pragma endregion IND_SYS

    #pragma region ProcMAN
    // --------------------------------------
    
        #include "../../../k8_ProcessManipulationAPIs/k8_ProcessManipulationAPIs.hpp"
        using namespace K8_ProcessManipulationAPIs;
    
    // --------------------------------------
    #pragma endregion ProcMAN
    
    #pragma region Crypt
    // --------------------------------------
    
        #include "../../../k8_CryptographyAPIs/k8_CryptographyAPIs.hpp"
        using namespace k8_CryptographyAPIs;
    
    // --------------------------------------
    #pragma endregion Crypt
    
    #pragma region NET
    // --------------------------------------
    
        #include "../../../k8_NetworkingAPIs/k8_NetworkingAPIs.hpp"
        using namespace k8_NetworkingAPIs;
    
    // --------------------------------------
    #pragma endregion NET
    
    #pragma region Reg
    // --------------------------------------
    
        #include "../../../k8_RegistryAPIs/k8_RegistryAPIs.hpp"
        using namespace RegistryAPIs;
    
    // --------------------------------------
    #pragma endregion Reg
    
    #pragma region dec
    // --------------------------------------
    
        #if defined(_MSC_VER)
        #include <intrin.h>
        #endif
    
        inline volatile int _obf_global_opaque_seed = 777 + (int)__TIME__[1] + (int)__TIME__[2];
    
    
        #define NOP() \
            do { \
                volatile int __obf_nop_val = __COUNTER__ ^ (int)__LINE__; \
                _obf_global_opaque_seed = (_obf_global_opaque_seed ^ __obf_nop_val ^ (int)std::time(nullptr)); \
                (void)__obf_nop_val; \
            } while(0)
    
        #if defined(_MSC_VER)
            #define K8_ASSUME(x) __assume(x)
        #else
            #define K8_ASSUME(x) ((void)0)
        #endif
    
        #if defined(_MSC_VER)
            #define K8_FORCEINLINE __forceinline
            #define K8_NOINLINE __declspec(noinline)
        #else
            #define K8_FORCEINLINE inline
            #define K8_NOINLINE
        #endif
    
    // --------------------------------------
    #pragma region dec
    
    #pragma region _Opaque_Predicate
    // --------------------------------------
    
        // --- Opaque predicates for flattening ---
        //
        //
        /*
            #define OBF_OPAQUE_PREDICATE_TRUE_1()  ((~0u >> 1) > 0 && (((__COUNTER__ + _obf_global_opaque_seed)) % 2 == ((__COUNTER__ + _obf_global_opaque_seed)) % 2))
            #define OBF_OPAQUE_PREDICATE_TRUE_2(x) (((unsigned int)(x) ^ (0x49382668U + __COUNTER__ + (unsigned int)_obf_global_opaque_seed)) != (0xDEADBEEFU + __LINE__))
            #define OBF_OPAQUE_PREDICATE_FALSE_1() (0 && (((__COUNTER__ + _obf_global_opaque_seed)) % 2 != ((__COUNTER__ + _obf_global_opaque_seed)) % 2))
            #define OBF_OPAQUE_PREDICATE_FALSE_2(x) (((unsigned int)(x) == ((unsigned int)(x)+1U)) && ((unsigned int)(x) != ((unsigned int)(x)+1U)))
        */
        //
        //
        #ifndef _obf_global_opaque_seed
        extern volatile int _obf_global_opaque_seed;
        #endif
    
        #define OBF_OPAQUE_PREDICATE_TRUE_1() \
            ( \
                ( \
                    ( ((~0u >> 1) > 0u) && \
                    (((unsigned int)(__COUNTER__) + (unsigned int)_obf_global_opaque_seed) % 2u == \
                    ((unsigned int)(__COUNTER__) + (unsigned int)_obf_global_opaque_seed) % 2u) && \
                    ((__LINE__ | (unsigned int)_obf_global_opaque_seed) >= 0u) \
                    ) \
                ) \
                && ( \
                    (((unsigned int)_obf_global_opaque_seed | 0xCAFEBABEu) ^ 0xCAFEBABEu) <= (unsigned int)_obf_global_opaque_seed \
                    || (((unsigned int)(__COUNTER__) ^ (unsigned int)(__LINE__)) & 1u) == (((unsigned int)(__COUNTER__) ^ (unsigned int)(__LINE__)) & 1u) \
                ) \
                && ( \
                    (((unsigned int)_obf_global_opaque_seed + 0x12345678u) ^ 0x87654321u) != (unsigned int)-1 \
                ) \
            )
    
        #define OBF_OPAQUE_PREDICATE_TRUE_2(x) \
            ( \
                ( \
                    (((unsigned int)(x) ^ (0x12345678u + (unsigned int)(__COUNTER__) + (unsigned int)_obf_global_opaque_seed)) != (0xDEADBEEFu + (unsigned int)(__LINE__))) \
                    || ((((unsigned int)(x) + (unsigned int)_obf_global_opaque_seed) & 0xFu) == (((unsigned int)_obf_global_opaque_seed) & 0xFu)) \
                ) \
                && ( \
                    (((unsigned int)(x) | 0xF00DFACEu) == ((unsigned int)(x) | 0xF00DFACEu)) && \
                    ((((unsigned int)(x) & 0xFFu) ^ ((unsigned int)_obf_global_opaque_seed & 0xFFu)) < 0x100u) \
                ) \
                && ( \
                    ((((unsigned int)(x) + (unsigned int)_obf_global_opaque_seed + __LINE__) & 1u) == (((unsigned int)(x) + (unsigned int)_obf_global_opaque_seed + __LINE__) % 2u)) \
                ) \
            )
    
        #define OBF_OPAQUE_PREDICATE_FALSE_1() \
            ( \
                0 && \
                ( \
                    ((((unsigned int)(__COUNTER__) + (unsigned int)_obf_global_opaque_seed) % 2u) != \
                    (((unsigned int)(__COUNTER__) + (unsigned int)_obf_global_opaque_seed) % 2u)) \
                    && (((unsigned int)(__LINE__) ^ (unsigned int)_obf_global_opaque_seed) == 0xDEADBEEF) \
                ) \
                && ( \
                    (((unsigned int)_obf_global_opaque_seed + 0xDEADu) == 0xBEEFu) \
                ) \
            )
    
        #define OBF_OPAQUE_PREDICATE_FALSE_2(x) \
            ( \
                ( \
                    (((unsigned int)(x) == ((unsigned int)(x) + 1u)) && ((unsigned int)(x) != ((unsigned int)(x) + 1u))) \
                    || (((unsigned int)(x) == ((unsigned int)(x) + 1u)) && ((unsigned int)_obf_global_opaque_seed == 0xDEADBEEF)) \
                ) \
                && ( \
                    (((unsigned int)(x) ^ 0xABADBABAu) == (((unsigned int)(x) ^ 0xABADBABAu) + 1u)) \
                ) \
                && ( \
                    ((((unsigned int)(x) + 0x1234u) | 0xFEDCu) == (((unsigned int)(x) + 0x1234u) | 0xFEDCu) - 1u) \
                ) \
            )
    
    // --------------------------------------
    #pragma endregion _Opaque_Predicate
    
    #pragma region MBA
    // --------------------------------------
    
        #define OBF_MBA_ADD(a, b) ( \
            ( ((unsigned int)(a) | (unsigned int)(b)) + ((unsigned int)(a) & (unsigned int)(b)) ) \
            - ( ((unsigned int)(a) ^ (unsigned int)(b)) ) \
            + ( ((unsigned int)(a) ^ (unsigned int)(b)) + 2U * ((unsigned int)(a) & (unsigned int)(b)) ) \
            - ( ((unsigned int)(a) | (unsigned int)(b)) - ((unsigned int)(a) & (unsigned int)(b)) ) \
            + ( ((unsigned int)(a) & ~(unsigned int)(b)) + ((unsigned int)(b) & ~(unsigned int)(a)) + 2U * ((unsigned int)(a) & (unsigned int)(b)) ) \
            ^ ( (((unsigned int)(a) | (unsigned int)(b))) - ((unsigned int)(a) & (unsigned int)(b)) ) \
            ^ ( (((unsigned int)(a)) | ((unsigned int)(b))) & ~(((unsigned int)(a)) & ((unsigned int)(b))) ) \
        )
    
        #define OBF_MBA_SUB(a, b) ( \
            ( ((unsigned int)(a)) + (~(unsigned int)(b)) + 1U ) \
            ^ ( ((unsigned int)(a)) ^ ((~(unsigned int)(b)) ^ 1U) ) \
            + ( ((unsigned int)(a) ^ ((unsigned int)(b) ^ 0xFFFFFFFFU)) + 2U * ((unsigned int)(a) & ((unsigned int)(b) ^ 0xFFFFFFFFU)) + 1U ) \
            - ( ((unsigned int)(a)) & (((unsigned int)(a)) - ((unsigned int)(b))) ) \
            + ( (((unsigned int)(a) | ~(unsigned int)(b))) - (~(unsigned int)(b)) ) \
            ^ ( (((unsigned int)(a)) | ((unsigned int)(b))) - ((unsigned int)(a) & (unsigned int)(b)) ) \
        )
    
        #define OBF_MBA_XOR(a, b) ( \
            ( (((unsigned int)(a)) & (~(unsigned int)(b))) | ((~(unsigned int)(a)) & ((unsigned int)(b))) ) \
            ^ ( ((unsigned int)(a) | (unsigned int)(b)) - ((unsigned int)(a) & (unsigned int)(b)) ) \
            ^ ( ~(~(unsigned int)(a) & ~(unsigned int)(b)) & ~( (unsigned int)(a) & (unsigned int)(b) ) ) \
            ^ ( (((unsigned int)(a)) | ((unsigned int)(b))) & (~((unsigned int)(a)) | ~(unsigned int)(b)) ) \
            + ( ((unsigned int)(a) + (unsigned int)(b)) - 2 * ((unsigned int)(a) & (unsigned int)(b)) ) \
        )
    
        #define OBF_MBA_NOT(a) ( \
            ( ((unsigned int)(a)) ^ 0xFFFFFFFFU ) \
            ^ ( ~((unsigned int)(a)) ) \
            + ( (0U - 1U) ^ ((unsigned int)(a)) ) \
            - ( 2 * (~((unsigned int)(a)) & ((unsigned int)(a))) ) \
            + ( 0xFFFFFFFFU - ((unsigned int)(a)) ) \
            ^ ( ~((unsigned int)(a)) | 0U ) \
        )
    
        #define OBF_MBA_MUL_CONST3(x) ( \
            ( (((unsigned int)(x)) << 1) + ((unsigned int)(x)) ) \
            ^ ( ((unsigned int)(x) << 2) - ((unsigned int)(x)) ) \
            + ( ((unsigned int)(x)) + ((unsigned int)(x)) + ((unsigned int)(x)) ) \
            - ( ((unsigned int)(x)) & (~( ((unsigned int)(x)) << 1 )) ) \
            + ( (((unsigned int)(x)) | ((unsigned int)(x)) << 1 ) - ( ((unsigned int)(x)) & ((unsigned int)(x)) << 1 ) ) \
        )
    
        #define OBF_MBA_MUL_CONST_ALT(x, c) ( \
            ( ((unsigned int)(x)) << (c) ) - ((unsigned int)(x)) \
            ^ ( ((unsigned int)(x)) * ((1U << (c)) - 1U) ) \
            + ( ( ( ((unsigned int)(x)) << (c) ) ^ ((unsigned int)(x)) ) - ( ( ( ((unsigned int)(x)) << (c) ) & ((unsigned int)(x)) ) << 1 ) ) \
            + ( (((unsigned int)(x)) << (c)) | ((unsigned int)(x)) ) - ( ((unsigned int)(x)) & ((unsigned int)(x)) << (c) ) \
        )
    
    // --------------------------------------
    #pragma endregion MBA
    
    #pragma region JUNK
    // --------------------------------------
    
        #ifndef _obf_global_opaque_seed
        extern volatile int _obf_global_opaque_seed;
        #endif
        // need more dev...
        #define OBF_JUNK_BODY_1 \
            volatile int x_jb = __COUNTER__ + 11 + _obf_global_opaque_seed; \
            x_jb ^= (0xDEADBEEFU + (int)__TIME__[0]); \
            x_jb += (int)std::time(nullptr); \
            return x_jb;
        #define OBF_JUNK_BODY_2 \
            volatile int x_jb = (__COUNTER__ * 3) ^ (_obf_global_opaque_seed); \
            for(int i_jb=0; i_jb<((__COUNTER__%2)+2); ++i_jb) x_jb ^= i_jb; \
            return x_jb;
        #define OBF_JUNK_BODY_3 \
            volatile int x_jb = (0x1234 | (99 + __COUNTER__)) ^ _obf_global_opaque_seed; \
            x_jb &= (0xFFFFU + (int)__TIME__[1]); \
            x_jb ^= (x_jb << (((__COUNTER__)%3)+1)%32); \
            return x_jb;
        #define OBF_JUNK_BODY_4 \
            volatile int x_jb4 = __COUNTER__ ^ _obf_global_opaque_seed, y_jb4 = 7 + (__COUNTER__ % 5); \
            x_jb4 += y_jb4 * y_jb4; \
            x_jb4 ^= y_jb4; \
            x_jb4 = (x_jb4 << 1) | (x_jb4 >> 31); \
            return x_jb4;
        #define OBF_JUNK_BODY_5 \
            volatile int x_jb5 = (((int)std::time(nullptr) ^ _obf_global_opaque_seed + __COUNTER__) % 7); \
            if (x_jb5 == 0) x_jb5 = 1; \
            x_jb5 = (x_jb5 * 13) + 71; \
            return x_jb5;
        #define OBF_JUNK_BODY_6 \
            volatile int x_jb = (int)std::time(nullptr) ^ (_obf_global_opaque_seed * __COUNTER__); \
            int z = ((x_jb & 0xFF) * 0x1F1F1F1F) ^ (__COUNTER__ + _obf_global_opaque_seed); \
            x_jb = z ^ (x_jb << 2); \
            x_jb ^= ((int)__TIME__[2] | (int)__TIME__[3]); \
            return x_jb;
        #define OBF_JUNK_BODY_7 \
            volatile int x_jb = ((int)std::time(nullptr) + _obf_global_opaque_seed + __COUNTER__) ^ 0x0F0F0F0F; \
            x_jb = ((x_jb << 3) | (x_jb >> 29)) ^ (int)__LINE__; \
            return x_jb;
    
        #define OBF_DECLARE_JUNK_FUNC(N, body) K8_FORCEINLINE static int obf_junk_func_##N() { body }
    
        namespace obf_junk_ns {
            OBF_DECLARE_JUNK_FUNC(1, OBF_JUNK_BODY_1) 
            OBF_DECLARE_JUNK_FUNC(2, OBF_JUNK_BODY_2)
            OBF_DECLARE_JUNK_FUNC(3, OBF_JUNK_BODY_3)
            OBF_DECLARE_JUNK_FUNC(4, OBF_JUNK_BODY_4)
            OBF_DECLARE_JUNK_FUNC(5, OBF_JUNK_BODY_5)
            OBF_DECLARE_JUNK_FUNC(6, OBF_JUNK_BODY_6)
            OBF_DECLARE_JUNK_FUNC(7, OBF_JUNK_BODY_7)
            OBF_DECLARE_JUNK_FUNC(8, OBF_JUNK_BODY_1)
            OBF_DECLARE_JUNK_FUNC(9, OBF_JUNK_BODY_2)
            OBF_DECLARE_JUNK_FUNC(10, OBF_JUNK_BODY_3)
            OBF_DECLARE_JUNK_FUNC(11, OBF_JUNK_BODY_4)
            OBF_DECLARE_JUNK_FUNC(12, OBF_JUNK_BODY_5)
            OBF_DECLARE_JUNK_FUNC(13, OBF_JUNK_BODY_6)
            OBF_DECLARE_JUNK_FUNC(14, OBF_JUNK_BODY_7)
            OBF_DECLARE_JUNK_FUNC(15, OBF_JUNK_BODY_1)
            OBF_DECLARE_JUNK_FUNC(16, OBF_JUNK_BODY_2)
            OBF_DECLARE_JUNK_FUNC(17, OBF_JUNK_BODY_3)
            OBF_DECLARE_JUNK_FUNC(18, OBF_JUNK_BODY_4)
            OBF_DECLARE_JUNK_FUNC(19, OBF_JUNK_BODY_5)
            OBF_DECLARE_JUNK_FUNC(20, OBF_JUNK_BODY_6)
            OBF_DECLARE_JUNK_FUNC(21, OBF_JUNK_BODY_7)
            OBF_DECLARE_JUNK_FUNC(22, OBF_JUNK_BODY_1)
            OBF_DECLARE_JUNK_FUNC(23, OBF_JUNK_BODY_2)
            OBF_DECLARE_JUNK_FUNC(24, OBF_JUNK_BODY_3)
            OBF_DECLARE_JUNK_FUNC(25, OBF_JUNK_BODY_4)
            OBF_DECLARE_JUNK_FUNC(26, OBF_JUNK_BODY_5)
            OBF_DECLARE_JUNK_FUNC(27, OBF_JUNK_BODY_6)
            OBF_DECLARE_JUNK_FUNC(28, OBF_JUNK_BODY_7)
    
            using obf_junk_func_ptr = int(*)();
            static obf_junk_func_ptr obf_junk_func_table[] = {
                obf_junk_func_1, obf_junk_func_2, obf_junk_func_3, obf_junk_func_4, obf_junk_func_5, obf_junk_func_6, obf_junk_func_7,
                obf_junk_func_8, obf_junk_func_9, obf_junk_func_10, obf_junk_func_11, obf_junk_func_12, obf_junk_func_13, obf_junk_func_14,
                obf_junk_func_15, obf_junk_func_16, obf_junk_func_17, obf_junk_func_18, obf_junk_func_19, obf_junk_func_20, obf_junk_func_21,
                obf_junk_func_22, obf_junk_func_23, obf_junk_func_24, obf_junk_func_25, obf_junk_func_26, obf_junk_func_27, obf_junk_func_28
            };
            constexpr size_t obf_junk_func_table_size = sizeof(obf_junk_func_table)/sizeof(obf_junk_func_ptr);
        }
    
        #define OBF_CALL_ANY_LOCAL_JUNK() \
            (obf_junk_ns::obf_junk_func_table[ \
                ((_obf_global_opaque_seed ^ __COUNTER__ ^ (int)std::time(nullptr) ^ (int)__LINE__) & 0x7FFFFFFF) % obf_junk_ns::obf_junk_func_table_size \
            ]())
    
    // --------------------------------------
    #pragma endregion JUNK
    
    #pragma region OBF_JUMPS
    // --------------------------------------
    
        // --- Anti-Disassembly Jump Instructions ---
        // --- Jump Instructions with the Same Target ---
        // These will always jump to TARGET_LABEL, but through obfuscated means
        #define OBF_JUMP_SKEW_1(TARGET_LABEL) \
            do { \
                NOP(); \
                if (OBF_OPAQUE_PREDICATE_TRUE_1()) { \
                    _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed, (int)__LINE__ + OBF_CALL_ANY_LOCAL_JUNK()); \
                    goto TARGET_LABEL; \
                } \
                K8_ASSUME(0); \
            } while(0)
    
        #define OBF_JUMP_SKEW_2(TARGET_LABEL) \
            do { \
                volatile unsigned int _skew_val = OBF_MBA_ADD((unsigned int)__COUNTER__, (unsigned int)_obf_global_opaque_seed); \
                _skew_val = OBF_MBA_XOR(_skew_val, (unsigned int)OBF_CALL_ANY_LOCAL_JUNK()); \
                if (OBF_OPAQUE_PREDICATE_TRUE_2(_skew_val)) { \
                    NOP(); \
                    goto TARGET_LABEL; \
                } \
                K8_ASSUME(0); \
            } while(0)
    
        #define OBF_JUMP_SKEW_3(TARGET_LABEL) \
            do { \
                OBF_CALL_ANY_LOCAL_JUNK(); \
                _obf_global_opaque_seed = OBF_MBA_SUB(_obf_global_opaque_seed, (int)__TIME__[0] ^ (int)__COUNTER__); \
                if (((_obf_global_opaque_seed ^ (int)__LINE__) | 1) != 0) { \
                    goto TARGET_LABEL; \
                } \
                K8_ASSUME(0); \
            } while(0)
    
        #define OBF_JUMP_SKEW_4(TARGET_LABEL) \
            do { \
                volatile int _s4_decoy = OBF_MBA_MUL_CONST3(_obf_global_opaque_seed ^ (int)__LINE__); \
                _s4_decoy += OBF_CALL_ANY_LOCAL_JUNK(); \
                if (OBF_OPAQUE_PREDICATE_TRUE_1() && (_s4_decoy != _s4_decoy + 1)) { \
                    NOP(); \
                    goto TARGET_LABEL; \
                } \
                K8_ASSUME(0); \
            } while(0)
    
        #define OBF_JUMP_SKEW_5(TARGET_LABEL) \
            do { \
                _obf_global_opaque_seed = OBF_MBA_NOT(_obf_global_opaque_seed ^ (int)OBF_CALL_ANY_LOCAL_JUNK()); \
                unsigned int val_a = (unsigned int)__LINE__ ^ (unsigned int)_obf_global_opaque_seed; \
                unsigned int val_b = OBF_MBA_XOR(val_a, 0U); \
                if (OBF_MBA_ADD(val_a, OBF_MBA_NOT(val_b)) == 0xFFFFFFFFU) { \
                    goto TARGET_LABEL; \
                } \
                K8_ASSUME(0); \
            } while(0)
    
        #define OBF_JUMP_SKEW_6(TARGET_LABEL) \
            do { \
                NOP(); NOP(); \
                if (OBF_OPAQUE_PREDICATE_TRUE_2((unsigned int)OBF_CALL_ANY_LOCAL_JUNK() ^ (unsigned int)_obf_global_opaque_seed)) { \
                     _obf_global_opaque_seed = OBF_MBA_ADD(_obf_global_opaque_seed, (int)__COUNTER__); \
                     goto TARGET_LABEL; \
                } \
                K8_ASSUME(0); \
            } while(0)
    
        #define OBF_JUMP_SKEW_7(TARGET_LABEL) \
            do { \
                volatile int _s7_temp1 = OBF_CALL_ANY_LOCAL_JUNK(); \
                volatile int _s7_temp2 = OBF_CALL_ANY_LOCAL_JUNK(); \
                _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed, _s7_temp1 ^ _s7_temp2 ^ (int)__LINE__); \
                if (OBF_OPAQUE_PREDICATE_TRUE_1() || OBF_OPAQUE_PREDICATE_FALSE_1()) { \
                    goto TARGET_LABEL; \
                } \
                K8_ASSUME(0); \
            } while(0)
    
        #define OBF_JUMP_SKEW_8(TARGET_LABEL) \
            do { \
                unsigned int _s8_v = (unsigned int)_obf_global_opaque_seed + (unsigned int)__COUNTER__; \
                if (OBF_MBA_XOR(_s8_v, OBF_MBA_XOR(_s8_v, 0U)) == 0U) { \
                    _obf_global_opaque_seed = OBF_MBA_ADD(_obf_global_opaque_seed, OBF_CALL_ANY_LOCAL_JUNK()); \
                    goto TARGET_LABEL; \
                } \
                K8_ASSUME(0); \
            } while(0)
    
        #define OBF_JUMP_SKEW_9(TARGET_LABEL) \
            do { \
                int junk_res = OBF_CALL_ANY_LOCAL_JUNK(); \
                if (OBF_OPAQUE_PREDICATE_TRUE_2((unsigned int)junk_res)) { \
                    _obf_global_opaque_seed = OBF_MBA_SUB(_obf_global_opaque_seed, junk_res ^ (int)__TIME__[1]); \
                    NOP(); \
                    goto TARGET_LABEL; \
                } \
                K8_ASSUME(0); \
            } while(0)
    
        #define OBF_JUMP_SKEW_10(TARGET_LABEL) \
            do { \
                if (!OBF_OPAQUE_PREDICATE_FALSE_1()) { \
                    _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed, (int)OBF_CALL_ANY_LOCAL_JUNK() + (int)__LINE__); \
                    goto TARGET_LABEL; \
                } \
                K8_ASSUME(0); \
            } while(0)
    
    
    
        // --- Jump Instructions with a Constant Condition ---
        // These will use opaque predicates to determine if the jump to TARGET_LABEL occurs
        // FALLTHROUGH_CODE_BLOCK will be executed if the jump is NOT taken (predicate is false).
        #define OBF_JUMP_CONST_COND_TRUE_1(TARGET_LABEL, FALLTHROUGH_CODE_BLOCK) \
            do { \
                volatile int _cc_val1 = OBF_MBA_ADD(__COUNTER__, _obf_global_opaque_seed); \
                if (OBF_OPAQUE_PREDICATE_TRUE_1()) { \
                    _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed, _cc_val1 ^ (int)__LINE__); \
                    OBF_CALL_ANY_LOCAL_JUNK(); \
                    goto TARGET_LABEL; \
                } else { \
                    K8_ASSUME(0);  \
                    FALLTHROUGH_CODE_BLOCK \
                } \
            } while(0)
    
        #define OBF_JUMP_CONST_COND_FALSE_1(TARGET_LABEL, FALLTHROUGH_CODE_BLOCK) \
            do { \
                volatile int _cc_val2 = OBF_MBA_SUB(__COUNTER__, _obf_global_opaque_seed); \
                if (OBF_OPAQUE_PREDICATE_FALSE_1()) { \
                     \
                    _obf_global_opaque_seed = OBF_MBA_ADD(_obf_global_opaque_seed, _cc_val2 ^ (int)__LINE__ ^ OBF_CALL_ANY_LOCAL_JUNK()); \
                    goto TARGET_LABEL; \
                } else { \
                     \
                    FALLTHROUGH_CODE_BLOCK \
                } \
                NOP(); \
            } while(0)
    
        #define OBF_JUMP_CONST_COND_TRUE_2(TARGET_LABEL, FALLTHROUGH_CODE_BLOCK) \
            do { \
                unsigned int _cc_val3 = (unsigned int)OBF_CALL_ANY_LOCAL_JUNK() ^ (unsigned int)__TIME__[2]; \
                if (OBF_OPAQUE_PREDICATE_TRUE_2(_cc_val3)) { \
                    _obf_global_opaque_seed = OBF_MBA_MUL_CONST3(_obf_global_opaque_seed ^ (int)_cc_val3); \
                    goto TARGET_LABEL; \
                } else { \
                    K8_ASSUME(0); \
                    FALLTHROUGH_CODE_BLOCK \
                } \
            } while(0)
    
        #define OBF_JUMP_CONST_COND_FALSE_2(TARGET_LABEL, FALLTHROUGH_CODE_BLOCK) \
            do { \
                unsigned int _cc_val4 = (unsigned int)_obf_global_opaque_seed + (unsigned int)__COUNTER__; \
                if (OBF_OPAQUE_PREDICATE_FALSE_2(_cc_val4)) { \
                    _obf_global_opaque_seed = OBF_MBA_NOT(_obf_global_opaque_seed + (int)_cc_val4); \
                    OBF_CALL_ANY_LOCAL_JUNK(); \
                    goto TARGET_LABEL; \
                } else { \
                    FALLTHROUGH_CODE_BLOCK \
                } \
                _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed, (int)_cc_val4); \
            } while(0)
    
        #define OBF_JUMP_MERGED_COND_SKEW_TRUE(TARGET_LABEL, FALLTHROUGH_CODE_BLOCK) \
            do { \
                if (OBF_OPAQUE_PREDICATE_TRUE_1()) { \
                    OBF_JUMP_SKEW_1(TARGET_LABEL); \
                } else { \
                    K8_ASSUME(0); \
                    FALLTHROUGH_CODE_BLOCK \
                } \
            } while(0)
    
    // --------------------------------------
    #pragma endregion OBF_JUMPS
    
    #pragma region OBF_STATE_TRANSITIONS
    // --------------------------------------
    
        namespace obf_dispatch_helpers
        {
                                enum class DispatchBlockID 
                                {
                                    INITIALIZE_DISPATCH_LOOP, CHECK_MAIN_LOOP_CONDITION,
                                    DETERMINE_AND_EXECUTE_HANDLER, MAYBE_CALL_EXTRA_JUNK,
                                    EXECUTE_EXTRA_JUNK, DETERMINE_PC_UPDATE_PATH,
                                    EXECUTE_PC_UPDATE_PATH_A, EXECUTE_PC_UPDATE_PATH_B,
                                    INCREMENT_MAIN_LOOP_COUNTER, EXIT_DISPATCH_LOOP,
                                    DEAD_CODE_TARGET_BLOCK
                                };
        }
    
        // --- Anti-Disassembly State Transition ---
        // Shared next_state_var_name will be passed to these.
        // Example: OBF_SET_NEXT_STATE_SKEW_1(DispatchBlockID::SOME_TARGET, local_next_state_var);
    
        // --- Unconditional State Transitions ---
        // These will always set next_state_var_name to TARGET_BLOCK_ID
        #define OBF_SET_NEXT_STATE_SKEW_1(TARGET_BLOCK_ID, next_state_var_name) \
            do { \
                NOP(); \
                if (OBF_OPAQUE_PREDICATE_TRUE_1()) { \
                    _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed, (int)__LINE__ + OBF_CALL_ANY_LOCAL_JUNK()); \
                    (next_state_var_name) = (TARGET_BLOCK_ID); \
                } else { \
                    K8_ASSUME(0); \
                    (next_state_var_name) = obf_dispatch_helpers::DispatchBlockID::DEAD_CODE_TARGET_BLOCK; \
                } \
            } while(0)
    
        #define OBF_SET_NEXT_STATE_SKEW_2(TARGET_BLOCK_ID, next_state_var_name) \
            do { \
                volatile unsigned int _skew_val = OBF_MBA_ADD((unsigned int)__COUNTER__, (unsigned int)_obf_global_opaque_seed); \
                _skew_val = OBF_MBA_XOR(_skew_val, (unsigned int)OBF_CALL_ANY_LOCAL_JUNK()); \
                if (OBF_OPAQUE_PREDICATE_TRUE_2(_skew_val)) { \
                    NOP(); \
                    (next_state_var_name) = (TARGET_BLOCK_ID); \
                } else { \
                    K8_ASSUME(0); \
                    (next_state_var_name) = obf_dispatch_helpers::DispatchBlockID::DEAD_CODE_TARGET_BLOCK; \
                } \
            } while(0)
    
        #define OBF_SET_NEXT_STATE_SKEW_3(TARGET_BLOCK_ID, next_state_var_name) \
            do { \
                OBF_CALL_ANY_LOCAL_JUNK(); \
                _obf_global_opaque_seed = OBF_MBA_SUB(_obf_global_opaque_seed, (int)__TIME__[0] ^ (int)__COUNTER__); \
                if (((_obf_global_opaque_seed ^ (int)__LINE__) | 1) != 0) { \
                    (next_state_var_name) = (TARGET_BLOCK_ID); \
                } else { K8_ASSUME(0); (next_state_var_name) = obf_dispatch_helpers::DispatchBlockID::DEAD_CODE_TARGET_BLOCK; } \
            } while(0)
    
        #define OBF_SET_NEXT_STATE_SKEW_4(TARGET_BLOCK_ID, next_state_var_name) \
            do { \
                if (OBF_OPAQUE_PREDICATE_TRUE_1() && OBF_OPAQUE_PREDICATE_TRUE_2(0xCAFE)) { \
                    _obf_global_opaque_seed = OBF_MBA_ADD(_obf_global_opaque_seed, OBF_CALL_ANY_LOCAL_JUNK()); \
                    (next_state_var_name) = (TARGET_BLOCK_ID); \
                } else { K8_ASSUME(0); (next_state_var_name) = obf_dispatch_helpers::DispatchBlockID::DEAD_CODE_TARGET_BLOCK; } \
            } while(0)
    
        #define OBF_SET_NEXT_STATE_SKEW_5(TARGET_BLOCK_ID, next_state_var_name) \
            OBF_SET_NEXT_STATE_SKEW_1(TARGET_BLOCK_ID, next_state_var_name)
    
        #define OBF_SET_NEXT_STATE_SKEW_6(TARGET_BLOCK_ID, next_state_var_name) \
            OBF_SET_NEXT_STATE_SKEW_2(TARGET_BLOCK_ID, next_state_var_name)
    
        #define OBF_SET_NEXT_STATE_SKEW_7(TARGET_BLOCK_ID, next_state_var_name) \
            OBF_SET_NEXT_STATE_SKEW_3(TARGET_BLOCK_ID, next_state_var_name)
    
        #define OBF_SET_NEXT_STATE_SKEW_8(TARGET_BLOCK_ID, next_state_var_name) \
            OBF_SET_NEXT_STATE_SKEW_4(TARGET_BLOCK_ID, next_state_var_name)
    
        #define OBF_SET_NEXT_STATE_SKEW_9(TARGET_BLOCK_ID, next_state_var_name) \
            OBF_SET_NEXT_STATE_SKEW_1(TARGET_BLOCK_ID, next_state_var_name)
    
        #define OBF_SET_NEXT_STATE_SKEW_10(TARGET_BLOCK_ID, next_state_var_name) \
            OBF_SET_NEXT_STATE_SKEW_2(TARGET_BLOCK_ID, next_state_var_name)
    
    
        // --- Conditional State Transitions ---
        // These will use opaque predicates to determine if next_state_var_name is set to
        // TARGET_BLOCK_ID_IF_TRUE or TARGET_BLOCK_ID_IF_FALSE
        #define OBF_SET_NEXT_STATE_CONST_COND_TRUE_1(TARGET_BLOCK_ID_IF_TRUE, TARGET_BLOCK_ID_IF_FALSE, next_state_var_name) \
            do { \
                volatile int _cc_val1 = OBF_MBA_ADD(__COUNTER__, _obf_global_opaque_seed); \
                if (OBF_OPAQUE_PREDICATE_TRUE_1()) { \
                    _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed, _cc_val1 ^ (int)__LINE__); \
                    OBF_CALL_ANY_LOCAL_JUNK(); \
                    (next_state_var_name) = (TARGET_BLOCK_ID_IF_TRUE); \
                } else { \
                    K8_ASSUME(0); \
                    (next_state_var_name) = (TARGET_BLOCK_ID_IF_FALSE); \
                } \
            } while(0)
    
        #define OBF_SET_NEXT_STATE_CONST_COND_FALSE_1(TARGET_BLOCK_ID_IF_TRUE_PATH_IS_DEAD, TARGET_BLOCK_ID_IF_FALSE_PATH_IS_LIVE, next_state_var_name) \
            do { \
                volatile int _cc_val2 = OBF_MBA_SUB(__COUNTER__, _obf_global_opaque_seed); \
                if (OBF_OPAQUE_PREDICATE_FALSE_1()) { \
                    _obf_global_opaque_seed = OBF_MBA_ADD(_obf_global_opaque_seed, _cc_val2 ^ (int)__LINE__ ^ OBF_CALL_ANY_LOCAL_JUNK()); \
                    (next_state_var_name) = (TARGET_BLOCK_ID_IF_TRUE_PATH_IS_DEAD); \
                } else { \
                    (next_state_var_name) = (TARGET_BLOCK_ID_IF_FALSE_PATH_IS_LIVE); \
                } \
                NOP(); \
            } while(0)
    
        #define OBF_SET_NEXT_STATE_CONST_COND_TRUE_2(TARGET_BLOCK_ID_IF_TRUE, TARGET_BLOCK_ID_IF_FALSE, next_state_var_name) \
            OBF_SET_NEXT_STATE_CONST_COND_TRUE_1(TARGET_BLOCK_ID_IF_TRUE, TARGET_BLOCK_ID_IF_FALSE, next_state_var_name)
    
    
        #define OBF_SET_NEXT_STATE_CONST_COND_FALSE_2(TARGET_BLOCK_ID_IF_TRUE_PATH_IS_DEAD, TARGET_BLOCK_ID_IF_FALSE_PATH_IS_LIVE, next_state_var_name) \
            OBF_SET_NEXT_STATE_CONST_COND_FALSE_1(TARGET_BLOCK_ID_IF_TRUE_PATH_IS_DEAD, TARGET_BLOCK_ID_IF_FALSE_PATH_IS_LIVE, next_state_var_name)
    
        #define OBF_SET_NEXT_STATE_MERGED_COND_SKEW_TRUE(TARGET_BLOCK_ID_ULTIMATE_IF_TRUE, TARGET_BLOCK_ID_IF_OUTER_FALSE, next_state_var_name) \
            do { \
                if (OBF_OPAQUE_PREDICATE_TRUE_1()) { \
                    OBF_SET_NEXT_STATE_SKEW_1(TARGET_BLOCK_ID_ULTIMATE_IF_TRUE, next_state_var_name); \
                } else { \
                    K8_ASSUME(0); \
                    (next_state_var_name) = (TARGET_BLOCK_ID_IF_OUTER_FALSE); \
                } \
            } while(0)
    
    // --------------------------------------
    #pragma endregion OBF_STATE_TRANSITIONS
    
    #pragma region VM_ENGINE
    // --------------------------------------
            namespace obf_vm_engine {
    
                struct VMState {
                    volatile unsigned int r0, r1, r2;
                    volatile unsigned int pc;
                    volatile unsigned int dispatch_key;
                    volatile int& global_seed_ref;
    
                    VMState(volatile int& seed_ref_param)
                        : r0(0U), r1(0U), r2(0U), pc(0U), dispatch_key(0U), global_seed_ref(seed_ref_param) {}
                };
    
                using vm_handler_ptr_t = void (*)(VMState&, int, char**);
    
                #define VM_OPQ_TRUE()   (((((unsigned int)(__LINE__ ^ _obf_global_opaque_seed)) | 1u) & 1u) == 1u)
                #define VM_OPQ_FALSE()  ((((unsigned int)(__LINE__ ^ _obf_global_opaque_seed)) & 1u) == 0u && 0)
    
                K8_NOINLINE static void vm_handle_op_arith(VMState& s, int ac, char** av) {
                    NOP();
                    unsigned int tmp = OBF_MBA_XOR(s.r1, (unsigned int)(__LINE__));
                    tmp = OBF_MBA_ADD(tmp, s.global_seed_ref ^ s.pc);
                    s.r0 = OBF_MBA_ADD(s.r0, tmp);
                    s.r1 = OBF_MBA_SUB(s.r1, (s.r2 + (unsigned int)ac + (s.pc * 7U)) ^ OBF_CALL_ANY_LOCAL_JUNK());
                    s.r2 = OBF_MBA_XOR(s.r2, s.dispatch_key ^ (unsigned int)(av && ac > 0 && av[0] ? (std::uintptr_t)av[0] : __COUNTER__));
                    s.dispatch_key = OBF_MBA_ADD(s.dispatch_key, s.r0 ^ 0x1A2B3C4DU ^ s.r1);
                    s.pc = OBF_MBA_ADD(s.pc, 1U ^ (s.r2 & 1U));
                    s.global_seed_ref = OBF_MBA_XOR(s.global_seed_ref, (int)(s.r0 ^ s.r1 ^ s.pc));
                    if (VM_OPQ_TRUE() || VM_OPQ_FALSE()) { OBF_CALL_ANY_LOCAL_JUNK(); }
                }
    
                K8_NOINLINE static void vm_handle_op_bitwise_logic(VMState& s, int ac, char** av) {
                    NOP();
                    s.r0 = OBF_MBA_XOR((s.r0 & s.r1) | (OBF_MBA_NOT(s.r0) & s.r2), (s.r1 ^ s.r2));
                    s.r1 = (s.r1 << ((s.pc % 3) + 1)) | (s.r1 >> (32 - ((s.pc % 3) + 1)));
                    if (OBF_OPAQUE_PREDICATE_TRUE_1()) {
                        s.r2 = OBF_MBA_XOR(s.r2, 0xDEADBEEFU + (unsigned int)s.global_seed_ref);
                    } else {
                        s.r2 = OBF_MBA_ADD(s.r2, 0xCAFEFACU);
                    }
                    s.dispatch_key = OBF_MBA_SUB(s.dispatch_key, (s.r1 ^ 0x55AA55AAU) ^ s.r2);
                    s.pc = OBF_MBA_ADD(s.pc, ((s.r0 & 1U) ? 2U : 1U) + ((s.r1 & 1U) ? 1U : 0U));
                    s.global_seed_ref = OBF_MBA_ADD(s.global_seed_ref, (int)(s.r2 ^ s.dispatch_key ^ s.pc));
                    if (VM_OPQ_TRUE() || VM_OPQ_FALSE()) { OBF_CALL_ANY_LOCAL_JUNK(); }
                }
    
                K8_NOINLINE static void vm_handle_op_key_mangle(VMState& s, int ac, char** av) {
                    NOP();
                    unsigned int temp_key = s.dispatch_key ^ (unsigned int)__LINE__;
                    temp_key = OBF_MBA_MUL_CONST3(temp_key ^ (s.r0 | s.r1));
                    temp_key = OBF_MBA_ADD(temp_key, s.r0 ^ s.r1 ^ s.r2 ^ s.pc);
                    temp_key = (temp_key << ((s.global_seed_ref % 5) + 1)) | (temp_key >> (32 - ((s.global_seed_ref % 5) + 1)));
                    temp_key ^= (unsigned int)OBF_CALL_ANY_LOCAL_JUNK();
                    s.dispatch_key = temp_key;
                    s.r0 = OBF_MBA_XOR(s.r0, s.dispatch_key ^ s.r2);
                    s.pc = OBF_MBA_SUB(s.pc, (s.r1 & 7U) ? 1U : 3U);
                    s.global_seed_ref = OBF_MBA_XOR(s.global_seed_ref, (int)s.dispatch_key ^ s.r2);
                    if (VM_OPQ_TRUE() || VM_OPQ_FALSE()) { OBF_CALL_ANY_LOCAL_JUNK(); }
                }
    
                K8_NOINLINE static void vm_handle_op_junk_sequence(VMState& s, int ac, char** av) {
                    NOP();
                    s.r0 = OBF_MBA_ADD(s.r0, (unsigned int)OBF_CALL_ANY_LOCAL_JUNK() ^ s.r1);
                    s.r1 = OBF_MBA_XOR(s.r1, (unsigned int)OBF_CALL_ANY_LOCAL_JUNK() ^ s.r2 ^ (unsigned int)ac);
                    s.r2 = OBF_MBA_SUB(s.r2, (unsigned int)OBF_CALL_ANY_LOCAL_JUNK() ^ (unsigned int)(av && ac > 0 && av[0] ? av[0][0] : __LINE__));
                    s.dispatch_key = OBF_MBA_NOT(s.dispatch_key ^ s.r0 ^ s.r2);
                    s.pc = OBF_MBA_ADD(s.pc, 1U + (s.r2 & 3U));
                    s.global_seed_ref = OBF_MBA_XOR(s.global_seed_ref, (int)(s.r0 ^ s.r1 ^ s.r2 ^ s.pc));
                    if (VM_OPQ_TRUE() || VM_OPQ_FALSE()) { OBF_CALL_ANY_LOCAL_JUNK(); }
                    NOP();
                }
    
                K8_NOINLINE static void vm_handle_op_conditional_update(VMState& s, int ac, char** av) {
                    NOP();
                    if (OBF_OPAQUE_PREDICATE_TRUE_2(s.r0 ^ s.dispatch_key ^ (unsigned int)s.global_seed_ref)) {
                        s.r0 = OBF_MBA_ADD(s.r0, s.r1 ^ (s.pc | 0xA5A5U));
                        s.r1 = OBF_MBA_SUB(s.r1, s.r2 ^ (s.pc & 0x5A5AU));
                        s.dispatch_key = OBF_MBA_XOR(s.dispatch_key, (s.pc * 0x1001U) ^ s.r1);
                    } else {
                        s.r0 = OBF_MBA_XOR(s.r0, 0xBAD0BAD0U ^ s.r2);
                        s.r1 = OBF_MBA_NOT(s.r1 ^ s.r0);
                        s.dispatch_key = OBF_MBA_ADD(s.dispatch_key, 0xC001C001U ^ s.r0);
                    }
                    s.r2 = OBF_MBA_XOR(s.r2, (unsigned int)OBF_CALL_ANY_LOCAL_JUNK() ^ s.r0);
                    s.pc = OBF_MBA_ADD(s.pc, ((s.r1 & 1U) + 1U) ^ (s.r2 & 3U));
                    s.global_seed_ref = OBF_MBA_SUB(s.global_seed_ref, (int)(s.r0 + s.r1 + s.pc));
                    if (VM_OPQ_TRUE() || VM_OPQ_FALSE()) { OBF_CALL_ANY_LOCAL_JUNK(); }
                }
    
                K8_NOINLINE static void vm_handle_op_mem_sim(VMState& s, int ac, char** av) {
                    NOP();
                    static unsigned int obf_vm_memory[32];
                    unsigned int addr1 = (s.r0 ^ s.pc ^ s.dispatch_key) % 32;
                    unsigned int addr2 = (s.r1 ^ s.dispatch_key ^ s.r2) % 32;
                    if (OBF_OPAQUE_PREDICATE_TRUE_1()) { obf_vm_memory[addr1] = OBF_MBA_ADD(s.r2, s.dispatch_key ^ (s.r1 & 0xAA55U)); }
                    if (VM_OPQ_TRUE() || VM_OPQ_FALSE()) { obf_vm_memory[addr2] = OBF_MBA_XOR(s.r0, s.r1 ^ (unsigned int)OBF_CALL_ANY_LOCAL_JUNK()); }
                    s.r0 = OBF_MBA_XOR(s.r0, obf_vm_memory[addr2]);
                    s.r1 = OBF_MBA_ADD(s.r1, obf_vm_memory[addr1 % 8] ^ s.r2);
                    s.dispatch_key = OBF_MBA_SUB(s.dispatch_key, obf_vm_memory[(addr1 + addr2) % 32]);
                    s.pc = OBF_MBA_ADD(s.pc, 1U ^ (s.dispatch_key & 1U));
                    s.global_seed_ref = OBF_MBA_XOR(s.global_seed_ref, (int)obf_vm_memory[s.pc % 32]);
                    if (VM_OPQ_TRUE() || VM_OPQ_FALSE()) { OBF_CALL_ANY_LOCAL_JUNK(); }
                }
    
                K8_NOINLINE static void vm_handle_op_pc_mangle(VMState& s, int ac, char** av) {
                    NOP();
                    s.pc = OBF_MBA_XOR(s.pc, s.r0 ^ s.r1 ^ s.dispatch_key ^ s.r2);
                    s.pc = OBF_MBA_ADD(s.pc, (unsigned int)__LINE__ + (s.dispatch_key & 0x3F));
                    s.pc %= 256;
                    s.r0 = OBF_MBA_ADD(s.r0, s.pc ^ (s.r1 & 0xF0F0U));
                    s.dispatch_key = OBF_MBA_NOT(s.dispatch_key ^ s.pc);
                    s.global_seed_ref = OBF_MBA_ADD(s.global_seed_ref, (int)s.pc ^ (int)OBF_CALL_ANY_LOCAL_JUNK());
                    if (!OBF_OPAQUE_PREDICATE_FALSE_1()) { s.r1 = OBF_MBA_XOR(s.r1, (unsigned int)OBF_CALL_ANY_LOCAL_JUNK() ^ s.r2); }
                }
    
                K8_NOINLINE 
                static 
                void 
                vm_handle_op_multi_mba(VMState& s, 
                                       int ac, 
                                       char** av) 
                {
                    NOP();
                    s.r0 = OBF_MBA_ADD(OBF_MBA_XOR(s.r0, s.dispatch_key ^ s.pc), OBF_MBA_MUL_CONST3(s.r1 ^ s.r2));
                    s.r1 = OBF_MBA_SUB(OBF_MBA_NOT(s.r1 ^ s.r0), OBF_MBA_XOR(s.r2 ^ s.r0, s.pc));
                    s.r2 = OBF_MBA_ADD(OBF_MBA_MUL_CONST_ALT(s.r2, 3), OBF_MBA_SUB(s.r0, s.r1) ^ s.dispatch_key);
                    s.dispatch_key = OBF_MBA_XOR(s.dispatch_key, OBF_MBA_NOT(s.r0 ^ s.r1 ^ s.r2));
                    s.pc = OBF_MBA_ADD(s.pc, 1U + (s.r0 & 1U));
                    s.global_seed_ref = OBF_MBA_XOR(s.global_seed_ref, (int)OBF_CALL_ANY_LOCAL_JUNK() ^ (int)s.dispatch_key);
                    if (VM_OPQ_TRUE() || VM_OPQ_FALSE()) { OBF_CALL_ANY_LOCAL_JUNK(); }
                }
    
                K8_NOINLINE static void _obf_dummy_func_A_impl(VMState& s, int i) {
                    OBF_CALL_ANY_LOCAL_JUNK();
                    s.r0 = OBF_MBA_ADD(s.r0, (unsigned int)i ^ (unsigned int)OBF_CALL_ANY_LOCAL_JUNK() ^ (unsigned int)__LINE__);
                    _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed, (int)s.r0);
                }
    
                K8_NOINLINE static void _obf_dummy_func_B_impl(VMState& s, int i) {
                    OBF_CALL_ANY_LOCAL_JUNK();
                    s.r1 = OBF_MBA_XOR(s.r1, (unsigned int)i + (unsigned int)OBF_CALL_ANY_LOCAL_JUNK() + (unsigned int)__COUNTER__);
                    _obf_global_opaque_seed = OBF_MBA_ADD(_obf_global_opaque_seed, (int)s.r1);
                }
    
                K8_NOINLINE static void _obf_exit_path_norm_impl(VMState& s, int i) {
                    OBF_CALL_ANY_LOCAL_JUNK();
                    s.r2 = OBF_MBA_SUB(s.r2, (unsigned int)i ^ (unsigned int)OBF_CALL_ANY_LOCAL_JUNK() ^ (unsigned int)s.pc);
                    _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed, (int)s.r2 + i);
                }
    
                K8_NOINLINE static void _obf_exit_path_alt_impl(VMState& s, int i) {
                    OBF_CALL_ANY_LOCAL_JUNK();
                    s.dispatch_key = OBF_MBA_NOT(s.dispatch_key + (unsigned int)i + (unsigned int)OBF_CALL_ANY_LOCAL_JUNK());
                    _obf_global_opaque_seed = OBF_MBA_SUB(_obf_global_opaque_seed, (int)s.dispatch_key ^ i);
                }
    
    
                // Static functions SEH (C2712-safe versions)
                K8_NOINLINE static void _seh_wrapped_vm_register_modification(VMState& s, unsigned int val) {
                    #if defined(_MSC_VER)
                    __try {
                        if (((s.global_seed_ref ^ __COUNTER__) % 13) == 1 && OBF_OPAQUE_PREDICATE_TRUE_1()) {
                            volatile int* p_crash = nullptr; *p_crash = val;
                        }
                        s.r0 = OBF_MBA_ADD(s.r0, val ^ (unsigned int)__TIME__[0] ^ (unsigned int)OBF_CALL_ANY_LOCAL_JUNK());
                    } __except(EXCEPTION_EXECUTE_HANDLER) {
                        s.r0 = OBF_MBA_XOR(s.r0, 0xDEADBEEF ^ (unsigned int)GetExceptionCode() ^ (unsigned int)OBF_CALL_ANY_LOCAL_JUNK());
                        s.global_seed_ref = OBF_MBA_XOR(s.global_seed_ref, (int)GetExceptionCode());
                    }
                    #else
                    s.r0 = OBF_MBA_ADD(s.r0, val ^ (unsigned int)__TIME__[0] ^ (unsigned int)OBF_CALL_ANY_LOCAL_JUNK());
                    #endif
                    OBF_CALL_ANY_LOCAL_JUNK(); NOP();
                }
    
    
                K8_NOINLINE static void _seh_forced_exception_effect(VMState& s) {
                    #if defined(_MSC_VER)
                    __try {
                        if (OBF_OPAQUE_PREDICATE_TRUE_1()) {
                            volatile int* _seh_p_force = nullptr; *_seh_p_force = __LINE__ ^ OBF_CALL_ANY_LOCAL_JUNK();
                        } else { K8_ASSUME(0); }
                    } __except (EXCEPTION_EXECUTE_HANDLER) {
                        s.r1 = OBF_MBA_XOR(s.r1, 0xBADCAFE ^ (unsigned int)GetExceptionCode() ^ (unsigned int)OBF_CALL_ANY_LOCAL_JUNK());
                        s.global_seed_ref = OBF_MBA_XOR(s.global_seed_ref, (int)GetExceptionCode() ^ (int)s.pc);
                    }
                    #else
                    s.r1 = OBF_MBA_XOR(s.r1, 0xBADCAFE ^ (unsigned int)OBF_CALL_ANY_LOCAL_JUNK());
                    #endif
                    OBF_CALL_ANY_LOCAL_JUNK(); NOP();
                }
    
    
                static vm_handler_ptr_t handler_table_raw[8] = {
                    vm_handle_op_arith, vm_handle_op_bitwise_logic, vm_handle_op_key_mangle,
                    vm_handle_op_junk_sequence, vm_handle_op_conditional_update, vm_handle_op_mem_sim,
                    vm_handle_op_pc_mangle, vm_handle_op_multi_mba
                };
    
                constexpr size_t HANDLER_COUNT = sizeof(handler_table_raw)/sizeof(vm_handler_ptr_t);
    
                static vm_handler_ptr_t* get_mem_dispatch_table(VMState& s) {
                    static vm_handler_ptr_t scrambled[HANDLER_COUNT] = {};
                    static bool inited = false;
                    if (!inited) {
                        unsigned int k = (unsigned int)s.global_seed_ref ^ (unsigned int)std::time(nullptr);
                        for (size_t i = 0; i < HANDLER_COUNT; ++i) scrambled[i] = nullptr;
                        for (size_t i = 0; i < HANDLER_COUNT; ++i) {
                            size_t idx = (k + i*5 + (k>>3) + (i<<2)) % HANDLER_COUNT;
                            while (scrambled[idx]) idx = (idx+1)%HANDLER_COUNT;
                            scrambled[idx] = handler_table_raw[i];
                        }
                        inited = true;
                    }
                    return scrambled;
                }
    
                static 
                size_t 
                reg_dispatch_idx(const VMState& s) 
                {
                    unsigned int h = s.r0 ^ ((s.r1<<5)|(s.r1>>27)) ^ (s.r2*19U) ^ (s.pc*7U) ^ s.dispatch_key ^ (unsigned int)s.global_seed_ref;
                    h ^= (h >> 13) ^ (h << 17);
                    h *= 0x9e3779b1U;
                    return (h ^ (h>>11)) % HANDLER_COUNT;
                }
    
                static 
                size_t 
                mixed_dispatch_idx(VMState& s) 
                {
                    size_t idx = reg_dispatch_idx(s);
                    if (OBF_OPAQUE_PREDICATE_TRUE_1() && ((s.r0 ^ s.r1 ^ s.r2 ^ s.dispatch_key) & 1U)) {
                        idx = (idx + 3 + (s.pc & 2U)) % HANDLER_COUNT;
                    }
                    if (OBF_OPAQUE_PREDICATE_TRUE_2(s.global_seed_ref) && ((s.dispatch_key & 4U) == 0)) {
                        idx = (idx ^ 5U) % HANDLER_COUNT;
                    }
                    if (OBF_OPAQUE_PREDICATE_FALSE_1() || (s.r2 & 2U)) {
                        idx = (idx + HANDLER_COUNT - 1) % HANDLER_COUNT;
                    }
                    idx = (idx + ((unsigned int)OBF_CALL_ANY_LOCAL_JUNK() & 3U)) % HANDLER_COUNT;
                    return idx;
                }
    
                K8_NOINLINE
                static
                void
                dsptch(VMState& s,
                                 int argc,
                                 char** argv,
                                 unsigned int steps)
                {
                    using obf_dispatch_helpers::DispatchBlockID;
    
                    auto* mem_table = get_mem_dispatch_table(s);
                    unsigned int i = 0;
                    size_t idx = 0;
    
                    DispatchBlockID current_block_id = DispatchBlockID::INITIALIZE_DISPATCH_LOOP;
                    DispatchBlockID next_block_id_for_switch = DispatchBlockID::INITIALIZE_DISPATCH_LOOP;
                    bool machine_is_running = true;
    
                    while (machine_is_running) {
                        current_block_id = next_block_id_for_switch;
    
                        switch (current_block_id) {
                            case DispatchBlockID::INITIALIZE_DISPATCH_LOOP:
                                NOP();
                                _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed, __LINE__ ^ (int)i);
                                OBF_SET_NEXT_STATE_SKEW_1(DispatchBlockID::CHECK_MAIN_LOOP_CONDITION, next_block_id_for_switch);
                                break;
    
                            case DispatchBlockID::CHECK_MAIN_LOOP_CONDITION:
                                if (i < steps) {
                                    OBF_SET_NEXT_STATE_SKEW_2(DispatchBlockID::DETERMINE_AND_EXECUTE_HANDLER, next_block_id_for_switch);
                                } else {
                                    OBF_SET_NEXT_STATE_SKEW_3(DispatchBlockID::EXIT_DISPATCH_LOOP, next_block_id_for_switch);
                                }
                                break;
    
                            case DispatchBlockID::DETERMINE_AND_EXECUTE_HANDLER:
                            {
                                int dispatcher_type = ((s.dispatch_key ^ s.pc ^ s.global_seed_ref ^ i ^ (int)std::time(nullptr)) & 3);
                                _obf_global_opaque_seed = OBF_MBA_ADD(_obf_global_opaque_seed, dispatcher_type ^ (int)__COUNTER__ ^ (int)OBF_CALL_ANY_LOCAL_JUNK());
    
                                size_t local_idx_for_handler = 0;
    
                                if (dispatcher_type == 0) {
                                    if (OBF_OPAQUE_PREDICATE_TRUE_1()) {
                                        local_idx_for_handler = reg_dispatch_idx(s);
                                        handler_table_raw[local_idx_for_handler](s, argc, argv);
                                    } else { K8_ASSUME(0); }
                                } else if (dispatcher_type == 1) {
                                    if (OBF_OPAQUE_PREDICATE_FALSE_1()) {
                                        K8_ASSUME(0);
                                    } else {
                                        unsigned int mem_mix = (s.dispatch_key + s.r1 * 7 + s.r2 * 13 + i * 5) ^ (unsigned int)OBF_CALL_ANY_LOCAL_JUNK();
                                        local_idx_for_handler = (mem_mix % HANDLER_COUNT);
                                        mem_table[local_idx_for_handler](s, argc, argv);
                                    }
                                } else if (dispatcher_type == 2) {
                                    local_idx_for_handler = mixed_dispatch_idx(s);
                                    if (OBF_OPAQUE_PREDICATE_TRUE_1()) {
                                        handler_table_raw[local_idx_for_handler](s, argc, argv);
                                    } else {
                                        K8_ASSUME(0);
                                        mem_table[(local_idx_for_handler + 5) % HANDLER_COUNT](s, argc, argv);
                                    }
                                } else { 
                                    local_idx_for_handler = ((s.pc ^ s.r0 ^ (unsigned int)OBF_CALL_ANY_LOCAL_JUNK() ^ s.dispatch_key) % HANDLER_COUNT);
                                    if (OBF_OPAQUE_PREDICATE_TRUE_2(s.r1 ^ s.r2)) {
                                        mem_table[local_idx_for_handler](s, argc, argv);
                                    } else {
                                        handler_table_raw[(local_idx_for_handler + 3) % HANDLER_COUNT](s, argc, argv);
                                    }
                                }
                                OBF_CALL_ANY_LOCAL_JUNK(); 
                                OBF_SET_NEXT_STATE_SKEW_4(DispatchBlockID::MAYBE_CALL_EXTRA_JUNK, next_block_id_for_switch);
                                break;
                            }
    
                            case DispatchBlockID::MAYBE_CALL_EXTRA_JUNK:
                                if ((i & 2) && OBF_OPAQUE_PREDICATE_TRUE_2(s.r0 ^ s.dispatch_key)) {
                                    OBF_SET_NEXT_STATE_MERGED_COND_SKEW_TRUE(
                                        DispatchBlockID::EXECUTE_EXTRA_JUNK,
                                        DispatchBlockID::DETERMINE_PC_UPDATE_PATH,
                                        next_block_id_for_switch
                                    );
                                } else {
                                    OBF_SET_NEXT_STATE_SKEW_5(DispatchBlockID::DETERMINE_PC_UPDATE_PATH, next_block_id_for_switch);
                                }
                                break;
    
                            case DispatchBlockID::EXECUTE_EXTRA_JUNK:
                                OBF_CALL_ANY_LOCAL_JUNK();
                                _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed, (int)__TIME__[1] ^ (int)i ^ (int)OBF_CALL_ANY_LOCAL_JUNK());
                                OBF_SET_NEXT_STATE_SKEW_6(DispatchBlockID::DETERMINE_PC_UPDATE_PATH, next_block_id_for_switch);
                                break;
    
                            case DispatchBlockID::DETERMINE_PC_UPDATE_PATH:
                                if (((i & 1) == 0)) {
                                    OBF_SET_NEXT_STATE_SKEW_7(DispatchBlockID::EXECUTE_PC_UPDATE_PATH_A, next_block_id_for_switch);
                                } else {
                                    OBF_SET_NEXT_STATE_SKEW_8(DispatchBlockID::EXECUTE_PC_UPDATE_PATH_B, next_block_id_for_switch);
                                }
                                break;
    
                            case DispatchBlockID::EXECUTE_PC_UPDATE_PATH_A:
                                s.pc = (s.pc + mixed_dispatch_idx(s) + (unsigned int)OBF_CALL_ANY_LOCAL_JUNK()) % HANDLER_COUNT;
                                OBF_SET_NEXT_STATE_SKEW_9(DispatchBlockID::INCREMENT_MAIN_LOOP_COUNTER, next_block_id_for_switch);
                                break;
    
                            case DispatchBlockID::EXECUTE_PC_UPDATE_PATH_B:
                                s.pc = (s.pc + reg_dispatch_idx(s)) % HANDLER_COUNT;
                                OBF_SET_NEXT_STATE_SKEW_10(DispatchBlockID::INCREMENT_MAIN_LOOP_COUNTER, next_block_id_for_switch);
                                break;
    
                            case DispatchBlockID::INCREMENT_MAIN_LOOP_COUNTER:
                                NOP();
                                i++;
                                _obf_global_opaque_seed = OBF_MBA_ADD(_obf_global_opaque_seed, (int)i ^ (int)__LINE__ ^ (int)OBF_CALL_ANY_LOCAL_JUNK());
                                OBF_SET_NEXT_STATE_SKEW_1(DispatchBlockID::CHECK_MAIN_LOOP_CONDITION, next_block_id_for_switch);
                                break;
    
                            case DispatchBlockID::DEAD_CODE_TARGET_BLOCK:
                                _obf_global_opaque_seed = OBF_MBA_NOT(_obf_global_opaque_seed ^ 0xBEEFBABE);
                                OBF_CALL_ANY_LOCAL_JUNK(); OBF_CALL_ANY_LOCAL_JUNK();
                                OBF_SET_NEXT_STATE_CONST_COND_FALSE_2(
                                    DispatchBlockID::DEAD_CODE_TARGET_BLOCK,
                                    DispatchBlockID::EXIT_DISPATCH_LOOP,
                                    next_block_id_for_switch
                                );
                                K8_ASSUME(0);
                                break;
    
                            case DispatchBlockID::EXIT_DISPATCH_LOOP:
                                NOP();
                                _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed, (int)std::time(nullptr) ^ (int)__COUNTER__ ^ s.pc);
                                machine_is_running = false;
                                break;
    
                            default:
                                NOP();
                                K8_ASSUME(0);
                                machine_is_running = false;
                                break;
                        }
                    }
                }
    
                static 
                vm_handler_ptr_t vm_handler_table[8] = 
                {
                        vm_handle_op_arith, vm_handle_op_bitwise_logic, 
                        vm_handle_op_key_mangle, vm_handle_op_junk_sequence, 
                        vm_handle_op_conditional_update, vm_handle_op_mem_sim,
                        vm_handle_op_pc_mangle, vm_handle_op_multi_mba
                };
    
                constexpr 
                size_t 
                VM_HANDLER_TABLE_SIZE = sizeof(vm_handler_table)/sizeof(vm_handler_ptr_t);
            }
    
    // --------------------------------------
    #pragma endregion VM_ENGINE 
    
    #pragma region CALLERS
    // --------------------------------------
    
        #ifndef PASTE_TOKENS_HELPER
        #define PASTE_TOKENS_HELPER(a, b) a##b
        #endif
        #ifndef PASTE_TOKENS
        #define PASTE_TOKENS(a, b) PASTE_TOKENS_HELPER(a, b)
        #endif
    
        /// --- JUMP --- 
        // These use goto Wrapping them in an OBF_OPAQUE_PREDICATE_FALSE_1() ensures they are compiled
        // but dont necessarily execute their jump logic during a normal call to CALLERS
        // preventing premature exit from this combined
        #define OBF_JMP(UNIQUE_ID) \
            do { \
                PASTE_TOKENS(_DUMMY_LABEL_JUMPS_, UNIQUE_ID): \
                    NOP(); \
                    OBF_JUMP_SKEW_1(PASTE_TOKENS(_DUMMY_LABEL_JUMPS_, UNIQUE_ID)); \
                    OBF_JUMP_SKEW_2(PASTE_TOKENS(_DUMMY_LABEL_JUMPS_, UNIQUE_ID)); \
                    OBF_JUMP_SKEW_3(PASTE_TOKENS(_DUMMY_LABEL_JUMPS_, UNIQUE_ID)); \
                    OBF_JUMP_SKEW_4(PASTE_TOKENS(_DUMMY_LABEL_JUMPS_, UNIQUE_ID)); \
                    OBF_JUMP_SKEW_5(PASTE_TOKENS(_DUMMY_LABEL_JUMPS_, UNIQUE_ID)); \
                    OBF_JUMP_SKEW_6(PASTE_TOKENS(_DUMMY_LABEL_JUMPS_, UNIQUE_ID)); \
                    OBF_JUMP_SKEW_7(PASTE_TOKENS(_DUMMY_LABEL_JUMPS_, UNIQUE_ID)); \
                    OBF_JUMP_SKEW_8(PASTE_TOKENS(_DUMMY_LABEL_JUMPS_, UNIQUE_ID)); \
                    OBF_JUMP_SKEW_9(PASTE_TOKENS(_DUMMY_LABEL_JUMPS_, UNIQUE_ID)); \
                    OBF_JUMP_SKEW_10(PASTE_TOKENS(_DUMMY_LABEL_JUMPS_, UNIQUE_ID)); \
                    OBF_JUMP_CONST_COND_TRUE_1(PASTE_TOKENS(_DUMMY_LABEL_JUMPS_, UNIQUE_ID), { NOP(); _obf_global_opaque_seed = OBF_MBA_ADD(_obf_global_opaque_seed, 1); }); \
                    OBF_JUMP_CONST_COND_FALSE_1(PASTE_TOKENS(_DUMMY_LABEL_JUMPS_, UNIQUE_ID), { NOP(); _obf_global_opaque_seed = OBF_MBA_SUB(_obf_global_opaque_seed, 1); }); \
                    OBF_JUMP_CONST_COND_TRUE_2(PASTE_TOKENS(_DUMMY_LABEL_JUMPS_, UNIQUE_ID), { NOP(); _obf_global_opaque_seed = OBF_MBA_ADD(_obf_global_opaque_seed, 2); }); \
                    OBF_JUMP_CONST_COND_FALSE_2(PASTE_TOKENS(_DUMMY_LABEL_JUMPS_, UNIQUE_ID), { NOP(); _obf_global_opaque_seed = OBF_MBA_SUB(_obf_global_opaque_seed, 2); }); \
                    OBF_JUMP_MERGED_COND_SKEW_TRUE(PASTE_TOKENS(_DUMMY_LABEL_JUMPS_, UNIQUE_ID), { NOP(); _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed, 0xFF); }); \
            } while(0) 
    
    
        #define CALLER() \
            do { \
                if (OBF_OPAQUE_PREDICATE_FALSE_1()) { \
                    OBF_JMP(__COUNTER__); \
                }\
                \
            } while(0)
    
    // --------------------------------------
    #pragma endregion CALLERS
    
    #pragma region _ANTI_RE_
    // --------------------------------------
    
        // --- Anti-RE (Conceptual) ---
        ///////////////////////////////////////////////
        #define OBF_CALL_VIA_OBF_PTR(func_ptr_type, real_func, arg1, arg2) \
            do { \
                volatile func_ptr_type _obf_fp_internal = (real_func); \
                unsigned int _obf_key_fp = OBF_MBA_XOR((unsigned int)__LINE__, (unsigned int)_obf_global_opaque_seed ^ (unsigned int)OBF_CALL_ANY_LOCAL_JUNK()); \
                _obf_fp_internal = (func_ptr_type)((std::uintptr_t)_obf_fp_internal ^ _obf_key_fp); \
                NOP(); \
                _obf_fp_internal = (func_ptr_type)((std::uintptr_t)_obf_fp_internal ^ _obf_key_fp); \
                if (OBF_OPAQUE_PREDICATE_TRUE_1()) { \
                    ((func_ptr_type)_obf_fp_internal)((arg1), (arg2)); \
                } else { K8_ASSUME(0); } \
            } while(0)
    
        #define OBF_CONDITIONAL_EXIT(state_var, val_for_normal_exit, val_for_alt_exit) \
            do { \
                if (OBF_OPAQUE_PREDICATE_TRUE_2(OBF_CALL_ANY_LOCAL_JUNK() ^ _obf_global_opaque_seed)) { \
                    (state_var) = (val_for_normal_exit);\
                } else { \
                    K8_ASSUME(0); \
                    (state_var) = (val_for_alt_exit); \
                } \
                NOP(); \
            } while(0)
    
    
    
        #if defined(_MSC_VER)
            #if defined(_MSC_VER)
                #include <malloc.h>
                #define K8_ALLOCA _alloca
            #endif
            #define OBF_STACK_ALLOC_MANIP(var_name, base_size) \
                volatile unsigned int _obf_alloc_size = OBF_MBA_ADD((base_size), ((unsigned int)OBF_CALL_ANY_LOCAL_JUNK() & 0xFFU)); \
                _obf_alloc_size = (_obf_alloc_size == 0) ? 16 : _obf_alloc_size; \
                volatile char* var_name = (volatile char*)K8_ALLOCA(_obf_alloc_size); \
                if (OBF_OPAQUE_PREDICATE_TRUE_1() && var_name) { \
                    for(unsigned int _i_sa = 0; _i_sa < (_obf_alloc_size > 4 ? 4: _obf_alloc_size) ; ++_i_sa) { \
                        var_name[_i_sa] = (char)(_obf_global_opaque_seed ^ _i_sa ^ __COUNTER__); \
                    } \
                } \
                NOP();
        #endif
    
        #define OBF_OBF_ARRAY_ACCESS(array_ptr, real_idx, obf_val_to_write) \
            do { \
                volatile unsigned int _obf_idx_calc1 = OBF_MBA_XOR((unsigned int)(real_idx), (unsigned int)OBF_CALL_ANY_LOCAL_JUNK()); \
                volatile unsigned int _obf_idx_calc2 = OBF_MBA_ADD((unsigned int)_obf_global_opaque_seed, (unsigned int)__LINE__); \
                volatile unsigned int _obf_final_idx = OBF_MBA_SUB(OBF_MBA_ADD(_obf_idx_calc1, _obf_idx_calc2), OBF_MBA_XOR(_obf_idx_calc2, (unsigned int)OBF_CALL_ANY_LOCAL_JUNK())); \
                if (OBF_OPAQUE_PREDICATE_TRUE_2(_obf_final_idx)) { \
                   (array_ptr)[(real_idx)] = (char)((obf_val_to_write) ^ _obf_global_opaque_seed); \
                } else { K8_ASSUME(0); } \
                NOP(); \
            } while(0)
    
        #define OBF_STACK_AND_ACCESS(base_size, idx_to_access, val_to_write) \
            do { \
                OBF_STACK_ALLOC_MANIP(_temp_stack_ptr_sa, base_size); \
                if (OBF_OPAQUE_PREDICATE_TRUE_1() && _temp_stack_ptr_sa && (idx_to_access) < (base_size) ) { \
                    OBF_OBF_ARRAY_ACCESS(_temp_stack_ptr_sa, idx_to_access, val_to_write); \
                } \
            } while(0)
    
    
        #define OBF_FAKE_PROLOGUE_MANIP() \
            do {\
                volatile std::uintptr_t _fake_ebp = (std::uintptr_t)&_obf_global_opaque_seed - (OBF_CALL_ANY_LOCAL_JUNK() & 0xFF); \
                volatile std::uintptr_t _fake_esp = _fake_ebp - ((OBF_CALL_ANY_LOCAL_JUNK() & 0x7F) + 16); \
                _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed, (int)_fake_ebp ^ (int)_fake_esp); \
                NOP(); \
            } while(0)
    
        #define OBF_PREPARE_OBF_RETURN(real_ret_val, temp_var) \
            do { \
                (temp_var) = (real_ret_val); \
                (temp_var) = OBF_MBA_XOR((temp_var), (unsigned int)_obf_global_opaque_seed ^ (unsigned int)OBF_CALL_ANY_LOCAL_JUNK()); \
                (temp_var) = OBF_MBA_XOR((temp_var), (unsigned int)_obf_global_opaque_seed ^ (unsigned int)OBF_CALL_ANY_LOCAL_JUNK()); \
                NOP(); \
            } while(0)
    
        #define OBF_STACK_AND_PROLOGUE_JUNK(stack_var_name, base_size) \
            do { \
                OBF_FAKE_PROLOGUE_MANIP(); \
                OBF_STACK_ALLOC_MANIP(stack_var_name, base_size); \
                OBF_CALL_ANY_LOCAL_JUNK(); \
            } while(0)
    
    
        K8_NOINLINE static void _obf_dummy_func_A(obf_vm_engine::VMState& s, int i) { s.r0 = OBF_MBA_ADD(s.r0, i ^ OBF_CALL_ANY_LOCAL_JUNK()); }
        K8_NOINLINE static void _obf_dummy_func_B(obf_vm_engine::VMState& s, int i) { s.r1 = OBF_MBA_XOR(s.r1, i + OBF_CALL_ANY_LOCAL_JUNK()); }
        #define OBF_CHAINED_OBF_CALLS(vm_state_ref, val) \
            do { \
                using dummy_func_t = void(*)(obf_vm_engine::VMState&, int); \
                OBF_CALL_VIA_OBF_PTR(dummy_func_t, obf_vm_engine::_obf_dummy_func_A_impl, vm_state_ref, val); \
                if (OBF_OPAQUE_PREDICATE_TRUE_1()) { \
                    OBF_CALL_VIA_OBF_PTR(dummy_func_t, obf_vm_engine::_obf_dummy_func_B_impl, vm_state_ref, (val) + 1 + (OBF_CALL_ANY_LOCAL_JUNK() & 1)); \
                } \
                NOP(); \
            } while(0)
    
    
        K8_NOINLINE static void _obf_exit_path_norm(obf_vm_engine::VMState& s, int i) { s.r2 = OBF_MBA_SUB(s.r2, i ^ OBF_CALL_ANY_LOCAL_JUNK()); }
        K8_NOINLINE static void _obf_exit_path_alt(obf_vm_engine::VMState& s, int i) { s.dispatch_key = OBF_MBA_NOT(s.dispatch_key + i + OBF_CALL_ANY_LOCAL_JUNK()); }
        #define OBF_EXIT_CHOICE_DRIVES_CALL(vm_state_ref, val, exit_choice_var, normal_choice_val) \
            do { \
                using exit_func_t = void(*)(obf_vm_engine::VMState&, int); \
                if (OBF_OPAQUE_PREDICATE_TRUE_1()) { \
                    volatile int _obf_choice = OBF_MBA_XOR((exit_choice_var), OBF_CALL_ANY_LOCAL_JUNK() & 1); \
                    _obf_choice = OBF_MBA_XOR(_obf_choice, OBF_CALL_ANY_LOCAL_JUNK() & 1); \
                    if (_obf_choice == (normal_choice_val)) { \
                        OBF_CALL_VIA_OBF_PTR(exit_func_t, obf_vm_engine::_obf_exit_path_norm_impl, vm_state_ref, val); \
                    } else { \
                        OBF_CALL_VIA_OBF_PTR(exit_func_t, obf_vm_engine::_obf_exit_path_alt_impl, vm_state_ref, val); \
                    } \
                } else { K8_ASSUME(0); } \
                NOP(); \
            } while(0)
    
        #define OBF_HEAVY_JUNK_OP(var_to_modify, val_to_add) \
            do { \
                OBF_CALL_ANY_LOCAL_JUNK(); NOP(); OBF_CALL_ANY_LOCAL_JUNK(); \
                unsigned int _temp_junk_val1 = (unsigned int)OBF_CALL_ANY_LOCAL_JUNK() ^ (unsigned int)__LINE__; \
                unsigned int _temp_junk_val2 = (unsigned int)_obf_global_opaque_seed + (unsigned int)__COUNTER__; \
                (var_to_modify) = OBF_MBA_ADD((var_to_modify), _temp_junk_val1); \
                (var_to_modify) = OBF_MBA_XOR((var_to_modify), _temp_junk_val2); \
                (var_to_modify) = OBF_MBA_SUB((var_to_modify), _temp_junk_val1); \
                (var_to_modify) = OBF_MBA_ADD((var_to_modify), (unsigned int)(val_to_add)); \
                (var_to_modify) = OBF_MBA_XOR((var_to_modify), _temp_junk_val2); \
                NOP(); OBF_CALL_ANY_LOCAL_JUNK(); NOP(); \
            } while(0)
    
    // --------------------------------------
    #pragma endregion _ANTI_RE_
    
    #pragma region _BOGUS_CONTROL_FLOW_
    // --------------------------------------
    
        #define V2()\
            do { \
                volatile unsigned int _bfl_counter = (unsigned int)__COUNTER__ ^ (unsigned int)_obf_global_opaque_seed; \
                volatile unsigned int _bfl_loop_var = OBF_MBA_XOR(_bfl_counter, (unsigned int)OBF_CALL_ANY_LOCAL_JUNK()); \
                _bfl_loop_var %= (5 + (OBF_CALL_ANY_LOCAL_JUNK() & 3)); \
                volatile unsigned int _bfl_selector = 0; \
                \
            kk_bfl_loop_start_point: \
                NOP(); \
                if (OBF_OPAQUE_PREDICATE_FALSE_1()) goto Z_bfl_dead_path_alpha; \
                \
                _bfl_selector = OBF_MBA_ADD(_bfl_selector, (_bfl_loop_var ^ (unsigned int)_obf_global_opaque_seed ^ (unsigned int)__LINE__)) % 7; \
                _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed, (int)_bfl_selector + (int)OBF_CALL_ANY_LOCAL_JUNK()); \
                \
                if (OBF_OPAQUE_PREDICATE_TRUE_1()) { \
                    switch (_bfl_selector) { \
                        case 0: goto _bfl_path_Z; \
                        case 1: if (OBF_OPAQUE_PREDICATE_TRUE_2(_bfl_counter)) goto _bfl_path_ZZ; else goto _bfl_path_CZ; \
                        case 2: goto _bfl_path_CZ; \
                        case 3: if (OBF_OPAQUE_PREDICATE_FALSE_1()) goto Z_bfl_dead_path_beta; else goto _bfl_path_Z; \
                        case 4: goto _bfl_path_ZZ; \
                        case 5: OBF_CALL_ANY_LOCAL_JUNK(); goto _bfl_path_Z_after_junk; \
                        default: goto _bfl_loop_decrementZ; \
                    } \
                } else { \
                    K8_ASSUME(0); \
                    goto Z_bfl_dead_path_gamma; \
                } \
                \
            _bfl_path_Z: \
                _obf_global_opaque_seed = OBF_MBA_ADD(_obf_global_opaque_seed, 0xAAAA ^ (int)OBF_CALL_ANY_LOCAL_JUNK()); \
                NOP(); \
                goto _bfl_path_Z_after_junk; \
            _bfl_path_Z_after_junk: \
                _obf_global_opaque_seed = OBF_MBA_SUB(_obf_global_opaque_seed, 0x1111); \
                if (OBF_OPAQUE_PREDICATE_TRUE_1()) goto _bfl_loop_decrementZ; else goto Z_bfl_dead_path_delta; \
                \
            _bfl_path_ZZ: \
                _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed, 0xBBBB ^ (int)OBF_CALL_ANY_LOCAL_JUNK()); \
                NOP(); NOP(); \
                goto _bfl_loop_decrementZ; \
                \
            _bfl_path_CZ: \
                _obf_global_opaque_seed = OBF_MBA_NOT(_obf_global_opaque_seed ^ 0xCCCC); \
                OBF_CALL_ANY_LOCAL_JUNK(); \
                if (OBF_OPAQUE_PREDICATE_TRUE_2(_bfl_selector)) goto _bfl_loop_decrementZ; else goto Z_bfl_dead_path_epsilon; \
                \
            _bfl_loop_decrementZ: \
                _bfl_loop_var = OBF_MBA_SUB(_bfl_loop_var, 1U); \
                _bfl_counter = OBF_MBA_ADD(_bfl_counter, 1U); \
                if (OBF_MBA_ADD(_bfl_loop_var, 1U) > 0U && OBF_OPAQUE_PREDICATE_TRUE_1()) {\
                    goto kk_bfl_loop_start_point; \
                } \
                goto _bfl_exit_labyrinthZ; \
                \
            Z_bfl_dead_path_alpha: K8_ASSUME(0); _obf_global_opaque_seed++; goto _bfl_loop_decrementZ; \
            Z_bfl_dead_path_beta:  K8_ASSUME(0); _obf_global_opaque_seed--; goto _bfl_path_ZZ; \
            Z_bfl_dead_path_gamma: K8_ASSUME(0); _obf_global_opaque_seed ^= 1; goto _bfl_loop_decrementZ; \
            Z_bfl_dead_path_delta: K8_ASSUME(0); _obf_global_opaque_seed += 2; goto _bfl_path_CZ; \
            Z_bfl_dead_path_epsilon: K8_ASSUME(0); _obf_global_opaque_seed -=3; goto _bfl_exit_labyrinthZ; \
                \
            _bfl_exit_labyrinthZ: \
                _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed, (int)0x1AB71214); \
                OBF_CALL_ANY_LOCAL_JUNK(); NOP(); \
            } while(0)
    
    
        #define OBF_BOGUS_FLOW_LABYRINTH() \
            do { \
                volatile unsigned int _bfl_counter = (unsigned int)__COUNTER__ ^ (unsigned int)_obf_global_opaque_seed; \
                volatile unsigned int _bfl_loop_var = OBF_MBA_XOR(_bfl_counter, (unsigned int)OBF_CALL_ANY_LOCAL_JUNK()); \
                _bfl_loop_var %= (5 + (OBF_CALL_ANY_LOCAL_JUNK() & 3)); \
                volatile unsigned int _bfl_selector = 0; \
                \
            _bfl_loop_start_point: \
                NOP(); \
                if (OBF_OPAQUE_PREDICATE_FALSE_1()) goto _bfl_dead_path_alpha; \
                \
                _bfl_selector = OBF_MBA_ADD(_bfl_selector, (_bfl_loop_var ^ (unsigned int)_obf_global_opaque_seed ^ (unsigned int)__LINE__)) % 7; \
                _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed, (int)_bfl_selector + (int)OBF_CALL_ANY_LOCAL_JUNK()); \
                \
                if (OBF_OPAQUE_PREDICATE_TRUE_1()) { \
                    switch (_bfl_selector) { \
                        case 0: goto _bfl_path_A; \
                        case 1: if (OBF_OPAQUE_PREDICATE_TRUE_2(_bfl_counter)) goto _bfl_path_B; else goto _bfl_path_C; \
                        case 2: goto _bfl_path_C; \
                        case 3: if (OBF_OPAQUE_PREDICATE_FALSE_1()) goto _bfl_dead_path_beta; else goto _bfl_path_A; \
                        case 4: goto _bfl_path_B; \
                        case 5: OBF_CALL_ANY_LOCAL_JUNK(); goto _bfl_path_A_after_junk; \
                        default: goto _bfl_loop_decrement; \
                    } \
                } else { \
                    K8_ASSUME(0); \
                    goto _bfl_dead_path_gamma; \
                } \
                \
            _bfl_path_A: \
                _obf_global_opaque_seed = OBF_MBA_ADD(_obf_global_opaque_seed, 0xAAAA ^ (int)OBF_CALL_ANY_LOCAL_JUNK()); \
                NOP(); \
                goto _bfl_path_A_after_junk; \
            _bfl_path_A_after_junk: \
                _obf_global_opaque_seed = OBF_MBA_SUB(_obf_global_opaque_seed, 0x1111); \
                if (OBF_OPAQUE_PREDICATE_TRUE_1()) goto _bfl_loop_decrement; else goto _bfl_dead_path_delta; \
                \
            _bfl_path_B: \
                _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed, 0xBBBB ^ (int)OBF_CALL_ANY_LOCAL_JUNK()); \
                NOP(); NOP(); \
                goto _bfl_loop_decrement; \
                \
            _bfl_path_C: \
                _obf_global_opaque_seed = OBF_MBA_NOT(_obf_global_opaque_seed ^ 0xCCCC); \
                OBF_CALL_ANY_LOCAL_JUNK(); \
                if (OBF_OPAQUE_PREDICATE_TRUE_2(_bfl_selector)) goto _bfl_loop_decrement; else goto _bfl_dead_path_epsilon; \
                \
            _bfl_loop_decrement: \
                _bfl_loop_var = OBF_MBA_SUB(_bfl_loop_var, 1U); \
                _bfl_counter = OBF_MBA_ADD(_bfl_counter, 1U); \
                if (OBF_MBA_ADD(_bfl_loop_var, 1U) > 0U && OBF_OPAQUE_PREDICATE_TRUE_1()) {\
                    goto _bfl_loop_start_point; \
                } \
                goto _bfl_exit_labyrinth; \
                \
            _bfl_dead_path_alpha: K8_ASSUME(0); _obf_global_opaque_seed++; goto _bfl_loop_decrement; \
            _bfl_dead_path_beta:  K8_ASSUME(0); _obf_global_opaque_seed--; goto _bfl_path_B; \
            _bfl_dead_path_gamma: K8_ASSUME(0); _obf_global_opaque_seed ^= 1; goto _bfl_loop_decrement; \
            _bfl_dead_path_delta: K8_ASSUME(0); _obf_global_opaque_seed += 2; goto _bfl_path_C; \
            _bfl_dead_path_epsilon: K8_ASSUME(0); _obf_global_opaque_seed -=3; goto _bfl_exit_labyrinth; \
                \
            _bfl_exit_labyrinth: \
                _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed, (int)0x1AB71214); \
                OBF_CALL_ANY_LOCAL_JUNK(); NOP(); \
            } while(0)
    
    
        #define OBF_BOGUS_FLOW_GRID() \
            do { \
                volatile unsigned int _bfg_state_x = (unsigned int)__LINE__ % 3; \
                volatile unsigned int _bfg_state_y = (unsigned int)__TIME__[0] % 3; \
                volatile unsigned int _bfg_initial_iter_val_obf = OBF_MBA_ADD(3U, (unsigned int)OBF_CALL_ANY_LOCAL_JUNK() & 1U); \
                volatile unsigned int _bfg_iter = (_bfg_initial_iter_val_obf % 2U) + 3U; \
                \
            _bfg_grid_main_loop: \
                NOP(); \
                _obf_global_opaque_seed = OBF_MBA_ADD(_obf_global_opaque_seed, (int)(_bfg_state_x + _bfg_state_y) ^ OBF_CALL_ANY_LOCAL_JUNK()); \
                \
                if (OBF_OPAQUE_PREDICATE_TRUE_1()){\
                    if (_bfg_state_x == 0) goto _bfg_row0_logic; \
                    if (_bfg_state_x == 1) goto _bfg_row1_logic; \
                    goto _bfg_row2_logic; \
                } else { K8_ASSUME(0); goto _bfg_grid_dead_end_A; } \
                \
            _bfg_row0_logic: \
                OBF_CALL_ANY_LOCAL_JUNK(); \
                if (OBF_OPAQUE_PREDICATE_TRUE_2(_bfg_state_y)) _bfg_state_y = OBF_MBA_ADD(_bfg_state_y, 1U) % 3; \
                else { K8_ASSUME(0); _bfg_state_y = 0; } \
                if (OBF_OPAQUE_PREDICATE_FALSE_1()) goto _bfg_grid_dead_end_B; \
                _bfg_state_x = 1; \
                goto _bfg_grid_check_iter; \
                \
            _bfg_row1_logic: \
                _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed, (int)0x621D0001 ^ (int)OBF_CALL_ANY_LOCAL_JUNK()); \
                if (OBF_OPAQUE_PREDICATE_TRUE_1()){ \
                    unsigned int _temp_y_before = _bfg_state_y; \
                    _bfg_state_y = OBF_MBA_SUB(_bfg_state_y, 1U); \
                    if (_temp_y_before == 0 && _bfg_state_y > 2) { \
                         _bfg_state_y = 2; \
                    } else if (_bfg_state_y > 2 && _temp_y_before != 0) { \
                         _bfg_state_y = _temp_y_before % 3; \
                    } \
                    _bfg_state_y %= 3; \
                } else { K8_ASSUME(0); } \
                _bfg_state_x = 2; \
                goto _bfg_grid_check_iter; \
                \
            _bfg_row2_logic: \
                NOP(); NOP(); \
                if (OBF_OPAQUE_PREDICATE_FALSE_2(_bfg_state_x)) goto _bfg_grid_dead_end_C; \
                _bfg_state_y = (_bfg_state_y + _bfg_state_x) % 3; \
                _obf_global_opaque_seed = OBF_MBA_SUB(_obf_global_opaque_seed, (int)0x621D0002); \
                _bfg_state_x = 0; \
                goto _bfg_grid_check_iter; \
                \
            _bfg_grid_check_iter: \
                if (_bfg_iter > 0U && OBF_OPAQUE_PREDICATE_TRUE_2(_bfg_iter)) { \
                    _bfg_iter--; \
                    goto _bfg_grid_main_loop; \
                } \
                goto _bfg_grid_exit; \
                \
            _bfg_grid_dead_end_A: K8_ASSUME(0); _obf_global_opaque_seed++; goto _bfg_grid_exit; \
            _bfg_grid_dead_end_B: K8_ASSUME(0); _obf_global_opaque_seed--; goto _bfg_grid_exit; \
            _bfg_grid_dead_end_C: K8_ASSUME(0); _obf_global_opaque_seed^=0xFF; goto _bfg_grid_exit; \
                \
            _bfg_grid_exit: \
                _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed, (int)0x621D3E17 ^ (int)OBF_CALL_ANY_LOCAL_JUNK()); \
                OBF_CALL_ANY_LOCAL_JUNK(); \
            } while(0)
    
        #define OBF_BOGUS_FLOW_SCRAMBLE() \
            do { \
                volatile unsigned int _bfs_mode = ((unsigned int)__TIME__[1] + (unsigned int)_obf_global_opaque_seed) % 4; \
                volatile int _bfs_accumulator = OBF_CALL_ANY_LOCAL_JUNK(); \
                int _bfs_loop_count = 2 + (OBF_CALL_ANY_LOCAL_JUNK() & 1); \
                V2();\
                \
            _bfs_outer_loop: \
                NOP(); \
                _obf_global_opaque_seed = OBF_MBA_ADD(_obf_global_opaque_seed, _bfs_accumulator ^ (int)_bfs_mode); \
            \
                if (OBF_OPAQUE_PREDICATE_TRUE_1()) { \
                    goto _bfs_decision_point_1; \
                } \
                K8_ASSUME(0); goto _bfs_dead_branch_X; \
            \
            _bfs_decision_point_1: \
                _bfs_accumulator = OBF_MBA_XOR(_bfs_accumulator, (int)__LINE__ + (int)_bfs_mode); \
                if (OBF_OPAQUE_PREDICATE_TRUE_2((unsigned int)_bfs_accumulator)) { \
                    if ((_bfs_mode % 2) == 0) goto _bfs_path_EVEN; else goto _bfs_path_ODD; \
                } else { \
                    K8_ASSUME(0); goto _bfs_dead_branch_Y; \
                } \
            \
            _bfs_path_EVEN: \
                OBF_CALL_ANY_LOCAL_JUNK(); \
                _bfs_accumulator = OBF_MBA_ADD(_bfs_accumulator, 0xE0E0); \
                _obf_global_opaque_seed = OBF_MBA_SUB(_obf_global_opaque_seed, _bfs_accumulator); \
                if (OBF_OPAQUE_PREDICATE_FALSE_1()) goto _bfs_dead_branch_Z; \
                _bfs_mode = (_bfs_mode + 1) % 4; \
                goto _bfs_decision_point_2; \
            \
            _bfs_path_ODD: \
                NOP(); NOP(); \
                _bfs_accumulator = OBF_MBA_SUB(_bfs_accumulator, 0xD0D0); \
                _obf_global_opaque_seed = OBF_MBA_ADD(_obf_global_opaque_seed, _bfs_accumulator); \
                if (OBF_OPAQUE_PREDICATE_TRUE_1()) { \
                    _bfs_mode = (_bfs_mode + 3) % 4; \
                    goto _bfs_decision_point_2; \
                } \
                K8_ASSUME(0); goto _bfs_dead_branch_W; \
            \
            _bfs_decision_point_2: \
                _bfs_accumulator = OBF_MBA_NOT(_bfs_accumulator ^ (int)_obf_global_opaque_seed); \
                if (OBF_OPAQUE_PREDICATE_TRUE_2((unsigned int)_bfs_mode)) { \
                    goto _bfs_inner_processing; \
                } else { \
                    K8_ASSUME(0); goto _bfs_dead_branch_V; \
                } \
            \
            _bfs_inner_processing: \
                _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed, _bfs_accumulator + (int)OBF_CALL_ANY_LOCAL_JUNK()); \
                _bfs_loop_count--; \
                if (_bfs_loop_count > 0 && OBF_OPAQUE_PREDICATE_TRUE_1()) { \
                    goto _bfs_outer_loop; \
                } \
                goto _bfs_scramble_exit; \
            \
            _bfs_dead_branch_X: K8_ASSUME(0); _bfs_accumulator += 100; goto _bfs_scramble_exit; \
            _bfs_dead_branch_Y: K8_ASSUME(0); _bfs_accumulator -= 200; goto _bfs_scramble_exit; \
            _bfs_dead_branch_Z: K8_ASSUME(0); _bfs_accumulator *= 2; goto _bfs_scramble_exit; \
            _bfs_dead_branch_W: K8_ASSUME(0); _bfs_accumulator /= 2; goto _bfs_scramble_exit; \
            _bfs_dead_branch_V: K8_ASSUME(0); _bfs_accumulator = 0; goto _bfs_scramble_exit; \
            \
            _bfs_scramble_exit: \
                _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed, 0x5C2A3B1E ^ _bfs_accumulator); \
                OBF_CALL_ANY_LOCAL_JUNK(); NOP(); OBF_CALL_ANY_LOCAL_JUNK(); \
            } while(0)
    
    // --------------------------------------
    #pragma endregion _BOGUS_CONTROL_FLOW_
    
    #pragma region _CONTROL_FLOW_
    // --------------------------------------
    
        #define OBF_BOGUS_FLOW_WEAVER() \
            do { \
                volatile unsigned int _weave_idx = (unsigned int)__COUNTER__ ^ (unsigned int)_obf_global_opaque_seed; \
                volatile unsigned int _weave_max_hops = 3U + (OBF_CALL_ANY_LOCAL_JUNK() & 3U); \
                volatile unsigned int _weave_current_hop = 0; \
                volatile unsigned int _weave_state_var = OBF_MBA_XOR(_weave_idx, (unsigned int)__TIME__[0]); \
                \
            _weave_hop_entry_point: \
                NOP(); \
                _obf_global_opaque_seed = OBF_MBA_ADD(_obf_global_opaque_seed, (int)_weave_state_var ^ (int)OBF_CALL_ANY_LOCAL_JUNK()); \
                if (OBF_OPAQUE_PREDICATE_FALSE_1()) goto _weave_impossible_fork; \
                \
                if (OBF_OPAQUE_PREDICATE_TRUE_1()) { \
                    _weave_state_var = OBF_MBA_XOR(_weave_state_var, (unsigned int)__LINE__ + _weave_current_hop); \
                    if ((_weave_state_var % 5) == 0) goto _weave_path_alpha; \
                    if ((_weave_state_var % 5) == 1) goto _weave_path_beta; \
                    if ((_weave_state_var % 5) == 2) goto _weave_path_gamma; \
                    if ((_weave_state_var % 5) == 3) goto _weave_path_delta; \
                    goto _weave_path_epsilon; \
                } else { \
                    K8_ASSUME(0); goto _weave_never_reached_A; \
                } \
                \
            _weave_path_alpha: \
                _weave_state_var = OBF_MBA_ADD(_weave_state_var, 0xDEAD0001U ^ (unsigned int)OBF_CALL_ANY_LOCAL_JUNK()); \
                if (OBF_OPAQUE_PREDICATE_TRUE_2(_weave_idx)) goto _weave_common_junction; else goto _weave_path_beta; \
                \
            _weave_path_beta: \
                _weave_state_var = OBF_MBA_SUB(_weave_state_var, 0xBEEF0002U + (unsigned int)OBF_CALL_ANY_LOCAL_JUNK()); \
                if (!OBF_OPAQUE_PREDICATE_FALSE_1()) goto _weave_common_junction; else goto _weave_path_gamma; \
                \
            _weave_path_gamma: \
                OBF_CALL_ANY_LOCAL_JUNK(); \
                _weave_state_var = OBF_MBA_NOT(_weave_state_var ^ 0xCAFE0003U); \
                if (OBF_OPAQUE_PREDICATE_TRUE_1()) goto _weave_common_junction; else goto _weave_path_delta; \
                \
            _weave_path_delta: \
                _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed, (int)_weave_state_var); \
                _weave_state_var = OBF_MBA_ADD(_weave_state_var, (_weave_current_hop << 3) ^ 0xF00D0004U); \
                if (OBF_OPAQUE_PREDICATE_TRUE_2(_weave_state_var)) goto _weave_common_junction; else goto _weave_path_epsilon; \
                \
            _weave_path_epsilon: \
                NOP(); \
                _weave_state_var = OBF_MBA_XOR(_weave_state_var, 0xBADC0005U + (unsigned int)_obf_global_opaque_seed); \
                \
            _weave_common_junction: \
                _weave_current_hop = OBF_MBA_ADD(_weave_current_hop, 1U); \
                _obf_global_opaque_seed = OBF_MBA_ADD(_obf_global_opaque_seed, (int)_weave_current_hop); \
                if (_weave_current_hop < _weave_max_hops && OBF_OPAQUE_PREDICATE_TRUE_1()) { \
                    goto _weave_hop_entry_point; \
                } \
                goto _weave_exit_point; \
                \
            _weave_impossible_fork: K8_ASSUME(0); _weave_state_var ^= 0xFFFFFFFFU; goto _weave_common_junction; \
            _weave_never_reached_A: K8_ASSUME(0); _weave_state_var += 1; goto _weave_path_alpha; \
                \
            _weave_exit_point: \
                _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed, (int)0xDEADBEEF ^ (int)_weave_state_var); \
                OBF_CALL_ANY_LOCAL_JUNK(); NOP(); \
            } while(0)
    
    
        #define OBF_BOGUS_FLOW_CASCADE() \
            do { \
                volatile unsigned int _cas_level = 0; \
                volatile unsigned int _cas_seed = (unsigned int)__TIME__[1] ^ (unsigned int)_obf_global_opaque_seed ^ (unsigned int)OBF_CALL_ANY_LOCAL_JUNK(); \
                volatile unsigned int _cas_val_A = OBF_MBA_ADD(_cas_seed, 0x11223344U); \
                volatile unsigned int _cas_val_B = OBF_MBA_SUB(_cas_seed, 0x55667788U); \
                \
                NOP(); \
                if (OBF_OPAQUE_PREDICATE_TRUE_1()) { \
                    _cas_level = OBF_MBA_ADD(_cas_level, 1U); \
                    _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed, (int)_cas_val_A + (int)OBF_CALL_ANY_LOCAL_JUNK()); \
                    _cas_val_A = OBF_MBA_XOR(_cas_val_A, _cas_val_B ^ (unsigned int)__LINE__); \
                    \
                    if (OBF_OPAQUE_PREDICATE_TRUE_2(_cas_val_A)) { \
                        _cas_level = OBF_MBA_ADD(_cas_level, 1U); \
                        _obf_global_opaque_seed = OBF_MBA_ADD(_obf_global_opaque_seed, (int)_cas_val_B ^ (int)OBF_CALL_ANY_LOCAL_JUNK()); \
                        _cas_val_B = OBF_MBA_NOT(_cas_val_A + _cas_val_B); \
                        \
                        if (!OBF_OPAQUE_PREDICATE_FALSE_1()) { \
                            _cas_level = OBF_MBA_ADD(_cas_level, 1U); \
                            _obf_global_opaque_seed = OBF_MBA_SUB(_obf_global_opaque_seed, (int)_cas_val_A - (int)_cas_val_B); \
                            _cas_val_A = OBF_MBA_MUL_CONST3(_cas_val_A ^ _cas_seed); \
                            \
                            if (OBF_OPAQUE_PREDICATE_TRUE_1() || OBF_OPAQUE_PREDICATE_FALSE_2(_cas_seed)) { \
                                _cas_level = OBF_MBA_ADD(_cas_level, 1U); \
                                _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed, (int)OBF_CALL_ANY_LOCAL_JUNK() ^ (int)__COUNTER__); \
                                _cas_val_B = OBF_MBA_ADD(_cas_val_B, _cas_val_A | (unsigned int)__LINE__); \
                            } else { \
                                K8_ASSUME(0); \
                                _obf_global_opaque_seed = OBF_MBA_NOT(_obf_global_opaque_seed); \
                            } \
                        } else { \
                            K8_ASSUME(0); \
                             _cas_val_A = OBF_MBA_XOR(_cas_val_A, 0xBAD0BAD0); \
                        } \
                    } else { \
                        K8_ASSUME(0);\
                         _cas_val_B = OBF_MBA_ADD(_cas_val_B, 0xC0DEC0DE); \
                    } \
                } else { \
                    K8_ASSUME(0); \
                    _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed, 0xFEEDF00D); \
                } \
                \
                _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed, (int)_cas_level ^ (int)_cas_val_A ^ (int)_cas_val_B); \
                OBF_CALL_ANY_LOCAL_JUNK(); NOP(); \
            } while(0)
    
    
        #define OBF_BOGUS_FLOW_CYCLONE() \
            do { \
                volatile unsigned int _cyc_state = ((unsigned int)__TIME__[2] + (unsigned int)_obf_global_opaque_seed) % 5; \
                volatile int _cyc_counter = OBF_CALL_ANY_LOCAL_JUNK() & 0x7; \
                volatile unsigned int _cyc_acc = (unsigned int)__COUNTER__; \
                \
            _cyclone_main_hub: \
                NOP(); \
                _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed, (int)_cyc_state ^ (int)_cyc_acc ^ (int)OBF_CALL_ANY_LOCAL_JUNK()); \
                _cyc_acc = OBF_MBA_ADD(_cyc_acc, _cyc_state ^ (unsigned int)__LINE__); \
                \
                switch(_cyc_state) { \
                    case 0: \
                        if(OBF_OPAQUE_PREDICATE_TRUE_1()) goto _cyclone_path_red; else goto _cyclone_path_blue; \
                    case 1: \
                        _cyc_acc = OBF_MBA_XOR(_cyc_acc, 0x1001F00D); \
                        if(OBF_OPAQUE_PREDICATE_TRUE_2(_cyc_acc)) goto _cyclone_path_green; else goto _cyclone_path_yellow; \
                    case 2: \
                        OBF_CALL_ANY_LOCAL_JUNK(); \
                        if(!OBF_OPAQUE_PREDICATE_FALSE_1()) goto _cyclone_path_blue; else goto _cyclone_path_red; \
                    case 3: \
                        _cyc_acc = OBF_MBA_NOT(_cyc_acc + 0xABCDEF01U); \
                        if(OBF_OPAQUE_PREDICATE_TRUE_1()) goto _cyclone_path_yellow; else goto _cyclone_path_green; \
                    case 4: \
                        goto _cyclone_check_loop; \
                    default: \
                        K8_ASSUME(0); goto _cyclone_exit_loop; \
                } \
                \
            _cyclone_path_red: \
                _obf_global_opaque_seed = OBF_MBA_ADD(_obf_global_opaque_seed, 1 + (int)_cyc_acc); \
                _cyc_state = (_cyc_state + 2 + (_cyc_acc & 1)) % 5; \
                if (OBF_OPAQUE_PREDICATE_TRUE_1()) goto _cyclone_check_loop; else { K8_ASSUME(0); goto _cyclone_path_green; } \
                \
            _cyclone_path_blue: \
                _obf_global_opaque_seed = OBF_MBA_SUB(_obf_global_opaque_seed, 2 - (int)_cyc_acc); \
                _cyc_state = (_cyc_state + 3 + ((_cyc_acc>>1) & 1)) % 5; \
                if (!OBF_OPAQUE_PREDICATE_FALSE_2(_cyc_state)) goto _cyclone_check_loop; else { K8_ASSUME(0); goto _cyclone_path_yellow; } \
                \
            _cyclone_path_green: \
                OBF_CALL_ANY_LOCAL_JUNK(); \
                _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed, 3 * (int)_cyc_acc); \
                _cyc_state = (_cyc_state + 1) % 5; \
                goto _cyclone_check_loop; \
                \
            _cyclone_path_yellow: \
                NOP(); NOP(); \
                _obf_global_opaque_seed = OBF_MBA_NOT(_obf_global_opaque_seed ^ (4 + (int)_cyc_acc)); \
                _cyc_state = (_cyc_state + 4 + ((_cyc_acc>>2) & 1)) % 5; \
                goto _cyclone_check_loop; \
                \
            _cyclone_check_loop: \
                _cyc_counter = OBF_MBA_SUB(_cyc_counter, 1); \
                if (_cyc_counter > 0 && OBF_OPAQUE_PREDICATE_TRUE_2((unsigned int)_cyc_counter)) { \
                    goto _cyclone_main_hub; \
                } \
                \
            _cyclone_exit_loop: \
                _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed, (int)0xC1C0FFEE ^ (int)_cyc_acc); \
                OBF_CALL_ANY_LOCAL_JUNK(); NOP(); \
            } while(0)
    
    
            #pragma region OBF_ICFF_COMMON_DEFS
            // --------------------------------------
    
                namespace obf_icff_ns_dcff {
                        enum class _ObfICFF_BlockId_DCFF : unsigned int {
                            BLOCK_INIT_SELECTOR,
    
                            BLOCK_CASE_0,
                            BLOCK_CASE_1,
                            BLOCK_CASE_2,
                            BLOCK_CASE_3,
                            BLOCK_CASE_4,
                            BLOCK_CASE_5,
                            BLOCK_CASE_6,
                            BLOCK_CASE_7,
                            BLOCK_CASE_8,
                            BLOCK_CASE_9,
                            BLOCK_DEFAULT,
    
                            BLOCK_COMMON_CONTINUE,
                            BLOCK_EXIT_ICFF_LOOP,
    
                            BLOCK_DECOY_A,
                            BLOCK_DECOY_B,
    
                            COUNT_DCFF
                        };
    
                        K8_FORCEINLINE unsigned int _obf_icff_gen_key_dcff(
                            int i_dcff,
                            const obf_vm_engine::VMState& vm_s_ref,
                            volatile int& global_seed_ref,
                            unsigned int unique_salt
                        ) {
                            return OBF_MBA_XOR(
                                       OBF_MBA_ADD((unsigned int)i_dcff * OBF_MBA_ADD(0xADDECFFA, unique_salt ^ (unsigned int)__TIME__[0]), vm_s_ref.dispatch_key ^ (unsigned int)__TIME__[(i_dcff ^ unique_salt) % 8]),
                                       OBF_MBA_SUB((unsigned int)global_seed_ref * OBF_MBA_SUB(0x10CCFB1A, unique_salt ^ (unsigned int)__TIME__[1]), vm_s_ref.pc ^ vm_s_ref.r0 ^ vm_s_ref.r1 ^ vm_s_ref.r2 ^ unique_salt ^ (unsigned int)__TIME__[2])
                                   );
                        }
    
                        #define OBF_ICFF_ENCODE_STATE_DCFF(state_id, i_dcff_val, vm_s_ref, global_seed_ref, unique_salt_for_transition) \
                            OBF_MBA_XOR( (unsigned int)(state_id), _obf_icff_gen_key_dcff(i_dcff_val, vm_s_ref, global_seed_ref, unique_salt_for_transition) )
    
                        #define OBF_ICFF_DECODE_STATE_DCFF(encoded_state_val, i_dcff_val, vm_s_ref, global_seed_ref, unique_salt_for_transition) \
                            (_ObfICFF_BlockId_DCFF)OBF_MBA_XOR( (unsigned int)(encoded_state_val), _obf_icff_gen_key_dcff(i_dcff_val, vm_s_ref, global_seed_ref, unique_salt_for_transition) )
    
                        K8_FORCEINLINE _ObfICFF_BlockId_DCFF _obf_icff_map_selector_to_block_id_dcff(unsigned int selector_val, volatile int& global_seed_ref) {
                            unsigned int s = OBF_MBA_XOR(selector_val, (unsigned int)global_seed_ref ^ (unsigned int)OBF_CALL_ANY_LOCAL_JUNK());
                            s = OBF_MBA_ADD(s, (unsigned int)__TIME__[s % 8] ^ (unsigned int)__LINE__);
                            s %= 10; 
    
                            switch (s) {
                                case 0: return _ObfICFF_BlockId_DCFF::BLOCK_CASE_0;
                                case 1: return _ObfICFF_BlockId_DCFF::BLOCK_CASE_1;
                                case 2: return _ObfICFF_BlockId_DCFF::BLOCK_CASE_2;
                                case 3: return _ObfICFF_BlockId_DCFF::BLOCK_CASE_3;
                                case 4: return _ObfICFF_BlockId_DCFF::BLOCK_CASE_4;
                                case 5: return _ObfICFF_BlockId_DCFF::BLOCK_CASE_5;
                                case 6: return _ObfICFF_BlockId_DCFF::BLOCK_CASE_6;
                                case 7: return _ObfICFF_BlockId_DCFF::BLOCK_CASE_7;
                                case 8: return _ObfICFF_BlockId_DCFF::BLOCK_CASE_8;
                                case 9: return _ObfICFF_BlockId_DCFF::BLOCK_CASE_9;
                                default: 
                                    K8_ASSUME(s >=0 && s <= 9);
                                    return _ObfICFF_BlockId_DCFF::BLOCK_DEFAULT;
                            }
                        }
                }
    
                using namespace obf_icff_ns_dcff;
    
                namespace obf_icff_ns_epd {
                        enum class _ObfICFF_BlockId_EPD : unsigned int {
                            BLOCK_INIT_SELECTOR,
    
                            BLOCK_CASE_0,
                            BLOCK_CASE_1,
                            BLOCK_CASE_2,
                            BLOCK_CASE_3,
                            BLOCK_CASE_4,
                            BLOCK_CASE_5,
                            BLOCK_CASE_6,
                            BLOCK_CASE_7,
                            BLOCK_DEFAULT,
    
                            BLOCK_COMMON_CONTINUE,
                            BLOCK_EXIT_ICFF_LOOP,
    
                            BLOCK_DECOY_A,
                            BLOCK_DECOY_B,
    
                            COUNT_EPD
                        };
    
                        K8_FORCEINLINE unsigned int _obf_icff_gen_key_epd(
                            int i_epd,
                            unsigned int epi_val,
                            const obf_vm_engine::VMState& vm_s_ref,
                            volatile int& global_seed_ref,
                            unsigned int unique_salt
                        ) {
                            return OBF_MBA_XOR(
                                       OBF_MBA_SUB((unsigned int)i_epd * OBF_MBA_XOR(0xBEEFB00B, unique_salt ^ (unsigned int)__TIME__[3]), epi_val ^ (unsigned int)__TIME__[(i_epd ^ epi_val ^ unique_salt) % 8]),
                                       OBF_MBA_ADD((unsigned int)global_seed_ref * OBF_MBA_NOT(0xF00DBAAC + unique_salt), vm_s_ref.dispatch_key ^ vm_s_ref.r1 ^ vm_s_ref.r2 ^ epi_val ^ unique_salt ^ (unsigned int)__TIME__[4])
                                   );
                        }
    
                        #define OBF_ICFF_ENCODE_STATE_EPD(state_id, i_epd_val, epi_val_ref, vm_s_ref, global_seed_ref, unique_salt_for_transition) \
                            OBF_MBA_XOR( (unsigned int)(state_id), _obf_icff_gen_key_epd(i_epd_val, epi_val_ref, vm_s_ref, global_seed_ref, unique_salt_for_transition) )
    
                        #define OBF_ICFF_DECODE_STATE_EPD(encoded_state_val, i_epd_val, epi_val_ref, vm_s_ref, global_seed_ref, unique_salt_for_transition) \
                            (_ObfICFF_BlockId_EPD)OBF_MBA_XOR( (unsigned int)(encoded_state_val), _obf_icff_gen_key_epd(i_epd_val, epi_val_ref, vm_s_ref, global_seed_ref, unique_salt_for_transition) )
    
    
                        K8_FORCEINLINE _ObfICFF_BlockId_EPD _obf_icff_map_selector_to_block_id_epd(unsigned int selector_val, volatile int& global_seed_ref) {
                            unsigned int s = OBF_MBA_XOR(selector_val, (unsigned int)global_seed_ref ^ (unsigned int)OBF_CALL_ANY_LOCAL_JUNK() ^ (unsigned int)__LINE__);
                            s = OBF_MBA_ADD(s, (unsigned int)__TIME__[(s % 8)+1]);
                            s %= 8;
    
                            switch (s) {
                                case 0: return _ObfICFF_BlockId_EPD::BLOCK_CASE_0;
                                case 1: return _ObfICFF_BlockId_EPD::BLOCK_CASE_1;
                                case 2: return _ObfICFF_BlockId_EPD::BLOCK_CASE_2;
                                case 3: return _ObfICFF_BlockId_EPD::BLOCK_CASE_3;
                                case 4: return _ObfICFF_BlockId_EPD::BLOCK_CASE_4;
                                case 5: return _ObfICFF_BlockId_EPD::BLOCK_CASE_5;
                                case 6: return _ObfICFF_BlockId_EPD::BLOCK_CASE_6;
                                case 7: return _ObfICFF_BlockId_EPD::BLOCK_CASE_7;
                                default:
                                    K8_ASSUME(s >= 0 && s <= 7);
                                    return _ObfICFF_BlockId_EPD::BLOCK_DEFAULT;
                            }
                        }
                }
    
                using namespace obf_icff_ns_epd;
    
            // --------------------------------------
            #pragma endregion OBF_ICFF_COMMON_DEFS
    
    // --------------------------------------
    #pragma endregion _CONTROL_FLOW_
    
    #pragma region MAIN_FLATTENING
    // --------------------------------------
    
        #define Runtime(vm_state_ref) \
            do { \
                unsigned int _rt_activation_key = OBF_MBA_XOR((unsigned int)std::time(nullptr), (unsigned int)_obf_global_opaque_seed ^ (unsigned int)__COUNTER__); \
                _rt_activation_key = OBF_MBA_ADD(_rt_activation_key, (vm_state_ref).r0 ^ (vm_state_ref).r1 ^ (vm_state_ref).pc); \
                \
                if (((_rt_activation_key >> ((OBF_CALL_ANY_LOCAL_JUNK() & 3) + 2)) & 0x7U) == ((unsigned int)__TIME__[(_rt_activation_key>>8)%8] & 0x7U) ) { \
                    NOP(); \
                    volatile int _rt_decision_val = OBF_MBA_XOR(_obf_global_opaque_seed, (int)__LINE__ ^ (int)std::time(nullptr) ^ (int)(vm_state_ref).dispatch_key); \
                    _rt_decision_val = OBF_MBA_ADD(_rt_decision_val, OBF_CALL_ANY_LOCAL_JUNK()); \
                    CALLER();\
                    \
                    if (OBF_OPAQUE_PREDICATE_TRUE_1() || !OBF_OPAQUE_PREDICATE_TRUE_1()) { \
                        CALLER();\
                    } else { K8_ASSUME(0); CALLER(); } \
                    \
                    unsigned int _rt_crash_cond_part1 = OBF_MBA_MUL_CONST3(_rt_decision_val ^ (vm_state_ref).r2); \
                    unsigned int _rt_crash_cond_part2 = OBF_MBA_NOT((unsigned int)_obf_global_opaque_seed + (vm_state_ref).pc); \
                    \
                    if ( (_rt_crash_cond_part1 & 0xFEFEFEFEU) == OBF_MBA_XOR(0x41414141U & 0xFEFEFEFEU, _rt_crash_cond_part2 & 0x01010101U) && \
                         OBF_OPAQUE_PREDICATE_TRUE_2(_rt_decision_val ^ (vm_state_ref).r0) || !OBF_OPAQUE_PREDICATE_TRUE_2(_rt_decision_val ^ (vm_state_ref).r0)) \
                    { \
                        OBF_CALL_ANY_LOCAL_JUNK(); \
                        if ((_rt_decision_val & 0x180) && (std::rand() & 1) && OBF_OPAQUE_PREDICATE_TRUE_1() || !OBF_OPAQUE_PREDICATE_TRUE_1()) { \
                            if (((unsigned int)_obf_global_opaque_seed ^ __LINE__) % 3 == 0) { \
                                obf_vm_engine::_seh_forced_exception_effect(vm_state_ref); \
                            } else { \
                                __debugbreak(); \
                            } \
                        } \
                        unsigned int _rt_err_seed = (unsigned int)_obf_global_opaque_seed ^ (unsigned int)__TIME__[0] ^ (unsigned int)__COUNTER__; \
                        auto llll = (((_rt_err_seed >> 8) & 0xFF) + (_rt_err_seed & 0xFF)) ^ (((vm_state_ref).r0 << 5) + (OBF_CALL_ANY_LOCAL_JUNK() % 10));\
                        throw std::runtime_error(OBFUSCATE_STRING("pojkdkddkeifpojkdkddkeifpojkdkddkeifpojkdkddkeif Oh skibiddi oooh")); \
                        if (((unsigned int)_obf_global_opaque_seed ^ __COUNTER__ << llll) % 3 == 0) { \
                            CALLER(); \
                        } \
                    } \
                    CALLER(); \
                    if (((unsigned int)_obf_global_opaque_seed ^ __COUNTER__) % 3 == 0) { \
                         CALLER(); \
                    } \
                } \
                NOP(); \
            } while (0)
    
        #define HANDLER_TABLE_MUTATE(table, sz, vm_state_ref) \
            do { \
                if ((sz) == 0) break;\
                volatile unsigned int _htm_outer_loop_count = (sz) + (OBF_CALL_ANY_LOCAL_JUNK() & 3U);\
                \
                for (size_t _htm_i = 0; _htm_i < _htm_outer_loop_count; ++_htm_i) { \
                    CALLER(); \
                    NOP(); \
                    \
                    unsigned int _htm_base_val1 = OBF_MBA_XOR((unsigned int)_htm_i * 13U, (unsigned int)std::time(nullptr) + (unsigned int)_obf_global_opaque_seed); \
                    _htm_base_val1 = OBF_MBA_ADD(_htm_base_val1, (vm_state_ref).r0 ^ (vm_state_ref).dispatch_key); \
                    size_t _htm_idx1 = _htm_base_val1 % (sz); \
                    \
                    unsigned int _htm_base_val2 = OBF_MBA_SUB((unsigned int)_htm_i * 7U, (unsigned int)_obf_global_opaque_seed ^ (unsigned int)__LINE__); \
                    _htm_base_val2 = OBF_MBA_XOR(_htm_base_val2, (vm_state_ref).r1 ^ (vm_state_ref).pc); \
                    size_t _htm_idx2 = _htm_base_val2 % (sz); \
                    \
                    if (OBF_OPAQUE_PREDICATE_TRUE_1() || !OBF_OPAQUE_PREDICATE_TRUE_1() && _htm_idx1 != _htm_idx2) { \
                        auto _htm_temp_ptr = (table)[_htm_idx1]; \
                        (table)[_htm_idx1] = (table)[_htm_idx2]; \
                        (table)[_htm_idx2] = _htm_temp_ptr; \
                        _obf_global_opaque_seed = OBF_MBA_ADD(_obf_global_opaque_seed, (int)(_htm_idx1 ^ _htm_idx2)); \
                    } else if (1 == 1) { \
                        unsigned int lo = _htm_base_val1;\
                        if(OBF_OPAQUE_PREDICATE_TRUE_2(_htm_base_val1) || !OBF_OPAQUE_PREDICATE_TRUE_2(lo))\
                        {\
                            unsigned int _htm_base_val3 = OBF_MBA_XOR((unsigned int)_obf_global_opaque_seed, (unsigned int)OBF_CALL_ANY_LOCAL_JUNK() ^ (vm_state_ref).r2); \
                                size_t _htm_idx3 = (_htm_base_val3 ^ _htm_idx1) % (sz); \
                                if (_htm_idx1 != _htm_idx3) {\
                                        auto _htm_extra_temp_ptr = (table)[_htm_idx1]; \
                                        (table)[_htm_idx1] = (table)[_htm_idx3]; \
                                        (table)[_htm_idx3] = _htm_extra_temp_ptr; \
                                        _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed, (int)(_htm_idx1 ^ _htm_idx3) + 1); \
                                } \
                        }\
                    } \
                    \
                    if (((unsigned int)_obf_global_opaque_seed ^ _htm_i) % 5 == 2) { \
                        OBF_BOGUS_FLOW_CASCADE(); \
                        if (_htm_i < _htm_outer_loop_count -1 ) _htm_i = OBF_MBA_ADD(_htm_i, 1U); else if (OBF_OPAQUE_PREDICATE_TRUE_1()) break; \
                    } \
                    if (OBF_OPAQUE_PREDICATE_FALSE_1()) { K8_ASSUME(0); break; }\
                    \
                    if (((_htm_idx1 + _htm_idx2) % 3) == 0 && OBF_OPAQUE_PREDICATE_TRUE_1()  || !OBF_OPAQUE_PREDICATE_TRUE_1()) { \
                        (vm_state_ref).r0 = OBF_MBA_XOR((vm_state_ref).r0, _htm_base_val1); \
                        (vm_state_ref).dispatch_key = OBF_MBA_ADD((vm_state_ref).dispatch_key, _htm_base_val2 ^ (unsigned int)_obf_global_opaque_seed); \
                    } \
                } \
                OBF_CALL_ANY_LOCAL_JUNK(); \
            } while (0)

    #pragma region OBF_CALSSMETHODS
    // --------------------------------------

            #include "../transform/PASSES/obf_cmethods.cxx"

            #define OBF_METHOD(ret_type, func_name, params, method_body) \
                                OBF_METHOD_(ret_type, func_name, params, method_body)

    // --------------------------------------
    #pragma endregion OBF_CALSSMETHODS

    #define _main(main_body) \
            int main(int argc = 0, char** argv = nullptr) { \
                OBF_BOGUS_FLOW_CYCLONE();\
                if (OBF_OPAQUE_PREDICATE_TRUE_1()  || !OBF_OPAQUE_PREDICATE_TRUE_1()) { OBF_BOGUS_FLOW_LABYRINTH(); }\
                OBF_BOGUS_FLOW_SCRAMBLE();\
                volatile unsigned int _d_seed = OBF_MBA_ADD((int)std::time(nullptr) ^ argc ^ (int)(__LINE__), _obf_global_opaque_seed ^ __COUNTER__); \
                _obf_global_opaque_seed = _d_seed; \
                OBF_FAKE_PROLOGUE_MANIP(); \
                OBF_STACK_AND_PROLOGUE_JUNK(_prologue_stack_junk_var1, 64 + (OBF_CALL_ANY_LOCAL_JUNK() & 63)); \
                OBF_STACK_AND_PROLOGUE_JUNK(_prologue_stack_junk_var2, 69 + (OBF_CALL_ANY_LOCAL_JUNK() & 68)); \
                OBF_STACK_AND_PROLOGUE_JUNK(_prologue_stack_junk_var3, 34 + (OBF_CALL_ANY_LOCAL_JUNK() & 44)); \
                OBF_STACK_AND_PROLOGUE_JUNK(_prologue_stack_junk_var4, 64 + (OBF_CALL_ANY_LOCAL_JUNK() & 32)); \
                obf_vm_engine::VMState vm_s(_obf_global_opaque_seed); \
                constexpr size_t VM_BYTECODE_LEN = 30; \
                std::array<unsigned int, VM_BYTECODE_LEN> _obf_vm_bytecode; \
                vm_s.r0 = (unsigned int)_obf_global_opaque_seed ^ (0xABCDEF01U + __LINE__); \
                vm_s.r1 = (unsigned int)(__TIME__[0] << 8) ^ __COUNTER__ ^ argc; \
                vm_s.r2 = (unsigned int)(argv ? (std::uintptr_t)argv[0] : __LINE__) ^ (0xBADF00DU + (unsigned int)__TIME__[2]); \
                vm_s.dispatch_key = (argc > 0 && argv != nullptr && argv[0] != nullptr) ? \
                                    OBF_MBA_ADD((unsigned int)argv[0][0], (unsigned int)((std::string(argv[0]).length() > 1 ? argv[0][1] : (char)__COUNTER__) ^ __COUNTER__)) : \
                                    (unsigned int)__COUNTER__; \
                OBF_FAKE_PROLOGUE_MANIP(); \
                vm_s.dispatch_key = (vm_s.dispatch_key == 0) ? (1u + (unsigned int)__TIME__[3]) : vm_s.dispatch_key; \
                vm_s.pc = ((unsigned int)__TIME__[4] ^ (unsigned int)_obf_global_opaque_seed) % VM_BYTECODE_LEN; \
                OBF_CHAINED_OBF_CALLS(vm_s, argc + 1);\
                volatile int _main_exit_choice = 0; \
                OBF_CONDITIONAL_EXIT(_main_exit_choice, 0, 1); \
                OBF_FAKE_PROLOGUE_MANIP(); \
                OBF_EXIT_CHOICE_DRIVES_CALL(vm_s, (int)(vm_s.pc % 10), _main_exit_choice, 0); \
                OBF_HEAVY_JUNK_OP(vm_s.r0, vm_s.r1 ^ (unsigned int)__LINE__); \
                obf_vm_engine::_seh_wrapped_vm_register_modification(vm_s, __LINE__ ^ (unsigned int)OBF_CALL_ANY_LOCAL_JUNK()); \
                for(size_t i_bc=0; i_bc < VM_BYTECODE_LEN; ++i_bc) { \
                    if ((i_bc % 5) == 0) { OBF_STACK_AND_ACCESS(32, i_bc % 32, (char)(i_bc ^ _obf_global_opaque_seed)); } \
                    unsigned int bc_val = ( (i_bc * (17U + (unsigned int)__TIME__[5])) + __COUNTER__ + (unsigned int)_obf_global_opaque_seed ); \
                    bc_val = OBF_MBA_XOR(bc_val, (unsigned int)__TIME__[i_bc % 8]); \
                    unsigned int encryption_key = OBF_MBA_ADD(0xDEADBEEFU, (i_bc * 0x101U) ^ (unsigned int)__LINE__); \
                    _obf_vm_bytecode[i_bc] = OBF_MBA_XOR(bc_val, encryption_key); \
                } \
                OBF_FAKE_PROLOGUE_MANIP(); \
                HANDLER_TABLE_MUTATE(obf_vm_engine::vm_handler_table, obf_vm_engine::VM_HANDLER_TABLE_SIZE, vm_s);\
                volatile unsigned int _vm_cipher_seed = 0x378829 ^ (unsigned int)__TIME__[5]; \
                for (size_t i_bc = 0; i_bc < VM_BYTECODE_LEN; ++i_bc) {\
                    if ((i_bc % 5) == 0) { OBF_STACK_AND_ACCESS(32, i_bc % 32, (char)(i_bc ^ _obf_global_opaque_seed)); } \
                        unsigned int bc_val = ((i_bc * (17U + (unsigned int)__TIME__[5])) + __COUNTER__ + (unsigned int)_obf_global_opaque_seed); \
                        bc_val = OBF_MBA_XOR(bc_val, (unsigned int)__TIME__[i_bc % 8]); \
                        unsigned int encryption_key = OBF_MBA_ADD(0xDEADBEEFU, (i_bc * 0x101U) ^ _vm_cipher_seed); \
                        _obf_vm_bytecode[i_bc] = OBF_MBA_XOR(bc_val, encryption_key); \
                } \
                HANDLER_TABLE_MUTATE(obf_vm_engine::vm_handler_table, obf_vm_engine::VM_HANDLER_TABLE_SIZE, vm_s); \
                int prologue_loop_iterations = (int)VM_BYTECODE_LEN + (((unsigned int)_obf_global_opaque_seed ^ vm_s.dispatch_key) % 7) + 5; \
                OBF_FAKE_PROLOGUE_MANIP(); \
                for (int iter_vm = 0; iter_vm < prologue_loop_iterations; ++iter_vm) {\
                    NOP();\
                    CALLER();\
                    unsigned int current_raw_bytecode = _obf_vm_bytecode[vm_s.pc % VM_BYTECODE_LEN]; \
                    unsigned int decryption_key = OBF_MBA_ADD(0xDEADBEEFU, ((vm_s.pc % VM_BYTECODE_LEN) * 0x101U) ^ _vm_cipher_seed); \
                    unsigned int handler_index = OBF_MBA_XOR(current_raw_bytecode, decryption_key) % obf_vm_engine::VM_HANDLER_TABLE_SIZE; \
                    if (OBF_OPAQUE_PREDICATE_TRUE_1() || !OBF_OPAQUE_PREDICATE_TRUE_1()) {\
                            vm_s.dispatch_key = OBF_MBA_XOR(vm_s.dispatch_key, vm_s.r0 + vm_s.r1 + (unsigned int)iter_vm + (unsigned int)__TIME__[(iter_vm + 1) % 8]); \
                            vm_s.dispatch_key = OBF_MBA_ADD(vm_s.dispatch_key, (vm_s.dispatch_key << ((iter_vm % 3) + 1)) | (vm_s.dispatch_key >> (32 - ((iter_vm % 3) + 1)))); \
                    }\
                    else {\
                        K8_ASSUME(0); \
                            vm_s.dispatch_key = OBF_MBA_SUB(vm_s.dispatch_key, 0xDEADDEADU); \
                    } \
                    vm_s.dispatch_key = (vm_s.dispatch_key == 0) ? ((unsigned int)iter_vm + 1u + (unsigned int)__COUNTER__) : vm_s.dispatch_key; \
                    obf_vm_engine::vm_handler_table[handler_index](vm_s, argc, argv); \
                    unsigned int pc_increment = (vm_s.r0 & 0x3U) + 1U; \
                    if (OBF_OPAQUE_PREDICATE_TRUE_2(vm_s.r1 ^ vm_s.dispatch_key)) {\
                        vm_s.pc = OBF_MBA_ADD(vm_s.pc, pc_increment); \
                    }\
                    else {\
                        K8_ASSUME(0); \
                        vm_s.pc = OBF_MBA_SUB(vm_s.pc, (vm_s.r2 & 0x1U) + 1U); \
                    } \
                    OBF_FAKE_PROLOGUE_MANIP(); \
                    vm_s.pc %= VM_BYTECODE_LEN; \
                    NOP(); \
                    if (iter_vm > 10 && OBF_OPAQUE_PREDICATE_FALSE_2(vm_s.r0 ^ vm_s.r1 ^ vm_s.r2)) { K8_ASSUME(0); break; } \
                    } \
                    \
                    int dsptch_steps = 5 + (((unsigned int)_obf_global_opaque_seed ^ vm_s.pc) % 5);\
                    vm_s.pc %= obf_vm_engine::HANDLER_COUNT; \
                    obf_vm_engine::dsptch(vm_s, argc, argv, (unsigned int)dsptch_steps); \
                    vm_s.pc %= VM_BYTECODE_LEN; \
                    \
                    volatile unsigned int _obf_direct_cff_seed = OBF_MBA_XOR(vm_s.r0, vm_s.dispatch_key ^ (unsigned int)__LINE__ ^ (unsigned int)__TIME__[6]); \
                    int direct_cff_loops = (((_obf_direct_cff_seed + (unsigned int)argc) % 4) + 5); \
               for (int i_dcff = 0; i_dcff < direct_cff_loops; ++i_dcff)\
               { \
                    NOP(); \
                    if ((i_dcff % 4) == 1) { \
                        obf_vm_engine::_seh_wrapped_vm_register_modification(vm_s, (_obf_direct_cff_seed >> (i_dcff % 24)) ^ (unsigned int)OBF_CALL_ANY_LOCAL_JUNK()); \
                    } \
                    OBF_FAKE_PROLOGUE_MANIP(); \
                    CALLER();\
                    unsigned int dcff_selector_val = (_obf_direct_cff_seed ^ (unsigned int)(i_dcff * (0x1F1F1F1FU + __COUNTER__)) ^ ((unsigned int)_obf_global_opaque_seed << ((i_dcff%2)+2))) % 10; \
                    _obf_global_opaque_seed = OBF_MBA_ADD(_obf_global_opaque_seed, (int)dcff_selector_val); \
                    \
                    OBF_FAKE_PROLOGUE_MANIP(); \
                    volatile unsigned int _icff_current_block_salt_dcff = __COUNTER__; \
                    volatile unsigned int _icff_current_block_encoded_dcff = OBF_ICFF_ENCODE_STATE_DCFF( \
                        _ObfICFF_BlockId_DCFF::BLOCK_INIT_SELECTOR, \
                        i_dcff, vm_s, _obf_global_opaque_seed, _icff_current_block_salt_dcff \
                    ); \
                    \
                    volatile bool _icff_run_dispatcher_dcff = true; \
                    unsigned int _icff_max_jumps_per_iter_dcff = 15 + (OBF_CALL_ANY_LOCAL_JUNK() & 0x0F); \
                    unsigned int _icff_jump_counter_dcff = 0; \
                    volatile unsigned int _icff_internal_dcff_selector = dcff_selector_val; \
                    \
                    while (_icff_run_dispatcher_dcff && _icff_jump_counter_dcff < _icff_max_jumps_per_iter_dcff) { \
                        _icff_jump_counter_dcff++; \
                        _ObfICFF_BlockId_DCFF _icff_decoded_block_dcff = OBF_ICFF_DECODE_STATE_DCFF( \
                            _icff_current_block_encoded_dcff, i_dcff, vm_s, _obf_global_opaque_seed, _icff_current_block_salt_dcff \
                        ); \
                        \
                        _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed, (int)_icff_decoded_block_dcff ^ (int)i_dcff ^ (int)_icff_internal_dcff_selector ^ OBF_CALL_ANY_LOCAL_JUNK()); \
                        unsigned int _icff_next_salt_dcff_val; \
                        OBF_FAKE_PROLOGUE_MANIP(); \
                        \
                        switch (_icff_decoded_block_dcff) { \
                            case _ObfICFF_BlockId_DCFF::BLOCK_INIT_SELECTOR: \
                                _icff_next_salt_dcff_val = __COUNTER__; \
                                _icff_current_block_encoded_dcff = OBF_ICFF_ENCODE_STATE_DCFF( \
                                    obf_icff_ns_dcff::_obf_icff_map_selector_to_block_id_dcff(_icff_internal_dcff_selector, _obf_global_opaque_seed), \
                                i_dcff, vm_s, _obf_global_opaque_seed, _icff_next_salt_dcff_val); \
                                _icff_current_block_salt_dcff = _icff_next_salt_dcff_val; \
                                OBF_FAKE_PROLOGUE_MANIP(); \
                                break; \
                            \
                            case _ObfICFF_BlockId_DCFF::BLOCK_CASE_0: \
                                vm_s.r0 = OBF_MBA_ADD(vm_s.r0, (unsigned int)(i_dcff ^ 0x1111U)); vm_s.r1 = OBF_MBA_XOR(vm_s.r1, vm_s.pc); \
                                _icff_next_salt_dcff_val = __COUNTER__; \
                                if (OBF_OPAQUE_PREDICATE_TRUE_1() || !OBF_OPAQUE_PREDICATE_TRUE_1()) { \
                                    _icff_current_block_encoded_dcff = OBF_ICFF_ENCODE_STATE_DCFF(_ObfICFF_BlockId_DCFF::BLOCK_COMMON_CONTINUE, i_dcff, vm_s, _obf_global_opaque_seed, _icff_next_salt_dcff_val); \
                                } else { K8_ASSUME(0); \
                                    _icff_current_block_encoded_dcff = OBF_ICFF_ENCODE_STATE_DCFF(_ObfICFF_BlockId_DCFF::BLOCK_CASE_3, i_dcff, vm_s, _obf_global_opaque_seed, _icff_next_salt_dcff_val); \
                                } \
                                _icff_current_block_salt_dcff = _icff_next_salt_dcff_val; \
                                break; \
                            \
                            case _ObfICFF_BlockId_DCFF::BLOCK_CASE_1: \
                                vm_s.dispatch_key = OBF_MBA_MUL_CONST3(OBF_MBA_ADD(vm_s.dispatch_key, (unsigned int)(i_dcff | 3U))); \
                                OBF_CALL_ANY_LOCAL_JUNK(); \
                                _icff_next_salt_dcff_val = __COUNTER__; \
                                if (OBF_OPAQUE_PREDICATE_TRUE_2(vm_s.dispatch_key ^ (unsigned int)i_dcff)) { \
                                    _icff_current_block_encoded_dcff = OBF_ICFF_ENCODE_STATE_DCFF(_ObfICFF_BlockId_DCFF::BLOCK_CASE_5, i_dcff, vm_s, _obf_global_opaque_seed, _icff_next_salt_dcff_val); \
                                } else { \
                                    _icff_current_block_encoded_dcff = OBF_ICFF_ENCODE_STATE_DCFF(_ObfICFF_BlockId_DCFF::BLOCK_CASE_2, i_dcff, vm_s, _obf_global_opaque_seed, _icff_next_salt_dcff_val); \
                                } \
                                _icff_current_block_salt_dcff = _icff_next_salt_dcff_val; \
                                break; \
                            \
                            case _ObfICFF_BlockId_DCFF::BLOCK_CASE_2: \
                                vm_s.r2 = OBF_MBA_SUB(((vm_s.r2 | (unsigned int)i_dcff) ^ (0xABCU + __LINE__)), 3U); \
                                _icff_next_salt_dcff_val = __COUNTER__; \
                                if (OBF_OPAQUE_PREDICATE_FALSE_1()) { K8_ASSUME(0); \
                                    _icff_current_block_encoded_dcff = OBF_ICFF_ENCODE_STATE_DCFF(_ObfICFF_BlockId_DCFF::BLOCK_INIT_SELECTOR, i_dcff, vm_s, _obf_global_opaque_seed, _icff_next_salt_dcff_val); \
                                } else { \
                                    _icff_current_block_encoded_dcff = OBF_ICFF_ENCODE_STATE_DCFF(_ObfICFF_BlockId_DCFF::BLOCK_COMMON_CONTINUE, i_dcff, vm_s, _obf_global_opaque_seed, _icff_next_salt_dcff_val); \
                                } \
                                _icff_current_block_salt_dcff = _icff_next_salt_dcff_val; \
                                break; \
                            \
                            case _ObfICFF_BlockId_DCFF::BLOCK_CASE_3: \
                                if (OBF_OPAQUE_PREDICATE_TRUE_1() || !OBF_OPAQUE_PREDICATE_TRUE_1()) vm_s.r0 = OBF_MBA_XOR(vm_s.r0, _obf_direct_cff_seed); else { K8_ASSUME(0); vm_s.r0 = OBF_MBA_ADD(vm_s.r0, vm_s.r1); } \
                                _icff_internal_dcff_selector = OBF_MBA_ADD(_icff_internal_dcff_selector,1U) % 10; \
                                _icff_next_salt_dcff_val = __COUNTER__; \
                                if(OBF_OPAQUE_PREDICATE_TRUE_2(_icff_internal_dcff_selector)) { \
                                    _icff_current_block_encoded_dcff = OBF_ICFF_ENCODE_STATE_DCFF(_ObfICFF_BlockId_DCFF::BLOCK_INIT_SELECTOR, i_dcff, vm_s, _obf_global_opaque_seed, _icff_next_salt_dcff_val); \
                                } else {K8_ASSUME(0); \
                                    _icff_current_block_encoded_dcff = OBF_ICFF_ENCODE_STATE_DCFF(_ObfICFF_BlockId_DCFF::BLOCK_COMMON_CONTINUE, i_dcff, vm_s, _obf_global_opaque_seed, _icff_next_salt_dcff_val); \
                                } \
                                _icff_current_block_salt_dcff = _icff_next_salt_dcff_val; \
                                break; \
                            \
                            case _ObfICFF_BlockId_DCFF::BLOCK_CASE_4: \
                                _obf_direct_cff_seed = OBF_MBA_ADD(_obf_direct_cff_seed, (vm_s.r0 ^ vm_s.r2)); vm_s.pc = (OBF_MBA_ADD(vm_s.pc, 2U) + 3U) % VM_BYTECODE_LEN; \
                                _icff_next_salt_dcff_val = __COUNTER__; \
                                _icff_current_block_encoded_dcff = OBF_ICFF_ENCODE_STATE_DCFF(_ObfICFF_BlockId_DCFF::BLOCK_COMMON_CONTINUE, i_dcff, vm_s, _obf_global_opaque_seed, _icff_next_salt_dcff_val); \
                                _icff_current_block_salt_dcff = _icff_next_salt_dcff_val; \
                                break; \
                            \
                            case _ObfICFF_BlockId_DCFF::BLOCK_CASE_5: \
                                vm_s.r1 = OBF_MBA_NOT(OBF_MBA_XOR(vm_s.r1, (unsigned int)OBF_CALL_ANY_LOCAL_JUNK())); \
                                _icff_next_salt_dcff_val = __COUNTER__; \
                                if (((unsigned int)_obf_global_opaque_seed ^ (unsigned int)i_dcff) % 3 == 0) { \
                                    _icff_current_block_encoded_dcff = OBF_ICFF_ENCODE_STATE_DCFF(_ObfICFF_BlockId_DCFF::BLOCK_CASE_0, i_dcff, vm_s, _obf_global_opaque_seed, _icff_next_salt_dcff_val); \
                                } else { \
                                    _icff_current_block_encoded_dcff = OBF_ICFF_ENCODE_STATE_DCFF(_ObfICFF_BlockId_DCFF::BLOCK_COMMON_CONTINUE, i_dcff, vm_s, _obf_global_opaque_seed, _icff_next_salt_dcff_val); \
                                } \
                                _icff_current_block_salt_dcff = _icff_next_salt_dcff_val; \
                                break; \
                            \
                            case _ObfICFF_BlockId_DCFF::BLOCK_CASE_6: \
                                if (OBF_OPAQUE_PREDICATE_TRUE_2(vm_s.dispatch_key)) vm_s.r0 = OBF_MBA_MUL_CONST_ALT(vm_s.r0, 2); else { K8_ASSUME(0); vm_s.r0 = OBF_MBA_XOR(vm_s.r0, 7U); } \
                                _icff_next_salt_dcff_val = __COUNTER__; \
                                _icff_current_block_encoded_dcff = OBF_ICFF_ENCODE_STATE_DCFF(_ObfICFF_BlockId_DCFF::BLOCK_EXIT_ICFF_LOOP, i_dcff, vm_s, _obf_global_opaque_seed, _icff_next_salt_dcff_val); \
                                _icff_current_block_salt_dcff = _icff_next_salt_dcff_val; \
                                break; \
                            \
                            case _ObfICFF_BlockId_DCFF::BLOCK_CASE_7: \
                                vm_s.r2 = (vm_s.r2 << 1) | (vm_s.r2 >> 31); _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed, (int)_obf_direct_cff_seed); \
                                _icff_next_salt_dcff_val = __COUNTER__; \
                                if (!OBF_OPAQUE_PREDICATE_FALSE_2(vm_s.r2)) { \
                                    _icff_current_block_encoded_dcff = OBF_ICFF_ENCODE_STATE_DCFF(_ObfICFF_BlockId_DCFF::BLOCK_CASE_1, i_dcff, vm_s, _obf_global_opaque_seed, _icff_next_salt_dcff_val); \
                                } else { K8_ASSUME(0); \
                                    _icff_current_block_encoded_dcff = OBF_ICFF_ENCODE_STATE_DCFF(_ObfICFF_BlockId_DCFF::BLOCK_EXIT_ICFF_LOOP, i_dcff, vm_s, _obf_global_opaque_seed, _icff_next_salt_dcff_val); \
                                } \
                                _icff_current_block_salt_dcff = _icff_next_salt_dcff_val; \
                                break; \
                            \
                            case _ObfICFF_BlockId_DCFF::BLOCK_CASE_8: \
                                vm_s.dispatch_key = OBF_MBA_ADD(vm_s.dispatch_key, OBF_MBA_SUB(vm_s.r0, vm_s.r1)); _obf_direct_cff_seed = OBF_MBA_NOT(_obf_direct_cff_seed); \
                                _icff_next_salt_dcff_val = __COUNTER__; \
                                _icff_current_block_encoded_dcff = OBF_ICFF_ENCODE_STATE_DCFF(_ObfICFF_BlockId_DCFF::BLOCK_COMMON_CONTINUE, i_dcff, vm_s, _obf_global_opaque_seed, _icff_next_salt_dcff_val); \
                                _icff_current_block_salt_dcff = _icff_next_salt_dcff_val; \
                                break; \
                            \
                            case _ObfICFF_BlockId_DCFF::BLOCK_CASE_9: \
                                vm_s.pc = OBF_MBA_XOR(vm_s.pc, (unsigned int)OBF_CALL_ANY_LOCAL_JUNK() ^ _obf_direct_cff_seed) % VM_BYTECODE_LEN; \
                                _icff_next_salt_dcff_val = __COUNTER__; \
                                _icff_current_block_encoded_dcff = OBF_ICFF_ENCODE_STATE_DCFF(_ObfICFF_BlockId_DCFF::BLOCK_EXIT_ICFF_LOOP, i_dcff, vm_s, _obf_global_opaque_seed, _icff_next_salt_dcff_val); \
                                _icff_current_block_salt_dcff = _icff_next_salt_dcff_val; \
                                break; \
                            \
                            case _ObfICFF_BlockId_DCFF::BLOCK_DEFAULT: \
                                NOP(); K8_ASSUME(0); \
                                _icff_next_salt_dcff_val = __COUNTER__; \
                                _icff_current_block_encoded_dcff = OBF_ICFF_ENCODE_STATE_DCFF(_ObfICFF_BlockId_DCFF::BLOCK_EXIT_ICFF_LOOP, i_dcff, vm_s, _obf_global_opaque_seed, _icff_next_salt_dcff_val); \
                                _icff_current_block_salt_dcff = _icff_next_salt_dcff_val; \
                                OBF_FAKE_PROLOGUE_MANIP(); \
                                break; \
                            \
                            case _ObfICFF_BlockId_DCFF::BLOCK_COMMON_CONTINUE: \
                                NOP(); \
                                _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed, (int)i_dcff ^ (int)vm_s.pc); \
                                _icff_next_salt_dcff_val = __COUNTER__; \
                                _icff_current_block_encoded_dcff = OBF_ICFF_ENCODE_STATE_DCFF(_ObfICFF_BlockId_DCFF::BLOCK_EXIT_ICFF_LOOP, i_dcff, vm_s, _obf_global_opaque_seed, _icff_next_salt_dcff_val); \
                                _icff_current_block_salt_dcff = _icff_next_salt_dcff_val; \
                                OBF_FAKE_PROLOGUE_MANIP(); \
                                break; \
                            \
                            case _ObfICFF_BlockId_DCFF::BLOCK_EXIT_ICFF_LOOP: \
                                _icff_run_dispatcher_dcff = false; \
                                break; \
                            \
                            case _ObfICFF_BlockId_DCFF::BLOCK_DECOY_A: \
                                OBF_CALL_ANY_LOCAL_JUNK(); vm_s.r1 = OBF_MBA_ADD(vm_s.r1, OBF_CALL_ANY_LOCAL_JUNK() ^ (unsigned int)i_dcff); \
                                 _icff_next_salt_dcff_val = __COUNTER__; \
                                if (OBF_OPAQUE_PREDICATE_TRUE_1() || !OBF_OPAQUE_PREDICATE_TRUE_1()) { \
                                   _icff_current_block_encoded_dcff = OBF_ICFF_ENCODE_STATE_DCFF( \
                                       (_ObfICFF_BlockId_DCFF)((OBF_CALL_ANY_LOCAL_JUNK() ^ _obf_global_opaque_seed ^ i_dcff) % (unsigned int)_ObfICFF_BlockId_DCFF::COUNT_DCFF), \
                                       i_dcff, vm_s, _obf_global_opaque_seed, _icff_next_salt_dcff_val); \
                                } else { \
                                   _icff_current_block_encoded_dcff = OBF_ICFF_ENCODE_STATE_DCFF(_ObfICFF_BlockId_DCFF::BLOCK_EXIT_ICFF_LOOP, i_dcff, vm_s, _obf_global_opaque_seed, _icff_next_salt_dcff_val); \
                                } \
                                _icff_current_block_salt_dcff = _icff_next_salt_dcff_val; \
                                break;\
                            case _ObfICFF_BlockId_DCFF::BLOCK_DECOY_B: \
                                vm_s.dispatch_key = OBF_MBA_NOT(vm_s.dispatch_key ^ (unsigned int)OBF_CALL_ANY_LOCAL_JUNK() ^ (unsigned int)i_dcff);\
                                 _icff_next_salt_dcff_val = __COUNTER__; \
                                if (OBF_OPAQUE_PREDICATE_TRUE_2(vm_s.r0)) { \
                                   _icff_current_block_encoded_dcff = OBF_ICFF_ENCODE_STATE_DCFF(_ObfICFF_BlockId_DCFF::BLOCK_CASE_4, i_dcff, vm_s, _obf_global_opaque_seed, _icff_next_salt_dcff_val); \
                                } else { \
                                   _icff_current_block_encoded_dcff = OBF_ICFF_ENCODE_STATE_DCFF(_ObfICFF_BlockId_DCFF::BLOCK_COMMON_CONTINUE, i_dcff, vm_s, _obf_global_opaque_seed, _icff_next_salt_dcff_val); \
                                } \
                                _icff_current_block_salt_dcff = _icff_next_salt_dcff_val; \
                                break;\
                            \
                            default: \
                                NOP(); K8_ASSUME(0); \
                                if (OBF_OPAQUE_PREDICATE_TRUE_1() || !OBF_OPAQUE_PREDICATE_TRUE_1()) obf_vm_engine::_seh_forced_exception_effect(vm_s); \
                                else Runtime(vm_s); \
                                _icff_run_dispatcher_dcff = false; \
                                break; \
                        } \
                    } \
                    if (_icff_jump_counter_dcff >= _icff_max_jumps_per_iter_dcff || _icff_jump_counter_dcff <= _icff_max_jumps_per_iter_dcff && !OBF_OPAQUE_PREDICATE_TRUE_1() || !OBF_OPAQUE_PREDICATE_TRUE_1()) { \
                         Runtime(vm_s); \
                    } \
                    \
                    OBF_STACK_AND_PROLOGUE_JUNK(_direct_cff_stack_junk_var2_x, 89 + (OBF_CALL_ANY_LOCAL_JUNK() & 81)); \
                    CALLER();\
                    OBF_FAKE_PROLOGUE_MANIP(); \
                    NOP(); \
                } \
                OBF_FAKE_PROLOGUE_MANIP(); \
                size_t g_bc; \
                for(g_bc=0; g_bc < VM_BYTECODE_LEN; ++g_bc){\
                        if ((g_bc % 5) == 0){ for(int ggg = 3; ggg <direct_cff_loops; ggg+=5){CALLER();CALLER();CALLER();} } else if(!((g_bc % 5) == 0)){ CALLER(); if(g_bc == 0){CALLER(); g_bc+=(unsigned int)OBF_CALL_ANY_LOCAL_JUNK() ^ (unsigned int)OBF_CALL_ANY_LOCAL_JUNK();} } else {CALLER(); g_bc = (OBF_CALL_ANY_LOCAL_JUNK() & 63) + (OBF_CALL_ANY_LOCAL_JUNK() & 68) - (OBF_CALL_ANY_LOCAL_JUNK() & 44) ^ (OBF_CALL_ANY_LOCAL_JUNK() & 32) << (OBF_CALL_ANY_LOCAL_JUNK() & 99);}\
                        CALLER();\
                }\
                OBF_BOGUS_FLOW_CASCADE();\
                Runtime(vm_s);\
                main_body\
                for(g_bc=0; g_bc < VM_BYTECODE_LEN; ++g_bc){ \
                        if ((g_bc % 5) == 0){ for(int ggg = 3; ggg <direct_cff_loops; ggg+=5){OBF_BOGUS_FLOW_GRID();CALLER();CALLER();CALLER();} } else if(!((g_bc % 5) == 0)){ CALLER(); if(g_bc == 0){CALLER(); g_bc+=(unsigned int)OBF_CALL_ANY_LOCAL_JUNK() ^ (unsigned int)OBF_CALL_ANY_LOCAL_JUNK();} } else {CALLER(); g_bc = (OBF_CALL_ANY_LOCAL_JUNK() & 63) + (OBF_CALL_ANY_LOCAL_JUNK() & 68) - (OBF_CALL_ANY_LOCAL_JUNK() & 44) ^ (OBF_CALL_ANY_LOCAL_JUNK() & 32) << (OBF_CALL_ANY_LOCAL_JUNK() & 99);}\
                        CALLER();\
                }\
                Runtime(vm_s);\
                OBF_BOGUS_FLOW_WEAVER();\
                volatile unsigned int epi_ = OBF_MBA_XOR(vm_s.r0, vm_s.r1 ^ (unsigned int)std::time(nullptr) ^ (unsigned int)__TIME__[7]); \
                epi_ = OBF_MBA_ADD(epi_, vm_s.r2 ^ vm_s.dispatch_key); \
                OBF_STACK_AND_PROLOGUE_JUNK(_epilogue_stack_junk, 32 + (epi_ & 31)); \
                OBF_HEAVY_JUNK_OP(epi_, (unsigned int)argc + 1u); \
                vm_s.r2 = epi_; \
                OBF_FAKE_PROLOGUE_MANIP(); \
                obf_vm_engine::_seh_wrapped_vm_register_modification(vm_s, vm_s.r2 ^ 0x0BFU); \
                epi_ = vm_s.r0; \
                int epilogue_direct_loops = (((unsigned int)_obf_global_opaque_seed ^ (unsigned int)__LINE__) % 5) + 6; \
                for(int i_epd = 0; i_epd < epilogue_direct_loops; ++i_epd) { \
                    HANDLER_TABLE_MUTATE(obf_vm_engine::vm_handler_table, obf_vm_engine::VM_HANDLER_TABLE_SIZE, vm_s); \
                    NOP(); \
                    if ((i_epd % 2) == 0) { OBF_CHAINED_OBF_CALLS(vm_s, i_epd + (OBF_CALL_ANY_LOCAL_JUNK() & 3)); } \
                    unsigned int epd_selector_val = (epi_ ^ (unsigned int)_obf_global_opaque_seed ^ (unsigned int)__COUNTER__ ^ (unsigned int)(i_epd * 0x7654321U)) % 8; \
                    _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed, (int)epd_selector_val ^ (int)epi_); \
                    \
                    volatile unsigned int _icff_current_block_salt_epd = __COUNTER__; \
                    volatile unsigned int _icff_current_block_encoded_epd = OBF_ICFF_ENCODE_STATE_EPD( \
                        _ObfICFF_BlockId_EPD::BLOCK_INIT_SELECTOR, \
                        i_epd, epi_, vm_s, _obf_global_opaque_seed, _icff_current_block_salt_epd \
                    ); \
                    \
                    volatile bool _icff_run_dispatcher_epd = true; \
                    unsigned int _icff_max_jumps_per_iter_epd = 12 + (OBF_CALL_ANY_LOCAL_JUNK() & 0x07); \
                    unsigned int _icff_jump_counter_epd = 0; \
                    volatile unsigned int _icff_internal_epd_selector = epd_selector_val; \
                    \
                    while (_icff_run_dispatcher_epd && _icff_jump_counter_epd < _icff_max_jumps_per_iter_epd) { \
                        _icff_jump_counter_epd++; \
                        _ObfICFF_BlockId_EPD _icff_decoded_block_epd = OBF_ICFF_DECODE_STATE_EPD( \
                            _icff_current_block_encoded_epd, i_epd, epi_, vm_s, _obf_global_opaque_seed, _icff_current_block_salt_epd \
                        ); \
                        \
                        _obf_global_opaque_seed = OBF_MBA_ADD(_obf_global_opaque_seed, (int)_icff_decoded_block_epd ^ (int)i_epd ^ (int)_icff_internal_epd_selector ^ (int)epi_ ^ OBF_CALL_ANY_LOCAL_JUNK()); \
                        unsigned int _icff_next_salt_epd_val; \
                        \
                        switch (_icff_decoded_block_epd) { \
                            case _ObfICFF_BlockId_EPD::BLOCK_INIT_SELECTOR: \
                                _icff_next_salt_epd_val = __COUNTER__; \
                                _icff_current_block_encoded_epd = OBF_ICFF_ENCODE_STATE_EPD( \
                                    obf_icff_ns_epd::_obf_icff_map_selector_to_block_id_epd(_icff_internal_epd_selector, _obf_global_opaque_seed), \
                                    i_epd, epi_, vm_s, _obf_global_opaque_seed, _icff_next_salt_epd_val); \
                                _icff_current_block_salt_epd = _icff_next_salt_epd_val; \
                                break; \
                            \
                            case _ObfICFF_BlockId_EPD::BLOCK_CASE_0: \
                                epi_ = OBF_MBA_ADD(epi_, (unsigned int)OBF_CALL_ANY_LOCAL_JUNK() ^ (unsigned int)i_epd); \
                                _icff_next_salt_epd_val = __COUNTER__; \
                                if (OBF_OPAQUE_PREDICATE_TRUE_1() || !OBF_OPAQUE_PREDICATE_TRUE_1()) { \
                                    _icff_current_block_encoded_epd = OBF_ICFF_ENCODE_STATE_EPD(_ObfICFF_BlockId_EPD::BLOCK_COMMON_CONTINUE, i_epd, epi_, vm_s, _obf_global_opaque_seed, _icff_next_salt_epd_val); \
                                } else { K8_ASSUME(0); \
                                    _icff_current_block_encoded_epd = OBF_ICFF_ENCODE_STATE_EPD(_ObfICFF_BlockId_EPD::BLOCK_CASE_4, i_epd, epi_, vm_s, _obf_global_opaque_seed, _icff_next_salt_epd_val); \
                                } \
                                _icff_current_block_salt_epd = _icff_next_salt_epd_val; \
                                break; \
                            \
                            case _ObfICFF_BlockId_EPD::BLOCK_CASE_1: \
                                epi_ = OBF_MBA_SUB(epi_, vm_s.pc + (unsigned int)__LINE__); \
                                _icff_next_salt_epd_val = __COUNTER__; \
                                if (!OBF_OPAQUE_PREDICATE_TRUE_2(epi_)) { K8_ASSUME(0); \
                                    _icff_current_block_encoded_epd = OBF_ICFF_ENCODE_STATE_EPD(_ObfICFF_BlockId_EPD::BLOCK_CASE_3, i_epd, epi_, vm_s, _obf_global_opaque_seed, _icff_next_salt_epd_val); \
                                } else { \
                                    _icff_current_block_encoded_epd = OBF_ICFF_ENCODE_STATE_EPD(_ObfICFF_BlockId_EPD::BLOCK_CASE_2, i_epd, epi_, vm_s, _obf_global_opaque_seed, _icff_next_salt_epd_val); \
                                } \
                                _icff_current_block_salt_epd = _icff_next_salt_epd_val; \
                                break; \
                            \
                            case _ObfICFF_BlockId_EPD::BLOCK_CASE_2: \
                                epi_ = OBF_MBA_XOR(epi_, vm_s.dispatch_key); \
                                if(OBF_OPAQUE_PREDICATE_TRUE_1() || !OBF_OPAQUE_PREDICATE_TRUE_1()) vm_s.r0 = OBF_MBA_XOR(vm_s.r0, epi_); else { K8_ASSUME(0); vm_s.r0 = OBF_MBA_ADD(vm_s.r0, epi_); } \
                                _icff_next_salt_epd_val = __COUNTER__; \
                                _icff_current_block_encoded_epd = OBF_ICFF_ENCODE_STATE_EPD(_ObfICFF_BlockId_EPD::BLOCK_COMMON_CONTINUE, i_epd, epi_, vm_s, _obf_global_opaque_seed, _icff_next_salt_epd_val); \
                                _icff_current_block_salt_epd = _icff_next_salt_epd_val; \
                                break; \
                            \
                            case _ObfICFF_BlockId_EPD::BLOCK_CASE_3: \
                                epi_ = OBF_MBA_NOT(epi_); vm_s.r1 = OBF_MBA_ADD(vm_s.r1, epi_); \
                                _icff_internal_epd_selector = OBF_MBA_ADD(_icff_internal_epd_selector, 2U) % 8; \
                                _icff_next_salt_epd_val = __COUNTER__; \
                                if (OBF_OPAQUE_PREDICATE_TRUE_1() || !OBF_OPAQUE_PREDICATE_TRUE_1()) { \
                                    _icff_current_block_encoded_epd = OBF_ICFF_ENCODE_STATE_EPD(_ObfICFF_BlockId_EPD::BLOCK_INIT_SELECTOR, i_epd, epi_, vm_s, _obf_global_opaque_seed, _icff_next_salt_epd_val); \
                                } else { \
                                     _icff_current_block_encoded_epd = OBF_ICFF_ENCODE_STATE_EPD(_ObfICFF_BlockId_EPD::BLOCK_CASE_4, i_epd, epi_, vm_s, _obf_global_opaque_seed, _icff_next_salt_epd_val); \
                                } \
                                _icff_current_block_salt_epd = _icff_next_salt_epd_val; \
                                break; \
                            \
                            case _ObfICFF_BlockId_EPD::BLOCK_CASE_4: \
                                epi_ = (epi_ << ((i_epd%2)+1)) | (epi_ >> (32-((i_epd%2)+1))); OBF_CALL_ANY_LOCAL_JUNK(); \
                                _icff_next_salt_epd_val = __COUNTER__; \
                                if (((unsigned int)_obf_global_opaque_seed ^ (unsigned int)i_epd) % 4 == 0) { \
                                    _icff_current_block_encoded_epd = OBF_ICFF_ENCODE_STATE_EPD(_ObfICFF_BlockId_EPD::BLOCK_CASE_0, i_epd, epi_, vm_s, _obf_global_opaque_seed, _icff_next_salt_epd_val); \
                                } else { \
                                    _icff_current_block_encoded_epd = OBF_ICFF_ENCODE_STATE_EPD(_ObfICFF_BlockId_EPD::BLOCK_EXIT_ICFF_LOOP, i_epd, epi_, vm_s, _obf_global_opaque_seed, _icff_next_salt_epd_val); \
                                } \
                                _icff_current_block_salt_epd = _icff_next_salt_epd_val; \
                                break; \
                            \
                            case _ObfICFF_BlockId_EPD::BLOCK_CASE_5: \
                                vm_s.r2 = OBF_MBA_XOR(vm_s.r2, epi_ + (unsigned int)argc); \
                                _icff_next_salt_epd_val = __COUNTER__; \
                                _icff_current_block_encoded_epd = OBF_ICFF_ENCODE_STATE_EPD(_ObfICFF_BlockId_EPD::BLOCK_COMMON_CONTINUE, i_epd, epi_, vm_s, _obf_global_opaque_seed, _icff_next_salt_epd_val); \
                                _icff_current_block_salt_epd = _icff_next_salt_epd_val; \
                                break; \
                            \
                            case _ObfICFF_BlockId_EPD::BLOCK_CASE_6: \
                                vm_s.dispatch_key = OBF_MBA_ADD(vm_s.dispatch_key, epi_ ^ vm_s.pc); _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed, (int)vm_s.r0); \
                                _icff_next_salt_epd_val = __COUNTER__; \
                                _icff_current_block_encoded_epd = OBF_ICFF_ENCODE_STATE_EPD(_ObfICFF_BlockId_EPD::BLOCK_EXIT_ICFF_LOOP, i_epd, epi_, vm_s, _obf_global_opaque_seed, _icff_next_salt_epd_val); \
                                _icff_current_block_salt_epd = _icff_next_salt_epd_val; \
                                break; \
                            \
                            case _ObfICFF_BlockId_EPD::BLOCK_CASE_7: \
                                epi_ = OBF_MBA_MUL_CONST3(epi_) ^ (unsigned int)OBF_CALL_ANY_LOCAL_JUNK(); NOP(); \
                                _icff_next_salt_epd_val = __COUNTER__; \
                                if (OBF_OPAQUE_PREDICATE_TRUE_2(epi_)) { \
                                    _icff_current_block_encoded_epd = OBF_ICFF_ENCODE_STATE_EPD(_ObfICFF_BlockId_EPD::BLOCK_CASE_1, i_epd, epi_, vm_s, _obf_global_opaque_seed, _icff_next_salt_epd_val); \
                                } else { K8_ASSUME(0); \
                                    _icff_current_block_encoded_epd = OBF_ICFF_ENCODE_STATE_EPD(_ObfICFF_BlockId_EPD::BLOCK_COMMON_CONTINUE, i_epd, epi_, vm_s, _obf_global_opaque_seed, _icff_next_salt_epd_val); \
                                } \
                                _icff_current_block_salt_epd = _icff_next_salt_epd_val; \
                                break; \
                            \
                            case _ObfICFF_BlockId_EPD::BLOCK_DEFAULT: \
                                K8_ASSUME(0); \
                                _icff_next_salt_epd_val = __COUNTER__; \
                                _icff_current_block_encoded_epd = OBF_ICFF_ENCODE_STATE_EPD(_ObfICFF_BlockId_EPD::BLOCK_EXIT_ICFF_LOOP, i_epd, epi_, vm_s, _obf_global_opaque_seed, _icff_next_salt_epd_val); \
                                _icff_current_block_salt_epd = _icff_next_salt_epd_val; \
                                break; \
                            \
                            case _ObfICFF_BlockId_EPD::BLOCK_COMMON_CONTINUE: \
                                NOP(); \
                                epi_ = OBF_MBA_ADD(epi_, (unsigned int)i_epd ^ vm_s.dispatch_key); \
                                _icff_next_salt_epd_val = __COUNTER__; \
                                _icff_current_block_encoded_epd = OBF_ICFF_ENCODE_STATE_EPD(_ObfICFF_BlockId_EPD::BLOCK_EXIT_ICFF_LOOP, i_epd, epi_, vm_s, _obf_global_opaque_seed, _icff_next_salt_epd_val); \
                                _icff_current_block_salt_epd = _icff_next_salt_epd_val; \
                                break; \
                            \
                            case _ObfICFF_BlockId_EPD::BLOCK_EXIT_ICFF_LOOP: \
                                _icff_run_dispatcher_epd = false; \
                                break; \
                            \
                            case _ObfICFF_BlockId_EPD::BLOCK_DECOY_A: \
                                 OBF_CALL_ANY_LOCAL_JUNK(); epi_ = OBF_MBA_XOR(epi_, (unsigned int)i_epd + (unsigned int)OBF_CALL_ANY_LOCAL_JUNK()); \
                                 _icff_next_salt_epd_val = __COUNTER__; \
                                if (OBF_OPAQUE_PREDICATE_TRUE_1() || !OBF_OPAQUE_PREDICATE_TRUE_1()) { \
                                   _icff_current_block_encoded_epd = OBF_ICFF_ENCODE_STATE_EPD( \
                                       (_ObfICFF_BlockId_EPD)((OBF_CALL_ANY_LOCAL_JUNK() ^ _obf_global_opaque_seed ^ i_epd ^ epi_) % (unsigned int)_ObfICFF_BlockId_EPD::COUNT_EPD), \
                                       i_epd, epi_, vm_s, _obf_global_opaque_seed, _icff_next_salt_epd_val); \
                                } else { \
                                   _icff_current_block_encoded_epd = OBF_ICFF_ENCODE_STATE_EPD(_ObfICFF_BlockId_EPD::BLOCK_EXIT_ICFF_LOOP, i_epd, epi_, vm_s, _obf_global_opaque_seed, _icff_next_salt_epd_val); \
                                } \
                                _icff_current_block_salt_epd = _icff_next_salt_epd_val; \
                                break;\
                            case _ObfICFF_BlockId_EPD::BLOCK_DECOY_B: \
                                 vm_s.r2 = OBF_MBA_XOR(vm_s.r2, (unsigned int)OBF_CALL_ANY_LOCAL_JUNK() ^ (unsigned int)i_epd ^ epi_); \
                                 _icff_next_salt_epd_val = __COUNTER__; \
                                if (OBF_OPAQUE_PREDICATE_FALSE_1()) { \
                                    K8_ASSUME(0); \
                                   _icff_current_block_encoded_epd = OBF_ICFF_ENCODE_STATE_EPD(_ObfICFF_BlockId_EPD::BLOCK_CASE_0, i_epd, epi_, vm_s, _obf_global_opaque_seed, _icff_next_salt_epd_val); \
                                } else { \
                                   _icff_current_block_encoded_epd = OBF_ICFF_ENCODE_STATE_EPD(_ObfICFF_BlockId_EPD::BLOCK_COMMON_CONTINUE, i_epd, epi_, vm_s, _obf_global_opaque_seed, _icff_next_salt_epd_val); \
                                } \
                                _icff_current_block_salt_epd = _icff_next_salt_epd_val; \
                                break;\
                            \
                            default: \
                                NOP(); K8_ASSUME(0); \
                                if (OBF_OPAQUE_PREDICATE_TRUE_2(epi_)) obf_vm_engine::_seh_forced_exception_effect(vm_s); \
                                else Runtime(vm_s); \
                                _icff_run_dispatcher_epd = false; \
                                break; \
                        } \
                    } \
                    if (_icff_jump_counter_epd >= _icff_max_jumps_per_iter_epd && OBF_OPAQUE_PREDICATE_TRUE_1() || !OBF_OPAQUE_PREDICATE_TRUE_1()) { \
                         Runtime(vm_s); \
                    } \
                    CALLER();\
                    _obf_global_opaque_seed = OBF_MBA_ADD(_obf_global_opaque_seed, (int)(epi_ ^ (unsigned int)i_epd ^ vm_s.dispatch_key)); \
                } \
                unsigned int ret_val_temp; \
                unsigned int ret = 0;\
                OBF_PREPARE_OBF_RETURN(OBF_MBA_XOR(vm_s.r0, vm_s.r1), ret_val_temp); \
                ret = ret_val_temp; \
                ret = OBF_MBA_ADD(ret, vm_s.r2 ^ vm_s.dispatch_key); \
                ret = OBF_MBA_SUB(ret, vm_s.pc + (unsigned int)_obf_global_opaque_seed); \
                ret = OBF_MBA_XOR(ret, epi_ ^ (unsigned int)__COUNTER__); \
                if (((ret ^ (unsigned int)__LINE__) & 0xFFFFU) == ((0xBADC0DEU + (unsigned int)__TIME__[0]) & 0xFFFFU)) { \
                     CALLER(); \
                } else {\
                     CALLER(); \
                }\
                return (int)(ret & 0xFF) ^ (int)((0x0B8FU & 0x0B8FU) ^ (unsigned int)__LINE__); \
            }
    
    // --------------------------------------
    
    #pragma endregion MAIN_FLATTENING
OPT

