#pragma once

#include <array>
#include <string>
#include <ctime>
#include <cstdint>
#include <random>
#include <type_traits>
#include <functional>
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
                _obf_global_opaque_seed = (_obf_global_opaque_seed ^ __obf_nop_val ^ (int)time(nullptr)); \
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

        #define OBF_JUNK_BODY_1 \
            volatile int x_jb = __COUNTER__ + 11 + _obf_global_opaque_seed; \
            x_jb ^= (0xDEADBEEFU + (int)__TIME__[0]); \
            x_jb += (int)time(nullptr); \
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
            volatile int x_jb5 = (((int)time(nullptr) ^ _obf_global_opaque_seed + __COUNTER__) % 7); \
            if (x_jb5 == 0) x_jb5 = 1; \
            x_jb5 = (x_jb5 * 13) + 71; \
            return x_jb5;

        #define OBF_JUNK_BODY_6 \
            volatile int x_jb = (int)time(nullptr) ^ (_obf_global_opaque_seed * __COUNTER__); \
            int z = ((x_jb & 0xFF) * 0x1F1F1F1F) ^ (__COUNTER__ + _obf_global_opaque_seed); \
            x_jb = z ^ (x_jb << 2); \
            x_jb ^= ((int)__TIME__[2] | (int)__TIME__[3]); \
            return x_jb;

        #define OBF_JUNK_BODY_7 \
            volatile int x_jb = ((int)time(nullptr) + _obf_global_opaque_seed + __COUNTER__) ^ 0x0F0F0F0F; \
            x_jb = ((x_jb << 3) | (x_jb >> 29)) ^ (int)__LINE__; \
            return x_jb;

        #define OBF_JUNK_BODY_8 \
            volatile uint64_t _tsc8 = __rdtsc(); \
            volatile int x_jb8 = (int)((_tsc8 ^ (uint64_t)_obf_global_opaque_seed) & 0xFFFFFFFFULL); \
            x_jb8 ^= (int)(__COUNTER__ * 0x6B2F5D1U); \
            return x_jb8;

        #define OBF_JUNK_BODY_9 \
            volatile uintptr_t _sp9 = (uintptr_t)_AddressOfReturnAddress(); \
            volatile int x_jb9 = (int)(_sp9 & 0xFFFFU) ^ _obf_global_opaque_seed ^ (int)__COUNTER__; \
            x_jb9 = ((x_jb9 << 7) | (x_jb9 >> 25)) ^ (int)__LINE__; \
            return x_jb9;

        #define OBF_JUNK_BODY_10 \
            volatile int _tid10 = (int)GetCurrentThreadId(); \
            volatile int x_jb10 = (_tid10 ^ _obf_global_opaque_seed) * (int)(__COUNTER__ | 1); \
            x_jb10 ^= (int)time(nullptr) & 0xFFFF; \
            return x_jb10;

        #define OBF_JUNK_BODY_11 \
            typedef int(*_jfp11_t)(); \
            volatile _jfp11_t _fp11 = []() -> int { \
                return (int)__COUNTER__ ^ (int)time(nullptr); \
            }; \
            uintptr_t _sc11 = (uintptr_t)__COUNTER__ ^ (uintptr_t)_obf_global_opaque_seed; \
            volatile _jfp11_t* _fpp11 = &_fp11; \
            _fp11 = (_jfp11_t)((uintptr_t)_fp11 ^ _sc11); \
            _fp11 = (_jfp11_t)((uintptr_t)_fp11 ^ _sc11); \
            return (*_fpp11)();

        #define OBF_JUNK_BODY_12 \
            volatile unsigned int _h12 = (unsigned int)_obf_global_opaque_seed ^ (unsigned int)__COUNTER__; \
            _h12 = (_h12 ^ 0xDEADBEEFU) + (_h12 << 4); \
            _h12 = _h12 ^ (_h12 >> 10); \
            _h12 = _h12 + (_h12 << 7); \
            _h12 = _h12 ^ (_h12 >> 13); \
            return (int)_h12;

        #define OBF_JUNK_BODY_13 \
            function<int()> _fn13 = [&]() -> int { \
                return (int)__COUNTER__ ^ _obf_global_opaque_seed ^ (int)time(nullptr); \
            }; \
            volatile uintptr_t _sfn13_addr = (uintptr_t)&_fn13; \
            function<int()>* _sfn13 = \
                (function<int()>*)(uintptr_t)_sfn13_addr; \
            return (*_sfn13)();

        #define OBF_JUNK_BODY_14 \
            volatile unsigned int _r14 = (unsigned int)__COUNTER__ ^ (unsigned int)_obf_global_opaque_seed; \
            unsigned int _sh14 = (unsigned int)__TIME__[3] & 0x1FU; \
            _r14 = (_r14 << _sh14) | (_r14 >> (32U - _sh14)); \
            _r14 ^= (unsigned int)(uintptr_t)_AddressOfReturnAddress() & 0xFFFFU; \
            _r14 *= 0x9E3779B1U; \
            return (int)(_r14 ^ (unsigned int)__LINE__);

        #define OBF_DECLARE_JUNK_FUNC(N, body) K8_FORCEINLINE static int obf_junk_func_##N() { body }

        namespace obf_junk_ns {
            OBF_DECLARE_JUNK_FUNC(1,  OBF_JUNK_BODY_1)
            OBF_DECLARE_JUNK_FUNC(2,  OBF_JUNK_BODY_2)
            OBF_DECLARE_JUNK_FUNC(3,  OBF_JUNK_BODY_3)
            OBF_DECLARE_JUNK_FUNC(4,  OBF_JUNK_BODY_4)
            OBF_DECLARE_JUNK_FUNC(5,  OBF_JUNK_BODY_5)
            OBF_DECLARE_JUNK_FUNC(6,  OBF_JUNK_BODY_6)
            OBF_DECLARE_JUNK_FUNC(7,  OBF_JUNK_BODY_7)
            OBF_DECLARE_JUNK_FUNC(8,  OBF_JUNK_BODY_8)
            OBF_DECLARE_JUNK_FUNC(9,  OBF_JUNK_BODY_9)
            OBF_DECLARE_JUNK_FUNC(10, OBF_JUNK_BODY_10)
            OBF_DECLARE_JUNK_FUNC(11, OBF_JUNK_BODY_11)
            OBF_DECLARE_JUNK_FUNC(12, OBF_JUNK_BODY_12)
            OBF_DECLARE_JUNK_FUNC(13, OBF_JUNK_BODY_13)
            OBF_DECLARE_JUNK_FUNC(14, OBF_JUNK_BODY_14)
            OBF_DECLARE_JUNK_FUNC(15, OBF_JUNK_BODY_1)
            OBF_DECLARE_JUNK_FUNC(16, OBF_JUNK_BODY_2)
            OBF_DECLARE_JUNK_FUNC(17, OBF_JUNK_BODY_3)
            OBF_DECLARE_JUNK_FUNC(18, OBF_JUNK_BODY_8)
            OBF_DECLARE_JUNK_FUNC(19, OBF_JUNK_BODY_9)
            OBF_DECLARE_JUNK_FUNC(20, OBF_JUNK_BODY_10)
            OBF_DECLARE_JUNK_FUNC(21, OBF_JUNK_BODY_11)
            OBF_DECLARE_JUNK_FUNC(22, OBF_JUNK_BODY_12)
            OBF_DECLARE_JUNK_FUNC(23, OBF_JUNK_BODY_13)
            OBF_DECLARE_JUNK_FUNC(24, OBF_JUNK_BODY_14)
            OBF_DECLARE_JUNK_FUNC(25, OBF_JUNK_BODY_4)
            OBF_DECLARE_JUNK_FUNC(26, OBF_JUNK_BODY_5)
            OBF_DECLARE_JUNK_FUNC(27, OBF_JUNK_BODY_6)
            OBF_DECLARE_JUNK_FUNC(28, OBF_JUNK_BODY_7)

            using obf_junk_func_ptr = int(*)();
            static obf_junk_func_ptr obf_junk_func_table[] = {
                obf_junk_func_1,  obf_junk_func_2,  obf_junk_func_3,  obf_junk_func_4,
                obf_junk_func_5,  obf_junk_func_6,  obf_junk_func_7,  obf_junk_func_8,
                obf_junk_func_9,  obf_junk_func_10, obf_junk_func_11, obf_junk_func_12,
                obf_junk_func_13, obf_junk_func_14, obf_junk_func_15, obf_junk_func_16,
                obf_junk_func_17, obf_junk_func_18, obf_junk_func_19, obf_junk_func_20,
                obf_junk_func_21, obf_junk_func_22, obf_junk_func_23, obf_junk_func_24,
                obf_junk_func_25, obf_junk_func_26, obf_junk_func_27, obf_junk_func_28
            };
            constexpr unsigned int obf_junk_func_table_size =
                (unsigned int)(sizeof(obf_junk_func_table)/sizeof(obf_junk_func_ptr));
        }

        #define OBF_CALL_ANY_LOCAL_JUNK() \
            (obf_junk_ns::obf_junk_func_table[ \
                (unsigned int)(((_obf_global_opaque_seed ^ __COUNTER__ ^ \
                 (int)time(nullptr) ^ (int)__LINE__) & 0x7FFFFFFF) \
                 % obf_junk_ns::obf_junk_func_table_size) \
            ]())

        template<unsigned int X> struct K8_XS32 {
            static constexpr unsigned int s1 = X ^ (X << 13u);
            static constexpr unsigned int s2 = s1 ^ (s1 >> 17u);
            static constexpr unsigned int value = s2 ^ (s2 << 5u);
        };

        template<unsigned int SEED, unsigned int BASE>
        struct K8_SC {
            static constexpr unsigned int value = BASE ^ SEED;
        };

        namespace k8_sink_ns {
            static volatile unsigned int k8_sink[64];
        }

        template<unsigned int SEED>
        K8_NOINLINE static void k8_fake_rc4_sched() {
            volatile unsigned char S[16];
            unsigned int k = K8_SC<SEED,0x61626364u>::value;
            for(int i=0; i < 16; ++i)
                S[i] = (unsigned char)(i ^ (k >> i));
            unsigned int j = 0;
            for(int i2 = 0; i2 < 16; ++i2){
                j = (j + S[i2] + (k >> (i2 & 7))) & 0xFu;
                unsigned char t = S[i2]; S[i2] = S[j]; S[j] = t;
            }
            k8_sink_ns::k8_sink[SEED&63u]^=(unsigned int)S[0]^K8_SC<SEED,0xFEED0000u>::value;
            _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed,(int)k8_sink_ns::k8_sink[SEED&63u]);
        }

        template<unsigned int SEED>
        K8_NOINLINE static void k8_fake_murmur3() {
            volatile unsigned int h = K8_SC<SEED, 0x9747B28Cu>::value^(unsigned int)_obf_global_opaque_seed;
            volatile unsigned int k2 = K8_SC<SEED, 0xCC9E2D51u>::value;
            k2 *= 0x1B873593u; k2 = (k2 << 15) | (k2 >> 17); k2 *= 0x85EBCA6Bu;
            h ^= k2; h = (h << 13) | (h >> 19);
            h = h * 5u + K8_SC<SEED, 0xE6546B64u>::value;
            h ^= h >> 16;
            h *= K8_SC<SEED, 0x85EBCA6Bu>::value;
            h ^= h >> 13;
            h *= K8_SC<SEED, 0xC2B2AE35u>::value;
            h ^= h >> 16;
            k8_sink_ns::k8_sink[(SEED >> 4) & 63u] += h;
            _obf_global_opaque_seed = OBF_MBA_ADD(_obf_global_opaque_seed, (int)h);
        }

        template<unsigned int SEED>
        K8_NOINLINE static void k8_fake_fnv1a() {
            volatile unsigned int h = 0x811C9DC5u ^ K8_SC<SEED, 0u>::value;
            for(int i=0;i<8;++i){
                unsigned char b=(unsigned char)((SEED>>(i*4))^K8_SC<SEED,0xA5u>::value);
                h=(h^b)*0x01000193u;
            }
            k8_sink_ns::k8_sink[(SEED>>8)&63u]^=h;
            _obf_global_opaque_seed=OBF_MBA_XOR(_obf_global_opaque_seed,(int)h);
        }

        template<unsigned int SEED>
        K8_NOINLINE static void k8_fake_crc32() {
            volatile unsigned int crc = 0xFFFFFFFFu ^ K8_SC<SEED, 0xDEAD0000u>::value;
            for(int i = 0 ; i < 8; ++i){
                unsigned char byte = (unsigned char)(SEED >> (i * 3));
                crc ^= (unsigned int)byte;
                for(int b2 = 0; b2 < 8;++b2)
                    crc = (crc >> 1) ^ (0xEDB88320u & (unsigned int)(0u - (crc & 1u)));
            }
            crc ^= 0xFFFFFFFFu;
            k8_sink_ns::k8_sink[(SEED >> 12) & 63u] += crc;
            _obf_global_opaque_seed=OBF_MBA_SUB(_obf_global_opaque_seed,(int)crc);
        }

        template<unsigned int SEED>
        K8_NOINLINE static void k8_fake_aes_sbox() {
            constexpr unsigned int _c0 = K8_SC<SEED,0x52096AD5u>::value;
            constexpr unsigned int _c1 = K8_SC<SEED,0x63636363u>::value;
            constexpr unsigned int _c2 = K8_SC<SEED,0x05050505u>::value;
            volatile unsigned int state[4];
            for(int i = 0; i < 4; ++i)
                state[i] = _c0 ^ ((unsigned int)i * 0x9E3779B9u);
            for(int r = 0; r < 4; ++r){
                unsigned int x = state[r];
                x = OBF_MBA_XOR(x, _c1);
                x = (x << 1) | (x >> 31);
                x ^= _c2;
                state[r] = x;
            }
            unsigned int out = state[0] ^ state[1] ^ state[2] ^ state[3];
            k8_sink_ns::k8_sink[(SEED >> 16) & 63u] ^= out;
            _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed, (int)out);
        }

        template<unsigned int SEED>
        K8_NOINLINE static void k8_fake_str_scan() {
            static const volatile char _buf[16] = {
                (char)(SEED & 0xFF), (char)((SEED >> 8) & 0xFF),
                (char)((SEED >> 16) & 0xFF),(char)((SEED >> 24) & 0xFF),
                'O', 'b', 'f', 'u', 's', 'k', '8', 0, 0, 0, 0, 0
            };
            volatile int len = 0;
            const volatile char* p = _buf;
            while(*p && len < 16)
            {
                ++p;
                ++len;
            }
            k8_sink_ns::k8_sink[(SEED >> 20) & 63u] += (unsigned int)len ^ K8_SC<SEED, 0xABCDu>::value;
            _obf_global_opaque_seed = OBF_MBA_ADD(_obf_global_opaque_seed, len ^ (int)__LINE__);
        }

        template<unsigned int SEED>
        K8_NOINLINE static void k8_fake_bitpack() {
            volatile unsigned int packed=0u;
            unsigned int fields[4] = {
                K8_SC<SEED, 0x1Fu>::value & 0x1Fu,
                K8_SC<SEED, 0x3Eu>::value & 0x3Fu,
                K8_SC<SEED, 0x7Du>::value & 0x7Fu,
                K8_SC<SEED, 0xFCu>::value & 0xFFu
            };
            packed |= (fields[0] & 0x1Fu);
            packed |= (fields[1] & 0x3Fu) << 5;
            packed |= (fields[2] & 0x7Fu) << 11;
            packed |= (fields[3] & 0xFFu) << 18;
            unsigned int a = (packed >> 0) & 0x1Fu;
            unsigned int b2 = (packed >> 5) & 0x3Fu;
            (void)a;
            (void)b2;
            k8_sink_ns::k8_sink[(SEED >> 3) & 63u] ^= packed;
            _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed, (int)packed);
        }

        template<unsigned int SEED>
        K8_NOINLINE static void k8_fake_memchk() {
            volatile unsigned int buf[8];
            for(int i = 0; i < 8; ++i)
                buf[i] = K8_SC<SEED, 0xDEADBEEFu>::value ^ ((unsigned int) i * 0x6B2F5D1u);
            volatile unsigned int sum = 0u;
            for(int i = 0; i < 8; ++i)
                sum = OBF_MBA_ADD(sum, buf[i]);
            sum ^= K8_SC<SEED,0x5A5A5A5Au>::value;
            k8_sink_ns::k8_sink[(SEED >> 6) & 63u] += sum;
            _obf_global_opaque_seed = OBF_MBA_ADD(_obf_global_opaque_seed, (int)sum);
        }

        template<unsigned int SEED>
        K8_NOINLINE static void k8_fake_lfsr() {
            volatile unsigned int reg = K8_SC<SEED, 0xACE1u>::value;
            volatile unsigned int taps = K8_SC<SEED, 0xB400u>::value;
            for(int i = 0; i < 16; ++i){
                unsigned int lsb=reg&1u;
                reg >>= 1;
                if(lsb)
                    reg ^= taps;
            }
            k8_sink_ns::k8_sink[(SEED >> 9) & 63u] ^= reg;
            _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed, (int)reg);
        }

        template<unsigned int SEED>
        K8_NOINLINE static void k8_fake_wang() {
            volatile unsigned int h=K8_SC<SEED,0x9E3779B9u>::value
                                   ^ (unsigned int)_obf_global_opaque_seed;
            h = (h ^ 0xDEADBEEFu) + (h << 4);
            h ^= h >> 10;
            h += (h << 7);
            h ^= h >> 13;
            h += K8_SC<SEED,0x165667B1u>::value;
            h ^= h >> 16;
            h *= K8_SC<SEED, 0x45D9F3Bu>::value;
            h ^= h >> 16;
            k8_sink_ns::k8_sink[(SEED >> 11) & 63u] += h;
            _obf_global_opaque_seed=OBF_MBA_XOR(_obf_global_opaque_seed, (int)h);
        }

        template<unsigned int SEED>
        K8_NOINLINE static void k8_fake_rol_chain() {
            volatile unsigned int v=K8_SC<SEED,0x12345678u>::value;
            for(int i=0;i<8;++i){
                unsigned int r=(K8_SC<SEED,0x1Fu>::value^(unsigned int)i)&0x1Fu;
                if(r==0) r=7u;
                v=(v<<r)|(v>>(32u-r));
                v^=K8_SC<K8_XS32<SEED>::value,0xCAFEBABEu>::value;
            }
            k8_sink_ns::k8_sink[(SEED>>14)&63u]^=v;
            _obf_global_opaque_seed=OBF_MBA_XOR(_obf_global_opaque_seed,(int)v);
        }

        template<unsigned int SEED>
        K8_NOINLINE static void k8_fake_xor_ladder() {
            constexpr unsigned int _c0 = K8_SC<SEED,0xAAAAAAAAu>::value;
            constexpr unsigned int _c1 = K8_SC<SEED,0x55555555u>::value;
            constexpr unsigned int _c2 = K8_SC<SEED,0xF0F0F0F0u>::value;
            volatile unsigned int a  = _c0;
            volatile unsigned int b2 = _c1;
            for(int i=0;i<8;++i){
                a  = OBF_MBA_XOR(a,  b2 ^ (unsigned int)(i*0x01010101u));
                b2 = OBF_MBA_ADD(b2, a  ^ _c2);
            }
            k8_sink_ns::k8_sink[(SEED>>17)&63u] += a^b2;
            _obf_global_opaque_seed = OBF_MBA_ADD(_obf_global_opaque_seed, (int)(a^b2));
        }

        template<unsigned int SEED>
        K8_NOINLINE static void k8_fake_matrix_mul() {
            volatile unsigned int m[4] = {
                K8_SC<SEED,0x11223344u>::value, K8_SC<SEED,0x55667788u>::value,
                K8_SC<SEED,0x99AABBCCu>::value, K8_SC<SEED,0xDDEEFF00u>::value
            };
            volatile unsigned int v2[2] = {K8_SC<SEED, 0x13579BDFu>::value,
                                         K8_SC<SEED, 0x2468ACEu>::value};
            volatile unsigned int r0 = OBF_MBA_ADD(OBF_MBA_MUL_CONST3(m[0] ^ v2[0]), m[1] ^ v2[1]);
            volatile unsigned int r1 = OBF_MBA_ADD(OBF_MBA_MUL_CONST3(m[2] ^ v2[0]), m[3] ^ v2[1]);
            k8_sink_ns::k8_sink[(SEED >> 2) & 63u] ^= r0 ^ r1;
            _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed, (int)(r0 ^ r1));
        }

        template<unsigned int SEED>
        K8_NOINLINE static void k8_fake_poly_eval() {
            volatile unsigned int x = K8_SC<SEED, 0xBEEFCAFEu>::value;
            volatile unsigned int r = K8_SC<SEED, 0xFEDCBA98u>::value;
            for(int i = 1; i < 6; ++i){
                unsigned int ci = K8_SC<K8_XS32<SEED>::value, 0x10000000u>::value ^ (unsigned int)i;
                r = OBF_MBA_ADD(OBF_MBA_MUL_CONST3(r), ci);
                r = OBF_MBA_XOR(r, x ^ (unsigned int)(i * 0x11111111u));
            }
            k8_sink_ns::k8_sink[(SEED >> 18)&63u] += r;
            _obf_global_opaque_seed = OBF_MBA_ADD(_obf_global_opaque_seed, (int)r);
        }

        template<unsigned int SEED>
        K8_NOINLINE static void k8_fake_bubble_sort() {
            volatile unsigned int arr[6]={
                K8_SC<SEED,0x31415926u>::value, K8_SC<SEED,0x27182818u>::value,
                K8_SC<SEED,0x16180339u>::value, K8_SC<SEED,0x14142135u>::value,
                K8_SC<SEED,0x17320508u>::value, K8_SC<SEED,0x26457513u>::value
            };
            for(int i = 0; i < 5; ++i)
                for(int j = 0; j < 5 - i; ++j)
                    if(arr[j] > arr[j + 1])
                    {
                        unsigned int t = arr[j];
                        arr[j] = arr[j + 1];
                        arr[j + 1] = t;
                    }
            k8_sink_ns::k8_sink[(SEED >> 22) & 63u] ^= arr[0] ^ arr[5];
            _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed, (int)(arr[0] ^ arr[5]));
        }

        template<unsigned int SEED>
        K8_NOINLINE static void k8_fake_base64_enc() {
            static const char _b64[] = 
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            volatile unsigned int in = K8_SC<SEED, 0xFEEDFACEu>::value;
            volatile char out[5] = {0};
            out[0]= _b64[(in >> 18) & 0x3Fu];
            out[1] = _b64[(in >> 12) & 0x3Fu];
            out[2] = _b64[(in >> 6) & 0x3Fu];
            out[3] = _b64[in & 0x3Fu];
            k8_sink_ns::k8_sink[(SEED >> 5) & 63u] ^= (unsigned int)out[0] ^ (unsigned int)out[3];
            _obf_global_opaque_seed = OBF_MBA_ADD(_obf_global_opaque_seed, (int)out[0] ^ (int)out[3]);
        }

        template<unsigned int SEED>
        K8_NOINLINE static void k8_fake_entropy_mix() {
            constexpr unsigned int _c0 = K8_SC<SEED,0x9E3779B1u>::value;
            constexpr unsigned int _c1 = K8_SC<SEED,0x6C62272Eu>::value;
            volatile uint64_t tsc = __rdtsc();
            volatile unsigned int t0 = (unsigned int)(tsc & 0xFFFFFFFFu);
            volatile unsigned int t1 = (unsigned int)(tsc >> 32);
            volatile unsigned int add_part = OBF_MBA_ADD(_c0, t0);
            volatile unsigned int mul_part = OBF_MBA_MUL_CONST3(t1 ^ _c1);
            volatile unsigned int mix = OBF_MBA_XOR(add_part, mul_part);
            k8_sink_ns::k8_sink[(SEED >> 7) & 63u] ^= mix;
            _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed, (int)mix);
        }

        template<unsigned int SEED>
        K8_NOINLINE static void k8_fake_crypt_stream() {
            volatile unsigned int s[4]={
                K8_SC<SEED,0x61707865u>::value, K8_SC<SEED,0x3320646Eu>::value,
                K8_SC<SEED,0x79622D32u>::value, K8_SC<SEED,0x6B206574u>::value
            };
            for(int r = 0; r < 4; ++r){
                s[0]+=s[1]; s[3]^=s[0]; s[3]=(s[3]<<16)|(s[3]>>16);
                s[2]+=s[3]; s[1]^=s[2]; s[1]=(s[1]<<12)|(s[1]>>20);
                s[0]+=s[1]; s[3]^=s[0]; s[3]=(s[3]<<8)|(s[3]>>24);
                s[2]+=s[3]; s[1]^=s[2]; s[1]=(s[1]<<7)|(s[1]>>25);
            }
            k8_sink_ns::k8_sink[(SEED>>10)&63u]+=s[0]^s[3];
            _obf_global_opaque_seed=OBF_MBA_XOR(_obf_global_opaque_seed,(int)(s[0]^s[3]));
        }

        template<unsigned int SEED>
        K8_NOINLINE static void k8_fake_vm_dispatch() {
            volatile unsigned int ip = K8_SC<SEED, 0u>::value&0xFu;
            volatile unsigned int regs[4] = {K8_SC<SEED, 1u>::value, K8_SC<SEED, 2u>::value,
                                           K8_SC<SEED, 3u>::value, K8_SC<SEED,4u>::value};
            static const unsigned int prog[16]={
                0x01230000u,0x12300001u,0x23010002u,0x30120003u,
                0x01230004u,0x12300005u,0x23010006u,0x30120007u,
                0x01230008u,0x12300009u,0x2301000Au,0x3012000Bu,
                0x0123000Cu,0x1230000Du,0x2301000Eu,0x3012000Fu
            };
            for(int i = 0; i < 8; ++i){
                unsigned int instr = prog[ip & 0xFu];
                unsigned int op = (instr >> 24) & 0xFFu;
                unsigned int rd = (instr >> 16) & 0x3u;
                unsigned int rs = (instr >> 8) & 0x3u;
                switch(op & 3u)
                {
                    case 0: regs[rd] = OBF_MBA_ADD(regs[rd], regs[rs]);
                        break;
                    case 1: regs[rd] = OBF_MBA_XOR(regs[rd], regs[rs]);
                        break;
                    case 2: regs[rd] = OBF_MBA_SUB(regs[rd], regs[rs]);
                        break;
                    default:regs[rd] = OBF_MBA_NOT(regs[rd] ^ regs[rs]);
                        break;
                }
                ip = (ip + 1u) & 0xFu;
            }
            k8_sink_ns::k8_sink[(SEED >> 13) & 63u] ^= regs[0] ^ regs[3];
            _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed, (int)(regs[0] ^ regs[3]));
        }

        template<unsigned int SEED, unsigned int BODY_IDX>
        struct K8_FakeBodyDispatch {
            K8_NOINLINE static void run() {
                k8_fake_fnv1a<SEED>();
            }
        };
        template<unsigned int S> struct K8_FakeBodyDispatch<S,0>  { K8_NOINLINE static void run(){k8_fake_rc4_sched<S>();} };
        template<unsigned int S> struct K8_FakeBodyDispatch<S,1>  { K8_NOINLINE static void run(){k8_fake_murmur3<S>();} };
        template<unsigned int S> struct K8_FakeBodyDispatch<S,2>  { K8_NOINLINE static void run(){k8_fake_fnv1a<S>();} };
        template<unsigned int S> struct K8_FakeBodyDispatch<S,3>  { K8_NOINLINE static void run(){k8_fake_crc32<S>();} };
        template<unsigned int S> struct K8_FakeBodyDispatch<S,4>  { K8_NOINLINE static void run(){k8_fake_aes_sbox<S>();} };
        template<unsigned int S> struct K8_FakeBodyDispatch<S,5>  { K8_NOINLINE static void run(){k8_fake_str_scan<S>();} };
        template<unsigned int S> struct K8_FakeBodyDispatch<S,6>  { K8_NOINLINE static void run(){k8_fake_bitpack<S>();} };
        template<unsigned int S> struct K8_FakeBodyDispatch<S,7>  { K8_NOINLINE static void run(){k8_fake_memchk<S>();} };
        template<unsigned int S> struct K8_FakeBodyDispatch<S,8>  { K8_NOINLINE static void run(){k8_fake_lfsr<S>();} };
        template<unsigned int S> struct K8_FakeBodyDispatch<S,9>  { K8_NOINLINE static void run(){k8_fake_wang<S>();} };
        template<unsigned int S> struct K8_FakeBodyDispatch<S,10> { K8_NOINLINE static void run(){k8_fake_rol_chain<S>();} };
        template<unsigned int S> struct K8_FakeBodyDispatch<S,11> { K8_NOINLINE static void run(){k8_fake_xor_ladder<S>();} };
        template<unsigned int S> struct K8_FakeBodyDispatch<S,12> { K8_NOINLINE static void run(){k8_fake_matrix_mul<S>();} };
        template<unsigned int S> struct K8_FakeBodyDispatch<S,13> { K8_NOINLINE static void run(){k8_fake_poly_eval<S>();} };
        template<unsigned int S> struct K8_FakeBodyDispatch<S,14> { K8_NOINLINE static void run(){k8_fake_bubble_sort<S>();} };
        template<unsigned int S> struct K8_FakeBodyDispatch<S,15> { K8_NOINLINE static void run(){k8_fake_base64_enc<S>();} };
        template<unsigned int S> struct K8_FakeBodyDispatch<S,16> { K8_NOINLINE static void run(){k8_fake_entropy_mix<S>();} };
        template<unsigned int S> struct K8_FakeBodyDispatch<S,17> { K8_NOINLINE static void run(){k8_fake_crypt_stream<S>();} };
        template<unsigned int S> struct K8_FakeBodyDispatch<S,18> { K8_NOINLINE static void run(){k8_fake_vm_dispatch<S>();} };
        template<unsigned int S> struct K8_FakeBodyDispatch<S,19> { K8_NOINLINE static void run(){k8_fake_rol_chain<K8_XS32<S>::value>();} };

        template<unsigned int SEED, int DEPTH>
        struct K8_BBChain {
            K8_NOINLINE static void run() {
                constexpr unsigned int rot=(K8_SC<SEED,0x1Fu>::value&0x1Fu)+1u;
                volatile unsigned long long junk=
                    (K8_SC<SEED,0x12345678u>::value^(unsigned)_obf_global_opaque_seed)
                    *K8_SC<SEED,0x9E3779B1u>::value;
                junk= (junk << rot) | (junk >> (32u - rot));
                _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed, (long long)junk ^ (long long)__LINE__);
                (void)junk;
                typedef void(*fn_t)();
                volatile fn_t next = K8_BBChain<K8_XS32<SEED>::value, DEPTH - 1>::run;
                uintptr_t k2 = (uintptr_t)K8_SC<SEED,0xABCD0000u>::value^(uintptr_t)__LINE__;
                next = (fn_t)((uintptr_t)next ^ k2);
                next = (fn_t)((uintptr_t)next ^ k2);
                next();
            }
        };
        template<unsigned int SEED>
        struct K8_BBChain<SEED, 0> {
            K8_NOINLINE static void run() {
                K8_FakeBodyDispatch<SEED, K8_SC<SEED, 0u>::value % 20u>::run();
            }
        };

        namespace k8_autospawn_ns {
            static constexpr unsigned int _base =
                30u + (
                    (unsigned int)(__TIME__[0]-'0')*10u +
                    (unsigned int)(__TIME__[1]-'0')*5u  +
                    (unsigned int)(__TIME__[6]-'0')*3u  +
                    (unsigned int)(__TIME__[7]-'0')
                ) % 51u;

            static constexpr unsigned int _seed0 =
                ((unsigned int)(__TIME__[0])<<24) |
                ((unsigned int)(__TIME__[3])<<16) |
                ((unsigned int)(__TIME__[6])<<8)  |
                 (unsigned int)(__TIME__[7]);

            template<unsigned int SEED, unsigned int N>
            struct Spawner {
                static void run() {
                    constexpr int depth=(int)((SEED%5u)+2u);
                    K8_BBChain<SEED, depth>::run();
                    typedef void(*fn_t)();
                    volatile fn_t next_spawn=Spawner<K8_XS32<SEED>::value,N-1>::run;
                    uintptr_t k3=(uintptr_t)SEED^(uintptr_t)__LINE__;
                    next_spawn=(fn_t)((uintptr_t)next_spawn^k3);
                    next_spawn=(fn_t)((uintptr_t)next_spawn^k3);
                    next_spawn();
                }
            };
            template<unsigned int SEED>
            struct Spawner<SEED,0> {
                static void run() {
                    K8_BBChain<SEED,2>::run();
                }
            };
        }

        #define K8_AUTOSPAWN() \
            do { \
                typedef void(*_asf_t)(); \
                volatile _asf_t _asf = \
                    k8_autospawn_ns::Spawner< \
                        k8_autospawn_ns::_seed0, \
                        k8_autospawn_ns::_base>::run; \
                uintptr_t _ask=(uintptr_t)__LINE__^(uintptr_t)_obf_global_opaque_seed; \
                _asf=(_asf_t)((uintptr_t)_asf^_ask); \
                _asf=(_asf_t)((uintptr_t)_asf^_ask); \
                _asf(); \
                _obf_global_opaque_seed=OBF_MBA_XOR(_obf_global_opaque_seed, \
                    (int)k8_sink_ns::k8_sink[0]^(int)k8_sink_ns::k8_sink[63]); \
            } while(0)

        #define K8_SPAWN_IMPL(depth, seed, body) \
            do { \
                auto CONCAT(_k8sp_lam_,seed) = [](){body}; \
                typedef void(*CONCAT(_k8sp_fp_, seed))(); \
                volatile CONCAT(_k8sp_fp_, seed) CONCAT(_k8sp_fn_, seed)= \
                    (CONCAT(_k8sp_fp_, seed))(CONCAT(_k8sp_lam_, seed)); \
                K8_BBChain<(unsigned int)(seed) * 0x9E3779B1u + 0xDEADBEEFu, depth>::run(); \
                CONCAT(_k8sp_fn_, seed)(); \
            } while(0)
        #define K8_SPAWN(depth,id,body) K8_SPAWN_IMPL(depth,__COUNTER__,body)

        #define K8_BB_LIGHT(id,body)   K8_SPAWN(3, id, body)
        #define K8_BB_MEDIUM(id,body)  K8_SPAWN(7, id, body)
        #define K8_BB_HEAVY(id,body)   K8_SPAWN(15,id, body)

        #define K8_FUNC_FACTORY(ret_type, func_name, params, depth, body) \
            namespace CONCAT(_k8ff_ns_, func_name){ \
                K8_NOINLINE static ret_type _core params{body} \
                template<unsigned int SEED, int D> struct _L{ \
                    K8_NOINLINE static ret_type run params{ \
                        constexpr unsigned int _rot = (K8_SC<SEED,0x1Fu>::value&0x1Fu)+1u; \
                        volatile unsigned int _jk = K8_SC<SEED,0xABCDEF01u>::value \
                            ^(unsigned)_obf_global_opaque_seed; \
                        _jk = (_jk<<_rot)|(_jk>>(32u-_rot)); \
                        _obf_global_opaque_seed = OBF_MBA_XOR( \
                            _obf_global_opaque_seed, (int)_jk ^ (int)__LINE__); \
                        (void)_jk; \
                        typedef ret_type(*_nfp_t)params; \
                        volatile _nfp_t _nf = _L<K8_XS32<SEED>::value,D-1>::run; \
                        uintptr_t _k=(uintptr_t)K8_SC<SEED, 0xFEED0000u>::value \
                                    ^(uintptr_t)_AddressOfReturnAddress(); \
                        _nf = (_nfp_t)((uintptr_t)_nf ^ _k); \
                        _nf = (_nfp_t)((uintptr_t)_nf ^ _k); \
                        return _nf params; \
                    } \
                }; \
                template<unsigned int SEED> struct _L<SEED,0>{ \
                    K8_NOINLINE static ret_type run params{return _core params;} \
                }; \
            } \
            K8_NOINLINE static ret_type func_name params{ \
                return CONCAT(_k8ff_ns_,func_name)::_L< \
                    (unsigned int)(__LINE__*0x9E3779B1u)^0xDEADBEEFu, \
                    depth>::run params; \
            }

        #define K8_STD_FUNC_BB_IMPL(body, _id) \
            do { \
                function<void()> CONCAT(_k8sf_fn_,_id) = [&]() { body }; \
                uintptr_t CONCAT(_k8sf_noise_,_id) = \
                    (uintptr_t)_AddressOfReturnAddress() & 0xFFFFu; \
                _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed, \
                    (int)CONCAT(_k8sf_noise_,_id) ^ (int)__LINE__); \
                volatile uintptr_t CONCAT(_k8sf_vaddr_,_id) = \
                    (uintptr_t)&CONCAT(_k8sf_fn_,_id); \
                function<void()>* CONCAT(_k8sf_vp_,_id) = \
                    (function<void()>*)(uintptr_t)CONCAT(_k8sf_vaddr_,_id); \
                (*CONCAT(_k8sf_vp_,_id))(); \
            } while(0)
        #define K8_STD_FUNC_BB(body) K8_STD_FUNC_BB_IMPL(body, __COUNTER__)

    #pragma endregion JUNK
    
    #pragma region OBF_JUMPS
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
    
                K8_FORCEINLINE static uint32_t _k8_self_crc(const void* fn) {
                    volatile uint32_t c = 0xFFFFFFFFu;
                    const uint8_t* p = (const uint8_t*)(uintptr_t)fn;
                    for (int i = 0; i < 32; ++i) {
                        c ^= p[i];
                        for (int b = 0; b < 8; ++b)
                            c = (c >> 1) ^ (0xEDB88320u & (uint32_t)(0u - (c & 1u)));
                    }
                    return (c ^ 0xFFFFFFFFu) ^ (uint32_t)((uintptr_t)fn & 0xFFFFu);
                }

                K8_FORCEINLINE static uint32_t _k8_rk(
                        uint32_t dk, uint32_t crc, const void* fn) {
                    volatile uint64_t tsc = __rdtsc();
                    volatile uint32_t tlo = (uint32_t)(tsc & 0xFFFFu);
                    volatile uint32_t sp  = (uint32_t)(
                        (uintptr_t)_AddressOfReturnAddress() & 0xFFFFu);
                    return (uint32_t)OBF_MBA_XOR(
                               (uint32_t)OBF_MBA_ADD(dk ^ crc, tlo ^ sp),
                               (uint32_t)((uintptr_t)fn & 0xFFFFu));
                }

                #define K8_DPSEL(cond, a, b) \
                    ((unsigned int)OBF_MBA_ADD( \
                        (unsigned int)(a) & (unsigned int)(0u-((unsigned int)((cond)!=0u))), \
                        (unsigned int)(b) & (unsigned int)(0u-((unsigned int)((cond)==0u)))))

                K8_NOINLINE static void vm_handle_op_arith(VMState& s, int ac, char** av) {
                    volatile uint32_t _crc = _k8_self_crc((void*)vm_handle_op_arith);
                    volatile uint32_t _rk  = _k8_rk(s.dispatch_key,_crc,(void*)vm_handle_op_arith);
                    volatile unsigned int _i0 = (unsigned int)OBF_MBA_XOR(0x1A2B3C4Du, _rk);
                    volatile unsigned int _i1 = (unsigned int)OBF_MBA_XOR(0xDEADF00Du, _rk ^ _crc);
                    NOP();
                    unsigned int tmp = (unsigned int)OBF_MBA_XOR(s.r1,(unsigned int)__LINE__);
                    tmp = (unsigned int)OBF_MBA_ADD(tmp, (unsigned int)s.global_seed_ref ^ s.pc ^ _rk);
                    tmp = (unsigned int)OBF_MBA_XOR(tmp, _i0 ^ _crc);
                    s.r0 = (unsigned int)OBF_MBA_ADD(s.r0, tmp);
                    unsigned int _p0 = (unsigned int)OBF_MBA_SUB(s.r1,
                        (s.r2 + (unsigned int)ac+(s.pc*7u))^(unsigned int)OBF_CALL_ANY_LOCAL_JUNK()^_i1);
                    unsigned int _p1 = (unsigned int)OBF_MBA_SUB(s.r1,
                        (s.r2 + (unsigned int)ac+(s.pc*7u))^(unsigned int)OBF_CALL_ANY_LOCAL_JUNK()^_i1);
                    s.r1 = K8_DPSEL(s.dispatch_key & 1u,_p0,_p1);
                    s.r2 = (unsigned int)OBF_MBA_XOR(s.r2, s.dispatch_key ^
                        (unsigned int)(av && ac > 0 && av[0] ? (uintptr_t)av[0] : (uintptr_t)__COUNTER__));
                    s.dispatch_key = (unsigned int)OBF_MBA_ADD(s.dispatch_key,
                        (unsigned int)OBF_MBA_XOR(s.r0 ^ _i0, s.r1 ^ _crc));
                    s.pc = (unsigned int)OBF_MBA_ADD(s.pc, 1u ^ (s.r2 & 1u));
                    s.global_seed_ref = (int)OBF_MBA_XOR(s.global_seed_ref,
                        (int)(s.r0 ^ s.r1 ^ s.pc ^ _crc ^ _rk));
                    if(VM_OPQ_TRUE() || VM_OPQ_FALSE())
                        OBF_CALL_ANY_LOCAL_JUNK();
                }

                K8_NOINLINE static void vm_handle_op_bitwise_logic(VMState& s, int ac, char** av) {
                    volatile uint32_t _crc = _k8_self_crc((void*)vm_handle_op_bitwise_logic);
                    volatile uint32_t _rk  = _k8_rk(s.dispatch_key,_crc,(void*)vm_handle_op_bitwise_logic);
                    volatile unsigned int _i0 = (unsigned int)OBF_MBA_XOR(0xDEADBEEFu,_rk);
                    volatile unsigned int _i1 = (unsigned int)OBF_MBA_XOR(0xCAFEFACEu,_rk^_crc);
                    NOP();
                    s.r0 = (unsigned int)OBF_MBA_XOR(
                        (s.r0 & s.r1)|((unsigned int)OBF_MBA_NOT(s.r0)&s.r2),
                        (s.r1 ^ s.r2 ^_rk));
                    unsigned int _rot=((s.pc % 3u) + 1u) ^ (_rk & 0x1Fu);
                    _rot = (_rot % 31u) + 1u;
                    unsigned int _r1a = (s.r1 << _rot) | (s.r1 >> (32u - _rot));
                    unsigned int _r1b = (s.r1 << _rot) | (s.r1 >> (32u - _rot));
                    s.r1 = K8_DPSEL(_crc & 1u, _r1a, _r1b);
                    s.r2 = (unsigned int)OBF_MBA_XOR(s.r2,_i0^(unsigned int)s.global_seed_ref^_crc);
                    s.dispatch_key = (unsigned int)OBF_MBA_SUB(s.dispatch_key,
                        (s.r1 ^ (0x55AA55AAu ^ _rk)) ^ s.r2);
                    s.pc = (unsigned int)OBF_MBA_ADD(s.pc, ((s.r0 & 1u) ? 2u : 1u) + ((s.r1 & 1u) ? 1u : 0u));
                    s.global_seed_ref = (int)OBF_MBA_ADD(s.global_seed_ref,
                        (int)(s.r2 ^ s.dispatch_key ^ s.pc ^ _i1 ^ _crc));
                    if(VM_OPQ_TRUE() || VM_OPQ_FALSE())
                        OBF_CALL_ANY_LOCAL_JUNK();
                }

                K8_NOINLINE static void vm_handle_op_key_mangle(VMState& s, int ac, char** av) {
                    volatile uint32_t _crc = _k8_self_crc((void*)vm_handle_op_key_mangle);
                    volatile uint32_t _rk  = _k8_rk(s.dispatch_key,_crc,(void*)vm_handle_op_key_mangle);
                    volatile unsigned int _i0 = (unsigned int)OBF_MBA_XOR(0xBEEFBABEu,_rk);
                    NOP();
                    unsigned int tk=s.dispatch_key^(unsigned int)__LINE__^_i0;
                    tk=(unsigned int)OBF_MBA_MUL_CONST3(tk^(s.r0|s.r1)^_crc);
                    tk=(unsigned int)OBF_MBA_ADD(tk,s.r0^s.r1^s.r2^s.pc^_rk);
                    unsigned int _krot=(_crc>>8u)&0x1Fu;
                    if(_krot==0u) _krot=7u;
                    tk=(tk<<_krot)|(tk>>(32u-_krot));
                    tk^=(unsigned int)OBF_CALL_ANY_LOCAL_JUNK()^_rk;
                    s.dispatch_key=tk;
                    s.r0 = (unsigned int)OBF_MBA_XOR(s.r0, s.dispatch_key ^ s.r2 ^ _i0);
                    s.pc = (unsigned int)OBF_MBA_SUB(s.pc, (s.r1 & 7u) ? 1u : 3u);
                    s.global_seed_ref=(int)OBF_MBA_XOR(s.global_seed_ref,
                        (int)s.dispatch_key ^ (int)s.r2 ^ (int)_crc ^ (int)_rk);
                    if(VM_OPQ_TRUE() || VM_OPQ_FALSE())
                        OBF_CALL_ANY_LOCAL_JUNK();
                }

                K8_NOINLINE static void vm_handle_op_junk_sequence(VMState& s, int ac, char** av) {
                    volatile uint32_t _crc = _k8_self_crc((void*)vm_handle_op_junk_sequence);
                    volatile uint32_t _rk  = _k8_rk(s.dispatch_key,_crc,(void*)vm_handle_op_junk_sequence);
                    volatile unsigned int _i0 = (unsigned int)OBF_MBA_XOR(0xF00DFACEu,_rk^_crc);
                    NOP();
                    s.r0=(unsigned int)OBF_MBA_ADD(s.r0,
                        (unsigned int)OBF_CALL_ANY_LOCAL_JUNK()^s.r1^_rk);
                    s.r1=(unsigned int)OBF_MBA_XOR(s.r1,
                        (unsigned int)OBF_CALL_ANY_LOCAL_JUNK()^s.r2^(unsigned int)ac^_i0);
                    s.r2=(unsigned int)OBF_MBA_SUB(s.r2,
                        (unsigned int)OBF_CALL_ANY_LOCAL_JUNK()^
                        (unsigned int)(av&&ac>0&&av[0]?av[0][0]:(char)__LINE__)^_crc);
                    s.dispatch_key=(unsigned int)OBF_MBA_NOT(s.dispatch_key^s.r0^s.r2^_rk);
                    s.pc=(unsigned int)OBF_MBA_ADD(s.pc,1u+(s.r2&3u));
                    s.global_seed_ref=(int)OBF_MBA_XOR(s.global_seed_ref,
                        (int)(s.r0^s.r1^s.r2^s.pc^_i0^_crc));
                    if(VM_OPQ_TRUE()||VM_OPQ_FALSE()) OBF_CALL_ANY_LOCAL_JUNK();
                    NOP();
                }

                K8_NOINLINE static void vm_handle_op_conditional_update(VMState& s, int ac, char** av) {
                    volatile uint32_t _crc = _k8_self_crc((void*)vm_handle_op_conditional_update);
                    volatile uint32_t _rk  = _k8_rk(s.dispatch_key,_crc,(void*)vm_handle_op_conditional_update);
                    volatile unsigned int _i0 = (unsigned int)OBF_MBA_XOR(0xBAD0C0DEu,_rk);
                    volatile unsigned int _i1 = (unsigned int)OBF_MBA_XOR(0xC001F00Du,_rk^_crc);
                    NOP();
                    volatile unsigned int _pred=(unsigned int)OBF_MBA_XOR(
                        s.r0^s.dispatch_key^(unsigned int)s.global_seed_ref,_rk);
                    if(OBF_OPAQUE_PREDICATE_TRUE_2(_pred)) {
                        s.r0=(unsigned int)OBF_MBA_ADD(s.r0,s.r1^(s.pc|(0xA5A5u^_i0)));
                        s.r1=(unsigned int)OBF_MBA_SUB(s.r1,s.r2^(s.pc&(0x5A5Au^_i1)));
                        s.dispatch_key=(unsigned int)OBF_MBA_XOR(s.dispatch_key,
                            (s.pc*0x1001u)^s.r1^_crc);
                    } else {
                        s.r0=(unsigned int)OBF_MBA_XOR(s.r0,(_i0^0xBAD0BAD0u)^s.r2);
                        s.r1=(unsigned int)OBF_MBA_NOT(s.r1^s.r0^_rk);
                        s.dispatch_key=(unsigned int)OBF_MBA_ADD(s.dispatch_key,
                            (_i1^0xC001C001u)^s.r0);
                    }
                    s.r2=(unsigned int)OBF_MBA_XOR(s.r2,
                        (unsigned int)OBF_CALL_ANY_LOCAL_JUNK()^s.r0^_i0);
                    s.pc=(unsigned int)OBF_MBA_ADD(s.pc,((s.r1&1u)+1u)^(s.r2&3u));
                    s.global_seed_ref=(int)OBF_MBA_SUB(s.global_seed_ref,
                        (int)(s.r0+s.r1+s.pc+_crc+_rk));
                    if(VM_OPQ_TRUE()||VM_OPQ_FALSE())
                        OBF_CALL_ANY_LOCAL_JUNK();
                }

                K8_NOINLINE static void vm_handle_op_mem_sim(VMState& s, int ac, char** av) {
                    volatile uint32_t _crc = _k8_self_crc((void*)vm_handle_op_mem_sim);
                    volatile uint32_t _rk  = _k8_rk(s.dispatch_key,_crc,(void*)vm_handle_op_mem_sim);
                    volatile unsigned int _i0 = (unsigned int)OBF_MBA_XOR(0xFEEDBEEFu,_rk);
                    NOP();
                    static volatile unsigned int _mem[32];
                    unsigned int a1=(s.r0^s.pc^s.dispatch_key^_rk)%32u;
                    unsigned int a2=(s.r1^s.dispatch_key^s.r2^_crc)%32u;
                    if(OBF_OPAQUE_PREDICATE_TRUE_1())
                        _mem[a1]=(unsigned int)OBF_MBA_ADD(s.r2,
                            s.dispatch_key^(s.r1&0xAA55u)^_i0);
                    if(VM_OPQ_TRUE()||VM_OPQ_FALSE())
                        _mem[a2]=(unsigned int)OBF_MBA_XOR(s.r0,
                            s.r1^(unsigned int)OBF_CALL_ANY_LOCAL_JUNK()^_rk);
                    unsigned int _ma=a2^(_rk&0u);
                    unsigned int _mb=a2^(_crc&0u);
                    s.r0=(unsigned int)OBF_MBA_XOR(s.r0,K8_DPSEL(_crc&1u,_mem[_ma],_mem[_mb]));
                    s.r1=(unsigned int)OBF_MBA_ADD(s.r1,_mem[a1%8u]^s.r2^_rk);
                    s.dispatch_key=(unsigned int)OBF_MBA_SUB(s.dispatch_key,
                        _mem[(a1+a2)%32u]^_i0);
                    s.pc=(unsigned int)OBF_MBA_ADD(s.pc,1u^(s.dispatch_key&1u));
                    s.global_seed_ref=(int)OBF_MBA_XOR(s.global_seed_ref,
                        (int)(_mem[s.pc%32u]^_crc^_rk));
                    if(VM_OPQ_TRUE()||VM_OPQ_FALSE()) OBF_CALL_ANY_LOCAL_JUNK();
                }

                K8_NOINLINE static void vm_handle_op_pc_mangle(VMState& s, int ac, char** av) {
                    volatile uint32_t _crc = _k8_self_crc((void*)vm_handle_op_pc_mangle);
                    volatile uint32_t _rk  = _k8_rk(s.dispatch_key,_crc,(void*)vm_handle_op_pc_mangle);
                    volatile unsigned int _i0 = (unsigned int)OBF_MBA_XOR(0xC0DE1337u,_rk^_crc);
                    NOP();
                    s.pc=(unsigned int)OBF_MBA_XOR(s.pc,s.r0^s.r1^s.dispatch_key^s.r2^_rk);
                    s.pc=(unsigned int)OBF_MBA_ADD(s.pc,
                        (unsigned int)__LINE__+(s.dispatch_key&0x3Fu)+(_i0&0u));
                    s.pc=(unsigned int)(s.pc%256u);
                    s.r0=(unsigned int)OBF_MBA_ADD(s.r0,s.pc^(s.r1&0xF0F0u)^_crc);
                    s.dispatch_key=(unsigned int)OBF_MBA_NOT(s.dispatch_key^s.pc^_rk);
                    s.global_seed_ref=(int)OBF_MBA_ADD(s.global_seed_ref,
                        (int)s.pc^(int)OBF_CALL_ANY_LOCAL_JUNK()^(int)_i0);
                    if(!OBF_OPAQUE_PREDICATE_FALSE_1())
                        s.r1=(unsigned int)OBF_MBA_XOR(s.r1,
                            (unsigned int)OBF_CALL_ANY_LOCAL_JUNK()^s.r2^_crc);
                }

                K8_NOINLINE static void vm_handle_op_multi_mba(VMState& s, int ac, char** av) {
                    volatile uint32_t _crc = _k8_self_crc((void*)vm_handle_op_multi_mba);
                    volatile uint32_t _rk  = _k8_rk(s.dispatch_key,_crc,(void*)vm_handle_op_multi_mba);
                    volatile unsigned int _i0 = (unsigned int)OBF_MBA_XOR(0xFACEB00Cu,_rk);
                    volatile unsigned int _i1 = (unsigned int)OBF_MBA_XOR(0x600DC0DEu,_rk^_crc);
                    NOP();
                    s.r0=(unsigned int)OBF_MBA_ADD(
                        OBF_MBA_XOR(s.r0,s.dispatch_key^s.pc^_i0),
                        OBF_MBA_MUL_CONST3(s.r1^s.r2^_rk));
                    s.r1=(unsigned int)OBF_MBA_SUB(
                        OBF_MBA_NOT(s.r1^s.r0^_crc),
                        OBF_MBA_XOR(s.r2^s.r0,s.pc^_rk));
                    s.r2=(unsigned int)OBF_MBA_ADD(
                        OBF_MBA_MUL_CONST_ALT(s.r2^_i1,3),
                        OBF_MBA_SUB(s.r0,s.r1)^s.dispatch_key^_crc);
                    s.dispatch_key=(unsigned int)OBF_MBA_XOR(s.dispatch_key,
                        OBF_MBA_NOT(s.r0^s.r1^s.r2^_rk));
                    s.pc=(unsigned int)OBF_MBA_ADD(s.pc,1u+(s.r0&1u));
                    s.global_seed_ref=(int)OBF_MBA_XOR(s.global_seed_ref,
                        (int)OBF_CALL_ANY_LOCAL_JUNK()^(int)s.dispatch_key^(int)_i0^(int)_crc);
                    if(VM_OPQ_TRUE()||VM_OPQ_FALSE()) OBF_CALL_ANY_LOCAL_JUNK();
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
    
                constexpr unsigned int HANDLER_COUNT = (unsigned int)(sizeof(handler_table_raw)/sizeof(vm_handler_ptr_t));
    
                static vm_handler_ptr_t* get_mem_dispatch_table(VMState& s) {
                    static vm_handler_ptr_t scrambled[HANDLER_COUNT] = {};
                    static bool inited = false;
                    if (!inited) {
                        unsigned int k = (unsigned int)s.global_seed_ref ^ (unsigned int)time(nullptr);
                        for (size_t i = 0; i < HANDLER_COUNT; ++i)
                            scrambled[i] = nullptr;
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
                                int dispatcher_type = ((s.dispatch_key ^ s.pc ^ s.global_seed_ref ^ i ^ (int)time(nullptr)) & 3);
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
                                _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed, (int)time(nullptr) ^ (int)__COUNTER__ ^ s.pc);
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
                unsigned int 
                VM_HANDLER_TABLE_SIZE = (unsigned int)(sizeof(vm_handler_table)/sizeof(vm_handler_ptr_t));
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
        #define OBF_CALL_VIA_OBF_PTR(func_ptr_type, real_func, arg1, arg2) \
            do { \
                volatile func_ptr_type _obf_fp_internal = (real_func); \
                unsigned int _obf_key_fp = OBF_MBA_XOR((unsigned int)__LINE__, (unsigned int)_obf_global_opaque_seed ^ (unsigned int)OBF_CALL_ANY_LOCAL_JUNK()); \
                _obf_fp_internal = (func_ptr_type)((uintptr_t)_obf_fp_internal ^ _obf_key_fp); \
                NOP(); \
                _obf_fp_internal = (func_ptr_type)((uintptr_t)_obf_fp_internal ^ _obf_key_fp); \
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
                volatile uintptr_t _fake_ebp = (uintptr_t)&_obf_global_opaque_seed - (OBF_CALL_ANY_LOCAL_JUNK() & 0xFF); \
                volatile uintptr_t _fake_esp = _fake_ebp - ((OBF_CALL_ANY_LOCAL_JUNK() & 0x7F) + 16); \
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
    
        #define OBF_BOGUS_FLOW_STORM() \
            do { \
                volatile unsigned int _stm_seed  = (unsigned int)__COUNTER__ ^ (unsigned int)_obf_global_opaque_seed; \
                volatile uint64_t _stm_tsc       = __rdtsc(); \
                volatile unsigned int _stm_acc   = (unsigned int)OBF_MBA_MUL_CONST3(_stm_seed ^ (unsigned int)(_stm_tsc & 0xFFFFu)); \
                volatile unsigned int _stm_key   = (unsigned int)OBF_MBA_XOR(_stm_acc, (unsigned int)OBF_CALL_ANY_LOCAL_JUNK()); \
                volatile unsigned int _stm_iter  = (OBF_CALL_ANY_LOCAL_JUNK() & 3U) + 3U; \
            _storm_hub_: \
                NOP(); \
                _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed, \
                    (int)_stm_acc ^ (int)_stm_key ^ (int)OBF_CALL_ANY_LOCAL_JUNK()); \
                _stm_acc = OBF_MBA_ADD(_stm_acc, _stm_key ^ (unsigned int)__LINE__); \
                if (OBF_OPAQUE_PREDICATE_TRUE_1()) { \
                    switch (_stm_acc % 6U) { \
                        case 0: \
                            _stm_key = (_stm_key << 5) | (_stm_key >> 27); \
                            if (OBF_OPAQUE_PREDICATE_TRUE_2(_stm_key)) goto _storm_alpha_; \
                            else { K8_ASSUME(0); goto _storm_beta_; } \
                        case 1: \
                            _obf_global_opaque_seed = OBF_MBA_SUB(_obf_global_opaque_seed, (int)_stm_key); \
                            goto _storm_beta_; \
                        case 2: \
                            _stm_acc = OBF_MBA_NOT(_stm_acc ^ _stm_seed); \
                            if (OBF_OPAQUE_PREDICATE_FALSE_1()) { K8_ASSUME(0); goto _storm_dead_X_; } \
                            goto _storm_gamma_; \
                        case 3: \
                            OBF_CALL_ANY_LOCAL_JUNK(); \
                            _stm_key = OBF_MBA_MUL_CONST3((unsigned int)__COUNTER__ ^ _stm_key); \
                            goto _storm_gamma_; \
                        case 4: \
                            _stm_acc = OBF_MBA_ADD(_stm_acc, 0xDEAD0001U ^ (unsigned int)OBF_CALL_ANY_LOCAL_JUNK()); \
                            goto _storm_alpha_; \
                        default: \
                            _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed, (int)_stm_acc); \
                            goto _storm_loop_end_; \
                    } \
                } else { K8_ASSUME(0); goto _storm_dead_Y_; } \
            _storm_alpha_: \
                _stm_acc = (_stm_acc >> 3) | (_stm_acc << 29); \
                _obf_global_opaque_seed = OBF_MBA_ADD(_obf_global_opaque_seed, (int)_stm_acc); \
                NOP(); goto _storm_loop_end_; \
            _storm_beta_: \
                _stm_acc = OBF_MBA_XOR(_stm_acc, 0xFACEFEEDU ^ (unsigned int)OBF_CALL_ANY_LOCAL_JUNK()); \
                NOP(); NOP(); goto _storm_loop_end_; \
            _storm_gamma_: \
                OBF_CALL_ANY_LOCAL_JUNK(); \
                _stm_key = OBF_MBA_ADD(_stm_key, _stm_acc ^ (unsigned int)__LINE__); \
                goto _storm_loop_end_; \
            _storm_dead_X_: K8_ASSUME(0); _obf_global_opaque_seed++; goto _storm_loop_end_; \
            _storm_dead_Y_: K8_ASSUME(0); _obf_global_opaque_seed--; goto _storm_loop_end_; \
            _storm_loop_end_: \
                _stm_iter = OBF_MBA_SUB(_stm_iter, 1U); \
                if (_stm_iter > 0U && OBF_OPAQUE_PREDICATE_TRUE_1()) goto _storm_hub_; \
                _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed, \
                    (int)0xFEEDF00DU ^ (int)_stm_acc ^ (int)_stm_key); \
                OBF_CALL_ANY_LOCAL_JUNK(); NOP(); \
            } while(0)

        #define OBF_BOGUS_FLOW_VORTEX() \
            do { \
                volatile unsigned int _vx_state = ((unsigned int)__TIME__[6] + (unsigned int)_obf_global_opaque_seed) % 7U; \
                volatile unsigned int _vx_spin  = OBF_MBA_MUL_CONST3((unsigned int)__COUNTER__ ^ (unsigned int)_obf_global_opaque_seed); \
                volatile unsigned int _vx_depth = (OBF_CALL_ANY_LOCAL_JUNK() & 3U) + 2U; \
                volatile unsigned int _vx_acc   = (_vx_spin << 11) | (_vx_spin >> 21); \
            _vortex_entry_: \
                NOP(); \
                _obf_global_opaque_seed = OBF_MBA_ADD(_obf_global_opaque_seed, \
                    (int)_vx_state ^ (int)_vx_spin ^ (int)OBF_CALL_ANY_LOCAL_JUNK()); \
                _vx_spin = OBF_MBA_XOR(OBF_MBA_XOR(_vx_spin, _vx_state), (unsigned int)__LINE__); \
                if (OBF_OPAQUE_PREDICATE_TRUE_2(_vx_spin)) { \
                    if ((_vx_state & 1U) == 0U) { \
                        _vx_acc = OBF_MBA_ADD(_vx_acc, (_vx_spin | _vx_depth)); \
                        if (!OBF_OPAQUE_PREDICATE_FALSE_1()) goto _vortex_arm_A_; \
                        else { K8_ASSUME(0); goto _vortex_dead_; } \
                    } else { \
                        _vx_acc = OBF_MBA_SUB(_vx_acc, (_vx_spin & _vx_depth)); \
                        goto _vortex_arm_B_; \
                    } \
                } else { K8_ASSUME(0); goto _vortex_dead_; } \
            _vortex_arm_A_: \
                _vx_state = ((_vx_state + _vx_acc) % 7U); \
                OBF_CALL_ANY_LOCAL_JUNK(); \
                goto _vortex_loop_chk_; \
            _vortex_arm_B_: \
                _vx_state = ((_vx_state ^ _vx_spin) % 7U); \
                NOP(); NOP(); \
                goto _vortex_loop_chk_; \
            _vortex_dead_: \
                K8_ASSUME(0); \
                _obf_global_opaque_seed ^= 0xBADC0DE; \
            _vortex_loop_chk_: \
                _vx_depth = OBF_MBA_SUB(_vx_depth, 1U); \
                if (_vx_depth > 0U && OBF_OPAQUE_PREDICATE_TRUE_1()) goto _vortex_entry_; \
                _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed, \
                    (int)0xC0FFEEU ^ (int)_vx_acc ^ (int)_vx_spin); \
                OBF_CALL_ANY_LOCAL_JUNK(); NOP(); OBF_CALL_ANY_LOCAL_JUNK(); \
            } while(0)

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
                unsigned int _rt_activation_key = OBF_MBA_XOR((unsigned int)time(nullptr), (unsigned int)_obf_global_opaque_seed ^ (unsigned int)__COUNTER__); \
                _rt_activation_key = OBF_MBA_ADD(_rt_activation_key, (vm_state_ref).r0 ^ (vm_state_ref).r1 ^ (vm_state_ref).pc); \
                \
                if (((_rt_activation_key >> ((OBF_CALL_ANY_LOCAL_JUNK() & 3) + 2)) & 0x7U) == ((unsigned int)__TIME__[(_rt_activation_key>>8)%8] & 0x7U) ) { \
                    NOP(); \
                    volatile int _rt_decision_val = OBF_MBA_XOR(_obf_global_opaque_seed, (int)__LINE__ ^ (int)time(nullptr) ^ (int)(vm_state_ref).dispatch_key); \
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
                        if ((_rt_decision_val & 0x180) && (rand() & 1) && OBF_OPAQUE_PREDICATE_TRUE_1() || !OBF_OPAQUE_PREDICATE_TRUE_1()) { \
                            if (((unsigned int)_obf_global_opaque_seed ^ __LINE__) % 3 == 0) { \
                                obf_vm_engine::_seh_forced_exception_effect(vm_state_ref); \
                            } else { \
                                __debugbreak(); \
                            } \
                        } \
                        unsigned int _rt_err_seed = (unsigned int)_obf_global_opaque_seed ^ (unsigned int)__TIME__[0] ^ (unsigned int)__COUNTER__; \
                        auto llll = (((_rt_err_seed >> 8) & 0xFF) + (_rt_err_seed & 0xFF)) ^ (((vm_state_ref).r0 << 5) + (OBF_CALL_ANY_LOCAL_JUNK() % 10));\
                        throw runtime_error(OBFUSCATE_STRING("pojkdkddkeifpojkdkddkeifpojkdkddkeifpojkdkddkeif Oh skibiddi oooh")); \
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
                    unsigned int _htm_base_val1 = OBF_MBA_XOR((unsigned int)_htm_i * 13U, (unsigned int)time(nullptr) + (unsigned int)_obf_global_opaque_seed); \
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

    K8_NOINLINE static void _k8_peb_check(volatile uint32_t* _k8_key) {
        volatile uintptr_t _ntd = 0;
        unsigned char* _stk = (unsigned char*)_AddressOfReturnAddress();
            for (int _wi = 0; _wi < 128; ++_wi, _stk += (1<<12)) {
            __try {
                unsigned char* _pg = (unsigned char*)((uintptr_t)_stk & ~(uintptr_t)0xFFFFu);
                if (_pg[0]==0x4Du && _pg[1]==0x5Au) {
                    uint32_t* _pe = (uint32_t*)(_pg + *(int*)(_pg+0x3C));
                    if (_pe[0] == 0x00004550u) {
                        uint32_t _erva = ((uint32_t*)(_pg+0x18+0x108+0x70))[0];
                        if (_erva) {
                            char* _nm = (char*)(_pg + *(uint32_t*)(_pg+_erva+0xC));
                            if (_nm[0]=='n'&&_nm[1]=='t'&&_nm[2]=='d'&&
                               _nm[3]=='l'&&_nm[4]=='l') {
                                _ntd = (uintptr_t)_pg; break;
                            }
                        }
                    }
                }
            } __except(1) {}
        }
        if (!_ntd) return;
        unsigned char* _b = (unsigned char*)_ntd;
        uint32_t _er = ((uint32_t*)(_b+((int*)(_b+0x3C))[0]+0x18+0x70))[0];
        if (!_er) return;
        uint32_t* _fn2 = (uint32_t*)(_b + *(uint32_t*)(_b+_er+0x1C));
        uint32_t* _nm2 = (uint32_t*)(_b + *(uint32_t*)(_b+_er+0x20));
        uint16_t* _od2 = (uint16_t*)(_b + *(uint32_t*)(_b+_er+0x24));
        uint32_t  _nc  = *(uint32_t*)(_b+_er+0x18);
        for (uint32_t _ei = 0; _ei < _nc; ++_ei) {
            char* _en = (char*)(_b + _nm2[_ei]);
            uint32_t _fh = 0x811C9DC5u;
            for (int _fi = 0; _en[_fi]; ++_fi)
                _fh = (_fh ^ (uint8_t)_en[_fi]) * 0x01000193u;
            if (_fh == 0x5B09E90Du) { // NtQueryInformationProcess
                typedef long(__stdcall*_QIP)(void*,int,void*,unsigned long,unsigned long*);
                _QIP _qip = (_QIP)(_b + _fn2[_od2[_ei]]);
                struct { uintptr_t p,a,b,c; } _pbi = {};
                if (_qip((void*)(uintptr_t)(uint64_t)-1,0,&_pbi,sizeof(_pbi),0) == 0) {
                    volatile uint8_t* _peb = (volatile uint8_t*)_pbi.p;
                    if (_peb[2]) *_k8_key = (uint32_t)OBF_MBA_NOT(*_k8_key ^ 0xDEADC0DEu);
                    uint32_t _ngf = *(uint32_t*)(_peb + 0xBC);
                    if (_ngf & 0x70u) *_k8_key = (uint32_t)OBF_MBA_XOR(*_k8_key, 0xBADDEB06u);
                    uintptr_t _hp = *(uintptr_t*)(_peb + 0x30);
                    if (_hp) {
                        uint32_t _hf = *(uint32_t*)((char*)_hp + 0x40);
                        if (_hf & 0x40u) *_k8_key = (uint32_t)OBF_MBA_ADD(*_k8_key, 0xC0DEC0DEu);
                    }
                } break;
            }
        }
    }

    #pragma region ADVANCED_HARDENING
    #ifndef K8_ANTI_DEBUG_TIMING
    #define K8_ANTI_DEBUG_TIMING() \
        do { \
            static volatile uint64_t _adt_prev = 0ULL; \
            volatile uint64_t _adt_now = __rdtsc(); \
            if (_adt_prev != 0ULL && (_adt_now - _adt_prev) > 500000ULL) \
                _obf_global_opaque_seed = OBF_MBA_XOR( \
                    _obf_global_opaque_seed, 0xDEADC0DEu); \
            _adt_prev = _adt_now; \
        } while(0)
    #endif

    #ifndef K8_HARDEN_FUNCTION_ENTRY
    #define K8_HARDEN_FUNCTION_ENTRY() \
        do { \
            K8_ANTI_DEBUG_TIMING(); \
            volatile char* _hfe = (volatile char*)_alloca( \
                (((unsigned)__LINE__ & 7u) + 4u) * 4u); \
            *(volatile unsigned*)_hfe = \
                (unsigned)_obf_global_opaque_seed ^ (unsigned)__LINE__; \
            (void)_hfe; \
            _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed, \
                (int)__COUNTER__ ^ (int)__LINE__); \
        } while(0)
    #endif

    #ifndef K8_HARDEN_FUNCTION_EXIT
    #define K8_HARDEN_FUNCTION_EXIT() \
        do { \
            _obf_global_opaque_seed = OBF_MBA_ADD(_obf_global_opaque_seed, \
                (int)__COUNTER__ ^ (int)__LINE__); \
            OBF_CALL_ANY_LOCAL_JUNK(); \
        } while(0)
    #endif

    #ifndef K8_HARDEN_LOOP_BODY
    #define K8_HARDEN_LOOP_BODY() \
        do { \
            volatile int _hlb = OBF_MBA_XOR( \
                (int)__COUNTER__, _obf_global_opaque_seed); \
            _hlb = OBF_MBA_ADD(_hlb, OBF_CALL_ANY_LOCAL_JUNK()); \
            _obf_global_opaque_seed = OBF_MBA_XOR( \
                _obf_global_opaque_seed, _hlb ^ (int)__LINE__); \
            (void)_hlb; \
        } while(0)
    #endif

    #ifndef K8_OPAQUE_ASSERT
    #define K8_OPAQUE_ASSERT(expr) \
        do { \
            if (OBF_OPAQUE_PREDICATE_TRUE_1()) { \
                if (OBF_OPAQUE_PREDICATE_TRUE_2( \
                        (unsigned int)_obf_global_opaque_seed)) { \
                    if (!(expr)) { \
                        _obf_global_opaque_seed = OBF_MBA_XOR( \
                            _obf_global_opaque_seed, 0xDEADBEEFu); \
                    } \
                } \
            } \
        } while(0)
    #endif

    #ifndef K8_POISON_RETURN
    #define K8_POISON_RETURN(val) \
        do { \
            _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed, \
                (int)__COUNTER__ ^ (int)__LINE__); \
            OBF_CALL_ANY_LOCAL_JUNK(); \
            return (val); \
        } while(0)
    #endif

    #ifndef K8_INDIRECT_CALL
    #define K8_INDIRECT_CALL(fn_type, fn_ptr, ...) \
        ([&]() -> decltype(((fn_type)nullptr)(__VA_ARGS__)) { \
            volatile fn_type _ic = (fn_ptr); \
            uintptr_t _ik = (uintptr_t)__COUNTER__ \
                ^ (uintptr_t)(unsigned)_obf_global_opaque_seed \
                ^ (uintptr_t)_AddressOfReturnAddress(); \
            volatile fn_type* _ip = &_ic; \
            _ic = (fn_type)((uintptr_t)_ic ^ _ik); \
            _ic = (fn_type)((uintptr_t)_ic ^ _ik); \
            return (*_ip)(__VA_ARGS__); \
        }())
    #endif

    #ifndef K8_ANTITAMPER_GUARD
    #define K8_ANTITAMPER_GUARD(stub, len, crc, ssn, gadget) \
        do { (void)(stub); (void)(len); (void)(crc); } while(0)
    #endif

    #ifndef K8_STRUCT_OBFUSCATE_FIELD
    #define K8_STRUCT_OBFUSCATE_FIELD(ptr, field, val) \
        do { \
            volatile uintptr_t _sof_addr = \
                (uintptr_t)&((ptr)->field); \
            typedef decltype((ptr)->field) _sof_t; \
            volatile _sof_t* _sof_p = (volatile _sof_t*)_sof_addr; \
            *_sof_p = (val); \
        } while(0)
    #endif

    namespace obf_vm_engine {
        K8_NOINLINE static void _k8_dsptch_hardened(
                VMState& s, int argc, char** argv, unsigned int steps)
        {
            K8_ANTI_DEBUG_TIMING();

            for (unsigned int _hi = 0;
                 _hi < (unsigned int)VM_HANDLER_TABLE_SIZE; ++_hi) {
                const uint8_t* _p =
                    (const uint8_t*)(uintptr_t)vm_handler_table[_hi];
                if (_p[0]==0xE9u ||
                    (_p[0]==0xFFu && _p[1]==0x25u) ||
                    _p[0]==0xCCu) {
                    s.dispatch_key = (unsigned int)OBF_MBA_NOT(
                        s.dispatch_key ^
                        (unsigned int)_hi ^
                        (unsigned int)0xDEADC0DEu);
                }
            }

            {
                volatile uint32_t _crc = 0xFFFFFFFFu;
                const uint8_t* _p =
                    (const uint8_t*)(uintptr_t)vm_handler_table[0];
                for (int _bi = 0; _bi < 32; ++_bi) {
                    _crc ^= _p[_bi];
                    for (int _bb = 0; _bb < 8; ++_bb)
                        _crc = (_crc>>1) ^
                            (0xEDB88320u & (uint32_t)(0u-(_crc&1u)));
                }
                s.dispatch_key = (unsigned int)OBF_MBA_XOR(
                    s.dispatch_key, (_crc ^ 0xFFFFFFFFu));
            }

            {
                volatile char* _hf = (volatile char*)_alloca(
                    (((unsigned)__LINE__ & 0xFu) + 4u) * 4u);
                *(volatile unsigned*)_hf =
                    (unsigned)_obf_global_opaque_seed ^ (unsigned)__LINE__;
                (void)_hf;
            }

            dsptch(s, argc, argv, steps);

            {
                volatile uint64_t _post_tsc = __rdtsc();
                _obf_global_opaque_seed = OBF_MBA_XOR(
                    _obf_global_opaque_seed,
                    (int)s.dispatch_key ^
                    (int)(uint32_t)(_post_tsc & 0xFFFFu) ^
                    (int)__COUNTER__);
            }
        }
    }
    #define dsptch _k8_dsptch_hardened

    // --------------------------------------
    #pragma endregion ADVANCED_HARDENING

    #pragma warning(push)
    #pragma warning(disable: 4267)
    #pragma warning(disable: 4533)
    #pragma warning(disable: 4503)
    #define _main(main_body) \
            int main(int argc = 0, char** argv = nullptr) { \
                volatile uint64_t _mp_tsc0 = __rdtsc(); \
                volatile uintptr_t _mp_sp  = (uintptr_t)_AddressOfReturnAddress(); \
                volatile uint32_t _mp_tid  = (uint32_t)GetCurrentThreadId(); \
                volatile uint32_t _mp_pid  = (uint32_t)GetCurrentProcessId(); \
                volatile uint32_t _mp_key  = (uint32_t)OBF_MBA_XOR( \
                    (uint32_t)OBF_MBA_ADD( \
                        (uint32_t)((_mp_tsc0>>8)&0xFFFFu)^(uint32_t)(_mp_sp&0xFFFFu), \
                        (uint32_t)_mp_tid^(uint32_t)_mp_pid), \
                    (uint32_t)__LINE__); \
                K8_AUTOSPAWN(); \
                static volatile uint32_t _mp_ct[256]; \
                { uint32_t _cs=_mp_key^(uint32_t)(_mp_tsc0&0xFFFFFFFFu); \
                  for(int _ci=0;_ci<256;++_ci){ \
                      _cs^=(_cs<<13);_cs^=(_cs>>17);_cs^=(_cs<<5); \
                      _mp_ct[_ci]=(uint32_t)OBF_MBA_XOR(_cs,(uint32_t)(_ci*0x9E3779B1u)); \
                  } \
                } \
                _k8_peb_check(&_mp_key); \
                { int _ci4[4]={0}; volatile uint64_t _t0,_t1; \
                  __cpuid(_ci4,0);_t0=__rdtsc(); \
                  __cpuid(_ci4,1);_t1=__rdtsc(); \
                  if((_t1-_t0)>1000000ULL) _mp_key=(uint32_t)OBF_MBA_XOR(_mp_key,0xDEB00000u); \
                } \
                volatile uint32_t _mp_can[8]; \
                { for(int _cc=0;_cc<8;++_cc) \
                      _mp_can[_cc]=(uint32_t)OBF_MBA_XOR(_mp_ct[(_cc*7)&0xFF], \
                          (uint32_t)(_cc*0x6B2F5D1u)^_mp_key); \
                } \
                { \
                    static uint8_t _stb[16]; \
                    DWORD _op=0; \
                    uint32_t _sk=_mp_key^_mp_ct[0]; \
                    uint32_t _sm=_mp_ct[1]^_mp_ct[2]; \
                    _stb[0]=(uint8_t)(0xB8u^(_mp_key&0xFFu)); \
                    _stb[1]=(uint8_t)(_sk&0xFFu); \
                    _stb[2]=(uint8_t)((_sk>>8)&0xFFu); \
                    _stb[3]=(uint8_t)((_sk>>16)&0xFFu); \
                    _stb[4]=(uint8_t)((_sk>>24)&0xFFu); \
                    _stb[5]=(uint8_t)(0x35u^(_mp_key&0xFFu)); \
                    _stb[6]=(uint8_t)(_sm&0xFFu); \
                    _stb[7]=(uint8_t)((_sm>>8)&0xFFu); \
                    _stb[8]=(uint8_t)((_sm>>16)&0xFFu); \
                    _stb[9]=(uint8_t)((_sm>>24)&0xFFu); \
                    _stb[10]=(uint8_t)(0xC3u^(_mp_key&0xFFu)); \
                    for(int _si=0;_si<11;++_si) _stb[_si]^=(uint8_t)(_mp_key&0xFFu); \
                    VirtualProtect(_stb,16,PAGE_EXECUTE_READWRITE,&_op); \
                    typedef uint32_t(*_stub_fn_t)(); \
                    volatile _stub_fn_t _sfn=(_stub_fn_t)(uintptr_t)_stb; \
                    volatile uint32_t _sr=_sfn(); \
                    VirtualProtect(_stb,16,_op,&_op); \
                    _mp_key=(uint32_t)OBF_MBA_XOR(_mp_key,_sr); \
                    for(int _si=0;_si<16;++_si) _stb[_si]=0; \
                } \
                { \
                    static uint8_t _nsl[128]; DWORD _np=0; \
                    VirtualProtect(_nsl,128,PAGE_EXECUTE_READWRITE,&_np); \
                    uint32_t _ns=_mp_key^(uint32_t)(_mp_tsc0>>32); \
                    for(int _ni=0;_ni<64;++_ni){ \
                        _ns=_ns*1664525u+1013904223u; \
                        switch(_ns&3u){ \
                        case 0:_nsl[_ni*2]=0x66;_nsl[_ni*2+1]=0x90;break; \
                        case 1:_nsl[_ni*2]=0x87;_nsl[_ni*2+1]=0xC0;break; \
                        case 2:_nsl[_ni*2]=0x66;_nsl[_ni*2+1]=0x87;break; \
                        default:_nsl[_ni*2]=0x0F;_nsl[_ni*2+1]=0x1F;break; \
                        } \
                    } \
                    typedef void(*_nop_fn_t)(); \
                    volatile _nop_fn_t _nfn=(_nop_fn_t)(uintptr_t)_nsl; \
                    if(OBF_OPAQUE_PREDICATE_FALSE_1())(*_nfn)(); \
                    VirtualProtect(_nsl,128,_np,&_np); \
                    _mp_key=(uint32_t)OBF_MBA_ADD(_mp_key,_ns); \
                } \
                { for(int _cv=0;_cv<8;++_cv){ \
                      uint32_t _ex=(uint32_t)OBF_MBA_XOR(_mp_ct[(_cv*7)&0xFF], \
                          (uint32_t)(_cv*0x6B2F5D1u)^_mp_key); \
                      if(_mp_can[_cv]!=_ex) \
                          _mp_key=(uint32_t)OBF_MBA_NOT(_mp_key^0xBADCAFE0u); \
                  } \
                } \
                { static volatile uint32_t* _sc=nullptr; \
                  if(!_sc) _sc=(volatile uint32_t*)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,4); \
                  if(_sc){(*_sc)++;if(*_sc==1)_mp_key=(uint32_t)OBF_MBA_XOR(_mp_key,0xF1135714u);} \
                } \
                for(int _wp=0;_wp<256;++_wp) \
                    _mp_ct[_wp]=(uint32_t)OBF_MBA_XOR(_mp_ct[_wp],_mp_key); \
                _obf_global_opaque_seed=(int)OBF_MBA_XOR(_obf_global_opaque_seed,(int)_mp_key); \
                if(OBF_OPAQUE_PREDICATE_FALSE_1()){ \
                    typedef void(NTAPI*_tls_cb_t)(void*,unsigned long,void*); \
                    volatile _tls_cb_t _tcb=nullptr; \
                    if(_tcb)_tcb(nullptr,1,nullptr); \
                } \
                { \
                    volatile uint8_t* _sv=(volatile uint8_t*)(uintptr_t)&_obf_global_opaque_seed; \
                    *(_sv+0)^=(uint8_t)(_mp_key&0xFFu); \
                    *(_sv+0)^=(uint8_t)(_mp_key&0xFFu); \
                } \
                OBF_BOGUS_FLOW_STORM(); \
                OBF_BOGUS_FLOW_VORTEX(); \
                { static volatile uint64_t _k8adt = 0ULL; \
                  uint64_t _k8now = __rdtsc(); \
                  if (_k8adt != 0ULL && (_k8now - _k8adt) > 2000000ULL) \
                      _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed, 0xDEADC0DEu); \
                  _k8adt = _k8now; } \
                OBF_BOGUS_FLOW_CYCLONE();\
                if (OBF_OPAQUE_PREDICATE_TRUE_1()  || !OBF_OPAQUE_PREDICATE_TRUE_1()) { OBF_BOGUS_FLOW_LABYRINTH(); }\
                OBF_BOGUS_FLOW_SCRAMBLE();\
                volatile unsigned int _d_seed = OBF_MBA_ADD((int)time(nullptr) ^ argc ^ (int)(__LINE__), _obf_global_opaque_seed ^ __COUNTER__); \
                _obf_global_opaque_seed = _d_seed; \
                OBF_FAKE_PROLOGUE_MANIP(); \
                OBF_STACK_AND_PROLOGUE_JUNK(_prologue_stack_junk_var1, 64 + (OBF_CALL_ANY_LOCAL_JUNK() & 63)); \
                OBF_STACK_AND_PROLOGUE_JUNK(_prologue_stack_junk_var2, 69 + (OBF_CALL_ANY_LOCAL_JUNK() & 68)); \
                OBF_STACK_AND_PROLOGUE_JUNK(_prologue_stack_junk_var3, 34 + (OBF_CALL_ANY_LOCAL_JUNK() & 44)); \
                OBF_STACK_AND_PROLOGUE_JUNK(_prologue_stack_junk_var4, 64 + (OBF_CALL_ANY_LOCAL_JUNK() & 32)); \
                obf_vm_engine::VMState vm_s(_obf_global_opaque_seed); \
                constexpr unsigned int VM_BYTECODE_LEN = 30U; \
                array<unsigned int, VM_BYTECODE_LEN> _obf_vm_bytecode; \
                vm_s.r0 = (unsigned int)_obf_global_opaque_seed ^ (0xABCDEF01U + __LINE__); \
                vm_s.r1 = (unsigned int)(__TIME__[0] << 8) ^ __COUNTER__ ^ argc; \
                vm_s.r2 = (unsigned int)(argv ? (uintptr_t)argv[0] : __LINE__) ^ (0xBADF00DU + (unsigned int)__TIME__[2]); \
                vm_s.dispatch_key = (argc > 0 && argv != nullptr && argv[0] != nullptr) ? \
                                    OBF_MBA_ADD((unsigned int)argv[0][0], (unsigned int)((string(argv[0]).length() > 1 ? argv[0][1] : (char)__COUNTER__) ^ __COUNTER__)) : \
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
                    unsigned int bc_val = ( ((unsigned int)i_bc * (17U + (unsigned int)__TIME__[5])) + __COUNTER__ + (unsigned int)_obf_global_opaque_seed ); \
                    bc_val = OBF_MBA_XOR(bc_val, (unsigned int)__TIME__[i_bc % 8]); \
                    unsigned int encryption_key = OBF_MBA_ADD(0xDEADBEEFU, ((unsigned int)i_bc * 0x101U) ^ (unsigned int)__LINE__); \
                    _obf_vm_bytecode[i_bc] = OBF_MBA_XOR(bc_val, encryption_key); \
                } \
                OBF_FAKE_PROLOGUE_MANIP(); \
                HANDLER_TABLE_MUTATE(obf_vm_engine::vm_handler_table, obf_vm_engine::VM_HANDLER_TABLE_SIZE, vm_s);\
                volatile unsigned int _vm_cipher_seed = 0x378829 ^ (unsigned int)__TIME__[5]; \
                for (size_t i_bc = 0; i_bc < VM_BYTECODE_LEN; ++i_bc) {\
                    if ((i_bc % 5) == 0) { OBF_STACK_AND_ACCESS(32, i_bc % 32, (char)(i_bc ^ _obf_global_opaque_seed)); } \
                        unsigned int bc_val = (((unsigned int)i_bc * (17U + (unsigned int)__TIME__[5])) + __COUNTER__ + (unsigned int)_obf_global_opaque_seed); \
                        bc_val = OBF_MBA_XOR(bc_val, (unsigned int)__TIME__[i_bc % 8]); \
                        unsigned int encryption_key = OBF_MBA_ADD(0xDEADBEEFU, ((unsigned int)i_bc * 0x101U) ^ _vm_cipher_seed); \
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
                    { \
                    const uint8_t* _k8ah = (const uint8_t*)(uintptr_t)obf_vm_engine::vm_handle_op_arith; \
                    if (_k8ah[0]==0xE9u||(_k8ah[0]==0xFFu&&_k8ah[1]==0x25u)||_k8ah[0]==0xCCu) \
                        _obf_global_opaque_seed = OBF_MBA_NOT(_obf_global_opaque_seed^(int)__LINE__); \
                    volatile uint64_t _k8dt0 = __rdtsc(); \
                    obf_vm_engine::dsptch(vm_s, argc, argv, (unsigned int)dsptch_steps); \
                    volatile uint64_t _k8dt1 = __rdtsc(); \
                    if ((_k8dt1 - _k8dt0) > 5000000ULL) \
                        _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed, 0xC0DEBEEFu); \
                    } \
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
                _obf_global_opaque_seed = OBF_MBA_XOR(_obf_global_opaque_seed,\
                    (int)__LINE__ ^ (int)OBF_CALL_ANY_LOCAL_JUNK()); \
                main_body \
                for(g_bc=0; g_bc < VM_BYTECODE_LEN; ++g_bc){ \
                        if ((g_bc % 5) == 0){ for(int ggg = 3; ggg <direct_cff_loops; ggg+=5){OBF_BOGUS_FLOW_GRID();CALLER();CALLER();CALLER();} } else if(!((g_bc % 5) == 0)){ CALLER(); if(g_bc == 0){CALLER(); g_bc+=(unsigned int)OBF_CALL_ANY_LOCAL_JUNK() ^ (unsigned int)OBF_CALL_ANY_LOCAL_JUNK();} } else {CALLER(); g_bc = (OBF_CALL_ANY_LOCAL_JUNK() & 63) + (OBF_CALL_ANY_LOCAL_JUNK() & 68) - (OBF_CALL_ANY_LOCAL_JUNK() & 44) ^ (OBF_CALL_ANY_LOCAL_JUNK() & 32) << (OBF_CALL_ANY_LOCAL_JUNK() & 99);}\
                        CALLER();\
                }\
                Runtime(vm_s);\
                OBF_BOGUS_FLOW_WEAVER();\
                volatile unsigned int epi_ = OBF_MBA_XOR(vm_s.r0, vm_s.r1 ^ (unsigned int)time(nullptr) ^ (unsigned int)__TIME__[7]); \
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
    #pragma warning(pop)
OPT