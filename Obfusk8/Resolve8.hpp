#pragma once
#pragma optimize("Obfusk8 no opt", off)
    
    #include <windows.h>
    #include <cstdint>
    #include <string>
    #include <cstdint>
    #include <type_traits>
    #include "AES8.hpp"
    
    #ifdef _MSC_VER
    #define MBA_INLINE __forceinline
    #else
    #define MBA_INLINE inline __attribute__((always_inline))
    #endif
    
    #pragma region MBA_OFF
    // ------------------------------------------------
        template<typename T>
        using mba_t = typename std::make_unsigned<typename std::decay<T>::type>::type;
    
        namespace mba_L1
        {
            template<typename T> MBA_INLINE T add_v1(T a, T b) {
                return (a ^ b) + ((a & b) << 1);
            }
            template<typename T> MBA_INLINE T add_v2(T a, T b) {
                return (a | b) + (a & b);
            }
            template<typename T> MBA_INLINE T sub_v1(T a, T b) {
                return (a ^ b) - ((~a & b) << 1);
            }
            template<typename T> MBA_INLINE T sub_v2(T a, T b) {
                return a + ~b + 1;
            }
            template<typename T> MBA_INLINE T xor_v1(T a, T b) {
                return (a | b) - (a & b);
            }
            template<typename T> MBA_INLINE T xor_v2(T a, T b) {
                return (a + b) - ((a & b) << 1);
            }
        }
    
        namespace mba_L2 {
            template<typename T> MBA_INLINE T add_v3(T a, T b) {
                return (2 * (a | b)) - (a ^ b);
            }
            template<typename T> MBA_INLINE T sub_v3(T a, T b) {
                return (a & ~b) - (~a & b);
            }
            template<typename T> MBA_INLINE T xor_v3(T a, T b) {
                return (~a & b) + (a & ~b);
            }
        }
    
        namespace mba_L3 {
            template<typename T> MBA_INLINE T add_v4(T a, T b)
            {
                T x = mba_L1::xor_v1(a, b);
                T y = (a & b) << 1;
                return mba_L2::add_v3(x, y);
            }
            template<typename T> MBA_INLINE T sub_v4(T a, T b) {
                T not_b = ~b;
                T neg_b = mba_L1::add_v1(not_b, (T)1);
                return mba_L1::add_v2(a, neg_b);
            }
            template<typename T> MBA_INLINE T xor_v4(T a, T b) {
                T sum = mba_L1::add_v1(a, b);
                T ded = (a & b) << 1;
                return mba_L1::sub_v1(sum, ded);
            }
        }
    
        namespace mba_dispatch
        {
            template<int I, typename T>
            MBA_INLINE T add_dispatch(T a, T b) {
                if constexpr (I % 4 == 0) return mba_L1::add_v1(a, b);
                else if constexpr (I % 4 == 1) return mba_L1::add_v2(a, b);
                else if constexpr (I % 4 == 2) return mba_L2::add_v3(a, b);
                else return mba_L3::add_v4(a, b);
            }
            template<int I, typename T>
            MBA_INLINE T sub_dispatch(T a, T b) {
                if constexpr (I % 4 == 0) return mba_L1::sub_v1(a, b);
                else if constexpr (I % 4 == 1) return mba_L1::sub_v2(a, b);
                else if constexpr (I % 4 == 2) return mba_L2::sub_v3(a, b);
                else return mba_L3::sub_v4(a, b);
            }
            template<int I, typename T>
            MBA_INLINE T xor_dispatch(T a, T b) {
                if constexpr (I % 4 == 0) return mba_L1::xor_v1(a, b);
                else if constexpr (I % 4 == 1) return mba_L1::xor_v2(a, b);
                else if constexpr (I % 4 == 2) return mba_L2::xor_v3(a, b);
                else return mba_L3::xor_v4(a, b);
            }
        }
    
        #define K8_CAST(val) ((size_t)(val))
    
        #ifndef OBF_MBA_ADD
        #define OBF_MBA_ADD(a, b) ((decltype(a))mba_dispatch::add_dispatch<__COUNTER__>(K8_CAST(a), K8_CAST(b)))
        #endif
    
        #ifndef OBF_MBA_SUB
        #define OBF_MBA_SUB(a, b) ((decltype(a))mba_dispatch::sub_dispatch<__COUNTER__>(K8_CAST(a), K8_CAST(b)))
        #endif
    
        #ifndef OBF_MBA_XOR
        #define OBF_MBA_XOR(a, b) ((decltype(a))mba_dispatch::xor_dispatch<__COUNTER__>(K8_CAST(a), K8_CAST(b)))
        #endif
    // ------------------------------------------------
    #pragma endregion MBA_OFF
    
    constexpr uint32_t _TIME_SEED = ((__TIME__[7] - '0') * 1 + (__TIME__[6] - '0') * 10 +
                                     (__TIME__[4] - '0') * 60 + (__TIME__[3] - '0') * 600 +
                                     (__TIME__[1] - '0') * 3600 + (__TIME__[0] - '0') * 36000);
    
    constexpr uint32_t HASH_IV =
        (aes_constexpr::sbox[(_TIME_SEED & 0xFF)] << 24) |
        (aes_constexpr::sbox[((_TIME_SEED >> 8) & 0xFF)] << 16) |
        (aes_constexpr::sbox[((_TIME_SEED >> 16) & 0xFF)] << 8) |
        (aes_constexpr::sbox[((_TIME_SEED >> 24) & 0xFF)]);
    
    __forceinline uintptr_t calc_offset_aes(uintptr_t target_offset)
    {
        volatile uintptr_t seed = _TIME_SEED & 0xFF;
        volatile uintptr_t sbox_val = aes_constexpr::sbox[seed];
        volatile uintptr_t enc_val = OBF_MBA_XOR(OBF_MBA_ADD(target_offset, seed), sbox_val);
        return OBF_MBA_SUB(OBF_MBA_XOR(enc_val, sbox_val), seed);
    }
    __forceinline uint32_t runtime_hash_aes(const char* str)
    {
        uint32_t h = HASH_IV;
        if (!str) return 0;
        
        while (*str) {
            char c = *str++;
            if (c >= 'a' && c <= 'z') c = (char)OBF_MBA_SUB((int)c, 0x20);
            uint8_t low_byte = (h & 0xFF) ^ (uint8_t)c;
            uint8_t sub = aes_constexpr::sbox[low_byte];
            h = (h >> 8) | (h << 24);
            h = OBF_MBA_XOR(h, (uint32_t)sub);
        }
        return h;
    }
    
    __forceinline uint32_t runtime_hash_w_aes(const wchar_t* str) {
        uint32_t h = HASH_IV;
        if (!str) return 0;
        while (*str) {
            wchar_t c = *str++;
            if (c >= L'a' && c <= L'z') c = (wchar_t)OBF_MBA_SUB((int)c, 0x20);
            uint8_t low_byte = (h & 0xFF) ^ (uint8_t)(c & 0xFF);
            uint8_t sub = aes_constexpr::sbox[low_byte];
            h = (h >> 8) | (h << 24);
            h = OBF_MBA_XOR(h, (uint32_t)sub);
        }
        return h;
    }
    
    #pragma region RESOLVER
    // ------------------------------------------------
        namespace StealthResolver
        {
    
            #if defined(_WIN64)
                #define OFF_TEB_PEB  0x60
                #define OFF_PEB_LDR  0x18
                #define OFF_LDR_LIST 0x20
            #else
                #define OFF_TEB_PEB  0x30
                #define OFF_PEB_LDR  0x0C
                #define OFF_LDR_LIST 0x14
            #endif
    
                template<typename T>
                __forceinline T* PtrAdd(void* base, uintptr_t offset) {
                    return (T*)OBF_MBA_ADD((uintptr_t)base, offset);
                }
    
                __forceinline uintptr_t GetPEB() {
                    uintptr_t off = calc_offset_aes(OFF_TEB_PEB);
            #if defined(_WIN64)
                    return (uintptr_t)__readgsqword(off);
            #else
                    return (uintptr_t)__readfsdword(off);
            #endif
                }
    
                __forceinline HMODULE GetModuleHandleH(uint32_t modHash) {
                    uintptr_t pPeb = GetPEB();
                    if (!pPeb) return nullptr;
    
                    uintptr_t pLdr = *PtrAdd<uintptr_t>((void*)pPeb, calc_offset_aes(OFF_PEB_LDR));
                    if (!pLdr) return nullptr;
    
                    LIST_ENTRY* pHead = PtrAdd<LIST_ENTRY>((void*)pLdr, calc_offset_aes(OFF_LDR_LIST));
                    if (!pHead) return nullptr;
                    LIST_ENTRY* pCurr = pHead->Flink;
                    if (!pCurr) return nullptr;
                    
                    while (pCurr != pHead) {
                        uintptr_t entryBase = OBF_MBA_SUB((uintptr_t)pCurr, sizeof(LIST_ENTRY));
    
            #if defined(_WIN64)
                        if (!entryBase) return nullptr;
                        uintptr_t dllBase = *PtrAdd<uintptr_t>((void*)entryBase, 0x30);
                        if (!dllBase) return nullptr;
                        USHORT nameLen    = *PtrAdd<USHORT>((void*)entryBase, 0x58);
                        wchar_t* nameBuf  = *PtrAdd<wchar_t*>((void*)entryBase, 0x60);
            #else
                        if (!entryBase) return nullptr;
                        uintptr_t dllBase = *PtrAdd<uintptr_t>((void*)entryBase, 0x18);
                        if (!dllBase) return nullptr;
                        USHORT nameLen    = *PtrAdd<USHORT>((void*)entryBase, 0x2C);
                        wchar_t* nameBuf  = *PtrAdd<wchar_t*>((void*)entryBase, 0x30);
            #endif
    
                        if (nameBuf && nameLen > 0) {
                            uint32_t currentHash = HASH_IV;
                            for (int i = 0; i < nameLen / 2; i++) {
                                wchar_t c = nameBuf[i];
                                if (c >= L'a' && c <= L'z') c = (wchar_t)OBF_MBA_SUB((int)c, 0x20);
    
                                uint8_t low_byte = (currentHash & 0xFF) ^ (uint8_t)(c & 0xFF);
                                uint8_t sub = aes_constexpr::sbox[low_byte];
                                currentHash = (currentHash >> 8) | (currentHash << 24);
                                currentHash = OBF_MBA_XOR(currentHash, (uint32_t)sub);
                            }
    
                            if (currentHash == modHash) {
                                return (HMODULE)dllBase;
                            }
                        }
                        pCurr = pCurr->Flink;
                    }
                    return nullptr;
                }
    
                __forceinline void* GetProcAddressH(HMODULE hMod, uint32_t funcHash) {
                    if (!hMod) return nullptr;
                    uintptr_t pBase = (uintptr_t)hMod;
                    if(!pBase)
                        return nullptr;
                    int32_t e_lfanew = *PtrAdd<int32_t>((void*)pBase, calc_offset_aes(0x3C));
                    if(!e_lfanew) return nullptr;
                    uintptr_t pNtHeaders = OBF_MBA_ADD(pBase, (uintptr_t)e_lfanew);
                    if(!pNtHeaders) return nullptr;
            #if defined(_WIN64)
                    uint32_t expRva  = *PtrAdd<uint32_t>((void*)pNtHeaders, calc_offset_aes(0x88));
                    uint32_t expSize = *PtrAdd<uint32_t>((void*)pNtHeaders, calc_offset_aes(0x8C));
            #else
                    uint32_t expRva  = *PtrAdd<uint32_t>((void*)pNtHeaders, calc_offset_aes(0x78));
                    uint32_t expSize = *PtrAdd<uint32_t>((void*)pNtHeaders, calc_offset_aes(0x7C));
            #endif
    
                    if (expRva == 0) return nullptr;
                    uintptr_t pExpDir = OBF_MBA_ADD(pBase, (uintptr_t)expRva);
                    uint32_t numberOfNames = *PtrAdd<uint32_t>((void*)pExpDir, calc_offset_aes(0x18));
                    uint32_t addrOfFunctions = *PtrAdd<uint32_t>((void*)pExpDir, calc_offset_aes(0x1C));
                    uint32_t addrOfNames = *PtrAdd<uint32_t>((void*)pExpDir, calc_offset_aes(0x20));
                    uint32_t addrOfOrdinals = *PtrAdd<uint32_t>((void*)pExpDir, calc_offset_aes(0x24));
    
                    for (uint32_t i = 0; i < numberOfNames; ++i) {
                        if(!addrOfNames)
                            return nullptr;
                        uintptr_t nameRvaPtr = OBF_MBA_ADD(pBase, OBF_MBA_ADD((uintptr_t)addrOfNames, (uintptr_t)(i * 4)));
                        if(nameRvaPtr)
                        {
                            uint32_t nameRva = *(uint32_t*)nameRvaPtr;
                            if(!nameRva)
                                return nullptr;
                            const char* name = (const char*)OBF_MBA_ADD(pBase, (uintptr_t)nameRva);
                            if(!name)
                                return nullptr;
                            if (runtime_hash_aes(name) == funcHash) {
                                uintptr_t ordPtr = OBF_MBA_ADD(pBase, OBF_MBA_ADD((uintptr_t)addrOfOrdinals, (uintptr_t)(i * 2)));
                                if(ordPtr)
                                {
                                    uint16_t ordinal = *(uint16_t*)ordPtr;
                                    if(!ordinal)
                                        return nullptr;
                                    uintptr_t funcRvaPtr = OBF_MBA_ADD(pBase, OBF_MBA_ADD((uintptr_t)addrOfFunctions, (uintptr_t)(ordinal * 4)));
                                    if(funcRvaPtr)
                                    {
                                        uint32_t funcRva = *(uint32_t*)funcRvaPtr;
                                        uintptr_t funcAddr = OBF_MBA_ADD(pBase, (uintptr_t)funcRva);
                                    
                                        if (funcRva >= expRva && funcRva < OBF_MBA_ADD(expRva, expSize)) {
                                            return nullptr;
                                        }
                                        return (void*)funcAddr;
                                    } else 
                                        return nullptr;
                                }
                            }
                        }
                    }
                    return nullptr;
                }
        }
    // ------------------------------------------------
    #pragma endregion RESOLVER

#pragma optimize("Obfusk8 with opt", on)
