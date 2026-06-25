#pragma once

#include "AES8.hpp"
#include "K8_UTILS/k8_utils.hpp"
#include "getpeb8.hpp"

NOOPT
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
    
        #ifndef VALID_OBF_MBA_ADD
        #define VALID_OBF_MBA_ADD(a, b) ((decltype(a))mba_dispatch::add_dispatch<__COUNTER__>(K8_CAST(a), K8_CAST(b)))
        #endif

        #ifndef VALID_OBF_MBA_SUB
        #define VALID_OBF_MBA_SUB(a, b) ((decltype(a))mba_dispatch::sub_dispatch<__COUNTER__>(K8_CAST(a), K8_CAST(b)))
        #endif

        #ifndef VALID_OBF_MBA_XOR
        #define VALID_OBF_MBA_XOR(a, b) ((decltype(a))mba_dispatch::xor_dispatch<__COUNTER__>(K8_CAST(a), K8_CAST(b)))
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
        volatile uintptr_t enc_val = VALID_OBF_MBA_XOR(VALID_OBF_MBA_ADD(target_offset, seed), sbox_val);
        return VALID_OBF_MBA_SUB(VALID_OBF_MBA_XOR(enc_val, sbox_val), seed);
    }
    __forceinline uint32_t runtime_hash_aes(const char* str)
    {
        uint32_t h = HASH_IV;
        if (!str) return 0;
        
        while (*str) {
            char c = *str++;
            if (c >= 'a' && c <= 'z') c = (char)VALID_OBF_MBA_SUB((int)c, 0x20);
            uint8_t low_byte = (h & 0xFF) ^ (uint8_t)c;
            uint8_t sub = aes_constexpr::sbox[low_byte];
            h = (h >> 8) | (h << 24);
            h = VALID_OBF_MBA_XOR(h, (uint32_t)sub);
        }
        return h;
    }
    
    __forceinline uint32_t runtime_hash_w_aes(const wchar_t* str) {
        uint32_t h = HASH_IV;
        if (!str) return 0;
        while (*str) {
            wchar_t c = *str++;
            if (c >= L'a' && c <= L'z') c = (wchar_t)VALID_OBF_MBA_SUB((int)c, 0x20);
            uint8_t low_byte = (h & 0xFF) ^ (uint8_t)(c & 0xFF);
            uint8_t sub = aes_constexpr::sbox[low_byte];
            h = (h >> 8) | (h << 24);
            h = VALID_OBF_MBA_XOR(h, (uint32_t)sub);
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
                    return (T*)VALID_OBF_MBA_ADD((uintptr_t)base, offset);
                }
    
                __forceinline uintptr_t GetPEB() {
                    return (GetPEB_ViaSyscall());
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
                    
                    while (pCurr != pHead)
                    {
                        uintptr_t entryBase = VALID_OBF_MBA_SUB((uintptr_t)pCurr, sizeof(LIST_ENTRY));
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
                                if (c >= L'a' && c <= L'z') c = (wchar_t)VALID_OBF_MBA_SUB((int)c, 0x20);
                                uint8_t low_byte = (currentHash & 0xFF) ^ (uint8_t)(c & 0xFF);
                                uint8_t sub = aes_constexpr::sbox[low_byte];
                                currentHash = (currentHash >> 8) | (currentHash << 24);
                                currentHash = VALID_OBF_MBA_XOR(currentHash, (uint32_t)sub);
                            }
                            if (currentHash == modHash)
                                return (HMODULE)dllBase;
                        }
                        pCurr = pCurr->Flink;
                    }
                    return nullptr;
                }

                __forceinline uint32_t runtime_hash_aes(const char* str)
                {
                    uint32_t h = HASH_IV;
                    if (!str) return 0;
                    while (*str) {
                        char c = *str++;
                        if (c >= 'a' && c <= 'z') c = c - 0x20;
                        uint8_t low_byte = (h & 0xFF) ^ (uint8_t)c;
                        uint8_t sub = aes_constexpr::sbox[low_byte];
                        h = (h >> 8) | (h << 24);
                        h = VALID_OBF_MBA_XOR(h, (uint32_t)sub);
                    }
                    return h;
                }

                __forceinline uint32_t runtime_hash_w_aes(const wchar_t* str)
                {
                    uint32_t h = HASH_IV;
                    if (!str) return 0;
                    while (*str) {
                        wchar_t c = *str++;
                        if (c >= L'a' && c <= L'z') c = c - 0x20;
                        uint8_t low_byte = (h & 0xFF) ^ (uint8_t)(c & 0xFF);
                        uint8_t sub = aes_constexpr::sbox[low_byte];
                        h = (h >> 8) | (h << 24);
                        h = VALID_OBF_MBA_XOR(h, (uint32_t)sub);
                    }
                    return h;
                }

                __forceinline HMODULE GetModuleHandleH_sys(uint32_t modHash)
                {
                    PPEB_K8 pPeb = reinterpret_cast<PPEB_K8>(GetPEB());
                    if (!pPeb || !pPeb->Ldr) return nullptr;

                    LIST_ENTRY* head = &pPeb->Ldr->InMemoryOrderModuleList;
                    LIST_ENTRY* curr = head->Flink;

                    while (curr != head) {
                        LDR_DATA_TABLE_ENTRY_K8* entry = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY_K8, InMemoryOrderLinks);
                        if (entry->BaseDllName.Buffer) {
                            uint32_t h = HASH_IV;
                            for (int i = 0; i < entry->BaseDllName.Length / 2; i++) {
                                wchar_t c = entry->BaseDllName.Buffer[i];
                                if (c >= L'a' && c <= L'z') c = c - 0x20;
                                uint8_t low_byte = (h & 0xFF) ^ (uint8_t)(c & 0xFF);
                                uint8_t sub = aes_constexpr::sbox[low_byte];
                                h = (h >> 8) | (h << 24);
                                h = VALID_OBF_MBA_XOR(h, (uint32_t)sub);
                            }
                            if (h == modHash) return (HMODULE)entry->DllBase;
                        }
                        curr = curr->Flink;
                    }
                    return nullptr;
                }

                __forceinline void* GetProcAddressH_sys(HMODULE hMod, uint32_t funcHash)
                {
                    if (!hMod) return nullptr;
                    uint8_t* base = (uint8_t*)hMod;
                    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
                    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(VALID_OBF_MBA_ADD(base, dos->e_lfanew));
                    uint32_t expRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                    if (expRva == 0) return nullptr;
                    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)(VALID_OBF_MBA_ADD(base, expRva));
                    uint32_t* nameArray = (uint32_t*)(VALID_OBF_MBA_ADD(base, exp->AddressOfNames));
                    uint32_t* funcArray = (uint32_t*)(VALID_OBF_MBA_ADD(base, exp->AddressOfFunctions));
                    uint16_t* ordArray = (uint16_t*)(VALID_OBF_MBA_ADD(base, exp->AddressOfNameOrdinals));
                    for (uint32_t i = 0; i < exp->NumberOfNames; ++i) {
                        uint16_t ord = ordArray[i];
                        if (ord >= exp->NumberOfFunctions) continue;
                        if (runtime_hash_aes((char*)(base + nameArray[i])) == funcHash)
                            return (void*)(base + funcArray[ord]);
                    }
                    return nullptr;
                }
    
                __forceinline void* GetProcAddressH(HMODULE hMod, uint32_t funcHash, uint32_t depth = 0)
                {
                    if (depth > 6) return nullptr;
                    if (!hMod) return nullptr;
                    uintptr_t pBase = (uintptr_t)hMod;
                    int32_t e_lfanew = *PtrAdd < int32_t > ((void *) pBase, calc_offset_aes(0x3C));
                    uintptr_t pNtHeaders = VALID_OBF_MBA_ADD(pBase, (uintptr_t)e_lfanew);
                    #if defined(_WIN64)
                                        uint32_t expRva  = *PtrAdd<uint32_t>((void*)pNtHeaders, calc_offset_aes(0x88));
                                        uint32_t expSize = *PtrAdd<uint32_t>((void*)pNtHeaders, calc_offset_aes(0x8C));
                    #else
                                        uint32_t expRva = *PtrAdd < uint32_t > ((void *) pNtHeaders, calc_offset_aes(0x78));
                                        uint32_t expSize = *PtrAdd < uint32_t > ((void *) pNtHeaders, calc_offset_aes(0x7C));
                    #endif

                    if (expRva == 0) return nullptr;
                    uint32_t numberOfNames = *PtrAdd < uint32_t > ((void *) VALID_OBF_MBA_ADD(pBase, (uintptr_t)expRva), calc_offset_aes(0x18));
                    uint32_t numberOfFunctions = *PtrAdd < uint32_t > ((void *) VALID_OBF_MBA_ADD(pBase, (uintptr_t)expRva), calc_offset_aes(0x14));
                    uint32_t addrOfFunctions = *PtrAdd < uint32_t > ((void *) VALID_OBF_MBA_ADD(pBase, (uintptr_t)expRva), calc_offset_aes(0x1C));
                    uint32_t addrOfNames = *PtrAdd < uint32_t > ((void *) VALID_OBF_MBA_ADD(pBase, (uintptr_t)expRva), calc_offset_aes(0x20));
                    uint32_t addrOfOrdinals = *PtrAdd < uint32_t > ((void *) VALID_OBF_MBA_ADD(pBase, (uintptr_t)expRva), calc_offset_aes(0x24));

                    for (uint32_t i = 0; i < numberOfNames; ++i)
                    {
                        if (!addrOfNames)
                            return nullptr;
                        uintptr_t
                        nameRvaPtr = VALID_OBF_MBA_ADD(pBase, VALID_OBF_MBA_ADD((uintptr_t)addrOfNames, (uintptr_t)(i * 4)));
                        if (nameRvaPtr) {
                            uint32_t
                            nameRva = *(uint32_t *)nameRvaPtr;
                            if (!nameRva)
                                return nullptr;
                            const char *name = (const char *) VALID_OBF_MBA_ADD(pBase, (uintptr_t)nameRva);
                            if (!name)
                                return nullptr;
                            if (runtime_hash_aes(name) == funcHash)
                            {
                                uintptr_t
                                ordPtr = VALID_OBF_MBA_ADD(pBase, VALID_OBF_MBA_ADD((uintptr_t)addrOfOrdinals, (uintptr_t)(i * 2)));
                                if (ordPtr) {
                                    uint16_t ordinal = *(uint16_t *) ordPtr;
                                    if (ordinal >= numberOfFunctions) return nullptr;
                                    uintptr_t funcRvaPtr = VALID_OBF_MBA_ADD(pBase, VALID_OBF_MBA_ADD((uintptr_t)addrOfFunctions, (uintptr_t)(ordinal * 4)));
                                    if (funcRvaPtr) {
                                        uint32_t funcRva = *(uint32_t * )funcRvaPtr;
                                        if (funcRva >= expRva && funcRva < VALID_OBF_MBA_ADD(expRva, expSize)) {
                                            const char* forwarder = (const char*)VALID_OBF_MBA_ADD(pBase, (uintptr_t)funcRva);
                                            if (!forwarder || !*forwarder) return nullptr;

                                            const char* sep = nullptr;
                                            for (const char* p = forwarder; *p; ++p) {
                                                if (*p == '.' || *p == '!') sep = p;
                                            }
                                            if (!sep || sep == forwarder || !sep[1]) return nullptr;

                                            char dllName[96] = { 0 };
                                            size_t dllLen = (size_t)(sep - forwarder);
                                            if (dllLen == 0 || dllLen >= sizeof(dllName) - 5) return nullptr;

                                            for (size_t j = 0; j < dllLen; ++j) {
                                                char c = forwarder[j];
                                                if (c >= 'a' && c <= 'z') c = (char)VALID_OBF_MBA_SUB((int)c, 0x20);
                                                dllName[j] = c;
                                            }
                                            dllName[dllLen] = '\0';

                                            bool hasDllExt = false;
                                            if (dllLen >= 4) {
                                                char c0 = dllName[dllLen - 4];
                                                char c1 = dllName[dllLen - 3];
                                                char c2 = dllName[dllLen - 2];
                                                char c3 = dllName[dllLen - 1];
                                                hasDllExt =
                                                    (c0 == '.') &&
                                                    (c1 == 'D' || c1 == 'd') &&
                                                    (c2 == 'L' || c2 == 'l') &&
                                                    (c3 == 'L' || c3 == 'l');
                                            }
                                            if (!hasDllExt) {
                                                dllName[dllLen++] = '.';
                                                dllName[dllLen++] = 'D';
                                                dllName[dllLen++] = 'L';
                                                dllName[dllLen++] = 'L';
                                                dllName[dllLen] = '\0';
                                            }

                                            HMODULE fwdMod = GetModuleHandleH(runtime_hash_aes(dllName));
                                            if (!fwdMod) {
                                                fwdMod = GetModuleHandleH_sys(runtime_hash_aes(dllName));
                                            }
                                            if (!fwdMod) {
                                                HMODULE hKernel32 = GetModuleHandleH(runtime_hash_aes("KERNEL32.DLL"));
                                                if (!hKernel32) {
                                                    hKernel32 = GetModuleHandleH_sys(runtime_hash_aes("KERNEL32.DLL"));
                                                }

                                                if (hKernel32) {
                                                    using LoadLibraryA_t = HMODULE(WINAPI*)(LPCSTR);
                                                    LoadLibraryA_t pLoadLibraryA = reinterpret_cast<LoadLibraryA_t>(
                                                        GetProcAddressH(hKernel32, runtime_hash_aes("LoadLibraryA"), depth + 1)
                                                    );
                                                    if (!pLoadLibraryA) {
                                                        pLoadLibraryA = reinterpret_cast<LoadLibraryA_t>(
                                                            GetProcAddressH_sys(hKernel32, runtime_hash_aes("LoadLibraryA"))
                                                        );
                                                    }
                                                    if (pLoadLibraryA) {
                                                        fwdMod = pLoadLibraryA(dllName);
                                                    }
                                                }
                                            }
                                            if (!fwdMod) return nullptr;

                                            const char* fwdApi = sep + 1;
                                            if (!fwdApi || !*fwdApi) return nullptr;

                                            if (*fwdApi == '#') {
                                                uint32_t ord = 0;
                                                for (const char* p = fwdApi + 1; *p; ++p) {
                                                    if (*p < '0' || *p > '9') return nullptr;
                                                    ord = (ord * 10U) + (uint32_t)(*p - '0');
                                                }
                                                if (ord == 0) return nullptr;

                                                uintptr_t fBase = (uintptr_t)fwdMod;
                                                int32_t fLfanew = *PtrAdd<int32_t>((void*)fBase, calc_offset_aes(0x3C));
                                                uintptr_t fNtHeaders = VALID_OBF_MBA_ADD(fBase, (uintptr_t)fLfanew);
                                                #if defined(_WIN64)
                                                    uint32_t fExpRva = *PtrAdd<uint32_t>((void*)fNtHeaders, calc_offset_aes(0x88));
                                                    uint32_t fExpSize = *PtrAdd<uint32_t>((void*)fNtHeaders, calc_offset_aes(0x8C));
                                                #else
                                                    uint32_t fExpRva = *PtrAdd<uint32_t>((void*)fNtHeaders, calc_offset_aes(0x78));
                                                    uint32_t fExpSize = *PtrAdd<uint32_t>((void*)fNtHeaders, calc_offset_aes(0x7C));
                                                #endif
                                                if (fExpRva == 0) return nullptr;

                                                uintptr_t fExp = VALID_OBF_MBA_ADD(fBase, (uintptr_t)fExpRva);
                                                uint32_t fOrdBase = *PtrAdd<uint32_t>((void*)fExp, calc_offset_aes(0x10));
                                                uint32_t fNumberOfFunctions = *PtrAdd<uint32_t>((void*)fExp, calc_offset_aes(0x14));
                                                uint32_t fAddrOfFunctions = *PtrAdd<uint32_t>((void*)fExp, calc_offset_aes(0x1C));

                                                if (ord < fOrdBase) return nullptr;
                                                uint32_t fIndex = ord - fOrdBase;
                                                if (fIndex >= fNumberOfFunctions) return nullptr;

                                                uintptr_t fFuncRvaPtr = VALID_OBF_MBA_ADD(
                                                    fBase,
                                                    VALID_OBF_MBA_ADD((uintptr_t)fAddrOfFunctions, (uintptr_t)(fIndex * 4))
                                                );
                                                if (!fFuncRvaPtr) return nullptr;

                                                uint32_t fFuncRva = *(uint32_t*)fFuncRvaPtr;
                                                if (!fFuncRva) return nullptr;

                                                if (fFuncRva >= fExpRva && fFuncRva < VALID_OBF_MBA_ADD(fExpRva, fExpSize)) {
                                                    const char* nestedForwarder = (const char*)VALID_OBF_MBA_ADD(fBase, (uintptr_t)fFuncRva);
                                                    if (!nestedForwarder || !*nestedForwarder) return nullptr;

                                                    const char* nestedSep = nullptr;
                                                    for (const char* p = nestedForwarder; *p; ++p) {
                                                        if (*p == '.' || *p == '!') nestedSep = p;
                                                    }
                                                    if (!nestedSep || nestedSep == nestedForwarder || !nestedSep[1]) return nullptr;

                                                    char nestedDll[96] = { 0 };
                                                    size_t nestedDllLen = (size_t)(nestedSep - nestedForwarder);
                                                    if (nestedDllLen == 0 || nestedDllLen >= sizeof(nestedDll) - 5) return nullptr;

                                                    for (size_t j = 0; j < nestedDllLen; ++j) {
                                                        char c = nestedForwarder[j];
                                                        if (c >= 'a' && c <= 'z') c = (char)VALID_OBF_MBA_SUB((int)c, 0x20);
                                                        nestedDll[j] = c;
                                                    }
                                                    nestedDll[nestedDllLen] = '\0';

                                                    bool nestedHasDllExt = false;
                                                    if (nestedDllLen >= 4) {
                                                        char c0 = nestedDll[nestedDllLen - 4];
                                                        char c1 = nestedDll[nestedDllLen - 3];
                                                        char c2 = nestedDll[nestedDllLen - 2];
                                                        char c3 = nestedDll[nestedDllLen - 1];
                                                        nestedHasDllExt =
                                                            (c0 == '.') &&
                                                            (c1 == 'D' || c1 == 'd') &&
                                                            (c2 == 'L' || c2 == 'l') &&
                                                            (c3 == 'L' || c3 == 'l');
                                                    }
                                                    if (!nestedHasDllExt) {
                                                        nestedDll[nestedDllLen++] = '.';
                                                        nestedDll[nestedDllLen++] = 'D';
                                                        nestedDll[nestedDllLen++] = 'L';
                                                        nestedDll[nestedDllLen++] = 'L';
                                                        nestedDll[nestedDllLen] = '\0';
                                                    }

                                                    HMODULE nestedMod = GetModuleHandleH(runtime_hash_aes(nestedDll));
                                                    if (!nestedMod) {
                                                        nestedMod = GetModuleHandleH_sys(runtime_hash_aes(nestedDll));
                                                    }
                                                    if (!nestedMod) return nullptr;

                                                    const char* nestedApi = nestedSep + 1;
                                                    if (!nestedApi || !*nestedApi || *nestedApi == '#') return nullptr;

                                                    return GetProcAddressH(nestedMod, runtime_hash_aes(nestedApi), depth + 1);
                                                }

                                                return (void*)VALID_OBF_MBA_ADD(fBase, (uintptr_t)fFuncRva);
                                            }

                                            uint32_t fwdHash = runtime_hash_aes(fwdApi);
                                            void* resolvedFwd = GetProcAddressH(fwdMod, fwdHash, depth + 1);
                                            if (resolvedFwd) return resolvedFwd;

                                            bool isApiSetContract =
                                                ((dllName[0] == 'A' || dllName[0] == 'a') &&
                                                 (dllName[1] == 'P' || dllName[1] == 'p') &&
                                                 (dllName[2] == 'I' || dllName[2] == 'i') &&
                                                 dllName[3] == '-') ||
                                                ((dllName[0] == 'E' || dllName[0] == 'e') &&
                                                 (dllName[1] == 'X' || dllName[1] == 'x') &&
                                                 (dllName[2] == 'T' || dllName[2] == 't') &&
                                                 dllName[3] == '-');

                                            if (isApiSetContract || fwdMod == hMod) {
                                                HMODULE hKernelBase = GetModuleHandleH(runtime_hash_aes("KERNELBASE.DLL"));
                                                if (!hKernelBase) {
                                                    hKernelBase = GetModuleHandleH_sys(runtime_hash_aes("KERNELBASE.DLL"));
                                                }
                                                if (hKernelBase && hKernelBase != fwdMod) {
                                                    resolvedFwd = GetProcAddressH(hKernelBase, fwdHash, depth + 1);
                                                    if (resolvedFwd) return resolvedFwd;
                                                }

                                                PPEB_K8 scanPeb = reinterpret_cast<PPEB_K8>(GetPEB());
                                                if (scanPeb && scanPeb->Ldr) {
                                                    LIST_ENTRY* scanHead = &scanPeb->Ldr->InMemoryOrderModuleList;
                                                    LIST_ENTRY* scanCurr = scanHead->Flink;

                                                    while (scanCurr != scanHead) {
                                                        LDR_DATA_TABLE_ENTRY_K8* scanEntry =
                                                            CONTAINING_RECORD(scanCurr, LDR_DATA_TABLE_ENTRY_K8, InMemoryOrderLinks);
                                                        if (scanEntry && scanEntry->DllBase) {
                                                            HMODULE scanMod = (HMODULE)scanEntry->DllBase;
                                                            if (scanMod != hMod && scanMod != fwdMod) {
                                                                resolvedFwd = GetProcAddressH(scanMod, fwdHash, depth + 1);
                                                                if (resolvedFwd) return resolvedFwd;
                                                            }
                                                        }
                                                        scanCurr = scanCurr->Flink;
                                                    }
                                                }
                                            }

                                            return nullptr;
                                        }
                                        return ((void *)VALID_OBF_MBA_ADD(pBase, (uintptr_t)funcRva));
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
OPT
