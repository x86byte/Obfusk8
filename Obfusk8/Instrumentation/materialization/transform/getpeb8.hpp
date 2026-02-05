#pragma once

#include <windows.h>
#include "K8_UTILS/k8_utils.hpp"
#include "AES8.hpp"

NOOPT
    #define _L_SUB(a, b) ( \
        ((unsigned int)(a) ^ (unsigned int)(b)) - \
        (2 * ((~(unsigned int)(a)) & (unsigned int)(b))) \
    )

    #define _L_XOR(a, b) ( \
        ((unsigned int)(a) | (unsigned int)(b)) - \
        ((unsigned int)(a) & (unsigned int)(b)) \
    )

    #define _L_OR(a, b) ( \
        ((unsigned int)(a) + (unsigned int)(b)) - \
        ((unsigned int)(a) & (unsigned int)(b)) \
    )

    K8_FORCEINLINE uint32_t _bstrap_hash(const char* str) {
        uint32_t h = _BSTRAP_IV;
        if (!str) return 0;

        while (*str) {
            char c = *str++;
            if (c >= 'a' && c <= 'z') {
                c = (char)_L_SUB((int)c, 0x20);
            }
            uint8_t low_byte = (uint8_t)_L_XOR((h & 0xFF), (uint32_t)c);
            uint8_t sub = aes_constexpr::sbox[low_byte];
            h = _L_OR((h >> 8), (h << 24));
            h = _L_XOR(h, (uint32_t)sub);
        }
        return h;
    }

    namespace K8_PEB_Syscall
    {
        typedef struct _UNICODE_STRING_K8 {
            USHORT Length;
            USHORT MaximumLength;
            PWSTR  Buffer;
        } UNICODE_STRING_K8;

        typedef struct _LDR_DATA_TABLE_ENTRY_K8 {
            LIST_ENTRY InLoadOrderLinks;
            LIST_ENTRY InMemoryOrderLinks;
            LIST_ENTRY InInitializationOrderLinks;
            PVOID DllBase;
            PVOID EntryPoint;
            ULONG SizeOfImage;
            UNICODE_STRING_K8 FullDllName;
            UNICODE_STRING_K8 BaseDllName;
        } LDR_DATA_TABLE_ENTRY_K8;

        typedef struct _PEB_LDR_DATA_K8
        {
            ULONG Length;
            BOOLEAN Initialized;
            PVOID SsHandle;
            LIST_ENTRY InLoadOrderModuleList;
            LIST_ENTRY InMemoryOrderModuleList;
            LIST_ENTRY InInitializationOrderModuleList;
        } PEB_LDR_DATA_K8;

        typedef struct _PEB_K8
        {
            BYTE Reserved1[2];
            BYTE BeingDebugged;
            BYTE Reserved2[1];
            PVOID Reserved3[2];
            PEB_LDR_DATA_K8* Ldr;
        } PEB_K8;

        K8_FORCEINLINE HMODULE GetNtdllBase() {
            #if defined(_WIN64)
                        uintptr_t pTeb = __readgsqword(0x30);
                        uintptr_t pPeb = *(uintptr_t*)(pTeb + 0x60);
            #else
                        uintptr_t pTeb = __readfsdword(0x18);
                        uintptr_t pPeb = *(uintptr_t*)(pTeb + 0x30);
            #endif
            PEB_K8* peb = (PEB_K8*)pPeb;
            PEB_LDR_DATA_K8* ldr = peb->Ldr;

            LIST_ENTRY* head = &ldr->InMemoryOrderModuleList;
            LIST_ENTRY* curr = head->Flink;

            while (curr != head) {
                LDR_DATA_TABLE_ENTRY_K8* entry = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY_K8, InMemoryOrderLinks);

                if (entry->BaseDllName.Buffer && entry->BaseDllName.Length == 18) { //18 bytes = L"ntdll.dll" 9 char * 2
                    wchar_t c = entry->BaseDllName.Buffer[0];
                    if (c == L'n' || c == L'N') return (HMODULE)entry->DllBase;
                }
                curr = curr->Flink;
            }
            return nullptr;
        }

        K8_FORCEINLINE uint32_t g_ssh_v_hash(HMODULE hNtdll, uint32_t t_hash) {
            uint8_t* base = (uint8_t*)hNtdll;
            PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
            uint32_t expRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)(base + expRva);

            uint32_t* names = (uint32_t*)(base + exp->AddressOfNames);
            uint32_t* funcs = (uint32_t*)(base + exp->AddressOfFunctions);
            uint16_t* ords = (uint16_t*)(base + exp->AddressOfNameOrdinals);

            uintptr_t targetAddr = 0;

            for (uint32_t i = 0; i < exp->NumberOfNames; ++i) {
                char* name = (char*)(base + names[i]);
                if (_bstrap_hash(name) == t_hash) {
                    targetAddr = (uintptr_t)(base + funcs[ords[i]]);
                    break;
                }
            }

            if (!targetAddr) return -1;

            uint32_t ssn = 0;
            for (uint32_t i = 0; i < exp->NumberOfNames; ++i) {
                char* name = (char*)(base + names[i]);
                if (name[0] == 'Z' && name[1] == 'w') {
                    uintptr_t addr = (uintptr_t)(base + funcs[ords[i]]);
                    if (addr < targetAddr) {
                        ssn++;
                    }
                }
            }
            return ssn;
        }

        #pragma pack(push, 1)
            struct Shellcode {
                uint8_t mov_r10_rcx[3] = { 0x4C, 0x8B, 0xD1 };
                uint8_t mov_eax[1] = { 0xB8 };
                uint32_t ssn = 0;
                uint8_t syscall[2] = { 0x0F, 0x05 };
                uint8_t ret[1] = { 0xC3 };
            };
        #pragma pack(pop)

        template <typename... Args>
        K8_FORCEINLINE NTSTATUS DoSyscall(uint32_t ssn, void* storage, Args... args) {
            if (!storage) return 0xC0000005;

            Shellcode* sc = (Shellcode*)storage;
            sc->mov_r10_rcx[0] = 0x4C; sc->mov_r10_rcx[1] = 0x8B; sc->mov_r10_rcx[2] = 0xD1;
            sc->mov_eax[0] = 0xB8;
            sc->ssn = ssn;
            sc->syscall[0] = 0x0F; sc->syscall[1] = 0x05;
            sc->ret[0] = 0xC3;

            typedef NTSTATUS(NTAPI* pSyscall)(void*, void*, void*, void*, void*, void*);
            pSyscall fn = (pSyscall)storage;

            void* arg_list[6] = { 0 };
            int i = 0;
            auto unpack = [&](auto arg) {
                if (i < 6) arg_list[i++] = (void*)(uintptr_t)arg;
                };
            (unpack(args), ...);

            return fn(arg_list[0], arg_list[1], arg_list[2], arg_list[3], arg_list[4], arg_list[5]);
        }
    }

    __forceinline uintptr_t GetPEB_ViaSyscall() {
        using namespace K8_PEB_Syscall;

        HMODULE hNtdll = GetNtdllBase();
        if (!hNtdll) return 0;

        uint32_t ssnAlloc = g_ssh_v_hash(hNtdll, _bstrap_hash(OBFUSCATE_STRING("ZwAllocateVirtualMemory").c_str()));
        if (ssnAlloc == -1) return 0;

        uint32_t ssnQuery = g_ssh_v_hash(hNtdll, _bstrap_hash(OBFUSCATE_STRING("ZwQueryInformationProcess").c_str()));
        if (ssnQuery == -1) return 0;

        uint8_t* base = (uint8_t*)hNtdll;
        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
        uint32_t expRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)(base + expRva);
        uint32_t* names = (uint32_t*)(base + exp->AddressOfNames);
        uint32_t* funcs = (uint32_t*)(base + exp->AddressOfFunctions);
        uint16_t* ords = (uint16_t*)(base + exp->AddressOfNameOrdinals);

        void* fnAllocAddr = nullptr;
        for (uint32_t i = 0; i < exp->NumberOfNames; ++i) {
            if (_bstrap_hash((char*)(base + names[i])) == _bstrap_hash(OBFUSCATE_STRING("NtAllocateVirtualMemory")))
            {
                fnAllocAddr = (void*)(base + funcs[ords[i]]);
                break;
            }
        }
        if (!fnAllocAddr) return 0;

        void* stub = nullptr;
        SIZE_T size = 4096;
        typedef NTSTATUS(NTAPI* pAlloc)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
        pAlloc fnAlloc = (pAlloc)fnAllocAddr;
        if (fnAlloc((HANDLE)-1, &stub, 0, &size, MEM_COMMIT, PAGE_EXECUTE_READWRITE) != 0) return 0;

        PROCESS_BASIC_INFORMATION_K8 pbi = { 0 };
        ULONG len = 0;
        NTSTATUS status = DoSyscall(ssnQuery, stub,
            (HANDLE)-1,
            (void*)0,
            &pbi,
            sizeof(pbi),
            &len
        );
        if (!status)
            return ((uintptr_t)pbi.PebBaseAddress);
        return 0;
    }
OPT