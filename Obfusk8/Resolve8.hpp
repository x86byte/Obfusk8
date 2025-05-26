#pragma once

#include <cstdint>
#include <cstdio>
#include <windows.h>
#include <winnt.h>

#pragma region DEF
// --------------------------------------

    typedef struct _UNICODE_STRING 
    {
        USHORT Length;
        USHORT MaximumLength;
        PWSTR  Buffer;
    } UNICODE_STRING;

    typedef struct _LDR_DATA_TABLE_ENTRY 
    {
        LIST_ENTRY InLoadOrderLinks;
        LIST_ENTRY InMemoryOrderLinks;
        LIST_ENTRY InInitializationOrderLinks;
        PVOID      DllBase;
        PVOID      EntryPoint;
        ULONG      SizeOfImage;
        UNICODE_STRING FullDllName;
        UNICODE_STRING BaseDllName;
    } LDR_DATA_TABLE_ENTRY;

    typedef struct _PEB_LDR_DATA 
    {
        ULONG Length;
        BOOLEAN Initialized;
        PVOID SsHandle;
        LIST_ENTRY InLoadOrderModuleList;
        LIST_ENTRY InMemoryOrderModuleList;
        LIST_ENTRY InInitializationOrderModuleList;
    } PEB_LDR_DATA;

    typedef struct _PEB 
    {
        BYTE Reserved1[2];
        BYTE BeingDebugged;
        BYTE Reserved2[1];
        PVOID Reserved3[2];
        PEB_LDR_DATA* Ldr;
    } PEB;

    #if defined(_WIN64)
        typedef struct _TEB_PARTIAL 
        {
            BYTE Reserved1[0x60];
            PEB* ProcessEnvironmentBlock;
        } TEB_PARTIAL;
    #else
        typedef struct _TEB_PARTIAL 
        {
            BYTE Reserved1[0x30];
            PEB* ProcessEnvironmentBlock;
        } TEB_PARTIAL;
    #endif


    inline uint32_t _CT_HASH(const char* s) 
    {
        uint32_t v = 0x811c9dc5;
        while (*s) v = (v ^ uint8_t(*s++)) * 0x01000193;
        return v;
    }

    #define CT_HASH(str) (_CT_HASH(str))

    inline PEB* g_PEP() {
        TEB_PARTIAL* pTeb;
    #if defined(_WIN64)

        pTeb = reinterpret_cast<TEB_PARTIAL*>(__readgsqword(0x30));
        if (!pTeb) return nullptr;
        return pTeb->ProcessEnvironmentBlock;
    #elif defined(_WIN32)
        pTeb = reinterpret_cast<TEB_PARTIAL*>(__readfsdword(0x18));
        if (!pTeb) return nullptr;
        return pTeb->ProcessEnvironmentBlock;
    #else
    #error "Unsupported architecture for g_PEP TEB trick"
        return nullptr;
    #endif
    }

// --------------------------------------
#pragma endregion DEF

inline HMODULE find_module_base(uint32_t modhash) {
    PEB* peb = g_PEP();
    if (!peb || !peb->Ldr) return nullptr;
    LIST_ENTRY* head = &peb->Ldr->InMemoryOrderModuleList;
    for (LIST_ENTRY* curr = head->Flink; curr != head; curr = curr->Flink) {
        LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        UNICODE_STRING* us = &entry->BaseDllName;
        char nameA[64]{};
        int i = 0;
        int num_wchars = (us->Length / sizeof(wchar_t));
        for (; i < num_wchars && i < (sizeof(nameA) - 1); ++i) {
            wchar_t c = us->Buffer[i];
            nameA[i] = (char)((c >= L'A' && c <= L'Z') ? (c | 0x20) : c);
        }
        nameA[i] = 0;
        if (CT_HASH(nameA) == modhash) return (HMODULE)entry->DllBase;
    }
    return nullptr;
}

inline void* find_export_byhash(HMODULE hmod, uint32_t funchash) {
    if (!hmod) return nullptr;
    uint8_t* base = (uint8_t*)hmod;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if(dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if(nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

    if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0) {
        return nullptr;
    }
    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(base +
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* names = (DWORD*)(base + exp->AddressOfNames);
    WORD* ords = (WORD*)(base + exp->AddressOfNameOrdinals);
    DWORD* funcs = (DWORD*)(base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        if (names[i] == 0) continue;
        char* name = (char*)(base + names[i]);
        if (CT_HASH(name) == funchash) {
            if (ords[i] >= exp->NumberOfFunctions) continue;
            return (BYTE*)base + funcs[ords[i]];
        }
    }
    return nullptr;
}