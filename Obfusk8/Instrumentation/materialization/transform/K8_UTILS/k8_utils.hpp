#pragma once

#ifndef OBFUSK8_K8_UTILS_HPP
#define OBFUSK8_K8_UTILS_HPP

#ifdef __clang__
    #pragma clang diagnostic ignored "-Wunknown-pragmas"
    #pragma clang diagnostic ignored "-Wmicrosoft-template"
    #pragma clang diagnostic ignored "-Winvalid-source-encoding"
    #pragma clang diagnostic ignored "-Wshift-count-overflow"
    #pragma clang diagnostic ignored "-Wshift-op-parentheses"
    #pragma clang diagnostic ignored "-Wparentheses"
    #pragma clang diagnostic ignored "-Wunused-value"
    #pragma clang diagnostic ignored "-Wunused-variable"
#endif

#include <windows.h>
#include <string>
#include <type_traits>
#include <cstdint>
#include <array>
#include <utility>
#include <iostream>
#include <vector>
#include <algorithm>

#pragma region _OPT
// ------------------------------------------------
    #define NOOPT _Pragma("optimize(\"\", off)");
    #define OPT _Pragma("optimize(\"\", on)");
// ------------------------------------------------
#pragma endregion _OPT

#pragma region DEFINES
// ------------------------------------------------
    #ifndef K8_FORCEINLINE
    #define K8_FORCEINLINE __forceinline
    #endif

    #ifdef _MSC_VER
    #define MBA_INLINE __forceinline
    #else
    #define MBA_INLINE inline __attribute__((always_inline))
    #endif

    constexpr uint32_t _BSTRAP_IV = 0x5AD009999;
// ------------------------------------------------
#pragma endregion DEFINES

#pragma region HELPERS_
// ------------------------------------------------
    K8_FORCEINLINE uint32_t _bstrap_hash(const char* str);
// ------------------------------------------------
#pragma endregion HELPERS_

#pragma region NT_STRUCTURES
// ------------------------------------------------
    typedef struct _UNICODE_STRING_K8 {
        USHORT Length;
        USHORT MaximumLength;
        PWSTR  Buffer;
    } UNICODE_STRING_K8;

    typedef struct _OBJECT_ATTRIBUTES_K8 {
        ULONG           Length;
        HANDLE          RootDirectory;
        UNICODE_STRING_K8* ObjectName;
        ULONG           Attributes;
        PVOID           SecurityDescriptor;
        PVOID           SecurityQualityOfService;
    } OBJECT_ATTRIBUTES_K8;

    typedef struct _CLIENT_ID_K8 {
        HANDLE UniqueProcess;
        HANDLE UniqueThread;
    } CLIENT_ID_K8;

    typedef struct _PEB_LDR_DATA_K8 {
        ULONG Length;
        BOOLEAN Initialized;
        PVOID SsHandle;
        LIST_ENTRY InLoadOrderModuleList;
        LIST_ENTRY InMemoryOrderModuleList;
        LIST_ENTRY InInitializationOrderModuleList;
    } PEB_LDR_DATA_K8, *PPEB_LDR_DATA_K8;

    typedef struct _LDR_DATA_TABLE_ENTRY_K8 {
        LIST_ENTRY InLoadOrderLinks;
        LIST_ENTRY InMemoryOrderLinks;
        LIST_ENTRY InInitializationOrderLinks;
        PVOID DllBase;
        PVOID EntryPoint;
        ULONG SizeOfImage;
        UNICODE_STRING_K8 FullDllName;
        UNICODE_STRING_K8 BaseDllName;
    } LDR_DATA_TABLE_ENTRY_K8, *PLDR_DATA_TABLE_ENTRY_K8;

    typedef struct _PEB_K8 {
        BYTE Reserved1[2];
        BYTE BeingDebugged;
        BYTE Reserved2[1];
        PVOID Reserved3[2];
        PPEB_LDR_DATA_K8 Ldr;
    } PEB_K8, *PPEB_K8;

    typedef struct _PROCESS_BASIC_INFORMATION_K8 {
        NTSTATUS ExitStatus;
        void* PebBaseAddress;
        ULONG_PTR AffinityMask;
        LONG BasePriority;
        ULONG_PTR UniqueProcessId;
        ULONG_PTR InheritedFromUniqueProcessId;
    } PROCESS_BASIC_INFORMATION_K8;

    // not nt but let it happen
    struct SyscallEntry
    {
        uint32_t hash;
        uintptr_t address;
        uint32_t ssn;
    };
// ------------------------------------------------
#pragma endregion NT_STRUCTURES

#endif

