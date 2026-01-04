#pragma once

#ifndef OBFUSK8_K8_UTILS_HPP
#define OBFUSK8_K8_UTILS_HPP

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

    __forceinline PPEB_K8 GetPEB()
    {
        #if defined(_WIN64)
            return (PPEB_K8)__readgsqword(0x60);
        #else
            return (PPEB_K8)__readfsdword(0x30);
        #endif
    }
// ------------------------------------------------
#pragma endregion NT_STRUCTURES

#endif
