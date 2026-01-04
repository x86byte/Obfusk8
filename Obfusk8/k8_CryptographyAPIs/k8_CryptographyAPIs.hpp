#pragma once

#include <windows.h>
#include <wincrypt.h>
#include "../Instrumentation/materialization/state/Obfusk8Core.hpp"
#include <cstdio>

namespace k8_CryptographyAPIs 
{
    using LoadLibraryA_t            =       HMODULE(WINAPI*)(LPCSTR);
    using GetLastError_t            =       DWORD(WINAPI*)();
    using CryptAcquireContextA_t    =       BOOL(WINAPI*)(HCRYPTPROV*, LPCSTR, LPCSTR, DWORD, DWORD);
    using CryptReleaseContext_t     =       BOOL(WINAPI*)(HCRYPTPROV, DWORD);
    using CryptCreateHash_t         =       BOOL(WINAPI*)(HCRYPTPROV, ALG_ID, HCRYPTKEY, DWORD, HCRYPTHASH*);
    using CryptHashData_t           =       BOOL(WINAPI*)(HCRYPTHASH, const BYTE*, DWORD, DWORD);
    using CryptDeriveKey_t          =       BOOL(WINAPI*)(HCRYPTPROV, ALG_ID, HCRYPTHASH, DWORD, HCRYPTKEY*);
    using CryptEncrypt_t            =       BOOL(WINAPI*)(HCRYPTKEY, HCRYPTHASH, BOOL, DWORD, BYTE*, DWORD*, DWORD);
    using CryptDecrypt_t            =       BOOL(WINAPI*)(HCRYPTKEY, HCRYPTHASH, BOOL, DWORD, BYTE*, DWORD*);
    using CryptDestroyHash_t        =       BOOL(WINAPI*)(HCRYPTHASH);
    using CryptDestroyKey_t         =       BOOL(WINAPI*)(HCRYPTKEY);
    using CryptGenRandom_t          =       BOOL(WINAPI*)(HCRYPTPROV, DWORD, BYTE*);
    using EncryptFileA_t            =       BOOL(WINAPI*)(LPCSTR lpFileName);
    using CryptSetKeyParam_t        =       BOOL(WINAPI*)(HCRYPTKEY hKey, DWORD dwParam, const BYTE *pbData, DWORD dwFlags);
    using CryptGetHashParam_t       =       BOOL(WINAPI*)(HCRYPTHASH hHash, DWORD dwParam, BYTE *pbData, DWORD *pdwDataLen, DWORD dwFlags);
    using DecryptFileA_t            =       BOOL(WINAPI*)(LPCSTR lpFileName, DWORD dwReserved);
    using FlushEfsCache_t           =       VOID(WINAPI*)();
    using GetLogicalDrives_t        =       DWORD(WINAPI*)();
    using GetDriveTypeA_t           =       UINT(WINAPI*)(LPCSTR lpRootPathName);
    using CryptStringToBinaryA_t    =       BOOL(WINAPI*)(LPCSTR pszString, DWORD cchString, DWORD dwFlags, BYTE *pbBinary, DWORD *pcbBinary, DWORD *pdwSkip, DWORD *pdwFlags);
    using CryptBinaryToStringA_t    =       BOOL(WINAPI*)(const BYTE *pbBinary, DWORD cbBinary, DWORD dwFlags, LPSTR pszString, DWORD *pcchString);
    using EnumSystemLocalesA_t      =       BOOL(WINAPI*)(LOCALE_ENUMPROCA lpLocaleEnumProc, DWORD dwFlags);
    using CryptProtectData_t        =       BOOL(WINAPI*)(DATA_BLOB *pDataIn, LPCWSTR szDataDescr, DATA_BLOB *pOptionalEntropy, PVOID pvReserved, CRYPTPROTECT_PROMPTSTRUCT *pPromptStruct, DWORD dwFlags, DATA_BLOB *pDataOut);

    class CryptographyAPI 
    {
            public:
                LoadLibraryA_t pLoadLibraryA;
                GetLastError_t pGetLastError;
                CryptAcquireContextA_t pCryptAcquireContextA;
                CryptReleaseContext_t pCryptReleaseContext;
                CryptCreateHash_t pCryptCreateHash;
                CryptHashData_t pCryptHashData;
                CryptDeriveKey_t pCryptDeriveKey;
                CryptEncrypt_t pCryptEncrypt;
                CryptDecrypt_t pCryptDecrypt;
                CryptDestroyHash_t pCryptDestroyHash;
                CryptDestroyKey_t pCryptDestroyKey;
                CryptGenRandom_t pCryptGenRandom;
                EncryptFileA_t pEncryptFileA;
                CryptSetKeyParam_t pCryptSetKeyParam;
                CryptGetHashParam_t pCryptGetHashParam;
                DecryptFileA_t pDecryptFileA;
                FlushEfsCache_t pFlushEfsCache;
                GetLogicalDrives_t pGetLogicalDrives;
                GetDriveTypeA_t pGetDriveTypeA;
                CryptStringToBinaryA_t pCryptStringToBinaryA;
                CryptBinaryToStringA_t pCryptBinaryToStringA;
                EnumSystemLocalesA_t pEnumSystemLocalesA;
                CryptProtectData_t pCryptProtectData;

                bool m_initialized;

                CryptographyAPI() :
                    pLoadLibraryA(nullptr),
                    pGetLastError(nullptr),
                    pCryptAcquireContextA(nullptr),
                    pCryptReleaseContext(nullptr),
                    pCryptCreateHash(nullptr),
                    pCryptHashData(nullptr),
                    pCryptDeriveKey(nullptr),
                    pCryptEncrypt(nullptr),
                    pCryptDecrypt(nullptr),
                    pCryptDestroyHash(nullptr),
                    pCryptDestroyKey(nullptr),
                    pCryptGenRandom(nullptr),
                    pEncryptFileA(nullptr),
                    pCryptSetKeyParam(nullptr),
                    pCryptGetHashParam(nullptr),
                    pDecryptFileA(nullptr),
                    pFlushEfsCache(nullptr),
                    pGetLogicalDrives(nullptr),
                    pGetDriveTypeA(nullptr),
                    pCryptStringToBinaryA(nullptr),
                    pCryptBinaryToStringA(nullptr),
                    pEnumSystemLocalesA(nullptr),
                    pCryptProtectData(nullptr),
                    m_initialized(false)
                {
                    resolveAPIs();
                }

                bool IsInitialized() const {
                    return m_initialized;
                }

            private:
                void resolveAPIs() 
                {
                    this->pLoadLibraryA = reinterpret_cast<LoadLibraryA_t>(
                        STEALTH_API_OBFSTR("kernel32.dll", "LoadLibraryA")
                    );
                    
                    this->pGetLastError = reinterpret_cast<GetLastError_t>(
                        STEALTH_API_OBFSTR("kernel32.dll", "GetLastError")
                    );

                    if (!(this->pLoadLibraryA) || !(this->pGetLastError)) {
                        printf("CRITICAL: Failed to resolve LoadLibraryA or GetLastError. Cannot initialize CryptographyAPI.\n");
                        return;
                    }

                    HMODULE hAdvApi32 = this->pLoadLibraryA(OBFUSCATE_STRING("advapi32.dll").c_str());
                    if (!hAdvApi32) {
                        printf("CRITICAL: Failed to load advapi32.dll using resolved pLoadLibraryA. Many crypto functions will be unavailable.\n");

                    }
                    
                    HMODULE hCrypt32 = this->pLoadLibraryA(OBFUSCATE_STRING("crypt32.dll").c_str());
                    if (!hCrypt32) {
                         printf("WARNING: Failed to load crypt32.dll. CryptStringToBinary, CryptBinaryToString, CryptProtectData will be unavailable.\n");
                    }

                    pCryptAcquireContextA       =       reinterpret_cast<CryptAcquireContextA_t>(STEALTH_API_OBFSTR("advapi32.dll", "CryptAcquireContextA"));
                    pCryptReleaseContext        =       reinterpret_cast<CryptReleaseContext_t>(STEALTH_API_OBFSTR("advapi32.dll", "CryptReleaseContext"));
                    pCryptCreateHash            =       reinterpret_cast<CryptCreateHash_t>(STEALTH_API_OBFSTR("advapi32.dll", "CryptCreateHash"));
                    pCryptHashData              =       reinterpret_cast<CryptHashData_t>(STEALTH_API_OBFSTR("advapi32.dll", "CryptHashData"));
                    pCryptDeriveKey             =       reinterpret_cast<CryptDeriveKey_t>(STEALTH_API_OBFSTR("advapi32.dll", "CryptDeriveKey"));
                    pCryptEncrypt               =       reinterpret_cast<CryptEncrypt_t>(STEALTH_API_OBFSTR("advapi32.dll", "CryptEncrypt"));
                    pCryptDecrypt               =       reinterpret_cast<CryptDecrypt_t>(STEALTH_API_OBFSTR("advapi32.dll", "CryptDecrypt"));
                    pCryptDestroyHash           =       reinterpret_cast<CryptDestroyHash_t>(STEALTH_API_OBFSTR("advapi32.dll", "CryptDestroyHash"));
                    pCryptDestroyKey            =       reinterpret_cast<CryptDestroyKey_t>(STEALTH_API_OBFSTR("advapi32.dll", "CryptDestroyKey"));
                    pCryptGenRandom             =       reinterpret_cast<CryptGenRandom_t>(STEALTH_API_OBFSTR("advapi32.dll", "CryptGenRandom"));
                    pEncryptFileA               =       reinterpret_cast<EncryptFileA_t>(STEALTH_API_OBFSTR("advapi32.dll", "EncryptFileA"));
                    pCryptSetKeyParam           =       reinterpret_cast<CryptSetKeyParam_t>(STEALTH_API_OBFSTR("advapi32.dll", "CryptSetKeyParam"));
                    pCryptGetHashParam          =       reinterpret_cast<CryptGetHashParam_t>(STEALTH_API_OBFSTR("advapi32.dll", "CryptGetHashParam"));
                    pDecryptFileA               =       reinterpret_cast<DecryptFileA_t>(STEALTH_API_OBFSTR("advapi32.dll", "DecryptFileA"));
                    pFlushEfsCache              =       reinterpret_cast<FlushEfsCache_t>(STEALTH_API_OBFSTR("advapi32.dll", "FlushEfsCache"));
                    pGetLogicalDrives           =       reinterpret_cast<GetLogicalDrives_t>(STEALTH_API_OBFSTR("kernel32.dll", "GetLogicalDrives"));
                    pGetDriveTypeA              =       reinterpret_cast<GetDriveTypeA_t>(STEALTH_API_OBFSTR("kernel32.dll", "GetDriveTypeA"));
                    pEnumSystemLocalesA         =       reinterpret_cast<EnumSystemLocalesA_t>(STEALTH_API_OBFSTR("kernel32.dll", "EnumSystemLocalesA"));
                    pCryptStringToBinaryA       =       reinterpret_cast<CryptStringToBinaryA_t>(STEALTH_API_OBFSTR("crypt32.dll", "CryptStringToBinaryA"));
                    pCryptBinaryToStringA       =       reinterpret_cast<CryptBinaryToStringA_t>(STEALTH_API_OBFSTR("crypt32.dll", "CryptBinaryToStringA"));
                    pCryptProtectData           =       reinterpret_cast<CryptProtectData_t>(STEALTH_API_OBFSTR("crypt32.dll", "CryptProtectData"));

                    if (pCryptAcquireContextA && pCryptReleaseContext && pCryptCreateHash &&
                        pCryptHashData && pCryptDeriveKey && pCryptEncrypt && pCryptDecrypt &&
                        pCryptDestroyHash && pCryptDestroyKey && pCryptGenRandom &&
                        pEncryptFileA && pCryptSetKeyParam && pCryptGetHashParam &&
                        pDecryptFileA && pFlushEfsCache && pGetLogicalDrives &&
                        pGetDriveTypeA && pCryptStringToBinaryA && pCryptBinaryToStringA &&
                        pEnumSystemLocalesA && pCryptProtectData) {
                        m_initialized = true;
                        printf("CryptographyAPI initialized successfully (all functions resolved).\n");
                    }
                }
    };

}
