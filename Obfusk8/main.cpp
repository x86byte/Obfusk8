#define STEALTH_API_MAIN

#include "Obfusk8Core.hpp"
#include <cstdio>
#include <iostream>

using namespace std;

void
REG_CALLE(RegistryAPI* _RegistryAPI)
{
        HKEY            hKey;
        DWORD           dwDisposition;
        char            readBuffer[256];
        DWORD           bufferSize          = sizeof(readBuffer);
        DWORD           type = 0;

        LSTATUS status = _RegistryAPI->pRegCreateKeyExA(
            HKEY_CURRENT_USER,
            "Software\\Obfusk8",
            0,
            NULL,
            REG_OPTION_NON_VOLATILE,
            KEY_ALL_ACCESS,
            NULL,
            &hKey,
            &dwDisposition
        );

        const char* valueData = "_Obfusk8";
        status = _RegistryAPI->pRegSetValueExA(
            hKey,
            "Obfusk8",
            0,
            REG_SZ,
            reinterpret_cast<const BYTE*>(valueData),
            strlen(valueData) + 1
        );

        status = _RegistryAPI->pRegQueryValueExA(
            hKey,
            "Obfusk8",
            NULL,
            &type,
            reinterpret_cast<LPBYTE>(readBuffer),
            &bufferSize
        );

        _RegistryAPI->pRegCloseKey(hKey);
}


bool _check = false; 

HANDLE 
check(NetworkingAPI* _NetworkingAPI){
    HANDLE _handle = _NetworkingAPI->pInternetOpenA(
                                    OBFUSCATE_STRING("StealthClient/1.0").c_str(),
                                    INTERNET_OPEN_TYPE_DIRECT,
                                    NULL, NULL, 0
                                    );
    if (!_handle) {
         _check = false;
    }

    _check = true;
    return _handle;
}


void 
Net_CALLE(NetworkingAPI* _NetworkingAPI)
{
        HANDLE _handle = check(_NetworkingAPI);
        if((_check) && !(_handle)) {
            if((_NetworkingAPI->pInternetConnectA(
                                    _handle,
                                    OBFUSCATE_STRING("198.28.28.1").c_str(),
                                    INTERNET_DEFAULT_HTTP_PORT,
                                    NULL, NULL,
                                    INTERNET_SERVICE_HTTP,
                                    0, 0
                                    ))){
            }
        }

}

void 
Cryp_CALLE(CryptographyAPI* _CryptographyAPI)
{
        HCRYPTPROV hProv = 0;
        HCRYPTHASH hHash = 0;
        HCRYPTKEY hKey = 0;

        if (!_CryptographyAPI->pCryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            if (_CryptographyAPI->pGetLastError && _CryptographyAPI->pGetLastError() == NTE_BAD_KEYSET) {
                 cout << OBFUSCATE_STRING("NTE_BAD_KEYSET, trying to create a new keyset (for testing only).\n").c_str();
                 if (!_CryptographyAPI->pCryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_NEWKEYSET))
                 {

                 }
            } else {

            }
        }

        if (!_CryptographyAPI->pCryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
        {

        }

        const char* password = OBFUSCATE_STRING("Obfusk8!").c_str();
        if (!_CryptographyAPI->pCryptHashData(hHash, (const BYTE*)password, (DWORD)strlen(password), 0))
        {

        }

        if (!_CryptographyAPI->pCryptDeriveKey(hProv, CALG_AES_128, hHash, 0, &hKey))
        {

        }

        char originalDataStr[] = "Obfusk8 C++17";
        std::vector<BYTE> dataBuffer(originalDataStr, originalDataStr + strlen(originalDataStr) + 1);
        DWORD dataLen = (DWORD)dataBuffer.size();
        DWORD bufferLen = dataLen;

        if (!_CryptographyAPI->pCryptEncrypt(hKey, 0, TRUE, 0, NULL, &bufferLen, 0)) 
        {
        }

        dataBuffer.resize(bufferLen);

        std::vector<BYTE> encryptedBuffer = dataBuffer;
        memcpy(encryptedBuffer.data(), originalDataStr, dataLen);
        DWORD encryptedDataLen = dataLen;

        if (!_CryptographyAPI->pCryptEncrypt(hKey, 0, TRUE, 0, encryptedBuffer.data(), &encryptedDataLen, (DWORD)encryptedBuffer.size()))
        {
        }

        std::vector<BYTE> decryptedBuffer = encryptedBuffer;
        DWORD decryptedDataLen = encryptedDataLen;

        if (!_CryptographyAPI->pCryptDecrypt(hKey, 0, TRUE, 0, decryptedBuffer.data(), &decryptedDataLen)) {

        }

        //cout << OBFUSCATE_STRING("CryptDecrypt: SUCCESS\n").c_str();

        decryptedBuffer.resize(decryptedDataLen);

        //cout << OBFUSCATE_STRING("Decrypted String: ").c_str() << (char*)decryptedBuffer.data() << endl;
}

void
ProcMan_CALLE(ProcessAPI* _ProcessManipulationAPIs)
{

    DWORD pid = _ProcessManipulationAPIs->pGetCurrentProcessId();
    cout << OBFUSCATE_STRING("-> [ProcessManipulationAPIs - INFO] Current Process ID: ").c_str() << pid << endl;

    HANDLE hProcess = _ProcessManipulationAPIs->pOpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        cerr << OBFUSCATE_STRING("-> [ProcessManipulationAPIs - ERROR] OpenProcess failed with error: ").c_str() << GetLastError() << endl;
    }

    cout << OBFUSCATE_STRING("-> [ProcessManipulationAPIs - INFO] Successfully opened current process.").c_str() << endl;

    const SIZE_T allocSize = 1024;
    LPVOID remoteMem = _ProcessManipulationAPIs->pVirtualAllocEx(hProcess, nullptr, allocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) {
    }

    cout << OBFUSCATE_STRING("-> [ProcessManipulationAPIs - INFO] Memory allocated at address: ").c_str() << remoteMem << std::endl;

    const char* message = OBFUSCATE_STRING("Obfusk8 C++17").c_str();
    SIZE_T bytesWritten = 0;
    if (!_ProcessManipulationAPIs->pWriteProcessMemory(hProcess, remoteMem, message, strlen(message) + 1, &bytesWritten)) {
        std::cerr << OBFUSCATE_STRING("-> [ProcessManipulationAPIs - ERROR] WriteProcessMemory failed with error: ").c_str() << GetLastError() << std::endl;
    }

    cout << OBFUSCATE_STRING("-> [ProcessManipulationAPIs - INFO] Wrote ").c_str() << bytesWritten << OBFUSCATE_STRING(" bytes to allocated memory.").c_str() << endl;

    char buffer[1024] = {0};
    SIZE_T bytesRead = 0;
    if (!_ProcessManipulationAPIs->pReadProcessMemory(hProcess, remoteMem, buffer, sizeof(buffer), &bytesRead)) {
        cerr << OBFUSCATE_STRING("-> [ProcessManipulationAPIs - ERROR] ReadProcessMemory failed with error: ").c_str() << GetLastError() << endl;
    }

    cout << OBFUSCATE_STRING("-> [ProcessManipulationAPIs - INFO] Read ").c_str() << bytesRead << OBFUSCATE_STRING(" bytes from allocated memory: ").c_str() << buffer << endl;
}

void 
CALLEE()
{
        #pragma region USING
        // --------------------------------------

            // ProcessManipulationAPIs
            ProcessAPI* _ProcessManipulationAPIs = new ProcessAPI;
            if(!(_ProcessManipulationAPIs->IsInitialized() == TRUE)){
                std::cout << OBFUSCATE_STRING("something are wrong in ProcessManipulationAPIs!! isn't Initialized...\n").c_str();
                delete _ProcessManipulationAPIs;
            } else {
                ProcMan_CALLE(_ProcessManipulationAPIs);
                delete _ProcessManipulationAPIs;
            }

            // CryptographyAPIs
            CryptographyAPI* _CryptographyAPI =  new CryptographyAPI;
            if(!( _CryptographyAPI->IsInitialized() == TRUE)){
                std::cout << OBFUSCATE_STRING("something are wrong in CryptographyAPI!! isn't Initialized...\n").c_str();
                delete _CryptographyAPI;
            } else {
                Cryp_CALLE(_CryptographyAPI);
                delete _CryptographyAPI;
            }

            // NetworkingAPIs
            NetworkingAPI* _NetworkingAPI = new NetworkingAPI;
            if(!(_NetworkingAPI->IsInitialized() == TRUE)){
                std::cout << OBFUSCATE_STRING("something are wrong in NetworkingAPI!! isn't Initialized...\n").c_str();
                delete _NetworkingAPI;
            } else {
                Net_CALLE(_NetworkingAPI);
                delete _NetworkingAPI;
            }

            // RegistryAPIs
            RegistryAPI* _RegistryAPI = new RegistryAPI;
            if(!(_RegistryAPI->IsInitialized() == TRUE)){
                std::cout << OBFUSCATE_STRING("something are wrong in RegistryAPIs!! isn't Initialized...\n").c_str();
                delete _RegistryAPI;
            } else {
                REG_CALLE(_RegistryAPI);
                delete _RegistryAPI;
            }

        // --------------------------------------
        #pragma endregion USING
}

#ifdef STEALTH_API_MAIN
    _main({
        using LoadLibraryA_t = HMODULE(WINAPI*)(LPCSTR);
        using MsgBoxA_t = int(WINAPI*)(HWND, LPCSTR, LPCSTR, UINT);

        auto pLoadLibraryA = reinterpret_cast<LoadLibraryA_t>(
            STEALTH_API_OBFSTR("kernel32.dll", "LoadLibraryA")
        );

        HMODULE hUser32 = pLoadLibraryA ? pLoadLibraryA(OBFUSCATE_STRING("user32.dll").c_str()) : nullptr;
        auto pMsgBoxA = hUser32 ? reinterpret_cast<MsgBoxA_t>(
            STEALTH_API_OBFSTR("user32.dll", "MessageBoxA")
        ) : nullptr;

        if (pMsgBoxA) {
            pMsgBoxA(nullptr, OBFUSCATE_STRING("Obfusk8 Library Ready to use :3\n").c_str(), OBFUSCATE_STRING("Ready").c_str(), 0);
        }

        CALLEE();
        
        return 0;
    })
#endif


/*

to hide the main use :
    _main({})
        
to Obfuscte ur apis use :
    STEALTH_API_OBFSTR

to Obfuscate STRINGS use :
    OBFUSCATE_STRING
*/




