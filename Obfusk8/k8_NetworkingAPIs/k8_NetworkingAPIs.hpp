#pragma once

#include <windows.h>
#include <wininet.h>
#include "../Obfusk8Core.hpp"

namespace k8_NetworkingAPIs
{
    using LoadLibraryA_t                =       HMODULE(WINAPI*)(LPCSTR);
    using GetLastError_t                =       DWORD(WINAPI*)();
    using HttpQueryInfoA_t              =       BOOL(WINAPI*)(HINTERNET, DWORD, LPVOID, LPDWORD, LPDWORD);
    using HttpSendRequestExA_t          =       BOOL(WINAPI*)(HINTERNET, LPINTERNET_BUFFERSA, LPINTERNET_BUFFERSA, DWORD, DWORD_PTR);
    using HttpEndRequestA_t             =       BOOL(WINAPI*)(HINTERNET, LPINTERNET_BUFFERSA, DWORD, DWORD_PTR);
    using HttpOpenRequestA_t            =       HINTERNET(WINAPI*)(HINTERNET, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPCSTR*, DWORD, DWORD_PTR);
    using InternetOpenA_t               =       HINTERNET(WINAPI*)(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD);
    using InternetConnectA_t            =       HINTERNET(WINAPI*)(HINTERNET, LPCSTR, INTERNET_PORT, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);
    using InternetGetConnectedState_t   =       BOOL(WINAPI*)(LPDWORD, DWORD);
    using InternetSetOptionA_t          =       BOOL(WINAPI*)(HINTERNET, DWORD, LPVOID, DWORD);
    using InternetWriteFile_t           =       BOOL(WINAPI*)(HINTERNET, LPCVOID, DWORD, LPDWORD);
    using InternetCrackUrlA_t           =       BOOL(WINAPI*)(LPCSTR, DWORD, DWORD, LPURL_COMPONENTSA);
    using InternetSetStatusCallbackA_t  =       INTERNET_STATUS_CALLBACK(WINAPI*)(HINTERNET, INTERNET_STATUS_CALLBACK);
    using InternetCloseHandle_t         =       BOOL(WINAPI*)(HINTERNET);
    using InternetOpenUrlA_t            =       HINTERNET(WINAPI*)(HINTERNET, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);
    using InternetReadFile_t            =       BOOL(WINAPI*)(HINTERNET, LPVOID, DWORD, LPDWORD);
    using InternetReadFileExA_t         =       BOOL(WINAPI*)(HINTERNET, LPINTERNET_BUFFERSA, DWORD, DWORD_PTR);
    using InternetSetCookieA_t          =       BOOL(WINAPI*)(LPCSTR, LPCSTR, LPCSTR);
    using InternetGetCookieA_t          =       BOOL(WINAPI*)(LPCSTR, LPCSTR, LPSTR, LPDWORD);

    class NetworkingAPI
    {
        public:
            LoadLibraryA_t pLoadLibraryA;
            GetLastError_t pGetLastError;

            HttpQueryInfoA_t pHttpQueryInfoA;
            HttpSendRequestExA_t pHttpSendRequestExA;
            HttpEndRequestA_t pHttpEndRequestA;
            HttpOpenRequestA_t pHttpOpenRequestA;
            InternetOpenA_t pInternetOpenA;
            InternetConnectA_t pInternetConnectA;
            InternetGetConnectedState_t pInternetGetConnectedState;
            InternetSetOptionA_t pInternetSetOptionA;
            InternetWriteFile_t pInternetWriteFile;
            InternetCrackUrlA_t pInternetCrackUrlA;
            InternetSetStatusCallbackA_t pInternetSetStatusCallbackA;
            InternetCloseHandle_t pInternetCloseHandle;
            InternetOpenUrlA_t pInternetOpenUrlA;
            InternetReadFile_t pInternetReadFile;
            InternetReadFileExA_t pInternetReadFileExA;
            InternetSetCookieA_t pInternetSetCookieA;
            InternetGetCookieA_t pInternetGetCookieA;

            bool m_initialized;

            NetworkingAPI() :
                pLoadLibraryA(nullptr),
                pGetLastError(nullptr),
                pHttpQueryInfoA(nullptr),
                pHttpSendRequestExA(nullptr),
                pHttpEndRequestA(nullptr),
                pHttpOpenRequestA(nullptr),
                pInternetOpenA(nullptr),
                pInternetConnectA(nullptr),
                pInternetGetConnectedState(nullptr),
                pInternetSetOptionA(nullptr),
                pInternetWriteFile(nullptr),
                pInternetCrackUrlA(nullptr),
                pInternetSetStatusCallbackA(nullptr),
                pInternetCloseHandle(nullptr),
                pInternetOpenUrlA(nullptr),
                pInternetReadFile(nullptr),
                pInternetReadFileExA(nullptr),
                pInternetSetCookieA(nullptr),
                pInternetGetCookieA(nullptr),
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
                pLoadLibraryA = reinterpret_cast<LoadLibraryA_t>(
                    STEALTH_API_OBFSTR("kernel32.dll", "LoadLibraryA")
                );

                if (!pLoadLibraryA) {
                    return;
                }

                pGetLastError = reinterpret_cast<GetLastError_t>(
                    STEALTH_API_OBFSTR("kernel32.dll", "GetLastError")
                );

                HMODULE hWinINet = pLoadLibraryA(OBFUSCATE_STRING("wininet.dll").c_str());
                if (!hWinINet) {
                    return;
                }

                pHttpQueryInfoA             =       reinterpret_cast<HttpQueryInfoA_t>(STEALTH_API_OBFSTR("wininet.dll", "HttpQueryInfoA"));
                pHttpSendRequestExA         =       reinterpret_cast<HttpSendRequestExA_t>(STEALTH_API_OBFSTR("wininet.dll", "HttpSendRequestExA"));
                pHttpEndRequestA            =       reinterpret_cast<HttpEndRequestA_t>(STEALTH_API_OBFSTR("wininet.dll", "HttpEndRequestA"));
                pHttpOpenRequestA           =       reinterpret_cast<HttpOpenRequestA_t>(STEALTH_API_OBFSTR("wininet.dll", "HttpOpenRequestA"));
                pInternetOpenA              =       reinterpret_cast<InternetOpenA_t>(STEALTH_API_OBFSTR("wininet.dll", "InternetOpenA"));
                pInternetConnectA           =       reinterpret_cast<InternetConnectA_t>(STEALTH_API_OBFSTR("wininet.dll", "InternetConnectA"));
                pInternetGetConnectedState  =       reinterpret_cast<InternetGetConnectedState_t>(STEALTH_API_OBFSTR("wininet.dll", "InternetGetConnectedState"));
                pInternetSetOptionA         =       reinterpret_cast<InternetSetOptionA_t>(STEALTH_API_OBFSTR("wininet.dll", "InternetSetOptionA"));
                pInternetWriteFile          =       reinterpret_cast<InternetWriteFile_t>(STEALTH_API_OBFSTR("wininet.dll", "InternetWriteFile"));
                pInternetCrackUrlA          =       reinterpret_cast<InternetCrackUrlA_t>(STEALTH_API_OBFSTR("wininet.dll", "InternetCrackUrlA"));
                pInternetSetStatusCallbackA =       reinterpret_cast<InternetSetStatusCallbackA_t>(STEALTH_API_OBFSTR("wininet.dll", "InternetSetStatusCallbackA"));
                pInternetCloseHandle        =       reinterpret_cast<InternetCloseHandle_t>(STEALTH_API_OBFSTR("wininet.dll", "InternetCloseHandle"));
                pInternetOpenUrlA           =       reinterpret_cast<InternetOpenUrlA_t>(STEALTH_API_OBFSTR("wininet.dll", "InternetOpenUrlA"));
                pInternetReadFile           =       reinterpret_cast<InternetReadFile_t>(STEALTH_API_OBFSTR("wininet.dll", "InternetReadFile"));
                pInternetReadFileExA        =       reinterpret_cast<InternetReadFileExA_t>(STEALTH_API_OBFSTR("wininet.dll", "InternetReadFileExA"));
                pInternetSetCookieA         =       reinterpret_cast<InternetSetCookieA_t>(STEALTH_API_OBFSTR("wininet.dll", "InternetSetCookieA"));
                pInternetGetCookieA         =       reinterpret_cast<InternetGetCookieA_t>(STEALTH_API_OBFSTR("wininet.dll", "InternetGetCookieA"));

                if (pHttpQueryInfoA && pHttpSendRequestExA && pHttpEndRequestA && pHttpOpenRequestA &&
                    pInternetOpenA && pInternetConnectA && pInternetGetConnectedState &&
                    pInternetSetOptionA && pInternetWriteFile && pInternetCrackUrlA &&
                    pInternetSetStatusCallbackA && pInternetCloseHandle &&
                    pInternetOpenUrlA && pInternetReadFile && pInternetReadFileExA &&
                    pInternetSetCookieA && pInternetGetCookieA)
                {
                    m_initialized = true;
                    printf("NetworkingAPIs initialized successfully (all functions resolved).\n");
                }
            }
    };
}