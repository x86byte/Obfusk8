 #pragma once

#include <windows.h>
#include <iostream>
#include "../Instrumentation/materialization/state/Obfusk8Core.hpp"
#include <cstdio>

namespace RegistryAPIs 
{
	using LoadLibraryA_t 			= 		HMODULE(WINAPI*)(LPCSTR);
	using GetLastError_t 			= 		DWORD(WINAPI*)();
	using RegSetValueExA_t 			= 		LSTATUS(WINAPI*)(HKEY, LPCSTR, DWORD, DWORD, const BYTE*, DWORD);
	using RegCreateKeyExA_t 		= 		LSTATUS(WINAPI*)(HKEY, LPCSTR, DWORD, LPSTR, DWORD, REGSAM, const LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
	using RegEnumKeyExA_t 			= 		LSTATUS(WINAPI*)(HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPSTR, LPDWORD, PFILETIME);
	using RegQueryValueExA_t 		= 		LSTATUS(WINAPI*)(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
	using RegOpenKeyExA_t 			= 		LSTATUS(WINAPI*)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
	using RegCloseKey_t 			= 		LSTATUS(WINAPI*)(HKEY);
	using RegEnumValueA_t 			= 		LSTATUS(WINAPI*)(HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPDWORD, LPBYTE, LPDWORD);

	class 
	RegistryAPI 
	{
		public:
		    LoadLibraryA_t pLoadLibraryA;
		    GetLastError_t pGetLastError;

		    RegSetValueExA_t pRegSetValueExA;
		    RegCreateKeyExA_t pRegCreateKeyExA;
		    RegEnumKeyExA_t pRegEnumKeyExA;
		    RegQueryValueExA_t pRegQueryValueExA;
		    RegOpenKeyExA_t pRegOpenKeyExA;
		    RegCloseKey_t pRegCloseKey;
		    RegEnumValueA_t pRegEnumValueA;

		    bool m_initialized;

		    RegistryAPI() :
		        pLoadLibraryA(nullptr),
		        pGetLastError(nullptr),
		        pRegSetValueExA(nullptr),
		        pRegCreateKeyExA(nullptr),
		        pRegEnumKeyExA(nullptr),
		        pRegQueryValueExA(nullptr),
		        pRegOpenKeyExA(nullptr),
		        pRegCloseKey(nullptr),
		        pRegEnumValueA(nullptr),
		        m_initialized(false)
		    {
		        resolveAPIs();
		    }

		    bool IsInitialized() const {
		        return m_initialized;
		    }

		private:
		    void 
		    resolveAPIs() 
		    {
		        pLoadLibraryA = reinterpret_cast<LoadLibraryA_t>(
		            STEALTH_API_OBFSTR("kernel32.dll", "LoadLibraryA")
		        );

		        pGetLastError = reinterpret_cast<GetLastError_t>(
		            STEALTH_API_OBFSTR("kernel32.dll", "GetLastError")
		        );

		        using namespace std;

		        if (!pLoadLibraryA || !pGetLastError) {
		           	cout << OBFUSCATE_STRING("CRITICAL: Failed to resolve LoadLibraryA or GetLastError. Cannot initialize RegistryAPI.\n");
		            return;
		        }

		        HMODULE hAdvApi32 = pLoadLibraryA(OBFUSCATE_STRING("advapi32.dll").c_str());
		        if (!hAdvApi32) {
		            cout << OBFUSCATE_STRING("CRITICAL: Failed to load advapi32.dll for RegistryAPI. Error: ").c_str() << pGetLastError();
		        }

		        // cout << OBFUSCATE_STRING"advapi32.dll loaded successfully for RegistryAPI, handle:").c_str() << hAdvApi32;

		        pRegSetValueExA 		= 		reinterpret_cast<RegSetValueExA_t>(STEALTH_API_OBFSTR("advapi32.dll", "RegSetValueExA"));
		        pRegCreateKeyExA 		= 		reinterpret_cast<RegCreateKeyExA_t>(STEALTH_API_OBFSTR("advapi32.dll", "RegCreateKeyExA"));
		        pRegEnumKeyExA 			= 		reinterpret_cast<RegEnumKeyExA_t>(STEALTH_API_OBFSTR("advapi32.dll", "RegEnumKeyExA"));
		        pRegQueryValueExA 		= 		reinterpret_cast<RegQueryValueExA_t>(STEALTH_API_OBFSTR("advapi32.dll", "RegQueryValueExA"));
		        pRegOpenKeyExA 			= 		reinterpret_cast<RegOpenKeyExA_t>(STEALTH_API_OBFSTR("advapi32.dll", "RegOpenKeyExA"));
		        pRegCloseKey 			= 		reinterpret_cast<RegCloseKey_t>(STEALTH_API_OBFSTR("advapi32.dll", "RegCloseKey"));
		        pRegEnumValueA 			= 		reinterpret_cast<RegEnumValueA_t>(STEALTH_API_OBFSTR("advapi32.dll", "RegEnumValueA"));

		        if (pRegSetValueExA && pRegCreateKeyExA && pRegEnumKeyExA &&
		            pRegQueryValueExA && pRegOpenKeyExA && pRegCloseKey && pRegEnumValueA) {
		            m_initialized = true;
		            cout << OBFUSCATE_STRING("RegistryAPI initialized successfully (all functions resolved).\n").c_str();
		        }
		    }
	};


}
