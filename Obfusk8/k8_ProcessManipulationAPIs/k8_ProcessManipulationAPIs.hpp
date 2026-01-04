/*
CreateFileMappingA
CreateProcessA
CreateRemoteThread
CreateRemoteThreadEx
GetModuleHandleA
GetProcAddress
GetThreadContext
HeapCreate
LoadLibraryA
LoadLibraryExA
LocalAlloc
MapViewOfFile
MapViewOfFile2
MapViewOfFile3
MapViewOfFileEx
OpenThread
Process32First
Process32Next
QueueUserAPC
ReadProcessMemory
ResumeThread
SetProcessDEPPolicy
SetThreadContext
SuspendThread
Thread32First
Thread32Next
Toolhelp32ReadProcessMemory
VirtualAlloc
VirtualAllocEx
VirtualProtect
VirtualProtectEx
WriteProcessMemory
VirtualAllocExNuma
VirtualAlloc2
VirtualAlloc2FromApp
VirtualAllocFromApp
VirtualProtectFromApp
CreateThread
WaitForSingleObject
OpenProcess
OpenFileMappingA
GetProcessHeap
GetProcessHeaps
HeapAlloc
HeapReAlloc
GlobalAlloc
AdjustTokenPrivileges
CreateProcessAsUserA
OpenProcessToken
CreateProcessWithTokenW
NtAdjustPrivilegesToken
NtAllocateVirtualMemory
NtContinue
NtCreateProcess
NtCreateProcessEx
NtCreateSection
NtCreateThread
NtCreateThreadEx
NtCreateUserProcess
NtDuplicateObject
NtMapViewOfSection
NtOpenProcess
NtOpenThread
NtProtectVirtualMemory
NtQueueApcThread
NtQueueApcThreadEx
NtQueueApcThreadEx2
NtReadVirtualMemory
NtResumeThread
NtUnmapViewOfSection
NtWaitForMultipleObjects
NtWaitForSingleObject
NtWriteVirtualMemory
RtlCreateHeap
LdrLoadDll
RtlMoveMemory
RtlCopyMemory
SetPropA
WaitForSingleObjectEx
WaitForMultipleObjects
WaitForMultipleObjectsEx
KeInsertQueueApc
Wow64SetThreadContext
NtSuspendProcess
NtResumeProcess
DuplicateToken
NtReadVirtualMemoryEx
CreateProcessInternal
EnumSystemLocalesA
UuidFromStringA
DebugActiveProcessStop
*/


#pragma once

#include <windows.h>
#include <tlhelp32.h>
#include <cstdio>
#include <string>

#include "../Instrumentation/materialization/state/Obfusk8Core.hpp"

// i got this from : https://ntdoc.m417z.com/processinfoclass
typedef enum _PROCESSINFOCLASS
{
    ProcessBasicInformation, // q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
    ProcessQuotaLimits, // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
    ProcessIoCounters, // q: IO_COUNTERS
    ProcessVmCounters, // q: VM_COUNTERS, VM_COUNTERS_EX, VM_COUNTERS_EX2
    ProcessTimes, // q: KERNEL_USER_TIMES
    ProcessBasePriority, // s: KPRIORITY
    ProcessRaisePriority, // s: ULONG
    ProcessDebugPort, // q: HANDLE
    ProcessExceptionPort, // s: PROCESS_EXCEPTION_PORT (requires SeTcbPrivilege)
    ProcessAccessToken, // s: PROCESS_ACCESS_TOKEN
    ProcessLdtInformation, // qs: PROCESS_LDT_INFORMATION // 10
    ProcessLdtSize, // s: PROCESS_LDT_SIZE
    ProcessDefaultHardErrorMode, // qs: ULONG
    ProcessIoPortHandlers, // s: PROCESS_IO_PORT_HANDLER_INFORMATION // (kernel-mode only)
    ProcessPooledUsageAndLimits, // q: POOLED_USAGE_AND_LIMITS
    ProcessWorkingSetWatch, // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
    ProcessUserModeIOPL, // qs: ULONG (requires SeTcbPrivilege)
    ProcessEnableAlignmentFaultFixup, // s: BOOLEAN
    ProcessPriorityClass, // qs: PROCESS_PRIORITY_CLASS
    ProcessWx86Information, // qs: ULONG (requires SeTcbPrivilege) (VdmAllowed)
    ProcessHandleCount, // q: ULONG, PROCESS_HANDLE_INFORMATION // 20
    ProcessAffinityMask, // (q >WIN7)s: KAFFINITY, qs: GROUP_AFFINITY
    ProcessPriorityBoost, // qs: ULONG
    ProcessDeviceMap, // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
    ProcessSessionInformation, // q: PROCESS_SESSION_INFORMATION
    ProcessForegroundInformation, // s: PROCESS_FOREGROUND_BACKGROUND
    ProcessWow64Information, // q: ULONG_PTR
    ProcessImageFileName, // q: UNICODE_STRING
    ProcessLUIDDeviceMapsEnabled, // q: ULONG
    ProcessBreakOnTermination, // qs: ULONG
    ProcessDebugObjectHandle, // q: HANDLE // 30
    ProcessDebugFlags, // qs: ULONG
    ProcessHandleTracing, // q: PROCESS_HANDLE_TRACING_QUERY; s: PROCESS_HANDLE_TRACING_ENABLE[_EX] or void to disable
    ProcessIoPriority, // qs: IO_PRIORITY_HINT
    ProcessExecuteFlags, // qs: ULONG (MEM_EXECUTE_OPTION_*)
    ProcessTlsInformation, // PROCESS_TLS_INFORMATION // ProcessResourceManagement
    ProcessCookie, // q: ULONG
    ProcessImageInformation, // q: SECTION_IMAGE_INFORMATION
    ProcessCycleTime, // q: PROCESS_CYCLE_TIME_INFORMATION // since VISTA
    ProcessPagePriority, // qs: PAGE_PRIORITY_INFORMATION
    ProcessInstrumentationCallback, // s: PVOID or PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION // 40
    ProcessThreadStackAllocation, // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
    ProcessWorkingSetWatchEx, // q: PROCESS_WS_WATCH_INFORMATION_EX[]; s: void
    ProcessImageFileNameWin32, // q: UNICODE_STRING
    ProcessImageFileMapping, // q: HANDLE (input)
    ProcessAffinityUpdateMode, // qs: PROCESS_AFFINITY_UPDATE_MODE
    ProcessMemoryAllocationMode, // qs: PROCESS_MEMORY_ALLOCATION_MODE
    ProcessGroupInformation, // q: USHORT[]
    ProcessTokenVirtualizationEnabled, // s: ULONG
    ProcessConsoleHostProcess, // qs: ULONG_PTR // ProcessOwnerInformation
    ProcessWindowInformation, // q: PROCESS_WINDOW_INFORMATION // 50
    ProcessHandleInformation, // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
    ProcessMitigationPolicy, // s: PROCESS_MITIGATION_POLICY_INFORMATION
    ProcessDynamicFunctionTableInformation, // s: PROCESS_DYNAMIC_FUNCTION_TABLE_INFORMATION
    ProcessHandleCheckingMode, // qs: ULONG; s: 0 disables, otherwise enables
    ProcessKeepAliveCount, // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
    ProcessRevokeFileHandles, // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
    ProcessWorkingSetControl, // s: PROCESS_WORKING_SET_CONTROL
    ProcessHandleTable, // q: ULONG[] // since WINBLUE
    ProcessCheckStackExtentsMode, // qs: ULONG // KPROCESS->CheckStackExtents (CFG)
    ProcessCommandLineInformation, // q: UNICODE_STRING // 60
    ProcessProtectionInformation, // q: PS_PROTECTION
    ProcessMemoryExhaustion, // s: PROCESS_MEMORY_EXHAUSTION_INFO // since THRESHOLD
    ProcessFaultInformation, // s: PROCESS_FAULT_INFORMATION
    ProcessTelemetryIdInformation, // q: PROCESS_TELEMETRY_ID_INFORMATION
    ProcessCommitReleaseInformation, // qs: PROCESS_COMMIT_RELEASE_INFORMATION
    ProcessDefaultCpuSetsInformation, // qs: SYSTEM_CPU_SET_INFORMATION[5]
    ProcessAllowedCpuSetsInformation, // qs: SYSTEM_CPU_SET_INFORMATION[5]
    ProcessSubsystemProcess, // s: void // EPROCESS->SubsystemProcess
    ProcessJobMemoryInformation, // q: PROCESS_JOB_MEMORY_INFO
    ProcessInPrivate, // q: BOOLEAN; s: void // ETW // since THRESHOLD2 // 70
    ProcessRaiseUMExceptionOnInvalidHandleClose, // qs: ULONG; s: 0 disables, otherwise enables
    ProcessIumChallengeResponse,
    ProcessChildProcessInformation, // q: PROCESS_CHILD_PROCESS_INFORMATION
    ProcessHighGraphicsPriorityInformation, // qs: BOOLEAN (requires SeTcbPrivilege)
    ProcessSubsystemInformation, // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
    ProcessEnergyValues, // q: PROCESS_ENERGY_VALUES, PROCESS_EXTENDED_ENERGY_VALUES
    ProcessPowerThrottlingState, // qs: POWER_THROTTLING_PROCESS_STATE
    ProcessReserved3Information, // ProcessActivityThrottlePolicy // PROCESS_ACTIVITY_THROTTLE_POLICY
    ProcessWin32kSyscallFilterInformation, // q: WIN32K_SYSCALL_FILTER
    ProcessDisableSystemAllowedCpuSets, // s: BOOLEAN // 80
    ProcessWakeInformation, // q: PROCESS_WAKE_INFORMATION
    ProcessEnergyTrackingState, // qs: PROCESS_ENERGY_TRACKING_STATE
    ProcessManageWritesToExecutableMemory, // MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
    ProcessCaptureTrustletLiveDump, // q: ULONG
    ProcessTelemetryCoverage, // q: TELEMETRY_COVERAGE_HEADER; s: TELEMETRY_COVERAGE_POINT
    ProcessEnclaveInformation,
    ProcessEnableReadWriteVmLogging, // qs: PROCESS_READWRITEVM_LOGGING_INFORMATION
    ProcessUptimeInformation, // q: PROCESS_UPTIME_INFORMATION
    ProcessImageSection, // q: HANDLE
    ProcessDebugAuthInformation, // s: CiTool.exe --device-id // PplDebugAuthorization // since RS4 // 90
    ProcessSystemResourceManagement, // s: PROCESS_SYSTEM_RESOURCE_MANAGEMENT
    ProcessSequenceNumber, // q: ULONGLONG
    ProcessLoaderDetour, // since RS5
    ProcessSecurityDomainInformation, // q: PROCESS_SECURITY_DOMAIN_INFORMATION
    ProcessCombineSecurityDomainsInformation, // s: PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION
    ProcessEnableLogging, // qs: PROCESS_LOGGING_INFORMATION
    ProcessLeapSecondInformation, // qs: PROCESS_LEAP_SECOND_INFORMATION
    ProcessFiberShadowStackAllocation, // s: PROCESS_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION // since 19H1
    ProcessFreeFiberShadowStackAllocation, // s: PROCESS_FREE_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION
    ProcessAltSystemCallInformation, // s: PROCESS_SYSCALL_PROVIDER_INFORMATION // since 20H1 // 100
    ProcessDynamicEHContinuationTargets, // s: PROCESS_DYNAMIC_EH_CONTINUATION_TARGETS_INFORMATION
    ProcessDynamicEnforcedCetCompatibleRanges, // s: PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGE_INFORMATION // since 20H2
    ProcessCreateStateChange, // since WIN11
    ProcessApplyStateChange,
    ProcessEnableOptionalXStateFeatures, // s: ULONG64 // optional XState feature bitmask
    ProcessAltPrefetchParam, // qs: OVERRIDE_PREFETCH_PARAMETER // App Launch Prefetch (ALPF) // since 22H1
    ProcessAssignCpuPartitions, // HANDLE
    ProcessPriorityClassEx, // s: PROCESS_PRIORITY_CLASS_EX
    ProcessMembershipInformation, // q: PROCESS_MEMBERSHIP_INFORMATION
    ProcessEffectiveIoPriority, // q: IO_PRIORITY_HINT // 110
    ProcessEffectivePagePriority, // q: ULONG
    ProcessSchedulerSharedData, // SCHEDULER_SHARED_DATA_SLOT_INFORMATION // since 24H2
    ProcessSlistRollbackInformation,
    ProcessNetworkIoCounters, // q: PROCESS_NETWORK_COUNTERS
    ProcessFindFirstThreadByTebValue, // PROCESS_TEB_VALUE_INFORMATION
    ProcessEnclaveAddressSpaceRestriction, // since 25H2
    ProcessAvailableCpus, // PROCESS_AVAILABLE_CPUS_INFORMATION
    MaxProcessInfoClass
} PROCESSINFOCLASS;

namespace K8_ProcessManipulationAPIs
{
    using OpenProcess_t                 =   HANDLE(WINAPI*)(DWORD, BOOL, DWORD);
    using TerminateProcess_t            =       BOOL(WINAPI*)(HANDLE, UINT);
    using CreateRemoteThread_t          =       HANDLE(WINAPI*)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
    using VirtualAllocEx_t              =       LPVOID(WINAPI*)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
    using WriteProcessMemory_t          =       BOOL(WINAPI*)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
    using ReadProcessMemory_t           =       BOOL(WINAPI*)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
    using GetProcAddress_t              =       FARPROC(WINAPI*)(HMODULE, LPCSTR);
    using GetModuleHandleA_t            =       HMODULE(WINAPI*)(LPCSTR);
    using NtQueryInformationProcess_t   =       NTSTATUS(WINAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    using SuspendThread_t               =       DWORD(WINAPI*)(HANDLE);
    using GetCurrentProcessId_t         =       DWORD(WINAPI*)();

    class ProcessAPI
    {
    public:
        OpenProcess_t pOpenProcess;
        TerminateProcess_t pTerminateProcess;
        CreateRemoteThread_t pCreateRemoteThread;
        VirtualAllocEx_t pVirtualAllocEx;
        WriteProcessMemory_t pWriteProcessMemory;
        ReadProcessMemory_t pReadProcessMemory;
        GetProcAddress_t pGetProcAddress;
        GetModuleHandleA_t pGetModuleHandleA;
        NtQueryInformationProcess_t pNtQueryInformationProcess;
        SuspendThread_t pSuspendThread;
        GetCurrentProcessId_t pGetCurrentProcessId;

        bool m_initialized;

        ProcessAPI() :
            pOpenProcess(nullptr),
            pTerminateProcess(nullptr),
            pCreateRemoteThread(nullptr),
            pVirtualAllocEx(nullptr),
            pWriteProcessMemory(nullptr),
            pReadProcessMemory(nullptr),
            pGetProcAddress(nullptr),
            pGetModuleHandleA(nullptr),
            pNtQueryInformationProcess(nullptr),
            pSuspendThread(nullptr),
            pGetCurrentProcessId(nullptr),
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
            pOpenProcess                    =       reinterpret_cast<OpenProcess_t>(STEALTH_API_OBFSTR("kernel32.dll", "OpenProcess"));
            pTerminateProcess               =       reinterpret_cast<TerminateProcess_t>(STEALTH_API_OBFSTR("kernel32.dll", "TerminateProcess"));
            pCreateRemoteThread             =       reinterpret_cast<CreateRemoteThread_t>(STEALTH_API_OBFSTR("kernel32.dll", "CreateRemoteThread"));
            pVirtualAllocEx                 =       reinterpret_cast<VirtualAllocEx_t>(STEALTH_API_OBFSTR("kernel32.dll", "VirtualAllocEx"));
            pWriteProcessMemory             =       reinterpret_cast<WriteProcessMemory_t>(STEALTH_API_OBFSTR("kernel32.dll", "WriteProcessMemory"));
            pReadProcessMemory              =       reinterpret_cast<ReadProcessMemory_t>(STEALTH_API_OBFSTR("kernel32.dll", "ReadProcessMemory"));
            pGetProcAddress                 =       reinterpret_cast<GetProcAddress_t>(STEALTH_API_OBFSTR("kernel32.dll", "GetProcAddress"));
            pGetModuleHandleA               =       reinterpret_cast<GetModuleHandleA_t>(STEALTH_API_OBFSTR("kernel32.dll", "GetModuleHandleA"));
            pNtQueryInformationProcess      =       reinterpret_cast<NtQueryInformationProcess_t>(STEALTH_API_OBFSTR("ntdll.dll", "NtQueryInformationProcess"));
            pSuspendThread                  =       reinterpret_cast<SuspendThread_t>(STEALTH_API_OBFSTR("kernel32.dll", "SuspendThread"));
            pGetCurrentProcessId            =       reinterpret_cast<GetCurrentProcessId_t>(STEALTH_API_OBFSTR("kernel32.dll", "GetCurrentProcessId"));

            if (pOpenProcess && pTerminateProcess && pCreateRemoteThread && pVirtualAllocEx &&
                pWriteProcessMemory && pReadProcessMemory && pGetProcAddress &&
                pGetModuleHandleA && pNtQueryInformationProcess && pSuspendThread && pGetCurrentProcessId)
            {
                m_initialized = true;
                printf("ProcessManipulationAPIs Initialized successfully (all functions resolved)..\n");
            }
        }
    };
}

