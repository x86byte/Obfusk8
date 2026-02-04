# Obfusk8: C++17-Based Obfuscation Library

**Obfusk8** is a lightweight, header-only C++17 library designed to significantly enhance the obfuscation of your applications, making reverse engineering a substantially more challenging endeavor. It achieves this through a diverse set of compile-time and runtime techniques aimed at protecting your code's logic and data.

   ![banner](https://github.com/user-attachments/assets/09a3c47f-fa56-42f5-b50a-b25d29922de5)


---
## Table of Contents
1. [Core Obfuscation Strategies](#core-obfuscation-strategies)
2. [Dependencies](#dependencies)
3. [Visualisation](#visualisation)
4. [Engine Analysis and Detection Profile](#engine-analysis-and-detection-profile)
5. [Structural and Forensic Characteristics](#structural-and-forensic-characteristics)
6. [Usage](#usage)
7. [Building](#building)
8. [Demo](#demo)
9. [contribution & Feedback](#contribution--feedback)
---


### Core Obfuscation Strategies

### 1. `main` Function Wrapping (`_main` Macro)
The entry point of your application (`main`) is transformed into a complex, multi-layered obfuscation engine:
*   **Virtual Machine (VM) Execution (Conceptual)**: Before your actual `main_body` code is executed, a mini-VM (simulated CPU) runs a sequence of "encrypted" instructions. This conceals the true entry point and initial operations. The VM's state (registers, program counter, dispatch key) is initialized with runtime-randomized values.
*   **Indirect Control Flow Flattening (ICFF)**: Critical loops within the `_main` macro (both in the prologue and epilogue) are transformed into intricate state machines. Control flow is not direct but determined by heavily "encrypted" state variables. The encoding/decoding keys for these state variables are dynamic, derived from VM state, loop counters, compile-time randomness (like `__COUNTER__`, `__LINE__`, `__TIME__`), and a global opaque seed. This makes static analysis of the control flow exceptionally difficult.
    *   Two distinct ICFF engines (`obf_icff_ns_dcff` and `obf_icff_ns_epd`) are used with different state transition logic and key generation, further complicating analysis.
*   **Bogus Control Flow (`OBF_BOGUS_FLOW_*` macros)**: Numerous misleading jump patterns and convoluted conditional structures are injected throughout `_main`. These use `goto` statements combined with opaque predicates (conditions that always evaluate to true or false but are computationally expensive or hard to determine statically). This creates a labyrinth of false paths for disassemblers and decompilers.
    *   Includes `OBF_BOGUS_FLOW_LABYRINTH`, `OBF_BOGUS_FLOW_GRID`, `OBF_BOGUS_FLOW_SCRAMBLE`, `OBF_BOGUS_FLOW_WEAVER`, `OBF_BOGUS_FLOW_CASCADE`, and `OBF_BOGUS_FLOW_CYCLONE` to generate diverse and complex bogus flows.
*   **Anti-Analysis & Anti-Debug Tricks (`Runtime` macro, SEH)**:
    *   **Forced Exceptions & SEH**: Structured Exception Handling (SEH) is used to create paths that involve forced exceptions. The `__except` blocks can alter program state, making it hard to follow if the debugger skips exceptions.
    *   **Debugger Checks (Conceptual)**: The `Runtime` macro contains conditions that, if met (due to specific VM states or timing), could trigger `__debugbreak()` or throw exceptions, designed to disrupt debugging sessions.

### 2. Virtual ISA Engine (`obf_vm_engine`)
A core component of the `_main` macro's obfuscation:
*   **Custom Mini-CPU Simulation**: Simulates a CPU with volatile registers (`r0`, `r1`, `r2`), a program counter (`pc`), and a `dispatch_key`. It executes custom "instructions" (handlers).
*   **Obfuscated Instructions**: VM instruction handlers perform operations that are heavily disguised using Mixed Boolean-Arithmetic (MBA) and bitwise manipulations. Handlers include arithmetic, bitwise logic, key mangling, junk sequences, conditional updates, memory simulation, and PC mangling.
*   **Dynamic Dispatch**: The selection of the next VM instruction handler is randomized through multiple dispatch mechanisms:
    *   Register-based dispatch (`reg_dispatch_idx`).
    *   Memory-table based dispatch (scrambled function pointer table `get_mem_dispatch_table`).
    *   Mixed dispatch (`mixed_dispatch_idx`).
    The `dispatch_key` is constantly mutated, making the sequence of executed handlers highly unpredictable.
*   **Handler Table Mutation**: The table of VM instruction handlers (`vm_handler_table`) is itself mutated at runtime within the `_main` prologue and epilogue, further obscuring the VM's behavior.

### 3. Compile-Time String Encryption (`OBFUSCATE_STRING` from `AES8.hpp`)
*   **Hidden Strings**: Encrypts all string literals at compile-time using a modified AES cipher.
*   **Dynamic Keys**: Encryption keys are unique per string instance, derived from string content, file location (`__FILE__`, `__LINE__`), and build time (`__DATE__`, `__TIME__`).
*   **Just-In-Time Decryption**: Strings are decrypted on the stack only when accessed at runtime, minimizing their plaintext lifetime in memory.
*   **(Optional) Decoy PE Sections**: Can store encrypted strings in custom PE sections designed to mimic common packer signatures, potentially misleading analysts (MSVC-specific feature from `AES8.hpp`).

### 4. Stealthy Windows API Calling (`STEALTH_API_OBFSTR` / `STEALTH_API_OBF` from `Resolve8.hpp`)
*   **IAT Obscurity**: Avoids leaving direct, easily identifiable entries for Windows APIs in the Import Address Table (IAT).
*   **PEB-Based Resolution**: Dynamically finds base addresses of loaded DLLs and the addresses of API functions by directly parsing Process Environment Block (PEB) data structures at runtime. This bypasses standard `GetModuleHandle` and `GetProcAddress` for initial resolution if those themselves are not yet resolved by this mechanism.
*   **Hashed Names**: Uses compile-time hashing (custom algorithm `CT_HASH`) of DLL and API names for lookups. This prevents plaintext DLL and API names from appearing in the binary's import-related data or string tables when using these macros.

### 5. Indirect Syscall Engine (`K8_SYSCALL`)
Obfusk8 now integrates a state-of-the-art Indirect Syscall mechanism to bypass User-Mode Hooks (EDRs/AVs) and static analysis checks.
*   **"The Sorting Hat" Resolution**: Instead of reading the .text section of ntdll.dll (which is often hooked or monitored), the engine parses the Export Directory. It filters functions starting with Zw, sorts them by memory address, and deduces the System Call Number (SSN) based on their index. This allows SSN resolution without ever touching executable code.
*   **Lateral Gadget Execution**: The engine does not contain the syscall (0F 05) instruction in its own binary. Instead, it locates a valid syscall; ret gadget inside ntdll.dll memory at runtime.
Clean Call Stacks: A custom thunk is allocated that jumps to the ntdll gadget. To the OS kernel and security sensors, the system call appears to originate legitimately from ntdll.dll, maintaining a clean call stack.
*   **Usage**:
     Simply use `K8_SYSCALL("ZwOpenProcess", ...)` instead of NtOpenProcess.

### 6. Method-Based Obfuscation with (`OBF_METHOD`)
Obfusk8 now provides granular control over your binary's security through **Method-Based Obfuscation**. Instead of obfuscating your entire project (which can impact performance), you can now selectively protect specific, high-value functions or class methods.

---

### **How to Use**

1. **Include the Pass**  
   Ensure you include the method obfuscation logic in your project:
   ```cpp
   #include "../transform/PASSES/obf_cmethods.cxx"
   ```

2. **The Macro Syntax**  
   Define your method using the `OBF_METHOD` macro:
   ```cpp
   OBF_METHOD(ret_type, func_name, params, method_body)
   ```
   *   **`ret_type`**: The return type of your function (e.g., `bool`, `int`, `void*`).
   *   **`func_name`**: The name of the method.
   *   **`params`**: The function parameters (must be enclosed in parentheses).
   *   **`method_body`**: The actual logic of your function enclosed in `{ }`.

---

### **Example: Standard vs Obfuscated methods**

In this example, `PrintStatus` is a normal, readable function. `Obfusk8_PrintStatus` is protected by Obfusk8.

```cpp
#include "Obfusk8Core.hpp"

class Obfusk8_C
{
public:
    // standard method which is visible to reverse engineers
    void PrintStatus(void)
    {
        printf_("method\n");
    }

    // Obfuscated method protected by Obfusk8
    OBF_METHOD_(void, Obfusk8_PrintStatus, (void),
    {
        printf_("same method but Obfuscated\n");
    })
};

_main({
    Obfusk8_C *pp = new Obfusk8_C;
    pp->PrintStatus();
    pp->Obfusk8_PrintStatus();
    delete pp;
})
```
*You can view the full example here: [obfusk8_methods.cpp](https://github.com/x86byte/Obfusk8/blob/main/Obfusk8/EXAMPLES/obfusk8_methods.cpp)*

---
### 6. API Abstraction Classes with Built-in Stealth
Obfusk8 provides helper classes that encapsulate common sets of Windows APIs. These classes automatically use the stealthy API resolution mechanism (`STEALTH_API_OBFSTR`) during their construction, ensuring that the underlying Windows functions are resolved without leaving obvious static import traces.

   - **`K8_ProcessManipulationAPIs::ProcessAPI` (`k8_ProcessManipulationAPIs.hpp`)**:
     *   Provides convenient access to Windows APIs for process manipulation, such as `OpenProcess`, `TerminateProcess`, `CreateRemoteThread`, `VirtualAllocEx`, `WriteProcessMemory`, `ReadProcessMemory`, `GetProcAddress`, `GetModuleHandleA`, `NtQueryInformationProcess`, `SuspendThread`, and `GetCurrentProcessId`.
     *   **Automatic Stealth Resolution**: Resolves necessary functions from `kernel32.dll` and `ntdll.dll` stealthily.
     *   Simplifies performing process-related operations with a reduced static analysis footprint. Includes the `PROCESSINFOCLASS` enum for use with `NtQueryInformationProcess`.

   - **`k8_CryptographyAPIs::CryptographyAPI` (`k8_CryptographyAPIs.hpp`)**:
     *   Offers wrappers for common Windows Cryptography API (CAPI/CNG) functions. (Functionality depends on the actual implementation of this file - the provided snippet was a duplicate. Assuming typical CAPI functions like `CryptAcquireContextA`, `CryptCreateHash`, etc.)
     *   **Automatic Stealth Resolution**: Resolves necessary functions primarily from `advapi32.dll` (and `kernel32.dll` for core functions) stealthily.
     *   Facilitates cryptographic operations while minimizing the exposure of crypto API usage.

   - **`k8_NetworkingAPIs::NetworkingAPI` (`k8_NetworkingAPIs.hpp`)**:
     *   Provides easy access to a wide range of networking functions from `wininet.dll` (e.g., `InternetOpenA`, `HttpOpenRequestA`, `FtpPutFileA`), `urlmon.dll` (e.g., `URLDownloadToFileA`), `ws2_32.dll` (e.g., `socket`, `connect`, `WSAStartup`), `shell32.dll` (e.g., `ShellExecuteA`), `dnsapi.dll` (e.g., `DnsQuery_A`), and `mpr.dll` (e.g., `WNetOpenEnumA`).
     *   **Automatic Stealth Resolution**: In its constructor, it uses `STEALTH_API_OBFSTR` and `OBFUSCATE_STRING` to resolve all required functions from their respective DLLs (and `kernel32.dll` for `LoadLibraryA`/`GetLastError`) without leaving obvious import traces.
     *   Simplifies making obfuscated network requests and performing other network-related tasks.

   - **`RegistryAPIs::RegistryAPI` (`k8_RegistryAPIs.hpp`)**:
     *   Wraps commonly used Windows Registry functions such as `RegSetValueExA`, `RegCreateKeyExA`, `RegOpenKeyExA`, `RegQueryValueExA`, `RegCloseKey`, etc.
     *   **Automatic Stealth Resolution**: Resolves functions from `advapi32.dll` (and `kernel32.dll`) stealthily during construction.
     *   Aids in performing registry operations with less traceable API calls.

### 7. Core Obfuscation Primitives (Macros in `Obfusk8Core.hpp`)
These are the building blocks used extensively throughout the library, especially in the `_main` macro and VM engine:
*   **Mixed Boolean-Arithmetic (MBA)**: Transforms simple mathematical and logical operations (ADD, SUB, XOR, NOT, MUL) into complex, but equivalent, sequences of bitwise and arithmetic formulas (e.g., `OBF_MBA_ADD`, `OBF_MBA_XOR`). These are designed to be very difficult for decompilers to simplify back to their original forms.
*   **Opaque Predicates**: Inserts conditional branches where the condition always evaluates to true (e.g., `OBF_OPAQUE_PREDICATE_TRUE_1`) or always false (e.g., `OBF_OPAQUE_PREDICATE_FALSE_1`). These conditions are constructed from complex, hard-to-statically-evaluate expressions involving `__COUNTER__`, `__LINE__`, `__TIME__`, and the `_obf_global_opaque_seed`. They create misleading code paths and can be used to guard dead code or force specific execution flows.
*   **Junk Code Injection**:
    *   `OBF_CALL_ANY_LOCAL_JUNK`: Calls one of many small, randomized junk functions defined in `obf_junk_ns`. These functions perform trivial, volatile operations and are selected randomly at compile time. Their purpose is to increase code entropy, break up simple code patterns, and potentially mislead signature-based detection or analysis tools.
    *   `NOP()`: A macro that inserts volatile operations designed to prevent easy removal by optimizers and to subtly modify a global seed.
*   **Anti-Disassembly & Anti-Analysis Tricks**:
    *   **Obfuscated Jumps (`OBF_JUMP_*` macros)**: Creates `goto` statements whose conditions or targets are obfuscated, often relying on opaque predicates or MBA.
    *   **Obfuscated State Transitions (`OBF_SET_NEXT_STATE_*` macros)**: Used in ICFF, these macros set the next state variable for the flattened control flow dispatcher using similar obfuscation techniques as the obfuscated jumps.
    *   **Stack Manipulation (`OBF_STACK_ALLOC_MANIP`, `OBF_FAKE_PROLOGUE_MANIP`)**: Allocates variable-sized chunks on the stack and performs bogus manipulations on them. Fake prologues attempt to confuse stack analysis.
    *   **Obfuscated Function Calls (`OBF_CALL_VIA_OBF_PTR`)**: Function pointers are XORed with a dynamic key before and after being used, obscuring the true call target.
    *   `K8_ASSUME(0)`: Used in dead code paths to hint to the MSVC compiler that these paths are unreachable, potentially allowing for different optimizations or code generation that might further confuse analysis if the assumption is violated by a patch.

### Dependencies

The Obfusk8 library is modular. Core functionality relies on:

- `Obfusk8/Instrumentation/materialization/state/Obfusk8Core.hpp`: (This file) The central header that orchestrates and provides the main obfuscation macros and primitives.
- `Obfusk8/Instrumentation/materialization/transform/AES8.hpp`: Provides AES-based compile-time string encryption and optional PE section manipulation features.
- `Obfusk8/Instrumentation/materialization/transform/Resolve8.hpp`: Implements the PEB-based stealthy Windows API resolution.
* `Obfusk8/Instrumentation/materialization/transform/k8_indsys.hpp`: Orchestrates the **Indirect Syscall Engine**. It manages the lifecycle of transition stubs and provides the interface for executing system calls through lateral memory gadgets.
* `Obfusk8/Instrumentation/materialization/transform/getpeb8.hpp`: Facilitates the initial bootstrap and **PEB Discovery**. It contains the custom hashing logic, native structure definitions, and the "Sorting Hat" algorithm for SSN deduction. It serves as the low-level foundation for all module enumeration tasks.
Optional helper API classes are provided in separate headers, typically located in subdirectories:
- `k8_ProcessManipulationAPIs/k8_ProcessManipulationAPIs.hpp`: For stealthy process manipulation APIs.
- `k8_CryptographyAPIs/k8_CryptographyAPIs.hpp`: For stealthy cryptography APIs.
- `k8_NetworkingAPIs/k8_NetworkingAPIs.hpp`: For stealthy networking APIs.
- `k8_RegistryAPIs/k8_RegistryAPIs.hpp`: For stealthy registry APIs.


### Visualisation

  *   **ida graph**:
    
      ![image](https://github.com/user-attachments/assets/680f542e-88c0-472e-8149-4ee6c80e82a2)
     
  *   **some chunks from ida pro**:
    
      ![image](https://github.com/user-attachments/assets/2bdc6270-96d9-4448-9557-54f9ef4035e3)
      ![image](https://github.com/user-attachments/assets/952584b4-f046-4ff4-a3a4-c485fa370aa8)
      ![image](https://github.com/user-attachments/assets/54128487-445c-42c9-86df-202f77a2eb73)
    
  *   **detect it easy signatures results**:
    
      ![image](https://github.com/user-attachments/assets/460889f8-49a7-4d6d-a226-442d4cece4db)

  *   **Crowdsourced YARA rules from virustotal**:

      ![yararules](https://github.com/user-attachments/assets/5ce206ef-37b7-43b2-a94d-5bde9afb002b)


  *   **memory map (from die)**:

      ![map](https://github.com/user-attachments/assets/396bda32-9054-4116-a1e7-80b0bc41096d)
  
  *   **sections**:

      ![sections](https://github.com/user-attachments/assets/7ac099ad-b5f3-4c19-9fcb-7573d94c7996)

  *   **bounded files**:

      ![bfiles](https://github.com/user-attachments/assets/704e55ab-da0c-4279-8bd6-f830b2e638c9)

### Engine Analysis and Detection Profile

Obfusk8 is designed to prioritize the bypass of static signature-based detection engines. Testing against industry-standard vendors shows that the core obfuscation logic remains undetected by major security products, including:

*   **Microsoft Defender**: Undetected
*   **Kaspersky**: Undetected
*   **ESET-NOD32**: Undetected
*   **BitDefender**: Undetected

While static signatures are bypassed, certain Next-Gen AVs and EDRs (such as CrowdStrike or Symantec) may generate heuristic flags labeled as "suspicious" or "high Confidence Malicious." These detections are typically triggered by the high architectural complexity and the presence of custom PE sections rather than identifiable malicious code.

### Structural and Forensic Characteristics

*   **entropy management**: The current implementation produces a global entropy of approximately 6.2. This is intentionally balanced to be high enough to obscure logic but low enough to avoid the common "packed file" alerts triggered by entropy levels above 7.0.
*   **Section Customization**: the default configuration includes 23 PE sections, some of which use decoy names (e.g., `.themida`, `.vmp0`, `.enigma2`) to mimic known commercial protectors. 
    *   **Heuristic Optimization**: to further reduce the suspicion score, users can rename these sections to generic strings (e.g., `.data_01`, `.rdata_aux`). Standardizing section names often lowers the heuristic "uniqueness" score, making the binary appear more like a conventional compiled application.
*   **Import Obfuscation**: The library successfully eliminates the Import Address Table (IAT) footprint for critical Windows APIs. By utilizing the Process Environment Block (PEB) for resolution and the Indirect Syscall engine, the binary maintains a clean call stack, preventing behavioral monitors from tracing system calls back to protected code regions.
     - **quick explanation**:
        *   **ssn deduction**: to bypass user-mode hooks often placed on the instruction stream of ntdll.dll, the engine utilizes a relative sorting algorithm. By parsing the Export Directory and sorting all Zw-prefixed functions by their memory addresses, the engine deduces System Service Numbers (SSNs) based on their relative index. This allows the framework to identify the correct syscall index without ever reading the hooked bytes of the function prologue.
Dynamic Syscall Stubs: Instead of utilizing static syscall instructions within the user-land binary, the library dynamically allocates executable memory to host transient transition stubs. The engine populates these stubs with a custom shellcode sequence (`mov r10, rcx; mov eax, ssnnumber; syscall; ret`) to execute system calls indirectly.
        *   **chain bootstrapping**: the resolution process is self-bootstrapped; the engine uses an initial resolved call to establish the environment for subsequent indirect syscalls. This ensures that the entire lifecycle of the process—from module enumeration to function execution—remains opaque to behavioral monitors and maintains a clean call stack.
*   **anti-Forensics**: The use of Mixed Boolean-Arithmetic (MBA) and multi-layered Virtual Instruction Set Architecture (V-ISA) ensures that even if a memory dump is obtained, the underlying logic is non-trivial to reconstruct through automated deobfuscation tools.

### Usage

1.  Include `Obfusk8/Instrumentation/materialization/state/Obfusk8Core.hpp` in your main project file (e.g., `main.cpp`).
    ```cpp
    #include "Obfusk8/Instrumentation/materialization/state/Obfusk8Core.hpp" // Adjust path as needed
    ```
2.  Wrap your `main` function's body with the `_main`:
    ```cpp
    _main({
        // Your application's original main code here
        // Example:
        // OBFUSCATE_STRING("Hello, Obfuscated World!").c_str();
        
        // Using an API wrapper class
        k8_NetworkingAPIs::NetworkingAPI* netAPI = new k8_NetworkingAPIs::NetworkingAPI;
        if (netAPI->IsInitialized() && netAPI->pInternetOpenA) {
            HINTERNET hInternet = netAPI->pInternetOpenA(OBFUSCATE_STRING("MyAgent").c_str(), INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
            if (hInternet) {
                // ... use hInternet ...
                netAPI->pInternetCloseHandle(hInternet);
            }
        }

        delete netAPI;
    })
    ```
3.  Use `OBFUSCATE_STRING("your string")` for all important string literals. Access the decrypted string via its `.c_str()` method if needed for API calls, or use its other methods like `.print_to_console()` if provided by `Obfusk8/Instrumentation/materialization/transform/AES8.hpp`.
4.  Use `STEALTH_API_OBFSTR("dll_name.dll", "FunctionNameA")` for direct stealthy API calls, or preferably use the API wrapper classes (e.g., `K8_ProcessManipulationAPIs::ProcessAPI`, `k8_NetworkingAPIs::NetworkingAPI`) for convenience and built-in stealth.
5.  Sprinkle `OBF_BOGUS_FLOW_*`, `OBF_CALL_ANY_LOCAL_JUNK`, `NOP()`, and other primitives in performance-insensitive critical sections of your code for added obfuscation layers.

* see the main.cpp file.

### Building

*   **Compiler Requirement**: This library is designed for C++17. The Microsoft C++ Compiler (`cl.exe`) is primarily targeted, especially for PE section features and SEH usage.
*   **Getting `cl.exe` (MSVC Compiler) on Windows**:
    1.  **Install Visual Studio**: The easiest way to get `cl.exe` is by installing Visual Studio. You can download the Visual Studio Community edition for free from the [Visual Studio website](https://visualstudio.microsoft.com/downloads/).
    2.  **Select Workload**: During installation, make sure to select the "Desktop development with C++" workload. This will install the C++ compiler, Windows SDK, and other necessary tools.
    3.  **Use Developer Command Prompt**: After installation, search for "Developer Command Prompt for VS" (e.g., "x64 Native Tools Command Prompt for VS 2022") in your Start Menu and run it. This command prompt automatically sets up the environment variables (PATH, INCLUDE, LIB) needed to use `cl.exe`.
*   **Include Paths**:
    *   Ensure the directory containing `Obfusk8/Instrumentation/materialization/state/Obfusk8Core.hpp` is in your compiler's include path.
    *   If `Obfusk8/Instrumentation/materialization/transform/AES8.hpp`, `Obfusk8/Instrumentation/materialization/transform/Resolve8.hpp`, and the API wrapper directories (e.g., `k8_NetworkingAPIs/`) are not in the same directory as `Obfusk8/Instrumentation/materialization/state/Obfusk8Core.hpp`, ensure their paths are also correctly configured. `Obfusk8/Instrumentation/materialization/state/Obfusk8Core.hpp` uses relative paths like `../Obfusk8Core.hpp` for some of its internal includes of the API wrappers, so the directory structure matters. If `Obfusk8/Instrumentation/materialization/state/Obfusk8Core.hpp` is at the root of your include directory for this library, then API wrappers should be in subdirectories like `k8_NetworkingAPIs/` relative to where `Obfusk8/Instrumentation/materialization/state/Obfusk8Core.hpp` expects them or adjust the include paths within `Obfusk8/Instrumentation/materialization/state/Obfusk8Core.hpp` itself.
*   **Compilation Example (using Developer Command Prompt)**:
    Assuming your `main.cpp` and the Obfusk8 headers are structured correctly, you can compile using a command similar to:
    ```bash
    cl /std:c++17 /EHsc main.cpp
    ```
    *   after opening `x64 Native Tools Command Prompt for VS 2022`:
      
        ![x64 Native Tools Command Prompt for VS 2022](https://github.com/user-attachments/assets/f5da8da0-b466-4836-a525-0e37acf4b8cb)

        
    *   `/std:c++17`: Specifies C++17 standard.
    *   `/EHsc`: Specifies the C++ exception handling model.
    *   `main.cpp`: Your main source file.
    *   `/I"path/to/your/obfusk8_includes"`: (Optional, if headers are not in default paths) Add the directory where `Obfusk8/Instrumentation/materialization/state/Obfusk8Core.hpp` and its dependencies are located. If they are in subdirectories, ensure the relative paths within `Obfusk8Core.hpp` match your layout.
    *   **Note on Libraries**: While the stealth API resolution aims to avoid static linking for the obfuscated functions, the Windows SDK headers themselves might require certain `.lib` files to be available to the linker for resolving any non-obfuscated SDK usage or internal types (e.g., `Ws2_32.lib`, `Wininet.lib`, `Advapi32.lib`, etc.). For a simple project like `cl /std:c++17 /EHsc main.cpp`, the linker often resolves these automatically if they are standard Windows libraries.

*   **CMAKE**: you can Build Obfusk8 using cmake too.
   1. clone and joing to the repo: `git clone https://github.com/x86byte/Obfusk8.git` and join to the dir `cd Obfusk8`
   2. configure and generate the files : `cmake CMakeLists.txt`
   3. auto selection of build tools and compiling: `cmake --build .`
   *   after opening `x64 Native Tools Command Prompt for VS 2022`:
     
        ![x64 Native Tools Command Prompt for VS 2022](https://github.com/user-attachments/assets/ef89b4c0-6bc4-40e0-b733-6f9c156677ac)

*   **CMAKE && Microsoft Visual Studio**:
    *   after opening `microsoft visual studio`, click on `Ctrl + B` to compile the project:
      
       ![Microsoft Visual Studio](https://github.com/user-attachments/assets/bd2bed8a-2aee-4a91-88fa-ffc79df3a416)
        
*   **Considerations on Binary Size & Future Enhancements**:
    *   **Size Impact**: Be aware that extensive use of header-only obfuscation, especially with techniques like inlining junk code, MBA expansions, and flattened control flow, can lead to a significant increase in the final binary size. A small program might grow from kilobytes to potentially 2MB or more, depending on the intensity of obfuscation applied.
    *   **Customization & Packing (Future Direction)**:
        *   Currently, Obfusk8 focuses on in-code obfuscation. Users might need to fine-tune the usage of various macros (e.g., reducing the density of `OBF_CALL_ANY_LOCAL_JUNK` or the complexity of `_main`'s loops) if binary size is a critical constraint.
        *   For substantial size reduction post-obfuscation, integrating or using an external PE packer (like UPX, MPRESS, or custom solutions) would be a separate step.
        *   Future development of Obfusk8 could explore options for more granular control over obfuscation intensity or even integrate lightweight packing/compression stubs directly within the library, though this would significantly increase its complexity.


### Demo
   [[Obfusk8: C++17-Based Obfuscation Library - IDA pro Graph View] ~Video Demo](https://youtu.be/B9g4KSg3tHQ)


### contribution & Feedback

This project, Obfusk8, is an ongoing exploration into advanced C++ obfuscation techniques. The current version lays a strong foundation with a multitude of interwoven strategies.

*   **Your Feedback is Invaluable**: As the developer of Obfusk8, I am keenly interested in your perspective, insights, and any feedback you might have. Whether it's suggestions for new features, improvements to existing techniques, reports of successful (or unsuccessful) reverse engineering attempts against code protected by Obfusk8, or general thoughts on the library's usability and effectiveness.
*   **Contribution**: all contributions are welcome and highly appreciated. This project thrives on community input and real-world testing to push its boundaries and become an even more formidable tool for code protection. Please feel free to share your thoughts, raise issues, or contribute to its evolution!.

**Disclaimer**
Obfuscation is a layer of defense, not a foolproof solution. Determined attackers with sufficient skill and time can often reverse engineer obfuscated code. Obfusk8 aims to significantly raise the bar for such efforts. Use in conjunction with other security measures.

**Get in Touch**
If you’d like to share feedback, discuss obfuscation techniques, report reverse engineering attempts, or just have a technical discussion, feel free to reach out directly. I’m always open to constructive conversations and collaboration (i would be happy to collab in obfuscation related projects or anything else).

- x : https://x.com/x86byte  
- telegram: https://t.me/x86byte  
- discord: @x86byte
