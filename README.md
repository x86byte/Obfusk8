# Obfusk8: C++17-Based Obfuscation Library

Obfusk8 is a lightweight, header-only C++17 library designed to significantly enhance the obfuscation of your applications, making reverse engineering a substantially more challenging endeavor. It achieves this through a diverse set of compile-time and runtime techniques aimed at protecting your code's logic and data.

**Core Obfuscation Strategies**

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

### 3. Compile-Time String Encryption (`OBFUSCATE_STRING` from `xtea8.hpp`)
*   **Hidden Strings**: Encrypts all string literals at compile-time using a modified XTEA cipher.
*   **Dynamic Keys**: Encryption keys are unique per string instance, derived from string content, file location (`__FILE__`, `__LINE__`), and build time (`__DATE__`, `__TIME__`).
*   **Just-In-Time Decryption**: Strings are decrypted on the stack only when accessed at runtime, minimizing their plaintext lifetime in memory.
*   **(Optional) Decoy PE Sections**: Can store encrypted strings in custom PE sections designed to mimic common packer signatures, potentially misleading analysts (MSVC-specific feature from `xtea8.hpp`).

### 4. Stealthy Windows API Calling (`STEALTH_API_OBFSTR` / `STEALTH_API_OBF` from `Resolve8.hpp`)
*   **IAT Obscurity**: Avoids leaving direct, easily identifiable entries for Windows APIs in the Import Address Table (IAT).
*   **PEB-Based Resolution**: Dynamically finds base addresses of loaded DLLs and the addresses of API functions by directly parsing Process Environment Block (PEB) data structures at runtime. This bypasses standard `GetModuleHandle` and `GetProcAddress` for initial resolution if those themselves are not yet resolved by this mechanism.
*   **Hashed Names**: Uses compile-time hashing (custom algorithm `CT_HASH`) of DLL and API names for lookups. This prevents plaintext DLL and API names from appearing in the binary's import-related data or string tables when using these macros.

### 5. API Abstraction Classes with Built-in Stealth
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

### 6. Core Obfuscation Primitives (Macros in `Obfusk8Core.hpp`)
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

**Dependencies**
The Obfusk8 library is modular. Core functionality relies on:
- `Obfusk8Core.hpp`: (This file) The central header that orchestrates and provides the main obfuscation macros and primitives.
- `xtea8.hpp`: Provides XTEA-based compile-time string encryption and optional PE section manipulation features.
- `Resolve8.hpp`: Implements the PEB-based stealthy Windows API resolution.

Optional helper API classes are provided in separate headers, typically located in subdirectories:
- `k8_ProcessManipulationAPIs/k8_ProcessManipulationAPIs.hpp`: For stealthy process manipulation APIs.
- `k8_CryptographyAPIs/k8_CryptographyAPIs.hpp`: For stealthy cryptography APIs.
- `k8_NetworkingAPIs/k8_NetworkingAPIs.hpp`: For stealthy networking APIs.
- `k8_RegistryAPIs/k8_RegistryAPIs.hpp`: For stealthy registry APIs.

  *  ida graph:
      ![image](https://github.com/user-attachments/assets/680f542e-88c0-472e-8149-4ee6c80e82a2)
     
  * some chunks from ida pro:
      ![image](https://github.com/user-attachments/assets/2bdc6270-96d9-4448-9557-54f9ef4035e3)
      ![image](https://github.com/user-attachments/assets/952584b4-f046-4ff4-a3a4-c485fa370aa8)
      ![image](https://github.com/user-attachments/assets/54128487-445c-42c9-86df-202f77a2eb73)
    
  * detect it easy signatures results:
      ![image](https://github.com/user-attachments/assets/460889f8-49a7-4d6d-a226-442d4cece4db)
    
  * memory map (from die):
    `
                  Offset	Address	Size	Name
                  0000000000000000	0000000140000000	0000000000000800	PE Header
                  0000000000000800	0000000140001000	000000000029b600	Section(0)['.text']
                  000000000029be00	000000014029d000	000000000004a400	Section(1)['.rdata']
                  00000000002e6200	00000001402e8000	0000000000001400	Section(2)['.data']
                  00000000002e7600	00000001402ef000	0000000000004200	Section(3)['.pdata']
                  00000000002eb800	00000001402f4000	0000000000000c00	Section(4)['.themida']
                  00000000002ec400	00000001402f5000	0000000000000c00	Section(5)['.vmp1']
                  00000000002ed000	00000001402f6000	0000000000000c00	Section(6)['.enigma2']
                  00000000002edc00	00000001402f7000	0000000000000c00	Section(7)['.xtls']
                  00000000002ee800	00000001402f8000	0000000000000c00	Section(8)['.arch']
                  00000000002ef400	00000001402f9000	0000000000000c00	Section(9)['.vmp0']
                  00000000002f0000	00000001402fa000	0000000000000c00	Section(10)['.xpdata']
                  00000000002f0c00	00000001402fb000	0000000000000c00	Section(11)['.vmp2']
                  00000000002f1800	00000001402fc000	0000000000000c00	Section(12)['.enigma1']
                  00000000002f2400	00000001402fd000	0000000000000c00	Section(13)['.PECompa']
                  00000000002f3000	00000001402fe000	0000000000000c00	Section(14)['.dsstext']
                  00000000002f3c00	00000001402ff000	0000000000000c00	Section(15)['.UPX0']
                  00000000002f4800	0000000140300000	0000000000000c00	Section(16)['.UPX1']
                  00000000002f5400	0000000140301000	0000000000000c00	Section(17)['.UPX2']
                  00000000002f6000	0000000140302000	0000000000000c00	Section(18)['.aspack']
                  00000000002f6c00	0000000140303000	0000000000000c00	Section(19)['.nsp0']
                  00000000002f7800	0000000140304000	0000000000000c00	Section(20)['.nsp1']
                  00000000002f8400	0000000140305000	0000000000000c00	Section(21)['.FSG!']
                  00000000002f9000	0000000140306000	0000000000000c00	Section(22)['.pec1']
                  00000000002f9c00	0000000140307000	0000000000000c00	Section(23)['.pec2']
                  00000000002fa800	0000000140308000	0000000000000c00	Section(24)['.petite']
                  00000000002fb400	0000000140309000	0000000000000c00	Section(25)['.mpress1']
                  00000000002fc000	000000014030a000	0000000000000c00	Section(26)['.mpress2']
                  00000000002fcc00	000000014030b000	0000000000000c00	Section(27)['.vmp3']
                  00000000002fd800	000000014030c000	0000000000000c00	Section(28)['.vmp4']
                  00000000002fe400	000000014030d000	0000000000000c00	Section(29)['.vmp5']
                  00000000002ff000	000000014030e000	0000000000000c00	Section(30)['.vmp6']
                  00000000002ffc00	000000014030f000	0000000000000c00	Section(31)['.vmp7']
                  0000000000300800	0000000140310000	0000000000000200	Section(32)['.fptable']
                  0000000000300a00	0000000140311000	0000000000000c00	Section(33)['.reloc']
`
**Demo**
    

**Usage**

1.  Include `Obfusk8Core.hpp` in your main project file (e.g., `main.cpp`).
    ```cpp
    #include "Obfusk8Core.hpp" // Adjust path as needed
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
        
        return 0;
    })
    ```
3.  Use `OBFUSCATE_STRING("your string")` for all important string literals. Access the decrypted string via its `.c_str()` method if needed for API calls, or use its other methods like `.print_to_console()` if provided by `xtea8.hpp`.
4.  Use `STEALTH_API_OBFSTR("dll_name.dll", "FunctionNameA")` for direct stealthy API calls, or preferably use the API wrapper classes (e.g., `K8_ProcessManipulationAPIs::ProcessAPI`, `k8_NetworkingAPIs::NetworkingAPI`) for convenience and built-in stealth.
5.  Sprinkle `OBF_BOGUS_FLOW_*`, `OBF_CALL_ANY_LOCAL_JUNK`, `NOP()`, and other primitives in performance-insensitive critical sections of your code for added obfuscation layers.

* see the main.cpp file.

**Building**

*   **Compiler Requirement**: This library is designed for C++17. The Microsoft C++ Compiler (`cl.exe`) is primarily targeted, especially for PE section features and SEH usage.
*   **Getting `cl.exe` (MSVC Compiler) on Windows**:
    1.  **Install Visual Studio**: The easiest way to get `cl.exe` is by installing Visual Studio. You can download the Visual Studio Community edition for free from the [Visual Studio website](https://visualstudio.microsoft.com/downloads/).
    2.  **Select Workload**: During installation, make sure to select the "Desktop development with C++" workload. This will install the C++ compiler, Windows SDK, and other necessary tools.
    3.  **Use Developer Command Prompt**: After installation, search for "Developer Command Prompt for VS" (e.g., "x64 Native Tools Command Prompt for VS 2022") in your Start Menu and run it. This command prompt automatically sets up the environment variables (PATH, INCLUDE, LIB) needed to use `cl.exe`.
*   **Include Paths**:
    *   Ensure the directory containing `Obfusk8Core.hpp` is in your compiler's include path.
    *   If `xtea8.hpp`, `Resolve8.hpp`, and the API wrapper directories (e.g., `k8_NetworkingAPIs/`) are not in the same directory as `Obfusk8Core.hpp`, ensure their paths are also correctly configured. `Obfusk8Core.hpp` uses relative paths like `../Obfusk8Core.hpp` for some of its internal includes of the API wrappers, so the directory structure matters. If `Obfusk8Core.hpp` is at the root of your include directory for this library, then API wrappers should be in subdirectories like `k8_NetworkingAPIs/` relative to where `Obfusk8Core.hpp` expects them or adjust the include paths within `Obfusk8Core.hpp` itself.
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
    *   `/I"path/to/your/obfusk8_includes"`: (Optional, if headers are not in default paths) Add the directory where `Obfusk8Core.hpp` and its dependencies are located. If they are in subdirectories, ensure the relative paths within `Obfusk8Core.hpp` match your layout.
    *   **Note on Libraries**: While the stealth API resolution aims to avoid static linking for the obfuscated functions, the Windows SDK headers themselves might require certain `.lib` files to be available to the linker for resolving any non-obfuscated SDK usage or internal types (e.g., `Ws2_32.lib`, `Wininet.lib`, `Advapi32.lib`, etc.). For a simple project like `cl /std:c++17 /EHsc main.cpp`, the linker often resolves these automatically if they are standard Windows libraries.

*   **Considerations on Binary Size & Future Enhancements**:
    *   **Size Impact**: Be aware that extensive use of header-only obfuscation, especially with techniques like inlining junk code, MBA expansions, and flattened control flow, can lead to a significant increase in the final binary size. A small program might grow from kilobytes to potentially 2MB or more, depending on the intensity of obfuscation applied.
    *   **Customization & Packing (Future Direction)**:
        *   Currently, Obfusk8 focuses on in-code obfuscation. Users might need to fine-tune the usage of various macros (e.g., reducing the density of `OBF_CALL_ANY_LOCAL_JUNK` or the complexity of `_main`'s loops) if binary size is a critical constraint.
        *   For substantial size reduction post-obfuscation, integrating or using an external PE packer (like UPX, MPRESS, or custom solutions) would be a separate step.
        *   Future development of Obfusk8 could explore options for more granular control over obfuscation intensity or even integrate lightweight packing/compression stubs directly within the library, though this would significantly increase its complexity.

**mindmap & Feedback**

This project, Obfusk8, is an ongoing exploration into advanced C++ obfuscation techniques. The current version lays a strong foundation with a multitude of interwoven strategies.

*   **Future Vision (Obfusk8 v2)**: I envision a "Version 2" that will delve into even more sophisticated areas. A key feature I'm aiming for is **self-packing/unpacking capabilities integrated directly into the obfuscation layer**. This would involve the `_main` macro or a similar mechanism not only obfuscating the code but also embedding the primary application logic in an encrypted/compressed form, which is then decrypted and executed in memory at runtime. This would further enhance resistance to static analysis and reduce the initial on-disk footprint if the compression is effective. Other potential v2 enhancements could include deeper integration of metamorphic code generation, and perhaps even user-configurable obfuscation profiles.

*   **Your Feedback is Invaluable**: As the developer of Obfusk8, I am keenly interested in your perspective, insights, and any feedback you might have. Whether it's suggestions for new features, improvements to existing techniques, reports of successful (or unsuccessful) reverse engineering attempts against code protected by Obfusk8, or general thoughts on the library's usability and effectiveness – all contributions are welcome and highly appreciated. This project thrives on community input and real-world testing to push its boundaries and become an even more formidable tool for code protection. Please feel free to share your thoughts, raise issues, or contribute to its evolution!

**Disclaimer**
Obfuscation is a layer of defense, not a foolproof solution. Determined attackers with sufficient skill and time can often reverse engineer obfuscated code. Obfusk8 aims to significantly raise the bar for such efforts. Use in conjunction with other security measures.
