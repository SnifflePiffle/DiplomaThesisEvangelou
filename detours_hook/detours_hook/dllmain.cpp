#include <iostream>
#undef _UNICODE
#include <cstdio>
#include <windows.h>
#include <detours.h>
#include <string>
#include <sstream>
#include <shellapi.h>
#include <iostream>
#include <process.h>
#include <winternl.h>
#include <sysinfoapi.h>
#include <libloaderapi.h>
#include <map>
#include <vector>
#include <tuple>
#include <fstream>
#include <cmdparser.hpp>
#include <nlohmann/json.hpp>
#include <winreg.h>
#include <locale>
#include <codecvt>

#pragma warning(disable:4996)

// If compiling as 64-bit
#ifdef _M_X64
#pragma comment (lib, "detoursx64.lib")
#endif // _M_X64


// If compiling as 32-bit
#ifdef _M_IX86
#pragma comment (lib, "detoursx86.lib")
#endif // _M_IX86

using namespace std;
using json = nlohmann::json;

// TO DO:
// Select Functions from malapi.io to hook (define some criteria for these functions)
// Selection:

// Categories --> Injection, Anti-Debugging, Helpers

// Packer Functionality
// 
//  GetProcAddress | 
//  LoadLibraryA  | Both are used by packers to restore IAT
//  VirtualAlloc |
//  VirtualProtect |
//  CreateThread |
//  WriteProcessMemory | These three are used to allocate memory, make it executable and write code to it
//  LoadResource

// Anti-Debug
// 
// IsDebuggerPresent
// CheckRemoteDebuggerPresent
// NtQueryInformationProcess
// FindWindowA
// GetTickCount(64) | Timing
// AddVectoredExceptionHandle

// Other measurements
//
// RegQueryInfoKeyA
// RegGetValueA
// RegEnumValueA
// RegQueryValueExA
// RegDeleteKeyA


// Format output to be a json
// 
// Format output as:{Category: {Hooked_Function:{"Times_Called":Value, Detail_Name:Value}, ...},... }

// Consult LLM to automate hooking --> Not Gonna Happen
// Automate Xenos (or search for other injector if not possible) --> DONE


// ---------------------    INSERT POINTERS TO ACTUAL FUNCTIONS HERE ----------------------

/*
* Anti-Debugging
*/

static BOOL(WINAPI* TrueIsDebuggerPresent)() = IsDebuggerPresent;
static BOOL(WINAPI* TrueCheckRemoteDebuggerPresent)(HANDLE hProcess, PBOOL pbDebuggerPresent) = CheckRemoteDebuggerPresent;
static HWND(WINAPI* TrueFindWindowA)(LPCSTR lpClassName, LPCSTR lpWindowName) = FindWindowA;
static HWND(WINAPI* TrueFindWindowW)(LPCWSTR lpClassName, LPCWSTR lpWindowName) = FindWindowW;
static DWORD(WINAPI* TrueGetTickCount)() = GetTickCount;
static ULONGLONG(WINAPI* TrueGetTickCount64)() = GetTickCount64;
static BOOL(WINAPI* TrueQueryPerformanceCounter)(LARGE_INTEGER* lpPerformanceCount) = QueryPerformanceCounter;
static PVOID(WINAPI* TrueException)(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler) = AddVectoredExceptionHandler;

/*
* Packer Functionality
*/


static FARPROC(WINAPI* TrueGetProcAddress)(HMODULE hModule, LPCSTR  lpProcName) = GetProcAddress;
static HMODULE(WINAPI* TrueLoadLibraryA)(LPCSTR lpLibFileName) = LoadLibraryA;
static HMODULE(WINAPI* TrueLoadLibraryExA)(LPCSTR lpLibFileName, HANDLE hFile,DWORD  dwFlags) = LoadLibraryExA;
static LPVOID(WINAPI* TrueVirtualAlloc)(LPVOID lpAddress,SIZE_T dwSize,DWORD  flAllocationType,DWORD  flProtect) = VirtualAlloc;
static BOOL(WINAPI* TrueVirtualProtect)(LPVOID lpAddress,SIZE_T dwSize,DWORD  flNewProtect,PDWORD lpflOldProtect) = VirtualProtect;
static BOOL(WINAPI* TrueWriteProcessMemory)(HANDLE  hProcess, LPVOID  lpBaseAddress, LPCVOID lpBuffer, SIZE_T  nSize, SIZE_T* lpNumberOfBytesWritten) = WriteProcessMemory;
static HANDLE(WINAPI* TrueCreateThread)(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE  lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) = CreateThread;


/*
* Other Artifacts
*/

static HMODULE(WINAPI* TrueGetModuleHandleA)(LPCSTR lpModuleName) = GetModuleHandleA;
static DWORD(WINAPI* TrueWaitForSingleObject)(HANDLE hHandle,DWORD  dwMilliseconds) = WaitForSingleObject;
static BOOL(WINAPI* TrueIsWow64Process)(HANDLE hProcess,PBOOL  Wow64Process) = IsWow64Process;

// ---------------------    INSERT MUTABLE VARIABLES INSIDE HOOKS HERE ----------------------

static LONG times_called_debugger = 0;
static LONG times_called_thread = 0;
static LONG times_called_alloc = 0;
static LONG times_called_memory = 0;
static LONG times_called_protect = 0;
static LONG times_called_findwindow = 0;
static LONG times_called_findwindow_w = 0;
static LONG times_called_veh = 0;
static LONG times_called_remote_debugger = 0;
static LONG times_called_tick_count = 0;
static LONG times_called_tick_count_64 = 0;
static LONG times_called_proc_address = 0;
static LONG times_called_load_library = 0;
static LONG times_called_load_library_ex = 0;
static LONG times_called_performance_counter = 0;
static LONG times_called_get_module = 0;
static LONG times_called_wait_object = 0;
static LONG times_called_wow_process = 0;


static vector<tuple<string, string, string, string>> Protection_Buffer;
static vector<string> Program_Names;
static vector<wstring> Program_Names_W;
static vector<tuple<string,string>> Alloced_Areas;
static map<string, vector<string>> GetProc_Names;
static vector<string> Library_Names;
static vector<string> Library_Names_Ex;
static vector<string> Thread_Areas;
static vector<string> Write_Areas;
static vector<string> Module_Names;

// Create an empty dictionary using map
map<DWORD, string> PROTECTION_CODES;


void update_map() {
    cout << "lol2\n";
    PROTECTION_CODES[0x10] = "PAGE_EXECUTE";
    PROTECTION_CODES[0x20] = "PAGE_EXECUTE_READ";
    PROTECTION_CODES[0x40] = "PAGE_EXECUTE_READWRITE";
    PROTECTION_CODES[0x80] = "PAGE_EXECUTE_WRITECOPY";
    PROTECTION_CODES[0x01] = "PAGE_NOACCESS";
    PROTECTION_CODES[0x02] = "PAGE_READONLY";
    PROTECTION_CODES[0x04] = "PAGE_READWRITE";
    PROTECTION_CODES[0x08] = "PAGE_WRITECOPY";
    PROTECTION_CODES[0x100] = "PAGE_GUARD";
    PROTECTION_CODES[0x200] = "PAGE_NOCACHE";
    PROTECTION_CODES[0x400] = "PAGE_WRITECOMBINE";
}


BOOL HOOKED_Debugger() {
    InterlockedExchangeAdd(&times_called_debugger, 1);
    return TrueIsDebuggerPresent();
}

BOOL HOOKED_CheckRemoteDebuggerPresent(HANDLE hProcess, PBOOL pbDebuggerPresent) {
    InterlockedExchangeAdd(&times_called_remote_debugger, 1);
    return TrueCheckRemoteDebuggerPresent(hProcess,pbDebuggerPresent);
    //pbDebuggerPresent = false;
}

DWORD HOOKED_GetTickCount() {
    InterlockedExchangeAdd(&times_called_tick_count, 1);
    return TrueGetTickCount();
}

ULONGLONG HOOKED_GetTickCount64() {
    InterlockedExchangeAdd(&times_called_tick_count_64, 1);
    return TrueGetTickCount64();
}

PVOID HOOKED_AddHandler(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler) {
    InterlockedExchangeAdd(&times_called_veh, 1);
    return TrueException(First, Handler);
}

FARPROC HOOKED_GetProcAddress(HMODULE hModule, LPCSTR  lpProcName) {
    InterlockedExchangeAdd(&times_called_proc_address, 1);

    LPSTR  lpFilename = new char[300];
    GetModuleFileNameA(hModule,lpFilename, 300);

    GetProc_Names[lpFilename].push_back(lpProcName);
    return TrueGetProcAddress(hModule, lpProcName);
}

HMODULE HOOKED_LoadLibraryA(LPCSTR lpLibFileName) {
    InterlockedExchangeAdd(&times_called_load_library, 1);

    Library_Names.push_back(lpLibFileName);
    return TrueLoadLibraryA(lpLibFileName);
}

HMODULE HOOKED_LoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile, DWORD  dwFlags) {
    InterlockedExchangeAdd(&times_called_load_library_ex, 1);

    Library_Names_Ex.push_back(lpLibFileName);
    return TrueLoadLibraryExA(lpLibFileName, hFile, dwFlags);
}

HANDLE HOOKED_CreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE  lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) {
    InterlockedExchangeAdd(&times_called_thread, 1);
    stringstream s_address;
    s_address << hex << reinterpret_cast<unsigned int>(lpStartAddress);

    Thread_Areas.push_back(s_address.str());

    return TrueCreateThread(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
}

LPVOID HOOKED_VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect) {
    InterlockedExchangeAdd(&times_called_alloc, 1);
    LPVOID addr = TrueVirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);

    stringstream s_address;
    s_address << hex << reinterpret_cast<unsigned int>(addr);
    Alloced_Areas.push_back(make_tuple(s_address.str(),PROTECTION_CODES[flProtect]));

    return addr;
}

BOOL HOOKED_WriteProcessMemory(HANDLE  hProcess, LPVOID  lpBaseAddress, LPCVOID lpBuffer, SIZE_T  nSize, SIZE_T* lpNumberOfBytesWritten) {
    InterlockedExchangeAdd(&times_called_memory, 1);
    
    stringstream s_address;
    s_address << hex << reinterpret_cast<unsigned int>(lpBaseAddress);

    Write_Areas.push_back(s_address.str());

    return TrueWriteProcessMemory(hProcess,lpBaseAddress,lpBuffer, nSize,lpNumberOfBytesWritten);
}

HWND HOOKED_FindWindow(LPCSTR lpClassName, LPCSTR lpWindowName) {
    if (lpWindowName) {
        Program_Names.push_back((string)lpWindowName);
    }
    else if (lpClassName){
        Program_Names.push_back((string)lpClassName);
    }

    InterlockedExchangeAdd(&times_called_findwindow, 1);
    return TrueFindWindowA(lpClassName, lpWindowName);
}

HWND HOOKED_FindWindowW(LPCWSTR lpClassName, LPCWSTR lpWindowName) {
    if (lpWindowName) {
        Program_Names_W.push_back((wstring)lpWindowName);
    }
    else if (lpClassName) {
        Program_Names_W.push_back((wstring)lpClassName);
    }

    InterlockedExchangeAdd(&times_called_findwindow_w, 1);
    return TrueFindWindowW(lpClassName, lpWindowName);
}

BOOL HOOKED_VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {
    
    MEMORY_BASIC_INFORMATION PreviousProt;
    VirtualQuery(lpAddress, &PreviousProt, dwSize);
    //Protection_Buffer.push_back(make_tuple("Address", "Size", "New Protection", "Previous Protection"));

    stringstream s_address;
    s_address << hex << reinterpret_cast<unsigned int>(lpAddress);
    Protection_Buffer.push_back(make_tuple(s_address.str(), to_string(dwSize), PROTECTION_CODES[flNewProtect], PROTECTION_CODES[PreviousProt.Protect]));
    
    InterlockedExchangeAdd(&times_called_protect, 1);
    return TrueVirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

BOOL HOOKED_QueryPerformanceCounter(LARGE_INTEGER* lpPerformanceCount) {
    InterlockedExchangeAdd(&times_called_performance_counter, 1);
    return TrueQueryPerformanceCounter(lpPerformanceCount);
}

HMODULE HOOKED_GetModuleHandleA(LPSTR lpModuleName) {
    //stringstream s_address;
    //s_address reinterpret_cast<char *>(hKey);
    InterlockedExchangeAdd(&times_called_get_module, 1);
    if (lpModuleName) {
        Module_Names.push_back((string)lpModuleName);
    }
    return TrueGetModuleHandleA(lpModuleName);
}

DWORD HOOKED_WaitForSingleObject(HANDLE hHandle, DWORD  dwMilliseconds) {
   
    InterlockedExchangeAdd(&times_called_wait_object, 1);
    return TrueWaitForSingleObject(hHandle,dwMilliseconds);
}

DWORD HOOKED_IsWow64Process(HANDLE hProcess, PBOOL  Wow64Process) {

    InterlockedExchangeAdd(&times_called_wow_process, 1);
    return TrueIsWow64Process(hProcess, Wow64Process);
}

BOOL InstallHook() {
    cout << "lol1\n";

    DWORD	dwDetoursErr = NULL;

    // Creating the transaction & updating it
    if ((dwDetoursErr = DetourTransactionBegin()) != NO_ERROR) {
        printf("[!] DetourTransactionBegin Failed With Error : %d \n", dwDetoursErr);
        return FALSE;
    }

    if ((dwDetoursErr = DetourUpdateThread(GetCurrentThread())) != NO_ERROR) {
        printf("[!] DetourUpdateThread Failed With Error : %d \n", dwDetoursErr);
        return FALSE;
    }

    // Running MyMessageBoxA instead of g_pMessageBoxA that is MessageBoxA
    if ((dwDetoursErr = DetourAttach((PVOID*)(&TrueIsDebuggerPresent), (PVOID)HOOKED_Debugger)) != NO_ERROR) {
        printf("[!] DetourAttach For IsDebuggerPresent Failed With Error : %d \n", dwDetoursErr);
        return FALSE;
    }
    if ((dwDetoursErr = DetourAttach((PVOID*)(&TrueCheckRemoteDebuggerPresent), (PVOID)HOOKED_CheckRemoteDebuggerPresent)) != NO_ERROR) {
        printf("[!] DetourAttach For CheckRemoteDebuggerPresent Failed With Error : %d \n", dwDetoursErr);
        return FALSE;
    }
    if ((dwDetoursErr = DetourAttach((PVOID*)(&TrueGetTickCount), (PVOID)HOOKED_GetTickCount)) != NO_ERROR) {
        printf("[!] DetourAttach For GetTickCount Failed With Error : %d \n", dwDetoursErr);
        return FALSE;
    }
    if ((dwDetoursErr = DetourAttach((PVOID*)(&TrueGetTickCount64), (PVOID)HOOKED_GetTickCount64)) != NO_ERROR) {
        printf("[!] DetourAttach For GetTickCount64 Failed With Error : %d \n", dwDetoursErr);
        return FALSE;
    }
    if ((dwDetoursErr = DetourAttach((PVOID*)(&TrueFindWindowA), (PVOID)HOOKED_FindWindow)) != NO_ERROR) {
        printf("[!] DetourAttach For FindWindowA Failed With Error : %d \n", dwDetoursErr);
        return FALSE;
    }
    if ((dwDetoursErr = DetourAttach((PVOID*)(&TrueFindWindowW), (PVOID)HOOKED_FindWindowW)) != NO_ERROR) {
        printf("[!] DetourAttach For FindWindowW Failed With Error : %d \n", dwDetoursErr);
        return FALSE;
    }
    if ((dwDetoursErr = DetourAttach((PVOID*)(&TrueException), (PVOID)HOOKED_AddHandler)) != NO_ERROR) {
        printf("[!] DetourAttach For AddVectoredExceptionHandler Failed With Error : %d \n", dwDetoursErr);
        return FALSE;
    }
    if ((dwDetoursErr = DetourAttach((PVOID*)(&TrueCreateThread), (PVOID)HOOKED_CreateThread)) != NO_ERROR) {
        printf("[!] DetourAttach For CreateThread Failed With Error : %d \n", dwDetoursErr);
        return FALSE;
    }
    if ((dwDetoursErr = DetourAttach((PVOID*)(&TrueVirtualAlloc), (PVOID)HOOKED_VirtualAlloc)) != NO_ERROR) {
        printf("[!] DetourAttach For VirtualAlloc Failed With Error : %d \n", dwDetoursErr);
        return FALSE;
    }
    if ((dwDetoursErr = DetourAttach((PVOID*)(&TrueWriteProcessMemory), (PVOID)HOOKED_WriteProcessMemory)) != NO_ERROR) {
        printf("[!] DetourAttach For WriteProcessMemory Failed With Error : %d \n", dwDetoursErr);
        return FALSE;
    }
    if ((dwDetoursErr = DetourAttach((PVOID*)(&TrueVirtualProtect), (PVOID)HOOKED_VirtualProtect)) != NO_ERROR) {
        printf("[!] DetourAttach For VirtualProtect Failed With Error : %d \n", dwDetoursErr);
        return FALSE;
    }
    if ((dwDetoursErr = DetourAttach((PVOID*)(&TrueGetProcAddress), (PVOID)HOOKED_GetProcAddress)) != NO_ERROR) {
        printf("[!] DetourAttach For GetProcAddress Failed With Error : %d \n", dwDetoursErr);
        return FALSE;
    }
    if ((dwDetoursErr = DetourAttach((PVOID*)(&TrueLoadLibraryA), (PVOID)HOOKED_LoadLibraryA)) != NO_ERROR) {
        printf("[!] DetourAttach For LoadLibraryA Failed With Error : %d \n", dwDetoursErr);
        return FALSE;
    }

    if ((dwDetoursErr = DetourAttach((PVOID*)(&TrueLoadLibraryExA), (PVOID)HOOKED_LoadLibraryExA)) != NO_ERROR) {
        printf("[!] DetourAttach For LoadLibraryExA Failed With Error : %d \n", dwDetoursErr);
        return FALSE;
    }

    if ((dwDetoursErr = DetourAttach((PVOID*)(&TrueQueryPerformanceCounter), (PVOID)HOOKED_QueryPerformanceCounter)) != NO_ERROR) {
        printf("[!] DetourAttach For TrueQueryPerformanceCounter Failed With Error : %d \n", dwDetoursErr);
        return FALSE;
    }

    if ((dwDetoursErr = DetourAttach((PVOID*)(&TrueGetModuleHandleA), (PVOID)HOOKED_GetModuleHandleA)) != NO_ERROR) {
        printf("[!] DetourAttach For GetModuleHandleA Failed With Error : %d \n", dwDetoursErr);
        return FALSE;
    }

    if ((dwDetoursErr = DetourAttach((PVOID*)(&TrueWaitForSingleObject), (PVOID)HOOKED_WaitForSingleObject)) != NO_ERROR) {
        printf("[!] DetourAttach For WaitForSingleObject Failed With Error : %d \n", dwDetoursErr);
        return FALSE;
    }

    if ((dwDetoursErr = DetourAttach((PVOID*)(&TrueIsWow64Process), (PVOID)HOOKED_IsWow64Process)) != NO_ERROR) {
        printf("[!] DetourAttach For IsWow64Process Failed With Error : %d \n", dwDetoursErr);
        return FALSE;
    }

    // Actual hook installing happen after `DetourTransactionCommit` - commiting the transaction
    if ((dwDetoursErr = DetourTransactionCommit()) != NO_ERROR) {
        printf("[!] DetourTransactionCommit Failed With Error : %d \n", dwDetoursErr);
        return FALSE;
    }

    return TRUE;
}

void configure_parser(cli::Parser& parser) {
    parser.set_optional<string>("s", "running_file", "C:\\Users\\mixlh\\stats", "Output file for the stats");
}

VOID atexitHandler(VOID) {

    HANDLE hFile;

    /* BEGIN JSON OBJECT */

    json Buffer;

    /* FIRST CATEGORY --> Packer Functionality*/
    json PF;

    /* VirtualAlloc */

    json VA;
    VA["Times_Called"] = to_string(times_called_alloc);
    VA["Allocated_Areas"] = Alloced_Areas;
    PF["VirtualAlloc"] = VA;

    /* VirtualProtect */

    json VP;
    VP["Times_Called"] = to_string(times_called_protect);
    VP["Details"] = Protection_Buffer;
    PF["VirtualProtect"] = VP;

    /* WriteProcessMemory */

    json WPM;
    WPM["Times_Called"] = to_string(times_called_memory);
    WPM["Areas_Written"] = Write_Areas;
    PF["WriteProcessMemory"] = WPM;

    /* CreateThread */

    json CT;
    CT["Times_Called"] = to_string(times_called_thread);
    CT["Start_Addresses"] = Thread_Areas;
    PF["CreateThread"] = CT;

    /* GetProcAddress */

    json GPA;
    GPA["Times_Called"] = to_string(times_called_proc_address);
    GPA["Modules_Functions"] = GetProc_Names;
    PF["GetProcAddress"] = GPA;

    /* LoadLibraryA */

    json LLA;
    LLA["Times_Called"] = to_string(times_called_load_library);
    LLA["Libraries"] = Library_Names;
    PF["LoadLibraryA"] = LLA;

    /* LoadLibraryExA */
    
    json LLEA;
    LLEA["Times_Called"] = to_string(times_called_load_library_ex);
    LLEA["Libraries"] = Library_Names_Ex;
    PF["LoadLibraryExA"] = LLEA;

    /* QueryPerformanceCounter */

    json QPC;
    QPC["Times_Called"] = to_string(times_called_performance_counter);
    PF["QueryPerformanceCounter"] = QPC;

    /* ADD PF TO BUFFER */

    Buffer["Packer_Functionality"] = PF;

    /* SECOND CATEGORY --> Anti Debugging */

    json AD;

    /* IsDebuggerPresent */

    json IDP;
    IDP["Times_Called"] = to_string(times_called_debugger);
    AD["IsDebuggerPresent"] = IDP;

    /* CheckRemoteDebuggerPresent */
    json CRDP;
    CRDP["Times_Called"] = to_string(times_called_remote_debugger);
    AD["CheckRemoteDebuggerPresent"] = CRDP;

    /* GetTickCount */

    json GTC;
    GTC["Times_Called"] = to_string(times_called_tick_count);
    AD["GetTickCount"] = GTC;

    /* GetTickCount64 */

    json GTC64;
    GTC64["Times_Called"] = to_string(times_called_tick_count_64);
    AD["GetTickCount64"] = GTC64;

    /* FindWindowA */

    json FW;
    FW["Times_Called"] = to_string(times_called_findwindow);
    FW["Details"] = Program_Names;
    AD["FindWindowA"] = FW;

    /* FindWindowW */

    json FWW;
    FWW["Times_Called"] = to_string(times_called_findwindow_w);
    FWW["Details"] = Program_Names_W;
    AD["FindWindowA"] = FWW;

    /* AddVectoredExceptionHandler */

    json AVEH;
    AVEH["Times_Called"] = to_string(times_called_veh);
    AD["AddVectoredExceptionHandler"] = AVEH;

    Buffer["Anti_Debugging"] = AD;

    /* Registry Artifacts */

    json OA;

    /* GetModuleHandleA */

    json GMHA;
    GMHA["Times_Called"] = to_string(times_called_get_module);
    GMHA["Module_Named"] = Module_Names;
    OA["GetModuleHandleA"] = GMHA;
 
    /* WaitForSingleObject */

    json WFSO;
    WFSO["Times_Called"] = to_string(times_called_wait_object);
    OA["WaitForSingleObject"] = WFSO;

    /* IsWow64Process */

    json IW64P;
    IW64P["Times_Called"] = to_string(times_called_wow_process);
    OA["IsWow64Process"] = IW64P;

    Buffer["Other_Artifacts"] = OA;

    CHAR buffer[MAX_PATH] = { 0 };
    
    // Get the fully-qualified path of the executable
    GetModuleFileNameA(NULL, buffer, MAX_PATH);
    string fullname = buffer;
    cout << fullname << endl;
    int numArgs;
    size_t lastindex = fullname.find_last_of(".");
    string rawname = fullname.substr(0, lastindex);
    lastindex = fullname.find_last_of("\\");
    rawname = rawname.substr(lastindex+1,(size_t)rawname.length());
    ofstream output_file("C:\\Users\\mixlh\\Diploma_Toolset\\results\\"+ rawname.substr(0, rawname.find_last_of("_")) + ".exe\\" + rawname + ".json");
    if (!output_file.is_open()) {
        std::cout << "\n Failed to open output file";
    }
    else {
        output_file << Buffer;
        output_file.close();
    }

    /*
    const char* DataBuffer = Buffer.c_str();

    DWORD dwBytesToWrite = (DWORD)strlen(DataBuffer);
    DWORD dwBytesWritten = 0;
    BOOL bErrorFlag = FALSE;
    hFile = CreateFile(L"C:\\Users\\mixlh\\stats.txt",                // name of the write
        GENERIC_WRITE,          // open for writing
        0,                      // do not share
        NULL,                   // default security
        CREATE_NEW,             // create new file only
        FILE_ATTRIBUTE_NORMAL,  // normal file
        NULL);                  // no attr. template

    bErrorFlag = WriteFile(
        hFile,           // open file handle
        DataBuffer,      // start of data to write
        dwBytesToWrite,  // number of bytes to write
        &dwBytesWritten, // number of bytes that were written
        NULL);            // no overlapped structure

    CloseHandle(hFile);
    */
}

BOOL APIENTRY DllMain(
    _In_ HINSTANCE hinstDLL,
    _In_ DWORD     fdwReason,
    _In_ LPVOID    lpvReserved
)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:

        // Update protection map
        FILE* file = freopen("C:\\Users\\mixlh\\errors.log", "w", stdout);
        update_map();
        //------------------------------------------------------------------
        //  Hooking

        if (!InstallHook())
            return -1;

        cout << "lol\n";

        atexit(atexitHandler);
        //at_quick_exit(atexitHandler);

    }

    return TRUE;
}